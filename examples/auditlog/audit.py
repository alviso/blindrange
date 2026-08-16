"""blindrange-audit: an audit trail the vendor holding it cannot read or alter.

Why an audit log, out of everything that could be built on blindrange: it is
the one workload where this design is not a privacy tax paid on top of a
worse database, but the better fit on the merits.

  * Audit trails are append-only. So are the per-writer PRF counter chains
    the index is made of — nothing here has to be bolted on to stop history
    being rewritten, because rewriting it was never expressible.
  * They need tamper-evidence. Every record is AES-GCM, so an altered blob
    does not decrypt. A holder cannot quietly change an entry; it can only
    destroy one, and the replica group makes that visible.
  * They are queried exactly the way this index is fast: actor prefix,
    action prefix, time range, sorted by time, counted. No full-text over
    payloads and no GROUP BY, which is genuinely not how anyone reads an
    audit log — you filter, then you read what came back.
  * The party holding your audit log being able to read it is a liability,
    not a feature. That is a rare sentence, and it is the whole pitch.

WHERE THIS RUNS MATTERS. The encrypting side is yours and must stay yours:
keys live in this process and in the .brdb file beside it, never on a node
and never with us. That is the same fork Storj draws between its hosted S3
gateway (server-side keys) and the self-hosted one (end-to-end) — run this
next to whatever is producing events, and the nodes storing them remain
unable to read a single field.

INGESTING FROM WHAT YOU ALREADY RUN. There is no plugin to install. Vector,
Fluent Bit and the OpenTelemetry Collector all ship a generic HTTP output,
so pointing them here is configuration, not code — see README.md.

  python3 examples/auditlog/audit.py --state ~/.blindrange/audit.brdb \\
      --bootstrap seed.blindrange.dev:7501 --secret blindrange-public

  POST /ingest    one event, a JSON array, or NDJSON
  GET  /events    ?from=&to=&actor=&action=&limit=
  GET  /count     same filters, answered from index metadata alone
  GET  /          a small console, including what a node operator sees
"""
import argparse
import json
import os
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from blindrange import Owner  # noqa: E402

# A timestamp field wide enough for 68 years of seconds. leaf_width is the
# privacy dial and it is deliberately exposed as a flag: it decides both
# what an adversary watching every query can ever resolve, and what the
# archive costs, because index entries scale with the number of levels.
TS_BITS = 31
# What makes an object look like an event rather than an envelope we have
# failed to recognise. Used only to refuse the latter.
# How far back an unbounded query looks. An ordered walk costs one lookup
# per leaf, so the full 31-bit domain is 524,288 leaves — from 1970 to 2038,
# almost all of it empty. /contrast asked for exactly that and never
# returned; a default /events did the same, slowly enough on a local node to
# look merely sluggish. A window is not a limitation here, it is the
# difference between a query and a hang.
DEFAULT_WINDOW_S = int(os.environ.get("BR_AUDIT_WINDOW", str(86400 * 30)))
EVENT_FIELDS = {"ts", "timestamp", "time", "@timestamp", "actor", "user",
                "action", "event", "message", "msg", "detail", "body",
                "severity", "level"}
DEFAULT_LEAF = 4096            # ~68 minutes: the power of two nearest an hour


def snap_leaf(seconds):
    """Round a human interval to a legal leaf width, and say what it became.

    Dyadic decomposition needs a power of two, so "3600" — the obvious way
    to ask for hourly resolution — is not expressible. Rejecting it would be
    correct and useless; silently accepting 4096 while calling it an hour
    would be a lie in the one place this project cannot afford one, since
    this number IS the privacy guarantee. Snap, then report the truth.
    """
    seconds = max(1, int(seconds))
    lo = 1 << max(0, seconds.bit_length() - 1)
    hi = lo << 1
    leaf = lo if (seconds - lo) <= (hi - seconds) else hi
    return min(leaf, 1 << (TS_BITS - 1))


def human(seconds):
    for unit, n in (("day", 86400), ("hour", 3600), ("minute", 60)):
        if seconds >= n:
            v = seconds / n
            return f"{v:.0f} {unit}{'s' if round(v) != 1 else ''}" if v == int(v) \
                else f"{v:.1f} {unit}s"
    return f"{seconds} seconds"


def schema(leaf):
    return {
        "ts": {"type": "int", "bits": TS_BITS, "leaf_width": leaf},
        # 6 characters of prefix at 5 bits each. Enough to find "alice@" or
        # "svc-deploy" without turning the actor into a searchable identity:
        # the index sees an ordered code for the prefix, never the string.
        "actor": {"type": "str", "bits": 30, "chars": 6, "leaf_width": 16},
        "action": {"type": "str", "bits": 30, "chars": 6, "leaf_width": 16},
    }


def normalise(ev, now=None):
    """Coerce whatever a shipper sends into the four fields we index.

    Deliberately forgiving about field names — Vector, Fluent Bit and OTLP
    each have their own idea of what a timestamp is called, and an audit
    pipeline that drops events because of a key name is worse than useless.
    Anything not recognised still rides along inside the encrypted payload.
    """
    if not isinstance(ev, dict):
        ev = {"message": str(ev)}
    ts = (ev.get("ts") or ev.get("timestamp") or ev.get("time")
          or ev.get("@timestamp") or ev.get("observedTimeUnixNano"))
    if isinstance(ts, str):
        try:
            ts = datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
        except ValueError:
            ts = None
    if isinstance(ts, (int, float)):
        ts = float(ts)
        while ts > 4e10:            # ns or ms epochs from OTLP / Fluent Bit
            ts /= 1000.0
    else:
        ts = now if now is not None else time.time()
    actor = str(ev.get("actor") or ev.get("user") or ev.get("principal")
                or ev.get("subject") or "unknown")
    action = str(ev.get("action") or ev.get("event") or ev.get("operation")
                 or ev.get("message") or "event")
    return {"ts": int(ts), "actor": actor[:64], "action": action[:64],
            "payload": ev}


class Trail:
    """The append-only store. No delete, no compact — on purpose.

    Both exist in the SDK and neither is exposed here. An audit trail whose
    own tooling can drop entries answers the wrong question when a regulator
    asks whether records could have been removed. Retention, when it is
    added, has to be a deliberate epoch-level expiry rather than a delete
    call sitting one HTTP route away.
    """

    def __init__(self, owner):
        self.owner = owner
        self.lock = threading.Lock()
        self.written = 0

    def append(self, events):
        rows = [normalise(e) for e in events]
        if not rows:
            return 0
        with self.lock:
            self.owner.insert_many(rows)
            self.written += len(rows)
        return len(rows)

    def _preds(self, q):
        def one(k):
            v = q.get(k, [None])[0]
            return v.strip() if v else None
        preds, lo, hi = [], one("from"), one("to")
        now = int(time.time())
        # Bounded by default, both ends. Unbounded meant walking every leaf
        # from the epoch to 2038 to answer "show me some events".
        t1 = int(float(hi)) if hi else now
        t0 = int(float(lo)) if lo else max(0, t1 - DEFAULT_WINDOW_S)
        preds.append({"field": "ts", "lo": t0, "hi": t1})
        for field in ("actor", "action"):
            val = one(field)
            if val:
                preds.append({"field": field, "prefix": val})
        return preds

    def window(self, q):
        """The time range a query actually covered.

        Returned with every answer, because the default is a window rather
        than all of history and an empty result would otherwise be
        indistinguishable from an empty database.
        """
        ts = next(p for p in self._preds(q) if p["field"] == "ts")
        return {"from": ts["lo"], "to": ts["hi"]}

    def events(self, q, limit=200, newest_first=True):
        preds = self._preds(q)
        out = []
        # order="-ts" walks dyadic leaves from the newest end. Both the
        # answer and the cost improve: an audit UI wants the most recent
        # events, and ascending had to pay for every leaf in the window
        # before it could know which ones were last — 527 lookups for a
        # 25-day range at hourly leaves, measured at 5.2s for five rows.
        # Either direction still exposes no ordering to the network; only
        # the key holder knows the leaves are in value order.
        order = "-ts" if newest_first else "ts"
        for row in self.owner.query_stream(preds, limit=limit, order=order):
            out.append({"ts": row.get("ts"), "actor": row.get("actor"),
                        "action": row.get("action"),
                        "payload": row.get("payload")})
        return out

    def count(self, q):
        """Answered from index metadata: no records fetched, none decrypted.

        Accurate to a leaf. That is the same privacy budget the queries are
        bounded by, showing up as an error bar instead of a leak.
        """
        preds = self._preds(q)
        ts = next(p for p in preds if p["field"] == "ts")
        if len(preds) == 1:
            return self.owner.count("ts", ts["lo"], ts["hi"]), "exact-to-leaf"
        return len(self.owner.query_multi(preds)), "filtered"


PAGE = """<!doctype html><meta charset=utf-8>
<title>blindrange-audit</title>
<style>
 :root{--bg:#0f1115;--panel:#171a21;--line:#262b36;--txt:#d7dce4;--dim:#8b93a1;
       --acc:#5cc8ff;--ok:#7fd18c;--warn:#e0b060}
 *{box-sizing:border-box;margin:0}
 body{background:var(--bg);color:var(--txt);font:14px/1.6 ui-monospace,Menlo,monospace;padding:28px}
 .wrap{max-width:1080px;margin:0 auto}
 h1{font-size:24px;margin-bottom:4px}h1 span{color:var(--acc)}
 .sub{color:var(--dim);margin-bottom:20px}
 .bar{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:16px}
 input,button{background:#10131a;color:var(--txt);border:1px solid var(--line);
   border-radius:7px;padding:7px 10px;font:13px ui-monospace,Menlo,monospace}
 button{cursor:pointer;border-color:var(--acc);color:var(--acc)}
 .stat{color:var(--dim);margin-bottom:12px}.stat b{color:var(--ok)}
 table{width:100%;border-collapse:collapse;font-size:13px}
 th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:top}
 th{color:var(--dim);text-transform:uppercase;font-size:11px;letter-spacing:.08em}
 td.t{color:var(--warn);white-space:nowrap}td.a{color:var(--acc)}
 pre{background:var(--panel);border:1px solid var(--line);border-radius:8px;
   padding:12px;overflow-x:auto;font-size:12px;color:var(--dim);margin-top:18px}
 .two{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:22px}
 .card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
 .card h3{font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:var(--dim);margin-bottom:8px}
</style>
<div class=wrap>
<h1>blindrange<span>-audit</span></h1>
<div class=sub>An append-only audit trail. The machines storing it hold
pseudorandom keys and AEAD blobs, and cannot read or alter a single field.</div>
<div class=bar>
  <input id=actor placeholder="actor prefix">
  <input id=action placeholder="action prefix">
  <input id=from placeholder="from (ISO or epoch)">
  <input id=to placeholder="to">
  <button onclick=load()>search</button>
  <button onclick="document.querySelectorAll('input').forEach(i=>i.value='');load()">clear</button>
</div>
<div class=stat id=stat>&nbsp;</div>
<table><thead><tr><th>when</th><th>actor</th><th>action</th><th>payload</th></tr></thead>
<tbody id=rows></tbody></table>
<div class=two>
 <div class=card><h3>What you see</h3><pre id=mine>—</pre></div>
 <div class=card><h3>What a node operator sees</h3><pre id=theirs>—</pre></div>
</div>
</div>
<script>
const q=()=>new URLSearchParams(Object.fromEntries(
  ['actor','action','from','to'].map(k=>[k,document.getElementById(k).value]).filter(([,v])=>v)));
async function load(){
  const p=q();
  const [ev,ct]=await Promise.all([
    fetch('/events?'+p).then(r=>r.json()), fetch('/count?'+p).then(r=>r.json())]);
  document.getElementById('stat').innerHTML=
    `<b>${ct.count.toLocaleString()}</b> events match · counted from index metadata `+
    `with <b>zero</b> records fetched · showing ${ev.events.length}`;
  document.getElementById('rows').innerHTML=ev.events.map(e=>{
    const d=new Date(e.ts*1000).toISOString().replace('T',' ').slice(0,19);
    const rest=Object.fromEntries(Object.entries(e.payload||{})
      .filter(([k])=>!['ts','timestamp','time','actor','action'].includes(k)));
    return `<tr><td class=t>${d}</td><td class=a>${e.actor}</td><td>${e.action}</td>`+
           `<td>${Object.keys(rest).length?JSON.stringify(rest):'<span style=color:#8b93a1>—</span>'}</td></tr>`;
  }).join('')||'<tr><td colspan=4 style=color:#8b93a1>no events</td></tr>';
  const v=await fetch('/contrast').then(r=>r.json());
  document.getElementById('mine').textContent=v.mine.join('\\n')||'—';
  document.getElementById('theirs').textContent=v.theirs.join('\\n')||'—';
}
load();
</script>"""


def make_handler(trail):
    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def _send(self, code, obj, ctype="application/json"):
            body = obj if isinstance(obj, bytes) else json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            u = urlparse(self.path)
            q = parse_qs(u.query)
            if u.path == "/":
                return self._send(200, PAGE.encode(), "text/html; charset=utf-8")
            if u.path == "/events":
                limit = min(int((q.get("limit", ["200"])[0]) or 200), 2000)
                # Newest first by default. With a limit, ascending answers a
                # question nobody asked — "the OLDEST five events in the last
                # 25 days" — and pays for a batch of leaves per round trip
                # walking away from the end the caller cares about. `?order=asc`
                # is there for exporting a trail in reading order.
                asc = (q.get("order", ["desc"])[0] or "desc").lower() == "asc"
                return self._send(200, {
                    "events": trail.events(q, limit, newest_first=not asc),
                    "window": trail.window(q)})
            if u.path == "/count":
                n, kind = trail.count(q)
                return self._send(200, {"count": n, "basis": kind,
                                        "window": trail.window(q)})
            if u.path == "/contrast":
                return self._send(200, contrast(trail))
            if u.path == "/healthz":
                return self._send(200, {"ok": True, "written": trail.written})
            self._send(404, {"error": "not found"})

        def do_POST(self):
            if urlparse(self.path).path != "/ingest":
                return self._send(404, {"error": "not found"})
            n = int(self.headers.get("Content-Length", 0))
            if n > 32_000_000:
                return self._send(413, {"error": "batch too large"})
            raw = self.rfile.read(n)
            try:
                events = parse_batch(raw)
            except ValueError as e:
                return self._send(400, {"error": str(e)})
            try:
                stored = trail.append(events)
            except Exception as e:                  # never lose the reason
                return self._send(503, {"error": f"{type(e).__name__}: {e}"})
            self._send(200, {"stored": stored})
    return H


def _otlp_value(v):
    """OTLP wraps every scalar in a typed box; unwrap to the plain value."""
    if not isinstance(v, dict):
        return v
    for k in ("stringValue", "boolValue", "doubleValue"):
        if k in v:
            return v[k]
    if "intValue" in v:
        try:
            return int(v["intValue"])
        except (TypeError, ValueError):
            return v["intValue"]
    return v


def unwrap_otlp(doc):
    """Flatten an OTLP/JSON logs envelope into plain events.

    Without this, the OpenTelemetry Collector's otlphttp exporter delivers
    one deeply nested object per batch and the whole batch would be stored
    as a single unqueryable event — the pipeline would look like it worked
    while quietly destroying the trail. Resource attributes are merged in
    first so service.name and friends survive, then record attributes win.
    """
    out = []
    for rl in doc.get("resourceLogs") or []:
        base = {}
        for a in (rl.get("resource") or {}).get("attributes") or []:
            base[a.get("key")] = _otlp_value(a.get("value"))
        for sl in rl.get("scopeLogs") or []:
            for rec in sl.get("logRecords") or []:
                ev = dict(base)
                for a in rec.get("attributes") or []:
                    ev[a.get("key")] = _otlp_value(a.get("value"))
                body = _otlp_value(rec.get("body"))
                if body is not None and "action" not in ev:
                    ev["message"] = body
                ts = rec.get("timeUnixNano") or rec.get("observedTimeUnixNano")
                if ts:
                    ev["ts"] = int(ts) / 1e9
                if rec.get("severityText"):
                    ev.setdefault("severity", rec["severityText"])
                out.append(ev)
    return out


def parse_batch(raw):
    """Accept the three shapes real shippers send.

    Vector's http sink posts a JSON array, Fluent Bit's http output posts an
    array or NDJSON depending on format, and hand-rolled callers post one
    object. Guessing wrong here means silently dropping an audit trail, so
    all three are handled explicitly rather than assumed.
    """
    text = raw.decode("utf-8", "replace").strip()
    if not text:
        return []
    if text[0] == "[":
        return json.loads(text)
    if text[0] == "{":
        try:
            doc = json.loads(text)
        except ValueError:
            doc = None
        if isinstance(doc, dict):
            if "resourceLogs" in doc:            # OpenTelemetry otlphttp
                return unwrap_otlp(doc)
            # A wrapper around a list is the other obvious thing to
            # post, and it used to fall through to "this whole object is
            # one event": a batch of 250 records became one row of
            # nonsense, answered with {"stored": 1}. For an audit trail
            # that is the worst failure available.
            #
            # The tell is a list of objects under some key, with nothing
            # event-shaped at the top level. Keyed on shape rather than on
            # a list of blessed names, so an unusual wrapper is handled
            # too — and guarded by the event-field check, so a real event
            # that happens to carry a list of objects (tags, attributes)
            # is still one event.
            if not (set(doc) & EVENT_FIELDS):
                nested = [v for v in doc.values()
                          if isinstance(v, list) and v
                          and all(isinstance(x, dict) for x in v)]
                if nested:
                    return max(nested, key=len)
            return [doc]
    out = []
    for line in text.splitlines():                  # NDJSON
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except ValueError:
                out.append({"message": line})
    return out


def contrast(trail):
    """Two windows on the same rows: the point of the whole system, shown
    rather than claimed."""
    mine, theirs = [], []
    try:
        now = int(time.time())
        rows = trail.owner.query_stream(
            [{"field": "ts", "lo": now - DEFAULT_WINDOW_S, "hi": now}],
            limit=3, order="-ts")
        for r in rows:
            when = datetime.fromtimestamp(r["ts"], timezone.utc).strftime("%H:%M:%S")
            mine.append(f"{when}  {r['actor']:<14} {r['action']}")
    except Exception:
        pass
    for n in trail.owner.network():
        addr = n.get("addr")
        if not addr or n.get("down"):
            continue
        try:
            # /intel takes `limit`, and returns sample as a LIST of [k, v]
            # pairs rather than an object — this panel is the whole demo, so
            # it fails loudly in the response instead of quietly rendering
            # an em dash that looks like "nothing to see".
            intel = trail.owner._get(addr, "/intel?limit=3")
        except Exception as e:
            theirs.append(f"({addr}: {type(e).__name__})")
            continue
        for pair in (intel.get("sample") or [])[:3]:
            try:
                k, v = pair
            except (TypeError, ValueError):
                continue
            theirs.append(f"{str(k)[:36]}  ->  {str(v)[:20]}")
        if theirs:
            theirs.append(f"({intel.get('count', 0):,} keys on this node, "
                          f"none of them readable)")
            break
    if not theirs:
        theirs = ["(no node reachable for an intel sample)"]
    # Say WHICH window was empty. "(no events yet)" on a trail full of
    # older events is a lie the panel tells confidently.
    empty = f"(no events in the last {human(DEFAULT_WINDOW_S)})"
    return {"mine": mine or [empty], "theirs": theirs}


def main():
    ap = argparse.ArgumentParser(description="blindrange audit trail")
    ap.add_argument("--state", default=os.path.expanduser("~/.blindrange/audit.brdb"))
    ap.add_argument("--passphrase", default=os.environ.get("BR_AUDIT_PASS", "audit"))
    ap.add_argument("--bootstrap", default="seed.blindrange.dev:7501")
    ap.add_argument("--secret", default="blindrange-public")
    ap.add_argument("--issuer", default="https://tokens.blindrange.dev")
    ap.add_argument("--account", default=os.environ.get("BR_ACCOUNT", ""))
    ap.add_argument("--leaf", type=int, default=DEFAULT_LEAF,
                    help="time resolution nobody can ever exceed, in seconds")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8710)
    ap.add_argument("--shards", type=int, default=1,
                    help="split the trail across N independent databases. "
                         "An audit trail only ever appends, so the client "
                         "ceiling — compaction rewriting an epoch in memory "
                         "— is the one it hits first. With >1 the --state "
                         "path is a DIRECTORY.")
    a = ap.parse_args()

    leaf = snap_leaf(a.leaf)
    if leaf != a.leaf:
        print(f"note: leaf_width must be a power of two; {a.leaf}s snapped to "
              f"{leaf}s ({human(leaf)}) — that is the real bound, not {a.leaf}s.",
              file=sys.stderr, flush=True)
    if a.shards > 1:
        from blindrange.sharded import ShardedOwner
        if os.path.exists(os.path.join(a.state, "shards.json")):
            owner = ShardedOwner.open(a.state, a.passphrase,
                                      bootstrap=[a.bootstrap])
        else:
            owner = ShardedOwner.create(a.state, a.passphrase, schema(leaf),
                                        bootstrap=[a.bootstrap],
                                        shards=a.shards,
                                        network_secret=a.secret)
    elif os.path.exists(a.state):
        owner = Owner.open(a.state, a.passphrase, bootstrap=[a.bootstrap])
    else:
        owner = Owner.create(a.state, a.passphrase, schema(leaf),
                             bootstrap=[a.bootstrap], network_secret=a.secret)
    if a.account:
        owner.configure_tokens(a.issuer, a.account)
    trail = Trail(owner)
    shard_note = (f"  ·  {a.shards} shards" if a.shards > 1 else "")
    print(f"blindrange-audit on http://{a.host}:{a.port}  ·  state {a.state}"
          f"{shard_note}\n"
          f"  time resolution nobody can exceed: {human(leaf)} "
          f"(leaf_width {leaf})\n"
          f"  POST /ingest  ·  GET /events /count /  ·  append-only, no delete",
          flush=True)
    ThreadingHTTPServer((a.host, a.port), make_handler(trail)).serve_forever()


if __name__ == "__main__":
    main()
