"""Serve a node's public status page on a CDN-proxyable port.

Modern browsers auto-upgrade http:// to https://, so a node's own status
page (plain HTTP on its protocol port) is effectively unreachable from a
browser. This tiny server re-serves it on a port a CDN can proxy — put
Cloudflare (or any TLS terminator) in front and the page gets HTTPS without
the node ever holding a certificate.

It reads only the node's unauthenticated /status.json; it holds no keys and
no network secret.

  python3 examples/status_server.py --node 127.0.0.1:7501 --port 8080
"""
import argparse
import collections
import json
import os
import threading
import time
import sys
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from blindrange.node import status_fragment, status_html  # noqa: E402
from blindrange import merkle, receipt  # noqa: E402

# Anonymous audit reports. Held in memory and, if BR_REPORT_STATE is set,
# checkpointed to disk so a deploy does not erase them (see _save/_load).
#
# What we deliberately do NOT keep: who sent a report, when beyond a coarse
# bucket, or anything joinable across submissions. Reports carry no owner or
# database identifier and no counts that could encode a reporter's size, so
# there is nothing here to link one submission to another or to a person.
# Aggregation is deliberately PESSIMISTIC. Reports are unauthenticated by
# design — demanding identity to submit would recreate exactly the linkage
# the report format avoids — so anyone can fabricate them. We therefore take
# a low quantile rather than a median: to make a failing node look good an
# attacker must supply most of its reports, while a handful of honest
# reports are enough to expose a problem. The asymmetry is the point, since
# the cost of over-paying a cheat exceeds the cost of under-paying briefly.
#
# Reports also expire: without that, a node's healthy history dilutes
# evidence of present failure, which is how a small flood first flipped a
# median here from 0.43 to 1.00.
#
# The quantile alone was mitigation, not a defence — enough fabricated
# reports still won. Three things now make one cost something, none of them
# asking who is submitting:
#
#   1. RECEIPTS. Every figure comes from a group of node signatures, and a
#      node id is a hash of its own public key, so each verifies here with
#      no roster to maintain and nobody to trust for it. Inventing a report
#      about a node now needs that node's private key.
#   2. CORROBORATION. A signature by itself proves only that some exchange
#      happened, and asking a node for keys that never existed gets an
#      honestly signed miss — perfect slander, free. So a group is scored
#      only against its own members, who were asked the identical batch
#      under one nonce (they committed to the same kdigest). Since the ring
#      picks a key's replicas, a fabricated key cannot be aimed at one node
#      while sparing the others, and a group where nobody held anything is
#      discarded rather than counted against everyone in it.
#   3. PROOF OF WORK, bound to the exact body, plus single-use signatures
#      inside a freshness window. Replay is out, and volume now has a price.
#
# What is still open, stated plainly: someone running real nodes with real
# data can still submit honest-looking reports about themselves. That buys
# little, because scoring is relative and honest nodes already score 1.0 —
# to gain, a cheat must push others down, which needs their signatures.
# Cheap identities are the other open one, but NOT in the way this comment
# first claimed. Share is structural x PROVED possession, and a minted
# identity can only realise its ring share by actually holding the data
# routed to it and passing audits on it. An attacker with a hundred
# identities earns a hundred times as much and stores a hundred times as
# much, which is not an attack — it is a large operator, and paying for
# stored data is the entire point.
#
# The real exposure is REPLICA CAPTURE, and it is about durability rather
# than money: at RF3, a party holding fraction k of the ring holds all
# three replicas of roughly k^3 of the keys, so half the ring means ~12% of
# data with no independent copy left to delete or ransom. Stake would make
# identities expensive without changing that arithmetic. Diversity-aware
# placement — refusing to route a key's replicas to nodes sharing a subnet,
# an ASN or a first-seen fingerprint — attacks the mechanism instead of the
# motive, and costs nothing.
REPORTS = collections.defaultdict(collections.deque)   # node_id -> (ts, rate)
REPORT_WINDOW = 500
REPORT_MAX_AGE = float(os.environ.get("BR_REPORT_MAX_AGE", "21600"))  # 6h
REPORT_QUANTILE = 0.25
# Possession is a claim about NOW. Reports already expire for that reason;
# this applies the same principle continuously instead of as a cliff, so a
# proof from four hours ago stops counting as much as one from twenty
# minutes ago. Without it the estimator was slow in BOTH directions: a node
# that finished catching up stayed pinned at 0% by its own honest early
# failures, and — the expensive direction — a node whose disk had just died
# kept a full share through its next audit, because the low quantile over
# [0,1,1,1] is still 1. One hour, against audits roughly two hours apart,
# makes the newest report dominate while older ones remain a real tail.
REPORT_HALFLIFE = float(os.environ.get("BR_REPORT_HALFLIFE", "3600"))
REPORT_MIN_GROUP = 2       # a receipt nobody corroborates proves nothing
POW_BITS = int(os.environ.get("BR_REPORT_POW_BITS", str(receipt.POW_BITS)))
SEEN_SIGS = collections.deque()        # (ts, sig-prefix) — anti-replay only
SEEN_SET = set()
REPORT_LOCK = threading.Lock()


def _fresh_sig(sig, now):
    """Single-use signatures, kept only as long as a receipt stays fresh.

    Deliberately not a log: a signature prefix is dropped the moment the
    beacon it was signed under stops being accepted, so this can never grow
    into a record of who submitted what.
    """
    horizon = now - receipt.BEACON_PERIOD * (receipt.BEACON_SLACK + 2)
    while SEEN_SIGS and SEEN_SIGS[0][0] < horizon:
        SEEN_SET.discard(SEEN_SIGS.popleft()[1])
    if sig in SEEN_SET:
        return False
    SEEN_SET.add(sig)
    SEEN_SIGS.append((now, sig))
    return True


# Reports have to outlive a restart. They are evidence a node earned its
# share, and this process restarts on every deploy — which silently reset
# every node to "unproved, 0 per-mille" and made a routine deploy erase the
# basis for paying people. Persisted state changes nothing about what is
# kept: still no owner, no database, no submitter, just (timestamp, rate)
# per node inside the same 6h expiry window, plus the spent signatures so
# a restart cannot reopen a replay window.
STATE_PATH = os.environ.get("BR_REPORT_STATE", "")     # empty = memory only


_SAVE_BROKEN = [False]


def _save():
    if not STATE_PATH:
        return
    try:
        tmp = STATE_PATH + ".tmp"
        with open(tmp, "w") as f:
            json.dump({"reports": {n: list(dq) for n, dq in REPORTS.items()},
                       "sigs": list(SEEN_SIGS)}, f)
        os.replace(tmp, STATE_PATH)
        _SAVE_BROKEN[0] = False
    except OSError as e:
        # Never fatal — the page must keep serving — but never silent
        # either. Swallowing this hid a systemd ProtectSystem=strict mount
        # that made every write fail while the page went on presenting
        # shares as durable evidence. Storage that quietly does nothing is
        # worse than none, so say so once, loudly, and again if it recovers
        # and breaks anew.
        if not _SAVE_BROKEN[0]:
            _SAVE_BROKEN[0] = True
            print(f"WARNING: cannot persist audit reports to {STATE_PATH}: "
                  f"{e}. Shares will reset on restart.",
                  file=sys.stderr, flush=True)


def _load():
    if not STATE_PATH:
        return
    try:
        with open(STATE_PATH) as f:
            saved = json.load(f)
    except (OSError, ValueError):
        return
    cutoff = time.time() - REPORT_MAX_AGE
    with REPORT_LOCK:
        for nid, rows in (saved.get("reports") or {}).items():
            dq = REPORTS[nid]
            for ts, rate in rows:
                if ts >= cutoff:       # expiry still applies across restarts
                    dq.append((ts, rate))
            while len(dq) > REPORT_WINDOW:
                dq.popleft()
        for ts, sig in (saved.get("sigs") or []):
            SEEN_SIGS.append((ts, sig))
            SEEN_SET.add(sig)


# ---------------------------------------------------------------- the log
# Everything else here removes a party you would have to trust. This part
# does not: we score the audits and compute the shares, and an operator has
# no way to check that a number was not revised afterwards. That is the one
# place we ARE the trusted party, and it sits badly next to the rest.
#
# So every accepted report and every share calculation goes into an
# append-only Merkle log. Reports are logged IN FULL — they were designed to
# be publishable, carrying no owner or database identifier — which buys more
# than tamper-evidence: anyone can re-run score_groups() over the logged
# inputs and check our arithmetic, not merely that we did not change our
# answer later.
#
# What it does not do is stated in blindrange/merkle.py, and matters: it
# cannot stop us declining to log something in the first place, and it
# cannot alone stop a split view. Detecting that needs operators to compare
# heads, which is a GET.
LOG_PATH = os.environ.get("BR_LOG_PATH", "")
LOG_KEY_PATH = os.environ.get("BR_LOG_KEY", "")
LOG = merkle.Log()
LOG_LOCK = threading.Lock()
LOG_SIGNER = [None]


def _log_key():
    if LOG_SIGNER[0] is not None:
        return LOG_SIGNER[0]
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    priv = None
    if LOG_KEY_PATH and os.path.exists(LOG_KEY_PATH):
        with open(LOG_KEY_PATH, "rb") as f:
            priv = Ed25519PrivateKey.from_private_bytes(f.read())
    elif LOG_KEY_PATH:
        priv = Ed25519PrivateKey.generate()
        with open(LOG_KEY_PATH, "wb") as f:
            os.fchmod(f.fileno(), 0o600)
            f.write(priv.private_bytes(serialization.Encoding.Raw,
                                       serialization.PrivateFormat.Raw,
                                       serialization.NoEncryption()))
    LOG_SIGNER[0] = priv
    return priv


def log_append(kind, payload):
    """Append one entry and persist it. Never rewrites: the file is opened
    for append and the in-memory tree only ever grows."""
    entry = json.dumps({"kind": kind, "at": int(time.time()), "body": payload},
                       sort_keys=True, separators=(",", ":")).encode()
    with LOG_LOCK:
        idx = LOG.append(entry)
        if LOG_PATH:
            try:
                with open(LOG_PATH, "ab") as f:
                    f.write(entry + b"\n")
            except OSError as e:
                print(f"WARNING: cannot persist transparency log to "
                      f"{LOG_PATH}: {e}. History will not survive restart.",
                      file=sys.stderr, flush=True)
    return idx


def log_load():
    if not LOG_PATH or not os.path.exists(LOG_PATH):
        return
    try:
        with open(LOG_PATH, "rb") as f:
            for line in f:
                line = line.rstrip(b"\n")
                if line:
                    LOG.append(line)
    except OSError:
        pass


def signed_head():
    """A head an operator can keep and come back with tomorrow."""
    with LOG_LOCK:
        size, rt = len(LOG), LOG.root()
    head = {"size": size, "root": rt.hex(), "at": int(time.time())}
    priv = _log_key()
    if priv is not None:
        from cryptography.hazmat.primitives import serialization
        msg = f"brlog|{head['size']}|{head['root']}|{head['at']}".encode()
        head["sig"] = priv.sign(msg).hex()
        head["pub"] = priv.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw).hex()
    return head


# ---------------------------------------------------------------- activity
# Rates for the public page, derived from two samples of the nodes' own
# cumulative counters rather than from anything a node reports about its
# own throughput. A counter that only goes up cannot flatter itself: if a
# node restarts the counter drops, and rather than render that as a huge
# negative rate we treat it as a gap and skip the interval.
#
# What this exposes is aggregate and nothing more — network-wide writes,
# deletes and reads per second. Per-database activity is not derivable from
# it, and could not be even if we wanted: nodes cannot tell whose keys are
# whose, which is the property the whole system is built on.
ACTIVITY = collections.deque(maxlen=240)      # (ts, writes, deletes, reads)
ACTIVITY_LOCK = threading.Lock()


def record_activity(nodes):
    tot_w = sum(int(n.get("writes") or 0) for n in nodes)
    tot_d = sum(int(n.get("deletes") or 0) for n in nodes)
    tot_r = sum(int(n.get("read_batches") or 0) for n in nodes)
    with ACTIVITY_LOCK:
        ACTIVITY.append((time.time(), tot_w, tot_d, tot_r))


def activity(window=120):
    """Per-second rates over the last `window` seconds, plus a short series
    for a sparkline."""
    with ACTIVITY_LOCK:
        pts = list(ACTIVITY)
    if len(pts) < 2:
        return {"writes_per_s": 0, "deletes_per_s": 0, "reads_per_s": 0,
                "samples": 0, "series": []}
    now = pts[-1][0]
    span = [p for p in pts if now - p[0] <= window] or pts[-2:]
    if len(span) < 2:
        span = pts[-2:]
    dt = span[-1][0] - span[0][0]
    if dt <= 0:
        return {"writes_per_s": 0, "deletes_per_s": 0, "reads_per_s": 0,
                "samples": len(span), "series": []}

    def rate(i):
        d = span[-1][i] - span[0][i]
        return round(max(d, 0) / dt, 1)       # counter reset -> 0, never negative

    series = []
    for a, b in zip(pts, pts[1:]):
        gap = b[0] - a[0]
        if gap <= 0:
            continue
        w = (b[1] - a[1]) / gap
        series.append(round(max(w, 0), 1))
    return {"writes_per_s": rate(1), "deletes_per_s": rate(2),
            "reads_per_s": rate(3), "samples": len(span),
            "window_s": round(dt), "series": series[-60:]}


def score_groups(payload, now):
    """Turn a report into per-node rates, trusting only what nodes signed.

    Everything the sender claims is treated as a hint and re-derived from
    the receipts: how many keys a node was asked for and how many it served
    are its own signed statements, and `verified` is only ever believed down
    to that ceiling. A group is scored relative to its best member, so the
    output says "this node held less than its replicas did", which is the
    only comparison a group can honestly support.
    """
    out = collections.defaultdict(list)
    for group in payload.get("proofs") or []:
        if not isinstance(group, dict) or len(group) < REPORT_MIN_GROUP:
            continue
        rows, sigs, kdigest, asked, ok = {}, [], None, None, True
        for nid, v in group.items():
            r = (v or {}).get("receipt") or {}
            if r.get("node_id") != nid or not receipt.verify(r, now):
                ok = False
                break
            # Same batch, same nonce, or these nodes are not comparable and
            # the group is exactly the slander vector we are closing.
            if kdigest is None:
                kdigest, asked = r["kdigest"], int(r["asked"])
            elif r["kdigest"] != kdigest or int(r["asked"]) != asked:
                ok = False
                break
            sigs.append(r["sig"][:32])
            rows[nid] = min(int((v or {}).get("verified", 0)),
                            int(r["served"]))
        if not ok or not asked or len(rows) < REPORT_MIN_GROUP:
            continue
        # Spend the signatures only once the group is known good, or a
        # rejected group would burn them and make an honest resubmission of
        # the same audit fail as a replay.
        if len(set(sigs)) != len(sigs) or not all(_fresh_sig(s, now)
                                                  for s in sigs):
            continue
        best = max(rows.values())
        if best <= 0:
            continue          # nobody held it: a bad batch, not a bad node
        for nid, held in rows.items():
            out[nid].append(held / best)
    return out


def record_report(payload):
    if payload.get("kind") != "blindrange-audit":
        raise ValueError("not an audit report")
    if not receipt.check(payload, POW_BITS):
        raise ValueError("insufficient proof of work")
    if len(payload.get("proofs") or []) > 256:
        raise ValueError("implausible report")
    now = time.time()
    accepted = 0
    with REPORT_LOCK:
        for nid, rates in score_groups(payload, now).items():
            dq = REPORTS[nid]
            dq.append((now, sum(rates) / len(rates)))
            while len(dq) > REPORT_WINDOW:
                dq.popleft()
            accepted += 1
    if not accepted:
        raise ValueError("no corroborated node receipts in report")
    _save()
    # Log the inputs, not a summary: the point is that our scoring can be
    # recomputed, not merely that it was not edited.
    idx = log_append("report", payload)
    return {"accepted": accepted, "log_index": idx,
            "log_size": len(LOG)}


def weighted_quantile(pairs, q):
    """The q-quantile of (value, weight) pairs, lowest value first.

    Returns the first value at which the running weight reaches q of the
    total — the inverse CDF. This is NOT what the previous code computed:
    `sorted(vals)[int(len(vals) * 0.25)]` floors the index, which skips the
    failing report when exactly one in four has failed, so p25 of [0,1,1,1]
    came out as 1.0. That off-by-one is the reason a node whose disk had
    just died kept a full share until a second audit failed. The property
    that chose a LOW quantile survives the change: the score falls to zero
    as soon as a quarter of the weight is failing, so a failure cannot be
    buried under a couple of passes — though enough same-age passes still
    outvote it, which is why fabrication is fenced off by node-signed
    receipts and proof-of-work rather than by this statistic.
    """
    if not pairs:
        return None
    ordered = sorted(pairs)
    total = sum(w for _, w in ordered)
    if total <= 0:                       # everything decayed to nothing
        return ordered[-1][0]
    target, run = q * total, 0.0
    for val, w in ordered:
        run += w
        if run >= target:
            return val
    return ordered[-1][0]


def possession():
    now = time.time()
    cutoff = now - REPORT_MAX_AGE
    with REPORT_LOCK:
        out = {}
        for nid, dq in REPORTS.items():
            fresh = [(ts, rate) for ts, rate in dq if ts >= cutoff]
            if not fresh:
                continue
            pairs = [(rate, 0.5 ** ((now - ts) / REPORT_HALFLIFE))
                     for ts, rate in fresh]
            rate = weighted_quantile(pairs, REPORT_QUANTILE)
            ts_last, rate_last = max(fresh)
            out[nid] = {"rate": round(rate, 3),
                        "reports": len(fresh),
                        # The aggregate deliberately lags a single report, so
                        # publish the newest one beside it. "0% · 2 audits"
                        # hid that the most recent audit had passed, which
                        # reads as a failing node rather than a recovering
                        # one.
                        "latest": round(rate_last, 3),
                        "latest_age_s": int(now - ts_last)}
        return out


# The page must never do network I/O while a browser waits. Fetching node
# stats can involve a relay round trip to a NAT'd tenant, so a request that
# rendered inline stalled for seconds and sometimes timed out. A background
# thread refreshes a snapshot; requests serve whatever is current, instantly.
SNAPSHOT = {"at": 0.0, "data": None, "error": None}


def refresh_loop(node_addr, every=15):
    while True:
        try:
            with urllib.request.urlopen(
                    f"http://{node_addr}/status.json", timeout=20) as r:
                SNAPSHOT["data"] = json.loads(r.read())
                SNAPSHOT["error"] = None
                record_activity(SNAPSHOT["data"].get("nodes") or [])
        except Exception as e:                       # keep the last good one
            SNAPSHOT["error"] = f"{type(e).__name__}: {e}"
        SNAPSHOT["at"] = time.time()
        time.sleep(every)


_LAST_SHARE_LOG = [0.0]


def log_shares(shares):
    """Record what each node was actually credited with.

    Reports are the inputs; this is the output, and an operator cares about
    the output. Rate-limited because the page recomputes on every refresh
    and a log that grows with page views is a log nobody will read.
    """
    if time.time() - _LAST_SHARE_LOG[0] < 900:
        return
    _LAST_SHARE_LOG[0] = time.time()
    log_append("shares", shares)


def with_shares(data):
    """Attach each node's share of a distribution pool, in per-mille.

    Share = structural x quality. Structural is a node's position on the
    ring, which is uniform today, so it need not be claimed by anyone.
    Quality is proved possession from anonymous audits — a node with no
    audits yet is marked unverified and earns nothing, since paying for
    unproved storage is exactly what the audits exist to prevent.

    Illustrative only: a share of a pool, not an entitlement, and not money.
    """
    seen = possession()
    rows = data.get("nodes", [])
    live = [r for r in rows if r.get("mode") != "down"]
    weights = {}
    for r in rows:
        m = seen.get(r["id"])
        r["measured"] = m
        structural = 1.0 / max(1, len(live)) if r in live else 0.0
        quality = m["rate"] if m else 0.0
        weights[r["id"]] = structural * quality
    total = sum(weights.values())
    for r in rows:
        r["share"] = (round(1000 * weights[r["id"]] / total)
                      if total > 0 else None)
    data["pool_covered"] = round(
        100 * sum(1 for r in rows if r.get("measured")) / max(1, len(rows)))
    if total > 0:
        log_shares({r["id"]: r["share"] for r in rows
                    if r.get("share") is not None})
    return data


def make_handler(node_addr):
    class Handler(BaseHTTPRequestHandler):
        def _json(self, obj, code=200):
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            u = urlparse(self.path)
            path, q = u.path, parse_qs(u.query)
            if path.startswith("/log"):
                return self._log_route(path, q)
            if path not in ("/", "/status.json", "/health",
                            "/possession.json", "/activity.json",
                            "/fragment"):
                self.send_error(404)
                return
            data = SNAPSHOT["data"]
            if data is None:
                self.send_error(503, SNAPSHOT["error"] or "warming up")
                return
            data = with_shares(json.loads(json.dumps(data)))
            if path == "/fragment":
                # Just the part that changes, rendered by the same code as
                # the page itself.
                data = with_shares(json.loads(json.dumps(SNAPSHOT["data"] or {})))
                body = status_fragment(data.get("nodes") or [],
                                       data.get("keys") or 0).encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if path == "/activity.json":
                data = with_shares(json.loads(json.dumps(SNAPSHOT["data"] or {})))
                nodes = data.get("nodes") or []
                body = json.dumps({
                    **activity(),
                    "nodes": len(nodes),
                    "keys": data.get("keys"),
                    "synthetic": True,
                }).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if path == "/possession.json":
                body = json.dumps(possession()).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if path == "/health":
                body, ctype = b'{"ok":true}', "application/json"
            elif path == "/status.json":
                body = json.dumps(data).encode()
                ctype = "application/json"
            else:
                body = status_html(data["nodes"], data["keys"],
                                   node_addr, signed_head()).encode()
                ctype = "text/html; charset=utf-8"
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "public, max-age=15")
            self.end_headers()
            self.wfile.write(body)

        def _log_route(self, path, q):
            """Endpoints an operator needs to check us, and nothing more.

            Deliberately unauthenticated and CORS-open: a transparency log
            that is awkward to read is not one, and everything in it was
            built to be published.
            """
            self.send_header  # (kept for clarity; headers set in _json)
            if path == "/log/sth":
                return self._json(signed_head())
            if path == "/log/entries":
                start = max(0, int((q.get("start", ["0"])[0]) or 0))
                end = min(len(LOG), start + min(
                    int((q.get("count", ["64"])[0]) or 64), 256))
                with LOG_LOCK:
                    rows = [LOG.entries[i].decode("utf-8", "replace")
                            for i in range(start, end)]
                return self._json({"start": start, "entries": rows,
                                   "size": len(LOG)})
            if path == "/log/proof":
                try:
                    m = int(q.get("leaf", [""])[0])
                    with LOG_LOCK:
                        proof = [h.hex() for h in LOG.inclusion(m)]
                        size, rt = len(LOG), LOG.root().hex()
                        leaf = LOG.entries[m].decode("utf-8", "replace")
                except (ValueError, IndexError):
                    return self._json({"error": "no such leaf"}, 404)
                return self._json({"leaf_index": m, "leaf": leaf,
                                   "tree_size": size, "root": rt,
                                   "proof": proof})
            if path == "/log/consistency":
                try:
                    m = int(q.get("first", [""])[0])
                    with LOG_LOCK:
                        proof = [h.hex() for h in LOG.consistency(m)]
                        size, rt = len(LOG), LOG.root().hex()
                except (ValueError, IndexError):
                    return self._json({"error": "bad first size"}, 400)
                return self._json({"first": m, "second": size, "root": rt,
                                   "proof": proof})
            return self._json({"error": "not found"}, 404)

        def do_POST(self):
            if urlparse(self.path).path != "/report":
                self.send_error(404)
                return
            n = int(self.headers.get("Content-Length", 0))
            if n > 64_000:
                self.send_error(413)
                return
            try:
                out = record_report(json.loads(self.rfile.read(n) or b"{}"))
            except (ValueError, TypeError) as e:
                self.send_error(400, str(e))
                return
            body = json.dumps(out).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    return Handler


def _restart_on_new_code():
    """Exit when the checkout moves, so the supervisor restarts us on the new
    renderer. Without this the status page keeps serving whatever it imported
    at boot, while the node it reports on self-updates underneath it."""
    import subprocess
    repo = str(Path(__file__).resolve().parents[1])

    def head():
        try:
            return subprocess.run(["git", "-C", repo, "rev-parse", "HEAD"],
                                  capture_output=True, text=True,
                                  timeout=15).stdout.strip()
        except Exception:
            return ""
    start = head()
    while True:
        time.sleep(60)
        now = head()
        if now and start and now != start:
            os._exit(0)


def main():
    ap = argparse.ArgumentParser(description="blindrange public status server")
    ap.add_argument("--node", default="127.0.0.1:7501",
                    help="node to read /status.json from")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8080)
    a = ap.parse_args()
    _load()                               # survive deploys
    log_load()
    threading.Thread(target=_restart_on_new_code, daemon=True).start()
    threading.Thread(target=refresh_loop, args=(a.node,), daemon=True).start()
    time.sleep(1.5)                       # let the first snapshot land
    ThreadingHTTPServer((a.host, a.port),
                        make_handler(a.node)).serve_forever()


if __name__ == "__main__":
    main()
