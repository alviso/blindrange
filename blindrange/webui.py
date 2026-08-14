"""Local web client for blindrange.

Runs on localhost and holds the keys in this process — never in the browser,
never on a server. Because the page is served over plain HTTP from
127.0.0.1, it can talk to plain-HTTP nodes without the mixed-content wall a
hosted HTTPS app would hit.

  blindrange ui [--file my.brdb] [--port 8700]
"""
import json
import os
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from . import schema as S
from .client import Owner

PUBLIC_SEED = "seed.blindrange.dev:7501"
PUBLIC_SECRET = "blindrange-public"

STATE = {"owner": None, "file": None, "lock": threading.Lock()}
UI_HTML = (Path(__file__).parent / "webui.html").read_text()

# Known databases: PATHS ONLY, never keys. The .brdb stays passphrase-
# encrypted because people back it up — to exactly the kind of provider this
# project exists not to trust. Optional convenience: the OS keychain can hold
# the passphrase if the user asks and `keyring` is installed.
RECENT = Path(os.environ.get("BR_RECENT",
                             Path.home() / ".blindrange" / "recent.json"))
KEYRING_SERVICE = "blindrange"

try:
    import keyring as _keyring
except Exception:
    _keyring = None


def recent_list():
    try:
        items = json.loads(RECENT.read_text())
    except (OSError, ValueError):
        return []
    out = []
    for it in items:
        exists = Path(it["file"]).expanduser().exists()
        out.append({**it, "exists": exists,
                    "remembered": bool(_keyring) and bool(
                        _keyring.get_password(KEYRING_SERVICE, it["file"]))})
    return [it for it in out if it["exists"]]


def remember_db(path, fields=None):
    RECENT.parent.mkdir(parents=True, exist_ok=True)
    try:
        items = json.loads(RECENT.read_text())
    except (OSError, ValueError):
        items = []
    items = [it for it in items if it["file"] != path]
    items.insert(0, {"file": path, "opened": int(time.time()),
                     "fields": fields or []})
    RECENT.write_text(json.dumps(items[:12], indent=1))


# ------------------------------------------------------------- helpers

def owner_or_none():
    return STATE["owner"]


def need_owner():
    o = STATE["owner"]
    if o is None:
        raise ValueError("no database is open")
    return o


def net_info(owner):
    try:
        owner.refresh_membership()          # pick up nodes that joined since
        nodes = owner.network()
    except Exception:
        nodes = []
    return [{"addr": n.get("addr", "?"), "keys": n.get("keys"),
             "mode": n.get("mode", "down" if n.get("down") else "?")}
            for n in nodes]


def state_payload():
    o = owner_or_none()
    if o is None:
        return {"open": False}
    return {"open": True, "file": STATE["file"],
            "schema": {n: {**sp, "describe": S.describe(n, sp)}
                       for n, sp in o.schema.items()},
            "writers": len(o._st.get("writers", [])),
            "nodes": net_info(o)}


def resolve_network(choice, secret):
    if choice in ("public", "", None):
        return [PUBLIC_SEED], PUBLIC_SECRET
    return [choice], (secret or "")


def rows_for_display(owner, records):
    schema = owner.schema
    out = []
    for rec in records:
        row = {"_rid": rec.get("_rid")}
        for k, v in rec.items():
            if k.startswith("_"):
                continue
            row[k] = (S.to_display(schema[k], v) if k in schema else v)
        out.append(row)
    return out


def record_from_raw(owner, raw):
    """UI/CSV values -> the record we store (indexed fields normalised)."""
    schema = owner.schema
    rec = {}
    for k, v in raw.items():
        if k in schema:
            rec[k] = S.to_stored(schema[k], v)
        elif not k.startswith("_"):
            rec[k] = v
    return rec


# -------------------------------------------------------------- actions

def api_open(body):
    path = body["file"]
    passphrase = body.get("passphrase") or ""
    if not passphrase and _keyring:                  # unlocked by the OS
        passphrase = _keyring.get_password(KEYRING_SERVICE, path) or ""
    if not passphrase:
        raise ValueError("passphrase required")
    owner = Owner.open(path, passphrase,
                       bootstrap=[PUBLIC_SEED] if body.get("public") else None)
    STATE["owner"], STATE["file"] = owner, path
    if body.get("remember") and _keyring:
        _keyring.set_password(KEYRING_SERVICE, path, passphrase)
    remember_db(path, list(owner.schema))
    return state_payload()


def api_create(body):
    bootstrap, secret = resolve_network(body.get("network"),
                                        body.get("secret"))
    schema = body["schema"]
    for spec in schema.values():             # UI sends numbers as strings
        spec["bits"] = int(spec["bits"])
        if "chars" in spec:
            spec["chars"] = int(spec["chars"])
        # any bucket the UI offers is snapped to a legal power of two
        spec["leaf_width"] = S.leaf_for(spec["bits"],
                                        int(spec.get("leaf_width", 1)))
    owner = Owner.create(body["file"], body["passphrase"], schema, bootstrap,
                         network_secret=secret)
    STATE["owner"], STATE["file"] = owner, body["file"]
    if body.get("remember") and _keyring:
        _keyring.set_password(KEYRING_SERVICE, body["file"],
                              body["passphrase"])
    remember_db(body["file"], list(owner.schema))
    return state_payload()


def api_infer(body):
    rows, cols = S.read_csv(body["csv"], limit=500)
    if not rows:
        raise ValueError("no rows found in that CSV")
    schema, skipped = S.infer(rows)
    return {"schema": {n: {**sp, "describe": S.describe(n, sp)}
                       for n, sp in schema.items()},
            "skipped": skipped, "columns": cols,
            "rows": rows[:6], "total": len(rows)}


def api_import(body):
    owner = need_owner()
    rows, _cols = S.read_csv(body["csv"])
    by_label = {sp.get("label") or n: n for n, sp in owner.schema.items()}
    prepared, bad = [], 0
    for raw in rows:
        mapped = {}
        for col, val in raw.items():
            key = by_label.get(col, col.strip().lower().replace(" ", "_"))
            mapped[key] = val
        try:
            prepared.append(record_from_raw(owner, mapped))
        except (ValueError, KeyError):
            bad += 1
    for i in range(0, len(prepared), 200):
        owner.insert_many(prepared[i:i + 200])
    return {"imported": len(prepared), "skipped": bad}


def api_insert(body):
    owner = need_owner()
    owner.insert(record_from_raw(owner, body["record"]))
    return {"inserted": 1}


def api_query(body):
    owner = need_owner()
    preds = []
    for p in body.get("predicates", []):
        field = p["field"]
        spec = owner.schema[field]
        if p.get("prefix") not in (None, ""):
            preds.append({"field": field, "prefix": p["prefix"]})
        else:
            preds.append({"field": field,
                          "lo": S.to_stored(spec, p["lo"]),
                          "hi": S.to_stored(spec, p["hi"])})
    if not preds:
        raise ValueError("add at least one condition")
    limit = max(1, min(int(body.get("limit", 200)), 2000))
    order = body.get("order") or None
    after = body.get("after") or None
    # streamed: memory stays O(page) however large the result is
    rows = list(owner.query_stream(preds, limit=limit + 1, order=order,
                                   after=after))
    more = len(rows) > limit
    rows = rows[:limit]
    cursor = rows[-1].get("_cursor") if rows else None
    return {"rows": rows_for_display(owner, rows), "count": len(rows),
            "more": more, "cursor": cursor, "stats": owner.last_stats}


def api_close(_body):
    """Close the open database. Keys are dropped from this process; nothing
    on disk or on the network changes."""
    STATE["owner"], STATE["file"] = None, None
    return {"open": False}


def api_forget(body):
    """Drop a database from the list, and any remembered passphrase. The
    file and the data are untouched."""
    path = body["file"]
    try:
        items = [it for it in json.loads(RECENT.read_text())
                 if it["file"] != path]
        RECENT.write_text(json.dumps(items, indent=1))
    except (OSError, ValueError):
        pass
    if _keyring:
        try:
            _keyring.delete_password(KEYRING_SERVICE, path)
        except Exception:
            pass
    return {"forgotten": path}


def api_browse(body):
    """Everything in the database — no query to compose.

    Walks whichever field can express "all values": a numeric or date field
    covers its whole domain, and a text field is matched with the empty
    prefix (an integer bound would be encoded as the literal string "0")."""
    owner = need_owner()
    schema = owner.schema
    field = body.get("field") or next(
        (n for n, sp in schema.items() if sp.get("kind") != "text"),
        next(iter(schema)))
    spec = schema[field]
    if spec.get("kind") == "text" or spec["type"] == "str":
        pred = {"field": field, "prefix": ""}
    else:
        pred = {"field": field, "lo": 0, "hi": (1 << spec["bits"]) - 1}
    limit = max(1, min(int(body.get("limit", 200)), 2000))
    rows = list(owner.query_stream([pred], limit=limit + 1,
                                   order=body.get("order") or None,
                                   after=body.get("after") or None))
    more = len(rows) > limit
    rows = rows[:limit]
    return {"rows": rows_for_display(owner, rows), "count": len(rows),
            "more": more, "cursor": rows[-1].get("_cursor") if rows else None,
            "stats": owner.last_stats, "field": field}


def api_aggregate(body):
    """Count and summarise a range without fetching or decrypting a row."""
    owner = need_owner()
    p = body["predicate"]
    field = p["field"]
    spec = owner.schema[field]
    lo, hi = S.to_stored(spec, p["lo"]), S.to_stored(spec, p["hi"])
    bars = owner.histogram(field, lo, hi, buckets=int(body.get("buckets", 20)))
    est, err, n = owner.approx_sum(field, lo, hi)
    scale = spec.get("scale", 1)
    return {"field": field, "kind": spec.get("kind", "number"), "count": n,
            "deleted_pending": owner.count_deleted(),
            "sum": est / scale, "sum_error": err / scale,
            "bars": [{"lo": S.to_display(spec, b["lo"]),
                      "hi": S.to_display(spec, b["hi"]),
                      "count": b["count"]} for b in bars]}


def api_delete(body):
    owner = need_owner()
    n = owner.delete_many(body["rids"])
    return {"deleted": n}


def api_invite(_body):
    return {"invite": need_owner().invite()}


def api_accept(body):
    owner = Owner.accept(body["file"], body["passphrase"], body["invite"])
    STATE["owner"], STATE["file"] = owner, body["file"]
    remember_db(body["file"], list(owner.schema))
    return state_payload()


def api_maintain(body):
    owner = need_owner()
    what = body.get("what")
    if what == "compact":
        return owner.compact()
    if what == "repair":
        return owner.repair()
    raise ValueError("unknown maintenance action")


ROUTES = {"/api/open": api_open, "/api/create": api_create,
          "/api/infer": api_infer, "/api/import": api_import,
          "/api/insert": api_insert, "/api/query": api_query,
          "/api/delete": api_delete, "/api/aggregate": api_aggregate, "/api/invite": api_invite,
          "/api/accept": api_accept, "/api/maintain": api_maintain,
          "/api/forget": api_forget, "/api/browse": api_browse,
          "/api/close": api_close}


# --------------------------------------------------------------- server

class Handler(BaseHTTPRequestHandler):
    def _send(self, obj, code=200, ctype="application/json"):
        body = obj if isinstance(obj, bytes) else json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/":
            self._send(UI_HTML.encode(), ctype="text/html; charset=utf-8")
        elif path == "/api/state":
            with STATE["lock"]:
                payload = state_payload()
                payload["recent"] = recent_list()
                payload["keyring"] = _keyring is not None
                self._send(payload)
        else:
            self._send({"error": "not found"}, 404)

    def do_POST(self):
        path = urlparse(self.path).path
        fn = ROUTES.get(path)
        if fn is None:
            self._send({"error": "not found"}, 404)
            return
        n = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(n)) if n else {}
        try:
            with STATE["lock"]:
                self._send(fn(body))
        except Exception as e:                       # surface, never crash
            if not isinstance(e, (ValueError, KeyError, OSError,
                                  FileNotFoundError, FileExistsError)):
                traceback.print_exc()
            self._send({"error": f"{type(e).__name__}: {e}"}, 400)

    def log_message(self, *a):
        pass


def serve(port=8700, file=None):
    if file:
        STATE["file"] = file
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
