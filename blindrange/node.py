"""blindrange-node: a distributable blind storage node.

Stores opaque key -> opaque blob in SQLite. Holds no data keys, evaluates no
comparisons, and answers only exact-match lookups. Membership is gossip: to
join, a node needs the address of any one live peer (or none, to start a new
network); to use the network, a client needs the address of any one live node.

Identity: each node generates an Ed25519 keypair on first start (kept in its
data directory). Its node id is a hash of the public key, and every gossip
heartbeat ("I am at <addr> at time <t>") is signed by the node itself and
verified by everyone who relays or receives it. Placement hashes node ids,
so a node can change address without reshuffling data. This is not Sybil
resistance: anyone holding the network secret can mint identities.

Self-assembly / NAT: on joining, a node asks a peer to DIAL IT BACK at its
advertised address. If that fails (typical home NAT — no port forwarding),
the node automatically becomes a RELAY TENANT: it keeps an outbound long-poll
open to a reachable peer (its relay) and advertises the address
"via:<relay-addr>/<node-id>". Anyone can reach it by posting an envelope to
the relay, which forwards over the tenant's own outbound connection. Every
reachable node is a relay — the bridge for unconnectable nodes is the network
itself, not a special server (though a dedicated always-on seed works too).
Reachability is re-checked periodically, so nodes move between direct and
tenant mode as their connectivity changes. Tenants still dial OUT directly
for gossip and repair; only inbound traffic uses the relay.

Self-healing: a background thread continuously walks this node's keys in
small batches and re-pushes each to the key's current replica set — so data
migrates to new nodes and replication heals after churn without any owner
involvement. Rate is tunable (BR_REPAIR_EVERY seconds, BR_REPAIR_BATCH keys).

  blindrange-node --port 7501 --data ~/.blindrange/n1 \
      [--seed host:port ...] [--secret <network-secret>] \
      [--host 0.0.0.0 --advertise 192.168.1.20:7501]

Transparency: GET /intel shows a sample of everything this operator can see.
"""
import argparse
import hashlib
import hmac
import json
import os
import random
import sqlite3
import sys
import threading
import time
from base64 import b64decode, b64encode
from collections import deque
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .transport import POOL

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)

from .ring import Ring
from . import direct as direct_mod
from . import receipt
from . import __version__ as VERSION

GOSSIP_EVERY = 2.0        # seconds between gossip rounds
PEER_TTL = 15.0           # drop peers silent for this long
REPAIR_EVERY = float(os.environ.get("BR_REPAIR_EVERY", "5"))
REPAIR_BATCH = int(os.environ.get("BR_REPAIR_BATCH", "0"))   # 0 = adaptive
# A fixed batch size silently stops being repair once a store is large: 200
# keys every 5s is a full sweep in minutes at test scale and in *days* at
# nine million keys, so a node that falls behind never catches up. Size the
# batch from the store instead, targeting a complete sweep in this many
# hours.
REPAIR_SWEEP_H = float(os.environ.get("BR_REPAIR_SWEEP_H", "3"))
REPAIR_BATCH_MAX = int(os.environ.get("BR_REPAIR_BATCH_MAX", "20000"))
REPAIR_SETTLE = 10.0      # don't repair while membership is still changing
DIALBACK_EVERY = float(os.environ.get("BR_DIALBACK_EVERY", "60"))
DIALBACK_FIRST = float(os.environ.get("BR_DIALBACK_FIRST", "4"))
POLL_WAIT = 20.0          # relay parks a tenant's poll this long
SEND_WAIT = 15.0          # relay waits this long for a tenant's reply
TENANT_FRESH = 45.0       # tenant counts as connected if polled this recently
CACHE_KB = int(os.environ.get("BR_CACHE_KB", "32000"))   # SQLite page cache
UPDATE_EVERY = float(os.environ.get("BR_UPDATE_EVERY", "900"))   # 15 min


def _git(*args):
    try:
        import subprocess
        repo = Path(__file__).resolve().parent.parent
        out = subprocess.run(["git", "-C", str(repo), *args],
                             capture_output=True, text=True, timeout=5)
        return out.stdout.strip() if out.returncode == 0 else ""
    except Exception:
        return ""


def _read_version():
    """Version of the code THIS PROCESS loaded.

    Captured once at import, never re-read: the checkout can move under a
    running process (that is exactly what auto-update does), and a node that
    reports its working tree rather than its running code makes the whole
    'who is behind' question useless.

    build is the commit count — an integer that increases along a
    fast-forward history. Commit hashes have no order, so comparing version
    strings silently ranks a1b2c3 above 9f8e7d.
    """
    commit = _git("rev-parse", "--short", "HEAD")
    count = _git("rev-list", "--count", "HEAD")
    return (f"{VERSION}+{commit}" if commit else VERSION,
            int(count) if count.isdigit() else 0)


VERSION_STR, BUILD = _read_version()
RUNNING_COMMIT = _git("rev-parse", "HEAD")   # the code THIS process imported


def code_version():
    return VERSION_STR


def _update_loop(secret):
    """Opt-in self-update: fast-forward this checkout and exit so the
    supervisor restarts on the new code.

    This is a real trust decision, not a convenience: a node running with
    --auto-update will run whatever the configured remote publishes next.
    That is reasonable for a network whose operator also maintains the code
    (our public demo network) and unreasonable for volunteers who don't know
    the maintainer. Hence: opt-in, never a default.
    """
    import subprocess
    repo = str(Path(__file__).resolve().parent.parent)
    while True:
        time.sleep(UPDATE_EVERY + random.random() * 30)   # stagger the fleet
        try:
            pull = subprocess.run(["git", "-C", repo, "pull", "--ff-only"],
                                  capture_output=True, text=True, timeout=120)
            if pull.returncode != 0:
                continue                       # dirty tree or diverged: leave it
            after = subprocess.run(["git", "-C", repo, "rev-parse", "HEAD"],
                                   capture_output=True, text=True,
                                   timeout=20).stdout.strip()
            # Compare against the code this PROCESS imported, not against HEAD
            # before the pull. Those differ whenever the checkout moved by any
            # other route — a maintainer committing locally, an operator
            # running `git pull` by hand — and then the pull is a no-op,
            # before == after, and the node serves stale code indefinitely
            # while still reporting itself as merely 'behind'. A node stuck
            # that way now proves nothing and earns nothing, so silently
            # never restarting is expensive.
            if after and RUNNING_COMMIT and after != RUNNING_COMMIT:
                print(f"auto-update: {RUNNING_COMMIT[:8]} -> {after[:8]}, "
                      f"restarting",
                      file=sys.stderr, flush=True)
                # Re-exec rather than exit. Exiting only works under a
                # supervisor, and a node started by hand in a terminal would
                # simply vanish — which is how a live network lost two of
                # three nodes mid-benchmark. execv replaces this process
                # with a fresh one on the new code, keeping the same command
                # line, and works identically under systemd.
                sys.stdout.flush()
                sys.stderr.flush()
                # Preserve HOW we were started. Under `python -m pkg.mod`,
                # sys.argv[0] is the module's file path, so re-execing it
                # directly runs the file as a top-level script and every
                # relative import fails. __main__.__spec__ carries the module
                # name precisely for this.
                spec = getattr(sys.modules.get("__main__"), "__spec__", None)
                if spec is not None:
                    args = [sys.executable, "-m", spec.name] + sys.argv[1:]
                else:
                    args = [sys.executable] + sys.argv
                os.execv(sys.executable, args)
        except Exception:
            continue


def is_via(addr: str) -> bool:
    return addr.startswith("via:")


def parse_via(addr: str):
    """"via:host:port/node_id" -> (relay_addr, node_id)"""
    rest = addr[4:]
    relay, _, nid = rest.rpartition("/")
    return relay, nid


class Identity:
    def __init__(self, data_dir):
        path = os.path.join(data_dir, "node.key")
        if os.path.exists(path):
            with open(path, "rb") as f:
                self.priv = Ed25519PrivateKey.from_private_bytes(f.read())
        else:
            self.priv = Ed25519PrivateKey.generate()
            raw = self.priv.private_bytes(
                serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                serialization.NoEncryption())
            with open(path, "wb") as f:
                os.fchmod(f.fileno(), 0o600) if hasattr(os, "fchmod") else None
                f.write(raw)
        self.pub_raw = self.priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.node_id = hashlib.sha256(self.pub_raw).hexdigest()[:16]

    def heartbeat(self, addr, udp=""):
        ts = int(time.time() * 1000)
        msg = f"{addr}|{udp}|{ts}".encode()
        return {"addr": addr, "udp": udp, "ts": ts, "pub": self.pub_raw.hex(),
                "sig": self.priv.sign(msg).hex()}

    def poll_token(self):
        ts = int(time.time() * 1000)
        return {"node_id": self.node_id, "ts": ts, "pub": self.pub_raw.hex(),
                "sig": self.priv.sign(f"poll|{ts}".encode()).hex()}


def verify_entry(node_id, e):
    """A peer entry is only accepted if its own key signed it."""
    try:
        pub_raw = bytes.fromhex(e["pub"])
        if hashlib.sha256(pub_raw).hexdigest()[:16] != node_id:
            return False
        Ed25519PublicKey.from_public_bytes(pub_raw).verify(
            bytes.fromhex(e["sig"]),
            f"{e['addr']}|{e.get('udp', '')}|{e['ts']}".encode())
        return True
    except Exception:
        return False


def verify_poll_token(tok):
    try:
        pub_raw = bytes.fromhex(tok["pub"])
        if hashlib.sha256(pub_raw).hexdigest()[:16] != tok["node_id"]:
            return False
        if abs(time.time() * 1000 - tok["ts"]) > 30_000:
            return False
        Ed25519PublicKey.from_public_bytes(pub_raw).verify(
            bytes.fromhex(tok["sig"]), f"poll|{tok['ts']}".encode())
        return True
    except Exception:
        return False


class Store:
    def __init__(self, path):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.lock = threading.Lock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        # Keys are pseudorandom, so writes land all over the B-tree — the
        # page cache is what keeps that from degrading as the table grows
        # (measured: 3x more write throughput at scale). synchronous=NORMAL
        # can lose the last commits on power loss but cannot corrupt; with
        # replication and background repair the network heals that, and the
        # alternative is fsyncing every batch.
        self.db.execute(f"PRAGMA cache_size=-{CACHE_KB}")
        self.db.execute("PRAGMA synchronous=NORMAL")
        # WITHOUT ROWID stores rows in the key's own B-tree instead of
        # maintaining a second index into a rowid table. Only applies to
        # tables created from now on; existing node stores keep their shape
        # and stay perfectly readable.
        self.db.execute("CREATE TABLE IF NOT EXISTS kv "
                        "(k TEXT PRIMARY KEY, v TEXT) WITHOUT ROWID")
        self.db.commit()
        self.read_batches = 0

    def put(self, entries):
        with self.lock:
            self.db.executemany("INSERT OR REPLACE INTO kv VALUES (?,?)", entries)
            self.db.commit()

    def put_nx(self, entries):
        with self.lock:
            existed = []
            for k, v in entries:
                if self.db.execute("SELECT 1 FROM kv WHERE k=?", (k,)).fetchone():
                    existed.append(k)
                else:
                    self.db.execute("INSERT INTO kv VALUES (?,?)", (k, v))
            self.db.commit()
            return existed

    def delete(self, keys):
        with self.lock:
            n = 0
            for k in keys:
                n += self.db.execute("DELETE FROM kv WHERE k=?", (k,)).rowcount
            self.db.commit()
            return n

    def mget(self, keys):
        with self.lock:
            self.read_batches += 1
            out = {}
            for k in keys:
                row = self.db.execute("SELECT v FROM kv WHERE k=?", (k,)).fetchone()
                if row:
                    out[k] = row[0]
            return out

    def batch_after(self, last_key, n):
        with self.lock:
            return self.db.execute(
                "SELECT k, v FROM kv WHERE k > ? ORDER BY k LIMIT ?",
                (last_key, n)).fetchall()

    def count(self):
        with self.lock:
            return self.db.execute("SELECT COUNT(*) FROM kv").fetchone()[0]

    def sample(self, n=4):
        with self.lock:
            return self.db.execute(
                "SELECT k, substr(v,1,48) FROM kv LIMIT ?", (n,)).fetchall()


class Peers:
    """Gossiped membership: node_id -> signed heartbeat. Only entries whose
    signature verifies against their own key are ever stored or relayed."""

    def __init__(self, ident: Identity, addr: str):
        self.ident = ident
        self.addr = addr                   # mutable: direct or via-addr
        self.udp = ""                      # mutable: observed public UDP
        self.lock = threading.Lock()
        self.table = {ident.node_id: ident.heartbeat(addr)}
        self.contacts = set()              # bare seed addrs (no identity yet)
        self.changed_at = time.time()

    def merge(self, other: dict):
        now = time.time()
        with self.lock:
            for nid, e in other.items():
                if nid == self.ident.node_id:
                    continue
                cur = self.table.get(nid)
                if (not cur or e["ts"] > cur["ts"]) and verify_entry(nid, e):
                    if not cur:
                        self.changed_at = now
                    self.table[nid] = e
            self.table[self.ident.node_id] = self.ident.heartbeat(
                self.addr, self.udp)
            dead = [nid for nid, e in self.table.items()
                    if now - e["ts"] / 1000 > PEER_TTL
                    and nid != self.ident.node_id]
            for nid in dead:
                del self.table[nid]
                self.changed_at = now

    def snapshot(self):
        with self.lock:
            self.table[self.ident.node_id] = self.ident.heartbeat(
                self.addr, self.udp)
            return dict(self.table)

    def live(self):
        now = time.time()
        return {nid: e for nid, e in self.snapshot().items()
                if now - e["ts"] / 1000 <= PEER_TTL}

    def live_direct(self, exclude_self=True):
        """Peers reachable without a relay (candidates for dialback/relaying)."""
        return {nid: e for nid, e in self.live().items()
                if not is_via(e["addr"])
                and not (exclude_self and nid == self.ident.node_id)}

    def stable_since(self):
        with self.lock:
            return time.time() - self.changed_at


class RelayHub:
    """The relay side, present on every node: tenants park long-polls here;
    anyone can post an envelope for a tenant; replies are matched back."""

    def __init__(self):
        self.lock = threading.Lock()
        self.tenants = {}      # node_id -> {"q": deque, "ev": Event, "seen": ts}
        self.replies = {}      # env_id -> {"ev": Event, "result": ...}

    def _tenant(self, nid):
        with self.lock:
            t = self.tenants.get(nid)
            if not t:
                t = {"q": deque(), "ev": threading.Event(), "seen": 0.0}
                self.tenants[nid] = t
            return t

    def poll(self, nid):
        """Park up to POLL_WAIT; return queued envelopes for this tenant."""
        t = self._tenant(nid)
        t["seen"] = time.time()
        t["ev"].wait(POLL_WAIT)
        with self.lock:
            envs = list(t["q"])
            t["q"].clear()
            t["ev"].clear()
            t["seen"] = time.time()
        return envs

    def send(self, nid, envelope):
        """Deliver an envelope to a connected tenant; wait for its reply."""
        t = self._tenant(nid)
        if time.time() - t["seen"] > TENANT_FRESH:
            return None                                # tenant not connected
        slot = {"ev": threading.Event(), "result": None}
        with self.lock:
            self.replies[envelope["id"]] = slot
            t["q"].append(envelope)
            t["ev"].set()
        slot["ev"].wait(SEND_WAIT)
        with self.lock:
            self.replies.pop(envelope["id"], None)
        return slot["result"]

    def reply(self, env_id, result):
        with self.lock:
            slot = self.replies.get(env_id)
        if slot:
            slot["result"] = result
            slot["ev"].set()


def _sign(secret: str, payload: bytes) -> str:
    return hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()


def _post_direct(addr, path, payload: bytes, secret: str, timeout=5):
    headers = {"Content-Type": "application/json"}
    if secret:
        headers["X-BR-Auth"] = _sign(secret, payload)
    status, data = POOL.request(addr, "POST", path, payload, headers,
                                timeout=timeout)
    if status >= 400:
        raise ConnectionError(f"HTTP {status} from {addr}{path}")
    return json.loads(data)


def post_any(addr, path, payload: bytes, secret: str, timeout=5):
    """POST to a direct address, or through a relay for a via-address."""
    if not is_via(addr):
        return _post_direct(addr, path, payload, secret, timeout)
    relay, nid = parse_via(addr)
    env = {"to": nid, "id": os.urandom(8).hex(), "method": "POST",
           "path": path, "body_b64": b64encode(payload).decode()}
    out = _post_direct(relay, "/relay/send", json.dumps(env).encode(),
                       secret, timeout=timeout + SEND_WAIT)
    if out.get("status") != 200:
        raise ConnectionError(f"relayed request failed: {out}")
    return json.loads(b64decode(out["body_b64"]))


# --------------------------------------------------------------- services
# Request handling shared by the HTTP server and the tenant envelope loop.

def service_post(store, peers, hub, secret, path, data, quic=None):
    if path == "/kv":
        entries = [(k, v) for k, v in data["entries"]]
        if data.get("nx"):
            existed = store.put_nx(entries)
            return 200, {"stored": len(entries) - len(existed),
                         "existed": existed}
        store.put(entries)
        return 200, {"stored": len(entries)}
    if path == "/mget":
        keys = data["keys"]
        values = store.mget(keys)
        out = {"values": values}
        nonce = data.get("nonce")
        # Signed on EVERY read that carries a nonce, never only on audits:
        # a node that could recognise an audit could serve those and drop
        # the rest, so the signature has to be worthless as a signal.
        if isinstance(nonce, str) and len(nonce) == 32:
            try:
                out["receipt"] = receipt.sign(
                    peers.ident.priv, peers.ident.node_id,
                    peers.ident.pub_raw, nonce, keys, values, time.time())
            except (ValueError, TypeError):
                pass
        return 200, out
    if path == "/delete":
        return 200, {"deleted": store.delete(data["keys"])}
    if path == "/gossip":
        peers.merge(data.get("peers", {}))
        return 200, {"peers": peers.snapshot()}
    if path == "/dialback":
        target = data.get("addr", "")
        asker = data.get("node_id", "")
        if is_via(target):
            return 400, {"error": "dialback is for direct addresses"}
        # reachable only if the node that ANSWERS at the address is the node
        # that ASKED — otherwise the probe hit someone else (classic case: a
        # loopback advertise makes the prober dial its own node) and the
        # address is useless as an advertise for the asker
        try:
            status, raw = POOL.request(target, "GET", "/stats", timeout=2)
            answered = json.loads(raw).get("node_id", "") if status == 200 else ""
            ok = bool(asker) and answered == asker
        except (OSError, ValueError):
            ok = False
        return 200, {"reachable": ok}
    if path == "/punch":
        # fired over the reliable relay path: open our NAT toward the caller
        target = data.get("udp", "")
        if quic is not None and target:
            quic.punch(target)
        return 200, {"punching": bool(quic and target),
                     "udp": quic.observed if quic else ""}
    if path == "/relay/poll":
        tok = data.get("token", {})
        if not verify_poll_token(tok):
            return 401, {"error": "bad poll token"}
        return 200, {"envelopes": hub.poll(tok["node_id"])}
    if path == "/relay/send":
        result = hub.send(data["to"], {"id": data["id"],
                                       "method": data.get("method", "POST"),
                                       "path": data["path"],
                                       "body_b64": data.get("body_b64", "")})
        if result is None:
            return 404, {"error": "tenant not connected"}
        return 200, result
    if path == "/relay/reply":
        hub.reply(data["id"], {"status": data["status"],
                               "body_b64": data.get("body_b64", "")})
        return 200, {"ok": True}
    return 404, {"error": "unknown"}


STATUS_CACHE = {"at": 0.0, "rows": [], "total": 0}


def _peer_stats(nid, e, secret, hub, self_id):
    """Best-effort /stats for one peer (key count and version). Tenants are
    reached over the relay connection they already hold with us."""
    try:
        if is_via(e["addr"]):
            _relay, tenant = parse_via(e["addr"])
            out = hub.send(tenant, {"id": os.urandom(8).hex(), "method": "GET",
                                    "path": "/stats", "body_b64": ""})
            if not out or out.get("status") != 200:
                return None
            return json.loads(b64decode(out["body_b64"]))
        status, raw = POOL.request(e["addr"], "GET", "/stats", timeout=2)
        return json.loads(raw) if status == 200 else None
    except (OSError, ValueError, KeyError):
        return None


def status_rows(store, peers, secret, hub):
    """Roster for the public status page; cached briefly."""
    now = time.time()
    if now - STATUS_CACHE["at"] < 10:
        return STATUS_CACHE["rows"], STATUS_CACHE["total"]
    rows, total = [], 0
    me = peers.ident.node_id
    for nid, e in sorted(peers.live().items()):
        stats = (None if nid == me else
                 _peer_stats(nid, e, secret, hub, me))
        keys = store.count() if nid == me else (stats or {}).get("keys")
        ver = (VERSION_STR if nid == me
               else (stats or {}).get("version") or "unknown")
        build = BUILD if nid == me else (stats or {}).get("build", 0)
        if keys:
            total += keys
        rows.append({"id": nid, "mode": "relay tenant" if is_via(e["addr"])
                     else "directly reachable", "keys": keys, "version": ver,
                     "build": build or 0,
                     "age": round(now - e["ts"] / 1000, 1)})
    # compare commit COUNTS: hashes have no order, and a node too old to
    # report one is behind by definition
    newest = max((r["build"] for r in rows), default=0)
    for r in rows:
        r["behind"] = r["build"] < newest
    STATUS_CACHE.update({"at": now, "rows": rows, "total": total})
    return rows, total


STATUS_CSS = """
:root{--bg:#0f1115;--panel:#171a21;--line:#262b36;--txt:#d7dce4;
--dim:#8b93a1;--acc:#5cc8ff;--gold:#e0b060;--ok:#7fd18c}
*{box-sizing:border-box;margin:0}
body{background:var(--bg);color:var(--txt);font:15px/1.65 ui-monospace,
SFMono-Regular,Menlo,monospace;padding:48px 24px 80px}
.wrap{max-width:760px;margin:0 auto}
h1{font-size:30px;margin-bottom:6px}h1 span{color:var(--acc)}
.sub{color:var(--dim);margin-bottom:28px}
.big{font-size:15px;color:var(--dim);margin:0 0 18px}
.big b{color:var(--ok);font-weight:normal;font-size:22px}
table{width:100%;border-collapse:collapse;margin-bottom:22px}
th,td{text-align:left;padding:9px 10px;border-bottom:1px solid var(--line)}
th{color:var(--dim);font-weight:normal;font-size:12px;
text-transform:uppercase;letter-spacing:.08em}
td.id{color:var(--gold)}td.num{text-align:right;font-variant-numeric:tabular-nums}
td.ver{color:var(--ok)}td.behind{color:#e0b060}td.share{color:var(--acc)}
.note{background:var(--panel);border:1px solid var(--line);border-radius:10px;
padding:16px 18px;color:var(--dim);font-size:13.5px;margin-bottom:16px}
.note b{color:var(--txt);font-weight:normal}
a{color:var(--acc);text-decoration:none}a:hover{text-decoration:underline}
.foot{color:var(--dim);font-size:13px;margin-top:26px}
"""


def status_html(rows, total, seed_addr):
    body = "".join(
        f"<tr><td class='id'>{r['id']}</td><td>{r['mode']}</td>"
        f"<td class='num'>{r['keys'] if r['keys'] is not None else '—'}</td>"
        f"<td class='{'ver' if (r.get('measured') or {}).get('rate', 0) >= 0.9 else 'behind'}'>"
        f"{(str(int((r['measured']['rate']) * 100)) + '% · ' + str(r['measured']['reports']) + ' audits') if r.get('measured') else '—'}</td>"
        f"<td class='{'behind' if r.get('behind') else 'ver'}'>"
        f"{'not reporting' if r.get('version') == 'unknown' else r.get('version', '?')}"
        f"{' · behind' if r.get('behind') else ''}</td>"
        f"<td class='num'>{r['age']}s</td>"
        f"<td class='num share'>{r['share'] if r.get('share') is not None else '—'}</td>"
        f"</tr>" for r in rows)
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>blindrange — public network status</title><style>{STATUS_CSS}</style>
</head><body><div class="wrap">
<h1>blind<span>range</span> — public network</h1>
<div class="sub">live status, served by the network itself</div>
<p class="big"><b>{len(rows)}</b> live nodes &nbsp;·&nbsp; <b>{total}</b>
encrypted keys stored</p>
<table><tr><th>node</th><th>reachability</th><th>keys (self-reported)</th>
<th>possession (proved)</th><th>version</th><th>last seen</th><th>share ‰</th></tr>
{body}</table>
<div class="note"><b>Key counts on this page are self-reported and
unverified.</b> A node returns whatever number it likes; nothing here checks
it. What can be proved is possession: a data owner can ask the node
responsible for a record to produce it and verify the AES-GCM tag, which a
node cannot fake — it can neither derive the key nor forge the ciphertext.
Reachability and last-seen are measured, not claimed.</div>
<div class="note">Membership is public within a network — this page is
everything an operator can publish about it. <b>Contents are not.</b> Every
database here is encrypted under its own master key, so records and index
entries are unlinkable pseudorandom pairs to every node, to every other user,
and to whoever runs this seed. You can see that someone is storing; never
what.</div>
<div class="note">Nodes marked <b>relay tenant</b> sit behind NAT and were
never configured for it — they diagnosed their own reachability and now
receive traffic over an outbound connection, with direct QUIC paths punched
when the networks allow.</div>
<div class="note"><b>share ‰</b> is each node's slice of a distribution pool
per thousand — 500 would be half of everything. It is structural position on
the ring multiplied by <b>proved</b> possession, so a node with no audits yet
earns nothing and a node that self-reports generously earns nothing extra.
Illustrative: a share of a pool, not an entitlement, and not money.</div>
<div class="foot">join with two commands ·
<a href="https://blindrange.dev">blindrange.dev</a> ·
<a href="https://github.com/alviso/blindrange">source</a><br>
demo network — no durability promises. seed: {seed_addr}</div>
</div></body></html>"""


def service_get(store, peers, path, query, quic=None, status=None):
    if path in ("/", "/status.json") and status is not None:
        rows, total = status
        if path == "/status.json":
            return 200, {"nodes": rows, "keys": total}
        return "html", status_html(rows, total, peers.addr)
    if path == "/peers":
        now = time.time()
        return 200, {"peers": {
            nid: {"addr": e["addr"], "udp": e.get("udp", ""),
                  "age": round(now - e["ts"] / 1000, 1)}
            for nid, e in peers.snapshot().items()}}
    if path == "/stats":
        return 200, {"addr": peers.addr, "node_id": peers.ident.node_id,
                     "keys": store.count(),
                     "read_batches": store.read_batches,
                     "peers": len(peers.live()),
                     "mode": "tenant" if is_via(peers.addr) else "direct",
                     "quic": quic is not None, "udp": peers.udp,
                     "version": VERSION_STR, "build": BUILD}
    if path == "/intel":
        n = int(parse_qs(query).get("limit", ["4"])[0])
        return 200, {"addr": peers.addr, "node_id": peers.ident.node_id,
                     "count": store.count(),
                     "sample": [[k, v] for k, v in store.sample(n)]}
    return 404, {"error": "unknown"}


# --------------------------------------------------------------- daemons

def _gossip_loop(peers: Peers, secret: str):
    while True:
        time.sleep(GOSSIP_EVERY + random.random() * 0.5)
        live = peers.live()
        targets = [e["addr"] for nid, e in live.items()
                   if nid != peers.ident.node_id]
        targets += [a for a in peers.contacts
                    if a not in {e["addr"] for e in live.values()}]
        if not targets:
            continue
        target = random.choice(targets)
        try:
            body = json.dumps({"peers": peers.snapshot()}).encode()
            got = post_any(target, "/gossip", body, secret)
            peers.merge(got["peers"])
        except OSError:
            pass                                       # peer down; TTL handles it


def _repair_loop(store: Store, peers: Peers, secret: str):
    cursor = ""
    while True:
        time.sleep(REPAIR_EVERY + random.random())
        if peers.stable_since() < REPAIR_SETTLE:
            continue
        live = peers.live()
        if len(live) < 2:
            continue
        ring = Ring(sorted(live), replicas=3)
        addr_of = {nid: e["addr"] for nid, e in live.items()}
        if REPAIR_BATCH:
            size = REPAIR_BATCH
        else:
            rounds = max(1.0, REPAIR_SWEEP_H * 3600 / max(0.1, REPAIR_EVERY))
            size = int(min(REPAIR_BATCH_MAX,
                           max(200, store.count() / rounds)))
        batch = store.batch_after(cursor, size)
        if not batch:
            cursor = ""
            continue
        cursor = batch[-1][0]
        by_addr = {}
        for k, v in batch:
            for nid in ring.route(k):
                if nid != peers.ident.node_id and nid in addr_of:
                    by_addr.setdefault(addr_of[nid], []).append([k, v])
        for addr, entries in by_addr.items():
            try:
                post_any(addr, "/kv",
                         json.dumps({"entries": entries}).encode(), secret)
            except OSError:
                pass


def _reachability_loop(store, peers, hub, secret, direct_addr):
    """Self-assembly: determine own reachability by dialback, become a relay
    tenant when unreachable, revert when reachable again."""
    ident = peers.ident
    time.sleep(DIALBACK_FIRST)
    relay_nid = None
    while True:
        candidates = peers.live_direct()
        if candidates:
            probe = random.choice(list(candidates.values()))
            try:
                got = post_any(probe["addr"], "/dialback",
                               json.dumps({"addr": direct_addr,
                                           "node_id": ident.node_id}).encode(),
                               secret)
                reachable = got.get("reachable", False)
            except OSError:
                reachable = None                       # probe failed; no info
            if reachable is True and is_via(peers.addr):
                peers.addr = direct_addr               # NAT opened up: go direct
                relay_nid = None
            elif reachable is False:
                pool = {n: e for n, e in candidates.items()}
                if relay_nid not in pool and pool:
                    relay_nid = random.choice(list(pool))
                if relay_nid:
                    via = f"via:{pool[relay_nid]['addr']}/{ident.node_id}"
                    if peers.addr != via:
                        peers.addr = via
                        threading.Thread(
                            target=_tenant_loop,
                            args=(store, peers, hub, secret,
                                  lambda: peers.addr),
                            daemon=True).start()
        time.sleep(DIALBACK_EVERY)


def _tenant_loop(store, peers, hub, secret, current_addr):
    """While in tenant mode: long-poll the relay, answer forwarded requests.
    Exits when the node returns to direct mode or switches relay. Also keeps
    the QUIC socket's NAT mapping warm and its public endpoint fresh by
    STUNing the relay every few poll cycles."""
    my_via = current_addr()
    relay, _nid = parse_via(my_via)
    stun_at = 0.0
    while current_addr() == my_via:
        quic = _tenant_loop.quic
        if quic is not None and time.time() > stun_at:
            try:
                # advertise ICE-style CANDIDATES: the LAN address first (works
                # for peers on the same network, and avoids needing hairpin
                # NAT when the dialer sits behind the same router), then the
                # STUN-observed public endpoint for everyone else
                got = quic.stun(relay)
                cands = []
                lip = direct_mod.local_ip()
                if lip:
                    cands.append(f"{lip}:{quic.port}")
                if got and got not in cands:
                    cands.append(got)
                if cands:
                    peers.udp = ",".join(cands)
            except Exception:
                pass
            stun_at = time.time() + 20
        try:
            body = json.dumps({"token": peers.ident.poll_token()}).encode()
            got = _post_direct(relay, "/relay/poll", body, secret,
                               timeout=POLL_WAIT + 10)
            for env in got.get("envelopes", []):
                if env["method"] == "GET":
                    path, _, query = env["path"].partition("?")
                    code, obj = service_get(store, peers, path, query,
                                            quic=_tenant_loop.quic)
                else:
                    data = json.loads(b64decode(env["body_b64"]) or b"{}")
                    code, obj = service_post(store, peers, hub, secret,
                                             env["path"], data,
                                             quic=_tenant_loop.quic)
                reply = {"id": env["id"], "status": code,
                         "body_b64": b64encode(json.dumps(obj).encode()).decode()}
                _post_direct(relay, "/relay/reply",
                             json.dumps(reply).encode(), secret)
        except OSError:
            time.sleep(2)                              # relay hiccup; retry


_tenant_loop.quic = None


def make_quic_service(store, peers, hub, secret):
    """bytes -> bytes request handler for direct QUIC streams. Frames:
    request {"m", "p", "q", "b" (b64 body), "a" (HMAC)} ->
    response {"s": status, "b": b64(json)}."""
    def service(raw: bytes) -> bytes:
        try:
            frame = json.loads(raw)
            body = b64decode(frame.get("b", "")) if frame.get("b") else b""
            if secret:
                payload = body if frame.get("m") == "POST" else \
                    frame.get("p", "").encode()
                good = hmac.compare_digest(frame.get("a", ""),
                                           _sign(secret, payload))
                if not good:
                    return json.dumps({"s": 401, "b": ""}).encode()
            if frame.get("m") == "GET":
                code, obj = service_get(store, peers, frame.get("p", ""),
                                        frame.get("q", ""))
            else:
                data = json.loads(body) if body else {}
                code, obj = service_post(store, peers, hub, secret,
                                         frame.get("p", ""), data,
                                         quic=_tenant_loop.quic)
            return json.dumps(
                {"s": code,
                 "b": b64encode(json.dumps(obj).encode()).decode()}).encode()
        except Exception as e:
            return json.dumps({"s": 500, "b": b64encode(
                json.dumps({"error": str(e)}).encode()).decode()}).encode()
    return service


# --------------------------------------------------------------- server

def make_handler(store: Store, peers: Peers, hub: RelayHub, secret: str = "",
                 quic=None, public_status=False):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"      # keep-alive: reused connections
        # Responses go out as headers-then-body, two small writes. With Nagle
        # on, the second waits for an ACK of the first, so a request costs
        # ~2 round trips instead of 1 — invisible on localhost, brutal across
        # an ocean (measured 430ms against a 187ms RTT).
        disable_nagle_algorithm = True

        def _json(self, obj, code=200):
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _authed(self, payload: bytes) -> bool:
            """Network-membership check: HMAC(secret, payload). Anti-vandalism
            only — every node and client holds the same secret, so this keeps
            outsiders out; it does not (and cannot) make nodes trustworthy.
            Data confidentiality never depends on it."""
            if not secret:
                return True
            given = self.headers.get("X-BR-Auth", "")
            return hmac.compare_digest(given, _sign(secret, payload))

        def do_POST(self):
            path = urlparse(self.path).path
            n = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(n) if n else b""
            if not self._authed(raw):
                self._json({"error": "unauthorized"}, 401)
                return
            data = json.loads(raw) if raw else {}
            code, obj = service_post(store, peers, hub, secret, path, data,
                                     quic=quic)
            self._json(obj, code)

        def do_GET(self):
            url = urlparse(self.path)
            if url.path in ("/peers", "/intel") and not self._authed(
                    url.path.encode()):
                self._json({"error": "unauthorized"}, 401)
                return
            st = (status_rows(store, peers, secret, hub)
                  if public_status and url.path in ("/", "/status.json")
                  else None)
            code, obj = service_get(store, peers, url.path, url.query,
                                    quic=quic, status=st)
            if code == "html":
                body = obj.encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self._json(obj, code)

        def log_message(self, *a):
            pass

    return Handler


def run(host, port, data_dir, seeds, secret="", advertise=None,
        quic_host="0.0.0.0", public_status=False, auto_update=False):
    os.makedirs(data_dir, exist_ok=True)
    addr = advertise or f"{host}:{port}"
    ident = Identity(data_dir)
    store = Store(os.path.join(data_dir, "kv.db"))
    peers = Peers(ident, addr)
    peers.contacts.update(seeds)
    hub = RelayHub()
    quic = None
    if not direct_mod.DISABLED:
        try:
            quic = direct_mod.NodeQuic(
                quic_host, port, ident.node_id,
                make_quic_service(store, peers, hub, secret))
        except Exception as e:              # QUIC is an optimization only
            import sys as _sys
            print(f"quic disabled: {type(e).__name__}: {e}", file=_sys.stderr)
            quic = None
    _tenant_loop.quic = quic
    if auto_update:
        threading.Thread(target=_update_loop, args=(secret,),
                         daemon=True).start()
    threading.Thread(target=_gossip_loop, args=(peers, secret),
                     daemon=True).start()
    threading.Thread(target=_repair_loop, args=(store, peers, secret),
                     daemon=True).start()
    threading.Thread(target=_reachability_loop,
                     args=(store, peers, hub, secret, addr),
                     daemon=True).start()
    server = ThreadingHTTPServer((host, port),
                                 make_handler(store, peers, hub, secret,
                                              quic=quic,
                                              public_status=public_status))
    server.serve_forever()


def main():
    ap = argparse.ArgumentParser(description="blindrange blind storage node")
    ap.add_argument("--host", default="127.0.0.1",
                    help="bind address (0.0.0.0 to serve a LAN)")
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--data", required=True, help="data directory for this node")
    ap.add_argument("--seed", action="append", default=[],
                    help="host:port of any live peer (repeatable; omit to start a new network)")
    ap.add_argument("--secret", default=os.environ.get("BLINDRANGE_SECRET", ""),
                    help="network-membership secret (or env BLINDRANGE_SECRET); "
                         "empty runs an open network")
    ap.add_argument("--auto-update", action="store_true",
                    default=os.environ.get("BR_AUTO_UPDATE") == "1",
                    help="periodically fast-forward this git checkout and "
                         "restart on new commits. You are trusting whoever "
                         "controls the remote to run code on your machine — "
                         "off unless you ask for it")
    ap.add_argument("--public-status", action="store_true",
                    help="serve an unauthenticated status page at / listing "
                         "live nodes and key counts (off by default: on a "
                         "private network, membership should not be public)")
    ap.add_argument("--quic-host", default=os.environ.get("BR_QUIC_HOST",
                                                          "0.0.0.0"),
                    help="bind address for the QUIC/UDP socket used by direct "
                         "paths (default all interfaces — hole punching needs "
                         "internet reachability even when HTTP is local)")
    ap.add_argument("--advertise", default=None,
                    help="host:port other machines should reach this node at "
                         "(defaults to --host:--port; set it when binding 0.0.0.0). "
                         "If it turns out to be unreachable, the node automatically "
                         "relays through a reachable peer instead.")
    a = ap.parse_args()
    run(a.host, a.port, a.data, a.seed, a.secret, a.advertise, a.quic_host,
        a.public_status, a.auto_update)


if __name__ == "__main__":
    main()
