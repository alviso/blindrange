"""blindrange-node: a distributable blind storage node.

Stores opaque key -> opaque blob in SQLite. Holds no key material, evaluates
no comparisons, and answers only exact-match lookups. Every node also gossips
a peer table, so the network has NO central infrastructure: to join, a node
needs the address of any one live peer (or none, to start a new network); to
use the network, a client needs the address of any one live node. Everything
else is discovered.

  blindrange-node --port 7501 --data ~/.blindrange/n1 [--seed host:port ...]

Transparency: GET /intel shows a sample of everything this operator can see.
"""
import argparse
import json
import os
import random
import sqlite3
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

GOSSIP_EVERY = 2.0        # seconds between gossip rounds
PEER_TTL = 15.0           # drop peers silent for this long


class Store:
    def __init__(self, path):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.lock = threading.Lock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT)")
        self.db.commit()
        self.read_batches = 0

    def put(self, entries):
        with self.lock:
            self.db.executemany("INSERT OR REPLACE INTO kv VALUES (?,?)", entries)
            self.db.commit()

    def mget(self, keys):
        with self.lock:
            self.read_batches += 1
            out = {}
            for k in keys:
                row = self.db.execute("SELECT v FROM kv WHERE k=?", (k,)).fetchone()
                if row:
                    out[k] = row[0]
            return out

    def count(self):
        with self.lock:
            return self.db.execute("SELECT COUNT(*) FROM kv").fetchone()[0]

    def sample(self, n=4):
        with self.lock:
            return self.db.execute(
                "SELECT k, substr(v,1,48) FROM kv LIMIT ?", (n,)).fetchall()


class Peers:
    """Gossiped membership table: addr -> last-heard-from timestamp."""

    def __init__(self, self_addr):
        self.self_addr = self_addr
        self.lock = threading.Lock()
        self.table = {self_addr: time.time()}

    def merge(self, other: dict):
        now = time.time()
        with self.lock:
            for addr, ts in other.items():
                ts = min(float(ts), now)               # never trust future stamps
                if ts > self.table.get(addr, 0):
                    self.table[addr] = ts
            self.table[self.self_addr] = now
            dead = [a for a, ts in self.table.items()
                    if now - ts > PEER_TTL and a != self.self_addr]
            for a in dead:
                del self.table[a]

    def snapshot(self):
        with self.lock:
            self.table[self.self_addr] = time.time()
            return dict(self.table)

    def live(self):
        now = time.time()
        return [a for a, ts in self.snapshot().items() if now - ts <= PEER_TTL]


def _gossip_loop(peers: Peers):
    while True:
        time.sleep(GOSSIP_EVERY + random.random() * 0.5)
        others = [a for a in peers.live() if a != peers.self_addr]
        if not others:
            continue
        target = random.choice(others)
        try:
            body = json.dumps({"peers": peers.snapshot()}).encode()
            req = urllib.request.Request(f"http://{target}/gossip", data=body,
                                         headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=3) as r:
                peers.merge(json.loads(r.read())["peers"])
        except OSError:
            pass                                       # peer down; TTL handles it


def make_handler(store: Store, peers: Peers):
    class Handler(BaseHTTPRequestHandler):
        def _json(self, obj, code=200):
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _body(self):
            n = int(self.headers.get("Content-Length", 0))
            return json.loads(self.rfile.read(n)) if n else {}

        def do_POST(self):
            path = urlparse(self.path).path
            data = self._body()
            if path == "/kv":
                store.put([(k, v) for k, v in data["entries"]])
                self._json({"stored": len(data["entries"])})
            elif path == "/mget":
                self._json({"values": store.mget(data["keys"])})
            elif path == "/gossip":
                peers.merge(data.get("peers", {}))
                self._json({"peers": peers.snapshot()})
            else:
                self._json({"error": "unknown"}, 404)

        def do_GET(self):
            url = urlparse(self.path)
            if url.path == "/peers":
                now = time.time()
                self._json({"peers": {a: round(now - ts, 1)
                                      for a, ts in peers.snapshot().items()}})
            elif url.path == "/stats":
                self._json({"addr": peers.self_addr, "keys": store.count(),
                            "read_batches": store.read_batches,
                            "peers": len(peers.live())})
            elif url.path == "/intel":
                n = int(parse_qs(url.query).get("limit", ["4"])[0])
                self._json({"addr": peers.self_addr, "count": store.count(),
                            "sample": [[k, v] for k, v in store.sample(n)]})
            else:
                self._json({"error": "unknown"}, 404)

        def log_message(self, *a):
            pass

    return Handler


def run(host, port, data_dir, seeds):
    addr = f"{host}:{port}"
    store = Store(os.path.join(data_dir, "kv.db"))
    peers = Peers(addr)
    if seeds:
        peers.merge({s: time.time() for s in seeds})
    threading.Thread(target=_gossip_loop, args=(peers,), daemon=True).start()
    server = ThreadingHTTPServer((host, port), make_handler(store, peers))
    server.serve_forever()


def main():
    ap = argparse.ArgumentParser(description="blindrange blind storage node")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--data", required=True, help="data directory for this node")
    ap.add_argument("--seed", action="append", default=[],
                    help="host:port of any live peer (repeatable; omit to start a new network)")
    a = ap.parse_args()
    run(a.host, a.port, a.data, a.seed)


if __name__ == "__main__":
    main()
