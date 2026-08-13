"""A dumb, persistent, blind key-value node.

Stores opaque key -> opaque value. No lists, no comparisons, no key material.
Persists to SQLite so it survives restarts (used in step 2). Being honest-but-
curious, it also logs every read batch and serves it at /intel.

  python3 kv_node.py <port> <db_path>
"""
import json
import sqlite3
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse


class Store:
    def __init__(self, path):
        self.lock = threading.Lock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT)")
        self.db.commit()
        self.reads = []            # curiosity: [{"t":, "keys":[...]}]

    def put(self, entries):
        with self.lock:
            self.db.executemany("INSERT OR REPLACE INTO kv VALUES (?,?)", entries)
            self.db.commit()

    def mget(self, keys):
        with self.lock:
            self.reads.append({"t": time.time(), "keys": list(keys)})
            out = {}
            for k in keys:
                row = self.db.execute("SELECT v FROM kv WHERE k=?", (k,)).fetchone()
                if row:
                    out[k] = row[0]
            return out

    def count(self):
        with self.lock:
            return self.db.execute("SELECT COUNT(*) FROM kv").fetchone()[0]


class Handler(BaseHTTPRequestHandler):
    store = None

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
        if path == "/kv":                       # {"entries": [[k, v], ...]}
            self.store.put(data["entries"])
            self._json({"stored": len(data["entries"])})
        elif path == "/mget":                   # {"keys": [...]} -> {k: v}
            self._json({"values": self.store.mget(data["keys"])})
        else:
            self._json({"error": "unknown"}, 404)

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/stats":
            self._json({"keys": self.store.count(), "reads": len(self.store.reads)})
        elif path == "/intel":                  # everything the operator sees
            with self.store.lock:
                sample = self.store.db.execute("SELECT k, v FROM kv LIMIT 4").fetchall()
            self._json({"count": self.store.count(),
                        "sample": [[k, v[:48]] for k, v in sample],
                        "read_batches": len(self.store.reads)})
        else:
            self._json({"error": "unknown"}, 404)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    port = int(sys.argv[1])
    db_path = sys.argv[2] if len(sys.argv) > 2 else f":memory:"
    Handler.store = Store(db_path)
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
