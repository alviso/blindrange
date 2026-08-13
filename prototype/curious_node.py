"""A curious-but-honest node: serves requests correctly, logs everything.

Identical wire behavior to node.py, but it retains all state at rest and
records every lookup with a timestamp. `/intel` hands an attacker the node's
complete observations: the tag->ids index and the query log. It NEVER sees a
key or a plaintext, and it decrypts nothing — every attack downstream is built
purely from tags, volumes, and access patterns.
"""
import json
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

TAGS = {}         # tag hex -> [record_id, ...]
RECORDS = {}      # record_id -> ciphertext (base64)
QUERY_LOG = []    # [{"t": epoch, "tags": [...], "returned": [record_id, ...]}]


class Handler(BaseHTTPRequestHandler):
    def _json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        length = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(length)) if length else {}

    def do_POST(self):
        path = urlparse(self.path).path
        data = self._body()
        if path == "/tags":
            for tag, rid in data["entries"]:
                TAGS.setdefault(tag, []).append(rid)
            self._json({"stored": len(data["entries"])})
        elif path == "/records":
            for rid, ct in data["entries"]:
                RECORDS[rid] = ct
            self._json({"stored": len(data["entries"])})
        elif path == "/lookup":
            hits = []
            for tag in data["tags"]:
                hits.extend(TAGS.get(tag, []))
            QUERY_LOG.append({"t": time.time(), "tags": list(data["tags"]),
                              "returned": list(hits)})   # <-- the espionage
            self._json({"record_ids": hits})
        elif path == "/fetch":
            self._json({"records": {rid: RECORDS[rid]
                                    for rid in data["record_ids"] if rid in RECORDS}})
        else:
            self._json({"error": "unknown"}, 404)

    def do_GET(self):
        if urlparse(self.path).path == "/intel":
            self._json({
                "tags": {t: ids for t, ids in TAGS.items()},
                "query_log": QUERY_LOG,
                "n_records": len(RECORDS),
            })
        elif urlparse(self.path).path == "/stats":
            self._json({"tags": len(TAGS), "records": len(RECORDS),
                        "lookups": len(QUERY_LOG)})
        else:
            self._json({"error": "unknown"}, 404)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    port = int(sys.argv[1])
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
