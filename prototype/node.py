"""A blind storage node.

Stores two things, and understands neither:
  - tags:    pseudorandom hex string  -> list of record ids
  - records: record id                -> ciphertext blob (base64)

It has no key, performs no comparisons, and answers only exact-match
lookups. Everything it could ever leak is visible via GET /dump.
"""
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

TAGS = {}     # tag hex -> [record_id, ...]
RECORDS = {}  # record_id -> ciphertext (base64 str)


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
        if path == "/tags":                    # {"entries": [[tag, record_id], ...]}
            for tag, rid in data["entries"]:
                TAGS.setdefault(tag, []).append(rid)
            self._json({"stored": len(data["entries"])})
        elif path == "/records":               # {"entries": [[record_id, ct_b64], ...]}
            for rid, ct in data["entries"]:
                RECORDS[rid] = ct
            self._json({"stored": len(data["entries"])})
        elif path == "/lookup":                # {"tags": [...]} -> matching record ids
            hits = []
            for tag in data["tags"]:
                hits.extend(TAGS.get(tag, []))
            self._json({"record_ids": hits})
        elif path == "/fetch":                 # {"record_ids": [...]} -> ciphertexts
            self._json({"records": {rid: RECORDS[rid] for rid in data["record_ids"] if rid in RECORDS}})
        else:
            self._json({"error": "unknown"}, 404)

    def do_GET(self):
        url = urlparse(self.path)
        if url.path == "/stats":
            self._json({"tags": len(TAGS), "records": len(RECORDS)})
        elif url.path == "/dump":              # what the node operator sees
            n = int(parse_qs(url.query).get("limit", ["5"])[0])
            self._json({
                "tags_sample": {t: ids for t, ids in list(TAGS.items())[:n]},
                "records_sample": {r: ct[:64] + "..." for r, ct in list(RECORDS.items())[:n]},
            })
        else:
            self._json({"error": "unknown"}, 404)

    def log_message(self, *args):  # keep 10 nodes from spamming the terminal
        pass


if __name__ == "__main__":
    port = int(sys.argv[1])
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
