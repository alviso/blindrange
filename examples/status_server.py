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
import json
import sys
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from blindrange.node import status_html  # noqa: E402


def make_handler(node_addr):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            path = urlparse(self.path).path
            if path not in ("/", "/status.json", "/health"):
                self.send_error(404)
                return
            try:
                with urllib.request.urlopen(
                        f"http://{node_addr}/status.json", timeout=5) as r:
                    data = json.loads(r.read())
            except OSError:
                self.send_error(502, "node unreachable")
                return
            if path == "/health":
                body, ctype = b'{"ok":true}', "application/json"
            elif path == "/status.json":
                body = json.dumps(data).encode()
                ctype = "application/json"
            else:
                body = status_html(data["nodes"], data["keys"],
                                   node_addr).encode()
                ctype = "text/html; charset=utf-8"
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "public, max-age=15")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    return Handler


def main():
    ap = argparse.ArgumentParser(description="blindrange public status server")
    ap.add_argument("--node", default="127.0.0.1:7501",
                    help="node to read /status.json from")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8080)
    a = ap.parse_args()
    ThreadingHTTPServer((a.host, a.port),
                        make_handler(a.node)).serve_forever()


if __name__ == "__main__":
    main()
