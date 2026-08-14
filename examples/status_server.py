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
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from blindrange.node import status_html  # noqa: E402

# Anonymous audit reports, kept in memory only.
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
# This is mitigation, not a solution: an attacker willing to submit enough
# reports still wins. Making that expensive needs a cost to submit, and
# every cheap way to impose one leaks who is submitting.
REPORTS = collections.defaultdict(collections.deque)   # node_id -> (ts, rate)
REPORT_WINDOW = 500
REPORT_MAX_AGE = float(os.environ.get("BR_REPORT_MAX_AGE", "21600"))  # 6h
REPORT_QUANTILE = 0.25
REPORT_LOCK = threading.Lock()


def record_report(payload):
    if payload.get("kind") != "blindrange-audit":
        raise ValueError("not an audit report")
    nodes = payload.get("nodes") or {}
    if len(nodes) > 256:
        raise ValueError("implausible report")
    accepted = 0
    with REPORT_LOCK:
        for nid, v in nodes.items():
            if not isinstance(nid, str) or len(nid) > 64:
                continue
            sampled, verified = int(v.get("sampled", 0)), int(v.get("verified", 0))
            if sampled <= 0 or not 0 <= verified <= sampled:
                continue
            dq = REPORTS[nid]
            dq.append((time.time(), verified / sampled))
            while len(dq) > REPORT_WINDOW:
                dq.popleft()
            accepted += 1
    return {"accepted": accepted}


def possession():
    cutoff = time.time() - REPORT_MAX_AGE
    with REPORT_LOCK:
        out = {}
        for nid, dq in REPORTS.items():
            vals = sorted(rate for ts, rate in dq if ts >= cutoff)
            if vals:
                idx = min(len(vals) - 1, int(len(vals) * REPORT_QUANTILE))
                out[nid] = {"rate": round(vals[idx], 3),
                            "reports": len(vals)}
        return out


def make_handler(node_addr):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            path = urlparse(self.path).path
            if path not in ("/", "/status.json", "/health",
                            "/possession.json"):
                self.send_error(404)
                return
            try:
                with urllib.request.urlopen(
                        f"http://{node_addr}/status.json", timeout=5) as r:
                    data = json.loads(r.read())
            except OSError:
                self.send_error(502, "node unreachable")
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
                seen = possession()
                for row in data["nodes"]:
                    row["measured"] = seen.get(row["id"])
                body = status_html(data["nodes"], data["keys"],
                                   node_addr).encode()
                ctype = "text/html; charset=utf-8"
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "public, max-age=15")
            self.end_headers()
            self.wfile.write(body)

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
    threading.Thread(target=_restart_on_new_code, daemon=True).start()
    ThreadingHTTPServer((a.host, a.port),
                        make_handler(a.node)).serve_forever()


if __name__ == "__main__":
    main()
