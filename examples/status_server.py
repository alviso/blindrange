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
from blindrange import receipt  # noqa: E402

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
# The unsolved one is the ring itself: identities are cheap, so an attacker
# minting many nodes gets a larger STRUCTURAL share regardless of any of
# this. That is Sybil resistance on placement, a separate problem.
REPORTS = collections.defaultdict(collections.deque)   # node_id -> (ts, rate)
REPORT_WINDOW = 500
REPORT_MAX_AGE = float(os.environ.get("BR_REPORT_MAX_AGE", "21600"))  # 6h
REPORT_QUANTILE = 0.25
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
        except Exception as e:                       # keep the last good one
            SNAPSHOT["error"] = f"{type(e).__name__}: {e}"
        SNAPSHOT["at"] = time.time()
        time.sleep(every)


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
    return data


def make_handler(node_addr):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            path = urlparse(self.path).path
            if path not in ("/", "/status.json", "/health",
                            "/possession.json"):
                self.send_error(404)
                return
            data = SNAPSHOT["data"]
            if data is None:
                self.send_error(503, SNAPSHOT["error"] or "warming up")
                return
            data = with_shares(json.loads(json.dumps(data)))
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
    threading.Thread(target=refresh_loop, args=(a.node,), daemon=True).start()
    time.sleep(1.5)                       # let the first snapshot land
    ThreadingHTTPServer((a.host, a.port),
                        make_handler(a.node)).serve_forever()


if __name__ == "__main__":
    main()
