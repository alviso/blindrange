"""blindrange sample application: an encrypted orders database you can demo.

Spawns a local decentralized network of blind nodes (or joins an existing one
via --bootstrap), seeds sample business data (customer orders), and serves a
web UI on http://127.0.0.1:8600 with three synchronized panels:

  * Owner view   — range/prefix queries, decrypted results (this process holds
                   the keys; it is the data owner's machine)
  * Network view — live nodes discovered via gossip, keys per node; buttons to
                   kill and spawn nodes mid-demo
  * Node view    — /intel of a real node: the opaque key->blob pairs an
                   operator actually sees

  python3 examples/webdemo/app.py                # self-contained: 8 local nodes
  python3 examples/webdemo/app.py --bootstrap 127.0.0.1:7501   # join a network
"""
import argparse
import json
import random
import subprocess
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from blindrange import Owner  # noqa: E402

UI = (Path(__file__).parent / "ui.html").read_text()

SCHEMA = {
    # cents, up to ~$10,000; leaf_width 256 = the privacy budget: no observer
    # ever resolves an amount finer than a $2.56 bucket
    "amount": {"type": "int", "bits": 20, "leaf_width": 256},
    # days since 2024-01-01, ~5.6 years of range, exact days
    "day":    {"type": "int", "bits": 11, "leaf_width": 1},
    # customer name, first 4 chars; leaf_width 16 blurs the last character
    "customer": {"type": "str", "bits": 20, "leaf_width": 16, "chars": 4},
}

CUSTOMERS = ["acme corp", "apex ltd", "birch & co", "cedar gmbh", "delta ag",
             "ember inc", "flint bv", "gale sa", "harbor plc", "iris kft",
             "sable zrt", "salt bt", "sandstone", "scout oy", "sierra srl",
             "summit as", "tidal ab", "umbra sarl"]
STATUSES = ["paid", "pending", "shipped", "refunded"]


def sample_orders(n=1000, seed=4):
    rng = random.Random(seed)
    out = []
    for i in range(n):
        cust = rng.choice(CUSTOMERS)
        out.append({
            "order": f"SO-{2024 + rng.randint(0, 2)}-{1000 + i}",
            "customer": cust,
            "amount": rng.randint(1_500, 990_000),      # cents
            "day": rng.randint(0, 1000),
            "status": rng.choice(STATUSES),
        })
    return out


class Net:
    """Local node processes this app spawned (killable/spawnable from the UI)."""

    def __init__(self, tmpdir, base_port=7501):
        self.tmp = tmpdir
        self.base = base_port
        self.procs = {}
        self.lock = threading.Lock()

    def spawn(self, port=None):
        with self.lock:
            port = port or (max(self.procs, default=self.base - 1) + 1)
            seeds = [f"127.0.0.1:{p}" for p, pr in self.procs.items()
                     if pr.poll() is None][:2]
            args = [sys.executable, "-m", "blindrange.node", "--port", str(port),
                    "--data", f"{self.tmp}/n{port}"]
            for s in seeds:
                args += ["--seed", s]
            self.procs[port] = subprocess.Popen(args, cwd=str(ROOT),
                                                stdout=subprocess.DEVNULL,
                                                stderr=subprocess.DEVNULL)
            return f"127.0.0.1:{port}"

    def kill(self, addr):
        port = int(addr.split(":")[1])
        with self.lock:
            p = self.procs.get(port)
            if p and p.poll() is None:
                p.terminate()
                p.wait()
                return True
        return False

    def stop_all(self):
        with self.lock:
            for p in self.procs.values():
                if p.poll() is None:
                    p.terminate()


def wait_http(addr, tries=60):
    for _ in range(tries):
        try:
            urllib.request.urlopen(f"http://{addr}/stats", timeout=1)
            return True
        except OSError:
            time.sleep(0.1)
    return False


def make_handler(owner: Owner, net):
    class Handler(BaseHTTPRequestHandler):
        def _json(self, obj, code=200):
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            url = urlparse(self.path)
            q = parse_qs(url.query)
            if url.path == "/":
                body = UI.encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            elif url.path == "/api/network":
                try:
                    owner.refresh_membership()
                except ConnectionError:
                    pass
                self._json({"nodes": owner.network(),
                            "local": net is not None})
            elif url.path == "/api/nodeview":
                addr = q.get("addr", [None])[0] or owner.ring.addrs[0]
                try:
                    with urllib.request.urlopen(f"http://{addr}/intel?limit=6",
                                                timeout=3) as r:
                        self._json(json.loads(r.read()))
                except OSError:
                    self._json({"addr": addr, "down": True})
            elif url.path == "/api/kill" and net:
                addr = q["addr"][0]
                self._json({"killed": net.kill(addr), "addr": addr})
            elif url.path == "/api/spawn" and net:
                addr = net.spawn()
                ok = wait_http(addr)
                self._json({"spawned": addr, "up": ok})
            else:
                self._json({"error": "unknown"}, 404)

        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            data = json.loads(self.rfile.read(n)) if n else {}
            if urlparse(self.path).path == "/api/query":
                t0 = time.time()
                field = data["field"]
                try:
                    if data.get("prefix") is not None:
                        rows = owner.query_prefix(field, data["prefix"])
                    else:
                        rows = owner.query(field, data["lo"], data["hi"])
                    rows.sort(key=lambda r: r.get("order", ""))
                    self._json({"rows": rows[:200], "total": len(rows),
                                "ms": round((time.time() - t0) * 1000),
                                "stats": owner.last_stats})
                except (ConnectionError, OSError) as e:
                    self._json({"error": str(e)}, 502)
            else:
                self._json({"error": "unknown"}, 404)

        def log_message(self, *a):
            pass

    return Handler


def main():
    ap = argparse.ArgumentParser(description="blindrange sample application")
    ap.add_argument("--port", type=int, default=8600)
    ap.add_argument("--nodes", type=int, default=8,
                    help="local blind nodes to spawn (self-contained mode)")
    ap.add_argument("--bootstrap", action="append", default=[],
                    help="join an existing network instead of spawning one")
    ap.add_argument("--state", default=None, help="owner state file path")
    ap.add_argument("--passphrase", default="demo")
    ap.add_argument("--orders", type=int, default=1000)
    a = ap.parse_args()

    import tempfile
    workdir = Path(tempfile.gettempdir()) / "blindrange_webdemo"
    workdir.mkdir(exist_ok=True)
    state_path = a.state or str(workdir / "owner.brdb")

    net = None
    if a.bootstrap:
        bootstrap = a.bootstrap
    else:
        net = Net(str(workdir))
        first = net.spawn()
        wait_http(first)
        for _ in range(a.nodes - 1):
            net.spawn()
        bootstrap = [first]
        for _ in range(120):                            # wait for gossip to converge
            try:
                with urllib.request.urlopen(f"http://{first}/peers", timeout=2) as r:
                    live = sum(1 for age in json.loads(r.read())["peers"].values()
                               if age <= 12)
                if live >= a.nodes:
                    break
            except OSError:
                pass
            time.sleep(0.25)
        print(f"spawned {a.nodes} local blind nodes (seed {first}, {live} live)")

    if Path(state_path).exists():
        try:
            owner = Owner.open(state_path, a.passphrase, bootstrap=bootstrap)
            print(f"opened existing owner state {state_path}")
        except ValueError:                       # pre-multi-writer state file
            Path(state_path).unlink()
            print("old-format state file removed; reseeding")
    if not Path(state_path).exists():
        owner = Owner.create(state_path, a.passphrase, SCHEMA, bootstrap)
        orders = sample_orders(a.orders)
        t0 = time.time()
        for i in range(0, len(orders), 100):
            owner.insert_many(orders[i:i + 100])
        print(f"seeded {len(orders)} encrypted orders in {time.time()-t0:.1f}s")

    print(f"\n  blindrange demo:  http://127.0.0.1:{a.port}\n")
    try:
        ThreadingHTTPServer(("127.0.0.1", a.port),
                            make_handler(owner, net)).serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        if net:
            net.stop_all()


if __name__ == "__main__":
    main()
