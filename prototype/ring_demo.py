"""Step 2 demo: consistent hashing + replication + persistence.

Shows the forward-private store (1) spreads keys evenly across a hash ring,
(2) keeps answering correctly after nodes are killed (read failover to
replicas), and (3) survives a node restart (SQLite on disk).

  python3 ring_demo.py
"""
import random
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

from fp_client import FPClient
from ring import Ring

HERE = Path(__file__).parent
PORTS = list(range(7401, 7411))
REPLICAS = 3


def wait_ready(port, tries=50):
    for _ in range(tries):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/stats", timeout=1)
            return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"node {port} never came up")


def node_keys(port):
    import json
    return json.loads(urllib.request.urlopen(
        f"http://127.0.0.1:{port}/stats").read())["keys"]


def start_node(port, db):
    return subprocess.Popen([sys.executable, str(HERE / "kv_node.py"), str(port), db],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def main():
    tmp = tempfile.mkdtemp(prefix="ringnodes_")
    dbs = {p: f"{tmp}/node_{p}.db" for p in PORTS}
    print(f"Starting {len(PORTS)} persistent nodes, replication factor {REPLICAS} ...")
    procs = {p: start_node(p, dbs[p]) for p in PORTS}
    try:
        for p in PORTS:
            wait_ready(p)

        ring = Ring(PORTS, vnodes=64, replicas=REPLICAS)
        client = FPClient(ring, bits=7, max_level=7)
        rng = random.Random(3)
        ages = [max(18, min(90, int(rng.gauss(45, 15)))) for _ in range(1200)]
        for i, a in enumerate(ages):
            client.insert({"age": a, "row": i})

        # (1) balance across the ring
        loads = sorted(node_keys(p) for p in PORTS)
        print(f"\n[1] Key balance across ring: min {loads[0]}, median "
              f"{loads[len(loads)//2]}, max {loads[-1]} keys/node "
              f"(each key on {REPLICAS} nodes).")

        def check(label):
            got = len(client.query(30, 40))
            want = sum(1 for a in ages if 30 <= a <= 40)
            print(f"    {label}: age in [30,40] -> {got} rows "
                  f"{'OK' if got == want else f'MISMATCH (want {want})'}")
            return got == want

        print("\n[2] Fault tolerance (read failover to replicas):")
        assert check("all nodes up")
        for victim in (PORTS[2], PORTS[5]):        # kill 2 of 10
            procs[victim].terminate()
            procs[victim].wait()
            print(f"    killed node {victim}")
        assert check("2 nodes down"), "replication should have covered the gap"

        print("\n[3] Persistence (restart a node from disk):")
        victim = PORTS[7]
        before = node_keys(victim)
        procs[victim].terminate()
        procs[victim].wait()
        print(f"    stopped node {victim} (held {before} keys)")
        procs[victim] = start_node(victim, dbs[victim])
        wait_ready(victim)
        after = node_keys(victim)
        print(f"    restarted node {victim} -> {after} keys recovered from disk "
              f"{'OK' if after == before else 'LOST DATA'}")
        assert after == before
        assert check("after restart")

        print("\nConsistent hashing + replication + persistence: all green.")
    finally:
        for pr in procs.values():
            if pr.poll() is None:
                pr.terminate()


if __name__ == "__main__":
    main()
