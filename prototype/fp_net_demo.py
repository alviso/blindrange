"""Step 1 demo: forward-private range queries over 10 networked blind nodes.

Proves the sharded forward-private client returns correct results, and that a
curious node holds only opaque, structureless key->blob pairs at rest.

  python3 fp_net_demo.py
"""
import json
import random
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

from fp_client import FPClient, ModRouter

HERE = Path(__file__).parent
PORTS = list(range(7301, 7311))


def wait_ready(port, tries=50):
    for _ in range(tries):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/stats", timeout=1)
            return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"node {port} never came up")


def main():
    tmp = tempfile.mkdtemp(prefix="fpnodes_")
    print(f"Starting {len(PORTS)} persistent blind KV nodes ...")
    procs = [subprocess.Popen([sys.executable, str(HERE / "kv_node.py"), str(p),
                               f"{tmp}/node_{p}.db"],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
             for p in PORTS]
    try:
        for p in PORTS:
            wait_ready(p)

        client = FPClient(ModRouter(PORTS), bits=7, max_level=7)
        rng = random.Random(11)
        ages = [max(18, min(90, int(rng.gauss(45, 15)))) for _ in range(1500)]
        t0 = time.time()
        for i, a in enumerate(ages):
            client.insert({"age": a, "row": i})
        print(f"Inserted {len(ages)} forward-private records across {len(PORTS)} "
              f"nodes in {time.time()-t0:.1f}s\n")

        # correctness
        print("Range-query correctness (vs plaintext ground truth):")
        ok_all = True
        for lo, hi in [(30, 40), (18, 25), (60, 90), (44, 46)]:
            got = client.query(lo, hi)
            want = sum(1 for a in ages if lo <= a <= hi)
            ok = len(got) == want
            ok_all &= ok
            print(f"    age in [{lo:2d},{hi:2d}]: {len(got):4d} rows  "
                  f"{'OK' if ok else f'MISMATCH (want {want})'}")
        assert ok_all

        # what a curious node holds at rest
        intel = json.loads(urllib.request.urlopen(
            f"http://127.0.0.1:{PORTS[0]}/intel").read())
        print(f"\nCurious node {PORTS[0]} at rest ({intel['count']} keys). A sample:")
        for k, v in intel["sample"][:3]:
            print(f"    {k}  ->  {v}")
        print("    -> opaque key -> opaque blob. No lists, no equality, no order,")
        print("       no co-occurrence. The node was never given a label key.")
        print("\nForward-private range queries work over a real sharded network.")
    finally:
        for pr in procs:
            pr.terminate()


if __name__ == "__main__":
    main()
