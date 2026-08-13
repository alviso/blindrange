"""End-to-end demo: 10 blind nodes, one key-holding client.

  python3 demo.py

Spawns 10 node processes (ports 7101-7110), inserts 2,000 encrypted
records, runs range/prefix queries, checks every result set against
plaintext ground truth, and shows what a node operator actually sees.
"""
import json
import random
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

from client import BlindRangeClient

HERE = Path(__file__).parent
PORTS = list(range(7101, 7111))

SCHEMA = {
    # age 0..127: exact leaves — every value has its own level-7 tag
    "age":    {"type": "int", "bits": 7,  "max_level": 7},
    # salary 0..2^20 (~1M): depth capped at 12 -> leaf buckets of 256.
    # Cheaper + leaks less; client post-filters the over-fetch.
    "salary": {"type": "int", "bits": 20, "max_level": 12},
    # name: first 4 chars, 5 bits each -> 20-bit ordered domain
    "name":   {"type": "str", "bits": 20, "max_level": 20, "chars": 4},
}

FIRST = ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi",
         "ivan", "judy", "mallory", "niaj", "olivia", "peggy", "quentin",
         "rupert", "sybil", "trent", "ursula", "victor", "walter", "smith",
         "smythe", "small", "sanders", "santos", "schmidt", "stone"]


def wait_ready(port, tries=50):
    for _ in range(tries):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/stats", timeout=1)
            return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"node on {port} never came up")


def main():
    print(f"Starting {len(PORTS)} blind nodes on ports {PORTS[0]}-{PORTS[-1]} ...")
    procs = [subprocess.Popen([sys.executable, str(HERE / "node.py"), str(p)],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
             for p in PORTS]
    try:
        for p in PORTS:
            wait_ready(p)

        rng = random.Random(42)
        people = [{"name": rng.choice(FIRST) + str(i),
                   "age": rng.randint(18, 90),
                   "salary": rng.randint(20_000, 250_000)}
                  for i in range(2000)]

        client = BlindRangeClient(b"only-the-owner-knows-this-key!!!", PORTS, SCHEMA)

        t0 = time.time()
        client.insert_many(people)
        print(f"Inserted {len(people)} encrypted records in {time.time()-t0:.1f}s\n")

        # ---- what does a node operator see? ------------------------
        with urllib.request.urlopen(f"http://127.0.0.1:{PORTS[0]}/dump?limit=3") as r:
            dump = json.loads(r.read())
        with urllib.request.urlopen(f"http://127.0.0.1:{PORTS[0]}/stats") as r:
            stats = json.loads(r.read())
        print(f"=== Node {PORTS[0]}'s complete world view "
              f"({stats['tags']} tags, {stats['records']} ciphertexts) ===")
        for tag, rids in dump["tags_sample"].items():
            print(f"  tag {tag}  ->  {len(rids)} record id(s), e.g. {rids[0]}")
        for rid, ct in dump["records_sample"].items():
            print(f"  record {rid}  ->  {ct}")
        print("  (no key, no order, no plaintext — exact-match lookups only)\n")

        # ---- range queries, verified against ground truth ----------
        def check(label, got, want_pred):
            want = [p for p in people if want_pred(p)]
            ok = sorted(r["name"] for r in got) == sorted(p["name"] for p in want)
            s = client.last_stats
            print(f"{label}")
            print(f"  -> {len(got)} rows ({'CORRECT' if ok else 'MISMATCH vs ground truth!'})   "
                  f"cover={s['cover_intervals']} tags, {s['candidates_fetched']} fetched, "
                  f"{s['overfetch']} over-fetch filtered client-side")
            if not ok:
                sys.exit(1)

        check("age BETWEEN 30 AND 40",
              client.query("age", 30, 40), lambda p: 30 <= p["age"] <= 40)

        check("salary BETWEEN 100000 AND 120000   (capped tree: leaves=256 wide)",
              client.query("salary", 100_000, 120_000),
              lambda p: 100_000 <= p["salary"] <= 120_000)

        check("name BETWEEN 'sa' AND 'sz' (alphanumeric range)",
              client.query("name", "sa", "sz~"),
              lambda p: "sa" <= p["name"][:4] <= "sz~~")

        check("name LIKE 'sm%' (prefix as range)",
              client.query_prefix("name", "sm"),
              lambda p: p["name"].startswith("sm"))

        t0 = time.time()
        client.query("age", 25, 65)
        print(f"\nwide query (age 25-65) round-trip: {(time.time()-t0)*1000:.0f} ms "
              f"across {len(PORTS)} nodes")
        print("\nAll queries verified against plaintext ground truth.")
    finally:
        for pr in procs:
            pr.terminate()


if __name__ == "__main__":
    main()
