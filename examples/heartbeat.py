"""Synthetic traffic, so the public network is visibly doing something.

A demo network with no users looks identical to a broken one. This writes,
queries, deletes and compacts in a loop so the live figures on
blindrange.dev move — and so the whole path stays continuously exercised
rather than only when someone remembers to run a benchmark.

IT IS SYNTHETIC AND MUST ALWAYS BE LABELLED AS SUCH. On a site whose entire
argument is that the disclosures are honest, presenting traffic we generate
ourselves as evidence of adoption would be the one lie that discredits
everything else on the page. The status server marks it, the homepage says
it in the panel, and this docstring exists so nobody removes those later
thinking they are clutter.

What it is genuinely good for:

  * liveness — a network that is writing, reading and deleting right now is
    provably not a screenshot
  * exercise — every cycle runs the real path (tokens, replication, dyadic
    index, tombstones, compaction), so breakage shows up in hours rather
    than the next time someone demos
  * honest cost — it churns, so the storage curve stays flat instead of
    climbing forever, and the token spend is visible

Each cycle inserts N records, queries them, deletes them, and compacts so
the space actually comes back. Net storage over a cycle is ~zero; what it
consumes is bandwidth, CPU and write capacity.

  python3 examples/heartbeat.py --records 100000
  python3 examples/heartbeat.py --records 5000 --once
"""
import argparse
import os
import random
import signal
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from blindrange import Owner  # noqa: E402

STOP = False


def _stop(*_):
    global STOP
    STOP = True
    print("  finishing the current cycle, then stopping", flush=True)


def cycle(owner, n, field="ts", verbose=True):
    """Insert, read, delete, compact. Returns per-phase seconds."""
    rng = random.Random()
    t = {}
    rows = [{"ts": rng.randrange(2_592_000), "m": f"hb {rng.randrange(1 << 30)}"}
            for _ in range(n)]

    t0 = time.time()
    owner.insert_many(rows)
    owner.drain()
    t["insert"] = time.time() - t0

    t0 = time.time()
    lo = rng.randrange(2_000_000)
    got = owner.count(field, lo, lo + 500_000)
    t["query"] = time.time() - t0
    t["matched"] = got

    t0 = time.time()
    rids = [r["_rid"] for r in owner.query_stream(
        [{"field": field, "lo": 0, "hi": (1 << 22) - 1}], limit=n)]
    for i in range(0, len(rids), 2000):
        owner.delete_many(rids[i:i + 2000])
    t["delete"] = time.time() - t0

    # Compaction is what actually reclaims the space. Without it this would
    # be a slow storage leak dressed up as a heartbeat.
    t0 = time.time()
    owner.compact()
    t["compact"] = time.time() - t0
    return t


def main():
    ap = argparse.ArgumentParser(description="synthetic load for the demo network")
    ap.add_argument("--state", default=os.path.expanduser("~/.blindrange/heartbeat.brdb"))
    ap.add_argument("--passphrase", default=os.environ.get("BR_HB_PASS", "heartbeat"))
    ap.add_argument("--bootstrap", default="127.0.0.1:7501")
    ap.add_argument("--secret", default="blindrange-public")
    ap.add_argument("--issuer", default="https://tokens.blindrange.dev")
    ap.add_argument("--account", default=os.environ.get("BR_ACCOUNT", ""))
    ap.add_argument("--records", type=int, default=10_000,
                    help="records per cycle")
    ap.add_argument("--pause", type=float, default=30.0,
                    help="seconds between cycles")
    ap.add_argument("--once", action="store_true")
    a = ap.parse_args()

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    if os.path.exists(a.state):
        owner = Owner.open(a.state, a.passphrase, bootstrap=[a.bootstrap])
    else:
        owner = Owner.create(a.state, a.passphrase,
                             {"ts": {"type": "int", "bits": 22,
                                     "leaf_width": 4096}},
                             bootstrap=[a.bootstrap], network_secret=a.secret)
    if a.account:
        owner.configure_tokens(a.issuer, a.account)

    print(f"heartbeat: {a.records:,} records per cycle, {a.pause}s pause — "
          f"SYNTHETIC traffic, label it as such wherever it is shown",
          flush=True)
    cycles = 0
    while not STOP:
        try:
            t = cycle(owner, a.records)
            cycles += 1
            print(f"  cycle {cycles}: insert {t['insert']:.0f}s "
                  f"({a.records / max(t['insert'], 1e-9):,.0f}/s) · "
                  f"count {t['query']:.1f}s ({t['matched']:,} matched) · "
                  f"delete {t['delete']:.0f}s · compact {t['compact']:.0f}s",
                  flush=True)
        except Exception as e:
            # Never die on one bad cycle: this runs unattended, and a
            # transient network fault should cost one cycle, not the
            # heartbeat. Say what happened, wait longer, carry on.
            print(f"  cycle failed: {type(e).__name__}: {str(e)[:160]}",
                  file=sys.stderr, flush=True)
            time.sleep(min(a.pause * 4, 300))
            continue
        if a.once:
            break
        for _ in range(int(a.pause)):
            if STOP:
                break
            time.sleep(1)
    print(f"  stopped after {cycles} cycle(s)", flush=True)


if __name__ == "__main__":
    main()
