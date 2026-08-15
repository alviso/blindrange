"""Synthetic traffic, so the public network is visibly doing something.

A demo network with no users looks identical to a broken one. This writes,
queries and deletes in a loop so the live figures on
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

Each cycle inserts N records, counts them, and deletes them. Compaction —
the part that actually reclaims space — runs every few cycles rather than
every one, because on the live network inserting 25,000 records took 11s
and compacting them took 565s. Net storage stays flat; what it consumes is
bandwidth, CPU and write capacity.

  python3 examples/heartbeat.py --records 5000
  python3 examples/heartbeat.py --records 2000 --once
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


def cycle(owner, n, field="ts", compact=False):
    """Insert, read, delete, and — periodically — compact.

    Compaction is deliberately NOT every cycle. Measured on the live
    network: 11s to insert 25,000 records and 565s to compact them, so
    compacting each time turns a heartbeat into a compaction stress test
    that is idle 94% of the time. Tombstones are cheap and the space comes
    back on the next sweep, so amortising it keeps the traffic steady and
    the storage curve still flat.
    """
    rng = random.Random()
    t = {}
    rows = [{"ts": rng.randrange(2_592_000), "m": f"hb {rng.randrange(1 << 30)}"}
            for _ in range(n)]

    t0 = time.time()
    owner.insert_many(rows)
    owner.drain()
    t["insert"] = time.time() - t0

    # Full range, so the number logged is meaningful every time. A random
    # window looked fine and quietly reported "0 matched", which reads as a
    # broken read path rather than an unlucky range.
    t0 = time.time()
    t["matched"] = owner.count(field, 0, (1 << 22) - 1)
    t["query"] = time.time() - t0

    t0 = time.time()
    rids = [r["_rid"] for r in owner.query_stream(
        [{"field": field, "lo": 0, "hi": (1 << 22) - 1}], limit=n)]
    for i in range(0, len(rids), 2000):
        owner.delete_many(rids[i:i + 2000])
    t["delete"] = time.time() - t0

    # Compaction is what actually reclaims the space. Without it eventually,
    # this would be a slow storage leak dressed up as a heartbeat.
    t["compact"] = 0.0
    if compact:
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
    ap.add_argument("--records", type=int, default=5_000,
                    help="records per cycle")
    ap.add_argument("--compact-every", type=int, default=5,
                    help="reclaim space every N cycles (0 = never)")
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
            due = a.compact_every and (cycles + 1) % a.compact_every == 0
            t = cycle(owner, a.records, compact=due)
            cycles += 1
            print(f"  cycle {cycles}: insert {t['insert']:.0f}s "
                  f"({a.records / max(t['insert'], 1e-9):,.0f}/s) · "
                  f"count {t['query']:.1f}s ({t['matched']:,} matched) · "
                  f"delete {t['delete']:.0f}s"
                  + (f" · compact {t['compact']:.0f}s" if t['compact'] else ""),
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
