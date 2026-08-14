"""Delete benchmark: how fast can data be removed, and reclaimed?

Deletion here is two distinct operations with very different costs, and it
is worth seeing them separately:

  delete_many()  appends a tombstone per record and removes the ciphertext.
                 Cheap and immediate — the rows stop being returned at once.
  compact()      rewrites the index into a new epoch without the tombstoned
                 entries, then removes the old epoch's keys. This is what
                 actually reclaims space and completes forgetting; it costs
                 a full pass over the label tree.

  python3 examples/bench_delete.py --state my.brdb --bootstrap host:port
"""
import argparse
import json
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from blindrange import Owner  # noqa: E402


def network_keys(bootstrap):
    """Total keys the network reports, to see space actually come back."""
    try:
        with urllib.request.urlopen(f"http://{bootstrap}/stats", timeout=10) as r:
            return json.loads(r.read()).get("keys", 0)
    except OSError:
        return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--state", required=True)
    ap.add_argument("--passphrase", default="pw")
    ap.add_argument("--bootstrap", default="seed.blindrange.dev:7501")
    ap.add_argument("--field", default="ts")
    ap.add_argument("--batch", type=int, default=2000)
    ap.add_argument("--limit", type=int, default=0,
                    help="delete at most this many (0 = everything)")
    ap.add_argument("--no-compact", action="store_true")
    a = ap.parse_args()

    owner = Owner.open(a.state, a.passphrase, bootstrap=[a.bootstrap])
    spec = owner.schema[a.field]
    lo, hi = 0, (1 << spec["bits"]) - 1

    before_keys = network_keys(a.bootstrap)
    t0 = time.time()
    n = owner.count(a.field, lo, hi)
    print(f"\n  {n:,} records · counted in {time.time() - t0:.2f}s "
          f"(no records fetched)")
    print(f"  one node holds {before_keys:,} keys right now")

    print("\n  enumerating record ids …")
    t0 = time.time()
    rids = [r["_rid"] for r in owner.query_stream(
        [{"field": a.field, "lo": lo, "hi": hi}],
        limit=a.limit or None)]
    enum_s = time.time() - t0
    print(f"    {len(rids):,} ids in {enum_s:.1f}s "
          f"({len(rids) / max(enum_s, 1e-9):,.0f} rec/s)")

    print("\n  deleting (tombstone + ciphertext removal) …")
    t0 = time.time()
    done = 0
    for i in range(0, len(rids), a.batch):
        owner.delete_many(rids[i:i + a.batch])
        done += len(rids[i:i + a.batch])
        el = time.time() - t0
        print(f"    {done:>8,} deleted  {el:7.1f}s  {done / el:8,.0f} rec/s",
              flush=True)
    del_s = time.time() - t0
    print(f"  deleted {len(rids):,} in {del_s:.1f}s "
          f"({len(rids) / max(del_s, 1e-9):,.0f} rec/s)")

    t0 = time.time()
    left = owner.count(a.field, lo, hi)
    pending = owner.count_deleted()
    print(f"\n  immediately after: query returns "
          f"{len(list(owner.query_stream([{'field': a.field, 'lo': lo, 'hi': hi}], limit=5)))}"
          f" rows · index still counts {left:,} entries "
          f"({pending:,} tombstoned, reclaimed by compaction)")

    if a.no_compact:
        return
    print("\n  compacting (rewrite without tombstoned entries) …")
    t0 = time.time()
    stats = owner.compact()
    comp_s = time.time() - t0
    after_keys = network_keys(a.bootstrap)
    print(f"    {stats} in {comp_s:.1f}s")
    print(f"  node keys: {before_keys:,} -> {after_keys:,} "
          f"({before_keys - after_keys:+,})")
    print(f"\n  totals: enumerate {enum_s:.0f}s · delete {del_s:.0f}s · "
          f"compact {comp_s:.0f}s\n")


if __name__ == "__main__":
    main()
