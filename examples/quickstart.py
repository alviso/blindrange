"""Every operation you need to build something, in one runnable file.

This is the code the guide at https://blindrange.dev/build quotes. It is a
script rather than a snippet collection so that the samples cannot drift
from what actually works: if this stops running, the guide is wrong, and
tests/test_quickstart.py fails.

    python3 examples/quickstart.py                     # the public network
    python3 examples/quickstart.py --bootstrap 127.0.0.1:7501 --secret mine

It creates a small orders database, writes to it, reads it back every way
the API supports, changes a record, deletes one, reclaims the space, and
then shows what the machines storing all of it can actually see. It cleans
up after itself unless you pass --keep.
"""
import argparse
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from blindrange import Owner  # noqa: E402


def step(n, title):
    print(f"\n\033[36m{n}. {title}\033[0m", flush=True)


def main():
    ap = argparse.ArgumentParser(description="blindrange in one file")
    ap.add_argument("--state", default="/tmp/blindrange-quickstart.brdb")
    ap.add_argument("--passphrase", default="quickstart passphrase")
    ap.add_argument("--bootstrap", default="seed.blindrange.dev:7501")
    ap.add_argument("--secret", default="blindrange-public")
    ap.add_argument("--keep", action="store_true",
                    help="leave the database on the network afterwards")
    a = ap.parse_args()

    # ---------------------------------------------------------------- 1
    step(1, "Describe your data")
    # `bits` is the size of the value domain: 2**20 covers amounts up to
    # about a million. `leaf_width` is the resolution the network can
    # distinguish — the ONLY number here with a privacy consequence.
    #
    # Queries are answered by fetching whole buckets of `leaf_width`, so no
    # observer can localise a value more precisely than that, however many
    # queries it watches. Coarser is cheaper AND more private; the cost of
    # fine resolution is paid in both.
    schema = {
        "amount": {"type": "int", "bits": 20, "leaf_width": 64},
        "day":    {"type": "int", "bits": 16, "leaf_width": 16},
        # A text field is indexed by its first `chars` characters, encoded
        # at 5 bits each into an ordered code. That is what makes prefix
        # search work — and it is the whole truth about what the index
        # holds: an ordered code for a prefix, never the string.
        "status": {"type": "str", "bits": 30, "chars": 6, "leaf_width": 16},
    }
    for f, spec in schema.items():
        print(f"   {f:<8} {spec}")

    # ---------------------------------------------------------------- 2
    step(2, "Create the database")
    # The passphrase never leaves this process. It unlocks a local state
    # file holding the master key; every index key on the network is an
    # HMAC under that key, so nodes see pseudorandom labels and nothing
    # else. Losing the state file AND the passphrase loses the data — no
    # one can recover it for you, which is the point.
    # Named locals rather than a.state / a.passphrase, because these lines
    # are quoted in the guide and argparse attribute names teach nobody
    # anything.
    state_path = a.state                  # local file; your keys live here
    passphrase = a.passphrase             # unlocks it; never leaves this box
    bootstrap = [a.bootstrap]             # any live peer, to find the rest
    network_secret = a.secret             # which network you are joining

    if os.path.exists(state_path):
        # No schema and no secret on reopen: both are inside the state file.
        db = Owner.open(state_path, passphrase, bootstrap=bootstrap)
        print(f"   reopened {state_path}")
    else:
        db = Owner.create(state_path, passphrase, schema,
                          bootstrap=bootstrap,
                          network_secret=network_secret)
        print(f"   created {state_path} · joined via {a.bootstrap}")
    print(f"   {len(db.network())} nodes visible")

    # ---------------------------------------------------------------- 3
    step(3, "CREATE — write records")
    rows = [{"amount": 100 + (i * 37) % 900, "day": 200 + i % 30,
             "status": "paid" if i % 3 else "refunded",
             "customer": f"cust-{i:03d}"} for i in range(120)]
    t0 = time.time()
    db.insert_many(rows)
    # insert_many returns as soon as a quorum of replicas has each key.
    # drain() waits for the rest — call it before you measure anything or
    # before the process exits, not after every insert.
    db.drain()
    print(f"   {len(rows)} records in {time.time() - t0:.2f}s")

    # ---------------------------------------------------------------- 4
    step(4, "READ — range, prefix, and AND")
    hits = db.query("amount", 300, 500)
    print(f"   amount 300..500          → {len(hits)} rows")

    prefix = db.query_prefix("status", "ref")
    print(f"   status prefix 'ref'      → {len(prefix)} rows")

    both = db.query_multi([{"field": "amount", "lo": 300, "hi": 500},
                           {"field": "day", "lo": 200, "hi": 210}])
    print(f"   amount AND day           → {len(both)} rows")

    # Large results stream in bounded memory. `order="-field"` walks the
    # range from the top, which is what you want for "the most recent N":
    # ascending would pay for every bucket in the range before reaching
    # the end you asked about.
    newest = list(db.query_stream([{"field": "day", "lo": 0, "hi": 65535}],
                                  limit=5, order="-day"))
    print(f"   newest 5 by day          → {[r['day'] for r in newest]}")

    # ---------------------------------------------------------------- 5
    step(5, "READ — answers without decrypting anything")
    # These come from index metadata alone. Nothing is fetched, nothing is
    # decrypted, and the cost does not grow with the number of matches.
    print(f"   count(amount 300..500)   → {db.count('amount', 300, 500)}")
    bars = db.histogram("amount", 0, 1023, buckets=4)
    print(f"   histogram                → "
          f"{[(b['lo'], b['count']) for b in bars]}")
    # Note it returns the error WITH the estimate. Each bucket contributes
    # count x midpoint, so the per-record error is at most leaf_width/2 —
    # the resolution you traded away for privacy is exactly the error bar,
    # and the API refuses to hand you the number without it.
    est, err, n = db.approx_sum("amount", 0, 1023)
    print(f"   approx_sum(amount)       → {est:,.0f} ± {err:,.0f} "
          f"over {n} rows")

    # ---------------------------------------------------------------- 6
    step(6, "UPDATE — there isn't one, and here is why")
    # A record is one sealed blob under a random handle. There is no
    # in-place edit: you delete the old handle and insert a new record.
    # Anything else would need the node to modify ciphertext it cannot
    # read. Do it in that order and a crash between the two costs you a
    # duplicate, not a hole.
    victim = hits[0]
    changed = {k: v for k, v in victim.items() if not k.startswith("_")}
    changed["status"] = "refunded"
    db.delete_many([victim["_rid"]])
    db.insert_many([changed])
    db.drain()
    print(f"   {victim['customer']}: {victim['status']} → {changed['status']}")

    # ---------------------------------------------------------------- 7
    step(7, "DELETE — and actually reclaiming the space")
    doomed = [r["_rid"] for r in db.query("amount", 900, 1023)]
    db.delete_many(doomed)
    db.drain()
    print(f"   deleted {len(doomed)} rows — gone from queries immediately")
    # A delete writes a tombstone: the record stops being returned at once,
    # but its index entries are still out there and still counted, which is
    # why count() can exceed what queries return. compact() is what rewrites
    # the index and reclaims the space — the only operation that forgets.
    print(f"   count() still says       → {db.count('amount', 900, 1023)}"
          f"  (tombstoned, not yet reclaimed)")
    stats = db.compact()
    # These are INDEX entries, not records: a record costs one entry per
    # dyadic level per indexed field, which is where storage amplification
    # comes from and why coarse leaf_width is cheaper.
    print(f"   compact()                → kept {stats['entries']:,} index "
          f"entries, dropped {stats['dropped']:,}")
    print(f"   count() now says         → {db.count('amount', 900, 1023)}")

    # ---------------------------------------------------------------- 8
    step(8, "What the machines storing this can see")
    for n in db.network():
        addr = n.get("addr")
        if not addr or n.get("down"):
            continue
        try:
            intel = db._get(addr, "/intel?limit=2")
        except Exception as e:
            print(f"   {addr}: {type(e).__name__}")
            continue
        for pair in (intel.get("sample") or [])[:2]:
            try:
                k, v = pair
            except (TypeError, ValueError):
                continue
            print(f"   {k[:34]}  →  {str(v)[:24]}")
        break
    print("   no field names, no values, no ordering — and none of the")
    print("   customer ids above appear anywhere on any node")

    if not a.keep:
        step(9, "Clean up")
        db.drop(confirm=True)
        os.path.exists(a.state) and os.remove(a.state)
        print("   database removed from the network")
    else:
        print(f"\n   kept: {a.state}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
