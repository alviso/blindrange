"""Step 3: bounded-precision queries — the query-watcher bounded BY CONSTRUCTION.

The insight: with a depth-capped index (max_level < bits), there simply are no
tags finer than a bucket. Whatever range a user asks for, the client fetches
whole candidate buckets and filters locally after decryption — so the access
pattern any node (or all of them colluding) can observe is bucket-aligned
automatically. Operator discipline is not required; the leak ceiling is a
property of the index itself.

This demo builds the observable access pattern for capped vs uncapped indexes
and runs the strong maximum-likelihood query-watcher from attack.py against
each. Expected: uncapped -> near-perfect reconstruction; capped with bucket
width W -> mean error pinned near the W/4 floor, no matter how many queries.

  python3 bounded_demo.py
"""
import random
import statistics

import attack                      # reuse the ML attacker + BITS domain
from attack import ml_reconstruction, skewed_ages

BITS = attack.BITS                 # 7 -> ages in [0,128)


def observable_pattern(true_age, workload, width):
    """What colluding nodes SEE for each query when leaves are `width` wide:
    the fetched candidates = every record in every touched bucket."""
    out = []
    for a, b in workload:
        lo = (a // width) * width
        hi = (b // width) * width + width - 1
        fetched = {rid for rid, v in true_age.items() if lo <= v <= hi}
        out.append((lo, hi, fetched))
    return out


def mae(pred, true):
    return statistics.mean(abs(pred[k] - true[k]) for k in true)


def main():
    rng = random.Random(7)
    ages = skewed_ages(rng, 1500)
    true_age = {f"r{i}": a for i, a in enumerate(ages)}
    workload = []
    for _ in range(150):
        a = rng.randint(18, 85)
        workload.append((a, min(90, a + rng.randint(2, 20))))

    print("=" * 68)
    print("BOUNDED-PRECISION QUERIES: the watcher's ceiling is structural")
    print("=" * 68)
    print("\nStrong ML query-watcher vs the access pattern nodes can observe,")
    print("150 queries, 1500 records. floor = best possible = ~W/4:\n")
    print("    leaf width W   observable MAE   theoretical floor")
    for width in (1, 4, 8, 16):
        pattern = observable_pattern(true_age, workload, width)
        rec = ml_reconstruction(true_age, pattern, min(120, len(pattern)))
        floor = sum(abs(v - ((v // width) * width + width // 2))
                    for v in true_age.values()) / len(true_age)
        print(f"    {width:>10}    {mae(rec, true_age):>10.2f} yrs   {floor:>10.2f} yrs")
    print("""
    -> Uncapped (W=1): watching queries reconstructs the column.
       Capped: reconstruction error is PINNED at the bucket floor and
       more queries cannot improve it — there is nothing finer to see.

The dial, stated honestly:
    W = 1   full precision, and a patient watcher recovers the column
    W = 8   watcher stuck at ~2 yrs error forever; queries over-fetch
            ~8x domain resolution, filtered client-side
    W = 16  watcher stuck at ~4 yrs; heavier over-fetch
Pick W per column at schema time. It is a privacy budget you cannot
accidentally overspend, because the index cannot express anything finer.""")


if __name__ == "__main__":
    main()
