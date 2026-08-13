"""The adversary. Measures what a fully-colluding network actually learns.

Ten curious nodes on one laptop = every node colludes = the strongest snapshot
attacker possible (honest-but-curious model). The attacker NEVER holds the key
and NEVER decrypts a payload. Everything below is reconstructed from tags,
volumes, and access patterns alone.

We index a single field (age) so the phenomenon is isolated; extra fields
only give the attacker more per-field leakage plus cross-field correlation.

  python3 attack.py

Runs three attacks (escalating) and two mitigations, each scored against
plaintext ground truth:

  A. Equality leakage      snapshot, NO auxiliary data
  B. Frequency inference   snapshot + a public age distribution   (Naveed-Kamara-Wright)
  E. Range reconstruction  access pattern + known query endpoints (Kellaris et al.)
  C. Mitigation: coarse leaves        (blunts A/B)
  D. Mitigation: volume padding       (blunts B)
"""
import json
import random
import statistics
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

from client import BlindRangeClient

HERE = Path(__file__).parent
PORTS = list(range(7201, 7211))
BITS = 7                       # age domain 0..127
N = 3000


# ----------------------------------------------------------- infrastructure

def wait_ready(port, tries=50):
    for _ in range(tries):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/stats", timeout=1)
            return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"node {port} never came up")


def pull_intel(port):
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/intel", timeout=10) as r:
        return json.loads(r.read())


def skewed_ages(rng, n):
    """A realistic, non-uniform age profile (young + working + retirement humps)."""
    ages = []
    for _ in range(n):
        hump = rng.choices([0, 1, 2], weights=[0.30, 0.45, 0.25])[0]
        mu, sd = [(24, 4), (44, 9), (70, 7)][hump]
        ages.append(max(18, min(90, int(rng.gauss(mu, sd)))))
    return ages


# ------------------------------------------------------------- attack tools

def find_leaves(tags):
    """Given {tag: [ids]}, return the minimal id-sets (the dyadic leaves).
    Nested-interval structure => a leaf is a set with no proper subset among
    the tags. Identical sets (sparse subtrees) collapse to one."""
    sets = [frozenset(ids) for ids in tags.values()]
    uniq = list({s for s in sets})
    leaves = []
    for s in uniq:
        if not any(o < s for o in uniq):      # no proper subset exists -> minimal
            leaves.append(s)
    return leaves


def mae(pred, true):
    return statistics.mean(abs(pred[k] - true[k]) for k in true)


def pct_exact(pred, true):
    return 100.0 * sum(pred[k] == true[k] for k in true) / len(true)


# ---- B/C/D frequency attack, run on an analytical index (verified == nodes)

def frequency_attack(true_age, ref_ages, bucket=1, pad=1):
    """Naveed-Kamara-Wright sorting attack.

    The attacker sees only unlabeled leaf VOLUMES (never which leaf is which
    age) plus an INDEPENDENT public reference population `ref_ages` (e.g. a
    census), and labels each leaf by matching sorted volumes to sorted
    reference counts. Errors come from the reference differing from the target
    and from volume ties. `bucket` models coarser leaves (width in years);
    `pad` models volume padding (volumes rounded up to a multiple of `pad`).
    Returns (recovered_age_by_record, storage_overhead)."""
    # leaves = groups of records sharing a bucket; attacker sees only their sizes
    groups = {}
    for rid, a in true_age.items():
        groups.setdefault(a // bucket, []).append(rid)
    real_vol = {b: len(g) for b, g in groups.items()}
    padded_vol = {b: ((v + pad - 1) // pad) * pad for b, v in real_vol.items()}
    overhead = sum(padded_vol.values()) / sum(real_vol.values())

    # independent public reference, bucketed the same way, sorted by count
    ref = {}
    for a in ref_ages:
        ref[a // bucket] = ref.get(a // bucket, 0) + 1
    ref_sorted = [vb for vb, _ in sorted(ref.items(), key=lambda kv: (-kv[1], kv[0]))]

    # rank leaves by (padded) volume; ties broken by a value-independent hash so
    # padding genuinely destroys the attacker's ability to order within a block
    order = sorted(groups, key=lambda b: (-padded_vol[b],
                                          hash((padded_vol[b], b)) & 0xffff))
    fallback = sorted(ref_ages)[len(ref_ages) // 2] // bucket
    recovered = {}
    for rank, b in enumerate(order):
        value_bucket = ref_sorted[rank] if rank < len(ref_sorted) else fallback
        guess = value_bucket * bucket + bucket // 2      # bucket -> representative age
        for rid in groups[b]:
            recovered[rid] = guess
    return recovered, overhead


# ------------------------------ E: Kellaris known-query range reconstruction

def range_reconstruction(true_age, access_pattern, k):
    """Attacker observes, for the first k range queries [a,b] (endpoints known),
    exactly which records each returned (access pattern). No volumes, no aux
    distribution. Bins records by their inclusion signature and places each bin
    at the midpoint of its feasible interval. Returns recovered age per record."""
    queries = access_pattern[:k]
    recovered = {}
    for rid in true_age:
        lo, hi = 0, (1 << BITS) - 1
        for (a, b, returned) in queries:
            if rid in returned:                       # value in [a,b]
                lo, hi = max(lo, a), min(hi, b)
            else:                                     # value outside [a,b]
                if a <= lo <= b:                      # range abuts lower end
                    lo = max(lo, b + 1)
                if a <= hi <= b:                      # range abuts upper end
                    hi = min(hi, a - 1)
        if lo > hi:
            lo = hi = (lo + hi) // 2
        recovered[rid] = (lo + hi) // 2
    return recovered


def ml_reconstruction(true_age, access_pattern, k):
    """A stronger, noise-tolerant attacker for [F]. For each record it picks the
    value that best agrees with the observed in/out pattern across all k queries
    (maximum agreement). With clean data this is exact; against random decoys it
    denoises by majority. Bitset-accelerated."""
    queries = access_pattern[:k]
    domain = 1 << BITS
    # qin[v] = bitmask of queries whose range contains v
    qin = [0] * domain
    for j, (a, b, _returned) in enumerate(queries):
        bit = 1 << j
        for v in range(a, b + 1):
            qin[v] |= bit
    pc_qin = [bin(m).count("1") for m in qin]         # |queries containing v|
    # r[rid] = bitmask of queries that returned rid
    r = {rid: 0 for rid in true_age}
    for j, (_a, _b, returned) in enumerate(queries):
        bit = 1 << j
        for rid in returned:
            if rid in r:
                r[rid] |= bit
    recovered = {}
    for rid, rmask in r.items():
        best_v, best_score = 0, -1
        for v in range(domain):
            a = bin(qin[v] & rmask).count("1")        # agree on "in"
            score = 2 * a - pc_qin[v]                 # agreements up to a per-record constant
            if score > best_score:
                best_score, best_v = score, v
        recovered[rid] = best_v
    return recovered


# ------------------------------------------------------------------ main

def main():
    print(f"Starting {len(PORTS)} COLLUDING curious nodes (worst case) ...\n")
    procs = [subprocess.Popen([sys.executable, str(HERE / "curious_node.py"), str(p)],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
             for p in PORTS]
    try:
        for p in PORTS:
            wait_ready(p)

        rng = random.Random(7)
        ages = skewed_ages(rng, N)
        records = [{"age": a, "row": i} for i, a in enumerate(ages)]

        schema = {"age": {"type": "int", "bits": BITS, "max_level": BITS}}  # exact leaves
        client = BlindRangeClient(b"only-the-owner-knows-this-key!!!", PORTS, schema)
        rids = client.insert_many(records)
        true_age = {rid: a for rid, a in zip(rids, ages)}

        # a realistic query workload, endpoints known to the attacker; each query
        # actually runs against the nodes (logged in their query_log)
        workload = []
        for _ in range(120):
            a = rng.randint(18, 85)
            b = min(90, a + rng.randint(2, 20))
            client.query("age", a, b)
            workload.append((a, b))
            time.sleep(0.005)
        # the colluding network's access pattern == which records each query
        # returned (== union of the nodes' /lookup hits for that query)
        access_pattern = [(a, b, {rid for rid in true_age if a <= true_age[rid] <= b})
                          for (a, b) in workload]

        intel = [pull_intel(p) for p in PORTS]
        merged_tags = {}
        total_lookups = 0
        for it in intel:
            merged_tags.update(it["tags"])
            total_lookups += len(it["query_log"])

        print("=" * 68)
        print(f"What the colluding network holds: {len(merged_tags)} opaque tags, "
              f"{sum(it['n_records'] for it in intel)} ciphertexts,")
        print(f"and a log of {total_lookups} tag-lookups across the {len(PORTS)} nodes.")
        print("It has no key. It has decrypted nothing.")
        print("=" * 68)

        # ---- Attack A: equality leakage (snapshot, NO auxiliary data) --------
        leaves = find_leaves(merged_tags)
        leaf_of = {}
        for i, leaf in enumerate(leaves):
            for rid in leaf:
                leaf_of[rid] = i
        # purity: does each recovered group hold exactly one true age?
        pure = 0
        for leaf in leaves:
            if len({true_age[r] for r in leaf}) == 1:
                pure += 1
        placed = sum(1 for r in true_age if r in leaf_of)
        print("\n[A] EQUALITY LEAKAGE  (snapshot only, no auxiliary data)")
        print(f"    Recovered {len(leaves)} value-groups from {placed}/{len(true_age)} records; "
              f"{pure}/{len(leaves)} are single-age pure.")
        print("    -> The network cannot read ages, but learns EXACTLY which")
        print("       records share an age, and each group's size. Values are")
        print("       NOT recovered here — that needs the auxiliary data in [B].")

        # verify analytical index matches node reality (leaf volume multiset)
        node_leaf_vols = sorted(len(l) for l in leaves)
        hist = {}
        for a in ages:
            hist[a] = hist.get(a, 0) + 1
        assert node_leaf_vols == sorted(hist.values()), "analytical model != node contents"

        # ---- Attack B: frequency inference (snapshot + public distribution) --
        # independent public reference populations (a "census" the attacker holds)
        ref_skewed = skewed_ages(random.Random(99), 20000)
        rec_b, _ = frequency_attack(true_age, ref_skewed, bucket=1, pad=1)
        print("\n[B] FREQUENCY INFERENCE  (snapshot + public age distribution; NKW'15)")
        print(f"    Skewed real-world ages:   MAE {mae(rec_b, true_age):5.2f} yrs, "
              f"{pct_exact(rec_b, true_age):5.1f}% recovered EXACTLY.")
        # honest control: same attack on a uniform column barely works
        urng = random.Random(1)
        uni = {rid: urng.randint(18, 90) for rid in true_age}
        ref_uni = [random.Random(2).randint(18, 90) for _ in range(20000)]
        rec_u, _ = frequency_attack(uni, ref_uni, bucket=1, pad=1)
        print(f"    Uniform control column:   MAE {mae(rec_u, uni):5.2f} yrs, "
              f"{pct_exact(rec_u, uni):5.1f}% exact  (flat frequencies => attack starves).")
        print("    -> Leakage of VALUES depends on how skewed the data is.")

        # ---- Attack E: range reconstruction (access pattern + known queries) -
        print("\n[E] RANGE RECONSTRUCTION  (access pattern + known query endpoints; Kellaris'16)")
        print("    No auxiliary distribution, no volumes — only which records")
        print("    each known range-query returned:")
        for k in (10, 30, 60, 120):
            rec_e = range_reconstruction(true_age, access_pattern, k)
            print(f"      after {k:3d} queries:  MAE {mae(rec_e, true_age):5.2f} yrs, "
                  f"{pct_exact(rec_e, true_age):5.1f}% exact")
        print("    -> Watching enough range queries reconstructs the axis. This is")
        print("       the cost of server-side ranges, and volume-hiding does NOT stop it.")

        # ---- Mitigation C: coarser leaves (cap max_level) --------------------
        # The guarantee coarse leaves buy is a RESOLUTION FLOOR: even a perfect
        # attacker who knows exactly which leaf is which can only localize a
        # value to within one leaf. We measure that best case (a lower bound on
        # everyone's error), so it's clean and monotonic.
        print("\n[C] MITIGATION - coarse leaves: best-case resolution floor")
        for width in (1, 4, 8, 16):
            floor = {rid: (a // width) * width + width // 2
                     for rid, a in true_age.items()}
            groups = len({a // width for a in true_age.values()})
            print(f"      leaf width {width:2d} yrs:  floor MAE {mae(floor, true_age):5.2f} yrs, "
                  f"{groups:2d} distinguishable groups (was 71)")
        print("    -> Wider leaves bound EVERY snapshot attacker's precision and")
        print("       shrink the index, at the cost of client-side over-fetch.")
        print("       (They also cap the query-watcher [E] structurally, because")
        print("        fetches are whole buckets — measured in bounded_demo.py.")
        print("        [E] below is the uncapped W=1 worst case.)")

        # ---- Mitigation D: volume padding ------------------------------------
        print("\n[D] MITIGATION - volume padding (quantize group sizes)  vs frequency attack [B]")
        for pad in (1, 10, 50, 200):
            rec_d, ov = frequency_attack(true_age, ref_skewed, bucket=1, pad=pad)
            print(f"      pad to /{pad:3d}:  MAE {mae(rec_d, true_age):5.2f} yrs, "
                  f"{pct_exact(rec_d, true_age):5.1f}% exact,  storage x{ov:.2f}")
        print("    -> Padding blurs the frequency signal [B] but does nothing for")
        print("       access-pattern reconstruction [E].")

        # ---- Defense F: access-pattern hiding vs the query-watcher [E] --------
        # Two ways to blur which records a query really returned, both measured
        # against the stronger noise-tolerant attacker (ml_reconstruction).
        drng = random.Random(5)
        all_ids = list(true_age)
        print("\n[F] DEFENSE - blurring access pattern vs the query-watcher [E]  (120 queries)")

        base = mae(ml_reconstruction(true_age, access_pattern, 120), true_age)
        print(f"    no defense:                       MAE {base:5.2f} yrs")

        print("    (i) random decoys - add false positives to every result:")
        for alpha in (0.5, 2.0, 5.0):
            noisy = []
            for (a, b, returned) in access_pattern:
                n_decoy = int(len(returned) * alpha)
                decoys = set(drng.sample(all_ids, min(n_decoy, len(all_ids))))
                noisy.append((a, b, returned | decoys))
            m = mae(ml_reconstruction(true_age, noisy, 120), true_age)
            print(f"        decoy rate x{alpha:<4}  (bandwidth x{1+alpha:.1f}):  MAE {m:5.2f} yrs")
        print("      -> a patient attacker denoises light/moderate decoys; only a")
        print("         heavy 6x-bandwidth rate finally bites. Expensive per bit of")
        print("         protection — coarse queries below buy the same far cheaper.")

        print("    (ii) coarse queries - snap every query to fixed W-wide buckets:")
        for W in (4, 8, 16):
            snapped = [((a // W) * W, (b // W) * W + W - 1,
                        {rid for rid in true_age
                         if (a // W) * W <= true_age[rid] <= (b // W) * W + W - 1})
                       for (a, b, _r) in access_pattern]
            m = mae(ml_reconstruction(true_age, snapped, 120), true_age)
            print(f"        bucket width {W:2d}:  MAE {m:5.2f} yrs")
        print("      -> consistent coarsening DOES bound [E] (to ~W/4), because the")
        print("         attacker can no longer resolve inside a bucket. Costs precision.")

        print("\n" + "=" * 68)
        print("Takeaway: payload confidentiality holds (no key, no decryption).")
        print("What leaks is metadata — equality always; values under a skewed")
        print("distribution [B] or a persistent query-watcher [E]. Coarse leaves")
        print("+ padding bound [B]; bounding [E] needs access-pattern hiding")
        print("(decoy results / query budgets), the known hard part.")
        print("=" * 68)
    finally:
        for pr in procs:
            pr.terminate()


if __name__ == "__main__":
    main()
