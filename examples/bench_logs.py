"""Log-ingest benchmark: how fast can we store, and how fast can we read back
an hour of it?

Writes synthetic log lines and reports where the time actually goes —
client-side crypto versus network — plus the read latency for hour-window
queries, which is the shape a log store is really asked for.

The number that matters most is not the record count, it is the number of
index entries each record creates: `bits - log2(leaf_width)` per indexed
field. Coarser buckets mean fewer entries, so the timestamp's granularity
sets ingest throughput far more than anything else.

  python3 examples/bench_logs.py --records 20000 --nodes 3
  python3 examples/bench_logs.py --records 20000 --granularity 1
"""
import argparse
import random
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from blindrange import Owner  # noqa: E402
from blindrange.dyadic import max_level  # noqa: E402

SERVICES = ["api-gateway", "auth-svc", "billing", "cache", "db-proxy",
            "ingest", "notifier", "scheduler", "search", "worker"]
LEVELS = ["debug", "info", "warn", "error"]
MESSAGES = ["request completed", "cache miss", "retry scheduled",
            "connection reset by peer", "slow query detected",
            "token refreshed", "queue depth high", "checkpoint written"]


def start_nodes(tmp, n, secret):
    procs, ports = [], []
    for i in range(n):
        port = 7901 + i
        args = [sys.executable, "-m", "blindrange.node", "--port", str(port),
                "--data", f"{tmp}/n{port}", "--secret", secret]
        if i:
            args += ["--seed", "127.0.0.1:7901"]
        procs.append(subprocess.Popen(args, cwd=str(ROOT),
                                      stdout=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL))
        ports.append(port)
    deadline = time.time() + 30
    while time.time() < deadline:
        try:
            urllib.request.urlopen("http://127.0.0.1:7901/stats", timeout=1)
            break
        except OSError:
            time.sleep(0.3)
    time.sleep(2 + n * 0.3)                      # let gossip settle
    return procs, ports


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--records", type=int, default=20000)
    ap.add_argument("--nodes", type=int, default=3)
    ap.add_argument("--batch", type=int, default=500)
    ap.add_argument("--granularity", type=int, default=4096,
                    help="timestamp leaf_width in seconds (power of two); "
                         "4096 is about 68 minutes")
    ap.add_argument("--days", type=int, default=30)
    ap.add_argument("--lean", action="store_true",
                    help="index only the timestamp — the cheapest useful log "
                         "schema")
    a = ap.parse_args()

    tmp = tempfile.mkdtemp(prefix="blindrange_bench_")
    secret = "bench"
    procs, _ports = start_nodes(tmp, a.nodes, secret)
    try:
        span = a.days * 86400
        bits = max(1, (span - 1).bit_length())
        schema = {"ts": {"type": "int", "bits": bits,
                         "leaf_width": a.granularity, "kind": "number"}}
        if not a.lean:
            schema["service"] = {"type": "str", "bits": 20, "chars": 4,
                                 "leaf_width": 16, "kind": "text"}
            schema["level"] = {"type": "int", "bits": 2, "leaf_width": 1,
                               "kind": "number"}
        per_record = 1 + sum(max_level(s["bits"], s["leaf_width"])
                             for s in schema.values())
        print(f"\n  {a.records:,} log lines · {a.nodes} nodes · "
              f"{a.days}d span · timestamp buckets of {a.granularity}s "
              f"(~{a.granularity // 60} min)")
        print(f"  index cost: {per_record} keys per record "
              f"(1 blob + {per_record - 1} index entries)")
        print(f"  {'':14}" + " ".join(f"{n}={max_level(s['bits'], s['leaf_width'])}"
                                      for n, s in schema.items()))

        owner = Owner.create(f"{tmp}/logs.brdb", "pw", schema,
                             [f"127.0.0.1:7901"], network_secret=secret)

        rng = random.Random(7)
        rows = [{"ts": rng.randrange(span),
                 "service": rng.choice(SERVICES),
                 "level": rng.randrange(4),
                 "msg": rng.choice(MESSAGES),
                 "host": f"host-{rng.randrange(40):02d}"}
                for _ in range(a.records)]

        print(f"\n  ingesting in batches of {a.batch} …")
        t0 = time.time()
        done = 0
        marks = []
        for i in range(0, len(rows), a.batch):
            owner.insert_many(rows[i:i + a.batch])
            done += len(rows[i:i + a.batch])
            if done % max(a.batch, a.records // 5) == 0 or done == len(rows):
                el = time.time() - t0
                prev_done, prev_el = marks[-1] if marks else (0, 0.0)
                marginal = (done - prev_done) / max(1e-9, el - prev_el)
                marks.append((done, el))
                print(f"    {done:>8,} records  {el:7.1f}s  "
                      f"avg {done / el:7,.0f} rec/s  "
                      f"marginal {marginal:7,.0f} rec/s")
        total = time.time() - t0
        rate = a.records / total

        marginal = ((marks[-1][0] - marks[-2][0]) /
                    (marks[-1][1] - marks[-2][1])) if len(marks) > 1 else rate
        print(f"\n  ingest: {rate:,.0f} rec/s average, "
              f"{marginal:,.0f} rec/s marginal at the end "
              f"({marginal * per_record:,.0f} index writes/s)")
        print("  marginal is the honest number — write rate falls as the "
              "database grows,")
        print("  so an average over the whole run flatters a long ingest.")
        for target, label in ((10, "10 lines/s (small service)"),
                              (100, "100 lines/s (busy service)"),
                              (1000, "1k lines/s (fleet)")):
            verdict = "keeps up" if marginal >= target else "too slow"
            print(f"    vs {label:<28} {verdict}")
        print(f"  1M records would store {1_000_000 * per_record / 1e6:,.1f}M "
              f"keys; at the marginal rate that is "
              f"{1_000_000 / marginal / 60:,.0f}+ min and falling")

        print("\n  reading back — hour windows:")
        for label, width in (("1 hour", 3600), ("6 hours", 6 * 3600),
                             ("1 day", 86400)):
            lo = rng.randrange(0, span - width)
            t0 = time.time()
            got = list(owner.query_stream([{"field": "ts", "lo": lo,
                                            "hi": lo + width}]))
            el = time.time() - t0
            truth = sum(1 for r in rows if lo <= r["ts"] <= lo + width)
            st = owner.last_stats
            ok = "ok" if len(got) >= truth else f"MISSING (want {truth})"
            print(f"    {label:<8} {len(got):>6,} rows in {el:6.2f}s  "
                  f"({st['units']} intervals, {st['batches']} batches)  {ok}")

        t0 = time.time()
        n = owner.count("ts", 0, span)
        print(f"\n  count over everything: {n:,} in {time.time() - t0:.2f}s "
              f"(no records fetched)")

        if "service" in schema:
            t0 = time.time()
            got = list(owner.query_stream([
                {"field": "ts", "lo": 0, "hi": span},
                {"field": "service", "prefix": "auth"}], limit=500))
            print(f"  service prefix 'auth', first 500: {len(got)} rows in "
                  f"{time.time() - t0:.2f}s")
        print()
    finally:
        for p in procs:
            if p.poll() is None:
                p.terminate()
            p.wait()
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
