"""Sharding must be invisible in results and visible only in scale.

Everything here compares a sharded database against a single one holding
the same rows. If any query answers differently, the abstraction is a lie
and the scaling it buys is worthless.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from blindrange import Owner                       # noqa: E402
from blindrange.sharded import ShardedOwner, index_keys, shard_of  # noqa: E402

SCHEMA = {"amount": {"type": "int", "bits": 20, "leaf_width": 64},
          "day": {"type": "int", "bits": 16, "leaf_width": 16}}
PORT = 7771
SECRET = "shardnet"


def wait_http(addr, tries=80):
    for _ in range(tries):
        try:
            urllib.request.urlopen(f"http://{addr}/stats", timeout=1)
            return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"{addr} never came up")


class ShardingCase(unittest.TestCase):
    """One local node, one plain owner and one sharded owner over it."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="blindrange_shard_")
        cls.proc = subprocess.Popen(
            [sys.executable, "-m", "blindrange.node", "--port", str(PORT),
             "--data", f"{cls.tmp}/node", "--secret", SECRET],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            cwd=str(ROOT), env={**os.environ})
        cls.addr = f"127.0.0.1:{PORT}"
        wait_http(cls.addr)

        cls.rows = [{"amount": (i * 37) % 4096, "day": i % 900,
                     "note": f"row {i}"} for i in range(240)]

        cls.plain = Owner.create(f"{cls.tmp}/plain.brdb", "pw", SCHEMA,
                                 [cls.addr], network_secret=SECRET)
        cls.plain.insert_many(cls.rows)
        cls.plain.drain()

        cls.sharded = ShardedOwner.create(f"{cls.tmp}/shards", "pw", SCHEMA,
                                          [cls.addr], shards=4,
                                          network_secret=SECRET)
        cls.sharded.insert_many(cls.rows)
        cls.sharded.drain()

    @classmethod
    def tearDownClass(cls):
        cls.proc.kill()
        shutil.rmtree(cls.tmp, ignore_errors=True)


class TestSameAnswers(ShardingCase):
    def test_range_query_matches_a_single_database(self):
        want = sorted(r["note"] for r in self.plain.query("amount", 100, 2000))
        got = sorted(r["note"] for r in self.sharded.query("amount", 100, 2000))
        self.assertEqual(got, want)
        self.assertTrue(want, "the fixture matched nothing; test proves little")

    def test_count_matches(self):
        for lo, hi in ((0, 4095), (100, 2000), (4000, 4095)):
            self.assertEqual(self.sharded.count("amount", lo, hi),
                             self.plain.count("amount", lo, hi), (lo, hi))

    def test_two_predicates_match(self):
        pred = [{"field": "amount", "lo": 0, "hi": 2000},
                {"field": "day", "lo": 0, "hi": 400}]
        want = sorted(r["note"] for r in self.plain.query_stream(pred))
        got = sorted(r["note"] for r in self.sharded.query_stream(pred))
        self.assertEqual(got, want)

    def test_ordered_stream_is_globally_sorted(self):
        """Each shard sorts its own rows; the merge has to interleave them,
        not concatenate them."""
        pred = [{"field": "amount", "lo": 0, "hi": 4095}]
        got = [r["amount"] for r in
               self.sharded.query_stream(pred, order="amount")]
        self.assertEqual(got, sorted(got), "not sorted across shards")
        self.assertEqual(len(got), len(self.rows))

    def test_histogram_merges_bar_for_bar(self):
        a = self.plain.histogram("amount", 0, 4095)
        b = self.sharded.histogram("amount", 0, 4095)
        self.assertEqual([(x["lo"], x["hi"], x["count"]) for x in b],
                         [(x["lo"], x["hi"], x["count"]) for x in a],
                         "sharded bars differ from a single database")

    def test_histogram_reduces_after_merging_not_before(self):
        """If each shard reduced to `buckets` on its own, the bars would
        land on different boundaries and adding them would be nonsense."""
        b = self.sharded.histogram("amount", 0, 4095, buckets=8)
        self.assertLessEqual(len(b), 8)
        self.assertEqual(sum(x["count"] for x in b),
                         sum(x["count"] for x in
                             self.sharded.histogram("amount", 0, 4095)))

    def test_limit_draws_from_every_shard(self):
        """An unordered limit must not drain shard 0 first — otherwise a
        caller taking the first N gets a biased sample of its own data."""
        pred = [{"field": "amount", "lo": 0, "hi": 4095}]
        seen = {r["_shard"] for r in
                self.sharded.query_stream(pred, limit=8)}
        self.assertGreater(len(seen), 1, f"limit came from one shard: {seen}")


class TestShardMechanics(ShardingCase):
    def test_rows_are_spread_evenly(self):
        counts = [s["records"] for s in self.sharded.stats("amount", 0, 4095)]
        self.assertEqual(sum(counts), len(self.rows))
        self.assertLessEqual(max(counts) - min(counts), 1,
                             f"uneven: {counts}")

    def test_rids_carry_their_shard_and_delete_routes(self):
        """On its own database: deleting mutates state, and undoing it by
        re-inserting left a tombstone behind that made the NEXT test see one
        record too many."""
        d = Path(self.tmp) / "delete-case"
        own = ShardedOwner.create(str(d), "pw", SCHEMA, [self.addr],
                                  shards=3, network_secret=SECRET)
        own.insert_many(self.rows[:30])
        own.drain()

        rows = own.query("amount", 0, 4095)
        victim = rows[0]
        self.assertEqual(shard_of(victim["_rid"]), victim["_shard"])
        own.delete_many([victim["_rid"]])
        own.drain()

        after = own.query("amount", 0, 4095)
        self.assertEqual(len(after), len(rows) - 1)
        self.assertNotIn(victim["note"], [r["note"] for r in after])
        # count() still includes it until compact(): the index cannot know a
        # row is tombstoned. Existing documented behaviour, unchanged by
        # sharding, and worth pinning so nobody "fixes" the sum.
        self.assertEqual(own.count("amount", 0, 4095), len(rows))

    def test_a_bare_rid_is_refused(self):
        """Silently guessing a shard would delete from the wrong one, or
        from none, and report success either way."""
        with self.assertRaises(ValueError):
            self.sharded.delete_many(["deadbeef"])

    def test_opening_a_partial_set_refuses(self):
        """Losing a shard file must not look like a smaller database."""
        d = Path(self.tmp) / "partial"
        s = ShardedOwner.create(str(d), "pw", SCHEMA, [self.addr], shards=3,
                                network_secret=SECRET)
        del s
        os.remove(sorted(d.glob("shard-*.brdb"))[-1])
        with self.assertRaises(FileNotFoundError):
            ShardedOwner.open(str(d), "pw", [self.addr])


class TestShardsAreUnlinkable(ShardingCase):
    def test_shards_index_the_same_value_under_different_keys(self):
        """The claim worth checking rather than asserting: if two shards
        produced the same index key for the same field, a node could join
        them and the separation would be decorative."""
        keysets = [set(index_keys(o, "amount", count=32))
                   for o in self.sharded.shards]
        for i, a in enumerate(keysets):
            for j, b in enumerate(keysets[i + 1:], start=i + 1):
                self.assertEqual(a & b, set(),
                                 f"shards {i} and {j} share index keys")

    def test_a_node_sees_one_undifferentiated_pile(self):
        """Whatever the node holds, nothing in it says which shard a key
        came from — that is the property the separation rests on."""
        import json
        from blindrange import node as nd
        out = nd.post_any(self.addr, "/digest",
                          json.dumps({"chars": 4}).encode(), SECRET)
        self.assertGreater(sum(out["buckets"].values()), 0)
        # Keys are all the same shape regardless of origin.
        prefixes = set(out["buckets"])
        self.assertTrue(all(p.startswith(("I:", "R:", "B:"))
                            for p in prefixes), prefixes)


if __name__ == "__main__":
    unittest.main()


class TestShardingActuallyLowersTheCeiling(ShardingCase):
    """The reason this exists, measured rather than asserted.

    Compaction rewrites an epoch in memory, which is the first ceiling a
    growing database hits — before the network runs out of anything. If
    sharding does not reduce that peak, it is pure overhead: slightly
    slower queries and more files, for nothing.
    """

    def test_compaction_peak_memory_falls_with_shard_count(self):
        import tracemalloc

        rows = [{"amount": (i * 37) % 4096, "day": i % 900,
                 "note": f"bench {i}"} for i in range(1200)]

        one = Owner.create(f"{self.tmp}/bench-one.brdb", "pw", SCHEMA,
                           [self.addr], network_secret=SECRET)
        one.insert_many(rows)
        one.drain()

        many = ShardedOwner.create(f"{self.tmp}/bench-many", "pw", SCHEMA,
                                   [self.addr], shards=4,
                                   network_secret=SECRET)
        many.insert_many(rows)
        many.drain()

        def peak(fn):
            tracemalloc.start()
            try:
                fn()
                return tracemalloc.get_traced_memory()[1]
            finally:
                tracemalloc.stop()

        single_peak = peak(one.compact)
        shard_peak = peak(many.compact)

        # Measured 28.4 MB against 7.9 MB at 4,000 records — a 3.6x drop
        # against a theoretical 4x. The bar is deliberately loose so this
        # fails on a regression, not on a noisy machine.
        self.assertLess(shard_peak, single_peak * 0.6,
                        f"sharded compaction peaked at {shard_peak/1e6:.1f} MB "
                        f"against {single_peak/1e6:.1f} MB unsharded — the "
                        f"ceiling this exists to raise did not move")

    def test_shards_hold_a_fraction_of_the_rows_each(self):
        """The per-shard size is the number that governs the ceiling."""
        counts = [s["records"] for s in self.sharded.stats("amount", 0, 4095)]
        self.assertLess(max(counts), len(self.rows) * 0.5,
                        f"a shard holds most of the database: {counts}")


class TestDescendingOrder(ShardingCase):
    """`order="-field"` walks the range from the top.

    Two things were wrong with newest-N queries. They returned the OLDEST
    rows in the window, because an ascending walk with a limit stops as
    soon as it has enough — at the wrong end. And they paid for a batch of
    leaves per round trip until they got there, when the answer was in the
    last leaf all along.
    """

    def test_descending_returns_the_newest_rows_not_the_oldest(self):
        pred = [{"field": "amount", "lo": 0, "hi": 4095}]
        top = [r["amount"] for r in
               self.plain.query_stream(pred, limit=5, order="-amount")]
        every = sorted((r["amount"] for r in self.plain.query_stream(pred)),
                       reverse=True)
        self.assertEqual(top, every[:5],
                         "a descending limit did not return the top rows")

    def test_descending_costs_fewer_round_trips(self):
        """The reason to do it: an ascending walk pays batch after batch
        before it reaches the end the caller actually asked about."""
        pred = [{"field": "amount", "lo": 0, "hi": 4095}]
        list(self.plain.query_stream(pred, limit=5, order="amount"))
        up = self.plain.last_stats["batches"]
        list(self.plain.query_stream(pred, limit=5, order="-amount"))
        down = self.plain.last_stats["batches"]
        self.assertLessEqual(down, up,
                             f"descending took more batches ({down}) than "
                             f"ascending ({up})")

    def test_sharded_descending_is_globally_sorted(self):
        """The merge has to strip the direction marker before looking the
        value up — it asked rows for a key called "-amount" and the server
        died on KeyError."""
        pred = [{"field": "amount", "lo": 0, "hi": 4095}]
        got = [r["amount"] for r in
               self.sharded.query_stream(pred, order="-amount")]
        self.assertEqual(got, sorted(got, reverse=True))
        self.assertEqual(len(got), len(self.rows))

    def test_sharded_descending_limit_matches_unsharded(self):
        pred = [{"field": "amount", "lo": 0, "hi": 4095}]
        a = [r["amount"] for r in
             self.plain.query_stream(pred, limit=7, order="-amount")]
        b = [r["amount"] for r in
             self.sharded.query_stream(pred, limit=7, order="-amount")]
        self.assertEqual(b, a)


class TestConcurrentShardWalks(ShardingCase):
    """Shard walks must overlap, not queue behind each other.

    heapq.merge pulls from its inputs synchronously, so four shards took
    four times as long as one: measured on the public network, an ordered
    newest-5 query went from 5.6s unsharded to 19.7s over four shards. The
    walks were serialised by the merge, not by anything inherent.
    """

    def test_abandoning_a_stream_does_not_leak_producers(self):
        """A `limit` abandons every other shard's stream mid-walk. Without
        a stop signal each one parks on a full queue forever, and every
        query leaks threads."""
        import threading
        before = threading.active_count()
        pred = [{"field": "amount", "lo": 0, "hi": 4095}]
        for _ in range(5):
            list(self.sharded.query_stream(pred, limit=2))
        for _ in range(50):
            if threading.active_count() <= before + len(self.sharded):
                break
            time.sleep(0.1)
        self.assertLessEqual(threading.active_count(), before + len(self.sharded),
                             "producer threads outlived their queries")

    def test_a_shard_error_reaches_the_caller(self):
        """Errors cross the thread boundary. A query that quietly skipped a
        broken shard would return a confidently incomplete answer."""
        class Boom:
            def query_stream(self, *a, **k):
                raise RuntimeError("shard on fire")
                yield  # pragma: no cover

        broken = ShardedOwner([Boom()], self.tmp)
        with self.assertRaises(RuntimeError):
            list(broken.query_stream([{"field": "amount", "lo": 0, "hi": 1}]))
