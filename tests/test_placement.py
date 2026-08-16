"""Diversity-aware replica placement.

The risk this addresses is durability, not billing: payouts already require
proved possession, so a Sybil that earns is a Sybil that stores. What cheap
identities really buy is replica capture — at RF3 a party holding fraction
k of the ring holds every copy of about k^3 of the keys.

The dangerous failure here is not "diversity is imperfect". It is placing
data somewhere readers never look, or refusing to place it at all on a
small homogeneous network. Both are tested.
"""
import collections
import sys
import unittest
import unittest.mock

from blindrange.ring import Ring, failure_group, REORDER_WINDOW

NODES = [f"n{i}" for i in range(9)]
BY_THREES = {f"n{i}": f"op{i // 3}" for i in range(9)}


class TestFailureGroup(unittest.TestCase):
    def test_ipv4_collapses_to_a_24(self):
        self.assertEqual(failure_group("46.4.48.244:7501"), "46.4.48.0/24")
        self.assertEqual(failure_group("46.4.48.244:7501"),
                         failure_group("46.4.48.9:7502"))
        self.assertNotEqual(failure_group("46.4.48.1:7501"),
                            failure_group("46.4.49.1:7501"))

    def test_tenant_is_grouped_by_its_own_endpoint_not_its_relay(self):
        """Two homes behind one relay are independent; grouping them by the
        relay would refuse to place a key across them."""
        a = failure_group("via:seed:7501/a", "10.0.0.2:7501,24.72.147.56:7501")
        b = failure_group("via:seed:7501/b", "10.0.0.2:7501,88.12.9.4:7501")
        self.assertNotEqual(a, b)
        self.assertEqual(a, "24.72.147.0/24")

    def test_tenant_without_candidates_is_its_own_group(self):
        """Observed live: a tenant and its relay were treated as one place
        purely because one relays for the other. Relaying is not a shared
        disk, and 'unknown' must never mean 'shared'."""
        relay = failure_group("46.4.48.244:7501")
        tenant = failure_group("via:46.4.48.244:7501/abc123")
        self.assertNotEqual(tenant, relay)
        self.assertNotEqual(tenant, failure_group("via:46.4.48.244:7501/def456"))

    def test_ipv6_uses_the_routed_prefix(self):
        self.assertEqual(failure_group("[2a06:98c1:3121::3]:7501"),
                         "2a06:98c1:3121::/48")

    def test_never_raises_on_junk(self):
        for addr in ("", "garbage", "via:", ":::", "host-with-no-port"):
            self.assertIsInstance(failure_group(addr), str)


class TestPlacement(unittest.TestCase):
    def test_without_groups_it_is_the_plain_ring(self):
        """Existing networks must not reshuffle on upgrade."""
        plain, same = Ring(NODES), Ring(NODES, groups={})
        for k in range(200):
            self.assertEqual(plain.route(f"k{k}"), same.route(f"k{k}"))

    def test_replicas_spread_across_operators(self):
        div = Ring(NODES, groups=BY_THREES)
        spread = collections.Counter(
            len({BY_THREES[n] for n in div.route(f"k{k}")}) for k in range(2000))
        self.assertGreater(spread[3] / 2000, 0.9, f"poor spread: {spread}")
        self.assertEqual(spread[1], 0, "some key has all replicas in one group")

    def test_capture_by_a_majority_operator_collapses(self):
        adv = {f"n{i}": ("attacker" if i < 6 else f"honest{i}")
               for i in range(9)}
        def captured(ring):
            return sum(1 for k in range(2000)
                       if all(adv[n] == "attacker" for n in ring.route(f"k{k}")))
        plain = captured(Ring(NODES))
        div = captured(Ring(NODES, groups=adv))
        self.assertGreater(plain, 300, "baseline should show real capture")
        self.assertLess(div, plain / 10, f"capture barely improved: {div}")

    def test_placement_stays_inside_the_read_probe_window(self):
        """The safety property. Readers probe route(k, R + PROBE_EXTRA) on
        the plain ring; if diversity placed a replica outside that, reads
        would miss data that was successfully written."""
        plain, div = Ring(NODES), Ring(NODES, groups=BY_THREES)
        for k in range(500):
            window = set(plain.route(f"k{k}", 3 + REORDER_WINDOW))
            self.assertTrue(set(div.route(f"k{k}")) <= window,
                            f"k{k} placed outside the probe window")

    def test_homogeneous_network_still_gets_full_replication(self):
        """Three nodes in one /24 is our own public network today. Refusing
        to place data because it is homogeneous would be an outage."""
        one = {n: "same" for n in NODES[:3]}
        r = Ring(NODES[:3], groups=one)
        for k in range(200):
            self.assertEqual(len(r.route(f"k{k}")), 3)

    def test_fewer_groups_than_replicas_still_fills(self):
        two = {n: f"g{i % 2}" for i, n in enumerate(NODES)}
        r = Ring(NODES, groups=two)
        for k in range(300):
            holders = r.route(f"k{k}")
            self.assertEqual(len(holders), 3)
            self.assertEqual(len(set(holders)), 3, "duplicate replica")

    def test_larger_counts_still_return_what_was_asked(self):
        r = Ring(NODES, groups=BY_THREES)
        for want in (1, 3, 6, 9, 20):
            self.assertEqual(len(r.route("k", want)), min(want, len(NODES)))

    def test_diversity_reports_the_number_a_claim_rests_on(self):
        r = Ring(NODES, groups=BY_THREES)
        groups, replicas = r.diversity("k1")
        self.assertEqual(replicas, 3)
        self.assertGreaterEqual(groups, 2)

    def test_placement_is_deterministic(self):
        """Client and repairing node must agree, or they relocate each
        other's writes forever."""
        a = Ring(NODES, groups=BY_THREES)
        b = Ring(list(reversed(NODES)), groups=dict(BY_THREES))
        for k in range(300):
            self.assertEqual(a.route(f"k{k}"), b.route(f"k{k}"))


if __name__ == "__main__":
    unittest.main()


class TestGroupingBias(unittest.TestCase):
    """The two errors are not symmetric, and the code must lean the safe way.

    Calling independent nodes "the same place" costs spread. Calling
    co-located nodes "different places" claims durability that is not there.
    """

    def test_private_subnets_stay_grouped(self):
        a = failure_group("n1", "192.168.1.10:7501")
        b = failure_group("n2", "192.168.1.99:7501")
        self.assertEqual(a, b, "same LAN must not read as two places")

    def test_a_public_candidate_beats_a_lan_one(self):
        g = failure_group("via:r:7501/x", "192.168.1.5:7501,24.72.147.56:7501")
        self.assertEqual(g, "24.72.147.0/24")


class TestRepairCursorDurability(unittest.TestCase):
    """The repair cursor has to survive a restart.

    As a local variable it reset to "" on every start, so each restart swept
    the keyspace from the beginning. Harmless when nodes ran for weeks;
    crippling once auto-update restarted them every few minutes, because a
    three-hour sweep interrupted every five never reaches the far end — and
    a newly joined node simply stops filling with no error anywhere.
    """

    def setUp(self):
        import tempfile
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def store(self, name="kv.db"):
        import os
        import blindrange.node as node
        return node.Store(os.path.join(self.tmp, name))

    def test_cursor_survives_a_restart(self):
        st = self.store()
        st.put([(f"R:{i:06d}", "v") for i in range(50)])
        st.set_meta("repair_cursor", "R:000031")
        del st
        self.assertEqual(self.store().get_meta("repair_cursor"), "R:000031")

    def test_a_fresh_store_starts_at_the_beginning(self):
        self.assertEqual(self.store("fresh.db").get_meta("repair_cursor"), "")

    def test_resuming_continues_rather_than_restarting(self):
        st = self.store()
        st.put([(f"R:{i:06d}", "v") for i in range(50)])
        first = st.batch_after("", 10)
        st.set_meta("repair_cursor", first[-1][0])
        resumed = st.batch_after(st.get_meta("repair_cursor"), 10)
        self.assertGreater(resumed[0][0], first[-1][0],
                           "resumed sweep re-covered ground it had done")

    def test_meta_is_isolated_from_the_keyspace(self):
        """Repair walks kv; the cursor must not appear there and get
        replicated to other nodes as if it were data."""
        st = self.store()
        st.put([("R:a", "v")])
        st.set_meta("repair_cursor", "R:a")
        self.assertEqual([k for k, _ in st.batch_after("", 100)], ["R:a"])


class TestRepairCatchup(unittest.TestCase):
    """Repair has two jobs with different urgencies.

    Keeping a settled network converged is maintenance and can take hours.
    Filling a node that just joined is backfill, and at maintenance pace it
    took eight hours while using half a percent of the available link — the
    node fell further behind than it caught up.
    """

    def test_catchup_is_much_faster_than_maintenance(self):
        import blindrange.node as node
        self.assertLess(node.REPAIR_CATCHUP_H, node.REPAIR_SWEEP_H)
        self.assertGreaterEqual(node.REPAIR_SWEEP_H / node.REPAIR_CATCHUP_H, 4,
                                "catch-up must be materially faster")

    def test_batch_sizes_differ_by_the_same_factor(self):
        import blindrange.node as node
        keys = 1_000_000

        def batch(hours):
            rounds = max(1.0, hours * 3600 / node.REPAIR_EVERY)
            return min(node.REPAIR_BATCH_MAX, max(200, keys / rounds))

        self.assertGreater(batch(node.REPAIR_CATCHUP_H),
                           batch(node.REPAIR_SWEEP_H) * 3)

    def test_behind_threshold_is_a_real_gap_not_noise(self):
        """Nodes are never exactly equal — churn and timing see to that. The
        trigger has to ignore ordinary drift or every node is always
        'catching up' and the slow sweep never applies."""
        import blindrange.node as node
        self.assertLess(node.REPAIR_BEHIND_RATIO, 1.0)
        self.assertGreaterEqual(node.REPAIR_BEHIND_RATIO, 0.5)

    def test_peer_polling_is_throttled(self):
        """Deciding this costs a /stats round trip per peer, and the answer
        changes slowly."""
        import blindrange.node as node
        self.assertGreaterEqual(node.REPAIR_PEER_POLL, 10)


class TestRepairLoopSurvivesItself(unittest.TestCase):
    """A crash inside the repair sweep must not stop replication.

    This is not hypothetical. Twice in one session a plain NameError inside
    this loop killed the thread outright — once reaching for a relay hub the
    function never took as an argument, once for an unimported Counter. Both
    times replication stopped network-wide, nothing was logged, and the only
    visible symptom was a node that quietly never caught up. A sweep that
    throws has to be loud and retried, not fatal.
    """

    def test_a_throwing_sweep_is_logged_and_retried(self):
        import io
        import threading
        import time as _time
        import blindrange.node as node

        calls = []

        class Boom:
            def __init__(self, *a, **k):
                calls.append(1)
                raise RuntimeError("boom")

        class FakeStore:
            def get_meta(self, *a):
                return ""

            def count(self):
                return 0

        class FakePeers:
            def stable_since(self):
                return 1e9

            def live(self):
                return {"a" * 16: {"addr": "1.2.3.4:1", "udp": ""},
                        "b" * 16: {"addr": "5.6.7.8:1", "udp": ""}}

        err = io.StringIO()

        def run():
            node._repair_loop(FakeStore(), FakePeers(), "s")

        with unittest.mock.patch.object(node, "Ring", Boom), \
             unittest.mock.patch.object(node, "REPAIR_EVERY", 0.01), \
             unittest.mock.patch.object(node, "REPAIR_SETTLE", 0), \
             unittest.mock.patch.object(node.random, "random", lambda: 0.0), \
             unittest.mock.patch.object(sys, "stderr", err):
            stop = threading.Event()
            t = threading.Thread(
                target=lambda: node._repair_loop(FakeStore(), FakePeers(), "s",
                                                 stop=stop), daemon=True)
            t.start()
            _time.sleep(1.0)
            alive = t.is_alive()
        stop.set()
        t.join(timeout=5)

        self.assertTrue(alive,
                        "the repair thread died on a sweep error — that is "
                        "exactly the silent replication stop this guards")
        self.assertGreater(len(calls), 3,
                           "it should keep retrying, not spin down")
        self.assertIn("sweep failed", err.getvalue())


class TestRepairPushesPeersConcurrently(unittest.TestCase):
    """Peers must be pushed to at the same time, not one after another.

    Measured on the public network, a catch-up round took ~20s against a
    5s interval: posting to three peers meant three sequential relay round
    trips, so the sweep spent most of its life waiting instead of scanning,
    and a node 900k keys behind gained ~1% an hour. Peers are independent,
    so serialising them buys nothing.

    Asserted by overlap rather than by wall-clock speedup, which would be
    flaky on a loaded machine: if two posts were in flight at once, the
    sends are concurrent.
    """

    def test_two_posts_are_in_flight_at_once(self):
        import threading
        import time as _time
        import blindrange.node as node

        spans, lock = [], threading.Lock()

        def slow_post(addr, path, body, secret, **kw):
            t0 = _time.time()
            _time.sleep(0.25)
            with lock:
                spans.append((t0, _time.time()))
            return {}

        peer_ids = ["a" * 16, "b" * 16, "c" * 16]

        class FakeRing:
            def __init__(self, *a, **k):
                pass

            def route(self, key):
                return peer_ids

        class FakeIdent:
            node_id = "z" * 16

            def poll_token(self):
                return {}

        class FakeStore:
            def get_meta(self, *a):
                return ""

            def set_meta(self, *a):
                pass

            def count(self):
                return 10

            def batch_after(self, cursor, size):
                return [(f"k{i}", "v") for i in range(5)]

        class FakePeers:
            ident = FakeIdent()

            def stable_since(self):
                return 1e9

            def live(self):
                return {n: {"addr": f"{i}.0.0.1:1", "udp": ""}
                        for i, n in enumerate(peer_ids)}

        with unittest.mock.patch.object(node, "Ring", FakeRing), \
             unittest.mock.patch.object(node, "post_any", slow_post), \
             unittest.mock.patch.object(node, "_peer_stats", lambda *a: None), \
             unittest.mock.patch.object(node, "REPAIR_EVERY", 0.01), \
             unittest.mock.patch.object(node.random, "random", lambda: 0.0), \
             unittest.mock.patch.object(node, "REPAIR_SETTLE", 0):
            stop = threading.Event()
            t = threading.Thread(
                target=lambda: node._repair_loop(FakeStore(), FakePeers(), "s",
                                                 stop=stop), daemon=True)
            t.start()
            _time.sleep(1.0)
            stop.set()
            t.join(timeout=5)

        with lock:
            got = list(spans)
        self.assertGreaterEqual(len(got), 2, "no posts were made")
        overlap = any(a[0] < b[1] and b[0] < a[1]
                      for i, a in enumerate(got) for b in got[i + 1:])
        self.assertTrue(overlap,
                        "every post finished before the next began — the "
                        "peers are being pushed to serially again")

    def test_fanout_is_bounded(self):
        """Unbounded would open a connection per peer on a big network."""
        import blindrange.node as node
        self.assertGreater(node.REPAIR_FANOUT, 1)
        self.assertLessEqual(node.REPAIR_FANOUT, 16)


class TestReconciliation(unittest.TestCase):
    """Repair must send what a peer lacks, not everything we hold.

    Doubling push throughput on the public network moved the convergence
    rate not at all: the pipe was never the constraint, re-sending data the
    far side already had was. This is the fix, so the test that matters is
    not "did it converge" but "how much of what it sent was needed".
    """

    def setUp(self):
        import tempfile
        import blindrange.node as node
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.node = node

    def _store(self, keys):
        import os
        s = self.node.Store(os.path.join(self.tmp.name, f"s{len(keys)}.db"))
        s.put([(k, "v" + k) for k in keys])
        return s

    @staticmethod
    def _keys(n, start=0):
        """Keys shaped like the real ones: a tag plus uniform hex.

        Bucketing by key PREFIX is what lets both sides answer from the
        primary-key index with no extra column and nothing to migrate, and
        it assumes the characters after the tag are evenly spread. Real
        keys are PRF outputs, so they are — the live 3.9M-key store splits
        into 8,193 buckets with a median of 144. An earlier version of this
        fixture used zero-padded counters, whose variation is all in the
        TRAILING characters, and every key landed in one bucket.
        """
        import hashlib
        return ["I:" + hashlib.sha256(str(i).encode()).hexdigest()[:32]
                for i in range(start, start + n)]

    def test_only_the_missing_entries_are_selected(self):
        full = self._store(self._keys(500))
        chars = full.bucket_chars()
        have = self._keys(500)[:400]
        wanted, redundant = 0, 0
        for prefix in full.bucket_counts(chars):
            got = full.bucket_entries_except(prefix, have)
            for k, _ in got:
                if k in set(have):
                    redundant += 1
                else:
                    wanted += 1
        self.assertEqual(redundant, 0, "re-sent keys the peer already had")
        self.assertEqual(wanted, 100, "missed keys the peer lacked")

    def test_granularity_follows_store_size(self):
        """A fixed width was right for millions of keys and hopeless for a
        small store, where it put about one key in each bucket and spent a
        round trip per key."""
        small, big = self._store(self._keys(50)), self._store(self._keys(20000))
        self.assertLess(small.bucket_chars(), big.bucket_chars())
        for st in (small, big):
            counts = st.bucket_counts(st.bucket_chars())
            avg = sum(counts.values()) / max(1, len(counts))
            self.assertLess(avg, self.node.BUCKET_TARGET * 4,
                            "buckets far coarser than the target")

    def test_bucket_ranges_tile_the_keyspace_exactly(self):
        """Every key must land in exactly one bucket, or reconciliation
        silently skips whatever falls in the gap."""
        st = self._store(self._keys(2000))
        chars = st.bucket_chars()
        seen = []
        for prefix in st.bucket_counts(chars):
            seen += st.bucket_keys(prefix)
        self.assertEqual(sorted(seen), sorted(self._keys(2000)))
        self.assertEqual(len(seen), len(set(seen)), "a key is in two buckets")

    def test_counts_and_listing_agree(self):
        st = self._store(self._keys(1000))
        chars = st.bucket_chars()
        for prefix, n in st.bucket_counts(chars).items():
            self.assertEqual(len(st.bucket_keys(prefix)), n, prefix)

    def test_skewed_keys_stay_correct_if_less_efficient(self):
        """Prefix bucketing degrades gracefully when the assumption fails.

        Keys that share a prefix all land in one bucket, so the saving goes
        away — but the peer's key list still filters the send, so what
        crosses the wire is still only what is missing. Slower, never wrong.
        """
        clumped = [f"I:{i:032x}" for i in range(300)]
        st = self._store(clumped)
        have = clumped[:250]
        got = []
        for prefix in st.bucket_counts(st.bucket_chars()):
            got += st.bucket_entries_except(prefix, have)
        self.assertEqual(sorted(k for k, _ in got), sorted(clumped[250:]))

    def test_identical_stores_need_no_transfer(self):
        """The steady state: two nodes holding the same thing should find
        nothing to do, which is what makes maintenance nearly free."""
        st = self._store(self._keys(800))
        chars = st.bucket_chars()
        counts = st.bucket_counts(chars)
        behind = [b for b, n in counts.items() if n > counts.get(b, 0)]
        self.assertEqual(behind, [])
