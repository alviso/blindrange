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
import unittest

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
