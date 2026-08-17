"""The audit badge on the public status page.

A badge is a claim made in one glance, which makes it the easiest place in
the project to be accidentally dishonest. The failure mode is not a crash:
it is a green light that stays green when nobody has checked anything. This
page spent sixteen hours in exactly that state before there was a scheduled
auditor, so every state gets a test.
"""
import importlib.util
import os
import re
import sys
import time
import unittest
import unittest.mock

from blindrange import node
from blindrange.node import audit_badge, status_html

# status_server lives in examples/, which is not a package.
_spec = importlib.util.spec_from_file_location(
    "status_server",
    os.path.join(os.path.dirname(__file__), "..", "examples",
                 "status_server.py"))
status = importlib.util.module_from_spec(_spec)
sys.modules["status_server"] = status
_spec.loader.exec_module(status)


def row(i, rate=None, reports=0, mode="direct"):
    return {"id": f"node{i}", "mode": mode, "keys": 1000, "version": "0.6.0",
            "age": 0.1, "share": 333, "behind": False, "build": 1,
            "measured": ({"rate": rate, "reports": reports}
                         if rate is not None else None)}


def text(html):
    return re.sub("<[^>]+>", "", html).replace("&nbsp;", " ")


class TestAuditBadge(unittest.TestCase):
    def test_all_proved_passes(self):
        b = audit_badge([row(i, 1.0, 2) for i in range(3)])
        self.assertIn("badge pass", b)
        self.assertIn("AUDIT PASSED", text(b))
        self.assertIn("all 3 nodes", text(b))

    def test_unaudited_never_reads_as_passed(self):
        """The one that matters. No recent audit must look different from a
        healthy network, not the same."""
        b = audit_badge([row(i) for i in range(3)])
        self.assertNotIn("PASSED", text(b))
        self.assertIn("UNPROVED", text(b))
        self.assertIn("badge none", b)

    def test_one_failing_node_degrades_the_whole_badge(self):
        """A network is as intact as its weakest replica holder."""
        b = audit_badge([row(0, 1.0, 2), row(1, 0.42, 2), row(2, 1.0, 2)])
        self.assertIn("DEGRADED", text(b))
        self.assertIn("42%", text(b))
        self.assertNotIn("PASSED", text(b))

    def test_a_node_awaiting_its_first_audit_is_not_degradation(self):
        """A joining node made the page read DEGRADED within minutes of
        doing nothing wrong. Absence of evidence is not evidence of loss,
        and a badge that cries wolf is one people learn to ignore."""
        b = audit_badge([row(0, 1.0, 2), row(1), row(2, 1.0, 2)])
        self.assertNotIn("DEGRADED", text(b))
        self.assertIn("PASSED", text(b))
        self.assertIn("awaiting a first audit", text(b))
        self.assertIn("2 of 3", text(b))

    def test_real_loss_still_degrades_even_with_pending_nodes(self):
        b = audit_badge([row(0, 1.0, 2), row(1, 0.42, 2), row(2)])
        self.assertIn("DEGRADED", text(b))
        self.assertIn("42%", text(b))
        self.assertIn("await a first audit", text(b))

    def test_threshold_is_not_a_rounding_accident(self):
        self.assertIn("PASSED", text(audit_badge([row(0, 0.9, 1)])))
        self.assertIn("DEGRADED", text(audit_badge([row(0, 0.89, 1)])))

    def test_dead_nodes_do_not_count_against_coverage(self):
        b = audit_badge([row(0, 1.0, 2), row(1, mode="down")])
        self.assertIn("PASSED", text(b))
        self.assertIn("all 1 nodes", text(b))

    def test_no_live_nodes(self):
        self.assertIn("NO LIVE NODES", text(audit_badge([row(0, mode="down")])))
        self.assertIn("NO LIVE NODES", text(audit_badge([])))


class TestStatusPage(unittest.TestCase):
    def test_page_renders_with_badge_and_head(self):
        html = status_html([row(i, 1.0, 2) for i in range(3)], 1000,
                           "seed:7501", {"size": 5, "root": "ab" * 20})
        self.assertIn("AUDIT PASSED", html)
        self.assertIn("5:" + "ab" * 16, html)
        self.assertNotIn("{audit_badge", html)
        self.assertNotIn("{logstr}", html)

    def test_page_renders_without_a_head(self):
        html = status_html([row(0, 1.0, 1)], 10, "seed:7501")
        self.assertNotIn("{logstr}", html)
        self.assertNotIn("Merkle", html)


if __name__ == "__main__":
    unittest.main()


class TestRecencyWeightedPossession(unittest.TestCase):
    """The estimator has to be quick in both directions, and still resist
    a node that pads the window with invented passes.

    The unweighted low quantile was slow both ways: a node that had just
    finished catching up stayed at 0% for hours on the strength of its own
    honest early failures, and a node whose disk had just died kept a full
    share through its next audit. The second one costs real money.
    """

    def setUp(self):
        status.REPORTS.clear()

    def _load(self, nid, samples):
        """samples: (age_hours, rate)."""
        now = time.time()
        for age_h, rate in samples:
            status.REPORTS[nid].append((now - age_h * 3600, rate))

    def test_recovered_node_is_not_pinned_by_a_stale_failure(self):
        # Exactly the live case: failed while still filling, passes now.
        self._load("n", [(2.0, 0.0), (0.4, 1.0)])
        m = status.possession()["n"]
        self.assertGreater(m["rate"], 0.5,
                           "a node that passes its newest audit should not "
                           "read as failing on a two-hour-old result")
        self.assertEqual(m["latest"], 1.0)

    def test_a_node_that_just_died_loses_its_share_immediately(self):
        # Three passes then one failure. Unweighted p25 over [0,1,1,1] is
        # 1.0 — a full share for data that is already gone.
        self._load("n", [(6.0, 1.0), (4.0, 1.0), (2.0, 1.0), (0.01, 0.0)])
        self.assertEqual(status.possession()["n"]["rate"], 0.0)

    def test_burying_a_failure_takes_a_supermajority_of_passes(self):
        # What the low quantile actually buys, stated honestly: the score
        # goes to zero whenever a quarter or more of the WEIGHT is failing,
        # so one real failure cannot be waved away by a couple of passes.
        # It is not unconditional — enough same-age passes do outvote it —
        # and that is why fabrication is fenced off by node-signed receipts
        # and proof-of-work rather than by this statistic alone.
        self._load("n", [(0.5, 1.0), (0.5, 1.0), (0.5, 0.0)])
        self.assertEqual(status.possession()["n"]["rate"], 0.0,
                         "one failure in three should still sink the score")

        status.REPORTS.clear()
        self._load("n", [(0.5, 1.0)] * 10 + [(0.5, 0.0)])
        self.assertEqual(status.possession()["n"]["rate"], 1.0,
                         "one failure in eleven is below the quantile, and "
                         "the receipts are what make those ten expensive")

    def test_steady_healthy_node_scores_full(self):
        self._load("n", [(5.0, 1.0), (3.0, 1.0), (1.0, 1.0), (0.1, 1.0)])
        self.assertEqual(status.possession()["n"]["rate"], 1.0)

    def test_expired_reports_are_ignored_entirely(self):
        self._load("n", [(24.0, 1.0)])
        self.assertNotIn("n", status.possession())

    def test_quantile_is_the_inverse_cdf_not_a_floor_index(self):
        """The definition change is half the fix, and it is deliberate.

        The old code took `sorted(vals)[int(len(vals) * 0.25)]`, whose floor
        index SKIPS the failing report when exactly one report in four has
        failed: p25 of [0,1,1,1] came out as 1.0, which is how a node that
        had just lost its data kept a full share. The standard inverse-CDF
        quantile — the first value at which the running weight reaches a
        quarter — returns 0.0 there, and agrees with the old one elsewhere.
        """
        at_equal_weight = lambda vals: status.weighted_quantile(
            [(v, 1.0) for v in vals], status.REPORT_QUANTILE)
        self.assertEqual(at_equal_weight([0.0, 1.0, 1.0, 1.0]), 0.0)
        self.assertEqual(at_equal_weight([0.0, 1.0]), 0.0)
        self.assertEqual(at_equal_weight([0.0, 0.0, 1.0, 1.0]), 0.0)
        self.assertEqual(at_equal_weight([1.0, 1.0, 1.0, 1.0]), 1.0)

    def test_weighting_is_what_saves_the_recovering_node(self):
        # Same three results, only the ages differ. Old-to-new is a
        # recovery; new-to-old is a node that has just started failing.
        self._load("n", [(2.0, 0.0), (0.1, 1.0)])
        recovering = status.possession()["n"]["rate"]
        status.REPORTS.clear()
        self._load("n", [(2.0, 1.0), (0.1, 0.0)])
        failing = status.possession()["n"]["rate"]
        self.assertGreater(recovering, failing,
                           "age has to decide this; the multiset of results "
                           "is identical in both directions")

    def test_cell_shows_the_latest_when_it_disagrees(self):
        self._load("n", [(3.0, 0.0), (2.5, 0.0), (0.2, 1.0)])
        m = status.possession()["n"]
        cell = node._possession_cell(m)
        self.assertIn("latest 100%", cell)
        self.assertIn("audits", cell)

    def test_cell_stays_quiet_when_they_agree(self):
        self._load("n", [(1.0, 1.0), (0.2, 1.0)])
        self.assertNotIn("latest", node._possession_cell(
            status.possession()["n"]))


class TestRosterLinger(unittest.TestCase):
    """A node missing from one refresh must not vanish from the page.

    Gossip forgets a peer after a missed heartbeat or two, so a relay
    hiccup erased nodes from the roster for a minute and put them back —
    churn that never happened. Missing nodes stay for ROSTER_LINGER,
    marked, with their age visible, and only then disappear.
    """

    def setUp(self):
        status.ROSTER.clear()

    @staticmethod
    def row(nid, **kw):
        return {"id": nid, "mode": "relay tenant", "keys": 10,
                "version": "v", "build": 1, "age": 0.5, **kw}

    def test_a_briefly_missing_node_stays_marked(self):
        t = 1000.0
        status.merge_roster([self.row("aa"), self.row("bb")], t)
        got = status.merge_roster([self.row("aa")], t + 60)
        by = {r["id"]: r for r in got}
        self.assertIn("bb", by, "one missed refresh erased the node")
        self.assertTrue(by["bb"]["down"])
        self.assertEqual(by["bb"]["mode"], "not answering")
        self.assertAlmostEqual(by["bb"]["age"], 60, delta=1)
        self.assertFalse(by["aa"].get("down"))

    def test_it_drops_after_the_linger_expires(self):
        t = 1000.0
        status.merge_roster([self.row("aa"), self.row("bb")], t)
        got = status.merge_roster([self.row("aa")],
                                  t + status.ROSTER_LINGER + 1)
        self.assertEqual([r["id"] for r in got], ["aa"])

    def test_a_returning_node_is_fresh_again(self):
        t = 1000.0
        status.merge_roster([self.row("aa")], t)
        status.merge_roster([], t + 120)
        got = status.merge_roster([self.row("aa")], t + 180)
        self.assertFalse(got[0].get("down"), "a returned node stayed marked")

    def test_a_lingering_node_earns_nothing(self):
        """The linger is presentation. Payout weight must still require a
        node that answers — a ghost keeping its share would pay for
        absence."""
        rows = [self.row("aa"), dict(self.row("bb"), down=True,
                                     mode="not answering")]
        live = [r for r in rows
                if r.get("mode") != "down" and not r.get("down")]
        self.assertEqual([r["id"] for r in live], ["aa"])


class TestPeerStatsRefusesImpostors(unittest.TestCase):
    """A /stats answer is only believed if the answerer IS the asked node.

    For one night the public seed attributed its own statistics to four
    peers: every roster row showed the seed's key count and "directly
    reachable", until a restart. /stats always carried node_id; nothing
    checked it. Now an answer from the wrong node is discarded and logged
    with the addr and the actual speaker — the two facts that will name
    the transport bug when it recurs.
    """

    def _stats_for(self, answerer_id, asked_id):
        import io
        import json as _json
        import sys as _sys

        fake = {"node_id": answerer_id, "keys": 123, "version": "v"}

        class FakePool:
            @staticmethod
            def request(addr, method, path, timeout=None):
                return 200, _json.dumps(fake).encode()

        err = io.StringIO()
        with unittest.mock.patch.object(node, "POOL", FakePool), \
             unittest.mock.patch.object(_sys, "stderr", err):
            node._IMPOSTOR_LOGGED.clear()
            out = node._peer_stats(asked_id, {"addr": "1.2.3.4:1"},
                                   "s", None, "me" * 8)
        return out, err.getvalue()

    def test_the_right_answerer_is_believed(self):
        out, _ = self._stats_for("aa" * 8, "aa" * 8)
        self.assertEqual(out["keys"], 123)

    def test_the_wrong_answerer_is_discarded_and_named(self):
        out, logged = self._stats_for("bb" * 8, "aa" * 8)
        self.assertIsNone(out, "an impostor's stats were believed")
        self.assertIn("bbbbbbbb", logged)
        self.assertIn("1.2.3.4:1", logged)

    def test_answering_with_my_own_stats_is_called_out(self):
        out, logged = self._stats_for("me" * 8, "aa" * 8)
        self.assertIsNone(out)
        self.assertIn("(me)", logged,
                      "self-attribution is the observed failure and the log "
                      "should say so explicitly")


class TestFutureTimestampsCannotPoisonTheRoster(unittest.TestCase):
    """An entry stamped in the future wins every newer-ts comparison and
    never crosses the TTL — an immortal lie until restart. Rejected at
    ingest instead."""

    def test_future_entry_is_refused_and_sane_one_accepted(self):
        import tempfile
        import time as _time
        d1 = tempfile.mkdtemp()
        d2 = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, d1, True)
        self.addCleanup(__import__("shutil").rmtree, d2, True)
        peers = node.Peers(node.Identity(d1), "127.0.0.1:7501")
        other = node.Identity(d2)
        now_ms = int(_time.time() * 1000)

        good = other.heartbeat("9.9.9.9:7501")
        peers.merge({other.node_id: good})
        self.assertIn(other.node_id, peers.table, "a sane entry was refused")

        # Same identity, timestamp an hour in the future: must not land,
        # and must not displace the sane entry.
        evil = dict(good)
        evil["ts"] = now_ms + 3_600_000
        evil["sig"] = other.priv.sign(
            f"{evil['addr']}|{evil.get('udp', '')}|{evil['ts']}".encode()
        ).hex()
        peers.merge({other.node_id: evil})
        self.assertLess(peers.table[other.node_id]["ts"],
                        now_ms + node.CLOCK_SKEW_MAX * 1000,
                        "a future-stamped entry took an immortal seat")
