"""The audit badge on the public status page.

A badge is a claim made in one glance, which makes it the easiest place in
the project to be accidentally dishonest. The failure mode is not a crash:
it is a green light that stays green when nobody has checked anything. This
page spent sixteen hours in exactly that state before there was a scheduled
auditor, so every state gets a test.
"""
import re
import unittest

from blindrange.node import audit_badge, status_html


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
        self.assertIn("3/3", text(b))

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
