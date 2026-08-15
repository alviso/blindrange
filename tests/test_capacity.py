"""Disk cap and space reclamation.

Both exist because of one measurement on a live node: a 1053 MB file whose
live data was 195 MB. SQLite reuses free pages but never returns them, so
the operator's disk showed five times the data actually held — and any cap
they set would have been wrong by that factor.
"""
import os
import shutil
import tempfile
import unittest

import blindrange.node as node


class TestParseSize(unittest.TestCase):
    def test_units(self):
        self.assertEqual(node.parse_size("10GB"), 10 << 30)
        self.assertEqual(node.parse_size("500M"), 500 << 20)
        self.assertEqual(node.parse_size("2.5G"), int(2.5 * (1 << 30)))
        self.assertEqual(node.parse_size("1TB"), 1 << 40)

    def test_percentage_of_the_filesystem(self):
        self.assertEqual(node.parse_size("10%", 1000), 100)
        self.assertEqual(node.parse_size("5%", 500 << 30), int(0.05 * (500 << 30)))

    def test_percentage_needs_a_filesystem(self):
        with self.assertRaises(ValueError):
            node.parse_size("5%")

    def test_empty_means_unlimited(self):
        self.assertIsNone(node.parse_size(""))
        self.assertIsNone(node.parse_size(None))

    def test_human_size_round_trips_readably(self):
        self.assertEqual(node.human_size(None), "unlimited")
        self.assertIn("GB", node.human_size(10 << 30))


class TestCap(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def store(self, cap=None, name="kv.db"):
        return node.Store(os.path.join(self.tmp, name), cap_bytes=cap)

    def test_no_cap_is_never_full(self):
        st = self.store()
        st.put([(f"R:{i}", "x" * 500) for i in range(500)])
        self.assertFalse(st.is_full())

    def test_full_once_the_file_passes_the_cap(self):
        st = self.store(cap=2 * 1024 * 1024)
        self.assertFalse(st.is_full())
        st.put([(f"R:{i:05d}", "x" * 900) for i in range(4000)])
        self.assertTrue(st.is_full(), f"used {st.disk_used()} vs cap {st.cap_bytes}")

    def test_a_cap_below_the_empty_baseline_is_full_immediately(self):
        """An empty WAL database already occupies space. A cap under that
        means the node accepts nothing while looking healthy — startup warns
        about it, and this pins the behaviour that makes the warning true."""
        st = self.store(cap=1024)
        self.assertTrue(st.is_full())

    def test_disk_used_counts_the_wal_not_just_the_db(self):
        """The operator's disk sees every file, so the cap must too."""
        st = self.store()
        st.put([(f"R:{i}", "x" * 200) for i in range(200)])
        self.assertGreater(st.disk_used(), os.path.getsize(st.path) - 1)

    def test_a_full_node_refuses_writes(self):
        st = self.store(cap=1024)
        self.assertTrue(st.is_full())
        code, body = node.service_post(st, None, None, "", "/kv",
                                       {"entries": [["R:new", "v"]]})
        self.assertEqual(code, 507)
        self.assertIn("disk limit", body["error"])

    def test_refusal_happens_before_anything_is_charged(self):
        """A write we are going to refuse must not cost the client a token."""
        import inspect
        src = inspect.getsource(node._service_post)
        full_at = src.index("store.is_full()")
        gate_at = src.index("GATE is not None")
        self.assertLess(full_at, gate_at,
                        "capacity must be checked before the token gate")

    def test_a_full_node_still_serves_reads(self):
        st = self.store(cap=1024)
        st.put([(f"R:{i:05d}", "x" * 400) for i in range(50)])
        code, body = node.service_post(st, None, None, "", "/mget",
                                       {"keys": ["R:00001"]})
        self.assertEqual(code, 200)
        self.assertIsNotNone(body["values"]["R:00001"])


class TestVacuum(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_new_stores_use_incremental_vacuum(self):
        st = node.Store(os.path.join(self.tmp, "kv.db"))
        mode = st.db.execute("PRAGMA auto_vacuum").fetchone()[0]
        self.assertEqual(mode, 2, "new stores must be able to shrink")

    def test_churn_is_reclaimed_rather_than_retained(self):
        st = node.Store(os.path.join(self.tmp, "kv.db"))
        st.put([(f"R:{i:06d}", "x" * 900) for i in range(4000)])
        peak = st.disk_used()
        st.delete([f"R:{i:06d}" for i in range(4000)])
        for _ in range(40):
            if not st.vacuum_step(5000):
                break
        self.assertLess(st.disk_used(), peak * 0.5,
                        f"file stayed at {st.disk_used()} after deleting "
                        f"everything (peak {peak})")

    def test_free_fraction_reports_dead_space(self):
        st = node.Store(os.path.join(self.tmp, "kv.db"))
        st.put([(f"R:{i:06d}", "x" * 900) for i in range(3000)])
        self.assertLess(st.free_fraction(), 0.2)
        st.delete([f"R:{i:06d}" for i in range(3000)])
        self.assertGreater(st.free_fraction(), 0.2)


if __name__ == "__main__":
    unittest.main()
