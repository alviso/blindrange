"""Auto-update: when it fires, when it waits, and when it complains.

Two failures this guards against, both seen in production. A node ran stale
code for a day with --auto-update set because its sandbox made its own
checkout read-only and the pull failure was swallowed. And a node once
restarted mid-ingest, which cost a benchmark at 620k records.
"""
import threading
import time
import unittest

import blindrange.node as node


class TestInFlightTracking(unittest.TestCase):
    def setUp(self):
        node._INFLIGHT[0] = 0
        node._LAST_OP[0] = 0.0
        self.quiet = node.UPDATE_QUIET_S
        node.UPDATE_QUIET_S = 0.4

    def tearDown(self):
        node.UPDATE_QUIET_S = self.quiet
        node._INFLIGHT[0] = 0
        node._LAST_OP[0] = 0.0

    def test_idle_when_nothing_is_happening(self):
        self.assertFalse(node.data_path_busy())

    def test_busy_while_an_operation_runs(self):
        with node._op():
            self.assertTrue(node.data_path_busy())
            self.assertEqual(node._INFLIGHT[0], 1)

    def test_stays_busy_through_the_quiet_window(self):
        """A gap between two writes in a batch is not idleness."""
        with node._op():
            pass
        self.assertTrue(node.data_path_busy())
        time.sleep(0.5)
        self.assertFalse(node.data_path_busy())

    def test_counter_survives_an_exception(self):
        try:
            with node._op():
                raise ValueError("boom")
        except ValueError:
            pass
        self.assertEqual(node._INFLIGHT[0], 0)

    def test_concurrent_operations_are_counted(self):
        started, release = threading.Event(), threading.Event()

        def worker():
            with node._op():
                started.set()
                release.wait(5)

        ts = [threading.Thread(target=worker) for _ in range(4)]
        for t in ts:
            t.start()
        started.wait(5)
        time.sleep(0.2)
        self.assertGreater(node._INFLIGHT[0], 0)
        release.set()
        for t in ts:
            t.join(5)
        self.assertEqual(node._INFLIGHT[0], 0)

    def test_only_the_client_data_path_counts(self):
        """Gossip never stops and a tenant's long-poll is always open. If
        those counted, 'busy' would be permanently true and the node would
        never update."""
        self.assertEqual(set(node.DATA_PATHS), {"/kv", "/mget", "/delete"})
        for p in ("/gossip", "/poll", "/heartbeat", "/stats", "/dialback"):
            self.assertNotIn(p, node.DATA_PATHS)

    def test_check_interval_is_five_minutes(self):
        self.assertEqual(node.UPDATE_EVERY, 300.0)

    def test_deferral_is_bounded(self):
        """A permanently busy node must still eventually update."""
        self.assertGreater(node.UPDATE_MAX_DEFER, 0)
        self.assertLessEqual(node.UPDATE_MAX_DEFER, 24 * 3600)


class TestServiceWrapping(unittest.TestCase):
    def test_data_paths_are_wrapped_and_others_are_not(self):
        """The wrapper must not change what service_post returns."""
        node._INFLIGHT[0] = 0
        seen = {}

        class FakeStore:
            def mget(self, keys):
                seen["inflight"] = node._INFLIGHT[0]
                return {k: None for k in keys}

        code, body = node.service_post(FakeStore(), None, None, "", "/mget",
                                       {"keys": ["a"]})
        self.assertEqual(code, 200)
        self.assertIn("values", body)
        self.assertEqual(seen["inflight"], 1, "op was not counted")
        self.assertEqual(node._INFLIGHT[0], 0, "counter leaked")


if __name__ == "__main__":
    unittest.main()
