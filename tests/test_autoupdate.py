"""Auto-update: when it fires, when it waits, and when it complains.

Two failures this guards against, both seen in production. A node ran stale
code for a day with --auto-update set because its sandbox made its own
checkout read-only and the pull failure was swallowed. And a node once
restarted mid-ingest, which cost a benchmark at 620k records.
"""
import threading
import time
import unittest

from pathlib import Path

import blindrange.node as node

ROOT = Path(__file__).resolve().parents[1]


class TestInFlightTracking(unittest.TestCase):
    def setUp(self):
        node._INFLIGHT[0] = 0
        node._LAST_OP[0] = 0.0

    def tearDown(self):
        node._INFLIGHT[0] = 0
        node._LAST_OP[0] = 0.0

    def test_idle_when_nothing_is_happening(self):
        self.assertFalse(node.data_path_busy())

    def test_busy_while_an_operation_runs(self):
        with node._op():
            self.assertTrue(node.data_path_busy())
            self.assertEqual(node._INFLIGHT[0], 1)

    def test_idle_the_moment_the_last_request_finishes(self):
        """Observed in production: also requiring a quiet window since the
        last COMPLETED request meant a node under steady traffic never went
        idle, deferred the full hour, and then restarted at an arbitrary
        moment having logged "0 operation(s) in flight" throughout."""
        with node._op():
            self.assertTrue(node.data_path_busy())
        self.assertFalse(node.data_path_busy(),
                         "steady traffic must not block updates forever")

    def test_continuous_traffic_still_yields_idle_gaps(self):
        """A stream of back-to-back requests, sampled between them, must
        show idle — otherwise the deferral never ends."""
        seen_idle = False
        for _ in range(20):
            with node._op():
                pass
            if not node.data_path_busy():
                seen_idle = True
        self.assertTrue(seen_idle)

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

    def test_idle_samples_are_configured(self):
        self.assertGreaterEqual(node.UPDATE_IDLE_SAMPLES, 1)
        self.assertLessEqual(node.UPDATE_IDLE_SAMPLES, 10)

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


class TestRestartMechanics(unittest.TestCase):
    """How a node comes back, which differs by platform.

    Unix replaces the process in place. Windows cannot: os.execv there
    spawns a new process and kills this one, leaving the console and the
    listening socket ambiguous for a moment. Either way the replacement can
    reach the port before the outgoing process has let go of it.
    """

    def test_bind_retry_is_configured(self):
        self.assertGreaterEqual(node.BIND_RETRY_S, 5,
                                "too short to cover a handover")
        self.assertLessEqual(node.BIND_RETRY_S, 120)

    def test_windows_uses_spawn_not_execv(self):
        import inspect
        src = inspect.getsource(node._update_loop)
        self.assertIn('os.name == "nt"', src)
        self.assertIn("subprocess.Popen", src)
        self.assertIn("os.execv", src, "unix path must remain")

    def test_restart_preserves_how_it_was_started(self):
        """Under `python -m pkg.mod`, argv[0] is a file path — re-execing it
        directly breaks every relative import."""
        import inspect
        src = inspect.getsource(node._update_loop)
        self.assertIn("__spec__", src)
        self.assertIn('"-m"', src)

    def test_node_waits_for_a_held_port_instead_of_dying(self):
        import socket
        import subprocess
        import sys
        import tempfile
        import shutil
        import urllib.request
        held = socket.socket()
        held.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        held.bind(("127.0.0.1", 0))
        port = held.getsockname()[1]
        held.listen(1)
        tmp = tempfile.mkdtemp()
        p = subprocess.Popen(
            [sys.executable, "-m", "blindrange.node", "--port", str(port),
             "--data", tmp, "--secret", "bindtest"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            cwd=str(ROOT))
        try:
            time.sleep(3)
            self.assertIsNone(p.poll(), "node gave up instead of retrying")
            held.close()
            for _ in range(20):
                try:
                    urllib.request.urlopen(
                        f"http://127.0.0.1:{port}/stats", timeout=1)
                    break
                except OSError:
                    time.sleep(1)
            else:
                self.fail("node never bound after the port was released")
        finally:
            if p.poll() is None:
                p.terminate()
            p.wait()
            shutil.rmtree(tmp, ignore_errors=True)
