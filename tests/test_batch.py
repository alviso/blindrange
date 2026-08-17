"""batch() and next_values(): the two levers that turn a 9-second
invoice-create route into one network barrier.

batch()'s contract: everything inside flushes as ONE replicated write;
an exception inside sends nothing and leaves no chain holes; reads
inside the block do not see the block's own writes. next_values'
contract: same uniqueness arbitration as next_value at the latency of
one claim.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import time
import threading
import unittest
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from blindrange import Owner                    # noqa: E402

PORT = 7861
SECRET = "batchnet"
SCHEMA = {"amount": {"type": "int", "bits": 16, "leaf_width": 16}}


class BatchCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="blindrange_batch_")
        cls.proc = subprocess.Popen(
            [sys.executable, "-m", "blindrange.node", "--port", str(PORT),
             "--data", f"{cls.tmp}/node", "--secret", SECRET],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            cwd=str(ROOT), env={**os.environ})
        for _ in range(80):
            try:
                urllib.request.urlopen(
                    f"http://127.0.0.1:{PORT}/stats", timeout=1)
                break
            except OSError:
                time.sleep(0.1)
        else:
            raise RuntimeError("node never came up")
        cls.owner = Owner.create(f"{cls.tmp}/db", "pw", SCHEMA,
                                 [f"127.0.0.1:{PORT}"], SECRET)

    @classmethod
    def tearDownClass(cls):
        cls.owner.drain()
        cls.proc.kill()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def rows(self, lo, hi):
        return sorted(r["row"] for r in self.owner.query("amount", lo, hi))


class TestBatch(BatchCase):
    def test_01_one_barrier_many_calls(self):
        # Count wire writes: inside the block there must be none; the
        # whole block must land as a single _put call.
        real_put = type(self.owner)._put
        calls = []

        def spy(o, kv):
            calls.append(len(list(kv)))
            return real_put(o, kv)

        with unittest.mock.patch.object(type(self.owner), "_put", spy):
            with self.owner.batch():
                for n in range(5):
                    self.owner.insert({"amount": 1000 + n, "row": n})
                # five inserts, zero wire writes so far: the batch gate
                # swallows each insert's _put into the buffer
                self.assertEqual(len([c for c in calls]), 5)
                inner = len(calls)
            # exit flushed exactly once more, carrying every pair
            self.assertEqual(len(calls), inner + 1)
        self.assertEqual(self.rows(1000, 1004), [0, 1, 2, 3, 4])

    def test_02_exception_sends_nothing_and_leaves_no_holes(self):
        with self.assertRaises(ValueError):
            with self.owner.batch():
                self.owner.insert({"amount": 2000, "row": 100})
                self.owner.insert({"amount": 2001, "row": 101})
                raise ValueError("route aborted")
        self.assertEqual(self.rows(2000, 2001), [])
        # The rollback must restore chain density: a later insert lands
        # on the SAME slots the aborted block claimed, and is findable —
        # a hole here would hide it and every entry after it.
        self.owner.insert({"amount": 2002, "row": 102})
        self.assertEqual(self.rows(2000, 2002), [102])

    def test_03_update_and_delete_ride_the_same_barrier(self):
        self.owner.insert({"amount": 3000, "row": 200})
        rid = self.owner.query("amount", 3000, 3000)[0]["_rid"]
        with self.owner.batch():
            self.owner.delete(rid)
            self.owner.insert({"amount": 3001, "row": 201})
        self.assertEqual(self.rows(3000, 3001), [201])

    def test_04_nesting_refused(self):
        with self.owner.batch():
            with self.assertRaises(RuntimeError):
                with self.owner.batch():
                    pass


class TestNextValues(BatchCase):
    def test_01_block_is_unique_sorted_and_advances(self):
        got = self.owner.next_values("inv", 5)
        self.assertEqual(len(got), 5)
        self.assertEqual(got, sorted(set(got)))
        nxt = self.owner.next_value("inv")
        self.assertGreater(nxt, max(got))

    def test_02_racing_writers_never_share_a_number(self):
        other = Owner.accept(f"{self.tmp}/dbB", "pw2", self.owner.invite())
        results = {}

        def claim(who, o):
            results[who] = o.next_values("race", 20)

        ts = [threading.Thread(target=claim, args=("a", self.owner)),
              threading.Thread(target=claim, args=("b", other))]
        [t.start() for t in ts]
        [t.join() for t in ts]
        a, b = set(results["a"]), set(results["b"])
        self.assertEqual(len(a), 20)
        self.assertEqual(len(b), 20)
        self.assertFalse(a & b, f"shared numbers: {sorted(a & b)}")


import unittest.mock  # noqa: E402  (used by TestBatch)

if __name__ == "__main__":
    unittest.main()
