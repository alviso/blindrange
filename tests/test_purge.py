"""purge_orphans must find what a crashed compaction strands — and prove
purge_epochs cannot.

The fixtures forge the two real wreckage shapes, in the same key format a
crash leaves behind:

  * an intact chain under a deep label whose ancestors were deleted —
    unreachable to the pruned walk, perfectly visible to anyone who asks;
  * a chain whose prefix was deleted and whose tail survives — invisible
    to galloping, which assumes chains are dense.

Both shapes come straight from deletion order: compaction removes chains
top-down, parents before children, prefixes before tails.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request
from base64 import b64encode
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from blindrange import Owner  # noqa: E402

PORT = 7813
SECRET = "purgenet"


class PurgeCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="blindrange_purge_")
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

        cls.owner = Owner.create(
            f"{cls.tmp}/o.brdb", "pw",
            {"amount": {"type": "int", "bits": 10, "leaf_width": 32}},
            [f"127.0.0.1:{PORT}"], network_secret=SECRET)
        cls.rows = [{"amount": (i * 7) % 1024, "row": i} for i in range(200)]
        cls.owner.insert_many(cls.rows)
        cls.owner.drain()
        # One clean compaction: epoch 0 is now dead and empty, epoch 1 live.
        cls.owner.compact()

    @classmethod
    def tearDownClass(cls):
        cls.proc.kill()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    # -- forgery helpers, writing exactly what a crash leaves ------------

    def forge_chain(self, label, epoch, indices, rid=None):
        o = self.owner
        k_w = o._k_w(label)
        me = o._st["writer"]
        puts, keys = [], []
        for i in indices:
            raw = rid if rid is not None else os.urandom(8)
            mask = o._mask(k_w, epoch, me, i)
            masked = bytes(x ^ y for x, y in zip(raw, mask))
            key = o._ut(k_w, epoch, me, i)
            puts.append((key, b64encode(masked).decode()))
            keys.append(key)
        o._put(puts)
        return keys

    def gone(self, keys):
        return not self.owner._mget(list(keys))

    def survey(self):
        return sorted(r["row"] for r in self.owner.query("amount", 0, 1023))


class TestTheOldPurgeMissesWhatTheNewOneFinds(PurgeCase):
    def test_unreachable_subtree_then_holed_prefix(self):
        # Shape 1: intact chain deep in the tree, ancestors gone. The
        # pruned walk never descends here; there is nothing wrong with the
        # chain itself.
        deep = self.forge_chain("amount|4|3", 0, range(1, 41))
        # Shape 2: prefix deleted, tail survives — longer than the lattice
        # stride, which is the guarantee the docstring actually makes.
        holed = self.forge_chain("amount|1|0", 0,
                                 range(600, 600 + 700))

        before = self.survey()

        old = self.owner.purge_epochs()
        self.assertEqual(old["keys_removed"], 0,
                         "purge_epochs found the forged wreckage — then "
                         "this test no longer demonstrates the gap and "
                         "purge_orphans needs a harder fixture")
        self.assertFalse(self.gone(deep))

        out = self.owner.purge_orphans()
        self.assertEqual(out["coverage"], "full")
        self.assertGreaterEqual(out["chain_keys_removed"],
                                len(deep) + len(holed))
        self.assertTrue(self.gone(deep), "unreachable subtree survived")
        self.assertTrue(self.gone(holed), "holed-prefix tail survived")
        self.assertGreater(out["beyond_gallop"], 0,
                           "nothing was found past a galloped end, so the "
                           "dense scan proved nothing")

        # The reason any of this is safe to run: live data is untouched.
        self.assertEqual(self.survey(), before)

        again = self.owner.purge_orphans()
        self.assertEqual(again["chain_keys_removed"], 0, "not idempotent")


class TestBlobHandling(PurgeCase):
    def test_dead_rids_lose_their_blobs_and_live_rids_keep_them(self):
        o = self.owner
        dead_rid = os.urandom(8)
        o._put([("R:" + dead_rid.hex(), b64encode(b"junkjunkjunk").decode())])
        # Dense from index 1, the shape a real crash leaves when the chain
        # was never touched by the delete phase at all. A LONE entry at a
        # high index would slip between lattice probes — that is the
        # documented residual, not a target.
        self.forge_chain("amount|2|1", 0, range(1, 8), rid=dead_rid)

        live = o.query("amount", 0, 1023)[0]["_rid"]
        # A forged dead-epoch entry that unmasks to a LIVE rid: the blob
        # belongs to current data and must survive the sweep.
        self.forge_chain("amount|2|2", 0, range(1, 4),
                         rid=bytes.fromhex(live))

        out = o.purge_orphans()
        self.assertGreaterEqual(out["blobs_removed"], 1)
        self.assertFalse(o._mget(["R:" + dead_rid.hex()]),
                         "the orphaned blob survived")
        self.assertTrue(o._mget(["R:" + live]),
                        "a live record's blob was deleted — data loss")
        self.assertEqual(len(self.survey()), len(self.rows))


class TestGuards(PurgeCase):
    def test_refuses_while_a_compaction_is_in_flight(self):
        o = self.owner
        E = o._refresh_epoch()
        slot = o._st["epoch_len"] + 1
        o._put_nx(o._sys_key(b"epoch", slot), o._sys_encode(f"open:{E + 1}"))
        o._st["epoch_len"] = slot
        o._st["epoch"] = E + 1
        o._st["chains"] = {}
        o._st["compacting"] = E + 1
        o._save()
        try:
            with self.assertRaises(RuntimeError) as cm:
                o.purge_orphans()
            self.assertIn("resume", str(cm.exception),
                          "the refusal must say how to get unstuck")
        finally:
            o.compact()      # resumes its own marker and seals cleanly
        self.assertEqual(len(self.survey()), len(self.rows))


if __name__ == "__main__":
    unittest.main()
