"""Local-first must change the cost of reads and nothing about their truth.

Every test here holds one of the mirror's stated promises to the fire:
identical answers with and without it, zero network rounds warm (absence
included — absence is where the WAN cost lived), writes visible to the
writer instantly, deletes that cannot resurrect, and a freshness contract
for other writers that degrades to slowness rather than to wrong answers.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import unittest.mock
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from blindrange import Owner  # noqa: E402

PORT = 7841
SECRET = "mirrornet"
SCHEMA = {"amount": {"type": "int", "bits": 16, "leaf_width": 16}}


class MirrorCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="blindrange_mirror_")
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

    @classmethod
    def tearDownClass(cls):
        cls.proc.kill()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def owner(self, name, mirror=True, sync_every=3600):
        o = Owner.create(f"{self.tmp}/{name}.brdb", "pw", SCHEMA,
                         [f"127.0.0.1:{PORT}"], network_secret=SECRET)
        if mirror:
            o.enable_mirror(sync_every=sync_every)
        return o

    @staticmethod
    def count_rounds(o):
        rounds = [0]
        real = o._mget_network
        o._mget_network = lambda keys: (
            rounds.__setitem__(0, rounds[0] + 1), real(keys))[1]
        return rounds


class TestSameAnswers(MirrorCase):
    def test_mirrored_and_plain_owners_agree(self):
        a = self.owner("plain", mirror=False)
        b = self.owner("mirrored")
        rows = [{"amount": (i * 13) % 4096, "n": i} for i in range(150)]
        a.insert_many(rows), b.insert_many(rows)
        a.drain(), b.drain()
        b.sync()
        for lo, hi in ((0, 4095), (100, 900), (4000, 4095)):
            want = sorted(r["n"] for r in a.query("amount", lo, hi))
            got = sorted(r["n"] for r in b.query("amount", lo, hi))
            self.assertEqual(got, want, (lo, hi))
            self.assertEqual(b.count("amount", lo, hi),
                             a.count("amount", lo, hi))


class TestLocality(MirrorCase):
    def test_warm_reads_touch_no_network_absence_included(self):
        o = self.owner("local")
        o.insert_many([{"amount": i, "n": i} for i in range(80)])
        o.drain()
        o.sync()
        rounds = self.count_rounds(o)
        got = o.query("amount", 10, 40)          # hits
        self.assertEqual(len(got), 31)
        self.assertEqual(o.query("amount", 3000, 4000), [])   # pure absence
        self.assertGreater(o.count("amount", 0, 4095), 0)
        self.assertEqual(rounds[0], 0,
                         "a warm mirrored read touched the network — the "
                         "entire point of local-first is that it does not")

    def test_own_writes_are_visible_with_zero_rounds_and_no_sync(self):
        o = self.owner("writethrough")
        o.insert_many([{"amount": 7, "n": 1}])
        o.drain()
        o.sync()
        o.insert_many([{"amount": 9, "n": 2}])   # after the sync pass
        o.drain()
        rounds = self.count_rounds(o)
        got = {r["n"] for r in o.query("amount", 0, 4095)}
        self.assertEqual(got, {1, 2}, "write-through missed a fresh write")
        self.assertEqual(rounds[0], 0)

    def test_deletes_cannot_resurrect_locally(self):
        o = self.owner("deletes")
        o.insert_many([{"amount": 5, "n": 1}, {"amount": 6, "n": 2}])
        o.drain()
        o.sync()
        rid = o.query("amount", 5, 5)[0]["_rid"]
        o.delete_many([rid])
        o.drain()
        got = {r["n"] for r in o.query("amount", 0, 4095)}
        self.assertEqual(got, {2}, "a mirrored read resurrected a delete")


class TestFreshnessContract(MirrorCase):
    def test_stale_mirror_falls_back_to_the_network(self):
        """The rule that keeps this honest: a miss is absence only while
        fresh. Force staleness and the miss must go ask the network."""
        from blindrange import mirror as mirror_mod
        o = self.owner("stale")
        o.insert_many([{"amount": 3, "n": 1}])
        o.drain()
        o.sync()
        # Forge a key landing on the network behind the mirror's back —
        # what another writer's insert looks like from here.
        o._mirror_backdoor = o._mirror
        m, o._mirror = o._mirror, None
        o.insert_many([{"amount": 4, "n": 2}])
        o.drain()
        o._mirror = m

        # Fresh: the new row is invisible (documented staleness), but the
        # old one answers locally.
        self.assertTrue(o._mirror.fresh())
        got = {r["n"] for r in o.query("amount", 0, 4095)}
        self.assertEqual(got, {1})

        # Stale: the same query must fall through and find everything.
        with unittest.mock.patch.object(mirror_mod, "MIRROR_STALE_S", 0.0), \
             unittest.mock.patch.object(type(o._mirror), "fresh",
                                        lambda self, stale_s=0: False):
            got = {r["n"] for r in o.query("amount", 0, 4095)}
        self.assertEqual(got, {1, 2},
                         "a stale mirror answered absence it could not know")

    def test_sync_delivers_another_writers_rows(self):
        o = self.owner("sync")
        o.insert_many([{"amount": 3, "n": 1}])
        o.drain()
        o.sync()
        m, o._mirror = o._mirror, None      # write behind the mirror's back
        o.insert_many([{"amount": 4, "n": 2}])
        o.drain()
        o._mirror = m
        o.sync()
        rounds = self.count_rounds(o)
        got = {r["n"] for r in o.query("amount", 0, 4095)}
        self.assertEqual(got, {1, 2}, "sync() did not deliver the new row")
        self.assertEqual(rounds[0], 0, "post-sync read was not local")


class TestRebuild(MirrorCase):
    def test_a_deleted_mirror_file_rebuilds_from_the_network(self):
        """The mirror is a cache with a contract, not a source of truth:
        losing the file costs a resync, never data."""
        o = self.owner("rebuild")
        o.insert_many([{"amount": i, "n": i} for i in range(40)])
        o.drain()
        o.sync()
        path = o._mirror.path
        o._mirror.close()
        o._mirror = None
        os.remove(path)
        o.enable_mirror(sync_every=3600)
        o.sync()
        self.assertEqual(len(o.query("amount", 0, 4095)), 40)
        rounds = self.count_rounds(o)
        o.query("amount", 0, 4095)
        self.assertEqual(rounds[0], 0, "rebuilt mirror is not serving reads")


if __name__ == "__main__":
    unittest.main()
