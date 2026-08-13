"""End-to-end test: a real decentralized network, no central infrastructure.

Covers: gossip membership discovery from a single seed; multi-field inserts
and range/prefix queries verified against plaintext ground truth; node death
(replica failover); node join (gossip propagation); owner restart from the
passphrase-encrypted state file; wrong-passphrase rejection.

  python3 -m unittest tests.test_e2e -v
"""
import random
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from blindrange import Owner  # noqa: E402

BASE = 7601


def wait_http(addr, tries=60):
    for _ in range(tries):
        try:
            urllib.request.urlopen(f"http://{addr}/stats", timeout=1)
            return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"{addr} never came up")


def wait_peers(addr, n, tries=120):
    import json
    for _ in range(tries):
        with urllib.request.urlopen(f"http://{addr}/peers", timeout=2) as r:
            peers = json.loads(r.read())["peers"]
        if sum(1 for age in peers.values() if age <= 12) >= n:
            return
        time.sleep(0.25)
    raise RuntimeError(f"{addr} never saw {n} live peers")


class TestE2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="blindrange_test_")
        cls.procs = {}
        for i in range(6):                          # 6-node network, one seed
            port = BASE + i
            seed = [] if i == 0 else ["--seed", f"127.0.0.1:{BASE}"]
            cls.procs[port] = subprocess.Popen(
                [sys.executable, "-m", "blindrange.node", "--port", str(port),
                 "--data", f"{cls.tmp}/n{port}"] + seed,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                cwd=str(Path(__file__).resolve().parents[1]))
        for port in cls.procs:
            wait_http(f"127.0.0.1:{port}")
        wait_peers(f"127.0.0.1:{BASE}", 6)          # gossip converges

        cls.schema = {
            "amount": {"type": "int", "bits": 20, "leaf_width": 256},
            "day":    {"type": "int", "bits": 11, "leaf_width": 1},
            "name":   {"type": "str", "bits": 20, "leaf_width": 16, "chars": 4},
        }
        cls.state = f"{cls.tmp}/owner.brdb"
        cls.owner = Owner.create(cls.state, "correct horse", cls.schema,
                                 bootstrap=[f"127.0.0.1:{BASE}"])
        rng = random.Random(21)
        names = ["acme", "apex", "birch", "cedar", "delta", "ember", "flint",
                 "gale", "harbor", "iris", "sable", "salt", "sand", "scout"]
        cls.rows = [{"amount": rng.randint(500, 900_000),
                     "day": rng.randint(0, 700),
                     "name": rng.choice(names) + str(i), "row": i}
                    for i in range(400)]
        cls.owner.insert_many(cls.rows)

    @classmethod
    def tearDownClass(cls):
        for p in cls.procs.values():
            if p.poll() is None:
                p.terminate()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    # ---- helpers ------------------------------------------------------
    def _want(self, pred):
        return sorted(r["row"] for r in self.rows if pred(r))

    def _got(self, results):
        return sorted(r["row"] for r in results)

    def assert_query(self, field, lo, hi):
        got = self._got(self.owner.query(field, lo, hi))
        want = self._want(lambda r: lo <= r[field] <= hi)
        self.assertEqual(got, want, f"{field} in [{lo},{hi}]")

    # ---- tests --------------------------------------------------------
    def test_01_membership_discovered(self):
        self.assertEqual(len(self.owner.ring.addrs), 6)

    def test_02_int_ranges(self):
        self.assert_query("amount", 100_000, 300_000)
        self.assert_query("amount", 0, 5000)
        self.assert_query("day", 100, 200)

    def test_03_prefix(self):
        got = self._got(self.owner.query_prefix("name", "sa"))
        want = self._want(lambda r: r["name"].startswith("sa"))
        self.assertEqual(got, want)

    def test_04_survives_node_death(self):
        for port in (BASE + 2, BASE + 4):           # kill 2 of 6 (RF=3)
            self.procs[port].terminate()
            self.procs[port].wait()
        self.assert_query("amount", 100_000, 300_000)

    def test_05_node_join_via_gossip(self):
        port = BASE + 9
        self.procs[port] = subprocess.Popen(
            [sys.executable, "-m", "blindrange.node", "--port", str(port),
             "--data", f"{self.tmp}/n{port}", "--seed", f"127.0.0.1:{BASE}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            cwd=str(Path(__file__).resolve().parents[1]))
        wait_http(f"127.0.0.1:{port}")
        wait_peers(f"127.0.0.1:{port}", 5)          # new node learns the network
        time.sleep(3)                               # let the dead pair expire
        addrs = self.owner.refresh_membership()
        self.assertIn(f"127.0.0.1:{port}", addrs)
        self.assert_query("amount", 100_000, 300_000)   # failover + read-repair

    def test_06_owner_reopen_and_insert(self):
        reopened = Owner.open(self.state, "correct horse")
        got = self._got(reopened.query("day", 100, 200))
        self.assertEqual(got, self._want(lambda r: 100 <= r["day"] <= 200))
        reopened.insert({"amount": 123_456, "day": 150, "name": "zeta", "row": 9999})
        rows = [r["row"] for r in reopened.query("amount", 123_456, 123_456)]
        self.assertIn(9999, rows)
        self.rows.append({"amount": 123_456, "day": 150, "name": "zeta", "row": 9999})

    def test_07_wrong_passphrase_rejected(self):
        from cryptography.exceptions import InvalidTag
        with self.assertRaises(InvalidTag):
            Owner.open(self.state, "wrong horse")

    def test_08_multi_writer(self):
        # onboard a second writer via invite; separate state, separate passphrase
        ownerB = Owner.accept(f"{self.tmp}/ownerB.brdb", "second pass",
                              self.owner.invite())
        rngb = random.Random(77)
        rows_b = [{"amount": rngb.randint(500, 900_000),
                   "day": rngb.randint(0, 700),
                   "name": "bay" + str(i), "row": 10_000 + i}
                  for i in range(60)]
        ownerB.insert_many(rows_b)
        self.rows.extend(rows_b)

        # A sees B's rows purely via registry + galloping (no state sharing)
        self.assert_query("amount", 100_000, 300_000)
        self.assertGreaterEqual(self.owner.last_stats["writers"], 2)
        # and B sees A's rows
        got = sorted(r["row"] for r in ownerB.query("day", 100, 200))
        self.assertEqual(got, self._want(lambda r: 100 <= r["day"] <= 200))

        # interleaved writes to the SAME value never collide (namespaced chains)
        self.owner.insert({"amount": 777_777, "day": 42, "name": "dup a",
                           "row": 20_001})
        ownerB.insert({"amount": 777_777, "day": 42, "name": "dup b",
                       "row": 20_002})
        rows = sorted(r["row"] for r in
                      self.owner.query("amount", 777_777, 777_777))
        self.assertEqual(rows, [20_001, 20_002])
        self.rows.extend([
            {"amount": 777_777, "day": 42, "name": "dup a", "row": 20_001},
            {"amount": 777_777, "day": 42, "name": "dup b", "row": 20_002}])

    def test_09_cache_loss_is_recoverable(self):
        # a brand-new writer with an empty cache reconstructs everything by
        # probing the network — counters are a cache, not the database
        fresh = Owner.accept(f"{self.tmp}/ownerC.brdb", "third pass",
                             self.owner.invite())
        got = sorted(r["row"] for r in fresh.query("amount", 100_000, 300_000))
        self.assertEqual(got,
                         self._want(lambda r: 100_000 <= r["amount"] <= 300_000))


if __name__ == "__main__":
    unittest.main(verbosity=2)
