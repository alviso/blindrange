"""End-to-end test: a real decentralized network, no central infrastructure.

Covers: gossip membership discovery from a single seed; multi-field inserts
and range/prefix queries verified against plaintext ground truth; node death
(replica failover); node join (gossip propagation); owner restart from the
passphrase-encrypted state file; wrong-passphrase rejection.

  python3 -m unittest tests.test_e2e -v
"""
import os
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


def wait_peers(addr, n, secret, tries=120):
    import hashlib
    import hmac
    import json
    sig = hmac.new(secret.encode(), b"/peers", hashlib.sha256).hexdigest()
    for _ in range(tries):
        try:
            req = urllib.request.Request(f"http://{addr}/peers",
                                         headers={"X-BR-Auth": sig})
            with urllib.request.urlopen(req, timeout=2) as r:
                peers = json.loads(r.read())["peers"]
            if sum(1 for e in peers.values() if e["age"] <= 12) >= n:
                return
        except OSError:
            pass                                    # node still starting
        time.sleep(0.25)
    raise RuntimeError(f"{addr} never saw {n} live peers")


class TestE2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="blindrange_test_")
        cls.secret = "testnet-secret"
        cls.procs = {}
        for i in range(6):                          # 6-node network, one seed
            port = BASE + i
            seed = [] if i == 0 else ["--seed", f"127.0.0.1:{BASE}"]
            cls.procs[port] = subprocess.Popen(
                [sys.executable, "-m", "blindrange.node", "--port", str(port),
                 "--data", f"{cls.tmp}/n{port}", "--secret", cls.secret] + seed,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                cwd=str(Path(__file__).resolve().parents[1]))
        for port in cls.procs:
            wait_http(f"127.0.0.1:{port}")
        wait_peers(f"127.0.0.1:{BASE}", 6, cls.secret)   # gossip converges

        cls.schema = {
            "amount": {"type": "int", "bits": 20, "leaf_width": 256},
            "day":    {"type": "int", "bits": 11, "leaf_width": 1},
            "name":   {"type": "str", "bits": 20, "leaf_width": 16, "chars": 4},
        }
        cls.state = f"{cls.tmp}/owner.brdb"
        cls.owner = Owner.create(cls.state, "correct horse", cls.schema,
                                 bootstrap=[f"127.0.0.1:{BASE}"],
                                 network_secret=cls.secret)
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
            p.wait()
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

    def test_03b_hot_label_striping(self):
        # 100 records with the SAME value: per-entry PRF keys must stripe the
        # hot label's entries across the ring, not pile onto one node
        import json
        def keycounts():
            out = {}
            for n in self.owner.network():
                if "keys" in n:
                    out[n["addr"]] = n["keys"]
            return out
        before = keycounts()
        hot = [{"amount": 999_999, "day": 999, "name": "hot" + str(i),
                "row": 40_000 + i} for i in range(100)]
        self.owner.insert_many(hot)
        self.rows.extend(hot)
        after = keycounts()
        gained = sum(1 for a in after if after[a] > before.get(a, 0))
        self.assertGreaterEqual(gained, 4,
                                f"hot label concentrated: {before} -> {after}")
        got = self._got(self.owner.query("amount", 999_999, 999_999))
        self.assertEqual(got, sorted(r["row"] for r in hot))

    def test_04_survives_node_death(self):
        for port in (BASE + 2, BASE + 4):           # kill 2 of 6 (RF=3)
            self.procs[port].terminate()
            self.procs[port].wait()
        self.assert_query("amount", 100_000, 300_000)

    def test_05_node_join_via_gossip(self):
        port = BASE + 9
        self.procs[port] = subprocess.Popen(
            [sys.executable, "-m", "blindrange.node", "--port", str(port),
             "--data", f"{self.tmp}/n{port}", "--seed", f"127.0.0.1:{BASE}",
             "--secret", self.secret],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            cwd=str(Path(__file__).resolve().parents[1]))
        wait_http(f"127.0.0.1:{port}")
        wait_peers(f"127.0.0.1:{port}", 5, self.secret)  # learns the network
        # membership is eventually consistent: poll until the owner's view
        # includes the new node and has dropped the dead pair
        deadline = time.time() + 20
        while time.time() < deadline:
            self.owner.refresh_membership()
            if f"127.0.0.1:{port}" in self.owner._addr_of.values():
                break
            time.sleep(0.5)
        self.assertIn(f"127.0.0.1:{port}",
                      self.owner._addr_of.values())
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

    def test_10_two_field_and_query(self):
        got = sorted(r["row"] for r in self.owner.query_multi([
            {"field": "amount", "lo": 100_000, "hi": 600_000},
            {"field": "day", "lo": 100, "hi": 400}]))
        want = self._want(lambda r: 100_000 <= r["amount"] <= 600_000
                          and 100 <= r["day"] <= 400)
        self.assertEqual(got, want)
        self.assertEqual(len(self.owner.last_stats["per_predicate"]), 2)
        # prefix AND range
        got = sorted(r["row"] for r in self.owner.query_multi([
            {"field": "name", "prefix": "ba"},
            {"field": "day", "lo": 0, "hi": 350}]))
        want = self._want(lambda r: r["name"].startswith("ba")
                          and 0 <= r["day"] <= 350)
        self.assertEqual(got, want)

    def test_11_delete_with_tombstones(self):
        victims = self.owner.query("amount", 777_777, 777_777)
        self.assertEqual(len(victims), 2)
        self.owner.delete_many([r["_rid"] for r in victims])
        self.assertEqual(self.owner.query("amount", 777_777, 777_777), [])
        # a completely fresh client sees the deletion too (tombstones are
        # on the network, not local state)
        fresh = Owner.accept(f"{self.tmp}/ownerD.brdb", "fourth pass",
                             self.owner.invite())
        self.assertEqual(fresh.query("amount", 777_777, 777_777), [])
        self.rows[:] = [r for r in self.rows if r["row"] not in (20_001, 20_002)]

    def test_12_compaction(self):
        stats = self.owner.compact()
        self.assertGreater(stats["entries"], 0)
        self.assertGreater(stats["dropped"], 0)      # tombstoned rows removed
        # everything still correct after the epoch rewrite
        self.assert_query("amount", 100_000, 300_000)
        self.assert_query("day", 100, 200)
        got = sorted(r["row"] for r in self.owner.query_prefix("name", "sa"))
        self.assertEqual(got,
                         self._want(lambda r: r["name"].startswith("sa")))
        # other writers pick up the new epoch with one probe and keep working
        late = Owner.accept(f"{self.tmp}/ownerE.brdb", "fifth pass",
                            self.owner.invite())
        late.insert({"amount": 555_555, "day": 77, "name": "late", "row": 30_000})
        rows = [r["row"] for r in self.owner.query("amount", 555_555, 555_555)]
        self.assertEqual(rows, [30_000])
        self.rows.append({"amount": 555_555, "day": 77, "name": "late",
                          "row": 30_000})

    def test_12b_streaming_matches_materialised_query(self):
        rows = self.owner.query("amount", 100_000, 600_000)
        streamed = list(self.owner.query_stream(
            [{"field": "amount", "lo": 100_000, "hi": 600_000}]))
        self.assertGreater(len(rows), 0)             # never pass vacuously
        self.assertEqual(sorted(r["row"] for r in streamed),
                         sorted(r["row"] for r in rows))

    def test_12c_streaming_orders_without_revealing_order(self):
        got = list(self.owner.query_stream(
            [{"field": "amount", "lo": 0, "hi": 900_000}], order="amount"))
        amounts = [r["amount"] for r in got]
        self.assertGreater(len(amounts), 10)
        self.assertEqual(amounts, sorted(amounts))
        self.assertTrue(self.owner.last_stats["ordered"])

    def test_12d_cursor_pages_without_gaps_or_repeats(self):
        preds = [{"field": "amount", "lo": 0, "hi": 900_000}]
        everything = list(self.owner.query_stream(preds))
        self.assertGreater(len(everything), 50)
        seen, cursor = [], None
        while len(seen) < len(everything):
            page = list(self.owner.query_stream(preds, limit=17, after=cursor))
            if not page:
                break
            seen += [r["row"] for r in page]
            cursor = page[-1]["_cursor"]
        self.assertEqual(sorted(seen), sorted(r["row"] for r in everything))
        self.assertEqual(len(seen), len(set(seen)))

    def test_12e_and_query_drives_off_the_cheaper_predicate(self):
        got = list(self.owner.query_stream([
            {"field": "amount", "lo": 0, "hi": 900_000},
            {"field": "day", "lo": 100, "hi": 120}]))
        want = [r for r in self.rows
                if 0 <= r["amount"] <= 900_000 and 100 <= r["day"] <= 120]
        self.assertGreater(len(want), 0)
        self.assertEqual(sorted(r["row"] for r in got),
                         sorted(r["row"] for r in want))
        self.assertEqual(self.owner.last_stats["driver"], "day")

    def test_12f_count_and_histogram_fetch_no_records(self):
        lo, hi = 100_000, 600_000
        want = [r for r in self.rows if lo <= r["amount"] <= hi]
        self.assertEqual(self.owner.count("amount", lo, hi), len(want))
        self.assertEqual(self.owner.last_stats["records_fetched"], 0)
        self.assertEqual(self.owner.last_stats["decrypted"], 0)

        bars = self.owner.histogram("amount", lo, hi, buckets=8)
        self.assertLessEqual(len(bars), 8)
        self.assertEqual(sum(b["count"] for b in bars), len(want))
        self.assertEqual(self.owner.last_stats["records_fetched"], 0)

    def test_12g_approx_sum_stays_inside_its_error_bound(self):
        lo, hi = 100_000, 600_000
        rows = [r["amount"] for r in self.rows if lo <= r["amount"] <= hi]
        est, err, n = self.owner.approx_sum("amount", lo, hi)
        self.assertEqual(n, len(rows))
        self.assertLessEqual(abs(est - sum(rows)), err,
                             "estimate escaped the leaf_width error bound")

    def test_12h_write_quorum_never_leaves_holes(self):
        """Returning before every replica acks must not break chain density:
        galloping discovery assumes entry i exists iff i <= end, so a key
        that landed nowhere would hide every later entry in its chain."""
        fast = Owner.accept(f"{self.tmp}/quorum.brdb", "q pass",
                            self.owner.invite())
        fast.write_acks = 1                      # return on the first ack
        rows = [{"amount": 700_000 + i, "day": 500, "name": "quor" + str(i),
                 "row": 60_000 + i} for i in range(120)]
        fast.insert_many(rows)
        fast.drain()                             # let the rest land

        got = sorted(r["row"] for r in fast.query("amount", 700_000, 700_200))
        self.assertEqual(got, sorted(r["row"] for r in rows))
        # and another writer sees the same chain, densely
        also = sorted(r["row"] for r in
                      self.owner.query("amount", 700_000, 700_200))
        self.assertEqual(also, sorted(r["row"] for r in rows))
        self.rows.extend(rows)

    def test_12i_inflight_writes_stay_bounded(self):
        fast = Owner.open(f"{self.tmp}/quorum.brdb", "q pass")
        fast.write_acks, fast.max_inflight = 1, 8
        for i in range(6):
            fast.insert_many([{"amount": 800_000 + i, "day": 1, "name": "bnd",
                               "row": 70_000 + i}])
            self.assertLessEqual(len(fast._inflight), 8 + self.owner.ring.replicas)
        fast.drain()
        self.assertEqual(len(fast._inflight), 0)
        self.rows.extend([{"amount": 800_000 + i, "day": 1, "name": "bnd",
                           "row": 70_000 + i} for i in range(6)])

    def test_12j_audit_measures_possession(self):
        """A node's key count is self-reported; possession is not. Auditing
        fetches records from the node the ring holds responsible and checks
        AES-GCM, which a node cannot fake — it can neither derive the key
        nor forge the ciphertext. Non-destructive; loss detection lives in
        TestAudit, which owns its own nodes."""
        self.owner.drain()
        report = self.owner.audit(sample=40)
        self.assertGreater(report["sampled_records"], 0)
        checked = [v for v in report["nodes"].values() if v["responsible"]]
        self.assertTrue(checked)
        # A spread is normal and honest: a third replica holds nothing until
        # repair reaches it (write_acks is below the replica count), and a
        # freshly joined node holds nothing at all. Possession is a rate,
        # not a verdict — which matters a great deal if it ever feeds payouts.
        best = max(checked, key=lambda v: v["possession"] or 0)
        self.assertGreater(best["possession"], 0.5)
        self.assertIsNotNone(best["claims"])     # self-report, for contrast

    def test_13_unauthenticated_requests_rejected(self):
        import json as _json
        req = urllib.request.Request(
            f"http://127.0.0.1:{BASE}/kv",
            data=_json.dumps({"entries": [["X:junk", "vandalism"]]}).encode(),
            headers={"Content-Type": "application/json"})
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=3)
        self.assertEqual(ctx.exception.code, 401)
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(f"http://127.0.0.1:{BASE}/peers", timeout=3)
        self.assertEqual(ctx.exception.code, 401)

    def test_14_repair_sweep(self):
        stats = self.owner.repair()
        self.assertGreater(stats["healed"], 0)
        self.assertGreaterEqual(stats["checked"], stats["healed"])
        self.assert_query("amount", 100_000, 300_000)
        self.assert_query("day", 100, 200)

    def test_15_concurrent_compaction(self):
        # a writer keeps inserting WHILE the compactor runs; the open/drain/
        # seal protocol must lose nothing
        import threading
        racer = Owner.accept(f"{self.tmp}/ownerF.brdb", "sixth pass",
                             self.owner.invite())
        raced = [{"amount": 888_000 + i, "day": 20 + (i % 30),
                  "name": "race" + str(i), "row": 50_000 + i}
                 for i in range(30)]
        errors = []

        def insert_loop():
            try:
                for rec in raced:
                    racer.insert(rec)
            except Exception as e:                    # surface, don't swallow
                errors.append(e)

        t = threading.Thread(target=insert_loop)
        t.start()
        stats = self.owner.compact()
        t.join()
        self.assertFalse(errors)
        self.assertGreater(stats["entries"], 0)
        self.rows.extend(raced)
        got = self._got(self.owner.query("amount", 888_000, 888_100))
        self.assertEqual(got, sorted(r["row"] for r in raced))
        self.assert_query("amount", 100_000, 300_000)   # older data intact


class TestAudit(unittest.TestCase):
    """Silent data loss is invisible in self-reported stats and obvious to an
    audit. Owns its nodes: the test destroys data deliberately."""

    def test_audit_catches_a_node_that_discards_data(self):
        import shutil as _shutil
        import sqlite3
        tmp = tempfile.mkdtemp(prefix="blindrange_audit_")
        secret, root = "audnet", str(Path(__file__).resolve().parents[1])
        procs = []
        try:
            for i, port in enumerate((7931, 7932, 7933)):
                args = [sys.executable, "-m", "blindrange.node", "--port",
                        str(port), "--data", f"{tmp}/n{port}",
                        "--secret", secret]
                if i:
                    args += ["--seed", "127.0.0.1:7931"]
                procs.append(subprocess.Popen(
                    args, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, cwd=root))
            wait_http("127.0.0.1:7931")
            wait_peers("127.0.0.1:7931", 3, secret)

            owner = Owner.create(f"{tmp}/a.brdb", "pw",
                                 {"ts": {"type": "int", "bits": 22,
                                         "leaf_width": 4096}},
                                 bootstrap=["127.0.0.1:7931"],
                                 network_secret=secret)
            owner.write_acks = 3                # all replicas, so 1.0 is fair
            rng = random.Random(6)
            owner.insert_many([{"ts": rng.randrange(2592000), "m": "x"}
                               for _ in range(600)])
            owner.drain()

            before = owner.audit(sample=40)["nodes"]
            for v in before.values():
                if v["responsible"]:
                    self.assertEqual(v["possession"], 1.0)

            victim = max(before, key=lambda n: before[n]["possession"] or 0)
            port = int(before[victim]["addr"].split(":")[1])
            db = sqlite3.connect(f"{tmp}/n{port}/kv.db")
            blobs = [r[0] for r in db.execute(
                "SELECT k FROM kv WHERE k LIKE 'R:%'").fetchall()]
            for k in blobs[:len(blobs) // 2]:
                db.execute("DELETE FROM kv WHERE k=?", (k,))
            db.commit()
            db.close()

            after = owner.audit(sample=60)["nodes"][victim]
            self.assertLess(after["possession"], 0.8,
                            "audit missed silently discarded data")
            self.assertIsNotNone(after["claims"])   # still reports a number
        finally:
            for p in procs:
                if p.poll() is None:
                    p.terminate()
                p.wait()
            _shutil.rmtree(tmp, ignore_errors=True)


class TestReportCost(unittest.TestCase):
    """Submitting an audit report must cost something, and every cheap lie
    about a node must fail. Owns its nodes: the tests forge and tamper."""

    PORTS = (7941, 7942, 7943)

    @classmethod
    def setUpClass(cls):
        import importlib.util
        root = Path(__file__).resolve().parents[1]
        cls.tmp = tempfile.mkdtemp(prefix="blindrange_cost_")
        cls.secret, cls.procs = "costnet" + cls.__name__, []
        for i, port in enumerate(cls.PORTS):
            args = [sys.executable, "-m", "blindrange.node", "--port",
                    str(port), "--data", f"{cls.tmp}/n{port}",
                    "--secret", cls.secret]
            if i:
                args += ["--seed", f"127.0.0.1:{cls.PORTS[0]}"]
            cls.procs.append(subprocess.Popen(
                args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                cwd=str(root)))
        wait_http(f"127.0.0.1:{cls.PORTS[0]}")
        wait_peers(f"127.0.0.1:{cls.PORTS[0]}", 3, cls.secret)

        spec = importlib.util.spec_from_file_location(
            "status_server", root / "examples" / "status_server.py")
        cls.agg = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.agg)
        cls.agg.POW_BITS = 8               # keep the suite fast; logic is same

        cls.owner = Owner.create(
            f"{cls.tmp}/a.brdb", "pw",
            {"ts": {"type": "int", "bits": 22, "leaf_width": 4096}},
            bootstrap=[f"127.0.0.1:{cls.PORTS[0]}"], network_secret=cls.secret)
        cls.owner.write_acks = 3           # every replica, so 1.0 is fair
        rng = random.Random(21)
        cls.owner.insert_many([{"ts": rng.randrange(2592000), "m": "x"}
                               for _ in range(400)])
        cls.owner.drain()

    @classmethod
    def tearDownClass(cls):
        for p in cls.procs:
            if p.poll() is None:
                p.terminate()
            p.wait()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def setUp(self):
        self.agg.REPORTS.clear()
        self.agg.SEEN_SET.clear()
        self.agg.SEEN_SIGS.clear()

    def report(self):
        from blindrange import receipt
        rep = self.owner.audit_report()
        rep["pow"] = receipt.solve(rep, self.agg.POW_BITS)
        return rep

    def test_honest_report_is_accepted_and_scores_every_node(self):
        out = self.agg.record_report(self.report())
        self.assertGreaterEqual(out["accepted"], 3)
        for nid, v in self.agg.possession().items():
            self.assertEqual(v["rate"], 1.0, f"{nid} should be intact")

    def test_reads_are_all_signed_so_an_audit_is_indistinguishable(self):
        """A node that could spot an audit could serve those and drop the
        rest, so an ordinary read must look exactly like an audited one."""
        from blindrange import receipt
        addr = self.owner._addr(next(iter(self.owner.ring.addrs)))
        nonce = "ab" * 16
        out = self.owner._post(addr, "/mget",
                               {"keys": ["R:nope"], "nonce": nonce})
        self.assertIn("receipt", out, "plain read went unsigned")
        self.assertTrue(receipt.verify(out["receipt"], time.time()))

    def test_report_without_proof_of_work_is_refused(self):
        rep = self.report()
        rep.pop("pow")
        with self.assertRaises(ValueError) as e:
            self.agg.record_report(rep)
        self.assertIn("proof of work", str(e.exception))

    def test_proof_of_work_does_not_transfer_to_another_report(self):
        rep = self.report()
        rep["nodes"] = {"deadbeefdeadbeef": {"sampled": 1, "verified": 1}}
        with self.assertRaises(ValueError) as e:
            self.agg.record_report(rep)
        self.assertIn("proof of work", str(e.exception))

    def test_fabricated_report_with_no_receipts_is_refused(self):
        """The original attack: arbitrary JSON, no exchange behind it."""
        from blindrange import receipt
        rep = {"kind": "blindrange-audit", "v": 1, "proofs": [],
               "nodes": {"f" * 16: {"sampled": 100, "verified": 100},
                         "e" * 16: {"sampled": 100, "verified": 0}}}
        rep["pow"] = receipt.solve(rep, self.agg.POW_BITS)
        with self.assertRaises(ValueError) as e:
            self.agg.record_report(rep)
        self.assertIn("corroborated", str(e.exception))

    def test_slander_with_invented_keys_earns_no_evidence(self):
        """Ask a node for keys that never existed and it will honestly sign
        that it returned none of them. That must not read as data loss."""
        from blindrange import receipt
        keys = [f"R:{i:040x}" for i in range(20)]      # nothing ever wrote these
        nonce = os.urandom(16).hex()
        group = {}
        for nid in self.owner.ring.route(keys[0]):
            addr = self.owner._addr(nid)
            if not addr:
                continue
            out = self.owner._post(addr, "/mget",
                                   {"keys": keys, "nonce": nonce})
            group[nid] = {"verified": 0, "receipt": out["receipt"]}
        self.assertGreaterEqual(len(group), 2, "need a group to slander")
        rep = {"kind": "blindrange-audit", "v": 1, "nodes": {},
               "proofs": [group]}
        rep["pow"] = receipt.solve(rep, self.agg.POW_BITS)
        with self.assertRaises(ValueError):
            self.agg.record_report(rep)
        self.assertEqual(self.agg.possession(), {},
                         "invented keys were counted against real nodes")

    def test_replaying_a_report_does_not_stack_evidence(self):
        rep = self.report()
        self.agg.record_report(rep)
        with self.assertRaises(ValueError):
            self.agg.record_report(rep)
        for v in self.agg.possession().values():
            self.assertEqual(v["reports"], 1, "replay counted twice")

    def test_verified_cannot_exceed_what_the_node_signed_for(self):
        """The sender's own numbers are a hint; the node's signature is the
        ceiling. Inflating past it must be clamped, not believed."""
        from blindrange import receipt
        rep = self.report()
        for group in rep["proofs"]:
            for v in group.values():
                v["verified"] = 10 ** 6
        rep["pow"] = receipt.solve(rep, self.agg.POW_BITS)
        self.agg.record_report(rep)
        for nid, v in self.agg.possession().items():
            self.assertEqual(v["rate"], 1.0)          # clamped to served
        self.assertTrue(self.agg.possession())

    def test_a_tampered_receipt_is_thrown_away(self):
        from blindrange import receipt
        rep = self.report()
        for group in rep["proofs"]:
            for v in group.values():
                v["receipt"]["served"] = int(v["receipt"]["served"]) + 5
        rep["pow"] = receipt.solve(rep, self.agg.POW_BITS)
        with self.assertRaises(ValueError):
            self.agg.record_report(rep)

class TestReportCostUnderLoss(TestReportCost):
    """The destructive half, on its own nodes. Folded into the shared class
    it ran first (alphabetically) and every later test then scored a network
    it had already damaged — which is precisely the 'healthy node reads 0.33'
    confusion this separation exists to prevent."""

    PORTS = (7951, 7952, 7953)

    def test_zz_a_node_that_discards_data_scores_below_its_replicas(self):
        import sqlite3
        self.agg.record_report(self.report())
        victim = next(iter(self.agg.possession()))
        port = int(self.owner._addr(victim).split(":")[1])
        db = sqlite3.connect(f"{self.tmp}/n{port}/kv.db")
        blobs = [r[0] for r in db.execute(
            "SELECT k FROM kv WHERE k LIKE 'R:%'").fetchall()]
        for k in blobs[:int(len(blobs) * 0.7)]:
            db.execute("DELETE FROM kv WHERE k=?", (k,))
        db.commit()
        db.close()

        self.setUp()                        # score the damaged network fresh
        self.agg.record_report(self.report())
        scores = self.agg.possession()
        self.assertLess(scores[victim]["rate"], 0.6,
                        "silent loss went unnoticed")
        for nid, v in scores.items():
            if nid != victim:
                self.assertEqual(v["rate"], 1.0,
                                 "healthy peer was dragged down")


class TestNodeBackgroundRepair(unittest.TestCase):
    """Nodes heal the network among THEMSELVES: data written before a node
    joined must migrate to it with no owner involvement, until the original
    holders can all die without data loss."""

    def test_gossip_driven_migration(self):
        import json
        import os
        tmp = tempfile.mkdtemp(prefix="blindrange_repair_")
        secret = "repairnet"
        env = {**os.environ, "BR_REPAIR_EVERY": "0.5",
               "BR_REPAIR_BATCH": "5000"}
        root = str(Path(__file__).resolve().parents[1])
        ports = [7701, 7702, 7703]

        def start(port, seeds):
            args = [sys.executable, "-m", "blindrange.node", "--port",
                    str(port), "--data", f"{tmp}/n{port}",
                    "--secret", secret]
            for s in seeds:
                args += ["--seed", s]
            return subprocess.Popen(args, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, cwd=root,
                                    env=env)
        procs = {}
        try:
            procs[7701] = start(7701, [])
            wait_http("127.0.0.1:7701")
            procs[7702] = start(7702, ["127.0.0.1:7701"])
            wait_peers("127.0.0.1:7701", 2, secret)

            owner = Owner.create(f"{tmp}/o.brdb", "pw",
                                 {"x": {"type": "int", "bits": 12,
                                        "leaf_width": 4}},
                                 bootstrap=["127.0.0.1:7701"],
                                 network_secret=secret)
            rows = [{"x": i * 3, "row": i} for i in range(150)]
            owner.insert_many(rows)

            procs[7703] = start(7703, ["127.0.0.1:7701"])   # joins AFTER data
            wait_http("127.0.0.1:7703")
            wait_peers("127.0.0.1:7703", 3, secret)
            # the owner must learn about the newcomer WHILE it can still ask
            # someone — a client whose entire contact list dies while it
            # slept has lost its network (same as losing all bootstraps)
            deadline = time.time() + 20
            while time.time() < deadline and len(owner.ring.addrs) < 3:
                owner.refresh_membership()
                time.sleep(0.5)
            self.assertEqual(len(owner.ring.addrs), 3)

            # with 3 nodes and RF3, background repair must copy EVERY key to
            # the newcomer — poll its key count up to ~60s
            import hashlib
            import hmac
            def keys_on(port):
                sig = hmac.new(secret.encode(), b"/intel",
                               hashlib.sha256).hexdigest()
                req = urllib.request.Request(
                    f"http://127.0.0.1:{port}/intel?limit=1",
                    headers={"X-BR-Auth": sig})
                with urllib.request.urlopen(req, timeout=3) as r:
                    return json.loads(r.read())["count"]
            target = keys_on(7701)
            deadline = time.time() + 60
            while time.time() < deadline and keys_on(7703) < target:
                time.sleep(1)
            self.assertGreaterEqual(keys_on(7703), target,
                                    "background repair never converged")

            # the original holders can now die: the newcomer alone suffices
            for p in (7701, 7702):
                procs[p].terminate()
                procs[p].wait()
            deadline = time.time() + 20
            while time.time() < deadline:
                try:
                    owner.refresh_membership()
                    if len(owner.ring.addrs) == 1:
                        break
                except ConnectionError:
                    pass
                time.sleep(0.5)
            got = sorted(r["row"] for r in owner.query("x", 30, 300))
            want = sorted(r["row"] for r in rows if 30 <= r["x"] <= 300)
            self.assertEqual(got, want)
        finally:
            for p in procs.values():
                if p.poll() is None:
                    p.terminate()
                p.wait()
            shutil.rmtree(tmp, ignore_errors=True)


class TestNATRelay(unittest.TestCase):
    """Network self-assembly: a node whose advertised address is unreachable
    (home NAT, no port forwarding) must diagnose that itself via dialback,
    become a relay tenant of a reachable peer, and keep serving — receiving
    replicas and answering reads — through the relay."""

    def test_unreachable_node_self_assembles_via_relay(self):
        import json
        import os
        tmp = tempfile.mkdtemp(prefix="blindrange_nat_")
        secret = "natnet"
        env = {**os.environ, "BR_DIALBACK_FIRST": "1", "BR_DIALBACK_EVERY": "2",
               "BR_REPAIR_EVERY": "0.5", "BR_REPAIR_BATCH": "5000"}
        root = str(Path(__file__).resolve().parents[1])

        def start(port, seeds, advertise=None):
            args = [sys.executable, "-m", "blindrange.node", "--port",
                    str(port), "--data", f"{tmp}/n{port}", "--secret", secret]
            if advertise:
                args += ["--advertise", advertise]
            for s in seeds:
                args += ["--seed", s]
            return subprocess.Popen(args, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, cwd=root,
                                    env=env)

        procs = []
        try:
            procs.append(start(7951, []))
            wait_http("127.0.0.1:7951")
            procs.append(start(7952, ["127.0.0.1:7951"]))
            wait_peers("127.0.0.1:7951", 2, secret)

            # the "NAT'd" node: listens on 7953 but advertises a dead port —
            # exactly what a home router does to an unsolicited inbound dial
            procs.append(start(7953, ["127.0.0.1:7951"],
                               advertise="127.0.0.1:7963"))
            wait_http("127.0.0.1:7953")

            # it must self-diagnose and re-advertise as via:<relay>/<id>
            import hashlib
            import hmac as _hmac
            sig = _hmac.new(secret.encode(), b"/peers",
                            hashlib.sha256).hexdigest()
            via_addr = None
            deadline = time.time() + 30
            while time.time() < deadline and via_addr is None:
                req = urllib.request.Request("http://127.0.0.1:7951/peers",
                                             headers={"X-BR-Auth": sig})
                with urllib.request.urlopen(req, timeout=3) as r:
                    peers = json.loads(r.read())["peers"]
                for e in peers.values():
                    if e["addr"].startswith("via:") and e["age"] <= 12:
                        via_addr = e["addr"]
                time.sleep(0.5)
            self.assertIsNotNone(via_addr, "node never entered tenant mode")

            # write data: with 3 nodes and RF3 the tenant replicates
            # everything — its copies arrive only through the relay
            owner = Owner.create(f"{tmp}/o.brdb", "pw",
                                 {"x": {"type": "int", "bits": 12,
                                        "leaf_width": 4}},
                                 bootstrap=["127.0.0.1:7951"],
                                 network_secret=secret)
            rows = [{"x": i * 3, "row": i} for i in range(120)]
            owner.insert_many(rows)

            def keys_on(port):          # test backdoor: the tenant's real port
                with urllib.request.urlopen(
                        f"http://127.0.0.1:{port}/stats", timeout=3) as r:
                    return json.loads(r.read())["keys"]
            deadline = time.time() + 60
            while time.time() < deadline and keys_on(7953) < keys_on(7951):
                time.sleep(1)
            self.assertGreaterEqual(keys_on(7953), keys_on(7951),
                                    "replicas never reached the tenant")

            # reads through the relay work: fetch the tenant's intel via its
            # via-address (client -> relay -> tenant -> back)
            intel = owner.intel(via_addr)
            self.assertGreater(intel["count"], 0)

            # and ordinary queries are correct with the tenant in the ring
            got = sorted(r["row"] for r in owner.query("x", 30, 300))
            want = sorted(r["row"] for r in rows if 30 <= r["x"] <= 300)
            self.assertEqual(got, want)
        finally:
            for p in procs:
                if p.poll() is None:
                    p.terminate()
                p.wait()
            shutil.rmtree(tmp, ignore_errors=True)


class TestQuicDirect(unittest.TestCase):
    """Punched direct paths: a client reaching a relay tenant should
    establish a QUIC connection (STUN-lite + punch choreography) and serve
    requests over it instead of the relay — falling back to the relay
    transparently when QUIC is unavailable."""

    def _network(self, tmp, secret, tenant_env=None):
        import os
        env = {**os.environ, "BR_DIALBACK_FIRST": "1", "BR_DIALBACK_EVERY": "2"}
        root = str(Path(__file__).resolve().parents[1])

        def start(port, seeds, advertise=None, extra_env=None):
            args = [sys.executable, "-m", "blindrange.node", "--port",
                    str(port), "--data", f"{tmp}/n{port}", "--secret", secret]
            if advertise:
                args += ["--advertise", advertise]
            for s in seeds:
                args += ["--seed", s]
            return subprocess.Popen(args, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, cwd=root,
                                    env={**env, **(extra_env or {})})
        procs = [start(7971, [])]
        wait_http("127.0.0.1:7971")
        # the "NAT'd" tenant: dead TCP advertise; QUIC still on its real port
        procs.append(start(7972, ["127.0.0.1:7971"],
                           advertise="127.0.0.1:7982",
                           extra_env=tenant_env))
        deadline = time.time() + 30
        via = None
        import hashlib
        import hmac as _hmac
        import json
        sig = _hmac.new(secret.encode(), b"/peers", hashlib.sha256).hexdigest()
        while time.time() < deadline and via is None:
            req = urllib.request.Request("http://127.0.0.1:7971/peers",
                                         headers={"X-BR-Auth": sig})
            with urllib.request.urlopen(req, timeout=3) as r:
                for e in json.loads(r.read())["peers"].values():
                    if e["addr"].startswith("via:") and e["age"] <= 12:
                        via = e["addr"]
            time.sleep(0.5)
        self.assertIsNotNone(via, "tenant never assembled")
        return procs

    def test_direct_path_used_and_fallback(self):
        import os
        import shutil as _shutil
        tmp = tempfile.mkdtemp(prefix="blindrange_quic_")
        secret = "quicnet"
        procs = self._network(tmp, secret)
        try:
            owner = Owner.create(f"{tmp}/o.brdb", "pw",
                                 {"x": {"type": "int", "bits": 12,
                                        "leaf_width": 4}},
                                 bootstrap=["127.0.0.1:7971"],
                                 network_secret=secret)
            rows = [{"x": i * 2, "row": i} for i in range(80)]
            owner.insert_many(rows)
            # tenant needs a moment to STUN + advertise its UDP endpoint
            deadline = time.time() + 15
            while time.time() < deadline:
                owner.refresh_membership()
                if getattr(owner, "_udp_of", {}):
                    break
                time.sleep(0.5)
            self.assertTrue(owner._udp_of, "tenant never advertised UDP")
            got = sorted(r["row"] for r in owner.query("x", 20, 100))
            want = sorted(r["row"] for r in rows if 20 <= r["x"] <= 100)
            self.assertEqual(got, want)
            self.assertGreater(owner.direct_requests, 0,
                               "no requests went over the punched path")
        finally:
            for p in procs:
                if p.poll() is None:
                    p.terminate()
                p.wait()
            _shutil.rmtree(tmp, ignore_errors=True)

    def test_relay_fallback_when_quic_disabled(self):
        import shutil as _shutil
        tmp = tempfile.mkdtemp(prefix="blindrange_noquic_")
        secret = "noquicnet"
        procs = self._network(tmp, secret, tenant_env={"BR_NO_QUIC": "1"})
        try:
            owner = Owner.create(f"{tmp}/o2.brdb", "pw",
                                 {"x": {"type": "int", "bits": 12,
                                        "leaf_width": 4}},
                                 bootstrap=["127.0.0.1:7971"],
                                 network_secret=secret)
            rows = [{"x": i * 2, "row": i} for i in range(60)]
            owner.insert_many(rows)
            got = sorted(r["row"] for r in owner.query("x", 20, 100))
            want = sorted(r["row"] for r in rows if 20 <= r["x"] <= 100)
            self.assertEqual(got, want)      # relay carried everything
        finally:
            for p in procs:
                if p.poll() is None:
                    p.terminate()
                p.wait()
            _shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
