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
