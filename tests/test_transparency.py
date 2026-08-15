"""The Merkle log, and the aggregator's use of it.

The property under test is narrow and worth stating precisely: not that the
aggregator is honest, but that it cannot revise what it already published
without anyone holding an old head noticing.
"""
import json
import unittest

from blindrange import merkle as M


class TestMerkle(unittest.TestCase):
    def test_inclusion_holds_for_every_leaf_at_every_size(self):
        for n in range(1, 33):
            entries = [f"e{i}".encode() for i in range(n)]
            log = M.Log(entries)
            root = log.root()
            for m in range(n):
                self.assertTrue(
                    M.verify_inclusion(M.leaf_hash(entries[m]), m, n,
                                       log.inclusion(m), root),
                    f"inclusion failed for leaf {m} of {n}")

    def test_consistency_holds_for_every_pair(self):
        for n in range(1, 25):
            entries = [f"e{i}".encode() for i in range(n)]
            log = M.Log(entries)
            root = log.root()
            for m in range(1, n + 1):
                old = M.Log(entries[:m]).root()
                self.assertTrue(
                    M.verify_consistency(m, old, n, root, log.consistency(m)),
                    f"consistency failed for {m} -> {n}")

    def test_rewriting_history_breaks_consistency(self):
        """The whole point. An operator who kept one old head detects any
        edit to anything that preceded it."""
        entries = [f"e{i}".encode() for i in range(8)]
        old_root = M.Log(entries[:5]).root()
        forged = M.Log([b"TAMPERED" if i == 2 else e
                        for i, e in enumerate(entries)])
        self.assertFalse(M.verify_consistency(5, old_root, 8, forged.root(),
                                              forged.consistency(5)))

    def test_dropping_an_entry_breaks_consistency(self):
        entries = [f"e{i}".encode() for i in range(8)]
        old_root = M.Log(entries[:6]).root()
        shortened = M.Log(entries[:3] + entries[4:])
        self.assertFalse(
            M.verify_consistency(6, old_root, len(shortened),
                                 shortened.root(), shortened.consistency(6)))

    def test_a_forged_inclusion_proof_fails(self):
        log = M.Log([f"e{i}".encode() for i in range(9)])
        self.assertFalse(M.verify_inclusion(M.leaf_hash(b"never-logged"), 3,
                                            9, log.inclusion(3), log.root()))

    def test_leaf_and_node_hashing_are_domain_separated(self):
        """Without the RFC 6962 prefixes an interior node could be passed
        off as a leaf."""
        a, b = M.leaf_hash(b"a"), M.leaf_hash(b"b")
        self.assertNotEqual(M.node_hash(a, b), M.leaf_hash(a + b))

    def test_append_only_growth(self):
        log = M.Log()
        roots = []
        for i in range(12):
            log.append(f"e{i}".encode())
            roots.append(log.root())
        self.assertEqual(len(set(roots)), 12, "head must move on every append")
        for i in range(1, 12):
            self.assertTrue(M.verify_consistency(i, roots[i - 1], 12,
                                                 roots[-1], log.consistency(i)))

    def test_empty_and_single(self):
        self.assertEqual(len(M.Log().root()), 32)
        one = M.Log([b"only"])
        self.assertEqual(one.root(), M.leaf_hash(b"only"))
        self.assertTrue(M.verify_inclusion(M.leaf_hash(b"only"), 0, 1, [],
                                           one.root()))


class TestAggregatorLog(unittest.TestCase):
    """The log as the status server drives it."""

    def setUp(self):
        import importlib.util
        from pathlib import Path
        import tempfile, os
        self.tmp = tempfile.mkdtemp()
        os.environ["BR_LOG_PATH"] = f"{self.tmp}/log.jsonl"
        os.environ["BR_LOG_KEY"] = f"{self.tmp}/log.key"
        root = Path(__file__).resolve().parents[1]
        spec = importlib.util.spec_from_file_location(
            "ss_tl", root / "examples" / "status_server.py")
        self.ss = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.ss)

    def tearDown(self):
        import shutil, os
        shutil.rmtree(self.tmp, ignore_errors=True)
        os.environ.pop("BR_LOG_PATH", None)
        os.environ.pop("BR_LOG_KEY", None)

    def test_head_is_signed_and_verifiable(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey)
        self.ss.log_append("report", {"a": 1})
        head = self.ss.signed_head()
        msg = f"brlog|{head['size']}|{head['root']}|{head['at']}".encode()
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(head["pub"])).verify(
            bytes.fromhex(head["sig"]), msg)          # raises if wrong
        self.assertEqual(head["size"], 1)

    def test_entries_survive_a_restart_with_the_same_root(self):
        for i in range(5):
            self.ss.log_append("report", {"i": i})
        before = self.ss.signed_head()["root"]
        self.ss.LOG = self.ss.merkle.Log()            # simulate a restart
        self.ss.log_load()
        self.assertEqual(self.ss.signed_head()["root"], before)
        self.assertEqual(len(self.ss.LOG), 5)

    def test_logged_reports_carry_no_identity(self):
        """Reports are logged in full so our scoring can be recomputed. That
        is only acceptable because the format has no owner in it."""
        self.ss.log_append("report", {"kind": "blindrange-audit",
                                      "nodes": {"abc": {"sampled": 100}}})
        blob = self.ss.LOG.entries[0].decode()
        for forbidden in ("account", "email", "owner", "database", "master"):
            self.assertNotIn(forbidden, blob)

    def test_share_logging_is_rate_limited(self):
        """The page recomputes on every refresh; a log that grows with page
        views is one nobody will read."""
        self.ss.log_shares({"n1": 500})
        self.ss.log_shares({"n1": 500})
        self.ss.log_shares({"n1": 500})
        self.assertEqual(len(self.ss.LOG), 1)


if __name__ == "__main__":
    unittest.main()
