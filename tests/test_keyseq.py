"""KEY columns and sequences: the two patterns applications invented,
now engine features with their sharp edges tested off.

KEY's contract: exact-match by opaque handle, collisions invisible to
callers, handles never leave the sealed record. SEQUENCE's contract:
unique and monotonic under concurrent writers, because the network — not
any client — arbitrates each claim.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import unittest.mock
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from blindrange import Owner                    # noqa: E402
from blindrange.sql import connect, Unsupported  # noqa: E402

PORT = 7851
SECRET = "keyseqnet"


class KeySeqCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="blindrange_keyseq_")
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
        cls.con = connect(f"{cls.tmp}/db", "pw",
                          [f"127.0.0.1:{PORT}"], SECRET)
        cls.con.execute("CREATE TABLE docs (id KEY, "
                        "amount INT BITS 16 BLUR 16, body STORED)")

    @classmethod
    def tearDownClass(cls):
        cls.con.close()
        cls.proc.kill()
        shutil.rmtree(cls.tmp, ignore_errors=True)


class TestKeyColumns(KeySeqCase):
    def test_lifecycle_by_handle(self):
        self.con.execute("INSERT INTO docs (id, amount, body) "
                         "VALUES ('inv-1', 100, 'a')")
        [row] = self.con.execute("SELECT * FROM docs WHERE id = 'inv-1'")
        self.assertEqual(row, {"id": "inv-1", "amount": 100, "body": "a"})

        self.con.execute("UPDATE docs SET body = 'b' WHERE id = 'inv-1'")
        [row] = self.con.execute("SELECT body FROM docs WHERE id = 'inv-1'")
        self.assertEqual(row["body"], "b")

        self.con.execute("UPDATE docs SET id = 'inv-9' WHERE id = 'inv-1'")
        self.assertEqual(self.con.execute(
            "SELECT * FROM docs WHERE id = 'inv-1'"), [])
        [row] = self.con.execute("SELECT body FROM docs WHERE id = 'inv-9'")
        self.assertEqual(row["body"], "b")

        [out] = self.con.execute("DELETE FROM docs WHERE id = 'inv-9'")
        self.assertEqual(out["rows_affected"], 1)

    def test_similar_handles_do_not_cross_match(self):
        """'inv-2' must never return 'inv-22': the bucket narrows, the
        sealed plaintext decides."""
        self.con.execute("INSERT INTO docs (id, amount, body) VALUES "
                         "('inv-2', 1, 'x'), ('inv-22', 2, 'y')")
        [row] = self.con.execute("SELECT body FROM docs WHERE id = 'inv-2'")
        self.assertEqual(row["body"], "x")
        self.con.execute("DELETE FROM docs WHERE id = 'inv-2'")
        self.con.execute("DELETE FROM docs WHERE id = 'inv-22'")

    def test_bucket_collisions_are_invisible_to_callers(self):
        """Force every handle into ONE bucket — the worst case ~1M buckets
        makes vanishingly rare — and lookups must still return exactly
        their own row. If this fails, collisions are data corruption; if
        it passes, they are a small read amplification and nothing else."""
        with unittest.mock.patch.object(Owner, "key_bucket",
                                        lambda self, f, v: 7):
            self.con.execute("INSERT INTO docs (id, amount, body) VALUES "
                             "('col-a', 1, 'A'), ('col-b', 2, 'B')")
            [a] = self.con.execute("SELECT body FROM docs WHERE id = 'col-a'")
            [b] = self.con.execute("SELECT body FROM docs WHERE id = 'col-b'")
            self.assertEqual((a["body"], b["body"]), ("A", "B"))
            self.con.execute("DELETE FROM docs WHERE id = 'col-a'")
            self.con.execute("DELETE FROM docs WHERE id = 'col-b'")

    def test_omitted_handle_is_generated_and_returned(self):
        [out] = self.con.execute(
            "INSERT INTO docs (amount, body) VALUES (5, 'auto')")
        self.assertEqual(len(out["ids"]), 1)
        gen = out["ids"][0]
        [row] = self.con.execute(f"SELECT body FROM docs WHERE id = '{gen}'")
        self.assertEqual(row["body"], "auto")
        self.con.execute(f"DELETE FROM docs WHERE id = '{gen}'")

    def test_a_key_has_no_order_and_says_so(self):
        for stmt in ("SELECT * FROM docs WHERE id LIKE 'inv%'",
                     "SELECT * FROM docs WHERE id BETWEEN 1 AND 2",
                     "SELECT * FROM docs ORDER BY id"):
            with self.assertRaises(Unsupported, msg=stmt) as cm:
                self.con.execute(stmt)
        self.assertIn("no order", str(cm.exception).lower())

    def test_the_network_never_sees_the_handle(self):
        """The whole point of KEY: the handle exists only inside the
        sealed record. Nothing stored on any node may contain it."""
        import json
        from blindrange import node as nd
        self.con.execute("INSERT INTO docs (id, amount, body) VALUES "
                         "('SECRET-HANDLE-XYZ', 3, 'z')")
        self.con._flush("docs")
        out = nd.post_any(f"127.0.0.1:{PORT}", "/digest",
                          json.dumps({"chars": 3}).encode(), SECRET)
        self.assertTrue(out["buckets"])          # node holds data...
        intel = self.con._owner("docs")._get(
            f"127.0.0.1:{PORT}", "/intel?limit=200")
        flat = json.dumps(intel)
        self.assertNotIn("SECRET-HANDLE-XYZ", flat,
                         "the handle leaked to a node")
        self.con.execute("DELETE FROM docs WHERE id = 'SECRET-HANDLE-XYZ'")


class TestSequences(KeySeqCase):
    def test_monotonic_and_unique_single_writer(self):
        got = [self.con.execute("SELECT NEXT VALUE FOR seq_a")[0]["value"]
               for _ in range(5)]
        self.assertEqual(got, sorted(got))
        self.assertEqual(len(set(got)), 5)

    def test_two_writers_racing_never_share_a_number(self):
        """The claim that matters: uniqueness is arbitrated by the network,
        so two INDEPENDENT WRITERS — the invite/accept model, each with its
        own state file — can collide on attempts but never on results.
        (Two Connections over one state directory is the documented
        single-writer violation, not the multi-writer model.)"""
        o1 = self.con._owner("docs")
        o2 = Owner.accept(f"{self.tmp}/second.brdb", "pw", o1.invite(),
                          bootstrap=[f"127.0.0.1:{PORT}"])
        results, errors = [], []
        lock = threading.Lock()

        def draw(o, n):
            try:
                for _ in range(n):
                    v = o.next_value("seq_race")
                    with lock:
                        results.append(v)
            except Exception as e:
                errors.append(e)

        t1 = threading.Thread(target=draw, args=(o1, 12))
        t2 = threading.Thread(target=draw, args=(o2, 12))
        t1.start(), t2.start()
        t1.join(), t2.join()
        self.assertFalse(errors, errors)
        self.assertEqual(len(results), 24)
        self.assertEqual(len(set(results)), 24,
                         f"two writers shared a sequence number: "
                         f"{sorted(results)}")

    def test_a_reopened_connection_continues_not_restarts(self):
        v1 = self.con.execute("SELECT NEXT VALUE FOR seq_persist")[0]["value"]
        con2 = connect(f"{self.tmp}/db", "pw",
                       [f"127.0.0.1:{PORT}"], SECRET)
        v2 = con2.execute("SELECT NEXT VALUE FOR seq_persist")[0]["value"]
        con2.close()
        self.assertGreater(v2, v1, "a fresh connection restarted the "
                                   "sequence — invoice numbers would repeat")


if __name__ == "__main__":
    unittest.main()
