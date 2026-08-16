"""The SQL dialect must answer exactly like the API it translates to.

Two families here. Parity tests run a statement and the equivalent Python
call on the same data and require identical answers — a friendlier syntax
that changes results is a translation error wearing a convenience. Refusal
tests pin the OTHER product surface: everything outside the dialect must
fail with a message that names why and what to use instead, because the
moment a refusal reads as a parse error, the honesty of the whole layer is
gone.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from blindrange import Owner                      # noqa: E402
from blindrange.sql import connect, Unsupported   # noqa: E402

PORT = 7811
SECRET = "sqlnet"


class SQLCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="blindrange_sql_")
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
        cls.con.execute(
            "CREATE TABLE orders (amount INT BITS 20 BLUR 64, "
            "day INT BITS 16 BLUR 16, status TEXT(6) BLUR 16, "
            "customer STORED)")
        rows = ", ".join(
            f"({100 + (i * 37) % 900}, {200 + i % 30}, "
            f"'{'paid' if i % 3 else 'refunded'}', 'cust-{i:03d}')"
            for i in range(60))
        cls.con.execute("INSERT INTO orders (amount, day, status, customer) "
                        f"VALUES {rows}")

    @classmethod
    def tearDownClass(cls):
        cls.con.close()
        cls.proc.kill()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def q(self, stmt):
        return self.con.execute(stmt)


class TestParityWithTheAPI(SQLCase):
    """Same data, same answers, or the dialect is lying."""

    def owner(self):
        return self.con._owner("orders")

    def test_range_select_matches_query(self):
        got = {r["customer"] for r in
               self.q("SELECT * FROM orders WHERE amount BETWEEN 300 AND 500")}
        want = {r["customer"] for r in self.owner().query("amount", 300, 500)}
        self.assertEqual(got, want)
        self.assertTrue(want, "fixture matched nothing; test proves little")

    def test_and_of_predicates_matches_query_multi(self):
        got = {r["customer"] for r in self.q(
            "SELECT * FROM orders WHERE amount BETWEEN 100 AND 700 "
            "AND day BETWEEN 200 AND 210")}
        want = {r["customer"] for r in self.owner().query_multi(
            [{"field": "amount", "lo": 100, "hi": 700},
             {"field": "day", "lo": 200, "hi": 210}])}
        self.assertEqual(got, want)

    def test_count_matches_and_names_its_basis(self):
        [row] = self.q("SELECT COUNT(*) FROM orders "
                       "WHERE amount BETWEEN 0 AND 1023")
        self.assertEqual(row["count"], self.owner().count("amount", 0, 1023))
        self.assertEqual(row["basis"], "exact-to-leaf")

    def test_approx_sum_carries_its_error_bar(self):
        [row] = self.q("SELECT APPROX SUM(amount) FROM orders")
        est, err, n = self.owner().approx_sum("amount", 0, (1 << 20) - 1)
        self.assertEqual((row["sum"], row["plus_minus"], row["rows"]),
                         (est, err, n))

    def test_order_by_desc_walks_from_the_top(self):
        got = [r["amount"] for r in
               self.q("SELECT amount FROM orders ORDER BY amount DESC LIMIT 5")]
        self.assertEqual(got, sorted(got, reverse=True))
        top = max(r["amount"] for r in
                  self.q("SELECT amount FROM orders"))
        self.assertEqual(got[0], top, "DESC LIMIT did not start at the top")

    def test_text_equality_is_exact_not_prefix(self):
        """'paid' must not match 'paidX': the index narrows to a prefix,
        so equality has to finish the job on the plaintext."""
        self.q("INSERT INTO orders (amount, day, status, customer) "
               "VALUES (999, 229, 'paidX', 'trap')")
        got = {r["customer"] for r in
               self.q("SELECT * FROM orders WHERE status = 'paid'")}
        self.assertNotIn("trap", got)
        self.assertTrue(got)
        self.q("DELETE FROM orders WHERE amount = 999")

    def test_like_prefix(self):
        got = {r["status"] for r in
               self.q("SELECT * FROM orders WHERE status LIKE 'ref%'")}
        self.assertEqual(got, {"refunded"})

    def test_greater_and_less_are_exclusive(self):
        every = sorted(r["amount"] for r in self.q("SELECT amount FROM orders"))
        lo, hi = every[5], every[-5]
        got = sorted(r["amount"] for r in self.q(
            f"SELECT amount FROM orders WHERE amount > {lo} "
            f"AND amount < {hi}"))
        self.assertEqual(got, [a for a in every if lo < a < hi])

    def test_contradictory_range_matches_nothing_quietly(self):
        self.assertEqual(
            self.q("SELECT * FROM orders WHERE amount > 500 AND amount < 300"),
            [])

    def test_projection(self):
        rows = self.q("SELECT customer, amount FROM orders "
                      "WHERE amount BETWEEN 300 AND 400")
        for r in rows:
            self.assertEqual(set(r), {"customer", "amount"})

    def test_stored_column_round_trips_but_never_indexes(self):
        rows = self.q("SELECT * FROM orders WHERE amount BETWEEN 100 AND 200")
        self.assertTrue(all(r["customer"].startswith("cust-") for r in rows))
        with self.assertRaises(Unsupported) as cm:
            self.q("SELECT * FROM orders WHERE customer = 'cust-001'")
        self.assertIn("STORED", str(cm.exception))


class TestWriteStatements(SQLCase):
    def test_update_is_delete_insert_and_reads_see_it(self):
        [before] = self.q("SELECT COUNT(*) FROM orders "
                          "WHERE amount BETWEEN 0 AND 1023")
        [out] = self.q("UPDATE orders SET status = 'audited' "
                       "WHERE day = 203")
        self.assertGreater(out["rows_affected"], 0)
        got = self.q("SELECT status FROM orders WHERE day = 203")
        self.assertTrue(all(r["status"] == "audited" for r in got))
        self.assertEqual(len(got), out["rows_affected"])

    def test_delete_removes_from_reads_immediately(self):
        self.q("INSERT INTO orders (amount, day, status, customer) "
               "VALUES (777, 228, 'doomed', 'victim')")
        [out] = self.q("DELETE FROM orders WHERE amount = 777")
        self.assertEqual(out["rows_affected"], 1)
        self.assertEqual(self.q("SELECT * FROM orders WHERE amount = 777"),
                         [])

    def test_reads_see_writes_without_anyone_calling_drain(self):
        """The word drain() must not exist at this layer."""
        self.q("INSERT INTO orders (amount, day, status, customer) "
               "VALUES (888, 227, 'fresh', 'ryw')")
        got = self.q("SELECT customer FROM orders WHERE amount = 888")
        self.assertEqual([r["customer"] for r in got], ["ryw"])
        self.q("DELETE FROM orders WHERE amount = 888")

    def test_autocompact_fires_past_the_threshold(self):
        con = connect(f"{self.tmp}/db2", "pw",
                      [f"127.0.0.1:{PORT}"], SECRET)
        con.execute("CREATE TABLE hot (n INT BITS 12 BLUR 4)")
        con.autocompact_threshold = 20
        rows = ", ".join(f"({i})" for i in range(40))
        con.execute(f"INSERT INTO hot (n) VALUES {rows}")
        con.execute("DELETE FROM hot WHERE n BETWEEN 0 AND 29")
        o = con._owner("hot")
        for _ in range(200):
            if o.count_deleted() == 0:
                break
            time.sleep(0.3)
        self.assertEqual(o.count_deleted(), 0,
                         "tombstones were never reclaimed — autocompact "
                         "did not run")
        got = {r["n"] for r in con.execute("SELECT n FROM hot")}
        self.assertEqual(got, set(range(30, 40)),
                         "autocompact changed the surviving rows")
        con.close()


class TestRefusals(SQLCase):
    """The refusal text is product surface: it must say why, not just no."""

    def refuse(self, stmt, *fragments):
        with self.assertRaises(Unsupported, msg=stmt) as cm:
            self.q(stmt)
        for frag in fragments:
            self.assertIn(frag, str(cm.exception), stmt)

    def test_join_names_the_reason(self):
        self.refuse("SELECT * FROM orders JOIN x ON 1", "sealed blobs")

    def test_or_names_the_alternative(self):
        self.refuse("SELECT * FROM orders WHERE amount = 1 OR day = 2",
                    "one query per")

    def test_plain_sum_points_at_approx(self):
        self.refuse("SELECT SUM(amount) FROM orders", "APPROX SUM")

    def test_group_by_points_at_histogram(self):
        self.refuse("SELECT * FROM orders GROUP BY day", "histogram")

    def test_leading_wildcard_names_the_index_shape(self):
        self.refuse("SELECT * FROM orders WHERE status LIKE '%aid'",
                    "prefix index")

    def test_non_power_of_two_blur_names_the_nearest(self):
        self.refuse("CREATE TABLE bad (a INT BITS 10 BLUR 100)",
                    "power of two", "64", "128")

    def test_int_without_blur_refuses_to_pick_a_privacy_budget(self):
        self.refuse("CREATE TABLE bad (a INT BITS 10)", "privacy budget")

    def test_insert_must_cover_every_indexed_column(self):
        self.refuse("INSERT INTO orders (amount) VALUES (1)",
                    "silently never find")

    def test_out_of_range_value_is_refused_not_lost(self):
        self.refuse("INSERT INTO orders (amount, day, status, customer) "
                    f"VALUES ({1 << 20}, 1, 'x', 'y')", "unfindable")

    def test_unknown_statement_lists_what_exists(self):
        self.refuse("VACUUM orders", "CREATE")


class TestSchemaLifecycle(SQLCase):
    def test_show_describe_drop_and_reopen(self):
        self.q("CREATE TABLE tmp (a INT BITS 8 BLUR 2)")
        self.assertIn({"table": "tmp"},
                      self.q("SHOW TABLES"))
        desc = {r["column"]: r for r in self.q("DESCRIBE tmp")}
        self.assertEqual(desc["a"]["bits"], 8)
        self.q("INSERT INTO tmp (a) VALUES (7)")

        # a second connection to the same directory sees the same table
        con2 = connect(f"{self.tmp}/db", "pw", [f"127.0.0.1:{PORT}"], SECRET)
        got = con2.execute("SELECT a FROM tmp WHERE a = 7")
        self.assertEqual(got, [{"a": 7}])
        con2.close()

        self.q("DROP TABLE tmp")
        self.assertNotIn({"table": "tmp"}, self.q("SHOW TABLES"))
        with self.assertRaises(Unsupported):
            self.q("SELECT * FROM tmp")


if __name__ == "__main__":
    unittest.main()
