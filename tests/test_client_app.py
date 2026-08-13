"""Schema helpers and the local client app.

The schema layer is pure and fast; the client-app tests drive the same HTTP
API the browser uses, against a real node network.

  python3 -m unittest tests.test_client_app -v
"""
import json
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from blindrange import schema as S  # noqa: E402
from blindrange import webui  # noqa: E402

CSV = """Order,Customer,Amount,Date,Status
SO-1001,acme corp,1879.26,2024-03-09,paid
SO-1002,tidal ab,865.13,2024-09-10,refunded
SO-1003,apex ltd,2440.10,2025-07-20,paid
SO-1004,salt bt,1864.17,2025-12-24,pending
SO-1005,harbor plc,2043.31,2024-06-17,shipped
"""


class TestSchema(unittest.TestCase):
    def test_leaf_width_is_always_legal(self):
        """Whatever bucket a user asks for, the spec must be constructible."""
        from blindrange.dyadic import max_level
        for bucket in (0, 1, 3, 7, 25, 2500, 10 ** 6):
            for spec in (S.money_field(10000, bucket / 100 or 0.01),
                         S.number_field(10 ** 6, bucket),
                         S.date_field(6, max(1, bucket)),
                         S.text_field(4, max(1, bucket))):
                lw = spec["leaf_width"]
                self.assertEqual(lw & (lw - 1), 0, f"{lw} not a power of two")
                max_level(spec["bits"], lw)          # raises if illegal

    def test_money_roundtrip_is_exact(self):
        spec = S.money_field(10000, 0.01)
        self.assertEqual(S.to_stored(spec, "1,879.26"), 187926)
        self.assertEqual(S.to_display(spec, 187926), "1,879.26")

    def test_date_roundtrip(self):
        spec = S.date_field(6, 1)
        self.assertEqual(S.to_display(spec, S.to_stored(spec, "2025-07-20")),
                         "2025-07-20")

    def test_infer_reads_a_csv(self):
        rows, _cols = S.read_csv(CSV)
        schema, skipped = S.infer(rows)
        self.assertEqual(schema["amount"]["kind"], "money")
        self.assertEqual(schema["date"]["kind"], "date")
        self.assertEqual(schema["customer"]["kind"], "text")
        self.assertIn("Status", skipped)        # unindexed, still stored

    def test_describe_states_the_budget(self):
        text = S.describe("amount", S.money_field(10000, 20.48))
        self.assertIn("$20.48", text)
        self.assertIn("never finer", text)


class TestClientApp(unittest.TestCase):
    """Drives the browser API end to end against real nodes."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="blindrange_app_")
        cls.secret = "apptest"
        root = str(Path(__file__).resolve().parents[1])
        cls.procs = []
        for i, port in enumerate((7841, 7842)):
            args = [sys.executable, "-m", "blindrange.node", "--port",
                    str(port), "--data", f"{cls.tmp}/n{port}",
                    "--secret", cls.secret]
            if i:
                args += ["--seed", "127.0.0.1:7841"]
            cls.procs.append(subprocess.Popen(
                args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                cwd=root))
        deadline = time.time() + 30
        while time.time() < deadline:
            try:
                urllib.request.urlopen("http://127.0.0.1:7841/stats", timeout=1)
                break
            except OSError:
                time.sleep(0.3)
        cls.port = 8791
        threading.Thread(target=webui.serve, args=(cls.port,),
                         daemon=True).start()
        time.sleep(1)

    @classmethod
    def tearDownClass(cls):
        webui.STATE["owner"] = None
        for p in cls.procs:
            if p.poll() is None:
                p.terminate()
            p.wait()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def post(self, path, body):
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}",
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"})
        return json.loads(urllib.request.urlopen(req, timeout=60).read())

    def test_01_csv_to_queryable_database(self):
        inferred = self.post("/api/infer", {"csv": CSV})
        self.assertEqual(inferred["total"], 5)
        state = self.post("/api/create", {
            "file": f"{self.tmp}/app.brdb", "passphrase": "pw",
            "schema": inferred["schema"], "network": "127.0.0.1:7841",
            "secret": self.secret})
        self.assertTrue(state["open"])
        self.assertEqual(self.post("/api/import", {"csv": CSV})["imported"], 5)

        got = self.post("/api/query", {"predicates": [
            {"field": "amount", "lo": "1000", "hi": "2000"}]})
        self.assertEqual(got["total"], 2)               # 1879.26, 1864.17
        amounts = sorted(r["amount"] for r in got["rows"])
        self.assertEqual(amounts, ["1,864.17", "1,879.26"])
        self.assertEqual(got["rows"][0]["status"] in
                         ("paid", "pending", "shipped", "refunded"), True)

    def test_02_and_across_fields_and_prefix(self):
        got = self.post("/api/query", {"predicates": [
            {"field": "amount", "lo": "800", "hi": "2500"},
            {"field": "date", "lo": "2024-01-01", "hi": "2024-12-31"}]})
        self.assertEqual(got["total"], 3)
        pref = self.post("/api/query", {"predicates": [
            {"field": "customer", "prefix": "ac"}]})
        self.assertEqual(pref["total"], 1)

    def test_03_insert_and_delete(self):
        self.post("/api/insert", {"record": {
            "order": "SO-9999", "customer": "zeta gmbh", "amount": "1500.00",
            "date": "2024-05-05", "note": "added by hand"}})
        got = self.post("/api/query", {"predicates": [
            {"field": "customer", "prefix": "ze"}]})
        self.assertEqual(got["total"], 1)
        self.assertEqual(got["rows"][0]["note"], "added by hand")
        self.post("/api/delete", {"rids": [got["rows"][0]["_rid"]]})
        self.assertEqual(self.post("/api/query", {"predicates": [
            {"field": "customer", "prefix": "ze"}]})["total"], 0)

    def test_04_invite_adds_a_device(self):
        invite = self.post("/api/invite", {})["invite"]
        state = self.post("/api/accept", {
            "invite": invite, "file": f"{self.tmp}/second.brdb",
            "passphrase": "pw2"})
        self.assertTrue(state["open"])
        got = self.post("/api/query", {"predicates": [
            {"field": "amount", "lo": "1000", "hi": "2000"}]})
        self.assertEqual(got["total"], 2)     # sees the first device's rows

    def test_05_errors_are_reported_not_crashed(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.post("/api/open", {"file": "/nope/missing.brdb",
                                    "passphrase": "x"})
        self.assertEqual(ctx.exception.code, 400)
        self.assertIn("error", json.loads(ctx.exception.read()))


if __name__ == "__main__":
    unittest.main(verbosity=2)
