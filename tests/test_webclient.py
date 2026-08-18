"""The browser client is a PORT, and this file is what makes that word
mean something: every key derivation is asserted byte-identical to the
reference, and a real network round-trip proves Python-written rows are
readable from JS, JS-written rows from Python, JS tombstones honored by
Python, and sequence numbers unique across the language boundary.

Skips (with a visible reason) when node >= 18 is not installed — the
JS client needs global fetch and WebCrypto.
"""
import json
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

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from blindrange import Owner                    # noqa: E402
import blindrange.client as _client             # noqa: E402

PORT = 7871
SECRET = "webnet"
SCHEMA = {
    "amount": {"type": "int", "bits": 20, "leaf_width": 256},
    "name":   {"type": "str", "bits": 20, "leaf_width": 16, "chars": 4},
}


def _node_ok():
    try:
        v = subprocess.run(["node", "--version"], capture_output=True,
                           text=True, timeout=10).stdout.strip()
        return int(v.lstrip("v").split(".")[0]) >= 18
    except Exception:
        return False


def _run_js(job):
    with tempfile.NamedTemporaryFile("w", suffix=".json",
                                     delete=False) as f:
        json.dump(job, f)
        path = f.name
    try:
        r = subprocess.run(
            ["node", str(ROOT / "tests" / "web" / "compat.mjs"), path],
            capture_output=True, text=True, timeout=180, cwd=str(ROOT))
        if r.returncode != 0:
            raise AssertionError(f"JS phase {job['phase']} failed:\n"
                                 f"{r.stderr[-2000:]}")
        return json.loads(r.stdout)
    finally:
        os.unlink(path)


@unittest.skipUnless(_node_ok(), "node >= 18 required for the JS client")
class TestWebClient(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="blindrange_web_")
        cls.procs = []
        for i in range(3):
            port = PORT + i
            seed = [] if i == 0 else ["--seed", f"127.0.0.1:{PORT}"]
            cls.procs.append(subprocess.Popen(
                [sys.executable, "-m", "blindrange.node", "--port",
                 str(port), "--data", f"{cls.tmp}/n{port}",
                 "--secret", SECRET] + seed,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                cwd=str(ROOT)))
        for i in range(3):
            addr = f"127.0.0.1:{PORT + i}"
            for _ in range(80):
                try:
                    urllib.request.urlopen(f"http://{addr}/stats",
                                           timeout=1)
                    break
                except OSError:
                    time.sleep(0.1)
            else:
                raise RuntimeError(f"{addr} never came up")
        cls.owner = Owner.create(f"{cls.tmp}/py.brdb", "py pass", SCHEMA,
                                 bootstrap=[f"127.0.0.1:{PORT}"],
                                 network_secret=SECRET)
        rng = random.Random(9)
        names = ["acme", "sable", "salt", "iris", "sand", "gale"]
        cls.rows = [{"amount": rng.randint(500, 900_000),
                     "name": rng.choice(names) + str(i), "row": i}
                    for i in range(60)]
        cls.owner.insert_many(cls.rows)
        cls.owner.drain()

    @classmethod
    def tearDownClass(cls):
        for p in cls.procs:
            if p.poll() is None:
                p.terminate()
            p.wait()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_01_derivations_are_byte_identical(self):
        """Drift here is silent corruption everywhere else — every wire
        key the two implementations would ever derive must agree."""
        master = "aa" * 32
        got = _run_js({"phase": "vectors", "master": master,
                       "schema": SCHEMA, "secret": SECRET,
                       "bootstrap": [f"127.0.0.1:{PORT}"]})

        import hashlib
        import hmac as _hmac
        from blindrange.dyadic import (dyadic_cover, encode_str,
                                       levels_for)
        m = bytes.fromhex(master)
        k_w = _hmac.new(m, b"label|amount|3|5", hashlib.sha256).digest()
        ut = "I:" + _hmac.new(k_w, b"UT|2|deadbeefdeadbeef|7",
                              hashlib.sha256).hexdigest()[:32]
        mask = list(_hmac.new(k_w, b"MASK|2|deadbeefdeadbeef|7",
                              hashlib.sha256).digest()[:8])
        self.assertEqual(got["ut"], ut)
        self.assertEqual(got["mask"], mask)

        def sys_key(kind, i):
            k = _hmac.new(m, b"sys|" + kind, hashlib.sha256).digest()
            return "I:" + _hmac.new(k, f"S|{i}".encode(),
                                    hashlib.sha256).hexdigest()[:32]
        self.assertEqual(got["sys_key"], sys_key(b"epoch", 3))
        self.assertEqual(got["seq_key"], sys_key(b"seq:inv", 12))
        self.assertEqual(got["registry_key"], sys_key(b"registry", 1))

        h = _hmac.new(m, b"keycol|id|doc-42", hashlib.sha256).digest()
        self.assertEqual(got["key_bucket"],
                         int.from_bytes(h[:4], "big") & ((1 << 20) - 1))
        self.assertEqual(int(got["encode_str"]), encode_str("sable", 4))
        self.assertEqual([tuple((int(l), int(i))) for l, i in got["levels"]],
                         levels_for(777, 11, 8))
        self.assertEqual([tuple((int(l), int(i))) for l, i in got["cover"]],
                         dyadic_cover(100, 200, 11, 8))

    def test_02_python_writes_js_reads_and_back(self):
        new_rows = [{"amount": 42_000 + i, "name": "webz" + str(i),
                     "row": 10_000 + i} for i in range(8)]
        got = _run_js({"phase": "accept", "invite": self.owner.invite(),
                       "new_rows": new_rows, "delete_rid": 7,
                       "gateway": f"http://127.0.0.1:{PORT}"})

        want_range = sorted(r["row"] for r in self.rows
                            if 100_000 <= r["amount"] <= 300_000)
        self.assertEqual(got["range_rows"], want_range,
                         "JS could not read Python-written rows by range")
        want_prefix = sorted(r["row"] for r in self.rows
                             if r["name"].startswith("sa"))
        self.assertEqual(got["prefix_rows"], want_prefix,
                         "JS prefix query disagrees with ground truth")
        self.assertEqual(got["deleted"], 1, "JS tombstone failed")
        self.assertEqual(len(got["seq_values"]),
                         len(set(got["seq_values"])),
                         "JS claimed duplicate sequence values")

        # Python reads what JS wrote — same rows, JS tombstone honored
        rows = self.owner.query("amount", 42_000, 42_007)
        self.assertEqual(sorted(r["row"] for r in rows),
                         [10_000 + i for i in range(8)],
                         "Python cannot read JS-written rows")
        all_rows = self.owner.query("amount", 0, 1_048_575)
        self.assertNotIn(7, [r["row"] for r in all_rows],
                         "Python still sees the row JS deleted")

        # the /fwd gateway path returns the same truth as direct access
        want_after = sorted(r["row"] for r in self.rows
                            if 100_000 <= r["amount"] <= 300_000)
        self.assertEqual(got["gateway_range_rows"], want_after,
                         "gateway (/fwd) answers differ from direct")

        # KEY buckets agree cross-language
        self.assertEqual(got["bucket"],
                         self.owner.key_bucket("id", "doc-1"))

        # sequences remain unique ACROSS languages: Python's next claim
        # must exceed or interleave with, never repeat, JS's
        py_val = self.owner.next_value("inv")
        self.assertNotIn(py_val, got["seq_values"],
                         "a sequence number was handed out twice")


if __name__ == "__main__":
    unittest.main()
