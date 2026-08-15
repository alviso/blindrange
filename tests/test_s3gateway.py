"""S3 gateway: protocol behaviour, signing, and the blindness claim.

Verified during development against boto3 — an independent SigV4
implementation, which is the only way to know the signer is right rather
than merely self-consistent. These tests use raw HTTP so the suite keeps no
external dependency, and cover the two bugs boto3 actually found.
"""
import hashlib
import json
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "examples" / "s3gateway"))
from tests.test_e2e import wait_http, wait_peers  # noqa: E402
import gateway  # noqa: E402

PORTS = (7861, 7862, 7863)


def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]; s.close(); return p


class TestSigning(unittest.TestCase):
    """Pure signing logic — fast, and where the shipped bug lived."""

    def test_canonical_query_encodes_paths(self):
        """The regression: an unfiltered listing signed fine while every
        prefixed one failed, because '/' was left unencoded."""
        self.assertEqual(gateway.canonical_query({"prefix": ["logs/2026/"]}),
                         "prefix=logs%2F2026%2F")
        self.assertEqual(gateway.canonical_query({"delimiter": ["/"]}),
                         "delimiter=%2F")

    def test_canonical_query_is_sorted_and_handles_empties(self):
        got = gateway.canonical_query({"prefix": ["a"], "delimiter": ["/"],
                                       "list-type": ["2"]})
        self.assertEqual(got, "delimiter=%2F&list-type=2&prefix=a")
        self.assertEqual(gateway.canonical_query({}), "")
        self.assertEqual(gateway.canonical_query({"uploads": [""]}), "uploads=")

    def test_canonical_query_leaves_unreserved_alone(self):
        self.assertEqual(gateway.canonical_query({"k": ["a-b_c.d~e"]}),
                         "k=a-b_c.d~e")

    def test_auth_disabled_when_no_secret(self):
        a = gateway.Auth("id", "")
        self.assertTrue(a.check("GET", "/b", {}, {}, "UNSIGNED-PAYLOAD"))

    def test_garbage_authorization_is_refused(self):
        a = gateway.Auth("id", "secret")
        for hdr in ("", "Basic abc", "AWS4-HMAC-SHA256 nonsense"):
            self.assertFalse(
                a.check("GET", "/b", {}, {"Authorization": hdr}, "x"))

    def test_aws_chunked_framing_is_stripped(self):
        """Storing the frames verbatim corrupts the object, and only a
        restore would ever reveal it."""
        payload = b"A" * 100 + b"B" * 50
        framed = (b"64;chunk-signature=deadbeef\r\n" + b"A" * 100 + b"\r\n"
                  b"32;chunk-signature=cafe\r\n" + b"B" * 50 + b"\r\n"
                  b"0;chunk-signature=zero\r\n\r\n")
        self.assertEqual(gateway.decode_chunked(framed), payload)

    def test_unframed_body_survives_the_decoder(self):
        self.assertEqual(gateway.decode_chunked(b""), b"")


class TestGateway(unittest.TestCase):
    """End-to-end over HTTP, with signature checks off so the tests exercise
    object semantics rather than re-testing the signer."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="brs3_")
        cls.procs, cls.secret = [], "s3testnet"
        for i, port in enumerate(PORTS):
            a = [sys.executable, "-m", "blindrange.node", "--port", str(port),
                 "--data", f"{cls.tmp}/n{port}", "--secret", cls.secret]
            if i:
                a += ["--seed", f"127.0.0.1:{PORTS[0]}"]
            cls.procs.append(subprocess.Popen(
                a, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=str(ROOT)))
        wait_http(f"127.0.0.1:{PORTS[0]}")
        wait_peers(f"127.0.0.1:{PORTS[0]}", 3, cls.secret)

        cls.port = free_port()
        cls.procs.append(subprocess.Popen(
            [sys.executable, str(ROOT / "examples" / "s3gateway" / "gateway.py"),
             "--state", f"{cls.tmp}/s3.brdb", "--bootstrap", f"127.0.0.1:{PORTS[0]}",
             "--secret", cls.secret, "--port", str(cls.port), "--no-auth"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=str(ROOT)))
        for _ in range(140):
            try:
                cls.req("GET", "/"); break
            except urllib.error.HTTPError:
                break
            except OSError:
                time.sleep(0.25)
        else:
            raise RuntimeError("gateway never came up")

    @classmethod
    def tearDownClass(cls):
        for p in cls.procs:
            if p.poll() is None:
                p.terminate()
            p.wait()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    @classmethod
    def req(cls, method, path, body=None, headers=None):
        r = urllib.request.Request(f"http://127.0.0.1:{cls.port}{path}",
                                   data=body, method=method,
                                   headers=headers or {})
        with urllib.request.urlopen(r, timeout=120) as resp:
            return resp.status, resp.read(), dict(resp.headers)

    def test_01_put_get_round_trip(self):
        body = b"hello from an archiving product\n"
        st, _, h = self.req("PUT", "/archive/logs/2026/08/a.txt", body)
        self.assertEqual(st, 200)
        self.assertIn("ETag", h)
        st, got, _ = self.req("GET", "/archive/logs/2026/08/a.txt")
        self.assertEqual(got, body)

    def test_02_large_object_spans_chunks(self):
        """Bigger than one blob chunk, so reassembly is actually exercised."""
        import os as _os
        body = _os.urandom(1_500_000)
        self.req("PUT", "/archive/logs/2026/08/big.bin", body)
        st, got, _ = self.req("GET", "/archive/logs/2026/08/big.bin")
        self.assertEqual(len(got), len(body))
        self.assertEqual(hashlib.md5(got).hexdigest(),
                         hashlib.md5(body).hexdigest())

    def test_03_listing_prefix_and_delimiter(self):
        self.req("PUT", "/archive/reports/q3.csv", b"a,b\n")
        _, xml, _ = self.req("GET", "/archive?list-type=2")
        self.assertIn(b"logs/2026/08/a.txt", xml)
        self.assertIn(b"reports/q3.csv", xml)
        _, xml, _ = self.req("GET", "/archive?list-type=2&prefix=logs/2026/")
        self.assertIn(b"logs/2026/08/a.txt", xml)
        self.assertNotIn(b"reports/q3.csv", xml)
        _, xml, _ = self.req("GET", "/archive?list-type=2&delimiter=/")
        self.assertIn(b"<Prefix>logs/</Prefix>", xml)
        self.assertIn(b"<Prefix>reports/</Prefix>", xml)

    def test_04_head_reports_one_content_length(self):
        """boto3 aborts outright on two conflicting Content-Length values."""
        st, _, h = self.req("HEAD", "/archive/logs/2026/08/a.txt")
        self.assertEqual(st, 200)
        self.assertEqual(int(h["Content-Length"]), 32)

    def test_05_missing_key_is_404_not_a_lie(self):
        with self.assertRaises(urllib.error.HTTPError) as e:
            self.req("GET", "/archive/nope.txt")
        self.assertEqual(e.exception.code, 404)
        self.assertIn(b"NoSuchKey", e.exception.read())

    def test_06_overwrite_replaces_rather_than_duplicates(self):
        self.req("PUT", "/archive/dup.txt", b"first")
        self.req("PUT", "/archive/dup.txt", b"second")
        _, got, _ = self.req("GET", "/archive/dup.txt")
        self.assertEqual(got, b"second")
        _, xml, _ = self.req("GET", "/archive?list-type=2&prefix=dup")
        self.assertEqual(xml.count(b"<Key>dup.txt</Key>"), 1,
                         "overwrite left a duplicate listing entry")

    def test_07_multipart_upload(self):
        _, xml, _ = self.req("POST", "/archive/mp.bin?uploads", b"")
        uid = xml.split(b"<UploadId>")[1].split(b"</UploadId>")[0].decode()
        p1, p2 = b"x" * 600_000, b"y" * 400_000
        self.req("PUT", f"/archive/mp.bin?partNumber=1&uploadId={uid}", p1)
        self.req("PUT", f"/archive/mp.bin?partNumber=2&uploadId={uid}", p2)
        done = (b"<CompleteMultipartUpload>"
                b"<Part><PartNumber>1</PartNumber></Part>"
                b"<Part><PartNumber>2</PartNumber></Part>"
                b"</CompleteMultipartUpload>")
        st, _, _ = self.req("POST", f"/archive/mp.bin?uploadId={uid}", done)
        self.assertEqual(st, 200)
        _, got, _ = self.req("GET", "/archive/mp.bin")
        self.assertEqual(got, p1 + p2)

    def test_08_delete(self):
        self.req("PUT", "/archive/gone.txt", b"bye")
        self.req("DELETE", "/archive/gone.txt")
        with self.assertRaises(urllib.error.HTTPError):
            self.req("GET", "/archive/gone.txt")

    def test_09_nodes_hold_nothing_readable(self):
        """The whole claim: content AND the object path are absent from
        every node's disk."""
        marker = b"TOP-SECRET-MARKER-9f3a"
        self.req("PUT", "/archive/confidential/salaries.csv", marker + b" payload")
        time.sleep(2)
        for port in PORTS:
            db = sqlite3.connect(f"{self.tmp}/n{port}/kv.db")
            blob = b"".join(
                (str(k) + str(v)).encode()
                for k, v in db.execute("SELECT k, v FROM kv").fetchall())
            db.close()
            self.assertNotIn(marker, blob, f"payload readable on node {port}")
            self.assertNotIn(b"salaries.csv", blob, f"key readable on node {port}")
            self.assertNotIn(b"confidential", blob, f"path readable on node {port}")


if __name__ == "__main__":
    unittest.main()
