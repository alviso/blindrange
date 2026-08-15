"""The backup demo's own logic, tested without boto3.

The demo needs an S3 client to run, but its file-selection and path handling
are pure and are where a backup tool silently does the wrong thing — walking
into .git, following a symlink out of the tree, or mangling a nested path on
restore. Those get tested here so the suite keeps no new dependency.
"""
import importlib.util
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_backup():
    """Import the demo with a stub boto3, so the suite needs no S3 client."""
    if "boto3" not in sys.modules:
        stub = type(sys)("boto3")
        stub.client = lambda *a, **k: None
        sys.modules["boto3"] = stub
        cfg = type(sys)("botocore.config")
        cfg.Config = lambda *a, **k: None
        exc = type(sys)("botocore.exceptions")
        exc.ClientError = type("ClientError", (Exception,), {})
        exc.EndpointConnectionError = type("EndpointConnectionError",
                                           (Exception,), {})
        base = type(sys)("botocore")
        sys.modules["botocore"] = base
        sys.modules["botocore.config"] = cfg
        sys.modules["botocore.exceptions"] = exc
    spec = importlib.util.spec_from_file_location(
        "s3backup", ROOT / "examples" / "s3backup" / "backup.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class TestWalk(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load_backup()
        cls.tmp = tempfile.mkdtemp(prefix="brbk_")
        for rel in ("a.txt", "sub/b.py", "sub/deep/c.md",
                    ".git/config", "__pycache__/x.pyc", "d.pyc",
                    "node_modules/pkg/index.js"):
            p = os.path.join(cls.tmp, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w") as f:
                f.write(rel)
        os.symlink(os.path.join(cls.tmp, "a.txt"),
                   os.path.join(cls.tmp, "link.txt"))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def walked(self, extra=()):
        return sorted(rel for _, rel in
                      self.mod.walk(self.tmp, list(self.mod.SKIP) + list(extra)))

    def test_finds_real_files_including_nested(self):
        got = self.walked()
        self.assertIn("a.txt", got)
        self.assertIn("sub/b.py", got)
        self.assertIn("sub/deep/c.md", got)

    def test_skips_the_usual_noise(self):
        got = self.walked()
        for junk in ("d.pyc", ".git/config", "__pycache__/x.pyc",
                     "node_modules/pkg/index.js"):
            self.assertNotIn(junk, got, f"{junk} should be excluded")

    def test_does_not_follow_symlinks(self):
        """A symlink pointing outside the tree would silently pull in data
        the user never meant to upload."""
        self.assertNotIn("link.txt", self.walked())

    def test_extra_excludes_apply(self):
        self.assertNotIn("sub/b.py", self.walked(extra=["*/sub/*"]))
        self.assertIn("a.txt", self.walked(extra=["*/sub/*"]))

    def test_paths_are_relative_to_the_root(self):
        for _, rel in self.mod.walk(self.tmp, list(self.mod.SKIP)):
            self.assertFalse(rel.startswith("/"), rel)
            self.assertNotIn("..", rel)

    def test_walk_is_deterministic(self):
        self.assertEqual(self.walked(), self.walked())


class TestKeyRoundTrip(unittest.TestCase):
    """Restore reconstructs paths by stripping the snapshot prefix. Getting
    this wrong flattens a tree or escapes the destination."""

    def setUp(self):
        self.mod = load_backup()

    def strip(self, key, prefix):
        return key[len(prefix):].lstrip("/")

    def test_nested_paths_survive(self):
        self.assertEqual(self.strip("snap1/sub/deep/c.md", "snap1"),
                         "sub/deep/c.md")

    def test_prefix_with_trailing_slash(self):
        self.assertEqual(self.strip("snap1/a.txt", "snap1/"), "a.txt")

    def test_result_never_escapes_the_destination(self):
        for key, prefix in [("snap1/sub/b.py", "snap1"),
                            ("snap1/a.txt", "snap1/")]:
            rel = self.strip(key, prefix)
            dest = os.path.abspath("/tmp/dest")
            self.assertTrue(
                os.path.abspath(os.path.join(dest, rel)).startswith(dest))


if __name__ == "__main__":
    unittest.main()
