"""Packaging metadata, which the rest of the suite never touches.

Every other test runs against an already-installed package, so a broken
pyproject.toml is invisible to them — and a broken pyproject.toml means
nobody can install the project at all. That happened: a multi-line inline
table (illegal TOML) shipped, and the first person to try `pip install -e .`
on a fresh machine hit it instead of us.
"""
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class TestPyproject(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(ROOT / "pyproject.toml", "rb") as f:
            cls.cfg = tomllib.load(f)          # raises if the TOML is invalid

    def test_the_essentials_are_present(self):
        proj = self.cfg["project"]
        for key in ("name", "version", "requires-python", "dependencies"):
            self.assertIn(key, proj)
        self.assertEqual(proj["name"], "blindrange")

    def test_module_version_matches_pyproject(self):
        """Two places record the version and only one gets bumped.

        Caught while assembling npm platform packages: the wheel's
        metadata said 0.7.0 while blindrange.__version__ still said
        0.6.0, which is the number a node reports to its peers and the
        status page prints. A published tarball would have carried the
        disagreement permanently.
        """
        import blindrange
        self.assertEqual(blindrange.__version__,
                         self.cfg["project"]["version"],
                         "blindrange.__version__ and pyproject.toml "
                         "disagree about which version this is")

    def test_console_scripts_point_at_real_callables(self):
        import importlib
        for script, target in self.cfg["project"]["scripts"].items():
            mod, _, fn = target.partition(":")
            m = importlib.import_module(mod)
            self.assertTrue(callable(getattr(m, fn, None)),
                            f"{script} -> {target} is not callable")

    def test_quic_is_optional_not_required(self):
        """A platform with no aioquic wheel must still be able to install:
        QUIC only upgrades a relay path to a direct one."""
        deps = " ".join(self.cfg["project"]["dependencies"])
        self.assertNotIn("aioquic", deps)
        extras = self.cfg["project"]["optional-dependencies"]
        self.assertIn("aioquic>=1.2", extras["quic"])

    def test_packages_listed_actually_exist(self):
        tool = self.cfg.get("tool", {}).get("setuptools", {})
        for pkg in tool.get("packages", []):
            self.assertTrue((ROOT / pkg.replace(".", "/")).is_dir(), pkg)


class TestImportsWithoutOptionalDeps(unittest.TestCase):
    def test_node_imports_without_aioquic(self):
        """The hard requirement this replaced: a bare aioquic import made
        the whole package unimportable where no wheel exists."""
        import subprocess
        import sys
        code = (
            "import sys, builtins\n"
            "real = builtins.__import__\n"
            "def blocked(n, *a, **k):\n"
            "    if n.startswith('aioquic'): raise ImportError('no wheel')\n"
            "    return real(n, *a, **k)\n"
            "builtins.__import__ = blocked\n"
            "import blindrange.node as n\n"
            "assert n.direct_mod.DISABLED, 'QUIC should disable itself'\n"
            "from blindrange import Owner\n"
            "print('ok')\n")
        r = subprocess.run([sys.executable, "-c", code], capture_output=True,
                           text=True, cwd=str(ROOT))
        self.assertIn("ok", r.stdout, r.stderr[-600:])


if __name__ == "__main__":
    unittest.main()


class TestDocumentedPythonFloor(unittest.TestCase):
    """The docs promise a minimum Python. It has to be the real one.

    Someone on an older box hit `Directory '.' is not installable. File
    'setup.py' not found` — a pre-PEP-517 pip failing on a pyproject-only
    project, and a message that names neither cause. The docs now state the
    floor so that person can tell in one command whether their interpreter
    or their pip is the problem, which is only useful while the number
    stays true.
    """

    def _floor(self):
        import re
        text = (ROOT / "pyproject.toml").read_text()
        m = re.search(r'requires-python\s*=\s*"[><=]*\s*(\d+\.\d+)', text)
        self.assertIsNotNone(m, "pyproject has no requires-python")
        return m.group(1)

    def test_readme_states_the_real_minimum(self):
        floor = self._floor()
        text = (ROOT / "README.md").read_text()
        self.assertIn(floor, text,
                      f"README never mentions Python {floor}")

    def test_landing_page_states_the_real_minimum(self):
        floor = self._floor()
        page = (ROOT / "docs" / "index.html").read_text()
        self.assertIn(f"Python {floor}", page,
                      f"the page a new operator reads should say {floor}")

    def test_install_instructions_upgrade_pip_first(self):
        """A new venv seeds the system pip, which on an older distro is from
        2018 and cannot install this project at all."""
        for name in ("README.md", "docs/index.html", "docs/demos.html"):
            text = (ROOT / name).read_text()
            if "pip install -e" not in text:
                continue
            self.assertIn("--upgrade pip", text,
                          f"{name} tells people to install without first "
                          f"upgrading pip inside the venv")
