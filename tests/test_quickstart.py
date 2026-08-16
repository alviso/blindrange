"""The guide's code samples must keep working.

docs/build.html quotes examples/quickstart.py rather than carrying its own
snippets, so that documentation cannot drift from a working program. This
test is the other half of that bargain: if the script stops running, the
guide is wrong and the build fails here rather than in someone's terminal.
"""
import os
import re
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PORT = 7799


class TestQuickstartRuns(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="blindrange_qs_")
        cls.proc = subprocess.Popen(
            [sys.executable, "-m", "blindrange.node", "--port", str(PORT),
             "--data", f"{cls.tmp}/n", "--secret", "qs"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            cwd=str(ROOT), env={**os.environ})
        for _ in range(80):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{PORT}/stats",
                                       timeout=1)
                break
            except OSError:
                time.sleep(0.1)
        else:
            raise RuntimeError("node never came up")

    @classmethod
    def tearDownClass(cls):
        cls.proc.kill()

    def test_every_step_runs_and_the_last_one_cleans_up(self):
        out = subprocess.run(
            [sys.executable, "examples/quickstart.py",
             "--state", f"{self.tmp}/qs.brdb",
             "--bootstrap", f"127.0.0.1:{PORT}", "--secret", "qs"],
            cwd=str(ROOT), capture_output=True, text=True, timeout=600)
        self.assertEqual(out.returncode, 0,
                         f"quickstart failed:\n{out.stdout[-2000:]}\n"
                         f"{out.stderr[-2000:]}")
        body = out.stdout
        for phrase in ("CREATE", "READ", "UPDATE", "DELETE",
                       "records in", "compact()", "removed from the network"):
            self.assertIn(phrase, body, f"missing step: {phrase}")
        self.assertFalse(os.path.exists(f"{self.tmp}/qs.brdb"),
                         "it left its state file behind")

    def test_the_guide_quotes_code_that_exists(self):
        """Every python line the page shows must appear in the script.

        The point of quoting a runnable file is lost the moment the page
        carries a snippet nobody executes.
        """
        page = (ROOT / "docs" / "build.html").read_text()
        script = (ROOT / "examples" / "quickstart.py").read_text()
        quoted = re.findall(r'<code class="from-quickstart">(.*?)</code>',
                            page, re.S)
        self.assertTrue(quoted, "the page quotes nothing from the script")
        import html as _html
        for block in quoted:
            for line in block.splitlines():
                line = _html.unescape(re.sub(r"<[^>]+>", "", line)).strip()
                if not line or line.startswith("#"):
                    continue
                self.assertIn(line, script,
                              f"the page shows a line the script does not "
                              f"contain: {line!r}")
