"""The npm package must work, and both languages must read each other.

Skipped when node is not installed. Everything else in this file is
non-negotiable: the bridge is how every non-Python caller reaches the
database, and the cross-language assertions at the bottom are the whole
argument for shipping the reference client instead of a port — if Python
cannot read what Node wrote through the bridge, the package is worthless
regardless of what its own tests say.
"""
import json
import os
import platform
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

PORT = 7819
SECRET = "bridgenet"
NODE = shutil.which("node")


def _python_shim(tmp):
    """A launcher that pins the interpreter to THIS machine's architecture.

    On macOS a universal python spawned from an x86_64 Node starts under
    Rosetta and then fails to load arm64 native wheels — found the first
    time this bridge ran, diagnosed entirely from the stderr tail the JS
    side attaches to failures. The bundled platform runtimes are per-arch,
    which removes the whole class; this shim is only for the dev fallback.
    """
    shim = Path(tmp) / "python-shim.sh"
    if platform.system() == "Darwin":
        shim.write_text(f"#!/bin/sh\nexec arch -{platform.machine()} "
                        f"{sys.executable} \"$@\"\n")
    else:
        shim.write_text(f"#!/bin/sh\nexec {sys.executable} \"$@\"\n")
    shim.chmod(0o755)
    return str(shim)


@unittest.skipUnless(NODE, "node is not installed")
class TestNodeBridge(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="blindrange_bridge_")
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
        cls.env = {**os.environ,
                   "BLINDRANGE_PYTHON": _python_shim(cls.tmp),
                   "PYTHONPATH": str(ROOT)}

    @classmethod
    def tearDownClass(cls):
        cls.proc.kill()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def run_node(self, script):
        path = Path(self.tmp) / "case.mjs"
        path.write_text(script)
        out = subprocess.run([NODE, str(path)], capture_output=True,
                             text=True, timeout=300, env=self.env,
                             cwd=str(ROOT))
        self.assertEqual(out.returncode, 0,
                         f"node failed:\n{out.stdout[-1500:]}\n"
                         f"{out.stderr[-1500:]}")
        return out.stdout

    def test_crud_refusals_and_cross_language_reads(self):
        pkg = (ROOT / "npm" / "blindrange" / "index.mjs").as_posix()
        db_dir = (Path(self.tmp) / "db").as_posix()
        out = self.run_node(f'''
import {{ connect, UnsupportedError }} from "{pkg}";
const db = await connect({{
  path: "{db_dir}", passphrase: "pw",
  bootstrap: ["127.0.0.1:{PORT}"], networkSecret: "{SECRET}",
}});
await db.execute(`CREATE TABLE orders (
  amount INT BITS 20 BLUR 64, status TEXT(6) BLUR 16, customer STORED)`);
await db.execute(`INSERT INTO orders (amount, status, customer) VALUES
  (450, 'paid', 'js-001'), (120, 'refunded', 'js-002'),
  (720, 'paid', 'js-003')`);
const rows = await db.execute(
  `SELECT customer FROM orders WHERE amount BETWEEN 300 AND 800
   ORDER BY amount DESC`);
console.log("ROWS " + JSON.stringify(rows.map(r => r.customer)));
const [c] = await db.execute(`SELECT COUNT(*) FROM orders`);
console.log("COUNT " + c.count + " " + c.basis);
let refused = "no";
try {{ await db.execute(`SELECT * FROM a JOIN b ON 1`); }}
catch (e) {{ refused = (e instanceof UnsupportedError) ? "typed" : "untyped"; }}
console.log("REFUSED " + refused);
await db.execute(`UPDATE orders SET status = 'shipped' WHERE amount = 450`);
await db.close();
console.log("CLOSED");
''')
        self.assertIn('ROWS ["js-003","js-001"]', out)
        self.assertIn("COUNT 3 exact-to-leaf", out)
        self.assertIn("REFUSED typed", out,
                      "refusals must arrive as UnsupportedError, or JS "
                      "callers cannot tell a boundary from a bug")
        self.assertIn("CLOSED", out)

        # The assertion the whole architecture rests on: Python opens the
        # very state Node wrote and reads the same data, including the
        # update. One implementation, two languages, nothing to drift.
        from blindrange.sql import connect as py_connect
        con = py_connect(db_dir, "pw", [f"127.0.0.1:{PORT}"], SECRET)
        rows = con.execute("SELECT status, customer FROM orders "
                           "WHERE amount = 450")
        self.assertEqual(rows, [{"status": "shipped", "customer": "js-001"}])

        # And the reverse: Python writes, Node reads it back.
        con.execute("INSERT INTO orders (amount, status, customer) "
                    "VALUES (999, 'python', 'py-001')")
        con.close()
        out = self.run_node(f'''
import {{ connect }} from "{pkg}";
const db = await connect({{
  path: "{db_dir}", passphrase: "pw",
  bootstrap: ["127.0.0.1:{PORT}"], networkSecret: "{SECRET}",
}});
const rows = await db.execute(`SELECT customer FROM orders WHERE amount = 999`);
console.log("BACK " + JSON.stringify(rows));
await db.close();
''')
        self.assertIn('BACK [{"customer":"py-001"}]', out)

    def test_a_dead_bridge_fails_loudly_with_its_stderr(self):
        pkg = (ROOT / "npm" / "blindrange" / "index.mjs").as_posix()
        out = subprocess.run(
            [NODE, "-e", f'''
import("{pkg}").then(async ({{ connect }}) => {{
  try {{
    await connect({{ path: "/tmp/x", passphrase: "p", bootstrap: [] ,
                     python: "/nonexistent/python3" }});
    console.log("OPENED");
  }} catch (e) {{
    console.log("ERR " + e.message.split("\\n")[0]);
  }}
}});'''],
            capture_output=True, text=True, timeout=120, env=self.env)
        self.assertIn("ERR", out.stdout,
                      f"expected a loud failure, got: {out.stdout!r} "
                      f"{out.stderr[-400:]!r}")
        self.assertNotIn("OPENED", out.stdout)


if __name__ == "__main__":
    unittest.main()
