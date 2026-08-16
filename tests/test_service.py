"""The generated service must not repeat the failures we already had.

Every assertion here is a bug that reached the public network: a shell
wrapper that swallowed SIGTERM, a stop timeout shorter than a compaction,
and three separate features that silently no-opped because
ProtectSystem=strict had made their target read-only.
"""
import importlib.util
import os
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "install_service", ROOT / "examples" / "install_service.py")
svc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(svc)


class Args:
    """Defaults matching the installer's own."""
    data = "/var/lib/blindrange/n1"
    port = 7501
    seed = ["seed.blindrange.dev:7501"]
    secret = "blindrange-public"
    max_disk = "20GB"
    host = ""
    auto_update = True
    user = "blindrange"
    log = ""
    name = "blindrange-node"
    repo = str(ROOT)


class TestSystemdUnit(unittest.TestCase):
    def unit(self, **over):
        a = Args()
        for k, v in over.items():
            setattr(a, k, v)
        return svc.systemd_unit(a, "/opt/br/.venv/bin/python")

    def test_execstart_runs_the_binary_not_a_shell(self):
        """Behind `/bin/sh -c` the shell is systemd's main process, SIGTERM
        goes to the shell, and the node never hears it. Every stop of the
        heartbeat ended in SIGKILL that way, mid-compaction."""
        line = next(l for l in self.unit().splitlines()
                    if l.startswith("ExecStart="))
        self.assertNotIn("/bin/sh", line)
        self.assertNotIn(" -c ", line)
        self.assertIn("--port 7501", line)

    def test_stop_timeout_outlasts_a_compaction(self):
        """A clean stop finishes the operation in flight, and compaction was
        measured at 565s. The 90s default is a guaranteed kill."""
        line = next(l for l in self.unit().splitlines()
                    if l.startswith("TimeoutStopSec="))
        self.assertGreaterEqual(int(line.split("=")[1]), 600)

    def test_data_directory_is_writable_under_protectsystem(self):
        """strict makes the whole filesystem read-only, home included."""
        unit = self.unit()
        self.assertIn("ProtectSystem=strict", unit)
        rw = next(l for l in unit.splitlines()
                  if l.startswith("ReadWritePaths="))
        self.assertIn("/var/lib/blindrange/n1", rw)

    def test_auto_update_makes_the_checkout_writable(self):
        """--auto-update rewrites this checkout by design. Without the repo
        in ReadWritePaths every git pull failed and the loop swallowed it:
        the seed reported a healthy version while running day-old code, with
        no log line for 24 hours."""
        rw = next(l for l in self.unit(auto_update=True).splitlines()
                  if l.startswith("ReadWritePaths="))
        self.assertIn(str(ROOT), rw)

    def test_without_auto_update_the_checkout_stays_read_only(self):
        rw = next(l for l in self.unit(auto_update=False).splitlines()
                  if l.startswith("ReadWritePaths="))
        self.assertNotIn(str(ROOT), rw)
        self.assertNotIn("--auto-update", self.unit(auto_update=False))

    def test_home_is_not_protected_away(self):
        """The default data directory lives under home. ProtectHome=true
        would make it unwritable, which under strict fails at runtime rather
        than at start — the exact shape of the last three of these bugs."""
        self.assertNotIn("ProtectHome=true", self.unit())

    def test_it_restarts_and_starts_at_boot(self):
        unit = self.unit()
        self.assertIn("Restart=always", unit)
        self.assertIn("WantedBy=multi-user.target", unit)

    def test_secret_and_seed_survive_into_the_command(self):
        line = next(l for l in self.unit().splitlines()
                    if l.startswith("ExecStart="))
        self.assertIn("--seed seed.blindrange.dev:7501", line)
        self.assertIn("--secret blindrange-public", line)
        self.assertIn("--max-disk 20GB", line)


class TestLaunchdPlist(unittest.TestCase):
    def test_plist_is_well_formed_and_keeps_the_node_alive(self):
        import plistlib
        text = svc.launchd_plist(Args(), "/opt/br/.venv/bin/python")
        d = plistlib.loads(text.encode())
        self.assertTrue(d["KeepAlive"])
        self.assertTrue(d["RunAtLoad"])
        self.assertIn("--port", d["ProgramArguments"])
        self.assertEqual(d["Label"], "blindrange-node")


class TestCommandBuilding(unittest.TestCase):
    def test_falls_back_to_module_form_when_no_console_script(self):
        """A venv built by `uv venv` has no pip and may have no console
        scripts until the package is installed; -m always works."""
        cmd = svc.node_command("/nonexistent/bin/python", Args())
        self.assertEqual(cmd[:3],
                         ["/nonexistent/bin/python", "-m", "blindrange.node"])

    def test_no_argument_is_a_pre_joined_string(self):
        """argv entries go to exec() unsplit; a joined 'a b' would arrive as
        one argument and be rejected."""
        for part in svc.node_command("/x/bin/python", Args()):
            self.assertNotIn(" ", part)



class TestRepoResolutionRefusesToGuess(unittest.TestCase):
    """Running the installer from a copy outside the checkout produced
    `ReadWritePaths=/`, which hands the service the entire filesystem and
    turns ProtectSystem=strict into decoration. systemd accepts it without
    complaint — `systemd-analyze verify` passed the unit — so nothing would
    have said a word."""

    def test_a_non_checkout_is_refused(self):
        with self.assertRaises(SystemExit):
            svc.resolve_repo("/tmp")

    def test_the_filesystem_root_is_refused(self):
        with self.assertRaises(SystemExit):
            svc.resolve_repo("/")

    def test_a_real_checkout_is_accepted(self):
        self.assertEqual(svc.resolve_repo(str(ROOT)), ROOT)

    def test_no_generated_unit_can_grant_the_whole_filesystem(self):
        a = Args()
        unit = svc.systemd_unit(a, "/opt/br/.venv/bin/python")
        rw = next(l for l in unit.splitlines()
                  if l.startswith("ReadWritePaths="))
        self.assertNotIn(" /\n", rw + "\n")
        self.assertNotEqual(rw.split("=", 1)[1].split(), ["/"])
        for path in rw.split("=", 1)[1].split():
            self.assertNotEqual(path, "/")


if __name__ == "__main__":
    unittest.main()
