"""Run a node in the background, surviving logout and reboot.

A node you have to keep a terminal open for is a node that goes away the
first time you close a laptop lid, and "my node vanished" is indistinguishable
from "the network lost my data" to everyone else on it. This writes a real
service definition — systemd on Linux, launchd on macOS — so the node starts
at boot, restarts if it dies, and logs somewhere you can read later.

    python3 examples/install_service.py --print          # show, install nothing
    sudo python3 examples/install_service.py --data ~/.blindrange/n1

Everything it encodes was learned by getting it wrong on the public network:

  * ExecStart runs the binary DIRECTLY, never `/bin/sh -c`. With a shell in
    front, systemd's main process is the shell, SIGTERM goes to the shell,
    and the node never hears it — every stop ended in SIGKILL, mid-write.
  * TimeoutStopSec is generous, because a clean stop finishes the operation
    in flight and compaction was measured at 565s. The 90s default guaranteed
    a kill.
  * ProtectSystem=strict makes the WHOLE filesystem read-only, including your
    home directory. Three separate features silently no-opped on the public
    seed before this was understood: the data directory and — with
    --auto-update, which rewrites the checkout by design — the repository
    itself must be listed in ReadWritePaths or they fail invisibly.

Windows is not covered here. Run the node in a terminal there, or wrap it
with a service manager; the node already supervises itself on Windows so
that auto-update can restart it.
"""
import argparse
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def resolve_repo(explicit=""):
    """Where the checkout actually is, or refuse to guess.

    This is not defensive padding. Run from a copy in /tmp, the old
    guess — the script's parent's parent — resolved to `/`, and the unit
    it produced said `ReadWritePaths=/`. That does not fail: it hands the
    service the whole filesystem and turns ProtectSystem=strict into
    decoration, quietly, in a file nobody reads again. systemd-analyze
    verify passes it happily.
    """
    root = Path(explicit).expanduser().resolve() if explicit else REPO
    if not (root / "blindrange" / "node.py").exists():
        raise SystemExit(
            f"{root} is not a blindrange checkout — pass --repo with the "
            f"path to one. Refusing to guess, because guessing produced "
            f"ReadWritePaths=/ and silently disabled the sandbox.")
    if root == Path(root.anchor):
        raise SystemExit("--repo cannot be the filesystem root")
    return root


def node_command(python, args):
    """The argv systemd or launchd will run. No shell, ever."""
    exe = Path(python).parent / "blindrange-node"
    cmd = ([str(exe)] if exe.exists()
           else [str(python), "-m", "blindrange.node"])
    cmd += ["--port", str(args.port), "--data", str(args.data)]
    for seed in args.seed:
        cmd += ["--seed", seed]
    if args.secret:
        cmd += ["--secret", args.secret]
    if args.max_disk:
        cmd += ["--max-disk", args.max_disk]
    if args.host:
        cmd += ["--host", args.host]
    if args.auto_update:
        cmd += ["--auto-update"]
    return cmd


def writable_paths(args):
    """Everything the service must be able to write.

    Under ProtectSystem=strict this is not hardening trivia — anything
    missing here fails silently at runtime rather than refusing to start.
    """
    paths = [str(Path(args.data).expanduser())]
    if args.auto_update:
        # --auto-update rewrites this checkout. Saying so plainly beats
        # discovering it as a node that reports a healthy version while
        # running week-old code.
        paths.append(str(resolve_repo(getattr(args, "repo", ""))))
    return paths


def systemd_unit(args, python):
    cmd = " ".join(node_command(python, args))
    rw = " ".join(writable_paths(args))
    user = args.user or os.environ.get("SUDO_USER") or "root"
    repo = resolve_repo(getattr(args, "repo", ""))
    return f"""[Unit]
Description=blindrange node ({args.name})
Documentation=https://blindrange.dev
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User={user}
WorkingDirectory={repo}
# Run the binary directly. Behind `/bin/sh -c` the shell becomes the main
# process, SIGTERM never reaches the node, and every stop is a SIGKILL.
ExecStart={cmd}
Restart=always
RestartSec=10
# A clean stop finishes the operation in flight; compaction was measured at
# 565s on the public network, and the 90s default killed it every time.
TimeoutStopSec=900
KillMode=mixed
Nice=5
NoNewPrivileges=true
# strict makes the entire filesystem read-only, home included. Anything not
# listed below fails silently at runtime instead of refusing to start.
ProtectSystem=strict
ReadWritePaths={rw}
# A private, writable /tmp. Without one, anything that needs scratch space
# fails at runtime under strict — SQLite reported "disk I/O error" on a box
# with 523G free, which is a true statement and a terrible clue.
PrivateTmp=true

[Install]
WantedBy=multi-user.target
"""


def launchd_plist(args, python):
    cmd = node_command(python, args)
    argv = "\n".join(f"    <string>{c}</string>" for c in cmd)
    log = Path(args.log or Path.home() / f"Library/Logs/{args.name}.log")
    repo = resolve_repo(getattr(args, "repo", ""))
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{args.name}</string>
  <key>ProgramArguments</key>
  <array>
{argv}
  </array>
  <key>WorkingDirectory</key><string>{repo}</string>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>{log}</string>
  <key>StandardErrorPath</key><string>{log}</string>
</dict>
</plist>
"""


def main():
    ap = argparse.ArgumentParser(
        description="install a blindrange node as a background service")
    ap.add_argument("--data", default="~/.blindrange/n1")
    ap.add_argument("--port", type=int, default=7501)
    ap.add_argument("--seed", action="append",
                    default=["seed.blindrange.dev:7501"])
    ap.add_argument("--secret", default="blindrange-public")
    ap.add_argument("--max-disk", default="20GB")
    ap.add_argument("--host", default="")
    ap.add_argument("--no-auto-update", dest="auto_update",
                    action="store_false",
                    help="do not let the node fast-forward its own checkout")
    ap.add_argument("--user", default="")
    ap.add_argument("--python", default=sys.executable)
    ap.add_argument("--log", default="")
    ap.add_argument("--name", default="blindrange-node")
    ap.add_argument("--repo", default="",
                    help="path to the checkout; only needed when this script "
                         "has been copied out of one")
    ap.add_argument("--target", choices=("auto", "linux", "macos"),
                    default="auto",
                    help="which service manager to write for; the default "
                         "follows this machine. Useful with --print to "
                         "generate a unit for a box you are not on.")
    ap.add_argument("--print", dest="show", action="store_true",
                    help="print the service definition and exit")
    a = ap.parse_args()
    a.data = str(Path(a.data).expanduser())

    mac = (platform.system() == "Darwin" if a.target == "auto"
           else a.target == "macos")
    if a.target != "auto" and not a.show and mac != (
            platform.system() == "Darwin"):
        print("--target only overrides generation; use --print and install "
              "the result on the machine it is for.", file=sys.stderr)
        return 1
    text = launchd_plist(a, a.python) if mac else systemd_unit(a, a.python)
    if a.show:
        print(text, end="")
        return 0

    if mac:
        dest = Path.home() / "Library/LaunchAgents" / f"{a.name}.plist"
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(text)
        subprocess.run(["launchctl", "unload", str(dest)],
                       capture_output=True)
        subprocess.run(["launchctl", "load", str(dest)], check=True)
        print(f"installed {dest}\n"
              f"  stop:    launchctl unload {dest}\n"
              f"  start:   launchctl load {dest}\n"
              f"  logs:    tail -f {a.log or Path.home()}"
              f"{'' if a.log else f'/Library/Logs/{a.name}.log'}")
        return 0

    if not shutil.which("systemctl"):
        print("no systemd and not macOS. Run it under your own supervisor, "
              "or in a terminal with:\n  " +
              " ".join(node_command(a.python, a)), file=sys.stderr)
        return 1
    if os.geteuid() != 0:
        print("needs root to write /etc/systemd/system — re-run with sudo, "
              "or use --print and install the unit yourself.", file=sys.stderr)
        return 1
    dest = Path(f"/etc/systemd/system/{a.name}.service")
    dest.write_text(text)
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "enable", "--now", a.name], check=True)
    print(f"installed {dest}\n"
          f"  status:  systemctl status {a.name}\n"
          f"  stop:    systemctl stop {a.name}\n"
          f"  start:   systemctl start {a.name}\n"
          f"  logs:    journalctl -u {a.name} -f")
    return 0


if __name__ == "__main__":
    sys.exit(main())
