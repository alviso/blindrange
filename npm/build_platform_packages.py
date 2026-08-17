"""Assemble the @blindrange/python-* platform packages for npm.

Each package carries a self-contained CPython (python-build-standalone,
the same prebuilt interpreters uv installs) with the blindrange wheel and
its dependencies already inside — so `npm install blindrange` needs no
Python on the machine, no compiler, and no network beyond npm itself.

    python3 npm/build_platform_packages.py --only darwin-arm64   # this machine
    python3 npm/build_platform_packages.py                       # all targets
    python3 npm/build_platform_packages.py --publish             # + npm publish

Publishing runs under YOUR npm login; this script never handles
credentials. Run `npm login` first, once.

Cross-platform assembly works because everything is wheels: the runtime
tarball is prebuilt, blindrange is pure Python, and `pip download` can
fetch another platform's cryptography wheel with --platform. Nothing is
compiled here, ever — if a wheel is missing for a target, the build FAILS
for that target rather than quietly shipping a package that would try to
compile Rust on some user's laptop.
"""
import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
# The repo's own SSL context helper: python.org macOS builds ship no CA
# bundle, and this script is the third caller to trip over it. One fix
# lives in blindrange.token; everything in this repo uses it.
from blindrange.token import _ssl_context  # noqa: E402
OUT = ROOT / "npm" / "dist"
PY_VERSION = "3.12"

# npm platform tag -> python-build-standalone target triple
TARGETS = {
    "darwin-arm64": "aarch64-apple-darwin",
    "darwin-x64": "x86_64-apple-darwin",
    "linux-x64": "x86_64-unknown-linux-gnu",
    "linux-arm64": "aarch64-unknown-linux-gnu",
    "win32-x64": "x86_64-pc-windows-msvc",
}
# pip --platform tags per target, for downloading native wheels
PIP_PLATFORMS = {
    "darwin-arm64": ["macosx_11_0_arm64"],
    "darwin-x64": ["macosx_10_12_x86_64"],
    "linux-x64": ["manylinux2014_x86_64", "manylinux_2_17_x86_64"],
    "linux-arm64": ["manylinux2014_aarch64", "manylinux_2_17_aarch64"],
    "win32-x64": ["win_amd64"],
}


def say(msg):
    print(msg, flush=True)


def latest_release_assets():
    req = urllib.request.Request(
        "https://api.github.com/repos/astral-sh/python-build-standalone/"
        "releases/latest", headers={"User-Agent": "blindrange-build"})
    with urllib.request.urlopen(req, timeout=60,
                                context=_ssl_context()) as r:
        rel = json.loads(r.read())
    return rel["tag_name"], {a["name"]: a["browser_download_url"]
                             for a in rel["assets"]}


def pick_asset(assets, triple):
    """Prefer install_only_stripped: same runtime, no debug symbols.

    The plain install_only linux build unpacked to 791 MB — debug info,
    a 100+ MB static libpython nobody links, and the stdlib test suite.
    Stripped exists for exactly this use and cuts it by hundreds of MB.
    """
    def match(suffix):
        return sorted(n for n in assets
                      if triple in n and n.endswith(suffix)
                      and f"cpython-{PY_VERSION}." in n)
    want = match("install_only_stripped.tar.gz") or match("install_only.tar.gz")
    if not want:
        raise SystemExit(f"no install_only cpython-{PY_VERSION} asset for "
                         f"{triple} — check PY_VERSION against the release")
    return want[-1]


def build_wheel():
    wheel_dir = OUT / "wheel"
    shutil.rmtree(wheel_dir, ignore_errors=True)
    wheel_dir.mkdir(parents=True)
    subprocess.run([sys.executable, "-m", "pip", "wheel", "--no-deps",
                    "-w", str(wheel_dir), str(ROOT)],
                   check=True, capture_output=True)
    return next(wheel_dir.glob("blindrange-*.whl"))


def site_packages(runtime_dir, tag):
    if tag.startswith("win32"):
        return runtime_dir / "python" / "Lib" / "site-packages"
    return (runtime_dir / "python" / "lib" / f"python{PY_VERSION}"
            / "site-packages")


def assemble(tag, triple, assets, urls, wheel, version):
    say(f"— {tag}")
    pkg = OUT / f"python-{tag}"
    shutil.rmtree(pkg, ignore_errors=True)
    pkg.mkdir(parents=True)

    name = pick_asset(assets, triple)
    tarball = OUT / name
    if not tarball.exists():
        say(f"  downloading {name}")
        req = urllib.request.Request(urls[name],
                                     headers={"User-Agent": "blindrange"})
        with urllib.request.urlopen(req, timeout=600,
                                    context=_ssl_context()) as r, \
                open(tarball, "wb") as f:
            shutil.copyfileobj(r, f)
    say("  extracting runtime")
    subprocess.run(["tar", "-xzf", str(tarball), "-C", str(pkg)], check=True)

    sp = site_packages(pkg, tag)
    say("  fetching native wheels for the target platform")

    def fetch(reqs, dl):
        cmd = [sys.executable, "-m", "pip", "download", *reqs,
               "-d", dl, "--only-binary", ":all:",
               "--python-version", PY_VERSION.replace(".", ""),
               "--implementation", "cp"]
        for plat in PIP_PLATFORMS[tag]:
            cmd += ["--platform", plat]
        subprocess.run(cmd, check=True, capture_output=True)

    with tempfile.TemporaryDirectory() as dl:
        fetch(["cryptography>=41"], dl)
        try:
            # QUIC direct paths, so the bundle has full features. Optional
            # per target: the client falls back to relayed connections by
            # design, so a platform without a wheel ships without QUIC and
            # SAYS so, rather than failing the whole build.
            fetch(["aioquic>=1.2"], dl)
        except subprocess.CalledProcessError:
            say(f"  no aioquic wheels for {tag} — QUIC off, relay still works")
        for whl in list(Path(dl).glob("*.whl")) + [wheel]:
            with zipfile.ZipFile(whl) as z:
                z.extractall(sp)

    # Dead weight a database client will never execute: the stdlib test
    # suite, tkinter/IDLE, ensurepip wheels, and any static library that
    # survived stripping. Deleting them is safe precisely because the
    # bridge imports a known, closed set of modules — and the smoke test
    # below this script in the workflow runs the REAL bridge against the
    # trimmed runtime, so an over-eager trim fails loudly before publish.
    lib = (pkg / "python" / "Lib" if tag.startswith("win32")
           else pkg / "python" / "lib")
    for victim in ([lib / f"python{PY_VERSION}" / "test",
                    lib / f"python{PY_VERSION}" / "idlelib",
                    lib / f"python{PY_VERSION}" / "tkinter",
                    lib / f"python{PY_VERSION}" / "ensurepip",
                    lib / "test", lib / "idlelib", lib / "tkinter",
                    lib / "ensurepip"]
                   + list(lib.glob("libpython*.a"))
                   + list((pkg / "python").glob("**/*.a"))):
        if victim.exists():
            (shutil.rmtree(victim, ignore_errors=True)
             if victim.is_dir() else victim.unlink())

    exe = ("python/python.exe" if tag.startswith("win32")
           else "python/bin/python3")
    (pkg / "index.js").write_text(
        'const path = require("node:path");\n'
        f'exports.python = path.join(__dirname, {json.dumps(exe)});\n'
        "exports.env = {};\n")
    os_name, cpu = tag.split("-")
    (pkg / "package.json").write_text(json.dumps({
        "name": f"@blindrange/python-{tag}",
        "version": version,
        "description": f"Self-contained CPython + blindrange for {tag}. "
                       f"Installed automatically by the blindrange package;"
                       f" never depend on this directly.",
        "license": "MIT",
        "repository": "github:alviso/blindrange",
        "main": "index.js",
        "os": [os_name],
        "cpu": [cpu],
    }, indent=2))
    size = sum(f.stat().st_size for f in pkg.rglob("*") if f.is_file())
    say(f"  assembled: {size / 1e6:.0f} MB unpacked")
    return pkg


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", action="append",
                    help="platform tag(s) to build; default all")
    ap.add_argument("--publish", action="store_true",
                    help="npm publish each package (runs under YOUR login)")
    a = ap.parse_args()
    targets = {t: TARGETS[t] for t in (a.only or TARGETS)}

    version = json.loads((ROOT / "npm" / "blindrange" /
                          "package.json").read_text())["version"]
    OUT.mkdir(parents=True, exist_ok=True)
    tag_name, urls = latest_release_assets()
    assets = list(urls)
    say(f"python-build-standalone {tag_name} · packages at v{version}")
    wheel = build_wheel()
    say(f"wheel: {wheel.name}")

    built = [assemble(tag, triple, assets, urls, wheel, version)
             for tag, triple in targets.items()]

    if a.publish:
        for pkg in built:
            subprocess.run(["npm", "publish", "--access", "public"],
                           cwd=pkg, check=True)
        subprocess.run(["npm", "publish", "--access", "public"],
                       cwd=ROOT / "npm" / "blindrange", check=True)
    else:
        say("\nnot published. Review, then either rerun with --publish or:")
        for pkg in built:
            say(f"  (cd {pkg} && npm publish --access public)")
        say(f"  (cd {ROOT / 'npm' / 'blindrange'} && npm publish "
            f"--access public)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
