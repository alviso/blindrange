"""Drop one or more blindrange databases from the network.

Removes every key each database owns, then (optionally) the .brdb file.
Order matters: drop first, delete the file second — without the file there
is no way left to name the keys, and they would sit on the nodes forever.

  python3 examples/drop_databases.py --bootstrap host:port a.brdb b.brdb
"""
import argparse
import json
import os
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from blindrange import Owner  # noqa: E402


def seed_keys(bootstrap):
    try:
        with urllib.request.urlopen(f"http://{bootstrap}/stats", timeout=20) as r:
            return json.loads(r.read()).get("keys", -1)
    except OSError:
        return -1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    ap.add_argument("--bootstrap", default="seed.blindrange.dev:7501")
    ap.add_argument("--passphrase", default="pw")
    ap.add_argument("--keep-file", action="store_true")
    a = ap.parse_args()

    for path in a.files:
        if not os.path.exists(path):
            print(f"  {os.path.basename(path):22} missing, skipped", flush=True)
            continue
        before = seed_keys(a.bootstrap)
        t0 = time.time()
        try:
            owner = Owner.open(path, a.passphrase, bootstrap=[a.bootstrap])
            res = owner.drop(confirm=True)
        except Exception as e:                      # report, never abort the rest
            print(f"  {os.path.basename(path):22} FAILED "
                  f"{type(e).__name__}: {e}", flush=True)
            continue
        time.sleep(2)
        after = seed_keys(a.bootstrap)
        print(f"  {os.path.basename(path):22} {res['records']:>8,} records · "
              f"{res['keys_removed']:>9,} keys · {time.time() - t0:6.0f}s · "
              f"seed {before:,} -> {after:,}", flush=True)
        if not a.keep_file:
            os.remove(path)
    print("  done", flush=True)


if __name__ == "__main__":
    main()
