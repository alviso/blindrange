"""Reclaim what a crashed compaction stranded on the network.

    python3 examples/purge_orphans.py --state ~/.blindrange/mydb.brdb

Works on any state file whose master key still exists — including one
whose database was already drop()ped, which only removes the keys the
pruned walk could name. Orphans whose owner state is truly gone can never
be named by anyone; that is the price of unlinkability, and this tool is
why keeping the state file until after a purge matters.
"""
import argparse
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from blindrange import Owner  # noqa: E402


def main():
    ap = argparse.ArgumentParser(description="sweep stranded epoch keys")
    ap.add_argument("--state", required=True)
    ap.add_argument("--passphrase", default=os.environ.get("BR_PASS", ""))
    ap.add_argument("--bootstrap", default="seed.blindrange.dev:7501")
    ap.add_argument("--issuer", default="https://tokens.blindrange.dev")
    ap.add_argument("--account", default=os.environ.get("BR_ACCOUNT", ""))
    a = ap.parse_args()
    if not a.passphrase:
        import getpass
        a.passphrase = getpass.getpass("passphrase: ")

    o = Owner.open(a.state, a.passphrase, bootstrap=[a.bootstrap])
    if a.account:
        o.configure_tokens(a.issuer, a.account)
    t0 = time.time()
    out = o.purge_orphans(verbose=True)
    mins = (time.time() - t0) / 60
    print(f"purged in {mins:.0f} min: {out['chain_keys_removed']:,} chain "
          f"keys and {out['blobs_removed']:,} blobs across epochs "
          f"{out['epochs']} · {out['beyond_gallop']:,} of them invisible "
          f"to galloping · coverage {out['coverage']}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
