"""Check that the payout log has not been rewritten.

The measurement is the one part of blindrange where you would otherwise
have to take our word for it: we score the audits and compute the shares.
This is the tool that removes that.

Run it whenever you like. It remembers the last tree head it saw and, on
the next run, demands a cryptographic proof that the current log still
contains that exact history — every entry, unchanged, in the same order. If
we ever edited or dropped a past report or share calculation, the proof
cannot be constructed and this exits non-zero.

  python3 examples/verify_log.py                       # check and remember
  python3 examples/verify_log.py --leaf 42             # also prove one entry
  python3 examples/verify_log.py --show 5              # print recent entries

What it proves and what it does not:

  PROVES   nothing already published has changed.
  DOES NOT prove we logged everything — we could decline to record a report
           at all, and no log can detect an omission it never saw.
  DOES NOT alone detect a SPLIT VIEW, where we show you one log and someone
           else another. That needs two people comparing heads, which is
           why the head is printed in a form you can paste to someone.
"""
import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from blindrange import merkle, token as tok  # noqa: E402


def verify_head_signature(head):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    if "sig" not in head or "pub" not in head:
        return None                       # unsigned log: still useful, weaker
    msg = f"brlog|{head['size']}|{head['root']}|{head['at']}".encode()
    try:
        Ed25519PublicKey.from_public_bytes(
            bytes.fromhex(head["pub"])).verify(bytes.fromhex(head["sig"]), msg)
        return True
    except Exception:
        return False


def main():
    ap = argparse.ArgumentParser(description="verify the blindrange payout log")
    ap.add_argument("--status", default="https://status.blindrange.dev")
    ap.add_argument("--state", default=os.path.expanduser("~/.blindrange/log-head.json"))
    ap.add_argument("--leaf", type=int, default=None,
                    help="also prove this entry is included")
    ap.add_argument("--show", type=int, default=0,
                    help="print this many of the most recent entries")
    a = ap.parse_args()
    base = a.status.rstrip("/")

    head = tok.fetch_json(f"{base}/log/sth", timeout=30)
    sig_ok = verify_head_signature(head)
    size, root = int(head["size"]), head["root"]
    print(f"  head      size {size}  root {root[:24]}…")
    if sig_ok is False:
        print("  SIGNATURE INVALID — the head is not from the key it claims",
              file=sys.stderr)
        return 2
    print(f"  signature {'valid' if sig_ok else 'absent (log is unsigned)'}")

    # --- the part that matters: is this an extension of what we saw before?
    prev = None
    if os.path.exists(a.state):
        try:
            prev = json.load(open(a.state))
        except ValueError:
            prev = None
    if prev and int(prev["size"]) <= size:
        m = int(prev["size"])
        got = tok.fetch_json(f"{base}/log/consistency?first={m}", timeout=30)
        proof = [bytes.fromhex(h) for h in got["proof"]]
        ok = merkle.verify_consistency(m, bytes.fromhex(prev["root"]),
                                       size, bytes.fromhex(root), proof)
        if not ok:
            print(f"\n  HISTORY WAS REWRITTEN. The log no longer contains the "
                  f"{m} entries seen on {prev.get('seen', 'a previous run')}.\n"
                  f"  This is the failure this tool exists to catch — keep "
                  f"{a.state} and report it.", file=sys.stderr)
            return 1
        print(f"  consistent with the {m} entries seen previously  ✓"
              f"  ({size - m} new)")
    elif prev:
        print(f"  LOG SHRANK: was {prev['size']} entries, now {size}",
              file=sys.stderr)
        return 1
    else:
        print("  no previous head stored — nothing to compare yet; this run "
              "establishes the baseline")

    if a.leaf is not None:
        got = tok.fetch_json(f"{base}/log/proof?leaf={a.leaf}", timeout=30)
        if "error" in got:
            print(f"  leaf {a.leaf}: {got['error']}", file=sys.stderr)
            return 1
        ok = merkle.verify_inclusion(
            merkle.leaf_hash(got["leaf"].encode()), got["leaf_index"],
            got["tree_size"], [bytes.fromhex(h) for h in got["proof"]],
            bytes.fromhex(got["root"]))
        print(f"  leaf {a.leaf} included  {'✓' if ok else '✗ PROOF FAILED'}")
        if not ok:
            return 1

    if a.show:
        start = max(0, size - a.show)
        got = tok.fetch_json(f"{base}/log/entries?start={start}&count={a.show}",
                             timeout=30)
        print()
        for i, raw in enumerate(got["entries"], start=start):
            try:
                e = json.loads(raw)
                body = e.get("body", {})
                if e.get("kind") == "shares":
                    detail = " ".join(f"{k[:8]}={v}" for k, v in
                                      sorted(body.items()))
                else:
                    detail = f"{len(body.get('nodes', {}))} nodes"
                print(f"  [{i}] {e.get('kind'):<7} {detail}")
            except ValueError:
                print(f"  [{i}] <unparseable>")

    os.makedirs(os.path.dirname(a.state) or ".", exist_ok=True)
    with open(a.state, "w") as f:
        import datetime
        json.dump({"size": size, "root": root,
                   "seen": datetime.datetime.now(
                       datetime.timezone.utc).isoformat(timespec="seconds")}, f)
    print(f"\n  head remembered in {a.state}")
    print(f"  compare with another operator: {size}:{root[:32]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
