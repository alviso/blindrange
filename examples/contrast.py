"""Side by side: what the owner reads, and what the network stores.

Runs one real range query against a blindrange network, then dumps a sample
of what a node operator can see of that same data. The two halves are the
whole point of the project.

  python3 examples/contrast.py                       # public demo network
  python3 examples/contrast.py STATE PASS SEED [FIELD LO HI]
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from blindrange import Owner  # noqa: E402

BOLD, DIM, CYAN, GOLD, GREEN, OFF = (
    "\033[1m", "\033[2m", "\033[36m", "\033[33m", "\033[32m", "\033[0m")


def main():
    state = sys.argv[1] if len(sys.argv) > 1 else "/tmp/pubtest.brdb"
    passphrase = sys.argv[2] if len(sys.argv) > 2 else "pass"
    seed = sys.argv[3] if len(sys.argv) > 3 else "seed.blindrange.dev:7501"
    owner = Owner.open(state, passphrase, bootstrap=[seed])

    field = sys.argv[4] if len(sys.argv) > 4 else next(iter(owner.schema))
    lo = int(sys.argv[5]) if len(sys.argv) > 5 else 100
    hi = int(sys.argv[6]) if len(sys.argv) > 6 else 300
    rows = owner.query(field, lo, hi)
    rows.sort(key=lambda r: r.get(field, 0))
    s = owner.last_stats

    print(f"\n{BOLD}{CYAN}  OWNER   {OFF}{CYAN}holds the key — reads plaintext"
          f"{OFF}")
    print(f"{DIM}  query: {field} BETWEEN {lo} AND {hi}{OFF}")
    for r in rows[:4]:
        vals = ", ".join(f"{k}={v}" for k, v in r.items()
                         if not k.startswith("_"))
        print(f"    {vals}")
    print(f"{DIM}    … {len(rows)} rows, decrypted here and nowhere else{OFF}")

    print(f"\n{BOLD}{GOLD}  NETWORK {OFF}{GOLD}holds no key — stores this"
          f"{OFF}")
    node = owner.ring.addrs[0]
    intel = owner.intel(owner._addr(node), limit=4)
    print(f"{DIM}  node {intel['node_id']} · {intel['count']} keys{OFF}")
    for k, v in intel["sample"]:
        print(f"    {k[:34]} → {v[:26]}…")
    print(f"{DIM}    no key · no order · no equality · no plaintext{OFF}")

    print(f"\n{GREEN}  {len(rows)} rows in {s['rounds']} network rounds · "
          f"{s['index_keys']} opaque lookups · "
          f"{s.get('overfetch', 0)} over-fetch filtered after decryption{OFF}\n")


if __name__ == "__main__":
    main()
