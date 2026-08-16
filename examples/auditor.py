"""A heartbeat for the possession measurement.

Audits are the only evidence a node has of having earned anything, and they
expire on purpose: possession is a claim about NOW, and a proof from
yesterday says nothing about a disk that died this morning. The consequence
only became visible once the page went live — with nobody auditing on a
schedule, every node reads "—" and earns nothing a few hours after the last
manual check, and the payout mechanism quietly never accumulates evidence.

This closes that with a small database of its own that it re-audits and
publishes. Two honest caveats, because this is weaker evidence than it
looks:

  * It proves nodes hold THIS database's keys. That is real proof of real
    possession, but a node could in principle serve a small well-known
    probe while dropping everything else. Real owners auditing real data is
    the stronger signal, and this is a floor under the measurement rather
    than a replacement for it.
  * It is one reporter. The aggregator takes a low quantile precisely so
    that no single reporter dominates, which means a lone prober cannot
    rescue a node that real owners find failing — by design.

Writes happen once, at creation. After that it only reads, so it costs
storage and no further capacity.

  python3 examples/auditor.py --state ~/.blindrange/probe.brdb \\
      --status https://status.blindrange.dev
"""
import argparse
import json
import os
import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from blindrange import Owner, token as tok  # noqa: E402

PROBE_ROWS = 300


def main():
    ap = argparse.ArgumentParser(description="publish a possession audit")
    ap.add_argument("--state", default=os.path.expanduser("~/.blindrange/probe.brdb"))
    ap.add_argument("--passphrase", default=os.environ.get("BR_PROBE_PASS", "probe"))
    ap.add_argument("--bootstrap", default="127.0.0.1:7501")
    ap.add_argument("--secret", default="blindrange-public")
    ap.add_argument("--status", default="https://status.blindrange.dev")
    ap.add_argument("--issuer", default="https://tokens.blindrange.dev")
    ap.add_argument("--account", default=os.environ.get("BR_ACCOUNT", ""))
    a = ap.parse_args()

    fresh = not os.path.exists(a.state)
    if fresh:
        owner = Owner.create(
            a.state, a.passphrase,
            {"ts": {"type": "int", "bits": 22, "leaf_width": 4096}},
            bootstrap=[a.bootstrap], network_secret=a.secret)
        if a.account:
            owner.configure_tokens(a.issuer, a.account)
        owner.write_acks = 3          # every replica, so 1.0 is a fair score
        rng = random.Random(4242)
        owner.insert_many([{"ts": rng.randrange(2592000), "m": "probe"}
                           for _ in range(PROBE_ROWS)])
        owner.drain()
        print(f"created probe database with {PROBE_ROWS} records", flush=True)
    else:
        owner = Owner.open(a.state, a.passphrase, bootstrap=[a.bootstrap])
        if a.account:
            owner.configure_tokens(a.issuer, a.account)

    report = owner.audit_report()
    groups = len(report.get("proofs") or [])
    if not groups:
        # Fail loudly. An auditor that silently publishes nothing leaves the
        # page looking exactly like an auditor that is not running at all.
        print("no corroborated receipt groups — nodes may be on old code "
              "or unreachable; nothing published", file=sys.stderr, flush=True)
        return 1

    size = len(json.dumps(report).encode())
    try:
        out = tok.fetch_json(a.status.rstrip("/") + "/report", report,
                             timeout=60)
    except Exception as e:
        # Name the consequence, not just the error. A rejected report is
        # invisible for hours and then arrives as every node's possession
        # expiring and its payout share going to zero — which reads as the
        # nodes misbehaving rather than as the aggregator refusing us.
        print(f"report REJECTED ({type(e).__name__}: {str(e)[:120]}) — "
              f"{groups} groups, {size:,} bytes. Nothing was published, so "
              f"possession will expire for every node this covered and "
              f"their shares will fall to zero until a report lands.",
              file=sys.stderr, flush=True)
        return 1
    print(f"published {groups} groups covering {len(report['nodes'])} nodes "
          f"in {size:,} bytes: {json.dumps(out)}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
