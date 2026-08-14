"""Node-signed read receipts: whatever a report says, a node said first.

An audit report is worth exactly what it costs to fake, and before receipts
it cost nothing. A report was arbitrary JSON, so anyone could POST "node X
served none of my data" and the aggregator had no way to notice that no
such exchange ever happened. Taking the 25th percentile instead of the
median bought time against a handful of fakes and nothing against someone
willing to send a thousand.

A receipt makes the node the author of the numbers. Every /mget answer
carries an Ed25519 signature over how many keys were asked for, which keys
those were, how many came back, and exactly which bytes came back. Two
properties do the work:

  * A node id IS sha256(pubkey)[:16], so a receipt verifies standing alone.
    No roster, no registry, no directory anyone has to be trusted to keep.
    Check the signature, re-derive the id from the key, done.
  * Nodes sign EVERY read, not the audited ones. A node able to tell an
    audit from an ordinary query could serve the audits and drop the rest;
    because it cannot tell, the only way to pass audits is to hold data.

The harder attack is slander, and counts alone cannot stop it: invent a
hundred key names, ask a node you dislike, and it will honestly sign that
it returned none of them. What defeats this is that nobody chooses where a
key lives — the ring does. So an audit asks the whole replica group of a
key the same batch under the same nonce, and every receipt in that group
commits to the same kdigest. A node's miss only counts when a peer holding
the identical batch produced the data, which makes a fabricated key useless
against one node without being equally useless against its replicas.

Privacy. A receipt names no owner and no database, and key names never
appear in one in any form — only counts and digests taken over a random
nonce the owner picks per request. The nonce is not decoration: without it,
two audits over the same data would produce identical digests, and an
aggregator could link them into exactly the co-occurrence map this project
exists to destroy. Within one report the shared nonce is what proves the
group saw one batch; across reports it guarantees nothing can be matched up.
"""
import hashlib
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

V = 1
BEACON_PERIOD = 600           # seconds; freshness bucket both sides derive
BEACON_SLACK = 1              # accept the neighbouring bucket for clock skew
POW_BITS = 22                 # ~1s to solve in Python, ~2us to check


def beacon(now):
    return int(now // BEACON_PERIOD)


def _kdigest(nonce, keys):
    h = hashlib.sha256(b"brkeys|" + bytes.fromhex(nonce))
    for k in sorted(keys):
        h.update(k.encode())
        h.update(b"\x00")
    return h.hexdigest()


def _vdigest(nonce, values):
    h = hashlib.sha256(b"brvals|" + bytes.fromhex(nonce))
    for k in sorted(values):
        v = values[k]
        if v is None:
            continue
        h.update(k.encode())
        h.update(b"\x00")
        h.update(v.encode() if isinstance(v, str) else v)
        h.update(b"\x00")
    return h.hexdigest()


def _msg(r):
    return ("brreceipt|{v}|{node_id}|{beacon}|{nonce}|{asked}|{kdigest}"
            "|{served}|{vdigest}").format(**r).encode()


def sign(priv, node_id, pub_raw, nonce, keys, values, now):
    """Called by a node on every /mget that carries a nonce."""
    r = {"v": V, "node_id": node_id, "beacon": beacon(now), "nonce": nonce,
         "asked": len(keys), "kdigest": _kdigest(nonce, keys),
         "served": sum(1 for v in values.values() if v is not None),
         "vdigest": _vdigest(nonce, values)}
    r["pub"] = pub_raw.hex()
    r["sig"] = priv.sign(_msg(r)).hex()
    return r


def verify(r, now):
    """Signature is real, the id derives from the key, the beacon is fresh.

    Deliberately needs nothing but the receipt: no network, no roster, no
    clock beyond the local one. An aggregator can check a receipt for a node
    it has never heard of and be as sure as it is about any other.
    """
    try:
        if r.get("v") != V:
            return False
        pub_raw = bytes.fromhex(r["pub"])
        if hashlib.sha256(pub_raw).hexdigest()[:16] != r["node_id"]:
            return False
        if abs(int(r["beacon"]) - beacon(now)) > BEACON_SLACK:
            return False
        if not 0 <= int(r["served"]) <= int(r["asked"]):
            return False
        Ed25519PublicKey.from_public_bytes(pub_raw).verify(
            bytes.fromhex(r["sig"]), _msg(r))
        return True
    except Exception:
        return False


def matches(r, nonce, keys, values):
    """Owner-side: the node signed the very answer we received.

    Stops a node signing a flattering receipt that has nothing to do with
    what it actually sent back, and stops a relay altering either.
    """
    try:
        return (r.get("nonce") == nonce
                and int(r["asked"]) == len(keys)
                and r["kdigest"] == _kdigest(nonce, keys)
                and r["vdigest"] == _vdigest(nonce, values)
                and int(r["served"]) == sum(1 for v in values.values()
                                            if v is not None))
    except Exception:
        return False


# ------------------------------------------------------------------ cost
# Receipts make a report truthful about what happened; they do not make
# submitting one cost anything. Proof of work does, and it is the only
# rate limit found that charges the sender without learning a thing about
# them — no account, no key, no address to remember, nothing to correlate
# later. It is bound to the exact report body, so a solved report cannot be
# re-spent on a different one.

def canonical(report):
    return json.dumps({k: v for k, v in report.items() if k != "pow"},
                      sort_keys=True, separators=(",", ":")).encode()


def _leading_zero_bits(digest):
    return 256 - int.from_bytes(digest, "big").bit_length()


def solve(report, bits=POW_BITS, limit=1 << 32):
    body = canonical(report)
    for n in range(limit):
        cand = str(n)
        h = hashlib.sha256(body + b"|" + cand.encode()).digest()
        if _leading_zero_bits(h) >= bits:
            return cand
    raise RuntimeError("proof of work not found")


def check(report, bits=POW_BITS):
    cand = report.get("pow")
    if not isinstance(cand, str) or len(cand) > 32:
        return False
    h = hashlib.sha256(canonical(report) + b"|" + cand.encode()).digest()
    return _leading_zero_bits(h) >= bits
