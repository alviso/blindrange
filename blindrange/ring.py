"""Consistent-hashing ring over node addresses ("host:port" strings).

Virtual nodes keep placement even at any node count; replication gives read
failover and survival of lost nodes. route(key) returns the R responsible
nodes in preference order.
"""
import bisect
import hashlib


def _h(s: str) -> int:
    return int(hashlib.sha256(s.encode()).hexdigest()[:16], 16)


class Ring:
    def __init__(self, addrs, vnodes: int = 64, replicas: int = 3):
        self.addrs = sorted(set(addrs))
        if not self.addrs:
            raise ValueError("empty ring")
        self.replicas = min(replicas, len(self.addrs))
        self.ring = sorted((_h(f"{a}#{v}"), a) for a in self.addrs
                           for v in range(vnodes))
        self.hashes = [h for h, _ in self.ring]

    def route(self, key: str, count: int = None):
        """The `count` (default R) distinct successor nodes for `key`, in
        preference order. Ask for more than R to probe beyond the replica set —
        e.g. for keys written under an earlier ring (reads fall back, then
        read-repair re-homes them)."""
        want = min(count or self.replicas, len(self.addrs))
        i = bisect.bisect(self.hashes, _h(key))
        out = []
        j = 0
        while len(out) < want and j < len(self.ring):
            addr = self.ring[(i + j) % len(self.ring)][1]
            if addr not in out:
                out.append(addr)
            j += 1
        return out

    def __eq__(self, other):
        return isinstance(other, Ring) and self.addrs == other.addrs

    def __hash__(self):
        return hash(tuple(self.addrs))
