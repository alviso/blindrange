"""Consistent-hashing ring with virtual nodes and replication.

route(key) -> the R distinct nodes responsible for that key, in preference
order (primary first, then fallback replicas). Virtual nodes keep the key
distribution even; replication lets reads fail over when a node is down and
lets the data survive a lost node.
"""
import bisect
import hashlib


def _h(s):
    return int(hashlib.sha256(s.encode()).hexdigest()[:16], 16)


class Ring:
    def __init__(self, ports, vnodes=64, replicas=3):
        self.ports = list(dict.fromkeys(ports))
        self.replicas = min(replicas, len(self.ports))
        self.ring = sorted((_h(f"{p}#{v}"), p) for p in self.ports
                           for v in range(vnodes))
        self.hashes = [h for h, _ in self.ring]

    def route(self, key):
        i = bisect.bisect(self.hashes, _h(key))
        out = []
        j = 0
        while len(out) < self.replicas and j < len(self.ring):
            port = self.ring[(i + j) % len(self.ring)][1]
            if port not in out:
                out.append(port)
            j += 1
        return out

    def distribution(self, keys):
        """How many of `keys` land primarily on each node (balance check)."""
        counts = {p: 0 for p in self.ports}
        for k in keys:
            counts[self.route(k)[0]] += 1
        return counts
