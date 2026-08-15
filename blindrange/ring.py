"""Consistent-hashing ring over node ids.

Virtual nodes keep placement even at any node count; replication gives read
failover and survival of lost nodes. route(key) returns the R responsible
nodes in preference order.

DIVERSITY. Hashing alone treats three nodes in one rack, one subnet, or one
operator's basement as three independent replicas, and they are not. At RF3
a party holding fraction k of the ring holds every copy of roughly k^3 of
the keys — half the ring is about an eighth of the data with no surviving
copy. Identities are cheap here, so that is reachable by anyone willing to
run processes, and it is a durability problem rather than a billing one:
payouts already require proved possession, so a Sybil that earns is a Sybil
that stores.

route() therefore fills the replica set from distinct FAILURE GROUPS where
it can. The critical constraint is that this must not move data out of
reach: picks are drawn only from the first (R + REORDER_WINDOW) ring
successors, which readers already probe, so a client and a repairing node
that disagree about groups still overlap. Diversity reorders within the
window; it never routes somewhere nobody will look.
"""
import bisect
import hashlib


def _h(s: str) -> int:
    return int(hashlib.sha256(s.encode()).hexdigest()[:16], 16)


REORDER_WINDOW = 3          # must stay <= the readers' PROBE_EXTRA


def failure_group(addr: str, udp: str = "") -> str:
    """What counts as "the same place" for durability.

    An IPv4 /24 is a coarse proxy for one operator, rack or home network.
    It is wrong at the edges in both directions — a big cloud region spans
    many /24s, and two strangers can share one behind CGNAT — but it is
    derived from data every participant already gossips, which matters more
    than precision: client and repairing node MUST compute this identically
    or they will place the same key differently and fight.

    Relay tenants advertise "via:<relay>/<id>", which describes the relay's
    network and not the tenant's. Their own public UDP candidate is the
    honest signal, so it wins when present; falling back to the relay would
    group every tenant of one relay together and quietly refuse to place
    data across them.
    """
    host = ""
    if udp:
        # candidates are "lan:port,public:port" — the last is the observed
        # public endpoint
        cand = [c.strip() for c in str(udp).split(",") if c.strip()]
        if cand:
            host = cand[-1].rsplit(":", 1)[0]
    if not host:
        a = str(addr)
        if a.startswith("via:"):
            a = a[4:].rpartition("/")[0]
        host = a.rsplit(":", 1)[0]
    host = host.strip("[]")
    parts = host.split(".")
    if len(parts) == 4 and all(x.isdigit() for x in parts):
        return ".".join(parts[:3]) + ".0/24"
    if ":" in host:                       # IPv6: /48 is the routed prefix
        return ":".join(host.split(":")[:3]) + "::/48"
    return host or "unknown"


class Ring:
    def __init__(self, addrs, vnodes: int = 64, replicas: int = 3,
                 groups=None):
        self.addrs = sorted(set(addrs))
        if not self.addrs:
            raise ValueError("empty ring")
        self.replicas = min(replicas, len(self.addrs))
        # node id -> failure group. Absent means "unknown", and unknown is
        # never treated as shared: guessing that two unlabelled nodes are
        # independent risks less than refusing to place data.
        self.groups = dict(groups or {})
        self.ring = sorted((_h(f"{a}#{v}"), a) for a in self.addrs
                           for v in range(vnodes))
        self.hashes = [h for h, _ in self.ring]

    def route(self, key: str, count: int = None):
        """The `count` (default R) distinct successor nodes for `key`, in
        preference order. Ask for more than R to probe beyond the replica set —
        e.g. for keys written under an earlier ring (reads fall back, then
        read-repair re-homes them)."""
        want = min(count or self.replicas, len(self.addrs))
        # Gather past `want` so there is something to reorder. Collecting
        # only `want` and then "diversifying" is a no-op — the list is
        # already exactly the answer — which is precisely the mistake the
        # first version of this made, and it looked correct.
        gather = min(want + (REORDER_WINDOW if self.groups else 0),
                     len(self.addrs))
        i = bisect.bisect(self.hashes, _h(key))
        out, j = [], 0
        while len(out) < gather and j < len(self.ring):
            addr = self.ring[(i + j) % len(self.ring)][1]
            if addr not in out:
                out.append(addr)
            j += 1
        if not self.groups or want <= 1:
            return out[:want]
        return self._diversify(out, want)

    def group_of(self, node):
        return self.groups.get(node)

    def _diversify(self, order, want):
        """Prefer one node per failure group, within the probe window.

        Two properties matter more than the diversity itself. The result is
        a PERMUTATION of nodes the plain ring already chose from — nothing
        is placed outside the window readers probe. And when there are not
        enough distinct groups to fill R, the set is completed anyway with
        whatever is left: refusing to place data because the network is
        homogeneous would turn a durability improvement into an outage, and
        a small network IS homogeneous.
        """
        window = order[:want + REORDER_WINDOW]
        picked, seen_groups = [], set()
        for node in window:
            if len(picked) >= want:
                break
            g = self.groups.get(node)
            if g is not None and g in seen_groups:
                continue
            picked.append(node)
            if g is not None:
                seen_groups.add(g)
        for node in order:                 # complete from ring order
            if len(picked) >= want:
                break
            if node not in picked:
                picked.append(node)
        return picked[:want]

    def diversity(self, key):
        """How many distinct failure groups the replica set spans, and how
        many replicas it has — the number a durability claim rests on."""
        holders = self.route(key)
        gs = {self.groups.get(n, f"?{n}") for n in holders}
        return len(gs), len(holders)

    def __eq__(self, other):
        return isinstance(other, Ring) and self.addrs == other.addrs

    def __hash__(self):
        return hash(tuple(self.addrs))
