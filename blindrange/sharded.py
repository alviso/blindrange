"""Split one logical database across several independent master keys.

The network shards data by itself: the ring spreads keys over every node,
and adding nodes adds capacity. The CLIENT is what does not scale. One
owner walks its whole index, decrypts everything it returns, and compacts
by rewriting an entire epoch in memory — so the practical ceiling is not
the network, it is how much one machine can hold.

A shard here is a whole separate database with its own master key. That is
already a supported thing to do; independent owners have always coexisted
invisibly on one network, because keys are PRF outputs and nothing on the
wire says which database they belong to. This just makes the pattern usable
as one object: write to a `ShardedOwner` and it spreads records across N
owners; read from it and it fans out and merges.

What it buys
------------
  * Compaction and index walks are bounded by SHARD size, not by total
    size — the ceiling that actually bites first.
  * Fan-out is concurrent, so aggregates over N shards take about as long
    as one.
  * A corrupted or lost shard state file costs you that shard, not
    everything.

What it costs
-------------
  * Every range query touches every shard. Records are spread by round
    robin, so no shard can be ruled out. Sharding by value range would fix
    that and is a different design — it needs rebalancing and it makes
    skewed data pile into one shard.
  * Rids are namespaced (`s3:ab12…`), because a delete has to know which
    shard owns the handle.
  * N state files to keep, and N wallets to top up.

What it does NOT buy, and this is the part to be honest about
-------------------------------------------------------------
Separate master keys mean nodes cannot LINK your shards cryptographically:
the same value in two shards produces two unrelated index keys, which the
tests here check. But a client that queries all its shards at once, from
one address, in one burst, correlates them by behaviour. Against a network
that logs timing, shards are not compartments — they are a scaling tool
that happens to also remove the cryptographic link. Treat the unlinkability
as a bonus, never as the reason.
"""
import concurrent.futures
import hashlib
import heapq
import json
import os
from pathlib import Path

from .client import Owner

MANIFEST = "shards.json"


def _fan(calls, workers=8):
    """Run per-shard work concurrently and return results in shard order.

    Errors are raised, not swallowed: a query that silently skipped an
    unreadable shard would return a confidently wrong answer, which is
    worse than failing.
    """
    calls = list(calls)
    if len(calls) == 1:
        return [calls[0]()]
    with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(len(calls), workers)) as pool:
        return [f.result() for f in [pool.submit(c) for c in calls]]


class ShardedOwner:
    """N independent databases presented as one."""

    def __init__(self, shards, path):
        self.shards = shards
        self.path = str(path)

    # ------------------------------------------------------------ lifecycle

    @classmethod
    def create(cls, path, passphrase, schema, bootstrap, shards=4,
               network_secret=""):
        """Create `shards` independent databases under one directory.

        Each gets its own randomly generated master key — not one key with
        a shard index mixed in. Derived keys would be just as unlinkable to
        anyone without the master, but independent ones mean there is no
        single secret whose compromise links the set.
        """
        if shards < 1:
            raise ValueError("need at least one shard")
        path = Path(path)
        path.mkdir(parents=True, exist_ok=True)
        manifest = path / MANIFEST
        if manifest.exists():
            raise FileExistsError(str(manifest))
        owners = []
        for i in range(shards):
            owners.append(Owner.create(str(path / f"shard-{i:02d}.brdb"),
                                       passphrase, schema, bootstrap,
                                       network_secret=network_secret))
        # The manifest holds no secrets and no schema — just how many parts
        # there are, so open() cannot silently find fewer than were written
        # and report a partial database as a whole one.
        manifest.write_text(json.dumps({"shards": shards, "v": 1}))
        return cls(owners, path)

    @classmethod
    def open(cls, path, passphrase, bootstrap=None):
        path = Path(path)
        want = json.loads((path / MANIFEST).read_text())["shards"]
        files = sorted(path.glob("shard-*.brdb"))
        if len(files) != want:
            raise FileNotFoundError(
                f"{path} says {want} shards, found {len(files)} — refusing to "
                f"open a partial database as though it were whole")
        return cls([Owner.open(str(f), passphrase, bootstrap) for f in files],
                   path)

    # -------------------------------------------------------------- routing

    def _shard_for_insert(self, i):
        """Round robin. Any assignment works, because a range query has to
        visit every shard regardless — so the only thing worth optimising
        for is even size."""
        return i % len(self.shards)

    @staticmethod
    def _tag(n, rid):
        return f"s{n}:{rid}"

    @staticmethod
    def _untag(rid):
        n, _, bare = str(rid).partition(":")
        if not bare or not n.startswith("s"):
            raise ValueError(
                f"{rid!r} is not a sharded rid — sharded handles carry the "
                f"shard that owns them, since a delete must know where to go")
        return int(n[1:]), bare

    # ---------------------------------------------------------------- write

    def insert_many(self, records):
        records = list(records)
        buckets = [[] for _ in self.shards]
        for i, rec in enumerate(records):
            buckets[self._shard_for_insert(i)].append(rec)
        _fan([(lambda o=o, rows=rows: o.insert_many(rows))
              for o, rows in zip(self.shards, buckets) if rows])
        return len(records)

    def insert(self, record):
        return self.insert_many([record])

    def delete_many(self, rids):
        by_shard = {}
        for rid in rids:
            n, bare = self._untag(rid)
            by_shard.setdefault(n, []).append(bare)
        _fan([(lambda n=n, r=r: self.shards[n].delete_many(r))
              for n, r in by_shard.items()])
        return len(rids)

    def delete(self, rid):
        return self.delete_many([rid])

    def drain(self):
        _fan([o.drain for o in self.shards])

    # ----------------------------------------------------------------- read

    def query_stream(self, predicates, limit=None, order=None, **kw):
        """Merge every shard's stream.

        Lazy on purpose. Each shard streams in O(batch) memory and the merge
        holds one row per shard, so the whole point — that memory follows
        shard size rather than total size — survives the fan-out. With
        `order`, the per-shard streams are already sorted, so a heap merge
        gives a globally sorted stream without materialising anything.
        """
        streams = []
        for n, o in enumerate(self.shards):
            def tagged(n=n, o=o):
                for rec in o.query_stream(predicates, limit=limit,
                                          order=order, **kw):
                    rec["_rid"] = self._tag(n, rec["_rid"])
                    rec["_shard"] = n
                    yield rec
            streams.append(tagged())
        merged = (heapq.merge(*streams, key=lambda r: r[order]) if order
                  else _interleave(streams))
        for i, rec in enumerate(merged):
            if limit is not None and i >= limit:
                return
            yield rec

    def query(self, field, lo, hi):
        return list(self.query_stream([{"field": field, "lo": lo, "hi": hi}]))

    def query_prefix(self, field, prefix):
        return list(self.query_stream([{"field": field, "prefix": prefix}]))

    def query_multi(self, predicates):
        """AND-of-predicates across every shard, concatenated.

        Each shard intersects its own index sets before fetching, which is
        the point of query_multi over a stream for small results; the shards
        are independent so there is nothing to intersect between them.
        """
        out = []
        for n, rows in enumerate(_fan(
                [(lambda o=o: o.query_multi(predicates)) for o in self.shards])):
            for rec in rows:
                rec["_rid"] = self._tag(n, rec["_rid"])
                rec["_shard"] = n
                out.append(rec)
        return out

    def _get(self, addr, path):
        """Talk to a node. Shard-independent: every shard shares the same
        network view, so any of them can ask."""
        return self.shards[0]._get(addr, path)

    def count(self, field, lo, hi):
        return sum(_fan([(lambda o=o: o.count(field, lo, hi))
                         for o in self.shards]))

    def count_deleted(self):
        return sum(_fan([o.count_deleted for o in self.shards]))

    def approx_sum(self, field, lo, hi):
        """Sums add. So do the error bars: each shard's estimate is bounded
        by its own leaf width, and N of them bound the total N times as
        loosely in the worst case."""
        return sum(_fan([(lambda o=o: o.approx_sum(field, lo, hi))
                         for o in self.shards]))

    def histogram(self, field, lo, hi, buckets=None):
        """Bars add, bucket by bucket.

        Every shard shares the schema, so its leaves fall on the same
        boundaries and the bars line up by (lo, hi). Merging happens BEFORE
        the optional `buckets` reduction is applied per shard, so ask each
        shard for full granularity and reduce once at the end — otherwise
        each shard would group differently and the bars would not align.
        """
        totals = {}
        for part in _fan([(lambda o=o: o.histogram(field, lo, hi))
                          for o in self.shards]):
            for bar in part:
                key = (bar["lo"], bar["hi"])
                totals[key] = totals.get(key, 0) + bar["count"]
        bars = [{"lo": lo_, "hi": hi_, "count": n}
                for (lo_, hi_), n in sorted(totals.items())]
        if buckets and len(bars) > buckets:
            step = -(-len(bars) // buckets)
            bars = [{"lo": grp[0]["lo"], "hi": grp[-1]["hi"],
                     "count": sum(g["count"] for g in grp)}
                    for grp in (bars[i:i + step]
                                for i in range(0, len(bars), step))]
        return bars

    # ------------------------------------------------------------ housekeeping

    def compact(self):
        """One shard at a time, deliberately.

        Compaction rewrites an epoch in memory, and doing every shard at
        once would rebuild exactly the peak this design exists to avoid.
        """
        return [o.compact() for o in self.shards]

    def configure_tokens(self, issuer, account):
        for o in self.shards:
            o.configure_tokens(issuer, account)

    def top_up(self, denom=1000, count=32):
        return _fan([(lambda o=o: o.top_up(denom, count))
                     for o in self.shards])

    def flush_wallet(self):
        for o in self.shards:
            o.flush_wallet()

    def stats(self, field=None, lo=0, hi=None):
        """Per-shard record counts — the number to watch, since the ceiling
        this exists to raise is per shard, not in total.

        Counting needs a field and a range because the index answers range
        questions, not "how many rows are there"; the widest range over any
        indexed field is the closest thing to a row count that costs no
        decryption.
        """
        sch = self.schema
        field = field or next(iter(sch))
        if hi is None:
            hi = (1 << sch[field].get("bits", 32)) - 1
        counts = _fan([(lambda o=o: o.count(field, lo, hi))
                       for o in self.shards])
        return [{"shard": n, "records": c} for n, c in enumerate(counts)]

    @property
    def schema(self):
        return self.shards[0].schema

    def network(self):
        return self.shards[0].network()

    def __len__(self):
        return len(self.shards)


def _interleave(streams):
    """Round robin across live streams, so an unordered query returns rows
    from every shard as it goes rather than draining shard 0 first — which
    matters the moment a caller stops early on `limit`."""
    live = [iter(s) for s in streams]
    while live:
        nxt = []
        for s in live:
            try:
                yield next(s)
                nxt.append(s)
            except StopIteration:
                pass
        live = nxt


def shard_of(rid):
    """Which shard a sharded rid belongs to."""
    return ShardedOwner._untag(rid)[0]


def index_keys(owner: Owner, field, count=8):
    """A few of the index keys this owner would write for a field.

    Exposed because the separation between shards is a claim worth checking
    rather than asserting: index keys are HMACs under the shard's own
    master, so two shards must never produce the same key for the same
    value. If they did, a node could join the shards and the whole
    arrangement would be decorative.
    """
    k_w = owner._k_w(field)
    epoch = owner._st.get("epoch", 0)
    writer = owner._st["writer"]
    return [owner._ut(k_w, epoch, writer, i) for i in range(count)]


def digest(path):
    """A stable fingerprint of a shard set, for tests and for operators."""
    p = Path(path)
    return hashlib.sha256(
        b"".join(sorted(f.name.encode() for f in p.glob("shard-*.brdb")))
    ).hexdigest()[:16]
