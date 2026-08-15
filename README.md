# blindrange

![blindrange — range queries on encrypted data, served by machines that cannot read it](docs/header.png)

[![CI](https://github.com/alviso/blindrange/actions/workflows/ci.yml/badge.svg)](https://github.com/alviso/blindrange/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)
[![Status: research](https://img.shields.io/badge/status-research%20prototype-orange.svg)](#threat-model--measured-not-asserted)

Range queries over encrypted data stored on **blind, decentralized nodes**.

A key-holding owner, an arbitrary number of small storage nodes that hold only
opaque `key → blob` pairs, and dyadic-interval cryptography in between. Nodes
never hold a key, never see plaintext, never evaluate a comparison, and never
learn an ordering. The network has **no central infrastructure and no single
point of failure**: membership is gossip-discovered, and joining — as a node or
as a client — requires only the address of any one live peer.

`WHERE amount BETWEEN 250 AND 500`, `WHERE date BETWEEN x AND y`,
`WHERE name LIKE 'sa%'` — on data the machines answering the query physically
cannot read.

**Project stance: full-honesty leakage disclosure.** Every scheme that makes
encrypted data queryable leaks *something*. This project measures its own
leakage with real attacks against ground truth ([prototype/](prototype/)),
publishes the numbers, and gives you structural dials to bound them. You judge
whether the profile fits your risk tolerance. It is **not** appropriate for
healthcare data or high-stakes PII; it is aimed at ordinary business data on
infrastructure you don't fully trust.

## What it's for

blindrange is not a faster or more capable database. If you are content to
trust a provider, use Postgres or a managed service — exact aggregates,
joins, transactions, decades of tooling, and none of the trade-offs on this
page.

It is a database that **survives not trusting anyone**. Every other property
here follows from removing the trusted party:

- **No operator to trust, so no compliance surface.** Nodes cannot read what
  they store, so data residency, subprocessor review, insider access and
  storage-layer breach exposure stop being questions you have to answer about
  someone else's staff and hardware.
- **Durability from machines you don't own.** Replication, self-healing and
  survival of node death — provided by hardware whose operators learn nothing
  from providing it.
- **Nothing to revoke.** No account to suspend, no provider whose pricing
  change, acquisition or shutdown takes your database with it.
- **Storage from spare capacity.** Structurally cheaper than a hyperscaler's,
  with no egress fees. Cost alone rarely justifies a migration; combined with
  the above it can.

**The qualifying question:** *right now, who can technically read your data
that you would rather couldn't?* If a name comes out immediately — a
provider, a jurisdiction, a subprocessor, an admin, a stranger running a
node — that name is the reason to be here. If nothing comes out, your trust
is free, and a managed database will serve you better.

Note that "would rather not trust" is not "believe to be malicious". It
includes parties you trust perfectly well but whose trust is expensive to
maintain: the provider you audit annually, the subprocessor you disclose in
every enterprise deal, the admin whose access you review each quarter.
Compliance is the industry of proving that trust was warranted. Nodes that
cannot read anything make most of that proof unnecessary.

### The inversion

Conventional security narrows *who holds* the data. blindrange makes holding
it irrelevant, so the data can be handed to thousands of strangers on
purpose. There is no readable database anywhere — the familiar headline, *"N
million records exposed"*, has no mechanism here, because no node ever holds
a record.

The risk does not disappear, though; it moves, and concentrates. Lose your
master key and the data is gone permanently, by design, with no provider to
call. You trade a large, shared, continuously-defended attack surface for one
small secret that is entirely your problem.

## How it works

```mermaid
flowchart LR
    subgraph OWNER["Data owner — the only place keys exist"]
        direction TB
        K["master key<br/>(.brdb state file)"]
        Q["query: amount BETWEEN a AND b"]
        DY["dyadic cover<br/>range → interval labels"]
        PRF["PRF chains<br/>label → opaque keys"]
        DEC["decrypt + post-filter<br/>AES-256-GCM"]
        Q --> DY --> PRF
        K --- PRF
    end

    subgraph NET["Blind node network — untrusted, self-healing"]
        direction TB
        N1["node<br/>opaque k→v"]
        N2["node<br/>opaque k→v"]
        N3["node<br/>opaque k→v"]
        N4["…thousands"]
        N1 <-. "gossip +<br/>background repair" .-> N2
        N2 <-. " " .-> N3
        N3 <-. " " .-> N4
    end

    PRF -- "exact-match lookups<br/>on pseudorandom keys" --> NET
    NET -- "ciphertext blobs" --> DEC

    style OWNER fill:#0d2137,stroke:#5cc8ff,color:#d7dce4
    style NET fill:#1a1408,stroke:#e0b060,color:#d7dce4
```

The nodes never hold a key, never see plaintext, never evaluate a comparison,
never learn an ordering. Everything on the right side of that boundary is
opaque `key → blob` storage plus gossip — which is why nodes can be run by
anyone.

Server-side `ORDER BY` fundamentally requires the server to see order — and
order leakage is what broke Order-Preserving Encryption (see the attack
literature below). But a range *filter* does not need order: it reduces to
**equality lookups** via dyadic decomposition. Each value is indexed under its
~log₂(domain) dyadic intervals; a query `[a,b]` becomes a minimal cover of
interval labels; the network answers exact-match fetches of pseudorandom keys.

Three design decisions do the heavy lifting:

1. **The owner walks the index, not the nodes.** Each dyadic label keeps a
   client-side counter `c`; entry *i* lives at `PRF(K_label, i)` with the
   record id masked by a second PRF stream. Nodes receive only derived keys —
   never a label key — so at rest the entire network holds unlinkable
   pseudorandom pairs: **no equality, no order, no co-occurrence, and forward
   privacy** (nothing a node has ever seen lets it recognize a future insert).
   This is Sophos-style forward privacy at HMAC speed — the public-key
   trapdoor is only needed when an untrusted *server* walks the chain
   (kept for reference in [prototype/fp_demo.py](prototype/fp_demo.py)).
2. **Leaf width is a structural privacy budget.** Each field's index tree is
   depth-capped so leaves are `leaf_width` wide. The owner always fetches whole
   buckets and filters after decryption, so *no observer — even watching every
   query forever — resolves a value finer than the leaf* (measured in
   [prototype/bounded_demo.py](prototype/bounded_demo.py)). Set it per field at
   schema time; it cannot be overspent later, because finer tags don't exist.
3. **Ordering is free, and the network still never sees it.** Dyadic leaves
   are already in value order, and only the key holder knows that order, so
   `query_stream(..., order=f)` walks leaves left to right and yields sorted
   rows while the nodes still answer nothing but exact-match lookups on
   opaque keys. Streaming also keeps memory at O(page) whatever the result
   size, pages by cursor, and — for AND queries — drives off whichever
   predicate has the fewest index entries, which chain lengths already tell
   us. Honest limit: the client decrypts every row it returns and nodes
   cannot compute on ciphertext, so there is no server-side aggregation.
   This is a store for data you need unreadable, not a warehouse.
4. **Placement is a consistent-hash ring over gossip membership.** Virtual
   nodes keep any number of nodes evenly loaded; replication (default 3) plus
   read-failover, extended ring probing, and read-repair keep data reachable
   through node death, joins, and churn. Payloads are AES-256-GCM; strings
   index via a 5-bit/char prefix encoding so alphanumeric ranges and `LIKE
   'x%'` are integer ranges.

## The client — start here

```bash
pip install -e .
blindrange ui
```

A local client opens in your browser. **Drop a CSV** and it reads the file on
your machine, proposes a schema, and shows in plain language what each field
would reveal — "amounts are indistinguishable within $20.48 buckets, and
never finer, however long anyone watches" — with a dial to change it. Confirm
and the rows are encrypted and stored across the network. Then query by
range, date, and prefix, add rows, delete them, and share the database with
another device by invite.

It opens on **your databases** — the client remembers which files you have
(paths and field names only, never keys) so you don't have to. Once open,
"show everything" browses without composing a query, and "count only"
answers how many rows match while fetching none of them.

Keys live in that local process — never in the browser, never on a server.
The page is served over plain HTTP from `127.0.0.1`, which is also why it can
talk to plain-HTTP nodes at all: a hosted HTTPS app could not.

Your `.brdb` file stays passphrase-encrypted, deliberately: people back that
file up, and often to exactly the kind of provider this project exists not to
trust — a plaintext key file would mean the storage nodes can't read your
data but your cloud backup can. Install the optional `keyring` package and
you can let your OS keychain hold the passphrase per device, which is the
same trade every other credential on your machine already makes.

Prefer the terminal? `blindrange init` walks through the same schema
questions and `blindrange info FILE` prints what an existing database
reveals.

## The public network

There is a live demo network. Join it — as a node or a client — via the
always-on seed:

```bash
pip install -e .
blindrange-node --port 7501 --data ~/.blindrange/n1 \
    --seed seed.blindrange.dev:7501 --secret blindrange-public
```

No port forwarding needed: if your machine isn't reachable, it self-assembles
as a relay tenant of the seed (watch `"mode"` in `/stats`). The network
"secret" `blindrange-public` is published on purpose — on this open demo
network it only filters drive-by scanners and has **no** security role;
confidentiality comes from your keys, which never leave your machine. Demo
network, no durability promises: run your own network (below) for anything
you care about.

## Quickstart (your own network)

```bash
pip install -e .
```

Start a network — each node is one process, one directory, one port. The first
node starts a new network; everyone else seeds off any live peer:

```bash
blindrange-node --port 7501 --data ~/.blindrange/n1 --secret <network-secret>
blindrange-node --port 7502 --data ~/.blindrange/n2 --seed 127.0.0.1:7501 --secret <network-secret>
blindrange-node --port 7503 --data ~/.blindrange/n3 --seed 127.0.0.1:7502 --secret <network-secret>
# ... as many as you like, on as many machines as you like
```

The `--secret` (or `BLINDRANGE_SECRET` env var) is a **network-membership
credential**: every request is HMAC-signed with it, so outsiders can't write,
delete, or probe your network. Be clear about what it is *not*: every node and
client holds it, so it does nothing against a curious or malicious node —
confidentiality never depends on it (that's the cryptography's job), and it is
not transport encryption (run inside TLS/VPN/Tailscale for that). Omit it for
an open playground network.

Every node also has an **identity**: an Ed25519 keypair generated on first
start (kept in its data directory). Gossip heartbeats ("I am at addr X at
time T") are signed by the node itself and verified by everyone who stores or
relays them, so no insider can forge another node's liveness or hijack its
traffic by advertising a wrong address. Placement hashes node *ids*, not
addresses — a node can move (DHCP, new network) without reshuffling data.
Identities are cheap — anyone with the network secret can mint them. The
cost of that is **durability, not earnings**: payouts follow proved
possession, so a minted node only earns by actually storing what it is
sent, which makes it a large operator rather than an attacker. What cheap
identities do buy is **replica capture** — at RF3, a party holding fraction
`k` of the ring holds all three replicas of roughly `k³` of the keys, and
can delete or ransom them. The fix is diversity-aware placement (spreading
a key's replicas across subnets and operators), which is not implemented
yet.

Nodes are **self-healing**: each continuously walks its own keys in small
batches (tunable via `BR_REPAIR_EVERY` / `BR_REPAIR_BATCH`) and re-pushes
them to each key's current replica set — so data migrates to newly joined
nodes and replication recovers after churn with no owner involvement. The
e2e suite proves the full arc: data written to a two-node network migrates
to a third node that joined later, and survives both original nodes dying.

### NAT and network self-assembly

Nobody should have to open a router port to run a node. On joining, every
node asks a peer to **dial it back** at its advertised address. If that
fails (a typical home NAT), the node automatically becomes a **relay
tenant**: it keeps an outbound long-poll open to a reachable peer (its
relay) and advertises itself as `via:<relay-addr>/<node-id>`. Anyone —
client or node — reaches it by handing an envelope to the relay, which
forwards it over the tenant's own outbound connection. Tenants still dial
*out* directly for gossip and repair; only inbound traffic is relayed.
Reachability is re-checked periodically, so nodes move between direct and
tenant mode as their connectivity changes — no configuration, no port
forwarding, no manual role assignment.

The "central component" this needs is deliberately minimal: **every
reachable node is a relay**, so the bridge for unconnectable nodes is the
network itself. A dedicated always-on seed node you run works as a
predictable relay of last resort, and that's the entire privileged
infrastructure.

**Direct paths via QUIC hole punching.** Relaying costs four internet
crossings; a punched path costs one. Measured on the public network (a
client and two NAT'd nodes on separate home networks, seed in Germany): the
same range query went from **1.7s over relays to 0.7s over punched paths**. Nodes run QUIC alongside their HTTP
port and answer a tiny discovery protocol (STUN-lite ping/pong, punch
bursts). A tenant learns its public UDP endpoint from its relay and
advertises it in its signed heartbeat; a client dialing that tenant STUNs
on a scratch socket, binds its QUIC dial to the same local port, and asks
the tenant — over the reliable relay path — to punch back. Roughly 80–90%
of NAT pairs connect directly; **every failure falls back to the relay
transparently** (with a retry blacklist), so the relay tier never goes
away. `BR_NO_QUIC=1` disables it entirely. Honest trade-offs: relayed
traffic costs the relay bandwidth and a hop of latency; a relay sees the
same opaque request/response bytes any node sees; and QUIC's TLS uses
throwaway self-signed certs — transport identity was never part of the
trust model (app-layer HMAC, identity-signed heartbeats, and ciphertext
payloads carry it).

### Running nodes on multiple machines

Bind to the LAN and advertise a reachable address:

```bash
# machine A (192.168.1.10) — starts the network
blindrange-node --port 7501 --data ~/.blindrange/n1 \
    --host 0.0.0.0 --advertise 192.168.1.10:7501 --secret <network-secret>

# machine B — joins via any live peer
blindrange-node --port 7501 --data ~/.blindrange/n1 \
    --host 0.0.0.0 --advertise 192.168.1.20:7501 \
    --seed 192.168.1.10:7501 --secret <network-secret>
```

Clients bootstrap the same way: `bootstrap=["192.168.1.10:7501"]`. A node
behind NAT just points `--seed` at any reachable peer and self-assembles as
a relay tenant (see above) — no port forwarding needed. At least one node in
the network must be directly reachable to serve as seed and relay.

Own a database (the only place keys ever exist):

```python
from blindrange import Owner

schema = {
    "amount": {"type": "int", "bits": 20, "leaf_width": 256},  # privacy budget
    "day":    {"type": "int", "bits": 11, "leaf_width": 1},
    "name":   {"type": "str", "bits": 20, "leaf_width": 16, "chars": 4},
}
owner = Owner.create("my.brdb", "passphrase", schema,
                     bootstrap=["127.0.0.1:7501"])   # any one live node
owner.insert_many([{"amount": 34999, "day": 512, "name": "acme corp"}, ...])

owner.query("amount", 25000, 50000)      # BETWEEN, decrypted only here
owner.query_prefix("name", "ac")         # LIKE 'ac%'
owner.query_multi([                      # AND of predicates: record-id sets
    {"field": "amount", "lo": 25000, "hi": 50000},   # intersect BEFORE any
    {"field": "day", "lo": 100, "hi": 400}])         # ciphertext is fetched

for row in owner.query_stream(               # bounded memory, any result size
        [{"field": "amount", "lo": 0, "hi": 10 ** 6}],
        limit=100, order="amount"):          # ordered — see below
    ...                                      # row["_cursor"] resumes later

rid = owner.query("amount", 25000, 50000)[0]["_rid"]
owner.delete(rid)                        # tombstone + ciphertext removal
owner.compact()                          # epoch rewrite: merges all writers'
                                         # chains, drops tombstoned entries
                                         # (real forgetting); SAFE under
                                         # concurrent writes (open/drain/seal)
owner.count("amount", 25000, 50000)      # exact, no records fetched at all
owner.histogram("amount", 0, 10 ** 6, buckets=20)
owner.approx_sum("amount", 0, 10 ** 6)   # (estimate, error_bound, count)

owner.repair()                           # full owner-driven anti-entropy pass
                                         # (nodes also heal continuously
                                         # among themselves)
```

`my.brdb` is a passphrase-encrypted state file (master key + writer identity +
counter caches). Reopen anywhere with `Owner.open("my.brdb", "passphrase")`.

**Multiple writers, no coordination.** The index is per-(label, writer)
append-only chains — a grow-only CRDT: writers never contend, views merge by
union, offline writers just append when they reconnect. Onboard a second
writer with an invite (a secret string — it contains the master key):

```python
invite = owner.invite()                       # transmit securely, then discard
other  = Owner.accept("their.brdb", "their pass", invite)
```

There is no sync protocol to run: entry keys are deterministic, so readers
discover other writers' chain lengths by **galloping probes** against the
network itself (exponential-then-binary, batched), and writers announce
themselves once in an encrypted on-network registry appended lock-free via
insert-if-absent. Counters — even your own — are treated as a cache and a
lower bound: a client with a stale or empty cache reconstructs everything by
probing, so the state file is not a correctness-critical single point of
failure. Only the master key is unrecoverable.

## The sample application

```bash
python3 examples/webdemo/app.py        # http://127.0.0.1:8600
```

A self-contained demo: spawns 8 local blind nodes, seeds 1,000 encrypted
customer orders, and serves a three-panel UI — **owner view** (run amount/date
ranges and customer-prefix queries, watch decrypted results with per-query
stats: cover intervals, opaque index lookups, over-fetch filtered client-side),
**network view** (gossip-discovered nodes with kill/spawn buttons — kill two
mid-demo and queries keep answering), and **node view** (a live `/intel` dump of
what a node operator actually sees: opaque keys, opaque blobs, nothing else).
Use `--bootstrap host:port` to point the same app at a real network instead.

## Performance, measured

`examples/bench_logs.py` runs a log-ingest workload and reports where the
time goes. Numbers below: 100k log lines, 9 nodes and the client all on one
laptop — a deliberately unfair setup, since real nodes don't share a CPU.

| | full schema (29 keys/record) | timestamp only (11 keys/record) |
|---|---|---|
| ingest, start | ~4,000 rec/s | ~9,300 rec/s |
| ingest, marginal at 100k | ~1,600 rec/s | ~4,500 rec/s |

**The lever is index depth, not record count.** Each indexed field costs
`bits - log2(leaf_width)` keys per record, so a coarser bucket or one fewer
indexed field buys throughput directly. Write rate also declines as a
database grows (pseudorandom keys are worst-case for a B-tree), which is why
the marginal rate is the honest one to quote — and why rotating databases by
period (one per day or week) is the right pattern for logs. Independent
databases coexist invisibly on the same nodes, so rotation costs nothing.

On the **public network** (client in Canada, seed in Germany, two nodes
behind separate home NATs), ingesting the same log workload:

| | rec/s | note |
|---|---|---|
| first run | 317 | network nearly empty |
| after the fixes below | **1,009** | network already holding ~22M keys |

Three things accounted for that, all found by measuring rather than guessing:
responses were written as headers-then-body so **Nagle** added a round trip
to every request (430ms against a 187ms RTT); writes waited for *every*
replica, so each batch paid the one distant node (**hedged writes** return at
quorum); and the client's liveness window was stricter than the node's own
TTL, so under load it **dropped live nodes**, shrinking the ring until quorum
had to wait on the far seed. The two NAT'd nodes are reached at 1ms and 13ms
over punched QUIC paths — the far one is the slow one, not the hidden ones.

**Reads do not degrade with size**, because a range collapses to a handful of
intervals whatever the database holds:

| query | rows | time |
|---|---|---|
| 1-hour window | 134 | 0.02s |
| 6-hour window | 770 | 0.03s |
| 1-day window | 3,214 | 0.08s |
| `count()` over everything | 100,000 | 0.03s, zero records fetched |

## Testing

```bash
python3 -m unittest tests.test_e2e -v
```

CI runs the suite on every push (GitHub Actions, Python 3.11 and 3.13).
Thirty-nine tests. Ten cover the schema helpers and the client app (CSV inference,
value round-trips, the guarantee that any precision a user picks is a legal
leaf width, and the browser API end to end against real nodes). Twenty-four are end-to-end against real gossip networks: membership
discovery, int/prefix query correctness vs plaintext ground truth, node death,
node join with read-repair, owner reopen from the encrypted state file,
wrong-passphrase rejection, two writers reading each other's data with
interleaved same-value inserts, full recovery from an empty counter cache,
two-field AND queries, deletes visible to fresh clients via tombstones, and
compaction (correctness preserved, tombstoned entries dropped, late writers
picking up the new epoch), rejection of unauthenticated requests, the
owner-driven repair sweep, hot-label striping across nodes, a writer
inserting concurrently with a running compaction, gossip-driven
node-to-node data migration surviving the death of all original holders,
a NAT'd node self-assembling as a relay tenant — diagnosed by dialback,
replicated to and read from entirely through its relay — and QUIC hole
punching establishing a direct path to that tenant, with clean relay
fallback when QUIC is disabled.

## Threat model — measured, not asserted

The adversary is the network itself: **all nodes colluding**, honest-but-
curious, keyless. The numbers below come from running real attacks in
[prototype/attack.py](prototype/attack.py) against plaintext ground truth
(3,000 records, realistic skewed distribution). Reproduce them yourself.

**Guaranteed:** payload confidentiality (AES-256-GCM, keys never leave the
owner) and, with the counter-chain index, **zero structure at rest** — a
snapshot of every disk in the network is unlinkable pseudorandom pairs.

**What queries leak, and the dials that bound it:**

- Serving a query reveals which (bucket-level) index keys were touched and
  which ciphertexts were fetched — the **access pattern**. A patient observer
  correlating many queries can localize records *up to the leaf width, never
  finer*: with uncapped leaves a strong reconstructor reached 94% exact value
  recovery after 120 observed queries; with `leaf_width` W its error is pinned
  at ~W/4 **forever** ([prototype/bounded_demo.py](prototype/bounded_demo.py)).
- Result volumes leak counts per queried bucket; on skewed columns with public
  reference distributions this admits frequency inference (measured: ~12yr MAE
  on skewed ages — and near-random on uniform columns). Padding and coarser
  leaves both blunt it (measured in [prototype/attack.py](prototype/attack.py)).
- Records fetched together are known to co-occur in some queried range —
  accumulating equality/grouping information about *queried* data over time.

**Rules of thumb:** don't index what you never range-query; set `leaf_width` to
the coarsest granularity your queries can live with; know that unqueried data
reveals nothing at all.

## Honest limitations (v0.1)

- Deletes are tombstone-then-compact: between a delete and the next
  `compact()`, index entries for the deleted record still exist (they resolve
  to nothing — the ciphertext is removed immediately — but a node that
  correlates old fetches could notice which entries went dead). Full backward
  privacy holds only after compaction.
- `compact()` is safe under concurrent writes via the open/drain/seal epoch
  protocol (readers consult both epochs mid-compaction; the drain re-walks
  the old epoch until stable). The residual edge: a write that checked the
  epoch *before* the open marker and then takes longer to land than a full
  drain pass could in principle be missed — the stability requirement makes
  this window effectively zero, but it is not cryptographically closed
  (write-intent leases would close it; future work). One compactor at a
  time, enforced by an insert-if-absent epoch slot.
- Read-repair heals what queries touch; `owner.repair()` sweeps everything
  else, but it is owner-driven — nodes do not yet repair among themselves.
- The network secret is shared membership auth (anti-vandalism), not
  per-node identity, and transport is plaintext HTTP — run inside
  TLS/VPN/Tailscale. The *confidentiality* model never depends on either:
  nodes are untrusted by construction.
- A malicious (not just curious) node can drop or serve stale blobs — AES-GCM
  makes forgery detectable, but availability attacks are only mitigated by
  replication, not proven impossible.
- Multiple writers are supported (per-writer chains, no coordination), but one
  writer *id* should have one live instance at a time: two devices sharing a
  copied state file are safe sequentially (queries re-probe own chains), not
  concurrently. Give each device its own invite instead.
- Read fan-out grows with the number of writers that touched a label since the
  last compaction, and every query spends a few galloping probes per
  (label, writer). `compact()` collapses all streams back to one per label.
- Under simultaneous first-time writer registrations, the registry append
  retries via insert-if-absent; a pathological race combined with the loss of
  a slot's primary replica could hide a writer id until re-registration —
  writer onboarding is rare and owner-driven, but know the edge exists.
- Hot labels do NOT concentrate on single nodes: every chain entry is its own
  PRF-derived key, so a popular value's entries stripe across the whole ring
  (verified in the e2e suite). What a hot label does cost is enumeration
  (reading a long chain at query time) — proportional to result size, and
  collapsed by compaction.
- Losing the master key loses the database; losing the rest of the state file
  costs only a re-probe. Back the key up accordingly.

## The research trail (`prototype/`)

The measured prototypes this package grew from, kept runnable on purpose —
they are the evidence for every claim above: the base scheme and its 10-node
demo, the honest-but-curious node, the attack harness (equality recovery,
frequency inference, ML range reconstruction, mitigation measurements), the
RSA/Sophos forward-privacy reference, the consistent-hashing failover demo, and
the structural-privacy-budget measurement.

Prior art: dyadic/structured-encryption ranges (Faber et al.; Demertzis et al.;
Kamara–Moataz; MongoDB Queryable Encryption), attacks (Naveed–Kamara–Wright
CCS'15; Grubbs et al. S&P'17/'19; Kellaris et al. CCS'16), forward privacy
(Stefanov–Papamanthou–Shi; Bost's Σoφoς).

## License

MIT
