# blindrange

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

## How it works

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
3. **Placement is a consistent-hash ring over gossip membership.** Virtual
   nodes keep any number of nodes evenly loaded; replication (default 3) plus
   read-failover, extended ring probing, and read-repair keep data reachable
   through node death, joins, and churn. Payloads are AES-256-GCM; strings
   index via a 5-bit/char prefix encoding so alphanumeric ranges and `LIKE
   'x%'` are integer ranges.

## Quickstart

```bash
pip install -e .
```

Start a network — each node is one process, one directory, one port. The first
node starts a new network; everyone else seeds off any live peer:

```bash
blindrange-node --port 7501 --data ~/.blindrange/n1
blindrange-node --port 7502 --data ~/.blindrange/n2 --seed 127.0.0.1:7501
blindrange-node --port 7503 --data ~/.blindrange/n3 --seed 127.0.0.1:7502
# ... as many as you like, on as many machines as you like
```

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
```

`my.brdb` is a passphrase-encrypted state file (master key + per-label
counters). It **is** the database from the owner's perspective — losing it
loses access. Reopen anywhere with `Owner.open("my.brdb", "passphrase")`.

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

## Testing

```bash
python3 -m unittest tests.test_e2e -v
```

Seven end-to-end tests against a real 6-node gossip network: membership
discovery, int/prefix query correctness vs plaintext ground truth, node death,
node join with read-repair, owner reopen from the encrypted state file, and
wrong-passphrase rejection.

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

- No deletes yet (tombstones + backward privacy are the next research step).
- Read-repair re-homes data lazily on access; there is no background
  anti-entropy sweep yet, so cold data on a churned ring is only healed when
  read (an explicit repair scan is a planned `blindrange-node` subcommand).
- No client↔node authentication or transport encryption yet — run it inside a
  trusted transport (localhost, VPN, or a mesh like Tailscale) for now. Note
  the *confidentiality* model never depends on transport: nodes are untrusted
  by construction.
- A malicious (not just curious) node can drop or serve stale blobs — AES-GCM
  makes forgery detectable, but availability attacks are only mitigated by
  replication, not proven impossible.
- One owner writes at a time (per-label counters are client state; concurrent
  writers need coordination or per-writer label spaces — planned).
- Hot labels concentrate entries; splitting oversized buckets across nodes is
  planned.
- The owner state file is a single point of failure for *access* (not for the
  network) — back it up like a key, because it is one.

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
