"""The data owner. The only place keys, plaintext, or order ever exist.

Index construction — forward-private PRF counter chains, multi-writer:
Because the OWNER walks the index (nodes never receive a label key), each
dyadic label w is a set of per-(epoch, writer) append-only chains: writer u's
i-th entry under w in epoch E lives at key UT = PRF(K_w, E, u, i) with the
record id masked by a second PRF stream. Writers never contend (each appends
only to its own chains), so the index is a grow-only CRDT: any two clients'
views merge by union, and no coordination exists anywhere. At rest the network
holds only unlinkable pseudorandom key->blob pairs — no equality, no order, no
co-occurrence — and a node can never derive a future key from anything it has
seen (Sophos-style forward privacy at HMAC speed; the public-key trapdoor is
only needed when an untrusted server walks the chain — prototype/fp_demo.py).

Sync — the network is the source of truth, counters are a cache:
Entry keys are deterministic, so a reader discovers any chain's length by
galloping probes (exponential then binary, batched across chains). Writers
announce themselves once in an encrypted on-network registry chain, appended
lock-free via insert-if-absent. A client's cached counters (even its own) are
a lower bound; losing the cache costs a re-probe, not the database. Only the
master key is unrecoverable.

Deletes — tombstone chains plus real removal:
delete_many() appends record ids to the writer's tombstone chain (readers
subtract them before fetching) and best-effort deletes the ciphertext blobs
from the nodes. Compaction later drops tombstoned entries from the index
entirely — actual forgetting, not just hiding.

Compaction — an LSM-style epoch rewrite:
compact() walks the label tree top-down (empty intervals prune their
subtrees), merges every writer's chains into single per-label streams under
epoch E+1, drops tombstoned entries, deletes epoch-E keys, then announces the
new epoch on an on-network chain. Run it while writers are quiescent — it is
an owner-driven maintenance operation, not a concurrent background process.
Readers and writers pick up the new epoch with one probe per operation.

Onboarding: owner_a.invite() -> secret string -> Owner.accept(path, pass,
invite) creates a new writer with its own state file. Treat an invite like
the key material it contains.

Schema: {field: {"type": "int"|"str", "bits": B, "leaf_width": W, "chars": C}}
`leaf_width` (power of 2) is the field's structural privacy budget — no
observer, ever, resolves finer than W (see prototype/bounded_demo.py).

Queries: query(field, lo, hi), query_prefix(field, p), and
query_multi([...]) — an AND of range/prefix predicates, intersected on
record ids before any ciphertext is fetched. Results carry "_rid", the handle
delete_many() takes.
"""
import hashlib
import hmac
import json
import os
from .transport import POOL
from base64 import b64decode, b64encode
from concurrent.futures import ThreadPoolExecutor

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .dyadic import (dyadic_cover, encode_str, levels_for, max_level,
                     prefix_range)
from .ring import Ring

PEER_LIVE_S = 12.0
TOMB = "@tomb"                     # reserved label for tombstone chains


class Owner:
    # ------------------------------------------------------------ lifecycle
    def __init__(self, state_path, passphrase, state):
        self._path = state_path
        self._pass = passphrase
        self._st = state
        self._master = bytes.fromhex(state["master"])
        self._data_key = hmac.new(self._master, b"data", hashlib.sha256).digest()
        self._aes = AESGCM(self._data_key)
        self.pool = ThreadPoolExecutor(max_workers=32)
        self.ring = None
        self.last_stats = {}
        self.refresh_membership()

    @classmethod
    def _new_state(cls, master_hex, schema, bootstrap):
        for f, spec in schema.items():
            if f.startswith("@"):
                raise ValueError("field names starting with '@' are reserved")
            max_level(spec["bits"], spec.get("leaf_width", 1))   # validate early
        return {"v": 4, "master": master_hex, "writer": os.urandom(8).hex(),
                "schema": schema, "epoch": 0, "epoch_len": 0, "sealed_max": -1,
                "chains": {}, "remote": {}, "writers": [], "reg_len": 0,
                "tombs": {"counts": {}, "rids": []},
                "secret": "", "bootstrap": list(bootstrap)}

    @classmethod
    def create(cls, state_path, passphrase, schema, bootstrap,
               network_secret=""):
        if os.path.exists(state_path):
            raise FileExistsError(state_path)
        state = cls._new_state(os.urandom(32).hex(), schema, bootstrap)
        state["secret"] = network_secret
        owner = cls(state_path, passphrase, state)
        owner._register_writer()
        owner._save()
        return owner

    def invite(self):
        """A secret onboarding string for a new writer. It CONTAINS the master
        key — transmit it like key material, then discard it."""
        return b64encode(json.dumps(
            {"master": self._st["master"], "schema": self._st["schema"],
             "secret": self._st.get("secret", ""),
             "bootstrap": self._st["bootstrap"]}).encode()).decode()

    @classmethod
    def accept(cls, state_path, passphrase, invite, bootstrap=None):
        """Join an existing database as a new writer, from an invite()."""
        if os.path.exists(state_path):
            raise FileExistsError(state_path)
        d = json.loads(b64decode(invite))
        state = cls._new_state(d["master"], d["schema"],
                               bootstrap or d["bootstrap"])
        state["secret"] = d.get("secret", "")
        owner = cls(state_path, passphrase, state)
        owner._register_writer()
        owner._save()
        return owner

    @classmethod
    def open(cls, state_path, passphrase, bootstrap=None):
        with open(state_path) as f:
            blob = json.load(f)
        key = hashlib.scrypt(passphrase.encode(), salt=bytes.fromhex(blob["salt"]),
                             n=2 ** 14, r=8, p=1, dklen=32)
        raw = AESGCM(key).decrypt(bytes.fromhex(blob["nonce"]),
                                  bytes.fromhex(blob["ct"]), None)
        state = json.loads(raw)
        if state.get("v") != 4:
            raise ValueError("state file uses an older format; "
                             "re-create the database")
        if bootstrap:
            state["bootstrap"] = sorted(set(state["bootstrap"]) | set(bootstrap))
        return cls(state_path, passphrase, state)

    def _save(self):
        salt, nonce = os.urandom(16), os.urandom(12)
        key = hashlib.scrypt(self._pass.encode(), salt=salt, n=2 ** 14, r=8,
                             p=1, dklen=32)
        ct = AESGCM(key).encrypt(nonce, json.dumps(self._st).encode(), None)
        tmp = self._path + ".tmp"
        with open(tmp, "w") as f:
            json.dump({"salt": salt.hex(), "nonce": nonce.hex(),
                       "ct": ct.hex()}, f)
        os.replace(tmp, self._path)

    # ---------------------------------------------------------- membership
    def refresh_membership(self):
        """Discover live nodes by asking any known node for its peer table.
        The ring hashes NODE IDS (stable identities), not addresses — a node
        can move address without reshuffling data placement."""
        contacts = list(self._st["bootstrap"])
        if self.ring:
            contacts = [self._addr_of[n] for n in self.ring.addrs
                        if n in getattr(self, "_addr_of", {})] + contacts
        found = {}
        answers = 0
        for addr in contacts:
            try:
                peers = self._get(addr, "/peers")["peers"]
                for nid, e in peers.items():
                    if e["age"] <= PEER_LIVE_S:
                        found[nid] = e["addr"]
                answers += 1
                if answers >= 2:        # merge two views; one may be stale
                    break
            except OSError:
                continue
        if not found:
            raise ConnectionError("no live blindrange node reachable "
                                  f"(tried {contacts})")
        self._addr_of = found
        new_ring = Ring(sorted(found), replicas=3)
        if new_ring != self.ring:
            self.ring = new_ring
        return sorted(found)

    def _addr(self, node_id):
        return self._addr_of.get(node_id)

    # ------------------------------------------------------------ crypto
    def _k_w(self, w):
        return hmac.new(self._master, b"label|" + w.encode(),
                        hashlib.sha256).digest()

    def _ut(self, k_w, epoch, writer, i):
        return "I:" + hmac.new(k_w, f"UT|{epoch}|{writer}|{i}".encode(),
                               hashlib.sha256).hexdigest()[:32]

    def _mask(self, k_w, epoch, writer, i):
        return hmac.new(k_w, f"MASK|{epoch}|{writer}|{i}".encode(),
                        hashlib.sha256).digest()[:8]

    def _sys_key(self, kind, i):
        k = hmac.new(self._master, b"sys|" + kind, hashlib.sha256).digest()
        return "I:" + hmac.new(k, f"S|{i}".encode(),
                               hashlib.sha256).hexdigest()[:32]

    def _sys_enc(self):
        return AESGCM(hmac.new(self._master, b"sys-enc",
                               hashlib.sha256).digest())

    def _sys_encode(self, text):
        nonce = os.urandom(12)
        return b64encode(nonce + self._sys_enc().encrypt(
            nonce, text.encode(), None)).decode()

    def _sys_decode(self, blob):
        raw = b64decode(blob)
        return self._sys_enc().decrypt(raw[:12], raw[12:], None).decode()

    def _encode(self, field, value):
        spec = self._st["schema"][field]
        return encode_str(str(value), spec["chars"]) if spec["type"] == "str" \
            else int(value)

    # ---------------------------------------------------------- transport
    def _sign(self, payload: bytes) -> dict:
        secret = self._st.get("secret", "")
        if not secret:
            return {}
        return {"X-BR-Auth": hmac.new(secret.encode(), payload,
                                      hashlib.sha256).hexdigest()}

    def _post(self, addr, path, payload):
        body = json.dumps(payload).encode()
        if addr.startswith("via:"):                    # relay-tenant node
            return self._relay(addr, "POST", path, body)
        status, data = POOL.request(
            addr, "POST", path, body,
            {"Content-Type": "application/json", **self._sign(body)},
            timeout=10)
        if status >= 400:
            raise ConnectionError(f"HTTP {status} from {addr}{path}")
        return json.loads(data)

    def _get(self, addr, path):
        if addr.startswith("via:"):
            return self._relay(addr, "GET", path, b"")
        base = path.split("?")[0]
        status, data = POOL.request(addr, "GET", path, None,
                                    self._sign(base.encode()), timeout=5)
        if status >= 400:
            raise ConnectionError(f"HTTP {status} from {addr}{path}")
        return json.loads(data)

    def _relay(self, via_addr, method, path, body):
        """Reach a NAT'd node through its relay: "via:relay-addr/node-id"."""
        relay, _, nid = via_addr[4:].rpartition("/")
        env = {"to": nid, "id": os.urandom(8).hex(), "method": method,
               "path": path, "body_b64": b64encode(body).decode()}
        raw = json.dumps(env).encode()
        status, data = POOL.request(
            relay, "POST", "/relay/send", raw,
            {"Content-Type": "application/json", **self._sign(raw)},
            timeout=30)
        if status >= 400:
            raise ConnectionError(f"HTTP {status} from relay {relay}")
        out = json.loads(data)
        if out.get("status") != 200:
            raise ConnectionError(f"relayed request failed: {out}")
        return json.loads(b64decode(out["body_b64"]))

    def _put(self, kv_pairs):
        """Replicated write with a durability floor: every key must be ACKed
        by at least MIN_ACKS live nodes (or every reachable one, if fewer).
        Keys that fall short — replicas dead, membership stale — are retried
        on further ring successors, so a write never silently ends up as a
        single copy on a node nobody else has discovered yet."""
        MIN_ACKS = 2
        by_node = {}
        for k, v in kv_pairs:
            for nid in self.ring.route(k):
                addr = self._addr(nid)
                if addr:
                    by_node.setdefault(addr, []).append([k, v])
        jobs = {a: self.pool.submit(self._post, a, "/kv", {"entries": e})
                for a, e in by_node.items()}
        acks = {k: 0 for k, _ in kv_pairs}
        for a, j in jobs.items():
            if _ok(j):
                for k, _v in by_node[a]:
                    acks[k] += 1
        vals = dict(kv_pairs)
        need = min(MIN_ACKS, max(1, len(self._addr_of)))
        weak = [k for k, n in acks.items() if n < need]
        if weak:
            for k in weak:
                for nid in self.ring.route(k, self.ring.replicas + 3):
                    if acks[k] >= need:
                        break
                    addr = self._addr(nid)
                    if not addr or any(k == k2 for k2, _ in
                                       by_node.get(addr, [])):
                        continue
                    try:
                        self._post(addr, "/kv", {"entries": [[k, vals[k]]]})
                        acks[k] += 1
                    except OSError:
                        continue
        if any(n == 0 for n in acks.values()):
            raise ConnectionError("write not durable: some keys got zero ACKs")

    def _put_nx(self, key, value):
        """Insert-if-absent on all replicas. False if any replica already had
        the key (a concurrent writer won the slot)."""
        won = True
        for nid in self.ring.route(key):
            addr = self._addr(nid)
            if not addr:
                continue
            try:
                r = self._post(addr, "/kv", {"entries": [[key, value]],
                                             "nx": True})
                if r.get("existed"):
                    won = False
            except OSError:
                continue
        return won

    def _delete(self, keys):
        """Best-effort removal from every node that might hold the keys."""
        PROBE_EXTRA = 3
        by_node = {}
        for k in keys:
            for nid in self.ring.route(k, self.ring.replicas + PROBE_EXTRA):
                addr = self._addr(nid)
                if addr:
                    by_node.setdefault(addr, []).append(k)
        jobs = [self.pool.submit(self._post, a, "/delete", {"keys": ks})
                for a, ks in by_node.items()]
        for j in jobs:
            _ok(j)

    def _mget(self, keys):
        """Replica lookup in two PARALLEL phases: the whole replica set at
        once, then (only for keys still missing) the extended probe levels —
        covering keys written under an earlier ring. Latency is 1 round trip
        for hits and 2 for misses, regardless of replica count; the cost is
        querying all replicas instead of stopping at the first hit, which is
        the right trade when hops traverse relays. Read-repair: any found key
        whose current primary did not answer is rewritten to that primary, so
        data migrates as the ring changes."""
        PROBE_EXTRA = 3
        R = self.ring.replicas
        route = {k: [self._addr(n) for n in
                     self.ring.route(k, R + PROBE_EXTRA) if self._addr(n)]
                 for k in keys}
        out, holders = {}, {}

        def fan(lo, hi, pending):
            by_node = {}
            for k in pending:
                for a in route[k][lo:hi]:
                    by_node.setdefault(a, []).append(k)
            jobs = {a: self.pool.submit(self._post, a, "/mget", {"keys": ks})
                    for a, ks in by_node.items()}
            for a, j in jobs.items():
                vals = _ok(j)
                if vals:
                    for k, v in vals["values"].items():
                        out[k] = v
                        holders.setdefault(k, set()).add(a)

        fan(0, R, list(keys))
        missing = [k for k in keys if k not in out]
        if missing:
            fan(R, R + PROBE_EXTRA, missing)
        by_primary = {}
        for k, v in out.items():
            primary = route[k][0] if route[k] else None
            if primary and primary not in holders.get(k, ()):
                by_primary.setdefault(primary, []).append([k, v])
        for a, e in by_primary.items():
            self.pool.submit(self._post, a, "/kv", {"entries": e})
        return out

    # -------------------------------------------- chain-length discovery
    def _discover_ends(self, chains_spec):
        """Batched galloping search for the true end of append-only chains.
        chains_spec: {id: (key_fn, cached_length)} -> {id: true_length}.
        Chains are dense (entry i exists iff i <= end), so exponential probing
        then binary search finds each end in O(log gap) batched rounds."""
        state = {cid: {"lo": known, "hi": None, "step": 1, "fn": fn}
                 for cid, (fn, known) in chains_spec.items()}
        ends = {}
        rounds = 0
        while state:
            rounds += 1
            batch = {cid: (st["lo"] + st["step"] if st["hi"] is None
                           else (st["lo"] + st["hi"]) // 2)
                     for cid, st in state.items()}
            keys = {cid: state[cid]["fn"](p) for cid, p in batch.items()}
            got = self._mget(list(set(keys.values())))
            done = []
            for cid, p in batch.items():
                st = state[cid]
                hit = keys[cid] in got
                if st["hi"] is None:
                    if hit:
                        st["lo"], st["step"] = p, st["step"] * 2
                        continue
                    st["hi"] = p
                elif hit:
                    st["lo"] = p
                else:
                    st["hi"] = p
                if st["hi"] == st["lo"] + 1:
                    ends[cid] = st["lo"]
                    done.append(cid)
            for cid in done:
                del state[cid]
        self._probe_rounds = rounds
        return ends

    # ---------------------------------------------------- system chains
    def _refresh_epoch(self):
        """One probe (typically) against the on-network epoch chain, whose
        entries are markers: "open:N" (epoch N exists — write there) and
        "sealed:N" (epoch N is fully merged into N+1 — stop reading it).
        Between a compactor's open and sealed markers, readers read BOTH
        epochs, which is what makes compaction safe under concurrent writes."""
        st = self._st
        end = self._discover_ends(
            {"e": (lambda i: self._sys_key(b"epoch", i),
                   st["epoch_len"])})["e"]
        if end > st["epoch_len"]:
            keys = {i: self._sys_key(b"epoch", i)
                    for i in range(st["epoch_len"] + 1, end + 1)}
            got = self._mget(list(keys.values()))
            for i in sorted(keys):
                if keys[i] not in got:
                    continue
                txt = self._sys_decode(got[keys[i]])
                if txt.startswith("open:"):
                    n = int(txt.split(":")[1])
                    if n > st["epoch"]:
                        st["epoch"] = n
                        st["chains"] = {}          # own chains were older-epoch
                elif txt.startswith("sealed:"):
                    st["sealed_max"] = max(st["sealed_max"],
                                           int(txt.split(":")[1]))
            st["epoch_len"] = end
            # prune caches for epochs no longer readable
            live = set(self._epochs())
            st["remote"] = {k: v for k, v in st["remote"].items()
                            if int(k.split("|")[0]) in live}
            st["tombs"]["counts"] = {
                k: v for k, v in st["tombs"]["counts"].items()
                if int(k.split("|")[0]) in live}
            self._save()
        return st["epoch"]

    def _epochs(self):
        """The epochs a correct reader must consult right now."""
        st = self._st
        if st["epoch"] > 0 and st["epoch"] - 1 > st["sealed_max"]:
            return [st["epoch"] - 1, st["epoch"]]
        return [st["epoch"]]

    def _refresh_writers(self):
        """Learn any new writers from the on-network registry chain."""
        end = self._discover_ends(
            {"r": (lambda i: self._sys_key(b"registry", i),
                   self._st["reg_len"])})["r"]
        if end > self._st["reg_len"]:
            keys = {i: self._sys_key(b"registry", i)
                    for i in range(self._st["reg_len"] + 1, end + 1)}
            got = self._mget(list(keys.values()))
            for i, k in keys.items():
                if k in got:
                    wid = self._sys_decode(got[k])
                    if wid not in self._st["writers"]:
                        self._st["writers"].append(wid)
            self._st["reg_len"] = end
            self._save()
        return self._st["writers"]

    def _register_writer(self):
        wid = self._st["writer"]
        self._refresh_writers()
        if wid in self._st["writers"]:
            return
        val = self._sys_encode(wid)
        while True:
            slot = self._st["reg_len"] + 1
            if self._put_nx(self._sys_key(b"registry", slot), val):
                self._st["writers"].append(wid)
                self._st["reg_len"] = slot
                break
            # lost a concurrent-join race: absorb the winner, take next slot
            got = self._mget([self._sys_key(b"registry", slot)])
            other = self._sys_decode(got[self._sys_key(b"registry", slot)])
            if other not in self._st["writers"]:
                self._st["writers"].append(other)
            self._st["reg_len"] = slot
        self._save()

    def _tomb_spec(self, writers):
        """Gallop spec for tombstone chains, batchable with other chains."""
        k_t = self._k_w(TOMB)
        spec = {}
        for ep in self._epochs():
            for u in writers:
                spec[("tomb", ep, u)] = (
                    (lambda i, e=ep, u=u: self._ut(k_t, e, u, i)),
                    self._st["tombs"]["counts"].get(f"{ep}|{u}", 0))
        return spec

    def _apply_tomb_ends(self, ends):
        """Fetch any new tombstone entries given discovered chain ends;
        returns the full deleted-rid set. ends keys: ("tomb", ep, u)."""
        k_t = self._k_w(TOMB)
        tombs = self._st["tombs"]
        new_keys = {}
        for (_t, ep, u), end in ends.items():
            for i in range(tombs["counts"].get(f"{ep}|{u}", 0) + 1, end + 1):
                new_keys[self._ut(k_t, ep, u, i)] = (ep, u, i)
        if new_keys:
            got = self._mget(list(new_keys))
            for ut, blob in got.items():
                ep, u, i = new_keys[ut]
                rid = bytes(x ^ y for x, y in
                            zip(b64decode(blob), self._mask(k_t, ep, u, i)))
                if rid.hex() not in tombs["rids"]:
                    tombs["rids"].append(rid.hex())
            for (_t, ep, u), end in ends.items():
                tombs["counts"][f"{ep}|{u}"] = end
            self._save()
        return set(tombs["rids"])

    def _refresh_tombs(self, writers):
        """The set of deleted record ids across all readable epochs (cached;
        only new tombstone entries are fetched)."""
        spec = self._tomb_spec(writers)
        ends = self._discover_ends(spec) if spec else {}
        return self._apply_tomb_ends(ends)

    # ------------------------------------------------------------- insert
    def insert_many(self, records):
        E = self._refresh_epoch()
        puts = []
        chains = self._st["chains"]        # own chains only; others never touched
        me = self._st["writer"]
        for rec in records:
            rid = os.urandom(8)
            nonce = os.urandom(12)
            ct = b64encode(nonce + self._aes.encrypt(
                nonce, json.dumps(rec).encode(), None)).decode()
            puts.append(("R:" + rid.hex(), ct))
            for field, spec in self._st["schema"].items():
                if field not in rec:
                    continue
                v = self._encode(field, rec[field])
                mlvl = max_level(spec["bits"], spec.get("leaf_width", 1))
                for lvl, idx in levels_for(v, spec["bits"], mlvl):
                    w = f"{field}|{lvl}|{idx}"
                    i = chains.get(w, 0) + 1
                    chains[w] = i
                    k_w = self._k_w(w)
                    masked = bytes(x ^ y for x, y in
                                   zip(rid, self._mask(k_w, E, me, i)))
                    puts.append((self._ut(k_w, E, me, i),
                                 b64encode(masked).decode()))
        self._put(puts)
        self._save()
        return len(records)

    def insert(self, record):
        return self.insert_many([record])

    # ------------------------------------------------------------- delete
    def delete_many(self, rids):
        """Tombstone record ids (the "_rid" of query results) and best-effort
        remove their ciphertexts. Index entries vanish at the next compact()."""
        E = self._refresh_epoch()
        me = self._st["writer"]
        k_t = self._k_w(TOMB)
        tombs = self._st["tombs"]
        base = tombs["counts"].get(f"{E}|{me}", 0)
        puts = []
        for n, rid_hex in enumerate(rids, start=base + 1):
            rid = bytes.fromhex(rid_hex)
            masked = bytes(x ^ y for x, y in zip(rid, self._mask(k_t, E, me, n)))
            puts.append((self._ut(k_t, E, me, n), b64encode(masked).decode()))
        self._put(puts)
        tombs["counts"][f"{E}|{me}"] = base + len(rids)
        for r in rids:
            if r not in tombs["rids"]:
                tombs["rids"].append(r)
        self._save()
        self._delete(["R:" + r for r in rids])
        return len(rids)

    def delete(self, rid):
        return self.delete_many([rid])

    # -------------------------------------------------------------- query
    def query(self, field, lo, hi):
        return self.query_multi([{"field": field, "lo": lo, "hi": hi}])

    def query_prefix(self, field, prefix):
        return self.query_multi([{"field": field, "prefix": prefix}])

    def query_multi(self, predicates, _retried=False):
        """AND of range/prefix predicates. Index phases run per predicate and
        intersect on record ids BEFORE any ciphertext is fetched.

        Latency-shaped for relay topologies with SPECULATIVE ENUMERATION: the
        client fetches every index entry its cached counters say exists AND
        one growth-probe per chain (epoch chain, writer registry, tombstones,
        every (label, epoch, writer) chain) in a single lookup round. If
        nothing grew — the common case — the entries are already in hand and
        one more round fetches ciphertexts: a stable warm query is TWO
        network rounds. Chains that did grow gallop from their probe hit and
        fetch the delta; a new epoch or writer refreshes state and re-runs
        the query once."""
        st = self._st
        me = st["writer"]
        top = st["epoch"]
        writers = list(st["writers"]) or [me]
        remote = st["remote"]
        k_t = self._k_w(TOMB)

        bounds = []
        for p in predicates:
            fs = st["schema"][p["field"]]
            if "prefix" in p:
                a, b = prefix_range(p["prefix"], fs["chars"])
            else:
                a, b = (self._encode(p["field"], p["lo"]),
                        self._encode(p["field"], p["hi"]))
            bounds.append((p["field"], a, b))

        # ---- chain descriptors: everything this query touches -------------
        chains = {("sys", "epoch"): {"fn": lambda i: self._sys_key(b"epoch", i),
                                     "cached": st["epoch_len"]},
                  ("sys", "reg"): {"fn": lambda i: self._sys_key(b"registry", i),
                                   "cached": st["reg_len"]}}
        for ep in self._epochs():
            for u in writers:
                chains[("tomb", ep, u)] = {
                    "fn": (lambda i, e=ep, u=u: self._ut(k_t, e, u, i)),
                    "cached": st["tombs"]["counts"].get(f"{ep}|{u}", 0)}
        covers = {}                  # field -> (cover, labels, k_ws)
        for field, a, b in bounds:
            fs = st["schema"][field]
            mlvl = max_level(fs["bits"], fs.get("leaf_width", 1))
            cover = dyadic_cover(a, b, fs["bits"], mlvl)
            labels = [f"{field}|{lvl}|{idx}" for lvl, idx in cover]
            k_ws = {w: self._k_w(w) for w in labels}
            covers[field] = (cover, labels, k_ws)
            for ep in self._epochs():
                for w in labels:
                    for u in writers:
                        cached = (st["chains"].get(w, 0)
                                  if u == me and ep == top
                                  else remote.get(f"{ep}|{w}", {}).get(u, 0))
                        chains[("lab", field, ep, w, u)] = {
                            "fn": (lambda i, e=ep, k=k_ws[w], u=u:
                                   self._ut(k, e, u, i)), "cached": cached}

        # ---- round 1: speculative enumeration + growth probes --------------
        enum_map = {}                # key -> (cid, i); label entries only
        probe_map = {}               # key -> cid
        for cid, ch in chains.items():
            if cid[0] == "lab":      # tomb rids are cached; sys needs no enum
                for i in range(1, ch["cached"] + 1):
                    enum_map[ch["fn"](i)] = (cid, i)
            probe_map[ch["fn"](ch["cached"] + 1)] = cid
        got = self._mget(list(enum_map) + list(probe_map))
        rounds = 1

        grown = {cid for k, cid in probe_map.items() if k in got}
        if any(cid[0] == "sys" for cid in grown):
            if _retried:
                raise RuntimeError("system chains unstable across retries")
            self._refresh_epoch()
            self._refresh_writers()
            return self.query_multi(predicates, _retried=True)

        # gallop only the chains that grew; their entry at cached+1 is
        # already in hand (the probe hit IS an entry)
        ends = {cid: ch["cached"] for cid, ch in chains.items()
                if cid[0] != "sys"}
        if grown:
            spec = {cid: (chains[cid]["fn"], chains[cid]["cached"] + 1)
                    for cid in grown}
            g_ends = self._discover_ends(spec)
            rounds += getattr(self, "_probe_rounds", 0)
            delta_keys = {}
            for cid, end in g_ends.items():
                ends[cid] = end
                for i in range(chains[cid]["cached"] + 2, end + 1):
                    delta_keys[chains[cid]["fn"](i)] = (cid, i)
            if delta_keys:
                got.update(self._mget(list(delta_keys)))
                rounds += 1
            for cid in grown:
                enum_map[chains[cid]["fn"](chains[cid]["cached"] + 1)] = (
                    cid, chains[cid]["cached"] + 1)
            enum_map.update(delta_keys)

        # ---- unmask entries; update caches ---------------------------------
        tombs_st = st["tombs"]
        rid_sets = {field: set() for field, _a, _b in bounds}
        dirty = False
        for key, (cid, i) in enum_map.items():
            blob = got.get(key)
            if blob is None:
                continue
            if cid[0] == "lab":
                _t, field, ep, w, u = cid
                k_w = covers[field][2][w]
                rid = bytes(x ^ y for x, y in zip(b64decode(blob),
                                                  self._mask(k_w, ep, u, i)))
                rid_sets[field].add(rid.hex())
            else:                    # ("tomb", ep, u)
                _t, ep, u = cid
                rid = bytes(x ^ y for x, y in zip(b64decode(blob),
                                                  self._mask(k_t, ep, u, i)))
                if rid.hex() not in tombs_st["rids"]:
                    tombs_st["rids"].append(rid.hex())
                    dirty = True
        for cid, end in ends.items():
            if cid[0] == "lab":
                _t, field, ep, w, u = cid
                if u == me and ep == top:
                    if end > st["chains"].get(w, 0):
                        st["chains"][w] = end
                        dirty = True
                elif end != remote.setdefault(f"{ep}|{w}", {}).get(u, 0):
                    remote[f"{ep}|{w}"][u] = end
                    dirty = True
            elif cid[0] == "tomb":
                _t, ep, u = cid
                if end != tombs_st["counts"].get(f"{ep}|{u}", 0):
                    tombs_st["counts"][f"{ep}|{u}"] = end
                    dirty = True
        if dirty:
            self._save()             # cache only; losable, re-probable

        tombs = set(tombs_st["rids"])
        sets = [rid_sets[field] for field, _a, _b in bounds]
        candidates = set.intersection(*sets) - tombs if sets else set()

        # ---- final round: ciphertexts --------------------------------------
        results = []
        blobs = self._mget(["R:" + r for r in candidates]) if candidates else {}
        rounds += 1 if candidates else 0
        for key, ct in blobs.items():
            raw = b64decode(ct)
            rec = json.loads(self._aes.decrypt(raw[:12], raw[12:], None))
            if all(a <= self._encode(f, rec[f]) <= b for f, a, b in bounds
                   if f in rec):
                rec["_rid"] = key[2:]
                results.append(rec)
        self.last_stats = {
            "cover": sum(len(covers[f][0]) for f, _a, _b in bounds),
            "index_keys": len(enum_map), "rounds": rounds,
            "grown_chains": len(grown), "writers": len(writers),
            "per_predicate": [len(s) for s in sets],
            "intersected": len(candidates),
            "candidates": len(blobs), "results": len(results),
            "overfetch": len(blobs) - len(results)}
        return results


    # --------------------------------------------------------- compaction
    def _walk_epoch(self, E, writers):
        """One full pass over epoch E's label tree: gallop every reachable
        chain, fetch entries, unmask. Returns (entries, old_keys) where
        entries = {label: [rid_hex, ...]} and old_keys are the index keys."""
        entries, old_keys = {}, []
        for field, spec in self._st["schema"].items():
            mlvl = max_level(spec["bits"], spec.get("leaf_width", 1))
            frontier = [(1, 0), (1, 1)]
            while frontier:
                labels = [f"{field}|{lvl}|{idx}" for lvl, idx in frontier]
                k_ws = {w: self._k_w(w) for w in labels}
                spec_map = {(w, u): ((lambda i, k=k_ws[w], u=u:
                                      self._ut(k, E, u, i)), 0)
                            for w in labels for u in writers}
                ends = self._discover_ends(spec_map) if spec_map else {}
                ut_map = {}
                for (w, u), c in ends.items():
                    for i in range(1, c + 1):
                        ut_map[self._ut(k_ws[w], E, u, i)] = (w, u, i)
                got = self._mget(list(ut_map)) if ut_map else {}
                nonempty = set()
                for ut, blob in got.items():
                    w, u, i = ut_map[ut]
                    rid = bytes(x ^ y for x, y in
                                zip(b64decode(blob),
                                    self._mask(k_ws[w], E, u, i)))
                    entries.setdefault(w, []).append(rid.hex())
                    old_keys.append(ut)
                    nonempty.add((int(w.split("|")[1]), int(w.split("|")[2])))
                frontier = [(lvl + 1, c) for (lvl, idx) in nonempty
                            if lvl + 1 <= mlvl
                            for c in (idx * 2, idx * 2 + 1)]
        for w in entries:
            entries[w].sort()
        return entries, old_keys

    def compact(self):
        """Merge all writers' chains into single per-label streams under a new
        epoch, dropping tombstoned entries, then delete the old epoch's keys.

        Safe under concurrent writes: it first announces "open:E+1" (writers
        move to the new epoch within one operation — every insert re-checks
        the epoch first), then DRAINS epoch E by re-walking it until two
        consecutive passes see identical contents (catching in-flight
        stragglers), merges, deletes E's keys, and announces "sealed:E".
        Readers consult both epochs between open and sealed, so nothing is
        ever invisible. One compactor at a time: the open marker is an
        insert-if-absent slot, and losing that race aborts cleanly."""
        import time as _time
        E = self._refresh_epoch()
        if len(self._epochs()) > 1:
            raise RuntimeError("a compaction is already in flight")
        writers = self._refresh_writers()
        me = self._st["writer"]
        new_E = E + 1

        slot = self._st["epoch_len"] + 1
        if not self._put_nx(self._sys_key(b"epoch", slot),
                            self._sys_encode(f"open:{new_E}")):
            self._refresh_epoch()
            raise RuntimeError("another compaction won the epoch slot")
        self._st["epoch_len"] = slot
        self._st["epoch"] = new_E
        self._st["chains"] = {}
        self._save()

        # drain epoch E: re-walk until a pass sees nothing new
        entries, old_keys = self._walk_epoch(E, writers)
        while True:
            _time.sleep(0.3)
            entries2, old_keys2 = self._walk_epoch(E, writers)
            if entries2 == entries:
                break
            entries, old_keys = entries2, old_keys2

        tombs = self._refresh_tombs(writers)         # includes epoch-E tombs
        puts = []
        new_chains = {}
        kept = dropped = 0
        for w, rid_list in entries.items():
            live = [r for r in rid_list if r not in tombs]
            dropped += len(rid_list) - len(live)
            k_w = self._k_w(w)
            for n, rid_hex in enumerate(live, start=1):
                rid = bytes.fromhex(rid_hex)
                masked = bytes(x ^ y for x, y in
                               zip(rid, self._mask(k_w, new_E, me, n)))
                puts.append((self._ut(k_w, new_E, me, n),
                             b64encode(masked).decode()))
            if live:
                new_chains[w] = len(live)
                kept += len(live)

        # epoch-E tombstone chains are consumed by this rewrite
        k_t = self._k_w(TOMB)
        t_ends = self._discover_ends(
            {u: ((lambda i, u=u: self._ut(k_t, E, u, i)), 0)
             for u in writers}) if writers else {}
        for u, c in t_ends.items():
            old_keys += [self._ut(k_t, E, u, i) for i in range(1, c + 1)]

        if puts:
            self._put(puts)
        self._delete(old_keys)
        seal_slot = self._st["epoch_len"] + 1
        self._put_nx(self._sys_key(b"epoch", seal_slot),
                     self._sys_encode(f"sealed:{E}"))
        self._st["epoch_len"] = seal_slot
        self._st["sealed_max"] = max(self._st["sealed_max"], E)
        for w, c in new_chains.items():
            self._st["chains"][w] = max(self._st["chains"].get(w, 0), c)
        self._st["remote"] = {}
        self._st["tombs"] = {"counts": {}, "rids": []}
        self._save()
        return {"labels": len(new_chains), "entries": kept, "dropped": dropped}


    # ------------------------------------------------------------- repair
    def repair(self):
        """Anti-entropy sweep: walk everything reachable (system chains, the
        whole label tree across readable epochs, tombstones, record blobs)
        and re-put each found key to its CURRENT replica set. Nodes also do
        this continuously among themselves in the background; this is the
        owner-driven full pass. Idempotent, safe to run any time."""
        self._refresh_epoch()
        writers = self._refresh_writers()
        keys = [self._sys_key(b"epoch", i)
                for i in range(1, self._st["epoch_len"] + 1)]
        keys += [self._sys_key(b"registry", i)
                 for i in range(1, self._st["reg_len"] + 1)]

        k_t = self._k_w(TOMB)
        rids = set()
        for E in self._epochs():
            t_ends = self._discover_ends(
                {u: ((lambda i, e=E, u=u: self._ut(k_t, e, u, i)), 0)
                 for u in writers}) if writers else {}
            for u, c in t_ends.items():
                keys += [self._ut(k_t, E, u, i) for i in range(1, c + 1)]
            entries, old_keys = self._walk_epoch(E, writers)
            keys += old_keys
            for rid_list in entries.values():
                rids.update(rid_list)
        keys += ["R:" + r for r in rids]

        # fetch whatever exists and re-place it under the current ring
        found = 0
        for i in range(0, len(keys), 2000):
            got = self._mget(keys[i:i + 2000])
            if got:
                self._put(list(got.items()))
                found += len(got)
        return {"checked": len(keys), "healed": found}

    # -------------------------------------------------------------- misc
    @property
    def schema(self):
        return dict(self._st["schema"])

    def network(self):
        """Live nodes with their stats (for dashboards)."""
        out = []
        for nid in (self.ring.addrs if self.ring else []):
            addr = self._addr(nid)
            if not addr:
                continue
            try:
                out.append(self._get(addr, "/stats"))
            except OSError:
                out.append({"addr": addr, "node_id": nid, "down": True})
        return out

    def intel(self, addr, limit=6):
        """A node's transparency dump (what its operator sees)."""
        return self._get(addr, f"/intel?limit={limit}")


def _ok(job):
    try:
        return job.result()
    except OSError:
        return None
