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
import urllib.request
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
        return {"v": 3, "master": master_hex, "writer": os.urandom(8).hex(),
                "schema": schema, "epoch": 0, "chains": {}, "remote": {},
                "writers": [], "reg_len": 0,
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
        if state.get("v") != 3:
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
        """Discover live nodes by asking any known node for its peer table."""
        contacts = list(self._st["bootstrap"])
        if self.ring:
            contacts = list(self.ring.addrs) + contacts
        seen = {}
        for addr in contacts:
            try:
                ages = self._get(addr, "/peers")["peers"]
                for a, age in ages.items():
                    if age <= PEER_LIVE_S:
                        seen[a] = True
                break                                   # one live answer is enough
            except OSError:
                continue
        if not seen:
            raise ConnectionError("no live blindrange node reachable "
                                  f"(tried {contacts})")
        new_ring = Ring(sorted(seen), replicas=3)
        if new_ring != self.ring:
            self.ring = new_ring
        return sorted(seen)

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
        req = urllib.request.Request(
            f"http://{addr}{path}", data=body,
            headers={"Content-Type": "application/json", **self._sign(body)})
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read())

    def _get(self, addr, path):
        base = path.split("?")[0]
        req = urllib.request.Request(f"http://{addr}{path}",
                                     headers=self._sign(base.encode()))
        with urllib.request.urlopen(req, timeout=3) as r:
            return json.loads(r.read())

    def _put(self, kv_pairs):
        by_node = {}
        for k, v in kv_pairs:
            for addr in self.ring.route(k):
                by_node.setdefault(addr, []).append([k, v])
        jobs = [self.pool.submit(self._post, a, "/kv", {"entries": e})
                for a, e in by_node.items()]
        failures = sum(1 for j in jobs if not _ok(j))
        if failures == len(jobs):
            raise ConnectionError("all replicas rejected the write")

    def _put_nx(self, key, value):
        """Insert-if-absent on all replicas. False if any replica already had
        the key (a concurrent writer won the slot)."""
        won = True
        for addr in self.ring.route(key):
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
            for addr in self.ring.route(k, self.ring.replicas + PROBE_EXTRA):
                by_node.setdefault(addr, []).append(k)
        jobs = [self.pool.submit(self._post, a, "/delete", {"keys": ks})
                for a, ks in by_node.items()]
        for j in jobs:
            _ok(j)

    def _mget(self, keys):
        """Replica failover + read-repair: keys found on a fallback replica are
        rewritten to the current primary, so data migrates as the ring changes.
        Probes PROBE_EXTRA successors beyond the replica set, covering keys
        written under an earlier ring whose holders have shifted out of it."""
        PROBE_EXTRA = 3
        route = {k: self.ring.route(k, self.ring.replicas + PROBE_EXTRA)
                 for k in keys}
        out, found_at = {}, {}
        for level in range(self.ring.replicas + PROBE_EXTRA):
            by_node = {}
            for k, reps in route.items():
                if k not in out and level < len(reps):
                    by_node.setdefault(reps[level], []).append(k)
            if not by_node:
                break
            jobs = {a: self.pool.submit(self._post, a, "/mget", {"keys": ks})
                    for a, ks in by_node.items()}
            for a, j in jobs.items():
                vals = _ok(j)
                if vals:
                    for k, v in vals["values"].items():
                        out[k] = v
                        found_at[k] = level
        repairs = [(k, out[k]) for k, lvl in found_at.items() if lvl > 0]
        if repairs:
            by_primary = {}
            for k, v in repairs:
                by_primary.setdefault(route[k][0], []).append([k, v])
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
        """One probe (typically) against the on-network epoch chain. A new
        epoch means a compaction happened: local chain caches reset (they are
        caches — probing rebuilds them)."""
        end = self._discover_ends(
            {"e": (lambda i: self._sys_key(b"epoch", i),
                   self._st["epoch"])})["e"]
        if end > self._st["epoch"]:
            self._st["epoch"] = end
            self._st["chains"] = {}
            self._st["remote"] = {}
            self._st["tombs"] = {"counts": {}, "rids": []}
            self._save()
        return self._st["epoch"]

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

    def _refresh_tombs(self, writers):
        """The set of deleted record ids in the current epoch (cached; only
        new tombstone entries are fetched)."""
        E = self._st["epoch"]
        k_t = self._k_w(TOMB)
        tombs = self._st["tombs"]
        spec = {u: ((lambda i, u=u: self._ut(k_t, E, u, i)),
                    tombs["counts"].get(u, 0)) for u in writers}
        ends = self._discover_ends(spec) if spec else {}
        new_keys = {}
        for u, end in ends.items():
            for i in range(tombs["counts"].get(u, 0) + 1, end + 1):
                new_keys[self._ut(k_t, E, u, i)] = (u, i)
        if new_keys:
            got = self._mget(list(new_keys))
            for ut, blob in got.items():
                u, i = new_keys[ut]
                rid = bytes(x ^ y for x, y in
                            zip(b64decode(blob), self._mask(k_t, E, u, i)))
                if rid.hex() not in tombs["rids"]:
                    tombs["rids"].append(rid.hex())
            for u, end in ends.items():
                tombs["counts"][u] = end
            self._save()
        return set(tombs["rids"])

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
        base = tombs["counts"].get(me, 0)
        puts = []
        for n, rid_hex in enumerate(rids, start=base + 1):
            rid = bytes.fromhex(rid_hex)
            masked = bytes(x ^ y for x, y in zip(rid, self._mask(k_t, E, me, n)))
            puts.append((self._ut(k_t, E, me, n), b64encode(masked).decode()))
        self._put(puts)
        tombs["counts"][me] = base + len(rids)
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

    def query_multi(self, predicates):
        """AND of range/prefix predicates. Index phases run per predicate and
        intersect on record ids BEFORE any ciphertext is fetched — the
        narrowest way to combine encrypted indexes."""
        self._refresh_epoch()
        writers = self._refresh_writers()
        tombs = self._refresh_tombs(writers)
        bounds = []
        for p in predicates:
            spec = self._st["schema"][p["field"]]
            if "prefix" in p:
                a, b = prefix_range(p["prefix"], spec["chars"])
            else:
                a, b = (self._encode(p["field"], p["lo"]),
                        self._encode(p["field"], p["hi"]))
            bounds.append((p["field"], a, b))

        rid_sets = []
        agg = {"cover": 0, "index_keys": 0, "probe_rounds": 0}
        for field, a, b in bounds:
            rids = self._candidate_rids(field, a, b, writers)
            agg["cover"] += self.last_stats["cover"]
            agg["index_keys"] += self.last_stats["index_keys"]
            agg["probe_rounds"] += self.last_stats["probe_rounds"]
            rid_sets.append(rids)
        candidates = set.intersection(*rid_sets) - tombs if rid_sets else set()

        results = []
        blobs = self._mget(["R:" + r for r in candidates]) if candidates else {}
        for key, ct in blobs.items():
            raw = b64decode(ct)
            rec = json.loads(self._aes.decrypt(raw[:12], raw[12:], None))
            if all(a <= self._encode(f, rec[f]) <= b for f, a, b in bounds
                   if f in rec):
                rec["_rid"] = key[2:]
                results.append(rec)
        self.last_stats = {**agg, "writers": len(writers),
                           "per_predicate": [len(s) for s in rid_sets],
                           "intersected": len(candidates),
                           "candidates": len(blobs), "results": len(results),
                           "overfetch": len(blobs) - len(results)}
        return results

    def _candidate_rids(self, field, a, b, writers):
        """Index phase for one predicate: encrypted-index lookups only, no
        ciphertext fetches. Returns the set of matching record ids."""
        E = self._st["epoch"]
        spec = self._st["schema"][field]
        mlvl = max_level(spec["bits"], spec.get("leaf_width", 1))
        me = self._st["writer"]
        remote = self._st["remote"]
        cover = dyadic_cover(a, b, spec["bits"], mlvl)
        labels = [f"{field}|{lvl}|{idx}" for lvl, idx in cover]
        k_ws = {w: self._k_w(w) for w in labels}

        # cached counters (even our own) are a lower bound; gallop to the end
        spec_map = {}
        for w in labels:
            for u in writers:
                cached = (self._st["chains"].get(w, 0) if u == me
                          else remote.get(w, {}).get(u, 0))
                spec_map[(w, u)] = (
                    (lambda i, k=k_ws[w], u=u: self._ut(k, E, u, i)), cached)
        ends = self._discover_ends(spec_map) if spec_map else {}
        dirty = False
        for (w, u), end in ends.items():
            if u == me:
                if end > self._st["chains"].get(w, 0):
                    self._st["chains"][w] = end     # future inserts append after
                    dirty = True
            elif end != remote.setdefault(w, {}).get(u, 0):
                remote[w][u] = end
                dirty = True
        if dirty:
            self._save()                     # cache only; losable, re-probable

        ut_map = {}
        for (w, u), c in ends.items():
            for i in range(1, c + 1):
                ut_map[self._ut(k_ws[w], E, u, i)] = (k_ws[w], u, i)
        rids = set()
        for ut, blob in self._mget(list(ut_map)).items():
            k_w, u, i = ut_map[ut]
            rid = bytes(x ^ y for x, y in zip(b64decode(blob),
                                              self._mask(k_w, E, u, i)))
            rids.add(rid.hex())
        self.last_stats = {"cover": len(cover), "index_keys": len(ut_map),
                           "probe_rounds": getattr(self, "_probe_rounds", 0)}
        return rids

    # --------------------------------------------------------- compaction
    def compact(self):
        """Merge all writers' chains into single per-label streams under a new
        epoch, dropping tombstoned entries, then delete the old epoch's keys.
        Owner-driven maintenance: run while writers are QUIESCENT. Returns
        {"labels": n, "entries": kept, "dropped": tombstoned_dropped}."""
        E = self._refresh_epoch()
        writers = self._refresh_writers()
        tombs = self._refresh_tombs(writers)
        me = self._st["writer"]
        new_E = E + 1
        puts, old_keys = [], []
        new_chains = {}
        kept = dropped = 0

        for field, spec in self._st["schema"].items():
            mlvl = max_level(spec["bits"], spec.get("leaf_width", 1))
            frontier = [(1, 0), (1, 1)]
            while frontier:
                labels = [f"{field}|{lvl}|{idx}" for lvl, idx in frontier]
                k_ws = {w: self._k_w(w) for w in labels}
                spec_map = {(w, u): ((lambda i, k=k_ws[w], u=u:
                                      self._ut(k, E, u, i)), 0)
                            for w in labels for u in writers}
                ends = self._discover_ends(spec_map)
                ut_map = {}
                for (w, u), c in ends.items():
                    for i in range(1, c + 1):
                        ut_map[self._ut(k_ws[w], E, u, i)] = (w, u, i)
                got = self._mget(list(ut_map)) if ut_map else {}
                per_label_rids = {w: [] for w in labels}
                for ut, blob in got.items():
                    w, u, i = ut_map[ut]
                    rid = bytes(x ^ y for x, y in
                                zip(b64decode(blob),
                                    self._mask(k_ws[w], E, u, i)))
                    per_label_rids[w].append(rid.hex())
                    old_keys.append(ut)
                nonempty = set()
                for (lvl, idx), w in zip(frontier, labels):
                    live = [r for r in per_label_rids[w] if r not in tombs]
                    dropped += len(per_label_rids[w]) - len(live)
                    if per_label_rids[w]:
                        nonempty.add((lvl, idx))
                    for n, rid_hex in enumerate(live, start=1):
                        rid = bytes.fromhex(rid_hex)
                        masked = bytes(x ^ y for x, y in
                                       zip(rid, self._mask(k_ws[w], new_E,
                                                           me, n)))
                        puts.append((self._ut(k_ws[w], new_E, me, n),
                                     b64encode(masked).decode()))
                    if live:
                        new_chains[w] = len(live)
                        kept += len(live)
                frontier = [(lvl + 1, c) for (lvl, idx) in nonempty
                            if lvl + 1 <= mlvl
                            for c in (idx * 2, idx * 2 + 1)]

        # old tombstone chains are consumed by this rewrite
        k_t = self._k_w(TOMB)
        t_ends = self._discover_ends(
            {u: ((lambda i, u=u: self._ut(k_t, E, u, i)), 0)
             for u in writers}) if writers else {}
        for u, c in t_ends.items():
            old_keys += [self._ut(k_t, E, u, i) for i in range(1, c + 1)]

        self._put(puts)
        self._put_nx(self._sys_key(b"epoch", new_E),
                     self._sys_encode(f"compacted-by:{me}"))
        self._delete(old_keys)
        self._st["epoch"] = new_E
        self._st["chains"] = new_chains
        self._st["remote"] = {}
        self._st["tombs"] = {"counts": {}, "rids": []}
        self._save()
        return {"labels": len(new_chains), "entries": kept, "dropped": dropped}

    # ------------------------------------------------------------- repair
    def repair(self):
        """Anti-entropy sweep: walk everything reachable (system chains, the
        whole label tree, tombstones, record blobs) and re-put each found key
        to its CURRENT replica set. Heals cold data after ring churn — the
        lazy read-repair only fixes what queries happen to touch. Owner-driven
        maintenance; safe to run any time (writes are idempotent)."""
        E = self._refresh_epoch()
        writers = self._refresh_writers()
        keys = [self._sys_key(b"epoch", i) for i in range(1, E + 1)]
        keys += [self._sys_key(b"registry", i)
                 for i in range(1, self._st["reg_len"] + 1)]

        # tombstone chains
        k_t = self._k_w(TOMB)
        t_ends = self._discover_ends(
            {u: ((lambda i, u=u: self._ut(k_t, E, u, i)), 0)
             for u in writers}) if writers else {}
        for u, c in t_ends.items():
            keys += [self._ut(k_t, E, u, i) for i in range(1, c + 1)]

        # full label-tree walk (empty intervals prune their subtrees)
        rids = set()
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
                    rids.add(rid.hex())
                    lvl = int(w.split("|")[1])
                    nonempty.add((lvl, int(w.split("|")[2])))
                keys += list(ut_map)
                frontier = [(lvl + 1, c) for (lvl, idx) in nonempty
                            if lvl + 1 <= mlvl
                            for c in (idx * 2, idx * 2 + 1)]
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
        for addr in (self.ring.addrs if self.ring else []):
            try:
                out.append(self._get(addr, "/stats"))
            except OSError:
                out.append({"addr": addr, "down": True})
        return out

    def intel(self, addr, limit=6):
        """A node's transparency dump (what its operator sees)."""
        return self._get(addr, f"/intel?limit={limit}")


def _ok(job):
    try:
        return job.result()
    except OSError:
        return None
