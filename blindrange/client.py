"""The data owner. The only place keys, plaintext, or order ever exist.

Index construction — forward-private PRF counter chains, multi-writer:
Because the OWNER walks the index (nodes never receive a label key), each
dyadic label w is a set of per-writer append-only chains: writer u's i-th
entry under w lives at key UT = PRF(K_w, u, i) with the record id masked by a
second PRF stream. Writers never contend (each appends only to its own
chains), so the index is a grow-only CRDT: any two clients' views merge by
union, and no coordination exists anywhere. At rest the network holds only
unlinkable pseudorandom key->blob pairs — no equality, no order, no
co-occurrence — and a node can never derive a future key from anything it has
seen (Sophos-style forward privacy at HMAC speed; the public-key trapdoor is
only needed when an untrusted server walks the chain — prototype/fp_demo.py).

Sync — the network is the source of truth, counters are a cache:
Entry keys are deterministic, so a reader discovers another writer's chain
length by galloping probes (exponential then binary, batched across chains).
Writers announce themselves once in an encrypted on-network registry chain,
appended lock-free via insert-if-absent. A client's cached counters only cut
probing cost; losing the cache costs a re-probe, not the database. Only the
master key is unrecoverable.

Onboarding: owner_a.invite() -> secret string -> Owner.accept(path, pass,
invite) creates a new writer with its own state file. Treat an invite like
the key material it contains.

Owner state (master key + writer id + counter caches + schema + membership)
persists in a single passphrase-encrypted file.

Schema: {field: {"type": "int"|"str", "bits": B, "leaf_width": W, "chars": C}}
`leaf_width` (power of 2) is the field's structural privacy budget — no
observer, ever, resolves finer than W (see prototype/bounded_demo.py).
"""
import hashlib
import hmac
import json
import os
import secrets
import urllib.request
from base64 import b64decode, b64encode
from concurrent.futures import ThreadPoolExecutor

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .dyadic import (dyadic_cover, encode_str, levels_for, max_level,
                     prefix_range)
from .ring import Ring

PEER_LIVE_S = 12.0


class Owner:
    # ------------------------------------------------------------ lifecycle
    def __init__(self, state_path, passphrase, state):
        self._path = state_path
        self._pass = passphrase
        self._st = state                    # dict: master, schema, chains, bootstrap
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
            max_level(spec["bits"], spec.get("leaf_width", 1))   # validate early
        return {"v": 2, "master": master_hex, "writer": os.urandom(8).hex(),
                "schema": schema, "chains": {}, "remote": {},
                "writers": [], "reg_len": 0, "bootstrap": list(bootstrap)}

    @classmethod
    def create(cls, state_path, passphrase, schema, bootstrap):
        if os.path.exists(state_path):
            raise FileExistsError(state_path)
        state = cls._new_state(os.urandom(32).hex(), schema, bootstrap)
        owner = cls(state_path, passphrase, state)
        owner._register_writer()
        owner._save()
        return owner

    def invite(self):
        """A secret onboarding string for a new writer. It CONTAINS the master
        key — transmit it like key material, then discard it."""
        return b64encode(json.dumps(
            {"master": self._st["master"], "schema": self._st["schema"],
             "bootstrap": self._st["bootstrap"]}).encode()).decode()

    @classmethod
    def accept(cls, state_path, passphrase, invite, bootstrap=None):
        """Join an existing database as a new writer, from an invite()."""
        if os.path.exists(state_path):
            raise FileExistsError(state_path)
        d = json.loads(b64decode(invite))
        state = cls._new_state(d["master"], d["schema"],
                               bootstrap or d["bootstrap"])
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
        if state.get("v") != 2:
            raise ValueError("state file predates the multi-writer format; "
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
                with urllib.request.urlopen(f"http://{addr}/peers", timeout=3) as r:
                    ages = json.loads(r.read())["peers"]
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

    @staticmethod
    def _ut(k_w, writer, i):
        return "I:" + hmac.new(k_w, f"UT|{writer}|{i}".encode(),
                               hashlib.sha256).hexdigest()[:32]

    @staticmethod
    def _mask(k_w, writer, i):
        return hmac.new(k_w, f"MASK|{writer}|{i}".encode(),
                        hashlib.sha256).digest()[:8]

    # ---------------------------------------------------- writer registry
    # A shared encrypted chain announcing writer ids. Slot i lives at
    # PRF(K_reg, i); appends use insert-if-absent, so concurrent joins race
    # harmlessly (the loser sees the winner's entry and takes the next slot).
    def _reg_key(self, i):
        k = hmac.new(self._master, b"registry", hashlib.sha256).digest()
        return "I:" + hmac.new(k, f"W|{i}".encode(),
                               hashlib.sha256).hexdigest()[:32]

    def _reg_enc(self):
        return AESGCM(hmac.new(self._master, b"registry-enc",
                               hashlib.sha256).digest())

    def _reg_decode(self, blob):
        raw = b64decode(blob)
        return self._reg_enc().decrypt(raw[:12], raw[12:], None).decode()

    def _refresh_writers(self):
        """Learn any new writers from the on-network registry chain."""
        end = self._discover_ends(
            {"reg": (self._reg_key, self._st["reg_len"])})["reg"]
        if end > self._st["reg_len"]:
            keys = [self._reg_key(i) for i in range(self._st["reg_len"] + 1,
                                                    end + 1)]
            got = self._mget(keys)
            for k in keys:
                if k in got:
                    wid = self._reg_decode(got[k])
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
        nonce = os.urandom(12)
        val = b64encode(nonce + self._reg_enc().encrypt(
            nonce, wid.encode(), None)).decode()
        while True:
            slot = self._st["reg_len"] + 1
            if self._put_nx(self._reg_key(slot), val):
                self._st["writers"].append(wid)
                self._st["reg_len"] = slot
                break
            # lost a concurrent-join race: absorb the winner, take next slot
            got = self._mget([self._reg_key(slot)])
            other = self._reg_decode(got[self._reg_key(slot)])
            if other not in self._st["writers"]:
                self._st["writers"].append(other)
            self._st["reg_len"] = slot
        self._save()

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

    def _encode(self, field, value):
        spec = self._st["schema"][field]
        return encode_str(str(value), spec["chars"]) if spec["type"] == "str" \
            else int(value)

    # ---------------------------------------------------------- transport
    def _post(self, addr, path, payload):
        req = urllib.request.Request(f"http://{addr}{path}",
                                     data=json.dumps(payload).encode(),
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as r:
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

    # ------------------------------------------------------------- insert
    def insert_many(self, records):
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
                                   zip(rid, self._mask(k_w, me, i)))
                    puts.append((self._ut(k_w, me, i),
                                 b64encode(masked).decode()))
        self._put(puts)
        self._save()                       # own counters are authoritative
        return len(records)

    def insert(self, record):
        return self.insert_many([record])

    # -------------------------------------------------------------- query
    def query(self, field, lo, hi):
        return self._query_encoded(field, self._encode(field, lo),
                                   self._encode(field, hi))

    def query_prefix(self, field, prefix):
        spec = self._st["schema"][field]
        a, b = prefix_range(prefix, spec["chars"])
        return self._query_encoded(field, a, b)

    def _query_encoded(self, field, a, b):
        spec = self._st["schema"][field]
        mlvl = max_level(spec["bits"], spec.get("leaf_width", 1))
        me = self._st["writer"]
        writers = self._refresh_writers()
        cover = dyadic_cover(a, b, spec["bits"], mlvl)
        labels = [f"{field}|{lvl}|{idx}" for lvl, idx in cover]
        k_ws = {w: self._k_w(w) for w in labels}
        remote = self._st["remote"]

        # discover every writer's chain lengths; cached counters (even our
        # own) are a lower bound, so another instance of this same writer id
        # (state file copied to a second device, used sequentially) is seen too
        spec_map = {}
        for w in labels:
            for u in writers:
                cached = (self._st["chains"].get(w, 0) if u == me
                          else remote.get(w, {}).get(u, 0))
                spec_map[(w, u)] = (
                    (lambda i, k=k_ws[w], u=u: self._ut(k, u, i)), cached)
        ends = self._discover_ends(spec_map) if spec_map else {}
        dirty = False
        counts = {}                          # (w, u) -> chain length
        for (w, u), end in ends.items():
            counts[(w, u)] = end
            if u == me:
                if end > self._st["chains"].get(w, 0):
                    self._st["chains"][w] = end     # future inserts append after
                    dirty = True
            elif end != remote.setdefault(w, {}).get(u, 0):
                remote[w][u] = end
                dirty = True
        if dirty:
            self._save()                     # cache only; losable, re-probable

        # enumerate every writer's entries under the covered labels
        ut_map = {}                          # ut -> (k_w, u, i)
        for (w, u), c in counts.items():
            for i in range(1, c + 1):
                ut_map[self._ut(k_ws[w], u, i)] = (k_ws[w], u, i)
        rids = []
        for ut, blob in self._mget(list(ut_map)).items():
            k_w, u, i = ut_map[ut]
            rid = bytes(x ^ y for x, y in zip(b64decode(blob),
                                              self._mask(k_w, u, i)))
            rids.append(rid.hex())
        results = []
        blobs = self._mget(["R:" + r for r in rids]) if rids else {}
        for ct in blobs.values():
            raw = b64decode(ct)
            rec = json.loads(self._aes.decrypt(raw[:12], raw[12:], None))
            if a <= self._encode(field, rec[field]) <= b:
                results.append(rec)
        self.last_stats = {"cover": len(cover), "index_keys": len(ut_map),
                           "candidates": len(blobs), "results": len(results),
                           "overfetch": len(blobs) - len(results),
                           "writers": len(writers),
                           "probe_rounds": getattr(self, "_probe_rounds", 0)}
        return results

    # -------------------------------------------------------------- misc
    @property
    def schema(self):
        return dict(self._st["schema"])

    def network(self):
        """Live nodes with their stats (for dashboards)."""
        out = []
        for addr in (self.ring.addrs if self.ring else []):
            try:
                with urllib.request.urlopen(f"http://{addr}/stats", timeout=3) as r:
                    out.append(json.loads(r.read()))
            except OSError:
                out.append({"addr": addr, "down": True})
        return out


def _ok(job):
    try:
        return job.result()
    except OSError:
        return None
