"""The data owner. The only place keys, plaintext, or order ever exist.

Index construction — forward-private PRF counter chains:
Because the OWNER walks the index (nodes never receive a label key), each
dyadic label w keeps a client-side counter c, and the i-th entry under w lives
at key UT_i = PRF(K_w, i) with the record id masked by PRF(K_w, i, "mask").
At rest the network holds only unlinkable pseudorandom key->blob pairs — no
equality, no order, no co-occurrence — and a node can never derive a future
key from anything it has seen. This gives Sophos-style forward privacy at
HMAC speed; the public-key trapdoor is only needed when an untrusted server
walks the chain itself (see prototype/fp_demo.py).

Owner state (master key + per-label counters + schema + membership) persists
in a single passphrase-encrypted file. Losing it loses the database.

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
    def create(cls, state_path, passphrase, schema, bootstrap):
        for f, spec in schema.items():
            max_level(spec["bits"], spec.get("leaf_width", 1))   # validate early
        if os.path.exists(state_path):
            raise FileExistsError(state_path)
        state = {"master": os.urandom(32).hex(), "schema": schema,
                 "chains": {}, "bootstrap": list(bootstrap)}
        owner = cls(state_path, passphrase, state)
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
    def _ut(k_w, i):
        return "I:" + hmac.new(k_w, f"UT|{i}".encode(),
                               hashlib.sha256).hexdigest()[:32]

    @staticmethod
    def _mask(k_w, i):
        return hmac.new(k_w, f"MASK|{i}".encode(), hashlib.sha256).digest()[:8]

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
        chains = self._st["chains"]
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
                                   zip(rid, self._mask(k_w, i)))
                    puts.append((self._ut(k_w, i), b64encode(masked).decode()))
        self._put(puts)
        self._save()                       # counters are part of the database
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
        chains = self._st["chains"]
        ut_map = {}                          # ut -> (k_w, i)
        cover = dyadic_cover(a, b, spec["bits"], mlvl)
        for lvl, idx in cover:
            w = f"{field}|{lvl}|{idx}"
            c = chains.get(w, 0)
            if not c:
                continue
            k_w = self._k_w(w)
            for i in range(1, c + 1):
                ut_map[self._ut(k_w, i)] = (k_w, i)
        rids = []
        for ut, blob in self._mget(list(ut_map)).items():
            k_w, i = ut_map[ut]
            rid = bytes(x ^ y for x, y in zip(b64decode(blob),
                                              self._mask(k_w, i)))
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
                           "overfetch": len(blobs) - len(results)}
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
