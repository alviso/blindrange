"""Forward-private, sharded range client over a network of blind KV nodes.

Combines the Sophos forward-private construction with dyadic-range indexing and
a pluggable key router. The CLIENT walks each interval's hash chain (with the
public exponent) and fetches every derived key by routing it to its node, so a
node is a dumb KV store that never receives K_w and can never derive a future
key. Nothing but the owner's key can produce or read a query.

Routing is injected (a `router` with .route(key)->port and .ports), so step 2
can swap mod-N for a consistent-hashing ring without touching this file.
"""
import hashlib
import hmac
import json
import os
import secrets
import urllib.request
from base64 import b64decode, b64encode
from concurrent.futures import ThreadPoolExecutor

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ------------------------------------------------- dyadic range primitives

def levels_for(value, bits, max_level):
    return [(lvl, value >> (bits - lvl)) for lvl in range(1, max_level + 1)]


def dyadic_cover(a, b, bits, max_level):
    out = []

    def rec(lo, hi, lvl, idx):
        if hi < a or lo > b:
            return
        if (a <= lo and hi <= b and lvl >= 1) or lvl == max_level:
            out.append((lvl, idx))
            return
        mid = (lo + hi) // 2
        rec(lo, mid, lvl + 1, idx * 2)
        rec(mid + 1, hi, lvl + 1, idx * 2 + 1)

    rec(0, 2 ** bits - 1, 0, 0)
    return out


# ------------------------------------------------------------ mod-N router

class ModRouter:
    replicas = 1

    def __init__(self, ports):
        self.ports = list(ports)

    def route(self, key):
        h = int(hashlib.sha256(key.encode()).hexdigest(), 16)
        return [self.ports[h % len(self.ports)]]     # list, so replication fits later


# ------------------------------------------------------------------ client

class FPClient:
    def __init__(self, router, bits=7, max_level=7, key_size=1024,
                 master=None, rsa_key=None):
        self.router = router
        self.bits = bits
        self.max_level = max_level
        self.master = master or os.urandom(32)
        self.data_key = hmac.new(self.master, b"data", hashlib.sha256).digest()
        key = rsa_key or rsa.generate_private_key(public_exponent=65537,
                                                  key_size=key_size)
        nums = key.private_numbers()
        self.n, self.e, self.d = nums.public_numbers.n, nums.public_numbers.e, nums.d
        self.state = {}              # label w -> (ST_latest, count)   OWNER SECRET
        self.pool = ThreadPoolExecutor(max_workers=32)

    # --- crypto helpers -------------------------------------------------
    def _k_w(self, w):
        return hmac.new(self.master, w.encode(), hashlib.sha256).digest()

    def _ut(self, k_w, st):
        return "I:" + hmac.new(k_w, b"UT" + str(st).encode(),
                               hashlib.sha256).hexdigest()[:32]

    def _mask(self, k_w, st):
        return hmac.new(k_w, b"MASK" + str(st).encode(), hashlib.sha256).digest()[:8]

    # --- transport ------------------------------------------------------
    def _post(self, port, path, payload):
        req = urllib.request.Request(f"http://127.0.0.1:{port}{path}",
                                     data=json.dumps(payload).encode(),
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read())

    def _put(self, kv_pairs):
        """kv_pairs: [(key, value_str)]. Writes to every replica (best effort)."""
        by_node = {}
        for k, v in kv_pairs:
            for port in self.router.route(k):
                by_node.setdefault(port, []).append([k, v])
        jobs = [self.pool.submit(self._post, p, "/kv", {"entries": e})
                for p, e in by_node.items()]
        for j in jobs:
            try:
                j.result()
            except OSError:
                pass                 # a replica is down; the others still hold it

    def _mget(self, keys):
        """Fetch keys, trying replicas in preference order until one answers."""
        route = {k: self.router.route(k) for k in keys}
        out = {}
        for level in range(self.router.replicas):
            by_node = {}
            for k, reps in route.items():
                if k not in out and level < len(reps):
                    by_node.setdefault(reps[level], []).append(k)
            if not by_node:
                break
            jobs = {p: self.pool.submit(self._post, p, "/mget", {"keys": ks})
                    for p, ks in by_node.items()}
            for p, j in jobs.items():
                try:
                    out.update(j.result()["values"])
                except OSError:
                    pass             # node down -> those keys retry on next replica
        return out

    # --- insert ---------------------------------------------------------
    def insert(self, record):
        """record: dict with the indexed field 'age' (+ any payload)."""
        rid = os.urandom(8)
        nonce = os.urandom(12)
        ct = b64encode(nonce + AESGCM(self.data_key).encrypt(
            nonce, json.dumps(record).encode(), None)).decode()
        puts = [("R:" + rid.hex(), ct)]
        for lvl, idx in levels_for(record["age"], self.bits, self.max_level):
            w = f"age|{lvl}|{idx}"
            if w in self.state:
                st_prev, c = self.state[w]
                st = pow(st_prev, self.d, self.n)      # pi^{-1}: advance (private)
                c += 1
            else:
                st, c = secrets.randbelow(self.n - 2) + 1, 1
            k_w = self._k_w(w)
            rid_masked = bytes(x ^ y for x, y in zip(rid, self._mask(k_w, st)))
            puts.append((self._ut(k_w, st), b64encode(rid_masked).decode()))
            self.state[w] = (st, c)
        self._put(puts)
        return rid.hex()

    # --- query ----------------------------------------------------------
    def query(self, lo, hi):
        # 1. client walks each covered interval's chain -> UT -> ST map
        ut_to_st = {}                # ut -> (k_w, st)  (to unmask later)
        for lvl, idx in dyadic_cover(lo, hi, self.bits, self.max_level):
            w = f"age|{lvl}|{idx}"
            if w not in self.state:
                continue
            st_latest, c = self.state[w]
            k_w = self._k_w(w)
            st = st_latest
            for _ in range(c):
                ut_to_st[self._ut(k_w, st)] = (k_w, st)
                st = pow(st, self.e, self.n)           # pi: walk back (public)
        # 2. fetch index blobs, unmask -> record ids
        rids = []
        for ut, blob in self._mget(list(ut_to_st)).items():
            k_w, st = ut_to_st[ut]
            masked = b64decode(blob)
            rid = bytes(x ^ y for x, y in zip(masked, self._mask(k_w, st)))
            rids.append(rid.hex())
        # 3. fetch ciphertexts, decrypt, post-filter
        results = []
        for ct in self._mget(["R:" + r for r in rids]).values():
            raw = b64decode(ct)
            rec = json.loads(AESGCM(self.data_key).decrypt(raw[:12], raw[12:], None))
            if lo <= rec["age"] <= hi:
                results.append(rec)
        return results
