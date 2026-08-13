"""Data-owner client: the only place keys, plaintext, or order ever exist.

Scheme (structured encryption, MongoDB-QE-style dyadic ranges):

  Insert:  record -> AES-256-GCM ciphertext (random nonce, fully randomized).
           For each indexed field, the value's dyadic-interval memberships
           (one interval per tree level) become HMAC-SHA256 tags.
           Tag and ciphertext placement = hash(tag) mod N  (stand-in for a DHT).

  Query:   [a, b] -> minimal dyadic cover (<= 2*bits intervals) -> HMAC tags
           -> exact-match lookups fanned out to the responsible nodes
           -> fetch ciphertexts -> decrypt -> client-side post-filter.

  Nodes evaluate no comparisons and hold no key. A capped tree depth
  (`max_level`) coarsens the leaves: less storage and less leakage, in
  exchange for over-fetch that the client filters out after decryption.

Strings index via a fixed-width prefix encoding (first `chars` chars,
5 bits each), so prefix/alphabetic ranges are just integer ranges.
"""
import hashlib
import hmac
import json
import os
from base64 import b64decode, b64encode
from concurrent.futures import ThreadPoolExecutor

import urllib.request

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ---------------------------------------------------------------- crypto

class Keys:
    def __init__(self, master: bytes):
        self.tag_key = hmac.new(master, b"tags", hashlib.sha256).digest()
        self.data_key = hmac.new(master, b"data", hashlib.sha256).digest()

    def tag(self, field: str, level: int, index: int) -> str:
        msg = f"{field}|{level}|{index}".encode()
        return hmac.new(self.tag_key, msg, hashlib.sha256).hexdigest()[:32]

    def encrypt(self, obj: dict) -> str:
        nonce = os.urandom(12)
        ct = AESGCM(self.data_key).encrypt(nonce, json.dumps(obj).encode(), None)
        return b64encode(nonce + ct).decode()

    def decrypt(self, blob: str) -> dict:
        raw = b64decode(blob)
        return json.loads(AESGCM(self.data_key).decrypt(raw[:12], raw[12:], None))


# ------------------------------------------------- dyadic decomposition

def levels_for(value: int, bits: int, max_level: int):
    """Every dyadic interval containing `value`, one per level 1..max_level.
    Level L splits the domain into 2^L intervals; index = top L bits."""
    return [(lvl, value >> (bits - lvl)) for lvl in range(1, max_level + 1)]


def dyadic_cover(a: int, b: int, bits: int, max_level: int):
    """Minimal set of stored intervals covering [a, b]. Intervals at
    max_level are included on mere overlap (superset semantics when the
    tree is capped) — the client post-filters after decryption."""
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


# ------------------------------------------------------ string encoding

def _char5(c: str) -> int:
    c = c.lower()
    return (ord(c) - ord("a") + 1) if "a" <= c <= "z" else 0  # 5 bits/char


def encode_str(s: str, chars: int) -> int:
    v = 0
    for i in range(chars):
        v = (v << 5) | (_char5(s[i]) if i < len(s) else 0)
    return v


def prefix_range(prefix: str, chars: int):
    """Integer range covering all strings starting with `prefix`."""
    lo = hi = 0
    for i in range(chars):
        if i < len(prefix):
            lo = (lo << 5) | _char5(prefix[i])
            hi = (hi << 5) | _char5(prefix[i])
        else:
            lo <<= 5
            hi = (hi << 5) | 31
    return lo, hi


# ------------------------------------------------------------- client

class BlindRangeClient:
    """`schema`: {field: {"bits": int, "max_level": int, "type": "int"|"str",
    ["chars": int]}}. max_level == bits gives exact leaves; smaller values
    coarsen leaves (bucket size 2^(bits-max_level))."""

    def __init__(self, master_key: bytes, node_ports, schema):
        self.keys = Keys(master_key)
        self.ports = list(node_ports)
        self.schema = schema
        self.pool = ThreadPoolExecutor(max_workers=len(self.ports) * 2)
        self.last_stats = {}

    # --- transport -------------------------------------------------
    def _post(self, port, path, payload):
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}{path}",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read())

    def _node_for(self, key: str) -> int:
        h = int(hashlib.sha256(key.encode()).hexdigest(), 16)
        return self.ports[h % len(self.ports)]  # stand-in for DHT routing

    # --- field encoding --------------------------------------------
    def _encode(self, field, value):
        spec = self.schema[field]
        return encode_str(value, spec["chars"]) if spec["type"] == "str" else int(value)

    # --- insert ----------------------------------------------------
    def insert_many(self, records):
        """records: list of dicts. Batches tag and ciphertext placement per node.
        Returns the assigned record ids, aligned with `records`."""
        tag_batches = {p: [] for p in self.ports}
        rec_batches = {p: [] for p in self.ports}
        rids = []
        for rec in records:
            rid = os.urandom(8).hex()
            rids.append(rid)
            rec_batches[self._node_for(rid)].append([rid, self.keys.encrypt(rec)])
            for field, spec in self.schema.items():
                v = self._encode(field, rec[field])
                for lvl, idx in levels_for(v, spec["bits"], spec["max_level"]):
                    t = self.keys.tag(field, lvl, idx)
                    tag_batches[self._node_for(t)].append([t, rid])
        jobs = [self.pool.submit(self._post, p, "/tags", {"entries": e})
                for p, e in tag_batches.items() if e]
        jobs += [self.pool.submit(self._post, p, "/records", {"entries": e})
                 for p, e in rec_batches.items() if e]
        for j in jobs:
            j.result()
        return rids

    # --- query -----------------------------------------------------
    def query(self, field, lo, hi):
        """All records with lo <= record[field] <= hi (ints), or
        lexicographic prefix-encoded range (strs)."""
        return self._query_encoded(field, self._encode(field, lo),
                                   self._encode(field, hi))

    def _query_encoded(self, field, a, b):
        spec = self.schema[field]
        cover = dyadic_cover(a, b, spec["bits"], spec["max_level"])
        tags = [self.keys.tag(field, lvl, idx) for lvl, idx in cover]

        # fan out exact-match tag lookups to responsible nodes
        by_node = {}
        for t in tags:
            by_node.setdefault(self._node_for(t), []).append(t)
        lookups = {p: self.pool.submit(self._post, p, "/lookup", {"tags": ts})
                   for p, ts in by_node.items()}
        rids = {rid for f in lookups.values() for rid in f.result()["record_ids"]}

        # fetch ciphertexts from wherever they live
        fetch_by_node = {}
        for rid in rids:
            fetch_by_node.setdefault(self._node_for(rid), []).append(rid)
        fetches = [self.pool.submit(self._post, p, "/fetch", {"record_ids": rs})
                   for p, rs in fetch_by_node.items()]
        blobs = {}
        for f in fetches:
            blobs.update(f.result()["records"])

        # decrypt and post-filter (needed when the tree is depth-capped)
        results = []
        for ct in blobs.values():
            rec = self.keys.decrypt(ct)
            if a <= self._encode(field, rec[field]) <= b:
                results.append(rec)
        self.last_stats = {
            "cover_intervals": len(cover), "tags_sent": len(tags),
            "nodes_contacted": len(set(lookups) | {p for p, _ in
                                    zip(fetch_by_node, fetch_by_node)}),
            "candidates_fetched": len(blobs), "results": len(results),
            "overfetch": len(blobs) - len(results),
        }
        return results

    def query_prefix(self, field, prefix):
        a, b = prefix_range(prefix, self.schema[field]["chars"])
        return self._query_encoded(field, a, b)
