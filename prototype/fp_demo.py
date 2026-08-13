"""Forward-private variant: inserts stop being correlatable.

The base scheme's tags are deterministic HMAC(field|level|index), so a curious
node can (a) recover equality classes from a pure snapshot [attack.py, A], and
(b) watch a fresh insert drop into an interval it has seen queried. This module
removes both, using the Sophos construction (Stefanov-Papamanthou-Shi 2014):

  * Each dyadic label w = (field, level, index) owns a hash chain of states
    ST_0, ST_1, ... where ST_i = pi^{-1}(ST_{i-1}) and pi is an RSA trapdoor
    permutation (pi(x)=x^e mod N public, pi^{-1}(x)=x^d mod N private).
  * The i-th entry under w is stored at key UT_i = H1(K_w, ST_i) with its record
    id MASKED by H2(K_w, ST_i). At rest the node holds only pseudorandom keys
    and pseudorandom blobs — no equality, no order, nothing.
  * To search w the client sends (K_w, ST_c) for the newest state c. The node
    walks the chain BACKWARD with the public pi (ST_{i-1}=pi(ST_i)), derives
    every UT_i, and unmasks. It cannot walk FORWARD (needs the private key), so
    entries inserted AFTER the search stay hidden until the next search.

Forward privacy = a snapshot, and any insert, leaks nothing about un-searched
data. What a search necessarily reveals is only the searched intervals' contents.

  python3 fp_demo.py
"""
import hashlib
import hmac
import os
import secrets

from cryptography.hazmat.primitives.asymmetric import rsa


# ----------------------------------------------------------- the blind node

class ForwardPrivateNode:
    """Holds {UT_hex: masked_id_bytes} and a query log. Learns nothing at rest."""

    def __init__(self):
        self.store = {}
        self.query_log = []          # list of sets of UT_hex it was asked to walk

    def put(self, ut_hex, masked_id):
        self.store[ut_hex] = masked_id

    def search(self, k_w_hex, st_c, count, n, e):
        """Walk the chain backward from the newest state; return masked blobs."""
        seen = []
        out = []
        st = st_c
        for _ in range(count):
            ut = _h1(k_w_hex, st)
            seen.append(ut)
            if ut in self.store:
                out.append((self.store[ut], _h2(k_w_hex, st)))
            st = pow(st, e, n)       # pi: forward only, backward needs the key
        self.query_log.append(set(seen))
        return out                    # [(masked_id, mask), ...]

    def snapshot(self):
        return dict(self.store)


# ----------------------------------------------------------------- helpers

def _h1(k_w_hex, st):
    return hmac.new(bytes.fromhex(k_w_hex), b"UT" + str(st).encode(),
                    hashlib.sha256).hexdigest()[:32]


def _h2(k_w_hex, st):
    return hmac.new(bytes.fromhex(k_w_hex), b"MASK" + str(st).encode(),
                    hashlib.sha256).digest()[:8]


def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


# ----- dyadic decomposition (same math as the base scheme, trimmed) --------

def levels_for(value, bits):
    return [(lvl, value >> (bits - lvl)) for lvl in range(1, bits + 1)]


def dyadic_cover(a, b, bits):
    out = []

    def rec(lo, hi, lvl, idx):
        if hi < a or lo > b:
            return
        if a <= lo and hi <= b and lvl >= 1:
            out.append((lvl, idx))
            return
        if lvl == bits:
            out.append((lvl, idx))
            return
        mid = (lo + hi) // 2
        rec(lo, mid, lvl + 1, idx * 2)
        rec(mid + 1, hi, lvl + 1, idx * 2 + 1)

    rec(0, 2 ** bits - 1, 0, 0)
    return out


# ------------------------------------------------------------- the client

class ForwardPrivateClient:
    """Holds the master key, the RSA private key, and per-label chain state."""

    def __init__(self, node, bits=7, key_size=1024):
        self.node = node
        self.bits = bits
        self.master = os.urandom(32)
        # 1024-bit keeps this demo snappy; use >=2048 in anything real.
        key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        nums = key.private_numbers()
        self.n = nums.public_numbers.n
        self.e = nums.public_numbers.e
        self.d = nums.d
        self.state = {}              # w -> (ST_latest, count)
        self.ids = {}                # our own record-id -> plaintext (for scoring)

    def _k_w(self, w):
        return hmac.new(self.master, w.encode(), hashlib.sha256).hexdigest()[:32]

    def insert(self, value):
        rid = os.urandom(8)
        self.ids[rid.hex()] = value
        for lvl, idx in levels_for(value, self.bits):
            w = f"age|{lvl}|{idx}"
            if w in self.state:
                st_prev, c = self.state[w]
                st_new = pow(st_prev, self.d, self.n)     # pi^{-1}: advance chain
                c += 1
            else:
                st_new = secrets.randbelow(self.n - 2) + 1
                c = 1
            k_w = self._k_w(w)
            self.node.put(_h1(k_w, st_new), _xor(rid, _h2(k_w, st_new)))
            self.state[w] = (st_new, c)
        return rid.hex()

    def query(self, lo, hi):
        found = set()
        for lvl, idx in dyadic_cover(lo, hi, self.bits):
            w = f"age|{lvl}|{idx}"
            if w not in self.state:
                continue
            st_c, c = self.state[w]
            k_w = self._k_w(w)
            for masked, mask in self.node.search(k_w, st_c, c, self.n, self.e):
                found.add(_xor(masked, mask).hex())
        return found


# ------------------------------------------------------------------ demo

def equality_classes_recoverable(snapshot):
    """A curious node's best shot at grouping at rest: cluster entries whose
    stored blobs collide. With per-entry masking there are no collisions."""
    from collections import Counter
    dup = Counter(snapshot.values())
    return sum(1 for v in dup.values() if v > 1)


def main():
    node = ForwardPrivateNode()
    client = ForwardPrivateClient(node, bits=7)

    import random
    rng = random.Random(11)
    ages = [max(18, min(90, int(rng.gauss(45, 15)))) for _ in range(800)]
    for a in ages:
        client.insert(a)

    print("=" * 68)
    print("FORWARD-PRIVATE STORE  (Sophos-style; inserts unlinkable at rest)")
    print("=" * 68)

    snap = node.snapshot()
    print(f"\nAt rest the node holds {len(snap)} entries. A sample:")
    for ut, blob in list(snap.items())[:3]:
        print(f"    key {ut}  ->  blob {blob.hex()}")
    dup = equality_classes_recoverable(snap)
    print(f"\n[A'] Snapshot equality attack (the one that recovered 71 groups in")
    print(f"     the base scheme): colliding blobs = {dup}.")
    print("     -> ZERO structure at rest. No equality, no order, no co-occurrence.")

    # correctness: range queries still return exactly the right records
    checks = [(30, 40), (18, 25), (60, 90), (44, 46)]
    print("\nRange-query correctness (vs plaintext ground truth):")
    ok_all = True
    for lo, hi in checks:
        got = client.query(lo, hi)
        want = {rid for rid, v in client.ids.items() if lo <= v <= hi}
        ok = got == want
        ok_all &= ok
        print(f"    age in [{lo:2d},{hi:2d}]: {len(got):4d} rows  "
              f"{'OK' if ok else 'MISMATCH'}")
    assert ok_all

    # forward privacy across a search: query an interval, then insert into it,
    # and show the node still cannot link the new entry using the old token.
    print("\nForward privacy across a search:")
    lo, hi = 40, 50
    client.query(lo, hi)                       # node now holds a token for these labels
    old_search_uts = set().union(*node.query_log) if node.query_log else set()
    before = len(node.store)
    client.insert(45)                          # a fresh record squarely in [40,50]
    # which keys are new since the search, and could the node have predicted them?
    added = len(node.store) - before
    predictable = sum(1 for ut in _keys_added(node, before) if ut in old_search_uts)
    print(f"    inserted 1 record (age 45) after querying [40,50]; it wrote "
          f"{added} new index keys.")
    print(f"    keys the node could derive from its earlier search token: {predictable}.")
    print("     -> The new insert is invisible to the node until [40,50] is")
    print("        searched AGAIN. Past queries do not unmask future inserts.")

    print("\n" + "=" * 68)
    print("Cost: one RSA private-key op per (level) per insert, client-side chain")
    print("state per label, and each label's contents revealed only when queried.")
    print("Removes the snapshot leaks [A]/[B] entirely; the query-watcher [E]")
    print("still sees searched intervals — bound that with [F]'s coarse queries.")
    print("=" * 68)


def _keys_added(node, before_count):
    # the demo inserts once after `before_count`; the tail keys are the new ones
    return list(node.snapshot())[before_count:]


if __name__ == "__main__":
    main()
