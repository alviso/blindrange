"""An append-only log nobody can quietly rewrite — including us.

Everything else in this project removes a party you would otherwise have to
trust. The payout measurement does not: we compute each node's share, and
if we revised a number afterwards there is nothing an operator could check.
That is a strange gap in a system whose pitch is "you don't have to trust
anyone", and it is the one place we are the trusted party.

A Merkle log closes the part that can be closed. Every accepted audit
report and every share calculation becomes a leaf; the tree head commits to
all of history at once, so changing any past entry changes the head. An
operator who recorded yesterday's head can demand a CONSISTENCY PROOF that
today's head extends it, and an INCLUSION PROOF that their own entry is
still in there. Neither proof can be forged without breaking SHA-256.

Be precise about what this does not do, because "blockchain-adjacent"
invites over-reading:

  * It does not stop us lying at write time. We could decline to log a
    report at all. What it stops is REVISING one after publishing it.
  * It does not by itself stop a SPLIT VIEW — showing one log to you and a
    different one to someone else. That needs the heads to be seen by
    parties who compare notes, which is why nodes record the heads they
    observe and serve them back. Two operators comparing heads is the whole
    detection mechanism, and it costs a GET.
  * It is not consensus and there is no chain. Ordering here is ours to
    choose; the guarantee is only that we cannot change our mind later.

Hashing follows RFC 6962 (Certificate Transparency), including the leaf and
interior prefixes that stop a leaf being reinterpreted as an interior node.
"""
import hashlib

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


def leaf_hash(entry: bytes) -> bytes:
    return hashlib.sha256(LEAF_PREFIX + entry).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def _split(n: int) -> int:
    """Largest power of two strictly less than n — RFC 6962's k."""
    k = 1
    while k << 1 < n:
        k <<= 1
    return k


def root(hashes) -> bytes:
    """Merkle tree head over a list of leaf hashes."""
    n = len(hashes)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return hashes[0]
    k = _split(n)
    return node_hash(root(hashes[:k]), root(hashes[k:]))


def inclusion_proof(hashes, m: int):
    """Audit path proving leaf `m` is in a tree of these leaves."""
    n = len(hashes)
    if not 0 <= m < n:
        raise IndexError("leaf out of range")
    if n == 1:
        return []
    k = _split(n)
    if m < k:
        return inclusion_proof(hashes[:k], m) + [root(hashes[k:])]
    return inclusion_proof(hashes[k:], m - k) + [root(hashes[:k])]


def verify_inclusion(leaf: bytes, m: int, n: int, proof, expect_root: bytes) -> bool:
    """Recompute the head from a leaf and its path. This is what an operator
    runs; it needs the leaf, its position, the tree size and the path — and
    notably not the log's cooperation beyond handing those over."""
    if not 0 <= m < n:
        return False
    h, index, size = leaf, m, n
    for sibling in proof:
        if index % 2 == 1 or index + 1 == size:
            # right-hand child, or the last node of an odd level
            if index % 2 == 0:
                # climb until this node is a right child
                while index % 2 == 0 and size > 1:
                    index //= 2
                    size = (size + 1) // 2
            h = node_hash(sibling, h)
        else:
            h = node_hash(h, sibling)
        index //= 2
        size = (size + 1) // 2
    return h == expect_root and size == 1


def consistency_proof(hashes, m: int):
    """Prove a tree of size m is a prefix of this one (RFC 6962 PROOF)."""
    n = len(hashes)
    if not 0 < m <= n:
        raise IndexError("bad prior size")
    return _subproof(hashes, m, True)


def _subproof(hashes, m: int, at_root: bool):
    n = len(hashes)
    if m == n:
        return [] if at_root else [root(hashes)]
    k = _split(n)
    if m <= k:
        return _subproof(hashes[:k], m, at_root) + [root(hashes[k:])]
    return _subproof(hashes[k:], m - k, False) + [root(hashes[:k])]


def verify_consistency(m: int, old_root: bytes, n: int, new_root: bytes,
                       proof) -> bool:
    """The proof that matters most: today's log still contains yesterday's,
    unchanged. An operator who kept one old head can detect any rewrite of
    anything that came before it."""
    if m < 1 or m > n:
        return False
    if m == n:
        return old_root == new_root and not proof
    proof = list(proof)
    if not proof:
        return False
    # RFC 6962 verification: rebuild both heads from the same path
    if m & (m - 1) == 0:                    # m is a power of two
        proof = [old_root] + proof
    fn, sn = m - 1, n - 1
    while fn % 2 == 1:
        fn //= 2
        sn //= 2
    fr = sr = proof[0]
    for step in proof[1:]:
        if sn == 0:
            return False
        if fn % 2 == 1 or fn == sn:
            fr = node_hash(step, fr)
            sr = node_hash(step, sr)
            while fn != 0 and fn % 2 == 0:
                fn //= 2
                sn //= 2
        else:
            sr = node_hash(sr, step)
        fn //= 2
        sn //= 2
    return sn == 0 and fr == old_root and sr == new_root


class Log:
    """Leaves in memory, head recomputed on demand.

    Recomputation is O(n) per head, which is the wrong shape for a log with
    millions of entries and entirely fine for one that grows by a handful of
    audit reports an hour. Choosing the simple version deliberately: a
    subtly wrong incremental tree would be worse than a slow correct one,
    since the whole value here is that the proofs are checkable.
    """

    def __init__(self, entries=None):
        self.entries = list(entries or [])
        self.hashes = [leaf_hash(e) for e in self.entries]

    def __len__(self):
        return len(self.entries)

    def append(self, entry: bytes) -> int:
        self.entries.append(entry)
        self.hashes.append(leaf_hash(entry))
        return len(self.entries) - 1

    def root(self) -> bytes:
        return root(self.hashes)

    def inclusion(self, m: int):
        return inclusion_proof(self.hashes, m)

    def consistency(self, m: int):
        return consistency_proof(self.hashes, m)
