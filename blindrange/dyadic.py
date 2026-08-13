"""Dyadic-interval math and value encoding. Pure functions, no crypto, no I/O.

A field's index is a binary tree over [0, 2^bits). Depth is capped so leaves
are `leaf_width` wide — the field's structural privacy budget: no tag finer
than a leaf exists, so no observer can ever resolve below it.
"""


def max_level(bits: int, leaf_width: int) -> int:
    if leaf_width < 1 or leaf_width & (leaf_width - 1):
        raise ValueError("leaf_width must be a power of two >= 1")
    lvl = bits - (leaf_width.bit_length() - 1)
    if lvl < 1:
        raise ValueError("leaf_width too large for domain")
    return lvl


def levels_for(value: int, bits: int, mlvl: int):
    """Every stored dyadic interval containing `value` (level, index)."""
    return [(lvl, value >> (bits - lvl)) for lvl in range(1, mlvl + 1)]


def dyadic_cover(a: int, b: int, bits: int, mlvl: int):
    """Minimal stored-interval cover of [a, b]; capped leaves are included on
    overlap (superset semantics — the owner post-filters after decryption)."""
    out = []

    def rec(lo, hi, lvl, idx):
        if hi < a or lo > b:
            return
        if (a <= lo and hi <= b and lvl >= 1) or lvl == mlvl:
            out.append((lvl, idx))
            return
        mid = (lo + hi) // 2
        rec(lo, mid, lvl + 1, idx * 2)
        rec(mid + 1, hi, lvl + 1, idx * 2 + 1)

    rec(0, 2 ** bits - 1, 0, 0)
    return out


# ---------------------------------------------------------- string encoding
# First `chars` characters, 5 bits each (a-z -> 1..26, everything else 0), so
# alphanumeric ranges and prefixes become integer ranges.

def _char5(c: str) -> int:
    c = c.lower()
    return (ord(c) - ord("a") + 1) if "a" <= c <= "z" else 0


def encode_str(s: str, chars: int) -> int:
    v = 0
    for i in range(chars):
        v = (v << 5) | (_char5(s[i]) if i < len(s) else 0)
    return v


def prefix_range(prefix: str, chars: int):
    lo = hi = 0
    for i in range(chars):
        if i < len(prefix):
            lo = (lo << 5) | _char5(prefix[i])
            hi = (hi << 5) | _char5(prefix[i])
        else:
            lo <<= 5
            hi = (hi << 5) | 31
    return lo, hi
