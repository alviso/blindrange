"""Blind tokens: charge for writes without learning whose writes they are.

The problem metering creates here is not billing, it is linkage. A network
that can attribute a key to a customer has rebuilt the co-occurrence map
this project exists to destroy, so the obvious implementations — per-tenant
API keys, signed writes, an account id on the wire — cost more than the
revenue is worth. What is needed is a way to prove *this write is paid for*
that carries no trace of who paid.

Chaum blind signatures do exactly that, and the split is the whole idea:

    ISSUANCE is identified.   You sign up, you have a quota, we know how
                              much you were granted.
    REDEMPTION is anonymous.  You spend a token at a node, and nothing
                              about it can be matched to the issuance —
                              not by the node, not by us, not by both
                              together.

The trick is that the issuer never sees what it signs. The client picks a
random nonce, multiplies its hash by r^e for a secret random r, and sends
that. The product is uniformly distributed over the group, so the issuer
learns nothing at all; it returns (m·r^e)^d = m^d·r, and dividing by r
leaves a signature on a nonce the issuer has never seen. When that nonce
later appears at a node, there is no computation anyone can do to connect
it to the account that paid.

Denominations, and why they are separate keys. A token has to be worth a
specific number of keys or a client would write a million of them against
one. But the issuer signs blind, so it cannot put a value *inside* the
message. Instead each denomination gets its own keypair: which public key
verifies a token is what tells you what it is worth. Unlinkability then
holds within a denomination, which is why there are few and they are
coarse — a rare denomination would identify its holder as surely as a name.

Epochs exist so spent-token sets stay finite. Keys rotate, nodes accept
only the current and previous epoch, and a node can drop every spent nonce
from an epoch that no longer verifies.

Honest limits, stated where they will be read:

  * This is textbook Chaum with an MGF1 full-domain hash, not RFC 9474
    (which blinds RSA-PSS). It is a well-understood construction and it is
    NOT independently audited. Treat accordingly.
  * Spent sets are per node. A batch legitimately goes to its whole replica
    group, so a node cannot treat a second sighting as fraud; what this
    does not stop is one token being spent at a *disjoint* set of nodes.
    That is bounded — see the node's redemption accounting — and detected
    in aggregate rather than prevented.
  * The issuer still learns how many tokens an account drew and when.
    Volume and timing are not hidden, only linkage.
"""
import hashlib
import json
import math
import secrets
from base64 import b64decode, b64encode

PUBLIC_EXPONENT = 65537
KEY_BITS = 2048
NONCE_BYTES = 32
MAX_ISSUE_BATCH = 512   # matches the issuer's per-request cap


def mgf1(seed: bytes, length: int) -> bytes:
    out, counter = b"", 0
    while len(out) < length:
        out += hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:length]


def fdh(msg: bytes, n: int) -> int:
    """Full-domain hash into Z_n.

    Hashing straight to 256 bits and reducing would be a mistake, not a
    shortcut: small hash images admit multiplicative forgeries, where an
    attacker combines signatures on values whose product is the target.
    Expanding to nearly the modulus width with MGF1 is what makes the
    one-more-forgery reduction hold.
    """
    bits = n.bit_length() - 1
    nbytes = (bits + 7) // 8
    x = int.from_bytes(mgf1(b"blindrange/token/fdh|" + msg, nbytes), "big")
    return x >> (nbytes * 8 - bits)


def keygen(bits: int = KEY_BITS):
    from cryptography.hazmat.primitives.asymmetric import rsa
    k = rsa.generate_private_key(public_exponent=PUBLIC_EXPONENT,
                                 key_size=bits)
    nums = k.private_numbers()
    pub = k.public_key().public_numbers()
    return {"n": pub.n, "e": pub.e, "d": nums.d}


def blind(nonce: bytes, n: int, e: int):
    """Returns (blinded_int, r). The issuer sees only blinded_int, which is
    uniform over Z_n* and therefore carries no information whatsoever."""
    m = fdh(nonce, n)
    while True:
        r = secrets.randbelow(n - 2) + 2
        if math.gcd(r, n) == 1:
            break
    return (m * pow(r, e, n)) % n, r


def sign_blinded(blinded: int, n: int, d: int) -> int:
    return pow(blinded % n, d, n)


def unblind(blind_sig: int, r: int, n: int) -> int:
    return (blind_sig * pow(r, -1, n)) % n


def verify(nonce: bytes, sig: int, n: int, e: int) -> bool:
    return pow(sig, e, n) == fdh(nonce, n)


# ------------------------------------------------------------------ wire

def key_id(epoch: str, denom: int) -> str:
    return f"{epoch}:{denom}"


def parse_key_id(kid: str):
    epoch, _, denom = kid.rpartition(":")
    return epoch, int(denom)


def encode_token(kid: str, nonce: bytes, sig: int) -> dict:
    size = (KEY_BITS + 7) // 8
    return {"kid": kid, "n": b64encode(nonce).decode(),
            "s": b64encode(sig.to_bytes(size, "big")).decode()}


def decode_token(tok: dict):
    return (tok["kid"], b64decode(tok["n"]),
            int.from_bytes(b64decode(tok["s"]), "big"))


def verify_token(tok: dict, pubkeys: dict):
    """Returns the denomination this token is worth, or None.

    pubkeys maps key_id -> {"n": int, "e": int}. Which key verifies is what
    establishes the value, so an unknown key id is worth nothing rather
    than being taken on trust.
    """
    try:
        kid, nonce, sig = decode_token(tok)
        pk = pubkeys.get(kid)
        if not pk or len(nonce) != NONCE_BYTES:
            return None
        if not verify(nonce, sig, pk["n"], pk["e"]):
            return None
        return parse_key_id(kid)[1]
    except Exception:
        return None


def token_ref(tok: dict) -> str:
    """Short handle a node stores to mark a token spent.

    The nonce itself would do, but a hash keeps the spent set from being a
    list of live bearer instruments — a leaked spent-set should not let
    anyone reconstruct spendable tokens for a node that has not seen them.
    """
    return hashlib.sha256(
        (tok.get("kid", "") + "|" + tok.get("n", "")).encode()).hexdigest()[:32]


# ------------------------------------------------------------------ wallet

class Wallet:
    """A client's unspent tokens, grouped by denomination.

    Deliberately dumb: tokens are bearer instruments, so this is a list of
    secrets and nothing more. It belongs inside the owner's encrypted state
    file for the same reason the master key does.
    """

    def __init__(self, tokens=None):
        self.tokens = list(tokens or [])

    def __len__(self):
        return len(self.tokens)

    def balance(self):
        total = 0
        for t in self.tokens:
            try:
                total += parse_key_id(t["kid"])[1]
            except Exception:
                pass
        return total

    def take(self, need: int):
        """Smallest single token that covers `need` keys, else the largest
        available. Returns None when empty."""
        if not self.tokens:
            return None
        fits = [t for t in self.tokens
                if parse_key_id(t["kid"])[1] >= need]
        pick = (min(fits, key=lambda t: parse_key_id(t["kid"])[1]) if fits
                else max(self.tokens, key=lambda t: parse_key_id(t["kid"])[1]))
        self.tokens.remove(pick)
        return pick

    def take_for(self, need: int):
        """Enough tokens to cover `need` keys, or None if the wallet cannot.

        A write is one request per node and the client batches hard — 33,000
        keys in a single POST is normal — so no single denomination can be
        assumed to cover a request. Paying with a SET of tokens is what makes
        the scheme fit the traffic instead of forcing the client to
        fragment writes to match the money, which would cost throughput and
        leak batch structure to the node.

        Largest-first, then the smallest token that closes the remainder, so
        overpayment is bounded by the smallest denomination held rather than
        by the largest.
        """
        if need <= 0:
            need = 1
        avail = sorted(self.tokens, key=lambda t: -parse_key_id(t["kid"])[1])
        chosen, total = [], 0
        for t in avail:
            if total >= need:
                break
            chosen.append(t)
            total += parse_key_id(t["kid"])[1]
        if total < need:
            return None
        # trade the last (largest) pick down for the smallest that still
        # closes the gap, so a big token is not spent to cover a few keys
        if chosen:
            covered = total - parse_key_id(chosen[-1]["kid"])[1]
            gap = need - covered
            better = [t for t in avail if t not in chosen
                      and parse_key_id(t["kid"])[1] >= gap]
            if better:
                small = min(better, key=lambda t: parse_key_id(t["kid"])[1])
                if parse_key_id(small["kid"])[1] < parse_key_id(chosen[-1]["kid"])[1]:
                    chosen[-1] = small
        for t in chosen:
            self.tokens.remove(t)
        return chosen

    def add(self, tokens):
        self.tokens.extend(tokens)

    def to_json(self):
        return json.dumps(self.tokens)

    @classmethod
    def from_json(cls, raw):
        try:
            return cls(json.loads(raw) if raw else [])
        except ValueError:
            return cls()


def request_tokens(post_json, issuer_addr, account_key, denom, count,
                   pubkeys):
    """Client side of issuance: blind, ask, unblind, verify.

    Verifying our own tokens before storing them is not paranoia about the
    issuer being malicious so much as about it being wrong — a bad batch
    discovered at write time is far more expensive than one discovered here.
    """
    pk = pubkeys[key_id_for(pubkeys, denom)]
    kid = key_id_for(pubkeys, denom)
    nonces, blinds, rs = [], [], []
    for _ in range(count):
        nonce = secrets.token_bytes(NONCE_BYTES)
        b, r = blind(nonce, pk["n"], pk["e"])
        nonces.append(nonce)
        blinds.append(str(b))
        rs.append(r)
    out = post_json(issuer_addr, "/issue",
                    {"account": account_key, "kid": kid, "blinded": blinds})
    tokens = []
    for nonce, r, bs in zip(nonces, rs, out["signed"]):
        sig = unblind(int(bs), r, pk["n"])
        if not verify(nonce, sig, pk["n"], pk["e"]):
            raise ValueError("issuer returned an invalid signature")
        tokens.append(encode_token(kid, nonce, sig))
    return tokens, out.get("remaining")


def key_id_for(pubkeys: dict, denom: int) -> str:
    """Newest epoch offering this denomination."""
    cands = [k for k in pubkeys if parse_key_id(k)[1] == denom]
    if not cands:
        raise ValueError(f"issuer offers no denomination {denom}")
    return max(cands, key=lambda k: parse_key_id(k)[0])
