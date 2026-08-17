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
import math
import os
import random
import ssl
import threading
import time
import urllib.error
import urllib.request
from .transport import POOL
from . import direct as direct_mod
from . import __version__ as VERSION
from . import receipt
from . import token as token_mod
from base64 import b64decode, b64encode
from concurrent.futures import ThreadPoolExecutor, as_completed

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .dyadic import (dyadic_cover, encode_str, levels_for, max_level,
                     prefix_range)
from .ring import Ring, failure_group

# A node applies its own TTL (15s) before serving /peers, so the client
# re-filtering more strictly than that just discards nodes the network still
# considers live. Under write load a busy node's heartbeat can lag several
# seconds; dropping it then shrinks the ring, which makes quorum wait on
# whatever slow node remains — the opposite of what you want under load.
PEER_LIVE_S = 40.0
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
        # Writes fan out across the pool, so the wallet is touched
        # concurrently; without this two threads can hand the same token to
        # two different nodes and the second one is refused as spent.
        self._wallet_lock = threading.Lock()
        self.ring = None
        self.last_stats = {}
        self.write_acks = int(os.environ.get("BR_WRITE_ACKS", "2"))
        self.max_inflight = int(os.environ.get("BR_MAX_INFLIGHT", "64"))
        self._inflight = set()
        self._dialer = None                # lazy QUIC dialer thread
        self._direct = {}                  # node_id -> DirectPath
        self._no_direct_until = {}         # node_id -> retry-after ts
        self.direct_requests = 0           # served over punched QUIC paths
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

    # --------------------------------------------------------------- blobs
    # Records are small and indexed; object bodies are large and never
    # queried. Forcing bytes through insert_many() would build a dyadic
    # index entry per level for content nobody will ever range over —
    # tens of wasted keys per megabyte, paid for at write time and again
    # every month it is stored.
    #
    # A blob is therefore raw KV: one PRF-derived key, one AEAD value, no
    # index. Nodes see exactly what they see for everything else, and the
    # name never travels — only an HMAC of it under a key they do not have.

    BLOB_CHUNK = 512 * 1024

    def _blob_key(self, name, part=0):
        h = hmac.new(self._master, f"blob|{name}|{part}".encode(),
                     hashlib.sha256).hexdigest()[:32]
        return "B:" + h

    def put_blob(self, name, data: bytes):
        """Store opaque bytes under `name`. Returns the number of chunks.

        Chunked so a large object spreads across the ring instead of
        landing whole on one replica set, and so a read can fetch parts in
        parallel. The chunk count is recoverable from the object's own
        record, so nothing here needs an index of its own.
        """
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("put_blob takes bytes")
        data = bytes(data)
        parts = [data[i:i + self.BLOB_CHUNK]
                 for i in range(0, len(data), self.BLOB_CHUNK)] or [b""]
        pairs = []
        for i, chunk in enumerate(parts):
            nonce = os.urandom(12)
            ct = self._aes.encrypt(nonce, chunk, None)
            pairs.append((self._blob_key(name, i),
                          b64encode(nonce + ct).decode()))
        self._put(pairs)
        return len(parts)

    def get_blob(self, name, chunks: int):
        """Reassemble a blob. None if any chunk is missing — a partial
        object is worse than an absent one, so it is never returned."""
        keys = [self._blob_key(name, i) for i in range(max(chunks, 1))]
        got = self._mget(keys)
        out = bytearray()
        for k in keys:
            v = got.get(k)
            if v is None:
                return None
            raw = b64decode(v)
            try:
                out += self._aes.decrypt(raw[:12], raw[12:], None)
            except Exception:
                return None
        return bytes(out)

    def delete_blob(self, name, chunks: int):
        keys = [self._blob_key(name, i) for i in range(max(chunks, 1))]
        for addr in {self._addr(n) for k in keys for n in self.ring.route(k)
                     if self._addr(n)}:
            try:
                self._post(addr, "/delete", {"keys": keys})
            except (OSError, ValueError):
                pass          # replicas that miss it are cleaned by repair

    # -------------------------------------------------------------- tokens
    # A wallet of blind tokens lives in the encrypted state file, for the
    # same reason the master key does: they are bearer instruments, and
    # anyone holding one can spend it. Nothing here identifies the owner —
    # that is the point of the scheme — so a stolen wallet costs capacity,
    # never privacy.

    def configure_tokens(self, issuer, account):
        self._st["issuer"] = issuer.rstrip("/")
        self._st["account"] = account
        self._st.setdefault("wallet", [])
        self._save()

    # The state file is passphrase-derived (scrypt), so writing it costs
    # ~21 ms. Persisting on every spend put that inside the write path,
    # under a lock shared by all threads — measured at ~48 batches/second
    # against ingest that already runs at a thousand records a second. The
    # wallet therefore lives in memory and is checkpointed lazily.
    #
    # Crash exposure is one flush interval of tokens, and it fails in the
    # safe direction: the file can only be STALER than reality, so a lost
    # flush means re-presenting tokens already spent, which nodes refuse.
    # Capacity is lost, never double-charged, and never silently reused.
    WALLET_FLUSH_S = 5.0

    @property
    def _wallet(self):
        if getattr(self, "_wal", None) is None:
            self._wal = token_mod.Wallet(self._st.get("wallet") or [])
            self._wal_dirty = False
            self._wal_flushed = 0.0
        return self._wal

    def _store_wallet(self, wallet, force=False):
        self._wal = wallet
        self._wal_dirty = True
        now = time.time()
        if force or now - getattr(self, "_wal_flushed", 0.0) >= self.WALLET_FLUSH_S:
            self._st["wallet"] = wallet.tokens
            self._save()
            self._wal_dirty = False
            self._wal_flushed = now

    def flush_wallet(self):
        """Checkpoint unspent tokens now. Called on drain() so a clean
        shutdown never loses capacity."""
        with self._wallet_lock:
            if getattr(self, "_wal", None) is not None and self._wal_dirty:
                self._store_wallet(self._wal, force=True)

    def token_balance(self):
        """Keys of write capacity currently held."""
        return self._wallet.balance()

    def _spend_token(self, n_entries):
        """Tokens covering this request, buying more if the wallet is short.

        Returns a LIST: the client batches a whole node's share of a write
        into one request — tens of thousands of keys is routine — so a
        request is paid with a set of tokens rather than one. Splitting
        writes to match denominations instead would cost throughput and
        hand the node a batch structure it has no business seeing.
        """
        if not self._st.get("issuer"):
            return None                      # unmetered network
        with self._wallet_lock:
            w = self._wallet
            need = max(n_entries, 1)
            if w.balance() < need and self._st.get("account"):
                try:
                    self._fetch_tokens(w, need)
                except Exception:
                    pass                     # let the node report the refusal
            toks = w.take_for(need)
            self._store_wallet(w)
            return toks

    def _refund_token(self, toks):
        with self._wallet_lock:
            w = self._wallet
            w.add(toks)
            self._store_wallet(w)

    # Identify the client honestly. urllib's default User-Agent is blocked
    # outright by Cloudflare's bot rules (measured: 403 for
    # "Python-urllib/3.13", 200 for anything else), so an unnamed client
    # fails against any CDN-fronted issuer — including ours.
    USER_AGENT = token_mod.USER_AGENT

    def _issuer_keys(self):
        body = token_mod.fetch_json(self._st["issuer"] + "/keys", timeout=15)
        return {kid: {"n": int(k["n"]), "e": int(k["e"])}
                for kid, k in (body.get("keys") or {}).items()}

    def _issuer_post(self, _addr, path, payload):
        return token_mod.fetch_json(self._st["issuer"] + path, payload,
                                    timeout=30)

    def top_up(self, denom=1000, count=32):
        """Buy write capacity. Blinding happens here, so the issuer sees
        only uniformly random values and cannot connect what it signs to
        anything this database later writes."""
        with self._wallet_lock:
            w = self._wallet
            n = self._fetch_tokens(w, 0, denom=denom, count=count)
            self._store_wallet(w, force=True)     # just paid for these
            return n

    def _fetch_tokens(self, wallet, need, denom=None, count=None):
        pubkeys = self._issuer_keys()
        if denom is None:
            offered = sorted({token_mod.parse_key_id(k)[1] for k in pubkeys})
            denom = next((d for d in offered if d >= max(need, 1)),
                         offered[-1] if offered else 1000)
        if count is None:
            # cover the shortfall plus headroom, in ONE issuance round trip;
            # topping up per request turned a 12,000 rec/s ingest into 5.
            short = max(need - wallet.balance(), 0)
            count = min(token_mod.MAX_ISSUE_BATCH,
                        max(8, -(-short // denom) * 2))
        tokens, _ = token_mod.request_tokens(
            self._issuer_post, None, self._st["account"], denom, count,
            pubkeys)
        wallet.add(tokens)
        return len(tokens)

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
        udp = {}
        answers = 0
        for addr in contacts:
            try:
                peers = self._get(addr, "/peers")["peers"]
                for nid, e in peers.items():
                    if e["age"] <= PEER_LIVE_S:
                        found[nid] = e["addr"]
                        if e.get("udp"):
                            udp[nid] = e["udp"]
                answers += 1
                if answers >= 2:        # merge two views; one may be stale
                    break
            except OSError:
                continue
        if not found:
            raise ConnectionError("no live blindrange node reachable "
                                  f"(tried {contacts})")
        self._addr_of = found
        self._udp_of = udp
        new_ring = Ring(sorted(found), replicas=3,
                        groups={nid: failure_group(a, udp.get(nid, ""))
                                for nid, a in found.items()})
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
        if path == "/kv" and "tokens" not in payload:
            tok = self._spend_token(len(payload.get("entries") or []))
            if tok:
                payload = {**payload, "tokens": tok}
                try:
                    return self._post_inner(addr, path, payload)
                except Exception:
                    # The write did not land, so the token was probably not
                    # redeemed either — put it back rather than burning
                    # paid-for capacity on a network blip. If the node did
                    # spend it and only the reply was lost, the retry is
                    # refused as already-spent, which costs one token and
                    # never double-charges.
                    self._refund_token(tok)
                    raise
        return self._post_inner(addr, path, payload)

    def _post_inner(self, addr, path, payload):
        if path == "/mget" and "nonce" not in payload:
            # Every read asks to be signed, not just audits. The receipt is
            # ignored on the ordinary path; what matters is that a node
            # watching its traffic cannot pick the audits out of it.
            payload = {**payload, "nonce": os.urandom(16).hex()}
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
        """Reach a NAT'd node: over a punched direct QUIC path when one can
        be established, else through its relay ("via:relay-addr/node-id")."""
        relay, _, nid = via_addr[4:].rpartition("/")
        direct = self._direct_path(nid, relay)
        if direct is not None:
            frame = {"m": method, "p": path.split("?")[0],
                     "q": path.partition("?")[2],
                     "b": b64encode(body).decode()}
            payload = body if method == "POST" else \
                path.split("?")[0].encode()
            sig = self._sign(payload)
            if sig:
                frame["a"] = sig["X-BR-Auth"]
            try:
                out = json.loads(direct.request(
                    json.dumps(frame).encode(), timeout=10))
                if out.get("s") == 200:
                    self.direct_requests += 1
                    return json.loads(b64decode(out["b"]))
                raise ConnectionError(f"direct request failed: {out.get('s')}")
            except ConnectionError:
                raise
            except Exception:
                self._drop_direct(nid)     # path died; fall back to relay
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
        """Replicated write that returns once each key has `write_acks`
        confirmations, leaving the rest in flight (hedged writes).

        Every replica is asked at once either way; the question is only how
        many answers we wait for. Waiting for all of them means every batch
        pays the slowest replica — brutal when some replicas are NAT'd and
        reached over a relay. Waiting for one means a write lives on a single
        node until background repair copies it, so an immediate death of that
        node loses it: fine for logs, wrong for a ledger. Two is the default.

        Never zero: galloping discovery assumes chains are dense (entry i
        exists iff i <= end), so a key that landed nowhere would punch a hole
        and hide every later entry in that chain. Keys short of quorum are
        retried on further ring successors, and a key with no ack at all
        raises rather than corrupting the chain.

        Outstanding un-awaited writes are capped, otherwise returning early
        just moves the bottleneck from the network into memory.
        """
        want = max(1, min(int(self.write_acks), self.ring.replicas))
        by_node = {}
        for k, v in kv_pairs:
            for nid in self.ring.route(k):
                addr = self._addr(nid)
                if addr:
                    by_node.setdefault(addr, []).append([k, v])
        jobs = {self.pool.submit(self._post, a, "/kv", {"entries": e}): a
                for a, e in by_node.items()}
        acks = {k: 0 for k, _ in kv_pairs}
        pending = set(jobs)
        for fut in as_completed(jobs):
            pending.discard(fut)
            if _ok(fut) is None:
                continue
            for k, _v in by_node[jobs[fut]]:
                acks[k] += 1
            if all(n >= want for n in acks.values()):
                break                     # quorum reached; rest lands async
        self._track(pending)

        vals = dict(kv_pairs)
        weak = [k for k, n in acks.items() if n < 1]
        for k in weak:                    # nobody has it: must not leave a hole
            for nid in self.ring.route(k, self.ring.replicas + 3):
                addr = self._addr(nid)
                if not addr:
                    continue
                try:
                    self._post(addr, "/kv", {"entries": [[k, vals[k]]]})
                    acks[k] += 1
                    break
                except OSError:
                    continue
        if any(n == 0 for n in acks.values()):
            raise ConnectionError("write not durable: some keys got zero ACKs")

    def _track(self, futures):
        """Keep un-awaited writes bounded so early return cannot balloon."""
        self._inflight = {f for f in getattr(self, "_inflight", set())
                          if not f.done()} | set(futures)
        if len(self._inflight) > self.max_inflight:
            for fut in list(self._inflight):
                _ok(fut)
                self._inflight.discard(fut)
                if len(self._inflight) <= self.max_inflight // 2:
                    break

    def drain(self):
        """Wait for every outstanding background write. Call before you
        measure durability, shut down, or assume full replication."""
        for fut in list(getattr(self, "_inflight", set())):
            _ok(fut)
        self._inflight = set()
        self.flush_wallet()

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

    CHUNK = 4000          # keys per request; see _delete

    def _delete(self, keys):
        """Best-effort removal from every node that might hold the keys.

        Chunked, because compaction hands this every key of an epoch at once:
        a million keys is a ~34MB request that simply times out, and since
        deletion is best-effort the failure is swallowed and the space is
        never reclaimed. That is invisible in a small test and total at
        scale — measured on a live network, a compaction reporting 1,000,000
        entries dropped freed nothing at all.
        """
        PROBE_EXTRA = 3
        keys = list(keys)
        for start in range(0, len(keys), self.CHUNK):
            by_node = {}
            for k in keys[start:start + self.CHUNK]:
                for nid in self.ring.route(k, self.ring.replicas + PROBE_EXTRA):
                    addr = self._addr(nid)
                    if addr:
                        by_node.setdefault(addr, []).append(k)
            jobs = [self.pool.submit(self._post, a, "/delete", {"keys": ks})
                    for a, ks in by_node.items()]
            for j in jobs:
                _ok(j)

    def _mget(self, keys):
        """Replica lookup in two parallel phases, with hedged reads.

        Every replica is asked at once, but we stop waiting the moment every
        requested key has an answer — a slow or relayed replica can no longer
        hold up a query, and it costs no extra requests because they were
        already in flight. Keys nobody answers fall through to a second
        parallel round over further ring successors, covering data written
        under an earlier ring.

        Absence still requires hearing from every replica (one node's "no"
        could just be a node that has not been repaired yet), so existence
        probes do not benefit — hits do, which is where query time goes.

        Read-repair: a key found elsewhere while its current primary
        *answered without it* is rewritten to that primary. A primary that
        merely never replied is left alone, so hedging cannot cause spurious
        repair writes.
        """
        PROBE_EXTRA = 3
        R = self.ring.replicas
        route = {k: [self._addr(n) for n in
                     self.ring.route(k, R + PROBE_EXTRA) if self._addr(n)]
                 for k in keys}
        out, holders, replied = {}, {}, set()

        def fan(lo, hi, pending):
            by_node = {}
            for k in pending:
                for a in route[k][lo:hi]:
                    by_node.setdefault(a, []).append(k)
            jobs = {self.pool.submit(self._post, a, "/mget", {"keys": ks}): a
                    for a, ks in by_node.items()}
            missing = set(pending)
            for fut in as_completed(jobs):
                addr = jobs[fut]
                try:
                    vals = fut.result()["values"]
                except OSError:
                    continue                     # replica down; others cover
                replied.add(addr)
                for k, v in vals.items():
                    out[k] = v
                    holders.setdefault(k, set()).add(addr)
                missing -= set(vals)
                if not missing:
                    return set()                 # hedged: ignore stragglers
            return missing

        missing = fan(0, R, list(keys))
        if missing:
            fan(R, R + PROBE_EXTRA, missing)
        by_primary = {}
        for k in out:
            primary = route[k][0] if route[k] else None
            if (primary and primary in replied
                    and primary not in holders.get(k, ())):
                by_primary.setdefault(primary, []).append([k, out[k]])
        for a, e in by_primary.items():
            self.pool.submit(self._post, a, "/kv", {"entries": e})
        return out

    def _direct_path(self, nid, relay):
        """A cached punched QUIC path to this tenant, dialing once if needed.
        Returns None (and remembers not to retry for a while) on failure."""
        if direct_mod.DISABLED:
            return None
        path = self._direct.get(nid)
        if path is not None:
            return path
        import time as _time
        if _time.time() < self._no_direct_until.get(nid, 0):
            return None
        cands = [c for c in
                 getattr(self, "_udp_of", {}).get(nid, "").split(",") if c]
        if not cands:
            self._no_direct_until[nid] = _time.time() + 60
            return None
        if self._dialer is None:
            self._dialer = direct_mod.Dialer()

        def request_punch(observed):
            # Best effort by definition: if the relay cannot carry the punch
            # request, the dial simply times out and we fall back to the
            # relay path. Raising here only produced "Future exception was
            # never retrieved" noise on a busy network.
            try:
                env = {"to": nid, "id": os.urandom(8).hex(), "method": "POST",
                       "path": "/punch",
                       "body_b64": b64encode(json.dumps(
                           {"udp": observed}).encode()).decode()}
                raw = json.dumps(env).encode()
                POOL.request(relay, "POST", "/relay/send", raw,
                             {"Content-Type": "application/json",
                              **self._sign(raw)}, timeout=15)
            except (OSError, ValueError):
                pass
        for cand in cands:            # LAN candidate first, then public
            try:
                path = self._dialer.dial(cand, relay, request_punch,
                                         timeout=3.0)
                self._direct[nid] = path
                return path
            except Exception:
                continue
        self._no_direct_until[nid] = _time.time() + 300
        return None

    def _drop_direct(self, nid):
        import time as _time
        path = self._direct.pop(nid, None)
        if path is not None:
            path.close()
        self._no_direct_until[nid] = _time.time() + 60

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
    # -------------------------------------------------------- aggregates
    # A leaf label IS a value bucket and a chain's length is how many entries
    # sit in it, so counts and histograms come from index metadata alone —
    # no ciphertext fetched, nothing decrypted. Exact sums are impossible
    # (nodes cannot compute on ciphertext); the approximation's error is
    # bounded by leaf_width, which is the privacy budget you already chose.

    def _chain_lengths(self, field, intervals, writers):
        """{(level, idx): entries} for the given index intervals."""
        gallop, k_ws = {}, {}
        for lvl, idx in intervals:
            w = f"{field}|{lvl}|{idx}"
            k_ws[w] = self._k_w(w)
            for ep in self._epochs():
                for u in writers:
                    gallop[(ep, lvl, idx, u)] = (
                        (lambda i, e=ep, k=k_ws[w], u=u: self._ut(k, e, u, i)),
                        0)
        ends = self._discover_ends(gallop) if gallop else {}
        out = {}
        for (_ep, lvl, idx, _u), c in ends.items():
            out[(lvl, idx)] = out.get((lvl, idx), 0) + c
        return out

    def count(self, field, lo, hi):
        """How many records match, without fetching or decrypting any.

        Costs one batched probe over the range's minimal cover (~2·log2 of
        the domain), so it is cheap however large the answer is.

        Caveats worth knowing: entries deleted since the last compact() are
        still counted (subtract count_deleted() if that matters), a range
        that does not fall on leaf boundaries counts whole edge leaves — the
        same resolution limit that protects the data — and while a
        compaction is in flight both epochs are read, which can double-count.
        """
        spec = self._st["schema"][field]
        mlvl = max_level(spec["bits"], spec.get("leaf_width", 1))
        a, b = self._encode(field, lo), self._encode(field, hi)
        self._refresh_epoch()
        writers = self._refresh_writers()
        cover = dyadic_cover(a, b, spec["bits"], mlvl)
        total = sum(self._chain_lengths(field, cover, writers).values())
        self.last_stats = {"cover": len(cover), "records_fetched": 0,
                           "decrypted": 0}
        return total

    def count_deleted(self):
        """Tombstones not yet reclaimed by compact() — the error bar on
        count() and histogram()."""
        return len(self._refresh_tombs(self._refresh_writers()))

    def histogram(self, field, lo, hi, buckets=None):
        """Distribution over [lo, hi] at leaf granularity, from metadata
        alone. Returns [{"lo", "hi", "count"}] in stored units, ascending.
        `buckets` merges adjacent leaves into at most that many bars."""
        spec = self._st["schema"][field]
        mlvl = max_level(spec["bits"], spec.get("leaf_width", 1))
        w = spec.get("leaf_width", 1)
        a, b = self._encode(field, lo), self._encode(field, hi)
        self._refresh_epoch()
        writers = self._refresh_writers()
        leaves = [(mlvl, idx) for idx in range(a // w, b // w + 1)]
        lengths = self._chain_lengths(field, leaves, writers)
        bars = [{"lo": idx * w, "hi": idx * w + w - 1,
                 "count": lengths.get((mlvl, idx), 0)}
                for _lvl, idx in leaves]
        if buckets and len(bars) > buckets:
            step = math.ceil(len(bars) / buckets)
            bars = [{"lo": grp[0]["lo"], "hi": grp[-1]["hi"],
                     "count": sum(g["count"] for g in grp)}
                    for grp in (bars[i:i + step]
                                for i in range(0, len(bars), step))]
        self.last_stats = {"buckets": len(bars), "records_fetched": 0,
                           "decrypted": 0}
        return bars

    def approx_sum(self, field, lo, hi):
        """Estimate the sum over a range without reading any record.

        Each bucket contributes count × midpoint, so the per-record error is
        at most leaf_width/2 — the resolution you traded away for privacy is
        exactly the error bar. Returns (estimate, worst_case_error, count).
        """
        bars = self.histogram(field, lo, hi)
        n = sum(bar["count"] for bar in bars)
        est = sum(bar["count"] * ((bar["lo"] + bar["hi"]) / 2) for bar in bars)
        half = (self._st["schema"][field].get("leaf_width", 1)) / 2
        return est, n * half, n

    # --------------------------------------------------------- streaming
    def _units(self, field, a, b, ordered):
        """The index intervals to walk for [a,b], in value order.

        Unordered: the minimal dyadic cover — fewest lookups.
        Ordered: every leaf the range touches. Leaves ARE in value order and
        only the key holder knows that order, so walking them left to right
        yields sorted results without the network ever learning an ordering.
        Costs one unit per leaf, so it is bounded by range/leaf_width."""
        spec = self._st["schema"][field]
        mlvl = max_level(spec["bits"], spec.get("leaf_width", 1))
        if not ordered:
            cover = dyadic_cover(a, b, spec["bits"], mlvl)
            width = lambda lvl: 1 << (spec["bits"] - lvl)      # noqa: E731
            return sorted(cover, key=lambda li: li[1] * width(li[0]))
        w = spec.get("leaf_width", 1)
        return [(mlvl, idx) for idx in range(a // w, b // w + 1)]

    def _unit_entries(self, field, units, writers):
        """Gallop and fetch one batch of units; returns record ids found."""
        spec = self._st["schema"][field]
        k_ws = {}
        gallop = {}
        for lvl, idx in units:
            w = f"{field}|{lvl}|{idx}"
            k_ws[w] = self._k_w(w)
            for ep in self._epochs():
                for u in writers:
                    gallop[(ep, w, u)] = (
                        (lambda i, e=ep, k=k_ws[w], u=u: self._ut(k, e, u, i)),
                        0)
        ends = self._discover_ends(gallop) if gallop else {}
        ut_map = {}
        for (ep, w, u), c in ends.items():
            for i in range(1, c + 1):
                ut_map[self._ut(k_ws[w], ep, u, i)] = (k_ws[w], ep, u, i)
        rids = []
        for ut, blob in (self._mget(list(ut_map)) if ut_map else {}).items():
            k_w, ep, u, i = ut_map[ut]
            rid = bytes(x ^ y for x, y in zip(b64decode(blob),
                                              self._mask(k_w, ep, u, i)))
            rids.append(rid.hex())
        return rids

    def query_stream(self, predicates, limit=None, order=None, batch=24,
                     after=None):
        """Yield matching records incrementally, in O(batch) memory.

        Walks ONE driving predicate's intervals — chosen as the most
        selective, using chain lengths already known from probing — and
        checks the other predicates after decryption, which the query path
        does anyway. `order=<field>` yields rows sorted by that field, and
        `order="-<field>"` sorts descending AND walks the range from the
        top — the difference between paying for every leaf in the window
        and stopping at the first one that fills the limit.
        `after` resumes from the cursor carried on a previously yielded row
        (rec["_cursor"]); pass it back to page through a large result.

        Use this for large or unbounded results; query_multi() is faster for
        small ones because it intersects index sets before fetching.
        """
        self._refresh_epoch()
        writers = self._refresh_writers()
        tombs = self._refresh_tombs(writers)
        bounds = []
        for p in predicates:
            spec = self._st["schema"][p["field"]]
            if "prefix" in p:
                lo, hi = prefix_range(p["prefix"], spec["chars"])
            else:
                lo, hi = (self._encode(p["field"], p["lo"]),
                          self._encode(p["field"], p["hi"]))
            bounds.append((p["field"], lo, hi))
        if not bounds:
            raise ValueError("no predicates")

        # `order="-field"` walks the range from the top down. It matters far
        # more than it sounds: an ordered walk costs one lookup per leaf, so
        # "the newest 5 events in the last 25 days" ascending pays for all
        # ~527 leaves in the window before it can know it has the last five.
        # Descending, it stops at the first leaf that fills the limit.
        desc = bool(order) and str(order).startswith("-")
        order_field = str(order)[1:] if desc else order
        driver = order_field or self._cheapest(bounds, writers)
        d_field, d_lo, d_hi = next(b for b in bounds if b[0] == driver)
        units = self._units(d_field, d_lo, d_hi, ordered=bool(order))
        if desc:
            units = list(reversed(units))
        start_unit, seen_in_unit = (after or {}).get("u", 0), \
            (after or {}).get("n", 0)

        yielded = 0
        stats = {"units": len(units), "batches": 0, "fetched": 0}
        for base in range(start_unit, len(units), batch):
            chunk = units[base:base + batch]
            stats["batches"] += 1
            rids = self._unit_entries(d_field, chunk, writers)
            rids = [r for r in rids if r not in tombs]
            blobs = self._mget(["R:" + r for r in rids]) if rids else {}
            stats["fetched"] += len(blobs)
            rows = []
            for key, ct in blobs.items():
                raw = b64decode(ct)
                rec = json.loads(self._aes.decrypt(raw[:12], raw[12:], None))
                if all(lo <= self._encode(f, rec[f]) <= hi
                       for f, lo, hi in bounds if f in rec):
                    rec["_rid"] = key[2:]
                    rows.append(rec)
            # Deterministic order within a batch: cursors index into this
            # list, and replies now arrive in whatever order the network
            # returns them (hedged reads), so the sort must not depend on it.
            if order:
                rows.sort(key=lambda r: (self._encode(order_field,
                                                      r[order_field]),
                                         r["_rid"]), reverse=desc)
            else:
                rows.sort(key=lambda r: r["_rid"])
            for n, rec in enumerate(rows):
                if base == start_unit and n < seen_in_unit:
                    continue                       # already delivered
                rec["_cursor"] = {"u": base, "n": n + 1}
                yield rec
                yielded += 1
                if limit is not None and yielded >= limit:
                    self.last_stats = {**stats, "results": yielded,
                                       "driver": d_field,
                                       "ordered": bool(order)}
                    return
        self.last_stats = {**stats, "results": yielded, "driver": d_field,
                           "ordered": bool(order), "exhausted": True}

    def _cheapest(self, bounds, writers):
        """Pick the predicate with the fewest index entries — chain lengths
        are metadata we already have, so this costs one batched probe."""
        if len(bounds) == 1:
            return bounds[0][0]
        totals = {}
        for field, lo, hi in bounds:
            spec = self._st["schema"][field]
            mlvl = max_level(spec["bits"], spec.get("leaf_width", 1))
            gallop = {}
            for lvl, idx in dyadic_cover(lo, hi, spec["bits"], mlvl):
                w = f"{field}|{lvl}|{idx}"
                k_w = self._k_w(w)
                for ep in self._epochs():
                    for u in writers:
                        gallop[(ep, w, u)] = (
                            (lambda i, e=ep, k=k_w, u=u: self._ut(k, e, u, i)),
                            0)
            ends = self._discover_ends(gallop) if gallop else {}
            totals[field] = sum(ends.values())
        return min(totals, key=totals.get)

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

    def compact(self, resume=False):
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
        writers = self._refresh_writers()
        me = self._st["writer"]

        # An unsealed previous epoch means a compaction opened and never
        # sealed. Until now that was permanent: two epochs exist, every
        # later compact() refused, and the database never reclaimed another
        # byte. It happened for real — the heartbeat was SIGKILLed
        # mid-compaction by a stop timeout and stopped compacting for good,
        # while its store grew all day.
        #
        # Resuming is safe because everything after the slot claim is
        # idempotent by construction: the drain re-walks until two passes
        # agree, the rewrite is keyed by (epoch, writer, index) so redoing
        # it overwrites identical values, and the seal is insert-if-absent.
        # `mine` is the evidence that WE own the unsealed epoch — it is
        # written after winning the slot and cleared after sealing, so a
        # compaction another writer is running is still refused.
        mine = self._st.get("compacting")
        resuming = len(self._epochs()) > 1 and (mine == E or resume)
        if len(self._epochs()) > 1 and not resuming:
            raise RuntimeError(
                f"a compaction is already in flight (epoch {E - 1} opened "
                f"but never sealed). If the process that started it died, "
                f"call compact(resume=True) to finish it — nothing else "
                f"will, and no space is reclaimed until it completes.")

        if resuming:
            # Pick up where it stopped: the epoch below ours is the one
            # left open, and our epoch is the one it was moving into.
            new_E, E = E, E - 1
        else:
            new_E = E + 1
            slot = self._st["epoch_len"] + 1
            if not self._put_nx(self._sys_key(b"epoch", slot),
                                self._sys_encode(f"open:{new_E}")):
                self._refresh_epoch()
                raise RuntimeError("another compaction won the epoch slot")
            self._st["epoch_len"] = slot
            self._st["epoch"] = new_E
            self._st["chains"] = {}
            self._st["compacting"] = new_E
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

        for start in range(0, len(puts), self.CHUNK):
            self._put(puts[start:start + self.CHUNK])
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
        self._st.pop("compacting", None)
        self._save()
        return {"labels": len(new_chains), "entries": kept, "dropped": dropped,
                "resumed": bool(resuming)}


    # ------------------------------------------------------------- audit
    def audit(self, sample=200, timeout=8):
        """Verify what each node ACTUALLY holds, without asking it.

        A node's /stats key count is self-reported and worth nothing the
        moment anything depends on it. This proves possession instead: pick
        records at random, ask each node the ring holds responsible for them
        — that node alone, not the usual replica fan-out — and check the
        answer. Record blobs are AES-GCM, so a returned value either
        decrypts and authenticates or it does not. A node cannot fabricate a
        hit: it cannot derive the key (a PRF of a master key it never sees)
        and it cannot forge the ciphertext.

        Returns per node: how many sampled keys it was responsible for, how
        many it returned, how many verified, its median latency, and what it
        claims to hold — so a claim far above what proofs support is visible.

        Honest limits. This measures only keys THIS database can name, so it
        says nothing about a node's total utilisation; that is only
        estimable by aggregating audits from many owners. And a node that
        fetches a blob from a replica on demand would pass — proving
        possession over time needs repeated audits, not one.
        """
        field = next((n for n, sp in self._st["schema"].items()
                      if sp.get("kind") != "text"), None)
        spec = self._st["schema"][field or next(iter(self._st["schema"]))]
        if field is None:
            field = next(iter(self._st["schema"]))
            pred = {"field": field, "prefix": ""}
        else:
            pred = {"field": field, "lo": 0, "hi": (1 << spec["bits"]) - 1}
        rids = [r["_rid"] for r in self.query_stream([pred], limit=sample)]

        report = {}
        for nid in self.ring.addrs:
            report[nid] = {"addr": self._addr(nid), "responsible": 0,
                           "returned": 0, "verified": 0, "latency_ms": None,
                           "claims": None}
        times = {nid: [] for nid in report}

        # Group the sample by REPLICA SET, and ask every node in a group the
        # identical batch under one shared nonce. Two reasons, and the second
        # is the one that matters. It batches, so an audit is a handful of
        # requests instead of one per key per replica. And it makes each
        # group self-corroborating: nobody picks where a key lives, the ring
        # does, so a made-up key cannot be aimed at a node without landing on
        # its replicas too. A miss counts only when a peer given the same
        # batch produced the data.
        groups = {}
        for rid in rids:
            key = "R:" + rid
            holders = tuple(n for n in self.ring.route(key)
                            if n in report and self._addr(n))
            if holders:
                groups.setdefault(holders, []).append(key)

        proofs = []
        for holders, keys in groups.items():
            nonce = os.urandom(16).hex()
            group = {}
            for nid in holders:
                report[nid]["responsible"] += len(keys)
                t0 = time.time()
                try:
                    out = self._post(self._addr(nid), "/mget",
                                     {"keys": keys, "nonce": nonce})
                except (OSError, ValueError, KeyError):
                    continue
                times[nid].append(((time.time() - t0) * 1000) / max(len(keys), 1))
                got = out.get("values") or {}
                verified = 0
                for key in keys:
                    blob = got.get(key)
                    if blob is None:
                        continue
                    report[nid]["returned"] += 1
                    try:                   # AEAD is the proof
                        raw = b64decode(blob)
                        self._aes.decrypt(raw[:12], raw[12:], None)
                        verified += 1
                    except Exception:
                        pass               # returned something, but not ours
                report[nid]["verified"] += verified
                rec = out.get("receipt")
                if rec and receipt.matches(rec, nonce, keys, got):
                    group[nid] = {"verified": verified, "receipt": rec}
            if len(group) > 1:             # a lone receipt corroborates nothing
                proofs.append(group)
        for nid, r in report.items():
            ts = sorted(times[nid])
            if ts:
                r["latency_ms"] = round(ts[len(ts) // 2], 1)
            try:
                r["claims"] = self._get(r["addr"], "/stats").get("keys")
            except (OSError, ValueError):
                pass
            r["possession"] = (round(r["verified"] / r["responsible"], 4)
                               if r["responsible"] else None)
        return {"sampled_records": len(rids), "nodes": report,
                "proofs": proofs}

    # Sample sizes are fixed, never chosen by the caller, so a report
    # cannot encode how much data the reporter holds.
    # Groups carried per report. Bounds the payload no matter how large
    # the network grows, and keeps every report the same size.
    REPORT_GROUPS = 12
    REPORT_SAMPLE = 100

    def audit_report(self):
        """A publishable audit result that reveals nothing about you.

        Payouts and reputation need to know how well nodes hold data, but a
        naive report — "owner A verified 40,312 keys on nodes X, Y, Z" —
        hands an aggregator exactly the co-occurrence map this project
        destroys. So a report carries:

          * no owner or database identifier, and nothing derived from the
            master key,
          * a FIXED sample size, so the numbers cannot encode how much data
            the reporter stores,
          * rates only — verified out of sampled — never absolute counts.

        What remains is which nodes were sampled, and that is not sensitive
        here: placement is uniform, so any database of real size lands on
        essentially every node. The answer is always "all of them".

        Volume deliberately does not appear. A node's expected share is
        structural — its position on the ring — so it never needs to claim
        anything, and the most forgeable input to a payout simply does not
        exist.

        What makes the report cost something is the last two fields. Each
        group carries the nodes' own signatures over what they were asked
        and what they returned, so the numbers are theirs rather than the
        reporter's; and `pow` is a hash puzzle bound to the exact body,
        which charges the sender without asking who they are. Neither adds
        an identifier, an account, or anything an aggregator could keep and
        correlate later — which is the whole reason it is a puzzle and not
        a login.
        """
        audit = self.audit(sample=self.REPORT_SAMPLE)
        nodes = {}
        for nid, v in audit["nodes"].items():
            if not v["responsible"]:
                continue
            nodes[nid] = {"sampled": v["responsible"],
                          "verified": v["verified"],
                          "latency_ms": v["latency_ms"]}
        # A FIXED number of proof groups, for the same reason the sample
        # size is fixed. Carrying every group made a report grow with the
        # reporter's view of the network, which is both a small leak and —
        # once the public network reached five nodes — larger than the
        # aggregator would accept: submissions started failing with HTTP
        # 413, no proofs were published for hours, and every node's
        # possession quietly expired and took its payout share with it.
        proofs = list(audit.get("proofs", []))
        if len(proofs) > self.REPORT_GROUPS:
            proofs = random.sample(proofs, self.REPORT_GROUPS)
        out = {"kind": "blindrange-audit", "v": 1, "nodes": nodes,
               "proofs": proofs}
        out["pow"] = receipt.solve(out)
        return out

    def drop(self, confirm=False):
        """Remove every key of this database from the network.

        The direct path for "I am finished with this dataset". Deleting the
        rows and compacting would write a tombstone per record, rewrite the
        whole index into a new epoch, and only then delete — far more work
        than deriving every key this database owns and removing it. Nothing
        else can be affected: the keys are PRFs of this master key.

        The .brdb file is left alone; delete it yourself if you want the key
        gone too — but drop first, or the keys stay on the nodes forever
        with no way left to name them.
        """
        if not confirm:
            raise ValueError("drop() erases everything; pass confirm=True")
        writers = self._refresh_writers()
        k_t = self._k_w(TOMB)
        keys, rids = [], set()
        for E in range(0, self._st["epoch"] + 1):
            entries, index_keys = self._walk_epoch(E, writers)
            keys += index_keys
            for lst in entries.values():
                rids.update(lst)
            t_ends = self._discover_ends(
                {u: ((lambda i, e=E, u=u: self._ut(k_t, e, u, i)), 0)
                 for u in writers}) if writers else {}
            for u, c in t_ends.items():
                keys += [self._ut(k_t, E, u, i) for i in range(1, c + 1)]
        keys += ["R:" + r for r in rids]
        keys += [self._sys_key(b"epoch", i)
                 for i in range(1, self._st["epoch_len"] + 1)]
        keys += [self._sys_key(b"registry", i)
                 for i in range(1, self._st["reg_len"] + 1)]
        self._delete(keys)
        return {"keys_removed": len(keys), "records": len(rids)}

    def purge_epochs(self, upto=None):
        """Delete leftover keys from epochs older than the current one.

        Compaction is supposed to remove the epoch it rewrote, but a failed
        or interrupted delete leaves entries nothing points at: no chain
        references them, no reader will ever fetch them, and they occupy
        space forever. They are still findable, because keys are
        deterministic — the same walk compaction used re-derives them, and
        galloping rediscovers the chain lengths precisely because those
        entries are still on the nodes.

        Safe to run any time and safe to repeat: it only ever derives keys
        of THIS database, never touches the current epoch, and finds nothing
        once an epoch is clean.
        """
        self._refresh_epoch()
        writers = self._refresh_writers()
        current = self._st["epoch"]
        last = current - 1 if upto is None else min(int(upto), current - 1)
        k_t = self._k_w(TOMB)
        removed, epochs = 0, []
        for E in range(0, last + 1):
            _entries, keys = self._walk_epoch(E, writers)
            t_ends = self._discover_ends(
                {u: ((lambda i, e=E, u=u: self._ut(k_t, e, u, i)), 0)
                 for u in writers}) if writers else {}
            for u, c in t_ends.items():
                keys += [self._ut(k_t, E, u, i) for i in range(1, c + 1)]
            if keys:
                self._delete(keys)
                removed += len(keys)
                epochs.append(E)
        return {"epochs_purged": epochs, "keys_removed": removed}

    # Orphan sweep tuning. Windows are index counts per probing batch;
    # the tail is how far past the last hit a dense scan keeps looking.
    PURGE_WINDOW = 512
    PURGE_MISS_TAIL = 1024
    PURGE_TIER3_LEVELS = 3
    PURGE_TIER3_STRIDE = 512
    PURGE_TIER3_MAX = 1 << 20
    PURGE_MAX_LABELS = 65_536
    PURGE_FULL_DEPTH = 8

    def purge_orphans(self, verbose=False, everything=False):
        """Find and delete every key a crashed compaction stranded.

        purge_epochs() above re-walks dead epochs the way compaction did,
        and that walk has two blind spots, both created by the crash it is
        cleaning up after:

          * The walk PRUNES: it only descends into children of non-empty
            labels. Compaction deletes top-down, so an interrupted delete
            removes parent chains first — leaving whole child subtrees
            fully intact but unreachable. Nothing is wrong with those
            chains; the walk just never asks about them. Measured on the
            public network, one interrupted compaction stranded roughly
            3.5 million keys this way.
          * Galloping assumes chains are dense. A chain whose prefix was
            deleted before the crash reads as empty from index 1, and its
            surviving tail is invisible.

        This sweep closes both. It enumerates the COMPLETE label set from
        the schema — every dyadic tree node, no pruning, since the label
        space is deterministic and needs no discovery — and gallops every
        (label, writer) chain of every dead epoch. Every non-empty chain
        is then dense-scanned past its discovered end, tolerating holes.
        And the top PURGE_TIER3_LEVELS of each field's tree get a lattice
        probe even when they look empty, because deletion order means the
        one prefix-holed chain is almost always an upper level.

        Stated residual, honestly: a chain BELOW those levels whose prefix
        was deleted and whose tail survives escapes this sweep. Deletion
        order makes that shape vanishingly rare, and a rerun after the
        next compaction will not resurrect it — it stays bounded, not
        growing.

        Blobs: chain values unmask to record ids, so any rid referenced
        only by dead epochs has its blob checked and removed too. Blobs
        of records that were never indexed by a reachable chain cannot be
        named by anyone, this sweep included; that is the price of blobs
        keyed by random handles.

        Refuses while a compaction is in flight, because epoch current-1
        is then still live for readers — finish it first with
        compact(resume=True).
        """
        # `everything=True` is for a database you have already drop()ped:
        # it sweeps LIVE epochs too, protects no rids, and ignores an
        # in-flight compaction — because on a dead database "in flight"
        # only means the crash happened mid-compaction, and resuming a
        # multi-hour rewrite purely to then delete its output would be
        # faithful, expensive nonsense. On a live database this flag is
        # data loss, which is why it is a word you must type and not a
        # fallback the guard quietly takes.
        self._refresh_epoch()
        if not everything and len(self._epochs()) > 1:
            raise RuntimeError(
                "a compaction is in flight (or died mid-flight), so the "
                "previous epoch is still live for readers. Finish it with "
                "compact(resume=True), then purge — or, if this database "
                "was already drop()ped, purge_orphans(everything=True) "
                "sweeps live epochs too.")
        writers = self._refresh_writers() or [self._st["writer"]]
        current = self._st["epoch"]
        if current == 0 and not everything:
            return {"epochs": [], "chain_keys_removed": 0,
                    "blobs_removed": 0, "beyond_gallop": 0,
                    "coverage": "full"}

        say = (lambda *a: print(*a, flush=True)) if verbose else (lambda *a: None)
        live_entries = self._walk_epoch(current, writers)[0]
        live_rids = set()
        if not everything:
            for rids in live_entries.values():
                live_rids.update(rids)

        # Which labels to sweep. A field's full label set is 2^(mlvl+1) —
        # 2,046 for a 22-bit field at leaf 4096, over a million for a
        # 31-bit one. Small trees are enumerated completely, which is the
        # whole point: no pruning, no blind spots. Large trees are swept
        # completely down to PURGE_FULL_DEPTH and guided below it by where
        # the CURRENT epoch holds data — value distributions do not move
        # between epochs of the same database, so dead-epoch keys live
        # under the same subtrees the live ones do. The one shape that
        # escapes guided mode is dead data in a value region the database
        # no longer touches at all, below the fully-swept depth; the
        # result reports which mode ran so nobody mistakes guided for
        # exhaustive.
        occupied = set(live_entries)

        def sweep_labels(field, spec):
            mlvl = max_level(spec["bits"], spec.get("leaf_width", 1))
            total = (1 << (mlvl + 1)) - 2
            if total <= self.PURGE_MAX_LABELS:
                for lvl in range(1, mlvl + 1):
                    for idx in range(1 << lvl):
                        yield f"{field}|{lvl}|{idx}", lvl
                return
            full_depth = self.PURGE_FULL_DEPTH
            for lvl in range(1, full_depth + 1):
                for idx in range(1 << lvl):
                    yield f"{field}|{lvl}|{idx}", lvl
            seen = set()
            for lab in occupied:
                try:
                    f, lvl_s, idx_s = lab.split("|")
                    lvl, idx = int(lvl_s), int(idx_s)
                except ValueError:
                    continue
                if f != field or lvl <= full_depth:
                    continue
                # the occupied label, its ancestors down to full_depth,
                # and its children one level below — the halo where a
                # crashed delete strands neighbours
                for l2, i2 in ([(lvl, idx)]
                               + [(lvl - d, idx >> d)
                                  for d in range(1, lvl - full_depth)]
                               + ([(lvl + 1, idx * 2), (lvl + 1, idx * 2 + 1)]
                                  if lvl < mlvl else [])):
                    if (l2, i2) not in seen:
                        seen.add((l2, i2))
                        yield f"{field}|{l2}|{i2}", l2

        removed = blobs_removed = beyond = 0
        epochs_touched = []
        dead_rids = set()
        coverage = "full"
        for E in range(0, current + (1 if everything else 0)):
            found_keys = []
            for field, spec in list(self._st["schema"].items()) + [(TOMB, None)]:
                if field != TOMB:
                    mlvl = max_level(spec["bits"],
                                     spec.get("leaf_width", 1))
                    if (1 << (mlvl + 1)) - 2 > self.PURGE_MAX_LABELS:
                        coverage = "guided"
                labels = ([(TOMB, 0)] if field == TOMB
                          else list(sweep_labels(field, spec)))
                k_ws = {lab: self._k_w(lab) for lab, _ in labels}
                spec_map = {(lab, u): ((lambda i, k=k_ws[lab], e=E, u=u:
                                        self._ut(k, e, u, i)), 0)
                            for lab, _ in labels for u in writers}
                ends = self._discover_ends(spec_map) if spec_map else {}
                lvl_of = dict(labels)
                for (lab, u), end in ends.items():
                    k_w = k_ws[lab]
                    hits = {}
                    for i in range(1, end + 1):
                        hits[i] = self._ut(k_w, E, u, i)
                    # Tier 2: holes above the galloped end. Non-empty
                    # chains only, so this stays cheap.
                    if end > 0:
                        extra = self._dense_scan(k_w, E, u, start=end + 1)
                        beyond += len(extra)
                        hits.update(extra)
                    # Tier 3: prefix-holed upper levels that look empty.
                    elif lvl_of.get(lab, 99) <= self.PURGE_TIER3_LEVELS:
                        first = self._lattice_probe(k_w, E, u)
                        if first:
                            extra = self._dense_scan(
                                k_w, E, u,
                                start=max(1, first - self.PURGE_TIER3_STRIDE))
                            beyond += len(extra)
                            hits.update(extra)
                    if not hits:
                        continue
                    got = self._mget(list(hits.values()))
                    for i, key in hits.items():
                        v = got.get(key)
                        if v is None:
                            continue
                        found_keys.append(key)
                        if field != TOMB:
                            try:
                                masked = b64decode(v)
                                mask = self._mask(k_w, E, u, i)
                                dead_rids.add(bytes(
                                    x ^ y for x, y in
                                    zip(masked, mask)).hex())
                            except Exception:
                                pass          # junk value; key still dies
            if found_keys:
                epochs_touched.append(E)
                say(f"  epoch {E}: {len(found_keys):,} stranded keys")
                for i in range(0, len(found_keys), self.CHUNK):
                    self._delete(found_keys[i:i + self.CHUNK])
                removed += len(found_keys)

        # Blobs referenced only by dead epochs. Existence-checked first so
        # the count reports what was actually there.
        candidates = ["R:" + r for r in dead_rids - live_rids]
        for i in range(0, len(candidates), self.CHUNK):
            chunk = candidates[i:i + self.CHUNK]
            present = list(self._mget(chunk))
            if present:
                self._delete(present)
                blobs_removed += len(present)
        return {"epochs": epochs_touched, "chain_keys_removed": removed,
                "blobs_removed": blobs_removed, "beyond_gallop": beyond,
                "coverage": coverage}

    def _dense_scan(self, k_w, E, u, start):
        """Window scan that survives holes: keeps going until a full miss
        tail past the last hit, instead of stopping at the first gap."""
        out, i, last_hit = {}, start, start - 1
        while i <= last_hit + self.PURGE_MISS_TAIL:
            window = {self._ut(k_w, E, u, j): j
                      for j in range(i, i + self.PURGE_WINDOW)}
            got = self._mget(list(window))
            for key in got:
                j = window[key]
                out[j] = key
                last_hit = max(last_hit, j)
            i += self.PURGE_WINDOW
        return out

    def _lattice_probe(self, k_w, E, u):
        """Cheapest question first: does ANYTHING survive in this chain?
        Arithmetic-stride probes across the plausible index range; returns
        the first surviving index or None. Deletion goes prefix-first, so
        survivors form a suffix and a stride-width suffix cannot slip
        between probes."""
        idxs = list(range(1, self.PURGE_TIER3_MAX, self.PURGE_TIER3_STRIDE))
        for base in range(0, len(idxs), 4096):
            window = {self._ut(k_w, E, u, j): j
                      for j in idxs[base:base + 4096]}
            got = self._mget(list(window))
            if got:
                return min(window[k] for k in got)
        return None

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
