"""blindrange-node: a distributable blind storage node.

Stores opaque key -> opaque blob in SQLite. Holds no data keys, evaluates no
comparisons, and answers only exact-match lookups. Membership is gossip: to
join, a node needs the address of any one live peer (or none, to start a new
network); to use the network, a client needs the address of any one live node.

Identity: each node generates an Ed25519 keypair on first start (kept in its
data directory). Its node id is a hash of the public key, and every gossip
heartbeat ("I am at <addr> at time <t>") is signed by the node itself and
verified by everyone who relays or receives it. Placement hashes node ids,
so a node can change address without reshuffling data. Identities are cheap
— anyone with the network secret can mint them — and the consequence is
durability, not payouts: earnings require proved possession, so a minted
node has to store what it is sent, but a party holding fraction k of the
ring holds every replica of about k^3 of the keys. Placement therefore
spreads a key's replicas across distinct FAILURE GROUPS (IPv4 /24, or a
tenant's own public endpoint rather than its relay's), reordering only
within the window readers already probe. Measured on 9 nodes where one
party ran 6: fully-captured keys fell from 26.8% to 0.4%.

Self-assembly / NAT: on joining, a node asks a peer to DIAL IT BACK at its
advertised address. If that fails (typical home NAT — no port forwarding),
the node automatically becomes a RELAY TENANT: it keeps an outbound long-poll
open to a reachable peer (its relay) and advertises the address
"via:<relay-addr>/<node-id>". Anyone can reach it by posting an envelope to
the relay, which forwards over the tenant's own outbound connection. Every
reachable node is a relay — the bridge for unconnectable nodes is the network
itself, not a special server (though a dedicated always-on seed works too).
Reachability is re-checked periodically, so nodes move between direct and
tenant mode as their connectivity changes. Tenants still dial OUT directly
for gossip and repair; only inbound traffic uses the relay.

Self-healing: a background thread continuously walks this node's keys in
small batches and re-pushes each to the key's current replica set — so data
migrates to new nodes and replication heals after churn without any owner
involvement. Rate is tunable (BR_REPAIR_EVERY seconds, BR_REPAIR_BATCH keys).

  blindrange-node --port 7501 --data ~/.blindrange/n1 \
      [--seed host:port ...] [--secret <network-secret>] \
      [--host 0.0.0.0 --advertise 192.168.1.20:7501]

Transparency: GET /intel shows a sample of everything this operator can see.
"""
import argparse
import concurrent.futures
import hashlib
import hmac
import json
import os
import random
import shutil
import sqlite3
import sys
import threading
import time
from base64 import b64decode, b64encode
from collections import Counter, deque
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import urllib.request
from urllib.parse import parse_qs, urlparse

from .transport import POOL

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)

from .ring import Ring, failure_group
from . import direct as direct_mod
from . import receipt
from . import token as tok_mod
from . import __version__ as VERSION

GOSSIP_EVERY = 2.0        # seconds between gossip rounds
PEER_TTL = 15.0           # drop peers silent for this long
REPAIR_EVERY = float(os.environ.get("BR_REPAIR_EVERY", "5"))
REPAIR_BATCH = int(os.environ.get("BR_REPAIR_BATCH", "0"))   # 0 = adaptive
# A fixed batch size silently stops being repair once a store is large: 200
# keys every 5s is a full sweep in minutes at test scale and in *days* at
# nine million keys, so a node that falls behind never catches up. Size the
# batch from the store instead, targeting a complete sweep in this many
# hours.
REPAIR_SWEEP_H = float(os.environ.get("BR_REPAIR_SWEEP_H", "3"))
# A three-hour sweep is right for maintenance and far too slow for backfill.
# Measured when a fourth node joined: it gained 54 keys/s against peers at
# 1.6M, an eight-hour convergence — while a single batch to that same node
# went through at 32,000 keys/s, so repair was using half a percent of the
# link. When a peer is visibly behind, sweep on this schedule instead.
REPAIR_CATCHUP_H = float(os.environ.get("BR_REPAIR_CATCHUP_H", "0.25"))
REPAIR_BEHIND_RATIO = float(os.environ.get("BR_REPAIR_BEHIND_RATIO", "0.9"))
REPAIR_PEER_POLL = float(os.environ.get("BR_REPAIR_PEER_POLL", "60"))
REPAIR_BATCH_MAX = int(os.environ.get("BR_REPAIR_BATCH_MAX", "20000"))
# Entries per POST. The sweep batch is how much we *scan*; this is how much
# goes on the wire at once. They stopped being the same number the moment
# catch-up sweeps started sizing batches for a whole store.
REPAIR_POST_MAX = int(os.environ.get("BR_REPAIR_POST_MAX", "2000"))
_repair_fail = {}                  # addr -> (consecutive failures, last log)
# How often repair says what it is doing. It used to say nothing at all
# unless a post failed, so "repair is running" and "repair is delivering
# nothing" produced identical logs — which is exactly the state the network
# was in while a node sat 900k keys behind.
REPAIR_LOG_EVERY = float(os.environ.get("BR_REPAIR_LOG_EVERY", "60"))
# Peers are pushed to concurrently. Serially, a round took ~20s against a
# 5s interval — measured on the public network, where posting a catch-up
# batch to three peers meant three sequential relay round trips and the
# sweep spent most of its time waiting rather than scanning. Peers are
# independent, so there is nothing to order between them; chunks WITHIN a
# peer stay sequential, so one slow node still gets a coherent stream and
# one failure still stops that peer rather than hammering it.
REPAIR_FANOUT = int(os.environ.get("BR_REPAIR_FANOUT", "4"))
# Reconciliation. A bucket is the first BUCKET_CHARS of a key, so with the
# `I:`/`R:` tag plus three hex digits there are ~4k buckets per tag and a
# few hundred keys in each — small enough that exchanging a bucket's key
# list is cheap, large enough that the list of buckets stays short.
BUCKET_CHARS = int(os.environ.get("BR_BUCKET_CHARS", "0"))   # 0 = by size
# Aim for this many keys in a bucket. Granularity is the whole economics of
# reconciliation: too coarse and a mismatched bucket drags along thousands
# of keys the peer already has; too fine and we spend a round trip per key.
# A fixed five characters was right for a 3.9M-key store and hopeless for a
# small one, where it meant roughly one key per bucket.
BUCKET_TARGET = int(os.environ.get("BR_BUCKET_TARGET", "200"))
BUCKET_CACHE_S = float(os.environ.get("BR_BUCKET_CACHE_S", "60"))
BUCKET_SEND_MAX = int(os.environ.get("BR_BUCKET_SEND_MAX", "5000"))
# Buckets reconciled per peer per round. Bounded so one enormous gap cannot
# monopolise a sweep, and so the round still ends in seconds.
RECONCILE_BUCKETS = int(os.environ.get("BR_RECONCILE_BUCKETS", "400"))
RECONCILE_KEYS = int(os.environ.get("BR_RECONCILE_KEYS", "50000"))
_repair_stat_lock = threading.Lock()
REPAIR_SETTLE = 10.0      # don't repair while membership is still changing
DIALBACK_EVERY = float(os.environ.get("BR_DIALBACK_EVERY", "60"))
DIALBACK_FIRST = float(os.environ.get("BR_DIALBACK_FIRST", "4"))
POLL_WAIT = 20.0          # relay parks a tenant's poll this long
SEND_WAIT = 15.0          # relay waits this long for a tenant's reply
TENANT_FRESH = 45.0       # tenant counts as connected if polled this recently
CACHE_KB = int(os.environ.get("BR_CACHE_KB", "32000"))   # SQLite page cache
UPDATE_EVERY = float(os.environ.get("BR_UPDATE_EVERY", "300"))   # 5 min
# An update must never land in the middle of someone's write. A node that
# vanished mid-ingest once cost a 1M-record benchmark at 620k, so a pending
# restart waits for the data path to go quiet — but not forever, because a
# node that is always busy would otherwise never update at all.
# Consecutive one-second samples with nothing in flight before restarting.
# Two is enough to land between requests without waiting for silence that a
# busy node will never produce.
UPDATE_IDLE_SAMPLES = int(os.environ.get("BR_UPDATE_IDLE_SAMPLES", "2"))
BIND_RETRY_S = int(os.environ.get("BR_BIND_RETRY_S", "15"))
VACUUM_EVERY = float(os.environ.get("BR_VACUUM_EVERY", "300"))
# Reclaim in slices. A full VACUUM rewrites the file and locks the database
# for as long as that takes, which on a gigabyte store is tens of seconds of
# a node being unavailable. Incremental gives the space back a few thousand
# pages at a time without ever blocking a request for long.
VACUUM_PAGES = int(os.environ.get("BR_VACUUM_PAGES", "2000"))


def parse_size(spec, total=None):
    """'10GB', '500M', '5%' -> bytes. None/'' means no limit.

    Percentages are of the filesystem the data lives on, because that is how
    someone donating spare capacity actually thinks about it — "you can have
    a tenth of this disk", not "you can have 43 GB".
    """
    if not spec:
        return None
    t = str(spec).strip().upper().replace(" ", "")
    if t.endswith("%"):
        if not total:
            raise ValueError("percentage needs a filesystem to measure")
        return int(total * float(t[:-1]) / 100)
    mult = 1
    for suffix, m in (("TB", 1 << 40), ("GB", 1 << 30), ("MB", 1 << 20),
                      ("KB", 1 << 10), ("T", 1 << 40), ("G", 1 << 30),
                      ("M", 1 << 20), ("K", 1 << 10), ("B", 1)):
        if t.endswith(suffix):
            t, mult = t[:-len(suffix)], m
            break
    return int(float(t) * mult)


def human_size(n):
    if n is None:
        return "unlimited"
    for unit, div in (("TB", 1 << 40), ("GB", 1 << 30), ("MB", 1 << 20)):
        if n >= div:
            return f"{n / div:.1f} {unit}"
    return f"{n / 1024:.0f} KB"
UPDATE_MAX_DEFER = float(os.environ.get("BR_UPDATE_MAX_DEFER", "3600"))


_UPDATE_BROKEN = [""]
UPDATE_BLOCKED_REASON = [""]      # surfaced in /stats and on the status page
_INFLIGHT = [0]
_LAST_OP = [0.0]
_OP_LOCK = threading.Lock()
# Only the client data path counts. Gossip and heartbeats never stop, a
# relay tenant's long-poll is open by definition, and repair is internal and
# resumable from its cursor — counting any of them would mean "busy" is
# always true and the node would never update.
DATA_PATHS = ("/kv", "/mget", "/delete")


class _op:
    def __enter__(self):
        with _OP_LOCK:
            _INFLIGHT[0] += 1
        return self

    def __exit__(self, *exc):
        with _OP_LOCK:
            _INFLIGHT[0] -= 1
            _LAST_OP[0] = time.time()
        return False


def data_path_busy():
    """True while a client operation is actually in flight.

    Deliberately NOT "and nothing finished recently". That version also
    required a quiet window since the last completed request, which sounds
    safer and is worse: a node under any steady traffic never sees the
    window clear, so it deferred for the full hour and then restarted
    anyway — at an arbitrary moment rather than a chosen one, having logged
    "deferred 240s, 0 operation(s) in flight" the whole time.

    What actually matters is not restarting mid-request. With nothing in
    flight there is no request to interrupt: the next one arrives at a
    closed port for the length of an exec, and hedged writes and replicas
    already cover that. The caller waits for a couple of consecutive idle
    samples so it lands between requests rather than inside one.
    """
    with _OP_LOCK:
        return _INFLIGHT[0] > 0


def _git(*args):
    try:
        import subprocess
        repo = Path(__file__).resolve().parent.parent
        out = subprocess.run(["git", "-C", str(repo), *args],
                             capture_output=True, text=True, timeout=5)
        return out.stdout.strip() if out.returncode == 0 else ""
    except Exception:
        return ""


def _read_version():
    """Version of the code THIS PROCESS loaded.

    Captured once at import, never re-read: the checkout can move under a
    running process (that is exactly what auto-update does), and a node that
    reports its working tree rather than its running code makes the whole
    'who is behind' question useless.

    build is the commit count — an integer that increases along a
    fast-forward history. Commit hashes have no order, so comparing version
    strings silently ranks a1b2c3 above 9f8e7d.
    """
    commit = _git("rev-parse", "--short", "HEAD")
    count = _git("rev-list", "--count", "HEAD")
    # A commit hash describes the checkout, not necessarily the code that
    # got imported: start a node with edits in the working tree and it
    # reports the last commit while running something else entirely. That
    # is exactly how a node appeared to be missing a fix it actually had.
    # Tracked files only — an untracked data directory next to the source
    # is normal and says nothing about which code is running.
    dirty = bool(_git("status", "--porcelain", "--untracked-files=no"))
    ver = f"{VERSION}+{commit}" if commit else VERSION
    return (ver + ("+dirty" if dirty else ""),
            int(count) if count.isdigit() else 0)


VERSION_STR, BUILD = _read_version()
RUNNING_COMMIT = _git("rev-parse", "HEAD")   # the code THIS process imported


def code_version():
    return VERSION_STR


def _update_loop(secret):
    """Opt-in self-update: fast-forward this checkout and come back on the
    new code — by replacing this process on Unix, or by asking the
    supervisor to relaunch it on Windows.

    This is a real trust decision, not a convenience: a node running with
    --auto-update will run whatever the configured remote publishes next.
    That is reasonable for a network whose operator also maintains the code
    (our public demo network) and unreasonable for volunteers who don't know
    the maintainer. Hence: opt-in, never a default.
    """
    import subprocess
    repo = str(Path(__file__).resolve().parent.parent)
    while True:
        time.sleep(UPDATE_EVERY + random.random() * 30)   # stagger the fleet
        try:
            pull = subprocess.run(["git", "-C", repo, "pull", "--ff-only"],
                                  capture_output=True, text=True, timeout=120)
            if pull.returncode != 0:
                # Say why, once. Silence here meant a node ran stale code for
                # a day with --auto-update set and looked configured
                # correctly: the service sandbox made its own checkout
                # read-only, the pull failed every time, and nothing was
                # logged. A node that cannot update must be noisy about it.
                why = (pull.stderr or pull.stdout or "").strip().splitlines()
                msg = why[-1] if why else f"git exited {pull.returncode}"
                # Also publish it. A warning that only reaches the journal
                # is one nobody reads: this node sat three versions behind
                # for an hour having said so once, an hour earlier, while
                # the dashboard showed a cheerful "behind" and no reason.
                UPDATE_BLOCKED_REASON[0] = msg
                if _UPDATE_BROKEN[0] != msg:
                    _UPDATE_BROKEN[0] = msg
                    print(f"auto-update BLOCKED: {msg} "
                          f"(repo {repo}) — this node will not self-update",
                          file=sys.stderr, flush=True)
                continue
            _UPDATE_BROKEN[0] = ""
            UPDATE_BLOCKED_REASON[0] = ""
            after = subprocess.run(["git", "-C", repo, "rev-parse", "HEAD"],
                                   capture_output=True, text=True,
                                   timeout=20).stdout.strip()
            # Compare against the code this PROCESS imported, not against HEAD
            # before the pull. Those differ whenever the checkout moved by any
            # other route — a maintainer committing locally, an operator
            # running `git pull` by hand — and then the pull is a no-op,
            # before == after, and the node serves stale code indefinitely
            # while still reporting itself as merely 'behind'. A node stuck
            # that way now proves nothing and earns nothing, so silently
            # never restarting is expensive.
            if after and RUNNING_COMMIT and after != RUNNING_COMMIT:
                print(f"auto-update: {RUNNING_COMMIT[:8]} -> {after[:8]}, "
                      f"restarting",
                      file=sys.stderr, flush=True)
                # Two ways back, by platform. On Unix, execv replaces this
                # process in place — a node started by hand in a terminal
                # must not simply vanish, which is how a live network once
                # lost two of three nodes mid-benchmark. Windows has no such
                # call, so there a parent process supervises and this one
                # exits with an agreed code for it to act on.
                #
                # Wait for the data path to go quiet. A restart between
                # requests is invisible; one in the middle of a write makes
                # the client retry and, at scale, can fail a long ingest.
                waited, idle_runs = 0.0, 0
                while waited < UPDATE_MAX_DEFER:
                    if data_path_busy():
                        idle_runs = 0
                    else:
                        idle_runs += 1
                        if idle_runs >= UPDATE_IDLE_SAMPLES:
                            break
                    if waited and waited % 60 < 2:
                        print(f"auto-update: deferred {int(waited)}s, "
                              f"{_INFLIGHT[0]} operation(s) in flight",
                              file=sys.stderr, flush=True)
                    time.sleep(1)
                    waited += 1
                if waited >= UPDATE_MAX_DEFER:
                    print(f"auto-update: proceeding after {int(waited)}s of "
                          f"continuous traffic — replicas and client retries "
                          f"cover the gap", file=sys.stderr, flush=True)
                elif waited:
                    print(f"auto-update: data path quiet after {int(waited)}s",
                          file=sys.stderr, flush=True)
                sys.stdout.flush()
                sys.stderr.flush()
                # Preserve HOW we were started. Under `python -m pkg.mod`,
                # sys.argv[0] is the module's file path, so re-execing it
                # directly runs the file as a top-level script and every
                # relative import fails. __main__.__spec__ carries the module
                # name precisely for this.
                spec = getattr(sys.modules.get("__main__"), "__spec__", None)
                if spec is not None:
                    args = [sys.executable, "-m", spec.name] + sys.argv[1:]
                else:
                    args = [sys.executable] + sys.argv
                if supervised():
                    # Under the Windows supervisor: exit with the agreed
                    # code and let the parent relaunch us. Spawning a
                    # replacement from here instead left the new node
                    # running while PowerShell took its prompt back — the
                    # node looked dead, Ctrl+C no longer reached it, and
                    # closing the window orphaned it.
                    os._exit(RESTART_CODE)
                os.execv(sys.executable, args)
        except Exception:
            continue


def is_via(addr: str) -> bool:
    return addr.startswith("via:")


def parse_via(addr: str):
    """"via:host:port/node_id" -> (relay_addr, node_id)"""
    rest = addr[4:]
    relay, _, nid = rest.rpartition("/")
    return relay, nid


class Identity:
    def __init__(self, data_dir):
        path = os.path.join(data_dir, "node.key")
        if os.path.exists(path):
            with open(path, "rb") as f:
                self.priv = Ed25519PrivateKey.from_private_bytes(f.read())
        else:
            self.priv = Ed25519PrivateKey.generate()
            raw = self.priv.private_bytes(
                serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                serialization.NoEncryption())
            with open(path, "wb") as f:
                os.fchmod(f.fileno(), 0o600) if hasattr(os, "fchmod") else None
                f.write(raw)
        self.pub_raw = self.priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.node_id = hashlib.sha256(self.pub_raw).hexdigest()[:16]

    def heartbeat(self, addr, udp=""):
        ts = int(time.time() * 1000)
        msg = f"{addr}|{udp}|{ts}".encode()
        return {"addr": addr, "udp": udp, "ts": ts, "pub": self.pub_raw.hex(),
                "sig": self.priv.sign(msg).hex()}

    def poll_token(self):
        ts = int(time.time() * 1000)
        return {"node_id": self.node_id, "ts": ts, "pub": self.pub_raw.hex(),
                "sig": self.priv.sign(f"poll|{ts}".encode()).hex()}


def verify_entry(node_id, e):
    """A peer entry is only accepted if its own key signed it."""
    try:
        pub_raw = bytes.fromhex(e["pub"])
        if hashlib.sha256(pub_raw).hexdigest()[:16] != node_id:
            return False
        Ed25519PublicKey.from_public_bytes(pub_raw).verify(
            bytes.fromhex(e["sig"]),
            f"{e['addr']}|{e.get('udp', '')}|{e['ts']}".encode())
        return True
    except Exception:
        return False


def verify_poll_token(tok):
    try:
        pub_raw = bytes.fromhex(tok["pub"])
        if hashlib.sha256(pub_raw).hexdigest()[:16] != tok["node_id"]:
            return False
        if abs(time.time() * 1000 - tok["ts"]) > 30_000:
            return False
        Ed25519PublicKey.from_public_bytes(pub_raw).verify(
            bytes.fromhex(tok["sig"]), f"poll|{tok['ts']}".encode())
        return True
    except Exception:
        return False


class TokenGate:
    """Decides whether a write is paid for, learning nothing about who paid.

    A node holds only the issuer's PUBLIC keys, so it can tell that a token
    is genuine and what it is worth, and can tell nothing else — not the
    account, not the grant, not whether two tokens came from the same
    wallet. Verification is local arithmetic; the issuer is contacted for
    key material and never for a spend.

    Two exemptions, both necessary and both bounded. Node-to-node repair is
    exempt, because the network heals itself continuously and charging a
    node to hold up its own replicas would make replication a billable
    event; that path is authenticated by the writing node's Ed25519
    identity, not by anything a client can mint. And a node with no issuer
    configured charges nothing at all, which is what keeps a private
    network private and a test network cheap.
    """

    def __init__(self, issuer_url, store):
        self.issuer = issuer_url.rstrip("/")
        self.store = store
        self.lock = threading.Lock()
        self.pubkeys = {}
        self.epochs = set()
        self.redeemed = 0          # tokens accepted since start, for /stats

    def refresh(self):
        try:
            body = tok_mod.fetch_json(self.issuer + "/keys", timeout=10)
        except (OSError, ValueError) as e:
            # Worth a line in the log: a node that cannot fetch keys fails
            # OPEN, so this is the difference between metered and not.
            print(f"issuer key fetch failed ({self.issuer}): {e}",
                  file=sys.stderr, flush=True)
            return False
        keys = {}
        for kid, k in (body.get("keys") or {}).items():
            try:
                keys[kid] = {"n": int(k["n"]), "e": int(k["e"])}
            except (KeyError, ValueError, TypeError):
                continue
        if not keys:
            return False
        with self.lock:
            self.pubkeys = keys
            self.epochs = {tok_mod.parse_key_id(k)[0] for k in keys}
        # Anything signed under a key we no longer accept can never be
        # spent again, so its spend records are dead weight. This is the
        # whole reason keys rotate by epoch.
        self.store.forget_epochs(self.epochs)
        return True

    def check(self, data, n_entries):
        """(ok, http_status, reason)."""
        node_tok = data.get("node_token")
        if isinstance(node_tok, dict) and verify_poll_token(node_tok):
            return True, 200, "repair"
        with self.lock:
            pubkeys = dict(self.pubkeys)
        if not pubkeys:
            # Fail OPEN when key material is missing. A node that cannot
            # reach the issuer is not evidence that a write is unpaid, and
            # refusing writes would turn a billing outage into a data
            # outage — the wrong failure for the party who did nothing
            # wrong.
            return True, 200, "no issuer keys"
        toks = data.get("tokens")
        if isinstance(data.get("token"), dict):     # single-token form
            toks = [data["token"]]
        if not isinstance(toks, list) or not toks:
            return False, 402, "write requires a token"
        if len(toks) > 512:
            return False, 402, "too many tokens"
        # Verify everything BEFORE spending anything: a batch that is going
        # to be refused should not burn the tokens that were valid.
        value = 0
        for t in toks:
            if not isinstance(t, dict):
                return False, 402, "malformed token"
            denom = tok_mod.verify_token(t, pubkeys)
            if denom is None:
                return False, 402, "token invalid or unknown denomination"
            value += denom
        if value < n_entries:
            return False, 402, (f"tokens cover {value} keys, "
                                f"batch has {n_entries}")
        refs = {tok_mod.token_ref(t) for t in toks}
        if len(refs) != len(toks):
            return False, 402, "duplicate token in one request"
        for t in toks:
            epoch = tok_mod.parse_key_id(t.get("kid", ""))[0]
            if not self.store.spend(tok_mod.token_ref(t), epoch):
                return False, 402, "token already spent"
        with self.lock:
            self.redeemed += len(toks)
        return True, 200, "paid"


def _token_key_loop(gate):
    while True:
        gate.refresh()
        time.sleep(300 + random.random() * 60)


GATE = None          # set at startup when --issuer is configured


class Store:
    def __init__(self, path, cap_bytes=None):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.path = path
        self.cap_bytes = cap_bytes
        self.lock = threading.Lock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        # INCREMENTAL before any table exists, so a NEW store can hand space
        # back without a rewrite. Measured on a live node before this: 81% of
        # a 1 GB file was free pages SQLite would reuse but never release, so
        # the operator's disk showed five times the live data — which makes
        # any disk cap they set wrong by the same factor.
        self.db.execute("PRAGMA auto_vacuum=INCREMENTAL")
        self.db.execute("PRAGMA journal_mode=WAL")
        # Keys are pseudorandom, so writes land all over the B-tree — the
        # page cache is what keeps that from degrading as the table grows
        # (measured: 3x more write throughput at scale). synchronous=NORMAL
        # can lose the last commits on power loss but cannot corrupt; with
        # replication and background repair the network heals that, and the
        # alternative is fsyncing every batch.
        self.db.execute(f"PRAGMA cache_size=-{CACHE_KB}")
        self.db.execute("PRAGMA synchronous=NORMAL")
        # WITHOUT ROWID stores rows in the key's own B-tree instead of
        # maintaining a second index into a rowid table. Only applies to
        # tables created from now on; existing node stores keep their shape
        # and stay perfectly readable.
        self.db.execute("CREATE TABLE IF NOT EXISTS kv "
                        "(k TEXT PRIMARY KEY, v TEXT) WITHOUT ROWID")
        # Spent blind tokens. Holds a hash of the token, never the token, so
        # a leaked spent-set is not a bag of bearer instruments. Rows are
        # dropped wholesale once their key epoch stops verifying, which is
        # the only reason epochs exist.
        self.db.execute("CREATE TABLE IF NOT EXISTS spent "
                        "(ref TEXT PRIMARY KEY, epoch TEXT, ts INT) "
                        "WITHOUT ROWID")
        # Small durable scratchpad. Today it holds the repair cursor, which
        # has to outlive the process: see _repair_loop.
        self.db.execute("CREATE TABLE IF NOT EXISTS meta "
                        "(k TEXT PRIMARY KEY, v TEXT) WITHOUT ROWID")
        self.db.commit()
        # Cumulative, never reset. A rate is the consumer's job: two
        # samples and a clock beat a counter that decays on its own, and it
        # means a restart shows as a visible discontinuity rather than a
        # quiet lie about how busy the node has been.
        self.read_batches = 0
        self.writes = 0
        self.deletes = 0
        self._buckets = None          # (computed_at, nchars, {prefix: count})

    def bucket_chars(self, target=BUCKET_TARGET):
        """How many leading characters make a bucket, for this store's size.

        Keys are a two-character tag plus uniform hex, so each extra
        character divides the space by sixteen. Both sides must agree, so
        the node that starts a reconciliation picks and the other answers at
        whatever granularity it was asked for.
        """
        if BUCKET_CHARS:
            return BUCKET_CHARS
        n, chars = max(1, self.count()), 2
        while n / (16 ** (chars - 2)) > target and chars < 8:
            chars += 1
        return chars

    def bucket_counts(self, nchars=None, max_age=BUCKET_CACHE_S):
        nchars = nchars or self.bucket_chars()
        """How many keys sit under each key prefix.

        Buckets are PREFIXES OF THE KEY, which is the whole trick. Keys are
        `I:<hex>` and `R:<hex>` — uniform after the tag — so a bucket is a
        contiguous range of the primary key and every question about it is
        answered by the index the table already has. No extra column, no
        extra index, and nothing to migrate on a store already holding
        millions of rows.

        The GROUP BY still walks the table, so the answer is cached: it is
        wanted once per reconciliation, not once per round.
        """
        now = time.time()
        got = self._buckets
        if got and got[1] == nchars and now - got[0] < max_age:
            return got[2]
        # Deliberately NOT `GROUP BY substr(k,1,n)`. That plan is
        # "USE TEMP B-TREE FOR GROUP BY", and a node under
        # ProtectSystem=strict has nowhere to put a temp b-tree: on the
        # public seed it failed every sweep with "disk I/O error" on a box
        # with 523G free. Seeking bucket to bucket instead touches only the
        # primary-key index, needs no scratch space, and visits only
        # non-empty buckets. Measured on 3.9M keys: 1.5s against 0.65s for
        # the GROUP BY, once a minute, for never needing a writable /tmp.
        out, lo = {}, None
        with self.lock:
            while True:
                row = self.db.execute(
                    "SELECT k FROM kv WHERE k >= ? ORDER BY k LIMIT 1",
                    (lo,)).fetchone() if lo is not None else self.db.execute(
                    "SELECT k FROM kv ORDER BY k LIMIT 1").fetchone()
                if not row:
                    break
                prefix = row[0][:nchars]
                blo, bhi = self.bucket_range(prefix)
                out[prefix] = self.db.execute(
                    "SELECT COUNT(*) FROM kv WHERE k >= ? AND k < ?",
                    (blo, bhi)).fetchone()[0]
                lo = bhi
        self._buckets = (now, nchars, out)
        return out

    @staticmethod
    def bucket_range(prefix):
        """[lo, hi) covering every key under a prefix.

        The successor of the last character works for hex because 'g' sorts
        after 'f' and before nothing else we store; doing it generically
        means the scheme survives a key tag that is not hex.
        """
        return prefix, prefix[:-1] + chr(ord(prefix[-1]) + 1)

    def bucket_keys(self, prefix):
        """Every key under a prefix, straight off the primary-key index."""
        lo, hi = self.bucket_range(prefix)
        with self.lock:
            return [k for (k,) in self.db.execute(
                "SELECT k FROM kv WHERE k >= ? AND k < ?", (lo, hi))]

    def bucket_entries_except(self, prefix, have, limit=BUCKET_SEND_MAX):
        """The entries under a prefix that `have` does not already list.

        This is the point of the whole exercise: repair used to re-send the
        contents of a range whether or not the far side had them.
        """
        lo, hi = self.bucket_range(prefix)
        have = set(have)
        out = []
        with self.lock:
            for k, v in self.db.execute(
                    "SELECT k, v FROM kv WHERE k >= ? AND k < ?", (lo, hi)):
                if k not in have:
                    out.append([k, v])
                    if len(out) >= limit:
                        break
        return out

    def disk_used(self):
        """Bytes this node occupies, as the operator's disk reports it —
        the database plus its write-ahead log, not the logical key size."""
        total = 0
        for suffix in ("", "-wal", "-shm"):
            try:
                total += os.path.getsize(self.path + suffix)
            except OSError:
                pass
        return total

    def is_full(self):
        return self.cap_bytes is not None and self.disk_used() >= self.cap_bytes

    def vacuum_step(self, pages=VACUUM_PAGES):
        """Give a slice of free space back. Returns bytes released."""
        with self.lock:
            mode = self.db.execute("PRAGMA auto_vacuum").fetchone()[0]
            if mode != 2:                    # 2 == INCREMENTAL
                return 0                     # pre-existing store, see convert()
            before = self.disk_used()
            # Two things that look optional and are not. The pragma does its
            # work one page per STEP, so an undrained cursor frees exactly
            # one page — measured: 1004 free pages went to 1003. And in WAL
            # mode the main file only shrinks at a checkpoint, so without one
            # the space comes back to SQLite but never to the operator's
            # disk, which is the number the cap is measured against.
            self.db.execute(f"PRAGMA incremental_vacuum({int(pages)})").fetchall()
            self.db.commit()
            self.db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()
            return max(0, before - self.disk_used())

    def free_fraction(self):
        with self.lock:
            q = lambda s: self.db.execute(s).fetchone()[0]
            count = q("PRAGMA page_count") or 1
            return (q("PRAGMA freelist_count") or 0) / count

    def convert_to_incremental(self):
        """One-time rewrite for a store created before incremental vacuum.

        Expensive and blocking, so it is done once, in the background, and
        only when there is enough dead space to be worth it.
        """
        with self.lock:
            if self.db.execute("PRAGMA auto_vacuum").fetchone()[0] == 2:
                return 0
            before = self.disk_used()
            self.db.execute("PRAGMA auto_vacuum=INCREMENTAL")
            self.db.execute("VACUUM").fetchall()
            self.db.commit()
            self.db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()
            return max(0, before - self.disk_used())

    def get_meta(self, key, default=""):
        with self.lock:
            row = self.db.execute("SELECT v FROM meta WHERE k=?",
                                  (key,)).fetchone()
            return row[0] if row else default

    def set_meta(self, key, value):
        with self.lock:
            self.db.execute("INSERT OR REPLACE INTO meta VALUES (?,?)",
                            (key, str(value)))
            self.db.commit()

    def spend(self, ref, epoch):
        """Record a token as spent. False if it already was.

        The uniqueness constraint does the work, so two concurrent requests
        presenting one token cannot both win — INSERT either lands or it
        does not, with no read-then-write gap to race through.
        """
        with self.lock:
            try:
                self.db.execute("INSERT INTO spent VALUES (?,?,?)",
                                (ref, epoch, int(time.time())))
                self.db.commit()
                return True
            except sqlite3.IntegrityError:
                return False

    def forget_epochs(self, keep):
        with self.lock:
            qs = ",".join("?" * len(keep)) or "''"
            cur = self.db.execute(
                f"DELETE FROM spent WHERE epoch NOT IN ({qs})", tuple(keep))
            self.db.commit()
            return cur.rowcount

    def spent_count(self):
        with self.lock:
            return self.db.execute("SELECT COUNT(*) FROM spent").fetchone()[0]

    def put(self, entries):
        with self.lock:
            self.db.executemany("INSERT OR REPLACE INTO kv VALUES (?,?)", entries)
            self.db.commit()
            self.writes += len(entries)

    def put_nx(self, entries):
        with self.lock:
            existed = []
            for k, v in entries:
                if self.db.execute("SELECT 1 FROM kv WHERE k=?", (k,)).fetchone():
                    existed.append(k)
                else:
                    self.db.execute("INSERT INTO kv VALUES (?,?)", (k, v))
            self.db.commit()
            return existed

    def delete(self, keys):
        with self.lock:
            n = 0
            for k in keys:
                n += self.db.execute("DELETE FROM kv WHERE k=?", (k,)).rowcount
            self.db.commit()
            self.deletes += n
            return n

    def mget(self, keys):
        with self.lock:
            self.read_batches += 1
            out = {}
            for k in keys:
                row = self.db.execute("SELECT v FROM kv WHERE k=?", (k,)).fetchone()
                if row:
                    out[k] = row[0]
            return out

    def batch_after(self, last_key, n):
        with self.lock:
            return self.db.execute(
                "SELECT k, v FROM kv WHERE k > ? ORDER BY k LIMIT ?",
                (last_key, n)).fetchall()

    def count(self):
        with self.lock:
            return self.db.execute("SELECT COUNT(*) FROM kv").fetchone()[0]

    def sample(self, n=4):
        with self.lock:
            return self.db.execute(
                "SELECT k, substr(v,1,48) FROM kv LIMIT ?", (n,)).fetchall()


class Peers:
    """Gossiped membership: node_id -> signed heartbeat. Only entries whose
    signature verifies against their own key are ever stored or relayed."""

    def __init__(self, ident: Identity, addr: str):
        self.ident = ident
        self.addr = addr                   # mutable: direct or via-addr
        self.udp = ""                      # mutable: observed public UDP
        self.lock = threading.Lock()
        self.table = {ident.node_id: ident.heartbeat(addr)}
        self.contacts = set()              # bare seed addrs (no identity yet)
        self.changed_at = time.time()

    def merge(self, other: dict):
        now = time.time()
        with self.lock:
            for nid, e in other.items():
                if nid == self.ident.node_id:
                    continue
                cur = self.table.get(nid)
                if (not cur or e["ts"] > cur["ts"]) and verify_entry(nid, e):
                    if not cur:
                        self.changed_at = now
                    self.table[nid] = e
            self.table[self.ident.node_id] = self.ident.heartbeat(
                self.addr, self.udp)
            dead = [nid for nid, e in self.table.items()
                    if now - e["ts"] / 1000 > PEER_TTL
                    and nid != self.ident.node_id]
            for nid in dead:
                del self.table[nid]
                self.changed_at = now

    def snapshot(self):
        with self.lock:
            self.table[self.ident.node_id] = self.ident.heartbeat(
                self.addr, self.udp)
            return dict(self.table)

    def live(self):
        now = time.time()
        return {nid: e for nid, e in self.snapshot().items()
                if now - e["ts"] / 1000 <= PEER_TTL}

    def live_direct(self, exclude_self=True):
        """Peers reachable without a relay (candidates for dialback/relaying)."""
        return {nid: e for nid, e in self.live().items()
                if not is_via(e["addr"])
                and not (exclude_self and nid == self.ident.node_id)}

    def stable_since(self):
        with self.lock:
            return time.time() - self.changed_at


class RelayHub:
    """The relay side, present on every node: tenants park long-polls here;
    anyone can post an envelope for a tenant; replies are matched back."""

    def __init__(self):
        self.lock = threading.Lock()
        self.tenants = {}      # node_id -> {"q": deque, "ev": Event, "seen": ts}
        self.replies = {}      # env_id -> {"ev": Event, "result": ...}

    def _tenant(self, nid):
        with self.lock:
            t = self.tenants.get(nid)
            if not t:
                t = {"q": deque(), "ev": threading.Event(), "seen": 0.0}
                self.tenants[nid] = t
            return t

    def poll(self, nid):
        """Park up to POLL_WAIT; return queued envelopes for this tenant."""
        t = self._tenant(nid)
        t["seen"] = time.time()
        t["ev"].wait(POLL_WAIT)
        with self.lock:
            envs = list(t["q"])
            t["q"].clear()
            t["ev"].clear()
            t["seen"] = time.time()
        return envs

    def send(self, nid, envelope):
        """Deliver an envelope to a connected tenant; wait for its reply."""
        t = self._tenant(nid)
        if time.time() - t["seen"] > TENANT_FRESH:
            return None                                # tenant not connected
        slot = {"ev": threading.Event(), "result": None}
        with self.lock:
            self.replies[envelope["id"]] = slot
            t["q"].append(envelope)
            t["ev"].set()
        slot["ev"].wait(SEND_WAIT)
        with self.lock:
            self.replies.pop(envelope["id"], None)
        return slot["result"]

    def reply(self, env_id, result):
        with self.lock:
            slot = self.replies.get(env_id)
        if slot:
            slot["result"] = result
            slot["ev"].set()


def _sign(secret: str, payload: bytes) -> str:
    return hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()


def _post_direct(addr, path, payload: bytes, secret: str, timeout=5):
    headers = {"Content-Type": "application/json"}
    if secret:
        headers["X-BR-Auth"] = _sign(secret, payload)
    status, data = POOL.request(addr, "POST", path, payload, headers,
                                timeout=timeout)
    if status >= 400:
        raise ConnectionError(f"HTTP {status} from {addr}{path}")
    return json.loads(data)


def post_any(addr, path, payload: bytes, secret: str, timeout=5):
    """POST to a direct address, or through a relay for a via-address."""
    if not is_via(addr):
        return _post_direct(addr, path, payload, secret, timeout)
    relay, nid = parse_via(addr)
    env = {"to": nid, "id": os.urandom(8).hex(), "method": "POST",
           "path": path, "body_b64": b64encode(payload).decode()}
    out = _post_direct(relay, "/relay/send", json.dumps(env).encode(),
                       secret, timeout=timeout + SEND_WAIT)
    if out.get("status") != 200:
        raise ConnectionError(f"relayed request failed: {out}")
    return json.loads(b64decode(out["body_b64"]))


# --------------------------------------------------------------- services
# Request handling shared by the HTTP server and the tenant envelope loop.

def service_post(store, peers, hub, secret, path, data, quic=None):
    if path in DATA_PATHS:
        with _op():
            return _service_post(store, peers, hub, secret, path, data, quic)
    return _service_post(store, peers, hub, secret, path, data, quic)


def _service_post(store, peers, hub, secret, path, data, quic=None):
    if path == "/kv":
        entries = [(k, v) for k, v in data["entries"]]
        # Capacity is checked BEFORE the token gate, so a write we are going
        # to refuse never costs the client a token. The cap applies to
        # node-to-node repair too — repair is how most data arrives, so
        # exempting it would make the limit decorative.
        if store.is_full():
            return 507, {"error": "node is at its configured disk limit",
                         "used": store.disk_used(), "cap": store.cap_bytes}
        if GATE is not None:
            ok, code, why = GATE.check(data, len(entries))
            if not ok:
                return code, {"error": why}
        if data.get("nx"):
            existed = store.put_nx(entries)
            return 200, {"stored": len(entries) - len(existed),
                         "existed": existed}
        store.put(entries)
        return 200, {"stored": len(entries)}
    if path == "/digest":
        # How many keys this node holds under each key prefix. Membership
        # gated like every other node-to-node path: it tells a peer which
        # ranges disagree, which is the whole basis of not re-sending data
        # the peer already has.
        # The asker chooses the granularity, because it is the one that
        # knows how big the disagreement is; answering at our own would give
        # two nodes two different pictures of the same key space.
        chars = int(data.get("chars") or store.bucket_chars())
        chars = max(2, min(8, chars))
        return 200, {"buckets": store.bucket_counts(chars),
                     "chars": chars, "keys": store.count()}
    if path == "/bucketkeys":
        # The keys this node holds under one prefix. Only keys — never
        # values — so the answer is a few kB and the asker learns nothing it
        # could not already learn by holding the same replica.
        return 200, {"keys": store.bucket_keys(str(data["prefix"]))}
    if path == "/mget":
        keys = data["keys"]
        values = store.mget(keys)
        out = {"values": values}
        nonce = data.get("nonce")
        # Signed on EVERY read that carries a nonce, never only on audits:
        # a node that could recognise an audit could serve those and drop
        # the rest, so the signature has to be worthless as a signal.
        if isinstance(nonce, str) and len(nonce) == 32:
            try:
                out["receipt"] = receipt.sign(
                    peers.ident.priv, peers.ident.node_id,
                    peers.ident.pub_raw, nonce, keys, values, time.time())
            except (ValueError, TypeError):
                pass
        return 200, out
    if path == "/delete":
        return 200, {"deleted": store.delete(data["keys"])}
    if path == "/gossip":
        peers.merge(data.get("peers", {}))
        return 200, {"peers": peers.snapshot()}
    if path == "/dialback":
        target = data.get("addr", "")
        asker = data.get("node_id", "")
        if is_via(target):
            return 400, {"error": "dialback is for direct addresses"}
        # reachable only if the node that ANSWERS at the address is the node
        # that ASKED — otherwise the probe hit someone else (classic case: a
        # loopback advertise makes the prober dial its own node) and the
        # address is useless as an advertise for the asker
        try:
            status, raw = POOL.request(target, "GET", "/stats", timeout=2)
            answered = json.loads(raw).get("node_id", "") if status == 200 else ""
            ok = bool(asker) and answered == asker
        except (OSError, ValueError):
            ok = False
        return 200, {"reachable": ok}
    if path == "/punch":
        # fired over the reliable relay path: open our NAT toward the caller
        target = data.get("udp", "")
        if quic is not None and target:
            quic.punch(target)
        return 200, {"punching": bool(quic and target),
                     "udp": quic.observed if quic else ""}
    if path == "/relay/poll":
        tok = data.get("token", {})
        if not verify_poll_token(tok):
            return 401, {"error": "bad poll token"}
        return 200, {"envelopes": hub.poll(tok["node_id"])}
    if path == "/relay/send":
        result = hub.send(data["to"], {"id": data["id"],
                                       "method": data.get("method", "POST"),
                                       "path": data["path"],
                                       "body_b64": data.get("body_b64", "")})
        if result is None:
            return 404, {"error": "tenant not connected"}
        return 200, result
    if path == "/relay/reply":
        hub.reply(data["id"], {"status": data["status"],
                               "body_b64": data.get("body_b64", "")})
        return 200, {"ok": True}
    return 404, {"error": "unknown"}


STATUS_CACHE = {"at": 0.0, "rows": [], "total": 0}


def _peer_stats(nid, e, secret, hub, self_id):
    """Best-effort /stats for one peer (key count and version). Tenants are
    reached over the relay connection they already hold with us."""
    try:
        if is_via(e["addr"]):
            _relay, tenant = parse_via(e["addr"])
            out = hub.send(tenant, {"id": os.urandom(8).hex(), "method": "GET",
                                    "path": "/stats", "body_b64": ""})
            if not out or out.get("status") != 200:
                return None
            return json.loads(b64decode(out["body_b64"]))
        status, raw = POOL.request(e["addr"], "GET", "/stats", timeout=2)
        return json.loads(raw) if status == 200 else None
    except (OSError, ValueError, KeyError):
        return None


def _possession_cell(m):
    """The aggregate, plus the newest audit when the two disagree.

    The score is a recency-weighted low quantile over a 6h window, so it
    lags any single result on purpose — that is what stops a fabricated
    pass from erasing a real failure. The cost is that a node which has
    just recovered still reads as failing, and "0% · 2 audits" gave the
    reader nothing to tell that apart from a node that is genuinely
    empty. Showing the latest result resolves it in the honest direction:
    both numbers are true and the difference is the story.
    """
    if not m:
        return "—"
    cell = f"{int(m['rate'] * 100)}% · {m['reports']} audits"
    latest = m.get("latest")
    if latest is not None and round(latest, 3) != round(m["rate"], 3):
        mins = (m.get("latest_age_s") or 0) // 60
        when = f"{mins}m ago" if mins < 90 else f"{mins // 60}h ago"
        cell += f" · latest {int(latest * 100)}% {when}"
    return cell


def status_rows(store, peers, secret, hub):
    """Roster for the public status page; cached briefly."""
    now = time.time()
    if now - STATUS_CACHE["at"] < 10:
        return STATUS_CACHE["rows"], STATUS_CACHE["total"]
    rows, total = [], 0
    me = peers.ident.node_id
    for nid, e in sorted(peers.live().items()):
        stats = (None if nid == me else
                 _peer_stats(nid, e, secret, hub, me))
        keys = store.count() if nid == me else (stats or {}).get("keys")
        ver = (VERSION_STR if nid == me
               else (stats or {}).get("version") or "unknown")
        build = BUILD if nid == me else (stats or {}).get("build", 0)
        if keys:
            total += keys
        # Carry the throughput counters through as well. Adding them to
        # /stats was not enough: the public activity figures are derived
        # from THIS aggregation, and a missing field summed to zero, so the
        # network read as idle while it was writing thousands of keys.
        rows.append({"id": nid, "mode": "relay tenant" if is_via(e["addr"])
                     else "directly reachable", "keys": keys, "version": ver,
                     "build": build or 0,
                     "update_blocked": (UPDATE_BLOCKED_REASON[0] if nid == me
                                        else (stats or {}).get("update_blocked", "")),
                     "writes": (store.writes if nid == me
                                else (stats or {}).get("writes", 0)) or 0,
                     "deletes": (store.deletes if nid == me
                                 else (stats or {}).get("deletes", 0)) or 0,
                     "read_batches": (store.read_batches if nid == me
                                      else (stats or {}).get("read_batches", 0)) or 0,
                     "age": round(now - e["ts"] / 1000, 1)})
    # compare commit COUNTS: hashes have no order, and a node too old to
    # report one is behind by definition
    newest = max((r["build"] for r in rows), default=0)
    for r in rows:
        r["behind"] = r["build"] < newest
    STATUS_CACHE.update({"at": now, "rows": rows, "total": total})
    return rows, total


STATUS_CSS = """
:root{--bg:#0f1115;--panel:#171a21;--line:#262b36;--txt:#d7dce4;
--dim:#8b93a1;--acc:#5cc8ff;--gold:#e0b060;--ok:#7fd18c}
*{box-sizing:border-box;margin:0}
body{background:var(--bg);color:var(--txt);font:15px/1.65 ui-monospace,
SFMono-Regular,Menlo,monospace;padding:48px 24px 80px}
.wrap{max-width:1080px;margin:0 auto}
h1{font-size:30px;margin-bottom:6px}h1 span{color:var(--acc)}
.sub{color:var(--dim);margin-bottom:28px}
.big{font-size:15px;color:var(--dim);margin:0 0 18px}
.big b{color:var(--ok);font-weight:normal;font-size:22px}
table{width:100%;border-collapse:collapse;margin-bottom:22px}
th,td{text-align:left;padding:9px 10px;border-bottom:1px solid var(--line)}
th{color:var(--dim);font-weight:normal;font-size:12px;
text-transform:uppercase;letter-spacing:.08em}
td.id{color:var(--gold)}td.num{text-align:right;font-variant-numeric:tabular-nums}
td.ver{color:var(--ok)}td.behind{color:#e0b060}td.share{color:var(--acc)}
.note{background:var(--panel);border:1px solid var(--line);border-radius:10px;
padding:16px 18px;color:var(--dim);font-size:13.5px;margin-bottom:16px}
.note b{color:var(--txt);font-weight:normal}
a{color:var(--acc);text-decoration:none}a:hover{text-decoration:underline}
.foot{color:var(--dim);font-size:13px;margin-top:26px}
.badge{display:inline-flex;align-items:center;gap:10px;border-radius:10px;
padding:11px 17px;font-size:14px;border:1px solid;margin:0 0 20px;
letter-spacing:.04em}
.badge .dot{width:9px;height:9px;border-radius:50%;flex:none}
.badge.pass{border-color:#2f6d3f;background:#122016;color:var(--ok)}
.badge.pass .dot{background:var(--ok)}
.badge.warn{border-color:#6d5a2f;background:#201c12;color:var(--gold)}
.badge.warn .dot{background:var(--gold)}
.badge.none{border-color:var(--line);background:var(--panel);color:var(--dim)}
.badge.none .dot{background:var(--dim)}
.badge small{color:var(--dim);font-size:12.5px;letter-spacing:0}
.upd{float:right;font-size:12px;color:var(--dim);font-weight:normal}
.upd.stale{color:var(--gold)}
#dyn{transition:opacity .15s}#dyn.loading{opacity:.55}
@media (max-width:700px){body{padding:28px 14px 60px}
th,td{padding:7px 6px;font-size:13px}}
"""


def audit_badge(rows):
    """One line answering the question people arrive with: is the data
    still there?

    Deliberately not a green light that is always on. It reports the WORST
    live node, because a network is only as intact as its weakest replica
    holder, and it says "unproved" rather than "passed" when nobody has
    audited recently. An unaudited network and a healthy one must never
    look the same — which is precisely what a decorative badge would do,
    and this page went sixteen hours in that state earlier today.
    """
    live = [r for r in rows if r.get("mode") != "down"]
    measured = [r for r in live if r.get("measured")]
    if not live:
        return '<div class="badge none"><span class="dot"></span>NO LIVE NODES</div>'
    if not measured:
        return ('<div class="badge none"><span class="dot"></span>'
                'UNPROVED <small>&nbsp;·&nbsp; no audit in the last 6 hours, '
                'so no node can currently show it holds anything</small></div>')
    worst = min(measured, key=lambda r: r["measured"]["rate"])
    rate = worst["measured"]["rate"]
    reports = sum(r["measured"]["reports"] for r in measured)
    pending = len(live) - len(measured)

    # A failing node and a node nobody has audited yet are different things,
    # and the first version called both DEGRADED. A node joining the network
    # then made the whole page cry wolf within minutes of doing nothing
    # wrong — which is how a badge teaches people to ignore it. Only
    # EVIDENCE of loss degrades; absence of evidence is reported as
    # absence of evidence.
    if rate < 0.9:
        return (f'<div class="badge warn"><span class="dot"></span>'
                f'DEGRADED <small>&nbsp;·&nbsp; a proved node is at '
                f'{int(rate * 100)}% — it is missing data it was sent'
                f'{f", and {pending} more await a first audit" if pending else ""}'
                f'</small></div>')
    if pending:
        return (f'<div class="badge pass"><span class="dot"></span>'
                f'AUDIT PASSED <small>&nbsp;·&nbsp; {len(measured)} of '
                f'{len(live)} nodes proved possession across {reports} '
                f'report(s), none below {int(rate * 100)}% &nbsp;·&nbsp; '
                f'{pending} awaiting a first audit</small></div>')
    return (f'<div class="badge pass"><span class="dot"></span>'
            f'AUDIT PASSED <small>&nbsp;·&nbsp; all {len(live)} nodes proved '
            f'possession across {reports} report(s) &nbsp;·&nbsp; weakest '
            f'node {int(rate * 100)}%</small></div>')


STATUS_JS = """<script>
// Refresh in place rather than reloading: a full reload loses your scroll
// position and blinks, and this page is meant to be left open. The server
// renders the fragment, so the badge rules live in exactly one place
// instead of being reimplemented here and drifting.
(function () {
  var last = Date.now(), failing = false;
  function ago() {
    var el = document.getElementById("upd");
    if (!el) return;
    var s = Math.round((Date.now() - last) / 1000);
    el.textContent = failing
      ? "not answering \u2014 showing the last good reading"
      : (s < 2 ? "updated just now" : "updated " + s + "s ago");
    el.className = "upd" + (failing || s > 45 ? " stale" : "");
  }
  async function poll() {
    var dyn = document.getElementById("dyn");
    try {
      dyn.classList.add("loading");
      var r = await fetch("/fragment", {cache: "no-store"});
      if (!r.ok) throw new Error(r.status);
      dyn.innerHTML = await r.text();
      last = Date.now(); failing = false;
    } catch (e) {
      // Keep the last good numbers and mark them stale. Blank figures would
      // imply an empty network rather than an unreachable one.
      failing = true;
    } finally {
      dyn.classList.remove("loading");
      ago();
    }
  }
  setInterval(poll, 10000);
  setInterval(ago, 1000);
  ago();
})();
</script>"""


def status_fragment(rows, total):
    """The part of the page that changes, rendered once and reused.

    The poller swaps this in rather than rebuilding rows in JavaScript.
    Duplicating the badge rules into the browser would mean two places to
    get "degraded versus not yet audited" right, and they would drift.
    """
    body = "".join(
        f"<tr><td class='id'>{r['id']}</td><td>{r['mode']}</td>"
        f"<td class='num'>{r['keys'] if r['keys'] is not None else '—'}</td>"
        f"<td class='{'ver' if (r.get('measured') or {}).get('rate', 0) >= 0.9 else 'behind'}'>"
        f"{_possession_cell(r.get('measured'))}</td>"
        f"<td class='{'behind' if r.get('behind') else 'ver'}'>"
        f"{'not reporting' if r.get('version') == 'unknown' else r.get('version', '?')}"
        f"{' · behind' if r.get('behind') else ''}"
        f"{' · modified' if str(r.get('version', '')).endswith('+dirty') else ''}"
        f"{' · CANNOT SELF-UPDATE' if r.get('update_blocked') else ''}"
        f"</td>"
        f"<td class='num'>{r['age']}s</td>"
        f"<td class='num share'>{r['share'] if r.get('share') is not None else '—'}</td>"
        f"</tr>" for r in rows)
    return (f"{audit_badge(rows)}"
            f"<p class=\"big\"><b>{len(rows)}</b> live nodes &nbsp;·&nbsp; "
            f"<b>{total}</b> encrypted keys stored"
            f"<span class='upd' id='upd'></span></p>"
            f"<table><tr><th>node</th><th>reachability</th>"
            f"<th>keys (self-reported)</th><th>possession (proved)</th>"
            f"<th>version</th><th>last seen</th><th>share ‰</th></tr>"
            f"{body}</table>")


def status_html(rows, total, seed_addr, head=None):
    # The shares above are computed by us, which makes this the one page on
    # the network where you would otherwise have to take our word for
    # something. Say where the receipts are, right next to the numbers they
    # are about.
    if head:
        logstr = (
            '<div class="note"><b>Every number above is logged.</b> Each '
            'accepted audit and each share calculation is a leaf in an '
            'append-only Merkle log, so we cannot revise one after the fact '
            'without anyone who kept an earlier head noticing. Current head: '
            f'<code>{head.get("size")}:{str(head.get("root", ""))[:32]}</code> '
            '(<a href="/log/sth">/log/sth</a>, '
            '<a href="/log/entries?start=0&amp;count=20">/log/entries</a>). '
            'Check it yourself with '
            '<code>python3 examples/verify_log.py</code> — it remembers this '
            'head and demands proof next time that the log still contains '
            'it. It cannot stop us declining to log something, and catching '
            'a split view needs two operators comparing heads.</div>')
    else:
        logstr = ""
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>blindrange — public network status</title><style>{STATUS_CSS}</style>
</head><body><div class="wrap">
<h1>blind<span>range</span> — public network</h1>
<div class="sub">live status, served by the network itself</div>
<div id="dyn">{status_fragment(rows, total)}</div>
<div class="note"><b>Key counts on this page are self-reported and
unverified.</b> A node returns whatever number it likes; nothing here checks
it. What can be proved is possession: a data owner can ask the node
responsible for a record to produce it and verify the AES-GCM tag, which a
node cannot fake — it can neither derive the key nor forge the ciphertext.
Reachability and last-seen are measured, not claimed.</div>
<div class="note">Membership is public within a network — this page is
everything an operator can publish about it. <b>Contents are not.</b> Every
database here is encrypted under its own master key, so records and index
entries are unlinkable pseudorandom pairs to every node, to every other user,
and to whoever runs this seed. You can see that someone is storing; never
what.</div>
<div class="note">Nodes marked <b>relay tenant</b> sit behind NAT and were
never configured for it — they diagnosed their own reachability and now
receive traffic over an outbound connection, with direct QUIC paths punched
when the networks allow.</div>
<div class="note"><b>share ‰</b> is each node's slice of a distribution pool
per thousand — 500 would be half of everything. It is structural position on
the ring multiplied by <b>proved</b> possession, so a node with no audits yet
earns nothing and a node that self-reports generously earns nothing extra.
Possession is scored over a six-hour window, weighting recent audits more
heavily — a proof from this morning says little about a disk now, in either
direction: a node that has just recovered stops being held to its earlier
failures, and one that has just lost data stops coasting on earlier passes.
Where the aggregate and the newest audit disagree, both are shown.
Illustrative: a share of a pool, not an entitlement, and not money.</div>
{logstr}
<div class="foot">join with two commands ·
<a href="https://blindrange.dev">blindrange.dev</a> ·
<a href="https://github.com/alviso/blindrange">source</a><br>
demo network — no durability promises. seed: {seed_addr}</div>
</div>
{STATUS_JS}
</body></html>"""


def service_get(store, peers, path, query, quic=None, status=None):
    if path in ("/", "/status.json") and status is not None:
        rows, total = status
        if path == "/status.json":
            return 200, {"nodes": rows, "keys": total}
        return "html", status_html(rows, total, peers.addr)
    if path == "/peers":
        now = time.time()
        return 200, {"peers": {
            nid: {"addr": e["addr"], "udp": e.get("udp", ""),
                  "age": round(now - e["ts"] / 1000, 1)}
            for nid, e in peers.snapshot().items()}}
    if path == "/stats":
        return 200, {"addr": peers.addr, "node_id": peers.ident.node_id,
                     "keys": store.count(),
                     "read_batches": store.read_batches,
                     "writes": store.writes, "deletes": store.deletes,
                     "disk_used": store.disk_used(),
                     "disk_cap": store.cap_bytes, "full": store.is_full(),
                     "update_blocked": UPDATE_BLOCKED_REASON[0],
                     "peers": len(peers.live()),
                     "mode": "tenant" if is_via(peers.addr) else "direct",
                     "quic": quic is not None, "udp": peers.udp,
                     "version": VERSION_STR, "build": BUILD}
    if path == "/intel":
        n = int(parse_qs(query).get("limit", ["4"])[0])
        return 200, {"addr": peers.addr, "node_id": peers.ident.node_id,
                     "count": store.count(),
                     "sample": [[k, v] for k, v in store.sample(n)]}
    return 404, {"error": "unknown"}


# --------------------------------------------------------------- daemons

def _gossip_loop(peers: Peers, secret: str):
    while True:
        time.sleep(GOSSIP_EVERY + random.random() * 0.5)
        live = peers.live()
        targets = [e["addr"] for nid, e in live.items()
                   if nid != peers.ident.node_id]
        targets += [a for a in peers.contacts
                    if a not in {e["addr"] for e in live.values()}]
        if not targets:
            continue
        target = random.choice(targets)
        try:
            body = json.dumps({"peers": peers.snapshot()}).encode()
            got = post_any(target, "/gossip", body, secret)
            peers.merge(got["peers"])
        except OSError:
            pass                                       # peer down; TTL handles it


def _reconcile(addr, store, peers, secret, stat, budget=RECONCILE_BUCKETS):
    """Send a peer only what it is missing, by comparing key ranges.

    Repair used to push the contents of a range whether or not the far side
    already had them. Measured on the public network, doubling how fast we
    could push moved the convergence rate not at all — the pipe was never
    the constraint, the redundancy was.

    Buckets are key prefixes, so both sides can count and list a range
    straight off the primary-key index. Compare counts, and only where they
    disagree ask for that bucket's key list and send the difference.

    Returns (keys_sent, buckets_examined), or (None, 0) if the peer is too
    old to answer — the caller falls back to the blind sweep, which matters
    because a network updates one node at a time.
    """
    chars = store.bucket_chars()
    tok = peers.ident.poll_token()
    try:
        theirs = post_any(addr, "/digest",
                          json.dumps({"node_token": tok,
                                      "chars": chars}).encode(), secret)
    except OSError as e:
        if "404" in str(e):
            return None, 0            # peer predates reconciliation
        raise
    if theirs.get("chars") != chars:
        return None, 0                # answered at another granularity
    peer_counts = theirs.get("buckets") or {}
    mine = store.bucket_counts(chars)

    # Only ranges where we hold more than they do. Equal counts can still
    # hide a difference, and that is deliberately left to the slow sweep:
    # paying a round trip per bucket to find nothing is the cost this whole
    # mechanism exists to avoid.
    behind = sorted((n - peer_counts.get(b, 0), b) for b, n in mine.items()
                    if n > peer_counts.get(b, 0))
    behind.reverse()                  # biggest gaps first
    sent = 0
    for _, prefix in behind[:budget]:
        if sent >= RECONCILE_KEYS:
            break
        try:
            have = post_any(addr, "/bucketkeys",
                            json.dumps({"prefix": prefix,
                                        "node_token": peers.ident.poll_token()
                                        }).encode(), secret).get("keys") or []
            missing = store.bucket_entries_except(prefix, have)
            if not missing:
                continue
            for i in range(0, len(missing), REPAIR_POST_MAX):
                chunk = missing[i:i + REPAIR_POST_MAX]
                post_any(addr, "/kv",
                         json.dumps({"entries": chunk,
                                     "node_token": peers.ident.poll_token()
                                     }).encode(), secret)
                sent += len(chunk)
        except OSError:
            break                     # peer is unwell; the sweep still runs
    if sent:
        with _repair_stat_lock:
            stat["sent"][addr] += sent
            stat["reconciled"] += sent
    return sent, min(len(behind), budget)


def _push_repair(addr, entries, peers, secret, stat):
    """Send one peer its share of a repair batch. Runs on its own thread.

    Chunked, because a catch-up sweep sizes its batch for the whole store
    and one post of that many entries is a different animal from the
    trickle a maintenance sweep sends: the big ones time out, and this
    used to swallow that as `except OSError: pass`, so a peer could
    receive nothing while the logs stayed clean.
    """
    sent = 0
    for i in range(0, len(entries), REPAIR_POST_MAX):
        chunk = entries[i:i + REPAIR_POST_MAX]
        try:
            post_any(addr, "/kv",
                     json.dumps({"entries": chunk,
                                 "node_token": peers.ident.poll_token()
                                 }).encode(), secret)
            sent += len(chunk)
        except OSError as e:
            # Log at most once a minute per peer. Silence here makes a
            # stalled catch-up look exactly like a healthy one.
            with _repair_stat_lock:
                n, last = _repair_fail.get(addr, (0, 0.0))
                n += 1
                if time.time() - last > 60:
                    print(f"repair: {addr} rejected {len(chunk)} keys "
                          f"({type(e).__name__}: {str(e)[:80]}) — "
                          f"{n} failure(s) since it last accepted any",
                          file=sys.stderr, flush=True)
                    last = time.time()
                _repair_fail[addr] = (n, last)
            break            # that peer is unwell; move on
    if sent:
        with _repair_stat_lock:
            _repair_fail.pop(addr, None)
            stat["sent"][addr] += sent
    return sent


def _repair_loop(store: Store, peers: Peers, secret: str, hub=None,
                 stop=None):
    # The cursor MUST outlive the process. It used to be a local reset to ""
    # on every start, so each restart swept the keyspace from the beginning
    # again — harmless when a node ran for weeks, and quietly crippling once
    # auto-update began restarting nodes every few minutes: a three-hour
    # sweep interrupted every five minutes never gets past its first few
    # percent, so a newly joined node stops filling and nothing says why.
    cursor = store.get_meta("repair_cursor", "")
    last_poll, catching_up = 0.0, False
    stat = {"scanned": 0, "sent": Counter(), "rounds": 0,
            "reconciled": 0, "since": time.time()}
    no_digest = set()          # peers too old to reconcile; sweep them blind
    behind_addrs = set()
    # `stop` exists so a test can end this thread. Without it every test that
    # exercised the loop left a daemon thread sweeping for the rest of the
    # run, which showed up as repair errors printed from a test that had
    # already passed.
    while not (stop is not None and stop.is_set()):
        # A crash in here is indistinguishable from a healthy
        # quiet network: the thread dies, replication stops, and
        # nothing is logged. That has now happened twice — once
        # reaching for the relay hub this loop never took as an
        # argument, once for an unimported Counter. Degrade to a
        # noisy retry instead of silently taking durability with
        # it.
        try:
            time.sleep(REPAIR_EVERY + random.random())
            if peers.stable_since() < REPAIR_SETTLE:
                continue
            live = peers.live()
            if len(live) < 2:
                continue
            # Same derivation as the client's, from the same gossiped fields —
            # if these two disagreed, repair would relocate keys the writer had
            # just placed and the pair would push data back and forth forever.
            ring = Ring(sorted(live), replicas=3,
                        groups={nid: failure_group(e["addr"], e.get("udp", ""))
                                for nid, e in live.items()})
            addr_of = {nid: e["addr"] for nid, e in live.items()}
            mine = store.count()
            # Is anyone visibly behind? Checked on a slow poll, because it costs
            # a /stats round trip per peer and the answer changes slowly.
            now_t = time.time()
            if now_t - last_poll > REPAIR_PEER_POLL:
                last_poll = now_t
                # Never let this decision kill the loop. Reaching for peer stats
                # without the relay hub in scope raised NameError on the first
                # poll, the repair thread died, and replication stopped network
                # wide with nothing logged — the tests caught it as "0 keys
                # migrated", which is the only symptom there would have been.
                try:
                    behind = set()
                    for nid, e in live.items():
                        if nid == peers.ident.node_id:
                            continue
                        st = _peer_stats(nid, e, secret, hub, peers.ident.node_id)
                        keys = (st or {}).get("keys")
                        if (keys is not None and mine > 0
                                and keys < mine * REPAIR_BEHIND_RATIO):
                            behind.add(nid)
                    catching_up = bool(behind)
                    behind_addrs = {addr_of[n] for n in behind
                                    if n in addr_of}
                except Exception as e:
                    print(f"repair: could not poll peers ({type(e).__name__}: "
                          f"{e}) — staying on the maintenance schedule",
                          file=sys.stderr, flush=True)
                    catching_up = False
            if REPAIR_BATCH:
                size = REPAIR_BATCH
            else:
                hours = REPAIR_CATCHUP_H if catching_up else REPAIR_SWEEP_H
                rounds = max(1.0, hours * 3600 / max(0.1, REPAIR_EVERY))
                size = int(min(REPAIR_BATCH_MAX, max(200, mine / rounds)))
            batch = store.batch_after(cursor, size)
            if not batch:                       # wrapped: start the next sweep
                cursor = ""
                store.set_meta("repair_cursor", cursor)
                continue
            cursor = batch[-1][0]
            store.set_meta("repair_cursor", cursor)
            stat["scanned"] += len(batch)
            stat["rounds"] += 1
            by_addr = {}
            for k, v in batch:
                for nid in ring.route(k):
                    if nid != peers.ident.node_id and nid in addr_of:
                        by_addr.setdefault(addr_of[nid], []).append([k, v])
            # Reconcile with whoever is behind: send them what they lack
            # instead of everything we hold. They come out of the blind push
            # below for this round, which would otherwise re-send the very
            # range they were just brought up to date on.
            for addr in sorted(behind_addrs):
                if addr in no_digest:
                    continue
                try:
                    got, _ = _reconcile(addr, store, peers, secret, stat)
                except OSError:
                    continue
                if got is None:
                    no_digest.add(addr)
                    print(f"repair: {addr} cannot reconcile (older node) — "
                          f"falling back to the blind sweep for it",
                          file=sys.stderr, flush=True)
                else:
                    by_addr.pop(addr, None)

            if by_addr:
                # One pool for the whole loop would be tidier, but a round can
                # be skipped entirely and peers come and go; a pool sized to
                # the work is cheap next to the relay round trips it hides.
                with concurrent.futures.ThreadPoolExecutor(
                        max_workers=min(len(by_addr), REPAIR_FANOUT)) as pool:
                    list(pool.map(
                        lambda kv: _push_repair(kv[0], kv[1], peers, secret,
                                                stat),
                        list(by_addr.items())))

            el = time.time() - stat["since"]
            if el >= REPAIR_LOG_EVERY:
                per = ", ".join(
                    f"{a.rsplit('/', 1)[-1][:8]}={n / el:,.0f}/s"
                    for a, n in stat["sent"].most_common(4)) or "nobody"
                print(f"repair: {'catch-up' if catching_up else 'maintenance'} "
                      f"· scanned {stat['scanned'] / el:,.0f} keys/s over "
                      f"{stat['rounds']} rounds · sent {per} · holding "
                      f"{mine:,} keys", file=sys.stderr, flush=True)
                stat = {"scanned": 0, "sent": Counter(), "rounds": 0,
                        "since": time.time()}
        except Exception as e:
            print(f"repair: sweep failed ({type(e).__name__}: "
                  f"{e}) — retrying", file=sys.stderr, flush=True)
            time.sleep(REPAIR_EVERY)


RESTART_CODE = 42          # child -> supervisor: "relaunch me on new code"


def needs_supervisor():
    """Windows cannot replace a running process, so it gets a parent.

    BR_FORCE_SUPERVISOR exists so this path can be exercised on a machine
    that is not Windows — otherwise it would only ever be tested by the
    person it breaks.
    """
    return os.name == "nt" or os.environ.get("BR_FORCE_SUPERVISOR") == "1"


def supervised():
    return os.environ.get("BR_SUPERVISED") == "1"


def supervise():
    """Run the node as a child and relaunch it when it asks to be.

    One parent, one child, forever — not a chain that grows by a process per
    update. The console stays attached to the parent, so Ctrl+C still stops
    it and the shell does not hand back the prompt while a node is quietly
    still running.
    """
    import subprocess
    spec = getattr(sys.modules.get("__main__"), "__spec__", None)
    base = ([sys.executable, "-m", spec.name] if spec is not None
            else [sys.executable, sys.argv[0]])
    env = {**os.environ, "BR_SUPERVISED": "1"}
    while True:
        rc = subprocess.call(base + sys.argv[1:], env=env)
        if rc != RESTART_CODE:
            return rc
        print("supervisor: node updated, relaunching", file=sys.stderr,
              flush=True)


def _vacuum_loop(store):
    """Hand free space back to the filesystem, a slice at a time.

    Without this the file only ever grows: SQLite reuses free pages
    internally but never returns them, so a node that churns looks far
    larger on disk than the data it holds — and any cap the operator sets is
    measured against the inflated number.
    """
    # A store predating incremental vacuum needs one rewrite. Do it in the
    # background and only when it would actually recover something.
    try:
        if store.free_fraction() > 0.25:
            freed = store.convert_to_incremental()
            if freed:
                print(f"reclaimed {human_size(freed)} converting the store to "
                      f"incremental vacuum", file=sys.stderr, flush=True)
    except Exception as e:
        print(f"vacuum conversion skipped: {type(e).__name__}: {e}",
              file=sys.stderr, flush=True)
    while True:
        time.sleep(VACUUM_EVERY + random.random() * 30)
        try:
            store.vacuum_step()
        except Exception as e:
            print(f"vacuum step failed: {type(e).__name__}: {e}",
                  file=sys.stderr, flush=True)


def _reachability_loop(store, peers, hub, secret, direct_addr):
    """Self-assembly: determine own reachability by dialback, become a relay
    tenant when unreachable, revert when reachable again."""
    ident = peers.ident
    time.sleep(DIALBACK_FIRST)
    relay_nid = None
    while True:
        candidates = peers.live_direct()
        if candidates:
            probe = random.choice(list(candidates.values()))
            try:
                got = post_any(probe["addr"], "/dialback",
                               json.dumps({"addr": direct_addr,
                                           "node_id": ident.node_id}).encode(),
                               secret)
                reachable = got.get("reachable", False)
            except OSError:
                reachable = None                       # probe failed; no info
            if reachable is True and is_via(peers.addr):
                peers.addr = direct_addr               # NAT opened up: go direct
                relay_nid = None
            elif reachable is False:
                pool = {n: e for n, e in candidates.items()}
                if relay_nid not in pool and pool:
                    relay_nid = random.choice(list(pool))
                if relay_nid:
                    via = f"via:{pool[relay_nid]['addr']}/{ident.node_id}"
                    if peers.addr != via:
                        peers.addr = via
                        threading.Thread(
                            target=_tenant_loop,
                            args=(store, peers, hub, secret,
                                  lambda: peers.addr),
                            daemon=True).start()
        time.sleep(DIALBACK_EVERY)


def _tenant_loop(store, peers, hub, secret, current_addr):
    """While in tenant mode: long-poll the relay, answer forwarded requests.
    Exits when the node returns to direct mode or switches relay. Also keeps
    the QUIC socket's NAT mapping warm and its public endpoint fresh by
    STUNing the relay every few poll cycles."""
    my_via = current_addr()
    relay, _nid = parse_via(my_via)
    stun_at = 0.0
    while current_addr() == my_via:
        quic = _tenant_loop.quic
        if quic is not None and time.time() > stun_at:
            try:
                # advertise ICE-style CANDIDATES: the LAN address first (works
                # for peers on the same network, and avoids needing hairpin
                # NAT when the dialer sits behind the same router), then the
                # STUN-observed public endpoint for everyone else
                got = quic.stun(relay)
                cands = []
                lip = direct_mod.local_ip()
                if lip:
                    cands.append(f"{lip}:{quic.port}")
                if got and got not in cands:
                    cands.append(got)
                if cands:
                    peers.udp = ",".join(cands)
            except Exception:
                pass
            stun_at = time.time() + 20
        try:
            body = json.dumps({"token": peers.ident.poll_token()}).encode()
            got = _post_direct(relay, "/relay/poll", body, secret,
                               timeout=POLL_WAIT + 10)
            for env in got.get("envelopes", []):
                if env["method"] == "GET":
                    path, _, query = env["path"].partition("?")
                    code, obj = service_get(store, peers, path, query,
                                            quic=_tenant_loop.quic)
                else:
                    data = json.loads(b64decode(env["body_b64"]) or b"{}")
                    code, obj = service_post(store, peers, hub, secret,
                                             env["path"], data,
                                             quic=_tenant_loop.quic)
                reply = {"id": env["id"], "status": code,
                         "body_b64": b64encode(json.dumps(obj).encode()).decode()}
                _post_direct(relay, "/relay/reply",
                             json.dumps(reply).encode(), secret)
        except OSError:
            time.sleep(2)                              # relay hiccup; retry


_tenant_loop.quic = None


def make_quic_service(store, peers, hub, secret):
    """bytes -> bytes request handler for direct QUIC streams. Frames:
    request {"m", "p", "q", "b" (b64 body), "a" (HMAC)} ->
    response {"s": status, "b": b64(json)}."""
    def service(raw: bytes) -> bytes:
        try:
            frame = json.loads(raw)
            body = b64decode(frame.get("b", "")) if frame.get("b") else b""
            if secret:
                payload = body if frame.get("m") == "POST" else \
                    frame.get("p", "").encode()
                good = hmac.compare_digest(frame.get("a", ""),
                                           _sign(secret, payload))
                if not good:
                    return json.dumps({"s": 401, "b": ""}).encode()
            if frame.get("m") == "GET":
                code, obj = service_get(store, peers, frame.get("p", ""),
                                        frame.get("q", ""))
            else:
                data = json.loads(body) if body else {}
                code, obj = service_post(store, peers, hub, secret,
                                         frame.get("p", ""), data,
                                         quic=_tenant_loop.quic)
            return json.dumps(
                {"s": code,
                 "b": b64encode(json.dumps(obj).encode()).decode()}).encode()
        except Exception as e:
            return json.dumps({"s": 500, "b": b64encode(
                json.dumps({"error": str(e)}).encode()).decode()}).encode()
    return service


# --------------------------------------------------------------- server

def make_handler(store: Store, peers: Peers, hub: RelayHub, secret: str = "",
                 quic=None, public_status=False):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"      # keep-alive: reused connections
        # Responses go out as headers-then-body, two small writes. With Nagle
        # on, the second waits for an ACK of the first, so a request costs
        # ~2 round trips instead of 1 — invisible on localhost, brutal across
        # an ocean (measured 430ms against a 187ms RTT).
        disable_nagle_algorithm = True

        def _json(self, obj, code=200):
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _authed(self, payload: bytes) -> bool:
            """Network-membership check: HMAC(secret, payload). Anti-vandalism
            only — every node and client holds the same secret, so this keeps
            outsiders out; it does not (and cannot) make nodes trustworthy.
            Data confidentiality never depends on it."""
            if not secret:
                return True
            given = self.headers.get("X-BR-Auth", "")
            return hmac.compare_digest(given, _sign(secret, payload))

        def do_POST(self):
            path = urlparse(self.path).path
            n = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(n) if n else b""
            if not self._authed(raw):
                self._json({"error": "unauthorized"}, 401)
                return
            data = json.loads(raw) if raw else {}
            code, obj = service_post(store, peers, hub, secret, path, data,
                                     quic=quic)
            self._json(obj, code)

        def do_GET(self):
            url = urlparse(self.path)
            if url.path in ("/peers", "/intel") and not self._authed(
                    url.path.encode()):
                self._json({"error": "unauthorized"}, 401)
                return
            st = (status_rows(store, peers, secret, hub)
                  if public_status and url.path in ("/", "/status.json")
                  else None)
            code, obj = service_get(store, peers, url.path, url.query,
                                    quic=quic, status=st)
            if code == "html":
                body = obj.encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self._json(obj, code)

        def log_message(self, *a):
            pass

    return Handler


def run(host, port, data_dir, seeds, secret="", advertise=None,
        quic_host="0.0.0.0", public_status=False, auto_update=False,
        issuer="", max_disk=""):
    os.makedirs(data_dir, exist_ok=True)
    addr = advertise or f"{host}:{port}"
    ident = Identity(data_dir)
    try:
        total = shutil.disk_usage(data_dir).total
    except OSError:
        total = None
    cap = parse_size(max_disk, total)
    store = Store(os.path.join(data_dir, "kv.db"), cap_bytes=cap)
    if cap:
        print(f"disk limit {human_size(cap)}"
              f"{f' ({max_disk} of {human_size(total)})' if '%' in str(max_disk) else ''}"
              f" · currently using {human_size(store.disk_used())}", flush=True)
        if store.is_full():
            # A cap below the empty database's own footprint means the node
            # accepts nothing, ever, while looking perfectly healthy. Say so
            # rather than letting someone wonder why their node never fills.
            print(f"WARNING: already at the limit ({human_size(store.disk_used())} "
                  f">= {human_size(cap)}) — this node will refuse every write "
                  f"until the limit is raised or space is reclaimed",
                  file=sys.stderr, flush=True)
    peers = Peers(ident, addr)
    peers.contacts.update(seeds)
    if issuer:
        global GATE
        GATE = TokenGate(issuer, store)
        if not GATE.refresh():
            print(f"warning: could not reach issuer {issuer}; writes are "
                  f"unmetered until its keys are available",
                  file=sys.stderr, flush=True)
        threading.Thread(target=_token_key_loop, args=(GATE,),
                         daemon=True).start()
    hub = RelayHub()
    quic = None
    if not direct_mod.DISABLED:
        try:
            quic = direct_mod.NodeQuic(
                quic_host, port, ident.node_id,
                make_quic_service(store, peers, hub, secret))
        except Exception as e:              # QUIC is an optimization only
            import sys as _sys
            print(f"quic disabled: {type(e).__name__}: {e}", file=_sys.stderr)
            quic = None
    _tenant_loop.quic = quic
    if auto_update:
        threading.Thread(target=_update_loop, args=(secret,),
                         daemon=True).start()
    threading.Thread(target=_gossip_loop, args=(peers, secret),
                     daemon=True).start()
    threading.Thread(target=_repair_loop, args=(store, peers, secret, hub),
                     daemon=True).start()
    threading.Thread(target=_vacuum_loop, args=(store,), daemon=True).start()
    threading.Thread(target=_reachability_loop,
                     args=(store, peers, hub, secret, addr),
                     daemon=True).start()
    # Bind with a short retry. On a re-exec the outgoing process may not
    # have released the port yet — on Windows especially, where the
    # replacement is a genuinely new process rather than this one wearing
    # new code. Failing instantly here would turn an auto-update into an
    # outage that needs a human.
    handler = make_handler(store, peers, hub, secret, quic=quic,
                           public_status=public_status)
    server = None
    for attempt in range(BIND_RETRY_S):
        try:
            server = ThreadingHTTPServer((host, port), handler)
            break
        except OSError as e:
            if attempt == BIND_RETRY_S - 1:
                print(f"cannot bind {host}:{port} after {BIND_RETRY_S}s: {e}",
                      file=sys.stderr, flush=True)
                raise
            if attempt == 0:
                print(f"{host}:{port} still busy, retrying for "
                      f"{BIND_RETRY_S}s (a previous instance may be exiting)",
                      file=sys.stderr, flush=True)
            time.sleep(1)
    server.serve_forever()


def main():
    ap = argparse.ArgumentParser(description="blindrange blind storage node")
    ap.add_argument("--host", default="127.0.0.1",
                    help="bind address (0.0.0.0 to serve a LAN)")
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--data", required=True, type=os.path.expanduser,
                    help="data directory for this node")
    ap.add_argument("--seed", action="append", default=[],
                    help="host:port of any live peer (repeatable; omit to start a new network)")
    ap.add_argument("--secret", default=os.environ.get("BLINDRANGE_SECRET", ""),
                    help="network-membership secret (or env BLINDRANGE_SECRET); "
                         "empty runs an open network")
    ap.add_argument("--auto-update", action="store_true",
                    default=os.environ.get("BR_AUTO_UPDATE") == "1",
                    help="periodically fast-forward this git checkout and "
                         "restart on new commits. You are trusting whoever "
                         "controls the remote to run code on your machine — "
                         "off unless you ask for it")
    ap.add_argument("--public-status", action="store_true",
                    help="serve an unauthenticated status page at / listing "
                         "live nodes and key counts (off by default: on a "
                         "private network, membership should not be public)")
    ap.add_argument("--quic-host", default=os.environ.get("BR_QUIC_HOST",
                                                          "0.0.0.0"),
                    help="bind address for the QUIC/UDP socket used by direct "
                         "paths (default all interfaces — hole punching needs "
                         "internet reachability even when HTTP is local)")
    ap.add_argument("--max-disk", default=os.environ.get("BR_MAX_DISK", ""),
                    help="stop accepting writes past this much disk, e.g. "
                         "10GB or 5%% (of the filesystem). Data already held "
                         "is never deleted to get under it.")
    ap.add_argument("--issuer", default=os.environ.get("BR_ISSUER", ""),
                    help="token issuer URL; writes require a blind token "
                         "when set (nodes hold only its public keys)")
    ap.add_argument("--advertise", default=None,
                    help="host:port other machines should reach this node at "
                         "(defaults to --host:--port; set it when binding 0.0.0.0). "
                         "If it turns out to be unreachable, the node automatically "
                         "relays through a reachable peer instead.")
    a = ap.parse_args()
    if a.auto_update and needs_supervisor() and not supervised():
        sys.exit(supervise())
    run(a.host, a.port, a.data, a.seed, a.secret, a.advertise, a.quic_host,
        a.public_status, a.auto_update, a.issuer, a.max_disk)


if __name__ == "__main__":
    main()
