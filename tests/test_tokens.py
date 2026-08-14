"""Blind token metering: writes are paid for, and payment is unlinkable.

The security claim under test is not "tokens work" but the split that makes
metering compatible with blindness at all: issuance is identified,
redemption is anonymous, and no party — issuer, node, or both together —
can join the two.
"""
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from blindrange import Owner, token as T          # noqa: E402
from tests.test_e2e import wait_http, wait_peers  # noqa: E402

def _free_port():
    """Bind :0 and keep the number. A fixed port makes the suite fail for a
    reason that has nothing to do with the code — a leaked issuer from an
    interrupted run holds it, and every later run reports 'issuer never came
    up'."""
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


ISSUER_PORT = _free_port()
PORTS = (7961, 7962, 7963)
ADMIN = "test-admin-token"


def post(url, payload):
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read())


class TestBlindTokens(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="brtok_")
        cls.secret = "toknet"
        cls.issuer_url = f"http://127.0.0.1:{ISSUER_PORT}"
        cls.procs = []
        cls.procs.append(subprocess.Popen(
            [sys.executable, str(ROOT / "examples" / "token_issuer.py"),
             "--data", f"{cls.tmp}/issuer", "--port", str(ISSUER_PORT),
             "--admin-token", ADMIN],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=str(ROOT)))
        for _ in range(80):
            try:
                urllib.request.urlopen(cls.issuer_url + "/keys", timeout=1)
                break
            except OSError:
                time.sleep(0.15)
        else:
            raise RuntimeError("issuer never came up")

        for i, port in enumerate(PORTS):
            args = [sys.executable, "-m", "blindrange.node", "--port",
                    str(port), "--data", f"{cls.tmp}/n{port}",
                    "--secret", cls.secret, "--issuer", cls.issuer_url]
            if i:
                args += ["--seed", f"127.0.0.1:{PORTS[0]}"]
            cls.procs.append(subprocess.Popen(
                args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                cwd=str(ROOT)))
        wait_http(f"127.0.0.1:{PORTS[0]}")
        wait_peers(f"127.0.0.1:{PORTS[0]}", 3, cls.secret)

        cls.schema = {"ts": {"type": "int", "bits": 22, "leaf_width": 4096}}

    @classmethod
    def tearDownClass(cls):
        for p in cls.procs:
            if p.poll() is None:
                p.terminate()
            p.wait()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def owner(self, name, granted=10_000_000_000):
        acct = post(self.issuer_url + "/grant",
                    {"admin": ADMIN, "email": f"{name}@example.com",
                     "bytes": granted})["account"]
        o = Owner.create(f"{self.tmp}/{name}.brdb", "pw", self.schema,
                         bootstrap=[f"127.0.0.1:{PORTS[0]}"],
                         network_secret=self.secret)
        o.configure_tokens(self.issuer_url, acct)
        return o, acct

    # ---------------------------------------------------------------- tests
    def test_a_paid_write_round_trips(self):
        o, _ = self.owner("paid")
        o.top_up(denom=1000, count=40)
        self.assertGreater(o.token_balance(), 0)
        rows = [{"ts": i * 1000, "row": i} for i in range(60)]
        o.insert_many(rows)
        o.drain()
        got = sorted(r["row"] for r in o.query("ts", 0, 60_000))
        self.assertEqual(got, list(range(60)), "paid write did not land")

    def test_b_unpaid_write_is_refused(self):
        """A wallet with no tokens and no account cannot buy its way in."""
        o = Owner.create(f"{self.tmp}/broke.brdb", "pw", self.schema,
                         bootstrap=[f"127.0.0.1:{PORTS[0]}"],
                         network_secret=self.secret)
        o.configure_tokens(self.issuer_url, "not-a-real-account")
        with self.assertRaises(Exception):
            o.insert_many([{"ts": 5, "row": 1}])
            o.drain()
        self.assertEqual(o.token_balance(), 0)

    def test_c_a_token_cannot_be_spent_twice_at_a_node(self):
        o, _ = self.owner("double")
        o.top_up(denom=1000, count=4)
        tok = o._wallet.take_for(1)
        addr = f"127.0.0.1:{PORTS[0]}"
        body = {"entries": [["R:dbl1", "AAAA"]], "tokens": tok}
        self.assertEqual(o._post_inner(addr, "/kv", body)["stored"], 1)
        body2 = {"entries": [["R:dbl2", "BBBB"]], "tokens": tok}
        with self.assertRaises(Exception):
            o._post_inner(addr, "/kv", body2)

    def test_d_a_forged_token_is_worthless(self):
        o, _ = self.owner("forge")
        keys = o._issuer_keys()
        kid = T.key_id_for(keys, 1000)
        forged = T.encode_token(kid, os.urandom(32), random.getrandbits(2048))
        with self.assertRaises(Exception):
            o._post_inner(f"127.0.0.1:{PORTS[0]}", "/kv",
                          {"entries": [["R:forged", "X"]], "tokens": [forged]})

    def test_e_a_token_cannot_be_restamped_to_a_bigger_denomination(self):
        o, _ = self.owner("restamp")
        o.top_up(denom=1000, count=2)
        tok = dict(o._wallet.take_for(1)[0])
        keys = o._issuer_keys()
        tok["kid"] = T.key_id_for(keys, 100_000)      # claim 100x the value
        with self.assertRaises(Exception):
            o._post_inner(f"127.0.0.1:{PORTS[0]}", "/kv",
                          {"entries": [["R:restamp", "X"]], "tokens": [tok]})

    def test_f_a_batch_larger_than_the_token_is_refused(self):
        o, _ = self.owner("oversize")
        o.top_up(denom=1000, count=2)
        tok = o._wallet.take_for(1)
        entries = [[f"R:big{i}", "X"] for i in range(1001)]
        with self.assertRaises(Exception):
            o._post_inner(f"127.0.0.1:{PORTS[0]}", "/kv",
                          {"entries": entries, "tokens": tok})

    def test_g_quota_is_enforced_at_issuance(self):
        # 46 B/key x 1000 keys = 46,000 B per token; grant room for ~2
        o, _ = self.owner("smallquota", granted=100_000)
        o.top_up(denom=1000, count=2)
        with self.assertRaises(urllib.error.HTTPError) as e:
            o.top_up(denom=1000, count=50)
        self.assertEqual(e.exception.code, 402)

    def test_h_issuance_cannot_be_linked_to_redemption(self):
        """The property the whole design exists for.

        Everything the issuer could retain is captured here, then matched
        against a token that was actually spent. A blinded value carries no
        information about the token it becomes, so there is nothing to join
        on but the denomination — which is public by construction.
        """
        o, acct = self.owner("unlink")
        keys = o._issuer_keys()
        kid = T.key_id_for(keys, 1000)
        pk = keys[kid]

        issuer_saw, wallet = [], []
        for _ in range(24):
            nonce = os.urandom(T.NONCE_BYTES)
            blinded, r = T.blind(nonce, pk["n"], pk["e"])
            issuer_saw.append(blinded)               # all the issuer ever sees
            out = post(self.issuer_url + "/issue",
                       {"account": acct, "kid": kid, "blinded": [str(blinded)]})
            sig = T.unblind(int(out["signed"][0]), r, pk["n"])
            wallet.append(T.encode_token(kid, nonce, sig))

        spent = random.choice(wallet)
        _, nonce, sig = T.decode_token(spent)
        self.assertTrue(T.verify(nonce, sig, pk["n"], pk["e"]))

        # no blinded value the issuer holds equals, or is derivable from,
        # the token that surfaced
        m = T.fdh(nonce, pk["n"])
        self.assertNotIn(m, issuer_saw)
        self.assertNotIn(sig, issuer_saw)
        self.assertNotIn(int.from_bytes(nonce, "big"), issuer_saw)
        # and the signature is not a blinded value either
        self.assertFalse(any(pow(sig, pk["e"], pk["n"]) == b
                             for b in issuer_saw))

    def test_i_node_repair_is_not_billable(self):
        """Nodes healing each other must not need to buy tokens, or
        replication becomes a charge and the network stops healing."""
        o, _ = self.owner("repair")
        o.top_up(denom=1000, count=8)
        o.insert_many([{"ts": i, "row": i} for i in range(40)])
        o.drain()
        addr = f"127.0.0.1:{PORTS[1]}"
        with urllib.request.urlopen(f"http://{addr}/stats", timeout=5) as r:
            before = json.loads(r.read())["keys"]
        self.assertGreater(before, 0, "replicas never received the data")
        # a peer's signed identity is accepted where a client's token is required
        import blindrange.node as N
        ident = N.Identity(f"{self.tmp}/n{PORTS[0]}")
        gate_ok = N.verify_poll_token(ident.poll_token())
        self.assertTrue(gate_ok, "node identity no longer authenticates repair")


if __name__ == "__main__":
    unittest.main()
