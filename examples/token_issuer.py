"""Token issuer: the one place that knows who you are.

This service is deliberately the only identified component in the system,
and it is worth being precise about what that costs. It knows an account
exists, what it was granted, and when it drew tokens. It does not know, and
cannot compute, which writes those tokens paid for — the signatures it
produces are over values it has never seen. Compromising it entirely yields
a customer list and a ledger of quota, and not one byte of anyone's data
nor any way to attribute a key on any node to any account.

That is the trade the architecture allows: identity for billing, blindness
for storage. It only holds if this service stays boring — no logging of
blinded values against accounts, no request timing kept, nothing that
would let issuance and redemption be joined after the fact.

  python3 examples/token_issuer.py --data ~/.blindrange/issuer --port 8090

Endpoints:
  GET  /keys    public keys by id — what nodes fetch to verify tokens
  POST /issue   {account, kid, blinded:[...]} -> {signed:[...], remaining}
  POST /grant   admin: top up an account's quota
"""
import argparse
import json
import os
import secrets
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from blindrange import token as T  # noqa: E402

# Few and coarse on purpose. A denomination is public — which key verifies
# a token is what gives it value — so a rare one narrows its holder to
# whoever asks for rare ones. Three sizes that most workloads round into.
DENOMINATIONS = (1_000, 10_000, 100_000)
MAX_BATCH = 512               # blinded messages per request
FREE_GRANT = 10_000_000_000   # bytes of network storage in the free tier

LOCK = threading.Lock()
STATE = {"keys": {}, "accounts": {}}
DATA_DIR = ""


def epoch_now():
    return datetime.now(timezone.utc).strftime("%Y-%m")


def _path(name):
    return os.path.join(DATA_DIR, name)


def load():
    for name in ("keys", "accounts"):
        try:
            with open(_path(name + ".json")) as f:
                STATE[name] = json.load(f)
        except (OSError, ValueError):
            STATE[name] = {}
    # keys arrive as strings so JSON keeps full precision on the modulus
    for kid, k in STATE["keys"].items():
        for f in ("n", "e", "d"):
            k[f] = int(k[f])


def save(name):
    data = STATE[name]
    if name == "keys":
        data = {kid: {f: str(v) for f, v in k.items()}
                for kid, k in data.items()}
    tmp = _path(name + ".json.tmp")
    with open(tmp, "w") as f:
        os.fchmod(f.fileno(), 0o600)
        json.dump(data, f)
    os.replace(tmp, _path(name + ".json"))


def ensure_keys():
    """One keypair per (epoch, denomination), minted on demand.

    Rotation is what keeps node spent-sets finite: once an epoch's key
    stops verifying, every nonce recorded against it can be dropped.
    """
    epoch, made = epoch_now(), False
    with LOCK:
        for denom in DENOMINATIONS:
            kid = T.key_id(epoch, denom)
            if kid not in STATE["keys"]:
                STATE["keys"][kid] = T.keygen()
                made = True
        if made:
            save("keys")
    return made


def public_keys():
    return {kid: {"n": str(k["n"]), "e": k["e"]}
            for kid, k in STATE["keys"].items()}


def grant(email, bytes_granted=FREE_GRANT):
    key = secrets.token_urlsafe(24)
    with LOCK:
        STATE["accounts"][key] = {"email": email,
                                  "granted": int(bytes_granted),
                                  "issued": 0}
        save("accounts")
    return key


def issue(account, kid, blinded):
    """Sign blinded messages, debiting the account by what they are worth.

    Quota is denominated in bytes of network storage, and a token worth N
    keys is charged at the measured average key size. The issuer never sees
    a key, a record or a schema — only how much capacity was bought.
    """
    if not isinstance(blinded, list) or not blinded:
        raise ValueError("no blinded messages")
    if len(blinded) > MAX_BATCH:
        raise ValueError(f"at most {MAX_BATCH} tokens per request")
    with LOCK:
        acct = STATE["accounts"].get(account)
        if not acct:
            raise PermissionError("unknown account")
        key = STATE["keys"].get(kid)
        if not key:
            raise ValueError("unknown key id")
        if T.parse_key_id(kid)[0] != epoch_now():
            raise ValueError("key id is not the current epoch")
        denom = T.parse_key_id(kid)[1]
        cost = len(blinded) * denom * AVG_KEY_BYTES
        remaining = acct["granted"] - acct["issued"]
        if cost > remaining:
            raise PermissionError(
                f"quota exhausted: need {cost:,} bytes, {remaining:,} left")
        signed = [str(T.sign_blinded(int(b), key["n"], key["d"]))
                  for b in blinded]
        acct["issued"] += cost
        save("accounts")
        return {"signed": signed, "remaining": acct["granted"] - acct["issued"]}


# Measured on a live network: index entries dominate and average out to
# this. Charging per key rather than per byte keeps the issuer from needing
# to know anything about the shape of the data it is metering.
AVG_KEY_BYTES = 46


def make_handler(admin_token):
    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass          # deliberately no request log: see module docstring

        def _send(self, code, obj):
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if urlparse(self.path).path == "/keys":
                ensure_keys()
                return self._send(200, {"keys": public_keys(),
                                        "denominations": list(DENOMINATIONS),
                                        "epoch": epoch_now()})
            self._send(404, {"error": "not found"})

        def do_POST(self):
            path = urlparse(self.path).path
            n = int(self.headers.get("Content-Length", 0))
            if n > 4_000_000:
                return self._send(413, {"error": "too large"})
            try:
                data = json.loads(self.rfile.read(n) or b"{}")
            except ValueError:
                return self._send(400, {"error": "bad json"})

            if path == "/issue":
                ensure_keys()
                try:
                    return self._send(200, issue(data.get("account", ""),
                                                 data.get("kid", ""),
                                                 data.get("blinded")))
                except PermissionError as e:
                    return self._send(402, {"error": str(e)})
                except (ValueError, TypeError) as e:
                    return self._send(400, {"error": str(e)})

            if path == "/grant":
                if not admin_token or data.get("admin") != admin_token:
                    return self._send(403, {"error": "forbidden"})
                key = grant(data.get("email", ""),
                            int(data.get("bytes", FREE_GRANT)))
                return self._send(200, {"account": key})

            self._send(404, {"error": "not found"})
    return H


def main():
    global DATA_DIR
    ap = argparse.ArgumentParser(description="blindrange token issuer")
    ap.add_argument("--data", default=os.path.expanduser("~/.blindrange/issuer"))
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8090)
    ap.add_argument("--admin-token", default=os.environ.get("BR_ADMIN_TOKEN", ""))
    a = ap.parse_args()
    DATA_DIR = a.data
    os.makedirs(DATA_DIR, exist_ok=True)
    load()
    ensure_keys()
    print(f"issuer on {a.host}:{a.port} · epoch {epoch_now()} · "
          f"{len(STATE['keys'])} keys · {len(STATE['accounts'])} accounts",
          flush=True)
    ThreadingHTTPServer((a.host, a.port), make_handler(a.admin_token)).serve_forever()


if __name__ == "__main__":
    main()
