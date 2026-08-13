"""Who is on the network right now?

Lists every live node the gossip layer knows about, flagging ones you don't
recognise. Membership is public within a network — but that is ALL you can
see: other people's databases use different master keys, so their records
and index entries are unlinkable pseudorandom pairs to you, exactly as your
data is to them. You can see that someone is storing; never what.

  python3 examples/whos_here.py                       # public demo network
  python3 examples/whos_here.py HOST:PORT SECRET
"""
import hashlib
import hmac
import json
import sys
import urllib.request

MINE = {                       # label the nodes you know are yours
    "77620e2495a50509": "seed (kda-hetzner-1)",
    "5e43181f91338f99": "your mac A",
    "ba8b3e555667bd8b": "your mac B",
}


def get(addr, path, secret):
    sig = hmac.new(secret.encode(), path.encode(), hashlib.sha256).hexdigest()
    req = urllib.request.Request(f"http://{addr}{path}",
                                 headers={"X-BR-Auth": sig} if secret else {})
    with urllib.request.urlopen(req, timeout=8) as r:
        return json.loads(r.read())


def main():
    addr = sys.argv[1] if len(sys.argv) > 1 else "seed.blindrange.dev:7501"
    secret = sys.argv[2] if len(sys.argv) > 2 else "blindrange-public"
    peers = get(addr, "/peers", secret)["peers"]
    live = {n: e for n, e in peers.items() if e["age"] <= 12}

    print(f"\n  {len(live)} live nodes on {addr}\n")
    newcomers = 0
    for nid, e in sorted(live.items(), key=lambda kv: kv[1]["addr"]):
        label = MINE.get(nid)
        if label is None:
            label = "*** NEW — someone joined ***"
            newcomers += 1
        mode = "tenant" if e["addr"].startswith("via:") else "direct"
        print(f"  {nid}  {mode:7}  {label}")
        print(f"  {'':16}  {'':7}  {e['addr'][:64]}")

    try:
        stats = get(addr, "/stats", "")
        print(f"\n  seed holds {stats['keys']} keys · "
              f"{stats['read_batches']} read batches served")
    except OSError:
        pass
    print(f"\n  {newcomers} node(s) you don't recognise\n")


if __name__ == "__main__":
    main()
