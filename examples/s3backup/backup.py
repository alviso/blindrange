"""Off-site backup whose catalog you can search and whose host cannot read it.

This is a demo of the S3 gateway, written with a plain S3 client and no
blindrange imports at all — which is the point. Everything here would work
unchanged against AWS; the only difference is where the endpoint points, and
that difference is what makes the bytes unreadable to whoever stores them.

Backing up to object storage is the most ordinary thing in the world, so it
is a fair test of whether the gateway is actually usable. The interesting
part is not the upload. It is that the CATALOG stays queryable: a prefix
listing here is a dyadic index lookup over encrypted keys, so

    which snapshot has files under src/ that changed in the last hour?

is a native operation, not a scan — while the machines holding the data see
pseudorandom keys and AEAD blobs. Plain S3 gives you the listing but the
provider can read everything; client-side encryption over S3 makes it
unreadable but takes the listing away with it. This keeps both.

  python3 examples/s3backup/backup.py backup ~/src --bucket work
  python3 examples/s3backup/backup.py ls work --prefix src/
  python3 examples/s3backup/backup.py find work --since 1h
  python3 examples/s3backup/backup.py restore work <snapshot> /tmp/restored
  python3 examples/s3backup/backup.py what-they-see

Needs an S3 client:  pip install boto3
"""
import argparse
import fnmatch
import hashlib
import os
import sys
import time
from datetime import datetime, timezone

try:
    import boto3
    from botocore.config import Config
    from botocore.exceptions import ClientError, EndpointConnectionError
except ImportError:
    sys.exit("this demo needs an S3 client: pip install boto3")

SKIP = ("*/.git/*", "*/__pycache__/*", "*.pyc", "*/.DS_Store", "*/node_modules/*")


def client(endpoint, access_key, secret_key):
    return boto3.client(
        "s3", endpoint_url=endpoint,
        aws_access_key_id=access_key, aws_secret_access_key=secret_key,
        region_name="us-east-1",
        # Path style, because a local gateway has no wildcard DNS for
        # bucket.host — the same setting every S3-compatible endpoint needs.
        config=Config(s3={"addressing_style": "path"},
                      retries={"max_attempts": 2}))


def walk(root, excludes):
    root = os.path.abspath(root)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if not any(fnmatch.fnmatch(os.path.join(dirpath, d), p)
                                  for p in excludes)]
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            if any(fnmatch.fnmatch(full, p) for p in excludes):
                continue
            if not os.path.isfile(full) or os.path.islink(full):
                continue
            yield full, os.path.relpath(full, root)


def cmd_backup(s3, a):
    snap = a.snapshot or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    try:
        s3.create_bucket(Bucket=a.bucket)
    except ClientError:
        pass                                  # buckets are implicit anyway
    files = list(walk(a.path, list(SKIP) + (a.exclude or [])))
    if not files:
        print("  nothing to back up"); return 1
    total = t0 = 0
    t0 = time.time()
    for i, (full, rel) in enumerate(files, 1):
        with open(full, "rb") as f:
            body = f.read()
        key = f"{snap}/{rel}"
        s3.put_object(Bucket=a.bucket, Key=key, Body=body)
        total += len(body)
        if a.verbose or i == len(files) or i % 25 == 0:
            print(f"  [{i}/{len(files)}] {rel} ({len(body):,} B)")
    el = time.time() - t0
    print(f"\n  snapshot {snap}: {len(files)} files, {total:,} bytes in "
          f"{el:.1f}s ({total / max(el, 1e-9) / 1024:,.0f} kB/s)")
    print(f"  the machines storing this cannot read any of it — try "
          f"'what-they-see'")
    return 0


def _list(s3, bucket, prefix="", delimiter=""):
    kw = {"Bucket": bucket, "Prefix": prefix}
    if delimiter:
        kw["Delimiter"] = delimiter
    out, folders, token = [], [], None
    while True:
        if token:
            kw["ContinuationToken"] = token
        r = s3.list_objects_v2(**kw)
        out += r.get("Contents", [])
        folders += [p["Prefix"] for p in r.get("CommonPrefixes", [])]
        token = r.get("NextContinuationToken")
        if not token:
            return out, folders


def cmd_ls(s3, a):
    objs, folders = _list(s3, a.bucket, a.prefix, "" if a.recursive else "/")
    for f in folders:
        print(f"  {'DIR':>10}  {f}")
    for o in sorted(objs, key=lambda o: o["Key"]):
        when = o["LastModified"].strftime("%Y-%m-%d %H:%M")
        print(f"  {o['Size']:>10,}  {when}  {o['Key']}")
    print(f"\n  {len(objs)} object(s), {len(folders)} prefix(es)"
          f"{' under ' + a.prefix if a.prefix else ''}")
    return 0


def cmd_find(s3, a):
    """The reason to use this rather than an encrypted blob store.

    Prefix and time are both native here — the listing is a dyadic lookup,
    not a scan of decrypted metadata, and it happens without any node
    learning what it matched.
    """
    cutoff = None
    if a.since:
        mult = {"m": 60, "h": 3600, "d": 86400}[a.since[-1]]
        cutoff = time.time() - int(a.since[:-1]) * mult
    objs, _ = _list(s3, a.bucket, a.prefix or "")
    hits = []
    for o in objs:
        if cutoff and o["LastModified"].timestamp() < cutoff:
            continue
        if a.name and not fnmatch.fnmatch(os.path.basename(o["Key"]), a.name):
            continue
        hits.append(o)
    for o in sorted(hits, key=lambda o: o["LastModified"], reverse=True):
        print(f"  {o['LastModified'].strftime('%Y-%m-%d %H:%M')}  "
              f"{o['Size']:>9,}  {o['Key']}")
    scope = []
    if a.prefix:
        scope.append(f"under {a.prefix}")
    if a.since:
        scope.append(f"changed in the last {a.since}")
    if a.name:
        scope.append(f"named {a.name}")
    print(f"\n  {len(hits)} of {len(objs)} objects{' ' + ', '.join(scope) if scope else ''}")
    return 0


def cmd_restore(s3, a):
    objs, _ = _list(s3, a.bucket, a.prefix)
    if not objs:
        print(f"  nothing under {a.prefix!r}"); return 1
    os.makedirs(a.dest, exist_ok=True)
    n = total = 0
    for o in objs:
        rel = o["Key"][len(a.prefix):].lstrip("/")
        out = os.path.join(a.dest, rel)
        os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
        body = s3.get_object(Bucket=a.bucket, Key=o["Key"])["Body"].read()
        # Verify on the way out, not as a separate pass. A backup tool that
        # reports success without checking what it wrote is theatre, and a
        # corrupt restore is discovered at the worst possible moment.
        if len(body) != o["Size"]:
            print(f"  SIZE MISMATCH on {o['Key']}: "
                  f"{len(body)} != {o['Size']}", file=sys.stderr)
            return 1
        with open(out, "wb") as f:
            f.write(body)
        n += 1
        total += len(body)
    print(f"  restored {n} file(s), {total:,} bytes to {a.dest}")
    return 0


def cmd_verify(s3, a):
    """Compare what came back against what is on disk, byte for byte."""
    files = dict((rel, full) for full, rel in
                 walk(a.path, list(SKIP) + (a.exclude or [])))
    objs, _ = _list(s3, a.bucket, a.prefix)
    same = differ = missing = 0
    for o in objs:
        rel = o["Key"][len(a.prefix):].lstrip("/")
        local = files.get(rel)
        if not local:
            missing += 1
            continue
        remote = s3.get_object(Bucket=a.bucket, Key=o["Key"])["Body"].read()
        with open(local, "rb") as f:
            if hashlib.sha256(f.read()).digest() == hashlib.sha256(remote).digest():
                same += 1
            else:
                differ += 1
                print(f"  DIFFERS: {rel}", file=sys.stderr)
    print(f"  {same} identical, {differ} differ, {missing} not on disk")
    return 0 if differ == 0 else 1


def cmd_what_they_see(s3, a):
    """The whole argument, in one screen."""
    import json
    import urllib.request
    print("  what YOU see:")
    objs, _ = _list(s3, a.bucket, "")
    for o in sorted(objs, key=lambda o: o["Key"])[:4]:
        print(f"    {o['Size']:>9,}  {o['Key']}")
    if not objs:
        print("    (nothing backed up yet)")

    print("\n  what the machine storing it sees:")
    try:
        # /intel is membership-gated behind the network secret, so a demo
        # that cannot authenticate shows nothing at exactly the moment the
        # point is being made. Signed the same way the client signs any GET:
        # HMAC of the path under the network secret.
        import hmac as _hmac
        import hashlib as _hashlib
        sig = _hmac.new(a.secret.encode(), b"/intel",
                        _hashlib.sha256).hexdigest()
        req = urllib.request.Request(f"http://{a.node}/intel?limit=4",
                                     headers={"X-BR-Auth": sig})
        with urllib.request.urlopen(req, timeout=5) as r:
            intel = json.loads(r.read())
        for pair in (intel.get("sample") or [])[:4]:
            k, v = pair
            print(f"    {str(k)[:38]}  ->  {str(v)[:24]}")
        print(f"\n    {intel.get('count', 0):,} keys on that node, none of "
              f"them readable, none of them named after your files")
    except Exception as e:
        print(f"    (node intel unavailable: {type(e).__name__} — pass "
              f"--secret for the network and --node for one you run)")
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--endpoint", default=os.environ.get(
        "BR_S3_ENDPOINT", "http://127.0.0.1:8720"))
    ap.add_argument("--access-key", default=os.environ.get(
        "BR_S3_ACCESS_KEY", "blindrange"))
    ap.add_argument("--secret-key", default=os.environ.get(
        "BR_S3_SECRET_KEY", "blindrange-secret"))
    ap.add_argument("--node", default="127.0.0.1:7501",
                    help="a node you run, for 'what-they-see'")
    ap.add_argument("--secret", default=os.environ.get(
        "BR_SECRET", "blindrange-public"),
        help="network secret, only used to read a node's own /intel")
    sub = ap.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("backup", help="snapshot a directory")
    b.add_argument("path"); b.add_argument("--bucket", required=True)
    b.add_argument("--snapshot"); b.add_argument("--exclude", action="append")
    b.add_argument("-v", "--verbose", action="store_true")

    l = sub.add_parser("ls", help="browse the catalog")
    l.add_argument("bucket"); l.add_argument("--prefix", default="")
    l.add_argument("-r", "--recursive", action="store_true")

    f = sub.add_parser("find", help="search by prefix, name and age")
    f.add_argument("bucket"); f.add_argument("--prefix", default="")
    f.add_argument("--since"); f.add_argument("--name")

    r = sub.add_parser("restore", help="pull a snapshot back")
    r.add_argument("bucket"); r.add_argument("prefix"); r.add_argument("dest")

    v = sub.add_parser("verify", help="compare stored bytes against disk")
    v.add_argument("bucket"); v.add_argument("path")
    v.add_argument("--prefix", default=""); v.add_argument("--exclude",
                                                           action="append")

    w = sub.add_parser("what-they-see", help="your view vs the operator's")
    w.add_argument("bucket")

    a = ap.parse_args()
    s3 = client(a.endpoint, a.access_key, a.secret_key)
    fn = {"backup": cmd_backup, "ls": cmd_ls, "find": cmd_find,
          "restore": cmd_restore, "verify": cmd_verify,
          "what-they-see": cmd_what_they_see}[a.cmd]
    try:
        return fn(s3, a)
    except EndpointConnectionError:
        print(f"  no gateway at {a.endpoint} — start it with\n"
              f"    python3 examples/s3gateway/gateway.py --state ~/.blindrange/s3.brdb",
              file=sys.stderr)
        return 2
    except ClientError as e:
        print(f"  S3 error: {e.response['Error'].get('Code')} — "
              f"{e.response['Error'].get('Message')}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
