"""An S3-compatible front door to storage that cannot read what it holds.

Almost everything that archives data can already write to S3. Backup tools,
log shippers, compliance archivers, Loki, rclone — the API is the lingua
franca of "put this somewhere and keep it." Speaking it is therefore worth
more than any number of bespoke integrations: it turns blindrange from
something you port to into something existing software can target today.

WHERE THIS PROCESS RUNS IS THE ENTIRE SECURITY MODEL, and it is worth being
blunt because S3 gateways are usually hosted for you. The master key lives
in this process. Objects are encrypted here, before anything leaves the
machine, and the nodes that store them hold pseudorandom keys and AEAD
blobs. Run it as a sidecar next to whatever is writing. If we hosted it,
we would hold your keys, and the only reason to choose this over S3 would
be gone. Storj draws exactly this line between its hosted gateway and its
self-hosted one; so do we, and we do not offer the hosted half.

HOW AN OBJECT IS STORED. Two pieces, deliberately:

  * a RECORD, indexed on bucket, key, mtime and size — this is what makes
    ListObjectsV2 with a prefix a native operation rather than a scan
  * its BYTES, as unindexed AEAD chunks spread across the ring, so a large
    object does not land whole on one replica set and does not pay for
    index entries nobody will ever query

WHAT IS AND IS NOT IMPLEMENTED is listed in README.md. The short version:
enough for archival writes, prefix listing, reads and deletes, including
multipart. Not a general-purpose S3 replacement, and it says so rather than
failing mysteriously on the parts it lacks.

  python3 examples/s3gateway/gateway.py --state ~/.blindrange/s3.brdb \\
      --bootstrap seed.blindrange.dev:7501 --secret blindrange-public
"""
import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import quote, unquote, urlparse, parse_qs
from xml.sax.saxutils import escape

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from blindrange import Owner  # noqa: E402

MAX_KEY = 1024
# Object keys are paths, so a prefix listing has to discriminate on more
# than a handful of characters — "logs/2026/08/" is 13 in before it means
# anything. 12 characters at 5 bits each is the widest the dyadic index
# takes while staying one field.
KEY_CHARS = 12


def schema():
    return {
        "bucket": {"type": "str", "bits": 40, "chars": 8, "leaf_width": 16},
        "okey":   {"type": "str", "bits": KEY_CHARS * 5, "chars": KEY_CHARS,
                   "leaf_width": 16},
        "mtime":  {"type": "int", "bits": 31, "leaf_width": 64},
        "size":   {"type": "int", "bits": 40, "leaf_width": 4096},
    }


def rfc3339(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S.000Z")


# ---------------------------------------------------------------- SigV4

def canonical_query(query):
    """SigV4's canonical query string: RFC3986-encode, then sort.

    Pulled out as a function because it is where this went wrong once and
    would go wrong again silently — an unfiltered listing signs fine while
    every prefixed one fails, so the bug hides behind the case people try
    first.
    """
    def enc(x):
        return quote(str(x), safe="-_.~")
    return "&".join(f"{enc(k)}={enc(v[0] if isinstance(v, list) else v)}"
                    for k, v in sorted(query.items()))


def _sig_key(secret, date, region, service):
    k = ("AWS4" + secret).encode()
    for part in (date, region, service, "aws4_request"):
        k = hmac.new(k, part.encode(), hashlib.sha256).digest()
    return k


class Auth:
    """SigV4 verification.

    Implemented rather than waved away because the alternative — accepting
    any credentials because the socket is on loopback — is exactly the
    assumption that stops being true the first time someone binds this to
    an interface. Verifying also means a wrong secret fails at the door
    with an S3 error the client understands, instead of writing garbage.

    Streaming uploads are accepted with the payload hash unverified: the
    aws-chunked framing carries per-chunk signatures that add nothing here,
    where the transport is a loopback socket. That is a deliberate,
    documented limit, not an oversight.
    """

    STREAMING = {"STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
                 "STREAMING-UNSIGNED-PAYLOAD-TRAILER",
                 "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER"}

    def __init__(self, access_key, secret_key, region="us-east-1"):
        self.access_key = access_key
        self.secret_key = secret_key
        self.region = region

    def check(self, method, path, query, headers, body_sha):
        if not self.secret_key:
            return True                      # explicitly disabled
        auth = headers.get("Authorization", "")
        m = re.match(r"AWS4-HMAC-SHA256\s+Credential=([^/]+)/(\d{8})/([^/]+)/"
                     r"([^/]+)/aws4_request,\s*SignedHeaders=([^,]+),\s*"
                     r"Signature=([0-9a-f]+)", auth)
        if not m:
            return False
        akid, date, region, service, signed, sig = m.groups()
        if akid != self.access_key:
            return False
        canon_headers = ""
        for h in signed.split(";"):
            v = headers.get(h, "")
            canon_headers += f"{h}:{' '.join(str(v).split())}\n"
        qs = canonical_query(query)
        canon = "\n".join([method, path, qs, canon_headers, signed, body_sha])
        scope = f"{date}/{region}/{service}/aws4_request"
        to_sign = "\n".join([
            "AWS4-HMAC-SHA256",
            headers.get("x-amz-date", ""), scope,
            hashlib.sha256(canon.encode()).hexdigest()])
        want = hmac.new(_sig_key(self.secret_key, date, region, service),
                        to_sign.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(want, sig)


def decode_chunked(body):
    """Undo aws-chunked framing.

    Clients using STREAMING-* wrap the payload in their own chunk headers,
    which are not HTTP chunked encoding and are not removed by the server
    stack. Storing the body as-is would silently save an object with size
    headers interleaved through it — corruption that only surfaces on
    restore, which for an archive is the worst possible time.
    """
    out, i = bytearray(), 0
    while i < len(body):
        nl = body.find(b"\r\n", i)
        if nl < 0:
            break
        header = body[i:nl].split(b";")[0].strip()
        try:
            n = int(header, 16)
        except ValueError:
            break
        i = nl + 2
        if n == 0:
            break
        out += body[i:i + n]
        i += n + 2
    return bytes(out)


class Store:
    """Objects as records; bytes as unindexed blobs beside them."""

    def __init__(self, owner):
        self.owner = owner
        self.lock = threading.Lock()
        self.uploads = {}            # uploadId -> {bucket,key,parts:{n:bytes}}

    # ---- naming -------------------------------------------------------
    @staticmethod
    def blob_name(bucket, key, version):
        return f"{bucket}/{key}#{version}"

    # ---- writes -------------------------------------------------------
    def put(self, bucket, key, body):
        etag = hashlib.md5(body).hexdigest()
        version = uuid.uuid4().hex[:12]
        name = self.blob_name(bucket, key, version)
        chunks = self.owner.put_blob(name, body)
        rec = {"bucket": bucket, "okey": key[:MAX_KEY], "mtime": int(time.time()),
               "size": len(body), "etag": etag, "version": version,
               "chunks": chunks, "fullkey": key}
        with self.lock:
            # Overwrite is a new record plus removal of the old, because the
            # index is append-only: without the delete, a listing would show
            # the same key twice and a GET would be a coin toss.
            old = self._find(bucket, key)
            self.owner.insert(rec)
            if old:
                self._forget(old)
        return etag

    def _forget(self, rec):
        try:
            self.owner.delete(rec["_rid"])
        except Exception:
            pass
        try:
            self.owner.delete_blob(
                self.blob_name(rec["bucket"], rec["fullkey"], rec["version"]),
                int(rec.get("chunks", 1)))
        except Exception:
            pass

    def delete(self, bucket, key):
        with self.lock:
            rec = self._find(bucket, key)
            if rec:
                self._forget(rec)
            return bool(rec)

    # ---- reads --------------------------------------------------------
    def _candidates(self, bucket, prefix=""):
        preds = [{"field": "bucket", "prefix": bucket}]
        if prefix:
            preds.append({"field": "okey", "prefix": prefix[:KEY_CHARS]})
        else:
            preds.append({"field": "mtime", "lo": 0, "hi": (1 << 31) - 1})
        return self.owner.query_multi(preds)

    def _find(self, bucket, key):
        for r in self._candidates(bucket, key):
            if r.get("bucket") == bucket and r.get("fullkey") == key:
                return r
        return None

    def head(self, bucket, key):
        return self._find(bucket, key)

    def get(self, bucket, key):
        rec = self._find(bucket, key)
        if not rec:
            return None, None
        body = self.owner.get_blob(
            self.blob_name(bucket, rec["fullkey"], rec["version"]),
            int(rec.get("chunks", 1)))
        return rec, body

    def list(self, bucket, prefix="", delimiter="", max_keys=1000, after=""):
        """ListObjectsV2, including the delimiter behaviour that makes S3
        browsers show folders. Prefix filtering is native — a dyadic prefix
        cover on the key field — and the final exact match is done here
        because the index resolves only the first characters."""
        rows = [r for r in self._candidates(bucket, prefix)
                if r.get("bucket") == bucket
                and str(r.get("fullkey", "")).startswith(prefix)]
        rows.sort(key=lambda r: r.get("fullkey", ""))
        keys, common = [], set()
        for r in rows:
            k = r["fullkey"]
            if after and k <= after:
                continue
            if delimiter:
                rest = k[len(prefix):]
                if delimiter in rest:
                    common.add(prefix + rest.split(delimiter)[0] + delimiter)
                    continue
            keys.append(r)
        truncated = len(keys) > max_keys
        return keys[:max_keys], sorted(common), truncated

    # ---- multipart ----------------------------------------------------
    def create_upload(self, bucket, key):
        uid = uuid.uuid4().hex
        with self.lock:
            self.uploads[uid] = {"bucket": bucket, "key": key, "parts": {}}
        return uid

    def put_part(self, uid, n, body):
        with self.lock:
            up = self.uploads.get(uid)
            if up is None:
                return None
            up["parts"][n] = body
        return hashlib.md5(body).hexdigest()

    def complete_upload(self, uid, wanted):
        with self.lock:
            up = self.uploads.pop(uid, None)
        if up is None:
            return None
        order = wanted or sorted(up["parts"])
        body = b"".join(up["parts"].get(n, b"") for n in order)
        etag = self.put(up["bucket"], up["key"], body)
        return up["bucket"], up["key"], etag

    def abort_upload(self, uid):
        with self.lock:
            return self.uploads.pop(uid, None) is not None

    def buckets(self):
        seen = {}
        for r in self.owner.query_stream(
                [{"field": "mtime", "lo": 0, "hi": (1 << 31) - 1}], limit=5000):
            b = r.get("bucket")
            if b:
                seen[b] = min(seen.get(b, 1 << 62), r.get("mtime", 0))
        return seen


def xml(body):
    return ('<?xml version="1.0" encoding="UTF-8"?>\n' + body).encode()


def err(code, message, status):
    return status, xml(f"<Error><Code>{code}</Code>"
                       f"<Message>{escape(message)}</Message></Error>")


def make_handler(store, auth):
    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "blindrange-s3"

        def log_message(self, *a):
            pass

        # ---- plumbing -------------------------------------------------
        def _h(self):
            return {k.lower(): v for k, v in self.headers.items()}

        def _split(self):
            u = urlparse(self.path)
            parts = unquote(u.path).lstrip("/").split("/", 1)
            bucket = parts[0] if parts and parts[0] else ""
            key = parts[1] if len(parts) > 1 else ""
            return bucket, key, parse_qs(u.query, keep_blank_values=True), u.path

        def _body(self):
            n = int(self.headers.get("Content-Length", 0) or 0)
            raw = self.rfile.read(n) if n else b""
            if self._h().get("x-amz-content-sha256") in Auth.STREAMING:
                raw = decode_chunked(raw)
            return raw

        def _auth_ok(self, method, query, raw_path):
            h = self._h()
            sha = h.get("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
            return auth.check(method, urlparse(raw_path).path, query,
                              {**h, **{k: v for k, v in self.headers.items()}},
                              sha)

        def _send(self, status, body=b"", extra=None):
            extra = extra or {}
            self.send_response(status)
            self.send_header("Content-Type", "application/xml")
            # HEAD reports the OBJECT's length while sending no body, so the
            # caller supplies Content-Length and the default must not also
            # be emitted — two conflicting values make a strict client abort
            # rather than fall back.
            if not any(k.lower() == "content-length" for k in extra):
                self.send_header("Content-Length", str(len(body)))
            for k, v in extra.items():
                self.send_header(k, str(v))
            self.end_headers()
            if self.command != "HEAD" and body:
                self.wfile.write(body)

        def _deny(self):
            st, body = err("SignatureDoesNotMatch",
                           "the request signature did not match", 403)
            self._send(st, body)

        # ---- verbs ----------------------------------------------------
        def do_GET(self):
            bucket, key, q, raw = self._split()
            if not self._auth_ok("GET", q, raw):
                return self._deny()
            if not bucket:
                return self._list_buckets()
            if not key:
                return self._list_objects(bucket, q)
            rec, body = store.get(bucket, key)
            if rec is None:
                st, b = err("NoSuchKey", f"no such key: {key}", 404)
                return self._send(st, b)
            if body is None:
                # A record with unreadable bytes is corruption, and saying
                # "not found" would hide it. Archives must fail loudly.
                st, b = err("InternalError",
                            "object bytes are missing or undecryptable", 500)
                return self._send(st, b)
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("ETag", f'"{rec["etag"]}"')
            self.send_header("Last-Modified", self.date_time_string(rec["mtime"]))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def do_HEAD(self):
            bucket, key, q, raw = self._split()
            if not self._auth_ok("HEAD", q, raw):
                return self._deny()
            if not key:
                return self._send(200 if bucket else 404)
            rec = store.head(bucket, key)
            if not rec:
                return self._send(404)
            self._send(200, b"", {"ETag": f'"{rec["etag"]}"',
                                  "Content-Length": rec["size"],
                                  "Last-Modified": self.date_time_string(rec["mtime"])})

        def do_PUT(self):
            bucket, key, q, raw = self._split()
            if not self._auth_ok("PUT", q, raw):
                return self._deny()
            body = self._body()
            if not key:
                return self._send(200)              # CreateBucket: implicit
            if "partNumber" in q and "uploadId" in q:
                etag = store.put_part(q["uploadId"][0],
                                      int(q["partNumber"][0]), body)
                if etag is None:
                    st, b = err("NoSuchUpload", "unknown uploadId", 404)
                    return self._send(st, b)
                return self._send(200, b"", {"ETag": f'"{etag}"'})
            etag = store.put(bucket, key, body)
            self._send(200, b"", {"ETag": f'"{etag}"'})

        def do_POST(self):
            bucket, key, q, raw = self._split()
            if not self._auth_ok("POST", q, raw):
                return self._deny()
            body = self._body()
            if "uploads" in q:
                uid = store.create_upload(bucket, key)
                return self._send(200, xml(
                    f"<InitiateMultipartUploadResult><Bucket>{escape(bucket)}"
                    f"</Bucket><Key>{escape(key)}</Key><UploadId>{uid}"
                    f"</UploadId></InitiateMultipartUploadResult>"))
            if "uploadId" in q:
                wanted = [int(n) for n in
                          re.findall(r"<PartNumber>(\d+)</PartNumber>",
                                     body.decode("utf-8", "replace"))]
                done = store.complete_upload(q["uploadId"][0], wanted)
                if done is None:
                    st, b = err("NoSuchUpload", "unknown uploadId", 404)
                    return self._send(st, b)
                b_, k_, etag = done
                return self._send(200, xml(
                    f"<CompleteMultipartUploadResult><Bucket>{escape(b_)}"
                    f"</Bucket><Key>{escape(k_)}</Key><ETag>&quot;{etag}&quot;"
                    f"</ETag></CompleteMultipartUploadResult>"))
            if "delete" in q:                       # DeleteObjects
                keys = re.findall(r"<Key>(.*?)</Key>",
                                  body.decode("utf-8", "replace"))
                out = "".join(f"<Deleted><Key>{escape(k)}</Key></Deleted>"
                              for k in keys if store.delete(bucket, k))
                return self._send(200, xml(f"<DeleteResult>{out}</DeleteResult>"))
            st, b = err("NotImplemented", "unsupported POST", 501)
            self._send(st, b)

        def do_DELETE(self):
            bucket, key, q, raw = self._split()
            if not self._auth_ok("DELETE", q, raw):
                return self._deny()
            if "uploadId" in q:
                store.abort_upload(q["uploadId"][0])
                return self._send(204)
            if key:
                store.delete(bucket, key)
            self._send(204)

        # ---- listings -------------------------------------------------
        def _list_buckets(self):
            rows = "".join(
                f"<Bucket><Name>{escape(b)}</Name>"
                f"<CreationDate>{rfc3339(t)}</CreationDate></Bucket>"
                for b, t in sorted(store.buckets().items()))
            self._send(200, xml(
                f"<ListAllMyBucketsResult><Owner><ID>blindrange</ID></Owner>"
                f"<Buckets>{rows}</Buckets></ListAllMyBucketsResult>"))

        def _list_objects(self, bucket, q):
            prefix = q.get("prefix", [""])[0]
            delim = q.get("delimiter", [""])[0]
            after = q.get("start-after", [q.get("marker", [""])[0]])[0]
            token = q.get("continuation-token", [""])[0]
            if token:
                after = base64.b64decode(token).decode("utf-8", "replace")
            maxk = min(int(q.get("max-keys", ["1000"])[0] or 1000), 1000)
            keys, common, truncated = store.list(bucket, prefix, delim, maxk, after)
            body = [f"<ListBucketResult><Name>{escape(bucket)}</Name>"
                    f"<Prefix>{escape(prefix)}</Prefix>"
                    f"<KeyCount>{len(keys)}</KeyCount>"
                    f"<MaxKeys>{maxk}</MaxKeys>"
                    f"<IsTruncated>{'true' if truncated else 'false'}</IsTruncated>"]
            if delim:
                body.append(f"<Delimiter>{escape(delim)}</Delimiter>")
            for r in keys:
                body.append(
                    f"<Contents><Key>{escape(r['fullkey'])}</Key>"
                    f"<LastModified>{rfc3339(r['mtime'])}</LastModified>"
                    f"<ETag>&quot;{r['etag']}&quot;</ETag>"
                    f"<Size>{r['size']}</Size>"
                    f"<StorageClass>STANDARD</StorageClass></Contents>")
            for c in common:
                body.append(f"<CommonPrefixes><Prefix>{escape(c)}</Prefix>"
                            f"</CommonPrefixes>")
            if truncated and keys:
                nxt = base64.b64encode(keys[-1]["fullkey"].encode()).decode()
                body.append(f"<NextContinuationToken>{nxt}</NextContinuationToken>")
            body.append("</ListBucketResult>")
            self._send(200, xml("".join(body)))
    return H


def main():
    ap = argparse.ArgumentParser(description="S3-compatible blindrange gateway")
    ap.add_argument("--state", default=os.path.expanduser("~/.blindrange/s3.brdb"))
    ap.add_argument("--passphrase", default=os.environ.get("BR_S3_PASS", "s3"))
    ap.add_argument("--bootstrap", default="seed.blindrange.dev:7501")
    ap.add_argument("--secret", default="blindrange-public")
    ap.add_argument("--issuer", default="https://tokens.blindrange.dev")
    ap.add_argument("--account", default=os.environ.get("BR_ACCOUNT", ""))
    ap.add_argument("--access-key", default=os.environ.get("BR_S3_ACCESS_KEY",
                                                           "blindrange"))
    ap.add_argument("--secret-key", default=os.environ.get("BR_S3_SECRET_KEY",
                                                           "blindrange-secret"))
    ap.add_argument("--no-auth", action="store_true",
                    help="skip SigV4 verification (loopback testing only)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8720)
    a = ap.parse_args()

    if os.path.exists(a.state):
        owner = Owner.open(a.state, a.passphrase, bootstrap=[a.bootstrap])
    else:
        owner = Owner.create(a.state, a.passphrase, schema(),
                             bootstrap=[a.bootstrap], network_secret=a.secret)
    if a.account:
        owner.configure_tokens(a.issuer, a.account)
    store = Store(owner)
    auth = Auth(a.access_key, "" if a.no_auth else a.secret_key)
    if a.host != "127.0.0.1" and a.no_auth:
        print("refusing to serve unauthenticated on a non-loopback address",
              file=sys.stderr)
        sys.exit(2)
    print(f"blindrange-s3 on http://{a.host}:{a.port}  ·  state {a.state}\n"
          f"  keys never leave this process; nodes hold AEAD blobs only\n"
          f"  access key {a.access_key}"
          f"{'  ·  SIGNATURE CHECKS OFF' if a.no_auth else ''}", flush=True)
    ThreadingHTTPServer((a.host, a.port), make_handler(store, auth)).serve_forever()


if __name__ == "__main__":
    main()
