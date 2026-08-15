# blindrange-s3

An S3-compatible endpoint in front of storage that cannot read what it holds.

Almost everything that archives data can already write to S3 — backup tools,
log shippers, compliance archivers, Loki, rclone. Speaking that API is worth
more than any number of bespoke integrations, because it turns blindrange
from something you port to into something existing software can target
today.

```bash
python3 examples/s3gateway/gateway.py \
    --state ~/.blindrange/s3.brdb \
    --bootstrap seed.blindrange.dev:7501 \
    --secret blindrange-public \
    --access-key blindrange --secret-key <choose one> \
    --account <key from tokens.blindrange.dev/signup>
```

Then point anything at `http://127.0.0.1:8720` with path-style addressing.

```python
s3 = boto3.client("s3", endpoint_url="http://127.0.0.1:8720",
                  aws_access_key_id="blindrange", aws_secret_access_key="...",
                  config=Config(s3={"addressing_style": "path"}))
s3.put_object(Bucket="archive", Key="logs/2026/08/app.log", Body=data)
```

```ini
# rclone
[blindrange]
type = s3
provider = Other
endpoint = http://127.0.0.1:8720
access_key_id = blindrange
secret_access_key = ...
force_path_style = true
```

## Run it beside your data, never in front of it

**Where this process runs is the entire security model.** The master key
lives here. Objects are encrypted here, before anything leaves the machine,
and the nodes holding them see pseudorandom keys and AEAD blobs.

This is the same line [Storj draws](https://storj.dev/dcs/api/s3/s3-compatible-gateway)
between its hosted gateway, where keys sit server-side, and its self-hosted
one that keeps encryption end-to-end. Hosting this for you would be more
convenient and would remove the only reason to choose it over S3, so we
don't offer that.

Verified, not asserted: with a `TOP-SECRET-MARKER` payload written to
`confidential/salaries.csv`, a scan of every key and value on all three
nodes' disks finds the payload absent, the filename absent, and the path
absent — while the object still reads back byte-identical. That check is
`test_09_nodes_hold_nothing_readable` in `tests/test_s3gateway.py`.

## How an object is stored

Two pieces, deliberately split:

- a **record**, indexed on bucket, key, mtime and size — which is what makes
  `ListObjectsV2` with a prefix a native dyadic lookup rather than a scan
- its **bytes**, as unindexed AEAD chunks (512 kB) spread across the ring,
  so a large object doesn't land whole on one replica set and doesn't pay
  for index entries nobody will ever query

## What works

Verified against **boto3** — an independent SigV4 implementation, which is
the only way to know the signer is right rather than merely self-consistent.

| | |
|---|---|
| `PutObject` / `GetObject` / `HeadObject` / `DeleteObject` | yes |
| `ListObjectsV2`, prefix, delimiter, continuation tokens | yes |
| `ListBuckets`, `CreateBucket`, `DeleteObjects` | yes |
| Multipart upload | yes — verified with a 5 MB boto3 `upload_file` |
| SigV4 signature verification | yes |
| `aws-chunked` streaming bodies | decoded |
| Large objects | verified byte-identical at 3 MB and 5 MB |

## What does not work, stated plainly

- **No versioning, ACLs, bucket policies, lifecycle rules, tagging, CORS,
  or presigned URLs.** An overwrite replaces the object.
- **No range GETs.** A `Range:` header is ignored and the whole object is
  returned, which will disappoint anything that seeks inside archives.
- **Buckets are implicit.** `CreateBucket` succeeds without creating
  anything; a bucket exists once it holds an object.
- **Multipart parts are held in memory** until completion, so a very large
  multipart upload is bounded by RAM.
- **Streaming payload signatures are not verified.** The `aws-chunked`
  per-chunk signatures are accepted without checking, since the transport
  is a loopback socket. Binding to a non-loopback interface with
  `--no-auth` is refused outright for the same reason.
- **Listing is bounded** by what the index can discriminate: the key field
  resolves the first 12 characters, and exact prefix matching is finished
  client-side. Correct, but a listing under a very deep shared prefix does
  more work than S3 would.

## Cost

Object bytes are unindexed, so they cost storage and replication and no
index amplification — much cheaper per byte than records. The *record* per
object is small and fixed. See the calculator at
[blindrange.dev](https://blindrange.dev/#pricing); an archive of few large
objects sits at the cheap end of the range, near object-storage pricing.
