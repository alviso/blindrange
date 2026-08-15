# s3backup — off-site backup with a catalog you can search

A demo of the [S3 gateway](../s3gateway), written with a plain S3 client and
**no blindrange imports at all**. That is the point: everything here would
work unchanged against AWS. The only difference is where the endpoint
points, and that difference is what makes the bytes unreadable to whoever
stores them.

Backing up a directory to object storage is the most ordinary thing in the
world, which makes it a fair test of whether the gateway is really usable.

## The gap it fills

| | catalog you can search | host cannot read it |
|---|---|---|
| plain S3 | yes | no — the provider reads everything |
| client-side encryption over S3 | no — you encrypted the names too | yes |
| **this** | **yes** | **yes** |

Encrypting before upload is easy; it just takes the catalog with it, and
you end up with a bucket of opaque blobs and a local index you have to keep
safe separately. Here the listing survives, because a prefix query is a
dyadic index lookup over encrypted keys rather than a scan of anything
readable.

## Run it

```bash
# one terminal: the gateway (this is where your keys live)
python3 examples/s3gateway/gateway.py --state ~/.blindrange/s3.brdb \
    --bootstrap seed.blindrange.dev:7501 --secret blindrange-public

# another: back something up
pip install boto3
python3 examples/s3backup/backup.py backup ~/src --bucket work
python3 examples/s3backup/backup.py ls work
python3 examples/s3backup/backup.py find work --name '*.py' --since 1h
python3 examples/s3backup/backup.py restore work <snapshot> /tmp/restored
python3 examples/s3backup/backup.py what-they-see work --secret <network secret>
```

## Measured, on a three-node network

Backing up `blindrange/` — 14 files, 259,724 bytes:

```
snapshot 20260815T180000Z: 14 files, 259,724 bytes in 0.3s (782 kB/s)

find work --name '*.py'   →  13 of 14 objects
restore + verify          →  14 identical, 0 differ, 0 missing
diff -r original restored →  IDENTICAL to the original tree
```

And the same data from the other side of the wire:

```
what YOU see:
      14,714  20260815T180000Z/direct.py

what the machine storing it sees:
  B:0c31fd78ff7a2432bd4eec2a0e68d5dd  ->  FkVzGNFZ1d9mPoXmYJUeluoF
  B:5619f394bdb1bd32fb6e1e5d587bec10  ->  46jrSv2aUjqM8ovsEcQFCdvT
  B:84d4adfbff87589b75b535fe8983e10f  ->  SN2A8eOTOaTkUFIaBEJ0PkE7

  2,059 keys on that node, none of them readable,
  none of them named after your files
```

Note what is absent from the second view: not just the contents, but the
**filenames and the directory structure**. `direct.py` does not appear
anywhere on any node.

## Honest notes

- **`verify` re-downloads.** It compares stored bytes against the local file
  rather than trusting a recorded hash, because a backup tool that reports
  success without checking what it wrote is theatre.
- **Restore checks size on the way out** and fails loudly rather than
  writing a short file. A corrupt restore is discovered at the worst
  possible moment.
- **Snapshots are whole copies, not incremental.** There is no dedup and no
  delta encoding, so a second snapshot of the same tree costs the same as
  the first. Fine for a demo, expensive for real use — see the
  [calculator](https://blindrange.dev/#pricing).
- **No compression, no exclusion of large binaries** beyond the obvious
  (`.git`, `__pycache__`, `node_modules`).
- **`what-they-see` needs the network secret**, because `/intel` is
  membership-gated. It is a demo affordance for a network you run, not
  something a stranger can point at someone else's node.
