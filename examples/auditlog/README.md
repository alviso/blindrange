# blindrange-audit

An append-only audit trail stored on machines that cannot read or alter it.

Of everything that could be built on blindrange, an audit log is the one
workload where this is the better fit *on the merits* rather than a privacy
tax paid on top of a worse database:

| audit trails need | blindrange gives |
|---|---|
| append-only history | per-writer PRF counter chains — rewriting was never expressible |
| tamper-evidence | AES-GCM per record: an altered blob does not decrypt |
| filter by actor / action / time, newest first | prefix + prefix + range, ordered by walking dyadic leaves |
| a holder who cannot read them | nodes hold pseudorandom keys and opaque blobs |

The last row is the point. For most data, "the vendor can read it" is a
feature you tolerate. For an audit trail it is a liability.

## Run it

```bash
python3 examples/auditlog/audit.py \
    --state ~/.blindrange/audit.brdb \
    --bootstrap seed.blindrange.dev:7501 \
    --secret blindrange-public \
    --account <your key from tokens.blindrange.dev/signup>
```

Then `http://127.0.0.1:8710` — search by actor, action and time window, with
a panel showing the same rows as *you* see them and as a **node operator**
sees them.

**Where this process runs is the whole security model.** The keys live here
and in the `.brdb` file beside it, never on a node and never with us. Run it
next to whatever produces your events. This is the same fork Storj draws
between its hosted S3 gateway (keys server-side) and the self-hosted one
(end-to-end) — the convenience of hosting it for you would cost exactly the
property you came for.

## Sending events from what you already run

There is no plugin to write. The major shippers all have a generic HTTP
output, so this is configuration:

**Vector**

```toml
[sinks.blindrange]
type      = "http"
inputs    = ["your_source"]
uri       = "http://127.0.0.1:8710/ingest"
method    = "post"
encoding.codec = "json"
```

**Fluent Bit**

```ini
[OUTPUT]
    Name   http
    Match  *
    Host   127.0.0.1
    Port   8710
    URI    /ingest
    Format json
```

**OpenTelemetry Collector**

```yaml
exporters:
  otlphttp/blindrange:
    logs_endpoint: http://127.0.0.1:8710/ingest
    encoding: json
service:
  pipelines:
    logs:
      exporters: [otlphttp/blindrange]
```

**Anything else**

```bash
curl -X POST http://127.0.0.1:8710/ingest -H 'Content-Type: application/json' \
  -d '{"actor":"alice@corp","action":"role.grant","target":"billing-admin"}'
```

Ingest accepts a single object, a JSON array, NDJSON, or an OTLP/JSON logs
envelope, and it unwraps OTLP into individual records rather than storing a
batch as one unqueryable blob. Timestamps are read from `ts`, `timestamp`,
`time`, `@timestamp` or `timeUnixNano`, in seconds, milliseconds or
nanoseconds; the actor from `actor`, `user`, `principal` or `subject`; the
action from `action`, `event`, `operation` or `message`. Everything else
rides along inside the encrypted payload. Being forgiving here is
deliberate: an audit pipeline that drops events over a key name is worse
than no pipeline.

## The privacy dial

`--leaf` sets the time resolution that **nobody** — not a node operator,
not someone logging every query you ever run — can ever exceed. It must be
a power of two, so a human interval is snapped and the real bound is
printed rather than the one you asked for:

```
--leaf 3600   ->  leaf_width 4096  (1.1 hours)
--leaf 60     ->  leaf_width 64    (1.1 minutes)
```

It is also the cost dial. Finer resolution means more dyadic levels, so
more index entries per event — see the calculator at blindrange.dev.
Coarser is cheaper *and* more private, which is the unusual direction.

## What it deliberately does not do

- **No delete, no compact.** Both exist in the SDK; neither is exposed. An
  audit trail whose own tooling can drop entries answers the wrong question
  when someone asks whether records could have been removed. Retention has
  to arrive as deliberate epoch-level expiry, not a route sitting next to
  `/ingest`.
- **No full-text search over payloads.** You filter by actor, action and
  time, then read what comes back — which is how audit logs are actually
  read. Claiming otherwise would need a different scheme with a different
  leakage profile.
- **No GROUP BY.** `/count` is answered from index metadata with zero
  records fetched, accurate to one leaf. The privacy budget shows up as the
  error bar.

## On compliance, carefully

SEC Rule 17a-4 was amended in 2022 to add an **audit-trail alternative** to
WORM: instead of write-once media, a system may qualify if it can recreate
an original record after any change and produce a complete, time-stamped
account of what happened. Append-only chains plus per-record AEAD sit much
closer to that alternative than to WORM, which this design cannot offer at
all — compaction rewrites, by construction.

That is a description of the regulation, **not a claim of compliance**. No
lawyer has reviewed this and none of it has been assessed against 17a-4,
FINRA 4511, or anything else. Treat it as the reason the question is worth
asking, not as an answer.
