# blindrange

Range queries, prefix search and counts over storage that **cannot read
your data** — a network of nodes holding pseudorandom keys and sealed
blobs, with every key derived from a master that never leaves your
machine.

```js
import { connect } from "blindrange";

const db = await connect({
  path: "./shop",                            // back this directory up
  passphrase: "correct horse battery staple",
  bootstrap: ["seed.blindrange.dev:7501"],
  networkSecret: "blindrange-public",
});

await db.execute(`CREATE TABLE orders (
  amount   INT BITS 20 BLUR 64,
  day      INT BITS 16 BLUR 16,
  status   TEXT(6) BLUR 16,
  customer STORED
)`);

await db.execute(`INSERT INTO orders (amount, day, status, customer)
  VALUES (450, 201, 'paid', 'cust-001')`);

const rows = await db.execute(
  `SELECT * FROM orders WHERE amount BETWEEN 300 AND 500`);

await db.close();
```

The statement language is **shaped like SQL and deliberately not SQL**:
everything the engine genuinely cannot do — `JOIN`, `OR`, exact `SUM()`,
leading-wildcard `LIKE` — is refused with a message that names why and
what to use instead (`UnsupportedError`). The full dialect and the
reasoning: https://blindrange.dev/build

## How this package works, honestly

It is **not** a JavaScript reimplementation. It spawns the reference
Python client as a child process it owns — a self-contained CPython
ships as a platform-specific optional dependency, so there is nothing to
install and no daemon to run. Stdio only: no port exists, so nothing
else on the machine can connect to your database, and the child dies
with your process.

Why: the client is where all cryptography lives. A parallel JS
implementation would have to match it byte-for-byte forever, and every
divergence would be silent data corruption. Running the reference means
there is exactly one implementation of everything that matters.

Costs, stated plainly: ~25 MB download for the bundled runtime, and
~100 ms child start per `connect()`. If the bundled runtime is missing
for your platform, the package falls back to `python3` on PATH with
`blindrange` installed, or an explicit path via `BLINDRANGE_PYTHON`.

## What this is not for

A research prototype on a demo network with no durability promises. Not
for healthcare or high-stakes PII — the threat model says exactly what
leaks and why: https://github.com/alviso/blindrange#threat-model
