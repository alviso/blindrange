// The Node guide, as a program. https://blindrange.dev/build-node quotes
// this file, and the Python test suite runs it (tests/test_node_bridge.py
// exercises the same package) — so the samples cannot drift from working
// code.
//
//   node examples/node/quickstart.mjs                # the public network
//
// With the package installed from npm, the import is simply:
//   import { connect, UnsupportedError } from "blindrange";
import { connect, UnsupportedError } from "../../npm/blindrange/index.mjs";

const db = await connect({
  path: process.env.BR_STATE || "/tmp/blindrange-node-quickstart",
  passphrase: "quickstart passphrase",
  bootstrap: [process.env.BR_BOOTSTRAP || "seed.blindrange.dev:7501"],
  networkSecret: process.env.BR_SECRET || "blindrange-public",
});

await db.execute(`CREATE TABLE orders (
  amount   INT BITS 20 BLUR 64,
  day      INT BITS 16 BLUR 16,
  status   TEXT(6) BLUR 16,
  customer STORED
)`);

await db.execute(`INSERT INTO orders (amount, day, status, customer) VALUES
  (450, 201, 'paid', 'cust-001'),
  (120, 205, 'refunded', 'cust-002'),
  (720, 210, 'paid', 'cust-003')`);

console.log(await db.execute(
  `SELECT customer, amount FROM orders WHERE amount BETWEEN 300 AND 800
   ORDER BY amount DESC`));

console.log(await db.execute(`SELECT COUNT(*) FROM orders`));
console.log(await db.execute(`SELECT APPROX SUM(amount) FROM orders`));

await db.execute(`UPDATE orders SET status = 'shipped' WHERE amount = 450`);
await db.execute(`DELETE FROM orders WHERE day > 208`);

// The boundary arrives typed, so a refusal is never mistaken for a bug:
try {
  await db.execute(`SELECT SUM(amount) FROM orders`);
} catch (e) {
  if (e instanceof UnsupportedError) console.log("refused:", e.message);
}

await db.execute(`DROP TABLE orders`);
await db.close();
console.log("done");
