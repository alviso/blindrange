/* Cross-language harness half: driven by tests/test_webclient.py.
 *
 * Reads a JSON job from argv[2] (path), performs the requested phase
 * against a REAL local network started by the Python side, and prints a
 * JSON result on stdout. Any thrown error fails the phase loudly.
 *
 * Phases:
 *   vectors  — derive keys/labels from a fixed master; Python asserts
 *              byte-equality (drift here = silent corruption, caught).
 *   accept   — accept a Python invite, query ranges + prefix, insert
 *              rows, claim sequence values, delete one Python rid.
 */
import { readFileSync } from "node:fs";
import { Owner, memoryAdapter, encodeStr, levelsFor, dyadicCover }
  from "../../web/blindrange.mjs";

const job = JSON.parse(readFileSync(process.argv[2], "utf8"));
const out = {};

if (job.phase === "vectors") {
  const adapter = memoryAdapter();
  // create against the live net but with a PINNED master: reach into
  // state pre-registration is not possible via the public API, so build
  // the derivations directly through a throwaway Owner.
  const o = await Owner.create(adapter, "pw", job.schema, job.bootstrap,
    { networkSecret: job.secret });
  o._st.master = job.master;
  o._master = Uint8Array.from(job.master.match(/.{2}/g)
    .map((x) => parseInt(x, 16)));
  o._kw = new Map();
  const kw = await o._kW("amount|3|5");
  out.ut = await o._ut(kw, 2, "deadbeefdeadbeef", 7);
  out.mask = Array.from(await o._mask(kw, 2, "deadbeefdeadbeef", 7));
  out.sys_key = await o._sysKey("epoch", 3);
  out.seq_key = await o._sysKey("seq:inv", 12);
  out.registry_key = await o._sysKey("registry", 1);
  out.key_bucket = await o.keyBucket("id", "doc-42");
  out.encode_str = encodeStr("sable", 4).toString();
  out.levels = levelsFor(777, 11, 8);
  out.cover = dyadicCover(100, 200, 11, 8);
} else if (job.phase === "accept") {
  const o = await Owner.accept(memoryAdapter(), "js pass", job.invite);
  const q1 = await o.query("amount", 100000, 300000);
  out.range_rows = q1.map((r) => r.row).sort((a, b) => a - b);
  const q2 = await o.queryPrefix("name", "sa");
  out.prefix_rows = q2.map((r) => r.row).sort((a, b) => a - b);
  await o.insertMany(job.new_rows);
  const seqs = [];
  seqs.push(await o.nextValue("inv"));
  seqs.push(...await o.nextValues("inv", 3));
  out.seq_values = seqs;
  out.bucket = await o.keyBucket("id", "doc-1");
  if (job.delete_rid) {
    // find the rid by row marker, then tombstone it from JS
    const all = await o.query("amount", 0, 1048575);
    const victim = all.find((r) => r.row === job.delete_rid);
    out.deleted = victim ? await o.delete(victim._rid) : 0;
  }
  const after = await o.query("amount", 0, 1048575);
  out.total_after = after.length;

  if (job.gateway) {
    // Same database, but every byte through ONE node's /fwd — the path
    // an HTTPS page must take. Answers must be identical.
    const g = await Owner.accept(memoryAdapter(), "gw pass", job.invite,
      { gateway: job.gateway });
    const gq = await g.query("amount", 100000, 300000);
    out.gateway_range_rows = gq.map((r) => r.row).sort((a, b) => a - b);
  }
}

process.stdout.write(JSON.stringify(out));
