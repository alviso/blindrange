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

  {
    // mirror + sync must see EXACTLY what direct queries see — the
    // level-1-only sync shortcut passed every other test and returned
    // zero rows in production
    const mo = await Owner.accept(memoryAdapter(), "mir pass", job.invite);
    await mo.enableMirror();
    await mo.sync();
    const viaMirror = await mo.query("amount", 100000, 300000);
    out.mirror_range_rows = viaMirror.map((r) => r.row).sort((a, b) => a - b);
    const pfx = await mo.queryPrefix("name", "sa");
    out.mirror_prefix_rows = pfx.map((r) => r.row).sort((a, b) => a - b);
  }

  if (job.gateway) {
    // Same database, but every byte through ONE node's /fwd — the path
    // an HTTPS page must take. Answers must be identical.
    const g = await Owner.accept(memoryAdapter(), "gw pass", job.invite,
      { gateway: job.gateway });
    const gq = await g.query("amount", 100000, 300000);
    out.gateway_range_rows = gq.map((r) => r.row).sort((a, b) => a - b);
  }
}

else if (job.phase === "mirrorstress") {
  // The derived-tree sync predicts the key set from the RECORDS, so
  // its hazard is records that exist in a label chain but can no
  // longer be read: deletions. Delete several, insert after deleting
  // (so live and dead entries interleave at every level), then demand
  // that a mirrored client agrees with a direct one on every query
  // shape — including a narrow deep-level range and a prefix.
  const w = await Owner.accept(memoryAdapter(), "stress pass", job.invite);
  const all = await w.query("amount", 0, 1048575);
  const victims = all.filter((r) => job.delete_rows.includes(r.row));
  out.deleted = 0;
  for (const v of victims) out.deleted += await w.delete(v._rid);
  await w.insertMany(job.after_rows);

  const direct = await Owner.accept(memoryAdapter(), "direct pass",
    job.invite);
  const mir = await Owner.accept(memoryAdapter(), "mirror pass",
    job.invite);
  await mir.enableMirror();
  await mir.sync();
  const shapes = {
    wide: (o) => o.query("amount", 0, 1048575),
    mid: (o) => o.query("amount", 100000, 300000),
    narrow: (o) => o.query("amount", 42000, 42007),
    prefix: (o) => o.queryPrefix("name", "sa"),
  };
  // Control and subject must be looking at the SAME network, or the
  // comparison measures node discovery instead of the mirror.
  for (const o of [direct, mir]) {
    for (let i = 0; i < 40 && o.network().length < 3; i++) {
      await new Promise((r) => setTimeout(r, 250));
      await o.refreshMembership();
    }
  }
  out.parity = {};
  for (const [nm, fn] of Object.entries(shapes)) {
    const d = (await fn(direct)).map((r) => r.row).sort((a, b) => a - b);
    const m2 = (await fn(mir)).map((r) => r.row).sort((a, b) => a - b);
    out.parity[nm] = { direct: d, mirror: m2,
      same: JSON.stringify(d) === JSON.stringify(m2) };
  }
  // a second sync must be a cheap no-op, not a re-walk that changes
  // the answers
  await mir.sync();
  const again = (await mir.query("amount", 0, 1048575))
    .map((r) => r.row).sort((a, b) => a - b);
  out.parity.after_resync = { direct: out.parity.wide.direct,
    mirror: again,
    same: JSON.stringify(out.parity.wide.direct) === JSON.stringify(again) };
}

process.stdout.write(JSON.stringify(out));
