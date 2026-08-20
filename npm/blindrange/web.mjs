/* blindrange browser/Node client — the reference protocol on WebCrypto.
 *
 * This is a PORT of the Python reference client (blindrange/client.py),
 * not a sibling design: every key derivation, wire shape and integrity
 * rule matches byte-for-byte, and tests/test_webclient.py pins that with
 * a cross-language harness (Python writes → JS reads → Python reads
 * back) against a real local network. If this file and client.py ever
 * disagree, client.py is right and the harness is supposed to have
 * caught it.
 *
 * What this makes possible: THE BROWSER IS THE BACKEND. A static HTML
 * page holds the keys, plans the queries, does the crypto, and talks to
 * blind storage directly — there is no server-side application to host,
 * so there is nothing to host it on. Durability, sync and uniqueness
 * arbitration come from the network; everything else was already
 * client-side in any web app.
 *
 * Ships in v1: create/accept/open (PBKDF2-encrypted state through a
 * pluggable storage adapter — browser state is device-local; INVITES
 * are the cross-platform bridge and match Python exactly), insert /
 * query / delete / count, KEY buckets, sequences (next_value /
 * next_values), quorum reads with the refusing-absence-from-silence
 * rule (silent replicas named, with provenance), an in-session mirror
 * (write-through + read cache with the reference freshness contract),
 * and a gateway mode (/fwd) so HTTPS pages can reach plain-HTTP nodes.
 * Not in v1, deliberately: QUIC direct paths (no browser API), SQL
 * dialect, compaction/purge (run those from any Python writer), batch().
 *
 * Runs unchanged in Node >= 18 (global fetch + WebCrypto), which is how
 * the compatibility harness drives it.
 */

const subtle = globalThis.crypto.subtle;

// ---------------------------------------------------------------- bytes
const te = new TextEncoder();
const td = new TextDecoder();
const utf8 = (s) => te.encode(s);

function hex(buf) {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
function unhex(s) {
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
  return out;
}
function b64(buf) {
  const u = new Uint8Array(buf);
  let s = "";
  for (let i = 0; i < u.length; i++) s += String.fromCharCode(u[i]);
  return btoa(s);
}
function unb64(s) {
  const raw = atob(s);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}
function randomBytes(n) {
  const b = new Uint8Array(n);
  globalThis.crypto.getRandomValues(b);
  return b;
}
function xor8(a, b) {
  const out = new Uint8Array(8);
  for (let i = 0; i < 8; i++) out[i] = a[i] ^ b[i];
  return out;
}

// --------------------------------------------------------------- crypto
async function hmac(keyBytes, msgBytes) {
  const k = await subtle.importKey("raw", keyBytes,
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await subtle.sign("HMAC", k, msgBytes));
}
async function sha256hex(s) {
  return hex(await subtle.digest("SHA-256", utf8(s)));
}
async function aesKey(raw) {
  return subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
}
async function aesSeal(key, nonce, plain) {
  return new Uint8Array(await subtle.encrypt(
    { name: "AES-GCM", iv: nonce }, key, plain));
}
async function aesOpen(key, nonce, ct) {
  return new Uint8Array(await subtle.decrypt(
    { name: "AES-GCM", iv: nonce }, key, ct));
}

// --------------------------------------------------------------- dyadic
// BigInt throughout: encode_str packs 5 bits per character, so anything
// past six characters overflows 32-bit JS bitwise ops — silently, which
// would be a placement disagreement with every Python writer.
export function maxLevel(bits, leafWidth) {
  if (leafWidth < 1 || (leafWidth & (leafWidth - 1)))
    throw new Error("leaf_width must be a power of two >= 1");
  const lvl = bits - (32 - Math.clz32(leafWidth) - 1);
  if (lvl < 1) throw new Error("leaf_width too large for domain");
  return lvl;
}
export function levelsFor(value, bits, mlvl) {
  const v = BigInt(value);
  const out = [];
  for (let lvl = 1; lvl <= mlvl; lvl++)
    out.push([lvl, (v >> BigInt(bits - lvl)).toString()]);
  return out;
}
export function dyadicCover(a, b, bits, mlvl) {
  const A = BigInt(a), B = BigInt(b);
  const out = [];
  const rec = (lo, hi, lvl, idx) => {
    if (hi < A || lo > B) return;
    if ((A <= lo && hi <= B && lvl >= 1) || lvl === mlvl) {
      out.push([lvl, idx.toString()]);
      return;
    }
    const mid = (lo + hi) / 2n;
    rec(lo, mid, lvl + 1, idx * 2n);
    rec(mid + 1n, hi, lvl + 1, idx * 2n + 1n);
  };
  rec(0n, 2n ** BigInt(bits) - 1n, 0, 0n);
  return out;
}
function char5(c) {
  c = c.toLowerCase();
  return c >= "a" && c <= "z" ? c.charCodeAt(0) - 96 : 0;
}
export function encodeStr(s, chars) {
  let v = 0n;
  for (let i = 0; i < chars; i++)
    v = (v << 5n) | BigInt(i < s.length ? char5(s[i]) : 0);
  return v;
}
export function prefixRange(prefix, chars) {
  let lo = 0n, hi = 0n;
  for (let i = 0; i < chars; i++) {
    if (i < prefix.length) {
      lo = (lo << 5n) | BigInt(char5(prefix[i]));
      hi = (hi << 5n) | BigInt(char5(prefix[i]));
    } else {
      lo <<= 5n;
      hi = (hi << 5n) | 31n;
    }
  }
  return [lo, hi];
}

// ----------------------------------------------------------------- ring
const REORDER_WINDOW = 3;

export function failureGroup(addr, udp = "") {
  let host = "";
  if (udp) {
    const cand = String(udp).split(",").map((c) => c.trim()).filter(Boolean);
    if (cand.length) {
      const last = cand[cand.length - 1];
      host = last.slice(0, last.lastIndexOf(":"));
    }
  }
  if (!host) {
    const a = String(addr);
    if (a.startsWith("via:")) return "tenant:" + a.slice(a.lastIndexOf("/") + 1);
    host = a.slice(0, a.lastIndexOf(":"));
  }
  host = host.replace(/^\[|\]$/g, "");
  const parts = host.split(".");
  if (parts.length === 4 && parts.every((x) => /^\d+$/.test(x)))
    return parts.slice(0, 3).join(".") + ".0/24";
  if (host.includes(":")) return host.split(":").slice(0, 3).join(":") + "::/48";
  return host || "unknown";
}

export class Ring {
  // Async factory: hashes need WebCrypto. Placement must match the
  // Python Ring exactly or this client and every repairing node fight.
  static async build(addrs, { vnodes = 64, replicas = 3, groups = null } = {}) {
    const r = new Ring();
    r.addrs = [...new Set(addrs)].sort();
    if (!r.addrs.length) throw new Error("empty ring");
    r.replicas = Math.min(replicas, r.addrs.length);
    r.groups = { ...(groups || {}) };
    const pairs = [];
    for (const a of r.addrs)
      for (let v = 0; v < vnodes; v++)
        pairs.push([BigInt("0x" + (await sha256hex(`${a}#${v}`)).slice(0, 16)),
                    a]);
    pairs.sort((x, y) => (x[0] < y[0] ? -1 : x[0] > y[0] ? 1 :
      x[1] < y[1] ? -1 : x[1] > y[1] ? 1 : 0));
    r.ring = pairs;
    r.hashes = pairs.map((p) => p[0]);
    return r;
  }

  async route(key, count = null) {
    const want = Math.min(count || this.replicas, this.addrs.length);
    const gather = Math.min(
      want + (Object.keys(this.groups).length ? REORDER_WINDOW : 0),
      this.addrs.length);
    const h = BigInt("0x" + (await sha256hex(key)).slice(0, 16));
    let lo = 0, hi = this.hashes.length;          // bisect right
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (this.hashes[mid] <= h) lo = mid + 1; else hi = mid;
    }
    const out = [];
    for (let j = 0; out.length < gather && j < this.ring.length; j++) {
      const addr = this.ring[(lo + j) % this.ring.length][1];
      if (!out.includes(addr)) out.push(addr);
    }
    if (!Object.keys(this.groups).length || want <= 1) return out.slice(0, want);
    return this._diversify(out, want);
  }

  _diversify(order, want) {
    const window = order.slice(0, want + REORDER_WINDOW);
    const picked = [], seen = new Set();
    for (const node of window) {
      if (picked.length >= want) break;
      const g = this.groups[node];
      if (g !== undefined && g !== null && seen.has(g)) continue;
      if (g !== undefined && g !== null) seen.add(g);
      picked.push(node);
    }
    for (const node of window) {
      if (picked.length >= want) break;
      if (!picked.includes(node)) picked.push(node);
    }
    return picked;
  }
}

// ------------------------------------------------------ storage adapters
export function memoryAdapter() {
  let blob = null;
  return { load: async () => blob, save: async (b) => { blob = b; } };
}
export function idbAdapter(name) {
  const open = () => new Promise((res, rej) => {
    const q = indexedDB.open("blindrange", 1);
    q.onupgradeneeded = () => q.result.createObjectStore("state");
    q.onsuccess = () => res(q.result);
    q.onerror = () => rej(q.error);
  });
  return {
    async load() {
      const db = await open();
      return new Promise((res, rej) => {
        const r = db.transaction("state").objectStore("state").get(name);
        r.onsuccess = () => res(r.result ?? null);
        r.onerror = () => rej(r.error);
      });
    },
    async save(blob) {
      const db = await open();
      return new Promise((res, rej) => {
        const t = db.transaction("state", "readwrite");
        t.objectStore("state").put(blob, name);
        t.oncomplete = () => res();
        t.onerror = () => rej(t.error);
      });
    },
  };
}

const PBKDF2_ITERS = 600_000;
const _sealCache = new Map();     // passphrase -> {saltHex, key}
async function sealState(passphrase, stateObj) {
  // PBKDF2 at 600k iterations costs ~250ms — fine once at unlock,
  // ruinous on every cache save (measured: it WAS the page latency
  // once reads went local). Derive once per passphrase per session;
  // a stable salt with fresh AES-GCM nonces is standard practice.
  let ck = _sealCache.get(passphrase);
  if (!ck) {
    const salt = randomBytes(16);
    const base = await subtle.importKey("raw", utf8(passphrase), "PBKDF2",
      false, ["deriveBits"]);
    ck = { saltHex: hex(salt),
      key: await aesKey(new Uint8Array(await subtle.deriveBits(
        { name: "PBKDF2", hash: "SHA-256", salt,
          iterations: PBKDF2_ITERS }, base, 256))) };
    _sealCache.set(passphrase, ck);
  }
  const nonce = randomBytes(12);
  const ct = await aesSeal(ck.key, nonce, utf8(JSON.stringify(stateObj)));
  return JSON.stringify({ v: 1, kdf: "pbkdf2-sha256", iters: PBKDF2_ITERS,
    salt: ck.saltHex, nonce: hex(nonce), ct: hex(ct) });
}
async function openState(passphrase, blob) {
  const d = JSON.parse(blob);
  const base = await subtle.importKey("raw", utf8(passphrase), "PBKDF2",
    false, ["deriveBits"]);
  const key = await aesKey(new Uint8Array(await subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: unhex(d.salt),
      iterations: d.iters }, base, 256)));
  return JSON.parse(td.decode(await aesOpen(key, unhex(d.nonce), unhex(d.ct))));
}

// ----------------------------------------------------------------- owner
const TOMB = "@tomb";
const PEER_LIVE_S = 40;
const PROBE_EXTRA = 3;
const KEY_BITS = 20;
const SYS_REFRESH_S = 5;

export class Owner {
  static _newState(masterHex, schema, bootstrap) {
    for (const [f, spec] of Object.entries(schema)) {
      if (f.startsWith("@")) throw new Error("field names starting with '@' are reserved");
      maxLevel(spec.bits, spec.leaf_width ?? 1);
    }
    return { v: 4, master: masterHex, writer: hex(randomBytes(8)),
      schema, epoch: 0, epoch_len: 0, sealed_max: -1,
      chains: {}, remote: {}, writers: [], reg_len: 0,
      tombs: { counts: {}, rids: [] }, secret: "", bootstrap: [...bootstrap] };
  }

  static async create(adapter, passphrase, schema, bootstrap,
                      { networkSecret = "", gateway = null } = {}) {
    if (await adapter.load() !== null) throw new Error("state already exists");
    const st = Owner._newState(hex(randomBytes(32)), schema, bootstrap);
    st.secret = networkSecret;
    const o = await Owner._init(adapter, passphrase, st, gateway);
    await o._registerWriter();
    await o._save();
    return o;
  }

  static async accept(adapter, passphrase, invite,
                      { bootstrap = null, gateway = null } = {}) {
    if (await adapter.load() !== null) throw new Error("state already exists");
    const d = JSON.parse(td.decode(unb64(invite)));
    const st = Owner._newState(d.master, d.schema, bootstrap || d.bootstrap);
    st.secret = d.secret || "";
    const o = await Owner._init(adapter, passphrase, st, gateway);
    await o._registerWriter();
    await o._save();
    return o;
  }

  static async open(adapter, passphrase, { gateway = null } = {}) {
    const blob = await adapter.load();
    if (blob === null) throw new Error("no state stored");
    const st = await openState(passphrase, blob);
    if (st.v !== 4) throw new Error("state uses an unknown format");
    return Owner._init(adapter, passphrase, st, gateway);
  }

  static async _init(adapter, passphrase, state, gateway) {
    const o = new Owner();
    o._adapter = adapter;
    o._pass = passphrase;
    o._st = state;
    o._master = unhex(state.master);
    o._dataKey = await aesKey(await hmac(o._master, utf8("data")));
    o._sysKeyEnc = await aesKey(await hmac(o._master, utf8("sys-enc")));
    o.gateway = gateway;
    o.writeAcks = 2;
    o.ring = null;
    o.lastUnresolved = new Set();
    o.lastSilent = {};
    o._membSrc = {};
    o._kw = new Map();                     // label -> key bytes (cache)
    o.mirror = null;                       // enableMirror() turns on
    await o.refreshMembership();
    return o;
  }

  invite() {
    return b64(utf8(JSON.stringify({ master: this._st.master,
      schema: this._st.schema, secret: this._st.secret || "",
      bootstrap: this._st.bootstrap })));
  }

  async _save() {
    await this._adapter.save(await sealState(this._pass, this._st));
  }

  // ---------------------------------------------------------- transport
  async _sign(payloadBytes) {
    const secret = this._st.secret || "";
    if (!secret) return {};
    return { "X-BR-Auth": hex(await hmac(utf8(secret), payloadBytes)) };
  }

  async _http(addr, method, path, bodyBytes) {
    // Browser pages served over HTTPS cannot fetch plain-HTTP nodes
    // (mixed content). gateway mode sends every request through one
    // HTTPS-fronted node's /fwd, which forwards to the target and
    // returns {status, body_b64}. The gateway sees who talks to whom —
    // nodes always did; that is inside the disclosed leakage.
    if (this.gateway) {
      // Gateways are a network role, not a landlord: pass several and
      // a dead one costs a retry, not the application.
      const gws = Array.isArray(this.gateway) ? this.gateway
        : [this.gateway];
      const env = { addr, method, path,
        body_b64: bodyBytes ? b64(bodyBytes) : "" };
      const raw = utf8(JSON.stringify(env));
      let lastErr = null;
      for (let n = 0; n < gws.length; n++) {
        const gw = gws[(this._gwIdx || 0 + n) % gws.length];
        try {
          const r = await fetch(`${gw}/fwd`, { method: "POST",
            headers: { "Content-Type": "application/json",
                       ...(await this._sign(raw)) },
            body: raw,
            // a dead node behind the gateway must cost seconds, not
            // the gateway's upstream timeout: measured, one downed
            // relay tenant held every fan phase ~30s and turned an
            // 18-record walk into five minutes. Timeout = silence,
            // and silence is already handled honestly by the quorum
            // rules — never treated as absence.
            signal: AbortSignal.timeout(this.httpTimeoutMs ?? 8000) });
          if (!r.ok) throw new Error(`gateway HTTP ${r.status}`);
          const out = await r.json();
          if (out.status >= 400)
            throw new Error(`HTTP ${out.status} from ${addr}${path}`);
          this._gwIdx = gws.indexOf(gw);
          return JSON.parse(td.decode(unb64(out.body_b64 || "")));
        } catch (e) {
          lastErr = e;
          if (String(e).includes(`from ${addr}`)) throw e; // real answer
        }
      }
      throw lastErr;
    }
    const headers = method === "POST"
      ? { "Content-Type": "application/json", ...(await this._sign(bodyBytes)) }
      : await this._sign(utf8(path.split("?")[0]));
    const r = await fetch(`http://${addr}${path}`, { method, headers,
      body: method === "POST" ? bodyBytes : undefined });
    if (r.status >= 400) throw new Error(`HTTP ${r.status} from ${addr}${path}`);
    return r.json();
  }

  async _post(addr, path, payload) {
    if (path === "/mget" && !("nonce" in payload))
      payload = { ...payload, nonce: hex(randomBytes(16)) };
    const body = utf8(JSON.stringify(payload));
    if (addr.startsWith("via:")) {
      const cut = addr.slice(4);
      const slash = cut.lastIndexOf("/");
      const relay = cut.slice(0, slash), nid = cut.slice(slash + 1);
      const env = { to: nid, id: hex(randomBytes(8)), method: "POST",
        path, body_b64: b64(body) };
      const out = await this._http(relay, "POST", "/relay/send",
        utf8(JSON.stringify(env)));
      if (!out || out.status >= 400)
        throw new Error(`relay HTTP ${out && out.status} from ${addr}${path}`);
      return JSON.parse(td.decode(unb64(out.body_b64 || "")));
    }
    return this._http(addr, "POST", path, body);
  }

  async _getJson(addr, path) {
    if (addr.startsWith("via:")) {
      const cut = addr.slice(4);
      const slash = cut.lastIndexOf("/");
      const relay = cut.slice(0, slash), nid = cut.slice(slash + 1);
      const env = { to: nid, id: hex(randomBytes(8)), method: "GET",
        path, body_b64: "" };
      const out = await this._http(relay, "POST", "/relay/send",
        utf8(JSON.stringify(env)));
      if (!out || out.status >= 400)
        throw new Error(`relay HTTP ${out && out.status} from ${addr}${path}`);
      return JSON.parse(td.decode(unb64(out.body_b64 || "")));
    }
    return this._http(addr, "GET", path, null);
  }

  // --------------------------------------------------------- membership
  async refreshMembership() {
    let contacts = [...this._st.bootstrap];
    if (this.ring)
      contacts = [...this.ring.addrs.map((n) => this._addrOf[n])
        .filter(Boolean), ...contacts];
    const found = {}, udp = {}, src = {};
    let answers = 0;
    for (const addr of contacts) {
      try {
        const peers = (await this._getJson(addr, "/peers")).peers;
        for (const [nid, e] of Object.entries(peers)) {
          if ((e.age ?? 1e9) <= PEER_LIVE_S && e.addr) {
            found[nid] = e.addr;
            if (!(e.addr in src)) src[e.addr] = [addr, e.age, Date.now()];
            if (e.udp) udp[nid] = e.udp;
          }
        }
        answers += 1;
        if (answers >= 2) break;
      } catch { continue; }
    }
    if (!Object.keys(found).length)
      throw new Error(`no live blindrange node reachable (tried ${contacts})`);
    this._addrOf = found;
    this._udpOf = udp;
    this._membSrc = src;
    const groups = {};
    for (const [nid, a] of Object.entries(found))
      groups[nid] = failureGroup(a, udp[nid] || "");
    this.ring = await Ring.build(Object.keys(found).sort(), { groups });
    return Object.keys(found).sort();
  }

  _addr(nid) { return this._addrOf[nid]; }

  // -------------------------------------------------------------- crypto
  async _kW(w) {
    if (!this._kw.has(w))
      this._kw.set(w, await hmac(this._master, utf8("label|" + w)));
    return this._kw.get(w);
  }
  async _ut(kw, epoch, writer, i) {
    return "I:" + hex(await hmac(kw, utf8(`UT|${epoch}|${writer}|${i}`)))
      .slice(0, 32);
  }
  async _mask(kw, epoch, writer, i) {
    return (await hmac(kw, utf8(`MASK|${epoch}|${writer}|${i}`))).slice(0, 8);
  }
  async _sysKey(kind, i) {
    const k = await hmac(this._master, utf8("sys|" + kind));
    return "I:" + hex(await hmac(k, utf8(`S|${i}`))).slice(0, 32);
  }
  async _sysEncode(text) {
    const nonce = randomBytes(12);
    const ct = await aesSeal(this._sysKeyEnc, nonce, utf8(text));
    const joined = new Uint8Array(12 + ct.length);
    joined.set(nonce); joined.set(ct, 12);
    return b64(joined);
  }
  async _sysDecode(blob) {
    const raw = unb64(blob);
    return td.decode(await aesOpen(this._sysKeyEnc, raw.slice(0, 12),
      raw.slice(12)));
  }
  _encode(field, value) {
    const spec = this._st.schema[field];
    return spec.type === "str" ? encodeStr(String(value), spec.chars)
      : BigInt(value);
  }

  // ------------------------------------------------------------ kv plane
  async _mgetQuick(keys) {
    keys = [...new Set(keys)];
    if (!keys.length) return {};
    const got = await this._mgetNetwork(keys, true);
    const m = this.mirror;
    if (m) {
      for (const [k, v] of Object.entries(got)) m.kv.set(k, v);
      if (m.persistPut) m.persistPut(Object.entries(got));
    }
    return got;
  }

  async _mget(keys, wan = false) {
    keys = [...new Set(keys)];
    if (!keys.length) { this.lastUnresolved = new Set(); return {}; }
    const m = this.mirror;
    if (!wan && m && !m.freshFor(this)) {
      // Not fresh enough to prove ABSENCE locally — but a cached HIT
      // is still a hit: records and index entries are immutable, and
      // other writers' deletes surface through tombstone chains, not
      // by mutating these keys. Without this, every page refetched
      // keys the previous page fetched seconds earlier: measured 3-10s
      // per page switch in session views.
      const out = {};
      const missing = [];
      for (const k of keys) {
        if (m.kv.has(k)) out[k] = m.kv.get(k);
        else missing.push(k);
      }
      if (!missing.length) { this.lastUnresolved = new Set(); return out; }
      const got = await this._mgetNetwork(missing);
      for (const [k, v] of Object.entries(got)) { m.kv.set(k, v); out[k] = v; }
      if (m.persistPut) m.persistPut(Object.entries(got));
      return out;
    }
    if (!wan && m && m.freshFor(this)) {
      // The reference contract, now ported completely: a FRESH mirror
      // answers absence locally. Most of what a query does is prove
      // that chains did NOT grow — forwarding those misses to the
      // network made every page walk the WAN while a complete local
      // copy sat in IndexedDB. Hits local, absence local; the network
      // is for writes and for staleness, not for every render.
      const out = {};
      for (const k of keys) if (m.kv.has(k)) out[k] = m.kv.get(k);
      this.lastUnresolved = new Set();
      return out;
    }
    const got = await this._mgetNetwork(keys);
    if (m) {
      for (const [k, v] of Object.entries(got)) m.kv.set(k, v);
      if (m.persistPut) m.persistPut(Object.entries(got));
    }
    return got;
  }

  async _mgetNetwork(keys, quick = false) {
    // The integrity rule, ported verbatim: a key is ABSENT only when
    // fewer than write_acks of its replicas stayed silent. Silence is
    // never evidence. Slow yes; wrong no.
    const R = this.ring.replicas;
    const route = {};
    for (const k of keys)
      route[k] = (await this.ring.route(k, R + PROBE_EXTRA))
        .map((n) => this._addr(n)).filter(Boolean);
    const out = {};
    const replied = new Set();

    const fan = async (from, to, subset) => {
      const byNode = {};
      for (const k of subset) {
        if (k in out) continue;
        for (const a of route[k].slice(from, to))
          (byNode[a] = byNode[a] || []).push(k);
      }
      await Promise.all(Object.entries(byNode).map(async ([a, ks]) => {
        try {
          const r = await this._post(a, "/mget", { keys: ks });
          replied.add(a);
          for (const [k, v] of Object.entries(r.values || {}))
            if (!(k in out)) out[k] = v;
        } catch { /* silent node: quorum accounting handles it */ }
      }));
    };

    await fan(0, R, keys);
    const missing1 = keys.filter((k) => !(k in out));
    if (missing1.length) await fan(R, R + PROBE_EXTRA, missing1);
    if (quick) {
      // sync's bulk speculation: absent-heavy by construction, and its
      // chain ends are strictly re-verified at the boundary — running
      // every overfetched key through the patience ladder cost minutes
      this.lastUnresolved = new Set();
      this.lastSilent = {};
      return out;
    }

    const unresolved = () => {
      // A missing key is unprovable if too many top-R replicas are
      // silent OR if ANY probed candidate is silent: under ring drift
      // the write's acks can sit outside today's top-R. Measured live:
      // a ledger whose every copy sat on two relay tenants read as
      // cleanly absent during a restart wave — both silent holders
      // were in the extras the old arithmetic ignored.
      const tolerable = Math.max(0, this.writeAcks - 1);
      return new Set(keys.filter((k) => !(k in out) &&
        (route[k].slice(0, R).filter((a) => !replied.has(a)).length
           > tolerable ||
         route[k].some((a) => !replied.has(a)))));
    };
    // Backoffs sized for real recoveries: a re-execing node rebinds in
    // ~1-3s, a relay tenant re-homes in ~5-20s. Give silence a chance
    // to become an answer before refusing.
    const waits = [300, 1500, 4000, 8000];
    for (let attempt = 0; attempt < waits.length + 1; attempt++) {
      const stuck = unresolved();
      if (!stuck.size) break;
      if (attempt < waits.length)
        await new Promise((r) => setTimeout(r, waits[attempt]));
      if (attempt >= 1) {
        await this.refreshMembership();
        for (const k of stuck)
          route[k] = (await this.ring.route(k, R + PROBE_EXTRA))
            .map((n) => this._addr(n)).filter(Boolean);
      }
      await fan(0, R + PROBE_EXTRA, [...stuck]);
    }
    this.lastUnresolved = unresolved();
    this.lastSilent = {};
    for (const k of this.lastUnresolved)
      this.lastSilent[k] = route[k].slice(0, R).filter((a) => !replied.has(a));
    return out;
  }

  async _put(kvPairs) {
    // Hedged, like the reference: every replica is asked at once, but
    // the caller returns the moment each key has write_acks answers —
    // the remaining copies land in the background (drain() awaits
    // them). v1 awaited every replica and each write paid the slowest
    // node on the ring; that alone was most of "a bit slow".
    const want = Math.max(1, Math.min(this.writeAcks, this.ring.replicas));
    const byNode = {};
    for (const [k, v] of kvPairs)
      for (const nid of await this.ring.route(k)) {
        const a = this._addr(nid);
        if (a) (byNode[a] = byNode[a] || []).push([k, v]);
      }
    const acks = Object.fromEntries(kvPairs.map(([k]) => [k, 0]));
    let settled = 0;
    const entriesCount = Object.keys(byNode).length;
    let resolveGate;
    const gate = new Promise((res) => { resolveGate = res; });
    const quorum = () => Object.values(acks).every((n) => n >= want);
    const jobs = Object.entries(byNode).map(([a, entries]) =>
      this._post(a, "/kv", { entries }).then(() => {
        for (const [k] of entries) acks[k] += 1;
        if (quorum()) resolveGate();
      }).catch(() => {}).finally(() => {
        settled += 1;
        if (settled === entriesCount) resolveGate();
      }));
    this._track(jobs);
    if (entriesCount) await gate;
    const vals = Object.fromEntries(kvPairs);
    for (const k of Object.keys(acks).filter((k) => acks[k] < 1)) {
      for (const nid of await this.ring.route(k, this.ring.replicas + 3)) {
        const a = this._addr(nid);
        if (!a) continue;
        try {
          await this._post(a, "/kv", { entries: [[k, vals[k]]] });
          acks[k] += 1;
          break;
        } catch { continue; }
      }
    }
    if (Object.values(acks).some((n) => n === 0))
      throw new Error("write not durable: some keys got zero ACKs");
    if (this.mirror) {
      for (const [k, v] of kvPairs) this.mirror.kv.set(k, v);
      if (this.mirror.persistPut) this.mirror.persistPut(kvPairs);
    }
  }

  _track(jobs) {
    this._inflight = this._inflight || new Set();
    for (const j of jobs) {
      this._inflight.add(j);
      j.finally(() => this._inflight.delete(j));
    }
  }

  async drain() {
    // Wait for every hedged background write. Call before you close
    // the tab if the last copy matters to you right now.
    await Promise.allSettled([...(this._inflight || [])]);
  }

  async _putNx(key, value) {
    let won = true;
    for (const nid of await this.ring.route(key)) {
      const a = this._addr(nid);
      if (!a) continue;
      try {
        const r = await this._post(a, "/kv", { entries: [[key, value]], nx: true });
        // existed is a LIST of already-present keys. [] is truthy in JS
        // (unlike Python), and reading it Python-style made every WIN
        // look like a loss — the register loop claimed slots forever.
        if ((r.existed || []).length) won = false;
      } catch { continue; }
    }
    if (this.mirror) {
      if (won) {
        this.mirror.kv.set(key, value);
        if (this.mirror.persistPut) this.mirror.persistPut([[key, value]]);
      } else {
        this.mirror.kv.delete(key);
        if (this.mirror.persistDel) this.mirror.persistDel([key]);
      }
    }
    return won;
  }

  async _delete(keys) {
    const byNode = {};
    for (const k of keys)
      for (const nid of await this.ring.route(k, this.ring.replicas + PROBE_EXTRA)) {
        const a = this._addr(nid);
        if (a) (byNode[a] = byNode[a] || []).push(k);
      }
    await Promise.all(Object.entries(byNode).map(([a, ks]) =>
      this._post(a, "/delete", { keys: ks }).catch(() => {})));
    if (this.mirror) {
      for (const k of keys) this.mirror.kv.delete(k);
      if (this.mirror.persistDel) this.mirror.persistDel(keys);
    }
  }

  _refuseUnresolved(keys, what) {
    // A query result must never silently shrink: entries the cached
    // counters prove exist, or candidate records, that stayed
    // unresolved mean a silent replica set — where a smaller answer is
    // a wrong answer. First seen live: a public-network query returned
    // 2 rows out of 3 during one degraded moment, with nothing raised.
    const stuck = keys.filter((k) => this.lastUnresolved.has(k));
    if (!stuck.length) return;
    const who = [...new Set(stuck.flatMap((k) => this.lastSilent[k] || []))]
      .sort();
    throw new Error(
      `query cannot be answered completely: ${stuck.length} ${what} ` +
      `unresolved; silent replicas: [${who}] — refusing to return ` +
      `silently fewer rows`);
  }

  // ----------------------------------------------------- chain discovery
  async _discoverEnds(spec, wan = false) {
    // spec: {id: {fn: async i -> key, cached}} -> {id: end}
    const state = {};
    for (const [cid, { fn, cached }] of Object.entries(spec))
      state[cid] = { lo: cached, hi: null, step: 1, fn };
    const ends = {};
    while (Object.keys(state).length) {
      const batch = {};
      for (const [cid, st] of Object.entries(state))
        batch[cid] = st.hi === null ? st.lo + st.step
          : Math.floor((st.lo + st.hi) / 2);
      const keys = {};
      for (const [cid, p] of Object.entries(batch))
        keys[cid] = await state[cid].fn(p);
      const got = await this._mget(
        [...new Set(Object.values(keys))], wan);
      const bad = this.lastUnresolved;
      const poisoned = Object.entries(keys)
        .filter(([, key]) => bad.has(key)).map(([cid]) => cid);
      if (poisoned.length) {
        const who = [...new Set(poisoned.flatMap(
          (cid) => this.lastSilent[keys[cid]] || []))].sort();
        throw new Error(
          `cannot determine chain end: ${poisoned.length} probe(s) ` +
          `unresolved; silent replicas: [${who}] — refusing to conclude ` +
          `absence from silence`);
      }
      for (const [cid, p] of Object.entries(batch)) {
        const st = state[cid];
        const hit = keys[cid] in got;
        if (st.hi === null) {
          if (hit) { st.lo = p; st.step *= 2; continue; }
          st.hi = p;
        } else if (hit) st.lo = p;
        else st.hi = p;
        if (st.hi === st.lo + 1) { ends[cid] = st.lo; delete state[cid]; }
      }
    }
    return ends;
  }

  _epochs() {
    const st = this._st;
    if (st.epoch > 0 && st.epoch - 1 > st.sealed_max)
      return [st.epoch - 1, st.epoch];
    return [st.epoch];
  }

  async _refreshEpoch(force = false) {
    const now = Date.now() / 1000;
    if (!force && now - (this._epochChecked || 0) < SYS_REFRESH_S)
      return this._st.epoch;
    const st = this._st;
    const end = (await this._discoverEnds(
      { e: { fn: (i) => this._sysKey("epoch", i), cached: st.epoch_len } },
      force)).e;
    if (end > st.epoch_len) {
      const keys = {};
      for (let i = st.epoch_len + 1; i <= end; i++)
        keys[i] = await this._sysKey("epoch", i);
      const got = await this._mget(Object.values(keys), force);
      for (const i of Object.keys(keys).map(Number).sort((a, b) => a - b)) {
        if (!(keys[i] in got)) continue;
        const txt = await this._sysDecode(got[keys[i]]);
        if (txt.startsWith("open:")) {
          const n = parseInt(txt.split(":")[1], 10);
          if (n > st.epoch) { st.epoch = n; st.chains = {}; }
        } else if (txt.startsWith("sealed:")) {
          st.sealed_max = Math.max(st.sealed_max,
            parseInt(txt.split(":")[1], 10));
        }
      }
      st.epoch_len = end;
      await this._save();
    }
    this._epochChecked = Date.now() / 1000;
    return st.epoch;
  }

  async _refreshWriters(force = false) {
    const now = Date.now() / 1000;
    if (!force && now - (this._writersChecked || 0) < SYS_REFRESH_S
        && this._writersCache) return this._writersCache;
    const st = this._st;
    const end = (await this._discoverEnds(
      { r: { fn: (i) => this._sysKey("registry", i), cached: st.reg_len } },
      force)).r;
    if (end > st.reg_len) {
      const keys = {};
      for (let i = st.reg_len + 1; i <= end; i++)
        keys[i] = await this._sysKey("registry", i);
      const got = await this._mget(Object.values(keys), force);
      for (const k of Object.values(keys))
        if (k in got) {
          const wid = await this._sysDecode(got[k]);
          if (!st.writers.includes(wid)) st.writers.push(wid);
        }
      st.reg_len = end;
      await this._save();
    }
    this._writersCache = st.writers;
    this._writersChecked = Date.now() / 1000;
    return st.writers;
  }

  async _registerWriter() {
    const st = this._st;
    const wid = st.writer;
    await this._refreshWriters();
    if (st.writers.includes(wid)) return;
    const val = await this._sysEncode(wid);
    for (;;) {
      const slot = st.reg_len + 1;
      if (await this._putNx(await this._sysKey("registry", slot), val)) {
        st.writers.push(wid);
        st.reg_len = slot;
        break;
      }
      const k = await this._sysKey("registry", slot);
      const got = await this._mget([k]);
      const other = await this._sysDecode(got[k]);
      if (!st.writers.includes(other)) st.writers.push(other);
      st.reg_len = slot;
    }
    await this._save();
  }

  // -------------------------------------------------------------- writes
  async insertMany(records) {
    const E = await this._refreshEpoch();
    const st = this._st;
    const puts = [];
    const me = st.writer;
    for (const rec of records) {
      const rid = randomBytes(8);
      const nonce = randomBytes(12);
      const ct = await aesSeal(this._dataKey, nonce, utf8(JSON.stringify(rec)));
      const joined = new Uint8Array(12 + ct.length);
      joined.set(nonce); joined.set(ct, 12);
      puts.push(["R:" + hex(rid), b64(joined)]);
      for (const [field, spec] of Object.entries(st.schema)) {
        if (!(field in rec)) continue;
        const v = this._encode(field, rec[field]);
        const mlvl = maxLevel(spec.bits, spec.leaf_width ?? 1);
        for (const [lvl, idx] of levelsFor(v, spec.bits, mlvl)) {
          const w = `${field}|${lvl}|${idx}`;
          const i = (st.chains[w] || 0) + 1;
          st.chains[w] = i;
          const kw = await this._kW(w);
          const masked = xor8(rid, await this._mask(kw, E, me, i));
          puts.push([await this._ut(kw, E, me, i), b64(masked)]);
        }
      }
    }
    await this._put(puts);
    await this._save();
    return records.length;
  }
  async insert(record) { return this.insertMany([record]); }

  async deleteMany(rids) {
    const E = await this._refreshEpoch();
    const st = this._st;
    const me = st.writer;
    const kT = await this._kW(TOMB);
    const base = st.tombs.counts[`${E}|${me}`] || 0;
    const puts = [];
    for (let n = 0; n < rids.length; n++) {
      const rid = unhex(rids[n]);
      const masked = xor8(rid, await this._mask(kT, E, me, base + 1 + n));
      puts.push([await this._ut(kT, E, me, base + 1 + n), b64(masked)]);
    }
    await this._put(puts);
    st.tombs.counts[`${E}|${me}`] = base + rids.length;
    for (const r of rids)
      if (!st.tombs.rids.includes(r)) st.tombs.rids.push(r);
    await this._save();
    await this._delete(rids.map((r) => "R:" + r));
    return rids.length;
  }
  async delete(rid) { return this.deleteMany([rid]); }

  // --------------------------------------------------------------- reads
  async query(field, lo, hi) {
    return this.queryMulti([{ field, lo, hi }]);
  }
  async queryPrefix(field, prefix) {
    return this.queryMulti([{ field, prefix }]);
  }

  async queryMulti(predicates, _retried = false) {
    // foreground marker: the background walk yields while any page
    // query runs — a browser gives one origin ~6 connections, and the
    // walk was starving every page switch behind its own fetches
    this._uiBusy = (this._uiBusy || 0) + 1;
    try { return await this._queryMultiInner(predicates, _retried); }
    finally { this._uiBusy -= 1; }
  }

  async _queryMultiInner(predicates, _retried = false) {
    const st = this._st;
    const me = st.writer;
    const top = st.epoch;
    const writers = st.writers.length ? [...st.writers] : [me];
    const kT = await this._kW(TOMB);

    const bounds = [];
    for (const p of predicates) {
      const fs = st.schema[p.field];
      let a, b;
      if ("prefix" in p) [a, b] = prefixRange(p.prefix, fs.chars);
      else [a, b] = [this._encode(p.field, p.lo), this._encode(p.field, p.hi)];
      bounds.push([p.field, a, b]);
    }

    const chains = {
      "sys|epoch": { fn: (i) => this._sysKey("epoch", i), cached: st.epoch_len,
        kind: "sys" },
      "sys|reg": { fn: (i) => this._sysKey("registry", i), cached: st.reg_len,
        kind: "sys" },
    };
    for (const ep of this._epochs())
      for (const u of writers)
        chains[`tomb|${ep}|${u}`] = {
          fn: (i) => this._ut(kT, ep, u, i),
          cached: st.tombs.counts[`${ep}|${u}`] || 0,
          kind: "tomb", ep, u };
    const covers = {};
    for (const [field, a, b] of bounds) {
      const fs = st.schema[field];
      const mlvl = maxLevel(fs.bits, fs.leaf_width ?? 1);
      const cover = dyadicCover(a, b, fs.bits, mlvl);
      const labels = cover.map(([lvl, idx]) => `${field}|${lvl}|${idx}`);
      const kws = {};
      for (const w of labels) kws[w] = await this._kW(w);
      covers[field] = { labels, kws };
      for (const ep of this._epochs())
        for (const w of labels)
          for (const u of writers) {
            const cached = (u === me && ep === top) ? (st.chains[w] || 0)
              : ((st.remote[`${ep}|${w}`] || {})[u] || 0);
            chains[`lab|${field}|${ep}|${w}|${u}`] = {
              fn: (i) => this._ut(kws[w], ep, u, i), cached,
              kind: "lab", field, ep, w, u };
          }
    }

    const enumMap = {};
    const probeMap = {};
    this._probed = this._probed || new Map();
    const probeTtlMs = (this.probeTtlS ?? 5) * 1000;
    const nowMs = Date.now();
    for (const [cid, ch] of Object.entries(chains)) {
      if (ch.kind === "lab")
        for (let i = 1; i <= ch.cached; i++)
          enumMap[await ch.fn(i)] = [cid, i];
      // a chain probed within the TTL is trusted not to have grown —
      // the same bargain SYS_REFRESH_S makes for system chains: a
      // stale window costs seeing another writer's newest rows a few
      // seconds late, never a wrong answer about existing rows
      if (ch.kind === "sys" ||
          nowMs - (this._probed.get(cid) || 0) >= probeTtlMs)
        probeMap[await ch.fn(ch.cached + 1)] = cid;
    }
    let got = await this._mget([...Object.keys(enumMap),
                                ...Object.keys(probeMap)]);
    this._refuseUnresolved(Object.keys(enumMap), "index entries");

    for (const cid of Object.values(probeMap))
      if (chains[cid].kind !== "sys") this._probed.set(cid, nowMs);
    const grown = new Set(Object.entries(probeMap)
      .filter(([k]) => k in got).map(([, cid]) => cid));
    if ([...grown].some((cid) => chains[cid].kind === "sys")) {
      if (_retried) throw new Error("system chains unstable across retries");
      await this._refreshEpoch(true);
      await this._refreshWriters(true);
      return this.queryMulti(predicates, true);
    }

    const ends = {};
    for (const [cid, ch] of Object.entries(chains))
      if (ch.kind !== "sys") ends[cid] = ch.cached;
    if (grown.size) {
      const spec = {};
      for (const cid of grown)
        spec[cid] = { fn: chains[cid].fn, cached: chains[cid].cached + 1 };
      const gEnds = await this._discoverEnds(spec);
      const deltaKeys = {};
      for (const [cid, end] of Object.entries(gEnds)) {
        ends[cid] = end;
        for (let i = chains[cid].cached + 2; i <= end; i++)
          deltaKeys[await chains[cid].fn(i)] = [cid, i];
      }
      if (Object.keys(deltaKeys).length) {
        Object.assign(got, await this._mget(Object.keys(deltaKeys)));
        this._refuseUnresolved(Object.keys(deltaKeys), "index entries");
      }
      for (const cid of grown)
        enumMap[await chains[cid].fn(chains[cid].cached + 1)] =
          [cid, chains[cid].cached + 1];
      Object.assign(enumMap, deltaKeys);
    }

    const ridSets = {};
    let dirty = grown.size > 0;
    for (const [field] of bounds) ridSets[field] = new Set();
    for (const [key, [cid, i]] of Object.entries(enumMap)) {
      const blob = got[key];
      if (blob === undefined) continue;
      const ch = chains[cid];
      if (ch.kind === "lab") {
        const kw = covers[ch.field].kws[ch.w];
        const rid = xor8(unb64(blob), await this._mask(kw, ch.ep, ch.u, i));
        ridSets[ch.field].add(hex(rid));
      } else if (ch.kind === "tomb") {
        const rid = xor8(unb64(blob), await this._mask(kT, ch.ep, ch.u, i));
        if (!st.tombs.rids.includes(hex(rid))) {
          st.tombs.rids.push(hex(rid));
          dirty = true;
        }
      }
    }
    // update caches: own chains for top epoch, remote for the rest
    for (const [cid, end] of Object.entries(ends)) {
      const ch = chains[cid];
      if (ch.kind === "lab") {
        if (ch.u === me && ch.ep === top) {
          if ((st.chains[ch.w] || 0) < end) {
            st.chains[ch.w] = end;
            dirty = true;
          }
        } else {
          const rk = `${ch.ep}|${ch.w}`;
          st.remote[rk] = st.remote[rk] || {};
          if (st.remote[rk][ch.u] !== end) {
            st.remote[rk][ch.u] = end;
            dirty = true;
          }
        }
      } else if (ch.kind === "tomb") {
        if (st.tombs.counts[`${ch.ep}|${ch.u}`] !== end) {
          st.tombs.counts[`${ch.ep}|${ch.u}`] = end;
          dirty = true;
        }
      }
    }
    if (dirty) await this._save();   // cache only; losable, re-probable

    let rids = null;
    for (const [field] of bounds)
      rids = rids === null ? ridSets[field]
        : new Set([...rids].filter((r) => ridSets[field].has(r)));
    const dead = new Set(st.tombs.rids);
    const live = [...(rids || [])].filter((r) => !dead.has(r));

    const recs = await this._mget(live.map((r) => "R:" + r));
    this._refuseUnresolved(live.map((r) => "R:" + r), "candidate records");
    const out = [];
    for (const r of live) {
      const blob = recs["R:" + r];
      if (blob === undefined) continue;
      const raw = unb64(blob);
      let rec;
      try {
        rec = JSON.parse(td.decode(
          await aesOpen(this._dataKey, raw.slice(0, 12), raw.slice(12))));
      } catch { continue; }
      let keep = true;
      for (const [field, a, b] of bounds) {
        if (!(field in rec)) { keep = false; break; }
        const v = this._encode(field, rec[field]);
        if (v < a || v > b) { keep = false; break; }
      }
      if (keep) out.push({ ...rec, _rid: r });
    }
    return out;
  }

  async count(field, lo, hi) {
    // Same lattice arithmetic as Python count(): chain lengths minus
    // tombstones is exact-to-leaf; capped leaves overlapping the bound
    // are included (superset), reported via basis.
    const rows = await this.queryMulti([{ field, lo, hi }]);
    return { count: rows.length, basis: "records" };
  }

  // -------------------------------------------------- documents/counters
  async keyBucket(field, value) {
    const h = await hmac(this._master, utf8(`keycol|${field}|${value}`));
    const n = (h[0] << 24 | h[1] << 16 | h[2] << 8 | h[3]) >>> 0;
    return n & ((1 << KEY_BITS) - 1);
  }

  async nextValue(name, timeoutS = 30) {
    const st = this._st;
    st.seqs = st.seqs || {};
    let i = st.seqs[String(name)] || 0;
    i = Math.max(i, (await this._discoverEnds(
      { s: { fn: (j) => this._sysKey(`seq:${name}`, j), cached: i } })).s);
    const me = st.writer;
    const deadline = Date.now() + timeoutS * 1000;
    while (Date.now() < deadline) {
      i += 1;
      if (await this._putNx(await this._sysKey(`seq:${name}`, i),
                            await this._sysEncode(`claimed:${me}`))) {
        st.seqs[String(name)] = i;
        await this._save();
        return i;
      }
      st.seqs[String(name)] = i;
    }
    throw new Error(`could not claim a value for sequence ${name}`);
  }

  async nextValues(name, n, timeoutS = 30) {
    if (n <= 0) return [];
    const st = this._st;
    st.seqs = st.seqs || {};
    let i = st.seqs[String(name)] || 0;
    i = Math.max(i, (await this._discoverEnds(
      { s: { fn: (j) => this._sysKey(`seq:${name}`, j), cached: i } })).s);
    const me = st.writer;
    const payload = await this._sysEncode(`claimed:${me}`);
    const won = [];
    const deadline = Date.now() + timeoutS * 1000;
    while (won.length < n && Date.now() < deadline) {
      const cands = [];
      for (let j = i + 1; j <= i + (n - won.length); j++) cands.push(j);
      i = cands[cands.length - 1];
      const results = await Promise.all(cands.map(async (j) =>
        [j, await this._putNx(await this._sysKey(`seq:${name}`, j), payload)]));
      for (const [j, ok] of results) if (ok) won.push(j);
      st.seqs[String(name)] = i;
    }
    if (won.length < n)
      throw new Error(`claimed ${won.length} of ${n} for sequence ${name}`);
    await this._save();
    return won.sort((a, b) => a - b);
  }

  // --------------------------------------------------------------- mirror
  async enableMirror(persistName = null) {
    if (this.mirror) return this.mirror;
    const m = { kv: new Map(), completeOnce: false, syncedAt: 0,
      lastPassS: 0,
      freshFor: (o) => {
        if (!m.completeOnce) return false;
        if (o._st.writers.length <= 1) return true;
        const win = Math.max(30, 3 * m.lastPassS);
        return Date.now() / 1000 - m.syncedAt < win;
      } };
    if (persistName && typeof indexedDB !== "undefined") {
      // Persistent mirror: a returning visitor reads locally from the
      // first click instead of re-walking the network. Same freshness
      // contract; the disk copy is just the Map surviving a reload.
      const db = await new Promise((res, rej) => {
        const q = indexedDB.open("blindrange-mirror", 1);
        q.onupgradeneeded = () => q.result.createObjectStore("kv");
        q.onsuccess = () => res(q.result);
        q.onerror = () => rej(q.error);
      });
      const pfx = persistName + "\u0000";
      await new Promise((res, rej) => {
        const st = db.transaction("kv").objectStore("kv");
        const rq = st.openCursor(IDBKeyRange.bound(pfx, pfx + "\uffff"));
        rq.onsuccess = () => {
          const c = rq.result;
          if (!c) { res(); return; }
          const k = String(c.key).slice(pfx.length);
          if (k === "@meta") {
            const meta = c.value || {};
            m.completeOnce = !!meta.completeOnce;
            m.syncedAt = meta.syncedAt || 0;
            m.lastPassS = meta.lastPassS || 0;
          } else m.kv.set(k, c.value);
          c.continue();
        };
        rq.onerror = () => rej(rq.error);
      });
      let queue = [];
      let timer = null;
      const flush = () => {
        const batch = queue;
        queue = [];
        timer = null;
        const t = db.transaction("kv", "readwrite");
        const st = t.objectStore("kv");
        for (const [op, k, v] of batch)
          op === "p" ? st.put(v, pfx + k) : st.delete(pfx + k);
        st.put({ completeOnce: m.completeOnce, syncedAt: m.syncedAt,
                 lastPassS: m.lastPassS }, pfx + "@meta");
      };
      const later = () => { if (!timer) timer = setTimeout(flush, 80); };
      m.persistPut = (pairs) => {
        for (const [k, v] of pairs) queue.push(["p", k, v]);
        later();
      };
      m.persistDel = (keys) => {
        for (const k of keys) queue.push(["d", k]);
        later();
      };
      m.persistMeta = later;
    }
    this.mirror = m;
    return m;
  }

  async _staleProbe() {
    // The cheap staleness check that makes freshness RENEWABLE: every
    // insert writes every level of its label tree, so any write by
    // anyone extends a level-1 chain of every field; deletes extend
    // the tombstone chain; membership changes extend the registry and
    // epoch chains. Probing just those boundaries — one quick round of
    // ~40 keys — therefore detects ANY change to the ledger. Quick
    // fan, no patience ladder: a silent replica can hide a brand-new
    // row for one cycle (the probe-TTL bargain, disclosed), never
    // corrupt what exists.
    const st = this._st;
    const me = st.writer;
    const top = st.epoch;
    const writers = st.writers.length ? [...st.writers] : [me];
    const kT = await this._kW(TOMB);
    const probes = [
      await this._sysKey("epoch", st.epoch_len + 1),
      await this._sysKey("registry", st.reg_len + 1),
    ];
    for (const ep of this._epochs())
      for (const u of writers) {
        const tc = st.tombs.counts[`${ep}|${u}`] || 0;
        probes.push(await this._ut(kT, ep, u, tc + 1));
        for (const field of Object.keys(st.schema))
          for (const idx of ["0", "1"]) {
            const w = `${field}|1|${idx}`;
            const cached = (u === me && ep === top) ? (st.chains[w] || 0)
              : ((st.remote[`${ep}|${w}`] || {})[u] || 0);
            probes.push(await this._ut(await this._kW(w), ep, u,
              cached + 1));
          }
      }
    const got = await this._mgetNetwork(probes, true);
    return Object.keys(got).length > 0;
  }

  async sync() {
    // A COMPLETE walk of the label tree, like the reference client's.
    // The first version ran one full-domain query per field — which
    // covers the domain with LEVEL-1 labels only, while real range
    // queries cover with deeper labels whose chains were never
    // fetched. Result, measured live: a mirror holding all 70 keys of
    // a ledger whose every query through it returned zero rows,
    // because "fresh" absence answered locally for chains the sync
    // never visited. Complete means EVERY level: descend only into
    // nonempty parents (every value writes all its levels, so a
    // child's entries partition its parent's) — cost tracks what
    // exists, not the domain size.
    const m = await this.enableMirror();
    if (m.completeOnce) {
      // renewal path: a complete mirror whose boundary probes all come
      // back empty has nothing to walk — stamp the window and return.
      // This is what keeps pages local FOREVER, not just for the 30s
      // after the first walk: the app re-runs sync() on a timer, and
      // each quiet pass costs one network round.
      if (!(await this._staleProbe())) {
        m.syncedAt = Date.now() / 1000;
        if (m.persistMeta) m.persistMeta();
        return 0;
      }
    }
    const t0 = Date.now();
    try {
      const st = this._st;
      const me = st.writer;
      const top = st.epoch;
      const writers = await this._refreshWriters(true);
      await this._refreshEpoch(true);
      const eps = this._epochs();
      const rids = new Set();

      const uiYield = async () => {
        while ((this._uiBusy || 0) > 0)
          await new Promise((r) => setTimeout(r, 150));
      };
      const walkLabels = async (labels, unmaskRids, boundFor) => {
        await uiYield();
        // One batch for a whole tree level. Level 1 gallops (two
        // labels, cheap). Every deeper level fetches SPECULATIVELY:
        // a child chain can never be longer than its parent (one
        // writer's entries partition downward), so keys 1..parentEnd
        // are fetched in a single round and the end is the contiguous
        // prefix found — no galloping. Measured before this: a
        // four-minute warmup, all of it round trips.
        const spec = {};
        const info = {};
        const specKeys = {};
        for (const w of labels) {
          const kw = await this._kW(w);
          for (const ep of eps)
            for (const u of writers) {
              const cid = `${w}\u0000${ep}\u0000${u}`;
              info[cid] = { w, ep, u, kw };
              const bound = boundFor ? boundFor(w, ep, u) : null;
              if (bound === null)
                spec[cid] = { fn: (i) => this._ut(kw, ep, u, i), cached: 0 };
              else if (bound > 0) {
                specKeys[cid] = [];
                for (let i = 1; i <= bound; i++)
                  specKeys[cid].push(await this._ut(kw, ep, u, i));
              }
            }
        }
        const ends = Object.keys(spec).length
          ? await this._discoverEnds(spec, true) : {};
        const allSpec = Object.values(specKeys).flat();
        const specGot = allSpec.length ? await this._mgetQuick(allSpec) : {};
        for (const [cid, ks] of Object.entries(specKeys)) {
          let end = 0;
          while (end < ks.length && ks[end] in specGot) end += 1;
          ends[cid] = end;
        }
        const entryKeys = {};
        for (const [cid, end] of Object.entries(ends)) {
          if (specKeys[cid]) {
            for (let i = 1; i <= end; i++)
              entryKeys[specKeys[cid][i - 1]] = [cid, i];
          } else {
            const { ep, u, kw } = info[cid];
            for (let i = 1; i <= end; i++)
              entryKeys[await this._ut(kw, ep, u, i)] = [cid, i];
          }
        }
        const missing = Object.keys(entryKeys)
          .filter((k) => !(k in specGot));
        const got = missing.length
          ? await this._mget(missing, true) : {};
        Object.assign(got, specGot);
        const totals = {};
        const chainEnds = {};
        const chainList = [];
        for (const [cid, end] of Object.entries(ends)) {
          const { w, ep, u, kw } = info[cid];
          chainList.push({ w, ep, u, kw, end });
          totals[w] = (totals[w] || 0) + end;
          chainEnds[`${w}\u0000${ep}\u0000${u}`] = end;
          if (u === me && ep === top) {
            if ((st.chains[w] || 0) < end) st.chains[w] = end;
          } else {
            const rk = `${ep}|${w}`;
            st.remote[rk] = st.remote[rk] || {};
            st.remote[rk][u] = end;
          }
        }
        if (unmaskRids)
          for (const [key, [cid, i]] of Object.entries(entryKeys)) {
            const blob = got[key];
            if (blob === undefined) continue;
            const { ep, u, kw } = info[cid];
            rids.add(hex(xor8(unb64(blob), await this._mask(kw, ep, u, i))));
          }
        return { totals, chainEnds, chainList };
      };

      // all fields walk concurrently: the walk is round-trip bound
      // (measured: sequential fields cost minutes through a gateway)
      await Promise.all(Object.entries(st.schema).map(
        async ([field, specF]) => {
          const mlvl = maxLevel(specF.bits, specF.leaf_width ?? 1);
          for (let round = 0; round < 4; round++) {
            const fieldChains = [];
            let frontier = [[1, 0n], [1, 1n]];
            let parentEnds = null;
            while (frontier.length) {
              const labels = frontier.map(([l, i]) => `${field}|${l}|${i}`);
              const boundFor = parentEnds === null ? null
                : (w, ep, u) => {
                    const parts = w.split("|");
                    const parent = `${parts[0]}|${+parts[1] - 1}|` +
                      (BigInt(parts[2]) / 2n);
                    return parentEnds[`${parent}\u0000${ep}\u0000${u}`]
                      || 0;
                  };
              const { totals, chainEnds, chainList } =
                await walkLabels(labels, true, boundFor);
              fieldChains.push(...chainList);
              const next = [];
              for (const [l, i] of frontier)
                if (l < mlvl && (totals[`${field}|${l}|${i}`] || 0) > 0)
                  next.push([l + 1, i * 2n], [l + 1, i * 2n + 1n]);
              frontier = next;
              parentEnds = chainEnds;
            }
            // ONE strict pass for the whole field: probe every chain's
            // end+1 with full integrity rules — a shared ladder at
            // worst, instead of one per level
            const probes = {};
            for (const ch of fieldChains)
              probes[await this._ut(ch.kw, ch.ep, ch.u, ch.end + 1)] = ch;
            const got = Object.keys(probes).length
              ? await this._mget(Object.keys(probes), true) : {};
            let extended = false;
            for (const [key, ch] of Object.entries(got.constructor === Object
                ? Object.fromEntries(Object.entries(probes)
                    .filter(([k]) => k in got)) : {})) {
              // the quick pass under-read this chain: record the entry
              // and re-walk the field so deeper levels catch up
              rids.add(hex(xor8(unb64(got[key]),
                await this._mask(ch.kw, ch.ep, ch.u, ch.end + 1))));
              extended = true;
            }
            if (!extended) break;
          }
        }));
      // tombstones: single label, all epochs and writers
      const kT = await this._kW(TOMB);
      const tSpec = {};
      for (const ep of eps)
        for (const u of writers)
          tSpec[`${ep}\u0000${u}`] = { fn: (i) => this._ut(kT, ep, u, i),
            cached: 0 };
      const tEnds = await this._discoverEnds(tSpec, true);
      const tKeys = {};
      for (const [cid, end] of Object.entries(tEnds))
        for (let i = 1; i <= end; i++)
          tKeys[await tSpec[cid].fn(i)] = [cid, i];
      const tGot = Object.keys(tKeys).length
        ? await this._mget(Object.keys(tKeys), true) : {};
      for (const [key, [cid, i]] of Object.entries(tKeys)) {
        const blob = tGot[key];
        if (blob === undefined) continue;
        const [ep, u] = cid.split("\u0000");
        const rid = hex(xor8(unb64(blob), await this._mask(kT, +ep, u, +i)));
        if (!st.tombs.rids.includes(rid)) st.tombs.rids.push(rid);
      }
      for (const [cid, end] of Object.entries(tEnds)) {
        const [ep, u] = cid.split("\u0000");
        st.tombs.counts[`${ep}|${u}`] = end;
      }
      // every record the entries name
      const rkeys = [...rids].map((r) => "R:" + r);
      for (let i = 0; i < rkeys.length; i += 64) {
        await uiYield();
        await this._mget(rkeys.slice(i, i + 64), true);
      }
      await this._save();               // counters are the query's map
    } finally { /* walk done or failed; nothing global to restore */ }
    m.completeOnce = true;
    m.syncedAt = Date.now() / 1000;
    m.lastPassS = (Date.now() - t0) / 1000;
    if (m.persistMeta) m.persistMeta();
    return m.lastPassS;
  }

  network() {
    return Object.entries(this._addrOf).map(([nid, addr]) => ({ nid, addr }));
  }
}
