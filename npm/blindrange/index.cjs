"use strict";
/* blindrange for Node — the reference Python client, shipped as a package.
 *
 * This is deliberately NOT a JavaScript reimplementation. The child this
 * module spawns IS the reference implementation, so there is nothing to
 * drift: every feature, fix and measurement the Python client gets, this
 * package gets on the same day, and a protocol change can never strand JS
 * users on stale crypto.
 *
 * The child speaks newline-JSON over stdio. No port, no daemon: nothing
 * another process could connect to, nothing to remember to shut down —
 * the child dies with your process.
 *
 * Interpreter resolution, in order:
 *   1. opts.python                    — explicit path
 *   2. env BLINDRANGE_PYTHON          — CI / development
 *   3. @blindrange/python-<platform>  — the bundled self-contained CPython
 *      installed automatically as a platform-specific optionalDependency
 *   4. python3 on PATH with the blindrange package importable
 */
const { spawn } = require("node:child_process");
const readline = require("node:readline");

class UnsupportedError extends Error {
  constructor(message) {
    super(message);
    this.name = "UnsupportedError";
  }
}

function resolvePython(opts) {
  if (opts.python) return { cmd: opts.python, env: {} };
  if (process.env.BLINDRANGE_PYTHON) {
    return { cmd: process.env.BLINDRANGE_PYTHON, env: {} };
  }
  const tag = `${process.platform}-${process.arch}`;
  try {
    // eslint-disable-next-line global-require
    const plat = require(`@blindrange/python-${tag}`);
    return { cmd: plat.python, env: plat.env || {} };
  } catch (e) {
    /* no bundled runtime for this platform — fall through */
  }
  return { cmd: "python3", env: {} };
}

class Connection {
  constructor(child, stderrTail) {
    this._child = child;
    this._pending = new Map();
    this._nextId = 1;
    this._stderrTail = stderrTail;
    this._closed = false;

    const rl = readline.createInterface({ input: child.stdout });
    rl.on("line", (line) => {
      let msg;
      try {
        msg = JSON.parse(line);
      } catch {
        return; // a corrupt frame poisons one line, not the session
      }
      const waiter = this._pending.get(msg.id);
      if (!waiter) return;
      this._pending.delete(msg.id);
      if (msg.ok) waiter.resolve(msg);
      else {
        waiter.reject(msg.kind === "unsupported"
          ? new UnsupportedError(msg.error)
          : new Error(msg.error));
      }
    });

    child.on("exit", (code) => {
      const tail = this._stderrTail.join("\n");
      const why = this._closed
        ? null
        : new Error(`blindrange bridge exited with code ${code}` +
                    (tail ? `\n--- bridge stderr ---\n${tail}` : ""));
      for (const { reject } of this._pending.values()) {
        reject(why || new Error("connection closed"));
      }
      this._pending.clear();
      this._exited = true;
    });
  }

  _send(frame) {
    return new Promise((resolve, reject) => {
      if (this._closed || this._exited) {
        reject(new Error("connection is closed"));
        return;
      }
      frame.id = this._nextId++;
      this._pending.set(frame.id, { resolve, reject });
      this._child.stdin.write(JSON.stringify(frame) + "\n");
    });
  }

  /** Run one statement in the SQL dialect; resolves to an array of row
   *  objects. Statements the engine cannot honour reject with
   *  UnsupportedError whose message names why and what to use instead. */
  async execute(stmt) {
    const msg = await this._send({ op: "execute", stmt });
    return msg.rows;
  }

  /** Flush pending writes and end the child. Safe to call twice. */
  async close() {
    if (this._closed) return;
    this._closed = true;
    this._child.stdin.end();
    await new Promise((resolve) => {
      if (this._exited) resolve();
      else this._child.once("exit", resolve);
    });
  }
}

/**
 * Open (or start) a directory of tables.
 *
 * @param {object} opts
 * @param {string} opts.path            directory for table state — back it up;
 *                                      the network only holds ciphertext
 * @param {string} opts.passphrase      unlocks local keys; sent to the child
 *                                      over stdin, never on argv or a socket
 * @param {string[]} opts.bootstrap     any one live peer, e.g.
 *                                      ["seed.blindrange.dev:7501"]
 * @param {string} [opts.networkSecret] which network (anti-vandal, not access
 *                                      control)
 * @param {string} [opts.issuer]        token issuer URL
 * @param {string} [opts.account]       metering account
 * @param {string} [opts.python]        explicit interpreter path
 * @returns {Promise<Connection>}
 */
async function connect(opts) {
  const { cmd, env } = resolvePython(opts);
  const stderrTail = [];
  const child = spawn(cmd, ["-u", "-m", "blindrange.bridge"], {
    env: { ...process.env, ...env },
    stdio: ["pipe", "pipe", "pipe"],
  });
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk) => {
    // Keep the tail, attach it to failures. Discarding stderr is how a
    // real fault hides behind "bridge exited with code 1".
    for (const line of chunk.split("\n")) {
      if (!line.trim()) continue;
      stderrTail.push(line);
      if (stderrTail.length > 50) stderrTail.shift();
    }
  });

  const con = new Connection(child, stderrTail);
  const spawnFailed = new Promise((_, reject) => {
    child.once("error", (e) => reject(new Error(
      `could not start the bridge (${e.message}). Install the platform ` +
      `package, set BLINDRANGE_PYTHON, or make python3 + blindrange ` +
      `available on PATH.`)));
  });
  await Promise.race([
    con._send({
      op: "open",
      path: opts.path,
      passphrase: opts.passphrase,
      bootstrap: opts.bootstrap || [],
      network_secret: opts.networkSecret || "",
      issuer: opts.issuer || "",
      account: opts.account || "",
    }),
    spawnFailed,
  ]);
  return con;
}

module.exports = { connect, Connection, UnsupportedError };
