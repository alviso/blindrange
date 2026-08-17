"""Line-JSON bridge over stdio, for clients in other languages.

The npm package spawns `python -m blindrange.bridge` as a child it owns and
speaks newline-delimited JSON over stdin/stdout. Stdio, not a socket, on
purpose: there is no port, so there is nothing another process on the
machine could ever connect to, and the child dies with its parent instead
of becoming a daemon somebody has to remember exists.

Protocol, in full:

  -> {"id": 1, "op": "open", "path": ..., "passphrase": ...,
      "bootstrap": [...], "network_secret": ..., "issuer": ..., "account": ...}
  <- {"id": 1, "ok": true}
  -> {"id": 2, "op": "execute", "stmt": "SELECT ..."}
  <- {"id": 2, "ok": true, "rows": [...]}
  <- {"id": 2, "ok": false, "kind": "unsupported"|"error", "error": "..."}
  -> EOF          (close(): pending writes are flushed, then exit 0)

The statement language is the SQL dialect (blindrange/sql.py), which makes
it the cross-language API: any runtime that can spawn a process and speak
JSON gets the whole database, and there is exactly one implementation of
everything that matters.

The passphrase arrives on stdin, never on argv — argv is visible to every
process on the machine via ps.
"""
import json
import os
import sys


def main():
    # Stdout is the protocol. Anything else that writes to fd 1 — a stray
    # print, a C library, an asyncio exception handler — would corrupt a
    # frame and break the session in a way that looks like a JSON bug on
    # the JS side. So: keep a private copy of the real stdout for frames,
    # and point fd 1 at stderr so every stray write in the entire process
    # lands somewhere harmless. This week alone, log noise on the wrong
    # stream cost hours; here it would cost correctness.
    proto = os.fdopen(os.dup(1), "w", buffering=1)
    os.dup2(2, 1)
    sys.stdout = sys.stderr

    from .sql import connect, Unsupported

    def reply(obj):
        proto.write(json.dumps(obj, separators=(",", ":")) + "\n")

    con = None
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except ValueError:
            reply({"id": None, "ok": False, "kind": "error",
                   "error": "unparseable request frame"})
            continue
        rid = req.get("id")
        op = req.get("op")
        try:
            if op == "open":
                if con is not None:
                    raise RuntimeError("already open")
                con = connect(req["path"], req["passphrase"],
                              req.get("bootstrap") or [],
                              req.get("network_secret", ""),
                              req.get("issuer", ""),
                              req.get("account", ""))
                reply({"id": rid, "ok": True})
            elif op == "execute":
                if con is None:
                    raise RuntimeError("open first")
                reply({"id": rid, "ok": True,
                       "rows": con.execute(req["stmt"])})
            elif op == "ping":
                reply({"id": rid, "ok": True})
            else:
                raise RuntimeError(f"unknown op {op!r}")
        except Unsupported as e:
            reply({"id": rid, "ok": False, "kind": "unsupported",
                   "error": str(e)})
        except Exception as e:
            reply({"id": rid, "ok": False, "kind": "error",
                   "error": f"{type(e).__name__}: {e}"})
    if con is not None:
        con.close()          # flush dirty tables; reads-see-writes holds
    return 0


if __name__ == "__main__":
    sys.exit(main())
