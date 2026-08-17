"""A local, complete copy of one database's encrypted keys.

This is the piece that makes blindrange practical to build applications
over, and it exists because the first real application proved the point
the hard way: with the WAN between the app and every answer, absence
proofs wait on the slowest NAT'd replica, every rule in the integration
guide was some disguise of that fact, and the app's steady state became
"serve from Mongo, shadow to blindrange". The mirror moves the read path
to where the app is. Reads — hits, absence, counts, cold opens — are
answered from a local SQLite file at local speed; the network's job
narrows to what it is actually good at: durable, unreadable replication.

What the mirror holds is exactly what a node holds for this database —
pseudorandom keys, sealed values. No new plaintext exists at rest; a
stolen mirror is worth what a stolen node is worth, which was priced into
the design on day one. The difference is that this copy sits with the one
party who can read it anyway.

Correctness contract, stated once and enforced in client.py:

  * Your own writes are always current: every network write lands in the
    mirror in the same call (write-through).
  * Other writers' data is as fresh as the last sync pass. A read that
    misses the mirror is treated as ABSENT only while the mirror is
    fresh (a completed pass within MIRROR_STALE_S); a stale mirror falls
    back to asking the network, which is exactly the pre-mirror
    behaviour. Correctness degrades to slowness, never to wrong answers.
  * Deletes and compaction remove from the mirror in the same breath as
    the network, so the mirror can never resurrect a forgotten record.
"""
import os
import sqlite3
import threading
import time

MIRROR_STALE_S = float(os.environ.get("BR_MIRROR_STALE_S", "30"))


class Mirror:
    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.execute("CREATE TABLE IF NOT EXISTS kv "
                        "(k TEXT PRIMARY KEY, v TEXT) WITHOUT ROWID")
        self.db.execute("CREATE TABLE IF NOT EXISTS meta "
                        "(k TEXT PRIMARY KEY, v TEXT) WITHOUT ROWID")
        self.db.commit()
        self.hits = 0                 # cumulative; consumers derive rates
        self.misses = 0

    # -- data ----------------------------------------------------------

    def get_many(self, keys):
        """{key: value} for the keys present. Chunked: SQLite's parameter
        limit is real, and a gallop batch can carry thousands of keys."""
        out = {}
        with self.lock:
            for i in range(0, len(keys), 512):
                chunk = keys[i:i + 512]
                qs = ",".join("?" * len(chunk))
                out.update(self.db.execute(
                    f"SELECT k, v FROM kv WHERE k IN ({qs})", chunk))
        return out

    def put_many(self, pairs):
        if not pairs:
            return
        with self.lock:
            self.db.executemany("INSERT OR REPLACE INTO kv VALUES (?,?)",
                                pairs)
            self.db.commit()

    def delete_many(self, keys):
        if not keys:
            return
        with self.lock:
            for i in range(0, len(keys), 512):
                chunk = keys[i:i + 512]
                qs = ",".join("?" * len(chunk))
                self.db.execute(f"DELETE FROM kv WHERE k IN ({qs})", chunk)
            self.db.commit()

    def count(self):
        with self.lock:
            return self.db.execute("SELECT COUNT(*) FROM kv").fetchone()[0]

    # -- freshness -----------------------------------------------------

    def mark_synced(self, duration_s=0.0):
        with self.lock:
            self.db.execute("INSERT OR REPLACE INTO meta VALUES "
                            "('synced_at', ?)", (str(time.time()),))
            self.db.execute("INSERT OR REPLACE INTO meta VALUES "
                            "('last_pass_s', ?)", (str(duration_s),))
            self.db.execute("INSERT OR REPLACE INTO meta VALUES "
                            "('complete_once', '1')")
            self.db.commit()

    def _meta(self, k):
        with self.lock:
            row = self.db.execute(
                "SELECT v FROM meta WHERE k=?", (k,)).fetchone()
        return row[0] if row else None

    def status(self):
        synced = self._meta("synced_at")
        return {"synced_at": float(synced) if synced else None,
                "last_pass_s": float(self._meta("last_pass_s") or 0),
                "complete_once": self._meta("complete_once") == "1",
                "keys": self.count(), "hits": self.hits,
                "misses": self.misses}

    def fresh(self, stale_s=None, single_writer=False):
        """May a local miss honestly be reported as absence?

        Two regimes, learned in production the expensive way:

        * SINGLE WRITER: yes, forever, once ONE pass has ever completed.
          Write-through means every later key came from this process, so
          the mirror is complete by construction and its AGE is
          irrelevant. The first deployment ran with an age gate anyway —
          and because a pass took ten minutes on that topology while the
          window was thirty seconds, the mirror never once counted as
          fresh, every absence walked the network, and reads measured
          WORSE than having no mirror at all.
        * MULTI WRITER: yes, within a window that a real pass can
          actually satisfy — the configured floor or three times the
          measured pass duration, whichever is larger. A static window
          shorter than a pass is not a safety margin, it is a rule that
          disables the feature while looking like caution.
        """
        if self._meta("complete_once") != "1":
            return False
        if single_writer:
            return True
        synced = self._meta("synced_at")
        if not synced:
            return False
        window = max(stale_s if stale_s is not None else MIRROR_STALE_S,
                     3.0 * float(self._meta("last_pass_s") or 0))
        return time.time() - float(synced) < window

    def close(self):
        with self.lock:
            self.db.close()
