"""SQL-shaped statements over blindrange. Shaped — not compatible.

The verbs are familiar so that using this does not require learning a new
API, but the grammar deliberately covers only what the engine can actually
do, and everything else is refused with a message that names why and what
to use instead. The alternative — accepting a friendly subset and failing
strangely at the edges — would invite people to bring their SQL mental
model along, and every architectural boundary would then read as a bug.

What this is NOT, stated up front because the syntax will tempt you:

  * No JOIN. Records are sealed blobs on nodes that cannot read them;
    there is nothing server-side to join ON. Join in your application,
    where the plaintext already is.
  * No OR. The index intersects predicates (AND); it cannot union them
    without fetching both sides, which your application can do just as
    well and should do knowingly.
  * No exact SUM. Aggregates come from index metadata without decrypting
    anything, so they are accurate to `leaf_width` — ask for APPROX SUM
    and you get the estimate WITH its error bar. A plain SUM() would have
    to pretend otherwise.
  * No transactions. UPDATE is delete-then-insert underneath; a crash
    between the two leaves a duplicate, never a hole. The guide says so
    and so does this docstring, because hiding it would be worse.

What you never have to think about here:

  * drain() — the session flushes pending writes before every read and on
    close, so reads always see your own writes.
  * compact() — tombstones are reclaimed automatically in the background
    once enough pile up (PRAGMA AUTOCOMPACT OFF to opt out). This is safe
    to automate only because compaction survives its own crash and
    resumes; automating it before that existed would have shipped a
    wedged database to everyone whose process died at the wrong moment.

Grammar, in full — if a statement is not here, it is refused:

  CREATE TABLE t (col INT BITS n BLUR w, col TEXT(chars) BLUR w,
                  col STORED, ...)
  DROP TABLE t
  SHOW TABLES        · DESCRIBE t
  INSERT INTO t (cols) VALUES (v, ...), (v, ...)
  SELECT cols|*|COUNT(*)|APPROX SUM(col) FROM t
         [WHERE cond AND cond ...] [ORDER BY col [ASC|DESC]] [LIMIT n]
  UPDATE t SET col = v, ... [WHERE ...]
  DELETE FROM t [WHERE ...]
  COMPACT t          · PRAGMA AUTOCOMPACT ON|OFF
                     · PRAGMA AUTOCOMPACT_THRESHOLD n

  cond: col BETWEEN a AND b · col >= a · col > a · col <= a · col < a
        · col = v · col LIKE 'prefix%'
"""
import json
import os
import re
import threading
from pathlib import Path

from .client import Owner

__all__ = ["connect", "Connection", "Unsupported"]


class Unsupported(ValueError):
    """A statement the engine genuinely cannot honour, with the reason."""


# ---------------------------------------------------------------- tokens

_TOKEN = re.compile(
    r"\s*(?:"
    r"('(?:[^']|'')*')|"            # string literal, '' escapes '
    r"(\d+)|"                       # integer
    r"([A-Za-z_][A-Za-z0-9_]*)|"    # identifier / keyword
    r"(>=|<=|<>|!=|[(),*=<>;])"     # operators
    r")")

_KEYWORDS = {
    "CREATE", "TABLE", "DROP", "SHOW", "TABLES", "DESCRIBE", "INSERT",
    "INTO", "VALUES", "SELECT", "FROM", "WHERE", "AND", "OR", "ORDER",
    "BY", "ASC", "DESC", "LIMIT", "UPDATE", "SET", "DELETE", "BETWEEN",
    "LIKE", "COUNT", "SUM", "APPROX", "INT", "TEXT", "BITS", "BLUR",
    "STORED", "COMPACT", "DRAIN", "PRAGMA", "ON", "OFF", "JOIN", "GROUP",
    "NOT", "IN", "NULL", "AVG", "MIN", "MAX", "HAVING", "UNION",
}


def _tokenize(text):
    out, pos = [], 0
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m or m.end() == pos:
            rest = text[pos:].strip()
            if not rest:
                break
            raise Unsupported(f"cannot read the statement at: {rest[:40]!r}")
        pos = m.end()
        s, num, ident, op = m.groups()
        if s is not None:
            out.append(("str", s[1:-1].replace("''", "'")))
        elif num is not None:
            out.append(("num", int(num)))
        elif ident is not None:
            up = ident.upper()
            out.append(("kw", up) if up in _KEYWORDS else ("ident", ident))
        else:
            out.append(("op", op))
    return out


class _P:
    """A cursor over tokens. Nothing clever: the grammar is small enough
    that recursive descent with two helpers covers all of it, and a small
    hand parser is a smaller bug surface than a clever one."""

    def __init__(self, text):
        self.toks = _tokenize(text)
        self.i = 0

    def peek(self, kind=None):
        if self.i >= len(self.toks):
            return None
        k, v = self.toks[self.i]
        if kind and k != kind:
            return None
        return v

    def try_kw(self, *words):
        if self.i < len(self.toks) and self.toks[self.i] == ("kw", words[0]):
            save = self.i
            for w in words:
                if self.i < len(self.toks) and self.toks[self.i] == ("kw", w):
                    self.i += 1
                else:
                    self.i = save
                    return False
            return True
        return False

    def eat(self, kind, what):
        if self.i >= len(self.toks):
            raise Unsupported(f"statement ends where {what} was expected")
        k, v = self.toks[self.i]
        if k != kind:
            raise Unsupported(f"expected {what}, found {v!r}")
        self.i += 1
        return v

    def eat_op(self, op):
        if self.i < len(self.toks) and self.toks[self.i] == ("op", op):
            self.i += 1
            return True
        return False

    def done(self):
        while self.i < len(self.toks) and self.toks[self.i] == ("op", ";"):
            self.i += 1
        if self.i < len(self.toks):
            k, v = self.toks[self.i]
            # A refusable keyword mid-statement gets its real explanation,
            # not a parse error: `... JOIN x` should say why there is no
            # JOIN, the same as a statement that starts with it.
            if k == "kw" and v in _REFUSE:
                raise Unsupported(_REFUSE[v])
            raise Unsupported(f"unexpected {v!r} after the statement")


# ------------------------------------------------------------- refusals
# Every one names the reason and the nearest thing that works. These are
# the product surface as much as the features are.

_REFUSE = {
    "JOIN": "no JOIN: records are sealed blobs on nodes that cannot read "
            "them, so there is nothing server-side to join ON. Query each "
            "table and join in your application, where the plaintext is.",
    "OR": "no OR: the index intersects predicates (AND). Run one query per "
          "branch and merge the results yourself — that is what the engine "
          "would have to do, and you should see the cost.",
    "GROUP": "no GROUP BY: the one grouped shape the index supports is a "
             "histogram over value buckets. Use the Python API's "
             "histogram() for that.",
    "NOT": "no NOT: the index proves what exists in a range, not what is "
           "absent from it.",
    "IN": "no IN: rewrite as an equality per value, one query each.",
    "NULL": "no NULL: a record simply carries the columns it carries.",
    "HAVING": "no HAVING (no GROUP BY).",
    "UNION": "no UNION: run both queries and concatenate.",
    "AVG": "no AVG: use APPROX SUM and COUNT and divide — then the error "
           "bar stays visible instead of vanishing into a ratio.",
    "MIN": "no MIN/MAX: ORDER BY col LIMIT 1 (or DESC) does this at the "
           "same cost and says what it is doing.",
    "MAX": "no MIN/MAX: ORDER BY col DESC LIMIT 1 does this at the same "
           "cost and says what it is doing.",
    "DRAIN": "no DRAIN statement: the session flushes writes before every "
             "read and on close; there is nothing for you to do.",
}


# ----------------------------------------------------------- connection

_META_SUFFIX = ".table.json"


class Connection:
    """All tables under one directory, one passphrase, one network.

    Each table is a full independent database with its own master key —
    the same isolation two unrelated owners get, applied between your own
    tables. That is why CREATE TABLE takes a moment: it is a keypair and a
    network registration, not a catalogue row.
    """

    AUTOCOMPACT_THRESHOLD = 50_000

    def __init__(self, path, passphrase, bootstrap, network_secret="",
                 issuer="", account=""):
        self.path = Path(os.path.expanduser(str(path)))
        self.path.mkdir(parents=True, exist_ok=True)
        self._pass = passphrase
        self._bootstrap = list(bootstrap)
        self._secret = network_secret
        self._issuer, self._account = issuer, account
        self._tables = {}                    # name -> Owner (opened lazily)
        self._dirty = set()                  # tables with unflushed writes
        self._compacting = set()
        self._lock = threading.Lock()
        self.autocompact = True
        self.autocompact_threshold = self.AUTOCOMPACT_THRESHOLD
        self.mirror = os.environ.get("BR_SQL_MIRROR", "1") != "0"

    # -- table plumbing ---------------------------------------------------

    def _meta_path(self, name):
        return self.path / f"{name}{_META_SUFFIX}"

    def _state_path(self, name):
        return self.path / f"{name}.brdb"

    def _meta(self, name):
        p = self._meta_path(name)
        if not p.exists():
            raise Unsupported(f"no table {name!r} — CREATE TABLE it first "
                              f"(tables here: {', '.join(self._names()) or 'none'})")
        return json.loads(p.read_text())

    def _names(self):
        return sorted(p.name[:-len(_META_SUFFIX)]
                      for p in self.path.glob(f"*{_META_SUFFIX}"))

    def _owner(self, name):
        if name not in self._tables:
            o = Owner.open(str(self._state_path(name)), self._pass,
                           bootstrap=self._bootstrap)
            if self._account:
                o.configure_tokens(self._issuer, self._account)
            if self.mirror:
                # Local-first is the default at this layer because this
                # layer is the door application builders come through, and
                # the first application proved that WAN-in-the-read-path
                # is the tax that makes everything else unattractive.
                o.enable_mirror()
            self._tables[name] = o
        return self._tables[name]

    def _flush(self, name):
        """Reads must see the caller's own writes; nobody should have to
        know the word drain() to get that."""
        if name in self._dirty:
            self._owner(name).drain()
            self._dirty.discard(name)

    def _maybe_compact(self, name):
        """Reclaim in the background once tombstones pile up.

        Only safe to automate because compaction survives concurrent
        writes and resumes after its own crash. Without the resume, a
        process dying mid-compaction would have left an auto-wedged
        database, silently, for everyone.
        """
        if not self.autocompact:
            return
        try:
            pending = self._owner(name).count_deleted()
        except Exception:
            return
        with self._lock:
            if pending < self.autocompact_threshold or name in self._compacting:
                return
            self._compacting.add(name)

        def run():
            try:
                self._owner(name).compact()
            except Exception as e:          # never silent — see the history
                print(f"autocompact({name}) failed: "
                      f"{type(e).__name__}: {e}", flush=True)
            finally:
                with self._lock:
                    self._compacting.discard(name)

        threading.Thread(target=run, daemon=True).start()

    def close(self):
        for name in list(self._dirty):
            self._flush(name)
        for o in self._tables.values():
            if hasattr(o, "close"):
                o.close()

    # -- entry point ------------------------------------------------------

    def execute(self, statement):
        """Run one statement; returns a list of row dicts.

        Writes return [{"rows_affected": n}] so every result has the same
        shape and a REPL can print anything it gets back.
        """
        p = _P(statement)
        kw = p.peek("kw")
        if kw in _REFUSE:
            raise Unsupported(_REFUSE[kw])
        if kw == "CREATE":
            return self._create(p)
        if kw == "DROP":
            return self._drop(p)
        if kw == "SHOW":
            p.try_kw("SHOW", "TABLES")
            p.done()
            return [{"table": n} for n in self._names()]
        if kw == "DESCRIBE":
            p.try_kw("DESCRIBE")
            name = p.eat("ident", "a table name")
            p.done()
            return [dict(column=c, **spec)
                    for c, spec in self._meta(name)["columns"].items()]
        if kw == "INSERT":
            return self._insert(p)
        if kw == "SELECT":
            return self._select(p)
        if kw == "UPDATE":
            return self._update(p)
        if kw == "DELETE":
            return self._delete(p)
        if kw == "COMPACT":
            p.try_kw("COMPACT")
            name = p.eat("ident", "a table name")
            p.done()
            self._flush(name)
            stats = self._owner(name).compact()
            return [stats]
        if kw == "PRAGMA":
            return self._pragma(p)
        raise Unsupported(
            f"not a statement this dialect has: {statement.strip()[:60]!r}. "
            f"It covers CREATE/DROP TABLE, SHOW TABLES, DESCRIBE, INSERT, "
            f"SELECT, UPDATE, DELETE, COMPACT and PRAGMA — anything else is "
            f"the Python API's job.")

    # -- DDL --------------------------------------------------------------

    def _create(self, p):
        p.try_kw("CREATE", "TABLE")
        name = p.eat("ident", "a table name")
        if self._meta_path(name).exists():
            raise Unsupported(f"table {name!r} already exists")
        if not p.eat_op("("):
            raise Unsupported("expected a column list in parentheses")
        columns, schema = {}, {}
        while True:
            col = p.eat("ident", "a column name")
            if p.try_kw("INT"):
                if not p.try_kw("BITS"):
                    raise Unsupported(
                        f"{col}: INT needs BITS — how large can the value "
                        f"get? e.g. `{col} INT BITS 20 BLUR 64` for values "
                        f"up to {2**20 - 1:,}")
                bits = p.eat("num", "a bit count")
                if not p.try_kw("BLUR"):
                    raise Unsupported(
                        f"{col}: INT needs BLUR — the resolution the network "
                        f"is allowed to distinguish. It is the privacy "
                        f"budget, so this dialect will not pick one for you.")
                blur = p.eat("num", "a blur width")
                self._check_blur(col, blur, bits)
                columns[col] = {"type": "int", "bits": bits, "blur": blur}
                schema[col] = {"type": "int", "bits": bits,
                               "leaf_width": blur}
            elif p.try_kw("TEXT"):
                if not p.eat_op("("):
                    raise Unsupported(
                        f"{col}: TEXT needs a prefix length — how many "
                        f"leading characters are searchable? e.g. "
                        f"`{col} TEXT(6) BLUR 16`")
                chars = p.eat("num", "a character count")
                if not p.eat_op(")"):
                    raise Unsupported(f"{col}: expected ')' after TEXT({chars}")
                if not p.try_kw("BLUR"):
                    raise Unsupported(f"{col}: TEXT needs BLUR, same as INT")
                blur = p.eat("num", "a blur width")
                bits = chars * 5
                self._check_blur(col, blur, bits)
                columns[col] = {"type": "text", "chars": chars, "blur": blur}
                schema[col] = {"type": "str", "bits": bits, "chars": chars,
                               "leaf_width": blur, "kind": "text"}
            elif p.try_kw("STORED"):
                # Carried in the sealed blob, returned on read, and never
                # indexed: nothing about it exists on any node.
                columns[col] = {"type": "stored"}
            else:
                raise Unsupported(
                    f"{col}: column type must be INT BITS n BLUR w, "
                    f"TEXT(chars) BLUR w, or STORED")
            if p.eat_op(")"):
                break
            if not p.eat_op(","):
                raise Unsupported("expected ',' or ')' in the column list")
        p.done()
        if not schema:
            raise Unsupported("a table needs at least one indexed column, "
                              "or nothing about it could ever be queried")
        o = Owner.create(str(self._state_path(name)), self._pass, schema,
                         bootstrap=self._bootstrap,
                         network_secret=self._secret)
        if self._account:
            o.configure_tokens(self._issuer, self._account)
        if self.mirror:
            o.enable_mirror()
        self._tables[name] = o
        self._meta_path(name).write_text(json.dumps({"columns": columns}))
        return [{"created": name}]

    @staticmethod
    def _check_blur(col, blur, bits):
        if blur < 1 or blur & (blur - 1):
            lo = 1 << max(0, blur.bit_length() - 1)
            raise Unsupported(
                f"{col}: BLUR must be a power of two — the index halves "
                f"ranges, so anything else silently becomes the next power "
                f"down. Nearest: {lo} or {lo * 2}.")
        if blur > (1 << bits):
            raise Unsupported(f"{col}: BLUR {blur} is wider than the whole "
                              f"domain (2^{bits})")

    def _drop(self, p):
        p.try_kw("DROP", "TABLE")
        name = p.eat("ident", "a table name")
        p.done()
        self._meta(name)                       # errors if absent
        self._flush(name)
        self._owner(name).drop(confirm=True)
        self._tables.pop(name, None)
        self._state_path(name).unlink(missing_ok=True)
        self._meta_path(name).unlink()
        return [{"dropped": name}]

    def _pragma(self, p):
        p.try_kw("PRAGMA")
        which = p.eat("ident", "a pragma name").upper()
        if which == "AUTOCOMPACT":
            if p.try_kw("ON"):
                self.autocompact = True
            elif p.try_kw("OFF"):
                self.autocompact = False
            else:
                raise Unsupported("PRAGMA AUTOCOMPACT takes ON or OFF")
            p.done()
            return [{"autocompact": self.autocompact}]
        if which == "AUTOCOMPACT_THRESHOLD":
            self.autocompact_threshold = p.eat("num", "a row count")
            p.done()
            return [{"autocompact_threshold": self.autocompact_threshold}]
        raise Unsupported(f"unknown pragma {which}")

    # -- WHERE ------------------------------------------------------------

    def _where(self, p, name):
        """Conjunctions only, into (predicates, postfilters).

        Postfilters run client-side after decryption — the query path does
        that anyway for secondary predicates — and exist because a TEXT
        index narrows to a prefix of `chars` characters, so an equality
        must still check the whole value on the plaintext.
        """
        meta = self._meta(name)["columns"]
        bounds, prefixes, posts = {}, {}, []
        while True:
            if p.peek("kw") == "OR":
                raise Unsupported(_REFUSE["OR"])
            if p.peek("kw") in _REFUSE:
                raise Unsupported(_REFUSE[p.peek("kw")])
            col = p.eat("ident", "a column name")
            spec = meta.get(col)
            if spec is None:
                raise Unsupported(f"no column {col!r} on this table")
            if spec["type"] == "stored":
                raise Unsupported(
                    f"{col} is STORED, not indexed — nothing about it exists "
                    f"on any node, which is the point of STORED. Declare it "
                    f"with INT/TEXT to query it, or filter in your code.")
            if p.try_kw("BETWEEN"):
                lo = p.eat("num", "a number")
                if not p.try_kw("AND"):
                    raise Unsupported("BETWEEN needs `AND high`")
                hi = p.eat("num", "a number")
                self._narrow(bounds, col, lo, hi, spec)
            elif p.try_kw("LIKE"):
                pat = p.eat("str", "a string pattern")
                if not pat.endswith("%") or "%" in pat[:-1] or "_" in pat:
                    raise Unsupported(
                        "LIKE supports a trailing %% only ('abc%%'): the "
                        "index is a prefix index. A leading or inner "
                        "wildcard would need a scan of data no node can "
                        "read.")
                self._prefix(prefixes, posts, col, pat[:-1], spec,
                             exact=False)
            elif p.eat_op("="):
                if spec["type"] == "int":
                    v = p.eat("num", "a number")
                    self._narrow(bounds, col, v, v, spec)
                else:
                    v = p.eat("str", "a string")
                    self._prefix(prefixes, posts, col, v, spec, exact=True)
            elif p.eat_op(">="):
                self._narrow(bounds, col, p.eat("num", "a number"), None, spec)
            elif p.eat_op(">"):
                self._narrow(bounds, col, p.eat("num", "a number") + 1,
                             None, spec)
            elif p.eat_op("<="):
                self._narrow(bounds, col, None, p.eat("num", "a number"), spec)
            elif p.eat_op("<"):
                self._narrow(bounds, col, None,
                             p.eat("num", "a number") - 1, spec)
            elif p.eat_op("<>") or p.eat_op("!="):
                raise Unsupported("no <>: the index proves presence in a "
                                  "range, not absence from one")
            else:
                raise Unsupported(f"cannot read the condition on {col!r}")
            if not p.try_kw("AND"):
                break
        preds = []
        for col, (lo, hi) in bounds.items():
            top = (1 << meta[col]["bits"]) - 1
            lo = 0 if lo is None else max(0, lo)
            hi = top if hi is None else min(top, hi)
            if lo > hi:
                # Contradictory, not invalid: WHERE x > 5 AND x < 3 matches
                # nothing, and matching nothing is the correct answer.
                return None, []
            preds.append({"field": col, "lo": lo, "hi": hi})
        for col, pre in prefixes.items():
            preds.append({"field": col, "prefix": pre})
        return preds, posts

    @staticmethod
    def _narrow(bounds, col, lo, hi, spec):
        if spec["type"] != "int":
            raise Unsupported(f"{col} is TEXT: use = or LIKE 'prefix%'")
        old = bounds.get(col, (None, None))
        nlo = old[0] if lo is None else (lo if old[0] is None else max(old[0], lo))
        nhi = old[1] if hi is None else (hi if old[1] is None else min(old[1], hi))
        bounds[col] = (nlo, nhi)

    @staticmethod
    def _prefix(prefixes, posts, col, value, spec, exact):
        chars = spec["chars"]
        if col in prefixes:
            raise Unsupported(f"two text conditions on {col}; use one")
        prefixes[col] = value[:chars]
        if exact:
            posts.append(lambda r, c=col, v=value: r.get(c) == v)
        elif len(value) > chars:
            # The index can only narrow to the first `chars` characters;
            # the rest of the prefix is checked on the decrypted row.
            posts.append(lambda r, c=col, v=value:
                         str(r.get(c, "")).startswith(v))

    # -- DML --------------------------------------------------------------

    def _insert(self, p):
        p.try_kw("INSERT", "INTO")
        name = p.eat("ident", "a table name")
        meta = self._meta(name)["columns"]
        if not p.eat_op("("):
            raise Unsupported("INSERT needs an explicit column list — "
                              "positional inserts break silently when a "
                              "table changes")
        cols = []
        while True:
            cols.append(p.eat("ident", "a column name"))
            if p.eat_op(")"):
                break
            if not p.eat_op(","):
                raise Unsupported("expected ',' or ')' in the column list")
        for c in cols:
            if c not in meta:
                raise Unsupported(f"no column {c!r} on {name} — declared "
                                  f"columns: {', '.join(meta)}")
        indexed = [c for c, s in meta.items() if s["type"] != "stored"]
        missing = [c for c in indexed if c not in cols]
        if missing:
            raise Unsupported(
                f"INSERT must provide every indexed column ({', '.join(missing)} "
                f"missing): a row absent from an index is a row your own "
                f"queries silently never find.")
        if not p.try_kw("VALUES"):
            raise Unsupported("expected VALUES")
        rows = []
        while True:
            if not p.eat_op("("):
                raise Unsupported("expected '(' before a value row")
            vals = []
            while True:
                v = p.peek("num")
                if v is not None:
                    p.i += 1
                else:
                    v = p.eat("str", "a value")
                vals.append(v)
                if p.eat_op(")"):
                    break
                if not p.eat_op(","):
                    raise Unsupported("expected ',' or ')' in a value row")
            if len(vals) != len(cols):
                raise Unsupported(f"{len(cols)} columns but {len(vals)} values")
            row = dict(zip(cols, vals))
            for c in indexed:
                self._check_value(c, meta[c], row[c])
            rows.append(row)
            if not p.eat_op(","):
                break
        p.done()
        self._owner(name).insert_many(rows)
        self._dirty.add(name)
        return [{"rows_affected": len(rows)}]

    @staticmethod
    def _check_value(col, spec, v):
        if spec["type"] == "int":
            if not isinstance(v, int):
                raise Unsupported(f"{col} is INT, got {v!r}")
            top = (1 << spec["bits"]) - 1
            if not 0 <= v <= top:
                raise Unsupported(
                    f"{col} = {v} is outside 0..{top:,} (BITS {spec['bits']})."
                    f" Out-of-range values would be silently unfindable, so "
                    f"they are refused instead.")
        elif spec["type"] == "text" and not isinstance(v, str):
            raise Unsupported(f"{col} is TEXT, got {v!r}")

    def _select(self, p):
        p.try_kw("SELECT")
        # projection ------------------------------------------------------
        agg = None
        cols = []
        if p.try_kw("COUNT"):
            if not (p.eat_op("(") and p.eat_op("*") and p.eat_op(")")):
                raise Unsupported("COUNT takes (*) — counting a column "
                                  "would imply NULLs, and there are none")
            agg = ("count",)
        elif p.try_kw("APPROX", "SUM"):
            if not p.eat_op("("):
                raise Unsupported("APPROX SUM needs (column)")
            agg = ("sum", p.eat("ident", "a column name"))
            if not p.eat_op(")"):
                raise Unsupported("expected ')'")
        elif p.peek("kw") == "SUM":
            raise Unsupported(
                "no exact SUM: aggregates come from index metadata without "
                "decrypting anything, so they are accurate to BLUR. Ask for "
                "APPROX SUM(col) and you get the estimate with its error "
                "bar — which is what an exact-looking SUM would secretly be.")
        elif p.eat_op("*"):
            cols = ["*"]
        else:
            while True:
                cols.append(p.eat("ident", "a column name"))
                if not p.eat_op(","):
                    break
        if not p.try_kw("FROM"):
            raise Unsupported("expected FROM")
        name = p.eat("ident", "a table name")
        meta = self._meta(name)["columns"]

        preds, posts = ([], [])
        if p.try_kw("WHERE"):
            preds, posts = self._where(p, name)
            if preds is None:                  # contradictory range
                p.done()
                return [{"count": 0}] if agg == ("count",) else []
        order, desc, limit = None, False, None
        if p.try_kw("ORDER", "BY"):
            order = p.eat("ident", "a column name")
            spec = meta.get(order)
            if spec is None or spec["type"] == "stored":
                raise Unsupported(f"ORDER BY needs an indexed column; "
                                  f"{order!r} is not one")
            desc = bool(p.try_kw("DESC")) or (p.try_kw("ASC") and False)
        if p.try_kw("LIMIT"):
            limit = p.eat("num", "a row count")
        p.done()

        self._flush(name)
        o = self._owner(name)

        if agg == ("count",):
            return self._count(o, name, meta, preds, posts)
        if agg and agg[0] == "sum":
            return self._approx_sum(o, meta, agg[1], preds, posts)

        if not preds:
            # SELECT with no WHERE walks the first indexed column's whole
            # domain — legal, but the caller should bound it.
            first = next(c for c, s in meta.items() if s["type"] != "stored")
            bits = (meta[first].get("bits")
                    or meta[first]["chars"] * 5)
            preds = [{"field": first, "lo": 0, "hi": (1 << bits) - 1}]
        kw = {}
        if order:
            # The ordered walk drives off the ORDER BY column, so it must
            # appear among the predicates even when the WHERE does not
            # mention it — its full domain, if nothing narrower.
            if not any(pr["field"] == order for pr in preds):
                bits = (meta[order].get("bits")
                        or meta[order]["chars"] * 5)
                preds.append({"field": order, "lo": 0, "hi": (1 << bits) - 1})
            kw["order"] = ("-" + order) if desc else order
        out = []
        for rec in o.query_stream(preds, limit=None if posts else limit, **kw):
            if posts and not all(f(rec) for f in posts):
                continue
            out.append(self._project(rec, cols, meta))
            if limit is not None and len(out) >= limit:
                break
        return out

    @staticmethod
    def _project(rec, cols, meta):
        if not cols or cols == ["*"]:
            return {c: rec.get(c) for c in meta}
        return {c: rec.get(c) for c in cols}

    def _count(self, o, name, meta, preds, posts):
        # One clean range and no client-side filters: the index answers
        # directly, without fetching or decrypting a single record.
        if len(preds) == 1 and not posts and "lo" in preds[0]:
            n = o.count(preds[0]["field"], preds[0]["lo"], preds[0]["hi"])
            return [{"count": n, "basis": "exact-to-leaf"}]
        if not preds:
            first = next(c for c, s in meta.items() if s["type"] != "stored")
            bits = meta[first].get("bits") or meta[first]["chars"] * 5
            n = o.count(first, 0, (1 << bits) - 1)
            return [{"count": n, "basis": "exact-to-leaf"}]
        rows = o.query_multi(preds)
        if posts:
            rows = [r for r in rows if all(f(r) for f in posts)]
        return [{"count": len(rows), "basis": "filtered"}]

    def _approx_sum(self, o, meta, col, preds, posts):
        spec = meta.get(col)
        if spec is None or spec["type"] != "int":
            raise Unsupported("APPROX SUM needs an INT column")
        if posts or any(pr["field"] != col for pr in preds):
            raise Unsupported(
                "APPROX SUM can only be bounded by its own column: the "
                "estimate comes from index metadata, and metadata for one "
                "field knows nothing about another. Filter first, or sum "
                "the rows in your application.")
        lo = preds[0]["lo"] if preds else 0
        hi = preds[0]["hi"] if preds else (1 << spec["bits"]) - 1
        est, err, n = o.approx_sum(col, lo, hi)
        return [{"sum": est, "plus_minus": err, "rows": n}]

    def _update(self, p):
        p.try_kw("UPDATE")
        name = p.eat("ident", "a table name")
        meta = self._meta(name)["columns"]
        if not p.try_kw("SET"):
            raise Unsupported("expected SET")
        changes = {}
        while True:
            col = p.eat("ident", "a column name")
            if col not in meta:
                raise Unsupported(f"no column {col!r} on {name}")
            if not p.eat_op("="):
                raise Unsupported(f"expected = after {col}")
            v = p.peek("num")
            if v is not None:
                p.i += 1
            else:
                v = p.eat("str", "a value")
            if meta[col]["type"] != "stored":
                self._check_value(col, meta[col], v)
            changes[col] = v
            if not p.eat_op(","):
                break
        preds, posts = ([], [])
        if p.try_kw("WHERE"):
            preds, posts = self._where(p, name)
            if preds is None:
                p.done()
                return [{"rows_affected": 0}]
        p.done()

        # Delete-then-insert, in that order, on purpose: a crash between
        # the two leaves a duplicate you can see, never a hole you cannot.
        self._flush(name)
        o = self._owner(name)
        rows = self._match(o, meta, preds, posts)
        if not rows:
            return [{"rows_affected": 0}]
        replacements = []
        for r in rows:
            new = {k: v for k, v in r.items()
                   if k in meta and not k.startswith("_")}
            new.update(changes)
            replacements.append(new)
        o.delete_many([r["_rid"] for r in rows])
        o.insert_many(replacements)
        self._dirty.add(name)
        self._maybe_compact(name)
        return [{"rows_affected": len(rows)}]

    def _delete(self, p):
        p.try_kw("DELETE", "FROM")
        name = p.eat("ident", "a table name")
        meta = self._meta(name)["columns"]
        preds, posts = ([], [])
        if p.try_kw("WHERE"):
            preds, posts = self._where(p, name)
            if preds is None:
                p.done()
                return [{"rows_affected": 0}]
        p.done()
        self._flush(name)
        o = self._owner(name)
        rows = self._match(o, meta, preds, posts)
        if rows:
            o.delete_many([r["_rid"] for r in rows])
            self._dirty.add(name)
            self._maybe_compact(name)
        return [{"rows_affected": len(rows)}]

    def _match(self, o, meta, preds, posts):
        if not preds:
            first = next(c for c, s in meta.items() if s["type"] != "stored")
            bits = meta[first].get("bits") or meta[first]["chars"] * 5
            preds = [{"field": first, "lo": 0, "hi": (1 << bits) - 1}]
        rows = list(o.query_stream(preds))
        if posts:
            rows = [r for r in rows if all(f(r) for f in posts)]
        return rows


def connect(path, passphrase, bootstrap, network_secret="",
            issuer="", account=""):
    """Open (or start) a directory of tables. See Connection."""
    return Connection(path, passphrase, bootstrap, network_secret,
                      issuer, account)


# ------------------------------------------------------------------ REPL

def _print_rows(rows):
    if not rows:
        print("(no rows)")
        return
    cols = list(rows[0])
    widths = {c: max(len(c), *(len(str(r.get(c, ""))) for r in rows))
              for c in cols}
    line = "  ".join(c.ljust(widths[c]) for c in cols)
    print(line)
    print("  ".join("-" * widths[c] for c in cols))
    for r in rows:
        print("  ".join(str(r.get(c, "")).ljust(widths[c]) for c in cols))


def main():
    import argparse
    import sys
    ap = argparse.ArgumentParser(
        description="SQL-shaped REPL over blindrange (shaped, not "
                    "compatible: unsupported statements say why)")
    ap.add_argument("--state", default=os.path.expanduser("~/.blindrange/sql"))
    ap.add_argument("--passphrase",
                    default=os.environ.get("BR_SQL_PASS", ""))
    ap.add_argument("--bootstrap", default="seed.blindrange.dev:7501")
    ap.add_argument("--secret", default="blindrange-public")
    ap.add_argument("--issuer", default="https://tokens.blindrange.dev")
    ap.add_argument("--account", default=os.environ.get("BR_ACCOUNT", ""))
    a = ap.parse_args()
    if not a.passphrase:
        import getpass
        a.passphrase = getpass.getpass("passphrase (unlocks local keys, "
                                       "never sent anywhere): ")
    con = connect(a.state, a.passphrase, [a.bootstrap], a.secret,
                  a.issuer, a.account)
    print(f"tables in {a.state}: {', '.join(con._names()) or '(none yet)'}\n"
          f"end statements with ';'  ·  Ctrl-D quits", flush=True)
    buf = ""
    while True:
        try:
            buf += input("...  " if buf else "sql> ") + "\n"
        except EOFError:
            print()
            break
        except KeyboardInterrupt:
            buf = ""
            print()
            continue
        if ";" not in buf:
            continue
        stmt, buf = buf.split(";", 1)
        if not stmt.strip():
            continue
        try:
            import time as _t
            t0 = _t.time()
            rows = con.execute(stmt)
            _print_rows(rows)
            print(f"({(_t.time() - t0):.2f}s)")
        except Unsupported as e:
            print(f"refused: {e}")
        except Exception as e:
            print(f"error: {type(e).__name__}: {e}")
    con.close()


if __name__ == "__main__":
    main()
