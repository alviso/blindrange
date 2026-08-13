"""Turn plain questions about your data into field specs — and say plainly
what each choice costs in privacy.

A blindrange field needs `bits` (how large the value domain is) and
`leaf_width` (the structural privacy budget: no observer, ever, resolves a
value finer than one leaf). Those are precise but unfriendly. This module
converts ordinary answers — "amounts up to $10,000", "dates over 5 years",
"customer names" — into specs, and describes the resulting leakage in a
sentence a non-cryptographer can act on.

Specs carry optional display metadata the storage layer ignores:
  kind   number | money | date | text   how the UI reads and writes it
  scale  multiplier applied before storing (money: 100, i.e. cents)
  epoch  ISO date that day 0 refers to (date fields)
  label  human column name
"""
import csv
import io
import math
import re
from datetime import date, datetime, timedelta

MAX_BITS = 36


# ------------------------------------------------------------- primitives

def bits_for(max_value: int) -> int:
    """Smallest domain that holds 0..max_value."""
    return max(1, min(MAX_BITS, math.ceil(math.log2(max(1, max_value) + 1))))


def pow2_floor(n: int) -> int:
    return 1 << max(0, int(n).bit_length() - 1) if n >= 1 else 1


def leaf_for(bits: int, bucket: int) -> int:
    """Nearest legal leaf_width (power of two) not exceeding `bucket`."""
    return max(1, min(pow2_floor(bucket), 1 << max(0, bits - 1)))


# ---------------------------------------------------------- field makers

def number_field(max_value, bucket=1, label=None):
    bits = bits_for(int(max_value))
    return {"type": "int", "bits": bits, "leaf_width": leaf_for(bits, bucket),
            "kind": "number", "scale": 1, "label": label}


def money_field(max_amount, bucket_amount=1.0, label=None):
    """Amounts are stored as cents so decimals stay exact."""
    bits = bits_for(int(round(float(max_amount) * 100)))
    bucket = max(1, int(round(float(bucket_amount) * 100)))
    return {"type": "int", "bits": bits, "leaf_width": leaf_for(bits, bucket),
            "kind": "money", "scale": 100, "label": label}


def date_field(years=6, bucket_days=1, epoch="2024-01-01", label=None):
    bits = bits_for(int(years * 366))
    return {"type": "int", "bits": bits,
            "leaf_width": leaf_for(bits, int(bucket_days)),
            "kind": "date", "scale": 1, "epoch": epoch, "label": label}


def text_field(chars=4, blur=16, label=None):
    """Prefix-searchable text: the first `chars` characters become an ordered
    domain (5 bits each), so ranges and LIKE 'x%' work."""
    bits = chars * 5
    return {"type": "str", "bits": bits, "chars": chars,
            "leaf_width": leaf_for(bits, blur), "kind": "text", "label": label}


# --------------------------------------------------------- value marshal

def to_stored(spec, value):
    """User-facing value -> the integer/string the index stores."""
    kind = spec.get("kind", "number")
    if kind == "money":
        return int(round(float(str(value).replace(",", "").lstrip("$")) * 100))
    if kind == "date":
        d = value if isinstance(value, date) else parse_date(str(value))
        if d is None:
            raise ValueError(f"not a date: {value!r}")
        return (d - parse_date(spec.get("epoch", "2024-01-01"))).days
    if kind == "text":
        return str(value)
    return int(float(str(value).replace(",", "")))


def to_display(spec, stored):
    kind = spec.get("kind", "number")
    if kind == "money":
        return f"{stored / 100:,.2f}"
    if kind == "date":
        base = parse_date(spec.get("epoch", "2024-01-01"))
        return (base + timedelta(days=int(stored))).isoformat()
    return stored


DATE_FORMATS = ("%Y-%m-%d", "%d/%m/%Y", "%m/%d/%Y", "%Y/%m/%d", "%d.%m.%Y",
                "%d %b %Y", "%b %d %Y", "%Y-%m-%dT%H:%M:%S")


def parse_date(text):
    text = str(text).strip()
    for fmt in DATE_FORMATS:
        try:
            return datetime.strptime(text[:len(text)], fmt).date()
        except ValueError:
            continue
    return None


# ------------------------------------------------------------- describe

def describe(name, spec):
    """One honest sentence about what this field's privacy budget means."""
    lw = spec.get("leaf_width", 1)
    kind = spec.get("kind", "number")
    if kind == "money":
        span = lw / 100
        fine = (f"amounts are indistinguishable within ${span:,.2f} buckets"
                if lw > 1 else "exact amounts are distinguishable")
    elif kind == "date":
        fine = (f"dates are indistinguishable within {lw}-day buckets"
                if lw > 1 else "exact days are distinguishable")
    elif kind == "text":
        chars = spec.get("chars", 4)
        blurred = math.log2(lw) / 5 if lw > 1 else 0
        if blurred < 1:
            tail = ("the last one only partially"
                    if blurred > 0 else "all of them exactly")
            fine = (f"prefix-searchable on the first {chars} characters, "
                    f"{tail}")
        else:
            fine = (f"prefix-searchable on the first {chars} characters, "
                    f"with the last {int(blurred)} blurred")
        return f"{name}: {fine} — and never finer, however long anyone watches."
    else:
        fine = (f"values are indistinguishable within buckets of {lw}"
                if lw > 1 else "exact values are distinguishable")
    return (f"{name}: values up to {2 ** spec['bits']:,} · {fine} — "
            f"and never finer, however long anyone watches.")


def summary(schema):
    return "\n".join(describe(n, s) for n, s in schema.items())


# --------------------------------------------------------- CSV inference

MONEY_HINTS = ("amount", "price", "cost", "total", "salary", "revenue",
               "value", "fee", "balance", "paid", "sum")
_NUM = re.compile(r"^-?[\d,]+(\.\d+)?$")


def sniff_column(values):
    """(kind, max_value_or_none) for a column of raw strings."""
    vals = [v for v in values if str(v).strip() != ""][:400]
    if not vals:
        return "text", None
    if all(parse_date(v) for v in vals):
        return "date", max(parse_date(v) for v in vals)
    cleaned = [str(v).strip().lstrip("$").replace(",", "") for v in vals]
    if all(_NUM.match(c or "x") for c in cleaned):
        nums = [float(c) for c in cleaned]
        if any("." in c for c in cleaned):
            return "money", max(nums)
        return "number", max(nums)
    return "text", None


def infer(rows, max_indexed=4):
    """Suggest a schema from parsed CSV rows (list of dicts).

    Indexes the first few columns that make sense to range-query; everything
    else still gets stored and returned, just not indexed (unindexed fields
    leak nothing at all — they are only ever inside the ciphertext)."""
    if not rows:
        return {}, []
    cols = list(rows[0].keys())
    schema, skipped = {}, []
    for col in cols:
        if len(schema) >= max_indexed:
            skipped.append(col)
            continue
        values = [r.get(col, "") for r in rows]
        kind, top = sniff_column(values)
        name = re.sub(r"[^a-z0-9_]", "_", col.strip().lower()) or "field"
        if name.startswith("@"):
            name = "f_" + name
        if kind == "date":
            years = max(1, math.ceil(
                ((top - date(2024, 1, 1)).days + 366) / 366)) if top else 6
            schema[name] = date_field(years=years, bucket_days=1, label=col)
        elif kind == "money" or (kind == "number"
                                 and any(h in col.lower()
                                         for h in MONEY_HINTS)):
            top = float(top or 1000)
            bucket = max(0.01, round(top / 4000, 2))
            schema[name] = money_field(top * 1.5, bucket, label=col)
        elif kind == "number":
            top = int(top or 1000)
            schema[name] = number_field(max(top * 2, 10),
                                        bucket=max(1, top // 4000), label=col)
        else:
            schema[name] = text_field(chars=4, blur=16, label=col)
    return schema, skipped


def read_csv(text, limit=None):
    """CSV text -> (rows as dicts, column names)."""
    buf = io.StringIO(text)
    try:
        dialect = csv.Sniffer().sniff(text[:4096], delimiters=",;\t|")
    except csv.Error:
        dialect = csv.excel
    reader = csv.DictReader(buf, dialect=dialect)
    rows = []
    for i, row in enumerate(reader):
        if limit is not None and i >= limit:
            break
        rows.append({(k or "").strip(): (v or "") for k, v in row.items()
                     if k is not None})
    return rows, (reader.fieldnames or [])
