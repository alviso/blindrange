"""blindrange command line: create a database, open the client, join a network.

  blindrange init            interactive: design a schema, create a database
  blindrange ui              local web client (browser)
  blindrange info FILE       what's in a database, and what it leaks
  blindrange node ...        run a storage node (same as blindrange-node)
"""
import argparse
import getpass
import os
import sys
import webbrowser

from . import schema as S
from .client import Owner

PUBLIC_SEED = "seed.blindrange.dev:7501"
PUBLIC_SECRET = "blindrange-public"

BOLD, DIM, CYAN, GOLD, GREEN, OFF = (
    "\033[1m", "\033[2m", "\033[36m", "\033[33m", "\033[32m", "\033[0m")


def say(text=""):
    print(text)


def ask(prompt, default=None, cast=str):
    suffix = f" [{default}]" if default is not None else ""
    while True:
        raw = input(f"  {prompt}{suffix}: ").strip()
        if not raw and default is not None:
            return default if not isinstance(default, str) else cast(default)
        if raw:
            try:
                return cast(raw)
            except ValueError:
                say(f"  {DIM}not a valid value — try again{OFF}")


def ask_choice(prompt, options, default=1):
    for i, (_key, label) in enumerate(options, 1):
        say(f"    {i}) {label}")
    while True:
        raw = input(f"  {prompt} [{default}]: ").strip() or str(default)
        if raw.isdigit() and 1 <= int(raw) <= len(options):
            return options[int(raw) - 1][0]


def ask_yes(prompt, default=True):
    d = "Y/n" if default else "y/N"
    raw = input(f"  {prompt} [{d}]: ").strip().lower()
    return default if not raw else raw.startswith("y")


# ------------------------------------------------------------------ init

FIELD_KINDS = [("money", "money — amounts, prices, balances"),
               ("date", "dates"),
               ("number", "plain numbers — counts, ids, scores"),
               ("text", "text you want to search by prefix (names, codes)")]

PRECISION = {
    "money": [(0.01, "exact to the cent — most precise, most revealing"),
              (1.28, "about $1"),
              (20.48, "about $20 — recommended"),
              (81.92, "about $80 — most private")],
    "date": [(1, "exact day — most precise, most revealing"),
             (8, "about a week — recommended"),
             (32, "about a month"),
             (128, "about a quarter — most private")],
    "number": [(1, "exact value — most precise, most revealing"),
               (8, "within 8"),
               (64, "within 64 — recommended"),
               (512, "within 512 — most private")],
    "text": [(1, "the whole prefix exactly — most revealing"),
             (16, "blur the last character — recommended"),
             (1024, "blur the last two characters — most private")],
}


def design_field(name):
    kind = ask_choice(f"what kind of data is '{name}'?", FIELD_KINDS)
    say()
    say(f"  {DIM}How precisely should '{name}' be queryable? Anything finer")
    say(f"  than your choice is hidden from every node, forever.{OFF}")
    bucket = ask_choice("precision", [(v, l) for v, l in PRECISION[kind]],
                        default=3 if kind != "text" else 2)
    if kind == "money":
        top = ask("largest amount you expect (e.g. 10000)", "10000", float)
        spec = S.money_field(top, bucket, label=name)
    elif kind == "date":
        years = ask("how many years should it cover", "6", int)
        spec = S.date_field(years, bucket, label=name)
    elif kind == "number":
        top = ask("largest value you expect", "1000000", int)
        spec = S.number_field(top, bucket, label=name)
    else:
        chars = ask("how many leading characters to make searchable", "4", int)
        spec = S.text_field(chars, bucket, label=name)
    say()
    say(f"  {GREEN}{S.describe(name, spec)}{OFF}")
    say()
    return spec


def cmd_init(args):
    say()
    say(f"{BOLD}  blindrange — new encrypted database{OFF}")
    say(f"{DIM}  Your data is encrypted here and stays unreadable to every")
    say(f"  machine that stores it. Only this file's key can read it.{OFF}")
    say()

    path = args.file or ask("database file", "my.brdb")
    if os.path.exists(path):
        say(f"  {GOLD}{path} already exists.{OFF}")
        return 1

    say()
    say(f"{BOLD}  1. Where should the encrypted data live?{OFF}")
    where = ask_choice("network", [
        ("public", "the public demo network (easiest, no durability promises)"),
        ("own", "my own network (I run the nodes)")])
    if where == "public":
        bootstrap, secret = [PUBLIC_SEED], PUBLIC_SECRET
    else:
        bootstrap = [ask("address of any live node", "127.0.0.1:7501")]
        secret = ask("network secret (blank for none)", "")
    say()

    say(f"{BOLD}  2. Which fields do you want to query by?{OFF}")
    say(f"{DIM}  Only these are indexed. Everything else you store is inside")
    say(f"  the ciphertext and leaks nothing at all.{OFF}")
    say()
    schema = {}
    while True:
        name = ask("field name (blank when done)", "" if schema else "amount")
        if not name:
            break
        name = name.strip().lower().replace(" ", "_")
        if name.startswith("@"):
            say("  names starting with @ are reserved")
            continue
        schema[name] = design_field(name)
        if len(schema) >= 6 and not ask_yes("add another field?", False):
            break
    if not schema:
        say(f"  {GOLD}no fields — nothing to index. Aborted.{OFF}")
        return 1

    say(f"{BOLD}  3. Passphrase for this database file{OFF}")
    say(f"{DIM}  It encrypts your master key. Lose it and the data is gone —")
    say(f"  there is no recovery, by design.{OFF}")
    pw = getpass.getpass("  passphrase: ")
    if pw != getpass.getpass("  again: "):
        say(f"  {GOLD}passphrases did not match{OFF}")
        return 1

    say()
    try:
        owner = Owner.create(path, pw, schema, bootstrap,
                             network_secret=secret)
    except ConnectionError as e:
        say(f"  {GOLD}could not reach the network: {e}{OFF}")
        return 1
    say(f"  {GREEN}created {path}{OFF} — {len(owner.ring.addrs)} live nodes")
    say()
    say(f"{DIM}  next:{OFF}  blindrange ui --file {path}")
    say()
    return 0


# ------------------------------------------------------------------ info

def cmd_info(args):
    pw = args.passphrase or getpass.getpass("  passphrase: ")
    owner = Owner.open(args.file, pw)
    say()
    say(f"{BOLD}  {args.file}{OFF}")
    say(f"  {len(owner.ring.addrs)} live nodes · writer "
        f"{owner._st['writer']} · epoch {owner._st['epoch']}")
    say()
    say(f"{BOLD}  indexed fields — and what each one reveals{OFF}")
    for name, spec in owner.schema.items():
        say(f"  {GREEN}·{OFF} {S.describe(name, spec)}")
    say()
    say(f"{DIM}  Unindexed fields inside your records leak nothing.")
    say(f"  Full threat model: https://blindrange.dev{OFF}")
    say()
    return 0


# -------------------------------------------------------------------- ui

def cmd_ui(args):
    from .webui import serve
    url = f"http://127.0.0.1:{args.port}/"
    say()
    say(f"  {BOLD}blindrange client{OFF} → {CYAN}{url}{OFF}")
    say(f"{DIM}  Your keys stay in this process. Close it and nothing")
    say(f"  about your database remains reachable from the browser.{OFF}")
    say()
    if not args.no_browser:
        webbrowser.open(url)
    serve(args.port, args.file)
    return 0


def main():
    ap = argparse.ArgumentParser(prog="blindrange",
                                 description="encrypted range-query database "
                                             "on blind, decentralized nodes")
    sub = ap.add_subparsers(dest="cmd")

    p = sub.add_parser("init", help="design a schema and create a database")
    p.add_argument("--file", help="database file to create")
    p.set_defaults(fn=cmd_init)

    p = sub.add_parser("ui", help="open the local web client")
    p.add_argument("--file", help="database file to open on start")
    p.add_argument("--port", type=int, default=8700)
    p.add_argument("--no-browser", action="store_true")
    p.set_defaults(fn=cmd_ui)

    p = sub.add_parser("info", help="describe a database and its leakage")
    p.add_argument("file")
    p.add_argument("--passphrase")
    p.set_defaults(fn=cmd_info)

    p = sub.add_parser("node", help="run a storage node (see blindrange-node)")
    p.set_defaults(fn=None)

    args, rest = ap.parse_known_args()
    if args.cmd == "node":
        from .node import main as node_main
        sys.argv = ["blindrange-node"] + rest
        return node_main()
    if not args.cmd:
        ap.print_help()
        return 0
    try:
        return args.fn(args)
    except KeyboardInterrupt:
        say("\n  cancelled")
        return 130


if __name__ == "__main__":
    sys.exit(main() or 0)
