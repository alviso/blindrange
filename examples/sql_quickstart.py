"""The SQL guide, as a program. https://blindrange.dev/build quotes this.

Same bargain as quickstart.py: the page carries no snippet that is not a
line of this file, and tests/test_quickstart.py runs it end to end — so if
the guide's SQL stops working, the build fails before a reader's terminal
does.

    python3 examples/sql_quickstart.py                 # the public network
    python3 examples/sql_quickstart.py --bootstrap 127.0.0.1:7501 --secret mine
"""
import argparse
import os
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from blindrange.sql import connect, Unsupported  # noqa: E402


def main():
    ap = argparse.ArgumentParser(description="blindrange SQL in one file")
    ap.add_argument("--state", default="/tmp/blindrange-sql-quickstart")
    ap.add_argument("--passphrase", default="quickstart passphrase")
    ap.add_argument("--bootstrap", default="seed.blindrange.dev:7501")
    ap.add_argument("--secret", default="blindrange-public")
    ap.add_argument("--keep", action="store_true")
    a = ap.parse_args()

    con = connect(a.state, a.passphrase, [a.bootstrap],
                  network_secret=a.secret)

    def run(stmt, expect_refusal=False):
        print(f"\nsql> {stmt}")
        try:
            for row in con.execute(stmt)[:5]:
                print(f"     {row}")
        except Unsupported as e:
            print(f"     refused: {e}")
            if not expect_refusal:
                raise

    # -- create ----------------------------------------------------------
    run("CREATE TABLE orders ("
        "  amount   INT BITS 20 BLUR 64,"
        "  day      INT BITS 16 BLUR 16,"
        "  status   TEXT(6) BLUR 16,"
        "  customer STORED"
        ")")

    # -- insert ------------------------------------------------------------
    run("INSERT INTO orders (amount, day, status, customer) VALUES"
        "  (450, 201, 'paid', 'cust-001'),"
        "  (120, 205, 'refunded', 'cust-002'),"
        "  (720, 210, 'paid', 'cust-003'),"
        "  (455, 202, 'paid', 'cust-004')")

    # -- read --------------------------------------------------------------
    run("SELECT * FROM orders WHERE amount BETWEEN 300 AND 500")
    run("SELECT customer, amount FROM orders"
        "  WHERE amount BETWEEN 300 AND 500 AND day <= 201")
    run("SELECT * FROM orders WHERE status LIKE 'ref%'")
    run("SELECT * FROM orders ORDER BY amount DESC LIMIT 2")

    # -- aggregates, from index metadata alone ------------------------------
    run("SELECT COUNT(*) FROM orders WHERE amount BETWEEN 0 AND 1000")
    run("SELECT APPROX SUM(amount) FROM orders")

    # -- update and delete ---------------------------------------------------
    run("UPDATE orders SET status = 'shipped' WHERE amount = 450")
    run("SELECT status, customer FROM orders WHERE amount = 450")
    run("DELETE FROM orders WHERE day > 208")
    run("SELECT COUNT(*) FROM orders")

    # -- documents and counters ---------------------------------------------
    run("CREATE TABLE docs ("
        "  id     KEY,"
        "  body   STORED"
        ")")
    run("INSERT INTO docs (id, body) VALUES ('doc-1', 'hello')")
    run("INSERT INTO docs (body) VALUES ('auto-id')")
    run("SELECT * FROM docs WHERE id = 'doc-1'")
    run("SELECT NEXT VALUE FOR invoice_no")
    run("SELECT NEXT VALUE FOR invoice_no")
    run("DROP TABLE docs")

    # -- and the boundary, on purpose ---------------------------------------
    run("SELECT * FROM orders JOIN other ON 1", expect_refusal=True)
    run("SELECT SUM(amount) FROM orders", expect_refusal=True)
    run("SELECT * FROM orders WHERE status LIKE '%aid'", expect_refusal=True)

    if not a.keep:
        run("DROP TABLE orders")
        con.close()
        shutil.rmtree(a.state, ignore_errors=True)
        print("\ncleaned up")
    else:
        con.close()
        print(f"\nkept: {a.state}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
