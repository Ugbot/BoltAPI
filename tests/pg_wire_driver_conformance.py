#!/usr/bin/env python3
"""Point REAL Postgres drivers at the wire layer (echo executor, no engine).

The echo executor answers every statement with the SQL text it received, so
each assertion pins exactly what the Extended Query path handed the host:
psycopg 3 always binds server-side (Parse/Bind/Describe/Execute/Sync), so a
passing run is conformance judged by a client we did not write.

Exit 0 = pass, 1 = a disagreement, 77 = psycopg unavailable (skip).
"""
import subprocess
import sys

try:
    import psycopg
except ImportError:
    print("SKIP: psycopg (3.x) is not importable")
    sys.exit(77)


def main(server):
    proc = subprocess.Popen([server], stdout=subprocess.PIPE, text=True)
    try:
        port = int(proc.stdout.readline().split()[1])
        dsn = f"host=127.0.0.1 port={port} user=t dbname=t sslmode=disable"
        failures = []

        def check(label, got, want):
            ok = got == want
            print(("ok   " if ok else "FAIL ") + f"{label}: {got!r}" + ("" if ok else f" != {want!r}"))
            if not ok:
                failures.append(label)

        with psycopg.connect(dsn, autocommit=True) as conn:
            cur = conn.cursor()
            cur.execute("select %s, %s, %s", (7, "it's", None))
            check("text params", cur.fetchone()[0], "select 7, 'it''s', NULL")

            cur.execute("select %s::int where x = %s", (-3, True))
            check("typed params", cur.fetchone()[0], "select (-3)::int where x = TRUE")

            for k in range(3):   # prepare=True -> named server-side statement
                cur.execute("select %s", (k,), prepare=True)
                check(f"prepared #{k}", cur.fetchone()[0], f"select {k}")

            bcur = conn.cursor(binary=True)
            bcur.execute("types")
            row = bcur.fetchone()
            check("binary int8", row[0], -42)
            check("binary float8", row[1], 1.5)
            check("binary text", row[2], "x'y")
            check("binary date", str(row[3]), "2024-02-29")
            check("binary numeric", str(row[4]), "-12.3450")
            check("binary bool", row[5], True)
            check("binary null", row[6], None)

            cur.execute("rows 250")
            check("row count", len(cur.fetchall()), 250)

            try:
                cur.execute("fail please %s", (1,))
                failures.append("error not raised")
            except psycopg.errors.SyntaxError as e:
                check("error sqlstate", e.sqlstate, "42601")
            cur.execute("select %s", ("after error",))
            check("usable after error", cur.fetchone()[0], "select 'after error'")

        return 1 if failures else 0
    finally:
        proc.terminate()
        proc.wait(timeout=5)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
