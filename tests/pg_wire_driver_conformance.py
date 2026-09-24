#!/usr/bin/env python3
"""Point REAL Postgres drivers at the wire layer (echo executor, no engine):
psycopg 3 always, pgJDBC too when java and a postgresql jar are found.

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


JAVA = r'''
import java.sql.*;
public class PgWireJdbcTx {
    public static void main(String[] a) throws Exception {
        String url = "jdbc:postgresql://127.0.0.1:" + a[0] + "/t?user=t&sslmode=disable";
        try (Connection c = DriverManager.getConnection(url)) {
            c.setAutoCommit(false);
            try (Statement st = c.createStatement()) {
                st.setFetchSize(4);
                int n = 0;
                try (ResultSet rs = st.executeQuery("rows 10")) { while (rs.next()) n++; }
                System.out.println("fetch " + n);
            }
            c.commit();
            try (PreparedStatement ps = c.prepareStatement("select ?")) {
                ps.setInt(1, 9);
                try (ResultSet rs = ps.executeQuery()) { rs.next(); System.out.println("param " + rs.getString(1)); }
            }
            c.rollback();
            c.setReadOnly(true);
            try (Statement st = c.createStatement()) {
                st.executeUpdate("ddl insert");
                System.out.println("readonly write ALLOWED");
            } catch (SQLException e) { System.out.println("readonly " + e.getSQLState()); }
            c.rollback();
            c.setReadOnly(false);
            try (Statement st = c.createStatement()) { st.executeUpdate("ddl insert"); }
            try { c.rollback(); System.out.println("rollback ALLOWED"); }
            catch (SQLException e) { System.out.println("rollback " + e.getSQLState()); }
            c.setAutoCommit(true);
            try (Statement st = c.createStatement(); ResultSet rs = st.executeQuery("select 1")) {
                rs.next(); System.out.println("autocommit " + rs.getString(1));
            }
        }
    }
}
'''


def run_jdbc(port, check):
    import glob, os, shutil, tempfile
    jars = sorted(glob.glob(os.path.expanduser(
        "~/.m2/repository/org/postgresql/postgresql/*/postgresql-*.jar")))
    if shutil.which("java") is None or not jars:
        print("skip pgJDBC: java or a postgresql jar not found")
        return []
    with tempfile.TemporaryDirectory() as d:
        src = os.path.join(d, "PgWireJdbcTx.java")
        with open(src, "w") as f:
            f.write(JAVA)
        r = subprocess.run(["java", "-cp", jars[-1], src, str(port)],
                           capture_output=True, text=True, timeout=120)
    out = r.stdout + r.stderr
    print(f"pgJDBC ({os.path.basename(jars[-1])}):\n" + out)
    failed = []
    for label, want in [("fetch", "10"), ("param", "select 9"), ("readonly", "25006"),
                        ("rollback", "0A000"), ("autocommit", "select 1")]:
        got = next((ln[len(label) + 1:] for ln in r.stdout.splitlines()
                    if ln.startswith(label + " ")), None)
        check(f"jdbc {label}", got, want)
        if got != want:
            failed.append(label)
    if r.returncode != 0:
        failed.append("jdbc exit")
    return failed


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

        # G2ETL-64: autocommit off -> the driver issues BEGIN; the wire layer
        # answers transaction control and reports the block in ReadyForQuery.
        with psycopg.connect(dsn) as conn:
            cur = conn.cursor()
            cur.execute("select %s", (1,))
            check("tx: in block after first statement", conn.info.transaction_status.name, "INTRANS")
            conn.commit()
            check("tx: idle after commit", conn.info.transaction_status.name, "IDLE")
            cur.execute("rows 7")
            check("tx: rows inside a block", len(cur.fetchall()), 7)
            conn.commit()   # the echo "rows" is not SELECT-shaped, so it counts as a write
            cur.execute("ddl insert")
            try:
                conn.rollback()
                failures.append("rollback after a write did not raise")
            except psycopg.errors.FeatureNotSupported as e:
                check("tx: rollback after write refused", e.sqlstate, "0A000")
            check("tx: idle after refused rollback", conn.info.transaction_status.name, "IDLE")
            conn.read_only = True
            try:
                cur.execute("ddl insert")
                failures.append("write in READ ONLY block did not raise")
            except psycopg.errors.ReadOnlySqlTransaction as e:
                check("tx: read-only refuses writes", e.sqlstate, "25006")
            conn.rollback()

        failures.extend(run_jdbc(port, check))
        return 1 if failures else 0
    finally:
        proc.terminate()
        proc.wait(timeout=5)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
