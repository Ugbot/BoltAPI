#!/usr/bin/env python3
"""Flight SQL wire conformance judged by clients we did not write.

Starts tests/flight_sql_echo_server_main.cpp and drives it with
pyarrow.flight (generic Flight client, hand-built Flight SQL commands) and,
when installed, ADBC's Flight SQL driver (adbc_driver_flightsql, Go gRPC).
Values are checked against the echo executor's generating rule.

Usage: flight_sql_client_conformance.py <path-to-flight_sql_echo_server>
Exit: 0 pass, 1 fail, 77 skip (pyarrow.flight not importable).
Set BOLTAPI_FLIGHT_PYTHON to an interpreter that has pyarrow (and ADBC).
"""

import os
import subprocess
import sys

SKIP = 77


def _reexec_if_needed():
    try:
        import pyarrow.flight  # noqa: F401
        return
    except ImportError:
        pass
    alt = os.environ.get("BOLTAPI_FLIGHT_PYTHON")
    if alt and os.path.realpath(alt) != os.path.realpath(sys.executable):
        os.execv(alt, [alt] + sys.argv)
    print("SKIP: pyarrow.flight is not importable (set BOLTAPI_FLIGHT_PYTHON)")
    sys.exit(SKIP)


_reexec_if_needed()

import pyarrow as pa  # noqa: E402
import pyarrow.flight as fl  # noqa: E402

SQL_PKG = "type.googleapis.com/arrow.flight.protocol.sql."


def _varint(v):
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _bytes_field(num, payload):
    return _varint((num << 3) | 2) + _varint(len(payload)) + payload


def statement_cmd(sql):
    """Any<CommandStatementQuery{query}> — built from FlightSql.proto by hand
    so the test does not trust the server's own encoder."""
    inner = _bytes_field(1, sql.encode())
    return _bytes_field(1, (SQL_PKG + "CommandStatementQuery").encode()) + _bytes_field(2, inner)


def expected(n):
    return {
        "id": list(range(n)),
        "name": ["row%d" % i for i in range(n)],
        "score": [i * 0.5 for i in range(n)],
    }


def run_query(client, sql, options=None):
    desc = fl.FlightDescriptor.for_command(statement_cmd(sql))
    info = client.get_flight_info(desc, options) if options else client.get_flight_info(desc)
    assert len(info.endpoints) == 1, info.endpoints
    reader = client.do_get(info.endpoints[0].ticket, options) if options else \
        client.do_get(info.endpoints[0].ticket)
    table = reader.read_all()
    return info, table


def check_pyarrow(port, failures):
    client = fl.FlightClient("grpc://127.0.0.1:%d" % port)
    for n in (3, 0, 100000):
        info, table = run_query(client, "SELECT %d" % n)
        schema = pa.schema([("id", pa.int64()), ("name", pa.string()), ("score", pa.float64())])
        if not info.schema.equals(schema):
            failures.append("FlightInfo.schema %s != %s" % (info.schema, schema))
        if info.total_records != n:
            failures.append("total_records %d != %d" % (info.total_records, n))
        if table.to_pydict() != expected(n):
            failures.append("values for SELECT %d differ" % n)
        if n == 100000 and table.to_batches() and len(table.to_batches()) < 2:
            failures.append("expected several record batches for 100000 rows")

    got = client.get_schema(fl.FlightDescriptor.for_command(statement_cmd("SELECT 1"))).schema
    if got.names != ["id", "name", "score"]:
        failures.append("GetSchema names %s" % got.names)

    try:
        run_query(client, "FAIL on purpose")
        failures.append("FAIL statement did not raise")
    except fl.FlightServerError as e:
        failures.append("FAIL mapped to generic server error: %s" % e)
    except pa.ArrowInvalid as e:
        if "echo executor refused" not in str(e):
            failures.append("error message lost: %s" % e)

    try:
        other = fl.FlightDescriptor.for_command(
            _bytes_field(1, (SQL_PKG + "CommandGetTables").encode()) + _bytes_field(2, b""))
        client.get_flight_info(other)
        failures.append("CommandGetTables did not raise")
    except pa.ArrowNotImplementedError as e:
        if "CommandGetTables" not in str(e):
            failures.append("unimplemented message lacks the command name: %s" % e)

    # Several calls on one channel exercise HPACK dynamic-table state.
    for _ in range(20):
        _, t = run_query(client, "SELECT 5")
        if t.to_pydict() != expected(5):
            failures.append("repeat call differs")
            break
    client.close()


def check_auth(port, failures):
    client = fl.FlightClient("grpc://127.0.0.1:%d" % port)
    try:
        run_query(client, "SELECT 1")
        failures.append("unauthenticated call succeeded")
    except fl.FlightUnauthenticatedError:
        pass
    opts = fl.FlightCallOptions(headers=[(b"authorization", b"Bearer s3cret")])
    _, t = run_query(client, "SELECT 2", opts)
    if t.to_pydict() != expected(2):
        failures.append("bearer-authenticated values differ")
    bad = fl.FlightCallOptions(headers=[(b"authorization", b"Bearer wrong")])
    try:
        run_query(client, "SELECT 1", bad)
        failures.append("wrong token accepted")
    except fl.FlightUnauthenticatedError:
        pass
    client.close()


def check_adbc(port, failures):
    try:
        import adbc_driver_flightsql.dbapi as fsql
    except ImportError:
        print("note: adbc_driver_flightsql not installed; ADBC leg skipped")
        return
    with fsql.connect("grpc://127.0.0.1:%d" % port) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 7")
            table = cur.fetch_arrow_table()
    if table.to_pydict() != expected(7):
        failures.append("ADBC values differ: %s" % table.to_pydict())
    print("ADBC Flight SQL driver: OK")


def start(server, *extra):
    p = subprocess.Popen([server] + list(extra), stdout=subprocess.PIPE, text=True)
    line = p.stdout.readline().strip()
    if not line.startswith("PORT "):
        p.kill()
        raise RuntimeError("server did not report a port: %r" % line)
    return p, int(line.split()[1])


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    failures = []
    p, port = start(sys.argv[1])
    try:
        check_pyarrow(port, failures)
        check_adbc(port, failures)
    finally:
        p.terminate()
        p.wait(timeout=10)
    p, port = start(sys.argv[1], "--token", "s3cret")
    try:
        check_auth(port, failures)
    finally:
        p.terminate()
        p.wait(timeout=10)
    for f in failures:
        print("FAIL:", f)
    if failures:
        return 1
    print("PASS: pyarrow.flight against the Flight SQL wire layer")
    return 0


if __name__ == "__main__":
    sys.exit(main())
