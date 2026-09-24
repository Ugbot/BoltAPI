#!/usr/bin/env python3
"""Flight SQL wire conformance judged by clients we did not write.

Starts tests/flight_sql_echo_server_main.cpp and drives it with
pyarrow.flight (generic Flight client, hand-built Flight SQL commands) and,
when installed, ADBC's Flight SQL driver (adbc_driver_flightsql, Go gRPC).
Values are checked against the echo executor's generating rule.

Usage: flight_sql_client_conformance.py <path-to-flight_sql_echo_server>
Exit: 0 pass, 1 fail, 77 skip (pyarrow.flight not importable).
Set BOLTAPI_FLIGHT_PYTHON to an interpreter that has pyarrow (and ADBC).
Set FLIGHT_SQL_JDBC_JAR to Arrow's flight-sql-jdbc-driver jar (and have
`java` on PATH) to also drive the endpoint through JDBC (FlightSqlJdbcProbe).
"""

import os
import shutil
import socket
import struct
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


def _varint_field(num, v):
    return _varint(num << 3) + _varint(v)


def any_cmd(name, payload=b""):
    return _bytes_field(1, (SQL_PKG + name).encode()) + _bytes_field(2, payload)


def pb_fields(buf):
    """Minimal protobuf reader: {field: [value, ...]} (varint or bytes)."""
    out, i = {}, 0
    while i < len(buf):
        tag, i = _read_varint(buf, i)
        num, wire = tag >> 3, tag & 7
        if wire == 0:
            v, i = _read_varint(buf, i)
        elif wire == 2:
            n, i = _read_varint(buf, i)
            v, i = bytes(buf[i:i + n]), i + n
        else:
            raise ValueError("unexpected wire type %d" % wire)
        out.setdefault(num, []).append(v)
    return out


def _read_varint(buf, i):
    v, shift = 0, 0
    while True:
        b = buf[i]
        i += 1
        v |= (b & 0x7F) << shift
        shift += 7
        if not b & 0x80:
            return v, i


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
        client.get_flight_info(fl.FlightDescriptor.for_command(
            any_cmd("CommandGetXdbcTypeInfo")))
        failures.append("CommandGetXdbcTypeInfo did not raise")
    except pa.ArrowNotImplementedError as e:
        if "CommandGetXdbcTypeInfo" not in str(e):
            failures.append("unimplemented message lacks the command name: %s" % e)

    # Several calls on one channel exercise HPACK dynamic-table state.
    for _ in range(20):
        _, t = run_query(client, "SELECT 5")
        if t.to_pydict() != expected(5):
            failures.append("repeat call differs")
            break
    client.close()


def metadata(client, name, payload=b""):
    info = client.get_flight_info(fl.FlightDescriptor.for_command(any_cmd(name, payload)))
    table = client.do_get(info.endpoints[0].ticket).read_all()
    if not info.schema.equals(table.schema):
        raise AssertionError("%s: FlightInfo.schema %s != DoGet %s" %
                             (name, info.schema, table.schema))
    if info.total_records != table.num_rows:
        raise AssertionError("%s: total_records %d != %d" %
                             (name, info.total_records, table.num_rows))
    got = client.get_schema(fl.FlightDescriptor.for_command(any_cmd(name, payload))).schema
    if not got.equals(table.schema):
        raise AssertionError("%s: GetSchema %s != DoGet %s" % (name, got, table.schema))
    return table


def check_metadata(port, failures):
    """Catalog commands against the echo executor's three-table catalog."""
    client = fl.FlightClient("grpc://127.0.0.1:%d" % port)

    def expect(cond, what):
        if not cond:
            failures.append(what)

    info = metadata(client, "CommandGetSqlInfo")
    expect(info.schema.field("info_name").type == pa.uint32(), "info_name is uint32")
    expect(pa.types.is_union(info.schema.field("value").type), "value is a union")
    kv = dict(zip(info.column("info_name").to_pylist(), info.column("value").to_pylist()))
    expect(kv.get(0) == "boltapi-echo" and kv.get(1) == "9.9.9", "server name/version %s" % kv)
    expect(kv.get(3) is True and kv.get(4) is True and kv.get(5) is False, "flags %s" % kv)
    expect(kv.get(8) == 0, "transactions NONE %s" % kv)
    packed = _bytes_field(1, _varint(1) + _varint(0) + _varint(99999))
    t = metadata(client, "CommandGetSqlInfo", packed)
    expect(t.column("info_name").to_pylist() == [1, 0], "requested ids in order: %s" % t)
    t = metadata(client, "CommandGetSqlInfo", _varint_field(1, 3))
    expect(t.to_pylist() == [{"info_name": 3, "value": True}], "unpacked id: %s" % t)

    t = metadata(client, "CommandGetCatalogs")
    expect(t.num_rows == 0 and t.schema.names == ["catalog_name"], "catalogs %s" % t)
    t = metadata(client, "CommandGetDbSchemas")
    expect(t.schema.names == ["catalog_name", "db_schema_name"] and
           t.to_pylist() == [{"catalog_name": None, "db_schema_name": ""}],
           "db schemas: the no-schema row %s" % t.to_pylist())
    t = metadata(client, "CommandGetDbSchemas", _bytes_field(2, b"public"))
    expect(t.num_rows == 0, "a named schema pattern lists nothing")
    t = metadata(client, "CommandGetDbSchemas", _bytes_field(1, b"elsewhere"))
    expect(t.num_rows == 0, "a named catalog lists no schema")

    t = metadata(client, "CommandGetTables")
    expect(t.schema.names == ["catalog_name", "db_schema_name", "table_name", "table_type"],
           "tables schema %s" % t.schema.names)
    expect(t.to_pylist() == [
        {"catalog_name": None, "db_schema_name": None, "table_name": n, "table_type": ty}
        for n, ty in (("customers", "TABLE"), ("orders", "TABLE"), ("top_orders", "VIEW"))],
        "tables %s" % t.to_pylist())

    def names(payload):
        return metadata(client, "CommandGetTables", payload).column("table_name").to_pylist()
    expect(names(_bytes_field(3, b"%order%")) == ["orders", "top_orders"], "name pattern")
    expect(names(_bytes_field(3, b"_rders")) == ["orders"], "underscore pattern")
    expect(names(_bytes_field(4, b"VIEW")) == ["top_orders"], "table_types filter")
    expect(names(_bytes_field(4, b"TABLE") + _bytes_field(4, b"VIEW")) ==
           ["customers", "orders", "top_orders"], "two table_types")
    expect(names(_bytes_field(1, b"elsewhere")) == [], "a named catalog matches nothing")
    expect(len(names(_bytes_field(1, b""))) == 3, "empty catalog = tables without one")
    expect(names(_bytes_field(2, b"public")) == [], "a named schema matches nothing")
    expect(len(names(_bytes_field(2, b"%"))) == 3, "schema pattern % matches")

    t = metadata(client, "CommandGetTables", _bytes_field(3, b"orders") + _varint_field(5, 1))
    expect(t.schema.names[-1] == "table_schema" and t.num_rows == 1, "include_schema %s" % t)
    if t.num_rows == 1:
        sch = pa.ipc.read_schema(pa.py_buffer(t.column("table_schema")[0].as_py()))
        expect(sch.names == ["id", "name", "score"], "table_schema %s" % sch)

    t = metadata(client, "CommandGetTableTypes")
    expect(t.column("table_type").to_pylist() == ["TABLE", "VIEW"], "table types %s" % t)

    t = metadata(client, "CommandGetPrimaryKeys", _bytes_field(3, b"customers"))
    expect([(r["column_name"], r["key_sequence"]) for r in t.to_pylist()] ==
           [("region", 1), ("id", 2)], "primary keys %s" % t.to_pylist())
    expect(t.schema.field("key_sequence").type == pa.int32(), "key_sequence int32")
    t = metadata(client, "CommandGetPrimaryKeys", _bytes_field(3, b"nope"))
    expect(t.num_rows == 0, "no such table -> no keys")
    for cmd in ("CommandGetImportedKeys", "CommandGetExportedKeys"):
        t = metadata(client, cmd, _bytes_field(3, b"orders"))
        expect(t.num_rows == 0 and len(t.schema) == 13, "%s %s" % (cmd, t.schema))
    t = metadata(client, "CommandGetCrossReference",
                 _bytes_field(3, b"orders") + _bytes_field(6, b"customers"))
    expect(t.num_rows == 0 and t.schema.field("update_rule").type == pa.uint8(),
           "cross reference %s" % t.schema)
    client.close()


def check_prepared(port, failures):
    client = fl.FlightClient("grpc://127.0.0.1:%d" % port)

    def expect(cond, what):
        if not cond:
            failures.append(what)

    actions = sorted(a.type for a in client.list_actions())
    expect(actions == ["ClosePreparedStatement", "CreatePreparedStatement"],
           "ListActions %s" % actions)

    create = fl.Action("CreatePreparedStatement", any_cmd(
        "ActionCreatePreparedStatementRequest", _bytes_field(1, b"SELECT 4")))
    results = list(client.do_action(create))
    expect(len(results) == 1, "one CreatePreparedStatement result")
    wrapped = pb_fields(results[0].body.to_pybytes())
    expect(wrapped[1][0].decode().endswith("ActionCreatePreparedStatementResult"),
           "result Any type %r" % wrapped[1][0])
    res = pb_fields(wrapped[2][0])
    handle = res[1][0]
    sch = pa.ipc.read_schema(pa.py_buffer(res[2][0]))
    expect(sch.names == ["id", "name", "score"], "dataset_schema %s" % sch)
    expect(3 not in res, "no parameter_schema")

    cmd = any_cmd("CommandPreparedStatementQuery", _bytes_field(1, handle))
    for _ in range(2):   # a handle is reusable
        info = client.get_flight_info(fl.FlightDescriptor.for_command(cmd))
        t = client.do_get(info.endpoints[0].ticket).read_all()
        expect(t.to_pydict() == expected(4) and info.total_records == 4,
               "prepared values %s" % t.to_pydict())
    got = client.get_schema(fl.FlightDescriptor.for_command(cmd)).schema
    expect(got.names == ["id", "name", "score"], "prepared GetSchema %s" % got)

    close = fl.Action("ClosePreparedStatement", any_cmd(
        "ActionClosePreparedStatementRequest", _bytes_field(1, handle)))
    expect(list(client.do_action(close)) == [], "close returns an empty stream")

    try:
        bogus = any_cmd("CommandPreparedStatementQuery", _bytes_field(1, b"SELECT 4"))
        client.get_flight_info(fl.FlightDescriptor.for_command(bogus))
        failures.append("a foreign handle was accepted")
    except pa.ArrowInvalid as e:
        expect("not issued by this endpoint" in str(e), "foreign handle message: %s" % e)
    try:
        list(client.do_action(fl.Action("CreatePreparedStatement", any_cmd(
            "ActionCreatePreparedStatementRequest", _bytes_field(1, b"FAIL prep")))))
        failures.append("a failing statement prepared")
    except pa.ArrowInvalid as e:
        expect("echo executor refused" in str(e), "prepare error: %s" % e)
    try:
        list(client.do_action(fl.Action("BeginTransaction", b"")))
        failures.append("BeginTransaction did not raise")
    except pa.ArrowNotImplementedError as e:
        expect("BeginTransaction" in str(e), "unknown action message: %s" % e)
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
    with fsql.connect("grpc://127.0.0.1:%d" % port) as conn:
        info = conn.adbc_get_info()
        if info.get("vendor_name") != "boltapi-echo" or info.get("vendor_version") != "9.9.9":
            failures.append("ADBC get_info %s" % info)
        types = conn.adbc_get_table_types()
        if types != ["TABLE", "VIEW"]:
            failures.append("ADBC table types %s" % types)
        sch = conn.adbc_get_table_schema("orders")
        if sch.names != ["id", "name", "score"]:
            failures.append("ADBC table schema %s" % sch)
        objs = conn.adbc_get_objects(depth="tables").read_all().to_pylist()
        tabs = sorted(t["table_name"] for c in objs for s in (c["catalog_db_schemas"] or [])
                      for t in (s["db_schema_tables"] or []))
        if tabs != ["customers", "orders", "top_orders"]:
            failures.append("ADBC get_objects tables %s (%s)" % (tabs, objs))
        with conn.cursor() as cur:
            cur.adbc_prepare("SELECT 6")
            cur.execute("SELECT 6")
            table = cur.fetch_arrow_table()
        if table.to_pydict() != expected(6):
            failures.append("ADBC prepared values %s" % table.to_pydict())
    print("ADBC Flight SQL driver: OK")


def run_jdbc_probe(port, query, table):
    """{key: value} printed by FlightSqlJdbcProbe.java, or None to skip."""
    jar = os.environ.get("FLIGHT_SQL_JDBC_JAR")
    java = shutil.which("java")
    if not jar or not os.path.isfile(jar) or not java:
        print("note: FLIGHT_SQL_JDBC_JAR/java not available; JDBC leg skipped")
        return None
    probe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "FlightSqlJdbcProbe.java")
    out = subprocess.run([java, "--add-opens=java.base/java.nio=ALL-UNNAMED", "-cp", jar,
                          probe, str(port), query, table],
                         capture_output=True, text=True, timeout=300)
    facts = dict(line.split("\t", 1) for line in out.stdout.splitlines() if "\t" in line)
    if facts.get("done") != "ok":
        raise AssertionError("JDBC probe failed: %s %s" % (out.stdout, out.stderr[-2000:]))
    return facts


def check_jdbc(port, failures):
    facts = run_jdbc_probe(port, "SELECT 3", "customers")
    if facts is None:
        return
    rows3 = "id,name,score;0,row0,0.0;1,row1,0.5;2,row2,1.0"
    want = {
        "product": "boltapi-echo", "version": "9.9.9", "read_only": "true",
        "table_types": "TABLE;VIEW", "catalogs": "", "schemas": "",
        "tables": "customers,TABLE;orders,TABLE;top_orders,VIEW",
        "columns": "id,BIGINT;name,VARCHAR;score,DOUBLE",
        "primary_keys": "region,1;id,2", "imported_keys": "",
        "statement": rows3, "prepared_1": rows3, "prepared_2": rows3,
    }
    for k, v in want.items():
        if facts.get(k) != v:
            failures.append("JDBC %s: %r != %r" % (k, facts.get(k), v))
    if "echo executor refused" not in facts.get("error", ""):
        failures.append("JDBC error message lost: %r" % facts.get("error"))
    print("Flight SQL JDBC driver: OK")


def _h2_frame(ftype, flags, sid, payload=b""):
    return struct.pack(">I", len(payload))[1:] + bytes([ftype, flags]) + \
        struct.pack(">I", sid) + payload


def _hpack_int(v):
    if v < 127:
        return bytes([v])
    out, v = bytearray([127]), v - 127
    while v >= 128:
        out.append((v & 0x7F) | 0x80)
        v >>= 7
    out.append(v)
    return bytes(out)


def _hpack_literal(name, value):
    return b"\x00" + _hpack_int(len(name)) + name + _hpack_int(len(value)) + value


def check_flow_control(port, failures, window=1024, rows=20000):
    """No client in the matrix shrinks the HTTP/2 window, so a raw socket
    does: SETTINGS_INITIAL_WINDOW_SIZE=`window`, then DoGet a result many
    windows long. Every DATA frame must fit the credit granted so far on
    both the stream and the connection; credit is only topped up once the
    stream's window is exhausted, so a server that ignores it is caught."""
    sql = ("SELECT %d" % rows).encode()
    ticket = any_cmd("TicketStatementQuery", _bytes_field(1, sql))
    body = _bytes_field(1, ticket)
    grpc = b"\x00" + struct.pack(">I", len(body)) + body
    headers = b"".join(_hpack_literal(n, v) for n, v in (
        (b":method", b"POST"), (b":scheme", b"http"),
        (b":path", b"/arrow.flight.protocol.FlightService/DoGet"),
        (b":authority", b"127.0.0.1"), (b"content-type", b"application/grpc"),
        (b"te", b"trailers")))
    sock = socket.create_connection(("127.0.0.1", port), 10)
    sock.settimeout(10)
    sock.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" +
                 _h2_frame(4, 0, 0, struct.pack(">HI", 4, window)) +
                 _h2_frame(1, 4, 1, headers) + _h2_frame(0, 1, 1, grpc))
    buf = b""

    def read_frame():
        nonlocal buf
        while len(buf) < 9 or len(buf) < 9 + int.from_bytes(buf[:3], "big"):
            chunk = sock.recv(65536)
            if not chunk:
                raise AssertionError("connection closed mid-stream")
            buf += chunk
        n = int.from_bytes(buf[:3], "big")
        f = (buf[3], buf[4], int.from_bytes(buf[5:9], "big") & 0x7FFFFFFF, buf[9:9 + n])
        buf = buf[9 + n:]
        return f

    stream_credit, conn_credit = window, 65535
    stream_got = conn_got = 0
    payload = b""
    status = None
    try:
        for _ in range(1000000):
            ftype, flags, sid, data = read_frame()
            if ftype == 4 and not flags & 1:
                sock.sendall(_h2_frame(4, 1, 0))
            elif ftype == 0 and sid == 1:
                stream_got += len(data)
                conn_got += len(data)
                payload += data
                if stream_got > stream_credit or conn_got > conn_credit:
                    failures.append("flow control: DATA past the window (stream %d/%d, "
                                    "connection %d/%d)" % (stream_got, stream_credit,
                                                           conn_got, conn_credit))
                    return
                if stream_got == stream_credit:
                    sock.sendall(_h2_frame(8, 0, 1, struct.pack(">I", window)))
                    stream_credit += window
                if conn_credit - conn_got < 16384:
                    sock.sendall(_h2_frame(8, 0, 0, struct.pack(">I", 65535)))
                    conn_credit += 65535
            elif ftype == 1 and sid == 1 and flags & 1:
                i = data.find(b"grpc-status")
                status = data[i + 12:i + 12 + data[i + 11]] if i >= 0 else b"?"
                break
            elif ftype in (3, 7):
                failures.append("flow control: stream reset / GOAWAY")
                return
    finally:
        sock.close()
    if status != b"0":
        failures.append("flow control: grpc-status %r" % status)
    if len(payload) < 20 * window:
        failures.append("flow control: only %d bytes, the window never bound" % len(payload))
    msgs, i = 0, 0
    while i + 5 <= len(payload):
        i += 5 + struct.unpack(">I", payload[i + 1:i + 5])[0]
        msgs += 1
    if i != len(payload) or msgs < 2:
        failures.append("flow control: %d gRPC messages, %d/%d bytes framed" %
                        (msgs, i, len(payload)))


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
        check_flow_control(port, failures)
        check_metadata(port, failures)
        check_prepared(port, failures)
        check_adbc(port, failures)
        check_jdbc(port, failures)
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
