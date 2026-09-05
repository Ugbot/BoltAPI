#!/usr/bin/env python3
"""Conformance-by-client for boltapi's Neo4j Bolt wire protocol.

THE ORACLE IS THE OFFICIAL `neo4j` PYTHON DRIVER. Nothing in this file parses
Bolt; the driver does. If the driver decodes our bytes into the values the echo
executor was asked to produce, the wire implementation agrees with a client we
did not write -- which is the only kind of conformance evidence that counts.

Assertions are on VALUES, never on row counts alone.

Usage:  neo4j_bolt_driver_conformance.py <path-to-echo-server-binary>

Exit codes:  0 pass · 1 fail · 77 skip (ctest SKIP_RETURN_CODE: the `neo4j`
module is not importable in this interpreter -- printed, never silent).
"""

import os
import re
import signal
import subprocess
import sys
import time

SKIP = 77


def fail(msg):
    print("FAIL: %s" % msg, flush=True)
    sys.exit(1)


def main():
    if len(sys.argv) < 2:
        fail("usage: %s <echo-server-binary>" % sys.argv[0])
    server_bin = sys.argv[1]
    if not os.path.exists(server_bin):
        fail("echo server binary not found: %s" % server_bin)

    # Re-exec into a driver-capable interpreter when one is named. CMake also
    # reads BOLTAPI_NEO4J_PYTHON, but only at CONFIGURE time; honouring it at
    # RUN time means `BOLTAPI_NEO4J_PYTHON=... ctest -R conformance` works on an
    # already-configured tree, which is how this actually gets run.
    alt = os.environ.get("BOLTAPI_NEO4J_PYTHON")
    if alt and os.path.abspath(alt) != os.path.abspath(sys.executable):
        os.environ.pop("BOLTAPI_NEO4J_PYTHON")
        os.execv(alt, [alt, os.path.abspath(__file__)] + sys.argv[1:])

    try:
        import neo4j
        from neo4j import GraphDatabase
    except ImportError as exc:
        print(
            "SKIP: the official `neo4j` driver is not importable in %s (%s).\n"
            "      This test is the ONLY external-client oracle for the Bolt\n"
            "      wire implementation; install it to run it:\n"
            "          python3 -m venv .venv && .venv/bin/pip install neo4j\n"
            "      then re-run with BOLTAPI_NEO4J_PYTHON=.venv/bin/python."
            % (sys.executable, exc),
            flush=True,
        )
        sys.exit(SKIP)

    print("driver: neo4j %s (python %s)" % (neo4j.__version__, sys.version.split()[0]),
          flush=True)

    proc = subprocess.Popen([server_bin, "--port", "0"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True)
    try:
        port = None
        deadline = time.time() + 15.0
        while time.time() < deadline:
            line = proc.stdout.readline()
            if not line:
                break
            m = re.match(r"^PORT (\d+)", line.strip())
            if m:
                port = int(m.group(1))
                break
        if port is None:
            err = proc.stderr.read() if proc.stderr else ""
            fail("echo server never reported a port; stderr=%r" % err)
        print("echo server on 127.0.0.1:%d" % port, flush=True)

        uri = "bolt://127.0.0.1:%d" % port
        driver = GraphDatabase.driver(uri, auth=None)
        try:
            run_checks(driver)
        finally:
            driver.close()
    finally:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()

    print("PASS: official neo4j driver conformance", flush=True)
    return 0


EXPECTED_KINDS = [None, True, -17, 3.5, "Größenmaßstäbe", [1, 2, 3], {"k": "v"}]


def check_kinds(kinds, where):
    """Every PackStream type the server emits, decoded by the driver."""
    if not isinstance(kinds, list) or len(kinds) != 7:
        fail("%s: kinds is %r, expected a 7-element list" % (where, kinds))
    for i, (got, want) in enumerate(zip(kinds, EXPECTED_KINDS)):
        if isinstance(want, float):
            if not isinstance(got, float) or abs(got - want) > 1e-12:
                fail("%s: kinds[%d] = %r, expected float %r" % (where, i, got, want))
        elif got != want or type(got) is not type(want):
            fail("%s: kinds[%d] = %r (%s), expected %r (%s)"
                 % (where, i, got, type(got).__name__, want, type(want).__name__))


def run_checks(driver):
    # 1. The smoke case the acceptance names: a session opens (handshake +
    #    HELLO + LOGON) and a query returns a record.
    with driver.session() as s:
        rec = s.run("RETURN 1").single()
        if rec is None:
            fail("RETURN 1 returned no record")
        if list(rec.keys()) != ["query", "params", "index", "kinds"]:
            fail("field names came back as %r" % (list(rec.keys()),))
        if rec["query"] != "RETURN 1":
            fail("query echoed as %r" % (rec["query"],))
        if rec["index"] != 0:
            fail("index was %r, expected 0" % (rec["index"],))
        if rec["params"] != {}:
            fail("params echoed as %r, expected {}" % (rec["params"],))
        check_kinds(rec["kinds"], "RETURN 1")
    print("  ok: RETURN 1 -> values correct, all 7 PackStream kinds decoded",
          flush=True)

    # 2. A parameterised query: the driver encodes params, we decode + echo
    #    them, the driver decodes them back. Values must survive the round trip.
    params = {
        "x": 7,
        "big": 2 ** 40,
        "neg": -129,
        "pi": 3.5,
        "name": "Größenmaßstäbe",
        "flag": True,
        "nothing": None,
        "xs": [1, 2, 3],
        "nested": {"a": {"b": [True, None, "z"]}},
    }
    with driver.session() as s:
        rec = s.run("RETURN $x AS v", **params).single()
        if rec is None:
            fail("parameterised query returned no record")
        if rec["query"] != "RETURN $x AS v":
            fail("parameterised query echoed as %r" % (rec["query"],))
        got = rec["params"]
        for k, want in params.items():
            if k not in got:
                fail("parameter %r missing from the echo (%r)" % (k, got))
            if isinstance(want, float):
                if abs(got[k] - want) > 1e-12:
                    fail("parameter %r round-tripped as %r" % (k, got[k]))
            elif got[k] != want:
                fail("parameter %r round-tripped as %r, expected %r" % (k, got[k], want))
    print("  ok: parameterised query -> 9 parameters round-tripped by value",
          flush=True)

    # 3. A multi-record stream, driven through the driver's own PULL batching.
    with driver.session() as s:
        result = s.run("stream", n=25)
        rows = list(result)
        if len(rows) != 25:
            fail("multi-record stream returned %d rows, expected 25" % len(rows))
        for i, row in enumerate(rows):
            if row["index"] != i:
                fail("row %d has index %r" % (i, row["index"]))
            if row["query"] != "stream":
                fail("row %d echoed query %r" % (i, row["query"]))
        check_kinds(rows[-1]["kinds"], "stream row 24")
    print("  ok: 25-record stream -> ordered, every index correct", flush=True)

    # 4. Batched fetching: force many PULL {n} round trips so has_more is
    #    exercised by the driver rather than only by our own wire test.
    with driver.session(fetch_size=3) as s:
        rows = list(s.run("batched", n=10))
        if [r["index"] for r in rows] != list(range(10)):
            fail("fetch_size=3 stream came back as %r" % [r["index"] for r in rows])
    print("  ok: fetch_size=3 over 10 records -> has_more batching correct",
          flush=True)

    # 5. An explicit transaction: BEGIN/RUN/PULL/COMMIT as no-op successes.
    with driver.session() as s:
        with s.begin_transaction() as tx:
            rec = tx.run("in a tx").single()
            if rec["query"] != "in a tx":
                fail("tx query echoed as %r" % (rec["query"],))
            tx.commit()
    print("  ok: explicit transaction -> BEGIN/RUN/PULL/COMMIT accepted", flush=True)

    # 6. A FAILURE must surface to the client as an error, NOT as an empty
    #    result. A wrong answer outranks an error; a silent zero-row success
    #    would be the failure mode this check exists to catch.
    # NOTE: an EMPTY query cannot be used here -- the official driver refuses it
    # client-side (ValueError) and never puts it on the wire, so it would test
    # the driver, not us. The echo executor therefore also refuses any query
    # starting with "FAIL", which the driver transmits happily.
    from neo4j.exceptions import Neo4jError
    with driver.session() as s:
        try:
            s.run("FAIL please").single()
        except Neo4jError as exc:
            if "SyntaxError" not in str(exc.code or ""):
                fail("failure surfaced with code %r, expected a SyntaxError code"
                     % (exc.code,))
        except Exception as exc:  # noqa: BLE001 - any other type is a real defect
            fail("failure surfaced as %s: %s" % (type(exc).__name__, exc))
        else:
            fail("an empty query returned SUCCESS -- a silent wrong answer")
        # ... and the session recovers (the driver sends RESET after a failure).
        rec = s.run("after failure").single()
        if rec["query"] != "after failure":
            fail("session did not recover after a failure: %r" % (rec,))
    print("  ok: FAILURE surfaces as a Neo4jError, session recovers", flush=True)

    # 7. Concurrent sessions over the driver's connection pool.
    sessions = [driver.session() for _ in range(4)]
    try:
        for i, s in enumerate(sessions):
            rec = s.run("conn %d" % i).single()
            if rec["query"] != "conn %d" % i:
                fail("pooled session %d echoed %r" % (i, rec["query"]))
    finally:
        for s in sessions:
            s.close()
    print("  ok: 4 pooled connections each served correctly", flush=True)


if __name__ == "__main__":
    sys.exit(main())
