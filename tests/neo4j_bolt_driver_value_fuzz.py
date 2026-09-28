#!/usr/bin/env python3
"""Random graph + temporal values through the OFFICIAL neo4j driver.

The echo server's `RANDOM <seed> <rows>` query streams random value trees
(nodes, relationships, paths, every temporal type, nested in lists and
dictionaries) next to the server's own canonical text for each one
(tests/neo4j_bolt_value_gen.h). This file renders what the DRIVER hydrated
into the same grammar and requires equality, for a Bolt 5 server and for a
server pinned to Bolt 4.4, so both wire dialects are judged by a client we
did not write.

Usage: neo4j_bolt_driver_value_fuzz.py <echo-server> [seeds]   (default 8;
NEO4J_VALUE_FUZZ_SEEDS overrides, for a longer campaign)

Exit: 0 pass, 1 fail, 77 skip (no driver in this interpreter).
"""

import datetime
import os
import re
import struct
import subprocess
import sys
import time
import warnings

SKIP = 77
ROWS = 64


def fail(msg):
    print("FAIL: %s" % msg, flush=True)
    sys.exit(1)


def hx(s):
    return s.encode("utf-8").hex()


def local_seconds(dt):
    from neo4j.time import Date
    days = dt.date().to_ordinal() - Date(1970, 1, 1).to_ordinal()
    return days * 86400 + dt.hour * 3600 + dt.minute * 60 + int(dt.second)


def describe(v):
    from neo4j.graph import Node, Path, Relationship
    from neo4j.time import Date, DateTime, Duration, Time

    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        return "f:" + struct.pack(">d", v).hex()
    if isinstance(v, str):
        return "s:" + hx(v)
    if isinstance(v, (bytes, bytearray)):
        return "b:" + bytes(v).hex()
    if isinstance(v, list):
        return "[" + ",".join(describe(x) for x in v) + "]"
    if isinstance(v, dict):
        return "{" + ",".join(hx(k) + "=" + describe(x) for k, x in v.items()) + "}"
    if isinstance(v, Node):
        return "N(%d,[%s],%s,e:%s)" % (
            v.id, ",".join(sorted(set(hx(l) for l in v.labels))),
            describe(dict(v.items())), hx(v.element_id))
    if isinstance(v, Relationship):
        return "R(%d,%d,%d,%s,%s,e:%s,e:%s,e:%s)" % (
            v.id, v.start_node.id, v.end_node.id, hx(v.type),
            describe(dict(v.items())), hx(v.element_id),
            hx(v.start_node.element_id), hx(v.end_node.element_id))
    if isinstance(v, Path):
        return "P([%s],[%s])" % (",".join(describe(n) for n in v.nodes),
                                 ",".join(describe(r) for r in v.relationships))
    if isinstance(v, DateTime):
        if v.tzinfo is None:
            return "d(%d,%d)" % (local_seconds(v), v.nanosecond)
        off = int(v.utcoffset().total_seconds())
        utc = local_seconds(v) - off
        key = getattr(v.tzinfo, "key", None) or getattr(v.tzinfo, "zone", None)
        if key is not None:
            return "i(%d,%d,%s)" % (utc, v.nanosecond, hx(key))
        return "I(%d,%d,%d)" % (utc, v.nanosecond, off)
    if isinstance(v, Date):
        return "D(%d)" % (v.to_ordinal() - Date(1970, 1, 1).to_ordinal())
    if isinstance(v, Time):
        if v.tzinfo is None:
            return "t(%d)" % v.ticks
        return "T(%d,%d)" % (v.ticks, int(v.utcoffset().total_seconds()))
    if isinstance(v, Duration):
        return "E(%d,%d,%d)" % (v.months, v.days,
                                v.seconds * 1000000000 + v.nanoseconds)
    return "?%s" % type(v).__name__


def start(server_bin, major):
    proc = subprocess.Popen([server_bin, "--port", "0", "--max-major", str(major)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    deadline = time.time() + 15.0
    while time.time() < deadline:
        line = proc.stdout.readline()
        m = re.match(r"^PORT (\d+)", line.strip()) if line else None
        if m:
            return proc, int(m.group(1))
        if not line:
            break
    proc.kill()
    fail("echo server printed no PORT line")


def run_major(server_bin, major, seeds):
    from neo4j import GraphDatabase
    proc, port = start(server_bin, major)
    checked = 0
    kinds = set()
    try:
        drv = GraphDatabase.driver("bolt://127.0.0.1:%d" % port, auth=None)
        with drv.session() as s:
            for seed in range(1, seeds + 1):
                q = "RANDOM %d %d%s" % (seed, ROWS, "" if major == 5 else " nozone")
                for rec in s.run(q):
                    got = describe(rec["value"])
                    want = rec["text"]
                    if got != want:
                        fail("Bolt %d seed %d:\n  server %s\n  driver %s"
                             % (major, seed, want, got))
                    kinds.update(re.findall(r"(?<![0-9a-f])([NRPDtTdIiE])\(", want))
                    checked += 1
            # a value the codec cannot send is a named FAILURE, not a dropped row
            try:
                list(s.run("BADVALUE"))
                fail("Bolt %d: an invalid Node was sent instead of refused" % major)
            except Exception as ex:  # neo4j.exceptions.DatabaseError
                if "could not be sent" not in str(ex):
                    fail("Bolt %d: wrong refusal: %s" % (major, ex))
            agreed = drv.get_server_info().protocol_version
            if agreed[0] != major:
                fail("negotiated Bolt %s, wanted major %d" % (agreed, major))
        drv.close()
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
    want_kinds = set("NRPDtTdIE") | ({"i"} if major == 5 else set())
    if not want_kinds <= kinds:
        fail("Bolt %d: kinds never generated: %s" % (major, sorted(want_kinds - kinds)))
    print("Bolt %d: %d random values agree (kinds %s)" % (major, checked, "".join(sorted(kinds))),
          flush=True)


def main():
    if len(sys.argv) < 2:
        fail("usage: %s <echo-server> [seeds]" % sys.argv[0])
    alt = os.environ.get("BOLTAPI_NEO4J_PYTHON")
    if alt and os.path.abspath(alt) != os.path.abspath(sys.executable):
        os.environ.pop("BOLTAPI_NEO4J_PYTHON")
        os.execv(alt, [alt, os.path.abspath(__file__)] + sys.argv[1:])
    try:
        import neo4j  # noqa: F401
    except ImportError as ex:
        print("SKIP: the official `neo4j` driver is not importable in %s (%s)"
              % (sys.executable, ex), flush=True)
        sys.exit(SKIP)
    warnings.simplefilter("ignore")
    seeds = int(os.environ.get("NEO4J_VALUE_FUZZ_SEEDS",
                               sys.argv[2] if len(sys.argv) > 2 else "8"))
    for major in (5, 4):
        run_major(sys.argv[1], major, seeds)
    print("PASS", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
