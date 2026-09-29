#!/usr/bin/env python3
"""Run h2spec (docker image summerwind/h2spec) against a real BoltAPI server,
over h2c (prior knowledge) and over TLS (ALPN h2).

Every failing h2spec case must be listed in EXPECTED_FAILURES with the ticket
that tracks it; an unlisted failure fails the test, and so does a listed case
that now passes (so the list cannot rot).

Exit 0 = pass, 1 = unexpected result, 77 = docker unavailable (skip).
Usage: h2spec_conformance.py <path to boltapi_h2spec_server>
"""
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import docker_run_once  # noqa: E402

IMAGE = "summerwind/h2spec"
# h2spec id -> tracker ticket. Keep empty unless a case is genuinely deferred.
EXPECTED_FAILURES = {}


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_listening(port, deadline):
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def docker_ready():
    if shutil.which("docker") is None:
        return "docker not on PATH"
    try:
        r = subprocess.run(["docker", "info"], capture_output=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired) as e:
        return f"docker info failed: {e}"
    if r.returncode != 0:
        return "docker daemon not reachable"
    r = subprocess.run(["docker", "image", "inspect", IMAGE], capture_output=True, timeout=20)
    if r.returncode != 0:
        pull = subprocess.run(["docker", "pull", IMAGE], capture_output=True, timeout=300)
        if pull.returncode != 0:
            return f"cannot pull {IMAGE}"
    return None


def run_h2spec(port, tls):
    host = os.environ.get("BOLTAPI_H2SPEC_HOST", "host.docker.internal")
    cmd = ["--add-host=host.docker.internal:host-gateway",
           IMAGE, "-h", host, "-p", str(port), "-o", "3", "-S"]
    if tls:
        cmd += ["-t", "-k"]
    r = docker_run_once.run("boltapi-h2spec", cmd, timeout=600)
    out = r.stdout + r.stderr
    # The "Failures:" section repeats each failed case under its spec line and
    # its numbered section heading; collect them as "<spec>/<section>/<case>".
    specs = (("Generic tests", "generic"), ("Hypertext Transfer Protocol", "http2"),
             ("HPACK", "hpack"))
    failed = set()
    spec = section = None
    in_failures = False
    for line in out.splitlines():
        if line.startswith("Failures:"):
            in_failures = True
            continue
        if not in_failures:
            continue
        for prefix, name in specs:
            if line.startswith(prefix):
                spec, section = name, None
        sec = re.match(r"^\s+(\d+(?:\.\d+)*)\.\s", line)
        if sec:
            section = sec.group(1)
            continue
        case = re.match(r"^\s*\u00d7\s*(\d+):", line)
        if case and spec and section:
            failed.add(f"{spec}/{section}/{case.group(1)}")
    summary = re.search(r"(\d+) tests, (\d+) passed, (\d+) skipped, (\d+) failed", out)
    return out, failed, summary


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    why = docker_ready()
    if why:
        print(f"SKIP: {why}")
        return 77
    h2c, tls = free_port(), free_port()
    # The server logs a lot under TLS; an unread pipe would wedge it.
    log = tempfile.TemporaryFile()
    server = subprocess.Popen([sys.argv[1], str(h2c), str(tls)],
                              stdout=log, stderr=subprocess.STDOUT)
    try:
        deadline = time.time() + 20
        if not (wait_listening(h2c, deadline) and wait_listening(tls, deadline)):
            print("FAIL: server did not start")
            return 1
        bad = False
        for label, port, use_tls in (("h2c", h2c, False), ("tls", tls, True)):
            out, failed, summary = run_h2spec(port, use_tls)
            print(f"==== h2spec over {label} ====")
            print(summary.group(0) if summary else out[-4000:])
            if summary is None:
                print("FAIL: no h2spec summary")
                bad = True
                continue
            unexpected = sorted(failed - EXPECTED_FAILURES.keys())
            fixed = sorted(k for k in EXPECTED_FAILURES if k not in failed)
            if int(summary.group(4)) > 0 and not failed:
                print(out[-6000:])
                print("FAIL: failures reported but none parsed")
                bad = True
            for k in unexpected:
                print(f"FAIL: unexpected h2spec failure {k}")
                bad = True
            for k in fixed:
                print(f"FAIL: {k} now passes; drop it from EXPECTED_FAILURES ({EXPECTED_FAILURES[k]})")
                bad = True
            if unexpected:
                print(out[out.find("Failures:"):][:8000])
            if server.poll() is not None:
                log.seek(0)
                print(log.read()[-4000:].decode(errors="replace"))
                print(f"FAIL: server exited ({server.returncode}) during h2spec {label}")
                bad = True
                break
        return 1 if bad else 0
    finally:
        server.terminate()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait()
        log.close()


if __name__ == "__main__":
    sys.exit(main())
