#!/usr/bin/env python3
"""Run the Autobahn|Testsuite fuzzingclient (docker crossbario/autobahn-testsuite)
against the BoltAPI WebSocket echo example.

A case fails when its behavior or close behavior is FAILED. Every failing case
must be listed in EXPECTED_FAILURES with its ticket; an unlisted failure fails
the test, and so does a listed case that now passes. NON-STRICT, INFORMATIONAL
and UNIMPLEMENTED are reported, not failed. permessage-deflate (12.*, 13.*) is
excluded: the server does not negotiate it.

Exit 0 = pass, 1 = unexpected result, 77 = docker unavailable (skip).
Usage: autobahn_conformance.py <path to boltapi_ws_echo> [case glob ...]
"""
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import docker_run_once  # noqa: E402

IMAGE = "crossbario/autobahn-testsuite"
EXCLUDED = ["12.*", "13.*"]
# case id -> tracker ticket.
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
        pull = subprocess.run(["docker", "pull", IMAGE], capture_output=True, timeout=600)
        if pull.returncode != 0:
            return f"cannot pull {IMAGE}"
    return None


def run_suite(port, cases, workdir):
    host = os.environ.get("BOLTAPI_AUTOBAHN_HOST", "host.docker.internal")
    spec = {
        "outdir": "/work/reports",
        "servers": [{"agent": "boltapi", "url": f"ws://{host}:{port}/ws"}],
        "cases": cases,
        "exclude-cases": EXCLUDED,
        "exclude-agent-cases": {},
    }
    with open(os.path.join(workdir, "fuzzingclient.json"), "w") as f:
        json.dump(spec, f)
    cmd = ["--add-host=host.docker.internal:host-gateway",
           "-v", f"{workdir}:/work", IMAGE,
           "wstest", "-m", "fuzzingclient", "-s", "/work/fuzzingclient.json"]
    r = docker_run_once.run("boltapi-autobahn", cmd, timeout=1500)
    index = os.path.join(workdir, "reports", "index.json")
    if not os.path.exists(index):
        return r.stdout[-3000:] + r.stderr[-3000:], None
    with open(index) as f:
        return "", json.load(f).get("boltapi")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    why = docker_ready()
    if why:
        print(f"SKIP: {why}")
        return 77
    cases = sys.argv[2:] or ["*"]
    port = free_port()
    workdir = tempfile.mkdtemp(prefix="autobahn-")
    log = tempfile.TemporaryFile()
    server = subprocess.Popen([sys.argv[1], str(port)], stdout=log, stderr=subprocess.STDOUT)
    try:
        if not wait_listening(port, time.time() + 20):
            print("FAIL: server did not start")
            return 1
        tail, results = run_suite(port, cases, workdir)
        if results is None:
            print(tail)
            print("FAIL: no Autobahn report")
            return 1
        counts, failed = {}, set()
        for cid, res in results.items():
            b, bc = res.get("behavior"), res.get("behaviorClose")
            counts[b] = counts.get(b, 0) + 1
            if b == "FAILED" or bc == "FAILED":
                failed.add(cid)
        print(f"autobahn: {len(results)} cases " +
              " ".join(f"{k}={v}" for k, v in sorted(counts.items())))
        bad = False
        for cid in sorted(failed - EXPECTED_FAILURES.keys()):
            r = results[cid]
            print(f"FAIL: unexpected Autobahn failure {cid} "
                  f"(behavior={r.get('behavior')} close={r.get('behaviorClose')})")
            bad = True
        for cid in sorted(k for k in EXPECTED_FAILURES if k not in failed and k in results):
            print(f"FAIL: {cid} now passes; drop it from EXPECTED_FAILURES ({EXPECTED_FAILURES[cid]})")
            bad = True
        if server.poll() is not None:
            log.seek(0)
            print(log.read()[-4000:].decode(errors="replace"))
            print(f"FAIL: server exited ({server.returncode}) during the suite")
            bad = True
        if bad:
            print(f"reports kept in {workdir}/reports")
        else:
            shutil.rmtree(workdir, ignore_errors=True)
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
