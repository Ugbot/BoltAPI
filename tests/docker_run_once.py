"""Run a one-shot `docker run --rm` that cannot outlive the test.

A timed-out subprocess.run kills the docker client, not the container, and a
container killed that way keeps its anonymous volumes. So the container gets a
unique name and the gestalt.test labels (Gestalt2's scripts/docker_test_sweep.py
removes any that still escape), and is removed with `docker rm -f -v` on every
exit path: normal return, timeout, exception, SIGINT, SIGTERM.
"""
import os
import random
import signal
import subprocess
import time


def labels(owner):
    return ["--label", "gestalt.test=1",
            "--label", f"gestalt.test.owner={owner}",
            "--label", f"gestalt.test.started={int(time.time())}"]


def _remove(name):
    subprocess.run(["docker", "rm", "-f", "-v", name], capture_output=True, timeout=120)


def run(owner, args, timeout):
    """docker run --rm --name <unique> <labels> <args...>; returns CompletedProcess."""
    name = f"{owner}-{os.getpid()}-{random.getrandbits(16):04x}"

    def on_term(signum, _frame):
        _remove(name)
        raise SystemExit(128 + signum)

    prev = signal.signal(signal.SIGTERM, on_term)
    try:
        cmd = ["docker", "run", "--rm", "--name", name] + labels(owner) + list(args)
        try:
            return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired as e:
            out, err = (x.decode(errors="replace") if isinstance(x, bytes) else (x or "")
                        for x in (e.stdout, e.stderr))
            return subprocess.CompletedProcess(cmd, 124, out, err + "\ntimeout")
    finally:
        _remove(name)
        signal.signal(signal.SIGTERM, prev)
