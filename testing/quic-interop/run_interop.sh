#!/bin/bash
# Run quic-interop-runner with the Bolt API server (image boltapi-qns) against
# real clients. The runner runs in a container (boltapi-qir-runner: tshark +
# docker CLI) driving the host daemon. The runner hardcodes /tmp for its temp
# dirs and passes them to compose as bind mounts the daemon resolves on the
# host, so host /tmp is mounted at /tmp and <workdir> must live under /tmp.
#   testing/quic-interop/run_interop.sh <workdir> [clients] [tests]
set -euo pipefail
work=$(cd "${1:?workdir}" && pwd)
clients=${2:-quic-go,ngtcp2}
tests=${3:-handshake,transfer,retry,resumption,multiplexing,zerortt,http3}
runner_rev=740c05a10b61d65e8abd3ad38d60898004d335d9
qir="$work/quic-interop-runner"
[ -d "$qir" ] || git clone -q https://github.com/quic-interop/quic-interop-runner "$qir"
git -C "$qir" checkout -q "$runner_rev"
python3 - "$qir/implementations_quic.json" <<'PY'
import json, sys
p = sys.argv[1]; d = json.load(open(p))
d["boltapi"] = {"image": "boltapi-qns:latest", "url": "https://github.com/Ugbot/BoltAPI", "role": "server"}
json.dump(d, open(p, "w"), indent=2)
PY
case "$work" in /tmp/*|/private/tmp/*) ;; *) echo "workdir must be under /tmp"; exit 2;; esac
work=${work#/private}
mkdir -p "$work/logs"
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
    -v /tmp:/tmp -w "$qir" boltapi-qir-runner \
    python3 run.py -s boltapi -c "$clients" -t "$tests" \
        -l "$work/logs/run-$(date +%s)" -j "$work/result.json" -m
