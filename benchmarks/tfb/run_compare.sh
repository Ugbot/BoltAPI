#!/usr/bin/env bash
# run_compare.sh — TechEmpower-style head-to-head: BoltAPI vs Drogon.
#
# Each framework runs in its OWN container; the SAME wrk container drives both
# over a shared docker network (this is how TFB itself isolates frameworks). The
# pure-framework endpoints /plaintext + /json are measured (no DB tests — BoltAPI
# dropped PostgreSQL, so this is a fair routing+serialization+I/O comparison).
#
#   benchmarks/tfb/run_compare.sh [--duration 15] [--conns 256] [--threads 4]
#                                 [--skip-build] [--endpoints "/plaintext /json"]
#
# CAVEAT: on a single dev box the server + wrk share the host CPU (TFB uses a
# separate load machine), so absolute numbers are lower than a dedicated rig —
# but BOTH frameworks face identical conditions, so the RATIO is meaningful. Run
# on an idle/cool box for stable numbers.
set -euo pipefail

DURATION=15
CONNS=256
THREADS=4
SKIP_BUILD=0
ENDPOINTS="/plaintext /json"

while [ $# -gt 0 ]; do
    case "$1" in
        --duration)  DURATION="$2"; shift 2;;
        --conns)     CONNS="$2"; shift 2;;
        --threads)   THREADS="$2"; shift 2;;
        --endpoints) ENDPOINTS="$2"; shift 2;;
        --skip-build) SKIP_BUILD=1; shift;;
        *) echo "unknown arg: $1" >&2; exit 2;;
    esac
done

repo="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$repo"
NET=boltbench

# BoltAPI thread config. Drogon uses one event-loop thread per core; BoltAPI
# splits IO threads + a worker pool, so ~half the cores as IO threads (workers
# auto-fill the rest) measured best — more IO threads than that oversubscribes.
CORES="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)"
BOLT_IO_THREADS=${IO_THREADS:-$(( CORES / 2 > 0 ? CORES / 2 : 1 ))}

if [ "$SKIP_BUILD" -eq 0 ]; then
    echo "==> Building images (BoltAPI + Drogon + wrk) ..."
    docker build -f benchmarks/tfb/Dockerfile.boltapi -t tfb-boltapi .
    docker build -f benchmarks/tfb/Dockerfile.drogon  -t tfb-drogon  .
    docker build -f benchmarks/tfb/Dockerfile.wrk     -t tfb-wrk benchmarks/tfb
fi

docker network create "$NET" >/dev/null 2>&1 || true
cleanup() {
    docker rm -f tfb-srv >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Run wrk against one framework's container for each endpoint; print req/s + p99.
run_fw() {
    local label="$1" image="$2"
    docker rm -f tfb-srv >/dev/null 2>&1 || true
    # IO_THREADS is read by the BoltAPI image; Drogon ignores it (uses all cores).
    docker run -d --rm --name tfb-srv --network "$NET" \
        -e IO_THREADS="$BOLT_IO_THREADS" "$image" >/dev/null
    sleep 4   # warmup / listen

    for ep in $ENDPOINTS; do
        local out rps p99
        out="$(docker run --rm --network "$NET" tfb-wrk \
                 --latency -t"$THREADS" -c"$CONNS" -d"${DURATION}s" \
                 "http://tfb-srv:8080${ep}" 2>/dev/null || true)"
        rps="$(printf '%s\n' "$out" | awk '/Requests\/sec/{print $2}')"
        p99="$(printf '%s\n' "$out" | awk '/^[[:space:]]*99%/{print $2}')"
        printf "%-9s %-12s req/s=%-12s p99=%s\n" "$label" "$ep" "${rps:-ERR}" "${p99:-ERR}"
    done
    docker rm -f tfb-srv >/dev/null 2>&1 || true
}

echo ""
echo "== TFB-style comparison (wrk -t$THREADS -c$CONNS -d${DURATION}s) =="
echo "   cores=$CORES  boltapi io-threads=$BOLT_IO_THREADS (drogon: thread-per-core)"
echo "   one box: server + wrk share CPU -> read the RATIO, not the absolutes"
echo ""
run_fw boltapi tfb-boltapi
run_fw drogon  tfb-drogon
echo ""
echo "(Done. For trustworthy absolutes, run on an idle box or a dedicated load machine.)"
