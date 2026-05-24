#!/usr/bin/env bash
# run_benchmarks.sh — Linux/Docker benchmark orchestration (Clang/lld build).
#
# Mirror of run_benchmarks.ps1. Builds the benchmark targets, starts the bench
# server, drives the in-tree load generator against each endpoint, and prints a
# table. The server is ALWAYS killed via a trap — no orphan, no hang. Each
# loadgen call is wrapped in `timeout` as a belt-and-suspenders self-terminate.
#
#   scripts/run_benchmarks.sh [--duration N] [--connections N] [--port N]
#                             [--build-dir DIR] [--io-threads N] [--workers N]
#                             [--skip-build]
set -euo pipefail

DURATION=10
CONNECTIONS=64
PORT=18080
BUILD_DIR="build/bench-linux"
IO_THREADS=1
WORKERS=0
SKIP_BUILD=0

while [ $# -gt 0 ]; do
    case "$1" in
        --duration)    DURATION="$2"; shift 2;;
        --connections) CONNECTIONS="$2"; shift 2;;
        --port)        PORT="$2"; shift 2;;
        --build-dir)   BUILD_DIR="$2"; shift 2;;
        --io-threads)  IO_THREADS="$2"; shift 2;;
        --workers)     WORKERS="$2"; shift 2;;
        --skip-build)  SKIP_BUILD=1; shift;;
        *) echo "unknown arg: $1" >&2; exit 2;;
    esac
done

repo="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo"

if [ "$SKIP_BUILD" -eq 0 ]; then
    echo "==> Configuring + building benchmarks ($BUILD_DIR) with Clang/lld"
    # Clang only (project policy: never GCC on Linux), lld linker.
    cmake -S . -B "$BUILD_DIR" -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_C_COMPILER=clang \
        -DCMAKE_CXX_COMPILER=clang++ \
        -DCMAKE_EXE_LINKER_FLAGS="-fuse-ld=lld" \
        -DBOLTAPI_BUILD_BENCHMARKS=ON
    cmake --build "$BUILD_DIR" -j"$(nproc)" \
        --target boltapi_bench_server boltapi_loadgen
fi

server_exe="$BUILD_DIR/benchmarks/boltapi_bench_server"
loadgen_exe="$BUILD_DIR/benchmarks/boltapi_loadgen"
for exe in "$server_exe" "$loadgen_exe"; do
    [ -x "$exe" ] || { echo "missing benchmark exe: $exe (build first?)" >&2; exit 1; }
done

endpoints=("/plaintext" "/json" "/db" "/queries?n=20" "/route/42")

echo "==> Starting bench server on 127.0.0.1:$PORT"
"$server_exe" "$PORT" --io-threads "$IO_THREADS" --workers "$WORKERS" >/dev/null 2>&1 &
SERVER_PID=$!
trap 'kill "$SERVER_PID" 2>/dev/null || true' EXIT
sleep 1   # warmup

printf "\n== BoltAPI benchmark results (conns=%s, dur=%ss) ==\n" "$CONNECTIONS" "$DURATION"
printf "%-16s %12s %10s %10s %10s %10s %8s\n" \
    endpoint req/s MiB/s p50_us p99_us p999_us errors

# Hard wall: each loadgen call may run at most duration + 10s.
hard=$((DURATION + 10))
for ep in "${endpoints[@]}"; do
    line="$(timeout "$hard" "$loadgen_exe" --host 127.0.0.1 --port "$PORT" \
        --path "$ep" --connections "$CONNECTIONS" --duration "$DURATION" \
        --io-threads "$IO_THREADS" --workers "$WORKERS" 2>/dev/null \
        | grep '^RESULT ' || true)"
    [ -n "$line" ] || { echo "  (no RESULT for $ep)"; continue; }
    # shellcheck disable=SC2086
    eval "$(echo "${line#RESULT }" | tr ' ' '\n' | sed 's/^/R_/')"
    mib=$(awk "BEGIN{printf \"%.2f\", ${R_bytes_per_s:-0}/1048576}")
    printf "%-16s %12.0f %10s %10s %10s %10s %8s\n" \
        "$ep" "${R_rps:-0}" "$mib" "${R_p50_us:-0}" "${R_p99_us:-0}" "${R_p999_us:-0}" "${R_failed:-0}"
done
