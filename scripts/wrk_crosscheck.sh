#!/usr/bin/env bash
# wrk_crosscheck.sh — OPTIONAL external load-tool cross-check (Linux/Docker only).
#
# Validates the in-tree boltapi_loadgen against `wrk`, an independent C load
# generator. wrk is NOT a dependency: if it is absent this script exits 0 (a
# clean skip, never a failure). wrk is not Windows-native, so this has no
# PowerShell counterpart.
#
# A divergence of more than ~15% between boltapi_loadgen and wrk on the same
# endpoint is the signal to investigate the in-tree loadgen, not the server.
#
#   scripts/wrk_crosscheck.sh [--port N] [--build-dir DIR] [--duration N]
#                             [--connections N] [--threads N]
set -euo pipefail

if ! command -v wrk >/dev/null 2>&1; then
    echo "wrk not found on PATH; skipping external cross-check (this is not a failure)."
    exit 0
fi

PORT=18080
BUILD_DIR="build/bench-linux"
DURATION=10
CONNECTIONS=64
THREADS=4

while [ $# -gt 0 ]; do
    case "$1" in
        --port)        PORT="$2"; shift 2;;
        --build-dir)   BUILD_DIR="$2"; shift 2;;
        --duration)    DURATION="$2"; shift 2;;
        --connections) CONNECTIONS="$2"; shift 2;;
        --threads)     THREADS="$2"; shift 2;;
        *) echo "unknown arg: $1" >&2; exit 2;;
    esac
done

repo="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo"

server_exe="$BUILD_DIR/benchmarks/boltapi_bench_server"
[ -x "$server_exe" ] || { echo "missing $server_exe (run run_benchmarks.sh first)" >&2; exit 1; }

echo "==> Starting bench server on 127.0.0.1:$PORT"
"$server_exe" "$PORT" >/dev/null 2>&1 &
SERVER_PID=$!
trap 'kill "$SERVER_PID" 2>/dev/null || true' EXIT
sleep 1

echo "==> wrk GET /plaintext"
wrk -t"$THREADS" -c"$CONNECTIONS" -d"${DURATION}s" "http://127.0.0.1:$PORT/plaintext"

echo "==> wrk GET /json"
wrk -t"$THREADS" -c"$CONNECTIONS" -d"${DURATION}s" "http://127.0.0.1:$PORT/json"

# POST cross-check via an inline Lua snippet (no vendored .lua file).
lua="$(mktemp)"
trap 'kill "$SERVER_PID" 2>/dev/null || true; rm -f "$lua"' EXIT
cat >"$lua" <<'LUA'
wrk.method = "POST"
wrk.body   = '{"hello":"world"}'
wrk.headers["Content-Type"] = "application/json"
LUA
echo "==> wrk POST /json (echoes; endpoint returns fixed body)"
wrk -t"$THREADS" -c"$CONNECTIONS" -d"${DURATION}s" -s "$lua" "http://127.0.0.1:$PORT/json"
