# Bolt API — manual / interop test harness

Reusable real-client tests against a running server. Build once, point real
clients (browser, aiortc, curl) at it. Grows one small client per protocol.

## Run the demo server
Build with WebRTC on (add `-DBOLTAPI_WITH_HTTP3=ON` for the QUIC endpoint), then
run the demo (serves this `web/` dir + echo handlers + the `/webrtc/offer`
signaling route; also brings up HTTP/3 on the same port over UDP and advertises
`alt-svc: h3=":8080"` on H1/H2 responses so browsers can upgrade):

```
cmake -S . -B build/wrtc -G "Visual Studio 17 2022" -A x64 -DBOLTAPI_WITH_WEBRTC=ON -DBOLTAPI_WITH_HTTP3=ON
cmake --build build/wrtc --config Release --target boltapi_demo_server
build/wrtc/examples/Release/boltapi_demo_server.exe   # H1/H2/WS on :8080 + H3 on UDP :8080
```

## Tests (point at the running server)

| What | How |
|---|---|
| **WebRTC data channel (browser)** | open `http://localhost:8080/webrtc.html`, click **Connect & echo** — expect "ECHO ROUND-TRIP OK" |
| **WebRTC data channel (headless)** | `uv run --with aiortc python testing/aiortc_datachannel.py 8080` — expect "INTEROP OK" |
| **WebRTC media echo (browser)** | open `http://localhost:8080/media.html`, click **Start camera & echo** — your audio+video is offered to the server and the echoed stream renders in the right `<video>` |
| **WebRTC media echo (headless)** | `uv run --no-project --with aiortc --with numpy --with av python tests/interop/aiortc_media.py 8080` — sends a synthetic audio+video track, expect "INTEROP OK: media echo round-tripped" |
| HTTP/1.1 + verbs | `curl -v http://localhost:8080/health` → `ok` (response carries `alt-svc: h3=":8080"`) |
| WebSocket | connect a WS client to `ws://localhost:8080/ws` (text echo) |
| **HTTP/3 (headless)** | `uv run --no-project --with aioquic python tests/interop/aioquic_client.py 8080` — GET /ping (200 "pong") + POST /echo (byte-exact) over QUIC; expect "INTEROP OK". aioquic is the independent pure-Python HTTP/3 stack `uv` fetches — the HTTP/3 analogue of aiortc. |
| HTTP/3 (curl, optional) | a curl built with an HTTP/3 backend: `curl -k --http3-only https://localhost:8080/ping` |

> The bounded gtest versions of the headless legs live in
> `tests/aiortc_interop_test.cpp` (WEBRTC=ON) and `tests/http3_interop_test.cpp`
> (HTTP3=ON). They run each child through `tests/interop/bounded_proc.h` — a hard
> wall-clock cap + whole-process-tree kill (Windows Job Object / POSIX process
> group) — so they can NEVER hang the suite and skip cleanly when `uv`/`curl` is
> absent. The in-process `tests/media_echo_test.cpp` (media) and
> `tests/http3_app_test.cpp` (HTTP/3 loopback) are the primary "it works"
> signals; the external-stack interop legs are bounded secondaries.
>
> CI H3 leg: a `BOLTAPI_WITH_HTTP3=ON` build runs the QUIC unit + loopback
> (`http3_app_test`) + bounded interop (`http3_interop_test`, skip-if-absent)
> tests. Default `ctest` (HTTP3=OFF) is unaffected (the interop test is an
> instant `GTEST_SKIP`).

All Python uses **uv** (`uv run --with <pkg>`), never bare pip/python.

## Why this exists
In-process gtests prove our stack against itself; this harness proves it against
**independent** clients (a real browser's WebRTC, aiortc's SCTP/DTLS/ICE) — the
true interop gate. Each protocol gets a tiny client here as it lands.
