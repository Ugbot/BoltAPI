# Bolt API — manual / interop test harness

Reusable real-client tests against a running server. Build once, point real
clients (browser, aiortc, curl) at it. Grows one small client per protocol.

## Run the demo server
Build with WebRTC on, then run the demo (serves this `web/` dir + echo handlers
+ the `/webrtc/offer` signaling route):

```
cmake -S . -B build/wrtc -G "Visual Studio 17 2022" -A x64 -DBOLTAPI_WITH_WEBRTC=ON
cmake --build build/wrtc --config Release --target boltapi_demo_server
build/wrtc/examples/Release/boltapi_demo_server.exe   # listens on :8080
```

## Tests (point at the running server)

| What | How |
|---|---|
| **WebRTC data channel (browser)** | open `http://localhost:8080/webrtc.html`, click **Connect & echo** — expect "ECHO ROUND-TRIP OK" |
| **WebRTC data channel (headless)** | `uv run --with aiortc python testing/aiortc_datachannel.py 8080` — expect "INTEROP OK" |
| HTTP/1.1 + verbs | `curl -v http://localhost:8080/...` (page TBD) |
| WebSocket / SSE | browser page TBD (same pattern) |

All Python uses **uv** (`uv run --with <pkg>`), never bare pip/python.

## Why this exists
In-process gtests prove our stack against itself; this harness proves it against
**independent** clients (a real browser's WebRTC, aiortc's SCTP/DTLS/ICE) — the
true interop gate. Each protocol gets a tiny client here as it lands.
