# Bolt API examples

Built when `BOLTAPI_BUILD_EXAMPLES=ON` (default for a top-level build). Binaries
land in `build/<preset>/` (e.g. `build/msvc/Release/`). Each takes an optional
`[port]` (default 8080).

| Binary | Source | Needs flag | What it shows |
|---|---|---|---|
| `boltapi_rest_api` | `rest_api.cpp` | — | **start here**: routing, path/query params, JSON body, middleware |
| `boltapi_hello` | `hello.cpp` | — | version + Bolt integration smoke |
| `boltapi_ws_echo` | `ws_echo.cpp` | — | WebSocket echo |
| `boltapi_sse_stream` | `sse_stream.cpp` | — | coroutine Server-Sent Events |
| `boltapi_http3_server` | `http3_server.cpp` | `BOLTAPI_WITH_HTTP3` to serve H3 | HTTP/1.1 + HTTP/3 on one app |
| `boltapi_webrtc_echo` | `webrtc_echo.cpp` | `BOLTAPI_WITH_WEBRTC` | WebRTC data-channel echo |
| `boltapi_demo_server` | `demo_server.cpp` | `BOLTAPI_WITH_WEBRTC` | the works: HTTP + WS + SSE + WebRTC data **and** audio/video echo |

## Run / test

```sh
# REST (start here)
./build/msvc/Release/boltapi_rest_api 8080
curl  http://127.0.0.1:8080/health
curl  http://127.0.0.1:8080/users/42
curl 'http://127.0.0.1:8080/search?q=bolt&limit=5'
curl -X POST http://127.0.0.1:8080/users -d '{"name":"ada","age":36}'
curl  http://127.0.0.1:8080/secret -H 'authorization: Bearer t0ken'

# WebSocket / SSE
./build/msvc/Release/boltapi_ws_echo 8080        # connect ws://127.0.0.1:8080/ws
./build/msvc/Release/boltapi_sse_stream 8080     # curl -N http://127.0.0.1:8080/events

# HTTP/3 (build with -DBOLTAPI_WITH_HTTP3=ON)
./build/msvc/Release/boltapi_http3_server 8080
uv run --no-project --with aioquic python tests/interop/aioquic_client.py 8080

# WebRTC (build with -DBOLTAPI_WITH_WEBRTC=ON), run from repo root for static files
./build/msvc/Release/boltapi_demo_server 8080
#   browser:  http://127.0.0.1:8080/webrtc.html   (data)   /media.html (audio+video)
#   headless: uv run --with aiortc python tests/interop/aiortc_datachannel.py 8080
```

Python interop uses `uv` (`uv run --with ...`) — never bare pip/python.
