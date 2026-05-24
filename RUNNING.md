# Running the Bolt API demo (Docker) — HTTP/1.1 + HTTP/2 + HTTP/3 + WebRTC

One container serves **all four protocols** plus the browser test pages.

## Build & run

```sh
docker build -t boltapi .

docker run --rm \
  -p 8080:8080/tcp \      # HTTP/1.1 (cleartext)
  -p 8443:8443/tcp \      # HTTP/1.1 + HTTP/2 over TLS
  -p 8443:8443/udp \      # HTTP/3 (QUIC)
  -p 9000:9000/udp \      # WebRTC media/data
  boltapi
```

| URL / port | Protocol |
|---|---|
| http://localhost:8080/ | HTTP/1.1 (cleartext) + serves the browser pages |
| https://localhost:8443/ | HTTP/1.1 + **HTTP/2** (TLS, ALPN) |
| https://localhost:8443/ (after Alt-Svc) | **HTTP/3** (QUIC, UDP 8443) |
| UDP 9000 | **WebRTC** ICE/DTLS/SRTP/SCTP |

## In a browser (locally)

The cert is **self-signed for `localhost`**, so TLS (H2/H3) needs the cert trusted
or Chrome started with a flag. `getUserMedia` (camera/mic) only needs a *secure
context*, and **`http://localhost` already counts as secure** — so WebRTC works on
the cleartext origin with no cert fuss.

- **HTTP/1.1 + WebRTC (easiest):** open <http://localhost:8080/>
  - `webrtc.html` — data-channel echo
  - `media.html` — camera/mic echo (audio + video looped back)
- **HTTP/2:** open <https://localhost:8443/> and accept the cert warning (or trust
  `certs/cert.pem`). DevTools → Network → *Protocol* column shows `h2`.
- **HTTP/3:** Chrome uses H3 after it sees the `alt-svc` header on an H2 response.
  For a self-signed cert, start a throwaway Chrome that trusts it:
  ```sh
  google-chrome --user-data-dir=/tmp/boltapi-demo \
    --ignore-certificate-errors \
    --origin-to-force-quic-on=localhost:8443 \
    https://localhost:8443/
  ```
  Reload once; the *Protocol* column shows `h3`.

> **WebRTC across Docker's NAT (important on Docker Desktop Win/Mac):** the WebRTC
> *stack* is verified working in the container (an aiortc peer in the same network
> namespace completes ICE+DTLS+SCTP and echoes a 64 KiB binary message). The host→
> container path goes through Docker Desktop's UDP proxy, which rewrites source
> addresses; **Chrome/Firefox handle this** (peer-reflexive ICE), but minimal stacks
> like aiortc-from-host may not. If WebRTC won't connect:
> - **Linux:** `docker run --network host boltapi` (direct, no NAT — most reliable).
> - **Windows/Mac:** use a real browser (Chrome/Firefox); its ICE copes with the
>   proxy. The server already advertises a `127.0.0.1` candidate reachable via
>   `-p 9000:9000/udp`.

## Verified (against this container image)

| Protocol | How verified | Result |
|---|---|---|
| HTTP/1.1 (cleartext) | `curl http://localhost:8080/ping` | ✅ `pong` |
| HTTP/1.1 over TLS | httpx (verify off) → `https://localhost:8443/ping` | ✅ `pong` |
| **HTTP/2** | httpx `http2=True` → `https://localhost:8443/api/info` | ✅ `HTTP/2` 200 |
| **HTTP/3 (QUIC)** | aioquic → `localhost:8443` GET/POST | ✅ byte-exact |
| **WebRTC** (data, incl. 64 KiB binary) | aiortc peer in the container netns | ✅ echo round-trip |

(HTTP/2 over TLS required fixing a real engine bug — app data was written to the
TLS socket in plaintext; now routed through `CoroTlsSocket`.)

## Headless verification (no browser needed)

These exercise the exact same stacks a browser would. From the host with the
container running:

```sh
# HTTP/1.1
curl http://localhost:8080/ping                      # -> pong
# HTTP/2 (and H1) over TLS  (-k: accept self-signed)
curl -k --http2 https://localhost:8443/ping          # -> pong
# HTTP/3 via an independent QUIC stack (aioquic, fetched by uv)
uv run --no-project --with aioquic \
  python tests/interop/aioquic_client.py 8443
# WebRTC data channel via an independent stack (aiortc)
uv run --no-project --with aiortc \
  python tests/interop/aiortc_datachannel.py 8080
# WebRTC audio+video echo
uv run --no-project --with aiortc \
  python tests/interop/aiortc_media.py 8080
```

(Python interop uses `uv` — never bare pip/python.)

## Configuration (env)

`BOLTAPI_WEB_ROOT`, `BOLTAPI_CERT`, `BOLTAPI_KEY`, `BOLTAPI_H1_PORT` (8080),
`BOLTAPI_TLS_PORT` (8443), `BOLTAPI_RTC_PORT` (9000). With no cert the server runs
cleartext H1 + WebRTC only (H2/H3 need TLS).
