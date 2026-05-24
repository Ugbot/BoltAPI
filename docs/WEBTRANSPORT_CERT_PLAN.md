# WebTransport in-browser via `serverCertificateHashes` — punch-card

Goal: make `new WebTransport(url, {serverCertificateHashes:[…]})` open in a normal
Chrome (no flags) against our self-signed server → the test page's **WebTransport
pill goes green**.

Diagnosis (proven via chrome-devtools MCP + QUIC trace): our QUIC/TLS handshake
already interoperates with Chrome (`failed=0`, full ServerHello+Cert+Finished sent),
but Chrome **rejects the self-signed cert** and CONNECTION_CLOSEs (→ Draining).
`--ignore-certificate-errors` does NOT enable WebTransport for self-signed certs.
`serverCertificateHashes` is the supported path.

## Chrome's `serverCertificateHashes` requirements (must ALL hold)
- [x] R1. Cert key type **ECDSA P-256** (secp256r1). *(generate_self_signed_p256 already is.)*
- [x] R2. Signature **ecdsa-with-SHA256**. *(already X509_sign(…, EVP_sha256()).)*
- [x] R3. Validity duration **≤ 14 days** (Chrome enforces; spec ≤2 weeks), and "now"
      within [notBefore, notAfter]. *(currently 365 days → MUST change.)*
- [x] R4. The server presents the **same cert on every connection** so the page can
      pin its hash. *(currently ephemeral per connection → MUST make stable.)*
- [x] R5. The page passes **SHA-256 of the cert DER** (32 bytes) as the hash value.

## Phase A — stable, WT-compatible QUIC server cert (`include/boltapi/quic/tls.h`)
- [x] A1. `generate_self_signed_p256`: set notBefore = now − 1h (skew), notAfter =
      now + 13 days (≤14, R3). Keep P-256 + SHA-256 (R1/R2).
- [x] A2. Make the server cert **process-stable**: generate the X509+key ONCE
      (function-local static, lazily), reused by every `init_server()` (R4). All
      QuicConnections in the process then present the identical cert.
- [x] A3. Expose `bool server_cert_sha256(std::uint8_t out[32])` (or similar): SHA-256
      of `i2d_X509(DER)` of the static cert. Bounded, noexcept, ≥2 asserts. Generates
      the static cert on demand so the hash is available before any connection.

## Phase B — expose the hash (`examples/docker_demo.cpp`, gated `BOLTAPI_WITH_HTTP3`)
- [x] B1. Add `GET /wt/cert-hash` → returns the QUIC cert SHA-256 as lowercase hex
      (and note: only meaningful under WITH_HTTP3; return empty/501 otherwise).
- [x] B2. Keep it cheap + CORS-safe (same origin; the page fetches it).

## Phase C — page uses it (`testing/web/index.html`)
- [x] C1. `wtConnect()`: `fetch('/wt/cert-hash')` → hex → `Uint8Array(32)`.
- [x] C2. `new WebTransport('https://'+location.hostname+':8443/wt',
      { serverCertificateHashes:[{algorithm:'sha-256', value: bytes}] })`.
- [x] C3. `await wt.ready` → pill green; clear error text on failure (hash mismatch,
      cert expired, etc.).

## Phase D — build, verify (chrome-devtools MCP), commit
- [x] D1. `docker build -t boltapi .` builds (cert-pin code compiles WITH_HTTP3).
- [~] D2. MCP real-Chrome: the pin is ACCEPTED — Chrome no longer immediately
      rejects the cert (pre-pin: `Draining`/CERTIFICATE_UNKNOWN; post-pin: no cert
      reject). BUT the QUIC handshake still does not COMPLETE: the server sends its
      full flight (ServerHello lvl0 + Cert/Finished lvl2) yet Chrome keeps
      re-sending Initials and times out (QUIC_HANDSHAKE_TIMEOUT). So the cert is no
      longer the blocker; a **Chrome QUIC handshake-completion** bug remains (#45).
      Pill NOT yet green.
- [x] D3. Real Chrome: H1/WS/SSE confirmed green via the MCP (unaffected).
- [x] D4. Headless regression on a FRESH container: aioquic H3 OK + WebTransport
      CONNECT->200 OK (cert change did not regress the proven path).
- [ ] D5. Commit + push (serverCertificateHashes done; handshake-completion open).

## REMAINING (the actual blocker, #45)
Chrome's QUIC handshake doesn't complete: server sends ServerHello+Handshake flight,
Chrome stays at the Initial level and times out. A stuck Chrome handshake also wedges
the single-peer endpoint (the reset only fires for connections PAST handshake, not
ones stuck in Handshaking). Next: trace why Chrome doesn't advance after the server's
flight (coalescing? anti-amplification? Handshake-key/packet-number? cert message
size?), and make the single-peer reset also recover stale Handshaking connections so
one bad attempt doesn't wedge the server.
- [ ] D6. Update RUNNING.md (WebTransport in-browser works, no flags) + tick #45.

## Notes / non-goals
- The QUIC cert (generate_self_signed_p256) is SEPARATE from the TCP H1/H2 TLS cert
  (Dockerfile `cert.pem`, 365 d). Only the QUIC cert changes here; H1/H2 unaffected.
- The 13-day cert is a **demo** cert; it expires — fine for a local demo, regenerate
  by rebuilding. Production should use a publicly-trusted cert.
- Datagram/stream payloads after `ready` remain a follow-up; this closes the
  *handshake/ready* gap that the pill measures.
- Puppeteer-image Chrome's `bad extension` (older build) is a separate TLS-extension
  interop nuance under #45; the user's Chrome does not hit it.
