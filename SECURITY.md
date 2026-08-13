# Security Policy

## Reporting a vulnerability

Please report security issues **privately** — do not open a public issue for a
suspected vulnerability.

- Preferred: [GitHub private vulnerability reporting](https://github.com/Ugbot/BoltAPI/security/advisories/new)
- Alternative: email the maintainer at <bengamble7@gmail.com>

Please include enough detail to reproduce: the affected version or commit, the
build configuration (compiler, platform, and which `BOLTAPI_WITH_*` options were
on), and a proof of concept if you have one.

Bolt API is maintained on a best-effort basis. Expect an initial acknowledgement
within a few days; there is no formal response SLA. You will be credited in the
advisory unless you ask otherwise.

## Scope

Bolt API is a network-facing framework that parses untrusted input across several
protocols, so the following are in scope:

- Memory safety in any parser or codec — HTTP/1.1, HTTP/2 (frames, HPACK), HTTP/3
  (QUIC, QPACK), WebSocket framing, SDP, STUN/ICE, DTLS, SCTP, RTP/RTCP, SRTP.
- Cryptographic mistakes in packet protection, key derivation, or the TLS/DTLS
  handshake paths.
- Request smuggling, response splitting, or header-parsing confusion.
- Path traversal in the static-file helper.
- Denial of service through unbounded resource growth, missing backpressure, or
  algorithmic blowup on attacker-controlled input.

Out of scope:

- Vulnerabilities in OpenSSL or other system dependencies — report those upstream.
- Issues that require a build configuration the project explicitly does not
  support (for example, MinGW on Windows, or GCC on Linux).
- The demo server, browser test pages under `testing/web/`, and the self-signed
  development certificates. These are development aids and are not intended to be
  exposed to untrusted networks.

## Supported versions

The project has not yet cut a stable release. Fixes land on `main`; there are no
maintained release branches, so please verify against `main` before reporting.

## Hardening notes

- The framework is compiled without exceptions and without RTTI, and relies on
  assertions to fail fast on programmer error. **Assertions are a safety
  mechanism** — do not build production binaries with them compiled out unless
  you have accounted for that.
- Bounded, fixed-capacity structures are used deliberately throughout; parsers
  are written to *skip or reject* input past a cap rather than grow.
- TLS/DTLS and all crypto primitives come from OpenSSL 3.x. Keep it current.
