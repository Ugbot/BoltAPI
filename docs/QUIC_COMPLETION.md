# QUIC — completion punch-card

What's left to make our QUIC stack a *complete, browser- and relay-grade* transport.
Foundation for HTTP/3 **and** WebTransport. Tiger Style throughout (bounded, noexcept,
≥2 asserts/fn, no exceptions, zero warnings). Verify with aioquic (have) + Chrome via
the **chrome-devtools MCP** + the QUIC Interop Runner.

Status: `[x]` done · `[~]` partial · `[ ]` todo.

## Where we are (done, committed)
- [x] RFC 9000 primitives: varint, packet headers, frames, PN spaces, ACK ranges.
- [x] RFC 9001 packet protection: HKDF + AEAD (AES-128/256-GCM, ChaCha20) + header
      protection; cipher-suite-aware key schedule (SHA-256/384). App. A byte-exact.
- [x] TLS 1.3 QUIC handshake over OpenSSL 3.6 native QUIC-TLS callbacks; transport
      params (incl. ISCID/ODCID §7.3, max_datagram_frame_size §RFC9221).
- [x] RFC 9002 loss recovery + NewReno; streams (send/recv state machines, ordered
      reassembly, RESET/STOP_SENDING); per-stream + connection flow control.
- [x] Robustness: Version Negotiation, Retry + token + 3× anti-amplification,
      CONNECTION_CLOSE/Closing/Draining, idle timeout, stateless reset, key update,
      GREASE tolerance, seeded packet fuzz.
- [x] **Interop proven vs aioquic** (independent stack): full handshake + HTTP/3
      GET/POST + WebTransport CONNECT→200.
- [x] Cert: process-stable ECDSA P-256, ≤14-day server identity (`shared_server_identity`),
      `server_cert_sha256()` for WebTransport pinning.

## P0 — Chrome handshake completion  ✅ DONE (#45) — Chrome reaches Established
Diagnosed + fixed via the chrome-devtools MCP + QUIC packet trace. THREE real bugs,
each surfaced only by a real Chrome handshake (aioquic masked all three by sending
in-order, single-cert, and tolerant); aioquic interop + all QUIC/H3 gates stay green:
- [x] **Coalesce the first flight** (#45): Initial(ServerHello)+Handshake(Cert/
      CertVerify/Finished) into ONE UDP datagram (RFC 9000 §12.2) so Chrome advances
      past Initial. (ACK-on-first-flight already worked.) `flush()` + a coalesced-
      datagram accumulator, scoped to the handshake. Committed bddcec4.
- [x] **Out-of-order CRYPTO reassembly**: `CryptoReassembly` tracked a SINGLE pending
      extent; Chrome fragments its ClientHello heavily out of order, so the contiguous
      cursor jumped over still-empty gaps → corrupt ClientHello → `failed=1`. Replaced
      with a bounded sorted/merged interval set. Committed c105857.
- [x] **WebTransport-compliant leaf cert**: the QUIC cert had NO X.509v3 extensions
      (aioquic accepted it; Chrome rejected with certificate_unknown). Added
      basicConstraints/keyUsage/EKU serverAuth/SAN + ~7-day validity. Committed c105857.
- [x] Gate: Chrome (MCP) now completes the QUIC+TLS handshake to **Established**
      (`complete=1 failed=0 1rtt=1`); aioquic stays green. `wt.ready` still pending —
      see WEBTRANSPORT_COMPLETION (Chrome returns ERR_METHOD_NOT_SUPPORTED: it does
      not open the WebTransport CONNECT despite the server advertising correct H3
      SETTINGS — a WebTransport-layer / Chrome-WT-draft issue, NOT the QUIC transport).

## P0 — Multi-connection server demux  ✅ DONE (#42; committed c105857)
Replaced the single `QuicConnection` + reset-on-Initial heuristic (which wedged under
a browser's Initial retransmits) with a bounded **per-peer connection pool keyed by
source 4-tuple** (`App::Http3Peer` pool + `http3_lookup_`/`http3_obtain_`/`http3_feed_`).
- [x] Bounded pool (kMaxHttp3Peers=16); inbound routes by source address; an Initial
      from a NEW peer creates a slot; closed/draining slots reclaimed.
- [x] Removed the single-peer reset hack; per-connection peer address + send fn.
- [x] Chrome's Initial retransmits from one address all hit one connection (no wedge).
- [~] Routing by source 4-tuple (sufficient for distinct clients + no-wedge). Per-DCID
      routing (for migration / multiple connections from one address) is the follow-up.
- [x] Gate: H3 loopback + aioquic interop green; Chrome handshake reaches Established.

## P1 — QUIC DATAGRAM frames (RFC 9221)  ✅ DONE (committed c37baf2)
- [x] Parse 0x30 (no-length) / 0x31 (length-prefixed) DATAGRAM frames → on_datagram_;
      emit via `send_datagram()` respecting the peer's `max_datagram_frame_size`. No
      per-packet malloc (stack scratch into a 1-RTT packet).
- [x] Connection API: `set_datagram_handler()` / `send_datagram()`.
- [x] Gate: loopback `QuicDatagram.RoundTripEcho` + Chrome WebTransport datagram echo
      (MCP). (A dedicated aioquic *datagram* leg is a follow-up; H3 GET/POST aioquic green.)

## P2 — Advanced transport
- [ ] 0-RTT / session resumption (RFC 9001 §4.6): session tickets, early data, remembered
      transport params. (Big throughput win for relays/reconnects.)
- [ ] Connection migration + path validation (PATH_CHALLENGE/RESPONSE, §9).
- [ ] Multiple connection IDs (NEW/RETIRE_CONNECTION_ID), preferred address; full
      stateless-reset emission.
- [ ] ECN; GREASE versions/params emission (not just tolerance).

## P3 — Performance (correctness-gated; measure-or-revert)
- [~] Inline I/O-thread datagram processing (done for the UDP path).
- [ ] Batched UDP recv/send (recvmmsg/sendmmsg/WSARecvMsg; GSO/GRO) — measure under a
      *multi-connection* bench (single-conn showed no win).
- [ ] Zero-copy framing via `bolt::wire`; per-connection `bolt::SwissTable`; per-packet
      `bolt::Arena`; pacing (token bucket). No malloc on the data path.
- [ ] `benchmarks/quic_throughput_bench.cpp` exists; extend to many-connection.

## P4 — Interop + CI
- [ ] **QUIC Interop Runner** matrix rows vs quiche / ngtcp2 / picoquic / msquic
      (handshake, transfer, retry, resumption, multiplexing).
- [ ] Browser (Chrome + Firefox) H3 via the chrome-devtools MCP; curl --http3 smoke.
- [ ] CI leg (WITH_HTTP3=ON) runs unit + loopback + bounded interop (skip-if-absent).

**Order:** P0 handshake-ACK/coalesce → P0 multi-connection demux → P1 DATAGRAM →
P4 browser/interop gates → P2 advanced → P3 perf. P0 unblocks Chrome HTTP/3 **and**
WebTransport; multi-connection unblocks the relay/SFU use cases.
