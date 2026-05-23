# Bolt API tests. M0 uses a dependency-free smoke test (no gtest yet — gtest is
# wired in at M1 alongside the first real units, mirroring Bolt's BoltGTest.cmake).

add_executable(boltapi_smoke_test smoke_test.cpp)
target_link_libraries(boltapi_smoke_test PRIVATE boltapi::boltapi)
boltapi_apply_hardening(boltapi_smoke_test)
boltapi_apply_sanitizers(boltapi_smoke_test)
add_test(NAME boltapi_smoke COMMAND boltapi_smoke_test)

# Bolt-native router unit test (plain main(), no gtest).
add_executable(boltapi_router_test router_test.cpp)
target_link_libraries(boltapi_router_test PRIVATE boltapi::boltapi)
boltapi_apply_hardening(boltapi_router_test)
boltapi_apply_sanitizers(boltapi_router_test)
add_test(NAME boltapi_router COMMAND boltapi_router_test)

# gtest-based units (http_fuzz generator). Uses boltapi_add_test() from BoltApiGTest.
boltapi_add_test(boltapi_util_fuzz_test util_fuzz_test.cpp)

# Router fan-out regression: >16 distinct sibling literal/param routes (would
# have OOB'd the old fixed [16] per-node child array).
boltapi_add_test(boltapi_router_fanout_test router_fanout_test.cpp)

# M1: App facade integration test — spins a real App on an ephemeral cleartext
# HTTP/1.1 port and drives it with a raw client socket + http_fuzz inputs.
boltapi_add_test(boltapi_app_integration_test app_integration_test.cpp)
if(WIN32)
    target_link_libraries(boltapi_app_integration_test PRIVATE ws2_32 mswsock)
endif()

# M1: middleware onion — chain order, short-circuit (401), sync+async mix.
boltapi_add_test(boltapi_middleware_test middleware_test.cpp)
if(WIN32)
    target_link_libraries(boltapi_middleware_test PRIVATE ws2_32 mswsock)
endif()

# M4 hardening: zero heap allocation across Router::match() and the http1
# parser hot paths (global operator new/delete counter).
boltapi_add_test(boltapi_no_alloc_test no_alloc_test.cpp)

# M4 hardening: bounded resources — App rejects oversized body (413) /
# headers (431), stays responsive after rejects, and Router handles
# over-deep / over-param paths gracefully (no UB).
boltapi_add_test(boltapi_bounded_resource_test bounded_resource_test.cpp)
if(WIN32)
    target_link_libraries(boltapi_bounded_resource_test PRIVATE ws2_32 mswsock)
endif()

# M2: WebSocket echo end-to-end through App — RFC6455 handshake (101 +
# Sec-WebSocket-Accept), masked client text frames echoed back unmasked,
# multiple messages on one connection, and a close frame.
boltapi_add_test(boltapi_ws_echo_test ws_echo_test.cpp)
if(WIN32)
    target_link_libraries(boltapi_ws_echo_test PRIVATE ws2_32 mswsock)
endif()

# M2: coroutine SSE end-to-end through App — text/event-stream content type and
# ordered data:/event: frames parsed off the wire, bounded with a read timeout.
boltapi_add_test(boltapi_sse_test sse_test.cpp)
if(WIN32)
    target_link_libraries(boltapi_sse_test PRIVATE ws2_32 mswsock)
endif()

# M2: response compression — gzip middleware. Passes in BOTH modes: with zlib
# (asserts Content-Encoding: gzip + roundtrip) and without (asserts identity).
boltapi_add_test(boltapi_compression_test compression_test.cpp)
if(WIN32)
    target_link_libraries(boltapi_compression_test PRIVATE ws2_32 mswsock)
endif()

# JSON facility — fionn (bolt::parse) wrapper. UNIT: parse objects/arrays/
# scalars/nested, member+element iteration, missing keys, type mismatches,
# malformed input -> error (no throw). INTEGRATION: a real App route reads
# req.json(), pulls typed/nested fields, replies — driven by a raw client
# socket with randomized JSON bodies. See docs/JSON.md.
boltapi_add_test(boltapi_json_test json_test.cpp)
if(WIN32)
    target_link_libraries(boltapi_json_test PRIVATE ws2_32 mswsock)
endif()

# WebRTC SDP codec — UNIT: parse a real Chrome data-channel offer (assert
# ufrag/pwd/fingerprint/setup/mid/sctp-port), generate + round-trip an answer,
# malformed input -> error (no throw/crash). Pure codec, no engine deps.
boltapi_add_test(boltapi_sdp_test sdp_test.cpp)

# WebRTC STUN codec — UNIT: RFC 5769 test vectors (sample request, IPv4
# response, long-term credential) asserting byte-exact encode + correct decode
# incl. MESSAGE-INTEGRITY (HMAC-SHA1) and FINGERPRINT (CRC-32). Correctness gate.
boltapi_add_test(boltapi_stun_test stun_test.cpp)

# WebRTC UDP transport — bind on an ephemeral port, round-trip a datagram from a
# raw client socket asserting the source address, verify RFC 7983 demux
# (STUN/DTLS/drop) + counters, clean start/stop with no hang. Pure transport, no
# engine deps. Links ws2_32/mswsock/iphlpapi on Windows.
boltapi_add_test(boltapi_udp_transport_test udp_transport_test.cpp)
if(WIN32)
    target_link_libraries(boltapi_udp_transport_test PRIVATE ws2_32 mswsock iphlpapi)
endif()

# WebRTC ICE-lite agent — THE LIVE STUN GATE. Real STUN Binding Request built
# with our codec (USERNAME/PRIORITY/ICE-CONTROLLING/USE-CANDIDATE/MESSAGE-
# INTEGRITY/FINGERPRINT) sent over the wire to a UdpTransport+IceAgent; asserts a
# Binding Success with XOR-MAPPED-ADDRESS == client addr + valid MI + FINGERPRINT
# + nominated selected pair. Negative: wrong integrity rejected, malformed input
# survives. Plus host-candidate gathering + candidate round-trip.
boltapi_add_test(boltapi_ice_test ice_test.cpp)
if(WIN32)
    target_link_libraries(boltapi_ice_test PRIVATE ws2_32 mswsock iphlpapi)
endif()

# WebRTC DTLS handshake — THE LIVE DTLS GATE. Stands up our UdpTransport +
# DtlsContext + DtlsSessionManager (the server / answerer, setup:passive) on an
# ephemeral loopback UDP port, then runs a REAL OpenSSL DTLS CLIENT (connected
# UDP socket + BIO_new_dgram + DTLS_client_method, SSL_connect) against it. The
# server feeds inbound datagrams to its DtlsSession and sends records back via
# the transport. Asserts: BOTH sides reach handshake-complete; the server-side
# session is Established; fingerprint verification PASSES (client cert SHA-256
# fed in as the "offer fingerprint"); a fingerprint MISMATCH is REJECTED; and a
# DTLS app-data round-trip (client SSL_write -> server read_app echoes ->
# client SSL_read) works. Bounded by a wall-clock deadline so it can't hang.
# Links OpenSSL + ws2_32/mswsock (Windows) for the live socket + crypto.
boltapi_add_test(boltapi_dtls_test dtls_test.cpp)
target_link_libraries(boltapi_dtls_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)
if(WIN32)
    target_link_libraries(boltapi_dtls_test PRIVATE ws2_32 mswsock iphlpapi)
endif()

# WebRTC DATA CHANNELS — THE DATA-CHANNEL GATE. (1) CRC-32c (RFC 3309) known
# vectors; (2) the SCTP 4-way association handshake + reliable/ordered DATA+SACK
# round-trip between two in-process SctpAssociation endpoints; (3) END-TO-END
# LOOPBACK: our full server stack (UdpTransport + DTLS server + DtlsSessionManager
# + WebRtcPeerHub with an App-shaped on_data_channel echo handler) against a
# CLIENT using our own SCTP active side over a real OpenSSL DTLS client —
# DATA_CHANNEL_OPEN -> handler fires with the right label -> string message
# echoed -> client receives the echo. Bounded by a deadline so it can't hang.
# Links OpenSSL + ws2_32/mswsock (Windows) for the live socket + crypto.
boltapi_add_test(boltapi_datachannel_test datachannel_test.cpp)
target_link_libraries(boltapi_datachannel_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)
if(WIN32)
    target_link_libraries(boltapi_datachannel_test PRIVATE ws2_32 mswsock iphlpapi)
endif()

# SCTP ROBUSTNESS GATE — hardened SCTP for real browser data channels, driven
# between two cross-wired in-process SctpAssociation endpoints (deterministic,
# no network): (1) 64 KiB + 256 KiB message fragmentation/reassembly both
# directions, ordered + unordered, byte-exact; (2) unordered delivery is not
# head-of-line blocked; (3) partial reliability abandons a message via
# FORWARD-TSN under simulated loss while later messages still arrive; (4) a
# lossy link (seeded deterministic packet drops) still completes a large
# reliable transfer via RTO retransmit, with cwnd growth + back-off observed.
# All bounded by an iteration cap (no hang); deterministic via fixed seeds.
boltapi_add_test(boltapi_sctp_robust_test sctp_robust_test.cpp)
if(WIN32)
    target_link_libraries(boltapi_sctp_robust_test PRIVATE ws2_32)
endif()

# M3: HTTP/3 + WebRTC seam — ProtocolRegistry mechanism (register/has/create),
# a dummy IProtocol returning NotImplemented, and (when the compile flags are
# ON) the real H3/WebRTC stub factories registering. Flag-AWARE: passes in the
# default flags-OFF build via a dummy protocol; does NOT require the flags on.
boltapi_add_test(boltapi_protocol_seam_test protocol_seam_test.cpp)
