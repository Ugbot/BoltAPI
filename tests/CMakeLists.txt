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

# WebRTC SIGNALING (offer->answer) — UNIT: parse a REAL captured aiortc 1.x
# data-channel OFFER SDP (srflx + multi-algo fingerprints + creds-after-
# candidates), extract peer ufrag/pwd + sha-256 fingerprint, and build OUR
# ANSWER asserting it is well-formed (ufrag/pwd, fingerprint:sha-256,
# setup:passive, ice-lite, >=1 candidate, application m-line) and round-trips.
# Pure codec, no engine deps, no python — keeps the default suite green.
boltapi_add_test(boltapi_signaling_test signaling_test.cpp)

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

# WI: WebRTC FULL ICE (RFC 8445) — THE FULL-ICE GATE (default suite, no external
# servers, deadline-bounded). Two of OUR OWN FullIceAgents (controlling +
# controlled) on two net::UdpTransports over ephemeral loopback UDP ports run
# connectivity checks in BOTH directions and converge on a NOMINATED valid pair;
# a redundant candidate is deduped + a dead candidate Fails without deadlocking;
# trickle delivers a candidate AFTER checks start; the role-conflict path (two
# controlling agents) resolves via the tie-breaker and still converges; ICE
# restart clears the checklist + regenerates credentials. Bounded by wall-clock
# deadlines + iteration caps (no hang). Links ws2_32/mswsock/iphlpapi on Windows.
boltapi_add_test(boltapi_ice_full_test ice_full_test.cpp)
if(WIN32)
    target_link_libraries(boltapi_ice_full_test PRIVATE ws2_32 mswsock iphlpapi)
endif()

# WI: WebRTC TURN (RFC 5766/8656) — THE TURN GATE (default suite, no external
# servers, deadline-bounded). Our OWN TurnClient against our OWN minimal
# in-process TurnServer over loopback UDP (control + relay sockets): Allocate
# (long-term cred: 401 -> authed retry -> XOR-RELAYED-ADDRESS relay candidate),
# CreatePermission, ChannelBind, then a datagram relayed THROUGH the server to a
# real peer socket and a reply forwarded back as ChannelData (both directions),
# then Refresh(0) releases the allocation. Plus a unit (MD5 long-term key +
# ChannelData classifier) and the ChannelData fast path. Links OpenSSL (HMAC/MD5)
# + ws2_32/mswsock/iphlpapi on Windows.
boltapi_add_test(boltapi_turn_test turn_test.cpp)
target_link_libraries(boltapi_turn_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)
if(WIN32)
    target_link_libraries(boltapi_turn_test PRIVATE ws2_32 mswsock iphlpapi)
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

# WebRTC AIORTC INTEROP — THE REAL INTEROP GATE (vs an independent WebRTC stack).
# Under WEBRTC=ON: starts the full App (signaling route + UDP ICE/DTLS/SCTP +
# on_data_channel("chat") echo) on a free port, then shells out to
# `uv run --with aiortc python tests/interop/aiortc_datachannel.py <port>` — a
# real aiortc RTCPeerConnection that offers a data channel, POSTs the offer,
# applies the answer, and asserts a text + 64 KiB binary echo round-trip. SKIPs
# (does not fail) when uv/aiortc can't bootstrap. Under WEBRTC=OFF it compiles to
# a single GTEST_SKIP so the default suite stays green. BOLTAPI_SOURCE_DIR lets
# the test locate the python script from the build dir.
boltapi_add_test(boltapi_aiortc_interop_test aiortc_interop_test.cpp)
target_compile_definitions(boltapi_aiortc_interop_test PRIVATE
    BOLTAPI_SOURCE_DIR="${CMAKE_SOURCE_DIR}")
if(WIN32)
    target_link_libraries(boltapi_aiortc_interop_test PRIVATE ws2_32 mswsock iphlpapi)
endif()

# HTTP/3 (QUIC) PURE PRIMITIVES — dependency-free wire codecs ported from
# FasterAPI (boltapi/quic/{varint,packet,frames,pn_space,ack}.h). RFC-vector
# units: RFC 9000 §A.1 varint samples + boundary/random round-trip; RFC 9001
# §A.1 client Initial public header parse + short/Retry/VN discrimination; ACK
# multi-range + ECN round-trip, STREAM/CRYPTO framing offsets, CONNECTION_CLOSE
# (transport+app), PADDING run; RFC 9000 §A.2/A.3 truncated PN encode/decode;
# AckRangeTracker received-PN -> ranges -> AckFrame (incl. randomized cross-check).
# No network, no crypto, no OpenSSL — compiles into the default suite.
boltapi_add_test(boltapi_quic_primitives_test quic_primitives_test.cpp)

# Wave 2: QUIC packet protection (RFC 9001 §5) — AEAD seal/open (AES-128/256-GCM,
# ChaCha20-Poly1305), header protection, HKDF-Expand-Label, Initial-secret
# derivation. GATE: RFC 9001 Appendix A worked examples (§A.1 keys, §A.2 client
# Initial, §A.3 server Initial, §A.5 ChaCha20) verified BYTE-EXACT, plus negative
# auth-fail tests and randomized AEAD round-trips. OpenSSL is always linked into
# boltapi, so this runs in the default suite. No TLS handshake (that is wave 3).
boltapi_add_test(boltapi_quic_protection_test quic_protection_test.cpp)
target_link_libraries(boltapi_quic_protection_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)

# Wave 3: TLS 1.3 QUIC handshake driver (boltapi/quic/tls.h) over OpenSSL 3.6's
# native QUIC-TLS callback API (SSL_set_quic_tls_cbs + OSSL_DISPATCH) + the QUIC
# transport-parameters codec (boltapi/quic/transport_params.h, RFC 9000 §18).
# GATE: an in-process client<->server handshake (no UDP) shuttling CRYPTO bytes
# per encryption level until both complete, then proving client/server secrets
# MATCH at Handshake + 1-RTT, transport params round-trip across the wire, and a
# PacketProtection derived from those secrets cross-seals/opens a packet (ties
# wave 2 + wave 3). OpenSSL is always linked, so this runs in the default suite.
boltapi_add_test(boltapi_quic_tls_test quic_tls_test.cpp)
target_link_libraries(boltapi_quic_tls_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)

# Wave 4: QUIC CONNECTION — THE LIVE HANDSHAKE GATE. Two QuicConnections (client
# + server, boltapi/quic/connection.h) on two net::UdpTransports over ephemeral
# loopback UDP ports run a REAL TLS 1.3 QUIC handshake end-to-end (Initial ->
# Handshake -> 1-RTT). Each transport's datagram handler feeds the owning
# connection; each connection's send fn pushes built datagrams to the peer.
# Asserts: BOTH reach Established; 1-RTT keys installed both sides; ALPN h3;
# transport params exchanged; a 1-RTT packet sealed by one opens on the other
# (PING+ACK round-trip over real UDP). Bounded by a wall-clock deadline (no
# hang). OpenSSL + ws2_32/mswsock on Windows. Runs in the default suite.
boltapi_add_test(boltapi_quic_connection_test quic_connection_test.cpp)
target_link_libraries(boltapi_quic_connection_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)
if(WIN32)
    target_link_libraries(boltapi_quic_connection_test PRIVATE ws2_32 mswsock iphlpapi)
endif()

# Wave 5a: QUIC TRANSPORT — RFC 9002 loss recovery + NewReno congestion control
# + QUIC streams + flow control (boltapi/quic/{loss,stream}.h wired into
# connection.h). UNIT: stream-id encoding (RFC 9000 §2.1), RTT/PTO math (RFC 9002
# §5.3/§6.2.1), NewReno transitions (§7), ordered reassembly. GATE (loopback UDP
# after a real handshake): (1) client opens a bidi stream, sends a multi-KB
# message spanning many STREAM frames/packets, server receives it byte-exact +
# in order and echoes it back with FIN, client receives the echo + FIN; (2) a
# ~15% seeded datagram-drop variant STILL completes via loss recovery/retransmit
# with cwnd growth then back-off; (3) a flow-controlled variant forcing window
# updates completes with no deadlock. Bounded by wall-clock deadlines (no hang).
# OpenSSL + ws2_32/mswsock on Windows. Runs in the default suite.
boltapi_add_test(boltapi_quic_stream_test quic_stream_test.cpp)
target_link_libraries(boltapi_quic_stream_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)
if(WIN32)
    target_link_libraries(boltapi_quic_stream_test PRIVATE ws2_32 mswsock iphlpapi)
endif()

# Wave 5d: QUIC/HTTP3 PROTOCOL ROBUSTNESS — RFC 9000 §8/§10/§17 + RFC 9001
# §5.8/§6 (boltapi/quic/robustness.h + connection.h wiring). UNIT: Version
# Negotiation packet build/parse, Retry integrity tag + address-validation token
# mint/verify (forged token rejected), anti-amplification 3x budget, stateless
# reset token derive + recognize. GATE (loopback UDP): (1) client offers a BOGUS
# version -> our server emits a VN -> client retries with v1 -> Established;
# (2) server REQUIRES Retry -> client's first Initial gets a Retry -> retries
# with the token -> Established; (3) one side sends CONNECTION_CLOSE -> peer
# Draining; a short max_idle_timeout fires -> closes (no hang); (4) a key update
# flips the key-phase -> a fresh 1-RTT PING round-trips under new keys + both
# generations advance; (5) GREASE: unknown transport param + unknown frame type
# ignored; (6) FUZZ: thousands of seeded random/truncated/malformed packets fed
# to the parser + a live connection never crash, never reach Established on
# noise, stay bounded. Wall-clock deadlines (no hang); seeded RNG. OpenSSL +
# ws2_32/mswsock/iphlpapi on Windows. Runs in the DEFAULT suite.
boltapi_add_test(boltapi_quic_robustness_test quic_robustness_test.cpp)
target_link_libraries(boltapi_quic_robustness_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)
if(WIN32)
    target_link_libraries(boltapi_quic_robustness_test PRIVATE ws2_32 mswsock iphlpapi)
endif()

# QPACK (HTTP/3 RFC 9204) — static table + RFC 7541 Huffman, encoder/decoder,
# bounded dynamic table. RFC 7541 C.4.1 Huffman vector byte-exact + round-trips.
boltapi_add_test(boltapi_qpack_test qpack_test.cpp)

# Wave 5b: HTTP/3 FRAME LAYER + APP BRIDGE — THE "SERVES REQUESTS" GATE. UNIT:
# RFC 9114 §7.1 frame header round-trip + truncation (NeedMore) + SETTINGS
# (RFC 9114 §7.2.4 / RFC 9204 §5) encode/parse. GATE (loopback our-client <->
# our-server over QUIC after a real handshake): an H3Connection (frame.h +
# h3_connection.h) bridges decoded bidi-stream requests through a REAL App's
# shared dispatch path (router + middleware + handler) and sends the response
# back as HEADERS(:status)+DATA+FIN. Exercises >1 route + >1 verb + randomized
# input: GET /ping->200 "pong", POST /echo <8KB random>-> byte-exact echo, and a
# 404 for an unrouted path. Bounded by wall-clock deadlines (no hang). frame.h /
# h3_connection.h compile unconditionally + App::dispatch_http3 is unconditional,
# so this runs in the DEFAULT suite (no BOLTAPI_WITH_HTTP3 flag). OpenSSL +
# ws2_32/mswsock/iphlpapi on Windows.
boltapi_add_test(boltapi_http3_app_test http3_app_test.cpp)
target_link_libraries(boltapi_http3_app_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)
if(WIN32)
    target_link_libraries(boltapi_http3_app_test PRIVATE ws2_32 mswsock iphlpapi)
endif()

# WebRTC RTP/RTCP codec (RFC 3550/8285 + SR/RR/SDES/BYE/NACK/PLI/FIR/REMB/TWCC).
boltapi_add_test(boltapi_rtp_test rtp_test.cpp)

# WebRTC SRTP/SRTCP (RFC 3711) — KDF (Appendix B.3 vectors byte-exact), AES-CM-
# HMAC-SHA1-80 + AEAD-AES-128-GCM protect/unprotect, ROC + replay window.
boltapi_add_test(boltapi_srtp_test srtp_test.cpp)
target_link_libraries(boltapi_srtp_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)

# WM1: DTLS-SRTP KEYING — THE LIVE KEYING GATE (RFC 5764). Stands up our
# UdpTransport + DtlsContext (server, use_srtp) + DtlsSessionManager on an
# ephemeral loopback UDP port, then runs a REAL OpenSSL DTLS CLIENT (also
# use_srtp) against it. Asserts BOTH reach handshake-complete; the negotiated
# SRTP profile MATCHES on both sides; BOTH export keying material and build
# inbound/outbound SrtpSessions; then the client SRTP-protects an RTP packet
# (built via rtp.h) which the server unprotects byte-exact (and the reverse),
# proving the role-mapped keys agree end-to-end. Bounded by a wall-clock
# deadline so it can't hang. Links OpenSSL + ws2_32/mswsock/iphlpapi (Windows).
boltapi_add_test(boltapi_dtls_srtp_test dtls_srtp_test.cpp)
target_link_libraries(boltapi_dtls_srtp_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)
if(WIN32)
    target_link_libraries(boltapi_dtls_srtp_test PRIVATE ws2_32 mswsock iphlpapi)
endif()

# WM4: MEDIA SDP NEGOTIATION — parse a REAL Chrome audio+video offer (m=audio
# Opus + m=video VP8/H264, BUNDLE, rtcp-mux, extmap, ssrc, ice-ufrag/pwd,
# fingerprint:sha-256); assert mids/codecs/fingerprint/ice for BOTH m-lines;
# intersect against Bolt's supported codecs (audio Opus/PCMU/PCMA, video
# VP8/VP9/H264) keeping only common PTs; build an answer (BUNDLE, rtcp-mux,
# setup:passive, ice-lite, negotiated PTs only) that round-trips through our own
# parser. Malformed input -> error (no throw/crash). Pure codec, no engine deps.
boltapi_add_test(boltapi_media_sdp_test media_sdp_test.cpp)

# WM5: MEDIA TRACK + INTERCEPTOR PIPELINE GATE — in-process, deterministic,
# deadline-bounded (runs in the DEFAULT suite, no BOLTAPI_WITH_WEBRTC flag).
# (1) Two srtp::SrtpSessions on a known key model one DTLS-SRTP direction; an
# audio MediaTrack + a video MediaTrack (distinct SSRCs) in a TrackRegistry; an
# outbound RTP packet runs the interceptor chain then SRTP-protect, and the
# protected bytes feed the inbound side (SRTP-unprotect -> RFC5761 demux ->
# correct track -> on_track-style handler fires with the right SSRC/PT/payload,
# byte-exact) over 64 randomized (seeded) rounds across both tracks. (2) A
# deliberate inbound sequence GAP makes the NackGenerator emit a Generic NACK,
# re-parsed via rtcp.h to assert the missing seqs. (3) The ReportInterceptor
# tick()/build_now produces a parseable SR/RR compound. Links OpenSSL (SRTP
# crypto); ws2_32/mswsock/iphlpapi on Windows for parity with the WebRTC TUs.
boltapi_add_test(boltapi_media_track_test media_track_test.cpp)
target_link_libraries(boltapi_media_track_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)
if(WIN32)
    target_link_libraries(boltapi_media_track_test PRIVATE ws2_32 mswsock iphlpapi)
endif()

# WM6: MEDIA ECHO — THE "AUDIO+VIDEO WORKS" PRIMARY GATE (default suite, NO
# external deps, deadline-bounded). Our OWN stack on BOTH ends drives the REAL
# server media-echo path end to end: a SERVER side (UdpTransport + DTLS server
# + WebRtcPeerHub with an on_track ECHO handler — exactly App::enable_media_echo)
# and a CLIENT side that is a REAL OpenSSL DTLS-SRTP peer (the same client as the
# live keying gate). After a genuine DTLS-SRTP handshake the client SRTP-protects
# audio + video RTP and sends it over real loopback UDP; the server hub
# unprotects -> RFC5761 demux -> per-SSRC MediaTrack -> echo -> track.write ->
# outbound interceptors -> SRTP-protect -> UDP; the client unprotects the echo
# and asserts it is BYTE-EXACT for BOTH tracks over 40 seeded randomized rounds.
# Proves "audio+video echo works" without aiortc. Bounded by an iteration cap +
# a wall-clock deadline (no hang). Links OpenSSL + ws2_32/mswsock/iphlpapi (Win).
boltapi_add_test(boltapi_media_echo_test media_echo_test.cpp)
target_link_libraries(boltapi_media_echo_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)
if(WIN32)
    target_link_libraries(boltapi_media_echo_test PRIVATE ws2_32 mswsock iphlpapi)
endif()

# WA: SIMULCAST (RFC 8851/8852) + SVC PASSTHROUGH — in-process, deterministic,
# deadline-bounded (DEFAULT suite, no external deps). (1) A 3-rid (q;h;f)
# simulcast video offer parses; negotiate_media echoes the rids + RID header-
# extension id; the answer carries a=rid recv x3 + a=simulcast:recv and round-
# trips. (2) Inbound RTP carrying the rtp-stream-id (RID) header extension
# demuxes into 3 per-encoding streams of a SimulcastTrack, each bound to its own
# SSRC, over seeded randomized rounds. (3) An SvcRelay classifies (spatial,
# temporal) from the Dependency Descriptor header extension and drops layers
# above a target WITHOUT decoding — keep/drop counts match the induced pattern.
# Pure codec/headers, no engine deps.
boltapi_add_test(boltapi_simulcast_test simulcast_test.cpp)

# WA: RTX (RFC 4588) + RED/ULPFEC (RFC 2198/5109) — in-process, deterministic,
# deadline-bounded (DEFAULT suite, no external deps). (1) Media packets flow
# through the RtxInterceptor (bounded cache); an inbound Generic NACK (PID + BLP
# bitmask) yields RTX packets on the dedicated rtx SSRC/PT whose OSN==N, and
# parse_rtx reconstructs each original payload BYTE-EXACT (seeded random
# payloads). (2) build_fec builds a ULPFEC packet over a media group; with ONE
# member dropped, recover() reconstructs it BYTE-EXACT from the FEC packet + the
# survivors over many randomized group sizes / drop indices; two-missing returns
# NotRecoverable. Pure codec/headers, no engine deps.
boltapi_add_test(boltapi_rtx_fec_test rtx_fec_test.cpp)

# WA: TWCC BANDWIDTH ESTIMATION + PACER — in-process, deterministic, deadline-
# bounded (DEFAULT suite, no external deps). (1) The receiver records (transport
# seq, arrival) and builds the transport-cc FCI (rides RTPFB FMT 15 via rtcp.h);
# the sender parses it back to (seq, arrival) records with the arrival spacing
# preserved. (2) A delay-based (GCC-style) estimator fed a timed sequence with
# GROWING one-way delay decreases its target rate (bounded, > floor) with a
# positive delay trend, then RECOVERS when delay goes flat. (3) A token-bucket
# Pacer driven by the estimate emits at ~the target rate over a 1s virtual window
# (bounded relative-error band) and a lower target emits proportionally fewer
# bytes. Pure headers (rtcp.h), no engine deps.
boltapi_add_test(boltapi_bwe_test bwe_test.cpp)

# M3: HTTP/3 + WebRTC seam — ProtocolRegistry mechanism (register/has/create),
# a dummy IProtocol returning NotImplemented, and (when the compile flags are
# ON) the real H3/WebRTC stub factories registering. Flag-AWARE: passes in the
# default flags-OFF build via a dummy protocol; does NOT require the flags on.
boltapi_add_test(boltapi_protocol_seam_test protocol_seam_test.cpp)
