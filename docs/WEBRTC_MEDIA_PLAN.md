# Bolt API — WebRTC Media (audio + video) Punch-Card

> Extends WebRTC beyond data channels (docs/WEBRTC_PLAN.md) to **audio + video**,
> targeting aiortc's `server` example: accept an offer, then **echo/relay** the
> peer's audio + video tracks and a data channel. Correctness-first, no rush.
>
> Shares the existing foundation — ICE-lite, **DTLS**, UdpTransport, signaling,
> SDP — and adds **DTLS-SRTP + RTP/RTCP + media SDP**. Media uses RTP over
> DTLS-SRTP (NOT SCTP). H1/H2 core untouched; all under `BOLTAPI_WITH_WEBRTC`.
> Status: `- [ ]` todo · `- [~]` wip · `- [x]` done.

## Scope
- **v1 = relay/echo, no transcoding** (like aiortc server): negotiate codecs,
  receive RTP, hand frames to `App` (`on_track`), send frames back out. Bolt does
  not encode/decode codecs in v1 — it relays RTP payloads. (Transcode = later.)
- Audio codecs to NEGOTIATE: **Opus** (111), **PCMU** (0), **PCMA** (8).
  Video: **VP8** (96-ish, dynamic), **H264** (dynamic). Just negotiate + relay.
- In: 1 audio + 1 video recvonly/sendrecv m-line + the data channel (BUNDLE).
  Out (later): multiple tracks, simulcast, TURN.

## Phase M1 — DTLS-SRTP keying
- [x] Enable `use_srtp` DTLS extension on the DtlsContext (SRTP profiles
      `SRTP_AEAD_AES_128_GCM` + `SRTP_AES128_CM_SHA1_80`); after handshake export
      keying material (`SSL_export_keying_material`, label "EXTRACTOR-dtls_srtp")
      → client/server SRTP master keys+salts (`DtlsSession::export_srtp_keying`
      + `SrtpKeying`).
- [x] Derive SRTP/SRTCP session keys (RFC 3711 KDF) via `SrtpKeying::build_sessions`
      → role-mapped inbound/outbound `srtp::SrtpSession` (server: out=server-write,
      in=client-write; client reversed). Live gate `tests/dtls_srtp_test.cpp`.

## Phase M2 — SRTP / SRTCP
- [ ] SRTP protect/unprotect: AES-CM-128 + HMAC-SHA1-80 AND AES-128-GCM; ROC
      (rollover counter) + replay window. **REBUILD** (FasterAPI rtp.cpp SRTP was
      fake — `rtp.cpp:147-205`).
- [ ] SRTCP protect/unprotect (RFC 3711 §3.4) for RTCP.
- [ ] Unit tests against RFC 3711 / libsrtp test vectors (the crypto gate).

## Phase M3 — RTP / RTCP
- [ ] RTP header parse/serialize (+ extensions, CSRC, padding). **PORT** the real
      codec from FasterAPI `webrtc/rtp.cpp:18-115` (header part is correct).
- [ ] RTCP: SR/RR, SDES, BYE; feedback PLI/FIR/NACK (RFC 4585) + REMB; compound
      packet parse/build. **REBUILD.** Demux RTP vs RTCP (RFC 5761 mux, pt 64-95).
- [ ] Jitter buffer (bounded, per-SSRC reorder); sequence/timestamp tracking.
      Bolt: SwissTable for SSRC→stream, Arena/ring for packets.

## Phase M4 — Media SDP negotiation
- [x] Parse/generate `m=audio`/`m=video` (UDP/TLS/RTP/SAVPF), a=rtpmap, a=fmtp,
      a=rtcp-fb, a=ssrc, a=mid, a=group:BUNDLE, a=setup, a=ice-*, a=extmap,
      direction (sendrecv/recvonly/sendonly). Extended our SDP codec
      (`SdpMedia::{direction,rtpmap_for,fmtp_for,payload_types,rtcp_mux,ssrc}`).
- [x] Codec intersection with the offer (pick common PT) via `negotiate_media`;
      `build_media_answer` answers with the agreed codecs; rtcp-mux + BUNDLE all
      m-lines onto the one ICE/DTLS transport. Gate `tests/media_sdp_test.cpp`.

## Phase M5 — Track API + relay/echo
- [x] `MediaTrack` (kind audio/video, SSRC, codec, PT; bounded `TrackRegistry`,
      `kMaxTracks`) + `App::on_track(handler)` and `track.write(rtp_packet)`;
      surface incoming SRTP-decrypted RTP as packets to the App handler (demux by
      SSRC, PT fallback). Plus `webrtc/interceptor` — an ordered, bounded
      RTP/RTCP middleware chain (`kMaxInterceptors`, inbound in-order + outbound
      reverse onion, no heap on the packet path) with built-ins NackGenerator,
      NackResponder, ReportInterceptor (SR/RR on tick). Wired into
      `WebRtcPeerHub`: SRTP keying via `make_srtp_sessions` after DTLS; first-byte
      128–191 datagrams demuxed (`rtcp::is_rtcp` ? SRTCP-unprotect → RTCP hooks :
      SRTP-unprotect → demux → track → on_track); outbound `track.write` →
      interceptors → SRTP-protect → UdpTransport. Gate `tests/media_track_test.cpp`
      (two tracks audio+video distinct SSRCs, 64 seeded randomized rounds
      byte-exact; sequence-gap → parseable Generic NACK; reporter tick →
      parseable SR/RR compound). Deadline-bounded, default suite.
- [x] Echo example: receive a track, loop its RTP back out (re-SRTP) — the aiortc
      `server` shape. `App::enable_media_echo()` installs an on_track handler that
      `track.write`s every inbound RTP straight back out (relay, NO transcode);
      signaling answers the offered audio/video m-lines sendrecv (+ data m-line
      when present) via `webrtc::build_echo_answer`. Wired into the demo server
      (`examples/demo_server.cpp`). PRIMARY GATE `tests/media_echo_test.cpp`
      (default suite, no aiortc): a REAL DTLS-SRTP client sends audio+video RTP
      through the production `WebRtcPeerHub` echo path; echoed RTP BYTE-EXACT for
      BOTH tracks over 40 seeded randomized rounds, deadline-bounded.

## Phase M6 — Interop + perf
- [x] aiortc interop (via `uv run --with aiortc --with numpy --with av`): the
      `server` shape — aiortc sends a synthetic audio+video track to Bolt and
      gets the echo (`tests/interop/aiortc_media.py` + bounded `AiortcMediaInterop`
      gtest, WEBRTC=ON, PASSES vs aiortc 1.14). Browser `getUserMedia` page
      `testing/web/media.html`. All interop legs run through the no-stall runner
      `tests/interop/bounded_proc.h` (hard timeout + WHOLE-tree kill; can never
      hang/leak — proven). (`videostream`/`webcam` shapes: later.)
- [ ] Perf: SRTP on the I/O thread (inline), batched recv, zero-copy RTP via
      bolt::wire, per-SSRC SwissTable; no per-packet malloc.

## Phase M7 — Full ICE / TURN / trickle (connectivity beyond ice-lite)
- [x] **Full ICE agent** (`webrtc::FullIceAgent`, RFC 8445) as an OPTION alongside
      ice-lite (`WebRtcConfig::full_ice`): controlling/controlled roles, candidate
      pairs + checklist with pair states, connectivity checks in BOTH directions
      (Binding req/resp w/ PRIORITY + ICE-CONTROLLING/CONTROLLED + USE-CANDIDATE),
      role-conflict resolution (tie-breaker), nomination, bounded retransmit, and
      ICE restart. Bounded `kMaxCandidates`/`kMaxPairs`, no exceptions. PRIMARY
      GATE `tests/ice_full_test.cpp` (default suite, no external servers,
      deadline-bounded): two of OUR agents converge on a nominated valid pair
      both directions; redundant candidate deduped + dead candidate Fails without
      deadlock; role-conflict resolves; restart clears state.
- [x] **Trickle ICE** (RFC 8838): `webrtc/sdp` `parse_trickle`/`generate_trickle`
      (RTCIceCandidateInit JSON / bare candidate line / `end-of-candidates`) +
      the `App` trickle route `POST /webrtc/candidate` (mirrors `/webrtc/offer`)
      feeding `FullIceAgent::add_remote_candidate`. The gate delivers a candidate
      AFTER checks start and still converges.
- [x] **TURN client + minimal TURN server** (`webrtc/turn`, RFC 5766/8656):
      client Allocate (long-term cred, REALM/NONCE 401 retry), Refresh,
      CreatePermission, ChannelBind, Send/Data + ChannelData, relay candidate from
      XOR-RELAYED-ADDRESS; an in-process server (control + relay sockets) gates it
      over loopback. GATE `tests/turn_test.cpp` (default suite, deadline-bounded):
      Allocate → relay candidate → CreatePermission/ChannelBind → datagram relayed
      THROUGH the server end-to-end (both directions) → Refresh(0) releases.
- [ ] Live srflx against a public STUN server; mDNS `.local`; IPv6 / dual-stack.

## Phase WA — Media advanced (Pion-level: simulcast/SVC/RTX/FEC/BWE)
- [x] **Simulcast** (RFC 8851 a=simulcast + RFC 8852 a=rid via the rtp-stream-id
      header extension): SDP parse+generate (`SdpMedia::{has_simulcast,simulcast,
      rids,rid_extmap_id}`, `NegotiatedMedia::{rids,rid_ext_id}`, answers emit
      `a=extmap`+`a=rid recv`+`a=simulcast:recv`); `rtp::rid_value` reads the RID
      header ext; `webrtc::SimulcastTrack` demuxes inbound layers by RID into per-
      encoding streams (bounded `kMaxEncodings`, lazy RID→SSRC bind).
- [x] **SVC passthrough** (`webrtc::SvcRelay`): classify (spatial,temporal) from
      the Dependency Descriptor header ext / VP8-VP9 payload temporal id and
      keep/drop against a target — no codec decode.
- [x] **RTX** (RFC 4588, `webrtc::RtxInterceptor`): negotiate apt/rtx PT; on
      inbound NACK retransmit as an OSN-prefixed RTX packet on the rtx SSRC/PT;
      `parse_rtx` recovers the original byte-exact.
- [x] **RED/ULPFEC** (RFC 2198 / RFC 5109, `webrtc/fec.h`): `build_fec` XORs a
      bounded media group into a ULPFEC packet; `recover` reconstructs one dropped
      packet byte-exact from the FEC + survivors.
- [x] **TWCC bandwidth estimation** (`webrtc/bwe.h`): transport-cc feedback
      build/parse; a GCC delay-based rate estimate; a token-bucket `Pacer`.
- [x] Gates (DEFAULT suite, deadline-bounded, no external deps):
      `tests/simulcast_test.cpp`, `tests/rtx_fec_test.cpp`, `tests/bwe_test.cpp`.
- [ ] Wire the interceptors (RTX/SVC) + pacer into the live `WebRtcPeerHub` send
      path + negotiate RTX/FEC/TWCC in the App signaling answer (follow-up).
- [ ] Key update / DTLS renegotiation.

## Salvage map (media)
| FasterAPI | Verdict | Reason |
|---|---|---|
| `webrtc/rtp.cpp` header parse/serialize (`:18-115`) | **PORT** | Correct RTP codec. |
| `webrtc/rtp.cpp` SRTP (`:147-205`) | **REBUILD** | encrypt/decrypt/derive all TODO; fake tag. |
| RTCP / jitter / track API | **REBUILD** | none existed. |

## Test harness (real clients)
- `testing/aiortc_media.py` (uv) — send a synthetic audio+video track, assert echo.
- `testing/web/media.html` — browser `getUserMedia` → Bolt → `<video>` of the echo.
- Reuse `/webrtc/offer` signaling; same demo server, add tracks.

> Dependency order: finish data-channel interop (docs/WEBRTC_PLAN.md) → M1 DTLS-SRTP
> → M2 SRTP → M3 RTP/RTCP → M4 SDP → M5 tracks/echo → M6 interop. Crypto (OpenSSL)
> is the justified stopgap; everything else Bolt-native.
