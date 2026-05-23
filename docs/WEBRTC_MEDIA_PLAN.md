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
- [ ] Enable `use_srtp` DTLS extension on the DtlsContext (SRTP profiles
      `SRTP_AEAD_AES_128_GCM` + `SRTP_AES128_CM_SHA1_80`); after handshake export
      keying material (`SSL_export_keying_material`, label "EXTRACTOR-dtls_srtp")
      → client/server SRTP master keys+salts. **REBUILD** (FasterAPI had none).
- [ ] Derive SRTP/SRTCP session keys (RFC 3711 KDF). Bolt: bolt::Arena; OpenSSL
      EVP for AES-CTR/GCM + HMAC-SHA1.

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
- [ ] Parse/generate `m=audio`/`m=video` (UDP/TLS/RTP/SAVPF), a=rtpmap, a=fmtp,
      a=rtcp-fb, a=ssrc, a=mid, a=group:BUNDLE, a=setup, a=ice-*, a=extmap,
      direction (sendrecv/recvonly/sendonly). Extend our SDP codec.
- [ ] Codec intersection with the offer (pick common PT); answer with the agreed
      codecs; rtcp-mux + BUNDLE everything onto the one ICE/DTLS transport.

## Phase M5 — Track API + relay/echo
- [ ] `MediaTrack` (kind audio/video, SSRC, codec) + `App::on_track(handler)` and
      `track.send(rtp_frame)`; surface incoming SRTP-decrypted RTP as frames.
- [ ] Echo example: receive a track, loop its RTP back out (re-SRTP) — the aiortc
      `server` shape. Wire into the demo server.

## Phase M6 — Interop + perf
- [ ] aiortc interop (via `uv run --with aiortc`): the `server`/`videostream`/
      `webcam` shapes — send audio+video to Bolt, get the echo. Browser
      `getUserMedia` test page in `testing/web/`.
- [ ] Perf: SRTP on the I/O thread (inline), batched recv, zero-copy RTP via
      bolt::wire, per-SSRC SwissTable; no per-packet malloc.

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
