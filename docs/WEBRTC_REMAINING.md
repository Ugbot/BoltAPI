# WebRTC — Remaining Work (ordered punch-card, Pion-parity: data + audio + video)

> Goal: a full WebRTC stack — **data channels + streaming audio + streaming video** —
> on par with Pion (aiortc's `server` shape), all Bolt-native except OpenSSL crypto.
> Execute top-to-bottom; each wave correctness-gated, default `ctest` green,
> committed. Detailed design: `docs/WEBRTC_PLAN.md` (data) + `docs/WEBRTC_MEDIA_PLAN.md`
> (media). Module map mirrors Pion (stun/ice/dtls/sctp/srtp/rtp/rtcp/sdp/interceptor).

## TESTING DISCIPLINE — "no stalls" (read first)
Every WebRTC test/interop MUST be non-hanging:
- **Hard deadline + watchdog on every gate.** Loopback gtests bounded (≤10s) with a
  deadline that fails (not hangs). Any subprocess (aiortc/Pion/curl) is launched
  with a kill-timeout; the gtest `GTEST_SKIP`s if the client/tool is absent and
  HARD-KILLS + fails (never blocks) if it runs over.
- **Prefer in-process / loopback deterministic gates** (our stack both ends, seeded
  RNG) as the primary signal; external-client interop is a *secondary, bounded* gate.
- `uv run --with <pkg>` for Python (never bare pip/python); pre-warm the env in a
  bounded step so the test itself doesn't pay the wheel download.
- CI: WebRTC tests run under a job timeout; interop legs are allowed-to-skip, never
  allowed-to-hang.

## DONE (committed)
- [x] SDP codec; STUN (RFC 5389/8489, RFC 5769 vectors); ICE-lite answerer (live STUN over the wire).
- [x] UDP transport on the unified event loop (inline I/O-thread demux).
- [x] DTLS server (handshake + fingerprint identity binding, live).
- [x] Bolt-native SCTP (assoc, DATA/SACK, fragmentation→256KiB, ordered/unordered, partial reliability/FORWARD-TSN, RTO + congestion control) + DCEP → `App::on_data_channel`.
- [x] **aiortc data-channel interop proven** (text + 64KiB binary echo, independent stack).
- [x] Signaling route `POST /webrtc/offer` (offer→answer) + demo server + `testing/` harness.

---

## WD — Data-channel completion / robustness
- [ ] **Multi-peer signaling**: key sessions by ICE ufrag (today single active peer); concurrent peers, lifecycle/teardown.
- [ ] SCTP graceful close: SHUTDOWN/SHUTDOWN-ACK/COMPLETE, ABORT; **stream reset** (RFC 8831 / RFC 6525 RE-CONFIG) for `dc.close()`.
- [ ] SCTP keepalive HEARTBEAT/HEARTBEAT-ACK + idle/path checks; duplicate-TSN reporting; PMTU.
- [ ] `bufferedAmount` + `bufferedAmountLowThreshold` backpressure on `IDataChannel`.
- [ ] Harden the aiortc interop test (hard timeout, no hang) + **browser** data-channel gate (Chrome + Firefox, documented + scripted).

## WM1 — DTLS-SRTP keying  (media foundation)
- [ ] DtlsContext `use_srtp` ext (profiles `SRTP_AEAD_AES_128_GCM`, `SRTP_AES128_CM_SHA1_80`); `SSL_export_keying_material` (label `EXTRACTOR-dtls_srtp`) → client/server master key+salt.
- [ ] RFC 3711 KDF → SRTP + SRTCP session keys. Bolt Arena; OpenSSL EVP.

## WM2 — SRTP / SRTCP  (`webrtc/srtp`)
- [ ] SRTP protect/unprotect: AES-CM-128-HMAC-SHA1-80 **and** AES-128-GCM; ROC + replay window. REBUILD (FasterAPI SRTP was fake).
- [ ] SRTCP protect/unprotect (RFC 3711 §3.4).
- [ ] Gate: RFC 3711 / libsrtp test vectors byte-exact.

## WM3 — RTP / RTCP  (`webrtc/rtp`, `webrtc/rtcp`)
- [ ] RTP header parse/serialize (+ extensions/CSRC/padding). PORT FasterAPI `rtp.cpp:18-115`.
- [ ] RTP/RTCP demux (RFC 5761); SSRC table = bolt::SwissTable; per-SSRC jitter/reorder buffer (bounded).
- [ ] RTCP SR/RR/SDES/BYE + compound parse/build; per-SSRC stats (jitter, loss, RTT).

## WM4 — Media SDP negotiation  (`webrtc/sdp`)
- [ ] Parse/generate `m=audio`/`m=video` (UDP/TLS/RTP/SAVPF), a=rtpmap/fmtp/rtcp-fb/ssrc/extmap/direction; **BUNDLE** + **rtcp-mux**; a=mid/group/msid.
- [ ] Codec intersection with offer → answer: audio **Opus/PCMU/PCMA**, video **VP8/VP9/H264** (relay PTs; no transcode).

## WM5 — Interceptor pipeline + Track API  (Pion-style)
- [ ] `webrtc/interceptor`: ordered RTP/RTCP middleware chain (mirrors our HTTP onion). Built-ins (each tickable): **NACK responder + generator (RTX)**, **RTCP SR/RR reporter**, **PLI/FIR** keyframe request, **TWCC** feedback + receiver bandwidth estimate.
- [ ] `MediaTrack` (kind/SSRC/codec/PT) + `App::on_track(handler)` + `track.write(rtp)`; SRTP-decrypted RTP → app; app → interceptors → SRTP → UdpTransport. Mirrors `on_data_channel`.

## WM6 — Media example milestones (each a bounded test target)
- [ ] **echo** (aiortc `server`): receive audio+video + data channel, loop back. Demo server + `testing/web/media.html` (getUserMedia).
- [ ] **play-from-disk** (stream a file: IVF/Ogg/H264 reader → RTP).
- [ ] **save-to-disk** (record received media to a container).
- [ ] **broadcast** (1 publisher → N viewers) and **SFU** (per-subscriber RTP forwarding, PLI/NACK via interceptors, no transcode).

## WI — Full ICE / TURN / trickle  (Pion ICE parity, beyond ice-lite)
- [ ] **Trickle ICE** (incremental candidate exchange over signaling + end-of-candidates).
- [ ] **Full ICE agent** (controlling/controlled, connectivity checks both directions, role conflict, restart) as an option alongside ice-lite.
- [ ] STUN srflx via external STUN server; **TURN client** (relay candidates, allocations, channels); optional **TURN server** (`webrtc/turn`).
- [ ] mDNS `.local` candidates; IPv6 / dual-stack; candidate prioritization/pairing.

## WA — Media advanced (Pion-level)
- [ ] **Simulcast** (multiple encodings per track, rid/mid extensions).
- [ ] **SVC** (scalable video coding) passthrough.
- [ ] **RTX** retransmission stream; **RED/ULPFEC** forward error correction.
- [ ] Bandwidth estimation (GCC / TWCC-based) + media pacing/congestion control.
- [ ] Key update / DTLS renegotiation; abs-send-time / transport-cc header extensions.

## WT — WebTransport (optional; shares HTTP/3)
- [ ] WebTransport over HTTP/3 (RFC 9297): CONNECT-UDP / H3 datagrams + streams. Depends on HTTP/3 (see HTTP3_REMAINING W5e datagrams). Reuses UdpTransport.

## WP — Performance
- [ ] SRTP encrypt/decrypt + RTP demux **inline on the I/O thread** (no per-packet worker hop — same fix as UDP/STUN).
- [ ] Batched UDP recv/send (recvmmsg/WSARecvMsg/GSO); zero-copy RTP via `bolt::wire`; per-SSRC `bolt::SwissTable`; per-packet `bolt::Arena`; no malloc on the media path. Bench vs aiortc/Pion.

## WX — Interop + harness (bounded, no-stall)
- [ ] `testing/aiortc_media.py` (uv): send synthetic audio+video track, assert echo (hard timeout).
- [ ] `testing/web/media.html`: browser getUserMedia → Bolt → echo `<video>`.
- [ ] **Pion (Go) peer**: a tiny data+media peer — strongest independent gate.
- [ ] Demo server: enable media echo + data; one server, all clients point at it.
- [ ] CI WebRTC leg (BOLTAPI_WITH_WEBRTC=ON) runs unit + loopback + (skip-if-absent, never-hang) interop.

## Salvage map (media)
| FasterAPI | Verdict | Reason |
|---|---|---|
| `webrtc/rtp.cpp` header (`:18-115`) | PORT | correct RTP codec |
| `webrtc/rtp.cpp` SRTP (`:147-205`) | REBUILD | fake auth tag, no real crypto |
| RTCP / interceptor / track / media SDP / TURN / full-ICE | REBUILD | none existed |

---
**Order:** WD (data polish) → WM1→WM6 (audio+video: keying→SRTP→RTP/RTCP→SDP→interceptors/track→echo/play/save/broadcast/SFU) → WI (full ICE/TURN/trickle) → WA (simulcast/SVC/RTX/FEC/BWE) → WP (perf) → WT (WebTransport, with HTTP/3) → WX (interop). **WM6 echo = "audio+video works"; WX/Pion = proves it against the world.** Crypto via OpenSSL is the only non-Bolt dep.
