# WebRTC — completion + relay/SFU punch-card

Goal: stream **audio + video both directions** in a browser easily, reach **Pion
parity**, and grow into a full **WebRTC relay / SFU** (N peers, selective forwarding,
no transcode). Builds on `docs/WEBRTC_PLAN.md` + `WEBRTC_MEDIA_PLAN.md` +
`WEBRTC_REMAINING.md`. Tiger Style (bounded, noexcept, ≥2 asserts/fn, no malloc on the
media path). Verify with aiortc (have), **Pion (Go)** — the strongest gate for the
relay goal — and real Chrome via the **chrome-devtools MCP** (getUserMedia).

Status: `[x]` done · `[~]` partial/unit-gated · `[ ]` todo.

## Where we are (done, committed)
- [x] Signaling (`POST /webrtc/offer`), SDP codec (data + media m-lines), STUN (RFC 5769).
- [x] ICE-lite **and** full ICE (RFC 8445: connectivity checks both ways, role conflict,
      restart), **TURN** client + minimal server (RFC 5766/8656), **trickle** (RFC 8838).
- [x] DTLS server (live) + **DTLS-SRTP keying** (use_srtp + EXTRACTOR export → SrtpSession).
- [x] Bolt-native SCTP + DCEP data channels → `App::on_data_channel`; **aiortc data
      interop proven** (text + 64 KiB binary).
- [x] SRTP/SRTCP (RFC 3711, byte-exact KDF, CM + GCM, ROC + replay), RTP/RTCP
      (3550/8285 + SR/RR/SDES/BYE/NACK/PLI/FIR/REMB/TWCC).
- [x] Interceptor pipeline (NACK gen/responder, SR/RR reporter) + `MediaTrack` +
      `App::on_track`; peer_hub routes inbound SRTP→demux→track, outbound→SRTP.
- [x] **Media echo (aiortc `server` shape) proven against aiortc 1.14** (audio+video).
- [~] Advanced codecs (WA, unit-gated): simulcast RID demux, SVC relay, RTX (4588),
      RED/ULPFEC, TWCC BWE + pacer.
- [~] WP: RTX/SVC/pacer + interceptors live-wired into peer_hub; inline-I/O SRTP confirmed.

## P0 — Real two-way media in a browser
- [ ] **#37 — negotiate, don't just echo.** Emit `a=rtpmap`/`a=fmtp`/`a=rtcp-fb`
      (nack, nack pli, ccm fir, transport-cc, goog-remb)/`a=rtx (apt)`/`a=ulpfec`/
      `a=extmap` (transport-cc, abs-send-time, rtp-stream-id) in the SDP **answer** so a
      browser actually turns on RTX/FEC/TWCC. Today the answer mostly echoes the offer.
- [ ] **Browser getUserMedia echo** verified in real Chrome via the chrome-devtools MCP
      (camera+mic → Bolt → echoed `<video>`), not just aiortc. (`testing/web/media.html`.)
- [ ] **#38 — fix SRTP `protect` ~25× slower than `unprotect`** (cache EVP_CIPHER_CTX /
      EVP_MAC_CTX, precompute session state). Must be fixed before relay scale.
- [ ] Renegotiation: add/remove a track mid-session (new offer/answer) without dropping
      the connection.
- [ ] Gate: Chrome ↔ Bolt sendrecv audio+video echo, stable for 60 s, no leak.

## P1 — Pion-parity peer features
- [ ] Codec set negotiated + relayed (no transcode): audio **Opus/PCMU/PCMA**, video
      **VP8/VP9/H264** (dynamic PTs); later **AV1**.
- [ ] RTX retransmission stream live (apt/rtx), RED/ULPFEC live, abs-send-time +
      transport-cc header extensions on the wire.
- [ ] RTCP: per-stream SR/RR with real stats (jitter, loss, RTT), compound packets,
      PLI/FIR/NACK/REMB/TWCC generation + handling.
- [ ] Stats API (getStats-equivalent): per-track/per-SSRC bytes, packets, loss, jitter,
      rtt, nack/pli counts.
- [ ] BUNDLE + rtcp-mux (have) across audio+video+data on one transport (verify live).
- [ ] mDNS `.local` candidate handling; IPv6/dual-stack (WI follow-ups).
- [ ] Gate: **Pion (Go) peer** ↔ Bolt — data + audio + video round-trip (the strongest
      independent signal; bounded, skip-if-absent via `bounded_proc.h`).

## P2 — Relay / SFU  (the headline: N peers, selective forwarding, no transcode)
- [ ] **Rooms / multi-peer session manager**: key peers by ICE ufrag; a room holds N
      `WebRtcPeerHub`s; bounded peer/room pools. (Today: single active peer in places.)
- [ ] **Selective Forwarding Unit**: forward each publisher's RTP to each subscriber
      with **per-subscriber SSRC + PT rewrite** and seq/timestamp continuity; no decode.
- [ ] **RTCP termination + per-leg generation**: do NOT forward raw RTCP; generate
      SR/RR/NACK/PLI per leg; map feedback between publisher and subscribers.
- [ ] **Keyframe management**: on a new subscriber or layer switch, send PLI/FIR upstream;
      buffer/forward the next keyframe.
- [ ] **Simulcast layer selection**: ingest multiple RID encodings from a publisher;
      pick the layer per subscriber by their estimated bandwidth (TWCC/REMB); switch
      layers with keyframe requests. (SVC: forward the target spatial/temporal layers.)
- [ ] **Per-subscriber NACK/RTX** + a bounded retransmit cache (recent packets per SSRC).
- [ ] **Bandwidth estimation per subscriber** (TWCC receiver estimate / REMB) → drive
      layer selection + the pacer.
- [ ] Bidirectional: every peer both publishes and subscribes; full mesh handled by the
      SFU (1 up + N down per peer).
- [ ] Gate: **2 browsers** join a room via Bolt → each sees the other's live video
      (SFU forwarding). Then **N peers**. Then simulcast layer-switch under bandwidth
      change (verified via the MCP + Pion).

## P3 — "Fun things" (example milestones, each a test target)
- [ ] **play-from-disk**: IVF (VP8/VP9) / Ogg (Opus) / H264 Annex-B reader → RTP → peer.
- [ ] **save-to-disk**: record received tracks to a container (IVF/Ogg).
- [ ] **broadcast**: 1 publisher → N viewers (SFU fan-out).
- [ ] Recording + relay together; optional server-side mixing later (transcode = future).
- [ ] (Later) insertable-streams / E2EE passthrough; data-channel + media combined apps.

## P4 — Performance (relay-grade)
- [ ] SRTP encrypt/decrypt + RTP demux/forward **inline on the I/O thread** (no per-pkt
      worker hop); per-SSRC `bolt::SwissTable`; per-packet `bolt::Arena`; zero-copy via
      `bolt::wire`; no malloc on the forward path. Batched recv/send (recvmmsg/GSO).
- [ ] Forwarding bench: N-subscriber fan-out throughput + CPU/stream; compare vs Pion.
- [ ] Fix #38 (SRTP protect) first — it dominates the send path.

## P5 — Interop + harness
- [ ] aiortc (have data+media) — extend to simulcast + RTX/FEC.
- [ ] **Pion peer** (`tests/interop/pion/`) — data + media + as an SFU counterpart.
- [ ] Browser (Chrome/Firefox) getUserMedia via the chrome-devtools MCP; multi-tab room.
- [ ] `testing/web/` room page (N tiles); one demo server ties it together.
- [ ] CI WEBRTC=ON leg: unit + loopback + bounded interop.

## Cross-cutting / known issues
- #37 SDP answer negotiation (P0) · #38 SRTP protect perf (P0) · #44 Chrome offer SDP
  parse (verify against real Chrome offers via the MCP) · #36 WX CI legs + browser pages.
- WebRTC is independent of QUIC (DTLS/SRTP over UDP, not QUIC) — the QUIC/WebTransport
  work does not block the relay; they share only `net::UdpTransport` + the event loop.

**Order:** P0 (negotiate + browser echo + SRTP perf) → P1 (Pion-parity peer) →
P2 (SFU/relay: rooms → forwarding → simulcast selection) → P3 (fun examples) →
P4 perf → P5 interop. The relay milestone = 2 browsers seeing each other's video
through Bolt; then N peers with bandwidth-aware simulcast.
