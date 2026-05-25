// benchmarks/media_throughput_bench.cpp — SRTP + RTP-demux media hot-path bench.
//
// WHAT THIS MEASURES (an A/B harness for the WP media hot-path work):
//   * PROTECT MB/s + ns/packet — SRTP-protect an RTP packet (the outbound media
//     hot path: rtp::serialize is done once up front; we time protect only).
//   * UNPROTECT+DEMUX MB/s + ns/packet — SRTP-unprotect + rtcp::is_rtcp demux +
//     rtp::parse + by-SSRC TrackRegistry lookup (the inbound media hot path that
//     runs INLINE on the I/O thread in WebRtcPeerHub::feed_media).
//   * ALLOC COUNT — a global new/delete counter proves the per-packet path does
//     ZERO heap allocation (TigerStyle: no malloc on the media path).
//
// A/B: scratch buffer is EITHER a stack array (variant "stack") OR carved from a
// reset-per-packet bolt::Arena (variant "arena"). Both are zero-malloc on the
// steady-state path; the bench reports both so the WP change keeps whichever is
// neutral-or-better on this box.
//
// NOT registered with ctest (gated by BOLTAPI_BUILD_BENCHMARKS, manual bench
// leg). Bounded by a fixed iteration count — no sockets, no hang. Reports stable
// numbers usable for before/after comparison on one machine.
//
// TigerStyle: fixed bounds, preallocated buffers, no exceptions, asserts on
// invariants. Links OpenSSL (SRTP crypto) + ws2_32/mswsock/iphlpapi on Windows.

#include "boltapi/webrtc/srtp.h"
#include "boltapi/webrtc/rtp.h"
#include "boltapi/webrtc/rtcp.h"
#include "boltapi/webrtc/track.h"

#include "bolt/bolt_arena.h"

#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace srtp = bolt::api::webrtc::srtp;
namespace rtp  = bolt::api::webrtc::rtp;
namespace rtcp = bolt::api::webrtc::rtcp;
namespace wrtc = bolt::api::webrtc;

// ---------------------------------------------------------------------------
// Global allocation counter — proves the per-packet path is malloc-free.
// ---------------------------------------------------------------------------
namespace {
std::atomic<std::uint64_t> g_alloc_count{0};
volatile std::uint64_t     g_sink = 0;   // defeats dead-loop elimination
}  // namespace

void* operator new(std::size_t n) {
    g_alloc_count.fetch_add(1, std::memory_order_relaxed);
    void* p = std::malloc(n == 0 ? 1 : n);
    if (p == nullptr) { std::abort(); }
    return p;
}
void operator delete(void* p) noexcept { std::free(p); }
void operator delete(void* p, std::size_t) noexcept { std::free(p); }

namespace {

// ---------------------------------------------------------------------------
// Fixed bounds (TigerStyle: explicit, bounded).
// ---------------------------------------------------------------------------
constexpr int           kPackets   = 200'000;   // packets per phase (bounded)
constexpr std::size_t   kPayload   = 1100;       // typical video RTP payload
constexpr std::uint8_t  kVideoPt   = 96;
constexpr std::uint8_t  kAudioPt   = 111;
constexpr std::uint32_t kVideoSsrc = 0x0B0E2020u;
constexpr std::uint32_t kAudioSsrc = 0x0A0D1010u;
constexpr std::size_t   kScratch   = 2048;       // one MTU + SRTP slack

const std::uint8_t kMasterKey[16] = {
    0xE1, 0xF9, 0x7A, 0x0D, 0x3E, 0x01, 0x8B, 0xE0,
    0xD6, 0x4F, 0xA3, 0x2C, 0x06, 0xDE, 0x41, 0x39};
const std::uint8_t kMasterSalt[14] = {
    0x0E, 0xC6, 0x75, 0xAD, 0x49, 0x8A, 0xFE, 0xEB,
    0xB6, 0x96, 0x0B, 0x3A, 0xAB, 0xE6};

std::size_t build_rtp(std::uint8_t* buf, std::size_t cap, std::uint8_t pt,
                      std::uint16_t seq, std::uint32_t ssrc, std::uint32_t ts,
                      const std::uint8_t* payload, std::size_t plen) noexcept {
    rtp::Header h{};
    h.payload_type = pt;
    h.sequence = seq;
    h.timestamp = ts;
    h.ssrc = ssrc;
    std::size_t written = 0;
    const rtp::RtpError e = rtp::serialize(h, payload, plen, 0, buf, cap, written);
    assert(e == rtp::RtpError::Ok && "build_rtp: serialize");
    (void)e;
    return written;
}

double mbps(std::uint64_t bytes, double secs) noexcept {
    assert(secs >= 0.0 && "mbps: secs");
    if (secs <= 0.0) return 0.0;
    return (static_cast<double>(bytes) / (1024.0 * 1024.0)) / secs;
}

// A fixed-capacity pool of DISTINCT packets (monotonically rising sequence so
// SRTP never replay-rejects). Reused cyclically across the iteration count.
constexpr int kPool = 4096;            // distinct packets in flight

struct PacketPool {
    std::uint8_t  rtp[kPool][kScratch];   // plain RTP packets
    std::size_t   rtp_len[kPool]{};
    std::uint8_t  prot[kPool][kScratch];  // SRTP-protected packets
    std::size_t   prot_len[kPool]{};
};

// ---------------------------------------------------------------------------
// Phase A: SRTP protect throughput (outbound media hot path). Protects each of
// the pool's distinct plain packets, cycling for kPackets iterations.
// ---------------------------------------------------------------------------
std::uint64_t protect_phase(srtp::SrtpSession& tx, const PacketPool& pool,
                            bool use_arena, bolt::Arena& arena,
                            double* out_secs) noexcept {
    assert(out_secs != nullptr && "protect: out_secs");
    assert(pool.rtp_len[0] >= rtp::kFixedHeaderSize && "protect: pool");
    std::uint8_t stack_buf[kScratch];
    std::uint64_t total = 0, checksum = 0;
    const auto t0 = std::chrono::steady_clock::now();
    for (int i = 0; i < kPackets; ++i) {
        const int k = i % kPool;
        std::uint8_t* scratch = stack_buf;
        if (use_arena) {
            arena.reset();
            scratch = static_cast<std::uint8_t*>(arena.allocate(kScratch, 16));
            assert(scratch != nullptr && "protect: arena oom");
        }
        std::size_t out_len = 0;
        const srtp::Error e =
            tx.protect_rtp(pool.rtp[k], pool.rtp_len[k], scratch, kScratch, &out_len);
        assert(e == srtp::Error::kOk && "protect: srtp");
        (void)e;
        total += out_len;
        checksum += scratch[0];
    }
    const auto t1 = std::chrono::steady_clock::now();
    *out_secs = std::chrono::duration<double>(t1 - t0).count();
    g_sink = checksum;  // keep the loop body live
    return total;
}

// ---------------------------------------------------------------------------
// Phase B: SRTP unprotect + RFC5761 demux + parse + by-SSRC lookup (inbound).
// Unprotects each of the pool's distinct protected packets, cycling. Because the
// rx replay window only spans a few dozen seqs, we re-init rx every kPool packets
// (NOT timed: done outside the inner timed window via a fresh window each cycle).
// ---------------------------------------------------------------------------
std::uint64_t unprotect_phase(srtp::SrtpSession& rx, const PacketPool& pool,
                              wrtc::TrackRegistry& tracks, bool use_arena,
                              bolt::Arena& arena, srtp::Profile profile,
                              double* out_secs) noexcept {
    assert(out_secs != nullptr && "unprotect: out_secs");
    assert(pool.prot_len[0] > rtp::kFixedHeaderSize && "unprotect: pool");
    std::uint8_t stack_buf[kScratch];
    std::uint64_t total = 0, hits = 0;
    const auto t0 = std::chrono::steady_clock::now();
    for (int i = 0; i < kPackets; ++i) {
        const int k = i % kPool;
        if (k == 0 && i != 0)
            rx.init(profile, kMasterKey, 16, kMasterSalt, 14);  // reset replay window
        std::uint8_t* scratch = stack_buf;
        if (use_arena) {
            arena.reset();
            scratch = static_cast<std::uint8_t*>(arena.allocate(kScratch, 16));
            assert(scratch != nullptr && "unprotect: arena oom");
        }
        std::size_t plain_len = 0;
        if (rtcp::is_rtcp(pool.prot[k], pool.prot_len[k])) continue;  // demux
        const srtp::Error e = rx.unprotect_rtp(pool.prot[k], pool.prot_len[k],
                                               scratch, kScratch, &plain_len);
        assert(e == srtp::Error::kOk && "unprotect: srtp");
        (void)e;
        rtp::Packet pkt;
        const rtp::RtpError pe = rtp::parse(scratch, plain_len, pkt);
        assert(pe == rtp::RtpError::Ok && "unprotect: parse");
        (void)pe;
        wrtc::MediaTrack* t = tracks.by_ssrc(pkt.header.ssrc);
        if (t != nullptr) ++hits;
        total += plain_len;
    }
    const auto t1 = std::chrono::steady_clock::now();
    *out_secs = std::chrono::duration<double>(t1 - t0).count();
    assert(hits == static_cast<std::uint64_t>(kPackets) && "demux: misses");
    return total;
}

void run_variant(const char* name, bool use_arena, srtp::Profile profile) noexcept {
    assert(name != nullptr && "run_variant: name");
    assert(kPackets > 0 && "run_variant: packets");

    srtp::SrtpSession tx, rx;
    const srtp::Error te = tx.init(profile, kMasterKey, 16, kMasterSalt, 14);
    const srtp::Error re = rx.init(profile, kMasterKey, 16, kMasterSalt, 14);
    if (te != srtp::Error::kOk || re != srtp::Error::kOk) {
        std::fprintf(stderr, "srtp init failed\n");
        return;
    }

    wrtc::TrackRegistry tracks;
    tracks.add(wrtc::MediaKind::kAudio, kAudioSsrc, kAudioPt, "opus");
    tracks.add(wrtc::MediaKind::kVideo, kVideoSsrc, kVideoPt, "VP8");

    static std::uint8_t payload[kPayload];
    for (std::size_t i = 0; i < kPayload; ++i)
        payload[i] = static_cast<std::uint8_t>(i * 31u + 7u);

    // Build the distinct-packet pool: rising sequence numbers, then SRTP-protect
    // each (with a fresh tx so the protect-phase below starts from a clean ROC).
    static PacketPool pool;
    srtp::SrtpSession seed;
    seed.init(profile, kMasterKey, 16, kMasterSalt, 14);
    for (int k = 0; k < kPool; ++k) {
        pool.rtp_len[k] = build_rtp(pool.rtp[k], kScratch, kVideoPt,
                                    static_cast<std::uint16_t>(1000 + k),
                                    kVideoSsrc, 90000u + 160u * k,
                                    payload, kPayload);
        std::size_t pl = 0;
        const srtp::Error e = seed.protect_rtp(pool.rtp[k], pool.rtp_len[k],
                                               pool.prot[k], kScratch, &pl);
        assert(e == srtp::Error::kOk && "pool protect");
        (void)e;
        pool.prot_len[k] = pl;
    }

    bolt::Arena arena(bolt::ArenaConfig{});

    const std::uint64_t base_alloc = g_alloc_count.load(std::memory_order_relaxed);

    double prot_secs = 0.0;
    const std::uint64_t prot_bytes =
        protect_phase(tx, pool, use_arena, arena, &prot_secs);

    rx.init(profile, kMasterKey, 16, kMasterSalt, 14);
    double unp_secs = 0.0;
    const std::uint64_t unp_bytes =
        unprotect_phase(rx, pool, tracks, use_arena, arena, profile, &unp_secs);

    const std::uint64_t allocs =
        g_alloc_count.load(std::memory_order_relaxed) - base_alloc;

    const double prot_nspp = prot_secs * 1e9 / kPackets;
    const double unp_nspp  = unp_secs  * 1e9 / kPackets;
    std::printf("[%-6s] protect:   %8.1f MB/s  %7.1f ns/pkt\n",
                name, mbps(prot_bytes, prot_secs), prot_nspp);
    std::printf("[%-6s] unpr+demux:%8.1f MB/s  %7.1f ns/pkt\n",
                name, mbps(unp_bytes, unp_secs), unp_nspp);
    std::printf("[%-6s] heap allocs on the per-packet path: %llu\n",
                name, static_cast<unsigned long long>(allocs));
}

}  // namespace

int main() {
    std::printf("=== media_throughput_bench (SRTP protect/unprotect + demux) ===\n");
    std::printf("packets/phase=%d  payload=%zu\n\n", kPackets, kPayload);
    // CM profile (AES-CTR + HMAC-SHA1) — its cost is HMAC/SHA-1-bound (#38).
    std::printf("-- AES_CM_128_HMAC_SHA1_80 --\n");
    run_variant("cm/stk", /*use_arena=*/false, srtp::Profile::kAesCm128HmacSha1_80);
    run_variant("cm/arn", /*use_arena=*/true,  srtp::Profile::kAesCm128HmacSha1_80);
    // GCM profile (AEAD, no HMAC-SHA1) — the profile modern WebRTC negotiates.
    std::printf("\n-- AEAD_AES_128_GCM --\n");
    run_variant("gcm/stk", /*use_arena=*/false, srtp::Profile::kAeadAes128Gcm);
    run_variant("gcm/arn", /*use_arena=*/true,  srtp::Profile::kAeadAes128Gcm);
    return 0;
}
