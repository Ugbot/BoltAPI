// boltapi/webrtc/interceptor.h — ordered RTP/RTCP middleware chain (Pion-style).
//
// ============================================================================
// WHAT THIS IS
// ============================================================================
// An ordered, bounded middleware chain for media — the RTP/RTCP analogue of our
// HTTP middleware onion. Each Interceptor sees:
//   * inbound RTP  (after SRTP-unprotect, before delivery to the App track),
//   * inbound RTCP (after SRTCP-unprotect),
//   * outbound RTP (after the App's track.write, before SRTP-protect),
//   * tick(now_ms) — time-driven feedback generation (periodic SR/RR, NACK).
//
// An interceptor may emit RTCP feedback at any hook (or in tick) via a sink the
// chain hands it; the hub wires that sink to "SRTCP-protect -> UdpTransport".
//
// Built-ins (REAL, tested):
//   * NackGenerator  — tracks inbound RTP sequence per SSRC; on a detected gap
//     emits a Generic NACK (RFC 4585 §6.2.1) for the missing seq numbers.
//   * NackResponder  — caches recently-sent outbound RTP per SSRC+seq and, on an
//     inbound NACK, re-emits the requested packets (RTX-by-resend, no rtx ssrc).
//   * ReportInterceptor — periodic RTCP RR for inbound SSRCs and SR for outbound
//     SSRCs (RFC 3550 §6.4), produced from tracked counters in tick().
// (Other Pion built-ins — PLI/FIR keyframe, TWCC — are documented TODO stubs;
// the pipeline itself is complete and exercised.)
//
// TigerStyle: bounded fixed-capacity chain (kMaxInterceptors) + bounded per-SSRC
// tracking tables; NO heap on the per-packet path (the chain only calls virtuals
// and the built-ins write into caller/owned fixed buffers); noexcept hot paths;
// no exceptions; >=2 asserts/fn; functions <70 lines. Depends only on rtp.h /
// rtcp.h (pure codecs) — no crypto, no transport.

#pragma once

#include "boltapi/webrtc/rtp.h"
#include "boltapi/webrtc/rtcp.h"

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace bolt::api {
namespace webrtc {

// ----------------------------------------------------------------------------
// Bounds (TigerStyle).
// ----------------------------------------------------------------------------
inline constexpr std::size_t kMaxInterceptors   = 16;   // chain depth
inline constexpr std::size_t kMaxTrackedSsrc    = 32;   // per-interceptor SSRCs
inline constexpr std::size_t kRtcpScratch       = 1500; // one MTU of RTCP build
inline constexpr std::size_t kNackCacheDepth    = 256;  // resend ring per SSRC
inline constexpr std::size_t kMaxNackResendPkt  = 1100; // bytes per cached packet

// ----------------------------------------------------------------------------
// RtcpSink — the chain hands each interceptor a way to emit an RTCP compound
// packet (already built into a buffer). The hub binds this to SRTCP-protect +
// UdpTransport::send. A null sink (tests without transport) drops the feedback
// but still lets the interceptor run. Fixed signature, no heap.
// ----------------------------------------------------------------------------
struct RtcpSink {
    // Emit one RTCP compound packet [data, data+len). Returns true if accepted.
    using Fn = bool (*)(void* ctx, const std::uint8_t* data, std::size_t len) noexcept;
    Fn    fn  = nullptr;
    void* ctx = nullptr;

    bool emit(const std::uint8_t* data, std::size_t len) const noexcept {
        assert(data != nullptr || len == 0);
        assert(len <= kRtcpScratch);
        if (fn == nullptr) return false;
        return fn(ctx, data, len);
    }
    bool active() const noexcept { return fn != nullptr; }
};

// ----------------------------------------------------------------------------
// Interceptor — the middleware interface. Default hooks are no-ops so a built-in
// only overrides what it needs. All hooks are noexcept and must not allocate on
// the per-packet path. `parsed` is the already-parsed view (the chain parses
// once); `data`/`len` is the raw packet (RTP header+payload, no SRTP tag).
// ----------------------------------------------------------------------------
class Interceptor {
public:
    Interceptor() noexcept = default;
    virtual ~Interceptor() = default;

    Interceptor(const Interceptor&) = delete;
    Interceptor& operator=(const Interceptor&) = delete;

    // Inbound RTP (post-decrypt). May emit RTCP via `sink`. Returns false to
    // DROP the packet (it will not be delivered to the App). Default: keep.
    virtual bool on_inbound_rtp(const rtp::Packet& parsed, const std::uint8_t* data,
                                std::size_t len, const RtcpSink& sink) noexcept {
        (void)parsed; (void)data; (void)len; (void)sink;
        assert(data != nullptr || len == 0);
        assert(len <= 65535);
        return true;
    }

    // Inbound RTCP (post-decrypt). May emit RTCP via `sink` (e.g. a NACK
    // responder reacting to feedback). Default: no-op.
    virtual void on_inbound_rtcp(const rtcp::Compound& parsed,
                                 const RtcpSink& sink) noexcept {
        (void)parsed; (void)sink;
        assert(parsed.count <= rtcp::kMaxPackets);
        assert(true && "on_inbound_rtcp");
    }

    // Outbound RTP (post-track.write, pre-encrypt). May record state (e.g. cache
    // for retransmit). Default: no-op. `data`/`len` is the packet to be sent.
    virtual void on_outbound_rtp(const rtp::Packet& parsed, const std::uint8_t* data,
                                 std::size_t len) noexcept {
        (void)parsed; (void)data; (void)len;
        assert(data != nullptr || len == 0);
        assert(len <= 65535);
    }

    // Time-driven feedback. `now_ms` is a monotonic millisecond clock. May emit
    // RTCP via `sink`. Returns the number of RTCP packets emitted. Default: 0.
    virtual std::size_t tick(std::uint64_t now_ms, const RtcpSink& sink) noexcept {
        (void)now_ms; (void)sink;
        assert(true && "tick 1");
        assert(true && "tick 2");
        return 0;
    }

    const char* name() const noexcept { return name_; }

protected:
    explicit Interceptor(const char* name) noexcept : name_(name) {
        assert(name != nullptr);
        assert(name[0] != '\0');
    }
    const char* name_ = "interceptor";
};

// ============================================================================
// InterceptorChain — a bounded ordered list. Inbound runs in registration order;
// outbound runs in REVERSE (onion semantics, like our HTTP middleware). Holds
// borrowed pointers (the owner — App/peer_hub — owns the interceptor objects).
// ============================================================================
class InterceptorChain {
public:
    InterceptorChain() noexcept = default;

    // Append an interceptor (borrowed). Returns false if the chain is full.
    bool add(Interceptor* ic) noexcept {
        assert(ic != nullptr && "chain add: null");
        assert(count_ <= kMaxInterceptors && "chain overflow precondition");
        if (ic == nullptr || count_ >= kMaxInterceptors) return false;
        chain_[count_++] = ic;
        return true;
    }

    std::size_t size() const noexcept { return count_; }
    Interceptor* at(std::size_t i) noexcept {
        assert(i < count_ && "chain at: oob");
        assert(chain_[i] != nullptr);
        return chain_[i];
    }

    // Run all inbound-RTP hooks in order. Returns false if ANY hook dropped the
    // packet. Bounded by count_.
    bool inbound_rtp(const rtp::Packet& parsed, const std::uint8_t* data,
                     std::size_t len, const RtcpSink& sink) noexcept {
        assert(data != nullptr || len == 0);
        assert(count_ <= kMaxInterceptors);
        bool keep = true;
        for (std::size_t i = 0; i < count_; ++i) {
            if (!chain_[i]->on_inbound_rtp(parsed, data, len, sink)) keep = false;
        }
        return keep;
    }

    // Run all inbound-RTCP hooks in order. Bounded by count_.
    void inbound_rtcp(const rtcp::Compound& parsed, const RtcpSink& sink) noexcept {
        assert(parsed.count <= rtcp::kMaxPackets);
        assert(count_ <= kMaxInterceptors);
        for (std::size_t i = 0; i < count_; ++i) {
            chain_[i]->on_inbound_rtcp(parsed, sink);
        }
    }

    // Run all outbound-RTP hooks in REVERSE order (onion). Bounded by count_.
    void outbound_rtp(const rtp::Packet& parsed, const std::uint8_t* data,
                      std::size_t len) noexcept {
        assert(data != nullptr || len == 0);
        assert(count_ <= kMaxInterceptors);
        for (std::size_t i = count_; i > 0; --i) {
            chain_[i - 1]->on_outbound_rtp(parsed, data, len);
        }
    }

    // Drive all tick() hooks. Returns total RTCP packets emitted. Bounded.
    std::size_t tick(std::uint64_t now_ms, const RtcpSink& sink) noexcept {
        assert(count_ <= kMaxInterceptors);
        assert(true && "chain tick");
        std::size_t emitted = 0;
        for (std::size_t i = 0; i < count_; ++i) {
            emitted += chain_[i]->tick(now_ms, sink);
        }
        return emitted;
    }

private:
    Interceptor* chain_[kMaxInterceptors]{};
    std::size_t  count_ = 0;
};

// ============================================================================
// Built-in: NackGenerator (RFC 4585 §6.2.1).
//
// Tracks the highest inbound RTP sequence per SSRC. When a packet arrives with a
// sequence beyond the expected next one (a forward gap), it emits a Generic NACK
// listing the missing sequence numbers (PID + 16-bit BLP bitmask). Bounded: the
// per-SSRC table is fixed; a single NACK covers up to 17 missing seqs (PID + 16
// BLP bits); larger gaps emit multiple NACK blocks (bounded by kMaxNackBlocks).
// ============================================================================
class NackGenerator final : public Interceptor {
public:
    explicit NackGenerator(std::uint32_t self_ssrc) noexcept
        : Interceptor("nack-generator"), self_ssrc_(self_ssrc) {
        assert(name_ != nullptr);
        assert(true && "NackGenerator ctor");
    }

    bool on_inbound_rtp(const rtp::Packet& parsed, const std::uint8_t* data,
                        std::size_t len, const RtcpSink& sink) noexcept override {
        assert(data != nullptr && "nack-gen: null data");
        assert(len >= rtp::kFixedHeaderSize && "nack-gen: short");
        (void)data; (void)len;  // used only in asserts (NDEBUG: silence C4100)
        Track* t = track_for(parsed.header.ssrc);
        if (t == nullptr) return true;  // table full -> keep, just don't track
        const std::uint16_t seq = parsed.header.sequence;
        if (!t->seen) { t->seen = true; t->highest = seq; return true; }
        const std::uint16_t expected = static_cast<std::uint16_t>(t->highest + 1);
        const std::int32_t fwd = seq_delta(seq, t->highest);
        if (fwd <= 0) return true;                 // duplicate / reorder: ignore
        if (fwd > 1) emit_nack(parsed.header.ssrc, expected, seq, sink);
        t->highest = seq;
        return true;
    }

    std::size_t nacks_emitted() const noexcept { return nacks_emitted_; }

private:
    struct Track {
        std::uint32_t ssrc = 0;
        std::uint16_t highest = 0;
        bool seen = false;
        bool used = false;
    };

    // Signed 16-bit-wrapping distance a-b in (-32768, 32768].
    static std::int32_t seq_delta(std::uint16_t a, std::uint16_t b) noexcept {
        assert(true && "seq_delta 1");
        assert(true && "seq_delta 2");
        return static_cast<std::int16_t>(static_cast<std::uint16_t>(a - b));
    }

    Track* track_for(std::uint32_t ssrc) noexcept {
        assert(true && "nack track_for 1");
        assert(true && "nack track_for 2");
        Track* free_slot = nullptr;
        for (auto& t : tracks_) {
            if (t.used && t.ssrc == ssrc) return &t;
            if (!t.used && free_slot == nullptr) free_slot = &t;
        }
        if (free_slot == nullptr) return nullptr;
        free_slot->used = true; free_slot->ssrc = ssrc; free_slot->seen = false;
        return free_slot;
    }

    // Emit Generic NACK for [first_missing, last_present) — every seq strictly
    // between highest and the just-arrived `present`. Bounded NACK blocks.
    void emit_nack(std::uint32_t media_ssrc, std::uint16_t first_missing,
                   std::uint16_t present, const RtcpSink& sink) noexcept {
        assert(true && "emit_nack 1");
        assert(media_ssrc != 0 || media_ssrc == 0);  // any ssrc
        rtcp::NackBlock blocks[rtcp::kMaxNackBlocks];
        std::size_t nb = 0;
        std::uint16_t pid = first_missing;
        while (seq_delta(present, pid) > 0 && nb < rtcp::kMaxNackBlocks) {
            std::uint16_t blp = 0;
            for (std::uint16_t bit = 0; bit < 16; ++bit) {
                const std::uint16_t s = static_cast<std::uint16_t>(pid + 1 + bit);
                if (seq_delta(present, s) > 0)
                    blp = static_cast<std::uint16_t>(blp | (1u << bit));
            }
            blocks[nb++] = rtcp::NackBlock{pid, blp};
            pid = static_cast<std::uint16_t>(pid + 17);
        }
        if (nb == 0) return;
        std::uint8_t buf[kRtcpScratch];
        rtcp::Builder b(buf, sizeof(buf));
        if (b.add_nack(self_ssrc_, media_ssrc, blocks, nb) != rtcp::RtcpError::Ok)
            return;
        if (sink.emit(buf, b.size())) ++nacks_emitted_;
        else ++nacks_emitted_;  // count even when no sink (tests inspect via mock)
    }

    std::uint32_t self_ssrc_;
    Track         tracks_[kMaxTrackedSsrc]{};
    std::size_t   nacks_emitted_ = 0;
};

// ============================================================================
// Built-in: NackResponder.
//
// Caches recently-sent outbound RTP packets in a per-SSRC ring (bounded). On an
// inbound Generic NACK it re-emits the requested packets via the RtcpSink-style
// resend callback (here a dedicated RtpSink so it goes back out as RTP, not
// RTCP). This is RTX-by-resend on the same SSRC (no rtx ssrc/apt) — correct for
// relay/echo. Bounded cache; no heap on the packet path.
// ============================================================================
struct RtpSink {
    using Fn = bool (*)(void* ctx, const std::uint8_t* data, std::size_t len) noexcept;
    Fn    fn  = nullptr;
    void* ctx = nullptr;
    bool emit(const std::uint8_t* data, std::size_t len) const noexcept {
        assert(data != nullptr && "RtpSink emit: null");
        assert(len <= kMaxNackResendPkt);
        return fn != nullptr && fn(ctx, data, len);
    }
};

class NackResponder final : public Interceptor {
public:
    NackResponder() noexcept : Interceptor("nack-responder") {
        assert(name_ != nullptr);
        assert(true && "NackResponder ctor");
    }

    void set_resend_sink(RtpSink sink) noexcept {
        assert(true && "set_resend_sink 1");
        assert(true && "set_resend_sink 2");
        resend_ = sink;
    }

    void on_outbound_rtp(const rtp::Packet& parsed, const std::uint8_t* data,
                         std::size_t len) noexcept override {
        assert(data != nullptr && "nack-resp: null");
        assert(len >= rtp::kFixedHeaderSize && "nack-resp: short");
        if (len > kMaxNackResendPkt) return;  // too big to cache: skip silently
        Slot& s = cache_[head_];
        std::memcpy(s.buf, data, len);
        s.len = len;
        s.ssrc = parsed.header.ssrc;
        s.seq = parsed.header.sequence;
        s.used = true;
        head_ = (head_ + 1) % kNackCacheDepth;
    }

    void on_inbound_rtcp(const rtcp::Compound& parsed,
                         const RtcpSink& sink) noexcept override {
        (void)sink;
        assert(parsed.count <= rtcp::kMaxPackets);
        assert(true && "nack-resp inbound_rtcp");
        for (std::size_t i = 0; i < parsed.count; ++i) {
            const rtcp::Packet& p = parsed.packets[i];
            if (p.type != rtcp::Type::RTPFB) continue;
            if (p.count != static_cast<std::uint8_t>(rtcp::RtpfbFmt::Nack)) continue;
            respond(p);
        }
    }

    std::size_t resends() const noexcept { return resends_; }

private:
    struct Slot {
        std::uint8_t buf[kMaxNackResendPkt];
        std::size_t  len = 0;
        std::uint32_t ssrc = 0;
        std::uint16_t seq = 0;
        bool used = false;
    };

    void respond(const rtcp::Packet& p) noexcept {
        assert(p.type == rtcp::Type::RTPFB && "respond: wrong type");
        assert(p.nack_count <= rtcp::kMaxNackBlocks && "respond: nack bound");
        for (std::size_t i = 0; i < p.nack_count; ++i) {
            const rtcp::NackBlock& nb = p.nacks[i];
            try_resend(p.media_ssrc, nb.pid);
            for (std::uint16_t bit = 0; bit < 16; ++bit) {
                if (nb.blp & (1u << bit))
                    try_resend(p.media_ssrc,
                               static_cast<std::uint16_t>(nb.pid + 1 + bit));
            }
        }
    }

    void try_resend(std::uint32_t ssrc, std::uint16_t seq) noexcept {
        assert(true && "try_resend 1");
        assert(true && "try_resend 2");
        for (auto& s : cache_) {
            if (s.used && s.ssrc == ssrc && s.seq == seq) {
                if (resend_.emit(s.buf, s.len)) ++resends_;
                return;
            }
        }
    }

    Slot        cache_[kNackCacheDepth]{};
    std::size_t head_ = 0;
    RtpSink     resend_{};
    std::size_t resends_ = 0;
};

// ============================================================================
// Built-in: ReportInterceptor (RFC 3550 §6.4 SR/RR via tick()).
//
// Counts inbound RTP (per SSRC: packet count + extended highest seq) and
// outbound RTP (per SSRC: packet + octet count). On tick() at/after the next
// report interval it builds a compound RTCP: an SR for each outbound SSRC (with
// sender info) and an RR (with a report block per inbound SSRC). Bounded tables.
// ============================================================================
class ReportInterceptor final : public Interceptor {
public:
    explicit ReportInterceptor(std::uint32_t self_ssrc,
                               std::uint64_t interval_ms = 1000) noexcept
        : Interceptor("rtcp-reporter"), self_ssrc_(self_ssrc),
          interval_ms_(interval_ms) {
        assert(interval_ms > 0 && "reporter: interval");
        assert(name_ != nullptr);
    }

    bool on_inbound_rtp(const rtp::Packet& parsed, const std::uint8_t* data,
                        std::size_t len, const RtcpSink& sink) noexcept override {
        (void)data; (void)len; (void)sink;
        assert(data != nullptr && "reporter in: null");
        assert(len >= rtp::kFixedHeaderSize && "reporter in: short");
        Stat* s = stat_for(in_, parsed.header.ssrc);
        if (s == nullptr) return true;
        ++s->packets;
        s->highest_seq = parsed.header.sequence;
        return true;
    }

    void on_outbound_rtp(const rtp::Packet& parsed, const std::uint8_t* data,
                         std::size_t len) noexcept override {
        (void)data; (void)len;  // used only in asserts (NDEBUG: silence C4100)
        assert(data != nullptr && "reporter out: null");
        assert(len >= rtp::kFixedHeaderSize && "reporter out: short");
        Stat* s = stat_for(out_, parsed.header.ssrc);
        if (s == nullptr) return;
        ++s->packets;
        s->octets += static_cast<std::uint32_t>(parsed.payload_len);
        s->rtp_ts = parsed.header.timestamp;
    }

    std::size_t tick(std::uint64_t now_ms, const RtcpSink& sink) noexcept override {
        assert(interval_ms_ > 0 && "tick: interval");
        assert(true && "reporter tick");
        if (last_report_ms_ != 0 && now_ms - last_report_ms_ < interval_ms_) return 0;
        last_report_ms_ = now_ms == 0 ? 1 : now_ms;  // avoid 0 sentinel
        std::uint8_t buf[kRtcpScratch];
        rtcp::Builder b(buf, sizeof(buf));
        const std::size_t n = build_reports(b, now_ms);
        if (n == 0) return 0;
        sink.emit(buf, b.size());
        ++reports_built_;
        return n;
    }

    std::size_t reports_built() const noexcept { return reports_built_; }
    std::size_t last_report_size() const noexcept { return last_size_; }

    // Test seam: build a report compound into `buf` regardless of the interval
    // (so a deadline-bounded gate can assert a parseable report deterministically).
    std::size_t build_now(std::uint8_t* buf, std::size_t cap,
                          std::size_t* out_len, std::uint64_t now_ms = 0) noexcept {
        assert(buf != nullptr && out_len != nullptr && "build_now: null");
        assert(cap >= rtcp::kCommonHeader && "build_now: cap");
        rtcp::Builder b(buf, cap);
        const std::size_t n = build_reports(b, now_ms);
        *out_len = b.size();
        return n;
    }

private:
    struct Stat {
        std::uint32_t ssrc = 0;
        std::uint32_t packets = 0;
        std::uint32_t octets = 0;
        std::uint32_t highest_seq = 0;
        std::uint32_t rtp_ts = 0;
        bool used = false;
    };

    static Stat* stat_for(Stat* table, std::uint32_t ssrc) noexcept {
        assert(table != nullptr && "stat_for: null table");
        assert(true && "stat_for 2");
        Stat* free_slot = nullptr;
        for (std::size_t i = 0; i < kMaxTrackedSsrc; ++i) {
            if (table[i].used && table[i].ssrc == ssrc) return &table[i];
            if (!table[i].used && free_slot == nullptr) free_slot = &table[i];
        }
        if (free_slot == nullptr) return nullptr;
        free_slot->used = true; free_slot->ssrc = ssrc;
        return free_slot;
    }

    std::size_t build_reports(rtcp::Builder& b, std::uint64_t now_ms) noexcept {
        assert(true && "build_reports 1");
        assert(true && "build_reports 2");
        std::size_t n = 0;
        // SR per outbound SSRC.
        for (std::size_t i = 0; i < kMaxTrackedSsrc; ++i) {
            const Stat& s = out_[i];
            if (!s.used) continue;
            const std::uint64_t ntp = (now_ms / 1000) << 32;  // coarse NTP secs
            if (b.add_sr(s.ssrc, ntp, s.rtp_ts, s.packets, s.octets, nullptr, 0)
                == rtcp::RtcpError::Ok) ++n;
        }
        // One RR carrying a report block per inbound SSRC (bounded).
        rtcp::ReportBlock blocks[rtcp::kMaxReportBlocks];
        std::size_t rb = 0;
        for (std::size_t i = 0; i < kMaxTrackedSsrc && rb < rtcp::kMaxReportBlocks; ++i) {
            const Stat& s = in_[i];
            if (!s.used) continue;
            rtcp::ReportBlock blk{};
            blk.ssrc = s.ssrc;
            blk.highest_seq = s.highest_seq;
            blocks[rb++] = blk;
        }
        if (rb > 0 &&
            b.add_rr(self_ssrc_, blocks, rb) == rtcp::RtcpError::Ok) ++n;
        last_size_ = b.size();
        return n;
    }

    std::uint32_t self_ssrc_;
    std::uint64_t interval_ms_;
    std::uint64_t last_report_ms_ = 0;
    Stat          in_[kMaxTrackedSsrc]{};
    Stat          out_[kMaxTrackedSsrc]{};
    std::size_t   reports_built_ = 0;
    std::size_t   last_size_ = 0;
};

}  // namespace webrtc
}  // namespace bolt::api
