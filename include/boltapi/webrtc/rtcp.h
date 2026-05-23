// boltapi/webrtc/rtcp.h — RTCP (RFC 3550 / RFC 4585 / RFC 5104) codec.
//
// ============================================================================
// WHAT THIS IS
// ============================================================================
// A REBUILT RTCP compound-packet parse + build. FasterAPI had no RTCP at all,
// so this is from scratch against the RFCs. Covers:
//
//   * Compound packet parse/build (multiple RTCP packets back to back)
//   * SR  (PT 200) Sender Report     — RFC 3550 §6.4.1
//   * RR  (PT 201) Receiver Report   — RFC 3550 §6.4.2
//   * SDES(PT 202) Source Description— RFC 3550 §6.5
//   * BYE (PT 203) Goodbye           — RFC 3550 §6.6
//   * APP (PT 204) Application-defined— RFC 3550 §6.7
//   * RTPFB (PT 205) transport-layer FB — RFC 4585: Generic NACK (FMT 1),
//       TWCC / transport-cc (FMT 15) raw payload exposed
//   * PSFB (PT 206) payload-specific FB — RFC 4585/5104: PLI (FMT 1),
//       FIR (FMT 4), REMB (FMT 15, "goog-remb")
//   * Report blocks: fraction lost / cumulative lost / highest seq / jitter /
//     LSR / DLSR  (RFC 3550 §6.4.1)
//   * RTP-vs-RTCP demux (RFC 5761): a UDP datagram whose second byte (the RTP
//     payload type / RTCP packet type) is in [64..95] is RTCP.
//
// Pure codec: no crypto, no engine deps. Header-only.
//
// TigerStyle: bounded report-block / NACK / SDES-item / packet counts, fixed
// caller buffers on build, noexcept, error-return, no heap. >=2 asserts/fn.

#pragma once

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace bolt::api {
namespace webrtc {
namespace rtcp {

// ----------------------------------------------------------------------------
// Constants
// ----------------------------------------------------------------------------
inline constexpr std::uint8_t kVersion        = 2;
inline constexpr std::size_t  kCommonHeader   = 4;     // V/P/RC, PT, length(16)
inline constexpr std::size_t  kReportBlockLen = 24;    // RFC 3550 §6.4.1
inline constexpr std::size_t  kMaxReportBlocks = 31;   // RC field is 5 bits
inline constexpr std::size_t  kMaxNackBlocks  = 64;    // bounded
inline constexpr std::size_t  kMaxSdesItems   = 16;    // bounded
inline constexpr std::size_t  kMaxByeSources  = 31;    // SC field is 5 bits
inline constexpr std::size_t  kMaxPackets     = 32;    // packets in a compound, bounded
inline constexpr std::size_t  kMaxFirEntries  = 16;    // bounded

// Packet types.
enum class Type : std::uint8_t {
    SR    = 200,
    RR    = 201,
    SDES  = 202,
    BYE   = 203,
    APP   = 204,
    RTPFB = 205,  // transport-layer feedback (RFC 4585)
    PSFB  = 206,  // payload-specific feedback (RFC 4585)
};

// Feedback message types (the RC field is reused as FMT for 205/206).
enum class RtpfbFmt : std::uint8_t { Nack = 1, Twcc = 15 };
enum class PsfbFmt  : std::uint8_t { Pli = 1, Fir = 4, Remb = 15 };

// SDES item types (RFC 3550 §6.5).
enum class SdesType : std::uint8_t {
    End  = 0, CName = 1, Name = 2, Email = 3, Phone = 4,
    Loc  = 5, Tool = 6, Note = 7, Priv = 8,
};

enum class RtcpError : std::uint8_t {
    Ok = 0,
    TooShort,        // buffer smaller than a declared section
    BadVersion,      // version != 2
    BadLength,       // length field inconsistent with the buffer
    TooManyBlocks,   // report blocks / nack blocks / items over the bound
    TooManyPackets,  // compound exceeded kMaxPackets
    BufferTooSmall,  // encode target buffer too small
    WrongType,       // accessor called on a packet of the wrong type
};

// ----------------------------------------------------------------------------
// Report block (RFC 3550 §6.4.1) — common to SR and RR.
// ----------------------------------------------------------------------------
struct ReportBlock {
    std::uint32_t ssrc            = 0;  // source this block reports on
    std::uint8_t  fraction_lost   = 0;  // fixed-point 8-bit fraction
    std::int32_t  cumulative_lost = 0;  // 24-bit signed
    std::uint32_t highest_seq     = 0;  // extended highest sequence number
    std::uint32_t jitter          = 0;  // interarrival jitter
    std::uint32_t lsr             = 0;  // last SR timestamp (middle 32 of NTP)
    std::uint32_t dlsr            = 0;  // delay since last SR (1/65536 s)
};

// ----------------------------------------------------------------------------
// Generic NACK block (RFC 4585 §6.2.1): one PID + 16-bit bitmask of lost.
// ----------------------------------------------------------------------------
struct NackBlock {
    std::uint16_t pid  = 0;   // first lost sequence number
    std::uint16_t blp  = 0;   // bitmask of following lost packets
};

// ----------------------------------------------------------------------------
// FIR entry (RFC 5104 §4.3.1): SSRC + sequence number.
// ----------------------------------------------------------------------------
struct FirEntry {
    std::uint32_t ssrc = 0;
    std::uint8_t  seq  = 0;
};

// ----------------------------------------------------------------------------
// SDES item (zero-copy text view into the source buffer).
// ----------------------------------------------------------------------------
struct SdesItem {
    SdesType    type = SdesType::End;
    const char* text = nullptr;
    std::uint8_t length = 0;
};

// ----------------------------------------------------------------------------
// Packet — one RTCP packet inside a compound. Union-ish: fields are populated
// per `type`. All variable arrays are bounded and (for SDES/feedback payload)
// zero-copy into the source buffer.
// ----------------------------------------------------------------------------
struct Packet {
    Type          type{};
    std::uint8_t  count = 0;       // RC / SC, or FMT for feedback (205/206)
    bool          padding = false;
    std::uint32_t ssrc = 0;        // sender SSRC (SR/RR/feedback); SDES first chunk

    // SR-only sender info.
    std::uint64_t ntp_timestamp = 0;
    std::uint32_t rtp_timestamp = 0;
    std::uint32_t packet_count  = 0;
    std::uint32_t octet_count   = 0;

    // SR / RR report blocks.
    ReportBlock report_blocks[kMaxReportBlocks]{};
    std::size_t report_count = 0;

    // Feedback (205/206): media-source SSRC + FCI payload view.
    std::uint32_t       media_ssrc = 0;
    const std::uint8_t* fci = nullptr;
    std::uint16_t       fci_len = 0;

    // Parsed feedback bodies (filled for known FMTs).
    NackBlock     nacks[kMaxNackBlocks]{};
    std::size_t   nack_count = 0;
    FirEntry      fir[kMaxFirEntries]{};
    std::size_t   fir_count = 0;
    std::uint32_t remb_bitrate_bps = 0;
    std::uint32_t remb_ssrcs[kMaxFirEntries]{};
    std::size_t   remb_ssrc_count = 0;

    // SDES items of the first chunk (zero-copy).
    SdesItem    sdes[kMaxSdesItems]{};
    std::size_t sdes_count = 0;

    // BYE source list.
    std::uint32_t bye_sources[kMaxByeSources]{};
    std::size_t   bye_count = 0;

    // Raw view of the whole packet (incl. its 4-byte header).
    const std::uint8_t* raw = nullptr;
    std::size_t         raw_len = 0;
};

// ----------------------------------------------------------------------------
// Compound — the parsed list of packets in a UDP datagram.
// ----------------------------------------------------------------------------
struct Compound {
    Packet      packets[kMaxPackets]{};
    std::size_t count = 0;
};

// ============================================================================
// Demux (RFC 5761) — classify a datagram as RTP or RTCP by the 2nd byte.
// ============================================================================
inline bool is_rtcp(const std::uint8_t* data, std::size_t len) noexcept {
    assert(data != nullptr || len == 0);
    if (data == nullptr || len < 2) return false;
    const std::uint8_t version = static_cast<std::uint8_t>((data[0] >> 6) & 0x03);
    const std::uint8_t pt = static_cast<std::uint8_t>(data[1] & 0x7F);
    assert(version <= 3);
    return version == kVersion && pt >= 64 && pt <= 95;
}

// ============================================================================
// Internal big-endian helpers.
// ============================================================================
namespace detail {

inline std::uint16_t rd16(const std::uint8_t* p) noexcept {
    assert(p != nullptr);
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(p[0]) << 8) | p[1]);
}
inline std::uint32_t rd24(const std::uint8_t* p) noexcept {
    assert(p != nullptr);
    return (static_cast<std::uint32_t>(p[0]) << 16) |
           (static_cast<std::uint32_t>(p[1]) << 8)  |
            static_cast<std::uint32_t>(p[2]);
}
inline std::uint32_t rd32(const std::uint8_t* p) noexcept {
    assert(p != nullptr);
    return (static_cast<std::uint32_t>(p[0]) << 24) |
           (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8)  |
            static_cast<std::uint32_t>(p[3]);
}
inline std::uint64_t rd64(const std::uint8_t* p) noexcept {
    assert(p != nullptr);
    return (static_cast<std::uint64_t>(rd32(p)) << 32) | rd32(p + 4);
}
inline void wr16(std::uint8_t* p, std::uint16_t v) noexcept {
    assert(p != nullptr);
    p[0] = static_cast<std::uint8_t>(v >> 8);
    p[1] = static_cast<std::uint8_t>(v & 0xFF);
}
inline void wr24(std::uint8_t* p, std::uint32_t v) noexcept {
    assert(p != nullptr);
    p[0] = static_cast<std::uint8_t>(v >> 16);
    p[1] = static_cast<std::uint8_t>(v >> 8);
    p[2] = static_cast<std::uint8_t>(v & 0xFF);
}
inline void wr32(std::uint8_t* p, std::uint32_t v) noexcept {
    assert(p != nullptr);
    p[0] = static_cast<std::uint8_t>(v >> 24);
    p[1] = static_cast<std::uint8_t>(v >> 16);
    p[2] = static_cast<std::uint8_t>(v >> 8);
    p[3] = static_cast<std::uint8_t>(v & 0xFF);
}
inline void wr64(std::uint8_t* p, std::uint64_t v) noexcept {
    assert(p != nullptr);
    wr32(p, static_cast<std::uint32_t>(v >> 32));
    wr32(p + 4, static_cast<std::uint32_t>(v & 0xFFFFFFFFu));
}

inline std::int32_t sign_extend24(std::uint32_t v) noexcept {
    assert(v <= 0xFFFFFFu);
    if (v & 0x800000u) return static_cast<std::int32_t>(v | 0xFF000000u);
    return static_cast<std::int32_t>(v);
}

// Parse report blocks for SR/RR. `p` points at the first block; `count` blocks.
inline RtcpError parse_report_blocks(Packet& pkt, const std::uint8_t* p,
                                     std::size_t count, std::size_t avail) noexcept {
    assert(p != nullptr || count == 0);
    assert(count <= kMaxReportBlocks);
    if (count > kMaxReportBlocks) return RtcpError::TooManyBlocks;
    if (avail < count * kReportBlockLen) return RtcpError::TooShort;
    for (std::size_t i = 0; i < count; ++i) {
        const std::uint8_t* b = p + i * kReportBlockLen;
        ReportBlock& rb = pkt.report_blocks[i];
        rb.ssrc            = rd32(b);
        rb.fraction_lost   = b[4];
        rb.cumulative_lost = sign_extend24(rd24(b + 5));
        rb.highest_seq     = rd32(b + 8);
        rb.jitter          = rd32(b + 12);
        rb.lsr             = rd32(b + 16);
        rb.dlsr            = rd32(b + 20);
    }
    pkt.report_count = count;
    return RtcpError::Ok;
}

// Parse a known feedback FCI body into structured fields.
inline RtcpError parse_feedback_body(Packet& pkt) noexcept {
    assert(pkt.type == Type::RTPFB || pkt.type == Type::PSFB);
    assert(pkt.fci != nullptr || pkt.fci_len == 0);
    const std::uint8_t* f = pkt.fci;
    const std::uint16_t n = pkt.fci_len;
    if (pkt.type == Type::RTPFB && pkt.count == static_cast<std::uint8_t>(RtpfbFmt::Nack)) {
        std::size_t off = 0;
        while (off + 4 <= n) {
            if (pkt.nack_count >= kMaxNackBlocks) return RtcpError::TooManyBlocks;
            pkt.nacks[pkt.nack_count++] = NackBlock{rd16(f + off), rd16(f + off + 2)};
            off += 4;
        }
    } else if (pkt.type == Type::PSFB && pkt.count == static_cast<std::uint8_t>(PsfbFmt::Fir)) {
        std::size_t off = 0;
        while (off + 8 <= n) {
            if (pkt.fir_count >= kMaxFirEntries) return RtcpError::TooManyBlocks;
            pkt.fir[pkt.fir_count++] = FirEntry{rd32(f + off), f[off + 4]};
            off += 8;
        }
    } else if (pkt.type == Type::PSFB && pkt.count == static_cast<std::uint8_t>(PsfbFmt::Remb)) {
        // "REMB" magic(4) | num-ssrc(1) | exp(6b)+mantissa(18b) | ssrc[]...
        if (n >= 8 && std::memcmp(f, "REMB", 4) == 0) {
            const std::uint8_t num = f[4];
            const std::uint32_t em = rd24(f + 5);
            const std::uint32_t exp = (em >> 18) & 0x3F;
            const std::uint32_t mant = em & 0x3FFFF;
            pkt.remb_bitrate_bps = mant << exp;
            std::size_t off = 8;
            for (std::uint8_t i = 0; i < num && off + 4 <= n; ++i) {
                if (pkt.remb_ssrc_count >= kMaxFirEntries) break;
                pkt.remb_ssrcs[pkt.remb_ssrc_count++] = rd32(f + off);
                off += 4;
            }
        }
    }
    // PLI / TWCC: no further structured body (TWCC raw FCI is exposed via fci/fci_len).
    return RtcpError::Ok;
}

// Parse the first SDES chunk's items (zero-copy).
inline RtcpError parse_sdes(Packet& pkt, const std::uint8_t* p,
                            std::size_t avail) noexcept {
    assert(p != nullptr || avail == 0);
    assert(pkt.sdes_count == 0);
    if (avail < 4) return RtcpError::TooShort;
    pkt.ssrc = rd32(p);
    std::size_t off = 4;
    while (off < avail) {
        const std::uint8_t t = p[off++];
        if (t == 0) break;                       // end of items for this chunk
        if (off >= avail) return RtcpError::TooShort;
        const std::uint8_t l = p[off++];
        if (off + l > avail) return RtcpError::TooShort;
        if (pkt.sdes_count >= kMaxSdesItems) return RtcpError::TooManyBlocks;
        pkt.sdes[pkt.sdes_count++] =
            SdesItem{static_cast<SdesType>(t),
                     reinterpret_cast<const char*>(p + off), l};
        off += l;
    }
    return RtcpError::Ok;
}

}  // namespace detail

// ----------------------------------------------------------------------------
// parse_one — decode a single RTCP packet beginning at data[0..len). Sets
// out.raw_len to the on-wire size of this packet (4 + length*4). Zero-copy.
// ----------------------------------------------------------------------------
inline RtcpError parse_one(const std::uint8_t* data, std::size_t len,
                           Packet& out) noexcept {
    assert(data != nullptr || len == 0);
    assert(kCommonHeader == 4);
    if (data == nullptr || len < kCommonHeader) return RtcpError::TooShort;

    out = Packet{};
    const std::uint8_t version = static_cast<std::uint8_t>((data[0] >> 6) & 0x03);
    if (version != kVersion) return RtcpError::BadVersion;
    out.padding = ((data[0] >> 5) & 0x01) != 0;
    out.count   = static_cast<std::uint8_t>(data[0] & 0x1F);
    out.type    = static_cast<Type>(data[1]);
    const std::uint16_t length_words = detail::rd16(data + 2);
    const std::size_t   pkt_len = (static_cast<std::size_t>(length_words) + 1) * 4;
    if (pkt_len > len) return RtcpError::BadLength;
    out.raw     = data;
    out.raw_len = pkt_len;

    const std::uint8_t* body = data + kCommonHeader;
    const std::size_t   body_len = pkt_len - kCommonHeader;

    switch (out.type) {
        case Type::SR: {
            if (body_len < 24) return RtcpError::TooShort;
            out.ssrc          = detail::rd32(body);
            out.ntp_timestamp = detail::rd64(body + 4);
            out.rtp_timestamp = detail::rd32(body + 12);
            out.packet_count  = detail::rd32(body + 16);
            out.octet_count   = detail::rd32(body + 20);
            return detail::parse_report_blocks(out, body + 24, out.count, body_len - 24);
        }
        case Type::RR: {
            if (body_len < 4) return RtcpError::TooShort;
            out.ssrc = detail::rd32(body);
            return detail::parse_report_blocks(out, body + 4, out.count, body_len - 4);
        }
        case Type::SDES:
            return detail::parse_sdes(out, body, body_len);
        case Type::BYE: {
            std::size_t off = 0;
            for (std::uint8_t i = 0; i < out.count; ++i) {
                if (off + 4 > body_len) return RtcpError::TooShort;
                if (out.bye_count >= kMaxByeSources) return RtcpError::TooManyBlocks;
                out.bye_sources[out.bye_count++] = detail::rd32(body + off);
                off += 4;
            }
            return RtcpError::Ok;
        }
        case Type::APP: {
            if (body_len < 8) return RtcpError::TooShort;
            out.ssrc    = detail::rd32(body);
            out.fci     = body + 8;  // name(4) consumed; expose data after name
            out.fci_len = static_cast<std::uint16_t>(body_len - 8);
            return RtcpError::Ok;
        }
        case Type::RTPFB:
        case Type::PSFB: {
            if (body_len < 8) return RtcpError::TooShort;
            out.ssrc       = detail::rd32(body);      // packet sender
            out.media_ssrc = detail::rd32(body + 4);  // media source
            out.fci        = body + 8;
            out.fci_len    = static_cast<std::uint16_t>(body_len - 8);
            return detail::parse_feedback_body(out);
        }
    }
    return RtcpError::WrongType;
}

// ----------------------------------------------------------------------------
// parse_compound — decode all RTCP packets in a datagram. Bounded by kMaxPackets.
// ----------------------------------------------------------------------------
inline RtcpError parse_compound(const std::uint8_t* data, std::size_t len,
                                Compound& out) noexcept {
    assert(data != nullptr || len == 0);
    assert(kMaxPackets > 0);
    out.count = 0;
    std::size_t off = 0;
    while (off + kCommonHeader <= len) {
        if (out.count >= kMaxPackets) return RtcpError::TooManyPackets;
        Packet& pkt = out.packets[out.count];
        const RtcpError e = parse_one(data + off, len - off, pkt);
        if (e != RtcpError::Ok) return e;
        ++out.count;
        off += pkt.raw_len;
    }
    return RtcpError::Ok;
}

// ============================================================================
// Builder — append RTCP packets into a caller buffer. No heap; each add_* writes
// a full RTCP packet and patches its length word. size() is the total.
// ============================================================================
class Builder {
public:
    Builder(std::uint8_t* buffer, std::size_t capacity) noexcept
        : buf_(buffer), cap_(capacity) {
        assert(buffer != nullptr);
        assert(capacity >= kCommonHeader);
    }

    std::size_t size() const noexcept { return len_; }

    // Sender Report. `blocks` may be null when count==0.
    RtcpError add_sr(std::uint32_t ssrc, std::uint64_t ntp, std::uint32_t rtp_ts,
                     std::uint32_t pkt_count, std::uint32_t octet_count,
                     const ReportBlock* blocks, std::size_t count) noexcept {
        assert(count <= kMaxReportBlocks);
        assert(blocks != nullptr || count == 0);
        if (count > kMaxReportBlocks) return RtcpError::TooManyBlocks;
        const std::size_t body = 24 + count * kReportBlockLen;
        std::uint8_t* p = begin(Type::SR, static_cast<std::uint8_t>(count), body);
        if (!p) return RtcpError::BufferTooSmall;
        detail::wr32(p, ssrc);
        detail::wr64(p + 4, ntp);
        detail::wr32(p + 12, rtp_ts);
        detail::wr32(p + 16, pkt_count);
        detail::wr32(p + 20, octet_count);
        write_blocks(p + 24, blocks, count);
        return commit(body);
    }

    // Receiver Report.
    RtcpError add_rr(std::uint32_t ssrc, const ReportBlock* blocks,
                     std::size_t count) noexcept {
        assert(count <= kMaxReportBlocks);
        assert(blocks != nullptr || count == 0);
        if (count > kMaxReportBlocks) return RtcpError::TooManyBlocks;
        const std::size_t body = 4 + count * kReportBlockLen;
        std::uint8_t* p = begin(Type::RR, static_cast<std::uint8_t>(count), body);
        if (!p) return RtcpError::BufferTooSmall;
        detail::wr32(p, ssrc);
        write_blocks(p + 4, blocks, count);
        return commit(body);
    }

    // SDES with a single chunk (the common case: our own CNAME etc.).
    RtcpError add_sdes(std::uint32_t ssrc, const SdesItem* items,
                       std::size_t count) noexcept {
        assert(items != nullptr || count == 0);
        assert(count <= kMaxSdesItems);
        if (count > kMaxSdesItems) return RtcpError::TooManyBlocks;
        std::size_t body = 4;  // SSRC
        for (std::size_t i = 0; i < count; ++i) body += 2 + items[i].length;
        body += 1;             // END item
        const std::size_t padded = (body + 3) & ~std::size_t(3);
        std::uint8_t* p = begin(Type::SDES, 1, padded);
        if (!p) return RtcpError::BufferTooSmall;
        std::memset(p, 0, padded);
        detail::wr32(p, ssrc);
        std::size_t off = 4;
        for (std::size_t i = 0; i < count; ++i) {
            p[off++] = static_cast<std::uint8_t>(items[i].type);
            p[off++] = items[i].length;
            if (items[i].length) std::memcpy(p + off, items[i].text, items[i].length);
            off += items[i].length;
        }
        // remaining bytes already zero (END item + padding)
        return commit(padded);
    }

    // BYE with a source list.
    RtcpError add_bye(const std::uint32_t* sources, std::size_t count) noexcept {
        assert(sources != nullptr || count == 0);
        assert(count <= kMaxByeSources);
        if (count > kMaxByeSources) return RtcpError::TooManyBlocks;
        const std::size_t body = count * 4;
        std::uint8_t* p = begin(Type::BYE, static_cast<std::uint8_t>(count), body);
        if (!p) return RtcpError::BufferTooSmall;
        for (std::size_t i = 0; i < count; ++i) detail::wr32(p + i * 4, sources[i]);
        return commit(body);
    }

    // APP packet: 4-char name + data.
    RtcpError add_app(std::uint8_t subtype, std::uint32_t ssrc,
                      const char name[4], const std::uint8_t* data,
                      std::size_t data_len) noexcept {
        assert(name != nullptr);
        assert(data != nullptr || data_len == 0);
        const std::size_t padded = (data_len + 3) & ~std::size_t(3);
        const std::size_t body = 8 + padded;
        std::uint8_t* p = begin(Type::APP, subtype & 0x1F, body);
        if (!p) return RtcpError::BufferTooSmall;
        detail::wr32(p, ssrc);
        std::memcpy(p + 4, name, 4);
        if (data_len) std::memcpy(p + 8, data, data_len);
        for (std::size_t i = data_len; i < padded; ++i) p[8 + i] = 0;
        return commit(body);
    }

    // Generic transport-layer feedback (RTPFB) with a raw FCI.
    RtcpError add_rtpfb(RtpfbFmt fmt, std::uint32_t sender, std::uint32_t media,
                        const std::uint8_t* fci, std::size_t fci_len) noexcept {
        return add_feedback(Type::RTPFB, static_cast<std::uint8_t>(fmt),
                            sender, media, fci, fci_len);
    }
    // Generic payload-specific feedback (PSFB) with a raw FCI.
    RtcpError add_psfb(PsfbFmt fmt, std::uint32_t sender, std::uint32_t media,
                       const std::uint8_t* fci, std::size_t fci_len) noexcept {
        return add_feedback(Type::PSFB, static_cast<std::uint8_t>(fmt),
                            sender, media, fci, fci_len);
    }

    // NACK (RTPFB FMT 1) from a list of NackBlocks.
    RtcpError add_nack(std::uint32_t sender, std::uint32_t media,
                       const NackBlock* blocks, std::size_t count) noexcept {
        assert(blocks != nullptr || count == 0);
        assert(count <= kMaxNackBlocks);
        if (count > kMaxNackBlocks) return RtcpError::TooManyBlocks;
        std::uint8_t tmp[kMaxNackBlocks * 4];
        for (std::size_t i = 0; i < count; ++i) {
            detail::wr16(tmp + i * 4, blocks[i].pid);
            detail::wr16(tmp + i * 4 + 2, blocks[i].blp);
        }
        return add_rtpfb(RtpfbFmt::Nack, sender, media, tmp, count * 4);
    }

    // PLI (PSFB FMT 1) — no FCI.
    RtcpError add_pli(std::uint32_t sender, std::uint32_t media) noexcept {
        assert(buf_ != nullptr);
        assert(cap_ >= kCommonHeader);
        return add_psfb(PsfbFmt::Pli, sender, media, nullptr, 0);
    }

    // FIR (PSFB FMT 4) from a list of FirEntries.
    RtcpError add_fir(std::uint32_t sender, std::uint32_t media,
                      const FirEntry* entries, std::size_t count) noexcept {
        assert(entries != nullptr || count == 0);
        assert(count <= kMaxFirEntries);
        if (count > kMaxFirEntries) return RtcpError::TooManyBlocks;
        std::uint8_t tmp[kMaxFirEntries * 8];
        for (std::size_t i = 0; i < count; ++i) {
            detail::wr32(tmp + i * 8, entries[i].ssrc);
            tmp[i * 8 + 4] = entries[i].seq;
            tmp[i * 8 + 5] = 0; tmp[i * 8 + 6] = 0; tmp[i * 8 + 7] = 0;  // reserved
        }
        return add_psfb(PsfbFmt::Fir, sender, media, tmp, count * 8);
    }

    // REMB (PSFB FMT 15, "goog-remb").
    RtcpError add_remb(std::uint32_t sender, std::uint32_t bitrate_bps,
                       const std::uint32_t* ssrcs, std::size_t count) noexcept {
        assert(ssrcs != nullptr || count == 0);
        assert(count <= kMaxFirEntries);
        if (count > kMaxFirEntries) return RtcpError::TooManyBlocks;
        std::uint8_t tmp[8 + kMaxFirEntries * 4];
        std::memcpy(tmp, "REMB", 4);
        tmp[4] = static_cast<std::uint8_t>(count);
        // pack bitrate as 6-bit exp + 18-bit mantissa
        std::uint32_t exp = 0, mant = bitrate_bps;
        while (mant > 0x3FFFF) { mant >>= 1; ++exp; }
        const std::uint32_t em = (exp << 18) | (mant & 0x3FFFF);
        detail::wr24(tmp + 5, em);
        for (std::size_t i = 0; i < count; ++i) detail::wr32(tmp + 8 + i * 4, ssrcs[i]);
        return add_psfb(PsfbFmt::Remb, sender, 0, tmp, 8 + count * 4);
    }

    // TWCC (RTPFB FMT 15) — raw transport-cc FCI built by the caller.
    RtcpError add_twcc(std::uint32_t sender, std::uint32_t media,
                       const std::uint8_t* fci, std::size_t fci_len) noexcept {
        assert(fci != nullptr || fci_len == 0);
        assert(fci_len <= 0xFFFF);
        return add_rtpfb(RtpfbFmt::Twcc, sender, media, fci, fci_len);
    }

private:
    // Reserve a packet header + body; return a pointer to the body or nullptr.
    std::uint8_t* begin(Type t, std::uint8_t count, std::size_t body_len) noexcept {
        assert(body_len % 4 == 0);
        assert((count & 0xE0) == 0);
        const std::size_t total = kCommonHeader + body_len;
        if (len_ + total > cap_) return nullptr;
        std::uint8_t* h = buf_ + len_;
        h[0] = static_cast<std::uint8_t>((kVersion << 6) | (count & 0x1F));
        h[1] = static_cast<std::uint8_t>(t);
        detail::wr16(h + 2, static_cast<std::uint16_t>(body_len / 4));  // (total/4 - 1)
        return h + kCommonHeader;
    }

    RtcpError commit(std::size_t body_len) noexcept {
        assert(body_len % 4 == 0);
        assert(len_ + kCommonHeader + body_len <= cap_);
        len_ += kCommonHeader + body_len;
        return RtcpError::Ok;
    }

    void write_blocks(std::uint8_t* p, const ReportBlock* blocks,
                      std::size_t count) noexcept {
        assert(p != nullptr || count == 0);
        assert(count <= kMaxReportBlocks);
        for (std::size_t i = 0; i < count; ++i) {
            std::uint8_t* b = p + i * kReportBlockLen;
            detail::wr32(b, blocks[i].ssrc);
            b[4] = blocks[i].fraction_lost;
            detail::wr24(b + 5, static_cast<std::uint32_t>(blocks[i].cumulative_lost) & 0xFFFFFFu);
            detail::wr32(b + 8, blocks[i].highest_seq);
            detail::wr32(b + 12, blocks[i].jitter);
            detail::wr32(b + 16, blocks[i].lsr);
            detail::wr32(b + 20, blocks[i].dlsr);
        }
    }

    RtcpError add_feedback(Type t, std::uint8_t fmt, std::uint32_t sender,
                           std::uint32_t media, const std::uint8_t* fci,
                           std::size_t fci_len) noexcept {
        assert(t == Type::RTPFB || t == Type::PSFB);
        assert(fci != nullptr || fci_len == 0);
        const std::size_t padded = (fci_len + 3) & ~std::size_t(3);
        const std::size_t body = 8 + padded;
        std::uint8_t* p = begin(t, fmt, body);
        if (!p) return RtcpError::BufferTooSmall;
        detail::wr32(p, sender);
        detail::wr32(p + 4, media);
        if (fci_len) std::memcpy(p + 8, fci, fci_len);
        for (std::size_t i = fci_len; i < padded; ++i) p[8 + i] = 0;
        return commit(body);
    }

    std::uint8_t* buf_;
    std::size_t   cap_;
    std::size_t   len_ = 0;
};

}  // namespace rtcp
}  // namespace webrtc
}  // namespace bolt::api
