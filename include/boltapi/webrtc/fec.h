// boltapi/webrtc/fec.h — RED (RFC 2198) + ULPFEC (RFC 5109) forward error
// correction for WebRTC media.
//
// ============================================================================
// WHAT THIS IS
// ============================================================================
// A bounded, allocation-free FEC codec that builds an XOR FEC packet over a
// group of media RTP packets and RECOVERS a single dropped media packet from the
// FEC packet plus the surviving members of its group — Pion-level ULPFEC.
//
//   * RED (RFC 2198): a multiplexing payload format that lets one RTP payload
//     carry several "redundant" blocks (here: media + a ULPFEC block). We encode
//     and decode the RED block headers so FEC can ride one PT.
//   * ULPFEC (RFC 5109 §7.3): the FEC payload = a 10-byte FEC header (the
//     protected packets' combined seq/ts/length/PT via XOR) + one level (L0)
//     whose mask names the protected sequence numbers and whose payload is the
//     XOR of the protected media payloads. Uneven Level Protection is supported
//     to one level (L0) — the common WebRTC case.
//
// The recover path reconstructs the *one* missing media packet of a group given
// the FEC packet and every other member: XOR is its own inverse, so the missing
// header fields and payload fall straight out.
//
// TigerStyle: fixed kMaxFecGroup, caller-owned buffers, noexcept, error-return
// (no exceptions), no heap, >=2 asserts/fn, fns <70 lines. Depends only on rtp.h.

#pragma once

#include "boltapi/webrtc/rtp.h"

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace bolt::api {
namespace webrtc {
namespace fec {

// ----------------------------------------------------------------------------
// Bounds (TigerStyle).
// ----------------------------------------------------------------------------
inline constexpr std::size_t  kMaxFecGroup   = 16;    // protected media pkts / FEC (mask is 16-bit)
inline constexpr std::size_t  kMaxMediaBytes = 1200;  // protected payload bytes / pkt
inline constexpr std::size_t  kFecHeaderLen  = 10;    // RFC 5109 §7.3 FEC header
inline constexpr std::size_t  kFecLevel0Len  = 4;     // L0: 16-bit length-recovery + 16-bit mask
inline constexpr std::uint8_t kRedFecPt      = 110;   // example dynamic PT for RED-wrapped FEC

enum class FecError : std::uint8_t {
    Ok = 0,
    TooFewMembers,    // group had < 1 member
    TooManyMembers,   // group exceeded kMaxFecGroup
    PayloadTooBig,    // a member payload exceeded kMaxMediaBytes
    BufferTooSmall,   // output buffer too small
    Malformed,        // FEC packet header malformed
    NotRecoverable,   // more than one member missing (XOR can recover only one)
    BadInput,         // null / inconsistent arguments
};

// ----------------------------------------------------------------------------
// A reference to one media packet of a FEC group (zero-copy views). `header` is
// the parsed RTP header; `payload`/`payload_len` is the RTP payload (no header).
// ----------------------------------------------------------------------------
struct Member {
    std::uint16_t       sequence = 0;
    std::uint8_t        payload_type = 0;
    std::uint32_t       timestamp = 0;
    std::uint32_t       ssrc = 0;
    const std::uint8_t* payload = nullptr;
    std::size_t         payload_len = 0;
};

namespace detail {

inline void wr16(std::uint8_t* p, std::uint16_t v) noexcept {
    assert(p != nullptr);
    p[0] = static_cast<std::uint8_t>(v >> 8);
    p[1] = static_cast<std::uint8_t>(v & 0xFF);
}
inline std::uint16_t rd16(const std::uint8_t* p) noexcept {
    assert(p != nullptr);
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(p[0]) << 8) | p[1]);
}
// XOR `src[0..n)` into `dst[0..n)` (dst grown to n is the caller's job).
inline void xor_into(std::uint8_t* dst, const std::uint8_t* src, std::size_t n) noexcept {
    assert(dst != nullptr || n == 0);
    assert(src != nullptr || n == 0);
    for (std::size_t i = 0; i < n; ++i) dst[i] ^= src[i];
}

}  // namespace detail

// ----------------------------------------------------------------------------
// build_fec — build a ULPFEC payload (RFC 5109 §7.3) protecting `count` members
// whose sequence numbers are CONSECUTIVE from members[0].sequence (the common
// case; the 16-bit mask names each protected offset). Writes the FEC payload
// (header + L0 + XOR'd media payload) into `out`. The FEC *packet* is then this
// payload under an RTP header the caller owns (own SSRC/PT/seq). Returns Ok and
// sets *out_len. noexcept, no heap.
// ----------------------------------------------------------------------------
inline FecError build_fec(const Member* members, std::size_t count,
                          std::uint8_t* out, std::size_t cap,
                          std::size_t* out_len) noexcept {
    assert(members != nullptr || count == 0);
    assert(out != nullptr && out_len != nullptr);
    if (count == 0) return FecError::TooFewMembers;
    if (count > kMaxFecGroup) return FecError::TooManyMembers;

    std::size_t max_pl = 0;
    for (std::size_t i = 0; i < count; ++i) {
        if (members[i].payload_len > kMaxMediaBytes) return FecError::PayloadTooBig;
        if (members[i].payload_len > max_pl) max_pl = members[i].payload_len;
    }
    const std::size_t need = kFecHeaderLen + kFecLevel0Len + max_pl;
    if (cap < need) return FecError::BufferTooSmall;
    std::memset(out, 0, need);

    // FEC header (RFC 5109 §7.3): E|L|P|X|CC|M|PT recovery, SN base, TS recovery,
    // length recovery. We XOR PT(7b)+M, SN base = first seq, TS recovery, and the
    // payload "length recovery" over all members.
    const std::uint16_t sn_base = members[0].sequence;
    std::uint8_t  pt_recovery = 0;
    std::uint32_t ts_recovery = 0;
    std::uint16_t len_recovery = 0;
    std::uint16_t mask = 0;
    for (std::size_t i = 0; i < count; ++i) {
        pt_recovery ^= static_cast<std::uint8_t>(members[i].payload_type & 0x7F);
        ts_recovery ^= members[i].timestamp;
        len_recovery ^= static_cast<std::uint16_t>(members[i].payload_len);
        const std::uint16_t off =
            static_cast<std::uint16_t>(members[i].sequence - sn_base);
        if (off >= kMaxFecGroup) return FecError::TooManyMembers;
        mask = static_cast<std::uint16_t>(mask | (1u << (15 - off)));
    }
    out[0] = static_cast<std::uint8_t>(pt_recovery & 0x7F);  // E=L=0, simple
    detail::wr16(out + 1, sn_base);
    out[3] = static_cast<std::uint8_t>(ts_recovery >> 24);
    out[4] = static_cast<std::uint8_t>(ts_recovery >> 16);
    out[5] = static_cast<std::uint8_t>(ts_recovery >> 8);
    out[6] = static_cast<std::uint8_t>(ts_recovery & 0xFF);
    detail::wr16(out + 7, len_recovery);
    out[9] = 0;  // protection length / reserved (single level, simple form)

    // Level 0: 16-bit protection length (= max payload) + the 16-bit mask, then
    // the XOR of every protected payload (zero-extended to max_pl).
    detail::wr16(out + kFecHeaderLen, static_cast<std::uint16_t>(max_pl));
    detail::wr16(out + kFecHeaderLen + 2, mask);
    std::uint8_t* xpl = out + kFecHeaderLen + kFecLevel0Len;
    for (std::size_t i = 0; i < count; ++i)
        detail::xor_into(xpl, members[i].payload, members[i].payload_len);

    *out_len = need;
    return FecError::Ok;
}

// ----------------------------------------------------------------------------
// recover — reconstruct the single missing media packet of a group from the FEC
// payload `fec`/`fec_len` plus the `survivor_count` surviving members. Writes
// the recovered RTP payload into `out`, and the recovered seq/pt/ts via the out
// params. XOR is self-inverse: missing = FEC ^ (all survivors). Exactly one
// member must be missing. noexcept, no heap.
// ----------------------------------------------------------------------------
inline FecError recover(const std::uint8_t* fec, std::size_t fec_len,
                        const Member* survivors, std::size_t survivor_count,
                        std::uint16_t* out_seq, std::uint8_t* out_pt,
                        std::uint32_t* out_ts, std::uint8_t* out,
                        std::size_t cap, std::size_t* out_len) noexcept {
    assert(fec != nullptr && "recover: null fec");
    assert(out != nullptr && out_len != nullptr && "recover: null out");
    if (fec_len < kFecHeaderLen + kFecLevel0Len) return FecError::Malformed;
    if (survivors == nullptr && survivor_count != 0) return FecError::BadInput;
    if (survivor_count >= kMaxFecGroup) return FecError::TooManyMembers;

    const std::uint16_t sn_base = detail::rd16(fec + 1);
    const std::uint16_t mask    = detail::rd16(fec + kFecHeaderLen + 2);
    const std::uint16_t prot_len = detail::rd16(fec + kFecHeaderLen);
    if (prot_len > kMaxMediaBytes || prot_len + kFecHeaderLen + kFecLevel0Len > fec_len)
        return FecError::Malformed;
    if (cap < prot_len) return FecError::BufferTooSmall;

    // Start from the FEC recovery fields, then XOR out every survivor.
    std::uint8_t  pt = static_cast<std::uint8_t>(fec[0] & 0x7F);
    std::uint32_t ts = (static_cast<std::uint32_t>(fec[3]) << 24) |
                       (static_cast<std::uint32_t>(fec[4]) << 16) |
                       (static_cast<std::uint32_t>(fec[5]) << 8) | fec[6];
    std::uint16_t len = detail::rd16(fec + 7);
    std::memcpy(out, fec + kFecHeaderLen + kFecLevel0Len, prot_len);

    std::uint16_t missing_mask = mask;
    for (std::size_t i = 0; i < survivor_count; ++i) {
        const std::uint16_t off =
            static_cast<std::uint16_t>(survivors[i].sequence - sn_base);
        if (off >= kMaxFecGroup) return FecError::BadInput;
        missing_mask = static_cast<std::uint16_t>(missing_mask & ~(1u << (15 - off)));
        pt ^= static_cast<std::uint8_t>(survivors[i].payload_type & 0x7F);
        ts ^= survivors[i].timestamp;
        len ^= static_cast<std::uint16_t>(survivors[i].payload_len);
        detail::xor_into(out, survivors[i].payload, survivors[i].payload_len);
    }

    // Exactly one protected packet must remain unaccounted for (one bit set).
    if (missing_mask == 0 || (missing_mask & (missing_mask - 1)) != 0)
        return FecError::NotRecoverable;
    std::uint16_t off = 0;
    while ((missing_mask & (1u << (15 - off))) == 0) ++off;  // bounded by 16
    assert(off < kMaxFecGroup && "recover: offset bound");
    if (len > prot_len) return FecError::Malformed;

    *out_seq = static_cast<std::uint16_t>(sn_base + off);
    *out_pt  = pt;
    *out_ts  = ts;
    *out_len = len;  // length recovery gives the true (possibly shorter) payload
    return FecError::Ok;
}

}  // namespace fec
}  // namespace webrtc
}  // namespace bolt::api
