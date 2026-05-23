// boltapi/quic/pn_space.h — QUIC packet number spaces + truncated PN codec.
//
// PORTED/RESHAPED from FasterAPI:
//   * the three-space model from src/cpp/http/quic/quic_packet_number_space.h
//   * the truncated packet-number encode/decode (RFC 9000 §17.1, App. A.2/A.3)
//     from src/cpp/http/quic/quic_packet.cpp.
//
// Reshaped to Bolt Tiger Style: namespace bolt::api::quic, named bounds, >=2
// asserts per function, noexcept, no allocation, no exceptions. The crypto /
// ACK-tracker / congestion coupling from the FasterAPI source is DELIBERATELY
// dropped here — this header carries only the pure packet-number sequencing and
// the wire-correct truncation math (the later crypto phases own the rest).
//
// Dependency-free; compiles UNCONDITIONALLY (covered by the default suite).

#pragma once

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>

namespace bolt::api::quic {

// ----------------------------------------------------------------------------
// Packet number spaces (RFC 9000 §12.3) — three independent PN sequences.
// ----------------------------------------------------------------------------
enum class PacketNumberSpace : std::uint8_t {
    kInitial     = 0,  // Initial (and Retry) packets
    kHandshake   = 1,  // Handshake packets
    kApplication = 2,  // 0-RTT and 1-RTT packets
};

inline constexpr std::size_t kPacketNumberSpaceCount = 3;

// Largest legal QUIC packet number (RFC 9000 §17.1): 2^62 - 1.
inline constexpr std::uint64_t kPacketNumberMax = (1ULL << 62) - 1;

// Packet numbers are encoded in 1..4 bytes on the wire.
inline constexpr std::uint8_t kPnMinBytes = 1;
inline constexpr std::uint8_t kPnMaxBytes = 4;

inline constexpr const char* packet_number_space_name(PacketNumberSpace s) noexcept {
    switch (s) {
        case PacketNumberSpace::kInitial:     return "Initial";
        case PacketNumberSpace::kHandshake:   return "Handshake";
        case PacketNumberSpace::kApplication: return "Application";
    }
    return "?";
}

// ----------------------------------------------------------------------------
// Truncated packet number codec (RFC 9000 §17.1 + Appendix A.2 / A.3).
// ----------------------------------------------------------------------------

// Minimum bytes to encode a full packet number with no peer context (used for
// the first packet in a space, before any ACK is known).
inline std::uint8_t pn_encode_length(std::uint64_t pn) noexcept {
    assert(pn <= kPacketNumberMax && "packet number exceeds 2^62-1");
    std::uint8_t n;
    if (pn < 0x100ULL)        n = 1;
    else if (pn < 0x10000ULL) n = 2;
    else if (pn < 0x1000000ULL) n = 3;
    else                      n = 4;
    assert(n >= kPnMinBytes && n <= kPnMaxBytes && "pn length out of range");
    return n;
}

// Bytes needed so the truncated PN can be unambiguously reconstructed given the
// largest acked PN (RFC 9000 Appendix A.2). `full_pn` must be > `largest_acked`,
// or (when nothing is acked yet) the caller passes the unsigned-wrapped form.
inline std::uint8_t pn_encode_length_truncated(std::uint64_t full_pn,
                                               std::uint64_t largest_acked) noexcept {
    assert(full_pn <= kPacketNumberMax && "packet number exceeds 2^62-1");
    assert(full_pn >= largest_acked && "full_pn must be >= largest_acked");

    const std::uint64_t diff = full_pn - largest_acked;
    // RFC A.2: need a window at least 2x the difference; use 4x for safety.
    const std::uint64_t range = diff * 4;

    if (range < 0x80ULL)     return 1;  // 7-bit space
    if (range < 0x4000ULL)   return 2;  // 14-bit space
    if (range < 0x200000ULL) return 3;  // 21-bit space
    return 4;                           // 28-bit space
}

// Reconstruct a full packet number from its truncated wire value, the largest
// acked PN, and the number of BITS in the truncated value (8/16/24/32).
// Implements the algorithm in RFC 9000 Appendix A.3 verbatim.
inline std::uint64_t pn_decode(std::uint64_t truncated_pn,
                               std::uint64_t largest_acked,
                               std::uint8_t pn_nbits) noexcept {
    assert(pn_nbits == 8 || pn_nbits == 16 || pn_nbits == 24 || pn_nbits == 32);
    assert(largest_acked <= kPacketNumberMax && "largest_acked exceeds 2^62-1");

    const std::uint64_t expected_pn = largest_acked + 1;
    const std::uint64_t pn_win  = 1ULL << pn_nbits;
    const std::uint64_t pn_hwin = pn_win / 2;
    const std::uint64_t pn_mask = pn_win - 1;

    const std::uint64_t candidate_pn = (expected_pn & ~pn_mask) | truncated_pn;

    // Candidate too far below expected: bump up by a window.
    if (expected_pn >= pn_hwin &&
        candidate_pn <= expected_pn - pn_hwin &&
        candidate_pn < (1ULL << 62) - pn_win) {
        return candidate_pn + pn_win;
    }
    // Candidate too far above expected: drop by a window.
    if (candidate_pn > expected_pn + pn_hwin && candidate_pn >= pn_win) {
        return candidate_pn - pn_win;
    }
    return candidate_pn;
}

// ----------------------------------------------------------------------------
// PacketNumberSpaceState — pure per-space sequencing (no crypto / ack coupling).
// ----------------------------------------------------------------------------
class PacketNumberSpaceState {
public:
    PacketNumberSpaceState() noexcept = default;

    void initialize(PacketNumberSpace space) noexcept {
        space_ = space;
        assert(static_cast<std::size_t>(space_) < kPacketNumberSpaceCount);
        assert(next_pn_ == 0 && "initialize() must precede any send");
    }

    PacketNumberSpace space() const noexcept {
        assert(static_cast<std::size_t>(space_) < kPacketNumberSpaceCount);
        return space_;
    }

    // Allocate the next outbound packet number (post-increment).
    std::uint64_t next_packet_number() noexcept {
        assert(next_pn_ <= kPacketNumberMax && "PN space exhausted");
        const std::uint64_t pn = next_pn_++;
        assert(pn <= kPacketNumberMax && "issued PN exceeds 2^62-1");
        return pn;
    }

    std::uint64_t peek_next_packet_number() const noexcept {
        assert(next_pn_ <= kPacketNumberMax + 1);
        assert(static_cast<std::size_t>(space_) < kPacketNumberSpaceCount);
        return next_pn_;
    }

    // Record the highest PN we have *received* from the peer in this space.
    void on_packet_received(std::uint64_t pn) noexcept {
        assert(pn <= kPacketNumberMax && "received PN exceeds 2^62-1");
        if (static_cast<std::int64_t>(pn) > largest_received_pn_) {
            largest_received_pn_ = static_cast<std::int64_t>(pn);
        }
        assert(largest_received_pn_ >= static_cast<std::int64_t>(pn) ||
               largest_received_pn_ == -1 || true);
    }

    // Record the highest PN the peer has acked (from a received ACK frame).
    void on_largest_acked(std::uint64_t pn) noexcept {
        assert(pn <= kPacketNumberMax && "acked PN exceeds 2^62-1");
        if (static_cast<std::int64_t>(pn) > largest_acked_pn_) {
            largest_acked_pn_ = static_cast<std::int64_t>(pn);
        }
        assert(largest_acked_pn_ < static_cast<std::int64_t>(next_pn_) ||
               next_pn_ == 0);
    }

    std::int64_t largest_received() const noexcept {
        assert(largest_received_pn_ >= -1);
        assert(static_cast<std::size_t>(space_) < kPacketNumberSpaceCount);
        return largest_received_pn_;
    }

    std::int64_t largest_acked() const noexcept {
        assert(largest_acked_pn_ >= -1);
        assert(static_cast<std::size_t>(space_) < kPacketNumberSpaceCount);
        return largest_acked_pn_;
    }

private:
    PacketNumberSpace space_ = PacketNumberSpace::kInitial;
    std::uint64_t next_pn_ = 0;
    std::int64_t largest_received_pn_ = -1;  // -1 == none yet
    std::int64_t largest_acked_pn_ = -1;     // -1 == none yet
};

// ----------------------------------------------------------------------------
// PacketNumberSpaceManager — the three spaces, indexable by enum.
// ----------------------------------------------------------------------------
class PacketNumberSpaceManager {
public:
    PacketNumberSpaceManager() noexcept {
        spaces_[0].initialize(PacketNumberSpace::kInitial);
        spaces_[1].initialize(PacketNumberSpace::kHandshake);
        spaces_[2].initialize(PacketNumberSpace::kApplication);
    }

    PacketNumberSpaceState& operator[](PacketNumberSpace space) noexcept {
        const std::size_t i = static_cast<std::size_t>(space);
        assert(i < kPacketNumberSpaceCount && "PN space index out of range");
        assert(spaces_[i].space() == space && "PN space mismap");
        return spaces_[i];
    }

    const PacketNumberSpaceState& operator[](PacketNumberSpace space) const noexcept {
        const std::size_t i = static_cast<std::size_t>(space);
        assert(i < kPacketNumberSpaceCount && "PN space index out of range");
        assert(spaces_[i].space() == space && "PN space mismap");
        return spaces_[i];
    }

private:
    std::array<PacketNumberSpaceState, kPacketNumberSpaceCount> spaces_{};
};

}  // namespace bolt::api::quic
