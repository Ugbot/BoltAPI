// boltapi/webrtc/stun.h — STUN (RFC 5389 / RFC 8489) message codec.
//
// ============================================================================
// WHAT THIS IS
// ============================================================================
// A real STUN message parse + generate with the attributes ICE connectivity
// checks need. REBUILT from scratch (FasterAPI's STUNMessage handled only the
// 20-byte header, no attributes). Covers:
//
//   * Header: type / length / magic cookie (0x2112A442) / 96-bit transaction id
//   * Attribute TLV with 4-byte padding (RFC 5389 §15)
//   * MAPPED-ADDRESS, XOR-MAPPED-ADDRESS, USERNAME, MESSAGE-INTEGRITY
//     (HMAC-SHA1 over the message with the length fixup, RFC 5389 §15.4),
//     FINGERPRINT (CRC-32 XOR 0x5354554e, §15.5), ERROR-CODE, PRIORITY,
//     USE-CANDIDATE, ICE-CONTROLLING, ICE-CONTROLLED
//   * Binding request / response build + parse
//   * FINGERPRINT + MESSAGE-INTEGRITY verification
//
// Correctness is gated against the RFC 5769 test vectors (byte-exact).
//
// Compiled UNCONDITIONALLY into boltapi (pure codec, no engine deps). Crypto:
// OpenSSL HMAC for MESSAGE-INTEGRITY (libcrypto already linked); CRC-32 is a
// small self-contained table here.
//
// TigerStyle: bounded attribute count, fixed caller buffers (no heap in the
// parse hot path), noexcept, no throwing. The encoder writes into a caller
// buffer and reports the byte count; nothing here allocates.

#pragma once

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace bolt::api {
namespace webrtc {
namespace stun {

// ----------------------------------------------------------------------------
// Constants
// ----------------------------------------------------------------------------
inline constexpr std::uint32_t kMagicCookie    = 0x2112A442u;
inline constexpr std::size_t   kHeaderSize     = 20;
inline constexpr std::size_t   kTransactionIdLen = 12;  // 96 bits
inline constexpr std::uint32_t kFingerprintXor = 0x5354554Eu;  // RFC 5389 §15.5
inline constexpr std::size_t   kMaxAttributes  = 24;    // bounded attribute count

// Message classes (top 2 of the 14 message-type bits).
enum class Class : std::uint8_t {
    Request          = 0,
    Indication       = 1,
    SuccessResponse  = 2,
    ErrorResponse    = 3,
};

// Method (only Binding is needed for ICE; the field is 12 bits).
enum class Method : std::uint16_t {
    Binding = 0x001,
};

// Attribute types (RFC 5389 §18.2, RFC 8445).
enum class AttrType : std::uint16_t {
    MappedAddress    = 0x0001,
    Username         = 0x0006,
    MessageIntegrity = 0x0008,
    ErrorCode        = 0x0009,
    XorMappedAddress = 0x0020,
    Priority         = 0x0024,  // RFC 8445
    UseCandidate     = 0x0025,  // RFC 8445 (flag, length 0)
    Fingerprint      = 0x8028,
    IceControlled    = 0x8029,  // RFC 8445 (8-byte tiebreaker)
    IceControlling   = 0x802A,  // RFC 8445 (8-byte tiebreaker)
};

enum class StunError : std::uint8_t {
    Ok = 0,
    TooShort,         // buffer smaller than header / attribute claims
    BadMagicCookie,   // magic cookie mismatch
    BadLength,        // declared length inconsistent with buffer
    TooManyAttrs,     // exceeded kMaxAttributes
    BufferTooSmall,   // encode target buffer too small
    IntegrityFail,    // MESSAGE-INTEGRITY HMAC mismatch
    FingerprintFail,  // FINGERPRINT CRC mismatch
    NotFound,         // requested attribute absent
    BadAddress,       // malformed MAPPED/XOR-MAPPED-ADDRESS
};

// Address family for MAPPED-ADDRESS family attributes.
enum class Family : std::uint8_t { IPv4 = 0x01, IPv6 = 0x02 };

// A decoded transport address. For IPv4 only addr[0..3] are meaningful.
struct Address {
    Family        family = Family::IPv4;
    std::uint16_t port   = 0;
    std::uint8_t  addr[16]{};  // network byte order; IPv4 uses first 4 bytes
};

// One parsed attribute: type + a view into the source buffer (value, unpadded).
struct Attribute {
    AttrType            type{};
    const std::uint8_t* value = nullptr;  // points into the parsed message
    std::uint16_t       length = 0;       // value length (without padding)
};

// ----------------------------------------------------------------------------
// Message — a parsed STUN message. All attribute values are zero-copy views
// into the source buffer (which must outlive the Message). Fixed attribute
// array (TigerStyle: no heap).
// ----------------------------------------------------------------------------
struct Message {
    Class         msg_class{};
    Method        method{};
    std::uint16_t length = 0;  // attribute section length from the header
    std::uint8_t  transaction_id[kTransactionIdLen]{};

    Attribute   attrs[kMaxAttributes]{};
    std::size_t attr_count = 0;

    const std::uint8_t* raw = nullptr;  // start of the parsed buffer
    std::size_t         raw_len = 0;    // 20 + length

    const Attribute* find(AttrType t) const noexcept;
    bool has(AttrType t) const noexcept { return find(t) != nullptr; }

    // Decode XOR-MAPPED-ADDRESS (preferred) or MAPPED-ADDRESS into `out`.
    StunError mapped_address(Address* out) const noexcept;
    // PRIORITY (RFC 8445). false if absent/malformed.
    bool priority(std::uint32_t* out) const noexcept;
};

// ----------------------------------------------------------------------------
// parse — decode a STUN message from `data[0..len)` into `out`. Verifies the
// magic cookie and that the declared length is consistent. Zero-copy, noexcept,
// no allocation. Does NOT verify MESSAGE-INTEGRITY/FINGERPRINT (call the verify
// helpers explicitly — connectivity checks need to choose the credential).
// ----------------------------------------------------------------------------
StunError parse(const std::uint8_t* data, std::size_t len, Message& out) noexcept;

// ----------------------------------------------------------------------------
// Builder — encode a STUN message into a caller-provided buffer. Append-style:
// add the header, then attributes, then optionally MESSAGE-INTEGRITY +
// FINGERPRINT (which must be the last two attributes per RFC 5389). finish()
// returns the total byte count or 0 on overflow.
//
// No heap: the builder writes straight into the caller buffer and tracks a
// cursor. add_message_integrity()/add_fingerprint() compute over the bytes
// already written with the proper header-length fixup.
// ----------------------------------------------------------------------------
class Builder {
public:
    Builder(std::uint8_t* buffer, std::size_t capacity) noexcept
        : buf_(buffer), cap_(capacity) {
        assert(buffer != nullptr);
        assert(capacity >= kHeaderSize);
    }

    // Write the 20-byte header. `txn` must point to 12 bytes. Call first.
    StunError begin(Class cls, Method method,
                    const std::uint8_t txn[kTransactionIdLen]) noexcept;

    // Generic raw attribute (value copied; padded to 4 bytes).
    StunError add_attribute(AttrType type, const std::uint8_t* value,
                            std::uint16_t length) noexcept;

    StunError add_username(const char* user, std::size_t len) noexcept;
    StunError add_priority(std::uint32_t priority) noexcept;
    StunError add_use_candidate() noexcept;  // flag attribute, length 0
    StunError add_ice_controlling(std::uint64_t tiebreaker) noexcept;
    StunError add_ice_controlled(std::uint64_t tiebreaker) noexcept;
    StunError add_xor_mapped_address(const Address& addr) noexcept;
    StunError add_error_code(std::uint16_t code, const char* reason,
                             std::size_t reason_len) noexcept;

    // MESSAGE-INTEGRITY: HMAC-SHA1 over the message (with the length field
    // temporarily set to include this attribute), keyed by `key`. RFC 5389 §15.4.
    StunError add_message_integrity(const std::uint8_t* key,
                                    std::size_t key_len) noexcept;

    // FINGERPRINT: CRC-32 (over the message incl. the length fixup) XOR the
    // magic 0x5354554e. RFC 5389 §15.5. Must be the LAST attribute.
    StunError add_fingerprint() noexcept;

    // Total bytes written.
    std::size_t size() const noexcept { return len_; }

private:
    StunError reserve(std::size_t extra) noexcept;
    void      patch_length() noexcept;  // write (len_ - 20) into the header

    std::uint8_t* buf_;
    std::size_t   cap_;
    std::size_t   len_ = 0;
};

// ----------------------------------------------------------------------------
// Verification helpers (operate on a parsed Message + its raw bytes).
// ----------------------------------------------------------------------------
// Verify FINGERPRINT (must be present and last). Ok / FingerprintFail / NotFound.
StunError verify_fingerprint(const Message& msg) noexcept;

// Verify MESSAGE-INTEGRITY with `key`. Recomputes HMAC-SHA1 over the message
// truncated at the MESSAGE-INTEGRITY attribute, with the header length fixed up
// to point just past it. Ok / IntegrityFail / NotFound.
StunError verify_message_integrity(const Message& msg, const std::uint8_t* key,
                                   std::size_t key_len) noexcept;

// ----------------------------------------------------------------------------
// CRC-32 (IEEE 802.3, reflected) — exposed for testing the FINGERPRINT path.
// ----------------------------------------------------------------------------
std::uint32_t crc32(const std::uint8_t* data, std::size_t len) noexcept;

}  // namespace stun
}  // namespace webrtc
}  // namespace bolt::api
