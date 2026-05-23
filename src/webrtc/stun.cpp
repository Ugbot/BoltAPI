// stun.cpp — implementation of the STUN codec (boltapi/webrtc/stun.h).
//
// REBUILT from scratch (FasterAPI's STUNMessage was a 20-byte-header stub with
// no attribute support). RFC 5389/8489 message + attribute TLV, with the
// MESSAGE-INTEGRITY (HMAC-SHA1, OpenSSL) and FINGERPRINT (CRC-32) machinery and
// the header-length fixups those require. Validated against RFC 5769 vectors.

#include "boltapi/webrtc/stun.h"

#include <openssl/hmac.h>
#include <openssl/sha.h>

namespace bolt::api {
namespace webrtc {
namespace stun {

namespace {

// --- big-endian read/write helpers (portable, no byteorder intrinsics) ------
inline std::uint16_t rd16(const std::uint8_t* p) noexcept {
    return static_cast<std::uint16_t>((p[0] << 8) | p[1]);
}
inline std::uint32_t rd32(const std::uint8_t* p) noexcept {
    return (static_cast<std::uint32_t>(p[0]) << 24) |
           (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8) |
            static_cast<std::uint32_t>(p[3]);
}
inline void wr16(std::uint8_t* p, std::uint16_t v) noexcept {
    p[0] = static_cast<std::uint8_t>(v >> 8);
    p[1] = static_cast<std::uint8_t>(v & 0xFF);
}
inline void wr32(std::uint8_t* p, std::uint32_t v) noexcept {
    p[0] = static_cast<std::uint8_t>(v >> 24);
    p[1] = static_cast<std::uint8_t>(v >> 16);
    p[2] = static_cast<std::uint8_t>(v >> 8);
    p[3] = static_cast<std::uint8_t>(v & 0xFF);
}
inline void wr64(std::uint8_t* p, std::uint64_t v) noexcept {
    for (int i = 0; i < 8; ++i)
        p[i] = static_cast<std::uint8_t>(v >> (56 - 8 * i));
}

inline std::size_t pad4(std::size_t n) noexcept { return (n + 3u) & ~std::size_t{3}; }

// Encode 14-bit message type from class + method (RFC 5389 §6).
std::uint16_t encode_type(Class cls, Method method) noexcept {
    const std::uint16_t m = static_cast<std::uint16_t>(method);
    const std::uint16_t c = static_cast<std::uint16_t>(cls);
    // M11..M5 | C1 | M4..M0 | C0 ... per the bit layout:
    //   bit0..3 = M0..M3, bit4 = C0, bit5..7 = M4..M6, bit8 = C1, bit9.. = M7..
    std::uint16_t t = 0;
    t |= static_cast<std::uint16_t>(m & 0x000F);          // M0..M3
    t |= static_cast<std::uint16_t>((c & 0x1) << 4);      // C0
    t |= static_cast<std::uint16_t>((m & 0x0070) << 1);   // M4..M6
    t |= static_cast<std::uint16_t>((c & 0x2) << 7);      // C1
    t |= static_cast<std::uint16_t>((m & 0x0F80) << 2);   // M7..M11
    return t;
}

void decode_type(std::uint16_t t, Class* cls, Method* method) noexcept {
    std::uint16_t m = 0;
    m |= static_cast<std::uint16_t>(t & 0x000F);            // M0..M3
    m |= static_cast<std::uint16_t>((t & 0x00E0) >> 1);     // M4..M6
    m |= static_cast<std::uint16_t>((t & 0x3E00) >> 2);     // M7..M11
    std::uint16_t c = 0;
    c |= static_cast<std::uint16_t>((t & 0x0010) >> 4);     // C0
    c |= static_cast<std::uint16_t>((t & 0x0100) >> 7);     // C1
    *method = static_cast<Method>(m);
    *cls = static_cast<Class>(c);
}

// --- CRC-32 (IEEE, reflected) — runtime-built table ------------------------
struct Crc32Table {
    std::uint32_t t[256];
    Crc32Table() noexcept {
        for (std::uint32_t i = 0; i < 256; ++i) {
            std::uint32_t c = i;
            for (int k = 0; k < 8; ++k)
                c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            t[i] = c;
        }
    }
};
const Crc32Table g_crc32;

}  // namespace

std::uint32_t crc32(const std::uint8_t* data, std::size_t len) noexcept {
    std::uint32_t c = 0xFFFFFFFFu;
    for (std::size_t i = 0; i < len; ++i)
        c = g_crc32.t[(c ^ data[i]) & 0xFFu] ^ (c >> 8);
    return c ^ 0xFFFFFFFFu;
}

// ---------------------------------------------------------------------------
// Message accessors
// ---------------------------------------------------------------------------
const Attribute* Message::find(AttrType t) const noexcept {
    for (std::size_t i = 0; i < attr_count; ++i)
        if (attrs[i].type == t) return &attrs[i];
    return nullptr;
}

StunError Message::mapped_address(Address* out) const noexcept {
    assert(out != nullptr);
    const Attribute* a = find(AttrType::XorMappedAddress);
    bool is_xor = true;
    if (!a) { a = find(AttrType::MappedAddress); is_xor = false; }
    if (!a) return StunError::NotFound;
    if (a->length < 4) return StunError::BadAddress;

    const std::uint8_t* v = a->value;
    const std::uint8_t fam = v[1];
    out->family = (fam == 0x02) ? Family::IPv6 : Family::IPv4;
    std::uint16_t port = rd16(v + 2);
    if (is_xor) port ^= static_cast<std::uint16_t>(kMagicCookie >> 16);
    out->port = port;

    const std::size_t alen = (out->family == Family::IPv6) ? 16u : 4u;
    if (a->length < 4 + alen) return StunError::BadAddress;
    std::memset(out->addr, 0, sizeof(out->addr));
    if (!is_xor) {
        std::memcpy(out->addr, v + 4, alen);
    } else {
        // XOR with magic cookie, then (IPv6) the transaction id.
        std::uint8_t mask[16];
        wr32(mask, kMagicCookie);
        std::memcpy(mask + 4, transaction_id, kTransactionIdLen);
        for (std::size_t i = 0; i < alen; ++i) out->addr[i] = v[4 + i] ^ mask[i];
    }
    return StunError::Ok;
}

bool Message::priority(std::uint32_t* out) const noexcept {
    assert(out != nullptr);
    const Attribute* a = find(AttrType::Priority);
    if (!a || a->length < 4) return false;
    *out = rd32(a->value);
    return true;
}

// ---------------------------------------------------------------------------
// parse
// ---------------------------------------------------------------------------
StunError parse(const std::uint8_t* data, std::size_t len, Message& out) noexcept {
    out = Message{};
    if (data == nullptr || len < kHeaderSize) return StunError::TooShort;

    // Top two bits must be zero for STUN.
    if ((data[0] & 0xC0) != 0) return StunError::BadMagicCookie;

    const std::uint16_t type = rd16(data);
    decode_type(type, &out.msg_class, &out.method);

    out.length = rd16(data + 2);
    if (rd32(data + 4) != kMagicCookie) return StunError::BadMagicCookie;
    std::memcpy(out.transaction_id, data + 8, kTransactionIdLen);

    const std::size_t total = kHeaderSize + out.length;
    if (total > len) return StunError::BadLength;
    if ((out.length & 0x3) != 0) return StunError::BadLength;  // must be 4-aligned

    out.raw = data;
    out.raw_len = total;

    std::size_t off = kHeaderSize;
    while (off + 4 <= total) {
        const std::uint16_t atype = rd16(data + off);
        const std::uint16_t alen  = rd16(data + off + 2);
        off += 4;
        if (off + alen > total) return StunError::BadLength;
        if (out.attr_count >= kMaxAttributes) return StunError::TooManyAttrs;
        Attribute& a = out.attrs[out.attr_count++];
        a.type = static_cast<AttrType>(atype);
        a.value = (alen > 0) ? (data + off) : nullptr;
        a.length = alen;
        off += pad4(alen);
    }
    return StunError::Ok;
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------
StunError Builder::reserve(std::size_t extra) noexcept {
    return (len_ + extra <= cap_) ? StunError::Ok : StunError::BufferTooSmall;
}

void Builder::patch_length() noexcept {
    wr16(buf_ + 2, static_cast<std::uint16_t>(len_ - kHeaderSize));
}

StunError Builder::begin(Class cls, Method method,
                         const std::uint8_t txn[kTransactionIdLen]) noexcept {
    assert(txn != nullptr);
    if (cap_ < kHeaderSize) return StunError::BufferTooSmall;
    wr16(buf_, encode_type(cls, method));
    wr16(buf_ + 2, 0);                 // length, patched as attrs are added
    wr32(buf_ + 4, kMagicCookie);
    std::memcpy(buf_ + 8, txn, kTransactionIdLen);
    len_ = kHeaderSize;
    return StunError::Ok;
}

StunError Builder::add_attribute(AttrType type, const std::uint8_t* value,
                                 std::uint16_t length) noexcept {
    const std::size_t padded = pad4(length);
    const StunError e = reserve(4 + padded);
    if (e != StunError::Ok) return e;
    wr16(buf_ + len_, static_cast<std::uint16_t>(type));
    wr16(buf_ + len_ + 2, length);
    if (length > 0 && value != nullptr) std::memcpy(buf_ + len_ + 4, value, length);
    // Zero the padding bytes for deterministic output.
    for (std::size_t i = length; i < padded; ++i) buf_[len_ + 4 + i] = 0;
    len_ += 4 + padded;
    patch_length();
    return StunError::Ok;
}

StunError Builder::add_username(const char* user, std::size_t len) noexcept {
    return add_attribute(AttrType::Username,
                         reinterpret_cast<const std::uint8_t*>(user),
                         static_cast<std::uint16_t>(len));
}

StunError Builder::add_priority(std::uint32_t priority) noexcept {
    std::uint8_t v[4];
    wr32(v, priority);
    return add_attribute(AttrType::Priority, v, 4);
}

StunError Builder::add_use_candidate() noexcept {
    return add_attribute(AttrType::UseCandidate, nullptr, 0);
}

StunError Builder::add_ice_controlling(std::uint64_t tiebreaker) noexcept {
    std::uint8_t v[8];
    wr64(v, tiebreaker);
    return add_attribute(AttrType::IceControlling, v, 8);
}

StunError Builder::add_ice_controlled(std::uint64_t tiebreaker) noexcept {
    std::uint8_t v[8];
    wr64(v, tiebreaker);
    return add_attribute(AttrType::IceControlled, v, 8);
}

StunError Builder::add_xor_mapped_address(const Address& addr) noexcept {
    const std::size_t alen = (addr.family == Family::IPv6) ? 16u : 4u;
    std::uint8_t v[4 + 16];
    v[0] = 0;
    v[1] = static_cast<std::uint8_t>(addr.family);
    wr16(v + 2, static_cast<std::uint16_t>(addr.port ^
                static_cast<std::uint16_t>(kMagicCookie >> 16)));
    std::uint8_t mask[16];
    wr32(mask, kMagicCookie);
    std::memcpy(mask + 4, buf_ + 8, kTransactionIdLen);  // txn id from header
    for (std::size_t i = 0; i < alen; ++i) v[4 + i] = addr.addr[i] ^ mask[i];
    return add_attribute(AttrType::XorMappedAddress, v,
                         static_cast<std::uint16_t>(4 + alen));
}

StunError Builder::add_error_code(std::uint16_t code, const char* reason,
                                  std::size_t reason_len) noexcept {
    // ERROR-CODE: 2 reserved bytes, class (hundreds), number, then reason phrase.
    std::uint8_t hdr[4] = {0, 0,
        static_cast<std::uint8_t>(code / 100),
        static_cast<std::uint8_t>(code % 100)};
    // Build value in a small fixed buffer (reason bounded for ICE use).
    std::uint8_t v[4 + 128];
    if (reason_len > sizeof(v) - 4) reason_len = sizeof(v) - 4;
    std::memcpy(v, hdr, 4);
    if (reason_len > 0 && reason != nullptr) std::memcpy(v + 4, reason, reason_len);
    return add_attribute(AttrType::ErrorCode, v,
                         static_cast<std::uint16_t>(4 + reason_len));
}

StunError Builder::add_message_integrity(const std::uint8_t* key,
                                         std::size_t key_len) noexcept {
    // RFC 5389 §15.4: the HMAC covers the message up to (but not including) the
    // MESSAGE-INTEGRITY attribute, with the header length set to include it.
    constexpr std::size_t kMiAttr = 4 + 20;  // header + 20-byte SHA1 digest
    const StunError e = reserve(kMiAttr);
    if (e != StunError::Ok) return e;

    // Temporarily patch length to include the MI attribute, then HMAC over the
    // already-written prefix (len_ bytes), then write the attribute.
    const std::uint16_t saved = rd16(buf_ + 2);
    wr16(buf_ + 2, static_cast<std::uint16_t>((len_ - kHeaderSize) + kMiAttr));

    unsigned char digest[20];
    unsigned int dlen = 0;
    HMAC(EVP_sha1(), key, static_cast<int>(key_len),
         buf_, len_, digest, &dlen);

    // restore (add_attribute will repatch to the true new length)
    wr16(buf_ + 2, saved);

    return add_attribute(AttrType::MessageIntegrity, digest,
                         static_cast<std::uint16_t>(dlen));
}

StunError Builder::add_fingerprint() noexcept {
    constexpr std::size_t kFpAttr = 4 + 4;
    const StunError e = reserve(kFpAttr);
    if (e != StunError::Ok) return e;

    // CRC covers the message with the header length already including FINGERPRINT.
    const std::uint16_t saved = rd16(buf_ + 2);
    wr16(buf_ + 2, static_cast<std::uint16_t>((len_ - kHeaderSize) + kFpAttr));
    const std::uint32_t fp = crc32(buf_, len_) ^ kFingerprintXor;
    wr16(buf_ + 2, saved);

    std::uint8_t v[4];
    wr32(v, fp);
    return add_attribute(AttrType::Fingerprint, v, 4);
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------
StunError verify_fingerprint(const Message& msg) noexcept {
    const Attribute* a = msg.find(AttrType::Fingerprint);
    if (!a || a->length != 4) return StunError::NotFound;

    // FINGERPRINT must be last; the CRC is over everything before its value,
    // i.e. the message truncated to just past the FINGERPRINT attribute header.
    // value pointer - raw gives the offset of the value; the attribute starts 4
    // bytes earlier. CRC covers [raw, attr_start).
    const std::size_t attr_start =
        static_cast<std::size_t>(a->value - msg.raw) - 4;
    const std::uint32_t expect = rd32(a->value);

    // Recompute over a temporary header-length fixup. We must compute the CRC
    // over [raw, attr_start) with the header length = attr_start - 20 + 8.
    // Copy the prefix is avoided: CRC the prefix as-is but with a patched length
    // field. Since msg.raw is const, build the CRC with the length substitution
    // by feeding bytes manually around offsets 2..3.
    std::uint8_t hdr_len[2];
    wr16(hdr_len, static_cast<std::uint16_t>((attr_start - kHeaderSize) + 8));

    // Streaming CRC with the two length bytes swapped in.
    std::uint32_t c = 0xFFFFFFFFu;
    auto feed = [&c](std::uint8_t b) {
        c = g_crc32.t[(c ^ b) & 0xFFu] ^ (c >> 8);
    };
    for (std::size_t i = 0; i < attr_start; ++i) {
        std::uint8_t b = (i == 2) ? hdr_len[0] : (i == 3) ? hdr_len[1] : msg.raw[i];
        feed(b);
    }
    const std::uint32_t got = (c ^ 0xFFFFFFFFu) ^ kFingerprintXor;
    return (got == expect) ? StunError::Ok : StunError::FingerprintFail;
}

StunError verify_message_integrity(const Message& msg, const std::uint8_t* key,
                                   std::size_t key_len) noexcept {
    const Attribute* a = msg.find(AttrType::MessageIntegrity);
    if (!a || a->length != 20) return StunError::NotFound;

    const std::size_t attr_start =
        static_cast<std::size_t>(a->value - msg.raw) - 4;

    // HMAC over [raw, attr_start) with the header length field patched to
    // (attr_start - 20) + 24 (the MI attribute is 24 bytes incl. its header).
    // OpenSSL HMAC needs a contiguous buffer; copy the prefix into a bounded
    // scratch (STUN connectivity-check messages are well under 1280 bytes).
    constexpr std::size_t kScratch = 1280;
    if (attr_start > kScratch) return StunError::IntegrityFail;
    std::uint8_t scratch[kScratch];
    std::memcpy(scratch, msg.raw, attr_start);
    wr16(scratch + 2, static_cast<std::uint16_t>((attr_start - kHeaderSize) + 24));

    unsigned char digest[20];
    unsigned int dlen = 0;
    HMAC(EVP_sha1(), key, static_cast<int>(key_len),
         scratch, attr_start, digest, &dlen);
    if (dlen != 20) return StunError::IntegrityFail;

    return (std::memcmp(digest, a->value, 20) == 0)
               ? StunError::Ok : StunError::IntegrityFail;
}

}  // namespace stun
}  // namespace webrtc
}  // namespace bolt::api
