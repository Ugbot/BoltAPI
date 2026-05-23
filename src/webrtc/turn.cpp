// src/webrtc/turn.cpp — TURN client + minimal in-process TURN server.
//
// Self-contained TURN message codec (the base STUN codec does not enumerate the
// TURN methods/attributes) + the long-term-credential client state machine and a
// loopback-sufficient server. Crypto: OpenSSL HMAC-SHA1 (MESSAGE-INTEGRITY),
// MD5 (long-term key), and a small CRC-32 for FINGERPRINT.
//
// Compiled UNCONDITIONALLY into boltapi.
//
// TigerStyle: fixed caller buffers, bounded tables, no exceptions, no recursion.

#include "boltapi/webrtc/turn.h"

#include "boltapi/net/udp_transport.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <cstring>

namespace bolt::api {
namespace webrtc {
namespace turn {

namespace {

// --- big-endian helpers -----------------------------------------------------
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
inline std::size_t pad4(std::size_t n) noexcept { return (n + 3u) & ~std::size_t{3}; }

std::uint16_t encode_type(Class cls, Method method) noexcept {
    const std::uint16_t m = static_cast<std::uint16_t>(method);
    const std::uint16_t c = static_cast<std::uint16_t>(cls);
    std::uint16_t t = 0;
    t |= static_cast<std::uint16_t>(m & 0x000F);
    t |= static_cast<std::uint16_t>((c & 0x1) << 4);
    t |= static_cast<std::uint16_t>((m & 0x0070) << 1);
    t |= static_cast<std::uint16_t>((c & 0x2) << 7);
    t |= static_cast<std::uint16_t>((m & 0x0F80) << 2);
    return t;
}
void decode_type(std::uint16_t t, Class* cls, Method* method) noexcept {
    std::uint16_t m = 0;
    m |= static_cast<std::uint16_t>(t & 0x000F);
    m |= static_cast<std::uint16_t>((t & 0x00E0) >> 1);
    m |= static_cast<std::uint16_t>((t & 0x3E00) >> 2);
    std::uint16_t c = 0;
    c |= static_cast<std::uint16_t>((t & 0x0010) >> 4);
    c |= static_cast<std::uint16_t>((t & 0x0100) >> 7);
    *method = static_cast<Method>(m);
    *cls = static_cast<Class>(c);
}

// --- CRC-32 (IEEE, reflected) for FINGERPRINT -------------------------------
std::uint32_t crc32(const std::uint8_t* data, std::size_t len) noexcept {
    std::uint32_t c = 0xFFFFFFFFu;
    for (std::size_t i = 0; i < len; ++i) {
        c ^= data[i];
        for (int k = 0; k < 8; ++k)
            c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
    }
    return c ^ 0xFFFFFFFFu;
}

// ----------------------------------------------------------------------------
// Writer — append TURN attributes into a caller buffer (no heap).
// ----------------------------------------------------------------------------
struct Writer {
    std::uint8_t* buf;
    std::size_t   cap;
    std::size_t   len = 0;

    bool begin(Class cls, Method method, const std::uint8_t txn[kTxnLen]) noexcept {
        if (cap < kHeaderSize) return false;
        wr16(buf, encode_type(cls, method));
        wr16(buf + 2, 0);
        wr32(buf + 4, kMagicCookie);
        std::memcpy(buf + 8, txn, kTxnLen);
        len = kHeaderSize;
        return true;
    }
    void patch() noexcept { wr16(buf + 2, static_cast<std::uint16_t>(len - kHeaderSize)); }

    bool attr(Attr type, const std::uint8_t* v, std::uint16_t vlen) noexcept {
        const std::size_t padded = pad4(vlen);
        if (len + 4 + padded > cap) return false;
        wr16(buf + len, static_cast<std::uint16_t>(type));
        wr16(buf + len + 2, vlen);
        if (vlen > 0 && v != nullptr) std::memcpy(buf + len + 4, v, vlen);
        for (std::size_t i = vlen; i < padded; ++i) buf[len + 4 + i] = 0;
        len += 4 + padded;
        patch();
        return true;
    }
    bool u32(Attr type, std::uint32_t v) noexcept {
        std::uint8_t b[4]; wr32(b, v); return attr(type, b, 4);
    }
    bool u16pad(Attr type, std::uint16_t v) noexcept {
        std::uint8_t b[4] = {0,0,0,0}; wr16(b, v); return attr(type, b, 4);
    }
    // XOR-mapped style address (family + xor-port + xor-addr), IPv4.
    bool xor_addr(Attr type, const sockaddr* sa) noexcept {
        if (sa->sa_family != AF_INET) return false;
        const auto* in = reinterpret_cast<const sockaddr_in*>(sa);
        std::uint8_t v[8];
        v[0] = 0; v[1] = 0x01;
        const std::uint16_t port = ntohs(in->sin_port);
        wr16(v + 2, static_cast<std::uint16_t>(port ^ (kMagicCookie >> 16)));
        std::uint8_t mask[4]; wr32(mask, kMagicCookie);
        const auto* ab = reinterpret_cast<const std::uint8_t*>(&in->sin_addr);
        for (int i = 0; i < 4; ++i) v[4 + i] = ab[i] ^ mask[i];
        return attr(type, v, 8);
    }
    bool message_integrity(const std::uint8_t key[16]) noexcept {
        constexpr std::size_t kMi = 4 + 20;
        if (len + kMi > cap) return false;
        const std::uint16_t saved = rd16(buf + 2);
        wr16(buf + 2, static_cast<std::uint16_t>((len - kHeaderSize) + kMi));
        unsigned char digest[20]; unsigned int dl = 0;
        HMAC(EVP_sha1(), key, 16, buf, len, digest, &dl);
        wr16(buf + 2, saved);
        return attr(Attr::MessageIntegrity, digest, static_cast<std::uint16_t>(dl));
    }
    bool fingerprint() noexcept {
        constexpr std::size_t kFp = 4 + 4;
        if (len + kFp > cap) return false;
        const std::uint16_t saved = rd16(buf + 2);
        wr16(buf + 2, static_cast<std::uint16_t>((len - kHeaderSize) + kFp));
        const std::uint32_t fp = crc32(buf, len) ^ 0x5354554Eu;
        wr16(buf + 2, saved);
        return u32(Attr::Fingerprint, fp);
    }
};

}  // namespace

// ----------------------------------------------------------------------------
// Reader — zero-copy parse of a TURN message (header + bounded attr scan). At
// `turn` namespace scope (not anonymous) so turn.h can forward-declare Parsed
// for the TurnServer per-message handler signatures; `static` keeps internal
// linkage (single-TU, no symbol export).
// ----------------------------------------------------------------------------
struct ParsedAttr { Attr type; const std::uint8_t* v; std::uint16_t len; };
struct Parsed {
    Class msg_class{};
    Method method{};
    std::uint8_t txn[kTxnLen]{};
    ParsedAttr attrs[24]{};
    std::size_t attr_count = 0;
    const std::uint8_t* raw = nullptr;
    std::size_t raw_len = 0;

    const ParsedAttr* find(Attr t) const noexcept {
        for (std::size_t i = 0; i < attr_count; ++i)
            if (attrs[i].type == t) return &attrs[i];
        return nullptr;
    }
};

static bool parse(const std::uint8_t* data, std::size_t len,
                  Parsed& out) noexcept {
    out = Parsed{};
    if (data == nullptr || len < kHeaderSize) return false;
    if ((data[0] & 0xC0) != 0) return false;
    decode_type(rd16(data), &out.msg_class, &out.method);
    if (rd32(data + 4) != kMagicCookie) return false;
    std::memcpy(out.txn, data + 8, kTxnLen);
    const std::size_t total = kHeaderSize + rd16(data + 2);
    if (total > len || (rd16(data + 2) & 0x3) != 0) return false;
    out.raw = data; out.raw_len = total;
    std::size_t off = kHeaderSize;
    while (off + 4 <= total) {
        const std::uint16_t at = rd16(data + off);
        const std::uint16_t al = rd16(data + off + 2);
        off += 4;
        if (off + al > total) return false;
        if (out.attr_count >= 24) return false;
        ParsedAttr& a = out.attrs[out.attr_count++];
        a.type = static_cast<Attr>(at);
        a.v = al > 0 ? data + off : nullptr;
        a.len = al;
        off += pad4(al);
    }
    return true;
}

// Decode an XOR-mapped style address attribute (IPv4) into a sockaddr_in.
static int decode_xor_addr(const ParsedAttr* a, const std::uint8_t txn[kTxnLen],
                           sockaddr_storage* out) noexcept {
    if (a == nullptr || a->len < 8 || a->v[1] != 0x01) return 0;
    (void)txn;
    std::memset(out, 0, sizeof(*out));
    auto* in = reinterpret_cast<sockaddr_in*>(out);
    in->sin_family = AF_INET;
    const std::uint16_t xport = rd16(a->v + 2);
    in->sin_port = htons(static_cast<std::uint16_t>(xport ^ (kMagicCookie >> 16)));
    std::uint8_t mask[4]; wr32(mask, kMagicCookie);
    auto* ab = reinterpret_cast<std::uint8_t*>(&in->sin_addr);
    for (int i = 0; i < 4; ++i) ab[i] = a->v[4 + i] ^ mask[i];
    return static_cast<int>(sizeof(sockaddr_in));
}

static bool verify_mi(const Parsed& m, const std::uint8_t key[16]) noexcept {
    const ParsedAttr* a = m.find(Attr::MessageIntegrity);
    if (a == nullptr || a->len != 20) return false;
    const std::size_t attr_start = static_cast<std::size_t>(a->v - m.raw) - 4;
    constexpr std::size_t kScratch = 2048;
    if (attr_start > kScratch) return false;
    std::uint8_t scratch[kScratch];
    std::memcpy(scratch, m.raw, attr_start);
    wr16(scratch + 2, static_cast<std::uint16_t>((attr_start - kHeaderSize) + 24));
    unsigned char digest[20]; unsigned int dl = 0;
    HMAC(EVP_sha1(), key, 16, scratch, attr_start, digest, &dl);
    return dl == 20 && std::memcmp(digest, a->v, 20) == 0;
}

// ---------------------------------------------------------------------------
// long_term_key = MD5(user ":" realm ":" pass)
// ---------------------------------------------------------------------------
void long_term_key(std::string_view user, std::string_view realm,
                   std::string_view pass, std::uint8_t out16[16]) noexcept {
    assert(out16 != nullptr);
    assert(!user.empty() && !realm.empty());
    // Long-term key = MD5(user ":" realm ":" pass) via the EVP digest API (the
    // bare MD5_* functions are deprecated in OpenSSL 3.0). Bounded scratch.
    std::uint8_t in[1024];
    std::size_t n = 0;
    auto push = [&](std::string_view s) noexcept {
        const std::size_t c = (n + s.size() <= sizeof(in)) ? s.size()
                                                           : sizeof(in) - n;
        std::memcpy(in + n, s.data(), c);
        n += c;
    };
    push(user); push(":"); push(realm); push(":"); push(pass);
    unsigned int dl = 0;
    EVP_Digest(in, n, out16, &dl, EVP_md5(), nullptr);
    assert(dl == 16);
    (void)dl;
}

// ===========================================================================
// TurnClient
// ===========================================================================
void TurnClient::configure(const sockaddr* server, int server_len,
                           std::string_view user, std::string_view pass) noexcept {
    assert(server != nullptr && server_len > 0);
    assert(!user.empty());
    const std::size_t n =
        static_cast<std::size_t>(server_len) <= sizeof(server_) ?
            static_cast<std::size_t>(server_len) : sizeof(sockaddr_in);
    std::memcpy(&server_, server, n);
    server_len_ = static_cast<int>(n);
    user_.assign(user.data(), user.size());
    pass_.assign(pass.data(), pass.size());
    state_ = State::Idle;
}

void TurnClient::next_txn(std::uint8_t txn[kTxnLen]) noexcept {
    assert(txn != nullptr);
    ++txn_ctr_;
    std::uint64_t a = txn_ctr_ * 0x9E3779B97F4A7C15ull;
    std::uint64_t b = (txn_ctr_ ^ 0xD1B54A32D192ED03ull) * 0x2545F4914F6CDD1Dull;
    for (int i = 0; i < 8; ++i) txn[i] = static_cast<std::uint8_t>(a >> (8 * i));
    for (int i = 0; i < 4; ++i) txn[8 + i] = static_cast<std::uint8_t>(b >> (8 * i));
}

std::size_t TurnClient::begin_authed(std::uint8_t* out, std::size_t cap,
                                     Method method,
                                     std::uint8_t txn[kTxnLen]) noexcept {
    assert(out != nullptr && cap >= kHeaderSize);
    assert(have_key_ && "begin_authed before realm/nonce known");
    Writer w{out, cap};
    next_txn(txn);
    if (!w.begin(Class::Request, method, txn)) return 0;
    if (method == Method::Allocate)
        if (!w.u32(Attr::RequestedTransport,
                   static_cast<std::uint32_t>(kProtoUdp) << 24)) return 0;
    return w.len;  // attrs after this are method-specific; MI/FP added by caller
}

bool TurnClient::allocate(net::UdpTransport& transport) noexcept {
    assert(server_len_ > 0 && "configure() first");
    std::uint8_t out[256];
    std::uint8_t txn[kTxnLen];
    Writer w{out, sizeof(out)};
    next_txn(txn);
    if (!w.begin(Class::Request, Method::Allocate, txn)) return false;
    if (!w.u32(Attr::RequestedTransport,
               static_cast<std::uint32_t>(kProtoUdp) << 24)) return false;
    if (have_key_) {  // authenticated retry (realm/nonce known)
        if (!w.attr(Attr::Username,
                    reinterpret_cast<const std::uint8_t*>(user_.data()),
                    static_cast<std::uint16_t>(user_.size()))) return false;
        if (!w.attr(Attr::Realm,
                    reinterpret_cast<const std::uint8_t*>(realm_.data()),
                    static_cast<std::uint16_t>(realm_.size()))) return false;
        if (!w.attr(Attr::Nonce, nonce_,
                    static_cast<std::uint16_t>(nonce_len_))) return false;
        if (!w.message_integrity(key_)) return false;
    }
    if (!w.fingerprint()) return false;
    state_ = State::Allocating;
    return transport.send(reinterpret_cast<const sockaddr*>(&server_),
                          server_len_, out, w.len) > 0;
}

bool TurnClient::refresh(net::UdpTransport& transport,
                         std::uint32_t lifetime) noexcept {
    if (!have_key_) return false;
    std::uint8_t out[256]; std::uint8_t txn[kTxnLen];
    Writer w{out, sizeof(out)};
    next_txn(txn);
    if (!w.begin(Class::Request, Method::Refresh, txn)) return false;
    if (!w.u32(Attr::Lifetime, lifetime)) return false;
    if (!w.attr(Attr::Username,
                reinterpret_cast<const std::uint8_t*>(user_.data()),
                static_cast<std::uint16_t>(user_.size()))) return false;
    if (!w.attr(Attr::Realm, reinterpret_cast<const std::uint8_t*>(realm_.data()),
                static_cast<std::uint16_t>(realm_.size()))) return false;
    if (!w.attr(Attr::Nonce, nonce_, static_cast<std::uint16_t>(nonce_len_)))
        return false;
    if (!w.message_integrity(key_)) return false;
    if (!w.fingerprint()) return false;
    return transport.send(reinterpret_cast<const sockaddr*>(&server_),
                          server_len_, out, w.len) > 0;
}

bool TurnClient::create_permission(net::UdpTransport& transport,
                                   const sockaddr* peer, int peer_len) noexcept {
    assert(peer != nullptr && peer_len > 0);
    (void)peer_len;
    if (!have_key_) return false;
    std::uint8_t out[256]; std::uint8_t txn[kTxnLen];
    Writer w{out, sizeof(out)};
    next_txn(txn);
    if (!w.begin(Class::Request, Method::CreatePermission, txn)) return false;
    if (!w.xor_addr(Attr::XorPeerAddress, peer)) return false;
    if (!w.attr(Attr::Username,
                reinterpret_cast<const std::uint8_t*>(user_.data()),
                static_cast<std::uint16_t>(user_.size()))) return false;
    if (!w.attr(Attr::Realm, reinterpret_cast<const std::uint8_t*>(realm_.data()),
                static_cast<std::uint16_t>(realm_.size()))) return false;
    if (!w.attr(Attr::Nonce, nonce_, static_cast<std::uint16_t>(nonce_len_)))
        return false;
    if (!w.message_integrity(key_)) return false;
    if (!w.fingerprint()) return false;
    return transport.send(reinterpret_cast<const sockaddr*>(&server_),
                          server_len_, out, w.len) > 0;
}

bool TurnClient::channel_bind(net::UdpTransport& transport, const sockaddr* peer,
                              int peer_len, std::uint16_t channel) noexcept {
    assert(peer != nullptr && peer_len > 0);
    assert(channel >= kChannelBase && channel <= kChannelMax);
    if (!have_key_) return false;
    std::uint8_t out[256]; std::uint8_t txn[kTxnLen];
    Writer w{out, sizeof(out)};
    next_txn(txn);
    if (!w.begin(Class::Request, Method::ChannelBind, txn)) return false;
    if (!w.u16pad(Attr::ChannelNumber, channel)) return false;
    if (!w.xor_addr(Attr::XorPeerAddress, peer)) return false;
    if (!w.attr(Attr::Username,
                reinterpret_cast<const std::uint8_t*>(user_.data()),
                static_cast<std::uint16_t>(user_.size()))) return false;
    if (!w.attr(Attr::Realm, reinterpret_cast<const std::uint8_t*>(realm_.data()),
                static_cast<std::uint16_t>(realm_.size()))) return false;
    if (!w.attr(Attr::Nonce, nonce_, static_cast<std::uint16_t>(nonce_len_)))
        return false;
    if (!w.message_integrity(key_)) return false;
    if (!w.fingerprint()) return false;
    const std::size_t n =
        static_cast<std::size_t>(peer_len) <= sizeof(bound_peer_) ?
            static_cast<std::size_t>(peer_len) : sizeof(sockaddr_in);
    std::memcpy(&bound_peer_, peer, n);
    bound_peer_len_ = static_cast<int>(n);
    bound_channel_ = channel;
    return transport.send(reinterpret_cast<const sockaddr*>(&server_),
                          server_len_, out, w.len) > 0;
}

bool TurnClient::send_to(net::UdpTransport& transport, const sockaddr* peer,
                         int peer_len, const std::uint8_t* data,
                         std::size_t len) noexcept {
    assert(peer != nullptr && peer_len > 0);
    assert(data != nullptr || len == 0);
    (void)peer_len;
    if (state_ != State::Allocated) return false;
    if (len > 1280) return false;  // bounded relay payload
    std::uint8_t out[1536]; std::uint8_t txn[kTxnLen];
    Writer w{out, sizeof(out)};
    next_txn(txn);
    if (!w.begin(Class::Indication, Method::Send, txn)) return false;
    if (!w.xor_addr(Attr::XorPeerAddress, peer)) return false;
    if (!w.attr(Attr::Data, data, static_cast<std::uint16_t>(len))) return false;
    return transport.send(reinterpret_cast<const sockaddr*>(&server_),
                          server_len_, out, w.len) > 0;
}

bool TurnClient::send_channel(net::UdpTransport& transport, const sockaddr* peer,
                              int peer_len, const std::uint8_t* data,
                              std::size_t len) noexcept {
    assert(peer != nullptr && peer_len > 0);
    if (!channel_acked_ || bound_channel_ == 0) return false;
    if (len > 1280) return false;
    (void)peer; (void)peer_len;
    std::uint8_t out[1536];
    wr16(out, bound_channel_);
    wr16(out + 2, static_cast<std::uint16_t>(len));
    if (len > 0 && data != nullptr) std::memcpy(out + 4, data, len);
    const std::size_t total = 4 + pad4(len);
    for (std::size_t i = 4 + len; i < total; ++i) out[i] = 0;
    return transport.send(reinterpret_cast<const sockaddr*>(&server_),
                          server_len_, out, total) > 0;
}

void TurnClient::ingest_channel_data(const std::uint8_t* data,
                                     std::size_t len) noexcept {
    assert(data != nullptr && len >= 4);
    const std::uint16_t plen = rd16(data + 2);
    if (4u + plen > len) return;
    const std::size_t cp = plen <= sizeof(relayed_buf_) ? plen
                                                        : sizeof(relayed_buf_);
    std::memcpy(relayed_buf_, data + 4, cp);
    relayed_len_ = cp;
    relayed_peer_ = bound_peer_;
    relayed_peer_len_ = bound_peer_len_;
    have_relayed_ = true;
}

void TurnClient::ingest_data_indication(const Parsed& m) noexcept {
    const ParsedAttr* d = m.find(Attr::Data);
    const ParsedAttr* pa = m.find(Attr::XorPeerAddress);
    if (d == nullptr) return;
    const std::size_t cp = d->len <= sizeof(relayed_buf_) ? d->len
                                                          : sizeof(relayed_buf_);
    std::memcpy(relayed_buf_, d->v, cp);
    relayed_len_ = cp;
    if (pa != nullptr)
        relayed_peer_len_ = decode_xor_addr(pa, m.txn, &relayed_peer_);
    have_relayed_ = true;
}

bool TurnClient::on_error_response(net::UdpTransport& transport,
                                   const Parsed& m) noexcept {
    const ParsedAttr* ec = m.find(Attr::ErrorCode);
    const bool is401 = ec != nullptr && ec->len >= 4 && ec->v[2] == 4 &&
                       ec->v[3] == 1;
    const ParsedAttr* re = m.find(Attr::Realm);
    const ParsedAttr* no = m.find(Attr::Nonce);
    if (is401 && re != nullptr && no != nullptr && no->len <= sizeof(nonce_)) {
        realm_.assign(reinterpret_cast<const char*>(re->v), re->len);
        std::memcpy(nonce_, no->v, no->len);
        nonce_len_ = no->len;
        long_term_key(user_, realm_, pass_, key_);
        have_key_ = true;
        if (m.method == Method::Allocate) allocate(transport);  // authed retry
        return true;
    }
    state_ = State::Failed;
    return true;
}

void TurnClient::on_success_response(const Parsed& m) noexcept {
    switch (m.method) {
        case Method::Allocate: {
            const ParsedAttr* ra = m.find(Attr::XorRelayedAddress);
            relay_addr_len_ = decode_xor_addr(ra, m.txn, &relay_addr_);
            const ParsedAttr* lt = m.find(Attr::Lifetime);
            if (lt != nullptr && lt->len >= 4) lifetime_ = rd32(lt->v);
            state_ = relay_addr_len_ > 0 ? State::Allocated : State::Failed;
            break;
        }
        case Method::Refresh: {
            const ParsedAttr* lt = m.find(Attr::Lifetime);
            if (lt != nullptr && lt->len >= 4) lifetime_ = rd32(lt->v);
            if (lifetime_ == 0) state_ = State::Idle;
            break;
        }
        case Method::CreatePermission: permission_acked_ = true; break;
        case Method::ChannelBind:      channel_acked_ = true;    break;
        default: break;
    }
}

bool TurnClient::feed(net::UdpTransport& transport, const sockaddr* from,
                      int from_len, const std::uint8_t* data,
                      std::size_t len) noexcept {
    assert(data != nullptr || len == 0);
    (void)from; (void)from_len;
    if (is_channel_data(data, len)) {
        ingest_channel_data(data, len);
        return true;
    }
    Parsed m;
    if (!parse(data, len, m)) return false;
    if (m.method == Method::Data && m.msg_class == Class::Indication) {
        ingest_data_indication(m);
        return true;
    }
    if (m.msg_class == Class::ErrorResponse) return on_error_response(transport, m);
    if (m.msg_class == Class::SuccessResponse) on_success_response(m);
    return true;
}

// ===========================================================================
// TurnServer
// ===========================================================================
void TurnServer::set_credentials(std::string_view realm, std::string_view user,
                                 std::string_view pass) noexcept {
    assert(!realm.empty() && !user.empty());
    realm_.assign(realm.data(), realm.size());
    user_.assign(user.data(), user.size());
    pass_.assign(pass.data(), pass.size());
    long_term_key(user_, realm_, pass_, key_);
    have_key_ = true;
    for (int i = 0; i < 16; ++i) nonce_[i] = static_cast<std::uint8_t>('a' + i);
}

void TurnServer::set_sockets(net::UdpTransport& control,
                             net::UdpTransport& relay) noexcept {
    control_ = &control;
    relay_ = &relay;
}

TurnServer::Allocation* TurnServer::find_alloc(const sockaddr* client,
                                               int client_len) noexcept {
    assert(client != nullptr);
    for (std::size_t i = 0; i < kMaxAllocations; ++i) {
        Allocation& a = allocs_[i];
        if (!a.used) continue;
        if (a.client_len != client_len) continue;
        if (client->sa_family != AF_INET) continue;
        const auto* x = reinterpret_cast<const sockaddr_in*>(&a.client);
        const auto* y = reinterpret_cast<const sockaddr_in*>(client);
        if (x->sin_port == y->sin_port && x->sin_addr.s_addr == y->sin_addr.s_addr)
            return &a;
    }
    return nullptr;
}

TurnServer::Allocation* TurnServer::obtain_alloc(const sockaddr* client,
                                                 int client_len) noexcept {
    Allocation* a = find_alloc(client, client_len);
    if (a != nullptr) return a;
    if (alloc_count_ >= kMaxAllocations) return nullptr;
    for (std::size_t i = 0; i < kMaxAllocations; ++i) {
        if (allocs_[i].used) continue;
        Allocation& na = allocs_[i];
        na = Allocation{};
        const std::size_t n =
            static_cast<std::size_t>(client_len) <= sizeof(na.client) ?
                static_cast<std::size_t>(client_len) : sizeof(sockaddr_in);
        std::memcpy(&na.client, client, n);
        na.client_len = static_cast<int>(n);
        na.used = true;
        ++alloc_count_;
        return &na;
    }
    return nullptr;
}

bool TurnServer::send_error(const sockaddr* to, int to_len, Method method,
                            const std::uint8_t txn[kTxnLen], std::uint16_t code,
                            bool with_realm) noexcept {
    assert(control_ != nullptr);
    std::uint8_t out[256];
    Writer w{out, sizeof(out)};
    if (!w.begin(Class::ErrorResponse, method, txn)) return false;
    std::uint8_t ec[4] = {0, 0, static_cast<std::uint8_t>(code / 100),
                          static_cast<std::uint8_t>(code % 100)};
    if (!w.attr(Attr::ErrorCode, ec, 4)) return false;
    if (with_realm) {
        if (!w.attr(Attr::Realm,
                    reinterpret_cast<const std::uint8_t*>(realm_.data()),
                    static_cast<std::uint16_t>(realm_.size()))) return false;
        if (!w.attr(Attr::Nonce, nonce_, 16)) return false;
    }
    if (!w.fingerprint()) return false;
    return control_->send(to, to_len, out, w.len) > 0;
}

bool TurnServer::verify_auth(const std::uint8_t* data, std::size_t len) noexcept {
    Parsed m;
    if (!parse(data, len, m)) return false;
    if (m.find(Attr::Username) == nullptr || m.find(Attr::Realm) == nullptr ||
        m.find(Attr::Nonce) == nullptr) {
        return false;
    }
    return have_key_ && verify_mi(m, key_);
}

bool TurnServer::on_channel_data(const sockaddr* from, int from_len,
                                 const std::uint8_t* data,
                                 std::size_t len) noexcept {
    assert(from != nullptr && data != nullptr);
    Allocation* a = find_alloc(from, from_len);
    if (a == nullptr || relay_ == nullptr) return false;
    const std::uint16_t ch = rd16(data);
    const std::uint16_t plen = rd16(data + 2);
    if (4u + plen > len) return false;
    for (std::size_t i = 0; i < kMaxChannels; ++i) {
        if (a->chans[i].used && a->chans[i].number == ch) {
            relay_->send(reinterpret_cast<const sockaddr*>(&a->chans[i].peer),
                         a->chans[i].peer_len, data + 4, plen);
            return true;
        }
    }
    return false;
}

void TurnServer::on_send_indication(const sockaddr* from, int from_len,
                                    const Parsed& m) noexcept {
    assert(from != nullptr);
    Allocation* a = find_alloc(from, from_len);
    const ParsedAttr* pa = m.find(Attr::XorPeerAddress);
    const ParsedAttr* d = m.find(Attr::Data);
    if (a == nullptr || pa == nullptr || d == nullptr || relay_ == nullptr) return;
    sockaddr_storage peer{};
    const int pl = decode_xor_addr(pa, m.txn, &peer);
    if (pl > 0)
        relay_->send(reinterpret_cast<const sockaddr*>(&peer), pl, d->v, d->len);
}

void TurnServer::on_allocate(const sockaddr* from, int from_len,
                             const Parsed& m) noexcept {
    assert(from != nullptr && control_ != nullptr);
    Allocation* a = obtain_alloc(from, from_len);
    if (a == nullptr || relay_ == nullptr) {
        send_error(from, from_len, m.method, m.txn, 508, false);
        return;
    }
    // The relayed address = the relay socket's bound address (loopback).
    sockaddr_in relay_sa{};
    relay_sa.sin_family = AF_INET;
    relay_sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    relay_sa.sin_port = htons(relay_->bound_port());
    std::uint8_t out[256];
    Writer w{out, sizeof(out)};
    if (!w.begin(Class::SuccessResponse, Method::Allocate, m.txn)) return;
    w.xor_addr(Attr::XorRelayedAddress,
               reinterpret_cast<const sockaddr*>(&relay_sa));
    w.xor_addr(Attr::XorMappedAddress, from);
    w.u32(Attr::Lifetime, a->lifetime);
    w.message_integrity(key_);
    w.fingerprint();
    control_->send(from, from_len, out, w.len);
}

void TurnServer::on_create_permission(Allocation& a, const sockaddr* from,
                                      int from_len, const Parsed& m) noexcept {
    assert(control_ != nullptr);
    const ParsedAttr* pa = m.find(Attr::XorPeerAddress);
    if (pa != nullptr) {
        sockaddr_storage peer{};
        const int pl = decode_xor_addr(pa, m.txn, &peer);
        for (std::size_t i = 0; i < kMaxPermissions; ++i) {
            if (!a.perms[i].used) {
                a.perms[i].peer = peer; a.perms[i].peer_len = pl;
                a.perms[i].used = true; break;
            }
        }
    }
    std::uint8_t out[256];
    Writer w{out, sizeof(out)};
    if (w.begin(Class::SuccessResponse, Method::CreatePermission, m.txn)) {
        w.message_integrity(key_); w.fingerprint();
        control_->send(from, from_len, out, w.len);
    }
}

void TurnServer::on_channel_bind(Allocation& a, const sockaddr* from,
                                 int from_len, const Parsed& m) noexcept {
    assert(control_ != nullptr);
    const ParsedAttr* cn = m.find(Attr::ChannelNumber);
    const ParsedAttr* pa = m.find(Attr::XorPeerAddress);
    if (cn != nullptr && cn->len >= 2 && pa != nullptr) {
        sockaddr_storage peer{};
        const int pl = decode_xor_addr(pa, m.txn, &peer);
        const std::uint16_t ch = rd16(cn->v);
        for (std::size_t i = 0; i < kMaxChannels; ++i) {
            if (!a.chans[i].used) {
                a.chans[i].number = ch; a.chans[i].peer = peer;
                a.chans[i].peer_len = pl; a.chans[i].used = true; break;
            }
        }
        for (std::size_t i = 0; i < kMaxPermissions; ++i) {  // implies permission
            if (!a.perms[i].used) {
                a.perms[i].peer = peer; a.perms[i].peer_len = pl;
                a.perms[i].used = true; break;
            }
        }
    }
    std::uint8_t out[256];
    Writer w{out, sizeof(out)};
    if (w.begin(Class::SuccessResponse, Method::ChannelBind, m.txn)) {
        w.message_integrity(key_); w.fingerprint();
        control_->send(from, from_len, out, w.len);
    }
}

void TurnServer::on_refresh(Allocation& a, const sockaddr* from, int from_len,
                            const Parsed& m) noexcept {
    assert(control_ != nullptr);
    const ParsedAttr* lt = m.find(Attr::Lifetime);
    const std::uint32_t life = (lt != nullptr && lt->len >= 4) ? rd32(lt->v) : 600;
    if (life == 0) { a.used = false; if (alloc_count_) --alloc_count_; }
    std::uint8_t out[256];
    Writer w{out, sizeof(out)};
    if (w.begin(Class::SuccessResponse, Method::Refresh, m.txn)) {
        w.u32(Attr::Lifetime, life);
        w.message_integrity(key_); w.fingerprint();
        control_->send(from, from_len, out, w.len);
    }
}

bool TurnServer::feed(const sockaddr* from, int from_len,
                      const std::uint8_t* data, std::size_t len) noexcept {
    assert(from != nullptr && control_ != nullptr);
    if (is_channel_data(data, len))
        return on_channel_data(from, from_len, data, len);
    Parsed m;
    if (!parse(data, len, m)) return false;
    if (m.method == Method::Send && m.msg_class == Class::Indication) {
        on_send_indication(from, from_len, m);
        return true;
    }
    if (m.msg_class != Class::Request) return true;  // consumed (indication/resp)

    // Long-term credential challenge: unauthenticated / bad-auth -> 401.
    if (m.find(Attr::MessageIntegrity) == nullptr || !verify_auth(data, len)) {
        send_error(from, from_len, m.method, m.txn, 401, /*with_realm=*/true);
        return true;
    }
    if (m.method == Method::Allocate) {
        on_allocate(from, from_len, m);
        return true;
    }
    Allocation* a = find_alloc(from, from_len);
    if (a == nullptr) {
        send_error(from, from_len, m.method, m.txn, 437, false);  // no alloc
        return true;
    }
    switch (m.method) {
        case Method::CreatePermission: on_create_permission(*a, from, from_len, m); break;
        case Method::ChannelBind:      on_channel_bind(*a, from, from_len, m);      break;
        case Method::Refresh:          on_refresh(*a, from, from_len, m);           break;
        default: break;
    }
    return true;
}

bool TurnServer::feed_relay(const sockaddr* from, int from_len,
                            const std::uint8_t* data, std::size_t len) noexcept {
    assert(from != nullptr);
    (void)from_len;
    if (control_ == nullptr) return false;
    // Find the allocation that permits `from`, then forward to its client as a
    // ChannelData (if a channel is bound) or a Data indication.
    for (std::size_t ai = 0; ai < kMaxAllocations; ++ai) {
        Allocation& a = allocs_[ai];
        if (!a.used) continue;
        for (std::size_t ci = 0; ci < kMaxChannels; ++ci) {
            Channel& c = a.chans[ci];
            if (!c.used) continue;
            const auto* x = reinterpret_cast<const sockaddr_in*>(&c.peer);
            const auto* y = reinterpret_cast<const sockaddr_in*>(from);
            if (from->sa_family == AF_INET && x->sin_port == y->sin_port &&
                x->sin_addr.s_addr == y->sin_addr.s_addr) {
                std::uint8_t out[1536];
                wr16(out, c.number);
                wr16(out + 2, static_cast<std::uint16_t>(len));
                const std::size_t cp = len <= sizeof(out) - 4 ? len : sizeof(out) - 4;
                std::memcpy(out + 4, data, cp);
                control_->send(reinterpret_cast<const sockaddr*>(&a.client),
                               a.client_len, out, 4 + cp);
                return true;
            }
        }
        for (std::size_t pi = 0; pi < kMaxPermissions; ++pi) {
            Permission& p = a.perms[pi];
            if (!p.used) continue;
            const auto* x = reinterpret_cast<const sockaddr_in*>(&p.peer);
            const auto* y = reinterpret_cast<const sockaddr_in*>(from);
            if (from->sa_family == AF_INET && x->sin_port == y->sin_port &&
                x->sin_addr.s_addr == y->sin_addr.s_addr) {
                std::uint8_t out[1536]; std::uint8_t txn[kTxnLen] = {0};
                txn[0] = static_cast<std::uint8_t>(ai + 1);
                Writer w{out, sizeof(out)};
                if (!w.begin(Class::Indication, Method::Data, txn)) return false;
                w.xor_addr(Attr::XorPeerAddress, from);
                const std::size_t cp = len <= 1280 ? len : 1280;
                w.attr(Attr::Data, data, static_cast<std::uint16_t>(cp));
                control_->send(reinterpret_cast<const sockaddr*>(&a.client),
                               a.client_len, out, w.len);
                return true;
            }
        }
    }
    return false;
}

}  // namespace turn
}  // namespace webrtc
}  // namespace bolt::api
