// src/webrtc/sctp.cpp — Bolt-native minimal SCTP over DTLS (RFC 4960 subset +
// RFC 8261 framing). See include/boltapi/webrtc/sctp.h for the architecture.
//
// CRC-32c is bolt::io::crc32c (RFC 3309 / Castagnoli, reflected) — hardware path
// on MSVC x64. SCTP zeroes the checksum field, computes the CRC over the whole
// packet, then stores the result LITTLE-ENDIAN in bytes [8..12).

#include "boltapi/webrtc/sctp.h"

#include "bolt/io/bolt_crc32c.h"

#include <cstring>
#include <random>

namespace bolt::api {
namespace webrtc {

namespace {

// --- big-endian read/write helpers (SCTP wire is network byte order) --------
inline std::uint16_t rd16(const std::uint8_t* p) noexcept {
    return static_cast<std::uint16_t>((p[0] << 8) | p[1]);
}
inline std::uint32_t rd32(const std::uint8_t* p) noexcept {
    return (static_cast<std::uint32_t>(p[0]) << 24) |
           (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8)  |
            static_cast<std::uint32_t>(p[3]);
}
inline void wr16(std::uint8_t* p, std::uint16_t v) noexcept {
    p[0] = static_cast<std::uint8_t>(v >> 8);
    p[1] = static_cast<std::uint8_t>(v);
}
inline void wr32(std::uint8_t* p, std::uint32_t v) noexcept {
    p[0] = static_cast<std::uint8_t>(v >> 24);
    p[1] = static_cast<std::uint8_t>(v >> 16);
    p[2] = static_cast<std::uint8_t>(v >> 8);
    p[3] = static_cast<std::uint8_t>(v);
}

// SCTP chunks are 4-byte aligned; the length field excludes padding.
inline std::size_t pad4(std::size_t n) noexcept { return (n + 3u) & ~static_cast<std::size_t>(3u); }

// TSN/SSN serial-number comparison (RFC 1982, 32-bit / 16-bit).
inline bool tsn_lt(std::uint32_t a, std::uint32_t b) noexcept {
    return static_cast<std::int32_t>(a - b) < 0;
}
inline bool tsn_le(std::uint32_t a, std::uint32_t b) noexcept {
    return a == b || tsn_lt(a, b);
}

std::uint32_t random32() noexcept {
    // Non-deterministic seed per call site is overkill; one PRNG suffices and is
    // never on a hot path (handshake only).
    static thread_local std::mt19937 rng{std::random_device{}()};
    std::uint32_t v = rng();
    if (v == 0) v = 1;  // verification tag must be non-zero (RFC 4960 §5.1)
    return v;
}

// Common header offsets.
constexpr std::size_t kHdrLen = 12;

}  // namespace

// ===========================================================================
// CRC-32c per RFC 3309. Compute over the packet with bytes [8..12) zeroed, then
// the result is stored little-endian. We return the value already laid out so
// the caller writes it straight into the header bytes via memcpy.
// ===========================================================================
std::uint32_t sctp_crc32c(const std::uint8_t* packet, std::size_t len) noexcept {
    if (!packet || len < kHdrLen) return 0;
    // Compute CRC with the checksum field treated as zero. We CRC the first 8
    // bytes, then 4 zero bytes, then the rest — avoids mutating the buffer.
    std::uint32_t crc = bolt::io::crc32c(packet, 8, 0);
    const std::uint8_t zero[4] = {0, 0, 0, 0};
    crc = bolt::io::crc32c_update(crc, zero, 4);
    if (len > kHdrLen) {
        crc = bolt::io::crc32c_update(crc, packet + kHdrLen, len - kHdrLen);
    }
    return crc;  // stored little-endian by the caller
}

// ===========================================================================
// SctpAssociation
// ===========================================================================
void SctpAssociation::init(Role role, SctpPacketSink sink,
                           SctpRecvHandler on_recv) noexcept {
    role_    = role;
    sink_    = std::move(sink);
    on_recv_ = std::move(on_recv);
    state_   = State::Closed;
    local_tag_ = random32();
    local_init_tsn_ = random32();
    next_tsn_  = local_init_tsn_;
}

void SctpAssociation::write_common_header(std::uint8_t* out,
                                          std::uint32_t verification_tag) noexcept {
    wr16(out + 0, src_port_);
    wr16(out + 2, dst_port_);
    wr32(out + 4, verification_tag);
    // Checksum bytes [8..12) zeroed; filled by ship_packet.
    out[8] = out[9] = out[10] = out[11] = 0;
}

bool SctpAssociation::ship_packet(std::uint8_t* out, std::size_t total_len) noexcept {
    if (!sink_ || total_len < kHdrLen || total_len > kSctpMaxPacket) return false;
    const std::uint32_t crc = sctp_crc32c(out, total_len);
    // RFC 3309: stored little-endian.
    out[8]  = static_cast<std::uint8_t>(crc & 0xFF);
    out[9]  = static_cast<std::uint8_t>((crc >> 8) & 0xFF);
    out[10] = static_cast<std::uint8_t>((crc >> 16) & 0xFF);
    out[11] = static_cast<std::uint8_t>((crc >> 24) & 0xFF);
    return sink_(out, total_len);
}

// --- handshake emitters -----------------------------------------------------
bool SctpAssociation::connect() noexcept {
    if (role_ != Role::Active || state_ != State::Closed) return false;
    return send_init();
}

bool SctpAssociation::send_init() noexcept {
    // INIT chunk (RFC 4960 §3.3.2): type=1, flags=0, length, then:
    //   Initiate Tag(4), a_rwnd(4), OS(2), MIS(2), Initial TSN(4).
    std::uint8_t out[kHdrLen + 4 + 16];
    write_common_header(out, 0);  // INIT carries verification tag 0
    std::uint8_t* c = out + kHdrLen;
    c[0] = static_cast<std::uint8_t>(ChunkType::Init);
    c[1] = 0;
    wr16(c + 2, static_cast<std::uint16_t>(4 + 16));
    wr32(c + 4, local_tag_);
    wr32(c + 8, kSctpInitialRwnd);
    wr16(c + 12, static_cast<std::uint16_t>(kSctpMaxStreams));  // OS
    wr16(c + 14, static_cast<std::uint16_t>(kSctpMaxStreams));  // MIS
    wr32(c + 16, local_init_tsn_);
    const std::size_t total = kHdrLen + 4 + 16;
    if (!ship_packet(out, total)) return false;
    state_ = State::CookieWait;
    return true;
}

bool SctpAssociation::send_init_ack(std::uint32_t peer_init_tag,
                                    std::uint32_t peer_init_tsn,
                                    std::uint16_t /*peer_streams*/,
                                    std::uint32_t peer_rwnd) noexcept {
    peer_tag_ = peer_init_tag;
    peer_init_tsn_ = peer_init_tsn;
    cum_ack_in_ = peer_init_tsn - 1;  // expect first DATA at peer_init_tsn
    have_cum_ack_ = true;
    peer_rwnd_ = peer_rwnd;

    // Deterministic state cookie: our tag + peer tag + peer init TSN, padded.
    std::memset(cookie_, 0, sizeof(cookie_));
    wr32(cookie_ + 0, local_tag_);
    wr32(cookie_ + 4, peer_tag_);
    wr32(cookie_ + 8, peer_init_tsn_);
    wr32(cookie_ + 12, local_init_tsn_);

    // INIT-ACK chunk: same fixed fields as INIT, then a State Cookie parameter
    // (type=7, len, value=cookie).
    const std::size_t cookie_param = 4 + kSctpCookieLen;  // TLV hdr + cookie
    std::uint8_t out[kHdrLen + 4 + 16 + 4 + kSctpCookieLen + 4];
    write_common_header(out, peer_tag_);  // verification tag = peer's tag
    std::uint8_t* c = out + kHdrLen;
    c[0] = static_cast<std::uint8_t>(ChunkType::InitAck);
    c[1] = 0;
    const std::uint16_t chunk_len =
        static_cast<std::uint16_t>(4 + 16 + cookie_param);
    wr16(c + 2, chunk_len);
    wr32(c + 4, local_tag_);
    wr32(c + 8, kSctpInitialRwnd);
    wr16(c + 12, static_cast<std::uint16_t>(kSctpMaxStreams));
    wr16(c + 14, static_cast<std::uint16_t>(kSctpMaxStreams));
    wr32(c + 16, local_init_tsn_);
    // State Cookie parameter.
    std::uint8_t* p = c + 20;
    wr16(p + 0, 7);  // State Cookie parameter type
    wr16(p + 2, static_cast<std::uint16_t>(cookie_param));
    std::memcpy(p + 4, cookie_, kSctpCookieLen);
    const std::size_t total = kHdrLen + chunk_len;
    return ship_packet(out, total);
}

bool SctpAssociation::send_cookie_echo(const std::uint8_t* cookie,
                                       std::size_t cookie_len) noexcept {
    if (cookie_len > kSctpCookieLen) cookie_len = kSctpCookieLen;
    std::uint8_t out[kHdrLen + 4 + kSctpCookieLen + 4];
    write_common_header(out, peer_tag_);
    std::uint8_t* c = out + kHdrLen;
    c[0] = static_cast<std::uint8_t>(ChunkType::CookieEcho);
    c[1] = 0;
    const std::uint16_t chunk_len = static_cast<std::uint16_t>(4 + cookie_len);
    wr16(c + 2, chunk_len);
    std::memcpy(c + 4, cookie, cookie_len);
    const std::size_t total = kHdrLen + pad4(chunk_len);
    // zero any pad bytes
    for (std::size_t i = kHdrLen + chunk_len; i < total; ++i) out[i] = 0;
    if (!ship_packet(out, total)) return false;
    state_ = State::CookieEchoed;
    return true;
}

bool SctpAssociation::send_cookie_ack() noexcept {
    std::uint8_t out[kHdrLen + 4];
    write_common_header(out, peer_tag_);
    std::uint8_t* c = out + kHdrLen;
    c[0] = static_cast<std::uint8_t>(ChunkType::CookieAck);
    c[1] = 0;
    wr16(c + 2, 4);
    return ship_packet(out, kHdrLen + 4);
}

bool SctpAssociation::send_sack() noexcept {
    if (!have_cum_ack_) return false;
    // SACK chunk (RFC 4960 §3.3.4): Cumulative TSN Ack(4), a_rwnd(4),
    // #gap-ack-blocks(2), #dup-tsns(2). v1 sends 0 gap blocks (cumulative only)
    // for simplicity; the cumulative ack covers contiguous delivery, which is
    // all reliable+ordered v1 needs. (Gap blocks parsing on the SEND side is
    // implemented for the peer.)
    std::uint8_t out[kHdrLen + 4 + 12];
    write_common_header(out, peer_tag_);
    std::uint8_t* c = out + kHdrLen;
    c[0] = static_cast<std::uint8_t>(ChunkType::Sack);
    c[1] = 0;
    wr16(c + 2, static_cast<std::uint16_t>(4 + 12));
    wr32(c + 4, cum_ack_in_);
    wr32(c + 8, kSctpInitialRwnd);
    wr16(c + 12, 0);  // gap ack blocks
    wr16(c + 14, 0);  // dup TSNs
    return ship_packet(out, kHdrLen + 4 + 12);
}

bool SctpAssociation::send_abort() noexcept {
    std::uint8_t out[kHdrLen + 4];
    write_common_header(out, peer_tag_);
    std::uint8_t* c = out + kHdrLen;
    c[0] = static_cast<std::uint8_t>(ChunkType::Abort);
    c[1] = 0;
    wr16(c + 2, 4);
    return ship_packet(out, kHdrLen + 4);
}

// --- chunk handlers ---------------------------------------------------------
void SctpAssociation::handle_init(const std::uint8_t* chunk, std::size_t len) noexcept {
    // INIT value: Initiate Tag(4) a_rwnd(4) OS(2) MIS(2) Initial TSN(4).
    if (len < 4 + 16) return;
    const std::uint8_t* v = chunk + 4;
    const std::uint32_t peer_tag  = rd32(v + 0);
    const std::uint32_t peer_rwnd = rd32(v + 4);
    const std::uint16_t peer_os   = rd16(v + 8);
    const std::uint32_t peer_tsn  = rd32(v + 12);
    if (peer_tag == 0) { state_ = State::Failed; return; }
    // As the responder, reply INIT-ACK with a state cookie. We stay stateless
    // until COOKIE-ECHO (the cookie carries what we need).
    send_init_ack(peer_tag, peer_tsn, peer_os, peer_rwnd);
}

void SctpAssociation::handle_init_ack(const std::uint8_t* chunk, std::size_t len) noexcept {
    if (role_ != Role::Active || state_ != State::CookieWait) return;
    if (len < 4 + 16) return;
    const std::uint8_t* v = chunk + 4;
    peer_tag_ = rd32(v + 0);
    peer_rwnd_ = rd32(v + 4);
    peer_init_tsn_ = rd32(v + 12);
    cum_ack_in_ = peer_init_tsn_ - 1;
    have_cum_ack_ = true;
    if (peer_tag_ == 0) { state_ = State::Failed; return; }

    // Find the State Cookie parameter (type 7) in the variable section.
    const std::size_t chunk_len = rd16(chunk + 2);
    std::size_t off = 4 + 16;  // after fixed fields
    const std::uint8_t* cookie = nullptr;
    std::size_t cookie_len = 0;
    while (off + 4 <= chunk_len && off + 4 <= len) {
        const std::uint16_t ptype = rd16(chunk + off);
        const std::uint16_t plen  = rd16(chunk + off + 2);
        if (plen < 4 || off + plen > len) break;
        if (ptype == 7) {
            cookie = chunk + off + 4;
            cookie_len = static_cast<std::size_t>(plen) - 4;
            break;
        }
        off += pad4(plen);
    }
    if (!cookie || cookie_len == 0) { state_ = State::Failed; return; }
    send_cookie_echo(cookie, cookie_len);
}

void SctpAssociation::handle_cookie_echo(const std::uint8_t* chunk, std::size_t len) noexcept {
    // Responder receives the echoed cookie; validate it carries our tag, then
    // promote to Established and reply COOKIE-ACK.
    if (len < 4 + 16) { /* tolerate short but require our 16-byte payload */ }
    const std::size_t chunk_len = rd16(chunk + 2);
    if (chunk_len < 4 + 16 || len < 4 + 16) { state_ = State::Failed; return; }
    const std::uint8_t* ck = chunk + 4;
    const std::uint32_t echoed_local = rd32(ck + 0);
    const std::uint32_t echoed_peer  = rd32(ck + 4);
    const std::uint32_t echoed_ptsn  = rd32(ck + 8);
    const std::uint32_t echoed_ltsn  = rd32(ck + 12);
    if (echoed_local != local_tag_) { state_ = State::Failed; return; }
    // Restore peer state from the cookie (stateless responder).
    peer_tag_ = echoed_peer;
    peer_init_tsn_ = echoed_ptsn;
    local_init_tsn_ = echoed_ltsn;
    next_tsn_ = local_init_tsn_;
    cum_ack_in_ = peer_init_tsn_ - 1;
    have_cum_ack_ = true;
    send_cookie_ack();
    state_ = State::Established;
}

void SctpAssociation::handle_cookie_ack(const std::uint8_t* /*chunk*/, std::size_t /*len*/) noexcept {
    if (role_ == Role::Active && state_ == State::CookieEchoed) {
        state_ = State::Established;
    }
}

void SctpAssociation::handle_data(const std::uint8_t* chunk, std::size_t len) noexcept {
    // DATA chunk (RFC 4960 §3.3.1): flags then TSN(4) StreamID(2) StreamSeq(2)
    // PPID(4) then user data.
    if (len < 4 + 12) return;
    const std::uint8_t flags = chunk[1];
    const std::size_t chunk_len = rd16(chunk + 2);
    if (chunk_len < 4 + 12 || chunk_len > len) return;
    const std::uint8_t* v = chunk + 4;
    const std::uint32_t tsn      = rd32(v + 0);
    const std::uint16_t sid      = rd16(v + 4);
    const std::uint16_t ssn      = rd16(v + 6);
    const std::uint32_t ppid     = rd32(v + 8);
    const std::uint8_t* payload  = v + 12;
    const std::size_t payload_len = chunk_len - (4 + 12);
    const bool unordered = (flags & kDataFlagUnordered) != 0;

    if (sid >= kSctpMaxStreams) return;  // bounded
    if (payload_len > kSctpMaxUserData) return;  // single-chunk v1 (no reassembly)

    // Update cumulative ack (only when this TSN is the next contiguous one).
    if (have_cum_ack_) {
        if (tsn == cum_ack_in_ + 1) {
            cum_ack_in_ = tsn;
        } else if (tsn_le(tsn, cum_ack_in_)) {
            // Duplicate of an already-acked TSN: ack again, don't redeliver.
            send_sack();
            return;
        } else {
            // Gap: out-of-order TSN. We still buffer it (below) but don't move
            // cum_ack_in_. A SACK with cumulative ack tells the peer to resend
            // the gap (v1: no gap-ack blocks emitted, so the peer retransmits).
        }
    }

    // Deliver. Ordered: respect per-stream SSN; buffer if early. Unordered:
    // deliver immediately.
    ++data_in_;
    if (unordered) {
        if (on_recv_) {
            SctpRecvMessage m{sid, ppid, payload, payload_len};
            on_recv_(m);
        }
        send_sack();
        return;
    }

    InStream& st = in_streams_[sid];
    if (ssn == st.next_ssn) {
        if (on_recv_) {
            SctpRecvMessage m{sid, ppid, payload, payload_len};
            on_recv_(m);
        }
        st.next_ssn = static_cast<std::uint16_t>(st.next_ssn + 1);
        deliver_in_order(sid);
    } else if (static_cast<std::uint16_t>(ssn - st.next_ssn) < 0x8000) {
        // Future SSN: buffer for later (bounded).
        for (std::size_t i = 0; i < kSctpRecvReorder; ++i) {
            if (!in_pending_[i].used) {
                InPending& p = in_pending_[i];
                p.used = true;
                p.stream_id = sid;
                p.ssn = ssn;
                p.ppid = ppid;
                p.len = payload_len;
                std::memcpy(p.data, payload, payload_len);
                break;
            }
        }
    }
    // else: old SSN duplicate, ignore.
    send_sack();
}

void SctpAssociation::deliver_in_order(std::uint16_t stream_id) noexcept {
    InStream& st = in_streams_[stream_id];
    bool progressed = true;
    while (progressed) {
        progressed = false;
        for (std::size_t i = 0; i < kSctpRecvReorder; ++i) {
            InPending& p = in_pending_[i];
            if (p.used && p.stream_id == stream_id && p.ssn == st.next_ssn) {
                if (on_recv_) {
                    SctpRecvMessage m{p.stream_id, p.ppid, p.data, p.len};
                    on_recv_(m);
                }
                st.next_ssn = static_cast<std::uint16_t>(st.next_ssn + 1);
                p.used = false;
                progressed = true;
                break;
            }
        }
    }
}

void SctpAssociation::handle_sack(const std::uint8_t* chunk, std::size_t len) noexcept {
    if (len < 4 + 12) return;
    const std::uint8_t* v = chunk + 4;
    const std::uint32_t cum_tsn = rd32(v + 0);
    peer_rwnd_ = rd32(v + 4);
    const std::uint16_t ngaps = rd16(v + 8);

    // Mark every in-flight DATA <= cum_tsn as acked (free its ring slot).
    for (std::size_t i = 0; i < kSctpSendQueue; ++i) {
        OutChunk& o = out_ring_[i];
        if (o.used && !o.acked && tsn_le(o.tsn, cum_tsn)) {
            o.acked = true;
            o.used  = false;
        }
    }
    // Process gap-ack blocks (RFC 4960 §3.3.4): each block is start/end offset
    // from cum_tsn; TSNs in those ranges are also acked.
    std::size_t off = 4 + 12;
    for (std::uint16_t g = 0; g < ngaps && off + 4 <= len; ++g, off += 4) {
        const std::uint16_t gstart = rd16(chunk + off);
        const std::uint16_t gend   = rd16(chunk + off + 2);
        const std::uint32_t lo = cum_tsn + gstart;
        const std::uint32_t hi = cum_tsn + gend;
        for (std::size_t i = 0; i < kSctpSendQueue; ++i) {
            OutChunk& o = out_ring_[i];
            if (o.used && !o.acked && tsn_le(lo, o.tsn) && tsn_le(o.tsn, hi)) {
                o.acked = true;
                o.used  = false;
            }
        }
    }
    // Any still-unacked in-flight chunk with TSN <= cum_tsn shouldn't exist; the
    // remaining unacked ones beyond cum_tsn accrue miss_count for fast resend.
    for (std::size_t i = 0; i < kSctpSendQueue; ++i) {
        OutChunk& o = out_ring_[i];
        if (o.used && !o.acked && tsn_lt(cum_tsn, o.tsn)) {
            ++o.miss_count;
        }
    }
}

// --- feed -------------------------------------------------------------------
bool SctpAssociation::feed(const std::uint8_t* data, std::size_t len) noexcept {
    if (state_ == State::Failed) return false;
    if (!data || len < kHdrLen) return state_ != State::Failed;

    // Verify CRC-32c.
    const std::uint32_t got =
        static_cast<std::uint32_t>(data[8]) |
        (static_cast<std::uint32_t>(data[9]) << 8) |
        (static_cast<std::uint32_t>(data[10]) << 16) |
        (static_cast<std::uint32_t>(data[11]) << 24);
    const std::uint32_t want = sctp_crc32c(data, len);
    if (got != want) {
        return state_ != State::Failed;  // drop corrupt packet, stay alive
    }

    // Iterate chunks.
    std::size_t off = kHdrLen;
    while (off + 4 <= len) {
        const std::uint8_t  ctype = data[off];
        const std::uint16_t clen  = rd16(data + off + 2);
        if (clen < 4) break;                       // malformed
        if (off + clen > len) break;               // truncated
        const std::uint8_t* chunk = data + off;

        switch (static_cast<ChunkType>(ctype)) {
            case ChunkType::Init:       handle_init(chunk, len - off); break;
            case ChunkType::InitAck:    handle_init_ack(chunk, len - off); break;
            case ChunkType::CookieEcho: handle_cookie_echo(chunk, len - off); break;
            case ChunkType::CookieAck:  handle_cookie_ack(chunk, len - off); break;
            case ChunkType::Data:       handle_data(chunk, len - off); break;
            case ChunkType::Sack:       handle_sack(chunk, len - off); break;
            case ChunkType::Abort:      state_ = State::Failed; break;
            case ChunkType::Heartbeat:  /* ignore in v1 */ break;
            default: break;  // skip unknown chunk
        }
        if (state_ == State::Failed) return false;
        off += pad4(clen);
        if (pad4(clen) == 0) break;  // safety
    }
    return true;
}

// --- send -------------------------------------------------------------------
bool SctpAssociation::send(std::uint16_t stream_id, std::uint32_t ppid,
                           const std::uint8_t* data, std::size_t len) noexcept {
    if (state_ != State::Established) return false;
    if (stream_id >= kSctpMaxStreams) return false;
    if (len > kSctpMaxUserData) return false;  // v1: single-chunk only

    // Find a free ring slot.
    OutChunk* slot = nullptr;
    for (std::size_t i = 0; i < kSctpSendQueue; ++i) {
        if (!out_ring_[i].used) { slot = &out_ring_[i]; break; }
    }
    if (!slot) return false;  // bounded send window full

    const std::uint32_t tsn = next_tsn_;
    const std::uint16_t ssn = out_ssn_[stream_id];

    // Build the packet: common header + one DATA chunk.
    std::uint8_t* out = slot->packet;
    write_common_header(out, peer_tag_);
    std::uint8_t* c = out + kHdrLen;
    c[0] = static_cast<std::uint8_t>(ChunkType::Data);
    c[1] = kDataFlagBegin | kDataFlagEnd;  // single, ordered, complete message
    const std::uint16_t chunk_len = static_cast<std::uint16_t>(4 + 12 + len);
    wr16(c + 2, chunk_len);
    wr32(c + 4, tsn);
    wr16(c + 8, stream_id);
    wr16(c + 10, ssn);
    wr32(c + 12, ppid);
    if (len > 0) std::memcpy(c + 16, data, len);
    const std::size_t unpadded = kHdrLen + chunk_len;
    const std::size_t total = kHdrLen + pad4(chunk_len);
    for (std::size_t i = unpadded; i < total; ++i) out[i] = 0;  // pad

    slot->used = true;
    slot->acked = false;
    slot->tsn = tsn;
    slot->miss_count = 0;
    slot->len = total;

    if (!ship_packet(out, total)) {
        slot->used = false;
        return false;
    }
    next_tsn_ = next_tsn_ + 1;
    out_ssn_[stream_id] = static_cast<std::uint16_t>(ssn + 1);
    ++data_out_;
    return true;
}

std::size_t SctpAssociation::tick_retransmit() noexcept {
    if (state_ != State::Established) return 0;
    std::size_t n = 0;
    for (std::size_t i = 0; i < kSctpSendQueue; ++i) {
        OutChunk& o = out_ring_[i];
        if (o.used && !o.acked && o.miss_count >= 1) {
            // Re-ship the saved framed packet (CRC already valid; verification
            // tag unchanged). Reset miss counter so we don't storm.
            if (sink_ && o.len >= kHdrLen) {
                sink_(o.packet, o.len);
                o.miss_count = 0;
                ++n;
            }
        }
    }
    return n;
}

}  // namespace webrtc
}  // namespace bolt::api
