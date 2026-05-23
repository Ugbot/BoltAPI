// src/webrtc/sctp.cpp — Bolt-native SCTP over DTLS (RFC 4960 subset +
// RFC 8261 framing + RFC 3758 partial reliability + RFC 6298 RTO). See
// include/boltapi/webrtc/sctp.h for the architecture.
//
// CRC-32c is bolt::io::crc32c (RFC 3309 / Castagnoli, reflected) — hardware path
// on MSVC x64. SCTP zeroes the checksum field, computes the CRC over the whole
// packet, then stores the result LITTLE-ENDIAN in bytes [8..12).

#include "boltapi/webrtc/sctp.h"

#include "bolt/io/bolt_crc32c.h"

#include <cassert>
#include <chrono>
#include <cstring>
#include <new>
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

inline std::size_t pad4(std::size_t n) noexcept { return (n + 3u) & ~static_cast<std::size_t>(3u); }

inline bool tsn_lt(std::uint32_t a, std::uint32_t b) noexcept {
    return static_cast<std::int32_t>(a - b) < 0;
}
inline bool tsn_le(std::uint32_t a, std::uint32_t b) noexcept {
    return a == b || tsn_lt(a, b);
}
inline bool tsn_gt(std::uint32_t a, std::uint32_t b) noexcept { return tsn_lt(b, a); }

std::uint32_t random32() noexcept {
    static thread_local std::mt19937 rng{std::random_device{}()};
    std::uint32_t v = rng();
    if (v == 0) v = 1;  // verification tag must be non-zero (RFC 4960 §5.1)
    return v;
}

std::uint64_t now_steady_ms() noexcept {
    using namespace std::chrono;
    return static_cast<std::uint64_t>(
        duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count());
}

constexpr std::size_t kHdrLen = 12;
constexpr std::size_t kDataHdr = 16;   // chunk type(1)+flags(1)+len(2)+TSN(4)+sid(2)+ssn(2)+ppid(4)

}  // namespace

// ===========================================================================
// CRC-32c per RFC 3309 (checksum field treated as zero).
// ===========================================================================
std::uint32_t sctp_crc32c(const std::uint8_t* packet, std::size_t len) noexcept {
    if (!packet || len < kHdrLen) return 0;
    std::uint32_t crc = bolt::io::crc32c(packet, 8, 0);
    const std::uint8_t zero[4] = {0, 0, 0, 0};
    crc = bolt::io::crc32c_update(crc, zero, 4);
    if (len > kHdrLen) {
        crc = bolt::io::crc32c_update(crc, packet + kHdrLen, len - kHdrLen);
    }
    return crc;
}

// ===========================================================================
// Lifecycle
// ===========================================================================
SctpAssociation::~SctpAssociation() {
    if (reasm_pool_) { delete[] reasm_pool_; reasm_pool_ = nullptr; }
    if (infrag_) { delete[] infrag_; infrag_ = nullptr; }
}

void SctpAssociation::ensure_pool() noexcept {
    if (!reasm_pool_) {
        // One bounded allocation. nothrow new -> nullptr on OOM (no exceptions).
        reasm_pool_ = new (std::nothrow) std::uint8_t[kReasmSlabs * kSctpMaxMessage];
        // If allocation fails, alloc_slab() returns nullptr and the caller ABORTs
        // the assoc gracefully rather than touching null.
    }
    if (!infrag_) {
        infrag_ = new (std::nothrow) InFrag[kSctpMaxFrags];
    }
}

std::uint8_t* SctpAssociation::alloc_slab() noexcept {
    ensure_pool();
    if (!reasm_pool_) return nullptr;
    for (std::size_t i = 0; i < kReasmSlabs; ++i) {
        if (!reasm_slab_used_[i]) {
            reasm_slab_used_[i] = true;
            return reasm_pool_ + i * kSctpMaxMessage;
        }
    }
    return nullptr;  // bounded: pool exhausted
}

void SctpAssociation::free_slab(std::uint8_t* p) noexcept {
    if (!p || !reasm_pool_) return;
    const std::size_t idx = static_cast<std::size_t>(p - reasm_pool_) / kSctpMaxMessage;
    if (idx < kReasmSlabs) reasm_slab_used_[idx] = false;
}

void SctpAssociation::init(Role role, SctpPacketSink sink,
                           SctpRecvHandler on_recv) noexcept {
    role_    = role;
    sink_    = std::move(sink);
    on_recv_ = std::move(on_recv);
    state_   = State::Closed;
    local_tag_ = random32();
    local_init_tsn_ = random32();
    next_tsn_  = local_init_tsn_;
    adv_ack_point_ = local_init_tsn_ - 1;
    cwnd_ = static_cast<std::uint32_t>(4 * kSctpMaxPacket);  // RFC 4960 §7.2.1
    ssthresh_ = kSctpInitialRwnd;
    rto_ms_ = kSctpRtoInitialMs;
    ensure_pool();
}

// ===========================================================================
// Packet framing
// ===========================================================================
void SctpAssociation::write_common_header(std::uint8_t* out,
                                          std::uint32_t verification_tag) noexcept {
    wr16(out + 0, src_port_);
    wr16(out + 2, dst_port_);
    wr32(out + 4, verification_tag);
    out[8] = out[9] = out[10] = out[11] = 0;
}

bool SctpAssociation::ship_packet(std::uint8_t* out, std::size_t total_len) noexcept {
    if (!sink_ || total_len < kHdrLen || total_len > kSctpMaxPacket) return false;
    const std::uint32_t crc = sctp_crc32c(out, total_len);
    out[8]  = static_cast<std::uint8_t>(crc & 0xFF);
    out[9]  = static_cast<std::uint8_t>((crc >> 8) & 0xFF);
    out[10] = static_cast<std::uint8_t>((crc >> 16) & 0xFF);
    out[11] = static_cast<std::uint8_t>((crc >> 24) & 0xFF);
    return sink_(out, total_len);
}

// ===========================================================================
// Handshake emitters
// ===========================================================================
bool SctpAssociation::connect() noexcept {
    if (role_ != Role::Active || state_ != State::Closed) return false;
    return send_init();
}

bool SctpAssociation::send_init() noexcept {
    // INIT (RFC 4960 §3.3.2). We advertise the FORWARD-TSN supported parameter
    // (type 49152 / 0xC000, RFC 3758 §3.1) so the peer enables partial rel.
    std::uint8_t out[kHdrLen + 4 + 16 + 4];
    write_common_header(out, 0);
    std::uint8_t* c = out + kHdrLen;
    c[0] = static_cast<std::uint8_t>(ChunkType::Init);
    c[1] = 0;
    wr32(c + 4, local_tag_);
    wr32(c + 8, kSctpInitialRwnd);
    wr16(c + 12, static_cast<std::uint16_t>(kSctpMaxStreams));  // OS
    wr16(c + 14, static_cast<std::uint16_t>(kSctpMaxStreams));  // MIS
    wr32(c + 16, local_init_tsn_);
    // Forward-TSN-Supported parameter (length 4, no value).
    std::uint8_t* p = c + 20;
    wr16(p + 0, 0xC000);
    wr16(p + 2, 4);
    const std::uint16_t chunk_len = static_cast<std::uint16_t>(4 + 16 + 4);
    wr16(c + 2, chunk_len);
    const std::size_t total = kHdrLen + chunk_len;
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
    cum_ack_in_ = peer_init_tsn - 1;
    have_cum_ack_ = true;
    peer_rwnd_ = peer_rwnd;

    std::memset(cookie_, 0, sizeof(cookie_));
    wr32(cookie_ + 0, local_tag_);
    wr32(cookie_ + 4, peer_tag_);
    wr32(cookie_ + 8, peer_init_tsn_);
    wr32(cookie_ + 12, local_init_tsn_);

    const std::size_t cookie_param = 4 + kSctpCookieLen;
    std::uint8_t out[kHdrLen + 4 + 16 + 4 + kSctpCookieLen + 8];
    write_common_header(out, peer_tag_);
    std::uint8_t* c = out + kHdrLen;
    c[0] = static_cast<std::uint8_t>(ChunkType::InitAck);
    c[1] = 0;
    wr32(c + 4, local_tag_);
    wr32(c + 8, kSctpInitialRwnd);
    wr16(c + 12, static_cast<std::uint16_t>(kSctpMaxStreams));
    wr16(c + 14, static_cast<std::uint16_t>(kSctpMaxStreams));
    wr32(c + 16, local_init_tsn_);
    std::uint8_t* p = c + 20;
    wr16(p + 0, 7);  // State Cookie parameter type
    wr16(p + 2, static_cast<std::uint16_t>(cookie_param));
    std::memcpy(p + 4, cookie_, kSctpCookieLen);
    // Forward-TSN-Supported parameter after the cookie.
    std::uint8_t* p2 = p + cookie_param;
    wr16(p2 + 0, 0xC000);
    wr16(p2 + 2, 4);
    const std::uint16_t chunk_len =
        static_cast<std::uint16_t>(4 + 16 + cookie_param + 4);
    wr16(c + 2, chunk_len);
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

// SACK with our OWN gap-ack blocks so the peer can fast-retransmit (RFC 4960
// §3.3.4). Blocks are offsets from cum_ack_in_ for contiguous runs of received
// TSNs above the cumulative ack.
bool SctpAssociation::send_sack() noexcept {
    if (!have_cum_ack_) return false;

    // Walk the receive bitmap, building up to a bounded number of gap blocks.
    constexpr std::size_t kMaxGaps = 32;
    std::uint16_t gstart[kMaxGaps];
    std::uint16_t gend[kMaxGaps];
    std::size_t ngaps = 0;

    bool in_run = false;
    std::uint32_t run_start = 0;
    for (std::uint32_t off = 1; off <= kRecvWindow; ++off) {
        const std::uint32_t tsn = cum_ack_in_ + off;
        const bool seen = tsn_received(tsn);
        if (seen && !in_run) { in_run = true; run_start = off; }
        if ((!seen || off == kRecvWindow) && in_run) {
            const std::uint32_t run_end = seen ? off : (off - 1);
            if (ngaps < kMaxGaps) {
                gstart[ngaps] = static_cast<std::uint16_t>(run_start);
                gend[ngaps]   = static_cast<std::uint16_t>(run_end);
                ++ngaps;
            }
            in_run = false;
            if (ngaps >= kMaxGaps) break;
        }
    }

    std::uint8_t out[kHdrLen + 4 + 12 + kMaxGaps * 4];
    write_common_header(out, peer_tag_);
    std::uint8_t* c = out + kHdrLen;
    c[0] = static_cast<std::uint8_t>(ChunkType::Sack);
    c[1] = 0;
    wr32(c + 4, cum_ack_in_);
    wr32(c + 8, kSctpInitialRwnd);
    wr16(c + 12, static_cast<std::uint16_t>(ngaps));
    wr16(c + 14, 0);  // dup TSNs (not reported)
    std::uint8_t* g = c + 16;
    for (std::size_t i = 0; i < ngaps; ++i) {
        wr16(g + 0, gstart[i]);
        wr16(g + 2, gend[i]);
        g += 4;
    }
    const std::uint16_t chunk_len =
        static_cast<std::uint16_t>(4 + 12 + ngaps * 4);
    wr16(c + 2, chunk_len);
    return ship_packet(out, kHdrLen + chunk_len);
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

// FORWARD-TSN (RFC 3758 §3.2): new cumulative TSN + per-stream highest abandoned
// ordered SSN, so the receiver can advance past abandoned fragments.
bool SctpAssociation::send_forward_tsn() noexcept {
    if (!sink_) return false;
    // Collect abandoned ordered streams + their highest abandoned SSN.
    constexpr std::size_t kMaxStreamEntries = 16;
    std::uint16_t sids[kMaxStreamEntries];
    std::uint16_t ssns[kMaxStreamEntries];
    std::size_t n = 0;
    for (std::size_t i = 0; i < kSctpSendQueue; ++i) {
        OutChunk& o = out_ring_[i];
        if (!o.used || !o.abandoned) continue;
        if ((o.flags & kDataFlagUnordered) != 0) continue;  // no SSN to report
        // Record/merge highest SSN per stream.
        bool found = false;
        for (std::size_t k = 0; k < n; ++k) {
            if (sids[k] == o.stream_id) {
                found = true;
                if (static_cast<std::uint16_t>(o.ssn - ssns[k]) < 0x8000) ssns[k] = o.ssn;
                break;
            }
        }
        if (!found && n < kMaxStreamEntries) {
            sids[n] = o.stream_id; ssns[n] = o.ssn; ++n;
        }
    }

    std::uint8_t out[kHdrLen + 8 + kMaxStreamEntries * 4];
    write_common_header(out, peer_tag_);
    std::uint8_t* c = out + kHdrLen;
    c[0] = static_cast<std::uint8_t>(ChunkType::ForwardTsn);
    c[1] = 0;
    wr32(c + 4, adv_ack_point_);  // New Cumulative TSN
    std::uint8_t* s = c + 8;
    for (std::size_t i = 0; i < n; ++i) {
        wr16(s + 0, sids[i]);
        wr16(s + 2, ssns[i]);
        s += 4;
    }
    const std::uint16_t chunk_len = static_cast<std::uint16_t>(8 + n * 4);
    wr16(c + 2, chunk_len);
    need_forward_tsn_ = false;
    return ship_packet(out, kHdrLen + chunk_len);
}

// ===========================================================================
// Handshake handlers
// ===========================================================================
void SctpAssociation::handle_init(const std::uint8_t* chunk, std::size_t len) noexcept {
    if (len < 4 + 16) return;
    const std::uint8_t* v = chunk + 4;
    const std::uint32_t peer_tag  = rd32(v + 0);
    const std::uint32_t peer_rwnd = rd32(v + 4);
    const std::uint16_t peer_os   = rd16(v + 8);
    const std::uint32_t peer_tsn  = rd32(v + 12);
    if (peer_tag == 0) { state_ = State::Failed; return; }
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

    const std::size_t chunk_len = rd16(chunk + 2);
    std::size_t off = 4 + 16;
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
    const std::size_t chunk_len = rd16(chunk + 2);
    if (chunk_len < 4 + 16 || len < 4 + 16) { state_ = State::Failed; return; }
    const std::uint8_t* ck = chunk + 4;
    const std::uint32_t echoed_local = rd32(ck + 0);
    const std::uint32_t echoed_peer  = rd32(ck + 4);
    const std::uint32_t echoed_ptsn  = rd32(ck + 8);
    const std::uint32_t echoed_ltsn  = rd32(ck + 12);
    if (echoed_local != local_tag_) { state_ = State::Failed; return; }
    peer_tag_ = echoed_peer;
    peer_init_tsn_ = echoed_ptsn;
    local_init_tsn_ = echoed_ltsn;
    next_tsn_ = local_init_tsn_;
    adv_ack_point_ = local_init_tsn_ - 1;
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

// ===========================================================================
// Receiver: TSN bookkeeping
// ===========================================================================
bool SctpAssociation::tsn_received(std::uint32_t tsn) const noexcept {
    if (!have_cum_ack_) return false;
    if (tsn_le(tsn, cum_ack_in_)) return true;  // already cumulatively acked
    const std::uint32_t off = tsn - cum_ack_in_ - 1;  // 0-based slot past cum
    if (off >= kRecvWindow) return false;
    return (recv_bitmap_[off >> 3] & (1u << (off & 7))) != 0;
}

bool SctpAssociation::record_received(std::uint32_t tsn) noexcept {
    if (!have_cum_ack_) return false;
    if (tsn_le(tsn, cum_ack_in_)) return false;  // duplicate/old
    const std::uint32_t off = tsn - cum_ack_in_ - 1;
    if (off >= kRecvWindow) return false;         // outside window: drop (bounded)
    std::uint8_t& byte = recv_bitmap_[off >> 3];
    const std::uint8_t bit = static_cast<std::uint8_t>(1u << (off & 7));
    if (byte & bit) return false;                 // already recorded (dup)
    byte |= bit;
    return true;
}

void SctpAssociation::advance_cum_ack() noexcept {
    if (!have_cum_ack_) return;
    // Walk contiguous set bits at the front of the window, advancing cum_ack_in_
    // and shifting the bitmap down.
    std::uint32_t advanced = 0;
    while (advanced < kRecvWindow) {
        const std::uint32_t next = cum_ack_in_ + 1;  // candidate
        const std::uint32_t off = 0;                 // always front after each advance
        (void)next; (void)off;
        if ((recv_bitmap_[0] & 1u) == 0) break;
        // Pop the front bit: advance cum ack, shift whole bitmap right by 1.
        cum_ack_in_ = cum_ack_in_ + 1;
        // Shift bitmap down by one bit.
        std::uint8_t carry = 0;
        for (std::size_t i = (kRecvWindow / 8); i-- > 0; ) {
            const std::uint8_t cur = recv_bitmap_[i];
            recv_bitmap_[i] = static_cast<std::uint8_t>((cur >> 1) | (carry << 7));
            carry = static_cast<std::uint8_t>(cur & 1u);
        }
        ++advanced;
    }
}

// ===========================================================================
// Receiver: DATA + reassembly
// ===========================================================================
void SctpAssociation::on_full_message(std::uint16_t sid, std::uint32_t ppid,
                                      bool unordered, std::uint16_t ssn,
                                      const std::uint8_t* data,
                                      std::size_t len) noexcept {
    if (unordered) {
        ++data_in_;
        if (on_recv_) { SctpRecvMessage m{sid, ppid, data, len}; on_recv_(m); }
        return;
    }
    InStream& st = in_streams_[sid];
    if (ssn == st.next_ssn) {
        ++data_in_;
        if (on_recv_) { SctpRecvMessage m{sid, ppid, data, len}; on_recv_(m); }
        st.next_ssn = static_cast<std::uint16_t>(st.next_ssn + 1);
        deliver_ordered(sid);
    } else if (static_cast<std::uint16_t>(ssn - st.next_ssn) < 0x8000) {
        // Future SSN: buffer the completed message (bounded; needs a slab).
        for (std::size_t i = 0; i < kSctpRecvReorder; ++i) {
            if (!in_pending_[i].used) {
                std::uint8_t* slab = alloc_slab();
                if (!slab) { send_abort(); state_ = State::Failed; return; }
                InPending& p = in_pending_[i];
                p.used = true; p.stream_id = sid; p.ssn = ssn; p.ppid = ppid;
                p.len = len; p.data = slab;
                if (len) std::memcpy(slab, data, len);
                return;
            }
        }
        // Reorder buffer full: drop (peer will not get this msg but stays alive).
    }
    // else: old SSN already delivered — ignore.
}

void SctpAssociation::deliver_ordered(std::uint16_t stream_id) noexcept {
    InStream& st = in_streams_[stream_id];
    bool progressed = true;
    while (progressed) {
        progressed = false;
        for (std::size_t i = 0; i < kSctpRecvReorder; ++i) {
            InPending& p = in_pending_[i];
            if (p.used && p.stream_id == stream_id && p.ssn == st.next_ssn) {
                ++data_in_;
                if (on_recv_) { SctpRecvMessage m{p.stream_id, p.ppid, p.data, p.len}; on_recv_(m); }
                st.next_ssn = static_cast<std::uint16_t>(st.next_ssn + 1);
                free_slab(p.data);
                p.used = false; p.data = nullptr;
                progressed = true;
                break;
            }
        }
    }
}

void SctpAssociation::handle_data(const std::uint8_t* chunk, std::size_t len) noexcept {
    if (len < kDataHdr) return;
    const std::uint8_t flags = chunk[1];
    const std::size_t chunk_len = rd16(chunk + 2);
    if (chunk_len < kDataHdr || chunk_len > len) return;
    const std::uint8_t* v = chunk + 4;
    const std::uint32_t tsn      = rd32(v + 0);
    const std::uint16_t sid      = rd16(v + 4);
    const std::uint16_t ssn      = rd16(v + 6);
    const std::uint32_t ppid     = rd32(v + 8);
    const std::uint8_t* payload  = v + 12;
    const std::size_t payload_len = chunk_len - kDataHdr;
    const bool unordered = (flags & kDataFlagUnordered) != 0;
    const bool begin = (flags & kDataFlagBegin) != 0;
    const bool end   = (flags & kDataFlagEnd) != 0;

    if (sid >= kSctpMaxStreams) return;
    // Accept the PEER's MTU-sized chunks (larger than our send chunk size).
    if (payload_len > kSctpMaxRecvChunkData) return;

    // Record the TSN; duplicates / out-of-window get a SACK but no redelivery.
    const bool fresh = record_received(tsn);
    if (!fresh) { send_sack(); return; }

    // Fast path: a complete single-chunk message (B and E both set). No need to
    // buffer — deliver immediately (ordered delivery handled by SSN downstream).
    if (begin && end) {
        advance_cum_ack();
        on_full_message(sid, ppid, unordered, ssn, payload, payload_len);
        drain_fragments();   // a buffered run may now be deliverable too
        send_sack();
        return;
    }

    // Multi-fragment chunk: BUFFER it (we only gap-acked it because we stored it,
    // so we never advertise data we then drop), then try to assemble.
    ingest_fragment(tsn, sid, ssn, ppid, flags, payload, payload_len);
    if (state_ == State::Failed) return;
    advance_cum_ack();
    drain_fragments();
    send_sack();
}

// Buffer one received DATA fragment into the bounded reorder store. Bounded:
// on overflow we ABORT (TigerStyle: never unbounded, never UB).
void SctpAssociation::ingest_fragment(std::uint32_t tsn, std::uint16_t sid,
                                      std::uint16_t ssn, std::uint32_t ppid,
                                      std::uint8_t flags,
                                      const std::uint8_t* payload,
                                      std::size_t plen) noexcept {
    if (!infrag_ || plen > kSctpMaxRecvChunkData) { send_abort(); state_ = State::Failed; return; }
    // Already buffered? (retransmit). Ignore the duplicate.
    for (std::size_t i = 0; i < kSctpMaxFrags; ++i) {
        if (infrag_[i].used && infrag_[i].tsn == tsn) return;
    }
    InFrag* slot = nullptr;
    for (std::size_t i = 0; i < kSctpMaxFrags; ++i) {
        if (!infrag_[i].used) { slot = &infrag_[i]; break; }
    }
    if (!slot) { send_abort(); state_ = State::Failed; return; }  // bounded overflow
    slot->used = true; slot->tsn = tsn; slot->stream_id = sid; slot->ssn = ssn;
    slot->ppid = ppid; slot->flags = flags; slot->len = static_cast<std::uint16_t>(plen);
    if (plen) std::memcpy(slot->data, payload, plen);
    ++infrag_count_;
}

// Assemble any complete message present in the fragment store: find a B fragment
// whose B..E run has consecutive TSNs all buffered, concatenate into a slab, and
// deliver. Repeats until no more progress (bounded by the store size).
void SctpAssociation::drain_fragments() noexcept {
    if (!infrag_ || infrag_count_ == 0) return;
    bool progressed = true;
    while (progressed) {
        progressed = false;
        for (std::size_t i = 0; i < kSctpMaxFrags; ++i) {
            InFrag& b = infrag_[i];
            if (!b.used || (b.flags & kDataFlagBegin) == 0) continue;
            // Walk consecutive TSNs from b until an E fragment; require all present.
            std::uint32_t want = b.tsn;
            std::size_t total = 0;
            bool complete = false;
            std::size_t steps = 0;
            for (;;) {
                // Find fragment with tsn == want.
                InFrag* f = nullptr;
                for (std::size_t j = 0; j < kSctpMaxFrags; ++j) {
                    if (infrag_[j].used && infrag_[j].tsn == want) { f = &infrag_[j]; break; }
                }
                if (!f) break;                       // gap: cannot assemble yet
                total += f->len;
                if (total > kSctpMaxMessage) {       // bounded
                    send_abort(); state_ = State::Failed; return;
                }
                if (f->flags & kDataFlagEnd) { complete = true; break; }
                ++want;
                if (++steps > kSctpMaxFrags) break;  // safety
            }
            if (!complete) continue;

            // Assemble into a slab.
            std::uint8_t* slab = alloc_slab();
            if (!slab) { send_abort(); state_ = State::Failed; return; }
            if (reasm_bytes_ + total > kSctpReasmBytes) {
                free_slab(slab); send_abort(); state_ = State::Failed; return;
            }
            std::size_t off = 0;
            std::uint32_t t = b.tsn;
            const std::uint16_t sid = b.stream_id;
            const std::uint16_t ssn = b.ssn;
            const std::uint32_t ppid = b.ppid;
            const bool unordered = (b.flags & kDataFlagUnordered) != 0;
            for (;;) {
                InFrag* f = nullptr;
                for (std::size_t j = 0; j < kSctpMaxFrags; ++j) {
                    if (infrag_[j].used && infrag_[j].tsn == t) { f = &infrag_[j]; break; }
                }
                if (!f) break;  // shouldn't happen (validated above)
                std::memcpy(slab + off, f->data, f->len);
                off += f->len;
                const bool is_end = (f->flags & kDataFlagEnd) != 0;
                f->used = false; --infrag_count_;
                if (is_end) break;
                ++t;
            }
            on_full_message(sid, ppid, unordered, ssn, slab, off);
            free_slab(slab);
            progressed = true;
            break;  // restart scan (indices shifted)
        }
    }
}

// FORWARD-TSN receive (RFC 3758 §3.2): advance our cumulative ack past abandoned
// TSNs, dropping any partial reassembly that they belonged to, and bump per-
// stream SSN for the listed ordered streams.
void SctpAssociation::handle_forward_tsn(const std::uint8_t* chunk, std::size_t len) noexcept {
    if (len < 8) return;
    const std::size_t chunk_len = rd16(chunk + 2);
    if (chunk_len < 8 || chunk_len > len) return;
    const std::uint32_t new_cum = rd32(chunk + 4);
    if (!have_cum_ack_) return;

    if (tsn_gt(new_cum, cum_ack_in_)) {
        // Mark every TSN in (cum_ack_in_, new_cum] as received so the bitmap +
        // cum ack walk advances cleanly, then advance.
        std::uint32_t t = cum_ack_in_ + 1;
        while (tsn_le(t, new_cum)) {
            record_received(t);  // ignores out-of-window safely
            if (t == new_cum) break;
            ++t;
        }
        // Drop any in-progress reassembly whose begin TSN was abandoned.
        for (std::size_t i = 0; i < kSctpMaxReasm; ++i) {
            Reasm& r = reasm_[i];
            if (r.used && tsn_le(r.begin_tsn, new_cum)) {
                reasm_bytes_ -= r.len;
                free_slab(r.data);
                r.used = false; r.data = nullptr; r.len = 0; r.have_begin = false;
            }
        }
        advance_cum_ack();
        // Drop buffered fragments now at/below the cumulative ack: their message's
        // earlier fragment was abandoned, so they can never be reassembled. Safe
        // here (post-FORWARD-TSN) because anything <= cum_ack is fully settled.
        if (infrag_) {
            for (std::size_t i = 0; i < kSctpMaxFrags; ++i) {
                if (infrag_[i].used && tsn_le(infrag_[i].tsn, cum_ack_in_)) {
                    infrag_[i].used = false; --infrag_count_;
                }
            }
        }
    }

    // Per-stream ordered-SSN skips: bump next_ssn so abandoned ordered messages
    // don't block delivery, then flush anything now in order.
    std::size_t off = 8;
    while (off + 4 <= chunk_len) {
        const std::uint16_t sid = rd16(chunk + off);
        const std::uint16_t ssn = rd16(chunk + off + 2);
        if (sid < kSctpMaxStreams) {
            InStream& st = in_streams_[sid];
            // Advance next_ssn to ssn+1 if the skip is ahead of us.
            const std::uint16_t target = static_cast<std::uint16_t>(ssn + 1);
            if (static_cast<std::uint16_t>(target - st.next_ssn) < 0x8000) {
                st.next_ssn = target;
            }
            deliver_ordered(sid);
        }
        off += 4;
    }
    send_sack();
}

// ===========================================================================
// Sender: SACK processing + RTO + congestion control
// ===========================================================================
void SctpAssociation::update_rto(std::uint32_t rtt_ms) noexcept {
    // RFC 6298. First measurement: SRTT=R, RTTVAR=R/2. Else EWMA.
    if (!have_rtt_) {
        srtt_ms_ = rtt_ms;
        rttvar_ms_ = rtt_ms / 2;
        have_rtt_ = true;
    } else {
        const std::int32_t err =
            static_cast<std::int32_t>(srtt_ms_) - static_cast<std::int32_t>(rtt_ms);
        const std::uint32_t abs_err = static_cast<std::uint32_t>(err < 0 ? -err : err);
        rttvar_ms_ = rttvar_ms_ - (rttvar_ms_ >> kSctpRtoBetaShift) +
                     (abs_err >> kSctpRtoBetaShift);
        srtt_ms_ = srtt_ms_ - (srtt_ms_ >> kSctpRtoAlphaShift) +
                   (rtt_ms >> kSctpRtoAlphaShift);
    }
    std::uint32_t rto = srtt_ms_ + 4 * rttvar_ms_;
    if (rto < kSctpRtoMinMs) rto = kSctpRtoMinMs;
    if (rto > kSctpRtoMaxMs) rto = kSctpRtoMaxMs;
    rto_ms_ = rto;
}

void SctpAssociation::on_data_acked(std::size_t slot, std::uint64_t now_ms) noexcept {
    OutChunk& o = out_ring_[slot];
    if (!o.used || o.acked) return;
    o.acked = true;
    if (o.sent && flight_size_ >= o.payload_len) flight_size_ -= static_cast<std::uint32_t>(o.payload_len);
    // RTT sample via Karn's algorithm: only if never retransmitted.
    if (o.rtt_pending && o.rtx_count == 0 && now_ms >= o.sent_at_ms) {
        update_rto(static_cast<std::uint32_t>(now_ms - o.sent_at_ms));
    }
    o.used = false;
}

void SctpAssociation::handle_sack(const std::uint8_t* chunk, std::size_t len) noexcept {
    if (len < 4 + 12) return;
    const std::uint8_t* v = chunk + 4;
    const std::uint32_t cum_tsn = rd32(v + 0);
    peer_rwnd_ = rd32(v + 4);
    const std::uint16_t ngaps = rd16(v + 8);
    const std::uint64_t now = cur_now_ms_ != 0 ? cur_now_ms_ : now_steady_ms();

    std::uint32_t newly_acked_bytes = 0;
    bool any_newly_acked = false;

    // Cumulative ack: free everything <= cum_tsn.
    for (std::size_t i = 0; i < kSctpSendQueue; ++i) {
        OutChunk& o = out_ring_[i];
        if (o.used && !o.acked && o.sent && tsn_le(o.tsn, cum_tsn)) {
            newly_acked_bytes += static_cast<std::uint32_t>(o.payload_len);
            any_newly_acked = true;
            on_data_acked(i, now);
        }
    }

    // Gap-ack blocks: ack TSNs inside the ranges; count misses for the rest.
    // First clear miss flags we'll recompute from this SACK.
    std::size_t off = 4 + 12;
    // Build the set of acked ranges and ack them.
    std::uint32_t highest_gap_acked = cum_tsn;
    for (std::uint16_t gi = 0; gi < ngaps && off + 4 <= len; ++gi, off += 4) {
        const std::uint16_t gstart = rd16(chunk + off);
        const std::uint16_t gend   = rd16(chunk + off + 2);
        const std::uint32_t lo = cum_tsn + gstart;
        const std::uint32_t hi = cum_tsn + gend;
        if (tsn_gt(hi, highest_gap_acked)) highest_gap_acked = hi;
        for (std::size_t i = 0; i < kSctpSendQueue; ++i) {
            OutChunk& o = out_ring_[i];
            if (o.used && !o.acked && o.sent && tsn_le(lo, o.tsn) && tsn_le(o.tsn, hi)) {
                newly_acked_bytes += static_cast<std::uint32_t>(o.payload_len);
                any_newly_acked = true;
                on_data_acked(i, now);
            }
        }
    }

    // Any unacked, in-flight chunk with TSN below the highest gap-acked TSN is
    // "missing" — bump its miss_count; 3 misses -> fast retransmit.
    bool do_fast_rtx = false;
    for (std::size_t i = 0; i < kSctpSendQueue; ++i) {
        OutChunk& o = out_ring_[i];
        if (o.used && !o.acked && o.sent && tsn_lt(o.tsn, highest_gap_acked)) {
            ++o.miss_count;
            if (o.miss_count == kSctpFastRtxDup) do_fast_rtx = true;
        }
    }

    // Congestion control update (RFC 4960 §7.2).
    if (any_newly_acked) {
        if (cwnd_ <= ssthresh_) {
            // Slow start: cwnd += min(newly_acked, MTU) per SACK that advances.
            const std::uint32_t inc =
                newly_acked_bytes < static_cast<std::uint32_t>(kSctpMaxPacket)
                    ? newly_acked_bytes : static_cast<std::uint32_t>(kSctpMaxPacket);
            cwnd_ += inc;
        } else {
            // Congestion avoidance: cwnd += MTU per RTT (track partial_bytes_acked).
            partial_bytes_acked_ += newly_acked_bytes;
            if (partial_bytes_acked_ >= cwnd_) {
                partial_bytes_acked_ -= cwnd_;
                cwnd_ += static_cast<std::uint32_t>(kSctpMaxPacket);
            }
        }
        consecutive_timeouts_ = 0;
        // Restart T3 if there's still outstanding data.
        if (flight_size_ > 0) {
            t3_deadline_ms_ = now + rto_ms_;
            t3_running_ = true;
        } else {
            t3_running_ = false;
        }
    }

    if (do_fast_rtx) {
        // Fast retransmit: ssthresh = max(cwnd/2, 4*MTU); cwnd = ssthresh.
        std::uint32_t half = cwnd_ / 2;
        const std::uint32_t floor = static_cast<std::uint32_t>(4 * kSctpMaxPacket);
        ssthresh_ = half > floor ? half : floor;
        cwnd_ = ssthresh_;
        partial_bytes_acked_ = 0;
        // Resend the missing chunks now (those at the fast-rtx threshold) — UNLESS
        // a rexmit-limited partial-reliability chunk has used its budget, in which
        // case ABANDON it (RFC 3758) rather than fast-retransmit.
        bool fwd = false;
        for (std::size_t i = 0; i < kSctpSendQueue; ++i) {
            OutChunk& o = out_ring_[i];
            if (!(o.used && !o.acked && o.sent && o.miss_count >= kSctpFastRtxDup)) continue;
            if (o.rel_rexmit && o.rtx_count >= o.rel_max_rtx) {
                o.abandoned = true;
                if (flight_size_ >= o.payload_len)
                    flight_size_ -= static_cast<std::uint32_t>(o.payload_len);
                if (tsn_gt(o.tsn, adv_ack_point_)) adv_ack_point_ = o.tsn;
                fwd = true;
                continue;
            }
            if (sink_ && o.len >= kHdrLen) {
                sink_(o.packet, o.len);
                o.rtx_count++; o.rtt_pending = false;  // Karn: invalidate RTT
                o.miss_count = 0;
                ++rtx_count_;
            }
        }
        if (fwd) {
            need_forward_tsn_ = true;
            send_forward_tsn();   // scans abandoned chunks for the SSN skip list
            for (std::size_t i = 0; i < kSctpSendQueue; ++i) {
                OutChunk& o = out_ring_[i];
                if (o.used && o.abandoned && tsn_le(o.tsn, adv_ack_point_)) o.used = false;
            }
        }
    }

    // Advance our adv_ack_point past anything cumulatively acked (for FWD-TSN
    // accounting). adv_ack_point only ever moves forward.
    if (tsn_gt(cum_tsn, adv_ack_point_)) adv_ack_point_ = cum_tsn;

    // Opportunistically push more queued data now that cwnd may have grown.
    flush_send(now);
}

void SctpAssociation::on_t3_timeout(std::uint64_t now_ms) noexcept {
    // RFC 4960 §7.2.3 + RFC 6298: ssthresh = max(cwnd/2, 4*MTU); cwnd = 1*MTU.
    std::uint32_t half = cwnd_ / 2;
    const std::uint32_t floor = static_cast<std::uint32_t>(4 * kSctpMaxPacket);
    ssthresh_ = half > floor ? half : floor;
    cwnd_ = static_cast<std::uint32_t>(kSctpMaxPacket);
    partial_bytes_acked_ = 0;
    // Exponential backoff of RTO (capped).
    rto_ms_ = rto_ms_ * 2;
    if (rto_ms_ > kSctpRtoMaxMs) rto_ms_ = kSctpRtoMaxMs;
    ++consecutive_timeouts_;
    if (consecutive_timeouts_ > kSctpMaxAssocRtx) {
        send_abort(); state_ = State::Failed; return;
    }
    // Partial reliability: a T3 timeout means every in-flight chunk needs a
    // retransmit. Any rexmit-limited chunk that has already used its budget is
    // ABANDONED now (RFC 3758) rather than retransmitted — including the case
    // max_retransmits==0 (abandon on first loss, never retransmit).
    for (std::size_t i = 0; i < kSctpSendQueue; ++i) {
        OutChunk& o = out_ring_[i];
        if (o.used && !o.acked && o.sent && !o.abandoned &&
            o.rel_rexmit && o.rtx_count >= o.rel_max_rtx) {
            // Mark all chunks of this message abandoned (same stream+ssn, ordered;
            // for unordered we abandon just this chunk's run is handled per-chunk).
            o.abandoned = true;
            if (flight_size_ >= o.payload_len)
                flight_size_ -= static_cast<std::uint32_t>(o.payload_len);
            if (tsn_gt(o.tsn, adv_ack_point_)) adv_ack_point_ = o.tsn;
            need_forward_tsn_ = true;
        }
    }
    // Retransmit the earliest unacked, in-flight, NON-abandoned chunk (one per
    // timeout, per RFC; the rest follow as the window allows).
    std::uint32_t lowest = 0; bool have_lowest = false; std::size_t lowest_i = 0;
    for (std::size_t i = 0; i < kSctpSendQueue; ++i) {
        OutChunk& o = out_ring_[i];
        if (o.used && !o.acked && o.sent && !o.abandoned) {
            if (!have_lowest || tsn_lt(o.tsn, lowest)) { lowest = o.tsn; lowest_i = i; have_lowest = true; }
        }
    }
    if (need_forward_tsn_) {
        // Announce the skip FIRST (scans abandoned chunks for the SSN list), then
        // free the abandoned slots covered by adv_ack_point.
        send_forward_tsn();
        for (std::size_t i = 0; i < kSctpSendQueue; ++i) {
            OutChunk& o = out_ring_[i];
            if (o.used && o.abandoned && tsn_le(o.tsn, adv_ack_point_)) o.used = false;
        }
    }
    if (have_lowest) {
        OutChunk& o = out_ring_[lowest_i];
        if (sink_ && o.len >= kHdrLen) {
            sink_(o.packet, o.len);
            o.rtx_count++; o.rtt_pending = false; o.miss_count = 0;
            ++rtx_count_;
        }
        t3_deadline_ms_ = now_ms + rto_ms_;
        t3_running_ = true;
    } else {
        t3_running_ = false;
    }
}

// Partial reliability: abandon messages that exceeded max_retransmits or
// max_lifetime, freeing their slots + scheduling a FORWARD-TSN.
void SctpAssociation::abandon_expired(std::uint64_t now_ms) noexcept {
    bool any = false;
    for (std::size_t i = 0; i < kSctpSendQueue; ++i) {
        OutChunk& o = out_ring_[i];
        if (!o.used || o.acked || o.abandoned) continue;
        bool give_up = false;
        if (o.rel_rexmit && o.rtx_count > o.rel_max_rtx) give_up = true;
        if (o.rel_timed && o.expiry_ms != 0 && now_ms >= o.expiry_ms) give_up = true;
        if (give_up) {
            o.abandoned = true;
            // Treat as no longer in flight for cwnd accounting.
            if (o.sent && flight_size_ >= o.payload_len)
                flight_size_ -= static_cast<std::uint32_t>(o.payload_len);
            // Advance adv_ack_point if this completes a contiguous abandoned run
            // right after it. We move adv_ack_point to at least this TSN.
            if (tsn_gt(o.tsn, adv_ack_point_)) adv_ack_point_ = o.tsn;
            any = true;
        }
    }
    if (any) {
        need_forward_tsn_ = true;
        // Announce the skip FIRST (it scans abandoned chunks for the per-stream
        // SSN list), THEN free the abandoned slots <= adv_ack_point.
        send_forward_tsn();
        for (std::size_t i = 0; i < kSctpSendQueue; ++i) {
            OutChunk& o = out_ring_[i];
            if (o.used && o.abandoned && tsn_le(o.tsn, adv_ack_point_)) {
                o.used = false;
            }
        }
    }
}

// ===========================================================================
// feed — parse one inbound packet
// ===========================================================================
bool SctpAssociation::feed(const std::uint8_t* data, std::size_t len,
                           std::uint64_t now_ms) noexcept {
    if (state_ == State::Failed) return false;
    if (!data || len < kHdrLen) return state_ != State::Failed;
    if (now_ms == 0) now_ms = now_steady_ms();
    cur_now_ms_ = now_ms;

    const std::uint32_t got =
        static_cast<std::uint32_t>(data[8]) |
        (static_cast<std::uint32_t>(data[9]) << 8) |
        (static_cast<std::uint32_t>(data[10]) << 16) |
        (static_cast<std::uint32_t>(data[11]) << 24);
    const std::uint32_t want = sctp_crc32c(data, len);
    if (got != want) return state_ != State::Failed;

    std::size_t off = kHdrLen;
    while (off + 4 <= len) {
        const std::uint8_t  ctype = data[off];
        const std::uint16_t clen  = rd16(data + off + 2);
        if (clen < 4) break;
        if (off + clen > len) break;
        const std::uint8_t* chunk = data + off;

        switch (static_cast<ChunkType>(ctype)) {
            case ChunkType::Init:       handle_init(chunk, len - off); break;
            case ChunkType::InitAck:    handle_init_ack(chunk, len - off); break;
            case ChunkType::CookieEcho: handle_cookie_echo(chunk, len - off); break;
            case ChunkType::CookieAck:  handle_cookie_ack(chunk, len - off); break;
            case ChunkType::Data:       handle_data(chunk, len - off); break;
            case ChunkType::Sack:       handle_sack(chunk, len - off); break;
            case ChunkType::ForwardTsn: handle_forward_tsn(chunk, len - off); break;
            case ChunkType::Abort:      state_ = State::Failed; break;
            case ChunkType::Heartbeat:  break;  // ignore in v1
            default: break;
        }
        if (state_ == State::Failed) return false;
        const std::size_t adv = pad4(clen);
        if (adv == 0) break;
        off += adv;
    }
    return true;
}

// ===========================================================================
// send — fragment a user message into queued DATA chunks
// ===========================================================================
bool SctpAssociation::enqueue_chunk(std::uint16_t sid, std::uint32_t ppid,
                                    std::uint8_t flags, std::uint16_t ssn,
                                    std::uint32_t tsn, const std::uint8_t* data,
                                    std::size_t plen, const SctpReliability& rel,
                                    std::uint64_t now_ms) noexcept {
    OutChunk* slot = nullptr;
    for (std::size_t i = 0; i < kSctpSendQueue; ++i) {
        if (!out_ring_[i].used) { slot = &out_ring_[i]; break; }
    }
    if (!slot) return false;

    std::uint8_t* out = slot->packet;
    write_common_header(out, peer_tag_);
    std::uint8_t* c = out + kHdrLen;
    c[0] = static_cast<std::uint8_t>(ChunkType::Data);
    c[1] = flags;
    const std::uint16_t chunk_len = static_cast<std::uint16_t>(kDataHdr + plen);
    wr16(c + 2, chunk_len);
    wr32(c + 4, tsn);
    wr16(c + 8, sid);
    wr16(c + 10, ssn);
    wr32(c + 12, ppid);
    if (plen > 0) std::memcpy(c + 16, data, plen);
    const std::size_t unpadded = kHdrLen + chunk_len;
    const std::size_t total = kHdrLen + pad4(chunk_len);
    for (std::size_t i = unpadded; i < total; ++i) out[i] = 0;

    // Compute + store the CRC-32c now: the framed packet is immutable after this
    // (re-shippable for retransmit), so the checksum is computed once (RFC 3309).
    if (total <= kSctpMaxPacket) {
        const std::uint32_t crc = sctp_crc32c(out, total);
        out[8]  = static_cast<std::uint8_t>(crc & 0xFF);
        out[9]  = static_cast<std::uint8_t>((crc >> 8) & 0xFF);
        out[10] = static_cast<std::uint8_t>((crc >> 16) & 0xFF);
        out[11] = static_cast<std::uint8_t>((crc >> 24) & 0xFF);
    }

    slot->used = true; slot->sent = false; slot->acked = false; slot->abandoned = false;
    slot->flags = flags; slot->stream_id = sid; slot->ssn = ssn; slot->tsn = tsn;
    slot->ppid = ppid; slot->miss_count = 0; slot->rtx_count = 0;
    slot->sent_at_ms = 0; slot->rtt_pending = false;
    slot->payload_len = plen; slot->len = total;
    slot->rel_rexmit = rel.rexmit_limited; slot->rel_timed = rel.time_limited;
    slot->rel_max_rtx = rel.max_retransmits;
    slot->expiry_ms = (rel.time_limited && rel.max_lifetime_ms > 0)
                        ? now_ms + rel.max_lifetime_ms : 0;
    return true;
}

std::size_t SctpAssociation::flush_send(std::uint64_t now_ms) noexcept {
    if (state_ != State::Established) return 0;
    std::size_t shipped = 0;
    // Ship queued (un-sent) chunks in TSN order while cwnd + rwnd allow.
    bool progressed = true;
    while (progressed) {
        progressed = false;
        // Find the lowest-TSN un-sent, non-abandoned chunk.
        OutChunk* next = nullptr;
        for (std::size_t i = 0; i < kSctpSendQueue; ++i) {
            OutChunk& o = out_ring_[i];
            if (o.used && !o.sent && !o.abandoned && !o.acked) {
                if (!next || tsn_lt(o.tsn, next->tsn)) next = &o;
            }
        }
        if (!next) break;
        // cwnd gate: allow if flight < cwnd (RFC 4960 §6.1).
        const std::uint32_t cw = cwnd_ > 0 ? cwnd_ : static_cast<std::uint32_t>(4 * kSctpMaxPacket);
        if (flight_size_ >= cw) break;
        // rwnd gate (peer receive window).
        if (peer_rwnd_ != 0 && flight_size_ + next->payload_len > peer_rwnd_ &&
            flight_size_ > 0) break;
        if (!sink_ || next->len < kHdrLen) break;
        if (!sink_(next->packet, next->len)) break;
        next->sent = true;
        next->sent_at_ms = now_ms;
        next->rtt_pending = true;
        flight_size_ += static_cast<std::uint32_t>(next->payload_len);
        if (!t3_running_) { t3_deadline_ms_ = now_ms + rto_ms_; t3_running_ = true; }
        ++shipped;
        progressed = true;
    }
    return shipped;
}

bool SctpAssociation::send(std::uint16_t stream_id, std::uint32_t ppid,
                           const std::uint8_t* data, std::size_t len,
                           const SctpReliability& rel,
                           std::uint64_t now_ms) noexcept {
    if (state_ != State::Established) return false;
    if (stream_id >= kSctpMaxStreams) return false;
    if (len > kSctpMaxMessage) return false;

    const std::uint64_t now = now_ms == 0 ? now_steady_ms() : now_ms;
    cur_now_ms_ = now;
    const bool unordered = rel.unordered;

    // Count fragments needed; ensure ring capacity before mutating TSN/SSN.
    const std::size_t per = kSctpMaxChunkData;
    std::size_t nfrag = len == 0 ? 1 : (len + per - 1) / per;
    if (nfrag == 0) nfrag = 1;
    std::size_t free_slots = 0;
    for (std::size_t i = 0; i < kSctpSendQueue; ++i) if (!out_ring_[i].used) ++free_slots;
    if (free_slots < nfrag) return false;  // bounded: backpressure

    const std::uint16_t ssn = unordered ? 0 : out_ssn_[stream_id];
    std::uint8_t base_flags = unordered ? kDataFlagUnordered : 0;

    std::size_t offset = 0;
    for (std::size_t f = 0; f < nfrag; ++f) {
        const std::size_t this_len = (len == 0) ? 0
            : (offset + per <= len ? per : len - offset);
        std::uint8_t flags = base_flags;
        if (f == 0) flags |= kDataFlagBegin;
        if (f == nfrag - 1) flags |= kDataFlagEnd;
        const std::uint32_t tsn = next_tsn_;
        if (!enqueue_chunk(stream_id, ppid, flags, ssn, tsn,
                           data ? data + offset : nullptr, this_len, rel, now)) {
            return false;  // shouldn't happen (we checked capacity)
        }
        next_tsn_ = next_tsn_ + 1;
        offset += this_len;
    }
    if (!unordered) out_ssn_[stream_id] = static_cast<std::uint16_t>(ssn + 1);
    ++data_out_;

    flush_send(now);
    return true;
}

// ===========================================================================
// tick — drive RTO timeout, partial-reliability abandonment, and flush
// ===========================================================================
std::size_t SctpAssociation::tick(std::uint64_t now_ms) noexcept {
    if (state_ != State::Established) return 0;
    if (now_ms == 0) now_ms = now_steady_ms();
    cur_now_ms_ = now_ms;

    const std::uint64_t before = rtx_count_;

    // Partial reliability: abandon expired messages first (may emit FORWARD-TSN).
    abandon_expired(now_ms);

    // T3-rtx timeout?
    if (t3_running_ && now_ms >= t3_deadline_ms_) {
        // Only fire if there is still in-flight data.
        bool have_inflight = false;
        for (std::size_t i = 0; i < kSctpSendQueue; ++i) {
            const OutChunk& o = out_ring_[i];
            if (o.used && !o.acked && o.sent) { have_inflight = true; break; }
        }
        if (have_inflight) on_t3_timeout(now_ms);
        else t3_running_ = false;
        if (state_ == State::Failed) return 0;
    }

    // Flush any queued data the window now permits.
    flush_send(now_ms);

    return static_cast<std::size_t>(rtx_count_ - before);
}

}  // namespace webrtc
}  // namespace bolt::api
