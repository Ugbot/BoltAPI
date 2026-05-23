// boltapi/quic/connection.h — QUIC CONNECTION: drives a real TLS 1.3 handshake
// end-to-end over UDP to ESTABLISHED (wave 4).
//
// This ties together the earlier waves into a working connection:
//   * wave 1 primitives — packet.h (header parse), frames.h (frame parse/
//     serialize), pn_space.h (packet-number spaces + truncated PN codec),
//     ack.h (received-PN -> ACK ranges);
//   * wave 2 packet_protection.h — AEAD seal/open + header protection (Initial
//     keys from the DCID; Handshake/1-RTT keys installed from the TLS secrets);
//   * wave 3 tls.h — the TLS 1.3 QUIC-TLS handshake driver (CRYPTO bytes in/out,
//     per-level secrets, transport params, ALPN h3);
//   * the existing net::UdpTransport — real UDP on the engine event loop.
//
// ADAPTED from FasterAPI's quic_secure_connection.h flow (the SECURE path that
// actually invokes the crypto — its plaintext base quic_connection.cpp was the
// stub the audit flagged). The inbound pipeline (parse header -> select level ->
// header-unprotect -> AEAD-open -> parse frames -> CRYPTO reassembly -> feed TLS
// -> install keys) and the outbound pipeline (pull TLS CRYPTO -> frame -> build
// header -> AEAD-seal -> header-protect -> send) mirror that file, reshaped to
// Bolt Tiger Style (namespace bolt::api::quic, >=2 asserts/fn, bounded buffers,
// no recursion on the hot path, <70-line fns, no exceptions, explicit returns)
// and retargeted onto boltapi/quic/* + net::UdpTransport.
//
// SCOPE (wave 4): get BOTH roles to ESTABLISHED over loopback (Initial ->
// Handshake -> 1-RTT). NO streams / flow control / QPACK / HTTP-3 (wave 5+).
// A minimal "retransmit unacked CRYPTO on a tick" keeps a clean loopback
// handshake reliable; full RFC 9002 loss recovery is wave 5.
//
// Header-only: OpenSSL is always linked into boltapi (and the gate test links
// OpenSSL::SSL/Crypto), so this compiles UNCONDITIONALLY — the default ctest
// suite runs the handshake gate. No BOLTAPI_WITH_HTTP3 flag.

#pragma once

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <vector>

#include "boltapi/quic/ack.h"
#include "boltapi/quic/frames.h"
#include "boltapi/quic/packet.h"
#include "boltapi/quic/packet_protection.h"
#include "boltapi/quic/pn_space.h"
#include "boltapi/quic/tls.h"
#include "boltapi/quic/transport_params.h"
#include "boltapi/quic/varint.h"

#ifdef BOLTAPI_QUIC_TRACE
#include <cstdio>
#include <cstdlib>
#define QTRACE(...)                                                    \
    do {                                                               \
        static const bool on = std::getenv("BOLTAPI_QUIC_TRACE") != 0; \
        if (on) {                                                      \
            std::fprintf(stderr, "[quic %s] ", is_server_ ? "S" : "C");\
            std::fprintf(stderr, __VA_ARGS__);                         \
            std::fprintf(stderr, "\n");                                \
        }                                                              \
    } while (0)
#else
#define QTRACE(...) ((void)0)
#endif

namespace bolt::api::quic {

// ----------------------------------------------------------------------------
// Named bounds (Tiger Style: every limit explicit + asserted).
// ----------------------------------------------------------------------------
inline constexpr std::size_t kMaxDatagramSize = 1500;     // path MTU budget
inline constexpr std::size_t kMaxCoalescedPackets = 8;    // packets per datagram
inline constexpr std::size_t kMaxCryptoBuffer = 64 * 1024;  // per-level reassembly
inline constexpr std::size_t kMaxPayloadSize = 1400;      // pre-AEAD frame budget
inline constexpr std::uint8_t kLocalCidLen = 8;           // our SCID length
inline constexpr std::size_t kCryptoChunk = 1024;         // CRYPTO bytes per frame
inline constexpr std::size_t kInitialMinDatagram = 1200;  // RFC 9000 §14.1

// Connection lifecycle (RFC 9000 §10 / §17.2 handshake progression).
enum class ConnState : std::uint8_t {
    kNew = 0,        // created, nothing sent/received yet
    kHandshaking,    // exchanging Initial/Handshake CRYPTO
    kEstablished,    // 1-RTT keys + handshake confirmed
    kClosing,        // sent/recv CONNECTION_CLOSE, draining out
    kDraining,       // peer closed; wind down
    kClosed,         // terminal
};

inline constexpr const char* conn_state_name(ConnState s) noexcept {
    switch (s) {
        case ConnState::kNew:         return "New";
        case ConnState::kHandshaking: return "Handshaking";
        case ConnState::kEstablished: return "Established";
        case ConnState::kClosing:     return "Closing";
        case ConnState::kDraining:    return "Draining";
        case ConnState::kClosed:      return "Closed";
    }
    return "?";
}

// ----------------------------------------------------------------------------
// CryptoReassembly — ordered, in-order CRYPTO-stream reassembly for one level.
// ADAPTED from FasterAPI quic_crypto_buffer.h (CryptoBuffer) but bounded to a
// single fixed array with a contiguous-receive cursor (no std::vector segment
// list; out-of-order bytes past the cursor are buffered in place and consumed
// once the gap fills). Sufficient for a loopback handshake; full gap tracking is
// not needed at this scope.
// ----------------------------------------------------------------------------
class CryptoReassembly {
public:
    CryptoReassembly() noexcept = default;

    // Accept CRYPTO-frame bytes at `offset`. Buffers them; advances the
    // contiguous cursor over any now-filled prefix. Returns false on overflow or
    // a duplicate-with-conflict (treated as protocol error). Duplicates of
    // already-consumed bytes are ignored.
    bool receive(std::uint64_t offset, const std::uint8_t* data,
                 std::size_t len) noexcept {
        assert((data != nullptr || len == 0) && "CryptoReassembly: null data");
        assert(offset <= kMaxCryptoBuffer && "CryptoReassembly: offset overflow");
        if (len == 0) return true;
        const std::uint64_t end = offset + len;
        if (end > kMaxCryptoBuffer) return false;
        if (end > highest_) highest_ = static_cast<std::size_t>(end);

        // Skip bytes already consumed contiguously.
        std::size_t copy_from = 0;
        std::uint64_t write_at = offset;
        if (offset < recv_cursor_) {
            const std::uint64_t skip = recv_cursor_ - offset;
            if (skip >= len) return true;  // wholly duplicate
            copy_from = static_cast<std::size_t>(skip);
            write_at = recv_cursor_;
        }
        const std::size_t n = len - copy_from;
        std::memcpy(buffer_ + write_at, data + copy_from, n);
        mark_filled(static_cast<std::size_t>(write_at), n);
        return true;
    }

    // Number of contiguous, unconsumed bytes available from read_cursor_.
    std::size_t available() const noexcept {
        assert(read_cursor_ <= recv_cursor_ && "read past recv");
        return recv_cursor_ - read_cursor_;
    }

    // Borrow a view of the contiguous unconsumed bytes (valid until consume()).
    const std::uint8_t* peek() const noexcept {
        assert(read_cursor_ <= kMaxCryptoBuffer && "read cursor overflow");
        return buffer_ + read_cursor_;
    }

    void consume(std::size_t n) noexcept {
        assert(read_cursor_ + n <= recv_cursor_ && "consume past contiguous");
        read_cursor_ += n;
    }

private:
    // Mark [start, start+n) present and extend the contiguous cursor if it now
    // reaches/passes recv_cursor_. With a single in-order stream (loopback) the
    // common path simply advances the cursor.
    void mark_filled(std::size_t start, std::size_t n) noexcept {
        assert(start + n <= kMaxCryptoBuffer && "mark_filled overflow");
        if (start <= recv_cursor_ && start + n > recv_cursor_) {
            recv_cursor_ = start + n;
        } else if (start > recv_cursor_) {
            // Out-of-order: remember the furthest filled extent so a later
            // gap-filling frame can re-trigger the advance below.
            if (start + n > pending_end_) pending_end_ = start + n;
            if (pending_start_ == 0 || start < pending_start_)
                pending_start_ = start;
        }
        // If a buffered out-of-order region is now contiguous, absorb it.
        if (pending_end_ > recv_cursor_ && pending_start_ <= recv_cursor_) {
            recv_cursor_ = pending_end_;
            pending_start_ = 0;
            pending_end_ = 0;
        }
        assert(recv_cursor_ <= highest_ && "cursor past highest");
    }

    std::uint8_t buffer_[kMaxCryptoBuffer]{};
    std::size_t read_cursor_ = 0;    // next byte handed to TLS
    std::size_t recv_cursor_ = 0;    // highest contiguous byte received
    std::size_t highest_ = 0;        // highest byte ever written
    std::size_t pending_start_ = 0;  // buffered out-of-order region [start,end)
    std::size_t pending_end_ = 0;
};

// Callbacks the connection raises (the connection layer is transport-agnostic;
// the owner supplies `send` to push a built datagram to the peer).
using QuicSendFn =
    std::function<void(const std::uint8_t* data, std::size_t len)>;

// ============================================================================
// QuicConnection — one endpoint (client or server) of a QUIC connection.
// ============================================================================
class QuicConnection {
public:
    QuicConnection() noexcept = default;
    ~QuicConnection() = default;
    QuicConnection(const QuicConnection&) = delete;
    QuicConnection& operator=(const QuicConnection&) = delete;

    // ------------------------------------------------------------------------
    // init — build the TLS driver, set ALPN/transport params, generate our SCID,
    // and (client) derive Initial keys from a fresh random DCID. `send` is the
    // sink for outbound datagrams (e.g. a UdpTransport::send wrapper). Returns
    // true on success.
    // ------------------------------------------------------------------------
    bool init(bool is_server, QuicSendFn send) noexcept {
        assert(send && "init: null send fn");
        is_server_ = is_server;
        send_ = std::move(send);
        gen_random(local_cid_.data, kLocalCidLen);
        local_cid_.length = kLocalCidLen;

        const bool ok = is_server_ ? tls_.init_server() : tls_.init_client();
        if (!ok) return false;
        static const std::uint8_t kAlpn[] = {2, 'h', '3'};
        if (!tls_.set_alpn(kAlpn, sizeof(kAlpn))) return false;
        if (!tls_.set_transport_params(make_local_params())) return false;

        if (!is_server_) {
            // Client: pick the initial DCID (random, >=8B per §7.2) and derive
            // Initial keys from it. The server learns it from our first Initial.
            gen_random(peer_cid_.data, kLocalCidLen);
            peer_cid_.length = kLocalCidLen;
            std::memcpy(initial_dcid_.data, peer_cid_.data, kLocalCidLen);
            initial_dcid_.length = kLocalCidLen;
            if (!derive_initial_keys(initial_dcid_)) return false;
        }
        state_ = ConnState::kNew;
        return true;
    }

    // start — client kicks off the handshake (builds the first Initial with the
    // ClientHello). The server starts on the first inbound Initial instead.
    bool start() noexcept {
        assert(send_ && "start before init");
        assert(!is_server_ && "server starts on first client Initial");
        state_ = ConnState::kHandshaking;
        tls_.advance();             // produces ClientHello CRYPTO at Initial
        flush();                    // build + send Initial packet(s)
        return !tls_.failed();
    }

    // ------------------------------------------------------------------------
    // feed_datagram — process one received UDP datagram (may coalesce multiple
    // QUIC packets). Drives the handshake forward and flushes any responses.
    // ------------------------------------------------------------------------
    void feed_datagram(const std::uint8_t* data, std::size_t len) noexcept {
        assert((data != nullptr || len == 0) && "feed_datagram: null");
        if (state_ == ConnState::kClosed || state_ == ConnState::kDraining)
            return;
        QTRACE("feed_datagram len=%zu state=%s", len, conn_state_name(state_));
        std::size_t off = 0;
        for (std::size_t i = 0; i < kMaxCoalescedPackets && off < len; ++i) {
            std::size_t consumed = 0;
            if (!process_one_packet(data + off, len - off, consumed)) {
                QTRACE("  process_one_packet FAILED at off=%zu", off);
                break;
            }
            if (consumed == 0) break;  // could not advance; stop
            off += consumed;
        }
        tls_.advance();
        QTRACE("after advance: complete=%d failed=%d app_wr=%d app_rd=%d 1rtt=%d "
               "state=%s",
               tls_.is_complete(), tls_.failed(),
               tls_.have_write_secret(TlsLevel::kApplication),
               tls_.have_read_secret(TlsLevel::kApplication),
               one_rtt_keys_ready(), conn_state_name(state_));
        maybe_promote_state();
        flush();
    }

    // tick — drive retransmission of unacked CRYPTO + send a pending ACK. Called
    // periodically by the owner to make a lossy/loopback handshake reliable
    // (minimal stand-in for RFC 9002 PTO — wave 5 replaces it).
    void tick() noexcept {
        if (state_ == ConnState::kClosed || state_ == ConnState::kDraining)
            return;
        tls_.advance();
        maybe_promote_state();
        // Re-send still-pending CRYPTO (TLS re-buffers nothing, so we replay our
        // own send offsets) and an ACK if one is due, then any new CRYPTO.
        retransmit_pending();
        flush();
    }

    // ------------------------------------------------------------------------
    // State + accessors.
    // ------------------------------------------------------------------------
    ConnState state() const noexcept { return state_; }
    bool is_established() const noexcept {
        return state_ == ConnState::kEstablished;
    }
    bool is_server() const noexcept { return is_server_; }

    QuicTls& tls() noexcept { return tls_; }
    const QuicTls& tls() const noexcept { return tls_; }

    const ConnectionId& local_cid() const noexcept { return local_cid_; }
    const ConnectionId& peer_cid() const noexcept { return peer_cid_; }

    bool one_rtt_keys_ready() const noexcept {
        return tls_.have_read_secret(TlsLevel::kApplication) &&
               tls_.have_write_secret(TlsLevel::kApplication);
    }

    // Largest 1-RTT (Application-space) packet number we have OPENED from the
    // peer, or -1 if none. >= 0 proves a peer-sealed 1-RTT packet was AEAD-opened
    // here (the wave-4 1-RTT round-trip evidence).
    std::int64_t app_largest_received() const noexcept {
        return spaces_[PacketNumberSpace::kApplication].largest_received();
    }

    // Negotiated ALPN convenience (true if "h3").
    bool alpn_is_h3() const noexcept {
        const std::uint8_t* p = nullptr;
        std::size_t n = 0;
        tls_.negotiated_alpn(&p, &n);
        return n == 2 && p != nullptr && p[0] == 'h' && p[1] == '3';
    }

    // ------------------------------------------------------------------------
    // send_one_rtt_ping — seal a single 1-RTT packet carrying PING(+ACK) and
    // send it. Used by the gate test to prove a 1-RTT round-trip after the
    // handshake. Returns true if a packet was sent.
    // ------------------------------------------------------------------------
    bool send_one_rtt_ping() noexcept {
        assert(one_rtt_keys_ready() && "1-RTT keys not ready");
        std::uint8_t payload[kMaxPayloadSize];
        std::size_t plen = 0;
        payload[plen++] = static_cast<std::uint8_t>(FrameType::kPing);
        plen += maybe_append_ack(PacketNumberSpace::kApplication,
                                 payload + plen, sizeof(payload) - plen);
        return send_app_packet(payload, plen);
    }

private:
    // ===================================================================
    // Inbound: process a single (possibly coalesced) packet at `data`.
    // Returns false on a fatal parse/decrypt error; sets out_consumed to the
    // total bytes this packet occupied in the datagram on success.
    // ===================================================================
    bool process_one_packet(const std::uint8_t* data, std::size_t len,
                            std::size_t& out_consumed) noexcept {
        assert((data != nullptr || len == 0) && "process_one_packet: null");
        if (len < 1) return false;
        // Trailing inter-packet PADDING (0x00) terminates the coalesced run
        // (RFC 9000 §12.2): consume the rest of the datagram cleanly.
        if (data[0] == 0x00) { out_consumed = len; return true; }
        PacketForm form = PacketForm::kShort;
        if (parse_form(data, len, form) != kParseOk) return false;

        if (form == PacketForm::kShort) {
            return process_short_packet(data, len, out_consumed);
        }
        if (form == PacketForm::kLongInitial ||
            form == PacketForm::kLongHandshake) {
            return process_long_packet(data, len, form, out_consumed);
        }
        // 0-RTT / Retry / VN are out of scope this wave; skip the datagram.
        return false;
    }

    // Handle a long-header Initial/Handshake packet (parse -> unprotect ->
    // open -> frames).
    bool process_long_packet(const std::uint8_t* data, std::size_t len,
                             PacketForm form, std::size_t& out_consumed) noexcept {
        LongHeader hdr;
        std::size_t hdr_len = 0;
        if (parse_long_header(data, len, hdr, hdr_len) != kParseOk) return false;
        if (!hdr.has_length) return false;
        const bool is_initial = (form == PacketForm::kLongInitial);
        const TlsLevel level =
            is_initial ? TlsLevel::kInitial : TlsLevel::kHandshake;

        // Server learns the client's DCID (== our Initial keying) + SCID on the
        // first Initial.
        if (is_server_ && is_initial && !server_initialized_) {
            if (!server_on_first_initial(hdr)) return false;
        }

        QTRACE("long pkt level=%d hdr_len=%zu length=%llu", (int)level, hdr_len,
               (unsigned long long)hdr.length);
        PacketProtection* pp = read_protection(level);
        if (pp == nullptr || !pp->is_initialized()) {
            // Keys for this level not installed yet; cannot process. Treat the
            // packet length as consumed so coalesced parsing can continue.
            QTRACE("  no read keys at level=%d", (int)level);
            out_consumed = hdr_len + static_cast<std::size_t>(hdr.length);
            return out_consumed <= len;
        }
        const std::size_t pkt_len = hdr_len + static_cast<std::size_t>(hdr.length);
        if (pkt_len > len) return false;
        if (!open_and_handle(data, pkt_len, hdr_len, level)) {
            QTRACE("  open_and_handle FAILED level=%d", (int)level);
            return false;
        }
        out_consumed = pkt_len;
        return true;
    }

    // Handle a short-header 1-RTT packet. Its length runs to the end of the
    // datagram (no Length field), so we treat the remainder as this packet.
    bool process_short_packet(const std::uint8_t* data, std::size_t len,
                              std::size_t& out_consumed) noexcept {
        PacketProtection* pp = read_protection(TlsLevel::kApplication);
        if (pp == nullptr || !pp->is_initialized()) {
            QTRACE("short pkt: no 1-RTT read keys");
            return false;
        }
        ShortHeader sh;
        std::size_t hdr_len = 0;
        if (parse_short_header(data, len, local_cid_.length, sh, hdr_len) !=
            kParseOk) {
            return false;
        }
        QTRACE("short pkt len=%zu hdr_len=%zu", len, hdr_len);
        if (!open_and_handle(data, len, hdr_len, TlsLevel::kApplication)) {
            QTRACE("  short open FAILED");
            return false;
        }
        out_consumed = len;
        return true;
    }

    // Common open path: header-unprotect + AEAD-open over a local scratch copy,
    // then dispatch frames. `pkt_len` is the on-wire length of this packet;
    // `pn_offset` is the offset of the (still-protected) packet number.
    bool open_and_handle(const std::uint8_t* data, std::size_t pkt_len,
                         std::size_t pn_offset, TlsLevel level) noexcept {
        assert(pkt_len <= kMaxDatagramSize && "open: oversize packet");
        assert(pn_offset < pkt_len && "open: pn_offset past packet");
        PacketProtection* pp = read_protection(level);
        if (pp == nullptr) return false;

        std::uint8_t buf[kMaxDatagramSize];
        std::memcpy(buf, data, pkt_len);
        const std::size_t sample_off = PacketProtection::sample_offset(pn_offset);
        if (sample_off + kHpSampleLength > pkt_len) return false;

        std::size_t pn_len = 0;
        if (!pp->unprotect_header(buf, pn_offset, data + sample_off, &pn_len))
            return false;
        const std::uint64_t pn = decode_pn(buf, pn_offset, pn_len, space_for(level));
        const std::size_t payload_off = pn_offset + pn_len;
        if (payload_off >= pkt_len) return false;

        std::uint8_t plain[kMaxDatagramSize];
        std::size_t plain_len = 0;
        if (!pp->decrypt(pn, buf, payload_off, data + payload_off,
                         pkt_len - payload_off, plain, &plain_len)) {
            return false;  // auth failure: drop
        }
        spaces_[space_for(level)].on_packet_received(pn);
        acks_[space_idx(level)].record(pn);
        QTRACE("  opened level=%d pn=%llu plain_len=%zu", (int)level,
               (unsigned long long)pn, plain_len);
        return handle_frames(level, plain, plain_len);
    }

    // Decode the truncated packet number from the unprotected header bytes.
    std::uint64_t decode_pn(const std::uint8_t* hdr, std::size_t pn_offset,
                            std::size_t pn_len, PacketNumberSpace space) noexcept {
        assert(pn_len >= 1 && pn_len <= 4 && "decode_pn: bad pn_len");
        std::uint64_t trunc = 0;
        for (std::size_t i = 0; i < pn_len; ++i)
            trunc = (trunc << 8) | hdr[pn_offset + i];
        const std::int64_t largest = spaces_[space].largest_received();
        if (largest < 0) return trunc;
        return pn_decode(trunc, static_cast<std::uint64_t>(largest),
                         static_cast<std::uint8_t>(pn_len * 8));
    }

    // Walk the decrypted frames and dispatch them (RFC 9000 §19).
    bool handle_frames(TlsLevel level, const std::uint8_t* data,
                       std::size_t len) noexcept {
        assert((data != nullptr || len == 0) && "handle_frames: null");
        std::size_t pos = 0;
        while (pos < len) {
            const std::uint8_t type = data[pos];
            std::size_t consumed = 0;
            if (!handle_one_frame(level, data + pos, len - pos, consumed))
                return false;
            // PADDING/PING are single-byte; everything else reports consumed.
            pos += (consumed == 0) ? padding_or_ping_run(type, data + pos,
                                                          len - pos)
                                   : consumed;
            if (consumed == 0 && (type != 0x00 && type != 0x01)) return false;
        }
        return true;
    }

    // Dispatch one frame; sets out_consumed (0 for PADDING/PING, handled by the
    // caller's run helper).
    bool handle_one_frame(TlsLevel level, const std::uint8_t* data,
                          std::size_t len, std::size_t& out_consumed) noexcept {
        assert(len > 0 && "handle_one_frame: empty");
        const std::uint8_t type = data[0];
        if (type == 0x00 || type == 0x01) { out_consumed = 0; return true; }
        if (type == 0x02 || type == 0x03)
            return handle_ack(level, data, len, type == 0x03, out_consumed);
        if (type == static_cast<std::uint8_t>(FrameType::kCrypto))
            return handle_crypto(level, data + 1, len - 1, out_consumed);
        if (type == static_cast<std::uint8_t>(FrameType::kConnectionClose) ||
            type == static_cast<std::uint8_t>(FrameType::kConnectionCloseApp))
            return handle_close(data, len, type == 0x1d, out_consumed);
        if (type == static_cast<std::uint8_t>(FrameType::kHandshakeDone)) {
            if (!is_server_) handshake_confirmed_ = true;
            QTRACE("  HANDSHAKE_DONE received");
            out_consumed = 1;
            return true;
        }
        if (is_stream_frame_type(type)) {
            // Streams are wave 5; skip the frame body cleanly (parse framing).
            StreamFrame sf;
            std::size_t c = 0;
            if (sf.parse(type, data + 1, len - 1, c) != kFrameOk) return false;
            out_consumed = 1 + c;
            return true;
        }
        return false;  // unknown frame -> protocol error
    }

    bool handle_ack(TlsLevel level, const std::uint8_t* data, std::size_t len,
                    bool ecn, std::size_t& out_consumed) noexcept {
        AckFrame ack;
        std::size_t c = 0;
        if (ack.parse(data + 1, len - 1, ecn, c) != kFrameOk) return false;
        spaces_[space_for(level)].on_largest_acked(ack.largest_acked);
        // Mark our CRYPTO at/below largest_acked as acked (coarse: clears the
        // pending flag so we stop retransmitting once the peer has it).
        crypto_acked_[static_cast<std::size_t>(level)] = true;
        out_consumed = 1 + c;
        return true;
    }

    bool handle_crypto(TlsLevel level, const std::uint8_t* data, std::size_t len,
                       std::size_t& out_consumed) noexcept {
        CryptoFrame cf;
        std::size_t c = 0;
        if (cf.parse(data, len, c) != kFrameOk) return false;
        const std::size_t li = static_cast<std::size_t>(level);
        QTRACE("  CRYPTO level=%d off=%llu len=%llu", (int)level,
               (unsigned long long)cf.offset, (unsigned long long)cf.length);
        if (!crypto_rx_[li].receive(cf.offset, cf.data,
                                    static_cast<std::size_t>(cf.length)))
            return false;
        drain_crypto_to_tls(level);
        out_consumed = 1 + c;
        return true;
    }

    bool handle_close(const std::uint8_t* data, std::size_t len, bool is_app,
                      std::size_t& out_consumed) noexcept {
        ConnectionCloseFrame cc;
        std::size_t c = 0;
        if (cc.parse(data + 1, len - 1, is_app, c) != kFrameOk) return false;
        state_ = ConnState::kDraining;
        out_consumed = 1 + c;
        return true;
    }

    // Hand all contiguous reassembled CRYPTO at `level` to the TLS driver.
    void drain_crypto_to_tls(TlsLevel level) noexcept {
        const std::size_t li = static_cast<std::size_t>(level);
        const std::size_t avail = crypto_rx_[li].available();
        if (avail == 0) return;
        tls_.feed_crypto(level, crypto_rx_[li].peek(), avail);
        crypto_rx_[li].consume(avail);
    }

    static std::size_t padding_or_ping_run(std::uint8_t type,
                                           const std::uint8_t* data,
                                           std::size_t len) noexcept {
        assert(len > 0 && "padding run: empty");
        if (type == 0x00) return parse_padding_run(data, len);
        return 1;  // PING
    }

    // ===================================================================
    // Server: derive Initial keys from the client's DCID and adopt the peer's
    // SCID on the first Initial.
    // ===================================================================
    bool server_on_first_initial(const LongHeader& hdr) noexcept {
        assert(is_server_ && "server_on_first_initial: not server");
        assert(!server_initialized_ && "double server init");
        std::memcpy(initial_dcid_.data, hdr.dest_cid.data, hdr.dest_cid.length);
        initial_dcid_.length = hdr.dest_cid.length;
        peer_cid_ = hdr.source_cid;  // reply to the client's SCID
        if (!derive_initial_keys(initial_dcid_)) return false;
        state_ = ConnState::kHandshaking;
        server_initialized_ = true;
        return true;
    }

    // ===================================================================
    // Outbound: build + send packets for each level that has data.
    // ===================================================================
    void flush() noexcept {
        if (state_ == ConnState::kClosed || state_ == ConnState::kDraining)
            return;
        flush_level(TlsLevel::kInitial, PacketForm::kLongInitial);
        flush_level(TlsLevel::kHandshake, PacketForm::kLongHandshake);
        flush_app_level();
    }

    // Build + send long-header (Initial/Handshake) packets at `level`. Pulls all
    // pending TLS CRYPTO and emits as many packets as needed to send it (a TLS
    // flight can exceed one packet's payload budget), prepending an ACK to the
    // first packet. Loops bounded by the CRYPTO byte budget.
    void flush_level(TlsLevel level, PacketForm form) noexcept {
        PacketProtection* pp = write_protection(level);
        if (pp == nullptr || !pp->is_initialized()) return;
        pull_pending_crypto(level);

        bool first = true;
        for (std::size_t i = 0; i <= kMaxCoalescedPackets; ++i) {
            std::uint8_t payload[kMaxPayloadSize];
            std::size_t plen = 0;
            if (first) {
                plen += maybe_append_ack(space_for(level), payload + plen,
                                         sizeof(payload) - plen);
            }
            plen += frame_crypto(level, payload + plen, sizeof(payload) - plen);
            if (plen == 0) break;  // nothing more to send at this level
            QTRACE("flush_level level=%d send payload=%zu", (int)level, plen);
            build_and_send_long(level, form, payload, plen);
            first = false;
            if (!has_unsent_crypto(level)) break;
        }
    }

    // Build + send 1-RTT short-header packets (server's HANDSHAKE_DONE + any
    // pending ACK once 1-RTT write keys exist).
    void flush_app_level() noexcept {
        PacketProtection* pp = write_protection(TlsLevel::kApplication);
        if (pp == nullptr || !pp->is_initialized()) return;
        std::uint8_t payload[kMaxPayloadSize];
        std::size_t plen = 0;
        if (is_server_ && tls_.is_complete() && !handshake_done_sent_) {
            payload[plen++] = static_cast<std::uint8_t>(FrameType::kHandshakeDone);
            handshake_done_sent_ = true;
        }
        plen += maybe_append_ack(PacketNumberSpace::kApplication, payload + plen,
                                 sizeof(payload) - plen);
        if (plen == 0) return;
        QTRACE("flush_app send payload=%zu hs_done_sent=%d", plen,
               handshake_done_sent_);
        send_app_packet(payload, plen);
    }

    // Move all pending TLS CRYPTO for `level` into our send buffer (so it can be
    // framed across multiple packets + retransmitted).
    void pull_pending_crypto(TlsLevel level) noexcept {
        std::vector<std::uint8_t> chunk;
        tls_.pull_crypto(level, chunk);
        if (chunk.empty()) return;
        const std::size_t li = static_cast<std::size_t>(level);
        crypto_tx_[li].insert(crypto_tx_[li].end(), chunk.begin(), chunk.end());
        crypto_acked_[li] = false;
        QTRACE("pull_crypto level=%d +%zu (total=%zu)", (int)level, chunk.size(),
               crypto_tx_[li].size());
    }

    bool has_unsent_crypto(TlsLevel level) const noexcept {
        const std::size_t li = static_cast<std::size_t>(level);
        return crypto_sent_off_[li] < crypto_tx_[li].size();
    }

    // Frame the unsent tail of crypto_tx_[level] into a CRYPTO frame (bounded by
    // kCryptoChunk and cap). Returns bytes written.
    std::size_t frame_crypto(TlsLevel level, std::uint8_t* out,
                             std::size_t cap) noexcept {
        const std::size_t li = static_cast<std::size_t>(level);
        const std::size_t total = crypto_tx_[li].size();
        if (crypto_sent_off_[li] >= total) return 0;
        std::size_t n = total - crypto_sent_off_[li];
        if (n > kCryptoChunk) n = kCryptoChunk;
        CryptoFrame cf;
        cf.offset = crypto_sent_off_[li];
        cf.length = n;
        cf.data = crypto_tx_[li].data() + crypto_sent_off_[li];
        // header: type(1) + varint(offset) + varint(len) + payload.
        const std::size_t need = 1 + varint_encoded_size(cf.offset) +
                                 varint_encoded_size(cf.length) + n;
        if (need > cap) return 0;
        const std::size_t wrote = cf.serialize(out);
        crypto_sent_off_[li] += n;
        assert(wrote == need && "frame_crypto: size mismatch");
        return wrote;
    }

    // Append an ACK frame if the space has received packets and an ACK is due.
    std::size_t maybe_append_ack(std::size_t space, std::uint8_t* out,
                                 std::size_t cap) noexcept {
        assert(space < kPacketNumberSpaceCount && "ack: bad space");
        AckFrame ack;
        if (!acks_[space].build_ack_frame(ack, 0)) return 0;
        // Worst case ACK size is bounded; cap-guard before serialize.
        if (cap < 64) return 0;
        return ack.serialize(out);
    }

    std::size_t maybe_append_ack(PacketNumberSpace space, std::uint8_t* out,
                                 std::size_t cap) noexcept {
        return maybe_append_ack(static_cast<std::size_t>(space), out, cap);
    }

    // Build a long-header packet around `payload`, AEAD-seal, header-protect,
    // and send. Initial packets are padded to >=1200 bytes (RFC 9000 §14.1).
    void build_and_send_long(TlsLevel level, PacketForm form,
                             const std::uint8_t* payload,
                             std::size_t payload_len) noexcept {
        assert(payload_len <= kMaxPayloadSize && "long: oversize payload");
        PacketProtection* pp = write_protection(level);
        if (pp == nullptr) return;
        const std::uint64_t pn = spaces_[space_for(level)].next_packet_number();
        const std::uint8_t pn_len = 4;  // fixed 4B PN (simplifies HP sample)

        std::uint8_t dgram[kMaxDatagramSize];
        std::size_t hdr_len = 0;
        const std::size_t length_field =
            pn_len + payload_len + kAeadTagLength;
        if (!write_long_header(dgram, &hdr_len, form, level, length_field))
            return;
        const std::size_t pn_offset = hdr_len;
        write_pn(dgram + pn_offset, pn, pn_len);
        seal_and_send(dgram, pn_offset, pn_len, payload, payload_len, pn, pp,
                      level == TlsLevel::kInitial);
    }

    // Build a 1-RTT short-header packet and send it.
    bool send_app_packet(const std::uint8_t* payload,
                         std::size_t payload_len) noexcept {
        assert(payload_len <= kMaxPayloadSize && "app: oversize payload");
        PacketProtection* pp = write_protection(TlsLevel::kApplication);
        if (pp == nullptr || !pp->is_initialized()) return false;
        const std::uint64_t pn =
            spaces_[PacketNumberSpace::kApplication].next_packet_number();
        const std::uint8_t pn_len = 4;

        std::uint8_t dgram[kMaxDatagramSize];
        // Short header: first byte 0x40 | (pn_len-1), then DCID, then PN.
        std::size_t pos = 0;
        dgram[pos++] = static_cast<std::uint8_t>(0x40 | (pn_len - 1));
        std::memcpy(dgram + pos, peer_cid_.data, peer_cid_.length);
        pos += peer_cid_.length;
        const std::size_t pn_offset = pos;
        write_pn(dgram + pn_offset, pn, pn_len);
        seal_and_send(dgram, pn_offset, pn_len, payload, payload_len, pn, pp,
                      false);
        return true;
    }

    // Shared seal + header-protect + send for both header shapes.
    void seal_and_send(std::uint8_t* dgram, std::size_t pn_offset,
                       std::uint8_t pn_len, const std::uint8_t* payload,
                       std::size_t payload_len, std::uint64_t pn,
                       PacketProtection* pp, bool pad_initial) noexcept {
        assert(pp != nullptr && "seal_and_send: null pp");
        const std::size_t aad_len = pn_offset + pn_len;
        std::uint8_t sealed[kMaxDatagramSize];
        std::size_t sealed_len = 0;
        if (!pp->encrypt(pn, dgram, aad_len, payload, payload_len, sealed,
                         &sealed_len)) {
            return;
        }
        std::memcpy(dgram + aad_len, sealed, sealed_len);
        std::size_t total = aad_len + sealed_len;
        const std::size_t sample_off = PacketProtection::sample_offset(pn_offset);
        assert(sample_off + kHpSampleLength <= total && "HP sample past packet");
        pp->protect_header(dgram, pn_offset, pn_len, dgram + sample_off);

        if (pad_initial && total < kInitialMinDatagram) {
            std::memset(dgram + total, 0, kInitialMinDatagram - total);
            total = kInitialMinDatagram;
        }
        assert(total <= kMaxDatagramSize && "datagram overflow");
        send_(dgram, total);
    }

    // Write a long header up to (excluding) the packet number. *out_len receives
    // the header length (== pn_offset). Returns false on overflow.
    bool write_long_header(std::uint8_t* out, std::size_t* out_len,
                           PacketForm form, TlsLevel level,
                           std::size_t length_field) noexcept {
        assert(out != nullptr && out_len != nullptr && "write_long_header: null");
        std::size_t pos = 0;
        const std::uint8_t type_bits =
            (form == PacketForm::kLongInitial)
                ? static_cast<std::uint8_t>(LongPacketType::kInitial)
                : static_cast<std::uint8_t>(LongPacketType::kHandshake);
        // first byte: form(1) fixed(1) type(2) reserved(2)=0 pn_len(2)=3 (4B PN)
        out[pos++] = static_cast<std::uint8_t>(0xC0 | (type_bits << 4) | 0x03);
        out[pos++] = (kQuicVersion1 >> 24) & 0xFF;
        out[pos++] = (kQuicVersion1 >> 16) & 0xFF;
        out[pos++] = (kQuicVersion1 >> 8) & 0xFF;
        out[pos++] = kQuicVersion1 & 0xFF;
        out[pos++] = peer_cid_.length;
        std::memcpy(out + pos, peer_cid_.data, peer_cid_.length);
        pos += peer_cid_.length;
        out[pos++] = local_cid_.length;
        std::memcpy(out + pos, local_cid_.data, local_cid_.length);
        pos += local_cid_.length;
        if (level == TlsLevel::kInitial) out[pos++] = 0x00;  // token length 0
        pos += varint_encode(length_field, out + pos);
        (void)level;
        *out_len = pos;
        assert(pos < kMaxDatagramSize && "header overflow");
        return true;
    }

    static void write_pn(std::uint8_t* out, std::uint64_t pn,
                         std::uint8_t pn_len) noexcept {
        assert(pn_len >= 1 && pn_len <= 4 && "write_pn: bad len");
        for (std::size_t i = 0; i < pn_len; ++i)
            out[i] = static_cast<std::uint8_t>(
                (pn >> ((pn_len - 1 - i) * 8)) & 0xFF);
    }

    // Retransmit unacked CRYPTO for Initial/Handshake by rewinding the send
    // offset so flush() re-frames it. Minimal stand-in for PTO.
    void retransmit_pending() noexcept {
        for (std::size_t li = 0; li < kNumTlsLevels; ++li) {
            if (li == static_cast<std::size_t>(TlsLevel::kEarlyData)) continue;
            if (crypto_acked_[li]) continue;
            if (crypto_sent_off_[li] > 0 &&
                crypto_sent_off_[li] >= crypto_tx_[li].size() &&
                !crypto_tx_[li].empty()) {
                crypto_sent_off_[li] = 0;  // re-send from the start
            }
        }
    }

    // ===================================================================
    // Keys + state helpers.
    // ===================================================================
    // Derive Initial read/write protection from `dcid` (RFC 9001 §5.2). Client
    // writes with the client secret + reads with the server secret; server is
    // the mirror.
    bool derive_initial_keys(const ConnectionId& dcid) noexcept {
        assert(dcid.length <= kMaxConnectionIdLen && "initial dcid too long");
        const bool write_is_server = is_server_;   // we WRITE our own direction
        const bool read_is_server = !is_server_;   // we READ the peer's
        if (!derive_initial(dcid.data, dcid.length, write_is_server,
                            initial_write_))
            return false;
        return derive_initial(dcid.data, dcid.length, read_is_server,
                              initial_read_);
    }

    PacketProtection* read_protection(TlsLevel level) noexcept {
        if (level == TlsLevel::kInitial) return &initial_read_;
        return &tls_.read_protection(level);
    }
    PacketProtection* write_protection(TlsLevel level) noexcept {
        if (level == TlsLevel::kInitial) return &initial_write_;
        return &tls_.write_protection(level);
    }

    static PacketNumberSpace space_for(TlsLevel level) noexcept {
        switch (level) {
            case TlsLevel::kInitial:   return PacketNumberSpace::kInitial;
            case TlsLevel::kHandshake: return PacketNumberSpace::kHandshake;
            default:                   return PacketNumberSpace::kApplication;
        }
    }
    static std::size_t space_idx(TlsLevel level) noexcept {
        return static_cast<std::size_t>(space_for(level));
    }
    void maybe_promote_state() noexcept {
        if (state_ == ConnState::kClosed || state_ == ConnState::kDraining)
            return;
        if (state_ == ConnState::kNew && tls_.failed() == false)
            state_ = ConnState::kHandshaking;
        const bool keys = one_rtt_keys_ready();
        const bool done = is_server_ ? tls_.is_complete() : handshake_confirmed_;
        if (keys && done && state_ != ConnState::kEstablished) {
            state_ = ConnState::kEstablished;
        }
        // Server treats TLS completion as established once it has emitted
        // HANDSHAKE_DONE machinery; client waits for the HANDSHAKE_DONE frame.
        if (is_server_ && keys && tls_.is_complete() &&
            state_ != ConnState::kEstablished) {
            state_ = ConnState::kEstablished;
        }
    }

    TransportParameters make_local_params() const noexcept {
        TransportParameters tp;
        tp.initial_max_data = 1u << 20;
        tp.initial_max_data_present = true;
        tp.initial_max_stream_data_bidi_local = 256u * 1024;
        tp.initial_max_stream_data_bidi_local_present = true;
        tp.initial_max_stream_data_bidi_remote = 256u * 1024;
        tp.initial_max_stream_data_bidi_remote_present = true;
        tp.initial_max_stream_data_uni = 128u * 1024;
        tp.initial_max_stream_data_uni_present = true;
        tp.initial_max_streams_bidi = 100;
        tp.initial_max_streams_bidi_present = true;
        tp.initial_max_streams_uni = 3;
        tp.initial_max_streams_uni_present = true;
        tp.max_idle_timeout = 30000;
        tp.max_idle_timeout_present = true;
        tp.active_connection_id_limit = 4;
        tp.active_connection_id_limit_present = true;
        return tp;
    }

    static void gen_random(std::uint8_t* out, std::size_t n) noexcept {
        assert(out != nullptr && "gen_random: null");
        assert(n <= kMaxConnectionIdLen && "gen_random: too long");
        RAND_bytes(out, static_cast<int>(n));
    }

    // ---- members ----------------------------------------------------------
    QuicTls tls_;
    QuicSendFn send_;
    bool is_server_ = false;
    bool server_initialized_ = false;
    bool handshake_done_sent_ = false;
    bool handshake_confirmed_ = false;  // client saw HANDSHAKE_DONE
    ConnState state_ = ConnState::kNew;

    ConnectionId local_cid_;     // our SCID
    ConnectionId peer_cid_;      // peer's SCID (our DCID for sends)
    ConnectionId initial_dcid_;  // DCID used to key Initial

    PacketProtection initial_read_;
    PacketProtection initial_write_;

    PacketNumberSpaceManager spaces_;
    AckRangeTracker acks_[kPacketNumberSpaceCount];
    CryptoReassembly crypto_rx_[kNumTlsLevels];

    // Outbound CRYPTO bytes per level + the running send offset + acked flag.
    std::vector<std::uint8_t> crypto_tx_[kNumTlsLevels];
    std::size_t crypto_sent_off_[kNumTlsLevels] = {0, 0, 0, 0};
    bool crypto_acked_[kNumTlsLevels] = {false, false, false, false};
};

}  // namespace bolt::api::quic
