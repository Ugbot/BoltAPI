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
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <new>
#include <vector>

#include "boltapi/quic/ack.h"
#include "boltapi/quic/frames.h"
#include "boltapi/quic/loss.h"
#include "boltapi/quic/packet.h"
#include "boltapi/quic/packet_protection.h"
#include "boltapi/quic/pn_space.h"
#include "boltapi/quic/stream.h"
#include "boltapi/quic/tls.h"
#include "boltapi/quic/transport_params.h"
#include "boltapi/quic/varint.h"

#include "bolt/bolt_arena.h"
#include "bolt/join/bolt_swiss.h"

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

// Raised when contiguous, in-order stream bytes are available (RFC 9000 §2);
// `fin` is true on the final delivery for the stream. The bytes are valid only
// for the duration of the call (borrowed from the stream's reassembly buffer).
using QuicStreamDataFn =
    std::function<void(std::uint64_t stream_id, const std::uint8_t* data,
                       std::size_t len, bool fin)>;

// STREAM payload budget per frame (leaves room for the frame header in a
// packet). Bounded so a multi-KB message spans several frames/packets.
inline constexpr std::size_t kMaxStreamChunk = 1024;
// Default connection-level recv window growth step + advertise threshold.
inline constexpr std::uint64_t kConnFlowChunk = 64 * 1024;

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

    // tick — RFC 9002 §6.2 PTO driver. On expiry, re-arm exponential backoff and
    // re-frame the oldest unacked CRYPTO/STREAM data into fresh packets, then
    // flush (which also emits any due ACKs / new data within cwnd).
    void tick() noexcept {
        if (state_ == ConnState::kClosed || state_ == ConnState::kDraining)
            return;
        tls_.advance();
        maybe_promote_state();
        maybe_pto_expire();
        flush();
    }

    // Check the PTO timer across spaces; on expiry, mark the oldest in-flight
    // ack-eliciting packet for retransmit (rewind its frontiers) and back off.
    void maybe_pto_expire() noexcept {
        const std::uint64_t now = now_us();
        bool fired = false;
        for (std::size_t si = 0; si < kPacketNumberSpaceCount; ++si) {
            SentPacketTracker& tr = sent_[si];
            std::uint64_t earliest = 0;
            if (!tr.earliest_in_flight_time(earliest)) continue;
            const std::uint64_t pto = rtt_.pto(max_ack_delay_us(), pto_backoff_);
            if (now < earliest + pto) continue;
            // PTO expired for this space: re-frame its oldest unacked packet.
            // RFC 9002 §6.2.4 lets a PTO probe ignore the congestion window, so
            // tail loss (no later packet to trigger packet-threshold) recovers.
            for (std::size_t i = 0; i < tr.count(); ++i) {
                SentPacketInfo& s = tr.at(i);
                if (s.acked || s.lost || !s.ack_eliciting) continue;
                requeue_lost(s);
                s.lost = true;
                if (s.in_flight) { s.in_flight = false; cc_.on_packet_lost(s.size); }
                fired = true;
                break;
            }
        }
        if (fired) {
            if (pto_probes_ < 2) ++pto_probes_;  // up to 2 probe packets
            if (pto_backoff_ < kMaxPtoBackoffShift) ++pto_backoff_;
        }
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
        FrameRange ranges[kMaxFrameRangesPerPacket];
        std::size_t rc = 0;
        return send_app_packet(payload, plen, /*ack_eliciting=*/true, ranges, rc);
    }

    // ------------------------------------------------------------------------
    // Stream API (RFC 9000 §2-§4). Available once 1-RTT keys exist.
    // ------------------------------------------------------------------------
    void set_stream_data_handler(QuicStreamDataFn fn) noexcept {
        on_stream_data_ = std::move(fn);
    }

    // Open a client/server-initiated bidirectional stream. Returns its id.
    std::uint64_t open_bidi() noexcept {
        return open_stream(/*uni=*/false);
    }
    // Open a unidirectional stream. Returns its id.
    std::uint64_t open_uni() noexcept {
        return open_stream(/*uni=*/true);
    }

    // Queue `data` (and optional FIN) on `id`, creating the stream if needed.
    // Returns bytes queued; respects per-stream + connection flow control on
    // flush. Does not itself send — flush()/tick() drain under cwnd.
    std::size_t stream_write(std::uint64_t id, const std::uint8_t* data,
                             std::size_t len, bool fin) noexcept {
        assert((data != nullptr || len == 0) && "stream_write: null");
        Stream* s = get_or_create_stream(id);
        if (s == nullptr) return 0;
        const std::size_t n = s->write(data, len, fin);
        flush();
        return n;
    }

    NewRenoCongestion& congestion() noexcept { return cc_; }
    const NewRenoCongestion& congestion() const noexcept { return cc_; }
    const RttEstimator& rtt() const noexcept { return rtt_; }

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
            // RFC 9002 §2: any frame other than ACK/PADDING (and CONNECTION_CLOSE)
            // is ack-eliciting -> we owe the peer an ACK for this packet.
            if (type != 0x00 && type != 0x02 && type != 0x03 && type != 0x1c &&
                type != 0x1d)
                ack_pending_[space_idx(level)] = true;
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
            return handle_stream(type, data + 1, len - 1, out_consumed);
        }
        if (type == static_cast<std::uint8_t>(FrameType::kMaxData))
            return handle_max_data(data + 1, len - 1, out_consumed);
        if (type == static_cast<std::uint8_t>(FrameType::kMaxStreamData))
            return handle_max_stream_data(data + 1, len - 1, out_consumed);
        if (type == static_cast<std::uint8_t>(FrameType::kMaxStreamsBidi) ||
            type == static_cast<std::uint8_t>(FrameType::kMaxStreamsUni))
            return handle_max_streams(data + 1, len - 1, out_consumed);
        if (type == static_cast<std::uint8_t>(FrameType::kDataBlocked))
            return skip_one_varint(data + 1, len - 1, out_consumed);
        if (type == static_cast<std::uint8_t>(FrameType::kStreamsBlockedBidi) ||
            type == static_cast<std::uint8_t>(FrameType::kStreamsBlockedUni))
            return skip_one_varint(data + 1, len - 1, out_consumed);
        if (type == static_cast<std::uint8_t>(FrameType::kStreamDataBlocked))
            return skip_two_varint(data + 1, len - 1, out_consumed);
        if (type == static_cast<std::uint8_t>(FrameType::kResetStream))
            return handle_reset_stream(data + 1, len - 1, out_consumed);
        if (type == static_cast<std::uint8_t>(FrameType::kStopSending))
            return handle_stop_sending(data + 1, len - 1, out_consumed);
        return false;  // unknown frame -> protocol error
    }

    bool handle_ack(TlsLevel level, const std::uint8_t* data, std::size_t len,
                    bool ecn, std::size_t& out_consumed) noexcept {
        AckFrame ack;
        std::size_t c = 0;
        if (ack.parse(data + 1, len - 1, ecn, c) != kFrameOk) return false;
        spaces_[space_for(level)].on_largest_acked(ack.largest_acked);
        process_ack(level, ack);  // RFC 9002 §A.7: RTT, free acked, detect loss
        out_consumed = 1 + c;
        return true;
    }

    // RFC 9002 §A.7: walk the ACK ranges, mark our sent packets acked (RTT
    // sample on the largest), free their flow/cwnd accounting, then detect loss.
    void process_ack(TlsLevel level, const AckFrame& ack) noexcept {
        assert(ack.range_count <= kMaxAckRanges && "ack range overflow");
        SentPacketTracker& tr = sent_[space_idx(level)];
        const std::uint64_t now = now_us();
        bool acked_largest = false;
        ack_range(tr, ack.largest_acked - ack.first_ack_range, ack.largest_acked,
                  ack.largest_acked, now, acked_largest);
        std::uint64_t smallest = ack.largest_acked - ack.first_ack_range;
        for (std::size_t i = 0; i < ack.range_count; ++i) {
            if (smallest < ack.ranges[i].gap + 2) break;  // malformed; stop
            smallest -= ack.ranges[i].gap + 2;
            const std::uint64_t hi = smallest;
            if (smallest < ack.ranges[i].length) break;
            smallest -= ack.ranges[i].length;
            ack_range(tr, smallest, hi, ack.largest_acked, now, acked_largest);
        }
        if (acked_largest && rtt_sample_us_ > 0) {
            // RFC 9002 §5.1/§5.3: ack_delay is encoded with the peer's exponent;
            // we advertised the default (3 -> microsecond * 8). Decode + clamp.
            const std::uint64_t ack_delay = ack.ack_delay << kDefaultAckDelayExponent;
            rtt_.on_rtt_sample(rtt_sample_us_, ack_delay);
            rtt_sample_us_ = 0;
        }
        pto_backoff_ = 0;  // RFC 9002 §6.2.1: reset on ack of new data
        pto_probes_ = 0;
        detect_loss(level, now);
    }

    // Mark every still-unacked packet in [lo,hi] acked; sample RTT + record the
    // send time of the largest acked packet (used by time-threshold loss).
    void ack_range(SentPacketTracker& tr, std::uint64_t lo, std::uint64_t hi,
                   std::uint64_t largest, std::uint64_t now,
                   bool& acked_largest) noexcept {
        assert(lo <= hi && "ack range inverted");
        // Iterate inclusive [lo,hi]. Use a do/while-style guard so pn never wraps
        // below 0 (lo can be 0). A not-found pn is simply already-acked/evicted.
        for (std::uint64_t pn = lo;; ++pn) {
            SentPacketInfo* s = tr.find_unacked(pn);
            if (s != nullptr) {
                s->acked = true;
                if (s->in_flight) {
                    s->in_flight = false;
                    cc_.on_packet_acked(s->size, s->time_sent_us);
                }
                if (pn == largest) {
                    time_largest_acked_sent_ = s->time_sent_us;
                    if (s->ack_eliciting) {
                        rtt_sample_us_ = now - s->time_sent_us;
                        acked_largest = true;
                    }
                }
            }
            if (pn == hi) break;  // inclusive upper bound reached
        }
    }

    // RFC 9002 §6.1: declare packets lost by packet-threshold (>= 3 higher-
    // numbered packets acked) or time-threshold (a later-acked packet was sent
    // more than 9/8*max(srtt,latest) after this one — true reordering evidence,
    // measured against the largest-acked send time, NOT wall-clock now, so a
    // clean link never false-positives). Re-frame lost frames; one cc event.
    void detect_loss(TlsLevel level, std::uint64_t now) noexcept {
        SentPacketTracker& tr = sent_[space_idx(level)];
        const std::int64_t largest_acked = spaces_[space_for(level)].largest_acked();
        if (largest_acked < 0) return;
        std::uint64_t rtt = rtt_.smoothed();
        if (rtt_.latest() > rtt) rtt = rtt_.latest();
        std::uint64_t loss_delay = (kTimeThresholdNum * rtt) / kTimeThresholdDen;
        if (loss_delay < kGranularityUs) loss_delay = kGranularityUs;
        bool any_lost = false;
        std::uint64_t earliest_lost_sent = 0;
        for (std::size_t i = 0; i < tr.count(); ++i) {
            SentPacketInfo& s = tr.at(i);
            if (s.acked || s.lost || !s.ack_eliciting) continue;
            if (static_cast<std::uint64_t>(largest_acked) <= s.packet_number)
                continue;  // no later packet acked -> not yet lost
            const bool by_pkt = static_cast<std::uint64_t>(largest_acked) >=
                                s.packet_number + kPacketThreshold;
            const bool by_time = time_largest_acked_sent_ >=
                                 s.time_sent_us + loss_delay;
            if (!by_pkt && !by_time) continue;
            s.lost = true;
            if (s.in_flight) { s.in_flight = false; cc_.on_packet_lost(s.size); }
            requeue_lost(s);
            if (!any_lost || s.time_sent_us < earliest_lost_sent)
                earliest_lost_sent = s.time_sent_us;
            any_lost = true;
        }
        if (any_lost) cc_.on_congestion_event(earliest_lost_sent, now);
    }

    // Re-frame a lost packet's content by rewinding the relevant send frontier
    // so flush() re-emits the bytes under a FRESH packet number (never reused).
    void requeue_lost(const SentPacketInfo& s) noexcept {
        assert(s.range_count <= kMaxFrameRangesPerPacket && "range overflow");
        for (std::size_t i = 0; i < s.range_count; ++i) {
            const FrameRange& r = s.ranges[i];
            if (r.is_crypto) {
                const std::size_t li = static_cast<std::size_t>(r.id);
                if (li < kNumTlsLevels && r.offset < crypto_sent_off_[li])
                    crypto_sent_off_[li] = static_cast<std::size_t>(r.offset);
            } else {
                Stream* st = find_stream(r.id);
                if (st != nullptr) st->rewind_sent(r.offset, r.fin);
            }
        }
    }

    static std::uint64_t now_us() noexcept {
        const auto t = std::chrono::steady_clock::now().time_since_epoch();
        return static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(t).count());
    }
    std::uint64_t max_ack_delay_us() const noexcept { return 25000; }  // 25 ms

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

    // Inbound STREAM frame: deliver to its stream's ordered reassembly, raise
    // the data callback for newly-contiguous bytes, advance conn flow control.
    bool handle_stream(std::uint8_t type, const std::uint8_t* data,
                       std::size_t len, std::size_t& out_consumed) noexcept {
        StreamFrame sf;
        std::size_t c = 0;
        if (sf.parse(type, data, len, c) != kFrameOk) return false;
        out_consumed = 1 + c;
        Stream* s = get_or_create_stream(sf.stream_id);
        if (s == nullptr) return false;
        if (!s->receive(sf.offset, sf.data, static_cast<std::size_t>(sf.length),
                        sf.fin))
            return false;
        conn_recv_total_ += static_cast<std::uint64_t>(sf.length);
        deliver_stream(*s);
        return true;
    }

    // Hand all contiguous unread bytes to the app callback; bump windows. The
    // FIN is signalled on the delivery that carries the final byte (i.e. once
    // consuming `avail` would reach the FIN offset), or on a FIN-only frame.
    void deliver_stream(Stream& s) noexcept {
        const std::size_t avail = s.recv_available();
        s.recv_consume(avail);                 // advance the read cursor first
        const bool fin = s.recv_finished();    // now reflects bytes just consumed
        if (avail > 0 || fin) {
            if (on_stream_data_)
                on_stream_data_(s.id(), s.recv_peek_consumed(avail), avail, fin);
        }
        if (s.needs_window_update(kConnFlowChunk / 2)) {
            s.grow_recv_window(kConnFlowChunk);
            stream_window_dirty_ = true;
        }
        if (conn_recv_max_ - conn_recv_total_ < kConnFlowChunk / 2) {
            conn_recv_max_ += kConnFlowChunk;
            conn_window_dirty_ = true;
        }
    }

    bool handle_max_data(const std::uint8_t* data, std::size_t len,
                         std::size_t& out_consumed) noexcept {
        std::uint64_t v = 0;
        const int c = varint_decode(data, len, v);
        if (c < 0) return false;
        if (v > conn_send_max_) conn_send_max_ = v;
        out_consumed = 1 + static_cast<std::size_t>(c);
        return true;
    }

    bool handle_max_stream_data(const std::uint8_t* data, std::size_t len,
                                std::size_t& out_consumed) noexcept {
        std::uint64_t id = 0, v = 0;
        int c1 = varint_decode(data, len, id);
        if (c1 < 0) return false;
        int c2 = varint_decode(data + c1, len - c1, v);
        if (c2 < 0) return false;
        Stream* s = get_or_create_stream(id);
        if (s != nullptr && v > s->flow().send_max) s->flow().send_max = v;
        out_consumed = 1 + static_cast<std::size_t>(c1 + c2);
        return true;
    }

    bool handle_max_streams(const std::uint8_t* data, std::size_t len,
                            std::size_t& out_consumed) noexcept {
        std::uint64_t v = 0;
        const int c = varint_decode(data, len, v);
        if (c < 0) return false;
        out_consumed = 1 + static_cast<std::size_t>(c);
        return true;  // we never approach the limit at this scope
    }

    bool handle_reset_stream(const std::uint8_t* data, std::size_t len,
                             std::size_t& out_consumed) noexcept {
        std::uint64_t id = 0, err = 0, fsize = 0;
        int c1 = varint_decode(data, len, id);
        if (c1 < 0) return false;
        int c2 = varint_decode(data + c1, len - c1, err);
        if (c2 < 0) return false;
        int c3 = varint_decode(data + c1 + c2, len - c1 - c2, fsize);
        if (c3 < 0) return false;
        out_consumed = 1 + static_cast<std::size_t>(c1 + c2 + c3);
        return true;
    }

    bool handle_stop_sending(const std::uint8_t* data, std::size_t len,
                             std::size_t& out_consumed) noexcept {
        std::uint64_t id = 0, err = 0;
        int c1 = varint_decode(data, len, id);
        if (c1 < 0) return false;
        int c2 = varint_decode(data + c1, len - c1, err);
        if (c2 < 0) return false;
        out_consumed = 1 + static_cast<std::size_t>(c1 + c2);
        return true;
    }

    static bool skip_one_varint(const std::uint8_t* data, std::size_t len,
                                std::size_t& out_consumed) noexcept {
        std::uint64_t v = 0;
        const int c = varint_decode(data, len, v);
        if (c < 0) return false;
        out_consumed = 1 + static_cast<std::size_t>(c);
        return true;
    }
    static bool skip_two_varint(const std::uint8_t* data, std::size_t len,
                                std::size_t& out_consumed) noexcept {
        std::uint64_t a = 0, b = 0;
        int c1 = varint_decode(data, len, a);
        if (c1 < 0) return false;
        int c2 = varint_decode(data + c1, len - c1, b);
        if (c2 < 0) return false;
        out_consumed = 1 + static_cast<std::size_t>(c1 + c2);
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
            FrameRange ranges[kMaxFrameRangesPerPacket];
            std::size_t rc = 0;
            if (first) {
                plen += maybe_append_ack(space_for(level), payload + plen,
                                         sizeof(payload) - plen);
            }
            bool has_range = false;
            plen += frame_crypto(level, payload + plen, sizeof(payload) - plen,
                                 &ranges[rc], &has_range);
            if (has_range) ++rc;
            if (plen == 0) break;  // nothing more to send at this level
            QTRACE("flush_level level=%d send payload=%zu", (int)level, plen);
            build_and_send_long(level, form, payload, plen, rc > 0, ranges, rc);
            first = false;
            if (!has_unsent_crypto(level)) break;
        }
    }

    // Build + send 1-RTT short-header packets: control frames (HANDSHAKE_DONE,
    // ACK, flow-control window updates) plus STREAM data, packetized under cwnd
    // and flow control. Each ack-eliciting packet is recorded for loss recovery.
    void flush_app_level() noexcept {
        PacketProtection* pp = write_protection(TlsLevel::kApplication);
        if (pp == nullptr || !pp->is_initialized()) return;

        // Packet 0: control frames + ACK (always sendable; ACK-only is not in
        // flight, so cwnd does not gate it).
        flush_app_control();

        // STREAM data packets, bounded by coalesce count, cwnd and flow control.
        // A pending PTO probe may send up to two packets ignoring cwnd (§6.2.4).
        for (std::size_t i = 0; i < kMaxCoalescedPackets; ++i) {
            const bool probe = pto_probes_ > 0;
            if (!probe && !cc_.can_send(NewRenoCongestion::kMaxDatagram)) break;
            if (!flush_app_stream_packet()) break;  // nothing more to send
            if (probe && pto_probes_ > 0) --pto_probes_;
        }
    }

    // One packet of control frames (HANDSHAKE_DONE, window updates) + an ACK.
    void flush_app_control() noexcept {
        std::uint8_t payload[kMaxPayloadSize];
        std::size_t plen = 0;
        bool ack_eliciting = false;
        if (is_server_ && tls_.is_complete() && !handshake_done_sent_) {
            payload[plen++] = static_cast<std::uint8_t>(FrameType::kHandshakeDone);
            handshake_done_sent_ = true;
            ack_eliciting = true;
        }
        plen += frame_flow_updates(payload + plen, sizeof(payload) - plen,
                                   &ack_eliciting);
        plen += maybe_append_ack(PacketNumberSpace::kApplication, payload + plen,
                                 sizeof(payload) - plen);
        if (plen == 0) return;
        FrameRange ranges[kMaxFrameRangesPerPacket];
        std::size_t rc = 0;
        send_app_packet(payload, plen, ack_eliciting, ranges, rc);
    }

    // Build one 1-RTT packet of STREAM data across ready streams. Returns false
    // when there is nothing left to send.
    bool flush_app_stream_packet() noexcept {
        std::uint8_t payload[kMaxPayloadSize];
        std::size_t plen = 0;
        FrameRange ranges[kMaxFrameRangesPerPacket];
        std::size_t rc = 0;
        for (std::size_t si = 0; si < stream_count_ && rc < kMaxFrameRangesPerPacket;
             ++si) {
            Stream& s = streams_[si];
            if (!s.in_use() || !s.has_send_work()) continue;
            const std::size_t before = plen;
            plen += frame_one_stream(s, payload + plen, sizeof(payload) - plen,
                                     &ranges[rc]);
            if (plen > before) ++rc;
        }
        if (plen == 0) return false;
        send_app_packet(payload, plen, /*ack_eliciting=*/true, ranges, rc);
        return true;
    }

    // Frame the next chunk of one stream into a STREAM frame, honoring per-stream
    // + connection send windows. Returns bytes written (0 if blocked/empty).
    std::size_t frame_one_stream(Stream& s, std::uint8_t* out, std::size_t cap,
                                 FrameRange* range) noexcept {
        assert(range != nullptr && "frame_one_stream: null range");
        std::uint64_t off = 0; const std::uint8_t* ptr = nullptr;
        std::size_t len = 0; bool fin = false;
        std::size_t chunk = (cap > 32) ? cap - 32 : 0;  // header budget
        if (chunk > kMaxStreamChunk) chunk = kMaxStreamChunk;
        if (chunk == 0) return 0;
        if (!s.peek_unsent(off, ptr, len, fin, chunk)) return 0;
        // Apply per-stream + connection flow-control caps.
        len = clamp_send_window(s, off, len);
        if (len == 0 && !(fin && off == s.flow().send_off)) return 0;
        StreamFrame sf;
        sf.stream_id = s.id();
        sf.offset = off;
        sf.length = len;
        sf.data = (len > 0) ? ptr : nullptr;
        sf.fin = fin;
        const std::size_t need = 1 + varint_encoded_size(sf.stream_id) +
                                 varint_encoded_size(sf.offset) +
                                 varint_encoded_size(sf.length) + len;
        if (need > cap) return 0;
        const std::size_t wrote = sf.serialize(out);
        const std::size_t fresh = s.mark_sent(len, fin);
        conn_send_total_ += fresh;  // count unique bytes only (not retransmits)
        range->is_crypto = false;
        range->id = s.id();
        range->offset = off;
        range->length = len;
        range->fin = fin;
        return wrote;
    }

    // Clamp a stream chunk to the smaller of the per-stream and connection send
    // windows (RFC 9000 §4.1). Emits DATA_BLOCKED/STREAM_DATA_BLOCKED next tick.
    std::size_t clamp_send_window(Stream& s, std::uint64_t off,
                                  std::size_t len) noexcept {
        assert(off <= (1ULL << 62) && "send offset absurd");
        std::uint64_t stream_room = (off < s.flow().send_max)
                                        ? s.flow().send_max - off : 0;
        std::uint64_t conn_room = (conn_send_total_ < conn_send_max_)
                                      ? conn_send_max_ - conn_send_total_ : 0;
        if (stream_room == 0) stream_blocked_ = true;
        if (conn_room == 0) conn_blocked_ = true;
        if (len > stream_room) len = static_cast<std::size_t>(stream_room);
        if (len > conn_room) len = static_cast<std::size_t>(conn_room);
        return len;
    }

    // Emit MAX_DATA / MAX_STREAM_DATA window updates + DATA_BLOCKED /
    // STREAM_DATA_BLOCKED frames as needed. Returns bytes written.
    std::size_t frame_flow_updates(std::uint8_t* out, std::size_t cap,
                                   bool* ack_eliciting) noexcept {
        assert(ack_eliciting != nullptr && "flow updates: null flag");
        std::size_t pos = 0;
        if (conn_window_dirty_ && cap - pos >= 9) {
            pos += serialize_single_varint(FrameType::kMaxData, conn_recv_max_,
                                           out + pos);
            conn_window_dirty_ = false;
            *ack_eliciting = true;
        }
        for (std::size_t si = 0; si < stream_count_ && cap - pos >= 18; ++si) {
            Stream& s = streams_[si];
            if (!s.in_use()) continue;
            if (stream_window_dirty_) {
                pos += serialize_stream_pair(FrameType::kMaxStreamData, s.id(),
                                             s.flow().recv_max, out + pos);
                *ack_eliciting = true;
            }
        }
        stream_window_dirty_ = false;
        if (conn_blocked_ && cap - pos >= 9) {
            pos += serialize_single_varint(FrameType::kDataBlocked,
                                           conn_send_max_, out + pos);
            conn_blocked_ = false;
            *ack_eliciting = true;
        }
        if (stream_blocked_ && cap - pos >= 18) {
            for (std::size_t si = 0; si < stream_count_ && cap - pos >= 18; ++si) {
                Stream& s = streams_[si];
                if (!s.in_use() || s.flow().send_window() != 0) continue;
                pos += serialize_stream_pair(FrameType::kStreamDataBlocked,
                                             s.id(), s.flow().send_max, out + pos);
                *ack_eliciting = true;
            }
            stream_blocked_ = false;
        }
        return pos;
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
    // kCryptoChunk and cap). Returns bytes written; records the framed range.
    std::size_t frame_crypto(TlsLevel level, std::uint8_t* out, std::size_t cap,
                             FrameRange* range, bool* has_range) noexcept {
        assert(range != nullptr && has_range != nullptr && "frame_crypto: null out");
        const std::size_t li = static_cast<std::size_t>(level);
        const std::size_t total = crypto_tx_[li].size();
        if (crypto_sent_off_[li] >= total) return 0;
        std::size_t n = total - crypto_sent_off_[li];
        if (n > kCryptoChunk) n = kCryptoChunk;
        CryptoFrame cf;
        cf.offset = crypto_sent_off_[li];
        cf.length = n;
        cf.data = crypto_tx_[li].data() + crypto_sent_off_[li];
        const std::size_t need = 1 + varint_encoded_size(cf.offset) +
                                 varint_encoded_size(cf.length) + n;
        if (need > cap) return 0;
        const std::size_t wrote = cf.serialize(out);
        range->is_crypto = true;
        range->id = static_cast<std::uint64_t>(level);
        range->offset = crypto_sent_off_[li];
        range->length = n;
        range->fin = false;
        *has_range = true;
        crypto_sent_off_[li] += n;
        assert(wrote == need && "frame_crypto: size mismatch");
        return wrote;
    }

    // Append an ACK frame only when one is DUE (an ack-eliciting packet has been
    // received in this space since our last ACK, RFC 9002 §2). Clears the
    // pending flag. Avoids ACK-only-packet spam + PN inflation.
    std::size_t maybe_append_ack(std::size_t space, std::uint8_t* out,
                                 std::size_t cap) noexcept {
        assert(space < kPacketNumberSpaceCount && "ack: bad space");
        if (!ack_pending_[space]) return 0;
        AckFrame ack;
        if (!acks_[space].build_ack_frame(ack, 0)) return 0;
        if (cap < 64) return 0;  // worst-case ACK is bounded; cap-guard
        ack_pending_[space] = false;
        return ack.serialize(out);
    }

    std::size_t maybe_append_ack(PacketNumberSpace space, std::uint8_t* out,
                                 std::size_t cap) noexcept {
        return maybe_append_ack(static_cast<std::size_t>(space), out, cap);
    }

    // Build a long-header packet around `payload`, AEAD-seal, header-protect,
    // send, and record it for loss recovery. Initial packets pad to >=1200B.
    void build_and_send_long(TlsLevel level, PacketForm form,
                             const std::uint8_t* payload, std::size_t payload_len,
                             bool ack_eliciting, const FrameRange* ranges,
                             std::size_t range_count) noexcept {
        assert(payload_len <= kMaxPayloadSize && "long: oversize payload");
        assert(range_count <= kMaxFrameRangesPerPacket && "range overflow");
        PacketProtection* pp = write_protection(level);
        if (pp == nullptr) return;
        const std::uint64_t pn = spaces_[space_for(level)].next_packet_number();
        const std::uint8_t pn_len = 4;  // fixed 4B PN (simplifies HP sample)

        std::uint8_t dgram[kMaxDatagramSize];
        std::size_t hdr_len = 0;
        const std::size_t length_field = pn_len + payload_len + kAeadTagLength;
        if (!write_long_header(dgram, &hdr_len, form, level, length_field))
            return;
        const std::size_t pn_offset = hdr_len;
        write_pn(dgram + pn_offset, pn, pn_len);
        const std::size_t wire =
            seal_and_send(dgram, pn_offset, pn_len, payload, payload_len, pn, pp,
                          level == TlsLevel::kInitial);
        record_sent(space_for(level), pn, wire, ack_eliciting, ranges,
                    range_count);
    }

    // Build a 1-RTT short-header packet, send it, and record it.
    bool send_app_packet(const std::uint8_t* payload, std::size_t payload_len,
                         bool ack_eliciting, const FrameRange* ranges,
                         std::size_t range_count) noexcept {
        assert(payload_len <= kMaxPayloadSize && "app: oversize payload");
        assert(range_count <= kMaxFrameRangesPerPacket && "range overflow");
        PacketProtection* pp = write_protection(TlsLevel::kApplication);
        if (pp == nullptr || !pp->is_initialized()) return false;
        const std::uint64_t pn =
            spaces_[PacketNumberSpace::kApplication].next_packet_number();
        const std::uint8_t pn_len = 4;

        std::uint8_t dgram[kMaxDatagramSize];
        std::size_t pos = 0;
        dgram[pos++] = static_cast<std::uint8_t>(0x40 | (pn_len - 1));
        std::memcpy(dgram + pos, peer_cid_.data, peer_cid_.length);
        pos += peer_cid_.length;
        const std::size_t pn_offset = pos;
        write_pn(dgram + pn_offset, pn, pn_len);
        const std::size_t wire = seal_and_send(dgram, pn_offset, pn_len, payload,
                                               payload_len, pn, pp, false);
        record_sent(PacketNumberSpace::kApplication, pn, wire, ack_eliciting,
                    ranges, range_count);
        return true;
    }

    // Record a sent packet into its space tracker + cwnd in-flight accounting.
    void record_sent(PacketNumberSpace space, std::uint64_t pn,
                     std::size_t wire, bool ack_eliciting,
                     const FrameRange* ranges, std::size_t range_count) noexcept {
        assert(range_count <= kMaxFrameRangesPerPacket && "range overflow");
        if (wire == 0) return;  // seal failed; nothing sent
        std::uint64_t evicted = 0;
        SentPacketInfo& s = sent_[static_cast<std::size_t>(space)].record(
            pn, now_us(), wire, ack_eliciting, &evicted);
        // A bounded ring must not leak bytes_in_flight: if it overwrote a still
        // in-flight (very old, effectively lost) packet, free its bytes.
        if (evicted > 0) cc_.on_packet_lost(evicted);
        s.range_count = range_count;
        for (std::size_t i = 0; i < range_count; ++i) s.ranges[i] = ranges[i];
        if (ack_eliciting) cc_.on_packet_sent(wire);
    }

    // Shared seal + header-protect + send for both header shapes. Returns the
    // on-wire datagram length (0 on seal failure).
    std::size_t seal_and_send(std::uint8_t* dgram, std::size_t pn_offset,
                              std::uint8_t pn_len, const std::uint8_t* payload,
                              std::size_t payload_len, std::uint64_t pn,
                              PacketProtection* pp, bool pad_initial) noexcept {
        assert(pp != nullptr && "seal_and_send: null pp");
        const std::size_t aad_len = pn_offset + pn_len;
        std::uint8_t sealed[kMaxDatagramSize];
        std::size_t sealed_len = 0;
        if (!pp->encrypt(pn, dgram, aad_len, payload, payload_len, sealed,
                         &sealed_len)) {
            return 0;
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
        return total;
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

    // ===================================================================
    // Stream pool + SwissTable map (stream_id -> pool index).
    // ===================================================================
    void ensure_stream_map() noexcept {
        if (stream_map_ready_) return;
        const bool ok = bolt::SwissTable::create(&stream_map_, kMaxStreams,
                                                 &stream_arena_);
        assert(ok && "stream map alloc failed");
        // Pre-allocate the bounded Stream pool from the arena (placement-new so
        // each Stream's default member initializers run). No per-stream malloc.
        void* raw = stream_arena_.allocate(kMaxStreams * sizeof(Stream),
                                           alignof(Stream));
        assert(raw != nullptr && "stream pool alloc failed");
        streams_ = static_cast<Stream*>(raw);
        for (std::size_t i = 0; i < kMaxStreams; ++i) new (&streams_[i]) Stream();
        (void)ok;
        stream_map_ready_ = true;
    }

    // Allocate a new locally-initiated stream and return its id.
    std::uint64_t open_stream(bool uni) noexcept {
        ensure_stream_map();
        assert(stream_count_ < kMaxStreams && "stream pool exhausted");
        std::uint64_t& seq = uni ? next_uni_seq_ : next_bidi_seq_;
        const std::uint64_t id = make_stream_id(seq++, is_server_, uni);
        Stream* s = alloc_stream(id);
        assert(s != nullptr && "open_stream alloc failed");
        (void)s;
        return id;
    }

    Stream* find_stream(std::uint64_t id) noexcept {
        if (!stream_map_ready_) return nullptr;
        const std::int32_t idx = stream_map_.find(id);
        if (idx < 0) return nullptr;
        assert(static_cast<std::size_t>(idx) < kMaxStreams && "stream idx oob");
        return &streams_[static_cast<std::size_t>(idx)];
    }

    Stream* get_or_create_stream(std::uint64_t id) noexcept {
        Stream* s = find_stream(id);
        if (s != nullptr) return s;
        return alloc_stream(id);
    }

    Stream* alloc_stream(std::uint64_t id) noexcept {
        ensure_stream_map();
        if (stream_count_ >= kMaxStreams) return nullptr;
        const std::size_t idx = stream_count_++;
        const std::uint64_t init_send_max = peer_initial_stream_window(id);
        Stream& s = streams_[idx];
        s.open(id, init_send_max, kStreamRecvWindow);
        if (!stream_map_.insert(id, static_cast<std::uint32_t>(idx))) {
            --stream_count_;
            return nullptr;
        }
        return &s;
    }

    // The peer's advertised initial per-stream send window for `id` (RFC 9000
    // §3.1): for a stream we initiate, our send limit is the peer's "remote"
    // window; for a peer-initiated bidi stream, the peer's "local" window. Uni
    // streams use initial_max_stream_data_uni. Defaults conservatively.
    std::uint64_t peer_initial_stream_window(std::uint64_t id) const noexcept {
        assert(id <= kVarIntMax && "stream id overflow");
        if (!tls_.have_peer_transport_params()) return kStreamRecvWindow;
        const TransportParameters& tp = tls_.peer_transport_params();
        std::uint64_t w = kStreamRecvWindow;
        const bool we_initiated =
            stream_is_server_initiated(id) == is_server_;
        if (stream_is_uni(id)) {
            if (tp.initial_max_stream_data_uni_present)
                w = tp.initial_max_stream_data_uni;
        } else if (we_initiated) {
            if (tp.initial_max_stream_data_bidi_remote_present)
                w = tp.initial_max_stream_data_bidi_remote;
        } else {
            if (tp.initial_max_stream_data_bidi_local_present)
                w = tp.initial_max_stream_data_bidi_local;
        }
        if (w > kStreamBufferSize) w = kStreamBufferSize;
        return w;
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
        const ConnState before = state_;
        if (keys && done && state_ != ConnState::kEstablished) {
            state_ = ConnState::kEstablished;
        }
        // Server treats TLS completion as established once it has emitted
        // HANDSHAKE_DONE machinery; client waits for the HANDSHAKE_DONE frame.
        if (is_server_ && keys && tls_.is_complete() &&
            state_ != ConnState::kEstablished) {
            state_ = ConnState::kEstablished;
        }
        if (before != ConnState::kEstablished &&
            state_ == ConnState::kEstablished) {
            // Handshake confirmed: Initial/Handshake packets leave flight
            // (RFC 9002 §6.4 / §9.3) so 1-RTT data starts with a clean window.
            cc_.reset_in_flight();
        }
        adopt_peer_flow_limits();
    }

    // Once the peer's transport params arrive, adopt its connection-level
    // MAX_DATA (initial_max_data) as our send limit (RFC 9000 §4.1 / §7.4).
    void adopt_peer_flow_limits() noexcept {
        if (conn_send_max_ != 0 || !tls_.have_peer_transport_params()) return;
        const TransportParameters& tp = tls_.peer_transport_params();
        conn_send_max_ = tp.initial_max_data_present ? tp.initial_max_data
                                                     : (1u << 20);
        assert(conn_send_max_ > 0 && "peer MAX_DATA zero");
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
    bool ack_pending_[kPacketNumberSpaceCount] = {false, false, false};
    CryptoReassembly crypto_rx_[kNumTlsLevels];

    // Outbound CRYPTO bytes per level + the running send offset + acked flag.
    std::vector<std::uint8_t> crypto_tx_[kNumTlsLevels];
    std::size_t crypto_sent_off_[kNumTlsLevels] = {0, 0, 0, 0};
    bool crypto_acked_[kNumTlsLevels] = {false, false, false, false};

    // ---- RFC 9002 loss recovery + NewReno (wave 5) ----
    SentPacketTracker sent_[kPacketNumberSpaceCount];
    RttEstimator rtt_;
    NewRenoCongestion cc_;
    std::uint32_t pto_backoff_ = 0;
    std::uint64_t rtt_sample_us_ = 0;  // staged latest RTT pending ack of largest
    std::uint64_t time_largest_acked_sent_ = 0;  // send time of largest acked pkt
    std::uint32_t pto_probes_ = 0;     // outstanding PTO probes (bypass cwnd)

    // ---- streams + flow control (wave 5) ----
    static constexpr std::uint64_t kStreamRecvWindow = 128 * 1024;
    QuicStreamDataFn on_stream_data_;
    // The Stream pool is pre-allocated from the connection arena (each Stream
    // carries large fixed send/recv buffers; embedding kMaxStreams of them by
    // value would blow the stack). Pool-style allocation per CLAUDE.md — no
    // per-stream heap churn; bounded by kMaxStreams.
    Stream* streams_ = nullptr;
    std::size_t stream_count_ = 0;
    std::uint64_t next_bidi_seq_ = 0;
    std::uint64_t next_uni_seq_ = 0;

    bolt::Arena stream_arena_;
    bolt::SwissTable stream_map_{};
    bool stream_map_ready_ = false;

    // Connection-level flow control (RFC 9000 §4.1).
    std::uint64_t conn_send_max_ = 0;            // peer's MAX_DATA (set on init)
    std::uint64_t conn_send_total_ = 0;          // total stream bytes we've sent
    std::uint64_t conn_recv_max_ = 1u << 20;     // our advertised MAX_DATA
    std::uint64_t conn_recv_total_ = 0;          // total stream bytes received
    bool conn_window_dirty_ = false;
    bool stream_window_dirty_ = false;
    bool conn_blocked_ = false;
    bool stream_blocked_ = false;
};

}  // namespace bolt::api::quic
