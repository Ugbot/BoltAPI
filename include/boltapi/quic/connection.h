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
#include "boltapi/quic/quic_limits.h"
#include "boltapi/quic/robustness.h"
#include "boltapi/quic/stream.h"
#include "boltapi/quic/tls.h"
#include "boltapi/quic/transport_params.h"
#include "boltapi/quic/varint.h"

#include "bolt/bolt_arena.h"

// Tracing is ALWAYS compiled in but RUNTIME-gated by the BOLTAPI_QUIC_TRACE env
// var (checked once via a function-local static), so it costs nothing unless the
// env var is set. (Was #ifdef-gated, which needed a special trace build; making
// it runtime-only lets any build emit a packet trace for diagnosis.)
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
inline constexpr std::uint8_t kMinInitialDcidLen = 8;     // RFC 9000 §7.2

// W5d robustness bounds (RFC 9000 §8/§10, RFC 9001 §6).
inline constexpr std::uint64_t kDefaultIdleTimeoutMs = 30000;  // local default
inline constexpr std::uint64_t kKeyUpdateGuardPkts = 8;  // reorder window margin

// QUIC transport error codes used by CONNECTION_CLOSE (RFC 9000 §20.1).
inline constexpr std::uint64_t kNoError = 0x00;
inline constexpr std::uint64_t kInternalError = 0x01;
inline constexpr std::uint64_t kProtocolViolation = 0x0a;
inline constexpr std::uint64_t kFlowControlError = 0x03;
inline constexpr std::uint64_t kStreamLimitError = 0x04;
inline constexpr std::uint64_t kStreamStateError = 0x05;
inline constexpr std::uint64_t kFinalSizeError = 0x06;
inline constexpr std::uint64_t kFrameEncodingError = 0x07;
inline constexpr std::uint64_t kCryptoBufferExceeded = 0x0d;

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
        assert(len <= kMaxCryptoBuffer && "CryptoReassembly: len above cap");
        if (offset > kMaxCryptoBuffer) return false;  // peer offset: runtime check
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
    // Bounded set of filled byte ranges (kept SORTED + MERGED, no overlaps/
    // adjacency). A real ClientHello arrives as a handful of CRYPTO fragments in
    // ARBITRARY order (Chrome fragments heavily out-of-order); tracking each
    // filled interval — rather than one pending extent — is required to advance
    // the contiguous cursor ONLY over bytes that are actually present (the old
    // single-region tracker jumped the cursor across still-empty gaps, handing
    // TLS a corrupt ClientHello). 64 ranges is ample: merging keeps the count at
    // the number of disjoint gaps, which a handshake never approaches.
    static constexpr std::size_t kMaxRanges = 64;

    // Insert [s,e) into the sorted/merged range set; coalesce overlaps + adjacency.
    // Returns false if the set is full and the range can't be merged (protocol
    // error — far more fragments than any real handshake).
    bool add_range(std::size_t s, std::size_t e) noexcept {
        assert(s < e && e <= kMaxCryptoBuffer && "add_range: bad [s,e)");
        // Find the first range whose end >= s (candidate to merge/precede).
        std::size_t i = 0;
        while (i < range_count_ && ranges_[i].end < s) ++i;
        // Merge all subsequent ranges that overlap/touch [s,e).
        std::size_t ns = s, ne = e;
        std::size_t j = i;
        while (j < range_count_ && ranges_[j].start <= ne) {
            if (ranges_[j].start < ns) ns = ranges_[j].start;
            if (ranges_[j].end   > ne) ne = ranges_[j].end;
            ++j;
        }
        // Replace ranges_[i, j) with the single merged [ns, ne).
        if (i == j) {  // pure insertion — make room
            if (range_count_ >= kMaxRanges) return false;
            for (std::size_t k = range_count_; k > i; --k) ranges_[k] = ranges_[k - 1];
            ++range_count_;
        } else if (j - i > 1) {  // collapse j-i ranges into one
            const std::size_t removed = (j - i) - 1;
            for (std::size_t k = i + 1; k + removed < range_count_; ++k)
                ranges_[k] = ranges_[k + removed];
            range_count_ -= removed;
        }
        ranges_[i].start = ns;
        ranges_[i].end   = ne;
        assert(range_count_ <= kMaxRanges && "range_count overflow");
        return true;
    }

    // Advance recv_cursor_ over the merged range anchored at byte 0 (the
    // contiguous prefix). Ranges are sorted, so it's ranges_[0] iff it starts at 0.
    void recompute_contiguous() noexcept {
        recv_cursor_ = (range_count_ > 0 && ranges_[0].start == 0)
                           ? ranges_[0].end : 0;
        assert(recv_cursor_ <= highest_ && "cursor past highest");
        assert(read_cursor_ <= recv_cursor_ && "read cursor past contiguous");
    }

    void mark_filled(std::size_t start, std::size_t n) noexcept {
        assert(start + n <= kMaxCryptoBuffer && "mark_filled overflow");
        if (n == 0) return;
        (void)add_range(start, start + n);  // bounded; drop on overflow (no jump)
        recompute_contiguous();
    }

    struct Range { std::size_t start = 0; std::size_t end = 0; };
    std::uint8_t buffer_[kMaxCryptoBuffer]{};
    Range       ranges_[kMaxRanges]{};
    std::size_t range_count_ = 0;
    std::size_t read_cursor_ = 0;    // next byte handed to TLS
    std::size_t recv_cursor_ = 0;    // highest contiguous-from-0 byte received
    std::size_t highest_ = 0;        // highest byte ever written
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

// Raised for each received QUIC DATAGRAM frame (RFC 9221). `data`/`len` is the
// datagram payload (valid only during the call — copy if retained). Unreliable,
// unordered; no retransmit. Enables WebTransport/H3 datagrams.
using QuicDatagramFn =
    std::function<void(const std::uint8_t* data, std::size_t len)>;

// STREAM payload budget per frame (leaves room for the frame header in a
// packet). Bounded so a multi-KB message spans several frames/packets.
inline constexpr std::size_t kMaxStreamChunk = kMaxPayloadSize;
// Default connection-level recv window growth step + advertise threshold.
inline constexpr std::uint64_t kConnFlowChunk = 64 * 1024;

// ============================================================================
// QuicConnection — one endpoint (client or server) of a QUIC connection.
// ============================================================================
struct QuicConnectionTestAccess;  // defined only by test/fuzz harnesses

class QuicConnection {
    friend struct QuicConnectionTestAccess;

public:
    QuicConnection() noexcept = default;
    // The pool lives in the arena; run the Stream destructors (held bodies).
    ~QuicConnection() {
        if (streams_ == nullptr) return;
        for (std::size_t i = 0; i < kMaxStreams; ++i) streams_[i].~Stream();
    }
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
        if (is_server_) {
            tls_.set_alpn_hook([this](const std::uint8_t* p, std::size_t n) {
                on_alpn_selected(p, n);
            });
        }
        static const std::uint8_t kAlpn[] = {2, 'h', '3'};
        if (!is_server_ && !tls_.set_alpn(kAlpn, sizeof(kAlpn))) return false;
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
        last_activity_us_ = now_us();  // arm the idle timer at creation
        return true;
    }

    // start — client kicks off the handshake (builds the first Initial with the
    // ClientHello). The server starts on the first inbound Initial instead.
    bool start() noexcept {
        assert(send_ && "start before init");
        assert(!is_server_ && "server starts on first client Initial");
        state_ = ConnState::kHandshaking;
        last_activity_us_ = now_us();
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
        // We advertise max_udp_payload_size = kMaxDatagramSize; a larger
        // datagram is a peer error and must never reach the fixed open buffers.
        if (len > kMaxDatagramSize) return;
        QTRACE("feed_datagram len=%zu state=%s", len, conn_state_name(state_));
        // RFC 9000 §10.3.1: a datagram whose tail matches the peer's stateless
        // reset token tears the connection down (we have no other recourse).
        if (have_peer_reset_token_ &&
            is_stateless_reset(data, len, peer_reset_token_)) {
            got_stateless_reset_ = true;
            state_ = ConnState::kDraining;
            return;
        }
        // RFC 9000 §8.1: count received bytes toward the anti-amplification
        // budget; any inbound also restarts the idle timer (§10.1).
        amp_.on_received(len);
        last_activity_us_ = now_us();
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
        replay_held_zero_rtt();
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
        if (state_ == ConnState::kClosed) return;
        // RFC 9000 §10.2: Closing/Draining only wind down. After a bounded
        // closing period, drop to Closed (no app traffic either way).
        if (state_ == ConnState::kClosing || state_ == ConnState::kDraining) {
            if (now_us() >= closing_since_us_ + closing_period_us()) {
                state_ = ConnState::kClosed;
            }
            return;
        }
        // RFC 9000 §10.1: idle timeout. On expiry the connection silently closes
        // (no CONNECTION_CLOSE) — enter Draining so it cannot hang.
        if (idle_expired()) {
            QTRACE("idle timeout -> Draining");
            state_ = ConnState::kDraining;
            closing_since_us_ = now_us();
            return;
        }
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
    bool alpn_is_h3() const noexcept { return alpn_is("h3"); }

    // True if the negotiated ALPN equals `proto`.
    bool alpn_is(const char* proto) const noexcept {
        assert(proto != nullptr && "alpn_is: null proto");
        const std::uint8_t* p = nullptr;
        std::size_t n = 0;
        tls_.negotiated_alpn(&p, &n);
        const std::size_t want = std::strlen(proto);
        assert(want < 256 && "alpn_is: ALPN longer than 255");
        return p != nullptr && n == want && std::memcmp(p, proto, n) == 0;
    }

    // Server: ALPN protocols accepted, in preference order (wire format:
    // length-prefixed). Call before the first Initial; defaults to "h3".
    bool set_server_alpn(const std::uint8_t* protos, std::size_t len) noexcept {
        assert(is_server_ && "set_server_alpn: client role");
        return tls_.set_server_alpn(protos, len);
    }

    // Server: connections that negotiate `alpn` grant `bidi` concurrent peer
    // bidi streams (<= kPeerBidiStreamsMax) instead of the default; decided
    // when TLS selects the ALPN, before our transport parameters are sent.
    bool set_alpn_bidi_streams(const char* alpn, std::uint64_t bidi) noexcept {
        assert(is_server_ && "set_alpn_bidi_streams: client role");
        assert(alpn != nullptr && "set_alpn_bidi_streams: null alpn");
        const std::size_t n = std::strlen(alpn);
        if (n == 0 || n > sizeof(alpn_raise_) || bidi == 0 || bidi > kPeerBidiStreamsMax)
            return false;
        std::memcpy(alpn_raise_, alpn, n);
        alpn_raise_len_ = n;
        alpn_bidi_streams_ = bidi;
        return true;
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

    // RFC 9221 — register a handler for received QUIC DATAGRAM frames.
    void set_datagram_handler(QuicDatagramFn fn) noexcept {
        on_datagram_ = std::move(fn);
    }

    // RFC 9221 — send one QUIC DATAGRAM (unreliable, unordered). Frames a
    // length-prefixed DATAGRAM (type 0x31) into a 1-RTT packet. Requires 1-RTT
    // keys + that the peer advertised a max_datagram_frame_size that fits. Returns
    // false if not sendable (no keys / peer disabled datagrams / too large).
    bool send_datagram(const std::uint8_t* data, std::size_t len) noexcept {
        assert((data != nullptr || len == 0) && "send_datagram: null with len>0");
        if (!one_rtt_keys_ready()) return false;
        // Peer's limit (0/absent => peer does not accept DATAGRAMs). The limit is
        // the WHOLE frame size (type byte + length varint + payload, RFC 9221 §3).
        if (!tls_.have_peer_transport_params()) return false;
        const TransportParameters& ptp = tls_.peer_transport_params();
        const std::uint64_t peer_max = ptp.max_datagram_frame_size_present
                                           ? ptp.max_datagram_frame_size : 0;
        if (peer_max == 0) return false;
        std::uint8_t payload[kMaxPayloadSize];
        std::size_t pos = 0;
        payload[pos++] = static_cast<std::uint8_t>(FrameType::kDatagramWithLen);
        pos += varint_encode(len, payload + pos);
        if (pos + len > sizeof(payload)) return false;          // exceeds MTU budget
        if (static_cast<std::uint64_t>(pos + len) > peer_max) return false;  // peer cap
        if (len > 0) std::memcpy(payload + pos, data, len);
        pos += len;
        FrameRange ranges[kMaxFrameRangesPerPacket];
        return send_app_packet(payload, pos, /*ack_eliciting=*/true, ranges, 0);
    }

    // True if the peer's stream credit (transport params + MAX_STREAMS) and
    // the pool allow opening one more local stream of that direction.
    bool can_open_bidi() noexcept { return can_open(false); }
    bool can_open_uni() noexcept { return can_open(true); }

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
        assert(id <= kVarIntMax && "stream_write: id out of range");
        Stream* s = writable_stream(id);
        if (s == nullptr) return 0;
        const std::size_t n = s->write(data, len, fin);
        flush();
        return n;
    }

    // Queue ALL of `body` (+FIN) on `id`: the stream ring takes what fits and
    // the rest follows as the peer acknowledges. False (nothing queued) if the
    // stream is closed, already holds a body, or the connection's held-bytes
    // budget would be exceeded.
    bool stream_write_owned(std::uint64_t id, std::string&& body, bool fin) noexcept {
        assert(id <= kVarIntMax && "stream_write_owned: id out of range");
        Stream* s = writable_stream(id);
        if (s == nullptr || !s->pending_empty()) return false;
        if (pending_total() + body.size() > kPendingSendBytesMax) return false;
        s->write_owned(std::move(body), fin);
        flush();
        assert(s->pending_bytes() <= kPendingSendBytesMax && "pending over budget");
        return true;
    }

    // Copying form of stream_write_owned for borrowed bytes.
    bool stream_write_all(std::uint64_t id, const std::uint8_t* data,
                          std::size_t len, bool fin) noexcept {
        assert((data != nullptr || len == 0) && "stream_write_all: null");
        Stream* s = writable_stream(id);
        if (s == nullptr || !s->pending_empty()) return false;
        const std::size_t n = s->write(data, len, fin);
        if (n == len) { flush(); return true; }
        std::string rest(reinterpret_cast<const char*>(data) + n, len - n);
        return stream_write_owned(id, std::move(rest), fin);
    }

    // Bytes stream_write() can still queue on `id` (0 if it is closed).
    std::size_t stream_send_space(std::uint64_t id) noexcept {
        assert(id <= kVarIntMax && "stream id out of range");
        const Stream* s = writable_stream(id);
        return s == nullptr ? 0 : s->send_space();
    }

    // Abandon our send side of `id` with RESET_STREAM (RFC 9000 §19.4).
    // Returns false if the stream is closed or has no send side.
    bool reset_stream(std::uint64_t id, std::uint64_t app_error) noexcept {
        assert(id <= kVarIntMax && "reset_stream: id out of range");
        assert(app_error <= kVarIntMax && "reset_stream: error out of range");
        Stream* s = writable_stream(id);
        if (s == nullptr) return false;
        queue_reset(id, app_error, s->queued_end());
        s->abandon_send();
        flush();
        return true;
    }

    // True if a datagram with destination CID `cid` belongs to this
    // connection: our CID, or (server) the client's first DCID / Retry SCID.
    bool matches_dcid(const std::uint8_t* cid, std::size_t len) const noexcept {
        assert(cid != nullptr || len == 0);
        assert(len <= kMaxConnectionIdLen && "matches_dcid: cid too long");
        const auto eq = [cid, len](const ConnectionId& c) {
            return c.length == len && len > 0 && std::memcmp(c.data, cid, len) == 0;
        };
        return eq(local_cid_) || eq(initial_dcid_) || eq(first_dcid_) ||
               (sent_retry_ && eq(retry_scid_));
    }

    // Live streams in the pool (freed once both directions finish).
    std::size_t live_streams() const noexcept {
        std::size_t n = 0;
        for (std::size_t i = 0; streams_ != nullptr && i < kMaxStreams; ++i)
            if (streams_[i].in_use()) ++n;
        assert(n <= kMaxStreams && "live stream count overflow");
        return n;
    }

    NewRenoCongestion& congestion() noexcept { return cc_; }
    const NewRenoCongestion& congestion() const noexcept { return cc_; }
    const RttEstimator& rtt() const noexcept { return rtt_; }

    // ------------------------------------------------------------------------
    // W5d robustness configuration + control surface.
    // ------------------------------------------------------------------------
    bool is_closing() const noexcept { return state_ == ConnState::kClosing; }
    bool is_draining() const noexcept { return state_ == ConnState::kDraining; }
    bool is_closed() const noexcept { return state_ == ConnState::kClosed; }

    // Server: require a Retry round-trip before completing the handshake
    // (RFC 9000 §8.1 address validation). Call before start()/first Initial.
    void set_require_retry(bool on) noexcept { require_retry_ = on; }

    // Client: force a specific offered version in the first Initial. A value
    // other than kQuicVersion1 provokes a Version Negotiation from a real peer
    // (RFC 9000 §6). Call before start().
    void set_offered_version(std::uint32_t v) noexcept {
        assert(v != 0 && "offered version 0 is reserved for VN");
        offered_version_ = v;
    }

    // Local idle timeout in ms (RFC 9000 §10.1). 0 disables. Effective timeout
    // is min(local, peer) once peer params arrive.
    void set_idle_timeout_ms(std::uint64_t ms) noexcept { local_idle_ms_ = ms; }

    // CONNECTION_CLOSE (RFC 9000 §10.2). Emits a close frame (transport 0x1c or
    // application 0x1d) and enters Closing. Idempotent.
    void close(std::uint64_t error_code, bool application,
               const char* reason) noexcept {
        assert(error_code <= kVarIntMax && "close: error code overflow");
        if (state_ == ConnState::kClosing || state_ == ConnState::kDraining ||
            state_ == ConnState::kClosed)
            return;
        close_error_ = error_code;
        close_is_app_ = application;
        close_reason_ = reason;
        close_reason_len_ = (reason != nullptr) ? std::strlen(reason) : 0;
        if (close_reason_len_ > kMaxCloseReason)
            close_reason_len_ = kMaxCloseReason;
        close_pending_ = true;
        state_ = ConnState::kClosing;
        closing_since_us_ = now_us();
        emit_connection_close();
    }

    // Initiate a 1-RTT key update (RFC 9001 §6.1): flip our key phase and derive
    // next-generation keys. Returns true if a new generation was installed.
    bool initiate_key_update() noexcept {
        assert(one_rtt_keys_ready() && "key update before 1-RTT");
        return rotate_keys(/*peer_initiated=*/false);
    }
    std::uint64_t key_phase_generation() const noexcept { return key_gen_; }

    // Enable stateless reset: derive our token for `local_cid_` from `secret`
    // and (server) advertise it. Recognizing a peer reset needs the peer's token
    // from its transport params (set via expect_peer_reset_token).
    bool enable_stateless_reset(const std::uint8_t* secret,
                                std::size_t secret_len) noexcept {
        assert(secret != nullptr && secret_len > 0 && "srt: null secret");
        if (!derive_stateless_reset_token(secret, secret_len, local_cid_,
                                          local_reset_token_))
            return false;
        have_local_reset_token_ = true;
        return true;
    }
    const std::uint8_t* local_reset_token() const noexcept {
        return have_local_reset_token_ ? local_reset_token_ : nullptr;
    }
    void expect_peer_reset_token(const std::uint8_t* token /*[16]*/) noexcept {
        assert(token != nullptr && "peer reset token null");
        std::memcpy(peer_reset_token_, token, kStatelessResetTokenLen);
        have_peer_reset_token_ = true;
    }
    bool got_stateless_reset() const noexcept { return got_stateless_reset_; }

    // True if the idle timer has fired (no activity within the negotiated idle
    // timeout). tick() also closes on idle expiry; this is for the gate.
    bool idle_expired() const noexcept {
        const std::uint64_t to = effective_idle_us();
        if (to == 0) return false;
        return now_us() >= last_activity_us_ + to;
    }

    // True when a peer that sent a bogus version received our VN.
    bool sent_version_negotiation() const noexcept { return sent_vn_; }
    // True when this (client) connection re-keyed after a Retry.
    bool did_retry() const noexcept { return did_retry_; }
    std::uint32_t negotiated_version() const noexcept { return negotiated_version_; }

private:
    // CONNECTION_CLOSE reason cap (RFC 9000 §19.19 — bounded, no unbounded copy).
    static constexpr std::size_t kMaxCloseReason = 256;

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
        if (form == PacketForm::kVersionNegotiation) {
            return process_version_negotiation(data, len, out_consumed);
        }
        if (form == PacketForm::kLongRetry) {
            return process_retry(data, len, out_consumed);
        }
        // RFC 9000 §6.1: a server that gets an unsupported version replies with
        // a Version Negotiation packet (client never sends VN).
        if (is_server_) {
            std::uint32_t ver = 0;
            if (read_version(data, len, ver) == kParseOk &&
                !is_supported_version(ver)) {
                emit_version_negotiation(data, len);
                out_consumed = len;  // consume the whole datagram
                return true;
            }
        }
        if (form == PacketForm::kLongInitial ||
            form == PacketForm::kLongHandshake) {
            return process_long_packet(data, len, form, out_consumed);
        }
        if (form == PacketForm::kLongZeroRtt)
            return process_zero_rtt(data, len, out_consumed);
        return false;
    }

    // 0-RTT (RFC 9001 §4.6): opened with the early keys once TLS accepts the
    // client's early data. A 0-RTT packet coalesced behind the Initial that
    // carries the ClientHello arrives before TLS has run, so a few are held
    // and replayed after the next advance().
    bool process_zero_rtt(const std::uint8_t* data, std::size_t len,
                          std::size_t& out_consumed) noexcept {
        assert((data != nullptr || len == 0) && "process_zero_rtt: null");
        LongHeader hdr;
        std::size_t hdr_len = 0;
        if (parse_long_header(data, len, hdr, hdr_len) != kParseOk) return false;
        if (!hdr.has_length || hdr.length > len - hdr_len) return false;
        const std::size_t pkt_len = hdr_len + static_cast<std::size_t>(hdr.length);
        if (pkt_len <= hdr_len) return false;
        out_consumed = pkt_len;
        if (!is_server_ || !server_initialized_) return true;  // ignore
        PacketProtection* pp = read_protection(TlsLevel::kEarlyData);
        if (pp != nullptr && pp->is_initialized())
            return open_and_handle(data, pkt_len, hdr_len, TlsLevel::kEarlyData) || true;
        if (!tls_.is_complete() && early_held_ < kEarlyHeldPackets) {
            std::memcpy(early_buf_[early_held_], data, pkt_len);
            early_len_[early_held_++] = pkt_len;
        }
        assert(early_held_ <= kEarlyHeldPackets && "early hold overflow");
        return true;
    }

    // Replay held 0-RTT packets once early keys exist (or drop them once the
    // handshake completes without them: early data rejected).
    void replay_held_zero_rtt() noexcept {
        if (early_held_ == 0) return;
        PacketProtection* pp = read_protection(TlsLevel::kEarlyData);
        const bool keys = pp != nullptr && pp->is_initialized();
        if (!keys && !tls_.is_complete()) return;
        const std::size_t n = early_held_;
        early_held_ = 0;
        for (std::size_t i = 0; keys && i < n; ++i) {
            std::size_t consumed = 0;
            (void)process_zero_rtt(early_buf_[i], early_len_[i], consumed);
        }
        assert(early_held_ == 0 && "replay re-held a packet");
    }

    // ===================================================================
    // W5d: Version Negotiation (RFC 9000 §6, §17.2.1).
    // ===================================================================
    // Server: build + send a VN listing our supported versions, echoing the
    // client's CIDs. Bounded scratch; never throws.
    void emit_version_negotiation(const std::uint8_t* data,
                                  std::size_t len) noexcept {
        assert(is_server_ && "VN only emitted by server");
        LongHeader hdr;
        std::size_t consumed = 0;
        if (parse_long_header(data, len, hdr, consumed) != kParseOk &&
            hdr.dest_cid.length == 0)
            return;  // could not read CIDs; drop silently
        const std::uint32_t supported[1] = {kQuicVersion1};
        std::uint8_t out[kMaxVnPacketLen];
        const std::size_t n = build_version_negotiation(
            hdr.dest_cid, hdr.source_cid, supported, 1, out, sizeof(out));
        assert(n <= sizeof(out) && "VN overran scratch");
        if (n == 0) return;
        send_raw(out, n);
        sent_vn_ = true;
    }

    // Client: parse the offered versions; if we support one, re-key + restart
    // the handshake under it (RFC 9000 §6.2). Consumes the whole datagram.
    bool process_version_negotiation(const std::uint8_t* data, std::size_t len,
                                     std::size_t& out_consumed) noexcept {
        out_consumed = len;
        if (is_server_) return true;  // servers ignore VN
        if (vn_handled_) return true;  // RFC 9000 §6.2: act on the first only
        LongHeader hdr;
        std::size_t body_off = 0;
        if (parse_long_header(data, len, hdr, body_off) != kParseOk) return true;
        std::uint32_t versions[kMaxVnVersions];
        const std::size_t cnt = parse_version_negotiation_versions(
            data, len, body_off, versions, kMaxVnVersions);
        std::uint32_t chosen = 0;
        for (std::size_t i = 0; i < cnt; ++i)
            if (is_supported_version(versions[i])) { chosen = versions[i]; break; }
        if (chosen == 0) { state_ = ConnState::kClosed; return true; }
        vn_handled_ = true;
        negotiated_version_ = chosen;
        offered_version_ = chosen;
        restart_handshake();
        return true;
    }

    // ===================================================================
    // W5d: Retry (RFC 9000 §8.1, §17.2.5, RFC 9001 §5.8).
    // ===================================================================
    // Client: validate the Retry integrity tag over our ORIGINAL DCID, adopt the
    // server's new SCID as our DCID (re-keying Initial), store the token, and
    // restart the handshake including the token on the next Initial.
    bool process_retry(const std::uint8_t* data, std::size_t len,
                       std::size_t& out_consumed) noexcept {
        out_consumed = len;
        if (is_server_ || did_retry_) return true;  // one Retry only (§17.2.5)
        if (!verify_retry_integrity(initial_dcid_, data, len)) return true;
        LongHeader hdr;
        std::size_t body_off = 0;
        if (parse_long_header(data, len, hdr, body_off) != kParseOk) return true;
        // Retry body = token || 16-byte tag (body_off points past the CIDs).
        if (len < body_off + kRetryIntegrityTagLen) return true;
        const std::size_t token_len = len - body_off - kRetryIntegrityTagLen;
        if (token_len == 0 || token_len > kMaxRetryToken) return true;
        std::memcpy(retry_token_, data + body_off, token_len);
        retry_token_len_ = token_len;
        // Server's SCID becomes our new DCID + new Initial keying (§7.2/§5.2).
        peer_cid_ = hdr.source_cid;
        std::memcpy(initial_dcid_.data, hdr.source_cid.data, hdr.source_cid.length);
        initial_dcid_.length = hdr.source_cid.length;
        did_retry_ = true;
        restart_handshake();
        return true;
    }

    // Server: build + send a Retry to `hdr`'s client. Mints an address-validation
    // token over the client's ORIGINAL DCID and offers a fresh SCID that the
    // client will use to re-key its retried Initial (RFC 9000 §8.1, §17.2.5).
    void emit_retry(const LongHeader& hdr) noexcept {
        assert(is_server_ && "emit_retry: not server");
        first_dcid_ = hdr.dest_cid;  // retransmitted first Initials still route here
        // Our Retry SCID (the client adopts this as its new DCID). Generate it
        // ONCE: a client may retransmit its first Initial, and every Retry MUST
        // carry the SAME SCID so the retried Initial's DCID matches (RFC 9000
        // §8.1 / §17.2.5) — regenerating it each time would deadlock validation.
        if (!sent_retry_) {
            gen_random(retry_scid_.data, kLocalCidLen);
            retry_scid_.length = kLocalCidLen;
        }
        std::uint8_t token[kMaxRetryToken];
        const std::size_t tlen =
            validator_.mint_token(hdr.dest_cid, token, sizeof(token));
        if (tlen == 0) return;
        std::uint8_t out[kMaxRetryPacketLen];
        const std::size_t n = build_retry(hdr.dest_cid, hdr.source_cid,
                                          retry_scid_, token, tlen, out,
                                          sizeof(out));
        assert(n <= sizeof(out) && "retry overran scratch");
        if (n == 0) return;
        send_raw(out, n);
        sent_retry_ = true;
    }

    // Server: validate the token on a retried Initial. The token MUST verify AND
    // the Initial's DCID MUST equal the Retry SCID we offered (RFC 9000 §8.1).
    bool server_check_token(const LongHeader& hdr) noexcept {
        assert(is_server_ && "server_check_token: not server");
        if (hdr.token == nullptr || hdr.token_length == 0) return false;
        if (hdr.token_length > kMaxRetryToken) return false;
        ConnectionId odcid;
        if (!validator_.verify_token(hdr.token,
                                     static_cast<std::size_t>(hdr.token_length),
                                     &odcid))
            return false;
        if (sent_retry_ && hdr.dest_cid != retry_scid_) return false;
        odcid_ = odcid;  // §7.3: echoed as original_destination_connection_id
        address_validated_ = true;
        amp_.validate();  // §8.1: a valid token lifts the 3x limit
        return true;
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
        // first Initial. With require_retry_, an untokened/invalid first Initial
        // gets a Retry instead (RFC 9000 §8.1 address validation).
        if (is_server_ && is_initial && !server_initialized_) {
            // RFC 9000 §7.2: a client's first Initial DCID is at least 8 bytes;
            // anything shorter is discarded before any keying.
            if (hdr.dest_cid.length < kMinInitialDcidLen) return false;
            if (require_retry_ && !address_validated_ &&
                !server_check_token(hdr)) {
                emit_retry(hdr);
                out_consumed = hdr_len + static_cast<std::size_t>(hdr.length);
                return out_consumed <= len;
            }
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
        if (hdr.length > len - hdr_len) return false;
        const std::size_t pkt_len = hdr_len + static_cast<std::size_t>(hdr.length);
        if (pkt_len <= hdr_len) return false;  // Length 0: no packet number
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
        if (hdr_len >= len) return false;  // no packet number bytes
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
        // Header protection uses the (unchanging) original keys; AEAD may use a
        // rotated key-update generation for 1-RTT (RFC 9001 §6.1: HP NOT updated).
        PacketProtection* hp = read_protection(level);
        if (hp == nullptr) return false;

        std::uint8_t buf[kMaxDatagramSize];
        std::memcpy(buf, data, pkt_len);
        const std::size_t sample_off = PacketProtection::sample_offset(pn_offset);
        if (sample_off + kHpSampleLength > pkt_len) return false;

        std::size_t pn_len = 0;
        if (!hp->unprotect_header(buf, pn_offset, data + sample_off, &pn_len))
            return false;
        const bool key_phase = (buf[0] & 0x04) != 0;  // §17.3 short-header bit
        const std::uint64_t pn = decode_pn(buf, pn_offset, pn_len, space_for(level));
        const std::size_t payload_off = pn_offset + pn_len;
        if (payload_off >= pkt_len) return false;

        std::uint8_t plain[kMaxDatagramSize];
        std::size_t plain_len = 0;
        if (!aead_open_app(level, key_phase, pn, buf, payload_off,
                           data + payload_off, pkt_len - payload_off, plain,
                           &plain_len, hp)) {
            return false;  // auth failure: drop
        }
        spaces_[space_for(level)].on_packet_received(pn);
        acks_[space_idx(level)].record(pn);
        QTRACE("  opened level=%d pn=%llu plain_len=%zu", (int)level,
               (unsigned long long)pn, plain_len);
        return handle_frames(level, plain, plain_len);
    }

    // AEAD-open with key-update awareness (RFC 9001 §6). For non-application
    // levels this is a plain decrypt with the level keys. For 1-RTT, the
    // key-phase bit selects the generation: matching phase -> current keys;
    // flipped phase -> the NEXT generation (and, on success, we commit the
    // update); the previous generation covers reordered pre-update packets.
    bool aead_open_app(TlsLevel level, bool key_phase, std::uint64_t pn,
                       const std::uint8_t* hdr, std::size_t hdr_len,
                       const std::uint8_t* ct, std::size_t ct_len,
                       std::uint8_t* out, std::size_t* out_len,
                       PacketProtection* fallback) noexcept {
        assert(fallback != nullptr && "aead_open_app: null fallback");
        if (level != TlsLevel::kApplication || !ku_ready_) {
            return fallback->decrypt(pn, hdr, hdr_len, ct, ct_len, out, out_len);
        }
        const bool cur_phase = (key_gen_ & 1ULL) != 0;
        if (key_phase == cur_phase) {
            return app_read_cur_.decrypt(pn, hdr, hdr_len, ct, ct_len, out,
                                         out_len);
        }
        // Flipped phase: try the next generation. Success commits the update.
        if (app_read_next_.is_initialized() &&
            app_read_next_.decrypt(pn, hdr, hdr_len, ct, ct_len, out, out_len)) {
            commit_peer_key_update();
            return true;
        }
        // Otherwise it may be a reordered packet from the previous generation.
        if (key_gen_ > 0 && app_read_prev_.is_initialized())
            return app_read_prev_.decrypt(pn, hdr, hdr_len, ct, ct_len, out,
                                          out_len);
        return false;
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
            if (level == TlsLevel::kEarlyData && !allowed_in_zero_rtt(type)) {
                close(kProtocolViolation, false, "frame not allowed in 0-RTT");
                return false;
            }
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

    // RFC 9000 §12.4 table 3: frames a client may not put in 0-RTT.
    static bool allowed_in_zero_rtt(std::uint8_t type) noexcept {
        switch (type) {
            case 0x02: case 0x03:  // ACK
            case 0x06:             // CRYPTO
            case 0x07:             // NEW_TOKEN
            case 0x1b:             // PATH_RESPONSE
            case 0x1e:             // HANDSHAKE_DONE
                return false;
            default:
                return true;
        }
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
            return handle_max_streams(
                type == static_cast<std::uint8_t>(FrameType::kMaxStreamsUni),
                data + 1, len - 1, out_consumed);
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
        if (type == static_cast<std::uint8_t>(FrameType::kNewToken))
            return handle_new_token(data + 1, len - 1, out_consumed);
        if (type == static_cast<std::uint8_t>(FrameType::kRetireConnectionId))
            return skip_one_varint(data + 1, len - 1, out_consumed);
        if (type == static_cast<std::uint8_t>(FrameType::kNewConnectionId))
            return handle_new_connection_id(data + 1, len - 1, out_consumed);
        if (type == static_cast<std::uint8_t>(FrameType::kPathChallenge) ||
            type == static_cast<std::uint8_t>(FrameType::kPathResponse))
            return handle_path(data + 1, len - 1, out_consumed);
        if (type == static_cast<std::uint8_t>(FrameType::kDatagram) ||
            type == static_cast<std::uint8_t>(FrameType::kDatagramWithLen))
            return handle_datagram(type == 0x31, data + 1, len - 1, out_consumed);
        return handle_unknown_frame(level, data, len, out_consumed);
    }

    // RFC 9000 §12.4: a frame type we do not recognize. GREASE frame types
    // (0x1f*N+0x21, RFC 9000 §18.1 spirit for frames) are reserved no-ops the
    // peer may send to exercise extensibility; we tolerate any single-byte/
    // varint-typed unknown frame by consuming just its type and ignoring it
    // (bounded; never reads past the buffer). This keeps us robust to GREASE.
    bool handle_unknown_frame(TlsLevel /*level*/, const std::uint8_t* data,
                              std::size_t len,
                              std::size_t& out_consumed) noexcept {
        assert(len > 0 && "unknown frame: empty");
        std::uint64_t type = 0;
        const int c = varint_decode(data, len, type);
        if (c < 0) return false;  // truncated type varint -> drop the packet
        out_consumed = static_cast<std::size_t>(c);
        return true;  // ignore the GREASE/unknown frame, keep parsing
    }

    // RFC 9221 DATAGRAM frame (the type byte is already consumed). `with_len`
    // (0x31): a varint length precedes the payload. Without (0x30): the payload
    // runs to the end of the packet's frame area. Delivers to on_datagram_ (the
    // bytes are a view into the decrypted packet buffer — valid for the call).
    bool handle_datagram(bool with_len, const std::uint8_t* data, std::size_t len,
                         std::size_t& out_consumed) noexcept {
        assert((data != nullptr || len == 0) && "handle_datagram: null with len>0");
        const std::uint8_t* payload = data;
        std::size_t plen = len;            // 0x30: remainder of the packet
        std::size_t hdr = 0;
        if (with_len) {
            std::uint64_t dl = 0;
            const int c = varint_decode(data, len, dl);
            if (c <= 0) return false;
            hdr = static_cast<std::size_t>(c);
            if (dl > len - hdr) return false;   // length past buffer -> malformed
            payload = data + hdr;
            plen = static_cast<std::size_t>(dl);
        }
        // out_consumed counts the bytes AFTER the type byte (which the caller adds).
        out_consumed = 1 + hdr + plen;
        if (on_datagram_) on_datagram_(payload, plen);
        return true;
    }

    bool handle_new_token(const std::uint8_t* data, std::size_t len,
                          std::size_t& out_consumed) noexcept {
        std::uint64_t tlen = 0;
        const int c = varint_decode(data, len, tlen);
        if (c < 0) return false;
        if (static_cast<std::uint64_t>(c) + tlen > len) return false;
        out_consumed = 1 + static_cast<std::size_t>(c) +
                       static_cast<std::size_t>(tlen);
        return true;  // we do not cache NEW_TOKEN at this scope (RFC 9000 §8.1)
    }

    // NEW_CONNECTION_ID (RFC 9000 §19.15): seq | retire_prior | cid_len | cid |
    // 16-byte stateless reset token. We record only the peer's reset token so we
    // can recognize a future stateless reset (§10.3.1); the CID itself is not
    // adopted at this scope (single-path loopback).
    bool handle_new_connection_id(const std::uint8_t* data, std::size_t len,
                                  std::size_t& out_consumed) noexcept {
        std::uint64_t seq = 0, retire = 0;
        int c1 = varint_decode(data, len, seq);
        if (c1 < 0) return false;
        int c2 = varint_decode(data + c1, len - c1, retire);
        if (c2 < 0) return false;
        std::size_t pos = static_cast<std::size_t>(c1 + c2);
        if (pos >= len) return false;
        const std::uint8_t cid_len = data[pos++];
        if (cid_len > kMaxConnectionIdLen) return false;
        if (pos + cid_len + kStatelessResetTokenLen > len) return false;
        pos += cid_len;
        std::memcpy(peer_reset_token_, data + pos, kStatelessResetTokenLen);
        have_peer_reset_token_ = true;
        pos += kStatelessResetTokenLen;
        out_consumed = 1 + pos;
        return true;
    }

    // PATH_CHALLENGE / PATH_RESPONSE carry an 8-byte opaque payload (RFC 9000
    // §19.17/§19.18). We consume it (path validation proper is W5e).
    bool handle_path(const std::uint8_t* data, std::size_t len,
                     std::size_t& out_consumed) noexcept {
        assert((data != nullptr || len == 0) && "handle_path: null");
        (void)data;
        if (len < 8) return false;
        out_consumed = 1 + 8;
        return true;
    }

    bool handle_ack(TlsLevel level, const std::uint8_t* data, std::size_t len,
                    bool ecn, std::size_t& out_consumed) noexcept {
        AckFrame ack;
        std::size_t c = 0;
        if (ack.parse(data + 1, len - 1, ecn, c) != kFrameOk) return false;
        // RFC 9000 §19.3.1: a first range past the largest is malformed; §13.1:
        // acknowledging a packet never sent is a PROTOCOL_VIOLATION.
        if (ack.first_ack_range > ack.largest_acked) {
            close(kFrameEncodingError, false, "ack range underflow");
            return false;
        }
        if (ack.largest_acked >=
            spaces_[space_for(level)].peek_next_packet_number()) {
            close(kProtocolViolation, false, "ack of unsent packet");
            return false;
        }
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
        assert(tr.count() <= kMaxSentPackets && "tracker overflow");
        // Cost is bounded by the tracker (kMaxSentPackets), not by the width
        // of the peer-supplied range, which may span 2^62 packet numbers.
        for (std::size_t i = 0; i < tr.count(); ++i) {
            SentPacketInfo& s = tr.at(i);
            if (s.packet_number < lo || s.packet_number > hi) continue;
            if (s.acked || s.lost) continue;
            s.acked = true;
            if (s.in_flight) {
                s.in_flight = false;
                cc_.on_packet_acked(s.size, s.time_sent_us);
            }
            on_packet_acked_ranges(s);
            if (s.packet_number == largest) {
                time_largest_acked_sent_ = s.time_sent_us;
                if (s.ack_eliciting) {
                    rtt_sample_us_ = now - s.time_sent_us;
                    acked_largest = true;
                }
            }
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

    // Acknowledged STREAM bytes leave their stream's send ring.
    void on_packet_acked_ranges(const SentPacketInfo& s) noexcept {
        assert(s.range_count <= kMaxFrameRangesPerPacket && "range overflow");
        assert(s.acked && "ranges of an unacked packet");
        for (std::size_t i = 0; i < s.range_count; ++i) {
            const FrameRange& r = s.ranges[i];
            if (r.is_crypto) continue;
            Stream* st = find_stream(r.id);
            if (st != nullptr) st->on_acked(r.offset, r.length, r.fin);
        }
    }

    // Re-frame a lost packet's content by rewinding the relevant send frontier
    // so flush() re-emits the bytes under a FRESH packet number (never reused).
    void requeue_lost(const SentPacketInfo& s) noexcept {
        assert(s.range_count <= kMaxFrameRangesPerPacket && "range overflow");
        requeue_lost_control(s.ctrl_flags);
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

    // RFC 9000 §10.1: effective idle timeout (us) = min(local, peer) of the
    // advertised max_idle_timeout values (each in ms; 0 disables that side).
    std::uint64_t effective_idle_us() const noexcept {
        std::uint64_t local_ms = local_idle_ms_;
        std::uint64_t peer_ms = 0;
        if (tls_.have_peer_transport_params()) {
            const TransportParameters& tp = tls_.peer_transport_params();
            if (tp.max_idle_timeout_present) peer_ms = tp.max_idle_timeout;
        }
        std::uint64_t eff = 0;
        if (local_ms != 0 && peer_ms != 0)
            eff = (local_ms < peer_ms) ? local_ms : peer_ms;
        else
            eff = (local_ms != 0) ? local_ms : peer_ms;
        return eff * 1000ULL;
    }

    // RFC 9000 §10.2.3: a closing/draining endpoint holds for 3x PTO. Bounded.
    std::uint64_t closing_period_us() const noexcept {
        const std::uint64_t pto = rtt_.pto(max_ack_delay_us(), 0);
        return 3 * pto;
    }

    // RFC 9000 §10.2: build + send a CONNECTION_CLOSE in the highest level we
    // have keys for (1-RTT if Established, else Initial). Bounded scratch.
    void emit_connection_close() noexcept {
        assert(close_pending_ && "emit close: not pending");
        std::uint8_t payload[kMaxPayloadSize];
        ConnectionCloseFrame cc;
        cc.error_code = close_error_;
        cc.is_application = close_is_app_;
        cc.frame_type = 0;
        cc.reason_length = close_reason_len_;
        cc.reason_phrase = (close_reason_len_ > 0) ? close_reason_ : nullptr;
        const std::size_t n = cc.serialize(payload);
        assert(n <= sizeof(payload) && "close frame overran");
        close_pending_ = false;
        if (one_rtt_keys_ready()) {
            FrameRange ranges[kMaxFrameRangesPerPacket];
            std::size_t rc = 0;
            send_app_packet(payload, n, /*ack_eliciting=*/false, ranges, rc);
        } else if (write_protection(TlsLevel::kInitial)->is_initialized()) {
            FrameRange ranges[kMaxFrameRangesPerPacket];
            build_and_send_long(TlsLevel::kInitial, PacketForm::kLongInitial,
                                payload, n, false, ranges, 0);
        }
    }

    bool handle_crypto(TlsLevel level, const std::uint8_t* data, std::size_t len,
                       std::size_t& out_consumed) noexcept {
        CryptoFrame cf;
        std::size_t c = 0;
        if (cf.parse(data, len, c) != kFrameOk) return false;
        const std::size_t li = static_cast<std::size_t>(level);
        QTRACE("  CRYPTO level=%d off=%llu len=%llu", (int)level,
               (unsigned long long)cf.offset, (unsigned long long)cf.length);
        if (cf.offset + cf.length > kMaxCryptoBuffer) {
            close(kCryptoBufferExceeded, false, "crypto buffer exceeded");
            return false;
        }
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
        bool fatal = false;
        Stream* s = inbound_stream(sf.stream_id, /*recv_frame=*/true, fatal);
        if (fatal) return false;
        if (s == nullptr) return true;  // closed stream: a retransmit, ignore
        const std::uint64_t high_before = s->flow().recv_high;
        if (!s->receive(sf.offset, sf.data, static_cast<std::size_t>(sf.length),
                        sf.fin)) {
            close(kFlowControlError, false, "stream data outside window");
            return false;
        }
        conn_recv_total_ += s->flow().recv_high - high_before;  // new bytes only
        if (conn_recv_total_ > conn_recv_max_) {
            close(kFlowControlError, false, "connection data over MAX_DATA");
            return false;
        }
        deliver_stream(*s);
        return true;
    }

    // Hand all contiguous unread bytes to the app callback; bump windows. The
    // FIN is signalled on the delivery that carries the final byte (i.e. once
    // consuming `avail` would reach the FIN offset), or on a FIN-only frame.
    void deliver_stream(Stream& s) noexcept {
        const std::uint64_t id = s.id();
        // The ring may wrap: at most two contiguous spans.
        for (std::size_t span = 0; span < 2; ++span) {
            const std::size_t n = s.recv_contiguous();
            const std::uint8_t* p = s.recv_peek();
            s.recv_consume(n);
            const bool more = s.recv_available() > 0;
            const bool fin = !more && s.take_fin_notice();
            if ((n > 0 || fin) && on_stream_data_) on_stream_data_(id, p, n, fin);
            if (!more) break;
        }
        assert(s.in_use() && s.id() == id && "stream freed during delivery");
        if (s.needs_window_update(kConnFlowChunk / 2)) {
            s.grow_recv_window(kConnFlowChunk);
            s.mark_window_dirty();
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
        out_consumed = 1 + static_cast<std::size_t>(c1 + c2);
        bool fatal = false;
        Stream* s = inbound_stream(id, /*recv_frame=*/false, fatal);
        if (fatal) return false;
        if (s != nullptr && v > s->flow().send_max) s->flow().send_max = v;
        return true;
    }

    bool handle_max_streams(bool uni, const std::uint8_t* data, std::size_t len,
                            std::size_t& out_consumed) noexcept {
        std::uint64_t v = 0;
        const int c = varint_decode(data, len, v);
        if (c < 0) return false;
        out_consumed = 1 + static_cast<std::size_t>(c);
        if (v > (1ull << 60)) {  // §19.11: beyond 2^60 is a FRAME_ENCODING_ERROR
            close(kFrameEncodingError, false, "MAX_STREAMS over 2^60");
            return false;
        }
        std::uint64_t& lim = uni ? local_uni_credit_ : local_bidi_credit_;
        if (v > lim) lim = v;
        return true;
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
        bool fatal = false;
        Stream* s = inbound_stream(id, /*recv_frame=*/true, fatal);
        if (fatal) return false;
        if (s == nullptr) return true;
        if (fsize < s->flow().recv_high ||
            (s->fin_received() && fsize != s->flow().recv_high)) {
            close(kFinalSizeError, false, "reset final size");
            return false;
        }
        s->on_peer_reset();
        (void)err;
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
        bool fatal = false;
        Stream* s = inbound_stream(id, /*recv_frame=*/false, fatal);
        if (fatal) return false;
        if (s == nullptr || s->send_state() == SendState::kResetSent) return true;
        // §3.5: answer STOP_SENDING with RESET_STREAM at the current size.
        queue_reset(id, err, s->queued_end());
        s->abandon_send();
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
        QTRACE("  CONNECTION_CLOSE app=%d error=0x%llx frame_type=0x%llx reason='%.*s'",
               (int)is_app, (unsigned long long)cc.error_code,
               (unsigned long long)cc.frame_type,
               (int)cc.reason_length,
               cc.reason_phrase ? cc.reason_phrase : "");
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
        // Now that we know the client's original DCID (RFC 9000 §7.3), re-publish
        // our transport parameters so the EncryptedExtensions carry both
        // initial_source_connection_id (local_cid_) and
        // original_destination_connection_id (initial_dcid_). This MUST happen
        // before TLS advances (it runs after this returns), so the values land in
        // the server's first handshake flight. Without ODCID/ISCID a conformant
        // client (aioquic) aborts with TRANSPORT_PARAMETER_ERROR.
        assert(initial_dcid_.length > 0 && "server odcid empty");
        if (!tls_.set_transport_params(make_local_params())) return false;
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
        // #45 — COALESCE the first flight: Initial(ServerHello) +
        // Handshake(Cert/CertVerify/Finished) (+ a trailing 1-RTT packet) into ONE
        // UDP datagram (RFC 9000 §12.2). The accumulator (`coalescing_`) collects
        // each sealed packet; seal_and_send appends instead of sending, and
        // flush_datagram() emits the datagram. Without coalescing Chrome stays at
        // Initial (it expects the ServerHello+Cert coalesced); aioquic tolerates
        // both. Long-header packets (Initial/Handshake) coalesce freely; a
        // short-header (1-RTT) packet has no length field so it MUST end the
        // datagram (seal_and_send flushes after a short packet).
        //
        // SCOPED to the handshake (pre-Established): the first flight is the only
        // place coalescing matters — the server's Initial(ServerHello)+Handshake
        // (Cert/Fin) must share one datagram so Chrome advances past Initial. Once
        // Established the traffic is all 1-RTT short-header packets, which cannot
        // coalesce with each other anyway, so we keep the EXACT prior per-packet
        // send path there.
        coalescing_ = (state_ != ConnState::kEstablished);
        dgram_len_ = 0;
        dgram_has_initial_ = false;
        flush_level(TlsLevel::kInitial, PacketForm::kLongInitial);
        flush_level(TlsLevel::kHandshake, PacketForm::kLongHandshake);
        flush_app_level();
        if (coalescing_) flush_datagram();   // emit whatever remains coalesced
        coalescing_ = false;
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

        // Refill stream rings from held bodies; free finished streams (which
        // may raise MAX_STREAMS credit for the control packet below).
        sweep_streams();

        // Packet 0: control frames + ACK (always sendable; ACK-only is not in
        // flight, so cwnd does not gate it).
        flush_app_control();
        flush_app_crypto();

        // STREAM data packets, bounded by coalesce count, cwnd and flow control.
        // A pending PTO probe may send up to two packets ignoring cwnd (§6.2.4).
        for (std::size_t i = 0; i < kMaxCoalescedPackets; ++i) {
            const bool probe = pto_probes_ > 0;
            if (!probe && !cc_.can_send(NewRenoCongestion::kMaxDatagram)) break;
            if (!tracker_has_room(PacketNumberSpace::kApplication)) break;
            if (!amp_allows(kMaxDatagramSize)) break;  // §8.1 before validation
            if (!flush_app_stream_packet()) break;  // nothing more to send
            if (probe && pto_probes_ > 0) --pto_probes_;
        }
    }

    // 1-RTT CRYPTO (post-handshake TLS: NewSessionTicket, RFC 9001 §4.1.3).
    void flush_app_crypto() noexcept {
        pull_pending_crypto(TlsLevel::kApplication);
        for (std::size_t i = 0; i < kMaxCoalescedPackets; ++i) {
            if (!has_unsent_crypto(TlsLevel::kApplication)) break;
            if (!tracker_has_room(PacketNumberSpace::kApplication)) break;
            std::uint8_t payload[kMaxPayloadSize];
            FrameRange ranges[kMaxFrameRangesPerPacket];
            bool has_range = false;
            const std::size_t plen = frame_crypto(TlsLevel::kApplication, payload,
                                                  sizeof(payload), &ranges[0],
                                                  &has_range);
            if (plen == 0) break;
            send_app_packet(payload, plen, /*ack_eliciting=*/true, ranges,
                            has_range ? 1 : 0);
        }
    }

    // The oldest tracked packet may be overwritten only once it is resolved;
    // otherwise sending stalls until ACKs arrive (bounds data in flight).
    bool tracker_has_room(PacketNumberSpace space) noexcept {
        SentPacketTracker& tr = sent_[static_cast<std::size_t>(space)];
        if (tr.count() < kMaxSentPackets) return true;
        const SentPacketInfo& old = tr.at(0);
        assert(tr.count() == kMaxSentPackets && "tracker count overflow");
        return old.acked || old.lost || !old.ack_eliciting;
    }

    // One packet of control frames (HANDSHAKE_DONE, window updates) + an ACK.
    void flush_app_control() noexcept {
        std::uint8_t payload[kMaxPayloadSize];
        std::size_t plen = 0;
        bool ack_eliciting = false;
        std::uint8_t flags = 0;
        if (is_server_ && tls_.is_complete() && !handshake_done_sent_) {
            payload[plen++] = static_cast<std::uint8_t>(FrameType::kHandshakeDone);
            handshake_done_sent_ = true;
            ack_eliciting = true;
            flags |= kCtrlHandshakeDone;
        }
        const std::size_t before_flow = plen;
        plen += frame_flow_updates(payload + plen, sizeof(payload) - plen,
                                   &ack_eliciting);
        if (plen > before_flow) flags |= kCtrlFlow;
        const std::size_t before_streams = plen;
        plen += frame_stream_credit(payload + plen, sizeof(payload) - plen);
        plen += frame_resets(payload + plen, sizeof(payload) - plen);
        if (plen > before_streams) { flags |= kCtrlStreams; ack_eliciting = true; }
        plen += maybe_append_ack(PacketNumberSpace::kApplication, payload + plen,
                                 sizeof(payload) - plen);
        if (plen == 0) return;
        QTRACE("flush_app_control send plen=%zu hsdone_now=%d", plen,
               (int)(handshake_done_sent_ && ack_eliciting));
        FrameRange ranges[kMaxFrameRangesPerPacket];
        std::size_t rc = 0;
        next_ctrl_flags_ = flags;
        send_app_packet(payload, plen, ack_eliciting, ranges, rc);
        next_ctrl_flags_ = 0;
    }

    // MAX_STREAMS (§19.11) for each direction whose credit grew.
    std::size_t frame_stream_credit(std::uint8_t* out, std::size_t cap) noexcept {
        assert(out != nullptr && "frame_stream_credit: null out");
        std::size_t pos = 0;
        PeerStreamBook* books[2] = {&peer_bidi_, &peer_uni_};
        const FrameType types[2] = {FrameType::kMaxStreamsBidi, FrameType::kMaxStreamsUni};
        for (std::size_t i = 0; i < 2; ++i) {
            if (books[i]->limit <= books[i]->sent_limit || cap - pos < 9) continue;
            pos += serialize_single_varint(types[i], books[i]->limit, out + pos);
            books[i]->sent_limit = books[i]->limit;
        }
        assert(pos <= cap && "stream credit overran");
        return pos;
    }

    // Queued RESET_STREAM frames (answers to STOP_SENDING).
    std::size_t frame_resets(std::uint8_t* out, std::size_t cap) noexcept {
        assert(out != nullptr && "frame_resets: null out");
        assert(reset_count_ <= kMaxStreams && "reset queue overflow");
        std::size_t pos = 0;
        std::size_t i = 0;
        for (; i < reset_count_ && cap - pos >= 25; ++i)
            pos += serialize_reset_stream(resets_[i].id, resets_[i].err,
                                          resets_[i].final_size, out + pos);
        for (std::size_t j = i; j < reset_count_; ++j) resets_[j - i] = resets_[j];
        reset_count_ -= i;
        return pos;
    }

    void queue_reset(std::uint64_t id, std::uint64_t err, std::uint64_t final_size) noexcept {
        assert(id <= kVarIntMax && "reset id out of range");
        if (reset_count_ >= kMaxStreams) return;  // one per stream slot at most
        resets_[reset_count_++] = {id, err, final_size};
        assert(reset_count_ <= kMaxStreams && "reset queue overflow");
    }

    // A lost packet's control frames are re-issued from current state.
    void requeue_lost_control(std::uint8_t flags) noexcept {
        if (flags & kCtrlHandshakeDone) handshake_done_sent_ = false;
        if (flags & kCtrlFlow) {
            conn_window_dirty_ = true;
            stream_window_dirty_ = true;
            for (std::size_t i = 0; streams_ != nullptr && i < kMaxStreams; ++i)
                if (streams_[i].in_use()) streams_[i].mark_window_dirty();
        }
        if (flags & kCtrlStreams) {
            peer_bidi_.sent_limit = 0;
            peer_uni_.sent_limit = 0;
        }
    }

    // Build one 1-RTT packet of STREAM data across ready streams. Returns false
    // when there is nothing left to send.
    bool flush_app_stream_packet() noexcept {
        std::uint8_t payload[kMaxPayloadSize];
        std::size_t plen = 0;
        FrameRange ranges[kMaxFrameRangesPerPacket];
        std::size_t rc = 0;
        if (streams_ == nullptr) return false;
        rr_next_ = (rr_next_ + 1) % kMaxStreams;  // rotate so no stream starves
        for (std::size_t k = 0; k < kMaxStreams && rc < kMaxFrameRangesPerPacket;
             ++k) {
            Stream& s = streams_[(rr_next_ + k) % kMaxStreams];
            if (!s.in_use() || !s.has_send_work()) continue;
            const std::size_t before = plen;
            plen += frame_one_stream(s, payload + plen, sizeof(payload) - plen,
                                     &ranges[rc]);
            if (plen > before) ++rc;
        }
        if (plen == 0) return false;
        QTRACE("flush_app_stream send plen=%zu streams=%zu", plen, rc);
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
        // Apply per-stream + connection flow-control caps; a clamped chunk no
        // longer reaches the end, so it must not carry the FIN.
        len = clamp_send_window(s, off, len);
        if (fin && off + len != s.queued_end()) fin = false;
        if (len == 0 && !fin) return 0;
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
        if (len > stream_room) len = static_cast<std::size_t>(stream_room);
        // Retransmitted bytes (below the high-water mark) were already counted
        // against MAX_DATA; only the new tail needs connection credit.
        const std::uint64_t hw = s.flow().send_off;
        const std::size_t retx =
            (off < hw) ? static_cast<std::size_t>((hw - off < len) ? hw - off : len) : 0;
        std::size_t fresh = len - retx;
        if (fresh > conn_room) fresh = static_cast<std::size_t>(conn_room);
        if (stream_room == 0 || (len == 0 && s.unsent() > 0)) stream_blocked_ = true;
        if (conn_room == 0 && retx < len) conn_blocked_ = true;
        return retx + fresh;
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
        // MAX_STREAM_DATA only for streams that receive (a send-only stream
        // would be a STREAM_STATE_ERROR at the peer, §19.10).
        bool left = false;
        for (std::size_t si = 0; stream_window_dirty_ && streams_ != nullptr &&
                                 si < kMaxStreams; ++si) {
            Stream& s = streams_[si];
            if (!s.in_use() || !s.window_dirty()) continue;
            if (!has_recv_side(s.id()) || s.recv_done()) { s.clear_window_dirty(); continue; }
            if (cap - pos < 18) { left = true; break; }
            pos += serialize_stream_pair(FrameType::kMaxStreamData, s.id(),
                                         s.flow().recv_max, out + pos);
            s.clear_window_dirty();
            *ack_eliciting = true;
        }
        stream_window_dirty_ = left;
        if (conn_blocked_ && cap - pos >= 9) {
            pos += serialize_single_varint(FrameType::kDataBlocked,
                                           conn_send_max_, out + pos);
            conn_blocked_ = false;
            *ack_eliciting = true;
        }
        if (stream_blocked_ && cap - pos >= 18) {
            for (std::size_t si = 0; streams_ != nullptr && si < kMaxStreams &&
                                     cap - pos >= 18; ++si) {
                Stream& s = streams_[si];
                if (!s.in_use() || s.flow().send_window() != 0) continue;
                if (!has_send_side(s.id()) || !s.has_send_work()) continue;
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
                          pp, level == TlsLevel::kInitial, /*short_header=*/false);
        record_sent(space_for(level), pn, wire, ack_eliciting, ranges,
                    range_count);
    }

    // Build a 1-RTT short-header packet, send it, and record it.
    bool send_app_packet(const std::uint8_t* payload, std::size_t payload_len,
                         bool ack_eliciting, const FrameRange* ranges,
                         std::size_t range_count) noexcept {
        assert(payload_len <= kMaxPayloadSize && "app: oversize payload");
        assert(range_count <= kMaxFrameRangesPerPacket && "range overflow");
        PacketProtection* hp = write_protection(TlsLevel::kApplication);
        if (hp == nullptr || !hp->is_initialized()) return false;
        // AEAD uses the current key-update generation (HP stays original).
        PacketProtection* aead = ku_ready_ ? &app_write_cur_ : hp;
        const std::uint64_t pn =
            spaces_[PacketNumberSpace::kApplication].next_packet_number();
        const std::uint8_t pn_len = 4;

        std::uint8_t dgram[kMaxDatagramSize];
        std::size_t pos = 0;
        std::uint8_t first = static_cast<std::uint8_t>(0x40 | (pn_len - 1));
        if (ku_ready_ && (key_gen_ & 1ULL)) first |= 0x04;  // key-phase bit
        dgram[pos++] = first;
        std::memcpy(dgram + pos, peer_cid_.data, peer_cid_.length);
        pos += peer_cid_.length;
        const std::size_t pn_offset = pos;
        write_pn(dgram + pn_offset, pn, pn_len);
        const std::size_t wire = seal_and_send(dgram, pn_offset, pn_len, payload,
                                               payload_len, pn, aead, hp,
                                               /*pad_initial=*/false,
                                               /*short_header=*/true);
        record_sent(PacketNumberSpace::kApplication, pn, wire, ack_eliciting,
                    ranges, range_count);
        return true;
    }

    // Record a sent packet into its space tracker + cwnd in-flight accounting.
    void record_sent(PacketNumberSpace space, std::uint64_t pn,
                     std::size_t wire, bool ack_eliciting,
                     const FrameRange* ranges, std::size_t range_count) noexcept {
        assert(range_count <= kMaxFrameRangesPerPacket && "range overflow");
        if (wire == 0) {
            // Not sent (amplification budget or seal failure): the framed
            // bytes must go out again.
            SentPacketInfo unsent{};
            unsent.range_count = range_count;
            for (std::size_t i = 0; i < range_count; ++i) unsent.ranges[i] = ranges[i];
            requeue_lost(unsent);
            return;
        }
        SentPacketTracker& tr = sent_[static_cast<std::size_t>(space)];
        if (tr.count() == kMaxSentPackets) {
            // Overwriting an unresolved packet: treat it as lost so its data
            // is re-sent instead of silently vanishing.
            SentPacketInfo& old = tr.at(0);
            if (!old.acked && !old.lost && old.ack_eliciting) {
                requeue_lost(old);
                old.lost = true;
            }
        }
        std::uint64_t evicted = 0;
        SentPacketInfo& s = tr.record(pn, now_us(), wire, ack_eliciting, &evicted);
        s.ctrl_flags = next_ctrl_flags_;
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
                              PacketProtection* aead, PacketProtection* hp,
                              bool pad_initial, bool short_header) noexcept {
        assert(aead != nullptr && hp != nullptr && "seal_and_send: null pp");
        // RFC 9000 §8.1: respect the 3x anti-amplification budget. A padded
        // Initial may exceed budget but is permitted (the client's Initial is at
        // least 1200B, giving 3600B headroom for the server's first flight).
        // While coalescing (#45) the amp gate + Initial padding move to
        // flush_datagram() so they apply to the WHOLE datagram, not per packet.
        if (!coalescing_) {
            const std::size_t projected =
                (pad_initial && payload_len + pn_offset + pn_len + kAeadTagLength <
                 kInitialMinDatagram)
                    ? kInitialMinDatagram
                    : pn_offset + pn_len + payload_len + kAeadTagLength;
            if (!amp_allows(projected)) return 0;
        }
        const std::size_t aad_len = pn_offset + pn_len;
        std::uint8_t sealed[kMaxDatagramSize];
        std::size_t sealed_len = 0;
        if (!aead->encrypt(pn, dgram, aad_len, payload, payload_len, sealed,
                           &sealed_len)) {
            return 0;
        }
        std::memcpy(dgram + aad_len, sealed, sealed_len);
        std::size_t total = aad_len + sealed_len;
        const std::size_t sample_off = PacketProtection::sample_offset(pn_offset);
        assert(sample_off + kHpSampleLength <= total && "HP sample past packet");
        hp->protect_header(dgram, pn_offset, pn_len, dgram + sample_off);

        if (coalescing_) {
            coalesce_append(dgram, total, pad_initial, short_header);
            return total;  // per-packet on-wire size (loss/cwnd accounting)
        }

        if (pad_initial && total < kInitialMinDatagram) {
            std::memset(dgram + total, 0, kInitialMinDatagram - total);
            total = kInitialMinDatagram;
        }
        assert(total <= kMaxDatagramSize && "datagram overflow");
        send_raw(dgram, total);
        return total;
    }

    // #45 — append one sealed packet to the coalesced-datagram accumulator. Long
    // packets (Initial/Handshake carry a Length field) coalesce freely; a
    // short-header (1-RTT) packet has NO length so it MUST be the last packet in
    // the datagram (RFC 9000 §12.2) — we flush right after appending one. If the
    // packet would overflow the path MTU, flush the current datagram first.
    void coalesce_append(const std::uint8_t* pkt, std::size_t len,
                         bool is_initial, bool short_header) noexcept {
        assert(pkt != nullptr && "coalesce_append: null");
        assert(len > 0 && len <= kMaxDatagramSize && "coalesce_append: bad len");
        if (dgram_len_ + len > kMaxDatagramSize) flush_datagram();
        assert(dgram_len_ + len <= kMaxDatagramSize && "coalesce: still overflow");
        std::memcpy(dgram_buf_ + dgram_len_, pkt, len);
        dgram_len_ += len;
        if (is_initial) dgram_has_initial_ = true;
        if (short_header) flush_datagram();  // 1-RTT must end the datagram
    }

    // #45 — emit the accumulated coalesced datagram (padding to >=1200B when it
    // contains an Initial, RFC 9000 §14.1; one anti-amp check for the whole
    // datagram). Resets the accumulator. No-op when empty.
    void flush_datagram() noexcept {
        if (dgram_len_ == 0) return;
        std::size_t out_len = dgram_len_;
        const bool pad = dgram_has_initial_ && out_len < kInitialMinDatagram;
        const std::size_t projected = pad ? kInitialMinDatagram : out_len;
        if (!amp_allows(projected)) {            // whole datagram over 3x budget
            QTRACE("flush_datagram AMP-BLOCKED projected=%zu", projected);
            dgram_len_ = 0; dgram_has_initial_ = false; return;
        }
        QTRACE("flush_datagram emit len=%zu (initial=%d pad=%d)", out_len,
               (int)dgram_has_initial_, (int)pad);
        if (pad) {
            assert(kInitialMinDatagram <= kMaxDatagramSize && "pad past MTU");
            std::memset(dgram_buf_ + out_len, 0, kInitialMinDatagram - out_len);
            out_len = kInitialMinDatagram;
        }
        assert(out_len <= kMaxDatagramSize && "coalesced datagram overflow");
        send_raw(dgram_buf_, out_len);
        dgram_len_ = 0;
        dgram_has_initial_ = false;
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
        // The client offers offered_version_ (defaults to v1; a bogus value
        // provokes a Version Negotiation, RFC 9000 §6). The server always
        // answers under v1 (negotiated_version_).
        const std::uint32_t ver = is_server_ ? negotiated_version_ : offered_version_;
        out[pos++] = (ver >> 24) & 0xFF;
        out[pos++] = (ver >> 16) & 0xFF;
        out[pos++] = (ver >> 8) & 0xFF;
        out[pos++] = ver & 0xFF;
        out[pos++] = peer_cid_.length;
        std::memcpy(out + pos, peer_cid_.data, peer_cid_.length);
        pos += peer_cid_.length;
        out[pos++] = local_cid_.length;
        std::memcpy(out + pos, local_cid_.data, local_cid_.length);
        pos += local_cid_.length;
        if (level == TlsLevel::kInitial) {
            // Initial token (RFC 9000 §17.2.2): empty unless the client holds a
            // Retry token, which it MUST echo on the retried Initial (§8.1).
            if (!is_server_ && retry_token_len_ > 0) {
                pos += varint_encode(retry_token_len_, out + pos);
                std::memcpy(out + pos, retry_token_, retry_token_len_);
                pos += retry_token_len_;
            } else {
                out[pos++] = 0x00;  // token length 0
            }
        }
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

    // TLS picked the ALPN (inside ClientHello processing, before our
    // EncryptedExtensions): apply its stream credit to the transport params.
    void on_alpn_selected(const std::uint8_t* p, std::size_t n) noexcept {
        assert(is_server_ && "alpn hook on a client");
        assert(p != nullptr || n == 0);
        if (alpn_raise_len_ == 0 || n != alpn_raise_len_ ||
            std::memcmp(p, alpn_raise_, n) != 0)
            return;
        peer_bidi_concurrency_ = alpn_bidi_streams_;
        peer_bidi_.update_limit(peer_bidi_concurrency_);
        peer_bidi_.sent_limit = peer_bidi_.limit;  // carried by the new params
        (void)tls_.set_transport_params(make_local_params());
    }

    // ===================================================================
    // Stream pool: kMaxStreams slots, reused once both directions finish.
    // ===================================================================
    void ensure_stream_pool() noexcept {
        if (streams_ != nullptr) return;
        // Pre-allocate the bounded pool from the arena (placement-new so each
        // Stream's default member initializers run). No per-stream malloc.
        void* raw = stream_arena_.allocate(kMaxStreams * sizeof(Stream),
                                           alignof(Stream));
        assert(raw != nullptr && "stream pool alloc failed");
        streams_ = static_cast<Stream*>(raw);
        for (std::size_t i = 0; i < kMaxStreams; ++i) new (&streams_[i]) Stream();
        assert(streams_[0].in_use() == false && "fresh pool slot live");
    }

    bool can_open(bool uni) noexcept {
        std::uint64_t credit = uni ? local_uni_credit_ : local_bidi_credit_;
        if (tls_.have_peer_transport_params()) {
            const TransportParameters& tp = tls_.peer_transport_params();
            const std::uint64_t init = uni ? tp.initial_max_streams_uni
                                           : tp.initial_max_streams_bidi;
            if (init > credit) credit = init;
        }
        const std::uint64_t next = uni ? next_uni_seq_ : next_bidi_seq_;
        if (next >= credit) return false;
        return live_streams() < kMaxStreams;
    }

    // Allocate a new locally-initiated stream and return its id.
    std::uint64_t open_stream(bool uni) noexcept {
        ensure_stream_pool();
        std::uint64_t& seq = uni ? next_uni_seq_ : next_bidi_seq_;
        const std::uint64_t id = make_stream_id(seq++, is_server_, uni);
        Stream* s = alloc_stream(id);
        assert(s != nullptr && "stream pool exhausted");
        (void)s;
        return id;
    }

    Stream* find_stream(std::uint64_t id) noexcept {
        if (streams_ == nullptr) return nullptr;
        for (std::size_t i = 0; i < kMaxStreams; ++i) {
            Stream& s = streams_[i];
            if (s.in_use() && s.id() == id) return &s;
        }
        return nullptr;
    }

    bool is_local_stream(std::uint64_t id) const noexcept {
        return stream_is_server_initiated(id) == is_server_;
    }
    bool has_send_side(std::uint64_t id) const noexcept {
        return stream_is_bidi(id) || is_local_stream(id);
    }
    bool has_recv_side(std::uint64_t id) const noexcept {
        return stream_is_bidi(id) || !is_local_stream(id);
    }

    // A stream the application may write: live and with a send side.
    Stream* writable_stream(std::uint64_t id) noexcept {
        assert(id <= kVarIntMax && "writable_stream: id out of range");
        if (!has_send_side(id)) return nullptr;
        Stream* s = find_stream(id);
        if (s == nullptr || s->send_state() == SendState::kResetSent) return nullptr;
        return s;
    }

    // Resolve the stream a peer frame names (RFC 9000 §2.1, §3, §4.6). Opens a
    // new peer stream within MAX_STREAMS credit; returns nullptr for a closed
    // stream (late retransmit). A frame the stream's direction forbids, or one
    // past our credit, closes the connection and sets `fatal`.
    Stream* inbound_stream(std::uint64_t id, bool recv_frame, bool& fatal) noexcept {
        assert(id <= kVarIntMax && "inbound_stream: id out of range");
        fatal = false;
        const bool uni = stream_is_uni(id);
        const bool local = is_local_stream(id);
        if ((recv_frame && !has_recv_side(id)) || (!recv_frame && !has_send_side(id))) {
            close(kStreamStateError, false, "frame for the wrong stream direction");
            fatal = true;
            return nullptr;
        }
        if (Stream* s = find_stream(id)) return s;
        const std::uint64_t seq = id >> 2;
        if (local) {
            const std::uint64_t next = uni ? next_uni_seq_ : next_bidi_seq_;
            if (seq < next) return nullptr;  // ours, already finished
            close(kStreamStateError, false, "frame for an unopened local stream");
            fatal = true;
            return nullptr;
        }
        PeerStreamBook& book = uni ? peer_uni_ : peer_bidi_;
        if (seq >= book.limit) {
            close(kStreamLimitError, false, "stream id over MAX_STREAMS");
            fatal = true;
            return nullptr;
        }
        if (book.is_closed(seq)) return nullptr;
        Stream* s = alloc_stream(id);
        if (s == nullptr) {
            close(kInternalError, false, "stream pool exhausted");
            fatal = true;
        }
        return s;
    }

    Stream* alloc_stream(std::uint64_t id) noexcept {
        ensure_stream_pool();
        assert(find_stream(id) == nullptr && "alloc of a live stream id");
        for (std::size_t i = 0; i < kMaxStreams; ++i) {
            Stream& s = streams_[i];
            if (s.in_use()) continue;
            if (!s.has_buffers()) {
                // First use of this slot: its rings stay with it across reuse.
                void* rings = stream_arena_.allocate(2 * kStreamBufferSize, 64);
                if (rings == nullptr) return nullptr;
                auto* b = static_cast<std::uint8_t*>(rings);
                s.attach_buffers(b, b + kStreamBufferSize);
            }
            s.open(id, peer_initial_stream_window(id), kStreamRecvWindow);
            return &s;
        }
        return nullptr;
    }

    // Held bytes across all streams (bounded by kPendingSendBytesMax).
    std::uint64_t pending_total() const noexcept {
        std::uint64_t n = 0;
        for (std::size_t i = 0; streams_ != nullptr && i < kMaxStreams; ++i)
            if (streams_[i].in_use()) n += streams_[i].pending_bytes();
        return n;
    }

    // Move held bytes into freed ring space; release streams whose send and
    // receive sides are both finished, crediting the peer (MAX_STREAMS).
    void sweep_streams() noexcept {
        if (streams_ == nullptr) return;
        for (std::size_t i = 0; i < kMaxStreams; ++i) {
            Stream& s = streams_[i];
            if (!s.in_use()) continue;
            s.refill();
            const std::uint64_t id = s.id();
            if (has_send_side(id) && !s.send_done()) continue;
            if (has_recv_side(id) && !s.recv_done()) continue;
            s.release();
            if (is_local_stream(id)) continue;
            PeerStreamBook& book = stream_is_uni(id) ? peer_uni_ : peer_bidi_;
            book.mark_closed(id >> 2);
            book.update_limit(stream_is_uni(id) ? kPeerUniStreamsMax
                                                : peer_bidi_concurrency_);
        }
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

    // Client: tear down handshake-in-progress state and re-run start() under a
    // (possibly new) version/DCID/token. Used by VN (§6.2) + Retry (§17.2.5).
    // Bounded: rebuilds the TLS driver + Initial keys once; no recursion.
    void restart_handshake() noexcept {
        assert(!is_server_ && "restart_handshake: client only");
        assert(send_ && "restart_handshake: no send fn");
        // Rebuild the TLS driver (placement-new over the destructed member; no
        // heap churn beyond what one SSL object holds).
        tls_.~QuicTls();
        new (&tls_) QuicTls();
        const bool ok = tls_.init_client();
        assert(ok && "restart: tls init failed");
        (void)ok;
        static const std::uint8_t kAlpn[] = {2, 'h', '3'};
        tls_.set_alpn(kAlpn, sizeof(kAlpn));
        tls_.set_transport_params(make_local_params());
        // Reset packet-number spaces, ACK state, sent trackers, crypto buffers.
        spaces_ = PacketNumberSpaceManager{};
        for (std::size_t i = 0; i < kPacketNumberSpaceCount; ++i) {
            acks_[i] = AckRangeTracker{};
            ack_pending_[i] = false;
            sent_[i] = SentPacketTracker{};
        }
        for (std::size_t i = 0; i < kNumTlsLevels; ++i) {
            crypto_rx_[i] = CryptoReassembly{};
            crypto_tx_[i].clear();
            crypto_sent_off_[i] = 0;
            crypto_acked_[i] = false;
        }
        // For a Retry we keep the server-chosen DCID; for VN we keep our random
        // DCID. Either way, re-derive Initial keys for the current DCID.
        const bool keyed = derive_initial_keys(initial_dcid_);
        assert(keyed && "restart: initial key derive failed");
        (void)keyed;
        state_ = ConnState::kHandshaking;
        tls_.advance();  // fresh ClientHello
        flush();
    }

    // Send a raw datagram (already a full packet) tracking the amplification
    // budget + idle activity, bypassing the per-level flush machinery.
    void send_raw(const std::uint8_t* data, std::size_t len) noexcept {
        assert((data != nullptr || len == 0) && "send_raw: null");
        amp_.on_sent(len);
        send_(data, len);
    }

    // RFC 9000 §8.1: the server MUST NOT send > 3x received bytes before the
    // peer's address is validated. Returns true if `len` is within budget. The
    // client and a validated server are always allowed.
    bool amp_allows(std::size_t len) const noexcept {
        if (!is_server_ || address_validated_) return true;
        return amp_.can_send(len);
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
            seed_key_update_keys();   // RFC 9001 §6: capture gen-0 1-RTT secrets
            amp_.validate();          // handshake completion validates the path
            address_validated_ = true;
        }
        adopt_peer_flow_limits();
    }

    // RFC 9001 §6.1: capture the gen-0 1-RTT secrets yielded by TLS so we can
    // derive next-generation AEAD keys for key updates. Idempotent.
    void seed_key_update_keys() noexcept {
        assert(state_ == ConnState::kEstablished && "seed: not established");
        if (ku_ready_) return;
        std::size_t rl = 0, wl = 0;
        const std::uint8_t* rs = tls_.read_secret(TlsLevel::kApplication, &rl);
        const std::uint8_t* ws = tls_.write_secret(TlsLevel::kApplication, &wl);
        ku_algo_ = tls_.aead_algorithm();
        // The 1-RTT secret length follows the negotiated suite's hash, not a
        // hardcoded 32B (RFC 9001 §5.1) — AES-256-GCM yields 48B SHA-384 secrets.
        const std::size_t want = hash_length(hash_for_aead(ku_algo_));
        if (rs == nullptr || ws == nullptr || rl != want || wl != want) return;
        assert(want <= kMaxSecretLength && "1-RTT secret too long");
        ku_secret_len_ = want;
        std::memcpy(app_read_secret_, rs, want);
        std::memcpy(app_write_secret_, ws, want);
        const bool ok = install_app_protection(app_read_cur_, app_read_secret_,
                                               app_write_cur_, app_write_secret_);
        if (!ok) return;
        // Pre-derive the next generation so an inbound flip opens immediately.
        derive_next_app_protection();
        key_gen_ = 0;
        ku_ready_ = true;
    }

    // Derive + initialize a read/write PacketProtection pair from 1-RTT secrets.
    bool install_app_protection(PacketProtection& read_pp,
                                const std::uint8_t* read_secret,
                                PacketProtection& write_pp,
                                const std::uint8_t* write_secret) noexcept {
        assert(read_secret != nullptr && write_secret != nullptr && "iap: null");
        assert(ku_secret_len_ == hash_length(hash_for_aead(ku_algo_)) &&
               "iap: secret length must match suite hash");
        PacketProtectionKeys rk, wk;
        if (!derive_packet_keys(read_secret, ku_secret_len_, ku_algo_, rk))
            return false;
        if (!derive_packet_keys(write_secret, ku_secret_len_, ku_algo_, wk))
            return false;
        read_pp = PacketProtection{};
        write_pp = PacketProtection{};
        return read_pp.initialize(rk) && write_pp.initialize(wk);
    }

    // RFC 9001 §6.1: compute the NEXT-generation secrets + read protection so a
    // peer-initiated update opens on arrival. The write side is installed only
    // when WE commit the update (so we never seal under keys the peer lacks).
    void derive_next_app_protection() noexcept {
        assert(ku_secret_len_ == hash_length(hash_for_aead(ku_algo_)) &&
               "dnap: secret length must match suite hash");
        const HashAlgorithm h = hash_for_aead(ku_algo_);
        if (!next_generation_secret(app_read_secret_, next_read_secret_,
                                    ku_secret_len_, h))
            return;
        if (!next_generation_secret(app_write_secret_, next_write_secret_,
                                    ku_secret_len_, h))
            return;
        PacketProtectionKeys rk;
        if (!derive_packet_keys(next_read_secret_, ku_secret_len_, ku_algo_, rk))
            return;
        app_read_next_ = PacketProtection{};
        app_read_next_.initialize(rk);
    }

    // Advance one key-update generation (RFC 9001 §6.1). `peer_initiated` is true
    // when we are responding to a flipped key-phase bit. Returns true on success.
    bool rotate_keys(bool peer_initiated) noexcept {
        if (!ku_ready_) return false;
        // Shift current -> previous (reorder window for the OLD generation).
        app_read_prev_ = std::move(app_read_cur_);
        // Promote the pre-derived next read keys to current.
        app_read_cur_ = std::move(app_read_next_);
        // Roll secrets forward and install the new write keys.
        assert(ku_secret_len_ <= kMaxSecretLength && "rotate: secret too long");
        std::memcpy(app_read_secret_, next_read_secret_, ku_secret_len_);
        std::memcpy(app_write_secret_, next_write_secret_, ku_secret_len_);
        PacketProtectionKeys wk;
        if (!derive_packet_keys(app_write_secret_, ku_secret_len_, ku_algo_, wk))
            return false;
        app_write_cur_ = PacketProtection{};
        if (!app_write_cur_.initialize(wk)) return false;
        ++key_gen_;
        derive_next_app_protection();  // pre-derive the following generation
        (void)peer_initiated;
        assert(key_gen_ > 0 && "rotate: generation did not advance");
        return true;
    }

    // A peer flipped the key-phase bit and we decrypted with the next keys:
    // commit the update so our subsequent sends use the new phase (RFC 9001 §6.2).
    void commit_peer_key_update() noexcept {
        assert(ku_ready_ && "commit: key update not ready");
        rotate_keys(/*peer_initiated=*/true);
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
        // Every stream opens with a window of exactly its receive ring.
        tp.initial_max_stream_data_bidi_local = kStreamRecvWindow;
        tp.initial_max_stream_data_bidi_local_present = true;
        tp.initial_max_stream_data_bidi_remote = kStreamRecvWindow;
        tp.initial_max_stream_data_bidi_remote_present = true;
        tp.initial_max_stream_data_uni = kStreamRecvWindow;
        tp.initial_max_stream_data_uni_present = true;
        tp.initial_max_streams_bidi = peer_bidi_concurrency_;
        tp.initial_max_streams_bidi_present = true;
        tp.initial_max_streams_uni = kPeerUniStreamsMax;
        tp.initial_max_streams_uni_present = true;
        tp.max_idle_timeout = 30000;
        tp.max_idle_timeout_present = true;
        tp.max_udp_payload_size = kMaxDatagramSize;  // our open buffers' size
        tp.max_udp_payload_size_present = true;
        tp.active_connection_id_limit = 4;
        tp.active_connection_id_limit_present = true;
        // RFC 9221: advertise QUIC DATAGRAM support so the peer may enable HTTP/3
        // datagrams (required for WebTransport). We accept full-size datagrams.
        tp.max_datagram_frame_size = 65535;
        tp.max_datagram_frame_size_present = true;

        // RFC 9000 §7.3: both endpoints MUST authenticate the connection IDs they
        // chose by echoing them in transport parameters. initial_source_connection_id
        // = the Source CID we put in OUR Initial packets (== local_cid_). A peer
        // (e.g. aioquic) aborts the handshake with TRANSPORT_PARAMETER_ERROR if
        // this is missing or mismatched — this was the post-crypto interop blocker.
        assert(local_cid_.length <= kMaxConnectionIdLength && "iscid too long");
        std::memcpy(tp.initial_source_connection_id, local_cid_.data,
                    local_cid_.length);
        tp.initial_source_connection_id_len = local_cid_.length;
        tp.initial_source_connection_id_present = true;

        // RFC 9000 §7.3: the SERVER also echoes original_destination_connection_id
        // = the DCID the client used in its first Initial (== initial_dcid_ once
        // server_on_first_initial has run). Unknown before that, so only when set.
        // After a Retry the ODCID is the client's FIRST DCID (from the token)
        // and retry_source_connection_id is the Retry's SCID.
        const ConnectionId& odcid = sent_retry_ ? odcid_ : initial_dcid_;
        if (is_server_ && odcid.length > 0) {
            assert(odcid.length <= kMaxConnectionIdLength && "odcid too long");
            std::memcpy(tp.original_destination_connection_id, odcid.data,
                        odcid.length);
            tp.original_destination_connection_id_len = odcid.length;
            tp.original_destination_connection_id_present = true;
        }
        if (is_server_ && sent_retry_) {
            assert(retry_scid_.length <= kMaxConnectionIdLength && "rscid too long");
            std::memcpy(tp.retry_source_connection_id, retry_scid_.data,
                        retry_scid_.length);
            tp.retry_source_connection_id_len = retry_scid_.length;
            tp.retry_source_connection_id_present = true;
        }
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

    // #45 — coalesced-datagram accumulator (active only inside flush()). Sealed
    // packets are appended here and emitted as ONE UDP datagram (RFC 9000 §12.2).
    bool         coalescing_        = false;
    bool         dgram_has_initial_ = false;
    std::size_t  dgram_len_         = 0;
    std::uint8_t dgram_buf_[kMaxDatagramSize]{};
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
    static constexpr std::uint64_t kStreamRecvWindow = kStreamBufferSize;
    QuicStreamDataFn on_stream_data_;
    QuicDatagramFn   on_datagram_;       // RFC 9221 received-DATAGRAM handler
    // The Stream pool is pre-allocated from the connection arena (each Stream
    // carries large fixed send/recv buffers; embedding kMaxStreams of them by
    // value would blow the stack). Pool-style allocation per CLAUDE.md — no
    // per-stream heap churn; bounded by kMaxStreams.
    Stream* streams_ = nullptr;
    std::uint64_t next_bidi_seq_ = 0;
    std::uint64_t next_uni_seq_ = 0;
    std::uint64_t local_bidi_credit_ = 0;  // peer's MAX_STREAMS for our streams
    std::uint64_t local_uni_credit_ = 0;
    std::size_t rr_next_ = 0;  // round-robin start for STREAM framing

    bolt::Arena stream_arena_;

    // Peer-initiated stream credit + closed-id memory, per direction.
    struct PeerStreamBook {
        static constexpr std::uint64_t kWords = kClosedStreamWindowMax / 64;
        std::uint64_t limit = 0;         // streams granted (MAX_STREAMS)
        std::uint64_t sent_limit = 0;    // last advertised
        std::uint64_t floor = 0;         // every seq below is closed
        std::uint64_t closed_total = 0;
        std::uint64_t bits[kWords] = {};

        bool bit(std::uint64_t seq) const noexcept {
            const std::uint64_t i = seq % kClosedStreamWindowMax;
            return (bits[i / 64] >> (i % 64)) & 1u;
        }
        void set_bit(std::uint64_t seq, bool on) noexcept {
            const std::uint64_t i = seq % kClosedStreamWindowMax;
            const std::uint64_t m = 1ull << (i % 64);
            bits[i / 64] = on ? (bits[i / 64] | m) : (bits[i / 64] & ~m);
        }
        bool is_closed(std::uint64_t seq) const noexcept {
            if (seq < floor) return true;
            if (seq - floor >= kClosedStreamWindowMax) return false;
            return bit(seq);
        }
        void mark_closed(std::uint64_t seq) noexcept {
            assert(seq >= floor && seq - floor < kClosedStreamWindowMax &&
                   "closed stream outside the window");
            assert(!bit(seq) && "stream closed twice");
            set_bit(seq, true);
            ++closed_total;
            for (std::uint64_t i = 0; i < kClosedStreamWindowMax && bit(floor); ++i) {
                set_bit(floor, false);
                ++floor;
            }
        }
        // Credit = closed + concurrency, never past the closed-id window.
        void update_limit(std::uint64_t concurrent) noexcept {
            std::uint64_t next = closed_total + concurrent;
            if (next > floor + kClosedStreamWindowMax)
                next = floor + kClosedStreamWindowMax;
            if (next > limit) limit = next;
            assert(limit <= floor + kClosedStreamWindowMax && "credit past window");
        }
    };
    PeerStreamBook peer_bidi_{kPeerBidiStreamsDefault, kPeerBidiStreamsDefault};
    std::uint64_t peer_bidi_concurrency_ = kPeerBidiStreamsDefault;
    // ALPN whose connections get alpn_bidi_streams_ concurrent bidi streams.
    std::uint8_t alpn_raise_[32] = {};
    std::size_t alpn_raise_len_ = 0;
    std::uint64_t alpn_bidi_streams_ = 0;
    PeerStreamBook peer_uni_{kPeerUniStreamsMax, kPeerUniStreamsMax};

    struct PendingReset { std::uint64_t id; std::uint64_t err; std::uint64_t final_size; };
    PendingReset resets_[kMaxStreams] = {};
    std::size_t reset_count_ = 0;

    // Control frames carried by the packet being built (re-issued on loss).
    static constexpr std::uint8_t kCtrlHandshakeDone = 1;
    static constexpr std::uint8_t kCtrlFlow = 2;
    static constexpr std::uint8_t kCtrlStreams = 4;
    std::uint8_t next_ctrl_flags_ = 0;

    // Connection-level flow control (RFC 9000 §4.1).
    std::uint64_t conn_send_max_ = 0;            // peer's MAX_DATA (set on init)
    std::uint64_t conn_send_total_ = 0;          // total stream bytes we've sent
    std::uint64_t conn_recv_max_ = 1u << 20;     // our advertised MAX_DATA
    std::uint64_t conn_recv_total_ = 0;          // total stream bytes received
    bool conn_window_dirty_ = false;
    bool stream_window_dirty_ = false;
    bool conn_blocked_ = false;
    bool stream_blocked_ = false;

    // ---- W5d robustness (RFC 9000 §8/§10, RFC 9001 §6) --------------------
    // Version negotiation.
    std::uint32_t offered_version_ = kQuicVersion1;     // client's offered ver
    std::uint32_t negotiated_version_ = kQuicVersion1;  // the agreed version
    bool vn_handled_ = false;                            // client acted on VN
    bool sent_vn_ = false;                               // server emitted a VN

    // Retry + address validation (RFC 9000 §8.1).
    bool require_retry_ = false;                         // server config
    bool sent_retry_ = false;                            // server emitted Retry
    bool did_retry_ = false;                             // client re-keyed
    bool address_validated_ = false;                     // server validated peer
    ConnectionId retry_scid_;                            // server's Retry SCID
    ConnectionId odcid_;                                 // ODCID from the token
    ConnectionId first_dcid_;                            // DCID of the Retried Initial

    // 0-RTT packets that arrived before TLS yielded the early keys.
    static constexpr std::size_t kEarlyHeldPackets = 4;
    std::uint8_t early_buf_[kEarlyHeldPackets][kMaxDatagramSize] = {};
    std::size_t early_len_[kEarlyHeldPackets] = {};
    std::size_t early_held_ = 0;
    AddressValidator validator_;                         // token mint/verify
    std::uint8_t retry_token_[kMaxRetryToken] = {};      // client-held token
    std::size_t retry_token_len_ = 0;
    AntiAmplification amp_;                              // 3x limit (§8.1)

    // CONNECTION_CLOSE + idle timeout (RFC 9000 §10).
    std::uint64_t local_idle_ms_ = kDefaultIdleTimeoutMs;
    std::uint64_t last_activity_us_ = 0;
    std::uint64_t closing_since_us_ = 0;
    std::uint64_t close_error_ = 0;
    bool close_is_app_ = false;
    bool close_pending_ = false;
    const char* close_reason_ = nullptr;
    std::size_t close_reason_len_ = 0;

    // Stateless reset (RFC 9000 §10.3).
    std::uint8_t local_reset_token_[kStatelessResetTokenLen] = {};
    std::uint8_t peer_reset_token_[kStatelessResetTokenLen] = {};
    bool have_local_reset_token_ = false;
    bool have_peer_reset_token_ = false;
    bool got_stateless_reset_ = false;

    // Key update (RFC 9001 §6). gen-0 secrets captured at Established; current/
    // next/previous AEAD protections drive seal/open across phase flips. The HP
    // keys are NEVER rotated (§6.1) — those stay in tls_.{read,write}_protection.
    bool ku_ready_ = false;
    std::uint64_t key_gen_ = 0;
    AeadAlgorithm ku_algo_ = AeadAlgorithm::kAes128Gcm;
    // 1-RTT traffic secrets are one hash output long (32B SHA-256 / 48B SHA-384),
    // sized to the maximum so AES-256-GCM-SHA384 key updates work (RFC 9001 §6.1).
    std::size_t ku_secret_len_ = kSecretLength;
    std::uint8_t app_read_secret_[kMaxSecretLength] = {};
    std::uint8_t app_write_secret_[kMaxSecretLength] = {};
    std::uint8_t next_read_secret_[kMaxSecretLength] = {};
    std::uint8_t next_write_secret_[kMaxSecretLength] = {};
    PacketProtection app_read_cur_;   // current generation read AEAD
    PacketProtection app_write_cur_;  // current generation write AEAD
    PacketProtection app_read_next_;  // pre-derived next-gen read AEAD
    PacketProtection app_read_prev_;  // previous-gen read AEAD (reorder window)
};

}  // namespace bolt::api::quic
