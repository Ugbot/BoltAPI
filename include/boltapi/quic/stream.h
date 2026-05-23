// boltapi/quic/stream.h — QUIC streams (RFC 9000 §2-§3) + flow control (§4) +
// per-stream ordered reassembly, plus serializers for the flow-control /
// stream-management frames that frames.h only carried constants for.
//
// ADAPTED from FasterAPI src/cpp/http/quic/quic_stream.h (QUICStream + send/recv
// state machines), quic_flow_control.h (FlowControl / StreamFlowControl) and
// stream_reassembly_buffer.h, reshaped to Bolt Tiger Style: namespace
// bolt::api::quic, >=2 asserts per function, named bounds, noexcept, no
// allocation (the FasterAPI RingBuffer + std::vector gap list become fixed
// per-stream byte arrays with a contiguous-receive cursor + a bounded
// out-of-order extent set), no recursion on the hot path, no exceptions,
// <70-line functions.
//
// Stream-id encoding (RFC 9000 §2.1): bit 0 = initiator (0 client / 1 server),
// bit 1 = directionality (0 bidi / 1 uni). The connection owns a fixed Stream
// pool and a bolt::SwissTable mapping stream_id -> pool index.
//
// Header-only, dependency-free apart from QUIC primitives + bolt::SwissTable.
// Compiles UNCONDITIONALLY (default ctest suite covers it).

#pragma once

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "boltapi/quic/frames.h"
#include "boltapi/quic/varint.h"

namespace bolt::api::quic {

// ----------------------------------------------------------------------------
// Named bounds (Tiger Style).
// ----------------------------------------------------------------------------

// Per-stream send + receive buffer. The gate transfers a multi-KB message; this
// comfortably holds it without regrowth (no std::vector). Bounded to keep the
// Stream object a fixed size.
inline constexpr std::size_t kStreamBufferSize = 256 * 1024;

// Max distinct out-of-order extents we track on the receive side before the gap
// must fill (RFC 9000 lets an endpoint bound reorder buffering). Loopback +
// the lossy variant never approach this.
inline constexpr std::size_t kMaxRecvExtents = 32;

// Max concurrently live streams per connection (fixed pool; SwissTable maps
// id -> index). The gate uses one; H3 will raise this in wave 5b. The pool is
// arena-allocated (each Stream carries large fixed buffers), so this bounds the
// arena footprint, not the connection object size.
inline constexpr std::size_t kMaxStreams = 16;

// Stream-id helpers (RFC 9000 §2.1).
inline constexpr std::uint64_t kStreamInitiatorBit = 0x1;  // 0 client / 1 server
inline constexpr std::uint64_t kStreamDirBit = 0x2;        // 0 bidi  / 1 uni

inline bool stream_is_client_initiated(std::uint64_t id) noexcept {
    return (id & kStreamInitiatorBit) == 0;
}
inline bool stream_is_server_initiated(std::uint64_t id) noexcept {
    return (id & kStreamInitiatorBit) != 0;
}
inline bool stream_is_bidi(std::uint64_t id) noexcept {
    return (id & kStreamDirBit) == 0;
}
inline bool stream_is_uni(std::uint64_t id) noexcept {
    return (id & kStreamDirBit) != 0;
}
// Compose a stream id from its index within a (initiator,dir) class.
inline std::uint64_t make_stream_id(std::uint64_t seq, bool server,
                                    bool uni) noexcept {
    assert(seq <= (kVarIntMax >> 2) && "stream sequence overflow");
    const std::uint64_t low = (server ? kStreamInitiatorBit : 0) |
                              (uni ? kStreamDirBit : 0);
    const std::uint64_t id = (seq << 2) | low;
    assert((id & 0x3) == low && "stream id low bits");
    return id;
}

// Stream send/recv state machines (RFC 9000 §3.1 / §3.2, condensed).
enum class SendState : std::uint8_t { kReady, kSend, kDataSent, kResetSent, kResetRecvd };
enum class RecvState : std::uint8_t { kRecv, kSizeKnown, kDataRecvd, kResetRecvd };

// ============================================================================
// StreamFlow — combined per-stream flow-control window pair (RFC 9000 §4.1).
// ============================================================================
struct StreamFlow {
    std::uint64_t send_max = 0;     // peer's MAX_STREAM_DATA for us (send limit)
    std::uint64_t send_off = 0;     // bytes we have queued/sent
    std::uint64_t recv_max = 0;     // our advertised limit to the peer
    std::uint64_t recv_high = 0;    // highest offset+len the peer has sent

    bool can_send(std::uint64_t bytes) const noexcept {
        assert(bytes <= kStreamBufferSize && "send chunk too big");
        return send_off + bytes <= send_max;
    }
    std::uint64_t send_window() const noexcept {
        return (send_off < send_max) ? send_max - send_off : 0;
    }
    bool recv_ok(std::uint64_t end_off) const noexcept {
        assert(end_off <= (1ULL << 62) && "recv offset absurd");
        return end_off <= recv_max;
    }
};

// ============================================================================
// Stream — one QUIC stream: send buffer, ordered receive reassembly, state.
// ============================================================================
class Stream {
public:
    Stream() noexcept = default;

    void open(std::uint64_t id, std::uint64_t init_send_max,
              std::uint64_t init_recv_max) noexcept {
        assert(id <= kVarIntMax && "stream id overflow");
        assert(init_recv_max <= kStreamBufferSize && "recv window > buffer");
        id_ = id;
        in_use_ = true;
        send_st_ = SendState::kReady;
        recv_st_ = RecvState::kRecv;
        flow_.send_max = init_send_max;
        flow_.recv_max = init_recv_max;
        bidi_ = stream_is_bidi(id);
    }

    bool in_use() const noexcept { return in_use_; }
    std::uint64_t id() const noexcept { assert(in_use_); return id_; }
    bool is_bidi() const noexcept { return bidi_; }
    SendState send_state() const noexcept { return send_st_; }
    RecvState recv_state() const noexcept { return recv_st_; }
    StreamFlow& flow() noexcept { return flow_; }
    const StreamFlow& flow() const noexcept { return flow_; }

    // ---- send side -------------------------------------------------------
    // Queue application bytes; mark FIN if requested. Bounded by the buffer.
    // Returns bytes queued (may be < len if the buffer is near full).
    std::size_t write(const std::uint8_t* data, std::size_t len, bool fin) noexcept {
        assert((data != nullptr || len == 0) && "stream write null");
        assert(send_st_ != SendState::kResetSent && "write after reset");
        std::size_t space = kStreamBufferSize - send_buf_len_;
        std::size_t n = (len < space) ? len : space;
        if (n > 0) { std::memcpy(send_buf_ + send_buf_len_, data, n); send_buf_len_ += n; }
        if (fin) want_fin_ = true;
        if (send_st_ == SendState::kReady && (n > 0 || fin)) send_st_ = SendState::kSend;
        return n;
    }

    // Bytes still queued and unsent (above send_acked_/send_sent_ frontier).
    std::size_t unsent() const noexcept {
        assert(send_sent_ <= send_buf_len_ && "sent past buffered");
        return send_buf_len_ - send_sent_;
    }
    bool fin_pending() const noexcept { return want_fin_ && !fin_sent_; }
    bool has_send_work() const noexcept { return unsent() > 0 || fin_pending(); }

    // Peek the next unsent chunk for framing. Returns offset/ptr/len; sets
    // out_fin if this chunk reaches the FIN. Does not advance the frontier.
    bool peek_unsent(std::uint64_t& off, const std::uint8_t*& ptr,
                     std::size_t& len, bool& out_fin, std::size_t cap) noexcept {
        assert(cap > 0 && "peek cap zero");
        const std::size_t avail = unsent();
        len = (avail < cap) ? avail : cap;
        off = send_sent_;
        ptr = send_buf_ + send_sent_;
        out_fin = want_fin_ && (send_sent_ + len == send_buf_len_);
        return len > 0 || (want_fin_ && !fin_sent_);
    }

    // Advance the sent frontier after a chunk was framed into a packet. Returns
    // the number of NEW bytes (those past the high-water mark) so connection-
    // level flow control counts unique stream bytes, not retransmits.
    std::size_t mark_sent(std::size_t len, bool fin) noexcept {
        assert(send_sent_ + len <= send_buf_len_ && "mark_sent overruns buffer");
        const std::uint64_t new_end = send_sent_ + len;
        std::size_t fresh = 0;
        if (new_end > flow_counted_) {
            fresh = static_cast<std::size_t>(new_end - flow_counted_);
            flow_counted_ = new_end;
        }
        send_sent_ += len;
        flow_.send_off = send_sent_;
        if (fin) { fin_sent_ = true; send_st_ = SendState::kDataSent; }
        return fresh;
    }

    // Rewind the sent frontier to `off` so loss recovery re-frames from there.
    void rewind_sent(std::uint64_t off, bool fin_was_sent) noexcept {
        assert(off <= send_buf_len_ && "rewind past buffer");
        if (off < send_sent_) send_sent_ = static_cast<std::size_t>(off);
        if (fin_was_sent) fin_sent_ = false;  // re-send the FIN too
        if (send_st_ == SendState::kDataSent) send_st_ = SendState::kSend;
    }

    // ---- receive side: ordered reassembly --------------------------------
    // Accept STREAM bytes at `offset`. Buffers + advances the contiguous cursor.
    // Returns false on flow-control violation / overflow.
    bool receive(std::uint64_t offset, const std::uint8_t* data, std::size_t len,
                 bool fin) noexcept {
        assert((data != nullptr || len == 0) && "stream recv null");
        const std::uint64_t end = offset + len;
        if (end > kStreamBufferSize) return false;            // window/buffer cap
        if (!flow_.recv_ok(end)) return false;                // §4.1 violation
        if (end > flow_.recv_high) flow_.recv_high = end;
        if (fin) { fin_off_ = end; have_fin_ = true; if (recv_st_ == RecvState::kRecv) recv_st_ = RecvState::kSizeKnown; }
        if (len > 0 && !store(offset, data, len)) return false;
        if (have_fin_ && recv_cursor_ >= fin_off_) recv_st_ = RecvState::kDataRecvd;
        return true;
    }

    // Contiguous, not-yet-read received bytes.
    std::size_t recv_available() const noexcept {
        assert(read_cursor_ <= recv_cursor_ && "read past recv");
        return static_cast<std::size_t>(recv_cursor_ - read_cursor_);
    }
    const std::uint8_t* recv_peek() const noexcept {
        assert(read_cursor_ <= kStreamBufferSize && "read cursor oob");
        return recv_buf_ + read_cursor_;
    }
    void recv_consume(std::size_t n) noexcept {
        assert(read_cursor_ + n <= recv_cursor_ && "consume past contiguous");
        read_cursor_ += n;
    }
    // Pointer to the `n` bytes most recently consumed (the prefix ending at the
    // current read cursor). Valid until the next receive() into the same region.
    const std::uint8_t* recv_peek_consumed(std::size_t n) const noexcept {
        assert(n <= read_cursor_ && "peek_consumed underflow");
        return recv_buf_ + (read_cursor_ - n);
    }
    bool recv_finished() const noexcept {
        return have_fin_ && read_cursor_ >= fin_off_;
    }
    bool fin_received() const noexcept { return have_fin_; }

    // Whether our advertised recv window should be bumped (consumed enough).
    bool needs_window_update(std::uint64_t bump_threshold) const noexcept {
        assert(bump_threshold > 0 && "zero threshold");
        return (flow_.recv_max - read_cursor_) < bump_threshold &&
               !recv_finished();
    }
    std::uint64_t grow_recv_window(std::uint64_t add) noexcept {
        assert(add > 0 && "zero window grow");
        std::uint64_t next = read_cursor_ + add;
        if (next > kStreamBufferSize) next = kStreamBufferSize;
        if (next > flow_.recv_max) flow_.recv_max = next;
        return flow_.recv_max;
    }

private:
    // Store bytes into the receive buffer, advancing the contiguous cursor over
    // any now-filled prefix (bounded out-of-order extent tracking).
    bool store(std::uint64_t offset, const std::uint8_t* data,
               std::size_t len) noexcept {
        assert(offset + len <= kStreamBufferSize && "store overflow");
        std::size_t from = 0;
        std::uint64_t at = offset;
        if (offset < recv_cursor_) {
            const std::uint64_t skip = recv_cursor_ - offset;
            if (skip >= len) return true;  // wholly duplicate
            from = static_cast<std::size_t>(skip);
            at = recv_cursor_;
        }
        const std::size_t n = len - from;
        std::memcpy(recv_buf_ + at, data + from, n);
        return mark_filled(static_cast<std::uint64_t>(at), n);
    }

    // Track [start,start+n) as present; advance recv_cursor_ over filled prefix.
    bool mark_filled(std::uint64_t start, std::size_t n) noexcept {
        assert(start + n <= kStreamBufferSize && "mark_filled overflow");
        if (start <= recv_cursor_ && start + n > recv_cursor_) {
            recv_cursor_ = start + n;
        } else if (start > recv_cursor_) {
            if (ext_count_ >= kMaxRecvExtents) return false;  // too much reorder
            extents_[ext_count_].start = start;
            extents_[ext_count_].end = start + n;
            ++ext_count_;
        }
        // Absorb any buffered extents now made contiguous (bounded sweep).
        bool progressed = true;
        while (progressed) {
            progressed = false;
            for (std::size_t i = 0; i < ext_count_; ++i) {
                if (extents_[i].start <= recv_cursor_ && extents_[i].end > recv_cursor_) {
                    recv_cursor_ = extents_[i].end;
                    extents_[i] = extents_[--ext_count_];
                    progressed = true;
                    break;
                }
                if (extents_[i].end <= recv_cursor_) {  // fully consumed
                    extents_[i] = extents_[--ext_count_];
                    progressed = true;
                    break;
                }
            }
        }
        assert(recv_cursor_ <= kStreamBufferSize && "cursor oob");
        return true;
    }

    struct Extent { std::uint64_t start = 0; std::uint64_t end = 0; };

    std::uint64_t id_ = 0;
    bool in_use_ = false;
    bool bidi_ = true;
    SendState send_st_ = SendState::kReady;
    RecvState recv_st_ = RecvState::kRecv;
    StreamFlow flow_{};

    // send side
    std::uint8_t send_buf_[kStreamBufferSize]{};
    std::size_t send_buf_len_ = 0;   // total queued
    std::size_t send_sent_ = 0;      // frontier framed into packets
    std::uint64_t flow_counted_ = 0; // high-water counted toward conn flow ctrl
    bool want_fin_ = false;
    bool fin_sent_ = false;

    // receive side
    std::uint8_t recv_buf_[kStreamBufferSize]{};
    std::uint64_t recv_cursor_ = 0;  // highest contiguous offset received
    std::uint64_t read_cursor_ = 0;  // delivered to the app
    std::uint64_t fin_off_ = 0;
    bool have_fin_ = false;
    Extent extents_[kMaxRecvExtents]{};
    std::size_t ext_count_ = 0;
};

// ============================================================================
// Flow-control / stream-management frame serializers (frames.h carried only the
// type constants). All RFC 9000 §19 wire-correct, fixed bounded output.
// ============================================================================

// MAX_DATA (0x10) / MAX_STREAMS_BIDI (0x12) / MAX_STREAMS_UNI (0x13):
// single-varint frames. Returns bytes written.
inline std::size_t serialize_single_varint(FrameType type, std::uint64_t v,
                                           std::uint8_t* out) noexcept {
    assert(out != nullptr && "serialize_single_varint null");
    assert(v <= kVarIntMax && "single-varint value overflow");
    std::size_t pos = 0;
    out[pos++] = static_cast<std::uint8_t>(type);
    pos += varint_encode(v, out + pos);
    return pos;
}

// MAX_STREAM_DATA (0x11) / STREAM_DATA_BLOCKED (0x15): stream_id + value.
inline std::size_t serialize_stream_pair(FrameType type, std::uint64_t id,
                                         std::uint64_t v, std::uint8_t* out) noexcept {
    assert(out != nullptr && "serialize_stream_pair null");
    assert(id <= kVarIntMax && v <= kVarIntMax && "stream pair overflow");
    std::size_t pos = 0;
    out[pos++] = static_cast<std::uint8_t>(type);
    pos += varint_encode(id, out + pos);
    pos += varint_encode(v, out + pos);
    return pos;
}

// RESET_STREAM (0x04): stream_id + app_error + final_size.
inline std::size_t serialize_reset_stream(std::uint64_t id, std::uint64_t err,
                                          std::uint64_t final_size,
                                          std::uint8_t* out) noexcept {
    assert(out != nullptr && "reset_stream null");
    assert(final_size <= kVarIntMax && "final size overflow");
    std::size_t pos = 0;
    out[pos++] = static_cast<std::uint8_t>(FrameType::kResetStream);
    pos += varint_encode(id, out + pos);
    pos += varint_encode(err, out + pos);
    pos += varint_encode(final_size, out + pos);
    return pos;
}

// STOP_SENDING (0x05): stream_id + app_error.
inline std::size_t serialize_stop_sending(std::uint64_t id, std::uint64_t err,
                                          std::uint8_t* out) noexcept {
    assert(out != nullptr && "stop_sending null");
    assert(id <= kVarIntMax && "stop_sending id overflow");
    std::size_t pos = 0;
    out[pos++] = static_cast<std::uint8_t>(FrameType::kStopSending);
    pos += varint_encode(id, out + pos);
    pos += varint_encode(err, out + pos);
    return pos;
}

}  // namespace bolt::api::quic
