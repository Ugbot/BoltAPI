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
#include <string>
#include <utility>

#include "boltapi/quic/frames.h"
#include "boltapi/quic/varint.h"

namespace bolt::api::quic {

// ----------------------------------------------------------------------------
// Named bounds (Tiger Style).
// ----------------------------------------------------------------------------

// Per-stream send + receive ring. Acknowledged send bytes and read receive
// bytes leave it, so a stream carries any length; this bounds what is in
// flight / buffered at once (the receive window never exceeds it).
inline constexpr std::size_t kStreamBufferSize = 256 * 1024;

// Max distinct out-of-order extents we track on the receive side before the gap
// must fill (RFC 9000 lets an endpoint bound reorder buffering). Loopback +
// the lossy variant never approach this.
inline constexpr std::size_t kMaxRecvExtents = 32;

// Max concurrently live streams per connection (fixed pool, slots reused once
// both directions finish). A slot's two rings are allocated the first time it
// is used, so memory follows peak concurrency (<= 2 * kStreamBufferSize each).
inline constexpr std::size_t kMaxStreams = 64;

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

    // The rings live outside the Stream (the connection allocates them the
    // first time a pool slot is used and keeps them across reuse).
    void attach_buffers(std::uint8_t* send_ring, std::uint8_t* recv_ring) noexcept {
        assert(send_ring != nullptr && recv_ring != nullptr && "null stream ring");
        assert(!in_use_ && "attach on a live stream");
        send_buf_ = send_ring;
        recv_buf_ = recv_ring;
    }
    bool has_buffers() const noexcept { return send_buf_ != nullptr; }

    void open(std::uint64_t id, std::uint64_t init_send_max,
              std::uint64_t init_recv_max) noexcept {
        assert(id <= kVarIntMax && "stream id overflow");
        assert(has_buffers() && "open without rings");
        assert(init_recv_max <= kStreamBufferSize && "recv window > buffer");
        assert(!in_use_ && "open on a live stream");
        id_ = id;
        in_use_ = true;
        send_st_ = SendState::kReady;
        recv_st_ = RecvState::kRecv;
        flow_ = StreamFlow{};
        flow_.send_max = init_send_max;
        flow_.recv_max = init_recv_max;
        bidi_ = stream_is_bidi(id);
    }

    // Return the slot to the pool: drop queued/pending bytes, reset cursors.
    // Buffers are left as-is (never read below the reset cursors).
    void release() noexcept {
        assert(in_use_ && "release of a free stream");
        std::string().swap(pending_);
        id_ = 0; in_use_ = false; bidi_ = true;
        send_st_ = SendState::kReady; recv_st_ = RecvState::kRecv;
        flow_ = StreamFlow{};
        send_base_ = send_end_ = send_sent_ = flow_counted_ = 0;
        ack_ext_.count = 0;
        want_fin_ = fin_sent_ = fin_acked_ = false;
        pending_off_ = 0; pending_fin_ = false;
        recv_cursor_ = read_cursor_ = fin_off_ = 0;
        have_fin_ = fin_notified_ = window_dirty_ = recv_reset_ = false;
        recv_ext_.count = 0;
        assert(!in_use_ && pending_.empty() && "release left the slot live");
    }

    bool in_use() const noexcept { return in_use_; }
    std::uint64_t id() const noexcept { assert(in_use_); return id_; }
    bool is_bidi() const noexcept { return bidi_; }
    SendState send_state() const noexcept { return send_st_; }
    RecvState recv_state() const noexcept { return recv_st_; }
    StreamFlow& flow() noexcept { return flow_; }
    const StreamFlow& flow() const noexcept { return flow_; }

    // ---- send side -------------------------------------------------------
    // The send buffer is a ring over absolute offsets [send_base_, send_end_):
    // bytes leave it once acknowledged, so a stream carries any length.

    // Queue bytes; FIN only once every byte is queued. Returns bytes queued.
    std::size_t write(const std::uint8_t* data, std::size_t len, bool fin) noexcept {
        assert((data != nullptr || len == 0) && "stream write null");
        assert(send_st_ != SendState::kResetSent && "write after reset");
        if (!pending_empty()) return 0;  // order: pending bytes go first
        const std::size_t n = ring_put(data, len);
        if (fin && n == len) want_fin_ = true;
        if (send_st_ == SendState::kReady && (n > 0 || want_fin_)) send_st_ = SendState::kSend;
        assert(n <= len && send_end_ - send_base_ <= kStreamBufferSize);
        return n;
    }

    // Queue ALL of `body` (+FIN): what fits goes to the ring now, the rest is
    // held and moved in as acknowledgements free ring space.
    void write_owned(std::string&& body, bool fin) noexcept {
        assert(send_st_ != SendState::kResetSent && "write after reset");
        assert(pending_empty() && "write_owned over pending bytes");
        pending_ = std::move(body);
        pending_off_ = 0;
        pending_fin_ = fin;
        if (send_st_ == SendState::kReady) send_st_ = SendState::kSend;
        refill();
        assert(pending_off_ <= pending_.size() && "pending cursor overrun");
    }

    bool pending_empty() const noexcept {
        return pending_off_ >= pending_.size() && !pending_fin_;
    }
    std::size_t pending_bytes() const noexcept {
        assert(pending_off_ <= pending_.size() && "pending cursor overrun");
        return pending_.size() - pending_off_;
    }

    // Move held bytes into freed ring space. Returns bytes moved.
    std::size_t refill() noexcept {
        if (pending_empty()) return 0;
        const std::size_t left = pending_.size() - pending_off_;
        const std::size_t n = ring_put(
            reinterpret_cast<const std::uint8_t*>(pending_.data()) + pending_off_, left);
        pending_off_ += n;
        if (pending_off_ == pending_.size()) {
            if (pending_fin_) want_fin_ = true;
            pending_fin_ = false;
            std::string().swap(pending_);
            pending_off_ = 0;
        }
        assert(pending_off_ <= pending_.size() && "refill overran");
        return n;
    }

    // Bytes write() can accept now.
    std::size_t send_space() const noexcept {
        assert(send_end_ - send_base_ <= kStreamBufferSize && "send ring overrun");
        if (!pending_empty()) return 0;
        return kStreamBufferSize - static_cast<std::size_t>(send_end_ - send_base_);
    }

    std::size_t unsent() const noexcept {
        assert(send_sent_ <= send_end_ && "sent past buffered");
        return static_cast<std::size_t>(send_end_ - send_sent_);
    }
    bool fin_pending() const noexcept { return want_fin_ && !fin_sent_; }
    bool has_send_work() const noexcept { return unsent() > 0 || fin_pending(); }

    // Next unsent chunk (contiguous in the ring). Does not advance the frontier.
    bool peek_unsent(std::uint64_t& off, const std::uint8_t*& ptr,
                     std::size_t& len, bool& out_fin, std::size_t cap) noexcept {
        assert(cap > 0 && "peek cap zero");
        const std::size_t pos = static_cast<std::size_t>(send_sent_ % kStreamBufferSize);
        std::size_t avail = unsent();
        if (avail > kStreamBufferSize - pos) avail = kStreamBufferSize - pos;
        len = (avail < cap) ? avail : cap;
        off = send_sent_;
        ptr = send_buf_ + pos;
        out_fin = want_fin_ && (send_sent_ + len == send_end_);
        assert(pos + len <= kStreamBufferSize && "peek past ring end");
        return len > 0 || (want_fin_ && !fin_sent_);
    }

    // Advance the sent frontier. Returns the NEW bytes (past the high-water
    // mark) so connection flow control counts unique bytes, not retransmits.
    std::size_t mark_sent(std::size_t len, bool fin) noexcept {
        assert(send_sent_ + len <= send_end_ && "mark_sent overruns buffer");
        const std::uint64_t new_end = send_sent_ + len;
        std::size_t fresh = 0;
        if (new_end > flow_counted_) {
            fresh = static_cast<std::size_t>(new_end - flow_counted_);
            flow_counted_ = new_end;
        }
        send_sent_ = new_end;
        if (send_sent_ > flow_.send_off) flow_.send_off = send_sent_;
        if (fin) { fin_sent_ = true; send_st_ = SendState::kDataSent; }
        return fresh;
    }

    // Rewind the frontier to `off` so loss recovery re-frames from there.
    // Bytes below send_base_ are acknowledged and gone.
    void rewind_sent(std::uint64_t off, bool fin_was_sent) noexcept {
        assert(send_base_ <= send_end_ && "ring base past end");
        if (off < send_base_) off = send_base_;
        if (off > send_end_) off = send_end_;
        if (off < send_sent_) send_sent_ = off;
        if (fin_was_sent && !fin_acked_) fin_sent_ = false;
        if (send_st_ == SendState::kDataSent && !fin_acked_) send_st_ = SendState::kSend;
    }

    // Peer acknowledged [off, off+len) (+FIN). Frees the acked ring prefix.
    void on_acked(std::uint64_t off, std::uint64_t len, bool fin) noexcept {
        assert(off + len >= off && "ack range wraps");
        if (fin && off + len == send_end_ && want_fin_) fin_acked_ = true;
        const std::uint64_t end = off + len;
        if (len > 0 && end > send_base_) {
            if (off <= send_base_) {
                send_base_ = end;
            } else if (!ack_ext_.add(off, end)) {
                // Tracking full: force this span to be resent; its ACK then
                // lands on the contiguous prefix instead.
                rewind_sent(off, false);
            }
            send_base_ = ack_ext_.absorb(send_base_);
        }
        if (send_base_ > send_end_) send_base_ = send_end_;
        if (send_sent_ < send_base_) send_sent_ = send_base_;
        assert(send_base_ <= send_end_ && "ack past queued bytes");
    }

    std::uint64_t send_acked_offset() const noexcept { return send_base_; }
    std::uint64_t queued_end() const noexcept { return send_end_; }
    bool fin_acked() const noexcept { return fin_acked_; }

    // Abandon the send side (STOP_SENDING / reset): nothing more is sent.
    void abandon_send() noexcept {
        assert(in_use_ && "abandon on a free stream");
        std::string().swap(pending_);
        pending_off_ = 0;
        pending_fin_ = false;
        send_base_ = send_end_;
        send_sent_ = send_end_;
        want_fin_ = false;
        send_st_ = SendState::kResetSent;
        assert(!has_send_work() && "abandoned stream still has work");
    }

    // Every byte (and the FIN) the send side will ever carry is acknowledged.
    bool send_done() const noexcept {
        return send_st_ == SendState::kResetSent ||
               (fin_acked_ && send_base_ == send_end_ && pending_empty());
    }

    // ---- receive side: ordered reassembly over a ring ------------------------
    // Accept STREAM bytes at `offset`. False on a flow-control violation or a
    // final-size change (RFC 9000 §4.5).
    bool receive(std::uint64_t offset, const std::uint8_t* data, std::size_t len,
                 bool fin) noexcept {
        assert((data != nullptr || len == 0) && "stream recv null");
        if (offset > kVarIntMax || len > kVarIntMax - offset) return false;
        const std::uint64_t end = offset + len;
        if (!flow_.recv_ok(end)) return false;                // §4.1 violation
        if (have_fin_ && (end > fin_off_ || (fin && end != fin_off_))) return false;
        if (fin && end < flow_.recv_high) return false;       // §4.5 final size
        if (end > read_cursor_ + kStreamBufferSize) return false;
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
    // Readable bytes up to the ring's physical end (recv_peek() spans these).
    std::size_t recv_contiguous() const noexcept {
        const std::size_t pos = static_cast<std::size_t>(read_cursor_ % kStreamBufferSize);
        const std::size_t avail = recv_available();
        assert(pos < kStreamBufferSize && "read cursor oob");
        return (avail < kStreamBufferSize - pos) ? avail : kStreamBufferSize - pos;
    }
    const std::uint8_t* recv_peek() const noexcept {
        const std::size_t pos = static_cast<std::size_t>(read_cursor_ % kStreamBufferSize);
        assert(pos < kStreamBufferSize && "read cursor oob");
        return recv_buf_ + pos;
    }
    void recv_consume(std::size_t n) noexcept {
        assert(read_cursor_ + n <= recv_cursor_ && "consume past contiguous");
        assert(n <= kStreamBufferSize && "consume larger than ring");
        read_cursor_ += n;
    }
    bool recv_finished() const noexcept {
        return have_fin_ && read_cursor_ >= fin_off_;
    }
    bool fin_received() const noexcept { return have_fin_; }

    // True exactly once, when the final byte has been read.
    bool take_fin_notice() noexcept {
        if (!recv_finished() || fin_notified_) return false;
        fin_notified_ = true;
        assert(have_fin_ && "fin notice without a FIN");
        return true;
    }

    // Our MAX_STREAM_DATA for this stream must be (re)sent.
    void mark_window_dirty() noexcept { window_dirty_ = true; }
    void clear_window_dirty() noexcept { window_dirty_ = false; }
    bool window_dirty() const noexcept { return window_dirty_; }

    // The peer reset its send side: nothing more will be read.
    void on_peer_reset() noexcept {
        assert(in_use_ && "reset on a free stream");
        recv_reset_ = true;
        recv_st_ = RecvState::kResetRecvd;
    }
    bool recv_done() const noexcept { return recv_reset_ || recv_finished(); }

    // Whether our advertised recv window should be bumped (consumed enough).
    bool needs_window_update(std::uint64_t bump_threshold) const noexcept {
        assert(bump_threshold > 0 && "zero threshold");
        return (flow_.recv_max - read_cursor_) < bump_threshold &&
               !recv_finished() && !recv_reset_;
    }
    std::uint64_t grow_recv_window(std::uint64_t add) noexcept {
        assert(add > 0 && "zero window grow");
        if (add > kStreamBufferSize) add = kStreamBufferSize;
        const std::uint64_t next = read_cursor_ + add;
        if (next > flow_.recv_max) flow_.recv_max = next;
        assert(flow_.recv_max <= read_cursor_ + kStreamBufferSize && "window > ring");
        return flow_.recv_max;
    }

private:
    // Bounded set of disjoint [start,end) extents above a contiguous cursor.
    struct ExtentSet {
        struct Extent { std::uint64_t start = 0; std::uint64_t end = 0; };
        Extent ext[kMaxRecvExtents]{};
        std::size_t count = 0;

        // Record [s,e); merges overlaps. False when the set is full.
        bool add(std::uint64_t s, std::uint64_t e) noexcept {
            assert(s < e && "empty extent");
            assert(count <= kMaxRecvExtents && "extent set overflow");
            for (std::size_t i = 0; i < count; ++i) {
                if (s <= ext[i].end && e >= ext[i].start) {
                    if (s < ext[i].start) ext[i].start = s;
                    if (e > ext[i].end) ext[i].end = e;
                    return true;
                }
            }
            if (count >= kMaxRecvExtents) return false;
            ext[count].start = s;
            ext[count].end = e;
            ++count;
            return true;
        }
        // Advance `cursor` over extents it now reaches; drop consumed ones.
        std::uint64_t absorb(std::uint64_t cursor) noexcept {
            for (std::size_t round = 0; round <= kMaxRecvExtents; ++round) {
                bool progressed = false;
                for (std::size_t i = 0; i < count; ++i) {
                    if (ext[i].start <= cursor) {
                        if (ext[i].end > cursor) cursor = ext[i].end;
                        ext[i] = ext[--count];
                        progressed = true;
                        break;
                    }
                }
                if (!progressed) break;
            }
            assert(count <= kMaxRecvExtents && "extent set overflow");
            return cursor;
        }
    };

    // Copy into the send ring (wrapping). Returns bytes stored.
    std::size_t ring_put(const std::uint8_t* data, std::size_t len) noexcept {
        assert(send_end_ - send_base_ <= kStreamBufferSize && "send ring overrun");
        const std::size_t space =
            kStreamBufferSize - static_cast<std::size_t>(send_end_ - send_base_);
        const std::size_t n = (len < space) ? len : space;
        const std::size_t pos = static_cast<std::size_t>(send_end_ % kStreamBufferSize);
        const std::size_t first = (n < kStreamBufferSize - pos) ? n : kStreamBufferSize - pos;
        if (first > 0) std::memcpy(send_buf_ + pos, data, first);
        if (n > first) std::memcpy(send_buf_, data + first, n - first);
        send_end_ += n;
        assert(send_end_ - send_base_ <= kStreamBufferSize && "ring_put overflow");
        return n;
    }

    // Store bytes into the receive ring, advancing the contiguous cursor.
    bool store(std::uint64_t offset, const std::uint8_t* data,
               std::size_t len) noexcept {
        assert(offset + len <= read_cursor_ + kStreamBufferSize && "store overflow");
        std::size_t from = 0;
        std::uint64_t at = offset;
        if (offset < recv_cursor_) {
            const std::uint64_t skip = recv_cursor_ - offset;
            if (skip >= len) return true;  // wholly duplicate
            from = static_cast<std::size_t>(skip);
            at = recv_cursor_;
        }
        const std::size_t n = len - from;
        const std::size_t pos = static_cast<std::size_t>(at % kStreamBufferSize);
        const std::size_t first = (n < kStreamBufferSize - pos) ? n : kStreamBufferSize - pos;
        std::memcpy(recv_buf_ + pos, data + from, first);
        if (n > first) std::memcpy(recv_buf_, data + from + first, n - first);
        if (at == recv_cursor_) {
            recv_cursor_ = at + n;
        } else if (!recv_ext_.add(at, at + n)) {
            return false;  // too much reorder
        }
        recv_cursor_ = recv_ext_.absorb(recv_cursor_);
        assert(recv_cursor_ <= read_cursor_ + kStreamBufferSize && "cursor oob");
        return true;
    }

    std::uint64_t id_ = 0;
    bool in_use_ = false;
    bool bidi_ = true;
    SendState send_st_ = SendState::kReady;
    RecvState recv_st_ = RecvState::kRecv;
    StreamFlow flow_{};

    // send side (absolute offsets; ring index = offset % kStreamBufferSize)
    std::uint8_t* send_buf_ = nullptr;  // kStreamBufferSize ring (owner-supplied)
    std::uint64_t send_base_ = 0;    // lowest unacknowledged byte
    std::uint64_t send_end_ = 0;     // total queued
    std::uint64_t send_sent_ = 0;    // frontier framed into packets
    std::uint64_t flow_counted_ = 0; // high-water counted toward conn flow ctrl
    ExtentSet ack_ext_{};            // acked spans above send_base_
    bool want_fin_ = false;
    bool fin_sent_ = false;
    bool fin_acked_ = false;
    std::string pending_;            // bytes waiting for ring space
    std::size_t pending_off_ = 0;
    bool pending_fin_ = false;

    // receive side
    std::uint8_t* recv_buf_ = nullptr;  // kStreamBufferSize ring (owner-supplied)
    std::uint64_t recv_cursor_ = 0;  // highest contiguous offset received
    std::uint64_t read_cursor_ = 0;  // delivered to the app
    std::uint64_t fin_off_ = 0;
    bool have_fin_ = false;
    bool fin_notified_ = false;
    bool window_dirty_ = false;
    bool recv_reset_ = false;
    ExtentSet recv_ext_{};
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
