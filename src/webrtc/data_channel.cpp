// src/webrtc/data_channel.cpp — DCEP (RFC 8832) + data-channel routing over the
// Bolt-native SctpAssociation. See include/boltapi/webrtc/data_channel.h.

#include "boltapi/webrtc/data_channel.h"

#include <cstring>

namespace bolt::api {
namespace webrtc {

namespace {

inline std::uint16_t rd16(const std::uint8_t* p) noexcept {
    return static_cast<std::uint16_t>((p[0] << 8) | p[1]);
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

}  // namespace

// ===========================================================================
// DataChannel
// ===========================================================================
DataChannel::DataChannel(DataChannelStack& stack, std::uint16_t stream_id,
                         std::string label, std::string protocol) noexcept
    : stack_(&stack), stream_id_(stream_id),
      label_(std::move(label)), protocol_(std::move(protocol)) {}

proto::Status DataChannel::send(const void* data, std::size_t len) {
    if (!open_) return proto::Status(core::error_code::invalid_state);
    return send_binary(data, len) ? proto::ok_status()
                                  : proto::Status(core::error_code::invalid_state);
}

bool DataChannel::send_text(std::string_view text) noexcept {
    if (!open_ || !stack_) return false;
    return stack_->send_on_stream(stream_id_, text.data(), text.size(), false);
}

bool DataChannel::send_binary(const void* data, std::size_t len) noexcept {
    if (!open_ || !stack_) return false;
    return stack_->send_on_stream(stream_id_, data, len, true);
}

void DataChannel::close() noexcept {
    if (!open_) return;
    open_ = false;
    if (on_close_) on_close_();
}

void DataChannel::deliver_message(const void* data, std::size_t len,
                                  bool is_binary) noexcept {
    if (on_message_) on_message_(data, len, is_binary);
}

void DataChannel::mark_open() noexcept {
    if (open_) return;
    open_ = true;
    if (on_open_) on_open_();
}

void DataChannel::mark_closed() noexcept {
    if (!open_) return;
    open_ = false;
    if (on_close_) on_close_();
}

// ===========================================================================
// DataChannelStack
// ===========================================================================
void DataChannelStack::init(SctpAssociation::Role role, SctpPacketSink sink,
                            ChannelOpenCallback on_channel) noexcept {
    role_ = role;
    on_channel_ = std::move(on_channel);
    assoc_.init(role, std::move(sink),
                [this](const SctpRecvMessage& m) { on_sctp_message(m); });
}

bool DataChannelStack::feed(const std::uint8_t* data, std::size_t len) noexcept {
    const bool ok = assoc_.feed(data, len);
    // On reaching Established, flush any pending active-side opens.
    if (assoc_.established() && !flushed_pending_) {
        flushed_pending_ = true;
        for (std::size_t i = 0; i < kMaxPending; ++i) {
            PendingOpen& p = pending_[i];
            if (p.used) {
                create_channel(p.stream_id, p.label, p.protocol);
                send_dcep_open(p.stream_id, p.label, p.protocol);
                p.used = false;
            }
        }
    }
    return ok;
}

DataChannel* DataChannelStack::channel_for_stream(std::uint16_t stream_id) noexcept {
    for (std::size_t i = 0; i < kMaxChannels; ++i) {
        if (channels_[i].used && channels_[i].stream_id == stream_id) {
            return channels_[i].ch.get();
        }
    }
    return nullptr;
}

DataChannel* DataChannelStack::create_channel(std::uint16_t stream_id,
                                              std::string label,
                                              std::string protocol) noexcept {
    DataChannel* existing = channel_for_stream(stream_id);
    if (existing) return existing;
    for (std::size_t i = 0; i < kMaxChannels; ++i) {
        Slot& s = channels_[i];
        if (!s.used) {
            s.used = true;
            s.stream_id = stream_id;
            s.ch = std::make_unique<DataChannel>(*this, stream_id,
                                                 std::move(label),
                                                 std::move(protocol));
            ++channel_count_;
            return s.ch.get();
        }
    }
    return nullptr;  // bounded
}

DataChannel* DataChannelStack::open_channel(std::string label,
                                            std::string protocol) noexcept {
    // RFC 8832 §6: the side that opens picks a stream id. The DTLS client (which
    // is the SCTP active side here) uses EVEN stream ids; passive uses ODD.
    std::uint16_t sid = next_active_stream_;
    if (role_ == SctpAssociation::Role::Active) {
        // even ids
        next_active_stream_ = static_cast<std::uint16_t>(sid + 2);
    } else {
        sid = static_cast<std::uint16_t>(sid | 1u);  // odd
        next_active_stream_ = static_cast<std::uint16_t>(sid + 2);
    }

    if (assoc_.established()) {
        DataChannel* ch = create_channel(sid, label, protocol);
        if (ch) send_dcep_open(sid, label, protocol);
        return ch;
    }
    // Defer until Established.
    for (std::size_t i = 0; i < kMaxPending; ++i) {
        if (!pending_[i].used) {
            pending_[i].used = true;
            pending_[i].stream_id = sid;
            pending_[i].label = std::move(label);
            pending_[i].protocol = std::move(protocol);
            // Return a channel object now so the caller can wire callbacks.
            return create_channel(sid, pending_[i].label, pending_[i].protocol);
        }
    }
    return nullptr;
}

void DataChannelStack::on_sctp_message(const SctpRecvMessage& msg) noexcept {
    if (msg.ppid == static_cast<std::uint32_t>(Ppid::Dcep)) {
        handle_dcep(msg.stream_id, msg.data, msg.len);
        return;
    }
    // User data: route to the channel for this stream.
    DataChannel* ch = channel_for_stream(msg.stream_id);
    if (!ch) {
        // Data arriving before/without DCEP open: create an implicit channel so
        // the message isn't dropped (some peers send data on the same packet).
        ch = create_channel(msg.stream_id, "", "");
        if (ch && on_channel_) on_channel_(*ch);
        if (ch) ch->mark_open();
    }
    if (!ch) return;

    const bool is_binary =
        msg.ppid == static_cast<std::uint32_t>(Ppid::Binary) ||
        msg.ppid == static_cast<std::uint32_t>(Ppid::BinaryEmpty);
    // Empty-* PPIDs carry one filler byte on the wire (RFC 8831); present them
    // to the App as a zero-length message.
    const bool is_empty =
        msg.ppid == static_cast<std::uint32_t>(Ppid::StringEmpty) ||
        msg.ppid == static_cast<std::uint32_t>(Ppid::BinaryEmpty);
    if (is_empty) {
        ch->deliver_message(msg.data, 0, is_binary);
    } else {
        ch->deliver_message(msg.data, msg.len, is_binary);
    }
}

void DataChannelStack::handle_dcep(std::uint16_t stream_id,
                                   const std::uint8_t* data,
                                   std::size_t len) noexcept {
    if (len < 1) return;
    const std::uint8_t mtype = data[0];

    if (mtype == kDcepAck) {
        // Our outgoing channel is acknowledged: surface it (so the owner can
        // attach on_message/on_open/on_close before delivery) then mark open.
        DataChannel* ch = channel_for_stream(stream_id);
        if (ch) {
            if (on_channel_) on_channel_(*ch);
            ch->mark_open();
        }
        return;
    }

    if (mtype != kDcepOpen) return;
    // DATA_CHANNEL_OPEN (RFC 8832 §5.1):
    //   type(1) channelType(1) priority(2) reliability(4) labelLen(2)
    //   protocolLen(2) label(labelLen) protocol(protocolLen)
    if (len < 12) return;
    const std::uint16_t label_len    = rd16(data + 8);
    const std::uint16_t protocol_len = rd16(data + 10);
    if (12 + static_cast<std::size_t>(label_len) +
        static_cast<std::size_t>(protocol_len) > len) return;

    std::string label(reinterpret_cast<const char*>(data + 12), label_len);
    std::string protocol(reinterpret_cast<const char*>(data + 12 + label_len),
                         protocol_len);

    DataChannel* ch = create_channel(stream_id, std::move(label),
                                     std::move(protocol));
    if (!ch) return;
    // Reply DATA_CHANNEL_ACK, surface to the App, then mark open.
    send_dcep_ack(stream_id);
    if (on_channel_) on_channel_(*ch);
    ch->mark_open();
}

bool DataChannelStack::send_dcep_open(std::uint16_t stream_id,
                                      std::string_view label,
                                      std::string_view protocol) noexcept {
    std::uint8_t buf[12 + 256];
    const std::size_t llen = label.size() > 200 ? 200 : label.size();
    const std::size_t plen = protocol.size() > 40 ? 40 : protocol.size();
    buf[0] = kDcepOpen;
    buf[1] = kDcepReliable;       // channel type: reliable, ordered (v1)
    wr16(buf + 2, 0);             // priority
    wr32(buf + 4, 0);             // reliability parameter (n/a for reliable)
    wr16(buf + 8, static_cast<std::uint16_t>(llen));
    wr16(buf + 10, static_cast<std::uint16_t>(plen));
    std::memcpy(buf + 12, label.data(), llen);
    std::memcpy(buf + 12 + llen, protocol.data(), plen);
    const std::size_t total = 12 + llen + plen;
    return assoc_.send(stream_id, static_cast<std::uint32_t>(Ppid::Dcep),
                       buf, total);
}

bool DataChannelStack::send_dcep_ack(std::uint16_t stream_id) noexcept {
    std::uint8_t ack = kDcepAck;
    return assoc_.send(stream_id, static_cast<std::uint32_t>(Ppid::Dcep),
                       &ack, 1);
}

bool DataChannelStack::send_on_stream(std::uint16_t stream_id, const void* data,
                                      std::size_t len, bool is_binary) noexcept {
    std::uint32_t ppid;
    if (is_binary) {
        ppid = static_cast<std::uint32_t>(len == 0 ? Ppid::BinaryEmpty
                                                   : Ppid::Binary);
    } else {
        ppid = static_cast<std::uint32_t>(len == 0 ? Ppid::StringEmpty
                                                   : Ppid::String);
    }
    // RFC 8831: an empty message still carries one byte on the wire so the
    // receiver can distinguish it; we send a single 0x00 with the empty PPID.
    if (len == 0) {
        const std::uint8_t z = 0;
        return assoc_.send(stream_id, ppid, &z, 1);
    }
    return assoc_.send(stream_id, ppid,
                       static_cast<const std::uint8_t*>(data), len);
}

}  // namespace webrtc
}  // namespace bolt::api
