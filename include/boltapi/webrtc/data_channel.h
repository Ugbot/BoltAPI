// boltapi/webrtc/data_channel.h — DCEP (RFC 8832) + the App-facing data-channel
// surface over a Bolt-native SCTP association.
//
// ============================================================================
// LAYERING
// ============================================================================
//   App::on_data_channel(label, handler)
//        ^                                     (App surface, app.h)
//        | DataChannelStack delivers on_open/on_message, routes send()
//        |
//   DataChannelStack  ── owns ─►  SctpAssociation  ── sink ─►  DtlsSession::send_app
//        |  parses/builds DCEP (DATA_CHANNEL_OPEN PPID 50 -> _ACK PPID 51)
//        |  maps SCTP DATA (PPID 51 string / 53 binary / 56/57 empty) to messages
//        v
//   DataChannel (concrete IDataChannel: send_text/send_binary/close + callbacks)
//
// FLOW (Bolt is the answerer = SCTP passive):
//   1. Peer's DTLS app-data -> DataChannelStack::feed -> SctpAssociation::feed.
//   2. Handshake completes (INIT..COOKIE-ACK). Peer sends DATA_CHANNEL_OPEN
//      (DCEP, PPID 50) on a stream with a label/protocol/reliability.
//   3. We create a DataChannel for that stream, reply DATA_CHANNEL_ACK (PPID 51),
//      look up the App's registered handler (by exact label, else the "" wildcard
//      handler), invoke on_open, and route subsequent DATA (PPID 51/53/56/57) to
//      on_message.
//   4. channel.send_text/binary -> SCTP DATA (PPID 51/53) -> DTLS -> UDP.
//
// The ACTIVE side (the test client) can call open_channel(label) to emit a
// DATA_CHANNEL_OPEN itself, mirroring browser createDataChannel.
//
// TigerStyle: bounded channel table, noexcept hot paths, no exceptions, explicit
// teardown. Compiled UNCONDITIONALLY (no engine deps). DEFERRED: unordered /
// partial-reliability channel types (mapped to reliable/ordered in v1).

#pragma once

#include "boltapi/webrtc/sctp.h"
#include "boltapi/protocol.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>

namespace bolt::api {
namespace webrtc {

class DataChannelStack;

// ----------------------------------------------------------------------------
// DataChannel — a concrete IDataChannel backed by one SCTP stream + DCEP state.
// ----------------------------------------------------------------------------
class DataChannel : public proto::IDataChannel {
public:
    using MessageHandler = std::function<void(const void* data, std::size_t len,
                                              bool is_binary)>;
    using OpenHandler    = std::function<void()>;
    using CloseHandler   = std::function<void()>;

    DataChannel(DataChannelStack& stack, std::uint16_t stream_id,
                std::string label, std::string protocol,
                SctpReliability reliability = SctpReliability::reliable()) noexcept;
    ~DataChannel() override = default;

    DataChannel(const DataChannel&) = delete;
    DataChannel& operator=(const DataChannel&) = delete;

    // IDataChannel surface.
    const char* label() const noexcept override { return label_.c_str(); }
    proto::Status send(const void* data, std::size_t len) override;  // binary
    void close() noexcept override;

    // Convenience typed sends.
    bool send_text(std::string_view text) noexcept;
    bool send_binary(const void* data, std::size_t len) noexcept;

    std::uint16_t stream_id() const noexcept { return stream_id_; }
    const std::string& protocol() const noexcept { return protocol_; }
    bool is_open() const noexcept { return open_; }
    const SctpReliability& reliability() const noexcept { return reliability_; }
    void set_reliability(const SctpReliability& r) noexcept { reliability_ = r; }

    // Callbacks (set by the App wiring when the handler fires).
    void on_message(MessageHandler h) noexcept { on_message_ = std::move(h); }
    void on_open(OpenHandler h) noexcept { on_open_ = std::move(h); }
    void on_close(CloseHandler h) noexcept { on_close_ = std::move(h); }

    // Internal: invoked by the stack.
    void deliver_message(const void* data, std::size_t len, bool is_binary) noexcept;
    void mark_open() noexcept;
    void mark_closed() noexcept;

private:
    DataChannelStack* stack_;
    std::uint16_t     stream_id_;
    std::string       label_;
    std::string       protocol_;
    SctpReliability   reliability_;
    bool              open_ = false;

    MessageHandler    on_message_;
    OpenHandler       on_open_;
    CloseHandler      on_close_;
};

// ----------------------------------------------------------------------------
// DataChannelStack — DCEP + channel routing over an SctpAssociation.
//
// One per peer/DTLS session. The owner (App) configures:
//   * the SCTP packet sink (DtlsSession::send_app),
//   * a channel-open callback invoked when a new channel is established, so the
//     App can attach on_message/on_open/on_close (and check the registered
//     label).
// ----------------------------------------------------------------------------
class DataChannelStack {
public:
    // Invoked when a channel is established (incoming DATA_CHANNEL_OPEN, or our
    // own open + ACK). The App uses this to wire callbacks on the channel.
    using ChannelOpenCallback = std::function<void(DataChannel& ch)>;

    DataChannelStack() noexcept = default;
    ~DataChannelStack() = default;

    DataChannelStack(const DataChannelStack&) = delete;
    DataChannelStack& operator=(const DataChannelStack&) = delete;

    // Configure. `sink` ships SCTP packets (DtlsSession::send_app wrapper);
    // role = Passive for the answerer (Bolt), Active for the test client.
    void init(SctpAssociation::Role role, SctpPacketSink sink,
              ChannelOpenCallback on_channel) noexcept;

    // ACTIVE side: begin the SCTP handshake (emit INIT). Passive: no-op.
    bool connect() noexcept { return assoc_.connect(); }

    // Feed inbound decrypted DTLS app-data (one SCTP packet) into the stack.
    bool feed(const std::uint8_t* data, std::size_t len) noexcept;

    // ACTIVE side: open a new data channel with `label` on the next free stream.
    // Emits DATA_CHANNEL_OPEN once the association is Established. Returns the
    // channel (owned by the stack) or nullptr on failure. `reliability` controls
    // ordering + partial reliability (mapped to the DCEP channel type byte).
    DataChannel* open_channel(std::string label, std::string protocol = "",
                              SctpReliability reliability =
                                  SctpReliability::reliable()) noexcept;

    // Drive retransmits + RTO + partial-reliability timers (passthrough).
    std::size_t tick_retransmit() noexcept { return assoc_.tick(0); }
    std::size_t tick(std::uint64_t now_ms = 0) noexcept { return assoc_.tick(now_ms); }

    SctpAssociation& association() noexcept { return assoc_; }
    bool established() const noexcept { return assoc_.established(); }

    // Send a user message on a stream (used by DataChannel). is_binary picks the
    // PPID; empty payloads use the empty-* PPIDs. `reliability` is the channel's
    // ordering + partial-reliability policy (plumbed into the SCTP send path).
    bool send_on_stream(std::uint16_t stream_id, const void* data,
                        std::size_t len, bool is_binary,
                        const SctpReliability& reliability =
                            SctpReliability::reliable()) noexcept;

    // Lookup / count for tests + App introspection.
    DataChannel* channel_for_stream(std::uint16_t stream_id) noexcept;
    std::size_t  channel_count() const noexcept { return channel_count_; }

private:
    static constexpr std::size_t kMaxChannels = kSctpMaxStreams;

    struct Slot {
        bool used = false;
        std::uint16_t stream_id = 0;
        std::unique_ptr<DataChannel> ch;
    };

    void on_sctp_message(const SctpRecvMessage& msg) noexcept;
    void handle_dcep(std::uint16_t stream_id, const std::uint8_t* data,
                     std::size_t len) noexcept;
    DataChannel* create_channel(std::uint16_t stream_id, std::string label,
                                std::string protocol,
                                SctpReliability reliability =
                                    SctpReliability::reliable()) noexcept;
    bool send_dcep_open(std::uint16_t stream_id, std::string_view label,
                        std::string_view protocol,
                        const SctpReliability& reliability) noexcept;
    bool send_dcep_ack(std::uint16_t stream_id) noexcept;

    SctpAssociation     assoc_;
    ChannelOpenCallback on_channel_;
    SctpAssociation::Role role_ = SctpAssociation::Role::Passive;

    Slot         channels_[kMaxChannels];
    std::size_t  channel_count_ = 0;
    std::uint16_t next_active_stream_ = 0;  // even=client, odd=server (RFC 8832)

    // Pending opens initiated by the active side before Established: emit on
    // handshake completion. Bounded.
    struct PendingOpen {
        bool used = false;
        std::uint16_t stream_id = 0;
        std::string label;
        std::string protocol;
        SctpReliability reliability;
    };
    static constexpr std::size_t kMaxPending = 16;
    PendingOpen pending_[kMaxPending];
    bool        flushed_pending_ = false;
};

}  // namespace webrtc
}  // namespace bolt::api
