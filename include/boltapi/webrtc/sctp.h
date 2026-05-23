// boltapi/webrtc/sctp.h — Bolt-native minimal SCTP over DTLS (RFC 4960 subset +
// RFC 8261 framing) and DCEP (RFC 8832), surfaced to App as data channels.
//
// ============================================================================
// WHAT THIS IS
// ============================================================================
// Browsers speak SCTP-over-DTLS for WebRTC data channels (RFC 8261: each SCTP
// packet rides as one DTLS *application* record). FasterAPI had NO SCTP. This is
// a focused, correctness-first, Bolt-native SCTP that implements ONLY the subset
// data channels need:
//
//   * Common header (ports, verification tag, CRC-32c) + chunk TLV framing.
//   * 4-way association handshake: INIT / INIT-ACK (state cookie) / COOKIE-ECHO
//     / COOKIE-ACK. Works as BOTH endpoints (passive answerer by default; active
//     for the test client), so a loopback test can run our stack on both ends.
//   * DATA chunk (TSN, stream id/seq, PPID, U/B/E flags) + SACK (cumulative TSN
//     ack + gap ack blocks). Reliable + ordered delivery for v1. Simple
//     threshold/timer retransmit on missing SACK.
//   * DCEP: DATA_CHANNEL_OPEN (PPID 50) -> DATA_CHANNEL_ACK (PPID 51); maps DATA
//     on a stream to channel messages (string PPID 51/53, binary, empty).
//
// TRANSPORT GLUE: SCTP does NOT own a socket. Outbound packets are handed to a
// caller-supplied sink (in production: DtlsSession::send_app -> the secure DTLS
// record layer -> UDP). Inbound DTLS app-data is handed to feed(). The standard
// WebRTC SCTP port is 5000 on both ends.
//
// DEFERRED (documented TODOs, not v1): unordered delivery, partial reliability
// (RFC 3758 / FORWARD-TSN), fragmentation/reassembly of >MTU messages,
// congestion control beyond a basic rwnd, multi-homing, HEARTBEAT keepalive.
//
// TigerStyle: bounded streams/queues (fixed arrays, no unbounded growth),
// preallocated per-association send/receive rings, noexcept hot paths, explicit
// teardown, asserts on bounds. CRC-32c uses bolt::io::crc32c (hardware path on
// MSVC x64) — see RFC 3309. Compiled UNCONDITIONALLY into boltapi (no engine
// deps beyond what's already linked); only App *start* wiring is gated by
// BOLTAPI_WITH_WEBRTC.

#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>

namespace bolt::api {
namespace webrtc {

// ----------------------------------------------------------------------------
// Bounds (TigerStyle: explicit, asserted at the boundaries).
// ----------------------------------------------------------------------------
inline constexpr std::uint16_t kSctpPort         = 5000;   // WebRTC standard
inline constexpr std::size_t   kSctpMaxPacket    = 1280;   // conservative MTU
inline constexpr std::size_t   kSctpMaxStreams   = 256;    // per association
inline constexpr std::size_t   kSctpSendQueue    = 256;    // in-flight DATA ring
inline constexpr std::size_t   kSctpRecvReorder  = 256;    // per-stream reorder
inline constexpr std::size_t   kSctpMaxUserData  = 1024;   // single-chunk msg cap
inline constexpr std::size_t   kSctpCookieLen    = 32;     // opaque state cookie
inline constexpr std::uint32_t kSctpInitialRwnd  = 256 * 1024;

// ----------------------------------------------------------------------------
// SCTP chunk types (RFC 4960 §3.2) — only the subset we implement.
// ----------------------------------------------------------------------------
enum class ChunkType : std::uint8_t {
    Data        = 0,
    Init        = 1,
    InitAck     = 2,
    Sack        = 3,
    Heartbeat   = 4,
    HeartbeatAck= 5,
    Abort       = 6,
    Shutdown    = 7,
    ShutdownAck = 8,
    Error       = 9,
    CookieEcho  = 10,
    CookieAck   = 11,
    ShutdownComplete = 14,
};

// DATA chunk flags (RFC 4960 §3.3.1): U(unordered) B(begin) E(end).
inline constexpr std::uint8_t kDataFlagEnd       = 0x01;
inline constexpr std::uint8_t kDataFlagBegin     = 0x02;
inline constexpr std::uint8_t kDataFlagUnordered = 0x04;

// ----------------------------------------------------------------------------
// WebRTC SCTP Payload Protocol Identifiers (RFC 8831 §8). DCEP rides PPID 50.
// ----------------------------------------------------------------------------
enum class Ppid : std::uint32_t {
    Dcep         = 50,  // DATA_CHANNEL_OPEN / _ACK
    String       = 51,  // UTF-8 text
    Binary       = 53,  // binary
    StringEmpty  = 56,  // empty string
    BinaryEmpty  = 57,  // empty binary
};

// ----------------------------------------------------------------------------
// DCEP message types (RFC 8832 §5.1).
// ----------------------------------------------------------------------------
inline constexpr std::uint8_t kDcepOpen = 0x03;  // DATA_CHANNEL_OPEN
inline constexpr std::uint8_t kDcepAck  = 0x02;  // DATA_CHANNEL_ACK

// DCEP channel types (RFC 8832 §5.1). v1 maps everything to reliable/ordered.
inline constexpr std::uint8_t kDcepReliable           = 0x00;
inline constexpr std::uint8_t kDcepReliableUnordered  = 0x80;

// ----------------------------------------------------------------------------
// CRC-32c (RFC 3309) over an SCTP packet with the checksum field zeroed. Uses
// bolt::io::crc32c (Castagnoli, reflected). Returned value is the on-wire
// checksum already in the byte order to store little-endian into the header.
// Defined in sctp.cpp (thin wrapper) so the bolt header is included once.
// ----------------------------------------------------------------------------
std::uint32_t sctp_crc32c(const std::uint8_t* packet, std::size_t len) noexcept;

// ----------------------------------------------------------------------------
// A parsed inbound DATA payload handed up to the association owner. `data` is a
// view into the receive scratch — valid only for the callback duration.
// ----------------------------------------------------------------------------
struct SctpRecvMessage {
    std::uint16_t stream_id = 0;
    std::uint32_t ppid      = 0;
    const std::uint8_t* data = nullptr;
    std::size_t   len       = 0;
};

// Sink that ships a fully-framed SCTP packet to the peer (in production:
// DtlsSession::send_app). Returns true if accepted.
using SctpPacketSink = std::function<bool(const std::uint8_t* pkt, std::size_t len)>;

// Delivered when an ordered, in-sequence user message is ready.
using SctpRecvHandler = std::function<void(const SctpRecvMessage& msg)>;

// ----------------------------------------------------------------------------
// SctpAssociation — one SCTP association over one DTLS channel.
//
// Role: passive (answerer/responder, default) or active (initiator — used by the
// test client). The active side calls connect() to emit INIT; the passive side
// reacts to an inbound INIT. Both converge to Established after the 4-way
// handshake, after which send() emits DATA and feed() delivers DATA upward.
// ----------------------------------------------------------------------------
class SctpAssociation {
public:
    enum class Role : std::uint8_t { Passive, Active };

    enum class State : std::uint8_t {
        Closed,
        CookieWait,      // active: sent INIT, awaiting INIT-ACK
        CookieEchoed,    // active: sent COOKIE-ECHO, awaiting COOKIE-ACK
        Established,
        Failed,
    };

    SctpAssociation() noexcept = default;
    ~SctpAssociation() = default;

    SctpAssociation(const SctpAssociation&) = delete;
    SctpAssociation& operator=(const SctpAssociation&) = delete;

    // Configure before driving: where outbound packets go and where ordered
    // inbound user messages are delivered. Role defaults to Passive.
    void init(Role role, SctpPacketSink sink, SctpRecvHandler on_recv) noexcept;

    State state() const noexcept { return state_; }
    bool established() const noexcept { return state_ == State::Established; }
    Role role() const noexcept { return role_; }

    // ACTIVE side: emit the INIT chunk to begin the handshake. No-op for passive.
    // Returns false if not configured / wrong role.
    bool connect() noexcept;

    // Feed one inbound SCTP packet (the decrypted DTLS app-data record). Parses
    // the common header (verifies CRC-32c) + chunks, advances the state machine,
    // delivers ordered DATA via the recv handler, and emits SACK/handshake
    // replies through the sink. noexcept; safe on malformed input. Returns false
    // only if the association has Failed.
    bool feed(const std::uint8_t* data, std::size_t len) noexcept;

    // ESTABLISHED: send a user message on `stream_id` with `ppid`. Frames a DATA
    // chunk into a packet and ships it via the sink (reliable+ordered). Returns
    // true if queued/sent. Bounded: drops (returns false) if the send ring is
    // full or the message exceeds kSctpMaxUserData.
    bool send(std::uint16_t stream_id, std::uint32_t ppid,
              const std::uint8_t* data, std::size_t len) noexcept;

    // Drive retransmits: if any in-flight DATA has not been SACK'd after the
    // threshold number of feed()-driven SACK opportunities, resend it. Called
    // opportunistically (e.g. from a timer). Returns the number retransmitted.
    std::size_t tick_retransmit() noexcept;

    // Verification tags (for tests / introspection).
    std::uint32_t local_tag() const noexcept { return local_tag_; }
    std::uint32_t peer_tag()  const noexcept { return peer_tag_; }

    // Counters.
    std::uint64_t data_in()  const noexcept { return data_in_; }
    std::uint64_t data_out() const noexcept { return data_out_; }

private:
    // --- packet building ---
    // Build a packet (common header + the chunk already written at `chunk` of
    // `chunk_len` into `out` after the 12-byte header), fix length/CRC, ship.
    bool ship_packet(std::uint8_t* out, std::size_t total_len) noexcept;
    void write_common_header(std::uint8_t* out, std::uint32_t verification_tag) noexcept;

    // --- handshake chunk emitters ---
    bool send_init() noexcept;
    bool send_init_ack(std::uint32_t peer_init_tag, std::uint32_t peer_init_tsn,
                       std::uint16_t peer_streams, std::uint32_t peer_rwnd) noexcept;
    bool send_cookie_echo(const std::uint8_t* cookie, std::size_t cookie_len) noexcept;
    bool send_cookie_ack() noexcept;
    bool send_sack() noexcept;
    bool send_abort() noexcept;

    // --- chunk handlers (return false on fatal parse error) ---
    void handle_init(const std::uint8_t* chunk, std::size_t len) noexcept;
    void handle_init_ack(const std::uint8_t* chunk, std::size_t len) noexcept;
    void handle_cookie_echo(const std::uint8_t* chunk, std::size_t len) noexcept;
    void handle_cookie_ack(const std::uint8_t* chunk, std::size_t len) noexcept;
    void handle_data(const std::uint8_t* chunk, std::size_t len) noexcept;
    void handle_sack(const std::uint8_t* chunk, std::size_t len) noexcept;

    // Deliver any now-in-order buffered messages for `stream_id`, advancing SSN.
    void deliver_in_order(std::uint16_t stream_id) noexcept;

    // --- in-flight DATA bookkeeping (the send/retransmit ring) ---
    struct OutChunk {
        bool          used = false;
        bool          acked = false;
        std::uint32_t tsn = 0;
        std::uint32_t miss_count = 0;       // SACK opportunities seen w/o ack
        std::size_t   len = 0;              // framed packet length
        std::uint8_t  packet[kSctpMaxPacket]{};  // full framed packet (re-shippable)
    };

    // --- per-stream receive reorder state (ordered delivery) ---
    struct InStream {
        std::uint16_t next_ssn = 0;        // next SSN to deliver
    };

    // A buffered out-of-order received message awaiting in-order delivery.
    struct InPending {
        bool          used = false;
        std::uint16_t stream_id = 0;
        std::uint16_t ssn = 0;
        std::uint32_t ppid = 0;
        std::size_t   len = 0;
        std::uint8_t  data[kSctpMaxUserData]{};
    };

    Role           role_  = Role::Passive;
    State          state_ = State::Closed;

    SctpPacketSink   sink_;
    SctpRecvHandler  on_recv_;

    std::uint16_t  src_port_ = kSctpPort;
    std::uint16_t  dst_port_ = kSctpPort;

    std::uint32_t  local_tag_ = 0;   // our verification tag (peer must echo)
    std::uint32_t  peer_tag_  = 0;   // peer's verification tag (we echo it)

    std::uint32_t  next_tsn_   = 0;  // next outbound DATA TSN
    std::uint32_t  cum_ack_in_ = 0;  // highest contiguous inbound TSN we've acked
    bool           have_cum_ack_ = false;
    std::uint32_t  peer_init_tsn_ = 0;
    std::uint32_t  local_init_tsn_ = 0;

    std::uint16_t  out_ssn_[kSctpMaxStreams]{};  // next outbound SSN per stream

    std::uint32_t  peer_rwnd_ = kSctpInitialRwnd;

    // Saved cookie for the passive side (echoed by peer in COOKIE-ECHO) — we
    // generate it deterministically from our tag so we can validate statelessly.
    std::uint8_t   cookie_[kSctpCookieLen]{};

    OutChunk   out_ring_[kSctpSendQueue];
    InStream   in_streams_[kSctpMaxStreams];
    InPending  in_pending_[kSctpRecvReorder];

    std::uint64_t  data_in_  = 0;
    std::uint64_t  data_out_ = 0;
};

}  // namespace webrtc
}  // namespace bolt::api
