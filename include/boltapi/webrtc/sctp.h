// boltapi/webrtc/sctp.h — Bolt-native SCTP over DTLS (RFC 4960 subset +
// RFC 8261 framing) and DCEP (RFC 8832), surfaced to App as data channels.
//
// ============================================================================
// WHAT THIS IS
// ============================================================================
// Browsers speak SCTP-over-DTLS for WebRTC data channels (RFC 8261: each SCTP
// packet rides as one DTLS *application* record). This is a focused,
// correctness-first, Bolt-native SCTP that implements the subset data channels
// need, hardened for real browser traffic:
//
//   * Common header (ports, verification tag, CRC-32c) + chunk TLV framing.
//   * 4-way association handshake: INIT / INIT-ACK (state cookie) / COOKIE-ECHO
//     / COOKIE-ACK. Works as BOTH endpoints (passive answerer by default; active
//     for the test client), so a loopback test can run our stack on both ends.
//   * DATA chunk (TSN, stream id/seq, PPID, U/B/E flags) + SACK (cumulative TSN
//     ack + GAP-ACK blocks). Reliable+ordered AND unordered delivery.
//   * MESSAGE FRAGMENTATION / REASSEMBLY (RFC 4960 §6.9): outbound messages
//     larger than kSctpMaxChunkData are split across consecutive-TSN DATA chunks
//     with B/M/E flags; inbound chunks are reassembled per stream into the full
//     user message before delivery. Bounded reassembly (cap per assoc), ABORT on
//     overflow — never unbounded. Handles browser messages up to 256 KiB.
//   * PARTIAL RELIABILITY (RFC 3758): the sender abandons a message (per
//     max_retransmits or max_lifetime from the DCEP channel) and emits
//     FORWARD-TSN; the receiver advances cumulative TSN past abandoned fragments.
//   * RTO + CONGESTION CONTROL (RFC 6298 + RFC 4960 §7): SRTT/RTTVAR, RTO
//     min/max + exponential backoff + Karn's algorithm; cwnd/ssthresh, slow
//     start + congestion avoidance, fast retransmit on 3 dup gap reports, T3-rtx
//     on timeout. We emit our OWN gap-ack blocks so the peer can fast-retransmit.
//   * DCEP: DATA_CHANNEL_OPEN (PPID 50) -> DATA_CHANNEL_ACK (PPID 51); maps DATA
//     on a stream to channel messages (string PPID 51/53, binary, empty), and
//     plumbs the per-channel reliability params into the send path.
//
// TRANSPORT GLUE: SCTP does NOT own a socket. Outbound packets are handed to a
// caller-supplied sink (in production: DtlsSession::send_app -> the secure DTLS
// record layer -> UDP). Inbound DTLS app-data is handed to feed(). The standard
// WebRTC SCTP port is 5000 on both ends.
//
// TIME: the assoc is driven by a monotonic millisecond clock supplied to feed()
// / tick() (default: an internal steady_clock read) so RTO is testable with a
// deterministic injected clock.
//
// DEFERRED (documented TODOs): multi-homing, HEARTBEAT keepalive, SACK
// duplicate-TSN reporting, stream reset (RFC 6525).
//
// TigerStyle: bounded streams/queues (fixed arrays, no unbounded growth),
// preallocated per-association send/receive/reassembly buffers, noexcept hot
// paths, explicit teardown, asserts on bounds, graceful ABORT on overflow (no
// UB). CRC-32c uses bolt::io::crc32c (hardware path on MSVC x64) — see RFC 3309.

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
// Per-DATA-chunk user payload cap. The on-wire packet is 12 (common hdr) +
// 16 (DATA hdr) + payload; with a conservative 1100 B payload we stay well
// under kSctpMaxPacket (1280) leaving room for DTLS record overhead upstream.
inline constexpr std::size_t   kSctpMaxChunkData = 1100;
// Largest single user message we will send or reassemble. Browsers send data
// channel messages up to 256 KiB (RFC 8831). We support exactly that.
inline constexpr std::size_t   kSctpMaxMessage   = 256 * 1024;
// In-flight DATA ring: each slot is one fragment (chunk). A 256 KiB message is
// ~239 chunks at 1100 B, so the ring must hold at least that plus headroom.
inline constexpr std::size_t   kSctpSendQueue    = 512;
// Bounded reassembly: how many partially-reassembled messages can be in flight
// across all streams at once, and the cap on total bytes buffered.
inline constexpr std::size_t   kSctpMaxReasm     = 8;       // concurrent partial msgs
inline constexpr std::size_t   kSctpReasmBytes   = 2 * kSctpMaxMessage;  // total cap
// Per-stream ordered reorder ring: how many completed-but-early messages we
// hold awaiting their in-order SSN.
inline constexpr std::size_t   kSctpRecvReorder  = 64;
inline constexpr std::size_t   kSctpCookieLen    = 32;     // opaque state cookie
inline constexpr std::uint32_t kSctpInitialRwnd  = 1024 * 1024;  // our advertised rwnd

// RTO / congestion-control constants (RFC 6298 + RFC 4960 §7.2).
inline constexpr std::uint32_t kSctpRtoInitialMs = 1000;
inline constexpr std::uint32_t kSctpRtoMinMs     = 100;    // RFC 4960 RTO.Min=1s; we
                                                           // use 100ms for snappy loopback
inline constexpr std::uint32_t kSctpRtoMaxMs     = 8000;
inline constexpr std::uint32_t kSctpRtoAlphaShift= 3;      // alpha = 1/8
inline constexpr std::uint32_t kSctpRtoBetaShift = 2;      // beta  = 1/4
inline constexpr std::uint32_t kSctpFastRtxDup   = 3;      // 3 missing reports -> fast rtx
inline constexpr std::uint32_t kSctpMaxAssocRtx  = 10;     // assoc dead after this many
                                                           // consecutive T3 timeouts

// ----------------------------------------------------------------------------
// SCTP chunk types (RFC 4960 §3.2 + RFC 3758) — only the subset we implement.
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
    ForwardTsn  = 192,  // 0xC0 (RFC 3758 §3.2)
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

// DCEP channel types (RFC 8832 §5.1).
inline constexpr std::uint8_t kDcepReliable             = 0x00;
inline constexpr std::uint8_t kDcepPartialRexmit        = 0x01;  // max_retransmits
inline constexpr std::uint8_t kDcepPartialTimed         = 0x02;  // max_lifetime
inline constexpr std::uint8_t kDcepReliableUnordered    = 0x80;
inline constexpr std::uint8_t kDcepPartialRexmitUnord   = 0x81;
inline constexpr std::uint8_t kDcepPartialTimedUnord    = 0x82;

// Per-message reliability policy (plumbed from DCEP into the send path).
struct SctpReliability {
    bool          unordered      = false;
    bool          rexmit_limited = false;  // abandon after max_retransmits
    bool          time_limited   = false;  // abandon after max_lifetime_ms
    std::uint32_t max_retransmits = 0;
    std::uint32_t max_lifetime_ms = 0;

    static SctpReliability reliable(bool unordered = false) noexcept {
        SctpReliability r; r.unordered = unordered; return r;
    }
};

// ----------------------------------------------------------------------------
// CRC-32c (RFC 3309) over an SCTP packet with the checksum field zeroed. Uses
// bolt::io::crc32c (Castagnoli, reflected). Returned value is stored
// little-endian into the header by the caller.
// ----------------------------------------------------------------------------
std::uint32_t sctp_crc32c(const std::uint8_t* packet, std::size_t len) noexcept;

// ----------------------------------------------------------------------------
// A fully-reassembled inbound user message handed up to the association owner.
// `data` points into the association's reassembly/scratch buffer — valid only
// for the callback duration.
// ----------------------------------------------------------------------------
struct SctpRecvMessage {
    std::uint16_t stream_id = 0;
    std::uint32_t ppid      = 0;
    const std::uint8_t* data = nullptr;
    std::size_t   len       = 0;
};

// Sink that ships a fully-framed SCTP packet to the peer. Returns true if accepted.
using SctpPacketSink = std::function<bool(const std::uint8_t* pkt, std::size_t len)>;

// Delivered when a full user message is ready (ordered in-sequence or unordered).
using SctpRecvHandler = std::function<void(const SctpRecvMessage& msg)>;

// ----------------------------------------------------------------------------
// SctpAssociation — one SCTP association over one DTLS channel.
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
    ~SctpAssociation();

    SctpAssociation(const SctpAssociation&) = delete;
    SctpAssociation& operator=(const SctpAssociation&) = delete;

    void init(Role role, SctpPacketSink sink, SctpRecvHandler on_recv) noexcept;

    State state() const noexcept { return state_; }
    bool established() const noexcept { return state_ == State::Established; }
    Role role() const noexcept { return role_; }

    bool connect() noexcept;

    // Feed one inbound SCTP packet (decrypted DTLS app-data). `now_ms` is a
    // monotonic millisecond clock (0 -> read internal steady clock). noexcept.
    bool feed(const std::uint8_t* data, std::size_t len, std::uint64_t now_ms = 0) noexcept;

    // ESTABLISHED: send a user message on `stream_id` with `ppid`. Fragments if
    // larger than kSctpMaxChunkData. Reliability controls ordering + partial
    // reliability. Returns true if fully queued (subject to cwnd/window: queued
    // chunks are flushed as the window opens). Bounded: false if the send ring
    // is full or len > kSctpMaxMessage.
    bool send(std::uint16_t stream_id, std::uint32_t ppid,
              const std::uint8_t* data, std::size_t len,
              const SctpReliability& rel = SctpReliability::reliable(),
              std::uint64_t now_ms = 0) noexcept;

    // Drive timers: RTO expiry (T3-rtx), partial-reliability abandonment +
    // FORWARD-TSN, and flushing queued DATA as cwnd opens. `now_ms` as in feed().
    // Returns the number of chunks retransmitted/sent.
    std::size_t tick(std::uint64_t now_ms = 0) noexcept;

    // Backwards-compatible alias used by older callers/tests.
    std::size_t tick_retransmit() noexcept { return tick(0); }

    // Verification tags (for tests / introspection).
    std::uint32_t local_tag() const noexcept { return local_tag_; }
    std::uint32_t peer_tag()  const noexcept { return peer_tag_; }

    // Counters / introspection.
    std::uint64_t data_in()  const noexcept { return data_in_; }   // user messages delivered
    std::uint64_t data_out() const noexcept { return data_out_; }  // user messages accepted
    std::uint64_t chunks_retransmitted() const noexcept { return rtx_count_; }
    std::uint32_t cwnd() const noexcept { return cwnd_; }
    std::uint32_t ssthresh() const noexcept { return ssthresh_; }
    std::uint32_t rto_ms() const noexcept { return rto_ms_; }
    std::uint32_t flight_size() const noexcept { return flight_size_; }

private:
    // --- packet building ---
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
    bool send_forward_tsn() noexcept;

    // --- chunk handlers ---
    void handle_init(const std::uint8_t* chunk, std::size_t len) noexcept;
    void handle_init_ack(const std::uint8_t* chunk, std::size_t len) noexcept;
    void handle_cookie_echo(const std::uint8_t* chunk, std::size_t len) noexcept;
    void handle_cookie_ack(const std::uint8_t* chunk, std::size_t len) noexcept;
    void handle_data(const std::uint8_t* chunk, std::size_t len) noexcept;
    void handle_sack(const std::uint8_t* chunk, std::size_t len) noexcept;
    void handle_forward_tsn(const std::uint8_t* chunk, std::size_t len) noexcept;

    // --- receive path ---
    void on_full_message(std::uint16_t sid, std::uint32_t ppid, bool unordered,
                         std::uint16_t ssn, const std::uint8_t* data,
                         std::size_t len) noexcept;
    void deliver_ordered(std::uint16_t stream_id) noexcept;
    void advance_cum_ack() noexcept;     // walk received-bitmap to extend cum_ack_in_
    bool record_received(std::uint32_t tsn) noexcept;  // mark TSN seen; false if dup/old
    bool tsn_received(std::uint32_t tsn) const noexcept;

    // --- send path ---
    bool enqueue_chunk(std::uint16_t sid, std::uint32_t ppid, std::uint8_t flags,
                       std::uint16_t ssn, std::uint32_t tsn,
                       const std::uint8_t* data, std::size_t len,
                       const SctpReliability& rel, std::uint64_t now_ms) noexcept;
    std::size_t flush_send(std::uint64_t now_ms) noexcept;  // ship eligible queued chunks
    void on_data_acked(std::size_t slot, std::uint64_t now_ms) noexcept;
    void on_t3_timeout(std::uint64_t now_ms) noexcept;
    void abandon_expired(std::uint64_t now_ms) noexcept;    // partial reliability
    void update_rto(std::uint32_t rtt_ms) noexcept;

    // --- in-flight / queued DATA bookkeeping (the send ring) ---
    struct OutChunk {
        bool          used = false;
        bool          sent = false;       // shipped at least once (in flight)
        bool          acked = false;
        bool          abandoned = false;  // partial-reliability give-up
        std::uint8_t  flags = 0;          // B/M/E/U as sent
        std::uint16_t stream_id = 0;
        std::uint16_t ssn = 0;
        std::uint32_t tsn = 0;
        std::uint32_t ppid = 0;
        std::uint32_t miss_count = 0;     // gap-report misses (for fast rtx)
        std::uint32_t rtx_count = 0;      // times retransmitted
        std::uint64_t sent_at_ms = 0;     // for RTT (Karn: only first send counts)
        bool          rtt_pending = false;// eligible for RTT sample (no rtx yet)
        std::size_t   payload_len = 0;    // user payload bytes (for flight accounting)
        std::size_t   len = 0;            // framed packet length
        // Partial reliability policy carried per chunk's message.
        bool          rel_rexmit = false;
        bool          rel_timed  = false;
        std::uint32_t rel_max_rtx = 0;
        std::uint64_t expiry_ms = 0;      // 0 = none
        std::uint8_t  packet[kSctpMaxPacket]{};  // full framed packet (re-shippable)
    };

    // --- per-stream receive ordering state ---
    struct InStream {
        std::uint16_t next_ssn = 0;        // next ordered SSN to deliver
    };

    // --- per-stream OUTBOUND reassembly-aware reorder buffer (completed msgs) ---
    struct InPending {
        bool          used = false;
        std::uint16_t stream_id = 0;
        std::uint16_t ssn = 0;
        std::uint32_t ppid = 0;
        std::size_t   len = 0;
        std::uint8_t* data = nullptr;     // points into reasm_pool_ region
    };

    // --- inbound reassembly context (one partial message under construction) ---
    struct Reasm {
        bool          used = false;
        bool          unordered = false;
        bool          have_begin = false;
        bool          have_end = false;
        std::uint16_t stream_id = 0;
        std::uint16_t ssn = 0;
        std::uint32_t ppid = 0;
        std::uint32_t begin_tsn = 0;      // TSN of the B fragment
        std::uint32_t next_tsn = 0;       // next contiguous TSN expected
        std::size_t   len = 0;            // bytes accumulated so far
        std::uint8_t* data = nullptr;     // points into reasm_pool_ region
    };

    // --- buffered out-of-order received DATA fragment (awaiting its predecessor
    //     TSN so reassembly can append it in order). Bounded ring; a fragment is
    //     only recorded in the receive bitmap (and thus gap-acked) once it is
    //     buffered here or consumed — so we never gap-ack data we then drop. ---
    struct InFrag {
        bool          used = false;
        std::uint32_t tsn = 0;
        std::uint16_t stream_id = 0;
        std::uint16_t ssn = 0;
        std::uint32_t ppid = 0;
        std::uint8_t  flags = 0;          // B/M/E/U
        std::uint16_t len = 0;            // payload bytes
        std::uint8_t  data[kSctpMaxChunkData]{};
    };
    static constexpr std::size_t kSctpMaxFrags = 512;  // bounded reorder of fragments

    // Process / reassemble fragments in the store that are now contiguous with a
    // reassembly context (or start one). Returns true if anything progressed.
    void drain_fragments() noexcept;
    void ingest_fragment(std::uint32_t tsn, std::uint16_t sid, std::uint16_t ssn,
                         std::uint32_t ppid, std::uint8_t flags,
                         const std::uint8_t* payload, std::size_t plen) noexcept;

    Role           role_  = Role::Passive;
    State          state_ = State::Closed;

    SctpPacketSink   sink_;
    SctpRecvHandler  on_recv_;

    std::uint16_t  src_port_ = kSctpPort;
    std::uint16_t  dst_port_ = kSctpPort;

    std::uint32_t  local_tag_ = 0;
    std::uint32_t  peer_tag_  = 0;

    std::uint32_t  next_tsn_   = 0;  // next outbound DATA TSN
    std::uint32_t  cum_ack_in_ = 0;  // highest contiguous inbound TSN we've acked
    bool           have_cum_ack_ = false;
    std::uint32_t  peer_init_tsn_ = 0;
    std::uint32_t  local_init_tsn_ = 0;

    std::uint16_t  out_ssn_[kSctpMaxStreams]{};  // next outbound ordered SSN per stream

    std::uint32_t  peer_rwnd_ = kSctpInitialRwnd;

    // FORWARD-TSN state (RFC 3758): the highest TSN we've abandoned + announced.
    std::uint32_t  adv_ack_point_ = 0;     // our sender's "advanced peer ack point"
    bool           need_forward_tsn_ = false;

    // Receiver-side: TSNs above cum_ack_in_ we've seen (sliding window bitmap).
    static constexpr std::size_t kRecvWindow = 4096;  // TSNs trackable past cum ack
    std::uint8_t   recv_bitmap_[kRecvWindow / 8]{};   // 1 bit per TSN past cum_ack_in_

    // --- RTO / congestion control ---
    std::uint32_t  srtt_ms_   = 0;
    std::uint32_t  rttvar_ms_ = 0;
    bool           have_rtt_  = false;
    std::uint32_t  rto_ms_    = kSctpRtoInitialMs;
    std::uint64_t  t3_deadline_ms_ = 0;    // 0 = timer not running
    bool           t3_running_ = false;
    std::uint32_t  consecutive_timeouts_ = 0;

    std::uint32_t  cwnd_      = 0;         // set at Established (4*MTU)
    std::uint32_t  ssthresh_  = kSctpInitialRwnd;
    std::uint32_t  flight_size_ = 0;       // bytes in flight (sent, unacked)
    std::uint32_t  partial_bytes_acked_ = 0;

    std::uint8_t   cookie_[kSctpCookieLen]{};

    OutChunk   out_ring_[kSctpSendQueue];
    InStream   in_streams_[kSctpMaxStreams];
    InPending  in_pending_[kSctpRecvReorder];
    Reasm      reasm_[kSctpMaxReasm];
    InFrag*    infrag_ = nullptr;          // heap (kSctpMaxFrags), allocated in init()
    std::size_t infrag_count_ = 0;

    // Reassembly backing storage: one kSctpMaxMessage slab per reassembly slot,
    // plus slabs for the reorder buffer. Preallocated; no per-message malloc.
    static constexpr std::size_t kReasmSlabs = kSctpMaxReasm + kSctpRecvReorder;
    // Reassembly backing storage: one contiguous buffer of kReasmSlabs slabs,
    // each kSctpMaxMessage bytes. ONE bounded one-time allocation in init(),
    // freed in the dtor. No per-message malloc (TigerStyle preallocation).
    std::uint8_t* reasm_pool_ = nullptr;   // kReasmSlabs * kSctpMaxMessage bytes
    bool          reasm_slab_used_[kReasmSlabs]{};
    void          ensure_pool() noexcept;
    std::uint8_t* alloc_slab() noexcept;
    void          free_slab(std::uint8_t* p) noexcept;
    std::size_t   reasm_bytes_ = 0;        // total bytes currently buffered (cap)

    std::uint64_t  data_in_  = 0;
    std::uint64_t  data_out_ = 0;
    std::uint64_t  rtx_count_ = 0;

    // The "current time" for the in-progress feed()/tick()/send() call, so chunk
    // handlers (esp. handle_sack: RTT sample + T3 restart) use the SAME clock the
    // caller drives (deterministic in tests; steady_clock in production).
    std::uint64_t  cur_now_ms_ = 0;
};

}  // namespace webrtc
}  // namespace bolt::api
