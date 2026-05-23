// boltapi/webrtc/turn.h — TURN client + minimal in-process TURN server.
//
// ============================================================================
// WHAT THIS IS
// ============================================================================
// A TURN (RFC 5766 / RFC 8656) client that obtains a RELAYED transport address
// (a relay ICE candidate) from a TURN server and relays data through it, plus a
// minimal in-process TURN SERVER sufficient to gate the client over loopback.
//
// Client surface (long-term credential, RFC 5389 §10.2):
//   * Allocate            — request a relayed address (auth via REALM/NONCE +
//                           MESSAGE-INTEGRITY keyed by MD5(user:realm:pass)).
//   * Refresh             — extend / tear down (LIFETIME=0) the allocation.
//   * CreatePermission    — authorize a peer address to send to us.
//   * ChannelBind         — bind a 0x4000.. channel number to a peer for the
//                           4-byte ChannelData fast path.
//   * Send / Data         — relay a datagram to a peer (Send indication) and
//                           receive one (Data indication) — plus ChannelData.
//
// The TURN message codec lives HERE (self-contained): TURN adds STUN methods
// (Allocate/Refresh/CreatePermission/ChannelBind + Send/Data indications) and
// attributes (LIFETIME, XOR-RELAYED-ADDRESS, XOR-PEER-ADDRESS, DATA, REALM,
// NONCE, REQUESTED-TRANSPORT, CHANNEL-NUMBER, ...) that the base STUN codec
// (boltapi/webrtc/stun.h) does not enumerate. Crypto: OpenSSL HMAC-SHA1 (MI) +
// MD5 (long-term key) + the STUN codec's CRC-32 for FINGERPRINT.
//
// TigerStyle: fixed caller buffers, bounded permission/channel tables, no
// exceptions, no throwing, allocation-light (credentials are the only owned
// std::strings; built once, never per packet). Compiled UNCONDITIONALLY.

#pragma once

#include "boltapi/net/sys_compat.h"

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace bolt::api {
namespace net { class UdpTransport; }
namespace webrtc {
namespace turn {

// Parsed TURN message (defined in turn.cpp). Forward-declared here so the
// TurnServer per-message handlers can take it by const-ref without pulling the
// codec into the header.
struct Parsed;

// ----------------------------------------------------------------------------
// Constants (RFC 5766 / RFC 8656).
// ----------------------------------------------------------------------------
inline constexpr std::uint32_t kMagicCookie = 0x2112A442u;
inline constexpr std::size_t   kHeaderSize  = 20;
inline constexpr std::size_t   kTxnLen      = 12;

// STUN methods used by TURN (12-bit method field).
enum class Method : std::uint16_t {
    Binding          = 0x001,
    Allocate         = 0x003,
    Refresh          = 0x004,
    Send             = 0x006,  // indication
    Data             = 0x007,  // indication
    CreatePermission = 0x008,
    ChannelBind      = 0x009,
};

enum class Class : std::uint8_t {
    Request         = 0,
    Indication      = 1,
    SuccessResponse = 2,
    ErrorResponse   = 3,
};

// TURN/STUN attributes (RFC 5766 §14, RFC 8656, RFC 5389 §18.2).
enum class Attr : std::uint16_t {
    MappedAddress      = 0x0001,
    Username           = 0x0006,
    MessageIntegrity   = 0x0008,
    ErrorCode          = 0x0009,
    UnknownAttributes  = 0x000A,
    Realm              = 0x0014,
    Nonce              = 0x0015,
    XorPeerAddress     = 0x0012,
    Data               = 0x0013,
    XorRelayedAddress  = 0x0016,
    RequestedTransport = 0x0019,
    XorMappedAddress   = 0x0020,
    ChannelNumber      = 0x000C,
    Lifetime           = 0x000D,
    Fingerprint        = 0x8028,
};

inline constexpr std::uint8_t kProtoUdp = 17;  // REQUESTED-TRANSPORT = UDP

// ----------------------------------------------------------------------------
// Bounds (TigerStyle).
// ----------------------------------------------------------------------------
inline constexpr std::size_t kMaxPermissions = 16;   // per allocation
inline constexpr std::size_t kMaxChannels    = 16;   // per allocation
inline constexpr std::size_t kMaxAllocations = 8;    // server-side
inline constexpr std::uint16_t kChannelBase  = 0x4000;
inline constexpr std::uint16_t kChannelMax   = 0x7FFF;

// ----------------------------------------------------------------------------
// Long-term credential helpers.
// ----------------------------------------------------------------------------
// Compute the long-term key = MD5(username ":" realm ":" password) into `out16`.
void long_term_key(std::string_view user, std::string_view realm,
                   std::string_view pass, std::uint8_t out16[16]) noexcept;

// First-byte classifier (RFC 7983 / RFC 5766 §11): a ChannelData message has a
// channel number in 0x4000..0x7FFF in its first 2 bytes; a STUN/TURN message has
// the top two bits zero (channel >= 0x4000 means first byte >= 0x40).
inline bool is_channel_data(const std::uint8_t* d, std::size_t n) noexcept {
    if (d == nullptr || n < 4) return false;
    const std::uint16_t ch = static_cast<std::uint16_t>((d[0] << 8) | d[1]);
    return ch >= kChannelBase && ch <= kChannelMax;
}

// ----------------------------------------------------------------------------
// TurnClient — obtains + uses a relayed transport address over a UdpTransport.
// The client drives its protocol by SENDING through the transport and FEEDING
// inbound datagrams (from the transport's datagram/STUN handler) into feed().
// ----------------------------------------------------------------------------
class TurnClient {
public:
    enum class State : std::uint8_t {
        Idle,        // no allocation
        Allocating,  // Allocate sent, awaiting (possibly 401 -> retry w/ nonce)
        Allocated,   // relay address obtained
        Failed,
    };

    TurnClient() noexcept = default;
    ~TurnClient() = default;
    TurnClient(const TurnClient&) = delete;
    TurnClient& operator=(const TurnClient&) = delete;

    // Configure the TURN server address + long-term credentials. Must be called
    // before allocate(). `server`/`server_len` is the TURN server transport addr.
    void configure(const sockaddr* server, int server_len, std::string_view user,
                   std::string_view pass) noexcept;

    // Send an Allocate request (REQUESTED-TRANSPORT=UDP). The first attempt is
    // unauthenticated; the server's 401 carries REALM+NONCE, which feed() stores
    // and (when `auto_retry`) re-sends authenticated. Returns true if a datagram
    // was sent. noexcept.
    bool allocate(net::UdpTransport& transport) noexcept;

    // Send a Refresh with `lifetime` seconds (0 = release the allocation).
    bool refresh(net::UdpTransport& transport, std::uint32_t lifetime) noexcept;

    // Authorize `peer` to relay through our allocation (CreatePermission).
    bool create_permission(net::UdpTransport& transport, const sockaddr* peer,
                           int peer_len) noexcept;

    // Bind a channel number to `peer` for the 4-byte ChannelData fast path.
    bool channel_bind(net::UdpTransport& transport, const sockaddr* peer,
                      int peer_len, std::uint16_t channel) noexcept;

    // Relay `len` bytes to `peer` via a Send indication (XOR-PEER-ADDRESS+DATA).
    bool send_to(net::UdpTransport& transport, const sockaddr* peer, int peer_len,
                 const std::uint8_t* data, std::size_t len) noexcept;

    // Relay `len` bytes to `peer` over the bound channel (ChannelData; requires a
    // prior channel_bind). Returns false if no channel is bound for `peer`.
    bool send_channel(net::UdpTransport& transport, const sockaddr* peer,
                      int peer_len, const std::uint8_t* data,
                      std::size_t len) noexcept;

    // Feed one inbound datagram (from the TURN server) into the client. Drives
    // state (Allocate success/401, Refresh/Permission/ChannelBind responses) and,
    // for relayed application data (Data indication / ChannelData), copies the
    // payload + peer into `relayed_*` and sets `have_relayed`. Returns true if it
    // consumed the datagram as TURN traffic.
    bool feed(net::UdpTransport& transport, const sockaddr* from, int from_len,
              const std::uint8_t* data, std::size_t len) noexcept;

    State state() const noexcept { return state_; }
    bool  allocated() const noexcept { return state_ == State::Allocated; }

    // The relayed transport address (relay candidate) once Allocated.
    const sockaddr_storage& relayed_address() const noexcept { return relay_addr_; }
    int relayed_address_len() const noexcept { return relay_addr_len_; }

    // Last application payload relayed IN to us (Data indication / ChannelData).
    bool have_relayed_data() const noexcept { return have_relayed_; }
    const std::uint8_t* relayed_data() const noexcept { return relayed_buf_; }
    std::size_t relayed_len() const noexcept { return relayed_len_; }
    const sockaddr_storage& relayed_peer() const noexcept { return relayed_peer_; }
    int relayed_peer_len() const noexcept { return relayed_peer_len_; }
    void clear_relayed() noexcept { have_relayed_ = false; relayed_len_ = 0; }

    std::uint32_t lifetime() const noexcept { return lifetime_; }
    bool permission_acked() const noexcept { return permission_acked_; }
    bool channel_acked() const noexcept { return channel_acked_; }

private:
    // Build the common request header + auth attrs into `out`; returns size or 0.
    std::size_t begin_authed(std::uint8_t* out, std::size_t cap, Method method,
                             std::uint8_t txn[kTxnLen]) noexcept;
    void next_txn(std::uint8_t txn[kTxnLen]) noexcept;
    // feed() helpers (keep feed() small: TigerStyle one-thing-per-fn).
    void ingest_channel_data(const std::uint8_t* data, std::size_t len) noexcept;
    void ingest_data_indication(const Parsed& m) noexcept;
    bool on_error_response(net::UdpTransport& transport, const Parsed& m) noexcept;
    void on_success_response(const Parsed& m) noexcept;

    sockaddr_storage server_{};
    int              server_len_ = 0;
    std::string      user_;
    std::string      pass_;
    std::string      realm_;
    std::uint8_t     nonce_[128]{};
    std::size_t      nonce_len_ = 0;
    std::uint8_t     key_[16]{};   // MD5(user:realm:pass)
    bool             have_key_ = false;

    State            state_ = State::Idle;
    sockaddr_storage relay_addr_{};
    int              relay_addr_len_ = 0;
    std::uint32_t    lifetime_ = 0;

    bool             permission_acked_ = false;
    bool             channel_acked_ = false;
    std::uint16_t    bound_channel_ = 0;
    sockaddr_storage bound_peer_{};
    int              bound_peer_len_ = 0;

    bool             have_relayed_ = false;
    std::uint8_t     relayed_buf_[2048]{};
    std::size_t      relayed_len_ = 0;
    sockaddr_storage relayed_peer_{};
    int              relayed_peer_len_ = 0;

    std::uint64_t    txn_ctr_ = 0;
};

// ----------------------------------------------------------------------------
// TurnServer — a minimal in-process TURN server (loopback gate). Authenticates
// with a single long-term credential (one user/realm/pass), grants ONE relayed
// address per client 5-tuple, handles CreatePermission / ChannelBind, and relays
// Send/ChannelData out to peers + peer datagrams back as Data/ChannelData.
//
// The relay address is a SECOND UdpTransport the server owns (the relay socket).
// The control socket (the one the client talks to) is supplied by the owner. The
// server is driven by feed() on the control socket + feed_relay() on the relay
// socket. Bounded allocations/permissions/channels; no exceptions.
// ----------------------------------------------------------------------------
class TurnServer {
public:
    TurnServer() noexcept = default;
    ~TurnServer() = default;
    TurnServer(const TurnServer&) = delete;
    TurnServer& operator=(const TurnServer&) = delete;

    // Set the single accepted long-term credential + the realm we challenge with.
    void set_credentials(std::string_view realm, std::string_view user,
                         std::string_view pass) noexcept;

    // Wire the two sockets: `control` is where clients send TURN requests;
    // `relay` is the socket whose bound address becomes the relayed address (peers
    // send application data to it). Both must be bound + started by the owner.
    void set_sockets(net::UdpTransport& control, net::UdpTransport& relay) noexcept;

    // Feed one datagram received on the CONTROL socket (a TURN request/indication
    // or ChannelData from a client). Returns true if handled as TURN.
    bool feed(const sockaddr* from, int from_len, const std::uint8_t* data,
              std::size_t len) noexcept;

    // Feed one datagram received on the RELAY socket (application data from a
    // permitted peer): forwarded to the owning client as a Data indication /
    // ChannelData. Returns true if it matched a permission/channel.
    bool feed_relay(const sockaddr* from, int from_len, const std::uint8_t* data,
                    std::size_t len) noexcept;

    std::size_t allocation_count() const noexcept { return alloc_count_; }

private:
    struct Channel {
        std::uint16_t    number = 0;
        sockaddr_storage peer{};
        int              peer_len = 0;
        bool             used = false;
    };
    struct Permission {
        sockaddr_storage peer{};
        int              peer_len = 0;
        bool             used = false;
    };
    struct Allocation {
        sockaddr_storage client{};       // the client's 5-tuple (control)
        int              client_len = 0;
        std::uint32_t    lifetime = 600;
        Permission       perms[kMaxPermissions]{};
        Channel          chans[kMaxChannels]{};
        bool             used = false;
    };

    Allocation* find_alloc(const sockaddr* client, int client_len) noexcept;
    Allocation* obtain_alloc(const sockaddr* client, int client_len) noexcept;
    bool send_error(const sockaddr* to, int to_len, Method method,
                    const std::uint8_t txn[kTxnLen], std::uint16_t code,
                    bool with_realm) noexcept;
    bool verify_auth(const std::uint8_t* data, std::size_t len) noexcept;
    // Per-message handlers (keep feed() small: TigerStyle one-thing-per-fn).
    bool on_channel_data(const sockaddr* from, int from_len,
                         const std::uint8_t* data, std::size_t len) noexcept;
    void on_send_indication(const sockaddr* from, int from_len,
                            const Parsed& m) noexcept;
    void on_allocate(const sockaddr* from, int from_len, const Parsed& m) noexcept;
    void on_create_permission(Allocation& a, const sockaddr* from, int from_len,
                              const Parsed& m) noexcept;
    void on_channel_bind(Allocation& a, const sockaddr* from, int from_len,
                         const Parsed& m) noexcept;
    void on_refresh(Allocation& a, const sockaddr* from, int from_len,
                    const Parsed& m) noexcept;

    net::UdpTransport* control_ = nullptr;
    net::UdpTransport* relay_   = nullptr;
    std::string realm_;
    std::string user_;
    std::string pass_;
    std::uint8_t key_[16]{};
    bool         have_key_ = false;
    std::uint8_t nonce_[16]{};  // fixed nonce for the loopback gate

    Allocation  allocs_[kMaxAllocations]{};
    std::size_t alloc_count_ = 0;
};

}  // namespace turn
}  // namespace webrtc
}  // namespace bolt::api
