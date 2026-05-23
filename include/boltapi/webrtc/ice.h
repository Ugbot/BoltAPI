// boltapi/webrtc/ice.h — ICE-lite agent (RFC 8445) + candidate model.
//
// ============================================================================
// WHAT THIS IS
// ============================================================================
// An ICE-LITE agent: Bolt is always the CONTROLLED answerer. We do NOT initiate
// connectivity checks. We:
//   * gather host candidates from real local interfaces (GetAdaptersAddresses
//     on Windows / getifaddrs on POSIX) and serialize them for the SDP answer;
//   * generate random ice-ufrag / ice-pwd (RFC 8445 §5.3 character set/length);
//   * RESPOND to STUN Binding Requests from the peer: validate it is a Binding
//     Request, check USERNAME ("ourUfrag:peerUfrag"), verify MESSAGE-INTEGRITY
//     with OUR ice-pwd, then build a Binding Success Response carrying
//     XOR-MAPPED-ADDRESS (the peer's source addr), MESSAGE-INTEGRITY (our pwd),
//     and FINGERPRINT, and send it back via the UdpTransport.
//   * track the peer as the SELECTED PAIR once a valid request with
//     USE-CANDIDATE arrives (controlled-agent nomination, RFC 8445 §7.3.1.5).
//
// PORTED from FasterAPI src/cpp/webrtc/ice.cpp:13-39: ICECandidate::to_string.
// REBUILT: ICECandidate::from_string (real tokenizing parse), host gathering,
//   credential generation, and the entire STUN binding-request responder (the
//   FasterAPI ICEAgent had none of this).
//
// Uses the Bolt-API STUN codec (boltapi/webrtc/stun.h). Compiled UNCONDITIONALLY
// into boltapi (pure logic + socket-address handling; the only "transport" it
// touches is a UdpTransport pointer it sends through). Crypto: the STUN codec's
// OpenSSL HMAC for MESSAGE-INTEGRITY.
//
// TigerStyle: fixed-capacity candidate array, bounded ufrag/pwd, no exceptions,
// no throwing, allocation-light (the only std::string use is the owned
// credentials + candidate strings, built once at gather time, never per packet).

#pragma once

#include "boltapi/net/sys_compat.h"
#include "boltapi/webrtc/stun.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace bolt::api {
namespace webrtc {

// Forward decl — IceAgent sends through it but does not own it.
}  // namespace webrtc
namespace net { class UdpTransport; }
namespace webrtc {

// ----------------------------------------------------------------------------
// Bounds (TigerStyle).
// ----------------------------------------------------------------------------
inline constexpr std::size_t kIceMaxCandidates = 16;   // host candidates we keep
inline constexpr std::size_t kIceUfragLen      = 8;    // >= 4 (RFC 8445 §5.3)
inline constexpr std::size_t kIcePwdLen        = 24;   // >= 22 (RFC 8445 §5.3)

// ----------------------------------------------------------------------------
// Candidate model (PORTED from FasterAPI, reshaped for -fno-exceptions).
// ----------------------------------------------------------------------------
enum class CandidateType : std::uint8_t { Host, Srflx, Prflx, Relay };
enum class IceTransport  : std::uint8_t { Udp, Tcp };

struct IceCandidate {
    CandidateType type      = CandidateType::Host;
    IceTransport  transport = IceTransport::Udp;

    std::string   foundation;        // candidate identifier (decimal here)
    std::uint32_t priority = 0;      // RFC 8445 §5.1.2
    std::string   address;           // dotted-quad IPv4 (or IPv6 literal)
    std::uint16_t port = 0;
    std::uint8_t  component = 1;     // 1 = RTP (only component for data channels)

    std::string   related_address;   // for srflx/relay (empty for host)
    std::uint16_t related_port = 0;

    // PORTED from FasterAPI ice.cpp:13-39 (to "candidate:..." SDP form).
    // Format: candidate:<foundation> <component> <proto> <priority> <addr>
    //         <port> typ <type> [raddr <ra> rport <rp>]
    std::string to_string() const;

    // REBUILT real tokenizing parser (FasterAPI returned a hardcoded candidate).
    // Accepts an optional leading "candidate:" prefix. Returns true on success.
    static bool from_string(std::string_view s, IceCandidate& out) noexcept;
};

// RFC 8445 §5.1.2.1 host-candidate priority:
//   priority = (2^24)*type_pref + (2^8)*local_pref + (256 - component)
// host type-pref = 126, local-pref = 65535 (single interface class here).
std::uint32_t host_priority(std::uint8_t component) noexcept;

// ----------------------------------------------------------------------------
// IceAgent — ICE-lite controlled answerer.
// ----------------------------------------------------------------------------
class IceAgent {
public:
    IceAgent() noexcept = default;
    ~IceAgent() = default;

    IceAgent(const IceAgent&) = delete;
    IceAgent& operator=(const IceAgent&) = delete;

    // Pin specific credentials (tests / deterministic signaling). Pass empty to
    // skip. Must satisfy the RFC length minimums or they are ignored.
    void set_credentials(std::string_view ufrag, std::string_view pwd) noexcept;

    // Generate random RFC 8445 ufrag/pwd if not already set. `seed` lets tests
    // be deterministic; pass 0 to derive a seed from a clock + address entropy.
    void generate_credentials(std::uint64_t seed = 0) noexcept;

    // Record the PEER (offerer) ICE credentials extracted from the SDP offer.
    // When the remote ufrag is set, handle_stun ADDITIONALLY checks the inbound
    // USERNAME's peer-side token ("ourUfrag:peerUfrag") matches it (RFC 8445
    // §7.3 — the request must be addressed FROM the known peer). Empty ufrag =>
    // peer-side check skipped (back-compat: integrity over our pwd still gates).
    // The remote pwd is stored for completeness (the controlled responder
    // verifies MESSAGE-INTEGRITY with OUR pwd, not the peer's).
    void set_expected_remote(std::string_view ufrag, std::string_view pwd) noexcept;

    std::string_view ufrag() const noexcept { return ufrag_; }
    std::string_view pwd()   const noexcept { return pwd_; }
    std::string_view remote_ufrag() const noexcept { return remote_ufrag_; }
    std::string_view remote_pwd()   const noexcept { return remote_pwd_; }

    // Gather host candidates from local interfaces, each on `port` (the bound
    // UDP port of the transport). Returns the number gathered (>= 1 in a normal
    // environment; loopback included only if no other usable IPv4 exists).
    //
    // `bind_host` is the address the UDP socket is actually bound to. When it is
    // a SPECIFIC address (not empty and not "0.0.0.0"), the socket only receives
    // datagrams sent to THAT address, so we advertise EXACTLY one host candidate
    // for it (e.g. "127.0.0.1" for a loopback bind — required for ICE to succeed
    // against a peer on the same host, incl. the aiortc interop gate). When
    // `bind_host` is empty or a wildcard, we enumerate all usable interfaces.
    std::size_t gather_host_candidates(std::uint16_t port,
                                       std::string_view bind_host) noexcept;
    // Back-compat overload: enumerate all interfaces (wildcard bind).
    std::size_t gather_host_candidates(std::uint16_t port) noexcept {
        return gather_host_candidates(port, std::string_view{});
    }

    std::size_t candidate_count() const noexcept { return candidate_count_; }
    const IceCandidate& candidate(std::size_t i) const noexcept {
        assert(i < candidate_count_);
        return candidates_[i];
    }

    // ----- STUN binding-request handling (the ICE-lite responder path) -------
    // Result of handling one inbound STUN datagram.
    enum class HandleResult : std::uint8_t {
        Responded,        // valid request -> success response sent
        RespondedSelected,// valid request WITH USE-CANDIDATE -> success + nominated
        ErrorResponse,    // bad username/integrity -> 401/400 error response sent
        Ignored,          // not a STUN binding request we handle (dropped)
    };

    // Handle a STUN datagram delivered by the UdpTransport. Validates it is a
    // Binding Request, checks USERNAME == "ourUfrag:<anything>", verifies
    // MESSAGE-INTEGRITY with our pwd, then builds + SENDS (via `transport`) a
    // Binding Success Response with XOR-MAPPED-ADDRESS(peer) + MESSAGE-INTEGRITY
    // + FINGERPRINT. On USE-CANDIDATE, records the peer as the selected pair.
    // Never throws, never crashes on malformed input.
    HandleResult handle_stun(net::UdpTransport& transport, const sockaddr* peer,
                             int peer_len, const std::uint8_t* data,
                             std::size_t len) noexcept;

    // Selected-pair (connected peer) accessors for the next (DTLS) wave.
    bool has_selected_peer() const noexcept { return have_selected_; }
    const sockaddr_storage& selected_peer() const noexcept { return selected_peer_; }
    int selected_peer_len() const noexcept { return selected_peer_len_; }

    // Counters (observability).
    std::uint64_t binding_requests()  const noexcept { return rx_requests_; }
    std::uint64_t binding_responses() const noexcept { return tx_responses_; }
    std::uint64_t binding_errors()    const noexcept { return tx_errors_; }

private:
    // Build + send a Binding Success Response for `req` to `peer`.
    bool send_success(net::UdpTransport& transport, const stun::Message& req,
                      const sockaddr* peer, int peer_len) noexcept;
    // Build + send a Binding Error Response (code, reason) to `peer`.
    bool send_error(net::UdpTransport& transport, const stun::Message& req,
                    std::uint16_t code, const char* reason, const sockaddr* peer,
                    int peer_len) noexcept;

    std::string ufrag_;
    std::string pwd_;
    std::string remote_ufrag_;  // peer ufrag from the SDP offer (optional check)
    std::string remote_pwd_;    // peer pwd from the SDP offer (stored only)

    IceCandidate candidates_[kIceMaxCandidates]{};
    std::size_t  candidate_count_ = 0;

    bool             have_selected_     = false;
    sockaddr_storage selected_peer_{};
    int              selected_peer_len_ = 0;

    std::uint64_t rx_requests_  = 0;
    std::uint64_t tx_responses_ = 0;
    std::uint64_t tx_errors_    = 0;
};

}  // namespace webrtc
}  // namespace bolt::api
