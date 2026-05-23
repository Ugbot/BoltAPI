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

// ============================================================================
// FULL ICE (RFC 8445) — controlling + controlled, connectivity checks in BOTH
// directions, candidate pairs + checklist with pair states, role-conflict
// resolution (tie-breaker), nomination, trickle, and ICE restart.
//
// This is an OPTION alongside IceAgent (ice-lite). Where IceAgent only RESPONDS
// to inbound Binding Requests, FullIceAgent ALSO generates Binding Requests
// (connectivity checks) toward remote candidates and tracks the per-pair state
// machine until a pair is nominated + valid.
//
// TigerStyle: fixed-capacity candidate/pair tables (kMaxCandidates/kMaxPairs),
// bounded check pacing, no recursion, no exceptions, allocation-light (the only
// std::string is the credentials + candidate addresses, built at gather time).
// ============================================================================

inline constexpr std::size_t kMaxCandidates = 16;  // remote candidates we track
inline constexpr std::size_t kMaxPairs      = 64;  // checklist capacity (bounded)

// RFC 8445 §6.1.2.6 candidate-pair state.
enum class PairState : std::uint8_t {
    Frozen     = 0,
    Waiting    = 1,
    InProgress = 2,
    Succeeded  = 3,
    Failed     = 4,
};

// RFC 8445 §5.2 agent role.
enum class IceRole : std::uint8_t { Controlling = 0, Controlled = 1 };

// A remote candidate (parsed from SDP / trickle), with a resolved sockaddr so
// connectivity checks can sendto it without re-parsing on the hot path.
struct RemoteCandidate {
    IceCandidate     cand{};
    sockaddr_storage addr{};
    int              addr_len = 0;
    bool             used     = false;
};

// A local candidate paired against remotes (host/srflx/relay; addr resolved).
struct LocalCandidate {
    IceCandidate     cand{};
    sockaddr_storage base{};      // the base transport address we send FROM
    int              base_len = 0;
    bool             used     = false;
};

// One candidate pair (RFC 8445 §6.1.2): local x remote + state + priority.
struct CandidatePair {
    std::size_t  local_idx  = 0;
    std::size_t  remote_idx = 0;
    std::uint64_t priority   = 0;   // RFC 8445 §6.1.2.3 pair priority
    PairState    state      = PairState::Frozen;
    bool         nominated  = false;
    bool         use_candidate_sent = false;
    std::uint8_t txn[stun::kTransactionIdLen]{};  // pending check txn id
    bool         have_txn   = false;
    std::uint32_t check_sent_ms = 0;  // last check send time (pacing/retransmit)
    std::uint8_t  retries    = 0;
    bool         used       = false;
};

// RFC 8445 §6.1.2.3 candidate-pair priority from the two component priorities.
std::uint64_t pair_priority(std::uint32_t controlling_pri,
                            std::uint32_t controlled_pri) noexcept;

// srflx priority (RFC 8445 §5.1.2.1): type-pref 100.
std::uint32_t srflx_priority(std::uint8_t component) noexcept;
// relay priority (RFC 8445 §5.1.2.1): type-pref 0.
std::uint32_t relay_priority(std::uint8_t component) noexcept;

class FullIceAgent {
public:
    FullIceAgent() noexcept = default;
    ~FullIceAgent() = default;
    FullIceAgent(const FullIceAgent&) = delete;
    FullIceAgent& operator=(const FullIceAgent&) = delete;

    // Result of processing one inbound STUN datagram in full-ICE mode.
    enum class HandleResult : std::uint8_t {
        Ignored,         // not a STUN message we handle
        Request,         // valid Binding Request -> success response sent
        Response,        // Binding Success Response to one of our checks
        ErrorResponse,   // we sent (or received) an error
        RoleConflict,    // 487 role conflict observed/handled
        Nominated,       // a valid pair got nominated as a result
    };

    void set_role(IceRole role) noexcept;
    IceRole role() const noexcept { return role_; }
    std::uint64_t tiebreaker() const noexcept { return tiebreaker_; }

    void set_credentials(std::string_view ufrag, std::string_view pwd) noexcept;
    void set_remote_credentials(std::string_view ufrag,
                                std::string_view pwd) noexcept;
    void generate_credentials(std::uint64_t seed) noexcept;
    void set_tiebreaker(std::uint64_t tb) noexcept;

    std::string_view ufrag()        const noexcept { return ufrag_; }
    std::string_view pwd()          const noexcept { return pwd_; }
    std::string_view remote_ufrag() const noexcept { return remote_ufrag_; }
    std::string_view remote_pwd()   const noexcept { return remote_pwd_; }

    // Add a LOCAL candidate (host/srflx/relay) we will check FROM. Returns the
    // index, or kMaxCandidates on overflow. `base` is the address we send from.
    std::size_t add_local_candidate(const IceCandidate& c, const sockaddr* base,
                                    int base_len) noexcept;
    // Add a REMOTE candidate (trickle or in-SDP). Forms pairs with all locals,
    // eliminates exact duplicates, and (when Waiting) unfreezes them. Returns the
    // index, or kMaxCandidates on overflow / parse failure.
    std::size_t add_remote_candidate(const IceCandidate& c) noexcept;

    std::size_t local_count()  const noexcept { return local_count_; }
    std::size_t remote_count() const noexcept { return remote_count_; }
    std::size_t pair_count()   const noexcept { return pair_count_; }
    const CandidatePair& pair(std::size_t i) const noexcept {
        assert(i < pair_count_);
        return pairs_[i];
    }

    // Drive ONE round of connectivity checks: pick the highest-priority Waiting
    // pair, send a Binding Request (with PRIORITY + ICE-CONTROLLING/CONTROLLED +
    // optional USE-CANDIDATE), mark it In-Progress. Also retransmits timed-out
    // In-Progress checks (bounded retries) and, for the controlling agent,
    // nominates the best succeeded pair. `now_ms` paces checks/retransmits.
    // Returns the number of checks sent this round (0..N). noexcept, bounded.
    std::size_t run_checks(net::UdpTransport& transport,
                           std::uint32_t now_ms) noexcept;

    // Handle an inbound STUN datagram from `peer`. Dispatches to the request
    // responder (incoming check -> success response, triggered check, role
    // conflict) or the response matcher (our check succeeded -> pair Succeeded,
    // discovered srflx -> prflx). noexcept, safe on malformed input.
    HandleResult handle_stun(net::UdpTransport& transport, const sockaddr* peer,
                             int peer_len, const std::uint8_t* data,
                             std::size_t len) noexcept;

    // ICE restart (RFC 8445 §9): regenerate ufrag/pwd, clear remotes + pairs,
    // keep local candidates. New credentials must then be signaled to the peer.
    void restart(std::uint64_t seed) noexcept;

    // Convergence state.
    bool has_nominated_pair() const noexcept { return have_nominated_; }
    const CandidatePair* nominated_pair() const noexcept {
        return have_nominated_ ? &pairs_[nominated_idx_] : nullptr;
    }
    bool selected_remote(sockaddr_storage* out, int* out_len) const noexcept;

    // Counters (observability).
    std::uint64_t checks_sent()    const noexcept { return checks_sent_; }
    std::uint64_t checks_succeeded() const noexcept { return checks_ok_; }
    std::uint64_t requests_handled() const noexcept { return reqs_handled_; }
    std::uint64_t role_conflicts() const noexcept { return role_conflicts_; }

private:
    // Form pairs of `remote_idx` against every local candidate (dedup + bound).
    void form_pairs_for_remote(std::size_t remote_idx) noexcept;
    // Send a Binding Request connectivity check for pairs_[i]. Returns true if
    // sent. `nominate` adds USE-CANDIDATE (controlling aggressive/regular).
    bool send_check(net::UdpTransport& transport, std::size_t i, bool nominate,
                    std::uint32_t now_ms) noexcept;
    // Handle an inbound Binding REQUEST (incoming connectivity check).
    HandleResult on_request(net::UdpTransport& transport, const stun::Message& m,
                            const sockaddr* peer, int peer_len) noexcept;
    // Validate an inbound request's USERNAME ("ourUfrag:..") + MESSAGE-INTEGRITY.
    bool request_authed(const stun::Message& m) const noexcept;
    // Detect + resolve a role conflict from the inbound check (tie-breaker).
    // Returns true if a conflict was observed (counted + role possibly switched).
    bool resolve_role_conflict(const stun::Message& m) noexcept;
    // Nominate the pair toward `remote_idx` (controlled side saw USE-CANDIDATE).
    bool nominate_remote(std::size_t remote_idx) noexcept;
    // Handle an inbound Binding SUCCESS/ERROR RESPONSE to one of our checks.
    HandleResult on_response(const stun::Message& m, const sockaddr* peer,
                             int peer_len) noexcept;
    // Build + send a Binding Success Response for an inbound check.
    bool send_request_success(net::UdpTransport& transport,
                              const stun::Message& req, const sockaddr* peer,
                              int peer_len) noexcept;
    // Find the pair index matching a pending check txn id (kMaxPairs if none).
    std::size_t pair_for_txn(const std::uint8_t* txn) const noexcept;
    // Add a peer-reflexive remote candidate discovered from an inbound check.
    std::size_t add_prflx_remote(const sockaddr* peer, int peer_len,
                                 std::uint32_t priority) noexcept;
    // Controlling agent: pick + nominate the best Succeeded pair (sets state).
    void maybe_nominate(net::UdpTransport& transport,
                        std::uint32_t now_ms) noexcept;

    IceRole       role_ = IceRole::Controlling;
    std::uint64_t tiebreaker_ = 0;
    std::string   ufrag_;
    std::string   pwd_;
    std::string   remote_ufrag_;
    std::string   remote_pwd_;

    LocalCandidate  locals_[kMaxCandidates]{};
    std::size_t     local_count_ = 0;
    RemoteCandidate remotes_[kMaxCandidates]{};
    std::size_t     remote_count_ = 0;
    CandidatePair   pairs_[kMaxPairs]{};
    std::size_t     pair_count_ = 0;

    bool        have_nominated_ = false;
    std::size_t nominated_idx_  = 0;

    std::uint64_t checks_sent_    = 0;
    std::uint64_t checks_ok_      = 0;
    std::uint64_t reqs_handled_   = 0;
    std::uint64_t role_conflicts_ = 0;
};

}  // namespace webrtc
}  // namespace bolt::api
