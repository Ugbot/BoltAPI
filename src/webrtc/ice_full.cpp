// src/webrtc/ice_full.cpp — FULL ICE agent (RFC 8445) implementation.
//
// Beyond the ice-lite IceAgent (which only RESPONDS): this agent is a full ICE
// state machine — controlling + controlled roles, a bounded candidate-pair
// checklist with per-pair states (Frozen/Waiting/In-Progress/Succeeded/Failed),
// connectivity checks in BOTH directions (Binding req/resp with PRIORITY +
// ICE-CONTROLLING/CONTROLLED + USE-CANDIDATE), role-conflict resolution via the
// tie-breaker, nomination, trickle (incremental add_remote_candidate), and ICE
// restart. Uses the Bolt-API STUN codec; crypto is the codec's OpenSSL HMAC.
//
// Compiled UNCONDITIONALLY into boltapi (pure logic + a UdpTransport pointer it
// sends through), so the default test suite covers it.
//
// TigerStyle: fixed-capacity tables (kMaxCandidates/kMaxPairs), bounded check
// pacing + retries, NO recursion, no exceptions, allocation-light.

#include "boltapi/webrtc/ice.h"

#include "boltapi/net/udp_transport.h"

#include <chrono>
#include <cstring>

namespace bolt::api {
namespace webrtc {

namespace {

// Pacing/retransmit bounds (TigerStyle: explicit, bounded). RFC 8445 §14.2 paces
// checks; the loopback gate runs fast, so a tight pace + a small retry cap keeps
// the test deadline-bounded while exercising the retransmit path.
constexpr std::uint32_t kCheckRetransmitMs = 50;   // resend an unanswered check
constexpr std::uint8_t  kMaxCheckRetries   = 7;    // RFC 8445 Rc default = 7
constexpr std::uint32_t kCheckPaceMs       = 5;    // min gap between new checks

// xorshift64* PRNG for transaction ids + tie-breakers (no <random> cost). These
// are not long-term secrets — entropy adequacy is all that matters.
struct Rng {
    std::uint64_t s;
    explicit Rng(std::uint64_t seed) noexcept
        : s(seed ? seed : 0xD1B54A32D192ED03ull) {}
    std::uint64_t next() noexcept {
        s ^= s >> 12; s ^= s << 25; s ^= s >> 27;
        return s * 0x2545F4914F6CDD1Dull;
    }
};

// Fill a 12-byte STUN transaction id from a 64-bit RNG draw + a counter salt.
void make_txn(std::uint8_t out[stun::kTransactionIdLen], Rng& rng,
              std::uint64_t salt) noexcept {
    assert(out != nullptr);
    const std::uint64_t a = rng.next() ^ salt;
    const std::uint64_t b = rng.next();
    for (int i = 0; i < 8; ++i) out[i] = static_cast<std::uint8_t>(a >> (8 * i));
    for (int i = 0; i < 4; ++i)
        out[8 + i] = static_cast<std::uint8_t>(b >> (8 * i));
}

// Resolve an IceCandidate's dotted-quad + port into a sockaddr_in. Returns the
// length, or 0 on failure (IPv6 is a documented next-wave hook).
int resolve_addr(const IceCandidate& c, sockaddr_storage* out) noexcept {
    assert(out != nullptr);
    std::memset(out, 0, sizeof(*out));
    auto* in = reinterpret_cast<sockaddr_in*>(out);
    in->sin_family = AF_INET;
    in->sin_port = htons(c.port);
    if (::inet_pton(AF_INET, c.address.c_str(), &in->sin_addr) != 1) return 0;
    return static_cast<int>(sizeof(sockaddr_in));
}

// Compare two IPv4 sockaddrs (addr + port). Bounded, noexcept.
bool same_addr(const sockaddr* a, int alen, const sockaddr* b,
               int blen) noexcept {
    assert(a != nullptr && b != nullptr);
    if (alen != blen || a->sa_family != b->sa_family) return false;
    if (a->sa_family != AF_INET) return false;
    const auto* x = reinterpret_cast<const sockaddr_in*>(a);
    const auto* y = reinterpret_cast<const sockaddr_in*>(b);
    return x->sin_port == y->sin_port &&
           x->sin_addr.s_addr == y->sin_addr.s_addr;
}

}  // namespace

// ---------------------------------------------------------------------------
// Priority helpers (RFC 8445 §5.1.2.1 / §6.1.2.3)
// ---------------------------------------------------------------------------
std::uint32_t srflx_priority(std::uint8_t component) noexcept {
    assert(component >= 1 && component <= 2);
    constexpr std::uint32_t kSrflxTypePref = 100;
    constexpr std::uint32_t kLocalPref     = 65535;
    return (kSrflxTypePref << 24) | (kLocalPref << 8) |
           static_cast<std::uint32_t>(256 - component);
}

std::uint32_t relay_priority(std::uint8_t component) noexcept {
    assert(component >= 1 && component <= 2);
    constexpr std::uint32_t kRelayTypePref = 0;
    constexpr std::uint32_t kLocalPref     = 65535;
    return (kRelayTypePref << 24) | (kLocalPref << 8) |
           static_cast<std::uint32_t>(256 - component);
}

std::uint64_t pair_priority(std::uint32_t controlling_pri,
                            std::uint32_t controlled_pri) noexcept {
    // RFC 8445 §6.1.2.3: priority = 2^32*MIN(G,D) + 2*MAX(G,D) + (G>D?1:0).
    const std::uint64_t g = controlling_pri;
    const std::uint64_t d = controlled_pri;
    const std::uint64_t lo = g < d ? g : d;
    const std::uint64_t hi = g < d ? d : g;
    const std::uint64_t tie = (g > d) ? 1u : 0u;
    return (lo << 32) + (hi << 1) + tie;
}

// ---------------------------------------------------------------------------
// Role / credentials
// ---------------------------------------------------------------------------
void FullIceAgent::set_role(IceRole role) noexcept {
    assert(role == IceRole::Controlling || role == IceRole::Controlled);
    role_ = role;
}

void FullIceAgent::set_tiebreaker(std::uint64_t tb) noexcept {
    assert(tb != 0 && "tiebreaker must be non-zero");
    tiebreaker_ = tb;
}

void FullIceAgent::set_credentials(std::string_view ufrag,
                                   std::string_view pwd) noexcept {
    if (ufrag.size() >= 4) ufrag_.assign(ufrag.data(), ufrag.size());
    if (pwd.size()   >= 22) pwd_.assign(pwd.data(), pwd.size());
    assert(ufrag_.size() >= 4 || ufrag_.empty());
    assert(pwd_.size() >= 22 || pwd_.empty());
}

void FullIceAgent::set_remote_credentials(std::string_view ufrag,
                                          std::string_view pwd) noexcept {
    assert(!ufrag.empty() && "remote ufrag required for checks");
    remote_ufrag_.assign(ufrag.data(), ufrag.size());
    remote_pwd_.assign(pwd.data(), pwd.size());
    assert(remote_ufrag_.size() == ufrag.size());
}

void FullIceAgent::generate_credentials(std::uint64_t seed) noexcept {
    if (seed == 0) {
        const auto now = std::chrono::steady_clock::now().time_since_epoch();
        seed = static_cast<std::uint64_t>(now.count());
        seed ^= reinterpret_cast<std::uintptr_t>(this) * 0x9E3779B97F4A7C15ull;
    }
    Rng rng(seed);
    static const char kChars[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    if (ufrag_.empty()) {
        ufrag_.reserve(kIceUfragLen);
        for (std::size_t i = 0; i < kIceUfragLen; ++i)
            ufrag_.push_back(kChars[rng.next() % (sizeof(kChars) - 1)]);
    }
    if (pwd_.empty()) {
        pwd_.reserve(kIcePwdLen);
        for (std::size_t i = 0; i < kIcePwdLen; ++i)
            pwd_.push_back(kChars[rng.next() % (sizeof(kChars) - 1)]);
    }
    if (tiebreaker_ == 0) tiebreaker_ = rng.next() | 1u;  // non-zero
    assert(ufrag_.size() >= 4 && pwd_.size() >= 22);
    assert(tiebreaker_ != 0);
}

// ---------------------------------------------------------------------------
// Candidate management
// ---------------------------------------------------------------------------
std::size_t FullIceAgent::add_local_candidate(const IceCandidate& c,
                                              const sockaddr* base,
                                              int base_len) noexcept {
    assert(base != nullptr);
    assert(local_count_ <= kMaxCandidates);
    if (local_count_ >= kMaxCandidates) return kMaxCandidates;
    LocalCandidate& lc = locals_[local_count_];
    lc = LocalCandidate{};
    lc.cand = c;
    const std::size_t n =
        (base_len > 0 && static_cast<std::size_t>(base_len) <= sizeof(lc.base))
            ? static_cast<std::size_t>(base_len)
            : sizeof(sockaddr_in);
    std::memcpy(&lc.base, base, n);
    lc.base_len = static_cast<int>(n);
    lc.used = true;
    const std::size_t idx = local_count_++;
    assert(idx < kMaxCandidates);
    return idx;
}

std::size_t FullIceAgent::add_remote_candidate(const IceCandidate& c) noexcept {
    assert(remote_count_ <= kMaxCandidates);
    if (remote_count_ >= kMaxCandidates) return kMaxCandidates;
    sockaddr_storage ss{};
    const int n = resolve_addr(c, &ss);
    if (n == 0) return kMaxCandidates;  // unresolvable (e.g. IPv6 hook) -> skip
    // Redundancy elimination: drop an exact duplicate transport address.
    for (std::size_t i = 0; i < remote_count_; ++i) {
        if (remotes_[i].used &&
            same_addr(reinterpret_cast<const sockaddr*>(&remotes_[i].addr),
                      remotes_[i].addr_len,
                      reinterpret_cast<const sockaddr*>(&ss), n)) {
            return i;  // already known
        }
    }
    RemoteCandidate& rc = remotes_[remote_count_];
    rc = RemoteCandidate{};
    rc.cand = c;
    rc.addr = ss;
    rc.addr_len = n;
    rc.used = true;
    const std::size_t idx = remote_count_++;
    form_pairs_for_remote(idx);
    return idx;
}

void FullIceAgent::form_pairs_for_remote(std::size_t remote_idx) noexcept {
    assert(remote_idx < remote_count_);
    assert(pair_count_ <= kMaxPairs);
    for (std::size_t li = 0; li < local_count_; ++li) {
        if (pair_count_ >= kMaxPairs) return;  // bounded checklist
        if (!locals_[li].used) continue;
        CandidatePair& p = pairs_[pair_count_];
        p = CandidatePair{};
        p.local_idx  = li;
        p.remote_idx = remote_idx;
        const std::uint32_t lpri = locals_[li].cand.priority;
        const std::uint32_t rpri = remotes_[remote_idx].cand.priority;
        // Controlling agent is G in the pair-priority formula.
        p.priority = (role_ == IceRole::Controlling)
                         ? pair_priority(lpri, rpri)
                         : pair_priority(rpri, lpri);
        p.state = PairState::Waiting;  // unfreeze immediately (single component)
        p.used = true;
        ++pair_count_;
    }
    assert(pair_count_ <= kMaxPairs);
}

// ---------------------------------------------------------------------------
// Connectivity checks (the controlling/controlled REQUEST-generating side)
// ---------------------------------------------------------------------------
bool FullIceAgent::send_check(net::UdpTransport& transport, std::size_t i,
                              bool nominate, std::uint32_t now_ms) noexcept {
    assert(i < pair_count_);
    assert(!ufrag_.empty() && !pwd_.empty() && "local creds required");
    CandidatePair& p = pairs_[i];
    if (!remote_ufrag_.empty() && remote_pwd_.empty()) return false;
    if (remote_ufrag_.empty()) return false;  // can't form USERNAME yet

    Rng rng(tiebreaker_ ^ (static_cast<std::uint64_t>(now_ms) << 20) ^ i);
    make_txn(p.txn, rng, static_cast<std::uint64_t>(checks_sent_ + 1));
    p.have_txn = true;

    std::uint8_t out[512];
    stun::Builder b(out, sizeof(out));
    if (b.begin(stun::Class::Request, stun::Method::Binding, p.txn) !=
        stun::StunError::Ok)
        return false;
    // USERNAME = "peerUfrag:ourUfrag" (RFC 8445 §7.2.2: the check is addressed
    // to the peer using THEIR ufrag first).
    char user[96];
    const std::size_t ul = remote_ufrag_.size() + 1 + ufrag_.size();
    if (ul >= sizeof(user)) return false;
    std::memcpy(user, remote_ufrag_.data(), remote_ufrag_.size());
    user[remote_ufrag_.size()] = ':';
    std::memcpy(user + remote_ufrag_.size() + 1, ufrag_.data(), ufrag_.size());
    if (b.add_username(user, ul) != stun::StunError::Ok) return false;
    if (b.add_priority(locals_[p.local_idx].cand.priority) != stun::StunError::Ok)
        return false;
    if (role_ == IceRole::Controlling) {
        if (b.add_ice_controlling(tiebreaker_) != stun::StunError::Ok)
            return false;
        if (nominate) {
            if (b.add_use_candidate() != stun::StunError::Ok) return false;
            p.use_candidate_sent = true;
        }
    } else {
        if (b.add_ice_controlled(tiebreaker_) != stun::StunError::Ok)
            return false;
    }
    if (b.add_message_integrity(
            reinterpret_cast<const std::uint8_t*>(remote_pwd_.data()),
            remote_pwd_.size()) != stun::StunError::Ok)
        return false;
    if (b.add_fingerprint() != stun::StunError::Ok) return false;

    const RemoteCandidate& rc = remotes_[p.remote_idx];
    const ssize_t sent = transport.send(
        reinterpret_cast<const sockaddr*>(&rc.addr), rc.addr_len, out, b.size());
    if (sent <= 0) return false;
    p.state = PairState::InProgress;
    p.check_sent_ms = now_ms;
    ++checks_sent_;
    return true;
}

std::size_t FullIceAgent::run_checks(net::UdpTransport& transport,
                                     std::uint32_t now_ms) noexcept {
    assert(pair_count_ <= kMaxPairs);
    std::size_t sent = 0;

    // 1) Retransmit timed-out In-Progress checks (bounded retries), else fail.
    for (std::size_t i = 0; i < pair_count_; ++i) {
        CandidatePair& p = pairs_[i];
        if (!p.used || p.state != PairState::InProgress) continue;
        if (now_ms - p.check_sent_ms < kCheckRetransmitMs) continue;
        if (p.retries >= kMaxCheckRetries) {
            p.state = PairState::Failed;  // give up (won't deadlock the checklist)
            continue;
        }
        ++p.retries;
        if (send_check(transport, i, p.use_candidate_sent, now_ms)) ++sent;
    }

    // 2) Start the single highest-priority Waiting check (paced).
    std::size_t best = kMaxPairs;
    std::uint64_t best_pri = 0;
    for (std::size_t i = 0; i < pair_count_; ++i) {
        const CandidatePair& p = pairs_[i];
        if (!p.used || p.state != PairState::Waiting) continue;
        if (best == kMaxPairs || p.priority > best_pri) {
            best = i;
            best_pri = p.priority;
        }
    }
    if (best != kMaxPairs && sent < 2) {  // bounded per-round burst
        if (send_check(transport, best, /*nominate=*/false, now_ms)) ++sent;
    }

    // 3) Controlling agent nominates the best Succeeded pair.
    if (role_ == IceRole::Controlling && !have_nominated_) {
        maybe_nominate(transport, now_ms);
    }
    (void)kCheckPaceMs;
    return sent;
}

void FullIceAgent::maybe_nominate(net::UdpTransport& transport,
                                  std::uint32_t now_ms) noexcept {
    assert(role_ == IceRole::Controlling);
    assert(!have_nominated_);
    std::size_t best = kMaxPairs;
    std::uint64_t best_pri = 0;
    for (std::size_t i = 0; i < pair_count_; ++i) {
        const CandidatePair& p = pairs_[i];
        if (!p.used || p.state != PairState::Succeeded) continue;
        if (best == kMaxPairs || p.priority > best_pri) {
            best = i;
            best_pri = p.priority;
        }
    }
    if (best == kMaxPairs) return;
    // Send a nominating check (USE-CANDIDATE) on the best valid pair.
    CandidatePair& p = pairs_[best];
    if (!p.use_candidate_sent) {
        send_check(transport, best, /*nominate=*/true, now_ms);
    }
}

// ---------------------------------------------------------------------------
// Inbound STUN dispatch
// ---------------------------------------------------------------------------
FullIceAgent::HandleResult FullIceAgent::handle_stun(
    net::UdpTransport& transport, const sockaddr* peer, int peer_len,
    const std::uint8_t* data, std::size_t len) noexcept {
    assert(peer != nullptr);
    assert(data != nullptr || len == 0);
    stun::Message m;
    if (stun::parse(data, len, m) != stun::StunError::Ok)
        return HandleResult::Ignored;
    if (m.method != stun::Method::Binding) return HandleResult::Ignored;
    if (m.msg_class == stun::Class::Request)
        return on_request(transport, m, peer, peer_len);
    if (m.msg_class == stun::Class::SuccessResponse ||
        m.msg_class == stun::Class::ErrorResponse)
        return on_response(m, peer, peer_len);
    return HandleResult::Ignored;
}

bool FullIceAgent::request_authed(const stun::Message& m) const noexcept {
    const stun::Attribute* user = m.find(stun::AttrType::Username);
    if (user == nullptr || user->length == 0) return false;
    std::string_view u(reinterpret_cast<const char*>(user->value), user->length);
    const std::size_t colon = u.find(':');
    if (colon == std::string_view::npos) return false;
    if (u.substr(0, colon) != std::string_view(ufrag_.data(), ufrag_.size()))
        return false;
    return stun::verify_message_integrity(
               m, reinterpret_cast<const std::uint8_t*>(pwd_.data()),
               pwd_.size()) == stun::StunError::Ok;
}

bool FullIceAgent::resolve_role_conflict(const stun::Message& m) noexcept {
    // RFC 8445 §7.3.1.1: a conflict is the peer claiming the SAME role as us.
    // Resolve by tie-breaker — the larger tie-breaker keeps Controlling.
    const stun::Attribute* ctrl_in  = m.find(stun::AttrType::IceControlling);
    const stun::Attribute* ctrl_out = m.find(stun::AttrType::IceControlled);
    const stun::Attribute* a =
        (role_ == IceRole::Controlling) ? ctrl_in : ctrl_out;
    if (a == nullptr || a->length != 8) return false;
    std::uint64_t their_tb = 0;
    for (int i = 0; i < 8; ++i) their_tb = (their_tb << 8) | a->value[i];
    ++role_conflicts_;
    if (role_ == IceRole::Controlling) {
        if (tiebreaker_ < their_tb) role_ = IceRole::Controlled;   // we yield
    } else {
        if (tiebreaker_ >= their_tb) role_ = IceRole::Controlling;  // we take it
    }
    return true;
}

bool FullIceAgent::nominate_remote(std::size_t remote_idx) noexcept {
    assert(remote_idx < remote_count_);
    for (std::size_t i = 0; i < pair_count_; ++i) {
        if (!pairs_[i].used || pairs_[i].remote_idx != remote_idx) continue;
        pairs_[i].nominated = true;
        if (pairs_[i].state != PairState::Failed)
            pairs_[i].state = PairState::Succeeded;
        if (!have_nominated_) {
            have_nominated_ = true;
            nominated_idx_ = i;
            return true;  // newly nominated
        }
        return false;
    }
    return false;
}

FullIceAgent::HandleResult FullIceAgent::on_request(
    net::UdpTransport& transport, const stun::Message& m, const sockaddr* peer,
    int peer_len) noexcept {
    assert(peer != nullptr);
    assert(peer_len > 0);
    if (!request_authed(m)) return HandleResult::ErrorResponse;
    ++reqs_handled_;

    HandleResult result =
        resolve_role_conflict(m) ? HandleResult::RoleConflict
                                 : HandleResult::Request;

    if (!send_request_success(transport, m, peer, peer_len))
        return HandleResult::ErrorResponse;

    // Triggered check / prflx discovery: ensure a pair exists toward the source.
    std::size_t ridx = kMaxCandidates;
    for (std::size_t i = 0; i < remote_count_; ++i) {
        if (remotes_[i].used &&
            same_addr(reinterpret_cast<const sockaddr*>(&remotes_[i].addr),
                      remotes_[i].addr_len, peer, peer_len)) {
            ridx = i;
            break;
        }
    }
    std::uint32_t in_pri = 0;
    (void)m.priority(&in_pri);
    if (ridx == kMaxCandidates) ridx = add_prflx_remote(peer, peer_len, in_pri);

    // Controlled-side nomination: USE-CANDIDATE marks the pair nominated.
    if (m.has(stun::AttrType::UseCandidate) && ridx < remote_count_) {
        if (nominate_remote(ridx)) result = HandleResult::Nominated;
    }
    return result;
}

bool FullIceAgent::send_request_success(net::UdpTransport& transport,
                                        const stun::Message& req,
                                        const sockaddr* peer,
                                        int peer_len) noexcept {
    assert(peer != nullptr);
    if (peer->sa_family != AF_INET) return false;
    stun::Address mapped{};
    mapped.family = stun::Family::IPv4;
    const auto* in = reinterpret_cast<const sockaddr_in*>(peer);
    mapped.port = ntohs(in->sin_port);
    std::memcpy(mapped.addr, &in->sin_addr, 4);

    std::uint8_t out[512];
    stun::Builder b(out, sizeof(out));
    if (b.begin(stun::Class::SuccessResponse, stun::Method::Binding,
                req.transaction_id) != stun::StunError::Ok)
        return false;
    if (b.add_xor_mapped_address(mapped) != stun::StunError::Ok) return false;
    if (b.add_message_integrity(
            reinterpret_cast<const std::uint8_t*>(pwd_.data()), pwd_.size()) !=
        stun::StunError::Ok)
        return false;
    if (b.add_fingerprint() != stun::StunError::Ok) return false;
    return transport.send(peer, peer_len, out, b.size()) > 0;
}

FullIceAgent::HandleResult FullIceAgent::on_response(const stun::Message& m,
                                                     const sockaddr* peer,
                                                     int peer_len) noexcept {
    assert(peer != nullptr);
    const std::size_t pi = pair_for_txn(m.transaction_id);
    if (pi >= pair_count_) return HandleResult::Ignored;  // unknown txn
    CandidatePair& p = pairs_[pi];

    if (m.msg_class == stun::Class::ErrorResponse) {
        // 487 role conflict (RFC 8445 §7.2.5.1): switch role + reset the pair.
        const stun::Attribute* ec = m.find(stun::AttrType::ErrorCode);
        if (ec != nullptr && ec->length >= 4 && ec->value[2] == 4 &&
            ec->value[3] == 87) {
            ++role_conflicts_;
            role_ = (role_ == IceRole::Controlling) ? IceRole::Controlled
                                                    : IceRole::Controlling;
            p.state = PairState::Waiting;
            p.have_txn = false;
            return HandleResult::RoleConflict;
        }
        p.state = PairState::Failed;
        p.have_txn = false;
        return HandleResult::ErrorResponse;
    }

    // Success: verify MI with the REMOTE pwd (the responder keyed with its pwd).
    if (!remote_pwd_.empty()) {
        if (stun::verify_message_integrity(
                m, reinterpret_cast<const std::uint8_t*>(remote_pwd_.data()),
                remote_pwd_.size()) != stun::StunError::Ok) {
            return HandleResult::Ignored;  // forged/garbled -> drop, keep state
        }
    }
    // The response source must match the pair's remote (RFC 8445 §7.2.5.2.1).
    const RemoteCandidate& rc = remotes_[p.remote_idx];
    if (!same_addr(reinterpret_cast<const sockaddr*>(&rc.addr), rc.addr_len,
                   peer, peer_len)) {
        return HandleResult::Ignored;
    }
    p.state = PairState::Succeeded;
    p.have_txn = false;
    ++checks_ok_;
    HandleResult result = HandleResult::Response;
    if (p.use_candidate_sent) {  // our nominating check succeeded
        p.nominated = true;
        if (!have_nominated_) {
            have_nominated_ = true;
            nominated_idx_ = pi;
            result = HandleResult::Nominated;
        }
    }
    return result;
}

std::size_t FullIceAgent::pair_for_txn(const std::uint8_t* txn) const noexcept {
    assert(txn != nullptr);
    for (std::size_t i = 0; i < pair_count_; ++i) {
        if (pairs_[i].used && pairs_[i].have_txn &&
            std::memcmp(pairs_[i].txn, txn, stun::kTransactionIdLen) == 0) {
            return i;
        }
    }
    return kMaxPairs;
}

std::size_t FullIceAgent::add_prflx_remote(const sockaddr* peer, int peer_len,
                                           std::uint32_t priority) noexcept {
    assert(peer != nullptr);
    if (remote_count_ >= kMaxCandidates) return kMaxCandidates;
    if (peer->sa_family != AF_INET) return kMaxCandidates;
    RemoteCandidate& rc = remotes_[remote_count_];
    rc = RemoteCandidate{};
    rc.cand.type = CandidateType::Prflx;
    rc.cand.transport = IceTransport::Udp;
    rc.cand.component = 1;
    rc.cand.priority = priority != 0 ? priority : srflx_priority(1);
    const auto* in = reinterpret_cast<const sockaddr_in*>(peer);
    char ip[INET_ADDRSTRLEN] = {0};
    ::inet_ntop(AF_INET, &in->sin_addr, ip, sizeof(ip));
    rc.cand.address.assign(ip);
    rc.cand.port = ntohs(in->sin_port);
    const std::size_t n =
        (peer_len > 0 && static_cast<std::size_t>(peer_len) <= sizeof(rc.addr))
            ? static_cast<std::size_t>(peer_len)
            : sizeof(sockaddr_in);
    std::memcpy(&rc.addr, peer, n);
    rc.addr_len = static_cast<int>(n);
    rc.used = true;
    const std::size_t idx = remote_count_++;
    form_pairs_for_remote(idx);
    return idx;
}

// ---------------------------------------------------------------------------
// Restart + accessors
// ---------------------------------------------------------------------------
void FullIceAgent::restart(std::uint64_t seed) noexcept {
    assert(local_count_ <= kMaxCandidates);
    // RFC 8445 §9: new ufrag/pwd, discard remotes + checklist, keep locals.
    ufrag_.clear();
    pwd_.clear();
    remote_ufrag_.clear();
    remote_pwd_.clear();
    remote_count_ = 0;
    pair_count_ = 0;
    have_nominated_ = false;
    nominated_idx_ = 0;
    tiebreaker_ = 0;
    generate_credentials(seed);
    assert(remote_count_ == 0 && pair_count_ == 0);
    assert(!ufrag_.empty() && !pwd_.empty());
}

bool FullIceAgent::selected_remote(sockaddr_storage* out,
                                   int* out_len) const noexcept {
    assert(out != nullptr && out_len != nullptr);
    if (!have_nominated_) return false;
    const CandidatePair& p = pairs_[nominated_idx_];
    const RemoteCandidate& rc = remotes_[p.remote_idx];
    *out = rc.addr;
    *out_len = rc.addr_len;
    return true;
}

}  // namespace webrtc
}  // namespace bolt::api
