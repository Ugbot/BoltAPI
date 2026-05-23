// src/webrtc/ice.cpp — ICE-lite agent implementation.
//
// PORTED:  IceCandidate::to_string  (FasterAPI src/cpp/webrtc/ice.cpp:13-39),
//          reshaped to manual std::string append (no <sstream>), -fno-exceptions.
// REBUILT: IceCandidate::from_string (real tokenizer), host gathering via
//          GetAdaptersAddresses / getifaddrs, RFC 8445 credential generation,
//          and the STUN binding-request responder (FasterAPI had none).
//
// Compiled UNCONDITIONALLY into boltapi.

#include "boltapi/webrtc/ice.h"

#include "boltapi/net/udp_transport.h"

#include <charconv>
#include <chrono>
#include <cstring>

#ifdef _WIN32
#include <iphlpapi.h>  // GetAdaptersAddresses
#else
#include <ifaddrs.h>
#include <net/if.h>
#endif

namespace bolt::api {
namespace webrtc {

namespace {

// Append a decimal integer to a std::string (no <sstream>).
void append_uint(std::string& out, std::uint64_t v) {
    char buf[20];
    auto r = std::to_chars(buf, buf + sizeof(buf), v);
    out.append(buf, static_cast<std::size_t>(r.ptr - buf));
}

const char* type_str(CandidateType t) noexcept {
    switch (t) {
        case CandidateType::Host:  return "host";
        case CandidateType::Srflx: return "srflx";
        case CandidateType::Prflx: return "prflx";
        case CandidateType::Relay: return "relay";
    }
    return "host";
}

bool parse_type(std::string_view s, CandidateType* out) noexcept {
    if (s == "host")  { *out = CandidateType::Host;  return true; }
    if (s == "srflx") { *out = CandidateType::Srflx; return true; }
    if (s == "prflx") { *out = CandidateType::Prflx; return true; }
    if (s == "relay") { *out = CandidateType::Relay; return true; }
    return false;
}

template <typename T>
bool parse_uint(std::string_view s, T* out) noexcept {
    if (s.empty()) return false;
    T v{};
    auto r = std::from_chars(s.data(), s.data() + s.size(), v);
    if (r.ec != std::errc{} || r.ptr != s.data() + s.size()) return false;
    *out = v;
    return true;
}

// Split off the next whitespace-delimited token; advance `s` past it.
std::string_view next_token(std::string_view& s) noexcept {
    std::size_t start = 0;
    while (start < s.size() && s[start] == ' ') ++start;
    std::size_t end = start;
    while (end < s.size() && s[end] != ' ') ++end;
    std::string_view tok = s.substr(start, end - start);
    s = (end < s.size()) ? s.substr(end + 1) : std::string_view{};
    return tok;
}

// RFC 8445 §5.3 ICE character set: ALPHA / DIGIT / '+' / '/'. We use the
// alphanumeric subset (browsers accept it) for a clean, URL/SDP-safe credential.
const char kIceChars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

// xorshift64* — small deterministic PRNG (no <random> heap/locale cost). Good
// enough for ICE credential entropy (these are not long-term secrets).
struct Rng {
    std::uint64_t s;
    explicit Rng(std::uint64_t seed) noexcept : s(seed ? seed : 0x9E3779B97F4A7C15ull) {}
    std::uint64_t next() noexcept {
        s ^= s >> 12; s ^= s << 25; s ^= s >> 27;
        return s * 0x2545F4914F6CDD1Dull;
    }
};

void fill_random(std::string& out, std::size_t n, Rng& rng) noexcept {
    out.clear();
    out.reserve(n);
    for (std::size_t i = 0; i < n; ++i) {
        out.push_back(kIceChars[rng.next() % (sizeof(kIceChars) - 1)]);
    }
}

}  // namespace

// ---------------------------------------------------------------------------
// host_priority (RFC 8445 §5.1.2.1)
// ---------------------------------------------------------------------------
std::uint32_t host_priority(std::uint8_t component) noexcept {
    constexpr std::uint32_t kHostTypePref = 126;    // RFC 8445 recommended
    constexpr std::uint32_t kLocalPref    = 65535;  // single interface class
    return (kHostTypePref << 24) | (kLocalPref << 8) |
           static_cast<std::uint32_t>(256 - component);
}

// ---------------------------------------------------------------------------
// IceCandidate::to_string — PORTED from FasterAPI ice.cpp:13-39.
// ---------------------------------------------------------------------------
std::string IceCandidate::to_string() const {
    std::string out;
    out.reserve(64);
    out.append("candidate:");
    out.append(foundation);
    out.push_back(' ');
    append_uint(out, component);
    out.push_back(' ');
    out.append(transport == IceTransport::Udp ? "udp" : "tcp");
    out.push_back(' ');
    append_uint(out, priority);
    out.push_back(' ');
    out.append(address);
    out.push_back(' ');
    append_uint(out, port);
    out.append(" typ ");
    out.append(type_str(type));
    if (type != CandidateType::Host && !related_address.empty()) {
        out.append(" raddr ");
        out.append(related_address);
        out.append(" rport ");
        append_uint(out, related_port);
    }
    return out;
}

// ---------------------------------------------------------------------------
// IceCandidate::from_string — REBUILT real tokenizing parser.
//   candidate:<foundation> <component> <proto> <priority> <addr> <port>
//             typ <type> [raddr <ra> rport <rp>]
// ---------------------------------------------------------------------------
bool IceCandidate::from_string(std::string_view s, IceCandidate& out) noexcept {
    out = IceCandidate{};
    // Optional "candidate:" prefix.
    constexpr std::string_view kPrefix = "candidate:";
    if (s.substr(0, kPrefix.size()) == kPrefix) s.remove_prefix(kPrefix.size());

    std::string_view foundation = next_token(s);
    if (foundation.empty()) return false;
    out.foundation.assign(foundation.data(), foundation.size());

    std::string_view comp = next_token(s);
    if (!parse_uint(comp, &out.component)) return false;

    std::string_view proto = next_token(s);
    if (proto == "udp" || proto == "UDP")      out.transport = IceTransport::Udp;
    else if (proto == "tcp" || proto == "TCP") out.transport = IceTransport::Tcp;
    else return false;

    if (!parse_uint(next_token(s), &out.priority)) return false;

    std::string_view addr = next_token(s);
    if (addr.empty()) return false;
    out.address.assign(addr.data(), addr.size());

    if (!parse_uint(next_token(s), &out.port)) return false;

    std::string_view typ_kw = next_token(s);
    if (typ_kw != "typ") return false;
    if (!parse_type(next_token(s), &out.type)) return false;

    // Optional raddr/rport (and any further extension attrs are ignored).
    while (!s.empty()) {
        std::string_view k = next_token(s);
        if (k.empty()) break;
        std::string_view v = next_token(s);
        if (k == "raddr") {
            out.related_address.assign(v.data(), v.size());
        } else if (k == "rport") {
            if (!parse_uint(v, &out.related_port)) return false;
        }
        // unknown key=value extension: skip silently.
    }
    return true;
}

// ---------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------
void IceAgent::set_credentials(std::string_view ufrag, std::string_view pwd) noexcept {
    if (ufrag.size() >= 4) ufrag_.assign(ufrag.data(), ufrag.size());
    if (pwd.size()   >= 22) pwd_.assign(pwd.data(), pwd.size());
}

void IceAgent::set_expected_remote(std::string_view ufrag,
                                   std::string_view pwd) noexcept {
    remote_ufrag_.assign(ufrag.data(), ufrag.size());
    remote_pwd_.assign(pwd.data(), pwd.size());
}

void IceAgent::generate_credentials(std::uint64_t seed) noexcept {
    if (seed == 0) {
        const auto now = std::chrono::steady_clock::now().time_since_epoch();
        seed = static_cast<std::uint64_t>(now.count());
        seed ^= reinterpret_cast<std::uintptr_t>(this) * 0x9E3779B97F4A7C15ull;
    }
    Rng rng(seed);
    if (ufrag_.empty()) fill_random(ufrag_, kIceUfragLen, rng);
    if (pwd_.empty())   fill_random(pwd_,   kIcePwdLen,   rng);
}

// ---------------------------------------------------------------------------
// Host candidate gathering
// ---------------------------------------------------------------------------
std::size_t IceAgent::gather_host_candidates(std::uint16_t port,
                                             std::string_view bind_host) noexcept {
    candidate_count_ = 0;
    net::sys::startup();

    auto add_candidate = [&](const char* ipv4, bool is_loopback) -> void {
        if (candidate_count_ >= kIceMaxCandidates) return;
        IceCandidate& c = candidates_[candidate_count_];
        c = IceCandidate{};
        c.type      = CandidateType::Host;
        c.transport = IceTransport::Udp;
        c.component = 1;
        c.priority  = host_priority(1);
        c.address.assign(ipv4);
        c.port      = port;
        // Foundation: per RFC 8445 §5.1.1.3 same base+type+proto share a
        // foundation; for our single-component host set a simple decimal index
        // is sufficient and unique-per-base here.
        c.foundation.clear();
        append_uint(c.foundation, candidate_count_ + 1);
        (void)is_loopback;
        ++candidate_count_;
    };

    // Specific bind address: the socket only receives datagrams sent to it, so
    // advertise EXACTLY that one host candidate (RFC 8445 — a candidate is a
    // transport address the peer can actually reach us on). A wildcard / empty
    // bind falls through to full interface enumeration.
    if (!bind_host.empty() && bind_host != "0.0.0.0") {
        char hostbuf[INET6_ADDRSTRLEN] = {0};
        const std::size_t n =
            bind_host.size() < sizeof(hostbuf) ? bind_host.size()
                                               : sizeof(hostbuf) - 1;
        std::memcpy(hostbuf, bind_host.data(), n);
        add_candidate(hostbuf, std::strncmp(hostbuf, "127.", 4) == 0);
        return candidate_count_;
    }

    char loopback_ip[INET_ADDRSTRLEN] = {0};
    bool have_nonloopback = false;

#ifdef _WIN32
    // GetAdaptersAddresses (link iphlpapi). One sizing call then one fill.
    ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                  GAA_FLAG_SKIP_DNS_SERVER;
    ULONG size = 0;
    if (::GetAdaptersAddresses(AF_INET, flags, nullptr, nullptr, &size) ==
        ERROR_BUFFER_OVERFLOW && size > 0) {
        auto* buf = static_cast<IP_ADAPTER_ADDRESSES*>(std::malloc(size));
        if (buf != nullptr) {
            // sys_compat.h #undef's NO_ERROR; use ERROR_SUCCESS (== 0).
            if (::GetAdaptersAddresses(AF_INET, flags, nullptr, buf, &size) ==
                ERROR_SUCCESS) {
                for (auto* ad = buf; ad != nullptr; ad = ad->Next) {
                    if (ad->OperStatus != IfOperStatusUp) continue;
                    for (auto* ua = ad->FirstUnicastAddress; ua != nullptr;
                         ua = ua->Next) {
                        auto* sa = ua->Address.lpSockaddr;
                        if (sa == nullptr || sa->sa_family != AF_INET) continue;
                        auto* in = reinterpret_cast<sockaddr_in*>(sa);
                        char ip[INET_ADDRSTRLEN] = {0};
                        if (::inet_ntop(AF_INET, &in->sin_addr, ip,
                                        sizeof(ip)) == nullptr)
                            continue;
                        const bool loop =
                            (ad->IfType == IF_TYPE_SOFTWARE_LOOPBACK) ||
                            (std::strncmp(ip, "127.", 4) == 0);
                        if (loop) {
                            if (loopback_ip[0] == '\0')
                                std::strncpy(loopback_ip, ip, sizeof(loopback_ip) - 1);
                            continue;
                        }
                        add_candidate(ip, false);
                        have_nonloopback = true;
                    }
                }
            }
            std::free(buf);
        }
    }
#else
    struct ifaddrs* ifaddr = nullptr;
    if (::getifaddrs(&ifaddr) == 0) {
        for (auto* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr == nullptr) continue;
            if (ifa->ifa_addr->sa_family != AF_INET) continue;
            if ((ifa->ifa_flags & IFF_UP) == 0) continue;
            auto* in = reinterpret_cast<sockaddr_in*>(ifa->ifa_addr);
            char ip[INET_ADDRSTRLEN] = {0};
            if (::inet_ntop(AF_INET, &in->sin_addr, ip, sizeof(ip)) == nullptr)
                continue;
            const bool loop = (ifa->ifa_flags & IFF_LOOPBACK) ||
                              (std::strncmp(ip, "127.", 4) == 0);
            if (loop) {
                if (loopback_ip[0] == '\0')
                    std::strncpy(loopback_ip, ip, sizeof(loopback_ip) - 1);
                continue;
            }
            add_candidate(ip, false);
            have_nonloopback = true;
        }
        ::freeifaddrs(ifaddr);
    }
#endif

    // Always advertise a loopback host candidate too (in addition to the real
    // interfaces) when the socket is bound to all interfaces: a peer on the SAME
    // host (incl. the aiortc interop gate) reaches us over 127.0.0.1, and a
    // no-NIC / tightly-firewalled box still yields >= 1 candidate. The socket is
    // bound to 0.0.0.0, so the loopback candidate is genuinely reachable.
    if (candidate_count_ < kIceMaxCandidates) {
        add_candidate(loopback_ip[0] ? loopback_ip : "127.0.0.1", true);
    }
    (void)have_nonloopback;

    return candidate_count_;
}

// ---------------------------------------------------------------------------
// STUN binding-request handling (ICE-lite responder).
// ---------------------------------------------------------------------------
IceAgent::HandleResult IceAgent::handle_stun(net::UdpTransport& transport,
                                             const sockaddr* peer, int peer_len,
                                             const std::uint8_t* data,
                                             std::size_t len) noexcept {
    stun::Message msg;
    if (stun::parse(data, len, msg) != stun::StunError::Ok) {
        return HandleResult::Ignored;  // malformed -> drop, never crash
    }
    // Only Binding Requests are handled by the controlled agent.
    if (msg.msg_class != stun::Class::Request ||
        msg.method != stun::Method::Binding) {
        return HandleResult::Ignored;
    }
    ++rx_requests_;

    // USERNAME must be present and of the form "ourUfrag:peerUfrag".
    const stun::Attribute* user = msg.find(stun::AttrType::Username);
    if (user == nullptr || user->length == 0) {
        send_error(transport, msg, 400, "Bad Request", peer, peer_len);
        return HandleResult::ErrorResponse;
    }
    std::string_view username(reinterpret_cast<const char*>(user->value),
                              user->length);
    const std::size_t colon = username.find(':');
    if (colon == std::string_view::npos) {
        send_error(transport, msg, 400, "Bad Request", peer, peer_len);
        return HandleResult::ErrorResponse;
    }
    const std::string_view req_local_ufrag = username.substr(0, colon);
    if (req_local_ufrag !=
        std::string_view(ufrag_.data(), ufrag_.size())) {
        // Wrong username (not addressed to us / unknown ufrag) -> 401.
        send_error(transport, msg, 401, "Unauthorized", peer, peer_len);
        return HandleResult::ErrorResponse;
    }
    // When the peer ufrag is known from signaling, the request's peer-side token
    // must match it too (RFC 8445 §7.3 — addressed FROM the expected peer).
    if (!remote_ufrag_.empty()) {
        const std::string_view req_peer_ufrag = username.substr(colon + 1);
        if (req_peer_ufrag !=
            std::string_view(remote_ufrag_.data(), remote_ufrag_.size())) {
            send_error(transport, msg, 401, "Unauthorized", peer, peer_len);
            return HandleResult::ErrorResponse;
        }
    }

    // MESSAGE-INTEGRITY must verify against OUR ice-pwd.
    const stun::StunError mi = stun::verify_message_integrity(
        msg, reinterpret_cast<const std::uint8_t*>(pwd_.data()), pwd_.size());
    if (mi != stun::StunError::Ok) {
        send_error(transport, msg, 401, "Unauthorized", peer, peer_len);
        return HandleResult::ErrorResponse;
    }

    // Valid request: send the Binding Success Response.
    if (!send_success(transport, msg, peer, peer_len)) {
        return HandleResult::ErrorResponse;  // send failed; nothing more we can do
    }

    // USE-CANDIDATE => nominate this pair (controlled agent, RFC 8445 §7.3.1.5).
    if (msg.has(stun::AttrType::UseCandidate)) {
        std::memset(&selected_peer_, 0, sizeof(selected_peer_));
        const std::size_t cplen =
            (peer_len > 0 &&
             static_cast<std::size_t>(peer_len) <= sizeof(selected_peer_))
                ? static_cast<std::size_t>(peer_len)
                : sizeof(sockaddr_in);
        std::memcpy(&selected_peer_, peer, cplen);
        selected_peer_len_ = static_cast<int>(cplen);
        have_selected_ = true;
        return HandleResult::RespondedSelected;
    }
    return HandleResult::Responded;
}

bool IceAgent::send_success(net::UdpTransport& transport,
                            const stun::Message& req, const sockaddr* peer,
                            int peer_len) noexcept {
    // XOR-MAPPED-ADDRESS = the peer's source transport address (IPv4 here).
    stun::Address mapped{};
    mapped.family = stun::Family::IPv4;
    if (peer->sa_family == AF_INET) {
        const auto* in = reinterpret_cast<const sockaddr_in*>(peer);
        mapped.port = ntohs(in->sin_port);
        std::memcpy(mapped.addr, &in->sin_addr, 4);  // network byte order
    } else {
        return false;  // IPv6 mapped-address is a TODO hook (next wave)
    }

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

    const ssize_t n = transport.send(peer, peer_len, out, b.size());
    if (n <= 0) return false;
    ++tx_responses_;
    return true;
}

bool IceAgent::send_error(net::UdpTransport& transport, const stun::Message& req,
                          std::uint16_t code, const char* reason,
                          const sockaddr* peer, int peer_len) noexcept {
    std::uint8_t out[512];
    stun::Builder b(out, sizeof(out));
    if (b.begin(stun::Class::ErrorResponse, stun::Method::Binding,
                req.transaction_id) != stun::StunError::Ok)
        return false;
    if (b.add_error_code(code, reason, reason ? std::strlen(reason) : 0) !=
        stun::StunError::Ok)
        return false;
    // MESSAGE-INTEGRITY on an error response is only added when we share a
    // credential; for a 400/401 we send FINGERPRINT only (RFC 5389 §10.1.2
    // permits omitting MI on 400/401). FINGERPRINT aids demux/diagnosis.
    if (b.add_fingerprint() != stun::StunError::Ok) return false;

    const ssize_t n = transport.send(peer, peer_len, out, b.size());
    if (n <= 0) return false;
    ++tx_errors_;
    return true;
}

}  // namespace webrtc
}  // namespace bolt::api
