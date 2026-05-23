// ice_test.cpp — THE LIVE STUN GATE for the ICE-lite agent.
//
// This is the real interop gate: a UdpTransport + ICE-lite IceAgent run on an
// ephemeral UDP port with KNOWN ufrag/pwd. From a raw client UDP socket we build
// a REAL STUN Binding Request (via the Bolt-API STUN codec) carrying:
//   USERNAME "ourUfrag:peerUfrag" + PRIORITY + ICE-CONTROLLING + USE-CANDIDATE
//   + MESSAGE-INTEGRITY (our pwd) + FINGERPRINT
// then sendto the transport and read the response off the wire. We assert:
//   * it is a Binding SUCCESS response,
//   * XOR-MAPPED-ADDRESS == the client's own source address,
//   * MESSAGE-INTEGRITY verifies with our pwd,
//   * FINGERPRINT verifies,
//   * USE-CANDIDATE nominated the peer (selected pair).
// Negative: a request with WRONG integrity is rejected (no success) and the
// server does not crash. Plus: host-candidate gathering returns >= 1 candidate,
// and candidate to_string/from_string round-trips.

#include "boltapi/net/udp_transport.h"
#include "boltapi/net/io_dispatcher.h"
#include "boltapi/core/worker_pool.h"
#include "boltapi/webrtc/ice.h"
#include "boltapi/webrtc/stun.h"

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <thread>

namespace net  = bolt::api::net;
namespace sys  = bolt::api::net::sys;
namespace core = bolt::api::core;
namespace ice  = bolt::api::webrtc;
namespace stun = bolt::api::webrtc::stun;

namespace {

// Shared event-loop fixture so the UdpTransport receive coroutine runs on the
// unified IODispatcher (worker pool + async_io) — the production path.
struct EventLoop {
    std::unique_ptr<core::WorkerThreadPool> pool;
    std::unique_ptr<net::IODispatcher>      disp;
    EventLoop() {
        pool = std::make_unique<core::WorkerThreadPool>(core::WorkerPoolConfig{});
        pool->start();
        disp = std::make_unique<net::IODispatcher>(pool.get());
        disp->start();
    }
    ~EventLoop() { disp->stop(); pool->stop(); }
};

net::IODispatcher& shared_dispatcher() {
    static EventLoop loop;
    return *loop.disp;
}

constexpr char kOurUfrag[]  = "SVRufrag";              // our (server) ufrag, >=4
constexpr char kOurPwd[]    = "serverpassword01234567";// our pwd, >=22
constexpr char kPeerUfrag[] = "CLIufrag";              // the client's ufrag

struct ClientSocket {
    net::socket_t fd = net::kInvalidSocket;
    bool open() {
        sys::startup();
        fd = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (fd == net::kInvalidSocket) return false;
        sockaddr_in any{};
        any.sin_family = AF_INET;
        any.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        any.sin_port = 0;
        if (::bind(fd, reinterpret_cast<sockaddr*>(&any), sizeof(any)) != 0)
            return false;
#ifdef _WIN32
        DWORD tmo = 2000;
        ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO,
                     reinterpret_cast<const char*>(&tmo), sizeof(tmo));
#else
        timeval tmo{2, 0};
        ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tmo, sizeof(tmo));
#endif
        return true;
    }
    void close() {
        if (fd != net::kInvalidSocket) { sys::close_socket(fd); fd = net::kInvalidSocket; }
    }
    ~ClientSocket() { close(); }
};

// Build a STUN Binding Request as an ICE controlling agent would. `good_pwd`
// selects whether MESSAGE-INTEGRITY is keyed with the correct server pwd.
std::size_t build_binding_request(std::uint8_t* out, std::size_t cap,
                                  bool use_candidate, const char* mi_key) {
    static const std::uint8_t txn[12] = {0x11,0x22,0x33,0x44,0x55,0x66,
                                         0x77,0x88,0x99,0xAA,0xBB,0xCC};
    stun::Builder b(out, cap);
    if (b.begin(stun::Class::Request, stun::Method::Binding, txn) !=
        stun::StunError::Ok) return 0;
    std::string user = std::string(kOurUfrag) + ":" + kPeerUfrag;
    if (b.add_username(user.c_str(), user.size()) != stun::StunError::Ok) return 0;
    if (b.add_priority(1845494015u) != stun::StunError::Ok) return 0;
    if (b.add_ice_controlling(0x0123456789ABCDEFull) != stun::StunError::Ok) return 0;
    if (use_candidate) {
        if (b.add_use_candidate() != stun::StunError::Ok) return 0;
    }
    if (b.add_message_integrity(reinterpret_cast<const std::uint8_t*>(mi_key),
                                std::strlen(mi_key)) != stun::StunError::Ok)
        return 0;
    if (b.add_fingerprint() != stun::StunError::Ok) return 0;
    return b.size();
}

}  // namespace

// ===========================================================================
// Candidate model round-trip (REBUILT from_string vs PORTED to_string).
// ===========================================================================
TEST(IceCandidate, ToFromStringRoundTrip) {
    ice::IceCandidate c;
    c.type = ice::CandidateType::Host;
    c.transport = ice::IceTransport::Udp;
    c.foundation = "1";
    c.component = 1;
    c.priority = ice::host_priority(1);
    c.address = "192.168.1.50";
    c.port = 54321;

    const std::string s = c.to_string();
    EXPECT_NE(s.find("candidate:1 1 udp "), std::string::npos);
    EXPECT_NE(s.find("192.168.1.50 54321 typ host"), std::string::npos);

    ice::IceCandidate parsed;
    ASSERT_TRUE(ice::IceCandidate::from_string(s, parsed));
    EXPECT_EQ(parsed.foundation, "1");
    EXPECT_EQ(parsed.component, 1);
    EXPECT_EQ(parsed.transport, ice::IceTransport::Udp);
    EXPECT_EQ(parsed.priority, c.priority);
    EXPECT_EQ(parsed.address, "192.168.1.50");
    EXPECT_EQ(parsed.port, 54321);
    EXPECT_EQ(parsed.type, ice::CandidateType::Host);

    // srflx with raddr/rport.
    ice::IceCandidate srflx;
    ASSERT_TRUE(ice::IceCandidate::from_string(
        "candidate:2 1 udp 1694498815 203.0.113.7 60000 typ srflx "
        "raddr 192.168.1.50 rport 54321", srflx));
    EXPECT_EQ(srflx.type, ice::CandidateType::Srflx);
    EXPECT_EQ(srflx.related_address, "192.168.1.50");
    EXPECT_EQ(srflx.related_port, 54321);

    // Malformed -> false, no crash.
    ice::IceCandidate junk;
    EXPECT_FALSE(ice::IceCandidate::from_string("candidate:bad", junk));
    EXPECT_FALSE(ice::IceCandidate::from_string("", junk));
}

TEST(IceAgent, GatherHostCandidates) {
    ice::IceAgent agent;
    const std::size_t n = agent.gather_host_candidates(12345);
    EXPECT_GE(n, 1u);
    ASSERT_EQ(n, agent.candidate_count());
    for (std::size_t i = 0; i < n; ++i) {
        const ice::IceCandidate& c = agent.candidate(i);
        EXPECT_EQ(c.type, ice::CandidateType::Host);
        EXPECT_EQ(c.port, 12345);
        EXPECT_FALSE(c.address.empty());
        EXPECT_NE(c.priority, 0u);
    }
}

TEST(IceAgent, CredentialGeneration) {
    ice::IceAgent agent;
    agent.generate_credentials(0xDEADBEEF);
    EXPECT_GE(agent.ufrag().size(), 4u);
    EXPECT_GE(agent.pwd().size(), 22u);
    // Deterministic for a fixed seed.
    ice::IceAgent agent2;
    agent2.generate_credentials(0xDEADBEEF);
    EXPECT_EQ(agent.ufrag(), agent2.ufrag());
    EXPECT_EQ(agent.pwd(), agent2.pwd());
}

// ===========================================================================
// THE LIVE STUN GATE — real binding request over the wire, success response.
// ===========================================================================
TEST(IceAgent, LiveStunBindingOverTheWire) {
    net::UdpTransport transport(shared_dispatcher());
    ASSERT_TRUE(transport.bind("127.0.0.1", 0));
    const std::uint16_t port = transport.bound_port();
    ASSERT_NE(port, 0);

    ice::IceAgent agent;
    agent.set_credentials(kOurUfrag, kOurPwd);
    ASSERT_EQ(agent.ufrag(), kOurUfrag);
    ASSERT_EQ(agent.pwd(), kOurPwd);

    // Route STUN datagrams to the agent (the ICE-lite responder path).
    transport.set_stun_handler([&](const sockaddr* peer, int plen,
                                   const std::uint8_t* data, std::size_t len) {
        agent.handle_stun(transport, peer, plen, data, len);
    });
    ASSERT_TRUE(transport.start());

    ClientSocket c;
    ASSERT_TRUE(c.open());
    sockaddr_in cli{};
    socklen_t cli_len = sizeof(cli);
    ASSERT_EQ(::getsockname(c.fd, reinterpret_cast<sockaddr*>(&cli), &cli_len), 0);
    const std::uint16_t client_port = ntohs(cli.sin_port);

    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    dst.sin_port = htons(port);

    // --- Build + send a valid binding request WITH USE-CANDIDATE ---
    std::uint8_t req[512];
    const std::size_t req_len =
        build_binding_request(req, sizeof(req), /*use_candidate=*/true, kOurPwd);
    ASSERT_GT(req_len, 0u);
    ASSERT_EQ(::sendto(c.fd, reinterpret_cast<const char*>(req),
                       static_cast<int>(req_len), 0,
                       reinterpret_cast<sockaddr*>(&dst), sizeof(dst)),
              static_cast<ssize_t>(req_len));

    // --- Read the response off the wire (bounded by RCVTIMEO) ---
    std::uint8_t resp[512];
    sockaddr_in from{};
    socklen_t from_len = sizeof(from);
    const ssize_t rn = ::recvfrom(c.fd, reinterpret_cast<char*>(resp),
                                  sizeof(resp), 0,
                                  reinterpret_cast<sockaddr*>(&from), &from_len);
    ASSERT_GT(rn, 0) << "no STUN response (timed out)";

    // --- Parse + assert it is a Binding SUCCESS response ---
    stun::Message msg;
    ASSERT_EQ(stun::parse(resp, static_cast<std::size_t>(rn), msg),
              stun::StunError::Ok);
    EXPECT_EQ(msg.msg_class, stun::Class::SuccessResponse);
    EXPECT_EQ(msg.method, stun::Method::Binding);

    // Transaction id must echo the request's.
    EXPECT_EQ(std::memcmp(msg.transaction_id, req + 8, 12), 0);

    // --- XOR-MAPPED-ADDRESS must equal the client's source address ---
    stun::Address mapped{};
    ASSERT_EQ(msg.mapped_address(&mapped), stun::StunError::Ok);
    EXPECT_EQ(mapped.family, stun::Family::IPv4);
    EXPECT_EQ(mapped.port, client_port);
    // Loopback 127.0.0.1 in network byte order.
    EXPECT_EQ(mapped.addr[0], 127);
    EXPECT_EQ(mapped.addr[3], 1);

    // --- MESSAGE-INTEGRITY verifies with OUR pwd, FINGERPRINT verifies ---
    EXPECT_EQ(stun::verify_message_integrity(
                  msg, reinterpret_cast<const std::uint8_t*>(kOurPwd),
                  std::strlen(kOurPwd)),
              stun::StunError::Ok);
    EXPECT_EQ(stun::verify_fingerprint(msg), stun::StunError::Ok);

    // --- USE-CANDIDATE nominated the peer (selected pair) ---
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::seconds(2);
    while (!agent.has_selected_peer() &&
           std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    EXPECT_TRUE(agent.has_selected_peer());
    EXPECT_GE(agent.binding_responses(), 1u);

    transport.stop();
}

// ===========================================================================
// Negative: WRONG MESSAGE-INTEGRITY -> rejected (not a success), no crash.
// ===========================================================================
TEST(IceAgent, WrongIntegrityRejected) {
    net::UdpTransport transport(shared_dispatcher());
    ASSERT_TRUE(transport.bind("127.0.0.1", 0));
    const std::uint16_t port = transport.bound_port();
    ASSERT_NE(port, 0);

    ice::IceAgent agent;
    agent.set_credentials(kOurUfrag, kOurPwd);
    transport.set_stun_handler([&](const sockaddr* peer, int plen,
                                   const std::uint8_t* data, std::size_t len) {
        agent.handle_stun(transport, peer, plen, data, len);
    });
    ASSERT_TRUE(transport.start());

    ClientSocket c;
    ASSERT_TRUE(c.open());
    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    dst.sin_port = htons(port);

    // MESSAGE-INTEGRITY keyed with the WRONG password.
    std::uint8_t req[512];
    const std::size_t req_len = build_binding_request(
        req, sizeof(req), /*use_candidate=*/true, "totally-wrong-password");
    ASSERT_GT(req_len, 0u);
    ASSERT_EQ(::sendto(c.fd, reinterpret_cast<const char*>(req),
                       static_cast<int>(req_len), 0,
                       reinterpret_cast<sockaddr*>(&dst), sizeof(dst)),
              static_cast<ssize_t>(req_len));

    std::uint8_t resp[512];
    sockaddr_in from{};
    socklen_t from_len = sizeof(from);
    const ssize_t rn = ::recvfrom(c.fd, reinterpret_cast<char*>(resp),
                                  sizeof(resp), 0,
                                  reinterpret_cast<sockaddr*>(&from), &from_len);

    // The server must NOT produce a success response and must NOT nominate.
    if (rn > 0) {
        stun::Message msg;
        if (stun::parse(resp, static_cast<std::size_t>(rn), msg) ==
            stun::StunError::Ok) {
            EXPECT_NE(msg.msg_class, stun::Class::SuccessResponse);
            EXPECT_EQ(msg.msg_class, stun::Class::ErrorResponse);
        }
    }
    EXPECT_FALSE(agent.has_selected_peer());
    EXPECT_EQ(agent.binding_responses(), 0u);

    transport.stop();  // no crash, clean shutdown
}

// ===========================================================================
// Robustness: random / malformed datagrams to the STUN handler don't crash.
// ===========================================================================
TEST(IceAgent, MalformedStunIgnored) {
    net::UdpTransport transport(shared_dispatcher());
    ASSERT_TRUE(transport.bind("127.0.0.1", 0));
    ice::IceAgent agent;
    agent.set_credentials(kOurUfrag, kOurPwd);
    transport.set_stun_handler([&](const sockaddr* peer, int plen,
                                   const std::uint8_t* data, std::size_t len) {
        agent.handle_stun(transport, peer, plen, data, len);
    });
    ASSERT_TRUE(transport.start());

    ClientSocket c;
    ASSERT_TRUE(c.open());
    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    dst.sin_port = htons(transport.bound_port());

    // First byte 0..3 (classified STUN) but garbage thereafter.
    for (int i = 0; i < 16; ++i) {
        std::uint8_t junk[40];
        for (auto& b : junk) b = static_cast<std::uint8_t>(i * 7 + 3);
        junk[0] = static_cast<std::uint8_t>(i & 0x03);  // ensure STUN class
        ::sendto(c.fd, reinterpret_cast<const char*>(junk), sizeof(junk), 0,
                 reinterpret_cast<sockaddr*>(&dst), sizeof(dst));
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_FALSE(agent.has_selected_peer());
    EXPECT_EQ(agent.binding_responses(), 0u);
    transport.stop();  // survived garbage, clean shutdown
}
