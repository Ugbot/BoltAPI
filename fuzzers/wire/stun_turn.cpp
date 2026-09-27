// stun_turn — STUN/TURN datagrams from a peer: the STUN codec and its
// verifiers, the ICE-lite responder, the full ICE agent, the TURN server
// (control and relay sockets) and the TURN client.
//
// Byte 0 picks the consumer; the rest is up to 8 datagrams, each raw or
// built well-formed (framing, MESSAGE-INTEGRITY under the consumer's key,
// FINGERPRINT) from input fields. Every consumer sends
// through transports whose socket is swapped for an AF_UNIX datagram socket,
// so no datagram leaves the process.
#include "fuzz_util.h"

#include "boltapi/net/udp_transport.h"
#include "boltapi/webrtc/ice.h"
#include "boltapi/webrtc/stun.h"
#include "boltapi/webrtc/turn.h"

#include <memory>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>

namespace st = bolt::api::webrtc::stun;
namespace tn = bolt::api::webrtc::turn;
namespace wr = bolt::api::webrtc;
using bolt::api::net::UdpTransport;

namespace {

constexpr char kUfrag[] = "ufrg";
constexpr char kPwd[] = "pwdpwdpwdpwdpwdpwdpwdp";
constexpr char kRemoteUfrag[] = "rmtu";
constexpr char kRemotePwd[] = "rmtpwdrmtpwdrmtpwdrmtp";
constexpr char kRealm[] = "realm";
constexpr char kUser[] = "user";
constexpr char kPass[] = "pass";
constexpr char kNonce[] = "abcdefghijklmnop";
constexpr std::size_t kMaxDatagram = 2048;

// A bound transport whose socket can no longer reach the network.
UdpTransport* make_sink_transport() {
    auto* t = new UdpTransport();
    FUZZ_CHECK(t->bind("127.0.0.1", 0));
    const int blackhole = ::socket(AF_UNIX, SOCK_DGRAM, 0);
    FUZZ_CHECK(blackhole >= 0);
    FUZZ_CHECK(::dup2(blackhole, static_cast<int>(t->native_handle())) >= 0);
    ::close(blackhole);
    return t;
}

sockaddr_in loopback(std::uint16_t port) {
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    return a;
}

// Builds a STUN/TURN message from the input: class/method, a few raw
// attributes, optional credentials, MESSAGE-INTEGRITY and FINGERPRINT.
std::size_t build(boltapi_fuzz::Input& in, std::uint8_t* out, std::size_t cap,
                  const std::uint8_t* key, std::size_t key_len, std::string_view user) {
    assert(out != nullptr && cap >= st::kHeaderSize);
    const std::uint8_t flags = in.u8();
    const auto cls = static_cast<st::Class>(in.u8() & 3);
    const auto method = static_cast<st::Method>(in.u16() & 0x0FFF);
    std::uint8_t txn[st::kTransactionIdLen];
    for (auto& b : txn) b = in.u8();
    st::Builder b(out, cap);
    if (b.begin(cls, method, txn) != st::StunError::Ok) return 0;
    if (flags & 1) (void)b.add_username(user.data(), user.size());
    if (flags & 2) {
        (void)b.add_attribute(static_cast<st::AttrType>(0x0014),
                              reinterpret_cast<const std::uint8_t*>(kRealm), 5);
        (void)b.add_attribute(static_cast<st::AttrType>(0x0015),
                              reinterpret_cast<const std::uint8_t*>(kNonce), 16);
    }
    const std::uint8_t n_attrs = in.u8() & 7;
    for (std::uint8_t i = 0; i < n_attrs; ++i) {
        const std::uint16_t type = in.u16();
        std::size_t got = 0;
        const std::uint8_t* v = in.take(in.u8(), &got);
        (void)b.add_attribute(static_cast<st::AttrType>(type), v,
                              static_cast<std::uint16_t>(got));
    }
    if (flags & 4) (void)b.add_message_integrity(key, key_len);
    if (flags & 8) (void)b.add_fingerprint();
    return b.size();
}

void codec(const std::uint8_t* d, std::size_t n) {
    st::Message m;
    if (st::parse(d, n, m) != st::StunError::Ok) return;
    FUZZ_CHECK(m.attr_count <= st::kMaxAttributes && m.raw_len <= n);
    for (std::size_t i = 0; i < m.attr_count; ++i) {
        const st::Attribute& a = m.attrs[i];
        FUZZ_CHECK(a.length == 0 || (a.value >= d && a.value + a.length <= d + n));
    }
    st::Address addr;
    (void)m.mapped_address(&addr);
    std::uint32_t pri = 0;
    (void)m.priority(&pri);
    (void)st::verify_fingerprint(m);
    (void)st::verify_message_integrity(m, reinterpret_cast<const std::uint8_t*>(kPwd),
                                       sizeof(kPwd) - 1);
}

// One datagram from the input: a header byte (bit0: build, bit1: secondary
// socket), then either build() fields or a u16 length and raw bytes.
std::size_t next_datagram(boltapi_fuzz::Input& in, std::uint8_t* buf, bool turn,
                          const std::uint8_t* key, std::size_t key_len, bool* secondary) {
    const std::uint8_t h = in.u8();
    *secondary = (h & 2) != 0;
    if (h & 1) {
        const std::string_view user = turn ? std::string_view(kUser) : "ufrg:rmtu";
        return build(in, buf, kMaxDatagram, key, key_len, user);
    }
    std::size_t got = 0;
    const std::uint8_t* raw = in.take(in.u16() % (kMaxDatagram + 1), &got);
    std::memcpy(buf, raw, got);
    return got;
}

constexpr int kMaxDatagrams = 8;

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    static UdpTransport* control = make_sink_transport();
    static UdpTransport* relay = make_sink_transport();
    static std::uint8_t turn_key[16];
    static const bool keyed = [] {
        tn::long_term_key(kUser, kRealm, kPass, turn_key);
        return true;
    }();
    (void)keyed;
    if (size < 1) return 0;
    boltapi_fuzz::Input in(data, size);
    const std::uint8_t sel = in.u8();
    const std::uint8_t consumer = sel % 5;
    const bool turn = consumer >= 3;
    const std::uint8_t* key =
        turn ? turn_key : reinterpret_cast<const std::uint8_t*>(kPwd);
    const std::size_t key_len = turn ? 16 : sizeof(kPwd) - 1;
    const sockaddr_in peer = loopback(static_cast<std::uint16_t>(40000 + (sel >> 4)));
    const auto* sa = reinterpret_cast<const sockaddr*>(&peer);

    wr::IceAgent lite;
    lite.set_credentials(kUfrag, kPwd);
    if (sel & 0x80) lite.set_expected_remote(kRemoteUfrag, kRemotePwd);
    auto full = std::make_unique<wr::FullIceAgent>();
    auto server = std::make_unique<tn::TurnServer>();
    auto client = std::make_unique<tn::TurnClient>();
    if (consumer == 2) {
        full->set_role((sel & 0x80) ? wr::IceRole::Controlling : wr::IceRole::Controlled);
        full->set_credentials(kUfrag, kPwd);
        full->set_remote_credentials(kRemoteUfrag, kRemotePwd);
        full->set_tiebreaker(0x1234);
        wr::IceCandidate local;
        local.foundation = "1";
        local.priority = wr::host_priority(1);
        local.address = "127.0.0.1";
        local.port = control->bound_port();
        (void)full->add_local_candidate(local, sa, sizeof(peer));
        wr::IceCandidate remote = local;
        remote.foundation = "2";
        remote.port = ntohs(peer.sin_port);
        (void)full->add_remote_candidate(remote);
        (void)full->run_checks(*control, 1);
    } else if (consumer == 3) {
        server->set_credentials(kRealm, kUser, kPass);
        server->set_sockets(*control, *relay);
    } else if (consumer == 4) {
        client->configure(sa, sizeof(peer), kUser, kPass);
        (void)client->allocate(*control);
    }

    std::uint8_t msg[kMaxDatagram];
    for (int k = 0; k < kMaxDatagrams && !in.empty(); ++k) {
        bool secondary = false;
        const std::size_t n0 = next_datagram(in, msg, turn, key, key_len, &secondary);
        FUZZ_CHECK(n0 <= kMaxDatagram);
        // Exact-size heap copy so a read past the datagram is visible to ASan.
        std::vector<std::uint8_t> dg(msg, msg + n0);
        dg.reserve(1);
        const std::uint8_t* d = dg.data();
        const std::size_t n = dg.size();
        switch (consumer) {
            case 0: codec(d, n); break;
            case 1: (void)lite.handle_stun(*control, sa, sizeof(peer), d, n); break;
            case 2:
                (void)full->handle_stun(*control, sa, sizeof(peer), d, n);
                (void)full->run_checks(*control, 1000u * static_cast<std::uint32_t>(k + 2));
                break;
            case 3:
                if (secondary) (void)server->feed_relay(sa, sizeof(peer), d, n);
                else (void)server->feed(sa, sizeof(peer), d, n);
                break;
            default:
                (void)client->feed(*control, sa, sizeof(peer), d, n);
                if (client->have_relayed_data()) FUZZ_CHECK(client->relayed_len() <= 2048);
                if (secondary && client->allocated()) {
                    (void)client->create_permission(*control, sa, sizeof(peer));
                    (void)client->channel_bind(*control, sa, sizeof(peer), 0x4000);
                }
                break;
        }
    }
    boltapi_fuzz::check_fd_leak();
    return 0;
}
