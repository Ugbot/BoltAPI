// dtls — DTLS datagrams from many peers into the DtlsSessionManager the
// WebRTC transport feeds (session table, ClientHello handling, OpenSSL's
// record/handshake parsing through our memory BIOs).
//
// Records: {peer index u8, u16 len, bytes}. After the input, a new peer's
// ClientHello must still get a session: strangers may not exhaust the table.
#include "fuzz_util.h"

#include "boltapi/net/udp_transport.h"
#include "boltapi/webrtc/dtls.h"

#include <arpa/inet.h>
#include <netinet/in.h>

#include <memory>
#include <vector>

namespace wr = bolt::api::webrtc;
using bolt::api::net::UdpTransport;

namespace {

constexpr int kMaxRecords = 256;
constexpr std::size_t kMaxDatagram = 2048;

UdpTransport* make_sink_transport() {
    auto* t = new UdpTransport();
    FUZZ_CHECK(t->bind("127.0.0.1", 0));
    const int blackhole = ::socket(AF_UNIX, SOCK_DGRAM, 0);
    FUZZ_CHECK(blackhole >= 0);
    FUZZ_CHECK(::dup2(blackhole, static_cast<int>(t->native_handle())) >= 0);
    ::close(blackhole);
    return t;
}

sockaddr_in peer_addr(std::uint32_t i) {
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(static_cast<std::uint16_t>(20000 + i));
    a.sin_addr.s_addr = htonl(0x7F000001u);
    return a;
}

// A ClientHello-shaped record header; the body is garbage.
constexpr std::uint8_t kHello[] = {22, 0xFE, 0xFD, 0, 0, 0, 0, 0, 0, 0, 0, 0, 20,
                                   1,  0,    0,    8, 0, 0, 0, 0, 0, 0, 0, 8, 0};

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    static UdpTransport* transport = make_sink_transport();
    static std::unique_ptr<wr::DtlsContext> ctx = wr::DtlsContext::create();
    FUZZ_CHECK(ctx != nullptr);
    auto mgr = std::make_unique<wr::DtlsSessionManager>(*ctx, *transport);
    if (size > 0 && (data[0] & 1)) mgr->set_offer_fingerprint("AB:CD");
    boltapi_fuzz::Input in(data, size);
    (void)in.u8();
    for (int k = 0; k < kMaxRecords && !in.empty(); ++k) {
        const sockaddr_in pa = peer_addr(in.u8());
        std::size_t got = 0;
        const std::uint8_t* d = in.take(in.u16() % (kMaxDatagram + 1), &got);
        std::vector<std::uint8_t> dg(d, d + got);
        dg.reserve(1);
        mgr->feed(reinterpret_cast<const sockaddr*>(&pa), sizeof(pa), dg.data(), dg.size());
        FUZZ_CHECK(mgr->session_count() <= 64);
    }
    const sockaddr_in fresh = peer_addr(4000);
    const auto* fa = reinterpret_cast<const sockaddr*>(&fresh);
    mgr->feed(fa, sizeof(fresh), kHello, sizeof(kHello));
    FUZZ_CHECK(mgr->find(fa, sizeof(fresh)) != nullptr);
    return 0;
}
