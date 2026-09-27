// sctp — SCTP packets and DCEP messages into the server's (passive)
// DataChannelStack, the layer WebRtcPeerHub feeds decrypted DTLS app-data.
// A real active stack on the other end completes the handshake so the input
// reaches Established-state chunk handling.
//
// Byte 0: bit0 handshake first. Then up to 32 records {op, ...}:
//   0: raw packet into the server (u16 len; bit4 of op fixes the verification
//      tag, bit5 keeps a bad CRC-32c, otherwise it is recomputed)
//   1: a user message from the client (u16 stream, u8 ppid, u16 len)
//   2: the client opens a channel (u8 label len)
//   3: advance time and tick both stacks (u16 ms)
//   4-7: the server sends on its first channel (u16 len)
#include "fuzz_util.h"

#include "boltapi/webrtc/data_channel.h"
#include "boltapi/webrtc/sctp.h"

#include <deque>
#include <memory>
#include <string>
#include <vector>

namespace wr = bolt::api::webrtc;

namespace {

constexpr int kMaxRecords = 32;
constexpr int kMaxPump = 64;
constexpr std::size_t kMaxPacket = 4096;
constexpr std::uint32_t kPpids[] = {50, 51, 53, 56, 57, 0, 7};

using Queue = std::deque<std::vector<std::uint8_t>>;

struct Pair {
    wr::DataChannelStack server, client;
    Queue to_server, to_client;
    wr::DataChannel* server_ch = nullptr;
    std::uint64_t now = 1;
};

void pump(Pair& p) {
    for (int i = 0; i < kMaxPump && (!p.to_server.empty() || !p.to_client.empty()); ++i) {
        if (!p.to_server.empty()) {
            std::vector<std::uint8_t> pkt = std::move(p.to_server.front());
            p.to_server.pop_front();
            (void)p.server.feed(pkt.data(), pkt.size());
        }
        if (!p.to_client.empty()) {
            std::vector<std::uint8_t> pkt = std::move(p.to_client.front());
            p.to_client.pop_front();
            (void)p.client.feed(pkt.data(), pkt.size());
        }
    }
    p.to_server.clear();
    p.to_client.clear();
}

void raw_into_server(Pair& p, std::uint8_t op, const std::uint8_t* d, std::size_t n) {
    std::vector<std::uint8_t> pkt(d, d + n);
    pkt.reserve(1);
    if (n >= 12) {
        if (op & 0x10) {
            const std::uint32_t tag = p.server.association().local_tag();
            pkt[4] = static_cast<std::uint8_t>(tag >> 24);
            pkt[5] = static_cast<std::uint8_t>(tag >> 16);
            pkt[6] = static_cast<std::uint8_t>(tag >> 8);
            pkt[7] = static_cast<std::uint8_t>(tag);
        }
        if (!(op & 0x20)) {
            std::memset(pkt.data() + 8, 0, 4);
            const std::uint32_t crc = wr::sctp_crc32c(pkt.data(), pkt.size());
            pkt[8] = static_cast<std::uint8_t>(crc);
            pkt[9] = static_cast<std::uint8_t>(crc >> 8);
            pkt[10] = static_cast<std::uint8_t>(crc >> 16);
            pkt[11] = static_cast<std::uint8_t>(crc >> 24);
        }
    }
    (void)p.server.feed(pkt.data(), pkt.size());
    pump(p);
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size < 1) return 0;
    boltapi_fuzz::Input in(data, size);
    const std::uint8_t flags = in.u8();
    auto p = std::make_unique<Pair>();
    Pair* pp = p.get();
    p->server.init(
        wr::SctpAssociation::Role::Passive,
        [pp](const std::uint8_t* d, std::size_t n) {
            if (pp->to_client.size() < 256) pp->to_client.emplace_back(d, d + n);
            return true;
        },
        [pp](wr::DataChannel& ch) {
            if (pp->server_ch == nullptr) pp->server_ch = &ch;
            ch.on_message([&ch](const void* m, std::size_t n, bool bin) {
                if (bin) (void)ch.send_binary(m, n);
                else (void)ch.send_text(std::string_view(static_cast<const char*>(m), n));
            });
        });
    p->client.init(
        wr::SctpAssociation::Role::Active,
        [pp](const std::uint8_t* d, std::size_t n) {
            if (pp->to_server.size() < 256) pp->to_server.emplace_back(d, d + n);
            return true;
        },
        [](wr::DataChannel&) {});
    if (flags & 1) {
        (void)p->client.connect();
        pump(*p);
    }

    for (int k = 0; k < kMaxRecords && !in.empty(); ++k) {
        const std::uint8_t op = in.u8();
        switch (op & 7) {
            case 0: {
                std::size_t got = 0;
                const std::uint8_t* d = in.take(in.u16() % (kMaxPacket + 1), &got);
                raw_into_server(*p, op, d, got);
                break;
            }
            case 1: {
                const std::uint16_t sid = in.u16() % 8;
                const std::uint32_t ppid = kPpids[in.u8() % (sizeof(kPpids) / sizeof(kPpids[0]))];
                std::size_t got = 0;
                const std::uint8_t* d = in.take(in.u16() % (kMaxPacket + 1), &got);
                wr::SctpReliability rel = wr::SctpReliability::reliable((op & 0x10) != 0);
                (void)p->client.association().send(sid, ppid, d, got, rel, p->now);
                pump(*p);
                break;
            }
            case 2: {
                std::size_t got = 0;
                const std::uint8_t* d = in.take(in.u8() % 64, &got);
                (void)p->client.open_channel(std::string(reinterpret_cast<const char*>(d), got));
                pump(*p);
                break;
            }
            case 3:
                p->now += in.u16();
                (void)p->server.tick(p->now);
                (void)p->client.tick(p->now);
                pump(*p);
                break;
            default: {
                std::size_t got = 0;
                const std::uint8_t* d = in.take(in.u16() % (kMaxPacket + 1), &got);
                if (p->server_ch != nullptr) (void)p->server_ch->send_binary(d, got);
                pump(*p);
                break;
            }
        }
    }
    return 0;
}
