// ws_parser — WebSocket frame parser, close payload parser, UTF-8 validator
// (differential against a strict RFC 3629 reference) and handshake helpers.

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <string_view>

#include "boltapi/http/websocket_parser.h"

namespace wsp = bolt::api::websocket;

namespace {

void check(bool ok, const char* what) {
    if (!ok) {
        std::fprintf(stderr, "ws_parser invariant failed: %s\n", what);
        std::abort();
    }
}

// Strict UTF-8 (RFC 3629): no overlongs, no surrogates, max U+10FFFF.
bool ref_utf8(const std::uint8_t* s, std::size_t n) {
    std::size_t i = 0;
    while (i < n) {
        const std::uint8_t c = s[i];
        std::size_t len = 0;
        std::uint32_t cp = 0, min = 0;
        if (c < 0x80) { ++i; continue; }
        if ((c & 0xE0) == 0xC0) { len = 2; cp = c & 0x1F; min = 0x80; }
        else if ((c & 0xF0) == 0xE0) { len = 3; cp = c & 0x0F; min = 0x800; }
        else if ((c & 0xF8) == 0xF0) { len = 4; cp = c & 0x07; min = 0x10000; }
        else return false;
        if (n - i < len) return false;
        for (std::size_t k = 1; k < len; ++k) {
            if ((s[i + k] & 0xC0) != 0x80) return false;
            cp = (cp << 6) | (s[i + k] & 0x3F);
        }
        if (cp < min || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) return false;
        i += len;
    }
    return true;
}

void fuzz_frames(const std::uint8_t* d, std::size_t n) {
    wsp::FrameParser p;
    std::size_t pos = 0;
    for (std::size_t guard = 0; guard < 1024 && pos < n; ++guard) {
        std::size_t used = 0;
        wsp::FrameHeader h;
        const std::uint8_t* payload = nullptr;
        std::size_t plen = 0;
        const int r = p.parse_frame(d + pos, n - pos, used, h, payload, plen);
        check(used <= n - pos, "parse_frame consumed past input");
        if (r != 0) break;
        check(plen == 0 || (payload >= d + pos && payload + plen <= d + n),
              "payload view outside input");
        p.reset();
        if (used == 0) break;
        pos += used;
    }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size < 1) return 0;
    const std::uint8_t* d = data + 1;
    const std::size_t n = size - 1;
    switch (data[0] % 4) {
        case 0: fuzz_frames(d, n); break;
        case 1:
            check(wsp::FrameParser::validate_utf8(d, n) == ref_utf8(d, n),
                  "validate_utf8 disagrees with RFC 3629");
            break;
        case 2: {
            wsp::CloseCode code{};
            std::string reason;
            (void)wsp::FrameParser::parse_close_payload(d, n, code, reason);
            break;
        }
        default: {
            const std::string_view sv(reinterpret_cast<const char*>(d), n);
            const std::string pick = wsp::HandshakeUtils::select_subprotocol(sv);
            check(pick.size() <= n, "subprotocol longer than offer");
            (void)wsp::HandshakeUtils::validate_upgrade_request(
                "GET", std::string(sv), "Upgrade", "13", std::string(sv));
            break;
        }
    }
    return 0;
}
