// ws_conn — server-side WebSocket connection fed exactly as the server's read
// loop feeds it (a fixed 16 KiB buffer, partial reads, consumed bytes shifted
// out). Oracle: the message/control event log must not depend on how the peer's
// byte stream was split across reads, so the same bytes are replayed once in
// large reads and once in fuzz-chosen small reads and the logs compared.

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "boltapi/http/websocket.h"

namespace ws = bolt::api::http;

namespace {

constexpr std::size_t kServerBuf = 16384;  // CoroUnifiedServer WS_BUFFER_SIZE
constexpr std::size_t kMaxEvents = 4096;

struct Log {
    std::string events;
    std::size_t count = 0;
    void add(char tag, const void* p, std::size_t n) {
        if (count >= kMaxEvents) return;
        ++count;
        events.push_back(tag);
        events.append(std::to_string(n));
        events.push_back(':');
        if (p != nullptr && n > 0) events.append(static_cast<const char*>(p), n);
        events.push_back('|');
    }
};

void wire(ws::WebSocketConnection& c, Log& log) {
    c.on_text_message = [&log](const std::string& m) { log.add('T', m.data(), m.size()); };
    c.on_binary_message = [&log](const std::uint8_t* d, std::size_t n) { log.add('B', d, n); };
    c.on_close = [&log](std::uint16_t code, const char*) { log.add('C', &code, 2); };
    c.on_ping = [&log]() { log.add('P', nullptr, 0); };
    c.on_pong = [&log]() { log.add('O', nullptr, 0); };
    c.on_error = [&log](const char* e) { log.add('E', e, std::strlen(e)); };
}

// CoroUnifiedServer::handle_websocket_connection's per-read step: append the
// read into the fixed buffer, feed(), shift out what was consumed. Returns
// false once the connection stops reading (closed).
bool server_feed(ws::WebSocketConnection& c, std::uint8_t* buf, std::size_t& buf_len,
                 const std::uint8_t* d, std::size_t n, Log& log) {
    if (n > kServerBuf - buf_len) {
        // The server would issue a zero-length read and drop the connection.
        std::fprintf(stderr, "ws_conn: read buffer full (%zu buffered)\n", buf_len);
        std::abort();
    }
    std::memcpy(buf + buf_len, d, n);
    buf_len += n;
    const std::size_t used = c.feed(buf, buf_len);
    if (used > buf_len) std::abort();
    std::memmove(buf, buf + used, buf_len - used);
    buf_len -= used;
    if (c.is_open() && buf_len >= bolt::api::websocket::FrameParser::kMaxHeaderLength) {
        std::fprintf(stderr, "ws_conn: %zu bytes left unconsumed on an open connection\n",
                     buf_len);
        std::abort();
    }
    return c.is_open();
}

Log run(const std::uint8_t* d, std::size_t n, std::uint32_t seed, bool small) {
    Log log;
    ws::WebSocketConnection::Config cfg;
    cfg.max_message_size = 1 << 16;
    ws::WebSocketConnection c(1, cfg);
    wire(c, log);
    static std::uint8_t buf[kServerBuf];
    std::size_t buf_len = 0;
    std::size_t pos = 0;
    std::uint32_t x = seed | 1u;
    for (std::size_t i = 0; i < n + 1 && pos < n; ++i) {
        std::size_t take = kServerBuf - buf_len;
        if (small) {
            x ^= x << 13; x ^= x >> 17; x ^= x << 5;
            take = 1 + (x % 257);
        }
        if (take > n - pos) take = n - pos;
        if (!server_feed(c, buf, buf_len, d + pos, take, log)) break;
        pos += take;
    }
    return log;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size < 4) return 0;
    std::uint32_t seed = 0;
    std::memcpy(&seed, data, 4);
    const Log whole = run(data + 4, size - 4, seed, false);
    const Log split = run(data + 4, size - 4, seed, true);
    if (whole.events != split.events) {
        std::fprintf(stderr, "ws_conn: event log depends on read split\nwhole=%.200s\nsplit=%.200s\n",
                     whole.events.c_str(), split.events.c_str());
        std::abort();
    }
    return 0;
}
