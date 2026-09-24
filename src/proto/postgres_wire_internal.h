// src/proto/postgres_wire_internal.h — socket + message-framing helpers
// shared by the Postgres wire server's simple- and extended-query paths.
// Private to boltapi; compiled only under BOLTAPI_WITH_PG_WIRE.
#pragma once

#include "boltapi/proto/postgres_wire.h"
#include "boltapi/net/sys_compat.h"

#include <atomic>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <string_view>

namespace bolt::api {
namespace proto {
namespace pgwire {
namespace detail {

// ---------------------------------------------------------------------------
// Socket helpers (same shape as neo4j_bolt_server.cpp's).
// ---------------------------------------------------------------------------
inline int wait_readable(int fd, int timeout_ms) noexcept {
    assert(fd >= 0);
    assert(timeout_ms >= 0);
    fd_set rd;
    FD_ZERO(&rd);
#if defined(_WIN32)
    FD_SET(static_cast<SOCKET>(fd), &rd);
#else
    if (fd >= FD_SETSIZE) return -1;
    FD_SET(fd, &rd);
#endif
    timeval tv;
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    const int r = ::select(fd + 1, &rd, nullptr, nullptr, &tv);
    return (r < 0) ? -1 : r;
}

inline bool read_exact(int fd, void* dst, std::size_t n, int poll_ms, int& idle_budget_ms,
                const std::atomic<bool>& stopping) noexcept {
    assert(dst != nullptr || n == 0);
    assert(poll_ms > 0);
    auto* p = static_cast<std::uint8_t*>(dst);
    std::size_t got = 0;
    while (got < n) {
        if (stopping.load(std::memory_order_acquire)) return false;
        const int ready = wait_readable(fd, poll_ms);
        if (ready < 0) return false;
        if (ready == 0) {
            idle_budget_ms -= poll_ms;
            if (idle_budget_ms <= 0) return false;
            continue;
        }
        const ssize_t r = net::sys::recv_bytes(fd, p + got, n - got);
        if (r <= 0) return false;
        got += static_cast<std::size_t>(r);
        assert(got <= n);
    }
    return true;
}

inline bool write_all(int fd, const void* src, std::size_t n) noexcept {
    assert(src != nullptr || n == 0);
    const auto* p = static_cast<const std::uint8_t*>(src);
    std::size_t sent = 0;
    while (sent < n) {
        const ssize_t w = net::sys::send_bytes(fd, p + sent, n - sent);
        if (w <= 0) return false;
        sent += static_cast<std::size_t>(w);
        assert(sent <= n);
    }
    return true;
}

inline std::int32_t read_be_i32(const std::uint8_t* p) noexcept {
    assert(p != nullptr);
    return static_cast<std::int32_t>(
        (static_cast<std::uint32_t>(p[0]) << 24) |
        (static_cast<std::uint32_t>(p[1]) << 16) |
        (static_cast<std::uint32_t>(p[2]) << 8) |
        static_cast<std::uint32_t>(p[3]));
}

// Locate a NUL-terminated string starting at `off` within `[buf, buf+len)`.
// On success, `*out` views the bytes before the NUL and `*next_off` is the
// offset just past it. Returns false if no NUL is found within bounds.
inline bool read_cstring(const std::uint8_t* buf, std::size_t len, std::size_t off,
                  std::string_view* out, std::size_t* next_off) noexcept {
    assert(buf != nullptr && out != nullptr && next_off != nullptr);
    if (off > len) return false;
    std::size_t i = off;
    while (i < len && buf[i] != 0) ++i;      // bounded by len
    if (i >= len) return false;              // no terminator found
    *out = std::string_view(reinterpret_cast<const char*>(buf + off), i - off);
    *next_off = i + 1;
    return true;
}

// ---------------------------------------------------------------------------
// MsgWriter — one bounded, reusable send buffer per connection. Every backend
// message is TYPE-BYTE + BIG-ENDIAN INT32 LENGTH (length includes itself, not
// the type byte) + payload. begin()/finish() backpatch the length so a
// variable-width message (RowDescription, DataRow) never needs a second pass.
// A write past capacity sets `overflowed_` and every subsequent put_* is a
// no-op — the caller checks ok() before finish()/send() and refuses to send a
// truncated message (bounded, refuse-don't-corrupt, matching the rest of this
// codebase's "never a silently short answer" rule).
// ---------------------------------------------------------------------------
class MsgWriter {
public:
    MsgWriter(std::uint8_t* buf, std::size_t cap) noexcept : buf_(buf), cap_(cap) {
        assert(buf != nullptr && cap >= 16);
    }

    void begin(char type) noexcept {
        assert(pos_ == 0);
        put_u8(static_cast<std::uint8_t>(type));
        len_start_ = pos_;
        pos_ += 4;  // reserved for the length, backpatched in finish()
        if (pos_ > cap_) overflowed_ = true;
    }

    void put_u8(std::uint8_t v) noexcept {
        if (overflowed_ || pos_ + 1 > cap_) { overflowed_ = true; return; }
        buf_[pos_++] = v;
    }
    void put_i16(std::int16_t v) noexcept {
        if (overflowed_ || pos_ + 2 > cap_) { overflowed_ = true; return; }
        const auto u = static_cast<std::uint16_t>(v);
        buf_[pos_++] = static_cast<std::uint8_t>(u >> 8);
        buf_[pos_++] = static_cast<std::uint8_t>(u);
    }
    void put_i32(std::int32_t v) noexcept {
        if (overflowed_ || pos_ + 4 > cap_) { overflowed_ = true; return; }
        const auto u = static_cast<std::uint32_t>(v);
        buf_[pos_++] = static_cast<std::uint8_t>(u >> 24);
        buf_[pos_++] = static_cast<std::uint8_t>(u >> 16);
        buf_[pos_++] = static_cast<std::uint8_t>(u >> 8);
        buf_[pos_++] = static_cast<std::uint8_t>(u);
    }
    void put_bytes(const void* p, std::size_t n) noexcept {
        if (overflowed_ || pos_ + n > cap_) { overflowed_ = true; return; }
        std::memcpy(buf_ + pos_, p, n);
        pos_ += n;
    }
    void put_cstring(std::string_view s) noexcept {
        put_bytes(s.data(), s.size());
        put_u8(0);
    }

    bool ok() const noexcept { return !overflowed_; }

    // Drop a partially built (or overflowed) message without sending it.
    void reset() noexcept {
        pos_ = 0;
        overflowed_ = false;
    }

    // Backpatch the length field. Returns false (and does not touch `buf_`)
    // on overflow — the caller must not send() in that case.
    bool finish() noexcept {
        if (overflowed_) return false;
        assert(pos_ >= len_start_ + 4);
        const std::uint32_t len = static_cast<std::uint32_t>(pos_ - len_start_);
        buf_[len_start_ + 0] = static_cast<std::uint8_t>(len >> 24);
        buf_[len_start_ + 1] = static_cast<std::uint8_t>(len >> 16);
        buf_[len_start_ + 2] = static_cast<std::uint8_t>(len >> 8);
        buf_[len_start_ + 3] = static_cast<std::uint8_t>(len);
        return true;
    }

    bool send(int fd) noexcept {
        assert(pos_ <= cap_);
        const bool sent = write_all(fd, buf_, pos_);
        pos_ = 0;
        overflowed_ = false;
        return sent;
    }

private:
    std::uint8_t* buf_;
    std::size_t   cap_;
    std::size_t   pos_ = 0;
    std::size_t   len_start_ = 0;
    bool          overflowed_ = false;
};

inline void send_error(int fd, MsgWriter& w, const char* sqlstate,
                std::string_view message) noexcept {
    assert(sqlstate != nullptr);
    w.reset();   // never splice an error into a half-built message
    w.begin('E');
    w.put_u8('S'); w.put_cstring("ERROR");
    w.put_u8('V'); w.put_cstring("ERROR");
    w.put_u8('C'); w.put_cstring(sqlstate);
    w.put_u8('M'); w.put_cstring(message);
    w.put_u8(0);   // terminator
    if (w.finish()) (void)w.send(fd);
    else w.reset();   // an unsendable error is dropped, never sent unframed
}

// NoticeResponse at WARNING severity (e.g. BEGIN inside a block).
inline void send_notice(int fd, MsgWriter& w, const char* sqlstate,
                        std::string_view message) noexcept {
    assert(sqlstate != nullptr);
    w.reset();
    w.begin('N');
    w.put_u8('S'); w.put_cstring("WARNING");
    w.put_u8('V'); w.put_cstring("WARNING");
    w.put_u8('C'); w.put_cstring(sqlstate);
    w.put_u8('M'); w.put_cstring(message);
    w.put_u8(0);
    if (w.finish()) (void)w.send(fd);
    else w.reset();
}

// `status`: 'I' idle, 'T' in a transaction block, 'E' in a failed block.
inline void send_ready_for_query(int fd, MsgWriter& w, char status) noexcept {
    assert(status == 'I' || status == 'T' || status == 'E');
    w.begin('Z');
    w.put_u8(static_cast<std::uint8_t>(status));
    if (w.finish()) (void)w.send(fd);
}

// Bounds-checked cursor over one inbound message body. Any read past the end
// latches `ok = false` and yields zero values, so a handler checks once.
struct BodyReader {
    const std::uint8_t* p;
    std::size_t         n;
    std::size_t         off = 0;
    bool                ok  = true;

    BodyReader(const std::uint8_t* body, std::size_t len) noexcept : p(body), n(len) {
        assert(body != nullptr || len == 0);
    }
    std::uint8_t u8() noexcept {
        if (!ok || off + 1 > n) { ok = false; return 0; }
        return p[off++];
    }
    std::int16_t i16() noexcept {
        if (!ok || off + 2 > n) { ok = false; return 0; }
        const auto v = static_cast<std::int16_t>((p[off] << 8) | p[off + 1]);
        off += 2;
        return v;
    }
    std::int32_t i32() noexcept {
        if (!ok || off + 4 > n) { ok = false; return 0; }
        const std::int32_t v = read_be_i32(p + off);
        off += 4;
        return v;
    }
    std::string_view cstr() noexcept {
        std::string_view out;
        std::size_t next = 0;
        if (!ok || !read_cstring(p, n, off, &out, &next)) { ok = false; return {}; }
        off = next;
        return out;
    }
    std::string_view bytes(std::size_t k) noexcept {
        if (!ok || off + k > n) { ok = false; return {}; }
        const std::string_view out(reinterpret_cast<const char*>(p + off), k);
        off += k;
        return out;
    }
};

// RowDescription ('T'). `formats` is null for all-text, else one code per
// field. Returns false if the message would not fit the writer.
inline bool put_row_description(MsgWriter& w, const FieldDesc* fields,
                                std::uint32_t count,
                                const std::int16_t* formats) noexcept {
    assert(fields != nullptr || count == 0);
    assert(count <= kMaxFields);
    w.begin('T');
    w.put_i16(static_cast<std::int16_t>(count));
    for (std::uint32_t c = 0; c < count; ++c) {   // bounded by kMaxFields
        w.put_cstring(fields[c].name);
        w.put_i32(0);                     // table OID: none
        w.put_i16(0);                     // column attr number: none
        w.put_i32(fields[c].type_oid);
        w.put_i16(fields[c].type_size);
        w.put_i32(-1);                    // type modifier: none
        w.put_i16(formats != nullptr ? formats[c] : 0);
    }
    return w.finish();
}

}  // namespace detail
}  // namespace pgwire
}  // namespace proto
}  // namespace bolt::api
