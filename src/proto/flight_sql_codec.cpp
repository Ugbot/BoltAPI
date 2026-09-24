// src/proto/flight_sql_codec.cpp — see boltapi/proto/flight_sql_codec.h.

#include "boltapi/proto/flight_sql_codec.h"

#if defined(BOLTAPI_WITH_FLIGHT_SQL)

#include <cassert>
#include <cstring>

namespace bolt::api::proto::flightsql::codec {

namespace {

constexpr std::size_t kMaxVarintBytes = 10;

bool read_varint(std::string_view buf, std::size_t* pos,
                 std::uint64_t* out) noexcept {
    assert(pos != nullptr && out != nullptr);
    std::uint64_t v = 0;
    for (std::size_t i = 0; i < kMaxVarintBytes; ++i) {
        if (*pos >= buf.size()) return false;
        const auto b = static_cast<std::uint8_t>(buf[(*pos)++]);
        v |= static_cast<std::uint64_t>(b & 0x7Fu) << (7u * i);
        if ((b & 0x80u) == 0) {
            *out = v;
            return true;
        }
    }
    return false;
}

std::uint32_t le_u32(const std::uint8_t* p) noexcept {
    return static_cast<std::uint32_t>(p[0]) |
           (static_cast<std::uint32_t>(p[1]) << 8) |
           (static_cast<std::uint32_t>(p[2]) << 16) |
           (static_cast<std::uint32_t>(p[3]) << 24);
}

std::uint16_t le_u16(const std::uint8_t* p) noexcept {
    return static_cast<std::uint16_t>(p[0] | (p[1] << 8));
}

// Reads Message.header_type (vtable slot 1) and Message.bodyLength (slot 3)
// out of an Arrow IPC Message flatbuffer. Every offset is bounds-checked.
bool read_message_table(std::string_view meta, std::uint8_t* header_type,
                        std::int64_t* body_len) noexcept {
    assert(header_type != nullptr && body_len != nullptr);
    const auto* m = reinterpret_cast<const std::uint8_t*>(meta.data());
    const std::size_t n = meta.size();
    if (n < 8) return false;
    const std::uint32_t table = le_u32(m);
    if (table > n - 4) return false;
    const auto soff = static_cast<std::int32_t>(le_u32(m + table));
    const std::int64_t vt = static_cast<std::int64_t>(table) - soff;
    if (vt < 0 || static_cast<std::size_t>(vt) > n - 4) return false;
    const std::uint16_t vt_size = le_u16(m + vt);
    if (vt_size < 4 || static_cast<std::size_t>(vt) + vt_size > n) return false;
    auto slot = [&](std::uint32_t i) -> std::uint16_t {
        const std::uint32_t at = 4u + 2u * i;
        return (at + 2u <= vt_size) ? le_u16(m + vt + at) : std::uint16_t{0};
    };
    *header_type = 0;
    *body_len = 0;
    if (const std::uint16_t o = slot(1); o != 0) {
        if (table + o >= n) return false;
        *header_type = m[table + o];
    }
    if (const std::uint16_t o = slot(3); o != 0) {
        if (static_cast<std::size_t>(table) + o + 8 > n) return false;
        std::int64_t v = 0;
        std::memcpy(&v, m + table + o, sizeof(v));   // little-endian hosts
        *body_len = v;
    }
    return *body_len >= 0;
}

}  // namespace

bool PbReader::next(PbField* out) noexcept {
    assert(out != nullptr);
    if (!ok_ || pos_ >= buf_.size()) return false;
    std::uint64_t tag = 0;
    if (!read_varint(buf_, &pos_, &tag) || (tag >> 3) == 0 || (tag >> 3) > 0x1FFFFFFFu) {
        ok_ = false;
        return false;
    }
    out->number = static_cast<std::uint32_t>(tag >> 3);
    out->wire = static_cast<std::uint32_t>(tag & 7u);
    out->varint = 0;
    out->bytes = {};
    switch (out->wire) {
        case kWireVarint:
            if (!read_varint(buf_, &pos_, &out->varint)) ok_ = false;
            break;
        case kWireFixed64:
        case kWireFixed32: {
            const std::size_t w = out->wire == kWireFixed64 ? 8 : 4;
            if (buf_.size() - pos_ < w) { ok_ = false; break; }
            std::memcpy(&out->varint, buf_.data() + pos_, w);
            pos_ += w;
            break;
        }
        case kWireBytes: {
            std::uint64_t len = 0;
            if (!read_varint(buf_, &pos_, &len) || len > buf_.size() - pos_) {
                ok_ = false;
                break;
            }
            out->bytes = buf_.substr(pos_, static_cast<std::size_t>(len));
            pos_ += static_cast<std::size_t>(len);
            break;
        }
        default:
            ok_ = false;   // groups (3/4) and reserved types
            break;
    }
    assert(pos_ <= buf_.size());
    return ok_;
}

void pb_put_varint_raw(std::string* out, std::uint64_t v) {
    assert(out != nullptr);
    for (std::size_t i = 0; i < kMaxVarintBytes; ++i) {
        const auto b = static_cast<char>(v & 0x7Fu);
        v >>= 7;
        if (v == 0) {
            out->push_back(b);
            return;
        }
        out->push_back(static_cast<char>(b | 0x80));
    }
    assert(false && "varint longer than 10 bytes");
}

void pb_put_varint(std::string* out, std::uint32_t field, std::uint64_t v) {
    assert(field > 0);
    pb_put_varint_raw(out, (static_cast<std::uint64_t>(field) << 3) | kWireVarint);
    pb_put_varint_raw(out, v);
}

void pb_put_int64(std::string* out, std::uint32_t field, std::int64_t v) {
    pb_put_varint(out, field, static_cast<std::uint64_t>(v));
}

void pb_put_bytes(std::string* out, std::uint32_t field, std::string_view v) {
    assert(field > 0);
    pb_put_varint_raw(out, (static_cast<std::uint64_t>(field) << 3) | kWireBytes);
    pb_put_varint_raw(out, v.size());
    out->append(v.data(), v.size());
}

bool decode_any(std::string_view buf, AnyMsg* out) noexcept {
    assert(out != nullptr);
    *out = AnyMsg{};
    PbReader r(buf);
    PbField f;
    bool have_url = false;
    for (std::size_t guard = 0; guard < 64 && r.next(&f); ++guard) {
        if (f.number == 1 && f.wire == kWireBytes) {
            const std::size_t slash = f.bytes.rfind('/');
            out->type_name = slash == std::string_view::npos
                                 ? f.bytes : f.bytes.substr(slash + 1);
            have_url = true;
        } else if (f.number == 2 && f.wire == kWireBytes) {
            out->value = f.bytes;
        }
    }
    return r.ok() && have_url;
}

void encode_any(std::string* out, std::string_view short_name,
                std::string_view value) {
    assert(out != nullptr && !short_name.empty());
    std::string url(kTypeUrlPrefix);
    url.append(short_name.data(), short_name.size());
    pb_put_bytes(out, 1, url);
    pb_put_bytes(out, 2, value);
}

bool decode_descriptor(std::string_view buf, Descriptor* out) noexcept {
    assert(out != nullptr);
    *out = Descriptor{};
    PbReader r(buf);
    PbField f;
    for (std::size_t guard = 0; guard < 256 && r.next(&f); ++guard) {
        if (f.number == 1 && f.wire == kWireVarint) out->type = f.varint;
        else if (f.number == 2 && f.wire == kWireBytes) out->cmd = f.bytes;
    }
    return r.ok();
}

bool decode_statement_query(std::string_view buf, std::string_view* query,
                            std::string_view* transaction_id) noexcept {
    assert(query != nullptr && transaction_id != nullptr);
    *query = {};
    *transaction_id = {};
    PbReader r(buf);
    PbField f;
    for (std::size_t guard = 0; guard < 64 && r.next(&f); ++guard) {
        if (f.number == 1 && f.wire == kWireBytes) *query = f.bytes;
        else if (f.number == 2 && f.wire == kWireBytes) *transaction_id = f.bytes;
    }
    return r.ok();
}

bool decode_single_bytes(std::string_view buf, std::string_view* out) noexcept {
    assert(out != nullptr);
    *out = {};
    PbReader r(buf);
    PbField f;
    for (std::size_t guard = 0; guard < 64 && r.next(&f); ++guard) {
        if (f.number == 1 && f.wire == kWireBytes) *out = f.bytes;
    }
    return r.ok();
}

void encode_flight_info(std::string* out, std::string_view schema_ipc,
                        std::string_view descriptor_raw,
                        std::string_view ticket, std::int64_t total_records) {
    assert(out != nullptr && !schema_ipc.empty());
    std::string ticket_msg;
    pb_put_bytes(&ticket_msg, 1, ticket);
    std::string endpoint;
    pb_put_bytes(&endpoint, 1, ticket_msg);
    pb_put_bytes(out, 1, schema_ipc);
    pb_put_bytes(out, 2, descriptor_raw);
    pb_put_bytes(out, 3, endpoint);
    pb_put_int64(out, 4, total_records);
    pb_put_int64(out, 5, -1);
}

void encode_flight_data(std::string* out, std::string_view data_header,
                        std::string_view data_body) {
    assert(out != nullptr && !data_header.empty());
    pb_put_bytes(out, 2, data_header);
    if (!data_body.empty()) pb_put_bytes(out, 1000, data_body);
}

GrpcFrame grpc_unframe(std::string_view buf, std::string_view* msg,
                       std::size_t* consumed) noexcept {
    assert(msg != nullptr && consumed != nullptr);
    *consumed = 0;
    if (buf.size() < 5) return GrpcFrame::kIncomplete;
    const auto* p = reinterpret_cast<const std::uint8_t*>(buf.data());
    if (p[0] > 1) return GrpcFrame::kBad;
    const std::uint32_t len = (static_cast<std::uint32_t>(p[1]) << 24) |
                              (static_cast<std::uint32_t>(p[2]) << 16) |
                              (static_cast<std::uint32_t>(p[3]) << 8) |
                              static_cast<std::uint32_t>(p[4]);
    if (buf.size() - 5 < len) return GrpcFrame::kIncomplete;
    if (p[0] == 1) return GrpcFrame::kCompressed;
    *msg = buf.substr(5, len);
    *consumed = 5u + len;
    return GrpcFrame::kOk;
}

void grpc_frame_prefix(std::uint8_t out[5], std::uint32_t len) noexcept {
    assert(out != nullptr);
    out[0] = 0;
    out[1] = static_cast<std::uint8_t>(len >> 24);
    out[2] = static_cast<std::uint8_t>(len >> 16);
    out[3] = static_cast<std::uint8_t>(len >> 8);
    out[4] = static_cast<std::uint8_t>(len);
}

std::size_t grpc_percent_encode(std::string_view in, char* out,
                                std::size_t cap) noexcept {
    assert(out != nullptr && cap > 0);
    static constexpr char kHex[] = "0123456789ABCDEF";
    std::size_t w = 0;
    for (const char ch : in) {
        const auto c = static_cast<std::uint8_t>(ch);
        if (c >= 0x20 && c <= 0x7E && c != '%') {
            if (w + 1 > cap) break;
            out[w++] = static_cast<char>(c);
        } else {
            if (w + 3 > cap) break;
            out[w++] = '%';
            out[w++] = kHex[c >> 4];
            out[w++] = kHex[c & 0xF];
        }
    }
    assert(w <= cap);
    return w;
}

bool base64_decode(std::string_view in, char* out, std::size_t cap,
                   std::size_t* out_len) noexcept {
    assert(out != nullptr && out_len != nullptr);
    std::uint32_t acc = 0;
    int bits = 0;
    std::size_t w = 0;
    for (const char ch : in) {
        int v;
        if (ch >= 'A' && ch <= 'Z') v = ch - 'A';
        else if (ch >= 'a' && ch <= 'z') v = ch - 'a' + 26;
        else if (ch >= '0' && ch <= '9') v = ch - '0' + 52;
        else if (ch == '+' || ch == '-') v = 62;
        else if (ch == '/' || ch == '_') v = 63;
        else if (ch == '=') break;
        else return false;
        acc = (acc << 6) | static_cast<std::uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (w >= cap) return false;
            out[w++] = static_cast<char>((acc >> bits) & 0xFFu);
        }
    }
    *out_len = w;
    assert(w <= cap);
    return true;
}

bool ipc_next_message(std::string_view stream, std::size_t* pos,
                      IpcMessage* out, bool* malformed) noexcept {
    assert(pos != nullptr && out != nullptr && malformed != nullptr);
    *malformed = false;
    const std::size_t start = *pos;
    if (start >= stream.size()) return false;
    const auto* p = reinterpret_cast<const std::uint8_t*>(stream.data());
    if (stream.size() - start < 8 || le_u32(p + start) != 0xFFFFFFFFu) {
        *malformed = true;
        return false;
    }
    const std::uint32_t meta_len = le_u32(p + start + 4);
    if (meta_len == 0) return false;   // end-of-stream marker
    const std::size_t meta_at = start + 8;
    if (meta_len > stream.size() - meta_at) { *malformed = true; return false; }
    out->metadata = stream.substr(meta_at, meta_len);
    std::int64_t body_len = 0;
    if (!read_message_table(out->metadata, &out->header_type, &body_len)) {
        *malformed = true;
        return false;
    }
    const std::size_t body_at = meta_at + meta_len;
    if (static_cast<std::uint64_t>(body_len) > stream.size() - body_at) {
        *malformed = true;
        return false;
    }
    out->encapsulated = stream.substr(start, 8u + meta_len);
    out->body = stream.substr(body_at, static_cast<std::size_t>(body_len));
    *pos = body_at + static_cast<std::size_t>(body_len);
    assert(*pos <= stream.size());
    return true;
}

}  // namespace bolt::api::proto::flightsql::codec

#endif  // BOLTAPI_WITH_FLIGHT_SQL
