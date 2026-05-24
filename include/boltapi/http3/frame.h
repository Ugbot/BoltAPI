// boltapi/http3/frame.h — HTTP/3 frame layer (RFC 9114).
//
// The wire framing that rides on top of QUIC streams: a frame is a varint type
// followed by a varint length followed by `length` payload bytes (RFC 9114 §7.1).
// This header provides:
//   * the frame-type constants (DATA/HEADERS/SETTINGS/GOAWAY/CANCEL_PUSH/
//     MAX_PUSH_ID) — RFC 9114 §7.2;
//   * a bounded frame *reader* that pulls one complete frame out of a byte span,
//     reporting "need more bytes" without copying;
//   * a frame *writer* that prepends the type+length varint header to a payload;
//   * the SETTINGS frame codec (QPACK_MAX_TABLE_CAPACITY / MAX_FIELD_SECTION_SIZE
//     / QPACK_BLOCKED_STREAMS) — RFC 9114 §7.2.4 + RFC 9204 §5;
//   * the unidirectional-stream type prefixes (control / push / QPACK encoder /
//     QPACK decoder) — RFC 9114 §6.2 + RFC 9204 §4.2.
//
// Tiger Style: header-only, no exceptions, >=2 asserts per function, every loop
// bounded, fixed-capacity buffers (no unbounded std::vector growth on the hot
// path). Reuses boltapi/quic/varint.h for the varint codec. Compiles
// UNCONDITIONALLY (varint.h is dependency-free), so the gate test runs in the
// default ctest suite — no BOLTAPI_WITH_HTTP3 gate on this file.

#pragma once

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "boltapi/quic/varint.h"

namespace bolt::api::http3 {

// ----------------------------------------------------------------------------
// Frame types (RFC 9114 §7.2 / §11.2.1). Values are QUIC varints on the wire.
// ----------------------------------------------------------------------------
enum class FrameType : std::uint64_t {
    kData       = 0x00,  // §7.2.1 — request/response body bytes
    kHeaders    = 0x01,  // §7.2.2 — QPACK-encoded field section
    kCancelPush = 0x03,  // §7.2.3
    kSettings   = 0x04,  // §7.2.4 — connection settings (control stream only)
    kGoaway     = 0x07,  // §7.2.6 — graceful shutdown
    kMaxPushId  = 0x0d,  // §7.2.7
};

// ----------------------------------------------------------------------------
// Unidirectional stream type prefixes (RFC 9114 §6.2 / RFC 9204 §4.2). The
// first varint on a uni stream selects its role.
// ----------------------------------------------------------------------------
enum class UniStreamType : std::uint64_t {
    kControl      = 0x00,  // §6.2.1 — carries SETTINGS, GOAWAY, etc.
    kPush         = 0x01,  // §6.2.2 — server push (unused here)
    kQpackEncoder = 0x02,  // RFC 9204 §4.2 — encoder-stream instructions
    kQpackDecoder = 0x03,  // RFC 9204 §4.2 — decoder-stream instructions
};

// ----------------------------------------------------------------------------
// SETTINGS identifiers (RFC 9114 §7.2.4.1 + RFC 9204 §5).
// ----------------------------------------------------------------------------
enum class SettingId : std::uint64_t {
    kQpackMaxTableCapacity = 0x01,  // RFC 9204 §5
    kMaxFieldSectionSize   = 0x06,  // RFC 9114 §7.2.4.1
    kQpackBlockedStreams   = 0x07,  // RFC 9204 §5
    kEnableConnectProtocol = 0x08,        // RFC 9220 — extended CONNECT (:protocol)
    kH3Datagram            = 0x33,        // RFC 9297 — HTTP/3 datagrams
    kWtMaxSessions         = 0x14e9cd29,  // WebTransport-over-HTTP/3 (SETTINGS_WT_MAX_SESSIONS)
};

// ----------------------------------------------------------------------------
// Named bounds (Tiger Style: every limit explicit + asserted).
// ----------------------------------------------------------------------------
inline constexpr std::size_t kFrameHeaderMaxBytes = 16;     // two 8-byte varints
inline constexpr std::size_t kSettingsMaxEntries  = 8;      // we emit/accept few
inline constexpr std::size_t kSettingsMaxBytes     = 64;    // 8 entries * 2 vints
inline constexpr std::uint64_t kFrameMaxPayloadLen = 1u << 20;  // 1 MiB cap

// Sentinels for the frame reader's status.
enum class FrameStatus : std::uint8_t {
    kOk       = 0,  // a full frame is available
    kNeedMore = 1,  // header/payload incomplete — feed more bytes
    kError    = 2,  // malformed (length overflow / varint error)
};

// ----------------------------------------------------------------------------
// A parsed-but-borrowed frame: type + a view of its payload inside the caller's
// buffer. No allocation; the payload pointer aliases the input span.
// ----------------------------------------------------------------------------
struct FrameView {
    std::uint64_t       type    = 0;
    const std::uint8_t* payload = nullptr;
    std::size_t         length  = 0;
};

// ----------------------------------------------------------------------------
// frame_parse — read ONE complete frame from `data[0..len)`.
//
// On kOk, `out` borrows the payload (valid while `data` is) and `consumed` is
// the total bytes (header + payload) the frame occupied. On kNeedMore nothing is
// written. On kError the input is malformed.
// ----------------------------------------------------------------------------
inline FrameStatus frame_parse(const std::uint8_t* data, std::size_t len,
                               FrameView& out, std::size_t& consumed) noexcept {
    assert((data != nullptr || len == 0) && "frame_parse: null with len>0");
    assert(len <= (std::size_t{1} << 24) && "frame_parse: span implausibly large");

    std::uint64_t type = 0;
    const int tn = quic::varint_decode(data, len, type);
    if (tn == quic::kVarIntNeedMore) return FrameStatus::kNeedMore;
    assert(tn > 0 && "varint decode returned non-positive on success");

    std::uint64_t flen = 0;
    const int ln = quic::varint_decode(data + tn, len - static_cast<std::size_t>(tn),
                                       flen);
    if (ln == quic::kVarIntNeedMore) return FrameStatus::kNeedMore;
    assert(ln > 0 && "length varint decode non-positive");
    if (flen > kFrameMaxPayloadLen) return FrameStatus::kError;

    const std::size_t hdr = static_cast<std::size_t>(tn) + static_cast<std::size_t>(ln);
    if (len - hdr < flen) return FrameStatus::kNeedMore;

    out.type    = type;
    out.payload = data + hdr;
    out.length  = static_cast<std::size_t>(flen);
    consumed    = hdr + static_cast<std::size_t>(flen);
    assert(consumed <= len && "frame consumed past buffer");
    return FrameStatus::kOk;
}

// ----------------------------------------------------------------------------
// frame_write_header — write `type` + `payload_len` varint header into `out`.
// Returns header bytes written, or 0 on overflow. `out` must have room for at
// least kFrameHeaderMaxBytes.
// ----------------------------------------------------------------------------
inline std::size_t frame_write_header(std::uint64_t type, std::uint64_t payload_len,
                                      std::uint8_t* out, std::size_t cap) noexcept {
    assert(out != nullptr && "frame_write_header: null out");
    assert(payload_len <= quic::kVarIntMax && "payload length not a varint");
    const std::size_t need = quic::varint_encoded_size(type) +
                             quic::varint_encoded_size(payload_len);
    if (cap < need) return 0;
    std::size_t pos = quic::varint_encode(type, out);
    pos += quic::varint_encode(payload_len, out + pos);
    assert(pos == need && "header byte count mismatch");
    return pos;
}

// ----------------------------------------------------------------------------
// SettingsFrame — the small set of settings we send + accept. Bounded by
// kSettingsMaxEntries; unknown ids are tolerated on parse (RFC 9114 §7.2.4.1).
// ----------------------------------------------------------------------------
struct SettingsFrame {
    std::uint64_t qpack_max_table_capacity = 0;
    std::uint64_t max_field_section_size    = 0;
    std::uint64_t qpack_blocked_streams     = 0;
    bool          has_max_field_section     = false;
    // WebTransport (advertised by the server so a browser will offer WebTransport).
    bool          enable_connect_protocol   = false;  // RFC 9220
    bool          h3_datagram               = false;  // RFC 9297
    std::uint64_t wt_max_sessions           = 0;      // 0 = WebTransport disabled

    // Encode the SETTINGS *payload* (id/value varint pairs) into `out`. Returns
    // payload bytes written, or 0 on overflow. Does NOT prepend the frame header
    // (the caller frames it with frame_write_header so control-stream framing is
    // explicit). Only non-default values are emitted.
    std::size_t encode_payload(std::uint8_t* out, std::size_t cap) const noexcept {
        assert(out != nullptr && "settings encode: null out");
        assert(cap >= kSettingsMaxBytes && "settings out buffer too small");
        std::size_t pos = 0;
        pos += put_setting(SettingId::kQpackMaxTableCapacity,
                           qpack_max_table_capacity, out, cap, pos);
        if (has_max_field_section) {
            pos += put_setting(SettingId::kMaxFieldSectionSize,
                               max_field_section_size, out, cap, pos);
        }
        pos += put_setting(SettingId::kQpackBlockedStreams,
                           qpack_blocked_streams, out, cap, pos);
        if (enable_connect_protocol)
            pos += put_setting(SettingId::kEnableConnectProtocol, 1, out, cap, pos);
        if (h3_datagram)
            pos += put_setting(SettingId::kH3Datagram, 1, out, cap, pos);
        if (wt_max_sessions > 0)
            pos += put_setting(SettingId::kWtMaxSessions, wt_max_sessions,
                               out, cap, pos);
        assert(pos <= cap && "settings encode overran buffer");
        return pos;
    }

    // Parse a SETTINGS payload (id/value pairs). Returns true on success. Bounded
    // loop (kSettingsMaxEntries); unknown ids are skipped, not rejected.
    bool parse_payload(const std::uint8_t* in, std::size_t len) noexcept {
        assert((in != nullptr || len == 0) && "settings parse: null with len>0");
        assert(len <= kFrameMaxPayloadLen && "settings payload implausibly large");
        std::size_t pos = 0;
        for (std::size_t i = 0; i < kSettingsMaxEntries && pos < len; ++i) {
            std::uint64_t id = 0;
            const int idn = quic::varint_decode(in + pos, len - pos, id);
            if (idn <= 0) return false;
            pos += static_cast<std::size_t>(idn);
            std::uint64_t val = 0;
            const int vn = quic::varint_decode(in + pos, len - pos, val);
            if (vn <= 0) return false;
            pos += static_cast<std::size_t>(vn);
            apply(id, val);
        }
        return pos == len;
    }

private:
    void apply(std::uint64_t id, std::uint64_t val) noexcept {
        assert(id <= quic::kVarIntMax && "setting id out of range");
        assert(val <= quic::kVarIntMax && "setting value out of range");
        if (id == static_cast<std::uint64_t>(SettingId::kQpackMaxTableCapacity)) {
            qpack_max_table_capacity = val;
        } else if (id == static_cast<std::uint64_t>(SettingId::kMaxFieldSectionSize)) {
            max_field_section_size = val;
            has_max_field_section  = true;
        } else if (id == static_cast<std::uint64_t>(SettingId::kQpackBlockedStreams)) {
            qpack_blocked_streams = val;
        }
        // Unknown ids ignored (RFC 9114 §7.2.4.1).
    }

    static std::size_t put_setting(SettingId id, std::uint64_t val,
                                   std::uint8_t* out, std::size_t cap,
                                   std::size_t pos) noexcept {
        assert(out != nullptr && "put_setting: null out");
        assert(pos <= cap && "put_setting: pos past cap");
        const std::uint64_t idv = static_cast<std::uint64_t>(id);
        const std::size_t need = quic::varint_encoded_size(idv) +
                                 quic::varint_encoded_size(val);
        if (cap - pos < need) return 0;
        std::size_t n = quic::varint_encode(idv, out + pos);
        n += quic::varint_encode(val, out + pos + n);
        return n;
    }
};

}  // namespace bolt::api::http3
