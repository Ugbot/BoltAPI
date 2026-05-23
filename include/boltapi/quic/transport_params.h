// boltapi/quic/transport_params.h — QUIC transport parameters codec (RFC 9000
// §18, §18.2) for the TLS 1.3 quic_transport_parameters extension.
//
// Wire format (RFC 9000 §18): a sequence of TLV triples, each
//   varint(parameter_id) varint(length) value[length]
// carried opaque in the TLS extension. Some parameters are zero-length flags
// (e.g. disable_active_migration); most integer parameters encode their value
// as a single QUIC varint inside the value field; the connection-id parameters
// carry raw CID bytes.
//
// Tiger Style (matching the rest of boltapi/quic/*): namespace bolt::api::quic,
// >=2 asserts per function, named bounds, noexcept, no allocation, no
// exceptions, explicit bool returns. Built UNCONDITIONALLY (pure code, no
// OpenSSL) so the default ctest suite covers the round-trip unit test.
//
// SCOPE (wave 3): the codec only. The handshake driver (tls.h) feeds the
// encoded bytes to SSL_set_quic_tls_transport_params and decodes the peer's via
// the got_transport_params callback.

#pragma once

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "boltapi/quic/varint.h"

namespace bolt::api::quic {

// ----------------------------------------------------------------------------
// Transport parameter IDs (RFC 9000 §18.2 + RFC 9000 Table 7). Only the
// parameters we encode/decode are enumerated; unknown IDs are skipped on decode
// (RFC 9000 §18.1: "An endpoint MUST ignore transport parameters that it does
// not support").
// ----------------------------------------------------------------------------
enum class TransportParamId : std::uint64_t {
    kOriginalDestinationConnectionId = 0x00,
    kMaxIdleTimeout = 0x01,
    kStatelessResetToken = 0x02,
    kMaxUdpPayloadSize = 0x03,
    kInitialMaxData = 0x04,
    kInitialMaxStreamDataBidiLocal = 0x05,
    kInitialMaxStreamDataBidiRemote = 0x06,
    kInitialMaxStreamDataUni = 0x07,
    kInitialMaxStreamsBidi = 0x08,
    kInitialMaxStreamsUni = 0x09,
    kAckDelayExponent = 0x0a,
    kMaxAckDelay = 0x0b,
    kDisableActiveMigration = 0x0c,
    kPreferredAddress = 0x0d,
    kActiveConnectionIdLimit = 0x0e,
    kInitialSourceConnectionId = 0x0f,
    kRetrySourceConnectionId = 0x10,
};

// ----------------------------------------------------------------------------
// Named bounds (RFC 9000 §18 / §18.2).
// ----------------------------------------------------------------------------
inline constexpr std::size_t kMaxConnectionIdLength = 20;   // RFC 9000 §17.2
inline constexpr std::size_t kStatelessResetTokenLength = 16;  // §10.3
inline constexpr std::uint64_t kDefaultMaxUdpPayloadSize = 65527;  // §18.2
inline constexpr std::uint64_t kDefaultAckDelayExponent = 3;       // §18.2
inline constexpr std::uint64_t kDefaultMaxAckDelay = 25;           // ms, §18.2
inline constexpr std::uint64_t kDefaultActiveConnIdLimit = 2;      // §18.2
inline constexpr std::uint64_t kMaxAckDelayExponent = 20;          // §18.2

// A generous upper bound on a single encoded transport-parameter block. RFC
// 9000 does not fix one, but a few hundred bytes covers every parameter we
// emit; callers size their scratch from this.
inline constexpr std::size_t kMaxTransportParamsBytes = 512;

// ----------------------------------------------------------------------------
// TransportParameters — the decoded/decodable parameter set. Integer
// parameters default to their RFC 9000 §18.2 defaults; the *_present flags mark
// which were explicitly set/seen so encode emits exactly the set ones and
// decode reports presence. Connection IDs are inline fixed buffers (no alloc).
// ----------------------------------------------------------------------------
struct TransportParameters {
    // Integer parameters (RFC 9000 §18.2). Defaults match the spec.
    std::uint64_t max_idle_timeout = 0;                   // ms; 0 = disabled
    std::uint64_t max_udp_payload_size = kDefaultMaxUdpPayloadSize;
    std::uint64_t initial_max_data = 0;
    std::uint64_t initial_max_stream_data_bidi_local = 0;
    std::uint64_t initial_max_stream_data_bidi_remote = 0;
    std::uint64_t initial_max_stream_data_uni = 0;
    std::uint64_t initial_max_streams_bidi = 0;
    std::uint64_t initial_max_streams_uni = 0;
    std::uint64_t ack_delay_exponent = kDefaultAckDelayExponent;
    std::uint64_t max_ack_delay = kDefaultMaxAckDelay;            // ms
    std::uint64_t active_connection_id_limit = kDefaultActiveConnIdLimit;

    bool disable_active_migration = false;

    // Connection-id parameters (raw bytes, RFC 9000 §18.2 / §7.3). Each carries
    // an explicit length + present flag.
    std::uint8_t initial_source_connection_id[kMaxConnectionIdLength] = {};
    std::size_t initial_source_connection_id_len = 0;
    bool initial_source_connection_id_present = false;

    std::uint8_t original_destination_connection_id[kMaxConnectionIdLength] = {};
    std::size_t original_destination_connection_id_len = 0;
    bool original_destination_connection_id_present = false;

    std::uint8_t retry_source_connection_id[kMaxConnectionIdLength] = {};
    std::size_t retry_source_connection_id_len = 0;
    bool retry_source_connection_id_present = false;

    std::uint8_t stateless_reset_token[kStatelessResetTokenLength] = {};
    bool stateless_reset_token_present = false;

    // Presence flags for the integer parameters (so encode only writes what was
    // explicitly set, and decode reports what the peer actually sent).
    bool max_idle_timeout_present = false;
    bool max_udp_payload_size_present = false;
    bool initial_max_data_present = false;
    bool initial_max_stream_data_bidi_local_present = false;
    bool initial_max_stream_data_bidi_remote_present = false;
    bool initial_max_stream_data_uni_present = false;
    bool initial_max_streams_bidi_present = false;
    bool initial_max_streams_uni_present = false;
    bool ack_delay_exponent_present = false;
    bool max_ack_delay_present = false;
    bool active_connection_id_limit_present = false;
};

namespace detail {

// Append a varint to out[*n], growing *n. Returns false if it would overflow
// cap. Bounded: writes at most 8 bytes.
inline bool tp_put_varint(std::uint8_t* out, std::size_t cap, std::size_t* n,
                          std::uint64_t value) noexcept {
    assert(out != nullptr && n != nullptr && "tp_put_varint: null");
    assert(value <= kVarIntMax && "tp_put_varint: value exceeds 2^62-1");
    const std::size_t need = varint_encoded_size(value);
    if (*n + need > cap) return false;
    const std::size_t wrote = varint_encode(value, out + *n);
    assert(wrote == need && "tp_put_varint: size mismatch");
    *n += wrote;
    return true;
}

// Append one integer parameter as id|len|varint(value). Returns false on
// overflow.
inline bool tp_put_int(std::uint8_t* out, std::size_t cap, std::size_t* n,
                       TransportParamId id, std::uint64_t value) noexcept {
    assert(out != nullptr && n != nullptr && "tp_put_int: null");
    const std::size_t vlen = varint_encoded_size(value);
    if (!tp_put_varint(out, cap, n, static_cast<std::uint64_t>(id))) return false;
    if (!tp_put_varint(out, cap, n, vlen)) return false;
    return tp_put_varint(out, cap, n, value);
}

// Append one raw-bytes parameter as id|len|bytes. Returns false on overflow.
inline bool tp_put_bytes(std::uint8_t* out, std::size_t cap, std::size_t* n,
                         TransportParamId id, const std::uint8_t* data,
                         std::size_t len) noexcept {
    assert(out != nullptr && n != nullptr && "tp_put_bytes: null");
    assert((data != nullptr || len == 0) && "tp_put_bytes: null data");
    if (!tp_put_varint(out, cap, n, static_cast<std::uint64_t>(id))) return false;
    if (!tp_put_varint(out, cap, n, len)) return false;
    if (*n + len > cap) return false;
    if (len > 0) std::memcpy(out + *n, data, len);
    *n += len;
    return true;
}

}  // namespace detail

// ----------------------------------------------------------------------------
// encode_transport_params — serialize the present parameters into out[0..cap)
// (RFC 9000 §18). Writes the byte count to *out_len. Returns false if the
// buffer is too small. Only parameters with their *_present flag (or a non-empty
// CID / a true flag) are emitted, so a peer sees exactly what we set.
// ----------------------------------------------------------------------------
inline bool encode_transport_params(const TransportParameters& tp,
                                    std::uint8_t* out, std::size_t cap,
                                    std::size_t* out_len) noexcept {
    assert(out != nullptr && out_len != nullptr && "encode_transport_params: null");
    assert(cap > 0 && "encode_transport_params: zero cap");

    std::size_t n = 0;
    bool ok = true;

    if (tp.max_idle_timeout_present)
        ok = ok && detail::tp_put_int(out, cap, &n,
                                      TransportParamId::kMaxIdleTimeout,
                                      tp.max_idle_timeout);
    if (tp.max_udp_payload_size_present)
        ok = ok && detail::tp_put_int(out, cap, &n,
                                      TransportParamId::kMaxUdpPayloadSize,
                                      tp.max_udp_payload_size);
    if (tp.initial_max_data_present)
        ok = ok && detail::tp_put_int(out, cap, &n,
                                      TransportParamId::kInitialMaxData,
                                      tp.initial_max_data);
    if (tp.initial_max_stream_data_bidi_local_present)
        ok = ok && detail::tp_put_int(
                       out, cap, &n,
                       TransportParamId::kInitialMaxStreamDataBidiLocal,
                       tp.initial_max_stream_data_bidi_local);
    if (tp.initial_max_stream_data_bidi_remote_present)
        ok = ok && detail::tp_put_int(
                       out, cap, &n,
                       TransportParamId::kInitialMaxStreamDataBidiRemote,
                       tp.initial_max_stream_data_bidi_remote);
    if (tp.initial_max_stream_data_uni_present)
        ok = ok && detail::tp_put_int(out, cap, &n,
                                      TransportParamId::kInitialMaxStreamDataUni,
                                      tp.initial_max_stream_data_uni);
    if (tp.initial_max_streams_bidi_present)
        ok = ok && detail::tp_put_int(out, cap, &n,
                                      TransportParamId::kInitialMaxStreamsBidi,
                                      tp.initial_max_streams_bidi);
    if (tp.initial_max_streams_uni_present)
        ok = ok && detail::tp_put_int(out, cap, &n,
                                      TransportParamId::kInitialMaxStreamsUni,
                                      tp.initial_max_streams_uni);
    if (tp.ack_delay_exponent_present)
        ok = ok && detail::tp_put_int(out, cap, &n,
                                      TransportParamId::kAckDelayExponent,
                                      tp.ack_delay_exponent);
    if (tp.max_ack_delay_present)
        ok = ok && detail::tp_put_int(out, cap, &n,
                                      TransportParamId::kMaxAckDelay,
                                      tp.max_ack_delay);
    if (tp.active_connection_id_limit_present)
        ok = ok && detail::tp_put_int(out, cap, &n,
                                      TransportParamId::kActiveConnectionIdLimit,
                                      tp.active_connection_id_limit);

    if (tp.disable_active_migration)
        ok = ok && detail::tp_put_bytes(out, cap, &n,
                                        TransportParamId::kDisableActiveMigration,
                                        nullptr, 0);

    if (tp.initial_source_connection_id_present)
        ok = ok && detail::tp_put_bytes(
                       out, cap, &n,
                       TransportParamId::kInitialSourceConnectionId,
                       tp.initial_source_connection_id,
                       tp.initial_source_connection_id_len);
    if (tp.original_destination_connection_id_present)
        ok = ok && detail::tp_put_bytes(
                       out, cap, &n,
                       TransportParamId::kOriginalDestinationConnectionId,
                       tp.original_destination_connection_id,
                       tp.original_destination_connection_id_len);
    if (tp.retry_source_connection_id_present)
        ok = ok && detail::tp_put_bytes(
                       out, cap, &n,
                       TransportParamId::kRetrySourceConnectionId,
                       tp.retry_source_connection_id,
                       tp.retry_source_connection_id_len);
    if (tp.stateless_reset_token_present)
        ok = ok && detail::tp_put_bytes(out, cap, &n,
                                        TransportParamId::kStatelessResetToken,
                                        tp.stateless_reset_token,
                                        kStatelessResetTokenLength);

    if (!ok) return false;
    assert(n <= cap && "encode_transport_params overran");
    *out_len = n;
    return true;
}

namespace detail {

// Decode a varint from data[*pos..len), storing it in *value and advancing
// *pos. Returns false on truncation.
inline bool tp_get_varint(const std::uint8_t* data, std::size_t len,
                          std::size_t* pos, std::uint64_t* value) noexcept {
    assert(data != nullptr && pos != nullptr && value != nullptr &&
           "tp_get_varint: null");
    assert(*pos <= len && "tp_get_varint: pos past end");
    const int got = varint_decode(data + *pos, len - *pos, *value);
    if (got <= 0) return false;
    *pos += static_cast<std::size_t>(got);
    return true;
}

// Copy a fixed-capacity CID/token value. Returns false if vlen > cap.
inline bool tp_copy_bytes(std::uint8_t* dst, std::size_t cap,
                          std::size_t* dst_len, const std::uint8_t* src,
                          std::size_t vlen) noexcept {
    assert(dst != nullptr && dst_len != nullptr && "tp_copy_bytes: null");
    if (vlen > cap) return false;
    if (vlen > 0) std::memcpy(dst, src, vlen);
    *dst_len = vlen;
    return true;
}

}  // namespace detail

// ----------------------------------------------------------------------------
// decode_transport_params — parse a TLV block (RFC 9000 §18) into *out. Unknown
// parameter IDs are skipped (§18.1). Returns false on a malformed/truncated
// block or an out-of-range value (e.g. a CID longer than 20 bytes). Bounded by
// the input length (each iteration consumes >=1 byte for the id varint).
// ----------------------------------------------------------------------------
inline bool decode_transport_params(const std::uint8_t* data, std::size_t len,
                                    TransportParameters* out) noexcept {
    assert((data != nullptr || len == 0) && "decode_transport_params: null");
    assert(out != nullptr && "decode_transport_params: null out");

    std::size_t pos = 0;
    while (pos < len) {
        std::uint64_t id = 0;
        std::uint64_t vlen = 0;
        if (!detail::tp_get_varint(data, len, &pos, &id)) return false;
        if (!detail::tp_get_varint(data, len, &pos, &vlen)) return false;
        if (vlen > len - pos) return false;  // value runs past the buffer
        const std::uint8_t* val = data + pos;

        // For integer parameters, decode the inner varint from the value field.
        auto read_int = [&](std::uint64_t* dst, bool* present) -> bool {
            std::size_t ipos = 0;
            std::uint64_t v = 0;
            if (!detail::tp_get_varint(val, static_cast<std::size_t>(vlen),
                                       &ipos, &v))
                return false;
            *dst = v;
            *present = true;
            return true;
        };

        bool ok = true;
        switch (static_cast<TransportParamId>(id)) {
            case TransportParamId::kMaxIdleTimeout:
                ok = read_int(&out->max_idle_timeout,
                              &out->max_idle_timeout_present);
                break;
            case TransportParamId::kMaxUdpPayloadSize:
                ok = read_int(&out->max_udp_payload_size,
                              &out->max_udp_payload_size_present);
                break;
            case TransportParamId::kInitialMaxData:
                ok = read_int(&out->initial_max_data,
                              &out->initial_max_data_present);
                break;
            case TransportParamId::kInitialMaxStreamDataBidiLocal:
                ok = read_int(&out->initial_max_stream_data_bidi_local,
                              &out->initial_max_stream_data_bidi_local_present);
                break;
            case TransportParamId::kInitialMaxStreamDataBidiRemote:
                ok = read_int(&out->initial_max_stream_data_bidi_remote,
                              &out->initial_max_stream_data_bidi_remote_present);
                break;
            case TransportParamId::kInitialMaxStreamDataUni:
                ok = read_int(&out->initial_max_stream_data_uni,
                              &out->initial_max_stream_data_uni_present);
                break;
            case TransportParamId::kInitialMaxStreamsBidi:
                ok = read_int(&out->initial_max_streams_bidi,
                              &out->initial_max_streams_bidi_present);
                break;
            case TransportParamId::kInitialMaxStreamsUni:
                ok = read_int(&out->initial_max_streams_uni,
                              &out->initial_max_streams_uni_present);
                break;
            case TransportParamId::kAckDelayExponent:
                ok = read_int(&out->ack_delay_exponent,
                              &out->ack_delay_exponent_present);
                break;
            case TransportParamId::kMaxAckDelay:
                ok = read_int(&out->max_ack_delay, &out->max_ack_delay_present);
                break;
            case TransportParamId::kActiveConnectionIdLimit:
                ok = read_int(&out->active_connection_id_limit,
                              &out->active_connection_id_limit_present);
                break;
            case TransportParamId::kDisableActiveMigration:
                // Zero-length flag (RFC 9000 §18.2). A non-empty value is an error.
                ok = (vlen == 0);
                out->disable_active_migration = true;
                break;
            case TransportParamId::kInitialSourceConnectionId:
                ok = detail::tp_copy_bytes(
                    out->initial_source_connection_id, kMaxConnectionIdLength,
                    &out->initial_source_connection_id_len, val,
                    static_cast<std::size_t>(vlen));
                out->initial_source_connection_id_present = ok;
                break;
            case TransportParamId::kOriginalDestinationConnectionId:
                ok = detail::tp_copy_bytes(
                    out->original_destination_connection_id,
                    kMaxConnectionIdLength,
                    &out->original_destination_connection_id_len, val,
                    static_cast<std::size_t>(vlen));
                out->original_destination_connection_id_present = ok;
                break;
            case TransportParamId::kRetrySourceConnectionId:
                ok = detail::tp_copy_bytes(
                    out->retry_source_connection_id, kMaxConnectionIdLength,
                    &out->retry_source_connection_id_len, val,
                    static_cast<std::size_t>(vlen));
                out->retry_source_connection_id_present = ok;
                break;
            case TransportParamId::kStatelessResetToken:
                ok = (vlen == kStatelessResetTokenLength);
                if (ok) {
                    std::memcpy(out->stateless_reset_token, val,
                                kStatelessResetTokenLength);
                    out->stateless_reset_token_present = true;
                }
                break;
            default:
                // Unknown / unsupported parameter (incl. preferred_address):
                // skip its value (RFC 9000 §18.1).
                ok = true;
                break;
        }
        if (!ok) return false;
        pos += static_cast<std::size_t>(vlen);
    }
    assert(pos == len && "decode_transport_params: trailing bytes");
    return pos == len;
}

}  // namespace bolt::api::quic
