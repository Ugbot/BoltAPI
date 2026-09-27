// boltapi/boltapi_limits.h — boltapi's entries in the bolt Limits registry.
//
// Each value is derived from the constant that enforces it. Kind A today;
// the limits review turns the wire-door caps into streamed encoders.

#pragma once

#include <cstdint>

#include "bolt/bolt_limits.h"
#include "boltapi/proto/postgres_wire.h"
#include "boltapi/quic/quic_limits.h"
#include "boltapi/router.h"
#include "boltapi/wire_limits.h"

#define BOLTAPI_LIMITS(X)                                                       \
    X(pgwire_max_fields, kInvariant, "columns",                                 \
      ::bolt::api::proto::pgwire::kMaxFields,                                   \
      ::bolt::api::proto::pgwire::kMaxFields,                                   \
      ::bolt::api::proto::pgwire::kMaxFields, nullptr, nullptr,                 \
      "columns in one Postgres RowDescription")                                 \
    X(router_max_params, kInvariant, "params", ::bolt::api::kMaxParams,          \
      ::bolt::api::kMaxParams, ::bolt::api::kMaxParams, nullptr, nullptr,       \
      "path parameters captured per route match")                               \
    X(ws_max_control_payload, kInvariant, "bytes", ::bolt::api::kWsMaxControlPayload, \
      ::bolt::api::kWsMaxControlPayload, ::bolt::api::kWsMaxControlPayload,     \
      nullptr, nullptr, "WebSocket control-frame payload (RFC 6455)")           \
    X(ws_max_frame_header, kInvariant, "bytes", ::bolt::api::kWsMaxFrameHeader,  \
      ::bolt::api::kWsMaxFrameHeader, ::bolt::api::kWsMaxFrameHeader, nullptr, \
      nullptr, "WebSocket frame header")                                        \
    X(qpack_max_int, kInvariant, "value", ::bolt::api::kQpackMaxIntValue,       \
      ::bolt::api::kQpackMaxIntValue, ::bolt::api::kQpackMaxIntValue, nullptr,  \
      nullptr, "largest QPACK integer (QUIC varint range)")                     \
    X(http3_max_method_len, kInvariant, "bytes", ::bolt::api::kHttp3MaxMethodLen, \
      ::bolt::api::kHttp3MaxMethodLen, ::bolt::api::kHttp3MaxMethodLen, nullptr, \
      nullptr, "HTTP/3 :method length routed; longer is a 400")                \
    X(hq_max_request_line, kInvariant, "bytes", ::bolt::api::kHqMaxRequestLine,   \
      ::bolt::api::kHqMaxRequestLine, ::bolt::api::kHqMaxRequestLine, nullptr,   \
      nullptr, "hq-interop (HTTP/0.9) request line; longer resets the stream")  \
    X(quic_peer_bidi_streams, kInvariant, "streams",                            \
      ::bolt::api::quic::kPeerBidiStreamsMax,                                   \
      ::bolt::api::quic::kPeerBidiStreamsMax,                                   \
      ::bolt::api::quic::kPeerBidiStreamsMax, nullptr, nullptr,                 \
      "concurrent peer bidi QUIC streams per connection")                       \
    X(quic_peer_uni_streams, kInvariant, "streams",                             \
      ::bolt::api::quic::kPeerUniStreamsMax,                                    \
      ::bolt::api::quic::kPeerUniStreamsMax,                                    \
      ::bolt::api::quic::kPeerUniStreamsMax, nullptr, nullptr,                  \
      "concurrent peer uni QUIC streams per connection")                        \
    X(quic_closed_stream_window, kInvariant, "streams",                         \
      ::bolt::api::quic::kClosedStreamWindowMax,                                \
      ::bolt::api::quic::kClosedStreamWindowMax,                                \
      ::bolt::api::quic::kClosedStreamWindowMax, nullptr, nullptr,              \
      "stream ids remembered past the lowest open one")                         \
    X(quic_pending_send_bytes, kInvariant, "bytes",                             \
      ::bolt::api::quic::kPendingSendBytesMax,                                  \
      ::bolt::api::quic::kPendingSendBytesMax,                                  \
      ::bolt::api::quic::kPendingSendBytesMax, nullptr, nullptr,                \
      "response bytes held per QUIC connection awaiting stream space")

namespace bolt::api {

BOLT_LIMITS_TABLE(boltapi_limits, "boltapi", BOLTAPI_LIMITS)

}  // namespace bolt::api
