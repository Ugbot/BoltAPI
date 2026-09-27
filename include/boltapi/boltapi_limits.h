// boltapi/boltapi_limits.h — boltapi's entries in the bolt Limits registry.
//
// Each value is derived from the constant that enforces it. Kind A today;
// the limits review turns the wire-door caps into streamed encoders.

#pragma once

#include <cstdint>

#include "bolt/bolt_limits.h"
#include "boltapi/proto/postgres_wire.h"
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
      nullptr, "HTTP/3 :method length routed; longer is a 400")

namespace bolt::api {

BOLT_LIMITS_TABLE(boltapi_limits, "boltapi", BOLTAPI_LIMITS)

}  // namespace bolt::api
