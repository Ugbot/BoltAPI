// boltapi/boltapi_limits.h — boltapi's entries in the bolt Limits registry.
//
// Each value is derived from the constant that enforces it. Kind A today;
// the limits review turns the wire-door caps into streamed encoders.

#pragma once

#include <cstdint>

#include "bolt/bolt_limits.h"
#include "boltapi/proto/grpc_limits.h"
#include "boltapi/proto/postgres_wire.h"
#include "boltapi/http/fixed_stream_limits.h"
#include "boltapi/quic/quic_limits.h"
#include "boltapi/router.h"
#include "boltapi/wire_limits.h"

#define BOLTAPI_LIMITS(X)                                                       \
    X(fixed_stream_slice_bytes, kFixedAtAlloc, "bytes",                             \
      ::bolt::api::kFixedStreamSliceBytes, ::bolt::api::kFixedStreamSliceBytes,  \
      ::bolt::api::kFixedStreamSliceBytes, nullptr, nullptr,                    \
      "bytes in each startup fixed-stream handoff slot")                       \
    X(fixed_stream_max_slots, kFixedAtAlloc, "slots",                               \
      ::bolt::api::kFixedStreamMaxSlots, ::bolt::api::kFixedStreamMaxSlots,      \
      ::bolt::api::kFixedStreamMaxSlots, nullptr, nullptr,                      \
      "maximum fixed-stream slots allocated at server startup")                \
    X(grpc_settings_max_concurrent_id, kInvariant, "id", ::bolt::api::proto::grpc::kSettingsMaxConcurrent, ::bolt::api::proto::grpc::kSettingsMaxConcurrent, ::bolt::api::proto::grpc::kSettingsMaxConcurrent, nullptr, nullptr, \
      "RFC 9113 SETTINGS_MAX_CONCURRENT_STREAMS identifier") \
    X(grpc_settings_max_frame_size_id, kInvariant, "id", ::bolt::api::proto::grpc::kSettingsMaxFrameSize, ::bolt::api::proto::grpc::kSettingsMaxFrameSize, ::bolt::api::proto::grpc::kSettingsMaxFrameSize, nullptr, nullptr, \
      "RFC 9113 SETTINGS_MAX_FRAME_SIZE identifier") \
    X(grpc_max_frame, kInvariant, "bytes", ::bolt::api::proto::grpc::kOurMaxFrame, ::bolt::api::proto::grpc::kOurMaxFrame, ::bolt::api::proto::grpc::kOurMaxFrame, nullptr, nullptr, \
      "HTTP/2 frame payload we accept (RFC 9113 initial max)") \
    X(grpc_max_window, kInvariant, "bytes", ::bolt::api::proto::grpc::kMaxWindow, ::bolt::api::proto::grpc::kMaxWindow, ::bolt::api::proto::grpc::kMaxWindow, nullptr, nullptr, \
      "HTTP/2 flow-control window (RFC 9113: 2^31-1)") \
    X(grpc_max_streams, kFixedAtAlloc, "streams", ::bolt::api::proto::grpc::kMaxStreamsCap, ::bolt::api::proto::grpc::kMaxStreamsCap, ::bolt::api::proto::grpc::kMaxStreamsCap, nullptr, nullptr, \
      "gRPC stream slots per connection") \
    X(grpc_header_block, kFixedAtAlloc, "bytes", ::bolt::api::proto::grpc::kHeaderBlockCap, ::bolt::api::proto::grpc::kHeaderBlockCap, ::bolt::api::proto::grpc::kHeaderBlockCap, nullptr, nullptr, \
      "gRPC HEADERS+CONTINUATION buffer per connection") \
    X(grpc_auth_bytes, kFixedAtAlloc, "bytes", ::bolt::api::proto::grpc::kAuthCap, ::bolt::api::proto::grpc::kAuthCap, ::bolt::api::proto::grpc::kAuthCap, nullptr, nullptr, \
      "authorization header bytes kept per gRPC stream") \
    X(grpc_path_bytes, kFixedAtAlloc, "bytes", ::bolt::api::proto::grpc::kPathCap, ::bolt::api::proto::grpc::kPathCap, ::bolt::api::proto::grpc::kPathCap, nullptr, nullptr, \
      ":path bytes kept per gRPC stream") \
    X(grpc_agent_bytes, kFixedAtAlloc, "bytes", ::bolt::api::proto::grpc::kAgentCap, ::bolt::api::proto::grpc::kAgentCap, ::bolt::api::proto::grpc::kAgentCap, nullptr, nullptr, \
      "user-agent bytes kept per gRPC stream") \
    X(grpc_frames_per_wait, kBudget, "frames", ::bolt::api::proto::grpc::kMaxFramesPerWait, 1, 0x7FFFFFFF, "BOLTAPI_GRPC_FRAMES_PER_WAIT", nullptr, \
      "frames read while a gRPC stream waits for send window") \
    X(grpc_tls_retries, kBudget, "retries", ::bolt::api::proto::grpc::kMaxTlsRetries, 1, 0x7FFFFFFF, "BOLTAPI_GRPC_TLS_RETRIES", nullptr, \
      "TLS WANT_READ/WRITE retries per gRPC IO") \
    X(grpc_poll_frames, kBudget, "frames", ::bolt::api::proto::grpc::kMaxPollFrames, 1, 0x7FFFFFFF, "BOLTAPI_GRPC_POLL_FRAMES", nullptr, \
      "frames handled per gRPC connection poll") \
    X(pgwire_max_fields, kInvariant, "columns",                                 \
      ::bolt::api::proto::pgwire::kMaxFields,                                   \
      ::bolt::api::proto::pgwire::kMaxFields,                                   \
      ::bolt::api::proto::pgwire::kMaxFields, nullptr, nullptr,                 \
      "columns in one Postgres RowDescription")                                 \
    X(bolt_max_offset_seconds, kInvariant, "seconds",                           \
      ::bolt::api::kBoltMaxOffsetSeconds, ::bolt::api::kBoltMaxOffsetSeconds,   \
      ::bolt::api::kBoltMaxOffsetSeconds, nullptr, nullptr,                     \
      "Neo4j Bolt time zone offset magnitude (spec: +-18:00)")                  \
    X(bolt_max_zone_id, kInvariant, "bytes", ::bolt::api::kBoltMaxZoneIdBytes,  \
      ::bolt::api::kBoltMaxZoneIdBytes, ::bolt::api::kBoltMaxZoneIdBytes,       \
      nullptr, nullptr, "Neo4j Bolt DateTime zone id; longer is refused")       \
    X(bolt_max_path_hops, kInvariant, "hops", ::bolt::api::kBoltMaxPathHops,    \
      ::bolt::api::kBoltMaxPathHops, ::bolt::api::kBoltMaxPathHops, nullptr,    \
      nullptr, "hops in one Neo4j Bolt Path value; longer is refused")          \
    X(bolt_tls_write_retries, kInvariant, "retries", ::bolt::api::kBoltTlsWriteRetries, \
      ::bolt::api::kBoltTlsWriteRetries, ::bolt::api::kBoltTlsWriteRetries, nullptr, \
      nullptr, "SSL_write retries on one Neo4j Bolt TLS write")                 \
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
    X(quic_handshake_speedups, kInvariant, "resends",                          \
      ::bolt::api::quic::kMaxHandshakeSpeedups,                                 \
      ::bolt::api::quic::kMaxHandshakeSpeedups,                                 \
      ::bolt::api::quic::kMaxHandshakeSpeedups, nullptr, nullptr,               \
      "early handshake-flight resends per QUIC connection")                     \
    X(quic_pending_send_bytes, kInvariant, "bytes",                             \
      ::bolt::api::quic::kPendingSendBytesMax,                                  \
      ::bolt::api::quic::kPendingSendBytesMax,                                  \
      ::bolt::api::quic::kPendingSendBytesMax, nullptr, nullptr,                \
      "response bytes held per QUIC connection awaiting stream space")

namespace bolt::api {

BOLT_LIMITS_TABLE(boltapi_limits, "boltapi", BOLTAPI_LIMITS)

}  // namespace bolt::api
