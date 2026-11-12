// boltapi/http3/h3_limits.h — HTTP/3 request caps. Registered in
// boltapi_limits.h (http3_max_streams); the request body budget is the host's
// max_body_size, the one the HTTP/1.1 and HTTP/2 doors read.

#pragma once

#include <cstddef>
#include <cstdint>

#include "boltapi/quic/quic_limits.h"

namespace bolt::api::http3 {

// Concurrent requests per connection (RFC 9114 §6.1: at least 100). The QUIC
// MAX_STREAMS credit and the H3 request slots are both set from it.
inline constexpr std::uint64_t kH3MaxStreamsDefault = quic::kPeerBidiStreamsDefault;
inline constexpr std::uint64_t kH3MaxStreamsCeiling = quic::kPeerBidiStreamsMax;
// Request (or, client side, response) body bytes when the host sets none:
// CoroUnifiedServerConfig::max_body_size's default.
inline constexpr std::size_t kH3MaxBodyBytesDefault = 10u * 1024u * 1024u;
// Stream buffer a request slot keeps for its next request; larger is freed.
inline constexpr std::size_t kH3RetainBytes = 16u * 1024u;

static_assert(kH3MaxStreamsDefault <= kH3MaxStreamsCeiling, "h3 stream default past ceiling");

}  // namespace bolt::api::http3
