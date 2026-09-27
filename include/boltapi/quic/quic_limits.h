// boltapi/quic/quic_limits.h — QUIC connection caps (limits kind A).
// Registered in boltapi_limits.h.

#pragma once

#include <cstddef>
#include <cstdint>

namespace bolt::api::quic {

// Concurrent peer-initiated bidi streams granted (MAX_STREAMS credit tracks
// closures): the default, and the ceiling an ALPN may raise it to
// (hq-interop). Both fit the stream pool beside the uni streams.
inline constexpr std::uint64_t kPeerBidiStreamsDefault = 8;
inline constexpr std::uint64_t kPeerBidiStreamsMax = 48;
// Concurrent peer-initiated uni streams (HTTP/3 control + QPACK enc/dec).
inline constexpr std::uint64_t kPeerUniStreamsMax = 3;
// Closed-stream memory window per direction: MAX_STREAMS never grants a stream
// id this far past the lowest still-open one.
inline constexpr std::uint64_t kClosedStreamWindowMax = 1024;
// Bytes a connection may hold for the application beyond the stream rings
// (large response bodies waiting for acknowledgements).
inline constexpr std::uint64_t kPendingSendBytesMax = 1ull << 30;

}  // namespace bolt::api::quic
