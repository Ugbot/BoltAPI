// boltapi/quic/quic_limits.h — QUIC connection caps (limits kind A).
// Registered in boltapi_limits.h.

#pragma once

#include <cstddef>
#include <cstdint>

namespace bolt::api::quic {

// Concurrent peer-initiated bidi streams granted (MAX_STREAMS credit tracks
// closures): the default (RFC 9114 §6.1: servers SHOULD allow at least 100,
// the http3_max_streams knob), and the ceiling a host or ALPN may set. Both
// fit the stream pool beside the uni streams; a stream's rings are allocated
// on first use, so the pool costs its slot metadata only.
inline constexpr std::uint64_t kPeerBidiStreamsDefault = 100;
inline constexpr std::uint64_t kPeerBidiStreamsMax = 128;
// Concurrent peer-initiated uni streams (HTTP/3 control + QPACK enc/dec).
inline constexpr std::uint64_t kPeerUniStreamsMax = 3;
// Closed-stream memory window per direction: MAX_STREAMS never grants a stream
// id this far past the lowest still-open one.
inline constexpr std::uint64_t kClosedStreamWindowMax = 1024;
// Bytes a connection may hold for the application beyond the stream rings
// (large response bodies waiting for acknowledgements).
inline constexpr std::uint64_t kPendingSendBytesMax = 1ull << 30;

// Early handshake-flight resends (RFC 9002 §6.2.3) per connection.
inline constexpr std::size_t kMaxHandshakeSpeedups = 8;

}  // namespace bolt::api::quic
