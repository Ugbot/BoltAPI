// boltapi/wire_limits.h — wire-format caps fixed by an RFC or by the parser's
// shape (limits kind A). Registered in boltapi_limits.h.

#pragma once

#include <cstddef>
#include <cstdint>

namespace bolt::api {

inline constexpr std::size_t kWsMaxControlPayload = 125;     // RFC 6455 §5.5
inline constexpr std::size_t kWsMaxFrameHeader = 14;         // 2 + 8 + 4
inline constexpr std::uint64_t kQpackMaxIntValue = (1ull << 62) - 1;  // QUIC varint
inline constexpr std::size_t kHttp3MaxMethodLen = 16;        // longest method we route
inline constexpr std::size_t kHqMaxRequestLine = 4096;       // "GET /path\r\n" (hq-interop)
inline constexpr std::int64_t kBoltMaxOffsetSeconds = 18 * 3600;  // Bolt time zone offset, +-18:00
inline constexpr std::uint32_t kBoltMaxZoneIdBytes = 64;     // longest IANA zone id sent
inline constexpr std::uint32_t kBoltMaxPathHops = 1u << 16;  // Path indices / 2

}  // namespace bolt::api
