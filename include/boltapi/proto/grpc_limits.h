// boltapi/proto/grpc_limits.h — gRPC server (HTTP/2) caps. Registered in
// boltapi_limits.h; the kind of each is noted beside it.

#pragma once

#include <cstddef>
#include <cstdint>

namespace bolt::api::proto::grpc {

// A: RFC 9113 SETTINGS identifiers and frame/window bounds.
inline constexpr std::uint16_t kSettingsMaxConcurrent = 0x3;  // SETTINGS_MAX_CONCURRENT_STREAMS
inline constexpr std::uint16_t kSettingsMaxFrameSize = 0x5;   // SETTINGS_MAX_FRAME_SIZE
inline constexpr std::size_t kOurMaxFrame = 16384;            // initial SETTINGS_MAX_FRAME_SIZE, never raised
inline constexpr std::int64_t kMaxWindow = 0x7FFFFFFF;        // 2^31-1 flow-control window

// B: sized once per connection / stream.
inline constexpr std::uint32_t kMaxStreamsCap = 128;          // stream slots per connection
inline constexpr std::size_t kHeaderBlockCap = 65536;         // HEADERS+CONTINUATION buffer
inline constexpr std::size_t kAuthCap = 4096;                 // authorization header bytes kept
inline constexpr std::size_t kPathCap = 256;                  // :path bytes kept
inline constexpr std::size_t kAgentCap = 256;                 // user-agent bytes kept

// C: defaults of runtime budgets (boltapi_limits(), env-overridable).
inline constexpr int kMaxFramesPerWait = 1 << 20;             // frames read waiting for window
inline constexpr int kMaxTlsRetries = 1024;                   // TLS WANT_READ/WRITE spins per IO
inline constexpr int kMaxPollFrames = 4096;                   // frames handled per poll

}  // namespace bolt::api::proto::grpc
