#pragma once
#include <cstddef>
#include <cstdint>

namespace bolt::api {
// Kind B: startup pool shape, independent of object length. Large sink writes
// are split across the one-slot handoff, so this never caps response bytes.
inline constexpr std::size_t kFixedStreamSliceBytes = 64u * 1024u;
inline constexpr std::size_t kFixedStreamMaxSlots = 1024;
// TLS H1/H2 fixed responses currently materialize before publishing headers.
inline constexpr std::size_t kDefaultFixedMaterializationBytes = 16u * 1024u * 1024u;
inline constexpr std::uint64_t kMaxFixedResponseBytes = 1ull << 40;
}  // namespace bolt::api
