#pragma once
#include <cstddef>

namespace bolt::api {
// Kind B: startup pool shape, independent of object length. Large sink writes
// are split across the one-slot handoff, so this never caps response bytes.
inline constexpr std::size_t kFixedStreamSliceBytes = 64u * 1024u;
inline constexpr std::size_t kFixedStreamMaxSlots = 1024;
}  // namespace bolt::api
