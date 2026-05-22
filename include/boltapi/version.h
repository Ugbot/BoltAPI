// boltapi/version.h — library version surface.
#pragma once

#include <cstdint>

namespace bolt::api {

inline constexpr int version_major = 0;
inline constexpr int version_minor = 1;
inline constexpr int version_patch = 0;

/// Returns the Bolt API version as a "MAJOR.MINOR.PATCH" string literal.
const char* version() noexcept;

/// Smoke check that the Bolt submodule is wired in and usable.
/// Allocates from a bolt::Arena and exercises a bolt primitive; returns true
/// on success. Used by the M0 build/link verification.
bool bolt_integration_ok() noexcept;

}  // namespace bolt::api
