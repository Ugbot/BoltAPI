// boltapi/auth/password_policy.h — pure password-strength validator.
//
// Exception-free, allocation-free. No I/O. The validator is config-driven
// so different services can pick their own floor without forking the code.
//
// The optional HaveIBeenPwned check is delegated to a caller-supplied
// callback so this primitive stays free of an HTTP-client dep. The
// callback receives the SHA-1 of the password as 40 uppercase hex chars
// (the format HIBP wants for k-anonymity range queries) and returns
// `true` if the prefix's range contains the suffix (i.e. the password is
// known-breached).
#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace bolt::api::auth::password_policy {

struct Config {
    uint32_t min_len           = 12;
    uint32_t max_len           = 256;
    bool     require_upper     = true;
    bool     require_lower     = true;
    bool     require_digit     = true;
    bool     require_symbol    = false;
    bool     forbid_whitespace = true;
};

struct Result {
    bool             ok = false;
    // Short stable reason: "ok" | "too_short" | "too_long" |
    // "missing_upper" | "missing_lower" | "missing_digit" |
    // "missing_symbol" | "has_whitespace" | "pwned".
    std::string_view reason = "ok";
};

// Pure validator. No allocations.
Result evaluate(std::string_view pw, const Config& cfg) noexcept;

// Optional HIBP check. Caller supplies a callback that does the HTTP fetch
// (boltapi has http::TlsClient). The callback is given the upper-hex sha1
// of the password and returns true if it is breached.
//
// Returns Result{ok=false, reason="pwned"} if the callback says yes;
// otherwise returns evaluate(pw, cfg).
using PwnedChecker = bool (*)(const char sha1_hex_upper[40], void* user) noexcept;

Result evaluate_with_pwned_check(std::string_view pw, const Config& cfg,
                                 PwnedChecker checker, void* user) noexcept;

// Compute the upper-hex SHA-1 of the password (writes 40 chars, no NUL).
// Exposed so callers building their own HIBP integrations don't have to
// duplicate it.
void sha1_upper_hex(std::string_view pw, char out[40]) noexcept;

}  // namespace bolt::api::auth::password_policy
