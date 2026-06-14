// boltapi/auth/signed_token.h — HMAC-SHA256 single-use, time-limited token.
//
// Used by password-reset, email-verify, user-invite flows. The token format
// is base64url(purpose) "." base64url(payload) "." dec(exp) "." base64url(mac)
// where mac = HMAC-SHA256(secret, purpose "." payload "." exp).
//
// `purpose_tag` prevents cross-flow replay (a reset token can't be used as
// an invite token). `payload` is opaque to the primitive — the caller puts
// in whatever it needs to look up the row (typically: user_id or an
// invite row hash).
//
// All fields fit in a fixed-cap buffer (default 256 bytes for the encoded
// token). No allocations past the small caller-owned scratch.
#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace bolt::api::auth::signed_token {

inline constexpr size_t kSecretMin    = 16;   // 128-bit floor
inline constexpr size_t kPurposeMax   = 16;
inline constexpr size_t kPayloadMax   = 96;
inline constexpr size_t kEncodedMax   = 320;  // safe upper bound

struct Parsed {
    bool                ok      = false;
    std::string_view    purpose;
    std::string_view    payload;     // base64url-decoded into the caller's scratch
    uint64_t            exp_unix = 0;
    // On failure, `reason` is a short stable string for logging/metrics:
    //   "malformed", "purpose_mismatch", "expired", "bad_signature".
    std::string_view    reason;
};

// Mint a token. Caller-owned `out` MUST have ≥ kEncodedMax bytes.
// Returns chars written, 0 on overflow / invalid inputs.
size_t mint(const uint8_t* secret, size_t secret_len,
            std::string_view purpose,
            std::string_view payload,
            uint64_t exp_unix,
            char* out, size_t out_cap) noexcept;

// Verify a token. `scratch` (≥ kPayloadMax) receives the decoded payload that
// `parsed.payload` will point into. `now_unix` is checked against `exp`.
// `expected_purpose` must match the token's `purpose` exactly.
//
// Returns Parsed{ok=true} on success, ok=false with `reason` set otherwise.
Parsed verify(const uint8_t* secret, size_t secret_len,
              std::string_view token,
              std::string_view expected_purpose,
              uint64_t now_unix,
              uint8_t* scratch, size_t scratch_cap) noexcept;

// Convenience: SHA-256 of a token string. Used to STORE the token hash so the
// raw token never lives on disk (mirrors the recovery-code hash pattern).
void hash_token(std::string_view token, uint8_t out[32]) noexcept;

}  // namespace bolt::api::auth::signed_token
