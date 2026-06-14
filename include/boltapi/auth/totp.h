// boltapi/auth/totp.h — RFC 6238 TOTP + recovery codes.
//
// Pure-crypto, exception-free, bounded. The reusable foundation that any
// boltapi-hosted service can wire up for two-factor authentication.
//
// Surface:
//   - generate_secret(out[20]) -> bool         random 160-bit secret (HMAC-SHA1 key)
//   - base32_encode(secret, out)               for QR provisioning URI
//   - base32_decode(s, out)                    inverse; also accepts no-padding form
//   - hotp_code(secret, counter)               RFC 4226 HMAC-based one-time password
//   - totp_code_at(secret, unix_time, period)  RFC 6238 (period defaults to 30s)
//   - totp_verify(secret, code, now, window)   ±window steps tolerance (default ±1)
//   - provisioning_uri(out, issuer, account, secret)
//                                              otpauth://totp/<issuer>:<account>?secret=…&issuer=…
//   - mint_recovery_codes(out[N])              N 8-char base32 codes; raw shown once
//   - hash_recovery_code(code) -> 32B          sha256(raw) — stored, never plaintext
//
// All buffers are caller-owned and fixed-size. No allocations on the hot path.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace bolt::api::auth::totp {

inline constexpr size_t kSecretBytes        = 20;   // 160-bit HMAC-SHA1 key
inline constexpr size_t kBase32SecretChars  = 32;   // ceil(20*8/5)
inline constexpr size_t kDefaultDigits      = 6;
inline constexpr uint32_t kDefaultPeriodSec = 30;
inline constexpr int32_t  kDefaultWindow    = 1;    // ±1 step (±30s)
inline constexpr size_t kRecoveryCodeChars  = 8;    // user-visible length
inline constexpr size_t kRecoveryCodeCount  = 10;
inline constexpr size_t kHashBytes          = 32;   // sha256

// Fill `out` with 20 cryptographically-random bytes. Returns false on
// OpenSSL RAND failure (rare; caller should surface to user).
bool generate_secret(uint8_t out[kSecretBytes]) noexcept;

// Base32 (RFC 4648) encode `n` bytes into `out`. `out` must be ≥ ceil(n*8/5)+1.
// Writes no padding (= chars omitted). Returns chars written (excl. NUL).
size_t base32_encode(const uint8_t* in, size_t n, char* out, size_t out_cap) noexcept;

// Base32 decode. Accepts upper/lowercase, ignores '=' padding and spaces.
// Returns bytes written, or 0 on invalid input.
size_t base32_decode(std::string_view in, uint8_t* out, size_t out_cap) noexcept;

// RFC 4226 HOTP. `digits` ∈ [6, 9]; returns the truncated decimal code.
uint32_t hotp_code(const uint8_t* secret, size_t secret_len,
                   uint64_t counter, uint32_t digits = kDefaultDigits) noexcept;

// RFC 6238 TOTP at the given unix time. `period_sec` default 30.
uint32_t totp_code_at(const uint8_t* secret, size_t secret_len,
                      uint64_t unix_time,
                      uint32_t period_sec = kDefaultPeriodSec,
                      uint32_t digits     = kDefaultDigits) noexcept;

// Verify `code` against `secret` with ±`window` steps tolerance.
// Constant-time compare; returns false on any decode/compute failure.
bool totp_verify(const uint8_t* secret, size_t secret_len,
                 uint32_t code, uint64_t now_unix,
                 int32_t  window     = kDefaultWindow,
                 uint32_t period_sec = kDefaultPeriodSec,
                 uint32_t digits     = kDefaultDigits) noexcept;

// Build an otpauth://totp/... provisioning URI for QR-code apps. Caller-owned
// `out` is ≤ 320 bytes is enough for typical issuer/account lengths.
// Returns chars written, 0 on overflow.
size_t provisioning_uri(char* out, size_t out_cap,
                        std::string_view issuer,
                        std::string_view account,
                        const uint8_t* secret, size_t secret_len,
                        uint32_t digits     = kDefaultDigits,
                        uint32_t period_sec = kDefaultPeriodSec) noexcept;

// Recovery codes: human-friendly base32, no ambiguous chars (no 0/1/O/I).
// Each call mints `count` codes into `out`, each `kRecoveryCodeChars` chars +
// NUL. Returns true on success.
bool mint_recovery_codes(char (*out)[kRecoveryCodeChars + 1], size_t count) noexcept;

// SHA-256 of the raw recovery-code string. Use this to STORE; compare against
// hash(user_input) at verify time. Constant-time compare is the caller's job
// (or use the equal-hashes helper below).
void hash_recovery_code(std::string_view raw, uint8_t out[kHashBytes]) noexcept;

// Constant-time hash equality. Returns true iff both buffers match.
bool ct_equal(const uint8_t* a, const uint8_t* b, size_t n) noexcept;

}  // namespace bolt::api::auth::totp
