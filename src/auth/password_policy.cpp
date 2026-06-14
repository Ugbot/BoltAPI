// boltapi/auth/password_policy.cpp — pure validator.

#include "boltapi/auth/password_policy.h"

#include <cassert>

#include <openssl/sha.h>

namespace bolt::api::auth::password_policy {

namespace {
bool is_upper(char c)  noexcept { return c >= 'A' && c <= 'Z'; }
bool is_lower(char c)  noexcept { return c >= 'a' && c <= 'z'; }
bool is_digit(char c)  noexcept { return c >= '0' && c <= '9'; }
bool is_space(char c)  noexcept { return c == ' ' || c == '\t' || c == '\n' || c == '\r'; }
bool is_symbol(char c) noexcept {
    return (c >= 33 && c <= 126) && !is_upper(c) && !is_lower(c) && !is_digit(c);
}
}  // namespace

Result evaluate(std::string_view pw, const Config& cfg) noexcept {
    Result r;
    if (pw.size() < cfg.min_len) { r.reason = "too_short"; return r; }
    if (pw.size() > cfg.max_len) { r.reason = "too_long";  return r; }

    bool has_upper = false, has_lower = false, has_digit = false, has_symbol = false;
    for (char c : pw) {
        if (cfg.forbid_whitespace && is_space(c)) { r.reason = "has_whitespace"; return r; }
        if (is_upper(c))  has_upper  = true;
        if (is_lower(c))  has_lower  = true;
        if (is_digit(c))  has_digit  = true;
        if (is_symbol(c)) has_symbol = true;
    }
    if (cfg.require_upper  && !has_upper)  { r.reason = "missing_upper";  return r; }
    if (cfg.require_lower  && !has_lower)  { r.reason = "missing_lower";  return r; }
    if (cfg.require_digit  && !has_digit)  { r.reason = "missing_digit";  return r; }
    if (cfg.require_symbol && !has_symbol) { r.reason = "missing_symbol"; return r; }

    r.ok = true;
    return r;
}

void sha1_upper_hex(std::string_view pw, char out[40]) noexcept {
    assert(out != nullptr);
    uint8_t h[20];
    SHA1(reinterpret_cast<const uint8_t*>(pw.data()), pw.size(), h);
    static constexpr char kHex[] = "0123456789ABCDEF";
    for (int i = 0; i < 20; ++i) {
        out[i * 2    ] = kHex[(h[i] >> 4) & 0xF];
        out[i * 2 + 1] = kHex[ h[i]       & 0xF];
    }
}

Result evaluate_with_pwned_check(std::string_view pw, const Config& cfg,
                                 PwnedChecker checker, void* user) noexcept {
    Result r = evaluate(pw, cfg);
    if (!r.ok) return r;
    if (checker != nullptr) {
        char hex[40];
        sha1_upper_hex(pw, hex);
        if (checker(hex, user)) { r.ok = false; r.reason = "pwned"; }
    }
    return r;
}

}  // namespace bolt::api::auth::password_policy
