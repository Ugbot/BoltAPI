// boltapi/auth/smtp_client.h — synchronous SMTP / SMTPS / STARTTLS sender.
//
// Sibling of bolt::api::http::TlsClient (sync OpenSSL). The same constraints
// apply: low-rate outbound (one email at a time), bounded I/O timeouts, no
// allocations after Message construction past OpenSSL's own.
//
// Two implementations of the same `Mailer` interface:
//   * SmtpClient   — STARTTLS or implicit-TLS (port 465) over OpenSSL.
//                    AUTH PLAIN only (the 80% — Mailgun/Postmark/SES).
//   * LogOnlyMailer — writes the email to stderr; default in dev.
//
// The caller picks one and stores it as `Mailer*` on its handlers. Tests
// inject a `CapturingMailer` that records sent messages in a vector.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace bolt::api::auth::smtp {

inline constexpr int kDefaultTimeoutMs = 15 * 1000;  // 15 s end-to-end

struct Message {
    std::string from;          // "sender@example.com"
    std::string from_name;     // optional display name (RFC 5322 §3.6.2)
    std::string to;            // "recipient@example.com" (single recipient only)
    std::string subject;
    std::string body_text;     // text/plain; UTF-8
    // Caller-supplied unique id for the email (optional; used as Message-ID).
    std::string message_id;
};

struct Result {
    bool        ok = false;
    int         smtp_status = 0;    // 250 on success; 0 on transport error
    std::string error;              // empty on success
};

class Mailer {
public:
    virtual ~Mailer() noexcept = default;
    virtual Result send(const Message& m) noexcept = 0;
};

// ---------------------------------------------------------------------------
// LogOnlyMailer — prints the message to a chosen FILE* (default stderr).
// Always succeeds; the default in dev when SMTP is not configured.
class LogOnlyMailer final : public Mailer {
public:
    LogOnlyMailer() noexcept;
    explicit LogOnlyMailer(void* file_ptr) noexcept;  // FILE*; opaque to avoid <cstdio>
    Result send(const Message& m) noexcept override;
private:
    void* fp_;
};

// ---------------------------------------------------------------------------
// CapturingMailer — collects messages in-memory; for unit tests.
class CapturingMailer final : public Mailer {
public:
    Result send(const Message& m) noexcept override;
    std::vector<Message> sent;
};

// ---------------------------------------------------------------------------
// SmtpClient — real outbound via OpenSSL. Supports:
//   * Implicit TLS (port 465)        — `implicit_tls = true`
//   * STARTTLS upgrade (port 587/25) — `implicit_tls = false, use_starttls = true`
//   * Cleartext (LAN relay)          — `implicit_tls = false, use_starttls = false`
// AUTH PLAIN only.
struct SmtpConfig {
    std::string host;
    uint16_t    port             = 587;
    bool        implicit_tls     = false;
    bool        use_starttls     = true;
    std::string username;          // empty -> no AUTH
    std::string password;
    std::string ehlo_domain      = "localhost";
    bool        insecure_skip_verify = false;
    int         timeout_ms       = kDefaultTimeoutMs;
};

class SmtpClient final : public Mailer {
public:
    explicit SmtpClient(SmtpConfig cfg) noexcept;
    ~SmtpClient() noexcept;
    SmtpClient(const SmtpClient&)            = delete;
    SmtpClient& operator=(const SmtpClient&) = delete;
    Result send(const Message& m) noexcept override;
private:
    SmtpConfig cfg_;
};

// Helpers exposed for tests --------------------------------------------------

// Build the RFC 5322 message body (headers + "\r\n" + body). Returns the
// composed string. Pure; no I/O.
std::string compose_rfc5322(const Message& m) noexcept;

// AUTH PLAIN initial-response token: base64("\0" username "\0" password).
std::string build_auth_plain(std::string_view user, std::string_view pw) noexcept;

// Bare-bones email-address syntax check (local@domain, no whitespace).
// Not a full RFC 5322 validator; deliberately strict so bad inputs reject early.
bool is_plausible_email(std::string_view addr) noexcept;

}  // namespace bolt::api::auth::smtp
