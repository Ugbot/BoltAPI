// boltapi/auth/smtp_client.cpp — sync SMTP/STARTTLS sender + helpers.
//
// Conversation:
//   S: 220 service ready
//   C: EHLO ehlo_domain
//   S: 250-...
//   [STARTTLS]
//     C: STARTTLS
//     S: 220 go ahead
//     [upgrade socket via SSL_connect]
//     C: EHLO ehlo_domain
//     S: 250-AUTH PLAIN...
//   [AUTH]
//     C: AUTH PLAIN <base64(\0user\0pass)>
//     S: 235 auth ok
//   C: MAIL FROM:<from>
//   S: 250 ok
//   C: RCPT TO:<to>
//   S: 250 ok
//   C: DATA
//   S: 354 go ahead
//   C: <rfc5322 message>\r\n.\r\n
//   S: 250 message accepted
//   C: QUIT
//   S: 221 bye

#include "boltapi/auth/smtp_client.h"

#include <cassert>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  using socket_t = SOCKET;
  static constexpr socket_t kInvalid = INVALID_SOCKET;
  static int close_sock(socket_t s) { return ::closesocket(s); }
#else
  #include <netdb.h>
  #include <sys/socket.h>
  #include <sys/types.h>
  #include <unistd.h>
  using socket_t = int;
  static constexpr socket_t kInvalid = -1;
  static int close_sock(socket_t s) { return ::close(s); }
#endif

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

namespace bolt::api::auth::smtp {

// ---------------- helpers ---------------------------------------------------

bool is_plausible_email(std::string_view a) noexcept {
    if (a.empty() || a.size() > 254) return false;
    size_t at = a.find('@');
    if (at == std::string_view::npos || at == 0 || at == a.size() - 1) return false;
    for (char c : a) {
        if (c <= ' ' || c >= 127) return false;
        if (c == ',' || c == ';' || c == '<' || c == '>') return false;
    }
    if (a.find('@', at + 1) != std::string_view::npos) return false;
    return true;
}

namespace {

constexpr char kB64Alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string b64_encode(const uint8_t* in, size_t n) {
    std::string out;
    out.reserve(((n + 2) / 3) * 4);
    size_t i = 0;
    while (i + 3 <= n) {
        const uint32_t v = (uint32_t(in[i]) << 16) | (uint32_t(in[i + 1]) << 8) | in[i + 2];
        out.push_back(kB64Alphabet[(v >> 18) & 63]);
        out.push_back(kB64Alphabet[(v >> 12) & 63]);
        out.push_back(kB64Alphabet[(v >>  6) & 63]);
        out.push_back(kB64Alphabet[ v        & 63]);
        i += 3;
    }
    if (i < n) {
        const size_t rem = n - i;
        uint32_t v = uint32_t(in[i]) << 16;
        if (rem > 1) v |= uint32_t(in[i + 1]) << 8;
        out.push_back(kB64Alphabet[(v >> 18) & 63]);
        out.push_back(kB64Alphabet[(v >> 12) & 63]);
        out.push_back(rem > 1 ? kB64Alphabet[(v >> 6) & 63] : '=');
        out.push_back('=');
    }
    return out;
}

}  // namespace

std::string build_auth_plain(std::string_view user, std::string_view pw) noexcept {
    std::string raw;
    raw.reserve(user.size() + pw.size() + 2);
    raw.push_back('\0');
    raw.append(user.data(), user.size());
    raw.push_back('\0');
    raw.append(pw.data(), pw.size());
    return b64_encode(reinterpret_cast<const uint8_t*>(raw.data()), raw.size());
}

std::string compose_rfc5322(const Message& m) noexcept {
    std::string out;
    out.reserve(256 + m.body_text.size());
    if (!m.from_name.empty()) {
        out.append("From: \"");
        out.append(m.from_name);
        out.append("\" <");
        out.append(m.from);
        out.append(">\r\n");
    } else {
        out.append("From: <"); out.append(m.from); out.append(">\r\n");
    }
    out.append("To: <"); out.append(m.to); out.append(">\r\n");
    out.append("Subject: "); out.append(m.subject); out.append("\r\n");
    out.append("MIME-Version: 1.0\r\n");
    out.append("Content-Type: text/plain; charset=UTF-8\r\n");
    if (!m.message_id.empty()) {
        out.append("Message-ID: <"); out.append(m.message_id); out.append(">\r\n");
    }
    out.append("\r\n");
    // Dot-stuff: any line that starts with '.' must be doubled (RFC 5321 §4.5.2).
    size_t pos = 0;
    while (pos < m.body_text.size()) {
        const size_t eol = m.body_text.find('\n', pos);
        const std::string_view line = (eol == std::string::npos)
            ? std::string_view{m.body_text.data() + pos, m.body_text.size() - pos}
            : std::string_view{m.body_text.data() + pos, eol - pos};
        if (!line.empty() && line.front() == '.') out.push_back('.');
        out.append(line.data(), line.size());
        out.append("\r\n");
        if (eol == std::string::npos) break;
        pos = eol + 1;
    }
    return out;
}

// ---------------- LogOnlyMailer --------------------------------------------

LogOnlyMailer::LogOnlyMailer() noexcept : fp_(stderr) {}
LogOnlyMailer::LogOnlyMailer(void* file_ptr) noexcept : fp_(file_ptr ? file_ptr : stderr) {}

Result LogOnlyMailer::send(const Message& m) noexcept {
    auto* fp = static_cast<std::FILE*>(fp_);
    std::fprintf(fp,
        "\n=== LogOnlyMailer ===\nFrom: %s\nTo: %s\nSubject: %s\n\n%s\n=====================\n",
        m.from.c_str(), m.to.c_str(), m.subject.c_str(), m.body_text.c_str());
    std::fflush(fp);
    return Result{true, 250, {}};
}

// ---------------- CapturingMailer ------------------------------------------

Result CapturingMailer::send(const Message& m) noexcept {
    sent.push_back(m);
    return Result{true, 250, {}};
}

// ---------------- SmtpClient (real) ----------------------------------------

namespace {

struct Wire {
    socket_t fd  = kInvalid;
    SSL*     ssl = nullptr;
    SSL_CTX* ctx = nullptr;
};

void close_wire(Wire& w) noexcept {
    if (w.ssl) { SSL_shutdown(w.ssl); SSL_free(w.ssl); w.ssl = nullptr; }
    if (w.fd  != kInvalid) { close_sock(w.fd); w.fd = kInvalid; }
    if (w.ctx) { SSL_CTX_free(w.ctx); w.ctx = nullptr; }
}

long long wire_write(Wire& w, const char* buf, size_t n) noexcept {
    if (w.ssl) return SSL_write(w.ssl, buf, int(n));
    return ::send(w.fd, buf, int(n), 0);
}

long long wire_read(Wire& w, char* buf, size_t cap) noexcept {
    if (w.ssl) return SSL_read(w.ssl, buf, int(cap));
    return ::recv(w.fd, buf, int(cap), 0);
}

bool send_line(Wire& w, const std::string& line) noexcept {
    return wire_write(w, line.data(), line.size()) == long long(line.size());
}

int read_reply(Wire& w, std::string* msg) noexcept {
    // SMTP reply: lines starting with NNN-... continue; NNN<space> ends.
    char buf[1024];
    msg->clear();
    int code = 0;
    for (;;) {
        const long long n = wire_read(w, buf, sizeof(buf));
        if (n <= 0) return 0;
        msg->append(buf, size_t(n));
        // Look for terminator: a line "NNN<space>..."
        size_t pos = 0;
        while (pos < msg->size()) {
            const size_t eol = msg->find('\n', pos);
            if (eol == std::string::npos) break;
            if (eol >= pos + 4) {
                const char* p = msg->data() + pos;
                if (p[0] >= '0' && p[0] <= '9' &&
                    p[1] >= '0' && p[1] <= '9' &&
                    p[2] >= '0' && p[2] <= '9' &&
                    p[3] == ' ') {
                    code = (p[0] - '0') * 100 + (p[1] - '0') * 10 + (p[2] - '0');
                    return code;
                }
            }
            pos = eol + 1;
        }
    }
}

socket_t dial_tcp(const char* host, uint16_t port, int /*timeout_ms*/) noexcept {
#ifdef _WIN32
    static bool wsa_inited = false;
    if (!wsa_inited) { WSADATA d; WSAStartup(MAKEWORD(2, 2), &d); wsa_inited = true; }
#endif
    addrinfo hints{}; hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
    char portbuf[8]; std::snprintf(portbuf, sizeof(portbuf), "%u", port);
    addrinfo* res = nullptr;
    if (getaddrinfo(host, portbuf, &hints, &res) != 0 || res == nullptr) return kInvalid;
    socket_t s = kInvalid;
    for (addrinfo* p = res; p != nullptr; p = p->ai_next) {
        s = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (s == kInvalid) continue;
        if (::connect(s, p->ai_addr, int(p->ai_addrlen)) == 0) break;
        close_sock(s); s = kInvalid;
    }
    freeaddrinfo(res);
    return s;
}

bool ssl_upgrade(Wire& w, const char* host, bool skip_verify) noexcept {
    w.ctx = SSL_CTX_new(TLS_client_method());
    if (w.ctx == nullptr) return false;
    if (!skip_verify) {
        SSL_CTX_set_default_verify_paths(w.ctx);
        SSL_CTX_set_verify(w.ctx, SSL_VERIFY_PEER, nullptr);
    } else {
        SSL_CTX_set_verify(w.ctx, SSL_VERIFY_NONE, nullptr);
    }
    w.ssl = SSL_new(w.ctx);
    if (w.ssl == nullptr) return false;
    SSL_set_tlsext_host_name(w.ssl, host);
    if (!skip_verify) {
        X509_VERIFY_PARAM* p = SSL_get0_param(w.ssl);
        X509_VERIFY_PARAM_set_hostflags(p, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
        X509_VERIFY_PARAM_set1_host(p, host, 0);
    }
    SSL_set_fd(w.ssl, int(w.fd));
    return SSL_connect(w.ssl) == 1;
}

}  // namespace

SmtpClient::SmtpClient(SmtpConfig cfg) noexcept : cfg_(std::move(cfg)) {}
SmtpClient::~SmtpClient() noexcept = default;

Result SmtpClient::send(const Message& m) noexcept {
    Result r{};
    if (!is_plausible_email(m.from) || !is_plausible_email(m.to)) {
        r.error = "invalid address"; return r;
    }
    if (cfg_.host.empty()) { r.error = "smtp host not set"; return r; }

    Wire w;
    w.fd = dial_tcp(cfg_.host.c_str(), cfg_.port, cfg_.timeout_ms);
    if (w.fd == kInvalid) { r.error = "connect failed"; return r; }

    if (cfg_.implicit_tls) {
        if (!ssl_upgrade(w, cfg_.host.c_str(), cfg_.insecure_skip_verify)) {
            r.error = "tls handshake failed"; close_wire(w); return r;
        }
    }

    std::string buf;
    int code = read_reply(w, &buf);
    if (code != 220) { r.error = "no banner"; r.smtp_status = code; close_wire(w); return r; }

    // EHLO
    code = read_reply(w, &buf);  // discard EHLO response after sending
    (void)code;
    {
        std::string ehlo = "EHLO " + cfg_.ehlo_domain + "\r\n";
        if (!send_line(w, ehlo)) { r.error = "ehlo write"; close_wire(w); return r; }
        code = read_reply(w, &buf);
        if (code != 250) { r.error = "ehlo refused"; r.smtp_status = code; close_wire(w); return r; }
    }

    if (cfg_.use_starttls && !cfg_.implicit_tls) {
        if (!send_line(w, "STARTTLS\r\n")) { r.error = "starttls write"; close_wire(w); return r; }
        code = read_reply(w, &buf);
        if (code != 220) { r.error = "starttls refused"; r.smtp_status = code; close_wire(w); return r; }
        if (!ssl_upgrade(w, cfg_.host.c_str(), cfg_.insecure_skip_verify)) {
            r.error = "tls handshake failed"; close_wire(w); return r;
        }
        // Re-EHLO post-upgrade (RFC 3207 §4.2).
        std::string ehlo2 = "EHLO " + cfg_.ehlo_domain + "\r\n";
        if (!send_line(w, ehlo2)) { r.error = "ehlo2 write"; close_wire(w); return r; }
        code = read_reply(w, &buf);
        if (code != 250) { r.error = "ehlo2 refused"; r.smtp_status = code; close_wire(w); return r; }
    }

    if (!cfg_.username.empty()) {
        std::string auth = "AUTH PLAIN " + build_auth_plain(cfg_.username, cfg_.password) + "\r\n";
        if (!send_line(w, auth)) { r.error = "auth write"; close_wire(w); return r; }
        code = read_reply(w, &buf);
        if (code != 235) { r.error = "auth failed"; r.smtp_status = code; close_wire(w); return r; }
    }

    std::string mf = "MAIL FROM:<" + m.from + ">\r\n";
    if (!send_line(w, mf)) { r.error = "mail from write"; close_wire(w); return r; }
    code = read_reply(w, &buf);
    if (code != 250) { r.error = "mail from refused"; r.smtp_status = code; close_wire(w); return r; }

    std::string rt = "RCPT TO:<" + m.to + ">\r\n";
    if (!send_line(w, rt)) { r.error = "rcpt to write"; close_wire(w); return r; }
    code = read_reply(w, &buf);
    if (code != 250 && code != 251) { r.error = "rcpt refused"; r.smtp_status = code; close_wire(w); return r; }

    if (!send_line(w, "DATA\r\n")) { r.error = "data write"; close_wire(w); return r; }
    code = read_reply(w, &buf);
    if (code != 354) { r.error = "data refused"; r.smtp_status = code; close_wire(w); return r; }

    std::string body = compose_rfc5322(m);
    body.append(".\r\n");
    if (wire_write(w, body.data(), body.size()) != long long(body.size())) {
        r.error = "body write"; close_wire(w); return r;
    }
    code = read_reply(w, &buf);
    if (code != 250) { r.error = "body refused"; r.smtp_status = code; close_wire(w); return r; }

    (void)send_line(w, "QUIT\r\n");
    (void)read_reply(w, &buf);

    close_wire(w);
    r.ok = true; r.smtp_status = 250;
    return r;
}

}  // namespace bolt::api::auth::smtp
