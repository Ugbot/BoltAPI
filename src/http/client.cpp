// src/http/client.cpp — outbound HTTP/1.1 client (see include/boltapi/http/client.h).

#include "boltapi/http/client.h"

#include <cctype>
#include <cstdlib>
#include <cstring>
#include <utility>

namespace bolt::api::http {

namespace sys = ::bolt::api::net::sys;

// ---------------------------------------------------------------------------
// serialize_request
// ---------------------------------------------------------------------------
std::size_t serialize_request(const ClientRequest& req,
                              std::string_view host_fallback,
                              std::string& out) {
    assert(!req.method.empty());
    assert(!req.path.empty());
    out.clear();
    out.append(req.method);
    out.push_back(' ');
    out.append(req.path);
    out.append(" HTTP/1.1\r\n");
    out.append("Host: ");
    out.append(req.host.empty() ? host_fallback : req.host);
    out.append("\r\n");
    assert(req.extra_count <= kClientMaxReqHeaders);
    for (std::size_t i = 0; i < req.extra_count && i < kClientMaxReqHeaders; ++i) {
        out.append(req.extra_headers[i].name);
        out.append(": ");
        out.append(req.extra_headers[i].value);
        out.append("\r\n");
    }
    if (!req.body.empty()) {
        out.append("Content-Type: ");
        out.append(req.content_type);
        out.append("\r\nContent-Length: ");
        out.append(std::to_string(req.body.size()));
        out.append("\r\n");
    }
    out.append("\r\n");
    out.append(req.body);
    assert(out.size() >= req.path.size());
    return out.size();
}

// ---------------------------------------------------------------------------
// ResponseParser
// ---------------------------------------------------------------------------
namespace {

// Case-insensitive search for lowercase `needle` within [b, e) of buf.
std::size_t find_ci(const std::string& buf, std::size_t b, std::size_t e,
                    const char* needle, std::size_t nlen) noexcept {
    assert(b <= e);
    assert(nlen > 0);
    if (e < nlen) return static_cast<std::size_t>(-1);
    for (std::size_t i = b; i + nlen <= e; ++i) {
        std::size_t k = 0;
        for (; k < nlen; ++k) {
            const char c = static_cast<char>(std::tolower(static_cast<unsigned char>(buf[i + k])));
            if (c != needle[k]) break;
        }
        if (k == nlen) return i;
    }
    return static_cast<std::size_t>(-1);
}

bool iequals(std::string_view a, std::string_view b) noexcept {
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i]))) return false;
    }
    return true;
}

}  // namespace

void ResponseParser::reset() noexcept {
    buf_.clear();
    field_count_ = 0;
    header_end_ = npos_;
    content_length_ = -1;
    status_ = 0;
    keep_alive_ = true;
}

bool ResponseParser::parse_head() noexcept {
    assert(header_end_ != npos_);
    assert(header_end_ <= buf_.size());
    if (buf_.size() < 12 || std::memcmp(buf_.data(), "HTTP/1.", 7) != 0) return false;
    status_ = std::atoi(buf_.c_str() + 9);
    if (status_ < 100 || status_ > 599) return false;

    if (find_ci(buf_, 0, header_end_, "transfer-encoding:", 18) != npos_) return false;  // chunked unsupported (v1)

    const std::size_t cl = find_ci(buf_, 0, header_end_, "content-length:", 15);
    if (cl != npos_) {
        content_length_ = std::atoll(buf_.c_str() + cl + 15);
        if (content_length_ < 0) return false;
    } else {
        content_length_ = 0;
    }

    const std::size_t cc = find_ci(buf_, 0, header_end_, "connection:", 11);
    if (cc != npos_ && find_ci(buf_, cc, header_end_, "close", 5) != npos_) keep_alive_ = false;

    // Parse header field lines (after the status line) into bounded views.
    field_count_ = 0;
    std::size_t line = buf_.find("\r\n");
    if (line == std::string::npos) return true;
    line += 2;  // skip status line
    while (line < header_end_ && field_count_ < kClientMaxRespHeaders) {
        std::size_t eol = buf_.find("\r\n", line);
        if (eol == std::string::npos || eol > header_end_) eol = header_end_;
        const std::size_t colon = buf_.find(':', line);
        if (colon != std::string::npos && colon < eol) {
            std::size_t vbeg = colon + 1;
            while (vbeg < eol && (buf_[vbeg] == ' ' || buf_[vbeg] == '\t')) ++vbeg;
            fields_[field_count_] = Field{line, colon - line, vbeg, eol - vbeg};
            ++field_count_;
        }
        if (eol >= header_end_) break;
        line = eol + 2;
    }
    return true;
}

ResponseParser::State ResponseParser::consume(const char* data, std::size_t len) noexcept {
    assert(data != nullptr || len == 0);
    if (buf_.size() + len > kClientMaxRespBytes) return State::Error;
    buf_.append(data, len);

    if (header_end_ == npos_) {
        const std::size_t pos = buf_.find("\r\n\r\n");
        if (pos == std::string::npos) return State::NeedMore;
        header_end_ = pos;
        if (!parse_head()) return State::Error;
    }
    assert(content_length_ >= 0);
    const std::size_t body_start = header_end_ + 4;
    const std::size_t have = buf_.size() - body_start;
    return (have >= static_cast<std::size_t>(content_length_)) ? State::Complete : State::NeedMore;
}

std::string_view ResponseParser::body() const noexcept {
    if (header_end_ == npos_ || content_length_ < 0) return {};
    const std::size_t body_start = header_end_ + 4;
    assert(body_start <= buf_.size());
    return std::string_view(buf_.data() + body_start, static_cast<std::size_t>(content_length_));
}

std::string_view ResponseParser::header_name(std::size_t i) const noexcept {
    assert(i < field_count_);
    return std::string_view(buf_.data() + fields_[i].name_off, fields_[i].name_len);
}

std::string_view ResponseParser::header_value(std::size_t i) const noexcept {
    assert(i < field_count_);
    return std::string_view(buf_.data() + fields_[i].val_off, fields_[i].val_len);
}

// ---------------------------------------------------------------------------
// ClientResponse
// ---------------------------------------------------------------------------
std::string_view ClientResponse::header(std::string_view name) const noexcept {
    for (const auto& h : headers) {
        if (iequals(h.name, name)) return h.value;
    }
    return {};
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------
Client::Client(net::IODispatcher* dispatcher) noexcept : Client(dispatcher, Config{}) {}

Client::Client(net::IODispatcher* dispatcher, Config cfg) noexcept
    : disp_(dispatcher), cfg_(cfg) {
    assert(disp_ != nullptr);
    assert(cfg_.max_conns_per_target >= 1);
    targets_.reserve(cfg_.max_targets);
}

Client::~Client() { close_idle(); }

Client::TargetPool* Client::get_target(std::string_view host, std::uint16_t port) noexcept {
    assert(!host.empty());
    assert(port != 0);
    std::lock_guard<std::mutex> lk(targets_mtx_);
    for (auto& up : targets_) {
        if (up->port == port && up->host == host) return up.get();
    }
    if (targets_.size() >= cfg_.max_targets) return nullptr;  // bounded: shed
    auto tp = std::make_unique<TargetPool>();
    tp->host.assign(host.data(), host.size());
    tp->port = port;
    std::memset(&tp->addr, 0, sizeof(tp->addr));
    tp->addr.sin_family = AF_INET;
    tp->addr.sin_port = htons(port);
    tp->addr_ok = (::inet_pton(AF_INET, tp->host.c_str(), &tp->addr.sin_addr) == 1);
    tp->idle.reserve(cfg_.max_conns_per_target);
    TargetPool* raw = tp.get();
    targets_.push_back(std::move(tp));
    return raw;
}

int Client::pop_idle(TargetPool& tp) noexcept {
    std::lock_guard<std::mutex> lk(tp.mtx);
    if (tp.idle.empty()) return -1;
    const int fd = tp.idle.back();
    tp.idle.pop_back();
    return fd;
}

bool Client::push_idle(TargetPool& tp, int fd) noexcept {
    assert(fd >= 0);
    std::lock_guard<std::mutex> lk(tp.mtx);
    if (tp.idle.size() >= cfg_.max_conns_per_target) return false;
    tp.idle.push_back(fd);
    return true;
}

void Client::close_idle() noexcept {
    std::lock_guard<std::mutex> lk(targets_mtx_);
    for (auto& up : targets_) {
        std::lock_guard<std::mutex> tlk(up->mtx);
        for (int fd : up->idle) { if (fd >= 0) sys::close_socket(fd); }
        up->idle.clear();
    }
}

std::size_t Client::idle_total() noexcept {
    std::size_t total = 0;
    std::lock_guard<std::mutex> lk(targets_mtx_);
    for (auto& up : targets_) {
        std::lock_guard<std::mutex> tlk(up->mtx);
        total += up->idle.size();
    }
    return total;
}

core::coro_task<ClientResponse> Client::send(std::string_view host, std::uint16_t port,
                                             const ClientRequest& req) {
    ClientResponse resp;  // .ok defaults false
    sys::startup();

    TargetPool* tp = get_target(host, port);
    if (tp == nullptr || !tp->addr_ok) co_return resp;  // capacity / bad host

    // Reuse a pooled keep-alive connection, else create + connect a new one.
    int fd = pop_idle(*tp);
    if (fd < 0) {
        fd = static_cast<int>(::socket(AF_INET, SOCK_STREAM, 0));
        if (fd < 0) co_return resp;
        sys::set_nonblocking(fd);
        const int cr = co_await disp_->async_connect(
            fd, reinterpret_cast<sockaddr*>(&tp->addr), sizeof(tp->addr));
        if (cr != 0) { sys::close_socket(fd); co_return resp; }
    }

    // Build the request once (host fallback = "host:port").
    std::string host_hdr;
    host_hdr.assign(tp->host).append(":").append(std::to_string(port));
    std::string wbuf;
    serialize_request(req, host_hdr, wbuf);

    bool broken = false;

    // Write the full request (partial-write loop, bounded by wbuf.size()).
    std::size_t sent = 0;
    while (sent < wbuf.size()) {
        const ssize_t n = co_await disp_->async_write(fd, wbuf.data() + sent, wbuf.size() - sent);
        if (n <= 0) { broken = true; break; }
        sent += static_cast<std::size_t>(n);
    }

    // Read until one full response is parsed.
    ResponseParser parser;
    char rbuf[kClientRecvChunk];
    bool complete = false;
    while (!broken && !complete) {
        const ssize_t n = co_await disp_->async_read(fd, rbuf, sizeof(rbuf));
        if (n <= 0) { broken = true; break; }
        const auto st = parser.consume(rbuf, static_cast<std::size_t>(n));
        if (st == ResponseParser::State::Complete) complete = true;
        else if (st == ResponseParser::State::Error) broken = true;
    }

    if (broken || !complete) { sys::close_socket(fd); co_return resp; }

    // Materialize an owned response (stable after the fd is recycled).
    resp.ok = true;
    resp.status = parser.status();
    resp.keep_alive = parser.keep_alive();
    const std::string_view b = parser.body();
    resp.body.assign(b.data(), b.size());
    resp.headers.reserve(parser.header_count());
    for (std::size_t i = 0; i < parser.header_count(); ++i) {
        resp.headers.push_back(ClientResponseHeader{
            std::string(parser.header_name(i)), std::string(parser.header_value(i))});
    }

    // Recycle the connection on keep-alive, else close it.
    if (resp.keep_alive) { if (!push_idle(*tp, fd)) sys::close_socket(fd); }
    else sys::close_socket(fd);

    co_return std::move(resp);
}

}  // namespace bolt::api::http
