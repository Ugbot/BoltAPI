// http_client.cpp — serializer + incremental response parser (see http_client.h).

#include "http_client.h"

#include <cctype>
#include <cstdlib>
#include <cstring>

namespace bolt::bench::http {

std::size_t serialize_request(const ClientRequest& req, std::string& out) {
    assert(!req.method.empty());
    assert(!req.path.empty());
    out.clear();
    out.append(req.method);
    out.push_back(' ');
    out.append(req.path);
    out.append(" HTTP/1.1\r\n");
    out.append("Host: ");
    out.append(req.host);
    out.append("\r\n");
    if (!req.body.empty()) {
        out.append("Content-Type: ");
        out.append(req.content_type);
        out.append("\r\nContent-Length: ");
        out.append(std::to_string(req.body.size()));
        out.append("\r\n");
    }
    out.append("\r\n");
    out.append(req.body);
    assert(out.size() >= req.path.size());  // produced a non-trivial request
    return out.size();
}

// Case-insensitive search for `needle` (lowercase ASCII) within [b, e) of buf.
// Returns offset or npos. Bounded by the buffer length.
static std::size_t find_ci(const std::string& buf, std::size_t b, std::size_t e,
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

bool ResponseParser::parse_head() noexcept {
    assert(header_end_ != npos_);
    assert(header_end_ <= buf_.size());
    // Status line: "HTTP/1.1 NNN ..." — status code at offset 9.
    if (buf_.size() < 12 || std::memcmp(buf_.data(), "HTTP/1.", 7) != 0) return false;
    status_ = std::atoi(buf_.c_str() + 9);
    if (status_ < 100 || status_ > 599) return false;

    // Reject chunked bodies (v1 unsupported; the bench server always uses CL).
    if (find_ci(buf_, 0, header_end_, "transfer-encoding:", 18) != npos_) return false;

    // Content-Length (required for framing in v1).
    const std::size_t cl = find_ci(buf_, 0, header_end_, "content-length:", 15);
    if (cl != npos_) {
        content_length_ = std::atoll(buf_.c_str() + cl + 15);
        if (content_length_ < 0) return false;
    } else {
        content_length_ = 0;  // no body declared
    }

    // Keep-alive: HTTP/1.1 defaults to keep-alive unless "Connection: close".
    const std::size_t cc = find_ci(buf_, 0, header_end_, "connection:", 11);
    if (cc != npos_ && find_ci(buf_, cc, header_end_, "close", 5) != npos_) {
        keep_alive_ = false;
    }
    return true;
}

ResponseParser::State ResponseParser::consume(const char* data, std::size_t len) noexcept {
    assert(data != nullptr || len == 0);
    if (buf_.size() + len > kMaxRespBytes) return State::Error;
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
    return (have >= static_cast<std::size_t>(content_length_)) ? State::Complete
                                                               : State::NeedMore;
}

}  // namespace bolt::bench::http
