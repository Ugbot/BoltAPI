// sse.cpp — text/event-stream framing; see sse.h.
#include "boltapi/http/sse.h"

#include <cassert>
#include <charconv>

namespace bolt::api::http {

namespace {

bool clean_field(std::string_view v) noexcept {
    if (v.size() > kSseMaxFieldBytes) return false;
    for (char c : v) {
        if (c == '\r' || c == '\n' || c == '\0') return false;
    }
    return true;
}

// Calls line(begin, end) for each line of `text`, split on CRLF, CR or LF
// (the terminators the client recognises). Always at least one line.
template <class F>
void for_each_line(std::string_view text, F&& line) {
    std::size_t start = 0;
    for (std::size_t i = 0; i < text.size(); ++i) {
        if (text[i] != '\r' && text[i] != '\n') continue;
        line(text.substr(start, i - start));
        if (text[i] == '\r' && i + 1 < text.size() && text[i + 1] == '\n') ++i;
        start = i + 1;
    }
    line(text.substr(start));
}

}  // namespace

bool sse_format_event(std::string& out, std::string_view event, std::string_view data,
                      std::string_view id) {
    if (!clean_field(event) || !clean_field(id)) return false;
    const std::size_t before = out.size();
    if (!id.empty()) {
        out.append("id: ").append(id).push_back('\n');
    }
    if (!event.empty()) {
        out.append("event: ").append(event).push_back('\n');
    }
    for_each_line(data, [&out](std::string_view l) { out.append("data: ").append(l).push_back('\n'); });
    out.push_back('\n');  // blank line dispatches the event
    assert(out.size() > before);
    assert(out.back() == '\n');
    return true;
}

void sse_format_comment(std::string& out, std::string_view text) {
    const std::size_t before = out.size();
    for_each_line(text, [&out](std::string_view l) { out.append(": ").append(l).push_back('\n'); });
    out.push_back('\n');
    assert(out.size() > before);
}

bool sse_format_retry(std::string& out, long long retry_ms) {
    if (retry_ms < 0) return false;
    char buf[24];
    const auto r = std::to_chars(buf, buf + sizeof(buf), retry_ms);
    assert(r.ec == std::errc());
    out.append("retry: ").append(buf, static_cast<std::size_t>(r.ptr - buf)).append("\n\n");
    return true;
}

}  // namespace bolt::api::http
