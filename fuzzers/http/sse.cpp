// sse.cpp — SSE framing against an independent WHATWG event-stream parser:
// whatever the id / event type / data / comment bytes, the formatted stream
// must dispatch exactly the one event it was asked for (data compared after
// the spec's line-terminator normalisation), and a comment none.
//
// Input: four fields separated by 0xFF bytes: id, event, data, comment.

#include "boltapi/http/sse.h"
#include "fuzz_util.h"

#include <string>
#include <string_view>
#include <vector>

using namespace bolt::api::http;

namespace {

struct Event {
    std::string type, data, id;
};

// HTML "Interpreting an event stream" (no BOM / reconnection handling needed).
std::vector<Event> parse(std::string_view s) {
    std::vector<Event> out;
    std::string data, type, last_id;
    bool have_data = false;
    std::size_t i = 0;
    for (std::size_t guard = 0; i < s.size() && guard <= s.size(); ++guard) {
        std::size_t j = i;
        while (j < s.size() && s[j] != '\r' && s[j] != '\n') ++j;
        if (j == s.size()) break;  // unterminated trailing line: ignored
        const std::string_view line = s.substr(i, j - i);
        i = (s[j] == '\r' && j + 1 < s.size() && s[j + 1] == '\n') ? j + 2 : j + 1;
        if (line.empty()) {
            if (have_data) {
                if (!data.empty() && data.back() == '\n') data.pop_back();
                out.push_back({type.empty() ? "message" : type, data, last_id});
            }
            data.clear();
            type.clear();
            have_data = false;
            continue;
        }
        if (line[0] == ':') continue;
        const std::size_t colon = line.find(':');
        std::string_view field = line, value;
        if (colon != std::string_view::npos) {
            field = line.substr(0, colon);
            value = line.substr(colon + 1);
            if (!value.empty() && value[0] == ' ') value.remove_prefix(1);
        }
        if (field == "event") type = value;
        else if (field == "data") { data.append(value); data.push_back('\n'); have_data = true; }
        else if (field == "id" && value.find('\0') == std::string_view::npos) last_id = value;
    }
    return out;
}

std::string normalise(std::string_view d) {
    std::string out;
    for (std::size_t i = 0; i < d.size(); ++i) {
        if (d[i] == '\r') {
            out.push_back('\n');
            if (i + 1 < d.size() && d[i + 1] == '\n') ++i;
        } else {
            out.push_back(d[i]);
        }
    }
    return out;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    std::string_view in(reinterpret_cast<const char*>(data), size);
    std::string_view f[4];
    for (int k = 0; k < 4; ++k) {
        const std::size_t sep = in.find('\xff');
        f[k] = in.substr(0, sep);
        in = sep == std::string_view::npos ? std::string_view() : in.substr(sep + 1);
    }
    std::string out;
    if (sse_format_event(out, f[1], f[2], f[0])) {
        const auto ev = parse(out);
        FUZZ_CHECK(ev.size() == 1);
        FUZZ_CHECK(ev[0].type == (f[1].empty() ? std::string("message") : std::string(f[1])));
        FUZZ_CHECK(ev[0].data == normalise(f[2]));
        FUZZ_CHECK(ev[0].id == f[0]);
    } else {
        FUZZ_CHECK(out.empty());
        const auto bad = [](std::string_view v) {
            return v.find_first_of(std::string_view("\r\n\0", 3)) != std::string_view::npos;
        };
        FUZZ_CHECK(bad(f[0]) || bad(f[1]));
    }
    std::string c;
    sse_format_comment(c, f[3]);
    FUZZ_CHECK(parse(c).empty());
    return 0;
}
