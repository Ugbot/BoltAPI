// sse.h — text/event-stream framing (WHATWG HTML "Server-sent events").
//
// A field value may not carry a line break: a CR, LF or CRLF inside an id,
// event type or data line would end the field early and let the rest be
// parsed as further fields or a second event. Data is split on every line
// terminator into one "data:" line each (the client rejoins them with LF);
// ids and event types with a terminator or NUL are refused.
#pragma once

#include <cstddef>
#include <string>
#include <string_view>

namespace bolt::api::http {

inline constexpr std::size_t kSseMaxFieldBytes = 1u << 20;  // id / event type

/** Appends one event to `out`. False (out unchanged) if id or event holds a
 *  CR, LF or NUL, or is longer than kSseMaxFieldBytes. */
bool sse_format_event(std::string& out, std::string_view event, std::string_view data,
                      std::string_view id = {});

/** Appends a comment (keep-alive); every line of `text` becomes its own
 *  comment line, so it can never start a field. */
void sse_format_comment(std::string& out, std::string_view text);

/** Appends a reconnection-time hint; false for a negative value. */
bool sse_format_retry(std::string& out, long long retry_ms);

}  // namespace bolt::api::http
