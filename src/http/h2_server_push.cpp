#include "boltapi/http/h2_server_push.h"
#include <cstring>
#include <iostream>

namespace bolt::api {
namespace http {

// ============================================================================
// PushRules Implementation
// ============================================================================

void PushRules::add_rule(
    const std::string& trigger_path,
    const std::vector<std::string>& resources
) {
    rules_[trigger_path] = resources;
}

std::vector<std::string> PushRules::get_push_resources(const std::string& path) const {
    auto it = rules_.find(path);
    if (it != rules_.end()) {
        return it->second;
    }
    return {};
}

bool PushRules::should_push(const std::string& path) const {
    return rules_.find(path) != rules_.end();
}

// ============================================================================
// ServerPush Implementation
// ============================================================================

ServerPush::ServerPush() {
}

uint32_t ServerPush::add_promise(
    uint32_t stream_id,
    const PushPromise& promise
) noexcept {
    uint32_t promised_stream_id = next_promised_stream_id_;
    next_promised_stream_id_ += 2;  // Server uses even IDs
    
    promises_sent_++;
    
    std::cout << "HTTP/2: Server push promise for " << promise.path 
              << " (stream " << promised_stream_id << ")" << std::endl;
    
    return promised_stream_id;
}

int ServerPush::build_push_promise_frame(
    uint32_t stream_id,
    uint32_t promised_stream_id,
    const PushPromise& promise,
    uint8_t* output,
    size_t capacity,
    size_t& out_written
) noexcept {
    if (capacity < 100) {
        return 1;  // Need reasonable buffer
    }
    
    // HTTP/2 PUSH_PROMISE frame format:
    // +---------------+
    // | Frame Header  | (9 bytes)
    // +---------------+
    // | Promised ID   | (4 bytes)
    // +---------------+
    // | Header Block  | (HPACK-encoded)
    // +---------------+
    
    size_t pos = 0;
    
    // Frame header (9 bytes) - placeholder for now
    // Type: 0x05 (PUSH_PROMISE)
    pos += 9;
    
    // Promised stream ID (4 bytes)
    output[pos++] = (promised_stream_id >> 24) & 0xFF;
    output[pos++] = (promised_stream_id >> 16) & 0xFF;
    output[pos++] = (promised_stream_id >> 8) & 0xFF;
    output[pos++] = promised_stream_id & 0xFF;
    
    // Encode headers with HPACK
    HPACKHeader headers[] = {
        {":method", promise.method.c_str()},
        {":path", promise.path.c_str()},
        {":scheme", "https"},
        {":authority", ""}  // Would be filled from request
    };
    
    size_t hpack_written;
    if (encoder_.encode(headers, 4, output + pos, capacity - pos, hpack_written) != 0) {
        return 1;
    }
    
    pos += hpack_written;
    
    // Update frame header length
    size_t payload_len = pos - 9;
    output[0] = (payload_len >> 16) & 0xFF;
    output[1] = (payload_len >> 8) & 0xFF;
    output[2] = payload_len & 0xFF;
    output[3] = 0x05;  // Type: PUSH_PROMISE
    output[4] = 0x04;  // Flags: END_HEADERS
    
    // Stream ID
    output[5] = (stream_id >> 24) & 0xFF;
    output[6] = (stream_id >> 16) & 0xFF;
    output[7] = (stream_id >> 8) & 0xFF;
    output[8] = stream_id & 0xFF;
    
    out_written = pos;
    return 0;
}

int ServerPush::build_pushed_response(
    uint32_t promised_stream_id,
    const PushPromise& promise,
    uint8_t* output,
    size_t capacity,
    size_t& out_written
) noexcept {
    // Build HEADERS frame + DATA frame for pushed resource
    
    size_t pos = 0;
    
    // HEADERS frame with response headers
    HPACKHeader headers[] = {
        {":status", "200"},
        {"content-type", promise.content_type.data()},
        {"content-length", std::to_string(promise.content.length()).c_str()}
    };
    
    // Frame header (9 bytes)
    pos += 9;
    
    // Encode headers
    size_t hpack_written;
    if (encoder_.encode(headers, 3, output + pos, capacity - pos, hpack_written) != 0) {
        return 1;
    }
    
    pos += hpack_written;
    
    // Update HEADERS frame header
    size_t headers_payload = pos - 9;
    output[0] = (headers_payload >> 16) & 0xFF;
    output[1] = (headers_payload >> 8) & 0xFF;
    output[2] = headers_payload & 0xFF;
    output[3] = 0x01;  // Type: HEADERS
    output[4] = 0x04;  // Flags: END_HEADERS
    
    output[5] = (promised_stream_id >> 24) & 0xFF;
    output[6] = (promised_stream_id >> 16) & 0xFF;
    output[7] = (promised_stream_id >> 8) & 0xFF;
    output[8] = promised_stream_id & 0xFF;
    
    // DATA frame with content
    size_t data_frame_start = pos;
    pos += 9;  // Frame header
    
    // Copy content
    if (pos + promise.content.length() > capacity) {
        return 1;
    }
    
    std::memcpy(output + pos, promise.content.data(), promise.content.length());
    pos += promise.content.length();
    
    // Update DATA frame header
    output[data_frame_start + 0] = (promise.content.length() >> 16) & 0xFF;
    output[data_frame_start + 1] = (promise.content.length() >> 8) & 0xFF;
    output[data_frame_start + 2] = promise.content.length() & 0xFF;
    output[data_frame_start + 3] = 0x00;  // Type: DATA
    output[data_frame_start + 4] = 0x01;  // Flags: END_STREAM
    
    output[data_frame_start + 5] = (promised_stream_id >> 24) & 0xFF;
    output[data_frame_start + 6] = (promised_stream_id >> 16) & 0xFF;
    output[data_frame_start + 7] = (promised_stream_id >> 8) & 0xFF;
    output[data_frame_start + 8] = promised_stream_id & 0xFF;
    
    out_written = pos;
    resources_pushed_++;
    bytes_pushed_ += promise.content.length();
    
    return 0;
}

void ServerPush::set_rules(const PushRules& rules) {
    rules_ = rules;
}

std::vector<PushPromise> ServerPush::get_pushes_for_path(const std::string& path) const {
    std::vector<PushPromise> pushes;
    
    auto resources = rules_.get_push_resources(path);
    for (const auto& resource : resources) {
        pushes.emplace_back(resource);
    }
    
    return pushes;
}

ServerPush::Stats ServerPush::get_stats() const noexcept {
    Stats stats;
    stats.promises_sent = promises_sent_;
    stats.resources_pushed = resources_pushed_;
    stats.bytes_pushed = bytes_pushed_;
    stats.pushes_rejected = pushes_rejected_;
    return stats;
}

} // namespace http
} // namespace bolt::api

