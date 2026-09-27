#include "boltapi/http/websocket_parser.h"
#include "boltapi/net/sys_compat.h"  // htons/ntohs (winsock on Windows, arpa/inet on POSIX)
#include <cassert>
#include <cstring>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

#ifdef __APPLE__
#include <libkern/OSByteOrder.h>
#define htobe64(x) OSSwapHostToBigInt64(x)
#define be64toh(x) OSSwapBigToHostInt64(x)
#endif

namespace bolt::api {
namespace websocket {

// WebSocket GUID for handshake (RFC 6455)
static const char* WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

// ============================================================================
// FrameParser Implementation
// ============================================================================

FrameParser::FrameParser() = default;

FrameParser::~FrameParser() = default;

int FrameParser::parse_header(
    const uint8_t* data,
    size_t length,
    FrameHeader& header,
    size_t& header_length
) {
    assert((data != nullptr || length == 0) && "parse_header: null with length");
    header_length = 0;
    if (length < 2) return -1;
    const uint8_t b0 = data[0];
    const uint8_t b1 = data[1];
    header.fin = (b0 & 0x80) != 0;
    header.rsv1 = (b0 & 0x40) != 0;
    header.rsv2 = (b0 & 0x20) != 0;
    header.rsv3 = (b0 & 0x10) != 0;
    header.opcode = static_cast<OpCode>(b0 & 0x0F);
    header.mask = (b1 & 0x80) != 0;
    const uint8_t len7 = b1 & 0x7F;
    size_t pos = 2;
    if (len7 < 126) {
        header.payload_length = len7;
    } else if (len7 == 126) {
        if (length < pos + 2) return -1;
        header.payload_length = (static_cast<uint64_t>(data[2]) << 8) | data[3];
        pos += 2;
    } else {
        if (length < pos + 8) return -1;
        uint64_t v = 0;
        for (size_t i = 0; i < 8; ++i) v = (v << 8) | data[pos + i];
        if ((v >> 63) != 0) return kErrorLength;  // RFC 6455 §5.2: MSB must be 0
        header.payload_length = v;
        pos += 8;
    }
    if (header.mask) {
        if (length < pos + 4) return -1;
        std::memcpy(header.masking_key, data + pos, 4);
        pos += 4;
    } else {
        std::memset(header.masking_key, 0, 4);
    }
    header_length = pos;
    assert(header_length <= kMaxHeaderLength && "header longer than 14 bytes");
    assert(header_length <= length && "header past input");
    return 0;
}

int FrameParser::parse_frame(
    const uint8_t* data,
    size_t length,
    size_t& consumed,
    FrameHeader& header,
    const uint8_t*& payload_start,
    size_t& payload_length
) {
    // Stateless: succeeds only when the header AND the whole payload are in
    // `data`; otherwise nothing is consumed and the caller retries with more.
    consumed = 0;
    size_t hlen = 0;
    const int r = parse_header(data, length, header, hlen);
    if (r != 0) return r;
    if (header.payload_length > length - hlen) return -1;
    payload_length = static_cast<size_t>(header.payload_length);
    payload_start = payload_length > 0 ? data + hlen : nullptr;
    consumed = hlen + payload_length;
    assert(consumed <= length && "frame past input");
    return 0;
}

void FrameParser::unmask(
    uint8_t* data,
    size_t length,
    const uint8_t* masking_key,
    size_t offset
) {
    assert((data != nullptr || length == 0) && "unmask: null data");
    assert(masking_key != nullptr && "unmask: null key");
    size_t i = 0;
    // Word-at-a-time with the key rotated to `offset`; memcpy keeps it
    // alignment-agnostic (payloads land at arbitrary buffer offsets).
    uint8_t rot[8];
    for (size_t j = 0; j < 8; ++j) rot[j] = masking_key[(offset + j) % 4];
    uint64_t mask64 = 0;
    std::memcpy(&mask64, rot, 8);
    for (; i + 8 <= length; i += 8) {
        uint64_t w = 0;
        std::memcpy(&w, data + i, 8);
        w ^= mask64;
        std::memcpy(data + i, &w, 8);
    }
    for (; i < length; ++i) data[i] ^= masking_key[(offset + i) % 4];
}

int FrameParser::build_frame(
    OpCode opcode,
    const uint8_t* payload,
    size_t length,
    bool fin,
    bool rsv1,
    std::string& output
) {
    // Build frame header
    uint8_t byte0 = static_cast<uint8_t>(opcode);
    if (fin) byte0 |= 0x80;
    if (rsv1) byte0 |= 0x40;
    
    output.push_back(byte0);
    
    // Payload length
    if (length < 126) {
        output.push_back(static_cast<uint8_t>(length));
    } else if (length <= 0xFFFF) {
        output.push_back(126);
        uint16_t len16 = htons(static_cast<uint16_t>(length));
        output.append(reinterpret_cast<const char*>(&len16), 2);
    } else {
        output.push_back(127);
        uint64_t len64 = htobe64(length);
        output.append(reinterpret_cast<const char*>(&len64), 8);
    }
    
    // Payload
    if (payload && length > 0) {
        output.append(reinterpret_cast<const char*>(payload), length);
    }
    
    return 0;
}

int FrameParser::build_close_frame(
    CloseCode code,
    const char* reason,
    std::string& output
) {
    uint16_t code16 = htons(static_cast<uint16_t>(code));
    std::string payload;
    payload.append(reinterpret_cast<const char*>(&code16), 2);
    
    if (reason && *reason) {
        payload.append(reason);
    }
    
    return build_frame(
        OpCode::CLOSE,
        reinterpret_cast<const uint8_t*>(payload.data()),
        payload.size(),
        true,
        false,
        output
    );
}

int FrameParser::parse_close_payload(
    const uint8_t* payload,
    size_t length,
    CloseCode& code,
    std::string& reason
) {
    assert((payload != nullptr || length == 0) && "close payload: null");
    reason.clear();
    if (length == 0) {
        code = CloseCode::NO_STATUS;
        return 0;
    }
    if (length < 2) {
        code = CloseCode::PROTOCOL_ERROR;
        return -1;  // RFC 6455 §5.5.1: a body carries at least the code
    }
    const uint16_t raw = static_cast<uint16_t>((payload[0] << 8) | payload[1]);
    code = static_cast<CloseCode>(raw);
    if (!is_valid_close_code(raw)) {
        code = CloseCode::PROTOCOL_ERROR;
        return -1;
    }
    if (!validate_utf8(payload + 2, length - 2)) {
        code = CloseCode::INVALID_PAYLOAD;
        return -1;
    }
    reason.assign(reinterpret_cast<const char*>(payload + 2), length - 2);
    return 0;
}

bool FrameParser::is_valid_close_code(uint16_t code) {
    // RFC 6455 §7.4: 1000-1003, 1007-1011 defined for the wire; 1004-1006 and
    // 1015 are reserved (never sent); 3000-4999 for libraries/applications.
    if (code >= 3000 && code <= 4999) return true;
    return (code >= 1000 && code <= 1003) || (code >= 1007 && code <= 1011);
}

bool FrameParser::validate_utf8(const uint8_t* data, size_t length) {
    // RFC 3629: rejects overlong forms, UTF-16 surrogates and > U+10FFFF.
    assert((data != nullptr || length == 0) && "validate_utf8: null");
    size_t i = 0;
    while (i < length) {
        const uint8_t c = data[i];
        if (c < 0x80) { ++i; continue; }
        size_t n = 0;
        uint8_t lo = 0x80, hi = 0xBF;  // allowed range of the 2nd byte
        if (c >= 0xC2 && c <= 0xDF) { n = 2; }
        else if (c == 0xE0) { n = 3; lo = 0xA0; }
        else if (c >= 0xE1 && c <= 0xEC) { n = 3; }
        else if (c == 0xED) { n = 3; hi = 0x9F; }
        else if (c >= 0xEE && c <= 0xEF) { n = 3; }
        else if (c == 0xF0) { n = 4; lo = 0x90; }
        else if (c >= 0xF1 && c <= 0xF3) { n = 4; }
        else if (c == 0xF4) { n = 4; hi = 0x8F; }
        else return false;
        if (length - i < n) return false;
        if (data[i + 1] < lo || data[i + 1] > hi) return false;
        for (size_t k = 2; k < n; ++k)
            if ((data[i + k] & 0xC0) != 0x80) return false;
        i += n;
    }
    assert(i == length && "validate_utf8 overran");
    return true;
}

void FrameParser::reset() {}

// ============================================================================
// HandshakeUtils Implementation
// ============================================================================

std::string HandshakeUtils::compute_accept_key(const std::string& key) {
    // Concatenate key with GUID
    std::string concat = key + WS_GUID;
    
    // Compute SHA-1 hash
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1(reinterpret_cast<const unsigned char*>(concat.c_str()), concat.length(), hash);
    
    // Base64 encode
    BIO* bio = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);
    
    BIO_write(bio, hash, SHA_DIGEST_LENGTH);
    BIO_flush(bio);
    
    BUF_MEM* buffer;
    BIO_get_mem_ptr(bio, &buffer);
    
    std::string result(buffer->data, buffer->length);
    BIO_free_all(bio);
    
    return result;
}

bool HandshakeUtils::validate_upgrade_request(
    const std::string& method,
    const std::string& upgrade,
    const std::string& connection,
    const std::string& ws_version,
    const std::string& ws_key
) {
    // Validate method
    if (method != "GET") {
        return false;
    }
    
    // Validate Upgrade header
    if (upgrade.find("websocket") == std::string::npos &&
        upgrade.find("WebSocket") == std::string::npos) {
        return false;
    }
    
    // Validate Connection header
    if (connection.find("Upgrade") == std::string::npos &&
        connection.find("upgrade") == std::string::npos) {
        return false;
    }
    
    // Validate WebSocket version
    if (ws_version != "13") {
        return false;
    }
    
    // Validate key (should be 24 characters base64)
    if (ws_key.empty() || ws_key.length() != 24) {
        return false;
    }

    return true;
}

std::string HandshakeUtils::select_subprotocol(std::string_view client_offered) {
    // RFC 6455 §4.2.2: server selects ONE subprotocol from the client's list,
    // or none. We bake first-class support for "mqtt" (the boltapi MQTT bus
    // subprotocol); otherwise we echo the first offered token verbatim to
    // keep browsers from refusing the upgrade.
    if (client_offered.empty()) return std::string();

    // Walk comma-separated tokens; trim ASCII whitespace; skip empties.
    // Bounded scan — header sizes are already capped upstream.
    const std::size_t n = client_offered.size();
    std::string first;
    std::size_t i = 0;
    while (i < n) {
        // Skip leading whitespace.
        while (i < n && (client_offered[i] == ' ' || client_offered[i] == '\t')) {
            ++i;
        }
        // Read the token.
        const std::size_t start = i;
        while (i < n && client_offered[i] != ',') ++i;
        std::size_t end = i;
        while (end > start && (client_offered[end - 1] == ' ' ||
                               client_offered[end - 1] == '\t')) {
            --end;
        }
        if (end > start) {
            const std::string_view tok(client_offered.data() + start, end - start);
            // "mqtt" wins outright (case-sensitive — RFC 6455 tokens are
            // case-sensitive and mqtt.js + browsers send lowercase).
            if (tok == "mqtt") return std::string("mqtt");
            if (first.empty()) first.assign(tok);
        }
        if (i < n && client_offered[i] == ',') ++i;
    }
    return first;
}

} // namespace websocket
} // namespace bolt::api





