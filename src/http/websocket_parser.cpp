#include "boltapi/http/websocket_parser.h"
#include "boltapi/net/sys_compat.h"  // htons/ntohs (winsock on Windows, arpa/inet on POSIX)
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

FrameParser::FrameParser()
    : state_(State::READING_HEADER),
      bytes_needed_(2),
      bytes_read_(0),
      temp_buffer_pos_(0) {
}

FrameParser::~FrameParser() = default;

int FrameParser::parse_frame(
    const uint8_t* data,
    size_t length,
    size_t& consumed,
    FrameHeader& header,
    const uint8_t*& payload_start,
    size_t& payload_length
) {
    consumed = 0;
    const uint8_t* ptr = data;
    size_t remaining = length;
    
    while (remaining > 0 && state_ != State::COMPLETE && state_ != State::ERROR) {
        switch (state_) {
            case State::READING_HEADER: {
                if (remaining < 2) {
                    return -1;  // Need more data
                }
                
                // Parse first two bytes
                uint8_t byte0 = ptr[0];
                uint8_t byte1 = ptr[1];
                
                current_header_.fin = (byte0 & 0x80) != 0;
                current_header_.rsv1 = (byte0 & 0x40) != 0;
                current_header_.rsv2 = (byte0 & 0x20) != 0;
                current_header_.rsv3 = (byte0 & 0x10) != 0;
                current_header_.opcode = static_cast<OpCode>(byte0 & 0x0F);
                current_header_.mask = (byte1 & 0x80) != 0;
                
                uint8_t payload_len = byte1 & 0x7F;
                
                ptr += 2;
                remaining -= 2;
                consumed += 2;
                
                // Determine payload length
                if (payload_len < 126) {
                    current_header_.payload_length = payload_len;
                    state_ = current_header_.mask ? State::READING_MASKING_KEY : State::READING_PAYLOAD;
                } else if (payload_len == 126) {
                    state_ = State::READING_PAYLOAD_LENGTH_16;
                    bytes_needed_ = 2;
                    temp_buffer_pos_ = 0;
                } else {  // 127
                    state_ = State::READING_PAYLOAD_LENGTH_64;
                    bytes_needed_ = 8;
                    temp_buffer_pos_ = 0;
                }
                break;
            }
            
            case State::READING_PAYLOAD_LENGTH_16: {
                size_t to_copy = std::min(bytes_needed_ - temp_buffer_pos_, remaining);
                std::memcpy(temp_buffer_ + temp_buffer_pos_, ptr, to_copy);
                temp_buffer_pos_ += to_copy;
                ptr += to_copy;
                remaining -= to_copy;
                consumed += to_copy;
                
                if (temp_buffer_pos_ == bytes_needed_) {
                    uint16_t len16;
                    std::memcpy(&len16, temp_buffer_, 2);
                    current_header_.payload_length = ntohs(len16);
                    state_ = current_header_.mask ? State::READING_MASKING_KEY : State::READING_PAYLOAD;
                    temp_buffer_pos_ = 0;
                }
                break;
            }
            
            case State::READING_PAYLOAD_LENGTH_64: {
                size_t to_copy = std::min(bytes_needed_ - temp_buffer_pos_, remaining);
                std::memcpy(temp_buffer_ + temp_buffer_pos_, ptr, to_copy);
                temp_buffer_pos_ += to_copy;
                ptr += to_copy;
                remaining -= to_copy;
                consumed += to_copy;
                
                if (temp_buffer_pos_ == bytes_needed_) {
                    uint64_t len64;
                    std::memcpy(&len64, temp_buffer_, 8);
                    current_header_.payload_length = be64toh(len64);
                    state_ = current_header_.mask ? State::READING_MASKING_KEY : State::READING_PAYLOAD;
                    temp_buffer_pos_ = 0;
                }
                break;
            }
            
            case State::READING_MASKING_KEY: {
                size_t to_copy = std::min(4 - temp_buffer_pos_, remaining);
                std::memcpy(current_header_.masking_key + temp_buffer_pos_, ptr, to_copy);
                temp_buffer_pos_ += to_copy;
                ptr += to_copy;
                remaining -= to_copy;
                consumed += to_copy;
                
                if (temp_buffer_pos_ == 4) {
                    state_ = State::READING_PAYLOAD;
                    temp_buffer_pos_ = 0;
                }
                break;
            }
            
            case State::READING_PAYLOAD: {
                // Payload starts here
                header = current_header_;
                payload_start = ptr;
                payload_length = std::min(current_header_.payload_length, static_cast<uint64_t>(remaining));
                consumed += payload_length;
                state_ = State::COMPLETE;
                return 0;  // Success
            }
            
            default:
                return -2;  // Error
        }
    }
    
    if (state_ == State::COMPLETE) {
        return 0;
    }

    // Handle zero-length payload case: we may have consumed all header/mask bytes
    // but the while loop exits before entering READING_PAYLOAD when remaining=0
    if (state_ == State::READING_PAYLOAD && current_header_.payload_length == 0) {
        header = current_header_;
        payload_start = nullptr;  // No payload
        payload_length = 0;
        state_ = State::COMPLETE;
        return 0;
    }

    return -1;  // Need more data
}

void FrameParser::unmask(
    uint8_t* data,
    size_t length,
    const uint8_t* masking_key,
    size_t offset
) {
    // High-performance unmasking inspired by uWebSockets approach
    // Process 8 bytes at a time when possible
    size_t i = 0;
    
    // Align to 8-byte boundary
    while (i < length && (i % 8) != 0) {
        data[i] ^= masking_key[(offset + i) % 4];
        i++;
    }
    
    // Process 8 bytes at a time
    uint64_t mask64 = 0;
    for (int j = 0; j < 8; j++) {
        mask64 |= static_cast<uint64_t>(masking_key[(offset + i + j) % 4]) << (j * 8);
    }
    
    while (i + 8 <= length) {
        uint64_t* data64 = reinterpret_cast<uint64_t*>(data + i);
        *data64 ^= mask64;
        i += 8;
    }
    
    // Process remaining bytes
    while (i < length) {
        data[i] ^= masking_key[(offset + i) % 4];
        i++;
    }
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
    if (length == 0) {
        code = CloseCode::NO_STATUS;
        return 0;
    }
    
    if (length < 2) {
        return -1;  // Invalid close frame
    }
    
    uint16_t code16;
    std::memcpy(&code16, payload, 2);
    code = static_cast<CloseCode>(ntohs(code16));
    
    if (length > 2) {
        reason.assign(reinterpret_cast<const char*>(payload + 2), length - 2);
        
        // Validate UTF-8
        if (!validate_utf8(payload + 2, length - 2)) {
            return -1;
        }
    }
    
    return 0;
}

bool FrameParser::validate_utf8(const uint8_t* data, size_t length) {
    // UTF-8 validation (our own implementation)
    size_t i = 0;
    while (i < length) {
        uint8_t byte = data[i];
        
        if ((byte & 0x80) == 0) {
            // Single-byte character (ASCII)
            i++;
        } else if ((byte & 0xE0) == 0xC0) {
            // Two-byte character
            if (i + 1 >= length || (data[i + 1] & 0xC0) != 0x80) {
                return false;
            }
            i += 2;
        } else if ((byte & 0xF0) == 0xE0) {
            // Three-byte character
            if (i + 2 >= length ||
                (data[i + 1] & 0xC0) != 0x80 ||
                (data[i + 2] & 0xC0) != 0x80) {
                return false;
            }
            i += 3;
        } else if ((byte & 0xF8) == 0xF0) {
            // Four-byte character
            if (i + 3 >= length ||
                (data[i + 1] & 0xC0) != 0x80 ||
                (data[i + 2] & 0xC0) != 0x80 ||
                (data[i + 3] & 0xC0) != 0x80) {
                return false;
            }
            i += 4;
        } else {
            return false;
        }
    }
    
    return true;
}

void FrameParser::reset() {
    state_ = State::READING_HEADER;
    bytes_needed_ = 2;
    bytes_read_ = 0;
    temp_buffer_pos_ = 0;
    current_header_ = FrameHeader();
}

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

} // namespace websocket
} // namespace bolt::api





