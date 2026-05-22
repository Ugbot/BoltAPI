#pragma once

#include <cstdint>
#include <atomic>
#include <cstring>
#include <array>

namespace bolt::api {
namespace core {

// Cache line size for false-sharing avoidance. Previously pulled from
// core/lockfree_queue.h (cut from the fork); inlined here to sever that include.
inline constexpr size_t CACHE_LINE_SIZE = 64;

/**
 * Lock-free Single-Producer Single-Consumer (SPSC) Ring Buffer.
 *
 * Based on Aeron's buffer design:
 * - Zero-copy message passing
 * - Lock-free (single producer, single consumer)
 * - Cache-line padding to avoid false sharing
 * - Memory barriers for correctness
 *
 * Aeron approach:
 * - Separate read/write positions
 * - Atomic operations with memory ordering
 * - Padding to prevent false sharing
 * - Power-of-2 sizes for fast modulo
 *
 * Perfect for:
 * - Reactor → Worker communication
 * - Media frame buffers
 * - Event streaming
 *
 * Performance: <50ns write, <30ns read
 */

/**
 * SPSC Ring Buffer.
 * 
 * Single producer, single consumer ring buffer with:
 * - Lock-free operations
 * - Zero-copy (direct buffer access)
 * - Cache-line padding
 * - Memory order guarantees
 */
template<typename T, size_t N>
class SPSCRingBuffer {
public:
    static_assert((N & (N - 1)) == 0, "Size must be power of 2");
    
    SPSCRingBuffer()
        : write_pos_(0), read_pos_(0) {
    }
    
    /**
     * Try to write item to buffer.
     * 
     * @param item Item to write
     * @return true if written, false if buffer full
     */
    bool try_write(const T& item) noexcept {
        const uint64_t current_write = write_pos_.load(std::memory_order_relaxed);
        const uint64_t next_write = current_write + 1;
        
        // Check if buffer is full
        const uint64_t current_read = read_pos_.load(std::memory_order_acquire);
        if (next_write - current_read > N) {
            return false;  // Full
        }
        
        // Write item
        buffer_[current_write & (N - 1)] = item;
        
        // Publish write (release semantics ensures item is visible)
        write_pos_.store(next_write, std::memory_order_release);
        
        return true;
    }
    
    /**
     * Try to read item from buffer.
     * 
     * @param out_item Output item
     * @return true if read, false if buffer empty
     */
    bool try_read(T& out_item) noexcept {
        const uint64_t current_read = read_pos_.load(std::memory_order_relaxed);
        
        // Check if buffer is empty
        const uint64_t current_write = write_pos_.load(std::memory_order_acquire);
        if (current_read >= current_write) {
            return false;  // Empty
        }
        
        // Read item
        out_item = buffer_[current_read & (N - 1)];
        
        // Publish read (release semantics)
        read_pos_.store(current_read + 1, std::memory_order_release);
        
        return true;
    }
    
    /**
     * Get number of items available to read.
     */
    size_t size() const noexcept {
        const uint64_t current_write = write_pos_.load(std::memory_order_acquire);
        const uint64_t current_read = read_pos_.load(std::memory_order_acquire);
        return current_write - current_read;
    }
    
    /**
     * Check if buffer is empty.
     */
    bool empty() const noexcept {
        return size() == 0;
    }
    
    /**
     * Check if buffer is full.
     */
    bool full() const noexcept {
        const uint64_t current_write = write_pos_.load(std::memory_order_acquire);
        const uint64_t current_read = read_pos_.load(std::memory_order_acquire);
        return (current_write - current_read) >= N;
    }
    
    /**
     * Get capacity.
     */
    size_t capacity() const noexcept {
        return N;
    }
    
private:
    // Cache-line padding to prevent false sharing (Aeron technique)
    alignas(CACHE_LINE_SIZE) std::atomic<uint64_t> write_pos_;
    alignas(CACHE_LINE_SIZE) std::atomic<uint64_t> read_pos_;
    alignas(CACHE_LINE_SIZE) std::array<T, N> buffer_;
};

/**
 * Simple byte-oriented ring buffer for streaming data.
 *
 * Used for streaming TCP buffers, etc.
 * - Fixed-size circular buffer
 * - Continuous read/write operations
 * - No message framing
 * - Zero-copy peek operations
 *
 * Not thread-safe - caller must handle synchronization.
 */
class RingBuffer {
public:
    /**
     * Create ring buffer with specified capacity.
     *
     * @param capacity Buffer capacity in bytes
     */
    explicit RingBuffer(size_t capacity);

    /**
     * Destructor.
     */
    ~RingBuffer();

    // No copy
    RingBuffer(const RingBuffer&) = delete;
    RingBuffer& operator=(const RingBuffer&) = delete;

    /**
     * Write data to buffer.
     *
     * @param data Data to write
     * @param length Number of bytes to write
     * @return Number of bytes actually written (may be less if buffer full)
     */
    size_t write(const uint8_t* data, size_t length) noexcept;

    /**
     * Read data from buffer.
     *
     * @param buffer Output buffer
     * @param length Maximum bytes to read
     * @return Number of bytes actually read (may be less if buffer empty)
     */
    size_t read(uint8_t* buffer, size_t length) noexcept;

    /**
     * Peek at data without consuming it.
     *
     * @param buffer Output buffer
     * @param length Maximum bytes to peek
     * @return Number of bytes available
     */
    size_t peek(uint8_t* buffer, size_t length) const noexcept;

    /**
     * Discard bytes from buffer without reading.
     *
     * @param length Number of bytes to discard
     * @return Number of bytes actually discarded
     */
    size_t discard(size_t length) noexcept;

    /**
     * Get number of bytes available to read.
     */
    size_t available() const noexcept {
        return size_;
    }

    /**
     * Get number of bytes available to write.
     */
    size_t space() const noexcept {
        return capacity_ - size_;
    }

    /**
     * Get total capacity.
     */
    size_t capacity() const noexcept {
        return capacity_;
    }

    /**
     * Check if buffer is empty.
     */
    bool is_empty() const noexcept {
        return size_ == 0;
    }

    /**
     * Check if buffer is full.
     */
    bool is_full() const noexcept {
        return size_ == capacity_;
    }

    /**
     * Clear buffer (reset to empty state).
     */
    void clear() noexcept {
        head_ = 0;
        tail_ = 0;
        size_ = 0;
    }

    /**
     * Get read pointer for zero-copy access.
     *
     * @return Pointer to readable data (valid until next read/discard)
     */
    const uint8_t* read_ptr() const noexcept {
        return buffer_ + tail_;
    }

    /**
     * Get amount of contiguous data available from read_ptr.
     * May be less than available() if data wraps around buffer end.
     *
     * @return Number of contiguous bytes available for reading
     */
    size_t contiguous_available() const noexcept {
        if (size_ == 0) return 0;
        // If data wraps around, only return up to buffer end
        size_t to_end = capacity_ - tail_;
        return (to_end < size_) ? to_end : size_;
    }

    /**
     * Get write pointer for zero-copy writes.
     *
     * @return Pointer to writable area
     */
    uint8_t* write_ptr() noexcept {
        return buffer_ + head_;
    }

    /**
     * Get amount of contiguous space available for writing.
     *
     * @return Number of contiguous bytes available for writing
     */
    size_t contiguous_space() const noexcept {
        size_t free = capacity_ - size_;
        if (free == 0) return 0;
        // If write position wraps, only return up to buffer end
        size_t to_end = capacity_ - head_;
        return (to_end < free) ? to_end : free;
    }

    /**
     * Commit bytes written directly via write_ptr().
     *
     * @param bytes Number of bytes that were written
     */
    void commit_write(size_t bytes) noexcept {
        size_t actual = bytes;
        size_t free = capacity_ - size_;
        if (actual > free) actual = free;

        head_ = (head_ + actual) % capacity_;
        size_ += actual;
    }

    /**
     * Consume bytes without copying (after reading via read_ptr).
     *
     * @param bytes Number of bytes to consume
     */
    void consume(size_t bytes) noexcept {
        size_t actual = bytes;
        if (actual > size_) actual = size_;

        tail_ = (tail_ + actual) % capacity_;
        size_ -= actual;
    }

private:
    uint8_t* buffer_;   // Buffer storage
    size_t capacity_;   // Total capacity
    size_t head_;       // Write position
    size_t tail_;       // Read position
    size_t size_;       // Current data size
};

/**
 * Message buffer for variable-length messages.
 *
 * Based on Aeron's message framing:
 * - Length-prefixed messages
 * - Zero-copy via claim/commit
 * - Padding for alignment
 *
 * Frame format:
 *   [4 bytes: length] [N bytes: data] [padding]
 */
class MessageBuffer {
public:
    static constexpr size_t MAX_MESSAGE_SIZE = 65536;  // 64KB
    static constexpr size_t BUFFER_SIZE = 1048576;     // 1MB
    
    MessageBuffer();
    
    /**
     * Claim space for writing a message.
     * 
     * @param size Message size
     * @return Pointer to write buffer, or nullptr if insufficient space
     */
    uint8_t* claim(size_t size) noexcept;
    
    /**
     * Commit claimed message.
     * 
     * Makes the message visible to readers.
     * 
     * @param size Actual size written (may be less than claimed)
     */
    void commit(size_t size) noexcept;
    
    /**
     * Read next message.
     * 
     * @param out_data Pointer to message data (view into buffer)
     * @param out_size Message size
     * @return true if message read, false if buffer empty
     */
    bool read(const uint8_t** out_data, size_t* out_size) noexcept;
    
    /**
     * Get number of bytes available to read.
     */
    size_t available() const noexcept;
    
private:
    alignas(CACHE_LINE_SIZE) std::atomic<uint64_t> write_pos_;
    alignas(CACHE_LINE_SIZE) std::atomic<uint64_t> read_pos_;
    alignas(CACHE_LINE_SIZE) std::array<uint8_t, BUFFER_SIZE> buffer_;
    
    size_t claimed_size_{0};
};

} // namespace core
} // namespace bolt::api

