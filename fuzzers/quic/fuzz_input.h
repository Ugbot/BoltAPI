// fuzz_input.h — bounded cursor over a fuzz input (no libFuzzer dependency,
// so the same harness builds in the replay-only Apple clang build).
#pragma once

#include <cassert>
#include <cstddef>
#include <cstdint>

namespace boltapi_fuzz {

class Input {
public:
    Input(const std::uint8_t* data, std::size_t size) noexcept
        : data_(data), size_(size) {
        assert((data != nullptr || size == 0) && "null input with size");
    }

    std::size_t remaining() const noexcept { return size_ - pos_; }
    bool empty() const noexcept { return pos_ >= size_; }

    std::uint8_t u8() noexcept {
        if (pos_ >= size_) return 0;
        return data_[pos_++];
    }
    std::uint16_t u16() noexcept {
        const std::uint16_t hi = u8();
        return static_cast<std::uint16_t>((hi << 8) | u8());
    }

    // Take up to `n` bytes; `out_len` gets the count actually available.
    const std::uint8_t* take(std::size_t n, std::size_t& out_len) noexcept {
        const std::size_t avail = remaining();
        out_len = n < avail ? n : avail;
        const std::uint8_t* p = data_ + pos_;
        pos_ += out_len;
        assert(pos_ <= size_ && "cursor overran input");
        return out_len > 0 ? p : nullptr;
    }

    // A length-prefixed chunk: u16 length (clamped to `cap`) then bytes.
    const std::uint8_t* chunk(std::size_t cap, std::size_t& out_len) noexcept {
        assert(cap > 0 && "zero chunk cap");
        std::size_t want = u16();
        if (want > cap) want %= (cap + 1);
        return take(want, out_len);
    }

private:
    const std::uint8_t* data_;
    std::size_t size_;
    std::size_t pos_ = 0;
};

}  // namespace boltapi_fuzz
