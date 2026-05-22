#pragma once

#include <type_traits>
#include <utility>
#include <cstring>

namespace bolt::api {
namespace core {

/**
 * Error codes for result<T>.
 */
enum class error_code : int {
    success = 0,
    invalid_state = 1,
    timeout = 2,
    cancelled = 3,
    not_ready = 4,
    internal_error = 5,
    host_error = 6,
    http_error = 7,
    parse_error = 8
};

/**
 * Exception-free result type (like Rust's Result<T, E>).
 *
 * Either contains a value T or an error code. No exceptions, zero-cost abstraction.
 *
 * Usage:
 *   result<int> get_value() {
 *       if (error) return error_code::internal_error;
 *       return 42;
 *   }
 *
 *   result<int> r = get_value();
 *   if (r.is_ok()) {
 *       int value = r.value();
 *   } else {
 *       error_code err = r.error();
 *   }
 */
template<typename T>
class result {
public:
    /**
     * Default constructor creates an error result.
     * Needed for compatibility with future<result<T>>.
     */
    result() noexcept
        : has_value_(false), error_(error_code::invalid_state) {}

    /**
     * Construct from value (success case).
     */
    result(const T& val) noexcept(std::is_nothrow_copy_constructible_v<T>)
        : has_value_(true) {
        new (value_storage_) T(val);
    }

    result(T&& val) noexcept(std::is_nothrow_move_constructible_v<T>)
        : has_value_(true) {
        new (value_storage_) T(std::move(val));
    }

    /**
     * Construct from error code (error case).
     */
    result(error_code err) noexcept
        : has_value_(false), error_(err) {}

    /**
     * Move constructor.
     */
    result(result&& other) noexcept(std::is_nothrow_move_constructible_v<T>)
        : has_value_(other.has_value_), error_(other.error_) {
        if (has_value_) {
            new (value_storage_) T(std::move(other.value()));
            other.has_value_ = false;
        }
    }

    /**
     * Move assignment.
     */
    result& operator=(result&& other) noexcept(std::is_nothrow_move_constructible_v<T>) {
        if (this != &other) {
            if (has_value_) {
                value().~T();
            }
            has_value_ = other.has_value_;
            error_ = other.error_;
            if (has_value_) {
                new (value_storage_) T(std::move(other.value()));
                other.has_value_ = false;
            }
        }
        return *this;
    }

    /**
     * Destructor.
     */
    ~result() {
        if (has_value_) {
            value().~T();
        }
    }

    /**
     * Check if result contains a value.
     */
    bool is_ok() const noexcept { return has_value_; }

    /**
     * Check if result contains an error.
     */
    bool is_err() const noexcept { return !has_value_; }

    /**
     * Get the value (undefined behavior if is_err()).
     */
    T& value() & noexcept {
        return *reinterpret_cast<T*>(value_storage_);
    }

    const T& value() const& noexcept {
        return *reinterpret_cast<const T*>(value_storage_);
    }

    T&& value() && noexcept {
        return std::move(*reinterpret_cast<T*>(value_storage_));
    }

    /**
     * Get the error code (undefined behavior if is_ok()).
     */
    error_code error() const noexcept {
        return error_;
    }

    /**
     * Get value or default.
     */
    T value_or(T&& default_value) && noexcept {
        return has_value_ ? std::move(value()) : std::move(default_value);
    }

    /**
     * Explicit conversion to bool (true if ok).
     */
    explicit operator bool() const noexcept { return has_value_; }

private:
    alignas(T) unsigned char value_storage_[sizeof(T)];
    bool has_value_;
    error_code error_{error_code::success};
};

/**
 * Specialization for void (only indicates success/error).
 */
template<>
class result<void> {
public:
    result() noexcept : error_(error_code::success) {}
    result(error_code err) noexcept : error_(err) {}

    bool is_ok() const noexcept { return error_ == error_code::success; }
    bool is_err() const noexcept { return error_ != error_code::success; }
    error_code error() const noexcept { return error_; }

    explicit operator bool() const noexcept { return is_ok(); }

private:
    error_code error_;
};

/**
 * Helper to create ok result.
 */
template<typename T>
result<T> ok(T value) noexcept(std::is_nothrow_move_constructible_v<T>) {
    return result<T>(std::move(value));
}

inline result<void> ok() noexcept {
    return result<void>();
}

/**
 * Helper to create error result.
 */
template<typename T>
result<T> err(error_code code) noexcept {
    return result<T>(code);
}

inline result<void> err(error_code code) noexcept {
    return result<void>(code);
}

} // namespace core
} // namespace bolt::api
