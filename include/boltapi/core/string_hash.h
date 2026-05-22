/**
 * @file string_hash.h
 * @brief Transparent hash for heterogeneous string lookups
 *
 * Enables O(1) lookups in unordered_map<string, T> using string_view
 * or const char* without creating temporary std::string objects.
 *
 * C++20 heterogeneous lookup requires both a transparent hash (with
 * is_transparent tag) and a transparent equality comparator (std::equal_to<>).
 *
 * Usage:
 *   std::unordered_map<std::string, int, StringHash, std::equal_to<>> map;
 *   map["hello"] = 42;
 *   auto it = map.find(std::string_view("hello"));  // No allocation!
 *   auto it2 = map.find("hello");                   // No allocation!
 *
 * References:
 * - https://www.cppstories.com/2021/heterogeneous-access-cpp20/
 * - https://en.cppreference.com/w/cpp/container/unordered_map/find
 */

#pragma once

#include <string>
#include <string_view>
#include <functional>

namespace bolt::api {
namespace core {

/**
 * Transparent hash functor for string types.
 *
 * The is_transparent tag enables heterogeneous lookup in C++20 unordered
 * containers, allowing find() to accept any string-like type without
 * constructing a temporary std::string.
 */
struct StringHash {
    using hash_type = std::hash<std::string_view>;
    using is_transparent = void;

    [[nodiscard]] size_t operator()(const char* str) const noexcept {
        return hash_type{}(str);
    }

    [[nodiscard]] size_t operator()(std::string_view str) const noexcept {
        return hash_type{}(str);
    }

    [[nodiscard]] size_t operator()(const std::string& str) const noexcept {
        return hash_type{}(str);
    }
};

/**
 * Type alias for string-keyed unordered_map with heterogeneous lookup.
 *
 * Usage:
 *   StringMap<int> my_map;
 *   my_map["key"] = 42;
 *   auto it = my_map.find(std::string_view("key"));  // No allocation
 */
template<typename T>
using StringMap = std::unordered_map<std::string, T, StringHash, std::equal_to<>>;

} // namespace core
} // namespace bolt::api
