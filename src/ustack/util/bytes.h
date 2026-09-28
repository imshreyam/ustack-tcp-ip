#pragma once

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace ustack {

using Bytes = std::vector<std::uint8_t>;
using ByteView = std::span<const std::uint8_t>;
using MutableByteView = std::span<std::uint8_t>;

// Copies a wire-format header out of a byte buffer. Using memcpy instead of
// reinterpret_cast'ing the buffer avoids unaligned access and strict-aliasing UB.
template <class T>
std::optional<T> read_struct(ByteView data) {
    static_assert(std::is_trivially_copyable_v<T>);
    if (data.size() < sizeof(T)) return std::nullopt;
    T value;
    std::memcpy(&value, data.data(), sizeof(T));
    return value;
}

template <class T>
void append_struct(Bytes& out, const T& value) {
    static_assert(std::is_trivially_copyable_v<T>);
    const auto* p = reinterpret_cast<const std::uint8_t*>(&value);
    out.insert(out.end(), p, p + sizeof(T));
}

template <class T>
ByteView struct_bytes(const T& value) {
    static_assert(std::is_trivially_copyable_v<T>);
    return {reinterpret_cast<const std::uint8_t*>(&value), sizeof(T)};
}

inline void append(Bytes& out, ByteView data) { out.insert(out.end(), data.begin(), data.end()); }

inline ByteView as_bytes(std::string_view text) {
    return {reinterpret_cast<const std::uint8_t*>(text.data()), text.size()};
}

inline std::string to_hex(ByteView data, std::size_t max_bytes = 64) {
    std::string out;
    const std::size_t n = data.size() < max_bytes ? data.size() : max_bytes;
    for (std::size_t i = 0; i < n; ++i) {
        char buf[4];
        std::snprintf(buf, sizeof(buf), "%02x", data[i]);
        if (i != 0) out += ' ';
        out += buf;
    }
    if (n < data.size()) out += " ...";
    return out;
}

}  // namespace ustack
