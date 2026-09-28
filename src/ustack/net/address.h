#pragma once

#include <arpa/inet.h>

#include <array>
#include <compare>
#include <cstdint>
#include <format>
#include <functional>
#include <optional>
#include <string>
#include <string_view>

namespace ustack {

struct MacAddress {
    std::array<std::uint8_t, 6> octets{};

    static constexpr MacAddress broadcast() { return {{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}}; }
    static constexpr MacAddress zero() { return {}; }
    static std::optional<MacAddress> parse(std::string_view text);
    static MacAddress from_bytes(const std::uint8_t* bytes);

    void copy_to(std::uint8_t* out) const;
    bool is_broadcast() const { return *this == broadcast(); }
    bool is_multicast() const { return (octets[0] & 0x01) != 0; }
    std::string to_string() const;

    friend bool operator==(const MacAddress&, const MacAddress&) = default;
};

// IPv4 address stored in *host* byte order; convert at the wire boundary only.
struct Ipv4Address {
    std::uint32_t value = 0;

    static constexpr Ipv4Address any() { return {0}; }
    static constexpr Ipv4Address broadcast() { return {0xffffffffu}; }
    static constexpr Ipv4Address from_octets(std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d) {
        return {(std::uint32_t{a} << 24) | (std::uint32_t{b} << 16) | (std::uint32_t{c} << 8) | d};
    }
    static std::optional<Ipv4Address> parse(std::string_view text);
    static Ipv4Address from_network(std::uint32_t network_order) { return {ntohl(network_order)}; }

    std::uint32_t to_network() const { return htonl(value); }
    std::string to_string() const;

    friend auto operator<=>(const Ipv4Address&, const Ipv4Address&) = default;
};

}  // namespace ustack

template <>
struct std::hash<ustack::MacAddress> {
    std::size_t operator()(const ustack::MacAddress& mac) const noexcept {
        std::uint64_t v = 0;
        for (auto b : mac.octets) v = (v << 8) | b;
        return std::hash<std::uint64_t>{}(v);
    }
};

template <>
struct std::hash<ustack::Ipv4Address> {
    std::size_t operator()(const ustack::Ipv4Address& ip) const noexcept { return std::hash<std::uint32_t>{}(ip.value); }
};

template <>
struct std::formatter<ustack::MacAddress> : std::formatter<std::string> {
    auto format(const ustack::MacAddress& mac, std::format_context& ctx) const {
        return std::formatter<std::string>::format(mac.to_string(), ctx);
    }
};

template <>
struct std::formatter<ustack::Ipv4Address> : std::formatter<std::string> {
    auto format(const ustack::Ipv4Address& ip, std::format_context& ctx) const {
        return std::formatter<std::string>::format(ip.to_string(), ctx);
    }
};
