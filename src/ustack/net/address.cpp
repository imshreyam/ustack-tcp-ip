#include "ustack/net/address.h"

#include <charconv>
#include <cstdio>
#include <string>

namespace ustack {

std::optional<MacAddress> MacAddress::parse(std::string_view text) {
    MacAddress mac;
    std::size_t pos = 0;
    for (std::size_t i = 0; i < 6; ++i) {
        if (i != 0) {
            if (pos >= text.size() || (text[pos] != ':' && text[pos] != '-')) return std::nullopt;
            ++pos;
        }
        if (pos + 2 > text.size()) return std::nullopt;
        unsigned value = 0;
        auto [ptr, ec] = std::from_chars(text.data() + pos, text.data() + pos + 2, value, 16);
        if (ec != std::errc{} || ptr != text.data() + pos + 2) return std::nullopt;
        mac.octets[i] = static_cast<std::uint8_t>(value);
        pos += 2;
    }
    if (pos != text.size()) return std::nullopt;
    return mac;
}

MacAddress MacAddress::from_bytes(const std::uint8_t* bytes) {
    MacAddress mac;
    for (std::size_t i = 0; i < 6; ++i) mac.octets[i] = bytes[i];
    return mac;
}

void MacAddress::copy_to(std::uint8_t* out) const {
    for (std::size_t i = 0; i < 6; ++i) out[i] = octets[i];
}

std::string MacAddress::to_string() const {
    char buf[18];
    std::snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x", octets[0], octets[1], octets[2], octets[3],
                  octets[4], octets[5]);
    return buf;
}

std::optional<Ipv4Address> Ipv4Address::parse(std::string_view text) {
    const std::string s(text);
    in_addr addr{};
    if (::inet_pton(AF_INET, s.c_str(), &addr) != 1) return std::nullopt;
    return from_network(addr.s_addr);
}

std::string Ipv4Address::to_string() const {
    return std::to_string(value >> 24) + '.' + std::to_string((value >> 16) & 0xff) + '.' +
           std::to_string((value >> 8) & 0xff) + '.' + std::to_string(value & 0xff);
}

}  // namespace ustack
