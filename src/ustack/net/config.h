#pragma once

#include <cstddef>
#include <optional>

#include "ustack/net/address.h"

namespace ustack {

// Configuration of the stack's single network interface.
struct InterfaceConfig {
    MacAddress mac = {{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}};  // locally administered
    Ipv4Address ip = Ipv4Address::from_octets(10, 0, 0, 2);
    Ipv4Address netmask = Ipv4Address::from_octets(255, 255, 255, 0);
    std::optional<Ipv4Address> gateway;
    std::size_t mtu = 1500;  // max IP packet size (Ethernet payload)

    bool on_link(Ipv4Address addr) const { return (addr.value & netmask.value) == (ip.value & netmask.value); }
    Ipv4Address subnet_broadcast() const { return {ip.value | ~netmask.value}; }
    bool is_broadcast(Ipv4Address addr) const {
        return addr == Ipv4Address::broadcast() || addr == subnet_broadcast();
    }
};

}  // namespace ustack
