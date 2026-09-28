#pragma once

#include <cstdint>
#include <functional>
#include <unordered_map>

#include "ustack/net/config.h"
#include "ustack/net/icmp.h"
#include "ustack/net/ipv4.h"

namespace ustack {

struct UdpStats {
    std::uint64_t rx_datagrams = 0;
    std::uint64_t rx_dropped = 0;
    std::uint64_t tx_datagrams = 0;
};

// UDP (RFC 768): checksum, header parsing, and port demultiplexing.
class UdpLayer {
public:
    using Handler = std::function<void(Ipv4Address src_ip, std::uint16_t src_port, std::uint16_t dst_port,
                                       ByteView data)>;

    UdpLayer(const InterfaceConfig& config, Ipv4Layer& ipv4, IcmpLayer& icmp)
        : config_(config), ipv4_(ipv4), icmp_(icmp) {}

    bool bind(std::uint16_t port, Handler handler);
    void unbind(std::uint16_t port) { bindings_.erase(port); }

    bool send_to(std::uint16_t src_port, Ipv4Address dst, std::uint16_t dst_port, ByteView data);

    void receive(const Ipv4Datagram& datagram);

    const UdpStats& stats() const noexcept { return stats_; }

private:
    const InterfaceConfig& config_;
    Ipv4Layer& ipv4_;
    IcmpLayer& icmp_;
    std::unordered_map<std::uint16_t, Handler> bindings_;
    UdpStats stats_;
};

}  // namespace ustack
