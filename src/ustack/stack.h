#pragma once

#include "ustack/core/timer.h"
#include "ustack/net/arp.h"
#include "ustack/net/config.h"
#include "ustack/net/ethernet.h"
#include "ustack/net/icmp.h"
#include "ustack/net/ipv4.h"
#include "ustack/net/tcp.h"
#include "ustack/net/udp.h"

namespace ustack {

// The whole stack wired together:
//
//   app  ->  TCP / UDP / ICMP  ->  IPv4  ->  ARP  ->  Ethernet  ->  FrameSink
//
// The stack knows nothing about TAP devices or real time. Frames go in via
// receive_frame(), come out via the FrameSink, and time comes from the
// TimerQueue; which is exactly what lets tests wire two stacks together.
//
// The TimerQueue must outlive the Stack.
class Stack {
public:
    Stack(const InterfaceConfig& config, TimerQueue& timers, EthernetLayer::FrameSink sink);

    Stack(const Stack&) = delete;
    Stack& operator=(const Stack&) = delete;

    // Announces our address (gratuitous ARP).
    void start() { arp_.announce(); }

    void receive_frame(ByteView frame) { ethernet_.receive(frame); }

    const InterfaceConfig& config() const noexcept { return config_; }
    TimerQueue& timers() noexcept { return timers_; }
    EthernetLayer& ethernet() noexcept { return ethernet_; }
    ArpLayer& arp() noexcept { return arp_; }
    Ipv4Layer& ipv4() noexcept { return ipv4_; }
    IcmpLayer& icmp() noexcept { return icmp_; }
    UdpLayer& udp() noexcept { return udp_; }
    TcpLayer& tcp() noexcept { return tcp_; }

private:
    InterfaceConfig config_;
    TimerQueue& timers_;
    EthernetLayer ethernet_;
    ArpLayer arp_;
    Ipv4Layer ipv4_;
    IcmpLayer icmp_;
    UdpLayer udp_;
    TcpLayer tcp_;
};

}  // namespace ustack
