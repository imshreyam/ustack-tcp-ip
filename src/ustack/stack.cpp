#include "ustack/stack.h"

#include "ustack/net/headers.h"

namespace ustack {

Stack::Stack(const InterfaceConfig& config, TimerQueue& timers, EthernetLayer::FrameSink sink)
    : config_(config),
      timers_(timers),
      ethernet_(config_.mac, std::move(sink)),
      arp_(config_, ethernet_, timers_),
      ipv4_(config_, timers_, arp_),
      icmp_(config_, ipv4_),
      udp_(config_, ipv4_, icmp_),
      tcp_(config_, timers_, ipv4_) {
    ethernet_.register_handler(ethertype::kArp, [this](ByteView p) { arp_.receive(p); });
    ethernet_.register_handler(ethertype::kIpv4, [this](ByteView p) { ipv4_.receive(p); });

    ipv4_.register_protocol(ip_protocol::kIcmp, [this](const Ipv4Datagram& d) { icmp_.receive(d); });
    ipv4_.register_protocol(ip_protocol::kUdp, [this](const Ipv4Datagram& d) { udp_.receive(d); });
    ipv4_.register_protocol(ip_protocol::kTcp, [this](const Ipv4Datagram& d) { tcp_.receive(d); });
    ipv4_.set_unknown_protocol_handler([this](const Ipv4Datagram& d) {
        icmp_.send_destination_unreachable(icmp_unreachable::kProtocol, d);
    });
}

}  // namespace ustack
