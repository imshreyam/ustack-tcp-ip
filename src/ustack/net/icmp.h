#pragma once

#include <cstdint>
#include <functional>

#include "ustack/net/config.h"
#include "ustack/net/ipv4.h"

namespace ustack {

namespace icmp_type {
inline constexpr std::uint8_t kEchoReply = 0;
inline constexpr std::uint8_t kDestinationUnreachable = 3;
inline constexpr std::uint8_t kEchoRequest = 8;
}  // namespace icmp_type

namespace icmp_unreachable {
inline constexpr std::uint8_t kProtocol = 2;
inline constexpr std::uint8_t kPort = 3;
}  // namespace icmp_unreachable

// ICMP (RFC 792): answers pings, can send pings, and reports errors such as
// "port unreachable" back to senders.
class IcmpLayer {
public:
    using EchoReplyHandler =
        std::function<void(Ipv4Address from, std::uint16_t id, std::uint16_t sequence, ByteView data)>;

    IcmpLayer(const InterfaceConfig& config, Ipv4Layer& ipv4) : config_(config), ipv4_(ipv4) {}

    void receive(const Ipv4Datagram& datagram);

    void send_echo_request(Ipv4Address dst, std::uint16_t id, std::uint16_t sequence, ByteView data);
    void send_destination_unreachable(std::uint8_t code, const Ipv4Datagram& original);

    void set_echo_reply_handler(EchoReplyHandler handler) { on_echo_reply_ = std::move(handler); }

private:
    void send_message(Ipv4Address dst, Bytes message);

    const InterfaceConfig& config_;
    Ipv4Layer& ipv4_;
    EchoReplyHandler on_echo_reply_;
};

}  // namespace ustack
