#include "ustack/net/icmp.h"

#include <arpa/inet.h>

#include <algorithm>

#include "ustack/net/checksum.h"
#include "ustack/net/headers.h"
#include "ustack/util/log.h"

namespace ustack {

void IcmpLayer::receive(const Ipv4Datagram& datagram) {
    const ByteView message = datagram.payload;
    auto header = read_struct<IcmpHeader>(message);
    if (!header) {
        log::debug("icmp", "truncated message from {}", datagram.src);
        return;
    }
    if (internet_checksum(message) != 0) {
        log::debug("icmp", "bad checksum from {}", datagram.src);
        return;
    }

    switch (header->type) {
        case icmp_type::kEchoRequest: {
            if (datagram.dst != config_.ip) return;  // ignore broadcast pings (like Linux does)
            log::info("icmp", "echo request from {} id={} seq={} ({} bytes)", datagram.src, ntohs(header->id),
                      ntohs(header->sequence), message.size() - sizeof(IcmpHeader));
            // The reply is the request with the type changed: same id, sequence and payload.
            Bytes reply(message.begin(), message.end());
            reply[0] = icmp_type::kEchoReply;
            send_message(datagram.src, std::move(reply));
            break;
        }
        case icmp_type::kEchoReply:
            log::debug("icmp", "echo reply from {} seq={}", datagram.src, ntohs(header->sequence));
            if (on_echo_reply_) {
                on_echo_reply_(datagram.src, ntohs(header->id), ntohs(header->sequence),
                               message.subspan(sizeof(IcmpHeader)));
            }
            break;
        case icmp_type::kDestinationUnreachable:
            log::warn("icmp", "destination unreachable (code {}) reported by {}", header->code, datagram.src);
            break;
        default:
            log::debug("icmp", "ignoring type {} from {}", header->type, datagram.src);
            break;
    }
}

void IcmpLayer::send_echo_request(Ipv4Address dst, std::uint16_t id, std::uint16_t sequence, ByteView data) {
    IcmpHeader header{};
    header.type = icmp_type::kEchoRequest;
    header.id = htons(id);
    header.sequence = htons(sequence);
    Bytes message;
    append_struct(message, header);
    append(message, data);
    send_message(dst, std::move(message));
}

void IcmpLayer::send_destination_unreachable(std::uint8_t code, const Ipv4Datagram& original) {
    // RFC 1122 3.2.2: never answer broadcasts or ICMP errors with ICMP errors.
    if (original.dst != config_.ip || original.protocol == ip_protocol::kIcmp) return;

    IcmpHeader header{};
    header.type = icmp_type::kDestinationUnreachable;
    header.code = code;
    Bytes message;
    append_struct(message, header);
    // Include the offending IP header plus the first 8 bytes of its payload.
    const std::size_t header_len = static_cast<std::size_t>(original.packet[0] & 0x0f) * 4;
    append(message, original.packet.first(std::min(original.packet.size(), header_len + 8)));
    log::debug("icmp", "sending destination unreachable (code {}) to {}", code, original.src);
    send_message(original.src, std::move(message));
}

void IcmpLayer::send_message(Ipv4Address dst, Bytes message) {
    message[2] = message[3] = 0;
    const std::uint16_t cs = internet_checksum(message);
    message[2] = static_cast<std::uint8_t>(cs >> 8);
    message[3] = static_cast<std::uint8_t>(cs);
    ipv4_.send(dst, ip_protocol::kIcmp, message);
}

}  // namespace ustack
