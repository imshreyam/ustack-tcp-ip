#include "ustack/net/udp.h"

#include <arpa/inet.h>

#include "ustack/net/checksum.h"
#include "ustack/net/headers.h"
#include "ustack/util/log.h"

namespace ustack {

bool UdpLayer::bind(std::uint16_t port, Handler handler) {
    auto [it, inserted] = bindings_.try_emplace(port, std::move(handler));
    if (!inserted) log::warn("udp", "port {} is already bound", port);
    return inserted;
}

bool UdpLayer::send_to(std::uint16_t src_port, Ipv4Address dst, std::uint16_t dst_port, ByteView data) {
    const std::size_t length = sizeof(UdpHeader) + data.size();
    if (length > 65535 - 20) return false;

    UdpHeader header{};
    header.src_port = htons(src_port);
    header.dst_port = htons(dst_port);
    header.length = htons(static_cast<std::uint16_t>(length));

    Bytes datagram;
    datagram.reserve(length);
    append_struct(datagram, header);
    append(datagram, data);

    const auto sum = checksum_accumulate(
        datagram, pseudo_header_sum(config_.ip, dst, ip_protocol::kUdp, static_cast<std::uint16_t>(length)));
    std::uint16_t cs = checksum_finish(sum);
    if (cs == 0) cs = 0xffff;  // 0 means "no checksum" in UDP, so send the equivalent all-ones
    datagram[6] = static_cast<std::uint8_t>(cs >> 8);
    datagram[7] = static_cast<std::uint8_t>(cs);

    ++stats_.tx_datagrams;
    return ipv4_.send(dst, ip_protocol::kUdp, datagram);
}

void UdpLayer::receive(const Ipv4Datagram& datagram) {
    ++stats_.rx_datagrams;
    auto header = read_struct<UdpHeader>(datagram.payload);
    const std::size_t length = header ? ntohs(header->length) : 0;
    if (!header || length < sizeof(UdpHeader) || length > datagram.payload.size()) {
        ++stats_.rx_dropped;
        log::debug("udp", "malformed datagram from {}", datagram.src);
        return;
    }
    const ByteView bytes = datagram.payload.first(length);

    if (header->checksum != 0) {  // checksum is optional over IPv4
        const auto sum = checksum_accumulate(
            bytes, pseudo_header_sum(datagram.src, datagram.dst, ip_protocol::kUdp, static_cast<std::uint16_t>(length)));
        if (checksum_finish(sum) != 0) {
            ++stats_.rx_dropped;
            log::debug("udp", "bad checksum from {}", datagram.src);
            return;
        }
    }

    const std::uint16_t src_port = ntohs(header->src_port);
    const std::uint16_t dst_port = ntohs(header->dst_port);
    log::debug("udp", "{}:{} -> port {} ({} bytes)", datagram.src, src_port, dst_port, length - sizeof(UdpHeader));

    auto it = bindings_.find(dst_port);
    if (it == bindings_.end()) {
        ++stats_.rx_dropped;
        icmp_.send_destination_unreachable(icmp_unreachable::kPort, datagram);
        return;
    }
    it->second(datagram.src, src_port, dst_port, bytes.subspan(sizeof(UdpHeader)));
}

}  // namespace ustack
