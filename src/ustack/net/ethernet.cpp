#include "ustack/net/ethernet.h"

#include <arpa/inet.h>

#include "ustack/net/headers.h"
#include "ustack/util/log.h"

namespace ustack {

namespace {
const char* ethertype_name(std::uint16_t type) {
    switch (type) {
        case ethertype::kIpv4: return "IPv4";
        case ethertype::kArp: return "ARP";
        case ethertype::kIpv6: return "IPv6";
        default: return "unknown";
    }
}
}  // namespace

void EthernetLayer::receive(ByteView frame) {
    ++stats_.rx_frames;
    stats_.rx_bytes += frame.size();

    auto header = read_struct<EthernetHeader>(frame);
    if (!header) {
        ++stats_.rx_dropped;
        log::debug("eth", "runt frame ({} bytes)", frame.size());
        return;
    }
    const MacAddress dst = MacAddress::from_bytes(header->dst);
    const MacAddress src = MacAddress::from_bytes(header->src);
    const std::uint16_t type = ntohs(header->ethertype);

    log::trace("eth", "rx {} -> {} type 0x{:04x} ({}) len {}", src, dst, type, ethertype_name(type), frame.size());

    // We only accept frames addressed to us or broadcast. (Multicast such as
    // IPv6 neighbour discovery from the host is ignored.)
    if (dst != mac_ && !dst.is_broadcast()) {
        ++stats_.rx_dropped;
        return;
    }

    auto it = handlers_.find(type);
    if (it == handlers_.end()) {
        ++stats_.rx_dropped;
        log::trace("eth", "no handler for ethertype 0x{:04x} ({})", type, ethertype_name(type));
        return;
    }
    it->second(frame.subspan(sizeof(EthernetHeader)));
}

void EthernetLayer::send(MacAddress dst, std::uint16_t ethertype, ByteView payload) {
    EthernetHeader header{};
    dst.copy_to(header.dst);
    mac_.copy_to(header.src);
    header.ethertype = htons(ethertype);

    Bytes frame;
    frame.reserve(sizeof(header) + payload.size());
    append_struct(frame, header);
    append(frame, payload);
    if (frame.size() < kMinFrameSize) frame.resize(kMinFrameSize, 0);  // pad short frames

    ++stats_.tx_frames;
    stats_.tx_bytes += frame.size();
    log::trace("eth", "tx {} -> {} type 0x{:04x} len {}", mac_, dst, ethertype, frame.size());
    sink_(frame);
}

}  // namespace ustack
