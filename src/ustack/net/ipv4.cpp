#include "ustack/net/ipv4.h"

#include <arpa/inet.h>

#include <algorithm>

#include "ustack/net/checksum.h"
#include "ustack/net/headers.h"
#include "ustack/util/log.h"

namespace ustack {

void Ipv4Layer::receive(ByteView data) {
    ++stats_.rx_packets;
    auto drop = [this](const char* why) {
        ++stats_.rx_dropped;
        log::debug("ip", "drop: {}", why);
    };

    auto header = read_struct<Ipv4Header>(data);
    if (!header) return drop("truncated header");
    if (header->version() != 4) return drop("not IPv4");

    const std::size_t header_len = header->header_length();
    const std::size_t total_len = ntohs(header->total_length);
    if (header_len < sizeof(Ipv4Header) || header_len > data.size()) return drop("bad header length");
    if (total_len < header_len || total_len > data.size()) return drop("bad total length");
    data = data.first(total_len);  // strip Ethernet padding

    if (internet_checksum(data.first(header_len)) != 0) return drop("bad header checksum");

    Ipv4Datagram datagram{
        .src = Ipv4Address::from_network(header->src),
        .dst = Ipv4Address::from_network(header->dst),
        .protocol = header->protocol,
        .ttl = header->ttl,
        .payload = data.subspan(header_len),
        .packet = data,
    };

    // We are a host, not a router: accept only what is addressed to us.
    if (datagram.dst != config_.ip && !config_.is_broadcast(datagram.dst)) return drop("not for us");

    log::trace("ip", "rx {} -> {} proto {} len {} ttl {}", datagram.src, datagram.dst, datagram.protocol, total_len,
               datagram.ttl);

    const std::uint16_t flags_fragment = ntohs(header->flags_fragment);
    const bool more_fragments = flags_fragment & kIpFlagMoreFragments;
    const std::size_t offset = static_cast<std::size_t>(flags_fragment & kIpFragmentOffsetMask) * 8;
    if (more_fragments || offset != 0) {
        reassemble(datagram, header_len, offset, more_fragments, ntohs(header->id));
        return;
    }
    deliver(datagram);
}

void Ipv4Layer::deliver(const Ipv4Datagram& datagram) {
    if (auto it = handlers_.find(datagram.protocol); it != handlers_.end()) {
        it->second(datagram);
    } else {
        log::debug("ip", "no handler for protocol {}", datagram.protocol);
        if (unknown_protocol_) unknown_protocol_(datagram);
    }
}

void Ipv4Layer::reassemble(const Ipv4Datagram& fragment, std::size_t header_len, std::size_t offset,
                           bool more_fragments, std::uint16_t id) {
    const FragmentKey key{fragment.src.value, fragment.dst.value, id, fragment.protocol};
    auto it = reassemblies_.find(key);
    if (it == reassemblies_.end()) {
        if (reassemblies_.size() >= kMaxReassemblies) {
            ++stats_.rx_dropped;
            log::warn("ip", "too many concurrent reassemblies; dropping fragment");
            return;
        }
        it = reassemblies_.emplace(key, Reassembly{}).first;
        it->second.expires = timers_.now() + kReassemblyTimeout;
        if (!sweep_timer_.armed()) sweep_timer_.arm(std::chrono::seconds(1), [this] { sweep_reassemblies(); });
    }
    Reassembly& r = it->second;

    const ByteView payload = fragment.payload;
    if (offset + payload.size() > 65535 - header_len) {
        ++stats_.rx_dropped;
        reassemblies_.erase(it);
        log::warn("ip", "oversized fragmented datagram from {}", fragment.src);
        return;
    }
    log::debug("ip", "fragment id {} offset {} len {}{}", id, offset, payload.size(), more_fragments ? " (MF)" : "");

    if (offset == 0) r.first_header.assign(fragment.packet.begin(), fragment.packet.begin() + header_len);
    if (!more_fragments) r.total_payload = offset + payload.size();
    r.pieces.try_emplace(offset, payload.begin(), payload.end());

    if (!r.total_payload || r.first_header.empty()) return;

    // Complete once the pieces cover [0, total) without holes.
    std::size_t covered = 0;
    for (const auto& [piece_offset, bytes] : r.pieces) {
        if (piece_offset > covered) return;
        covered = std::max(covered, piece_offset + bytes.size());
    }
    if (covered < *r.total_payload) return;

    const std::size_t hlen = r.first_header.size();
    const std::size_t total = *r.total_payload;
    Bytes packet = r.first_header;
    packet.resize(hlen + total);
    for (const auto& [piece_offset, bytes] : r.pieces) {
        const std::size_t n = std::min(bytes.size(), total - std::min(total, piece_offset));
        std::copy_n(bytes.begin(), n, packet.begin() + static_cast<std::ptrdiff_t>(hlen + piece_offset));
    }
    // Rewrite the header so it describes the whole, unfragmented datagram.
    packet[2] = static_cast<std::uint8_t>((hlen + total) >> 8);
    packet[3] = static_cast<std::uint8_t>(hlen + total);
    packet[6] = packet[7] = 0;
    packet[10] = packet[11] = 0;
    const std::uint16_t cs = internet_checksum(ByteView(packet).first(hlen));
    packet[10] = static_cast<std::uint8_t>(cs >> 8);
    packet[11] = static_cast<std::uint8_t>(cs);

    reassemblies_.erase(it);
    ++stats_.rx_reassembled;
    log::debug("ip", "reassembled datagram id {} ({} bytes)", id, total);

    Ipv4Datagram whole = fragment;
    whole.payload = ByteView(packet).subspan(hlen);
    whole.packet = packet;
    deliver(whole);
}

void Ipv4Layer::sweep_reassemblies() {
    const TimePoint now = timers_.now();
    std::erase_if(reassemblies_, [&](const auto& entry) {
        if (entry.second.expires > now) return false;
        log::debug("ip", "reassembly of id {} timed out", entry.first.id);
        return true;
    });
    if (!reassemblies_.empty()) sweep_timer_.arm(std::chrono::seconds(1), [this] { sweep_reassemblies(); });
}

std::optional<Ipv4Address> Ipv4Layer::route(Ipv4Address dst) const {
    if (config_.is_broadcast(dst) || config_.on_link(dst)) return dst;
    return config_.gateway;
}

bool Ipv4Layer::send(Ipv4Address dst, std::uint8_t protocol, ByteView payload) {
    const auto next_hop = route(dst);
    if (!next_hop) {
        log::warn("ip", "no route to {}", dst);
        return false;
    }
    if (payload.size() > 65535 - sizeof(Ipv4Header)) {
        log::warn("ip", "payload of {} bytes is too large for IPv4", payload.size());
        return false;
    }

    const std::uint16_t id = next_id_++;
    const std::size_t mtu_payload = max_payload();
    if (payload.size() <= mtu_payload) {
        ++stats_.tx_packets;
        arp_.send_ipv4(*next_hop, build_packet(dst, protocol, id, 0, payload));
        return true;
    }

    // Fragment: every fragment except the last carries a multiple of 8 bytes.
    const std::size_t chunk = mtu_payload & ~std::size_t{7};
    for (std::size_t offset = 0; offset < payload.size(); offset += chunk) {
        const std::size_t len = std::min(chunk, payload.size() - offset);
        const bool more = offset + len < payload.size();
        const auto field = static_cast<std::uint16_t>((more ? kIpFlagMoreFragments : 0) | (offset / 8));
        ++stats_.tx_fragments;
        arp_.send_ipv4(*next_hop, build_packet(dst, protocol, id, field, payload.subspan(offset, len)));
    }
    ++stats_.tx_packets;
    log::debug("ip", "fragmented {} bytes to {} into {} fragments", payload.size(), dst,
               (payload.size() + chunk - 1) / chunk);
    return true;
}

Bytes Ipv4Layer::build_packet(Ipv4Address dst, std::uint8_t protocol, std::uint16_t id, std::uint16_t flags_fragment,
                              ByteView payload) const {
    Ipv4Header h{};
    h.version_ihl = 0x45;  // version 4, 5 x 32-bit words (no options)
    h.total_length = htons(static_cast<std::uint16_t>(sizeof(h) + payload.size()));
    h.id = htons(id);
    h.flags_fragment = htons(flags_fragment);
    h.ttl = kDefaultTtl;
    h.protocol = protocol;
    h.src = config_.ip.to_network();
    h.dst = dst.to_network();
    h.checksum = htons(internet_checksum(struct_bytes(h)));

    Bytes packet;
    packet.reserve(sizeof(h) + payload.size());
    append_struct(packet, h);
    append(packet, payload);
    return packet;
}

}  // namespace ustack
