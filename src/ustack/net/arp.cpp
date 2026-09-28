#include "ustack/net/arp.h"

#include <arpa/inet.h>

#include "ustack/net/headers.h"
#include "ustack/util/log.h"

namespace ustack {

namespace {
constexpr std::uint16_t kHardwareEthernet = 1;
constexpr std::uint16_t kOpRequest = 1;
constexpr std::uint16_t kOpReply = 2;
}  // namespace

void ArpLayer::receive(ByteView data) {
    auto pkt = read_struct<ArpPacket>(data);
    if (!pkt || ntohs(pkt->hardware_type) != kHardwareEthernet || ntohs(pkt->protocol_type) != ethertype::kIpv4 ||
        pkt->hardware_len != 6 || pkt->protocol_len != 4) {
        log::debug("arp", "dropping malformed/unsupported ARP packet");
        return;
    }

    const std::uint16_t op = ntohs(pkt->operation);
    const MacAddress sender_mac = MacAddress::from_bytes(pkt->sender_mac);
    const Ipv4Address sender_ip = Ipv4Address::from_network(pkt->sender_ip);
    const Ipv4Address target_ip = Ipv4Address::from_network(pkt->target_ip);

    log::debug("arp", "{} {} ({}) -> {}", op == kOpRequest ? "who-has" : "is-at", sender_ip, sender_mac, target_ip);

    // RFC 826 "packet reception" algorithm: refresh an existing entry for the
    // sender, and only add a *new* entry when the packet is aimed at us.
    const bool known_sender = sender_ip != Ipv4Address::any() && cache_.contains(sender_ip);
    if (known_sender) update_cache(sender_ip, sender_mac);

    if (target_ip != config_.ip) return;

    if (!known_sender && sender_ip != Ipv4Address::any()) update_cache(sender_ip, sender_mac);

    if (op == kOpRequest) {
        log::debug("arp", "replying: {} is-at {}", config_.ip, config_.mac);
        send_arp(kOpReply, sender_mac, sender_mac, sender_ip);
    }
}

void ArpLayer::send_ipv4(Ipv4Address next_hop, Bytes packet) {
    if (config_.is_broadcast(next_hop)) {
        ethernet_.send(MacAddress::broadcast(), ethertype::kIpv4, packet);
        return;
    }
    if (auto mac = lookup(next_hop)) {
        ethernet_.send(*mac, ethertype::kIpv4, packet);
        return;
    }

    auto [it, inserted] = pending_.try_emplace(next_hop, timers_);
    PendingResolution& pending = it->second;
    if (pending.packets.size() >= kMaxQueuedPackets) pending.packets.pop_front();
    pending.packets.push_back(std::move(packet));
    if (inserted) send_request(next_hop, pending);
}

std::optional<MacAddress> ArpLayer::lookup(Ipv4Address ip) {
    auto it = cache_.find(ip);
    if (it == cache_.end()) return std::nullopt;
    if (it->second.expires <= timers_.now()) {
        log::debug("arp", "cache entry for {} expired", ip);
        cache_.erase(it);
        return std::nullopt;
    }
    return it->second.mac;
}

void ArpLayer::announce() {
    log::info("arp", "announcing {} is-at {}", config_.ip, config_.mac);
    send_arp(kOpRequest, MacAddress::broadcast(), MacAddress::zero(), config_.ip);
}

void ArpLayer::send_arp(std::uint16_t operation, MacAddress eth_dst, MacAddress target_mac, Ipv4Address target_ip) {
    ArpPacket pkt{};
    pkt.hardware_type = htons(kHardwareEthernet);
    pkt.protocol_type = htons(ethertype::kIpv4);
    pkt.hardware_len = 6;
    pkt.protocol_len = 4;
    pkt.operation = htons(operation);
    config_.mac.copy_to(pkt.sender_mac);
    pkt.sender_ip = config_.ip.to_network();
    target_mac.copy_to(pkt.target_mac);
    pkt.target_ip = target_ip.to_network();
    ethernet_.send(eth_dst, ethertype::kArp, struct_bytes(pkt));
}

void ArpLayer::send_request(Ipv4Address target, PendingResolution& pending) {
    ++pending.requests_sent;
    log::debug("arp", "who-has {}? (attempt {}/{})", target, pending.requests_sent, kMaxRequests);
    send_arp(kOpRequest, MacAddress::broadcast(), MacAddress::zero(), target);
    pending.retry_timer.arm(kRequestInterval, [this, target] { on_retry(target); });
}

void ArpLayer::on_retry(Ipv4Address target) {
    auto it = pending_.find(target);
    if (it == pending_.end()) return;
    if (it->second.requests_sent >= kMaxRequests) {
        log::warn("arp", "{} did not answer; dropping {} queued packet(s)", target, it->second.packets.size());
        pending_.erase(it);
        return;
    }
    send_request(target, it->second);
}

void ArpLayer::update_cache(Ipv4Address ip, MacAddress mac) {
    auto [it, inserted] = cache_.insert_or_assign(ip, CacheEntry{mac, timers_.now() + kEntryLifetime});
    if (inserted) log::info("arp", "learned {} is-at {}", ip, mac);

    // Flush packets that were waiting for this resolution.
    if (auto p = pending_.find(ip); p != pending_.end()) {
        std::deque<Bytes> packets = std::move(p->second.packets);
        pending_.erase(p);
        for (auto& packet : packets) ethernet_.send(mac, ethertype::kIpv4, packet);
    }
}

}  // namespace ustack
