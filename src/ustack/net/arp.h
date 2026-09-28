#pragma once

#include <chrono>
#include <deque>
#include <optional>
#include <unordered_map>

#include "ustack/core/timer.h"
#include "ustack/net/address.h"
#include "ustack/net/config.h"
#include "ustack/net/ethernet.h"
#include "ustack/util/bytes.h"

namespace ustack {

// ARP (RFC 826): answers "who has <our IP>?", resolves peer MACs, and caches
// the results. IPv4 packets for a next hop whose MAC is unknown are queued
// until the reply arrives (or dropped after a few unanswered requests).
class ArpLayer {
public:
    static constexpr Duration kEntryLifetime = std::chrono::seconds(60);
    static constexpr Duration kRequestInterval = std::chrono::seconds(1);
    static constexpr int kMaxRequests = 3;
    static constexpr std::size_t kMaxQueuedPackets = 32;

    struct CacheEntry {
        MacAddress mac;
        TimePoint expires;
    };

    ArpLayer(const InterfaceConfig& config, EthernetLayer& ethernet, TimerQueue& timers)
        : config_(config), ethernet_(ethernet), timers_(timers) {}

    void receive(ByteView packet);

    // Sends an IPv4 packet to `next_hop`, resolving its MAC first if needed.
    void send_ipv4(Ipv4Address next_hop, Bytes packet);

    std::optional<MacAddress> lookup(Ipv4Address ip);

    // Broadcasts a gratuitous ARP so neighbours learn (or refresh) our MAC.
    void announce();

    const std::unordered_map<Ipv4Address, CacheEntry>& cache() const noexcept { return cache_; }

private:
    struct PendingResolution {
        explicit PendingResolution(TimerQueue& timers) : retry_timer(timers) {}
        std::deque<Bytes> packets;
        int requests_sent = 0;
        Timer retry_timer;
    };

    void send_arp(std::uint16_t operation, MacAddress eth_dst, MacAddress target_mac, Ipv4Address target_ip);
    void send_request(Ipv4Address target, PendingResolution& pending);
    void on_retry(Ipv4Address target);
    void update_cache(Ipv4Address ip, MacAddress mac);

    const InterfaceConfig& config_;
    EthernetLayer& ethernet_;
    TimerQueue& timers_;
    std::unordered_map<Ipv4Address, CacheEntry> cache_;
    std::unordered_map<Ipv4Address, PendingResolution> pending_;
};

}  // namespace ustack
