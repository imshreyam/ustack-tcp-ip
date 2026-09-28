#pragma once

#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <unordered_map>

#include "ustack/core/timer.h"
#include "ustack/net/address.h"
#include "ustack/net/arp.h"
#include "ustack/net/config.h"
#include "ustack/util/bytes.h"

namespace ustack {

// A received (and, if necessary, reassembled) IPv4 datagram. The views point
// into the receive buffer and are only valid during the handler call.
struct Ipv4Datagram {
    Ipv4Address src;
    Ipv4Address dst;
    std::uint8_t protocol = 0;
    std::uint8_t ttl = 0;
    ByteView payload;  // transport-layer bytes
    ByteView packet;   // full IP packet (header + payload), used for ICMP errors
};

struct Ipv4Stats {
    std::uint64_t rx_packets = 0;
    std::uint64_t rx_dropped = 0;
    std::uint64_t rx_reassembled = 0;
    std::uint64_t tx_packets = 0;
    std::uint64_t tx_fragments = 0;
};

// Layer 3: header validation, checksum, local delivery, fragment reassembly,
// fragmentation on send, and (single-interface) routing.
class Ipv4Layer {
public:
    using Handler = std::function<void(const Ipv4Datagram&)>;

    static constexpr std::uint8_t kDefaultTtl = 64;
    static constexpr Duration kReassemblyTimeout = std::chrono::seconds(30);
    static constexpr std::size_t kMaxReassemblies = 64;

    Ipv4Layer(const InterfaceConfig& config, TimerQueue& timers, ArpLayer& arp)
        : config_(config), timers_(timers), arp_(arp), sweep_timer_(timers) {}

    void register_protocol(std::uint8_t protocol, Handler handler) { handlers_[protocol] = std::move(handler); }
    void set_unknown_protocol_handler(Handler handler) { unknown_protocol_ = std::move(handler); }

    void receive(ByteView packet);

    // Sends `payload` to `dst`, fragmenting when it exceeds the MTU.
    bool send(Ipv4Address dst, std::uint8_t protocol, ByteView payload);

    // Next hop for `dst`: the host itself when on-link, else the gateway.
    std::optional<Ipv4Address> route(Ipv4Address dst) const;

    std::size_t max_payload() const noexcept { return config_.mtu - 20; }
    const Ipv4Stats& stats() const noexcept { return stats_; }

private:
    struct FragmentKey {
        std::uint32_t src;
        std::uint32_t dst;
        std::uint16_t id;
        std::uint8_t protocol;
        friend bool operator==(const FragmentKey&, const FragmentKey&) = default;
    };
    struct FragmentKeyHash {
        std::size_t operator()(const FragmentKey& k) const noexcept {
            std::uint64_t h = (std::uint64_t{k.src} << 32) ^ k.dst;
            h ^= (std::uint64_t{k.id} << 8 | k.protocol) * 0x9e3779b97f4a7c15ull;
            return std::hash<std::uint64_t>{}(h);
        }
    };
    struct Reassembly {
        std::map<std::size_t, Bytes> pieces;  // fragment offset -> payload bytes
        std::optional<std::size_t> total_payload;  // known once the last fragment (MF=0) arrives
        Bytes first_header;  // header of the offset-0 fragment
        TimePoint expires;
    };

    void deliver(const Ipv4Datagram& datagram);
    void reassemble(const Ipv4Datagram& fragment, std::size_t header_len, std::size_t offset, bool more_fragments,
                    std::uint16_t id);
    void sweep_reassemblies();
    Bytes build_packet(Ipv4Address dst, std::uint8_t protocol, std::uint16_t id, std::uint16_t flags_fragment,
                       ByteView payload) const;

    const InterfaceConfig& config_;
    TimerQueue& timers_;
    ArpLayer& arp_;
    std::unordered_map<std::uint8_t, Handler> handlers_;
    Handler unknown_protocol_;
    std::unordered_map<FragmentKey, Reassembly, FragmentKeyHash> reassemblies_;
    Timer sweep_timer_;
    std::uint16_t next_id_ = 1;
    Ipv4Stats stats_;
};

}  // namespace ustack
