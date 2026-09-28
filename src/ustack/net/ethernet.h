#pragma once

#include <cstdint>
#include <functional>
#include <unordered_map>

#include "ustack/net/address.h"
#include "ustack/util/bytes.h"

namespace ustack {

struct EthernetStats {
    std::uint64_t rx_frames = 0;
    std::uint64_t rx_bytes = 0;
    std::uint64_t rx_dropped = 0;
    std::uint64_t tx_frames = 0;
    std::uint64_t tx_bytes = 0;
};

// Layer 2: frame parsing, MAC filtering, and demultiplexing by EtherType.
class EthernetLayer {
public:
    using FrameSink = std::function<void(ByteView frame)>;
    using Handler = std::function<void(ByteView payload)>;

    static constexpr std::size_t kMinFrameSize = 60;  // without FCS

    EthernetLayer(MacAddress mac, FrameSink sink) : mac_(mac), sink_(std::move(sink)) {}

    void register_handler(std::uint16_t ethertype, Handler handler) { handlers_[ethertype] = std::move(handler); }

    void receive(ByteView frame);
    void send(MacAddress dst, std::uint16_t ethertype, ByteView payload);

    MacAddress mac() const noexcept { return mac_; }
    const EthernetStats& stats() const noexcept { return stats_; }

private:
    MacAddress mac_;
    FrameSink sink_;
    std::unordered_map<std::uint16_t, Handler> handlers_;
    EthernetStats stats_;
};

}  // namespace ustack
