#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <random>
#include <unordered_map>

#include "ustack/core/timer.h"
#include "ustack/net/config.h"
#include "ustack/net/ipv4.h"
#include "ustack/net/tcp_connection.h"
#include "ustack/net/tcp_types.h"

namespace ustack {

struct TcpStats {
    std::uint64_t rx_segments = 0;
    std::uint64_t rx_dropped = 0;
    std::uint64_t tx_segments = 0;
    std::uint64_t retransmitted_segments = 0;
    std::uint64_t resets_sent = 0;
    std::uint64_t connections_accepted = 0;
};

// Layer 4 (TCP): segment parsing/checksums, the connection table keyed by
// 4-tuple, listening sockets, and segment transmission.
class TcpLayer {
public:
    using AcceptHandler = TcpConnection::AcceptHandler;

    static constexpr std::size_t kMaxConnections = 1024;

    TcpLayer(const InterfaceConfig& config, TimerQueue& timers, Ipv4Layer& ipv4);

    // Passive open: `on_accept` runs for every connection that completes the handshake.
    bool listen(std::uint16_t port, AcceptHandler on_accept);
    void unlisten(std::uint16_t port) { listeners_.erase(port); }

    // Active open: returns immediately in SYN_SENT; see set_on_connected().
    std::shared_ptr<TcpConnection> connect(Ipv4Address remote_ip, std::uint16_t remote_port);

    void receive(const Ipv4Datagram& datagram);

    const std::unordered_map<TcpTuple, std::shared_ptr<TcpConnection>>& connections() const noexcept {
        return connections_;
    }
    TcpStats& stats() noexcept { return stats_; }
    const TcpStats& stats() const noexcept { return stats_; }

    // ---- used by TcpConnection ----
    TimerQueue& timers() noexcept { return timers_; }
    std::uint32_t max_segment_size() const noexcept { return static_cast<std::uint32_t>(config_.mtu - 40); }
    std::uint32_t generate_iss() { return rng_(); }
    void transmit(const TcpTuple& tuple, std::uint32_t seq, std::uint32_t ack, std::uint8_t flags,
                  std::uint16_t window, ByteView payload, std::optional<std::uint16_t> mss = std::nullopt);
    // Removes a CLOSED connection from the table (deferred, so it is safe to
    // call from inside the connection's own member functions).
    void release(TcpConnection* connection);

private:
    void handle_listen(const TcpTuple& tuple, const TcpSegment& seg, const AcceptHandler& on_accept);
    void send_reset(const TcpTuple& tuple, const TcpSegment& seg);
    std::optional<std::uint16_t> allocate_ephemeral_port(Ipv4Address remote_ip, std::uint16_t remote_port);

    const InterfaceConfig& config_;
    TimerQueue& timers_;
    Ipv4Layer& ipv4_;
    std::unordered_map<TcpTuple, std::shared_ptr<TcpConnection>> connections_;
    std::unordered_map<std::uint16_t, AcceptHandler> listeners_;
    std::mt19937 rng_{std::random_device{}()};
    std::uint16_t next_ephemeral_port_ = 49152;
    TcpStats stats_;
};

}  // namespace ustack
