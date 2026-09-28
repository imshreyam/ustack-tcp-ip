#include "ustack/net/tcp.h"

#include <arpa/inet.h>

#include "ustack/net/checksum.h"
#include "ustack/net/headers.h"
#include "ustack/util/log.h"

namespace ustack {

using namespace tcp_flag;

std::string tcp_flags_to_string(std::uint8_t flags) {
    std::string s;
    if (flags & kSyn) s += 'S';
    if (flags & kFin) s += 'F';
    if (flags & kRst) s += 'R';
    if (flags & kPsh) s += 'P';
    if (flags & kAck) s += '.';
    if (flags & kUrg) s += 'U';
    return s.empty() ? "none" : s;
}

const char* to_string(TcpState state) {
    switch (state) {
        case TcpState::Closed: return "CLOSED";
        case TcpState::Listen: return "LISTEN";
        case TcpState::SynSent: return "SYN_SENT";
        case TcpState::SynReceived: return "SYN_RCVD";
        case TcpState::Established: return "ESTABLISHED";
        case TcpState::FinWait1: return "FIN_WAIT_1";
        case TcpState::FinWait2: return "FIN_WAIT_2";
        case TcpState::CloseWait: return "CLOSE_WAIT";
        case TcpState::Closing: return "CLOSING";
        case TcpState::LastAck: return "LAST_ACK";
        case TcpState::TimeWait: return "TIME_WAIT";
    }
    return "?";
}

namespace {

constexpr std::uint8_t kOptionEnd = 0;
constexpr std::uint8_t kOptionNop = 1;
constexpr std::uint8_t kOptionMss = 2;

// Parses TCP options; only MSS is used, everything else is skipped.
std::optional<std::uint16_t> parse_mss_option(ByteView options) {
    std::optional<std::uint16_t> mss;
    std::size_t i = 0;
    while (i < options.size()) {
        const std::uint8_t kind = options[i];
        if (kind == kOptionEnd) break;
        if (kind == kOptionNop) {
            ++i;
            continue;
        }
        if (i + 1 >= options.size()) break;
        const std::uint8_t len = options[i + 1];
        if (len < 2 || i + len > options.size()) break;  // malformed
        if (kind == kOptionMss && len == 4) {
            mss = static_cast<std::uint16_t>((options[i + 2] << 8) | options[i + 3]);
        }
        i += len;
    }
    return mss;
}

}  // namespace

TcpLayer::TcpLayer(const InterfaceConfig& config, TimerQueue& timers, Ipv4Layer& ipv4)
    : config_(config), timers_(timers), ipv4_(ipv4) {}

bool TcpLayer::listen(std::uint16_t port, AcceptHandler on_accept) {
    auto [it, inserted] = listeners_.try_emplace(port, std::move(on_accept));
    if (inserted) {
        log::info("tcp", "listening on {}:{}", config_.ip, port);
    } else {
        log::warn("tcp", "port {} already has a listener", port);
    }
    return inserted;
}

std::shared_ptr<TcpConnection> TcpLayer::connect(Ipv4Address remote_ip, std::uint16_t remote_port) {
    const auto local_port = allocate_ephemeral_port(remote_ip, remote_port);
    if (!local_port) {
        log::warn("tcp", "no free ephemeral ports");
        return nullptr;
    }
    const TcpTuple tuple{config_.ip, *local_port, remote_ip, remote_port};
    auto conn = std::make_shared<TcpConnection>(*this, tuple);
    connections_.emplace(tuple, conn);
    log::info("tcp", "{} connecting", tuple);
    conn->open_active();
    return conn;
}

std::optional<std::uint16_t> TcpLayer::allocate_ephemeral_port(Ipv4Address remote_ip, std::uint16_t remote_port) {
    for (int attempt = 0; attempt < 16384; ++attempt) {
        const std::uint16_t port = next_ephemeral_port_;
        next_ephemeral_port_ = next_ephemeral_port_ == 65535 ? 49152 : next_ephemeral_port_ + 1;
        if (listeners_.contains(port)) continue;
        if (!connections_.contains(TcpTuple{config_.ip, port, remote_ip, remote_port})) return port;
    }
    return std::nullopt;
}

void TcpLayer::receive(const Ipv4Datagram& datagram) {
    ++stats_.rx_segments;
    const ByteView data = datagram.payload;
    auto header = read_struct<TcpHeader>(data);
    const std::size_t header_len = header ? header->header_length() : 0;
    if (!header || header_len < sizeof(TcpHeader) || header_len > data.size()) {
        ++stats_.rx_dropped;
        log::debug("tcp", "malformed segment from {}", datagram.src);
        return;
    }
    if (datagram.dst != config_.ip) {
        ++stats_.rx_dropped;
        return;  // no TCP over broadcast
    }
    const auto sum = checksum_accumulate(
        data, pseudo_header_sum(datagram.src, datagram.dst, ip_protocol::kTcp, static_cast<std::uint16_t>(data.size())));
    if (checksum_finish(sum) != 0) {
        ++stats_.rx_dropped;
        log::debug("tcp", "bad checksum from {}", datagram.src);
        return;
    }

    TcpSegment seg;
    seg.seq = ntohl(header->seq);
    seg.ack = ntohl(header->ack);
    seg.flags = header->flags;
    seg.window = ntohs(header->window);
    seg.mss = parse_mss_option(data.subspan(sizeof(TcpHeader), header_len - sizeof(TcpHeader)));
    seg.payload = data.subspan(header_len);

    const TcpTuple tuple{datagram.dst, ntohs(header->dst_port), datagram.src, ntohs(header->src_port)};
    log::trace("tcp", "rx {} [{}] seq={} ack={} win={} len={}", tuple, tcp_flags_to_string(seg.flags), seg.seq,
               seg.ack, seg.window, seg.payload.size());

    if (auto it = connections_.find(tuple); it != connections_.end()) {
        auto conn = it->second;  // hold a reference while it processes the segment
        conn->handle_segment(seg);
        return;
    }
    if (auto it = listeners_.find(tuple.local_port); it != listeners_.end()) {
        const AcceptHandler on_accept = it->second;
        handle_listen(tuple, seg, on_accept);
        return;
    }
    // No such connection and nobody listening: "connection refused".
    if (!seg.has(kRst)) send_reset(tuple, seg);
}

void TcpLayer::handle_listen(const TcpTuple& tuple, const TcpSegment& seg, const AcceptHandler& on_accept) {
    if (seg.has(kRst)) return;
    if (seg.has(kAck)) {  // an ACK for a connection we don't know
        send_reset(tuple, seg);
        return;
    }
    if (!seg.has(kSyn)) return;
    if (connections_.size() >= kMaxConnections) {
        log::warn("tcp", "connection table full; ignoring SYN from {}", tuple.remote_ip);
        return;
    }

    log::info("tcp", "{} incoming connection", tuple);
    auto conn = std::make_shared<TcpConnection>(*this, tuple);
    connections_.emplace(tuple, conn);
    ++stats_.connections_accepted;
    conn->open_passive(seg, on_accept);
}

void TcpLayer::send_reset(const TcpTuple& tuple, const TcpSegment& seg) {
    // RFC 793 "reset generation": make the RST acceptable to the sender.
    if (seg.has(kAck)) {
        transmit(tuple, seg.ack, 0, kRst, 0, {});
    } else {
        transmit(tuple, 0, seg.seq + seg.length(), kRst | kAck, 0, {});
    }
}

void TcpLayer::transmit(const TcpTuple& tuple, std::uint32_t seq, std::uint32_t ack, std::uint8_t flags,
                        std::uint16_t window, ByteView payload, std::optional<std::uint16_t> mss) {
    const std::size_t options_len = mss ? 4 : 0;
    TcpHeader header{};
    header.src_port = htons(tuple.local_port);
    header.dst_port = htons(tuple.remote_port);
    header.seq = htonl(seq);
    header.ack = htonl(ack);
    header.data_offset = static_cast<std::uint8_t>(((sizeof(TcpHeader) + options_len) / 4) << 4);
    header.flags = flags;
    header.window = htons(window);

    Bytes segment;
    segment.reserve(sizeof(header) + options_len + payload.size());
    append_struct(segment, header);
    if (mss) {
        segment.insert(segment.end(), {kOptionMss, 4, static_cast<std::uint8_t>(*mss >> 8),
                                       static_cast<std::uint8_t>(*mss & 0xff)});
    }
    append(segment, payload);

    const auto sum = checksum_accumulate(segment, pseudo_header_sum(tuple.local_ip, tuple.remote_ip, ip_protocol::kTcp,
                                                                    static_cast<std::uint16_t>(segment.size())));
    const std::uint16_t cs = checksum_finish(sum);
    segment[16] = static_cast<std::uint8_t>(cs >> 8);
    segment[17] = static_cast<std::uint8_t>(cs);

    ++stats_.tx_segments;
    if (flags & kRst) ++stats_.resets_sent;
    log::trace("tcp", "tx {} [{}] seq={} ack={} win={} len={}", tuple, tcp_flags_to_string(flags), seq, ack, window,
               payload.size());
    ipv4_.send(tuple.remote_ip, ip_protocol::kTcp, segment);
}

void TcpLayer::release(TcpConnection* connection) {
    const TcpTuple tuple = connection->tuple();
    timers_.schedule_after(Duration::zero(), [this, tuple, connection] {
        auto it = connections_.find(tuple);
        if (it != connections_.end() && it->second.get() == connection) connections_.erase(it);
    });
}

}  // namespace ustack
