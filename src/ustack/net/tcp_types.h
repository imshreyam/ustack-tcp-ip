#pragma once

#include <cstdint>
#include <format>
#include <functional>
#include <optional>
#include <string>

#include "ustack/net/address.h"
#include "ustack/util/bytes.h"

namespace ustack {

namespace tcp_flag {
inline constexpr std::uint8_t kFin = 0x01;
inline constexpr std::uint8_t kSyn = 0x02;
inline constexpr std::uint8_t kRst = 0x04;
inline constexpr std::uint8_t kPsh = 0x08;
inline constexpr std::uint8_t kAck = 0x10;
inline constexpr std::uint8_t kUrg = 0x20;
}  // namespace tcp_flag

std::string tcp_flags_to_string(std::uint8_t flags);

// RFC 793 connection states.
enum class TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
};

const char* to_string(TcpState state);

// Sequence-number comparisons modulo 2^32 (RFC 793 section 3.3). Plain `<`
// breaks as soon as the sequence space wraps around.
constexpr bool seq_lt(std::uint32_t a, std::uint32_t b) { return static_cast<std::int32_t>(a - b) < 0; }
constexpr bool seq_le(std::uint32_t a, std::uint32_t b) { return static_cast<std::int32_t>(a - b) <= 0; }
constexpr bool seq_gt(std::uint32_t a, std::uint32_t b) { return seq_lt(b, a); }
constexpr bool seq_ge(std::uint32_t a, std::uint32_t b) { return seq_le(b, a); }
// start <= seq < start + len
constexpr bool seq_in_window(std::uint32_t seq, std::uint32_t start, std::uint32_t len) {
    return seq_le(start, seq) && seq_lt(seq, start + len);
}

// Connection identity: the 4-tuple, seen from our side.
struct TcpTuple {
    Ipv4Address local_ip;
    std::uint16_t local_port = 0;
    Ipv4Address remote_ip;
    std::uint16_t remote_port = 0;

    friend bool operator==(const TcpTuple&, const TcpTuple&) = default;
};

// A parsed incoming segment (payload view is valid only during processing).
struct TcpSegment {
    std::uint32_t seq = 0;
    std::uint32_t ack = 0;
    std::uint8_t flags = 0;
    std::uint16_t window = 0;
    std::optional<std::uint16_t> mss;
    ByteView payload;

    bool has(std::uint8_t flag) const { return (flags & flag) != 0; }
    // Sequence space consumed: data plus one each for SYN and FIN.
    std::uint32_t length() const {
        return static_cast<std::uint32_t>(payload.size()) + (has(tcp_flag::kSyn) ? 1 : 0) +
               (has(tcp_flag::kFin) ? 1 : 0);
    }
};

}  // namespace ustack

template <>
struct std::hash<ustack::TcpTuple> {
    std::size_t operator()(const ustack::TcpTuple& t) const noexcept {
        std::uint64_t a = (std::uint64_t{t.local_ip.value} << 16) | t.local_port;
        std::uint64_t b = (std::uint64_t{t.remote_ip.value} << 16) | t.remote_port;
        return std::hash<std::uint64_t>{}(a * 0x9e3779b97f4a7c15ull ^ b);
    }
};

template <>
struct std::formatter<ustack::TcpTuple> : std::formatter<std::string> {
    auto format(const ustack::TcpTuple& t, std::format_context& ctx) const {
        return std::formatter<std::string>::format(
            std::format("{}:{}<->{}:{}", t.local_ip, t.local_port, t.remote_ip, t.remote_port), ctx);
    }
};

template <>
struct std::formatter<ustack::TcpState> : std::formatter<std::string_view> {
    auto format(ustack::TcpState s, std::format_context& ctx) const {
        return std::formatter<std::string_view>::format(ustack::to_string(s), ctx);
    }
};
