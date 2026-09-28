#pragma once

// Wire-format protocol headers.
//
// Every multi-byte field is stored in *network* byte order exactly as it
// appears on the wire; use ntohs/ntohl when reading and htons/htonl when
// writing. The structs are packed so that sizeof() equals the on-wire size.
// Never reinterpret_cast a packet buffer to these types: copy with
// read_struct<T>() (util/bytes.h) instead.

#include <cstdint>

namespace ustack {

namespace ethertype {
inline constexpr std::uint16_t kIpv4 = 0x0800;
inline constexpr std::uint16_t kArp = 0x0806;
inline constexpr std::uint16_t kIpv6 = 0x86dd;
}  // namespace ethertype

namespace ip_protocol {
inline constexpr std::uint8_t kIcmp = 1;
inline constexpr std::uint8_t kTcp = 6;
inline constexpr std::uint8_t kUdp = 17;
}  // namespace ip_protocol

#pragma pack(push, 1)

struct EthernetHeader {
    std::uint8_t dst[6];
    std::uint8_t src[6];
    std::uint16_t ethertype;
};

// ARP for Ethernet/IPv4 (RFC 826).
struct ArpPacket {
    std::uint16_t hardware_type;  // 1 = Ethernet
    std::uint16_t protocol_type;  // 0x0800 = IPv4
    std::uint8_t hardware_len;    // 6
    std::uint8_t protocol_len;    // 4
    std::uint16_t operation;      // 1 = request, 2 = reply
    std::uint8_t sender_mac[6];
    std::uint32_t sender_ip;
    std::uint8_t target_mac[6];
    std::uint32_t target_ip;
};

// IPv4 header without options (RFC 791).
struct Ipv4Header {
    std::uint8_t version_ihl;  // version (high nibble), header length in 32-bit words (low nibble)
    std::uint8_t tos;
    std::uint16_t total_length;
    std::uint16_t id;
    std::uint16_t flags_fragment;  // 3 flag bits (reserved, DF, MF) + 13-bit offset in 8-byte units
    std::uint8_t ttl;
    std::uint8_t protocol;
    std::uint16_t checksum;
    std::uint32_t src;
    std::uint32_t dst;

    std::uint8_t version() const { return version_ihl >> 4; }
    std::size_t header_length() const { return static_cast<std::size_t>(version_ihl & 0x0f) * 4; }
};

inline constexpr std::uint16_t kIpFlagDontFragment = 0x4000;
inline constexpr std::uint16_t kIpFlagMoreFragments = 0x2000;
inline constexpr std::uint16_t kIpFragmentOffsetMask = 0x1fff;

// ICMP header; `rest` is type-specific (identifier + sequence for echo).
struct IcmpHeader {
    std::uint8_t type;
    std::uint8_t code;
    std::uint16_t checksum;
    std::uint16_t id;
    std::uint16_t sequence;
};

struct UdpHeader {
    std::uint16_t src_port;
    std::uint16_t dst_port;
    std::uint16_t length;  // header + payload
    std::uint16_t checksum;
};

// TCP header without options (RFC 793).
struct TcpHeader {
    std::uint16_t src_port;
    std::uint16_t dst_port;
    std::uint32_t seq;
    std::uint32_t ack;
    std::uint8_t data_offset;  // header length in 32-bit words (high nibble)
    std::uint8_t flags;
    std::uint16_t window;
    std::uint16_t checksum;
    std::uint16_t urgent;

    std::size_t header_length() const { return static_cast<std::size_t>(data_offset >> 4) * 4; }
};

#pragma pack(pop)

static_assert(sizeof(EthernetHeader) == 14);
static_assert(sizeof(ArpPacket) == 28);
static_assert(sizeof(Ipv4Header) == 20);
static_assert(sizeof(IcmpHeader) == 8);
static_assert(sizeof(UdpHeader) == 8);
static_assert(sizeof(TcpHeader) == 20);

}  // namespace ustack
