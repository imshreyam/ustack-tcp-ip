#pragma once

#include <cstdint>

#include "ustack/net/address.h"
#include "ustack/util/bytes.h"

namespace ustack {

// Internet checksum (RFC 1071): the 16-bit one's complement of the one's
// complement sum of all 16-bit big-endian words. The functions are split so a
// checksum can be built incrementally (pseudo-header + segment for TCP/UDP).
//
// Results are host-order values: store them with htons(), or byte-by-byte
// big-endian. Verifying a received header works by summing it *including*
// its checksum field; a valid header yields 0.

std::uint64_t checksum_accumulate(ByteView data, std::uint64_t sum = 0);
std::uint16_t checksum_finish(std::uint64_t sum);

inline std::uint16_t internet_checksum(ByteView data) { return checksum_finish(checksum_accumulate(data)); }

// Sum of the TCP/UDP IPv4 pseudo-header (RFC 793 section 3.1, RFC 768).
std::uint64_t pseudo_header_sum(Ipv4Address src, Ipv4Address dst, std::uint8_t protocol, std::uint16_t length);

}  // namespace ustack
