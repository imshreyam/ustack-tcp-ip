#include "ustack/net/checksum.h"

namespace ustack {

std::uint64_t checksum_accumulate(ByteView data, std::uint64_t sum) {
    std::size_t i = 0;
    for (; i + 1 < data.size(); i += 2) {
        sum += (std::uint64_t{data[i]} << 8) | data[i + 1];
    }
    if (i < data.size()) {
        sum += std::uint64_t{data[i]} << 8;  // odd trailing byte is padded with a zero byte
    }
    return sum;
}

std::uint16_t checksum_finish(std::uint64_t sum) {
    // Fold the carries back in (end-around carry) until the sum fits in 16 bits.
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return static_cast<std::uint16_t>(~sum & 0xffff);
}

std::uint64_t pseudo_header_sum(Ipv4Address src, Ipv4Address dst, std::uint8_t protocol, std::uint16_t length) {
    std::uint64_t sum = 0;
    sum += src.value >> 16;
    sum += src.value & 0xffff;
    sum += dst.value >> 16;
    sum += dst.value & 0xffff;
    sum += protocol;  // zero byte followed by the protocol byte
    sum += length;
    return sum;
}

}  // namespace ustack
