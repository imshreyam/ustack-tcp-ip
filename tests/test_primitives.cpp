// Unit tests for the building blocks: addresses, checksums, sequence math, timers.

#include <chrono>
#include <string>
#include <vector>

#include "test_framework.h"
#include "ustack/core/timer.h"
#include "ustack/net/address.h"
#include "ustack/net/checksum.h"
#include "ustack/net/tcp_types.h"

using namespace ustack;
using namespace std::chrono_literals;

TEST(mac_address_parse_and_format) {
    auto mac = MacAddress::parse("02:00:5e:10:ab:FF");
    REQUIRE(mac.has_value());
    CHECK_EQ(mac->to_string(), std::string("02:00:5e:10:ab:ff"));
    CHECK(!mac->is_broadcast());
    CHECK(MacAddress::broadcast().is_broadcast());
    CHECK(!MacAddress::parse("02:00:5e:10:ab").has_value());
    CHECK(!MacAddress::parse("02:00:5e:10:ab:ff:00").has_value());
    CHECK(!MacAddress::parse("zz:00:5e:10:ab:ff").has_value());
}

TEST(ipv4_address_parse_and_format) {
    auto ip = Ipv4Address::parse("192.168.1.20");
    REQUIRE(ip.has_value());
    CHECK_EQ(ip->value, 0xc0a80114u);
    CHECK_EQ(ip->to_string(), std::string("192.168.1.20"));
    CHECK_EQ(Ipv4Address::from_network(ip->to_network()), *ip);
    CHECK(!Ipv4Address::parse("300.1.1.1").has_value());
}

TEST(checksum_rfc1071_example) {
    // RFC 1071 section 3 example: words 0001 f203 f4f5 f6f7 sum to 0x2ddf0,
    // which folds to 0xddf2; the checksum is its complement.
    const std::vector<std::uint8_t> data{0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7};
    CHECK_EQ(internet_checksum(data), static_cast<std::uint16_t>(~0xddf2 & 0xffff));
}

TEST(checksum_verifies_real_ipv4_header) {
    // A real captured IPv4 header with a valid checksum (0xb861) sums to zero.
    const std::vector<std::uint8_t> header{0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11,
                                           0xb8, 0x61, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7};
    CHECK_EQ(internet_checksum(header), std::uint16_t{0});

    auto zeroed = header;
    zeroed[10] = zeroed[11] = 0;
    CHECK_EQ(internet_checksum(zeroed), std::uint16_t{0xb861});
}

TEST(checksum_odd_length) {
    const std::vector<std::uint8_t> data{0x01, 0x02, 0x03};
    // 0x0102 + 0x0300 = 0x0402 -> ~ = 0xfbfd
    CHECK_EQ(internet_checksum(data), std::uint16_t{0xfbfd});
}

TEST(sequence_number_wraparound) {
    CHECK(seq_lt(1, 2));
    CHECK(seq_lt(0xfffffff0u, 0x10u));  // wraps around
    CHECK(seq_gt(0x10u, 0xfffffff0u));
    CHECK(seq_le(5, 5));
    CHECK(seq_in_window(0x5u, 0xfffffffeu, 16));
    CHECK(!seq_in_window(0xfffffffdu, 0xfffffffeu, 16));
}

TEST(timer_queue_runs_in_deadline_order) {
    TimerQueue q(TimePoint{});
    std::vector<int> order;
    q.schedule_after(30ms, [&] { order.push_back(3); });
    q.schedule_after(10ms, [&] { order.push_back(1); });
    const auto cancelled = q.schedule_after(15ms, [&] { order.push_back(99); });
    q.schedule_after(20ms, [&] { order.push_back(2); });
    CHECK(q.cancel(cancelled));

    q.advance_to(TimePoint{} + 25ms);
    CHECK_EQ(q.run_expired(), std::size_t{2});
    q.advance_to(TimePoint{} + 30ms);
    q.run_expired();
    CHECK(order == (std::vector<int>{1, 2, 3}));
    CHECK(!q.next_deadline().has_value());
}

TEST(timer_rearm_and_destroy_cancels) {
    TimerQueue q(TimePoint{});
    int fired = 0;
    {
        Timer t(q);
        t.arm(10ms, [&] { ++fired; });
        t.arm(20ms, [&] { fired += 10; });  // re-arm replaces
        CHECK(t.armed());
        CHECK_EQ(q.size(), std::size_t{1});
    }  // destroyed -> cancelled
    q.advance_to(TimePoint{} + 1s);
    q.run_expired();
    CHECK_EQ(fired, 0);
}
