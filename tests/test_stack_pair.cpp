// Integration tests: two complete stacks connected by a simulated Ethernet
// link that can drop, reorder and duplicate frames. Time is simulated, so a
// test that "waits" 30 seconds of retransmission timeouts runs instantly.

#include <chrono>
#include <functional>
#include <memory>
#include <random>
#include <string>

#include "test_framework.h"
#include "ustack/stack.h"

using namespace ustack;
using namespace std::chrono_literals;

namespace {

const Ipv4Address kIpA = Ipv4Address::from_octets(10, 0, 0, 1);
const Ipv4Address kIpB = Ipv4Address::from_octets(10, 0, 0, 2);

class VirtualLink {
public:
    double loss = 0.0;       // probability a frame is dropped
    double reorder = 0.0;    // probability a frame is delayed extra (so it overtakes/gets overtaken)
    double duplicate = 0.0;  // probability a frame is delivered twice
    Duration latency = 1ms;

    TimerQueue timers{TimePoint{}};
    std::unique_ptr<Stack> a;
    std::unique_ptr<Stack> b;
    std::uint64_t frames_carried = 0;
    std::uint64_t frames_dropped = 0;

    explicit VirtualLink(std::uint32_t seed = 1) : rng_(seed) {
        InterfaceConfig ca;
        ca.mac = *MacAddress::parse("02:00:00:00:00:0a");
        ca.ip = kIpA;
        InterfaceConfig cb;
        cb.mac = *MacAddress::parse("02:00:00:00:00:0b");
        cb.ip = kIpB;
        a = std::make_unique<Stack>(ca, timers, [this](ByteView f) { carry(f, *b); });
        b = std::make_unique<Stack>(cb, timers, [this](ByteView f) { carry(f, *a); });
    }

    ~VirtualLink() {
        // Stacks own Timers registered in `timers`; destroy them first.
        a.reset();
        b.reset();
    }

    // Advances simulated time event by event until `done` or `limit` elapses.
    bool run_until(const std::function<bool()>& done, Duration limit = 120s) {
        const TimePoint deadline = timers.now() + limit;
        while (!done()) {
            const auto next = timers.next_deadline();
            if (!next || *next > deadline) {
                timers.advance_to(deadline);
                return done();
            }
            timers.advance_to(*next);
            timers.run_expired();
        }
        return true;
    }

    void run_for(Duration d) { run_until([] { return false; }, d); }

private:
    bool chance(double p) { return p > 0 && std::uniform_real_distribution<>(0, 1)(rng_) < p; }

    void carry(ByteView frame, Stack& to) {
        ++frames_carried;
        if (chance(loss)) {
            ++frames_dropped;
            return;
        }
        Duration delay = latency;
        if (chance(reorder)) delay += std::chrono::milliseconds(std::uniform_int_distribution<>(1, 5)(rng_));
        const int copies = chance(duplicate) ? 2 : 1;
        for (int i = 0; i < copies; ++i) {
            timers.schedule_after(delay, [&to, bytes = Bytes(frame.begin(), frame.end())] { to.receive_frame(bytes); });
        }
    }

    std::mt19937 rng_;
};

Bytes pattern(std::size_t n, std::uint32_t seed) {
    std::mt19937 rng(seed);
    Bytes out(n);
    for (auto& b : out) b = static_cast<std::uint8_t>(rng());
    return out;
}

// Client on A sends `payload` to an echo server on B, reads the echo back and
// then closes. Checks data integrity in both directions and a clean close.
void run_echo_transfer(VirtualLink& link, std::size_t size) {
    const Bytes payload = pattern(size, 7);

    std::shared_ptr<TcpConnection> server;
    std::optional<TcpConnection::CloseReason> server_closed;
    link.b->tcp().listen(7, [&](std::shared_ptr<TcpConnection> conn) {
        server = conn;
        std::weak_ptr<TcpConnection> weak = conn;
        conn->set_on_data([weak] {
            if (auto c = weak.lock()) c->send(c->recv());
        });
        conn->set_on_peer_closed([weak] {
            if (auto c = weak.lock()) c->close();
        });
        conn->set_on_closed([&](TcpConnection::CloseReason r) { server_closed = r; });
    });

    Bytes received;
    std::optional<TcpConnection::CloseReason> client_closed;
    auto client = link.a->tcp().connect(kIpB, 7);
    REQUIRE(client != nullptr);
    std::weak_ptr<TcpConnection> weak = client;
    client->set_on_connected([&, weak] {
        if (auto c = weak.lock()) CHECK_EQ(c->send(payload), payload.size());
    });
    client->set_on_data([&, weak] {
        auto c = weak.lock();
        const Bytes chunk = c->recv();
        received.insert(received.end(), chunk.begin(), chunk.end());
        if (received.size() == payload.size()) c->close();
    });
    client->set_on_closed([&](TcpConnection::CloseReason r) { client_closed = r; });

    const bool finished = link.run_until([&] { return client_closed && server_closed; }, 300s);
    CHECK(finished);
    CHECK_EQ(received.size(), payload.size());
    CHECK(received == payload);
    REQUIRE(client_closed && server_closed);
    CHECK(*client_closed == TcpConnection::CloseReason::Normal);
    CHECK(*server_closed == TcpConnection::CloseReason::Normal);
    // Deferred cleanup runs on the next timer tick.
    link.run_for(1s);
    CHECK_EQ(link.a->tcp().connections().size(), std::size_t{0});
    CHECK_EQ(link.b->tcp().connections().size(), std::size_t{0});
}

}  // namespace

TEST(arp_resolution_and_ping) {
    VirtualLink link;
    int replies = 0;
    link.a->icmp().set_echo_reply_handler([&](Ipv4Address from, std::uint16_t id, std::uint16_t seq, ByteView data) {
        CHECK_EQ(from, kIpB);
        CHECK_EQ(id, std::uint16_t{42});
        CHECK_EQ(seq, std::uint16_t{1});
        CHECK_EQ(std::string(data.begin(), data.end()), std::string("ping!"));
        ++replies;
    });
    link.a->icmp().send_echo_request(kIpB, 42, 1, as_bytes("ping!"));
    CHECK(link.run_until([&] { return replies == 1; }, 5s));
    CHECK(link.a->arp().lookup(kIpB).has_value());
    CHECK(link.b->arp().lookup(kIpA).has_value());  // learned from A's request
}

TEST(arp_gives_up_on_silent_host) {
    VirtualLink link;
    link.a->icmp().send_echo_request(Ipv4Address::from_octets(10, 0, 0, 99), 1, 1, as_bytes("x"));
    link.run_for(10s);
    CHECK(!link.a->arp().lookup(Ipv4Address::from_octets(10, 0, 0, 99)).has_value());
}

TEST(udp_echo) {
    VirtualLink link;
    link.b->udp().bind(7, [&](Ipv4Address src, std::uint16_t sport, std::uint16_t, ByteView data) {
        link.b->udp().send_to(7, src, sport, data);
    });
    std::string got;
    link.a->udp().bind(5000, [&](Ipv4Address src, std::uint16_t sport, std::uint16_t, ByteView data) {
        CHECK_EQ(src, kIpB);
        CHECK_EQ(sport, std::uint16_t{7});
        got.assign(data.begin(), data.end());
    });
    link.a->udp().send_to(5000, kIpB, 7, as_bytes("hello, udp"));
    CHECK(link.run_until([&] { return !got.empty(); }, 5s));
    CHECK_EQ(got, std::string("hello, udp"));
}

TEST(udp_to_closed_port_is_dropped) {
    VirtualLink link;
    link.a->udp().send_to(5000, kIpB, 9, as_bytes("anyone?"));
    link.run_for(2s);
    CHECK_EQ(link.b->udp().stats().rx_dropped, std::uint64_t{1});
}

TEST(ip_fragmentation_and_reassembly) {
    VirtualLink link;
    link.reorder = 0.5;  // fragments may arrive out of order
    const Bytes big = pattern(4000, 3);  // > MTU, so 3 fragments each way
    link.b->udp().bind(7, [&](Ipv4Address src, std::uint16_t sport, std::uint16_t, ByteView data) {
        link.b->udp().send_to(7, src, sport, data);
    });
    Bytes got;
    link.a->udp().bind(5000, [&](Ipv4Address, std::uint16_t, std::uint16_t, ByteView data) {
        got.assign(data.begin(), data.end());
    });
    link.a->udp().send_to(5000, kIpB, 7, big);
    CHECK(link.run_until([&] { return !got.empty(); }, 5s));
    CHECK(got == big);
    CHECK_EQ(link.b->ipv4().stats().rx_reassembled, std::uint64_t{1});
    CHECK_EQ(link.a->ipv4().stats().rx_reassembled, std::uint64_t{1});
}

TEST(tcp_echo_clean_link) {
    VirtualLink link;
    run_echo_transfer(link, 200 * 1024);
    CHECK_EQ(link.a->tcp().stats().retransmitted_segments, std::uint64_t{0});
}

TEST(tcp_echo_lossy_link) {
    VirtualLink link(12345);
    link.loss = 0.08;
    link.reorder = 0.2;
    link.duplicate = 0.05;
    run_echo_transfer(link, 300 * 1024);
    CHECK(link.frames_dropped > 0);
    CHECK(link.a->tcp().stats().retransmitted_segments + link.b->tcp().stats().retransmitted_segments > 0);
}

TEST(tcp_echo_lossy_link_many_seeds) {
    for (std::uint32_t seed = 1; seed <= 40; ++seed) {
        VirtualLink link(seed);
        link.loss = 0.15;
        link.reorder = 0.3;
        link.duplicate = 0.1;
        const int before = testing::failures();
        run_echo_transfer(link, 64 * 1024);
        if (testing::failures() != before) {
            std::fprintf(stderr, "    (seed %u)\n", seed);
            return;
        }
    }
}

TEST(tcp_connection_refused) {
    VirtualLink link;
    std::optional<TcpConnection::CloseReason> reason;
    auto conn = link.a->tcp().connect(kIpB, 81);  // nobody listening
    conn->set_on_closed([&](TcpConnection::CloseReason r) { reason = r; });
    CHECK(link.run_until([&] { return reason.has_value(); }, 5s));
    CHECK(reason == TcpConnection::CloseReason::Reset);
}

TEST(tcp_connect_timeout_when_peer_silent) {
    VirtualLink link;
    link.loss = 1.0;  // black hole
    std::optional<TcpConnection::CloseReason> reason;
    auto conn = link.a->tcp().connect(kIpB, 80);
    conn->set_on_closed([&](TcpConnection::CloseReason r) { reason = r; });
    CHECK(link.run_until([&] { return reason.has_value(); }, 600s));
    CHECK(reason == TcpConnection::CloseReason::Timeout);
}

TEST(tcp_flow_control_zero_window) {
    VirtualLink link;
    const Bytes payload = pattern(256 * 1024, 11);

    std::shared_ptr<TcpConnection> server;
    link.b->tcp().listen(9, [&](std::shared_ptr<TcpConnection> conn) { server = conn; });  // app doesn't read (yet)

    auto client = link.a->tcp().connect(kIpB, 9);
    client->set_on_connected([&] { client->send(payload); });

    // The receiver's 64 KiB buffer fills and its window drops to zero; the
    // sender must stall (and probe) rather than overrun it.
    link.run_for(20s);
    REQUIRE(server != nullptr);
    CHECK_EQ(server->available(), TcpConnection::kReceiveBufferSize);
    CHECK(client->unacknowledged_bytes() > 0);
    CHECK_EQ(client->state(), TcpState::Established);

    // Now the app starts reading: window updates let the transfer finish.
    Bytes received;
    auto drain = [&] {
        const Bytes chunk = server->recv();
        received.insert(received.end(), chunk.begin(), chunk.end());
    };
    server->set_on_data(drain);
    drain();
    CHECK(link.run_until([&] { return received.size() == payload.size(); }, 120s));
    CHECK(received == payload);
    client->abort();
    server->abort();
}

TEST(tcp_simultaneous_close) {
    VirtualLink link;
    std::shared_ptr<TcpConnection> server;
    link.b->tcp().listen(80, [&](std::shared_ptr<TcpConnection> conn) { server = conn; });
    auto client = link.a->tcp().connect(kIpB, 80);
    CHECK(link.run_until([&] { return server && client->state() == TcpState::Established; }, 5s));
    REQUIRE(server != nullptr);

    // Both sides close at the same instant: FIN_WAIT_1 -> CLOSING -> TIME_WAIT.
    client->close();
    server->close();
    CHECK(link.run_until([&] {
        return client->state() == TcpState::TimeWait && server->state() == TcpState::TimeWait;
    }, 5s));
    CHECK(link.run_until([&] { return client->state() == TcpState::Closed && server->state() == TcpState::Closed; },
                         2 * TcpConnection::kMsl + 1s));
}

TEST(tcp_abort_sends_reset) {
    VirtualLink link;
    std::shared_ptr<TcpConnection> server;
    std::optional<TcpConnection::CloseReason> server_reason;
    link.b->tcp().listen(80, [&](std::shared_ptr<TcpConnection> conn) {
        server = conn;
        conn->set_on_closed([&](TcpConnection::CloseReason r) { server_reason = r; });
    });
    auto client = link.a->tcp().connect(kIpB, 80);
    CHECK(link.run_until([&] { return server != nullptr; }, 5s));
    client->abort();
    CHECK(link.run_until([&] { return server_reason.has_value(); }, 5s));
    CHECK(server_reason == TcpConnection::CloseReason::Reset);
}
