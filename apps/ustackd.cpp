// ustackd: runs the user-space TCP/IP stack on a TAP device.
//
// Services:
//   ICMP echo          ping <ip>
//   UDP echo, port 7   echo hi | nc -u -q1 <ip> 7
//   TCP echo, port 7   nc <ip> 7
//   HTTP, port 80      curl http://<ip>/
//
// Optional active-side demos:
//   --ping <ip>                  the stack pings someone (exercises ARP resolution)
//   --fetch <ip>:<port>/<path>   the stack acts as an HTTP client (active open)

#include <signal.h>
#include <sys/signalfd.h>

#include <array>
#include <charconv>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>

#include "ustack/app/http_server.h"
#include "ustack/core/event_loop.h"
#include "ustack/net/tap_device.h"
#include "ustack/stack.h"
#include "ustack/util/fd.h"
#include "ustack/util/log.h"

using namespace ustack;

namespace {

struct Options {
    std::string device = "tap0";
    InterfaceConfig iface;
    std::optional<Ipv4Address> ping_target;
    std::optional<std::string> fetch_url;
    log::Level log_level = log::Level::Info;
};

void usage(const char* argv0) {
    std::fprintf(stderr,
                 "usage: %s [options]\n"
                 "  --dev NAME         TAP device (default tap0)\n"
                 "  --ip ADDR          our IPv4 address (default 10.0.0.2)\n"
                 "  --netmask MASK     (default 255.255.255.0)\n"
                 "  --gateway ADDR     default gateway (optional)\n"
                 "  --mac MAC          our MAC (default 02:00:00:00:00:02)\n"
                 "  --mtu N            (default 1500)\n"
                 "  --ping ADDR        send ICMP echo requests to ADDR every second\n"
                 "  --fetch IP:PORT/PATH  HTTP GET using our TCP (active open), print the response\n"
                 "  -v / -vv           debug / trace logging\n",
                 argv0);
}

[[noreturn]] void die(const std::string& message) {
    std::fprintf(stderr, "error: %s\n", message.c_str());
    std::exit(2);
}

Ipv4Address parse_ip(std::string_view s) {
    auto ip = Ipv4Address::parse(s);
    if (!ip) die("invalid IPv4 address: " + std::string(s));
    return *ip;
}

Options parse_args(int argc, char** argv) {
    Options opt;
    for (int i = 1; i < argc; ++i) {
        const std::string_view arg = argv[i];
        auto value = [&]() -> std::string_view {
            if (i + 1 >= argc) die(std::string(arg) + " needs a value");
            return argv[++i];
        };
        if (arg == "--dev") {
            opt.device = value();
        } else if (arg == "--ip") {
            opt.iface.ip = parse_ip(value());
        } else if (arg == "--netmask") {
            opt.iface.netmask = parse_ip(value());
        } else if (arg == "--gateway") {
            opt.iface.gateway = parse_ip(value());
        } else if (arg == "--mac") {
            auto mac = MacAddress::parse(value());
            if (!mac) die("invalid MAC address");
            opt.iface.mac = *mac;
        } else if (arg == "--mtu") {
            const auto v = value();
            std::size_t mtu = 0;
            std::from_chars(v.data(), v.data() + v.size(), mtu);
            if (mtu < 576 || mtu > 9000) die("MTU must be between 576 and 9000");
            opt.iface.mtu = mtu;
        } else if (arg == "--ping") {
            opt.ping_target = parse_ip(value());
        } else if (arg == "--fetch") {
            opt.fetch_url = std::string(value());
        } else if (arg == "-v") {
            opt.log_level = log::Level::Debug;
        } else if (arg == "-vv") {
            opt.log_level = log::Level::Trace;
        } else if (arg == "-h" || arg == "--help") {
            usage(argv[0]);
            std::exit(0);
        } else {
            usage(argv[0]);
            die("unknown option: " + std::string(arg));
        }
    }
    return opt;
}

void start_echo_services(Stack& stack) {
    stack.udp().bind(7, [&stack](Ipv4Address src, std::uint16_t src_port, std::uint16_t, ByteView data) {
        log::info("udp-echo", "{} bytes from {}:{}", data.size(), src, src_port);
        stack.udp().send_to(7, src, src_port, data);
    });

    stack.tcp().listen(7, [](std::shared_ptr<TcpConnection> conn) {
        std::weak_ptr<TcpConnection> weak = conn;
        conn->set_on_data([weak] {
            if (auto c = weak.lock()) c->send(c->recv());
        });
        conn->set_on_peer_closed([weak] {
            if (auto c = weak.lock()) c->close();
        });
    });
}

void start_pinger(Stack& stack, Ipv4Address target, Timer& timer, std::uint16_t& seq) {
    static std::unordered_map<std::uint16_t, TimePoint> sent;
    stack.icmp().set_echo_reply_handler([&stack](Ipv4Address from, std::uint16_t, std::uint16_t s, ByteView data) {
        auto it = sent.find(s);
        if (it == sent.end()) return;
        const auto rtt = std::chrono::duration<double, std::milli>(stack.timers().now() - it->second).count();
        log::info("ping", "{} bytes from {}: icmp_seq={} time={:.3f} ms", data.size(), from, s, rtt);
        sent.erase(it);
    });

    struct Tick {
        Stack& stack;
        Ipv4Address target;
        Timer& timer;
        std::uint16_t& seq;
        void operator()() const {
            static const std::string payload = "ustack ping payload 0123456789abcdef";
            sent[seq] = stack.timers().now();
            stack.icmp().send_echo_request(target, 0x5553, seq, as_bytes(payload));
            ++seq;
            timer.arm(std::chrono::seconds(1), *this);
        }
    };
    Tick{stack, target, timer, seq}();
}

std::shared_ptr<TcpConnection> start_fetch(Stack& stack, const std::string& url) {
    // Format: IP:PORT/PATH   (e.g. 10.0.0.1:8000/index.html)
    const auto colon = url.find(':');
    const auto slash = url.find('/', colon == std::string::npos ? 0 : colon);
    if (colon == std::string::npos) die("--fetch expects IP:PORT/PATH");
    const Ipv4Address ip = parse_ip(url.substr(0, colon));
    const std::string port_str = url.substr(colon + 1, slash == std::string::npos ? std::string::npos : slash - colon - 1);
    const std::string path = slash == std::string::npos ? "/" : url.substr(slash);
    const int port = std::atoi(port_str.c_str());
    if (port <= 0 || port > 65535) die("invalid port in --fetch");

    auto conn = stack.tcp().connect(ip, static_cast<std::uint16_t>(port));
    if (!conn) die("connect failed");
    std::weak_ptr<TcpConnection> weak = conn;
    const std::string request =
        "GET " + path + " HTTP/1.0\r\nHost: " + ip.to_string() + "\r\nUser-Agent: ustack\r\n\r\n";

    conn->set_on_connected([weak, request] {
        log::info("fetch", "connected; sending request");
        if (auto c = weak.lock()) c->send(request);
    });
    conn->set_on_data([weak] {
        if (auto c = weak.lock()) {
            const Bytes data = c->recv();
            std::fwrite(data.data(), 1, data.size(), stdout);
            std::fflush(stdout);
        }
    });
    conn->set_on_peer_closed([weak] {
        log::info("fetch", "server closed the connection");
        if (auto c = weak.lock()) c->close();
    });
    conn->set_on_closed([](TcpConnection::CloseReason reason) {
        log::info("fetch", "connection closed ({})", to_string(reason));
    });
    return conn;
}

}  // namespace

int main(int argc, char** argv) {
    const Options opt = parse_args(argc, argv);
    log::threshold() = opt.log_level;

    try {
        // Order matters: the loop (and its TimerQueue) and the TAP device must
        // outlive the stack, so they are declared first.
        EventLoop loop;
        TapDevice tap = TapDevice::open(opt.device);
        Stack stack(opt.iface, loop.timers(), [&tap](ByteView frame) { tap.write(frame); });

        log::info("main", "stack up: {} / {} on {} (mac {})", opt.iface.ip, opt.iface.netmask, tap.name(),
                  opt.iface.mac);

        std::array<std::uint8_t, 65536> buffer{};
        loop.watch_readable(tap.fd(), [&] {
            while (auto n = tap.read(buffer)) stack.receive_frame(ByteView(buffer.data(), *n));
        });

        // Clean shutdown on Ctrl-C / SIGTERM via signalfd.
        sigset_t mask;
        sigemptyset(&mask);
        sigaddset(&mask, SIGINT);
        sigaddset(&mask, SIGTERM);
        sigprocmask(SIG_BLOCK, &mask, nullptr);
        FileDescriptor sigfd(::signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC));
        loop.watch_readable(sigfd.get(), [&] {
            signalfd_siginfo info{};
            [[maybe_unused]] auto r = ::read(sigfd.get(), &info, sizeof(info));
            log::info("main", "caught signal {}, shutting down", info.ssi_signo);
            loop.stop();
        });

        start_echo_services(stack);
        HttpServer http(stack, 80);

        Timer ping_timer(loop.timers());
        std::uint16_t ping_seq = 1;
        if (opt.ping_target) start_pinger(stack, *opt.ping_target, ping_timer, ping_seq);

        std::shared_ptr<TcpConnection> fetch;
        if (opt.fetch_url) fetch = start_fetch(stack, *opt.fetch_url);

        stack.start();
        loop.run();
    } catch (const std::exception& e) {
        log::error("main", "{}", e.what());
        return 1;
    }
    return 0;
}
