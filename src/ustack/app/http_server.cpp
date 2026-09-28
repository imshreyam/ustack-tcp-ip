#include "ustack/app/http_server.h"

#include <format>
#include <sstream>

#include "ustack/util/log.h"

namespace ustack {

namespace {

std::string http_response(int status, std::string_view reason, std::string_view content_type,
                          const std::string& body, bool head_only) {
    std::string response = std::format(
        "HTTP/1.1 {} {}\r\n"
        "Server: ustack/0.1 (user-space TCP/IP)\r\n"
        "Content-Type: {}\r\n"
        "Content-Length: {}\r\n"
        "Connection: close\r\n"
        "\r\n",
        status, reason, content_type, body.size());
    if (!head_only) response += body;
    return response;
}

std::string html_escape(std::string_view s) {
    std::string out;
    for (char c : s) {
        switch (c) {
            case '<': out += "&lt;"; break;
            case '>': out += "&gt;"; break;
            case '&': out += "&amp;"; break;
            case '"': out += "&quot;"; break;
            default: out += c;
        }
    }
    return out;
}

}  // namespace

HttpServer::HttpServer(Stack& stack, std::uint16_t port) : stack_(stack) {
    stack_.tcp().listen(port, [this](std::shared_ptr<TcpConnection> conn) { on_accept(conn); });
}

void HttpServer::on_accept(const std::shared_ptr<TcpConnection>& conn) {
    auto request = std::make_shared<std::string>();
    std::weak_ptr<TcpConnection> weak = conn;  // weak: avoid a conn -> callback -> conn cycle

    conn->set_on_data([this, weak, request] {
        auto c = weak.lock();
        if (!c) return;
        const Bytes data = c->recv();
        request->append(data.begin(), data.end());
        if (request->size() > kMaxRequestSize) {
            log::warn("http", "request too large; aborting");
            c->abort();
            return;
        }
        if (request->find("\r\n\r\n") == std::string::npos) return;  // wait for the full header block

        std::istringstream line(request->substr(0, request->find("\r\n")));
        std::string method, path, version;
        line >> method >> path >> version;
        log::info("http", "{}:{} \"{} {} {}\"", c->tuple().remote_ip, c->tuple().remote_port, method, path, version);

        c->send(build_response(method, path));
        c->close();
        request->clear();
        ++requests_served_;
    });
    conn->set_on_peer_closed([weak] {
        if (auto c = weak.lock()) c->close();
    });
}

std::string HttpServer::build_response(const std::string& method, const std::string& path) {
    const bool head = method == "HEAD";
    if (method != "GET" && !head) {
        return http_response(405, "Method Not Allowed", "text/plain", "method not allowed\n", false);
    }
    if (path == "/" || path == "/index.html") {
        return http_response(200, "OK", "text/html; charset=utf-8", status_page(path), head);
    }
    if (path == "/big") {
        std::string body;
        body.reserve(kBigBodySize);
        for (std::size_t line = 0; body.size() < kBigBodySize; ++line) {
            body += std::format("{:08} the quick brown fox jumps over the lazy dog, via a user-space TCP stack\n", line);
        }
        body.resize(kBigBodySize);
        return http_response(200, "OK", "text/plain", body, head);
    }
    return http_response(404, "Not Found", "text/plain", "not found\n", head);
}

std::string HttpServer::status_page(const std::string& path) {
    const auto& cfg = stack_.config();
    const auto& eth = stack_.ethernet().stats();
    const auto& ip = stack_.ipv4().stats();
    const auto& tcp = stack_.tcp().stats();
    const auto& udp = stack_.udp().stats();

    std::string arp_rows;
    for (const auto& [addr, entry] : stack_.arp().cache()) {
        arp_rows += std::format("<tr><td>{}</td><td>{}</td></tr>", addr, entry.mac);
    }
    std::string tcp_rows;
    for (const auto& [tuple, conn] : stack_.tcp().connections()) {
        tcp_rows += std::format("<tr><td>{}:{}</td><td>{}:{}</td><td>{}</td></tr>", tuple.local_ip, tuple.local_port,
                                tuple.remote_ip, tuple.remote_port, conn->state());
    }

    return std::format(R"(<!doctype html>
<html><head><meta charset="utf-8"><title>ustack</title>
<style>
body{{font:15px/1.5 system-ui,sans-serif;max-width:52rem;margin:2rem auto;padding:0 1rem;color:#222}}
table{{border-collapse:collapse;margin:.5rem 0 1.5rem}} td,th{{border:1px solid #ccc;padding:.25rem .6rem;text-align:left}}
code{{background:#f3f3f3;padding:.1rem .3rem;border-radius:3px}}
</style></head><body>
<h1>Hello from a user-space TCP/IP stack</h1>
<p>This response travelled through hand-written Ethernet, ARP, IPv4 and TCP code,
reading and writing raw frames on a TAP device. The kernel's TCP never saw it.</p>
<p>You requested <code>{}</code>. Request #{} served.</p>
<h2>Interface</h2>
<table><tr><th>MAC</th><td>{}</td></tr><tr><th>IPv4</th><td>{}</td></tr>
<tr><th>Netmask</th><td>{}</td></tr><tr><th>MTU</th><td>{}</td></tr></table>
<h2>ARP cache</h2>
<table><tr><th>IP</th><th>MAC</th></tr>{}</table>
<h2>TCP connections</h2>
<table><tr><th>Local</th><th>Remote</th><th>State</th></tr>{}</table>
<h2>Counters</h2>
<table>
<tr><th>Ethernet frames rx / tx</th><td>{} / {}</td></tr>
<tr><th>IPv4 packets rx / tx / dropped</th><td>{} / {} / {}</td></tr>
<tr><th>IPv4 datagrams reassembled</th><td>{}</td></tr>
<tr><th>UDP datagrams rx / tx</th><td>{} / {}</td></tr>
<tr><th>TCP segments rx / tx</th><td>{} / {}</td></tr>
<tr><th>TCP retransmissions</th><td>{}</td></tr>
<tr><th>TCP connections accepted</th><td>{}</td></tr>
</table>
<p>Try <code>curl -o /dev/null http://{}/big</code> for a 1 MiB transfer.</p>
</body></html>
)",
                       html_escape(path), requests_served_ + 1, cfg.mac, cfg.ip, cfg.netmask, cfg.mtu, arp_rows,
                       tcp_rows, eth.rx_frames, eth.tx_frames, ip.rx_packets, ip.tx_packets, ip.rx_dropped,
                       ip.rx_reassembled, udp.rx_datagrams, udp.tx_datagrams, tcp.rx_segments, tcp.tx_segments,
                       tcp.retransmitted_segments, tcp.connections_accepted, cfg.ip);
}

}  // namespace ustack
