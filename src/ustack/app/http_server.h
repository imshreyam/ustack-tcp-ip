#pragma once

#include <cstdint>
#include <memory>
#include <string>

#include "ustack/stack.h"

namespace ustack {

// Minimal HTTP/1.0-style server running on our own TCP (not OS sockets).
// Routes:
//   /       status page (interface, ARP cache, TCP connections, counters)
//   /big    1 MiB of text; exercises windows, cwnd growth, and retransmits
//   other   404
class HttpServer {
public:
    static constexpr std::size_t kBigBodySize = 1024 * 1024;
    static constexpr std::size_t kMaxRequestSize = 16 * 1024;

    HttpServer(Stack& stack, std::uint16_t port = 80);

    std::uint64_t requests_served() const noexcept { return requests_served_; }

private:
    void on_accept(const std::shared_ptr<TcpConnection>& conn);
    std::string build_response(const std::string& method, const std::string& path);
    std::string status_page(const std::string& path);

    Stack& stack_;
    std::uint64_t requests_served_ = 0;
};

}  // namespace ustack
