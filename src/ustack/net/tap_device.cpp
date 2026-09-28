#include "ustack/net/tap_device.h"

#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <system_error>

#include "ustack/util/log.h"

namespace ustack {

TapDevice TapDevice::open(std::string_view name) {
    FileDescriptor fd(::open("/dev/net/tun", O_RDWR | O_NONBLOCK | O_CLOEXEC));
    if (!fd) throw std::system_error(errno, std::generic_category(), "open(/dev/net/tun)");

    ifreq ifr{};
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;  // raw Ethernet frames, no extra packet-info header
    const std::size_t len = name.size() < IFNAMSIZ - 1 ? name.size() : IFNAMSIZ - 1;
    std::memcpy(ifr.ifr_name, name.data(), len);

    if (::ioctl(fd.get(), TUNSETIFF, &ifr) < 0) {
        const int err = errno;
        throw std::system_error(err, std::generic_category(),
                                "ioctl(TUNSETIFF) on '" + std::string(name) +
                                    "' (create it first with scripts/tap-up.sh, or run inside scripts/netns-demo.sh)");
    }
    log::info("tap", "attached to {}", ifr.ifr_name);
    return TapDevice(std::move(fd), ifr.ifr_name);
}

std::optional<std::size_t> TapDevice::read(MutableByteView buffer) {
    for (;;) {
        const ssize_t n = ::read(fd_.get(), buffer.data(), buffer.size());
        if (n >= 0) return static_cast<std::size_t>(n);
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return std::nullopt;
        throw std::system_error(errno, std::generic_category(), "read(tap)");
    }
}

bool TapDevice::write(ByteView frame) {
    for (;;) {
        const ssize_t n = ::write(fd_.get(), frame.data(), frame.size());
        if (n == static_cast<ssize_t>(frame.size())) return true;
        if (n < 0 && errno == EINTR) continue;
        log::warn("tap", "write failed: {}", n < 0 ? std::strerror(errno) : "short write");
        return false;
    }
}

}  // namespace ustack
