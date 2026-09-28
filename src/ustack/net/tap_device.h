#pragma once

#include <optional>
#include <string>
#include <string_view>

#include "ustack/util/bytes.h"
#include "ustack/util/fd.h"

namespace ustack {

// A Linux TAP interface opened in IFF_TAP | IFF_NO_PI mode: every read()
// returns exactly one raw Ethernet frame (no FCS) and every write() injects
// one frame into the kernel as if it arrived on the wire.
class TapDevice {
public:
    // Attaches to (or, with CAP_NET_ADMIN, creates) the named TAP device.
    // Throws std::system_error on failure.
    static TapDevice open(std::string_view name);

    int fd() const noexcept { return fd_.get(); }
    const std::string& name() const noexcept { return name_; }

    // Reads one frame; std::nullopt when no frame is pending (non-blocking fd).
    std::optional<std::size_t> read(MutableByteView buffer);
    bool write(ByteView frame);

private:
    TapDevice(FileDescriptor fd, std::string name) : fd_(std::move(fd)), name_(std::move(name)) {}

    FileDescriptor fd_;
    std::string name_;
};

}  // namespace ustack
