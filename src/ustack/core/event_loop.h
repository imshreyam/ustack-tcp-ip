#pragma once

#include <functional>
#include <unordered_map>

#include "ustack/core/timer.h"
#include "ustack/util/fd.h"

namespace ustack {

// Single-threaded epoll loop. File descriptors get readability callbacks;
// timers live in a TimerQueue whose earliest deadline is mirrored into a
// timerfd so that epoll wakes up exactly when the next timer is due.
class EventLoop {
public:
    EventLoop();

    TimerQueue& timers() noexcept { return timers_; }

    void watch_readable(int fd, std::function<void()> on_readable);
    void unwatch(int fd);

    void run();
    void stop() noexcept { running_ = false; }

private:
    void arm_timerfd();

    FileDescriptor epoll_;
    FileDescriptor timerfd_;
    TimerQueue timers_;
    std::unordered_map<int, std::function<void()>> handlers_;
    bool running_ = false;
};

}  // namespace ustack
