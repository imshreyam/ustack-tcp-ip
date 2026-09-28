#include "ustack/core/event_loop.h"

#include <sys/epoll.h>
#include <sys/timerfd.h>

#include <cerrno>
#include <chrono>
#include <system_error>

namespace ustack {

namespace {
[[noreturn]] void throw_errno(const char* what) { throw std::system_error(errno, std::generic_category(), what); }
}  // namespace

EventLoop::EventLoop()
    : epoll_(::epoll_create1(EPOLL_CLOEXEC)),
      timerfd_(::timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC)),
      timers_(Clock::now()) {
    if (!epoll_) throw_errno("epoll_create1");
    if (!timerfd_) throw_errno("timerfd_create");
    epoll_event ev{};
    ev.events = EPOLLIN;
    ev.data.fd = timerfd_.get();
    if (::epoll_ctl(epoll_.get(), EPOLL_CTL_ADD, timerfd_.get(), &ev) < 0) throw_errno("epoll_ctl(timerfd)");
}

void EventLoop::watch_readable(int fd, std::function<void()> on_readable) {
    epoll_event ev{};
    ev.events = EPOLLIN;
    ev.data.fd = fd;
    if (::epoll_ctl(epoll_.get(), EPOLL_CTL_ADD, fd, &ev) < 0) throw_errno("epoll_ctl(add)");
    handlers_[fd] = std::move(on_readable);
}

void EventLoop::unwatch(int fd) {
    ::epoll_ctl(epoll_.get(), EPOLL_CTL_DEL, fd, nullptr);
    handlers_.erase(fd);
}

void EventLoop::arm_timerfd() {
    itimerspec spec{};
    if (auto deadline = timers_.next_deadline()) {
        // steady_clock is CLOCK_MONOTONIC on Linux, so its epoch matches the timerfd's.
        auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(deadline->time_since_epoch()).count();
        if (ns <= 0) ns = 1;  // an all-zero it_value would disarm the timer
        spec.it_value.tv_sec = ns / 1'000'000'000;
        spec.it_value.tv_nsec = ns % 1'000'000'000;
    }
    if (::timerfd_settime(timerfd_.get(), TFD_TIMER_ABSTIME, &spec, nullptr) < 0) throw_errno("timerfd_settime");
}

void EventLoop::run() {
    running_ = true;
    while (running_) {
        timers_.advance_to(Clock::now());
        timers_.run_expired();
        if (!running_) break;
        arm_timerfd();

        epoll_event events[32];
        const int n = ::epoll_wait(epoll_.get(), events, 32, -1);
        if (n < 0) {
            if (errno == EINTR) continue;
            throw_errno("epoll_wait");
        }
        timers_.advance_to(Clock::now());
        for (int i = 0; i < n; ++i) {
            const int fd = events[i].data.fd;
            if (fd == timerfd_.get()) {
                std::uint64_t expirations;
                [[maybe_unused]] auto r = ::read(fd, &expirations, sizeof(expirations));
                continue;  // expired timers run at the top of the loop
            }
            if (auto it = handlers_.find(fd); it != handlers_.end()) {
                auto handler = it->second;  // copy: the handler may unwatch itself
                handler();
            }
        }
    }
}

}  // namespace ustack
