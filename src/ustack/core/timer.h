#pragma once

#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <unordered_map>
#include <utility>

namespace ustack {

using Clock = std::chrono::steady_clock;
using TimePoint = Clock::time_point;
using Duration = Clock::duration;

// A queue of one-shot timers driven by an externally supplied "now".
//
// The queue never reads the clock itself: the event loop advances it with
// real time, while tests advance it with simulated time. That is what lets the
// whole stack (retransmission timers included) run deterministically in tests.
class TimerQueue {
public:
    using TimerId = std::uint64_t;
    using Callback = std::function<void()>;

    explicit TimerQueue(TimePoint start = Clock::now()) : now_(start) {}

    TimerQueue(const TimerQueue&) = delete;
    TimerQueue& operator=(const TimerQueue&) = delete;

    TimePoint now() const noexcept { return now_; }
    void advance_to(TimePoint t) noexcept {
        if (t > now_) now_ = t;
    }

    TimerId schedule_at(TimePoint deadline, Callback cb);
    TimerId schedule_after(Duration delay, Callback cb) { return schedule_at(now_ + delay, std::move(cb)); }
    bool cancel(TimerId id);

    std::optional<TimePoint> next_deadline() const;
    std::size_t size() const noexcept { return timers_.size(); }

    // Runs every timer whose deadline is <= now(). Callbacks may freely
    // schedule or cancel other timers.
    std::size_t run_expired();

private:
    using Key = std::pair<TimePoint, TimerId>;
    std::map<Key, Callback> timers_;
    std::unordered_map<TimerId, TimePoint> deadlines_;
    TimerId next_id_ = 1;
    TimePoint now_;
};

// RAII handle for a single re-armable timer. Destroying the Timer cancels it,
// so a callback capturing `this` of the owning object can never dangle.
// The owning object must be destroyed before the TimerQueue.
class Timer {
public:
    explicit Timer(TimerQueue& queue) noexcept : queue_(&queue) {}
    ~Timer() { cancel(); }

    Timer(const Timer&) = delete;
    Timer& operator=(const Timer&) = delete;

    void arm(Duration delay, TimerQueue::Callback cb);
    void cancel();
    bool armed() const noexcept { return id_ != 0; }

private:
    TimerQueue* queue_;
    TimerQueue::TimerId id_ = 0;
};

}  // namespace ustack
