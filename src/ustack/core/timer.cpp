#include "ustack/core/timer.h"

namespace ustack {

TimerQueue::TimerId TimerQueue::schedule_at(TimePoint deadline, Callback cb) {
    const TimerId id = next_id_++;
    timers_.emplace(Key{deadline, id}, std::move(cb));
    deadlines_.emplace(id, deadline);
    return id;
}

bool TimerQueue::cancel(TimerId id) {
    auto it = deadlines_.find(id);
    if (it == deadlines_.end()) return false;
    timers_.erase(Key{it->second, id});
    deadlines_.erase(it);
    return true;
}

std::optional<TimePoint> TimerQueue::next_deadline() const {
    if (timers_.empty()) return std::nullopt;
    return timers_.begin()->first.first;
}

std::size_t TimerQueue::run_expired() {
    std::size_t ran = 0;
    while (!timers_.empty()) {
        auto it = timers_.begin();
        if (it->first.first > now_) break;
        // Move the callback out before running it: the callback may cancel or
        // schedule timers, which would invalidate `it`.
        Callback cb = std::move(it->second);
        deadlines_.erase(it->first.second);
        timers_.erase(it);
        cb();
        ++ran;
    }
    return ran;
}

void Timer::arm(Duration delay, TimerQueue::Callback cb) {
    cancel();
    id_ = queue_->schedule_after(delay, [this, cb = std::move(cb)] {
        id_ = 0;
        cb();  // may destroy *this; nothing touches `this` afterwards
    });
}

void Timer::cancel() {
    if (id_ != 0) {
        queue_->cancel(id_);
        id_ = 0;
    }
}

}  // namespace ustack
