#pragma once

#include <chrono>
#include <cstdio>
#include <ctime>
#include <format>
#include <string_view>
#include <utility>

namespace ustack::log {

enum class Level { Trace = 0, Debug, Info, Warn, Error };

inline Level& threshold() noexcept {
    static Level level = Level::Info;
    return level;
}

inline bool enabled(Level level) noexcept { return level >= threshold(); }

inline const char* level_name(Level level) noexcept {
    switch (level) {
        case Level::Trace: return "TRACE";
        case Level::Debug: return "DEBUG";
        case Level::Info: return "INFO";
        case Level::Warn: return "WARN";
        case Level::Error: return "ERROR";
    }
    return "?";
}

inline void emit(Level level, std::string_view component, std::string_view message) {
    using namespace std::chrono;
    const auto now = system_clock::now();
    const auto ms = duration_cast<milliseconds>(now.time_since_epoch()).count() % 1000;
    const std::time_t t = system_clock::to_time_t(now);
    std::tm tm{};
    localtime_r(&t, &tm);
    std::fprintf(stderr, "%02d:%02d:%02d.%03d %-5s [%.*s] %.*s\n", tm.tm_hour, tm.tm_min, tm.tm_sec,
                 static_cast<int>(ms), level_name(level), static_cast<int>(component.size()),
                 component.data(), static_cast<int>(message.size()), message.data());
}

template <class... Args>
void write(Level level, std::string_view component, std::format_string<Args...> fmt, Args&&... args) {
    if (!enabled(level)) return;
    emit(level, component, std::format(fmt, std::forward<Args>(args)...));
}

template <class... Args>
void trace(std::string_view component, std::format_string<Args...> fmt, Args&&... args) {
    write(Level::Trace, component, fmt, std::forward<Args>(args)...);
}
template <class... Args>
void debug(std::string_view component, std::format_string<Args...> fmt, Args&&... args) {
    write(Level::Debug, component, fmt, std::forward<Args>(args)...);
}
template <class... Args>
void info(std::string_view component, std::format_string<Args...> fmt, Args&&... args) {
    write(Level::Info, component, fmt, std::forward<Args>(args)...);
}
template <class... Args>
void warn(std::string_view component, std::format_string<Args...> fmt, Args&&... args) {
    write(Level::Warn, component, fmt, std::forward<Args>(args)...);
}
template <class... Args>
void error(std::string_view component, std::format_string<Args...> fmt, Args&&... args) {
    write(Level::Error, component, fmt, std::forward<Args>(args)...);
}

}  // namespace ustack::log
