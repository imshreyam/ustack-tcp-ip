#pragma once

// A deliberately tiny test framework, so the project has no dependencies.

#include <cstdio>
#include <format>
#include <functional>
#include <string>
#include <vector>

namespace testing {

struct TestCase {
    const char* name;
    std::function<void()> fn;
};

inline std::vector<TestCase>& registry() {
    static std::vector<TestCase> tests;
    return tests;
}

inline int& failures() {
    static int count = 0;
    return count;
}

struct Registrar {
    Registrar(const char* name, std::function<void()> fn) { registry().push_back({name, std::move(fn)}); }
};

inline void report_failure(const char* file, int line, const std::string& message) {
    ++failures();
    std::fprintf(stderr, "    FAILED %s:%d: %s\n", file, line, message.c_str());
}

}  // namespace testing

#define TEST_CONCAT_INNER(a, b) a##b
#define TEST_CONCAT(a, b) TEST_CONCAT_INNER(a, b)

#define TEST(name)                                                                        \
    static void name();                                                                   \
    static ::testing::Registrar TEST_CONCAT(registrar_, name)(#name, &name);             \
    static void name()

#define CHECK(cond)                                                                       \
    do {                                                                                  \
        if (!(cond)) ::testing::report_failure(__FILE__, __LINE__, "CHECK(" #cond ")");  \
    } while (0)

#define CHECK_EQ(a, b)                                                                    \
    do {                                                                                  \
        const auto& va_ = (a);                                                            \
        const auto& vb_ = (b);                                                            \
        if (!(va_ == vb_))                                                                \
            ::testing::report_failure(__FILE__, __LINE__,                                 \
                                      std::format("CHECK_EQ({}, {}): {} != {}", #a, #b, va_, vb_)); \
    } while (0)

#define REQUIRE(cond)                                                                     \
    do {                                                                                  \
        if (!(cond)) {                                                                    \
            ::testing::report_failure(__FILE__, __LINE__, "REQUIRE(" #cond ")");         \
            return;                                                                       \
        }                                                                                 \
    } while (0)
