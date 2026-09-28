#include <cstring>

#include "test_framework.h"
#include "ustack/util/log.h"

int main(int argc, char** argv) {
    // Pass -v for stack debug logs, -vv for per-packet traces; optionally a test-name filter.
    ustack::log::threshold() = ustack::log::Level::Error;
    const char* filter = nullptr;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "-v") == 0) {
            ustack::log::threshold() = ustack::log::Level::Debug;
        } else if (std::strcmp(argv[i], "-vv") == 0) {
            ustack::log::threshold() = ustack::log::Level::Trace;
        } else {
            filter = argv[i];
        }
    }

    int run = 0;
    int failed_tests = 0;
    for (const auto& test : testing::registry()) {
        if (filter && !std::strstr(test.name, filter)) continue;
        const int before = testing::failures();
        std::fprintf(stderr, "[ RUN  ] %s\n", test.name);
        test.fn();
        ++run;
        if (testing::failures() != before) {
            ++failed_tests;
            std::fprintf(stderr, "[ FAIL ] %s\n", test.name);
        } else {
            std::fprintf(stderr, "[  OK  ] %s\n", test.name);
        }
    }
    std::fprintf(stderr, "\n%d test(s) run, %d failed\n", run, failed_tests);
    return failed_tests == 0 ? 0 : 1;
}
