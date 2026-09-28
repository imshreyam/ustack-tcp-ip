cmake_minimum_required(VERSION 3.20)
project(ustack VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "Build type" FORCE)
endif()

option(USTACK_SANITIZE "Build with AddressSanitizer + UndefinedBehaviorSanitizer" OFF)

add_library(ustack_warnings INTERFACE)
target_compile_options(ustack_warnings INTERFACE -Wall -Wextra -Wpedantic -Wshadow -Wnon-virtual-dtor)
if(USTACK_SANITIZE)
  target_compile_options(ustack_warnings INTERFACE -fsanitize=address,undefined -fno-omit-frame-pointer)
  target_link_options(ustack_warnings INTERFACE -fsanitize=address,undefined)
endif()

add_library(ustack STATIC
  src/ustack/core/timer.cpp
  src/ustack/core/event_loop.cpp
  src/ustack/net/address.cpp
  src/ustack/net/checksum.cpp
  src/ustack/net/tap_device.cpp
  src/ustack/net/ethernet.cpp
  src/ustack/net/arp.cpp
  src/ustack/net/ipv4.cpp
  src/ustack/net/icmp.cpp
  src/ustack/net/udp.cpp
  src/ustack/net/tcp_connection.cpp
  src/ustack/net/tcp.cpp
  src/ustack/stack.cpp
  src/ustack/app/http_server.cpp
)
target_include_directories(ustack PUBLIC src)
target_link_libraries(ustack PUBLIC ustack_warnings)

add_executable(ustackd apps/ustackd.cpp)
target_link_libraries(ustackd PRIVATE ustack)

enable_testing()
add_executable(ustack_tests
  tests/test_main.cpp
  tests/test_primitives.cpp
  tests/test_stack_pair.cpp
)
target_link_libraries(ustack_tests PRIVATE ustack)
add_test(NAME ustack_tests COMMAND ustack_tests)
