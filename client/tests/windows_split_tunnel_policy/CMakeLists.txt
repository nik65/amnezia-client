cmake_minimum_required(VERSION 3.25)

project(WindowsSplitTunnelPolicyTests LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

enable_testing()

set(CLIENT_ROOT "${CMAKE_CURRENT_LIST_DIR}/../..")

add_executable(windows_split_tunnel_policy_tests
    tst_windows_split_tunnel_policy.cpp
    "${CLIENT_ROOT}/platforms/windows/daemon/windowssplittunnelpolicy.h"
)

target_include_directories(windows_split_tunnel_policy_tests PRIVATE "${CLIENT_ROOT}")

if(MSVC)
    target_compile_options(windows_split_tunnel_policy_tests PRIVATE /W4 /WX /permissive-)
else()
    target_compile_options(windows_split_tunnel_policy_tests PRIVATE -Wall -Wextra -Werror)
endif()

add_test(NAME windows_split_tunnel_policy COMMAND windows_split_tunnel_policy_tests)
