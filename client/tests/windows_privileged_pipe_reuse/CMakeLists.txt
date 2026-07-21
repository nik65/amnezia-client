cmake_minimum_required(VERSION 3.25)

project(WindowsPrivilegedPipeReuseTests LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_AUTOMOC ON)

find_package(Qt6 REQUIRED COMPONENTS Core Core5Compat Network)

enable_testing()

set(REPOSITORY_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../..")

add_executable(windows_privileged_pipe_reuse_tests
    tst_windows_privileged_pipe_reuse.cpp
    "${REPOSITORY_ROOT}/ipc/localpeerauthentication.cpp"
    "${REPOSITORY_ROOT}/ipc/localpeerauthentication.h"
    "${REPOSITORY_ROOT}/ipc/windowsprivilegedpipe.cpp"
    "${REPOSITORY_ROOT}/ipc/windowsprivilegedpipe.h"
)

target_include_directories(windows_privileged_pipe_reuse_tests PRIVATE
    "${REPOSITORY_ROOT}/ipc"
)
target_link_libraries(windows_privileged_pipe_reuse_tests PRIVATE
    Qt6::Core
    Qt6::Core5Compat
    Qt6::Network
    Advapi32
    Authz
)

if(MSVC)
    target_compile_options(windows_privileged_pipe_reuse_tests PRIVATE /W4 /WX /permissive-)
else()
    target_compile_options(windows_privileged_pipe_reuse_tests PRIVATE -Wall -Wextra -Werror)
endif()

add_test(NAME windows_privileged_pipe_reuse COMMAND windows_privileged_pipe_reuse_tests)
