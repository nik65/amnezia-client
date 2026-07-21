cmake_minimum_required(VERSION 3.25)

project(RemoteLogSanitizerTests LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
find_package(Qt6 REQUIRED COMPONENTS Core)

enable_testing()

set(CLIENT_ROOT "${CMAKE_CURRENT_LIST_DIR}/../..")

add_executable(remote_log_sanitizer_tests
    tst_remote_log_sanitizer.cpp
    "${CLIENT_ROOT}/core/utils/remoteLogSanitizer.cpp"
    "${CLIENT_ROOT}/core/utils/remoteLogSanitizer.h"
)

target_include_directories(remote_log_sanitizer_tests PRIVATE "${CLIENT_ROOT}")
target_link_libraries(remote_log_sanitizer_tests PRIVATE Qt6::Core)
if(MSVC)
    target_compile_options(remote_log_sanitizer_tests PRIVATE /W4 /WX)
endif()

add_test(NAME remote_log_sanitizer COMMAND remote_log_sanitizer_tests)
