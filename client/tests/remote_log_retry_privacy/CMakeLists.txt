cmake_minimum_required(VERSION 3.16)
project(tst_remote_log_retry_privacy LANGUAGES CXX)

set(CMAKE_AUTOMOC ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Qt6 REQUIRED COMPONENTS Core Test)

add_executable(tst_remote_log_retry_privacy
    tst_remote_log_retry_privacy.cpp
)
target_include_directories(tst_remote_log_retry_privacy PRIVATE ../..)
target_link_libraries(tst_remote_log_retry_privacy PRIVATE Qt6::Core Qt6::Test)

enable_testing()
add_test(NAME remote_log_retry_privacy COMMAND tst_remote_log_retry_privacy)
