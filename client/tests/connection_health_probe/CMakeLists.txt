cmake_minimum_required(VERSION 3.16)
project(connection_health_probe_tests LANGUAGES CXX)

enable_testing()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

find_package(Qt6 REQUIRED COMPONENTS Core Network)

add_executable(connection_health_probe_tests
    tst_connection_health_probe.cpp
    ../../core/controllers/connectionHealthController.cpp
    ../../core/controllers/connectionHealthController.h
)

target_include_directories(connection_health_probe_tests PRIVATE ../..)
target_link_libraries(connection_health_probe_tests PRIVATE Qt6::Core Qt6::Network)
if(MSVC)
    target_compile_options(connection_health_probe_tests PRIVATE /W4 /WX /permissive-)
else()
    target_compile_options(connection_health_probe_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()

add_test(NAME connection_health_probe COMMAND connection_health_probe_tests)
