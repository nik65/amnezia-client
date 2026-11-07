cmake_minimum_required(VERSION 3.25)

project(AmneziaHyperVSocketRelay LANGUAGES CXX)

if(NOT WIN32)
    message(FATAL_ERROR "AF_HYPERV relay is Windows-only")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(amnezia_hyperv_socket_relay hyperv_socket_relay.cpp)
target_link_libraries(amnezia_hyperv_socket_relay PRIVATE ws2_32)

add_executable(amnezia_hyperv_socket_relay_supervisor hyperv_socket_relay_supervisor.cpp)

if(MSVC)
    target_compile_options(amnezia_hyperv_socket_relay PRIVATE /W4 /WX /permissive-)
    target_compile_options(amnezia_hyperv_socket_relay_supervisor PRIVATE /W4 /WX /permissive-)
else()
    target_compile_options(amnezia_hyperv_socket_relay PRIVATE -Wall -Wextra -Werror)
    target_compile_options(amnezia_hyperv_socket_relay_supervisor PRIVATE -Wall -Wextra -Werror)
endif()
