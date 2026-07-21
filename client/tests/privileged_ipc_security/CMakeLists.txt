cmake_minimum_required(VERSION 3.25)

project(PrivilegedIpcSecurityTests LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_AUTOMOC ON)

find_package(Qt6 REQUIRED COMPONENTS Core Core5Compat Network)

enable_testing()

set(REPOSITORY_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../..")

add_executable(privileged_ipc_security_tests
    tst_privileged_ipc_security.cpp
    "${REPOSITORY_ROOT}/ipc/localpeerauthentication.cpp"
    "${REPOSITORY_ROOT}/ipc/localpeerauthentication.h"
    "${REPOSITORY_ROOT}/ipc/ipc.h"
)

target_include_directories(privileged_ipc_security_tests PRIVATE
    "${REPOSITORY_ROOT}/ipc"
    "${REPOSITORY_ROOT}/client"
)
target_link_libraries(privileged_ipc_security_tests PRIVATE Qt6::Core Qt6::Core5Compat Qt6::Network)

if(WIN32)
    target_sources(privileged_ipc_security_tests PRIVATE
        "${REPOSITORY_ROOT}/ipc/windowsprivilegedpipe.cpp"
        "${REPOSITORY_ROOT}/ipc/windowsprivilegedpipe.h"
    )
    target_link_libraries(privileged_ipc_security_tests PRIVATE Advapi32)
endif()

if(APPLE)
    find_library(FW_COREFOUNDATION CoreFoundation REQUIRED)
    find_library(FW_SECURITY Security REQUIRED)
    find_library(LIB_PROC proc REQUIRED)
    target_link_libraries(privileged_ipc_security_tests PRIVATE
        ${FW_COREFOUNDATION}
        ${FW_SECURITY}
        ${LIB_PROC}
    )
endif()

if(MSVC)
    target_compile_options(privileged_ipc_security_tests PRIVATE /W4 /WX /permissive-)
else()
    target_compile_options(privileged_ipc_security_tests PRIVATE -Wall -Wextra -Werror)
endif()

add_test(NAME privileged_ipc_security COMMAND privileged_ipc_security_tests)
