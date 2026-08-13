cmake_minimum_required(VERSION 3.25)

project(ManagedDnsConvergenceTests LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

find_package(Qt6 REQUIRED COMPONENTS Core Test)

enable_testing()

set(CLIENT_ROOT "${CMAKE_CURRENT_LIST_DIR}/../..")

add_executable(managed_dns_convergence_tests
    tst_managed_dns_convergence.cpp
    "${CLIENT_ROOT}/core/utils/managedDnsConvergence.h"
)

target_include_directories(managed_dns_convergence_tests PRIVATE "${CLIENT_ROOT}")
target_link_libraries(managed_dns_convergence_tests PRIVATE Qt6::Core Qt6::Test)

if(MSVC)
    target_compile_options(managed_dns_convergence_tests PRIVATE /W4 /WX /permissive-)
else()
    target_compile_options(managed_dns_convergence_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()

add_test(NAME managed_dns_convergence COMMAND managed_dns_convergence_tests)
