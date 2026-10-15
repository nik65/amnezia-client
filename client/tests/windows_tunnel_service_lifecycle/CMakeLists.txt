cmake_minimum_required(VERSION 3.25)

project(WindowsTunnelServiceLifecycle LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

get_filename_component(REPO "${CMAKE_CURRENT_LIST_DIR}/../../.." ABSOLUTE)

add_executable(windows_tunnel_service_lifecycle_tests
    test_windowstunnelservicepolicy.cpp)
target_include_directories(windows_tunnel_service_lifecycle_tests PRIVATE
    "${REPO}/client")

enable_testing()
add_test(NAME windows_tunnel_service_lifecycle
         COMMAND windows_tunnel_service_lifecycle_tests)
