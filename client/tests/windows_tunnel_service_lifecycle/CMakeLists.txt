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

find_package(Python3 REQUIRED COMPONENTS Interpreter)
set(MONITOR_FIXTURE "${CMAKE_CURRENT_BINARY_DIR}/monitor_fixture.cpp")
add_custom_command(OUTPUT "${MONITOR_FIXTURE}"
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_LIST_DIR}/test_windowstunnelservicemonitor.py"
        --source "${REPO}/client/platforms/windows/daemon/windowstunnelservice.cpp"
        --out "${CMAKE_CURRENT_BINARY_DIR}" --emit-only
    DEPENDS "${REPO}/client/platforms/windows/daemon/windowstunnelservice.cpp"
        "${CMAKE_CURRENT_LIST_DIR}/test_windowstunnelservicemonitor.py"
    VERBATIM)
add_executable(windows_tunnel_service_monitor_tests "${MONITOR_FIXTURE}")
add_test(NAME windows_tunnel_service_monitor
    COMMAND windows_tunnel_service_monitor_tests)
