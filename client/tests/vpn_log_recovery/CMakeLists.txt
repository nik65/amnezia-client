cmake_minimum_required(VERSION 3.25)
project(VpnLogRecoveryTests LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_AUTOMOC ON)
find_package(Qt6 REQUIRED COMPONENTS Core Gui Network Test)
find_package(Python3 REQUIRED COMPONENTS Interpreter)
enable_testing()
get_filename_component(REPO "${CMAKE_CURRENT_LIST_DIR}/../../.." ABSOLUTE)
set(GENERATED_METHODS "${CMAKE_CURRENT_BINARY_DIR}/production_methods.inc")
add_custom_command(OUTPUT "${GENERATED_METHODS}"
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_LIST_DIR}/extract_worker_methods.py"
            "${REPO}/client/vpnConnection.cpp" "${GENERATED_METHODS}"
    DEPENDS "${REPO}/client/vpnConnection.cpp" extract_worker_methods.py
    VERBATIM)
add_executable(vpn_route_recovery_tests test_worker.cpp "${GENERATED_METHODS}")
set_source_files_properties("${GENERATED_METHODS}" PROPERTIES SKIP_AUTOMOC ON)
target_include_directories(vpn_route_recovery_tests PRIVATE "${REPO}/client" "${CMAKE_CURRENT_BINARY_DIR}")
target_link_libraries(vpn_route_recovery_tests PRIVATE Qt6::Core Qt6::Network Qt6::Test)
add_test(NAME vpn_route_recovery COMMAND vpn_route_recovery_tests)

add_executable(exclusion_transaction_tests test_exclusion_transaction.cpp)
target_include_directories(exclusion_transaction_tests PRIVATE "${REPO}/client")
target_link_libraries(exclusion_transaction_tests PRIVATE Qt6::Core Qt6::Test)
add_test(NAME exclusion_transaction COMMAND exclusion_transaction_tests)

file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/version.h"
    "#define APPLICATION_NAME \"TunnelLoggerUnitTest\"\n#define SERVICE_NAME \"TunnelLoggerUnitTestService\"\n")
add_executable(daemon_exclusion_tests test_daemon_exclusions.cpp
    "${REPO}/client/daemon/daemon.cpp" "${REPO}/client/daemon/daemon.h"
    "${REPO}/client/daemon/wireguardutils.h" "${REPO}/client/daemon/dnsutils.h"
    "${REPO}/client/daemon/interfaceconfig.cpp" "${REPO}/client/daemon/interfaceconfig.h"
    "${REPO}/client/mozilla/shared/ipaddress.cpp"
    "${REPO}/common/logger/logger.cpp" "${REPO}/common/logger/logger.h")
target_include_directories(daemon_exclusion_tests PRIVATE "${REPO}/client" "${REPO}/client/mozilla/shared"
    "${REPO}/common/logger" "${CMAKE_CURRENT_BINARY_DIR}")
target_link_libraries(daemon_exclusion_tests PRIVATE Qt6::Core Qt6::Network Qt6::Gui Qt6::Test)
add_test(NAME daemon_exclusions COMMAND daemon_exclusion_tests)

add_executable(daemon_deactivate_cleanup_tests test_daemon_deactivate_cleanup.cpp
    "${REPO}/client/daemon/daemon.cpp" "${REPO}/client/daemon/daemon.h"
    "${REPO}/client/daemon/wireguardutils.h" "${REPO}/client/daemon/dnsutils.h"
    "${REPO}/client/daemon/interfaceconfig.cpp" "${REPO}/client/daemon/interfaceconfig.h"
    "${REPO}/client/mozilla/shared/ipaddress.cpp"
    "${REPO}/common/logger/logger.cpp" "${REPO}/common/logger/logger.h")
target_include_directories(daemon_deactivate_cleanup_tests PRIVATE "${REPO}/client"
    "${REPO}/client/mozilla/shared" "${REPO}/common/logger" "${CMAKE_CURRENT_BINARY_DIR}")
target_link_libraries(daemon_deactivate_cleanup_tests PRIVATE Qt6::Core Qt6::Network Qt6::Gui Qt6::Test)
add_test(NAME daemon_deactivate_cleanup COMMAND daemon_deactivate_cleanup_tests)

add_executable(tunnel_logger_recovery_tests test_tunnel_logger.cpp
    "${REPO}/client/platforms/windows/daemon/windowstunnellogger.cpp"
    "${REPO}/client/platforms/windows/daemon/windowstunnellogger.h"
    "${REPO}/common/logger/logger.cpp" "${REPO}/common/logger/logger.h")
target_include_directories(tunnel_logger_recovery_tests PRIVATE
    "${REPO}/client" "${REPO}/common/logger" "${REPO}/client/mozilla/shared" "${CMAKE_CURRENT_BINARY_DIR}")
target_link_libraries(tunnel_logger_recovery_tests PRIVATE Qt6::Core Qt6::Gui Qt6::Test)
add_test(NAME tunnel_logger_recovery COMMAND tunnel_logger_recovery_tests)
add_test(NAME tunnel_logger_warning_bound COMMAND "${Python3_EXECUTABLE}"
    "${CMAKE_CURRENT_LIST_DIR}/verify_warning_bound.py" "$<TARGET_FILE:tunnel_logger_recovery_tests>")

if(WIN32)
    add_executable(windows_route_monitor_tests test_windows_route_monitor.cpp
        "${REPO}/client/platforms/windows/daemon/windowsroutemonitor.h"
        "${REPO}/client/mozilla/shared/ipaddress.cpp"
        "${REPO}/common/logger/logger.cpp" "${REPO}/common/logger/logger.h")
    target_include_directories(windows_route_monitor_tests PRIVATE "${REPO}/client"
        "${REPO}/client/mozilla/shared" "${REPO}/common/logger" "${CMAKE_CURRENT_BINARY_DIR}")
    target_compile_definitions(windows_route_monitor_tests PRIVATE _WINSOCKAPI_)
    target_link_libraries(windows_route_monitor_tests PRIVATE Qt6::Core Qt6::Gui Qt6::Network Qt6::Test iphlpapi)
    add_test(NAME windows_route_monitor COMMAND windows_route_monitor_tests)
    # Compile the real watcher without starting a product or changing the host.
    add_library(windows_watcher_compile OBJECT "${REPO}/client/platforms/windows/windowsnetworkwatcher.cpp"
        "${REPO}/client/platforms/windows/daemon/windowsroutemonitor.cpp"
        "${REPO}/client/platforms/windows/daemon/wireguardutilswindows.cpp"
        "${REPO}/client/platforms/windows/daemon/windowstunnelservice.cpp"
        "${REPO}/client/platforms/windows/daemon/windowstunnellogger.cpp"
        "${REPO}/client/daemon/daemon.cpp")
    target_include_directories(windows_watcher_compile PRIVATE "${REPO}/client" "${REPO}/client/mozilla"
        "${REPO}/common/logger" "${REPO}/client/mozilla/shared")
    target_compile_definitions(windows_watcher_compile PRIVATE _WINSOCKAPI_)
    target_link_libraries(windows_watcher_compile PRIVATE Qt6::Core Qt6::Network)
endif()
