cmake_minimum_required(VERSION 3.25)

project(WindowsUapiPeerContracts LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_AUTOMOC ON)

find_package(Qt6 REQUIRED COMPONENTS Core Gui Network Test)

enable_testing()
get_filename_component(REPO "${CMAKE_CURRENT_LIST_DIR}/../../.." ABSOLUTE)
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/version.h"
    "#define APPLICATION_NAME \"WindowsUapiPeerContractTests\"\n"
    "#define SERVICE_NAME \"WindowsUapiPeerContractTestsService\"\n")

add_executable(windows_uapi_result_tests test_uapi_result.cpp)
target_include_directories(windows_uapi_result_tests PRIVATE "${REPO}/client")
target_link_libraries(windows_uapi_result_tests PRIVATE Qt6::Core Qt6::Test)
add_test(NAME windows_uapi_result COMMAND windows_uapi_result_tests)

add_executable(windows_uapi_transport_tests
    test_uapi_transport.cpp
    "${REPO}/common/logger/logger.cpp"
    "${REPO}/common/logger/logger.h"
    "${REPO}/client/platforms/windows/daemon/windowstunnelservice.h"
    "${REPO}/client/platforms/windows/daemon/windowstunnellogger.h")
target_include_directories(windows_uapi_transport_tests PRIVATE
    "${REPO}/client" "${REPO}/client/mozilla/shared" "${REPO}/common/logger"
    "${CMAKE_CURRENT_BINARY_DIR}")
target_compile_definitions(windows_uapi_transport_tests PRIVATE _WINSOCKAPI_)
target_link_libraries(windows_uapi_transport_tests PRIVATE Qt6::Core Qt6::Gui Qt6::Network Qt6::Test)
add_test(NAME windows_uapi_transport COMMAND windows_uapi_transport_tests)

add_executable(windows_peer_behavior_tests
    test_windows_peer_behavior.cpp
    "${REPO}/client/daemon/interfaceconfig.cpp"
    "${REPO}/client/mozilla/shared/ipaddress.cpp"
    "${REPO}/common/logger/logger.cpp"
    "${REPO}/client/daemon/wireguardutils.h"
    "${REPO}/client/platforms/windows/daemon/wireguardutilswindows.h"
    "${REPO}/client/platforms/windows/daemon/windowstunnelservice.h"
    "${REPO}/client/platforms/windows/daemon/windowsroutemonitor.h"
    "${REPO}/client/platforms/windows/daemon/windowsfirewall.h")
target_include_directories(windows_peer_behavior_tests PRIVATE
    "${REPO}/client" "${REPO}/client/mozilla/shared" "${REPO}/common/logger"
    "${CMAKE_CURRENT_BINARY_DIR}")
target_compile_definitions(windows_peer_behavior_tests PRIVATE _WINSOCKAPI_)
target_link_libraries(windows_peer_behavior_tests PRIVATE Qt6::Core Qt6::Gui Qt6::Network Qt6::Test)
add_test(NAME windows_peer_behavior COMMAND windows_peer_behavior_tests)
