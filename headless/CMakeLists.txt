cmake_minimum_required(VERSION 3.25)

project(AmneziaVPNHeadless LANGUAGES CXX)

set(AMNEZIA_HEADLESS_UPDATE_PUBLIC_KEY "" CACHE FILEPATH
    "Provisioning-time Ed25519 public key; never supplied by an update archive")

if(NOT UNIX OR APPLE OR ANDROID OR IOS)
    message(FATAL_ERROR "AmneziaVPNHeadless requires a native Linux build")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

include(GNUInstallDirs)
find_package(Qt6 REQUIRED COMPONENTS Core Network)
option(BUILD_TESTING "Build headless test executables" OFF)
if(BUILD_TESTING)
    find_package(Qt6 REQUIRED COMPONENTS Test)
endif()
find_package(OpenSSL REQUIRED COMPONENTS Crypto)

add_library(amnezia_headless_core STATIC
    headlessProtocol.cpp
    headlessProtocol.h
    profileStore.cpp
    profileStore.h
    serverRoutingPolicy.cpp
    serverRoutingPolicy.h
    linuxRouteReconciler.cpp
    linuxRouteReconciler.h
    headlessRoutingController.cpp
    headlessRoutingController.h
    headlessUpdateManager.cpp
    headlessUpdateManager.h
    vpnBackend.cpp
    vpnBackend.h
    privilegedDaemonBridge.cpp
    privilegedDaemonBridge.h
    daemon.cpp
    daemon.h
)
target_include_directories(amnezia_headless_core PUBLIC "${CMAKE_CURRENT_LIST_DIR}")
target_link_libraries(amnezia_headless_core PUBLIC Qt6::Core Qt6::Network OpenSSL::Crypto)
if(NOT DEFINED HEADLESS_BUILD_VERSION OR HEADLESS_BUILD_VERSION STREQUAL "")
    if(DEFINED AMNEZIAVPN_VERSION AND NOT AMNEZIAVPN_VERSION STREQUAL "")
        set(HEADLESS_BUILD_VERSION "${AMNEZIAVPN_VERSION}")
    else()
        set(HEADLESS_BUILD_VERSION "5.0.1.16")
    endif()
endif()
target_compile_definitions(amnezia_headless_core PUBLIC
    AMNEZIA_HEADLESS_VERSION="${HEADLESS_BUILD_VERSION}")

add_executable(amneziad daemonMain.cpp)
target_link_libraries(amneziad PRIVATE amnezia_headless_core Qt6::Core Qt6::Network)

add_executable(amnezia-cli cli.cpp)
target_link_libraries(amnezia-cli PRIVATE amnezia_headless_core Qt6::Core Qt6::Network)

if(BUILD_TESTING)
add_executable(headless_protocol_tests
    tests/tst_headless_protocol.cpp
)
target_link_libraries(headless_protocol_tests PRIVATE amnezia_headless_core Qt6::Core Qt6::Test)

add_executable(headless_daemon_tests
    tests/tst_headless_daemon.cpp
)
target_link_libraries(headless_daemon_tests PRIVATE amnezia_headless_core Qt6::Core Qt6::Network Qt6::Test)

add_executable(headless_profile_store_tests
    tests/tst_profile_store.cpp
)
target_link_libraries(headless_profile_store_tests PRIVATE amnezia_headless_core Qt6::Core Qt6::Test)

add_executable(headless_vpn_backend_tests
    tests/tst_vpn_backend.cpp
)
target_link_libraries(headless_vpn_backend_tests PRIVATE amnezia_headless_core Qt6::Core Qt6::Network Qt6::Test)

add_executable(headless_privileged_daemon_bridge_tests
    tests/tst_privileged_daemon_bridge.cpp
)
target_link_libraries(headless_privileged_daemon_bridge_tests PRIVATE amnezia_headless_core Qt6::Core Qt6::Network Qt6::Test)

add_executable(headless_server_routing_tests
    tests/tst_server_routing.cpp
)
target_link_libraries(headless_server_routing_tests PRIVATE amnezia_headless_core Qt6::Core Qt6::Network Qt6::Test)

add_executable(headless_update_tests
    tests/tst_headless_updates.cpp
)
target_link_libraries(headless_update_tests PRIVATE amnezia_headless_core Qt6::Core Qt6::Network Qt6::Test)

enable_testing()
add_test(NAME headless_protocol COMMAND headless_protocol_tests)
add_test(NAME headless_daemon COMMAND headless_daemon_tests)
add_test(NAME headless_profile_store COMMAND headless_profile_store_tests)
add_test(NAME headless_vpn_backend COMMAND headless_vpn_backend_tests)
add_test(NAME headless_privileged_daemon_bridge COMMAND headless_privileged_daemon_bridge_tests)
add_test(NAME headless_server_routing COMMAND headless_server_routing_tests)
add_test(NAME headless_updates COMMAND headless_update_tests)
endif()

configure_file(
    "${CMAKE_CURRENT_LIST_DIR}/amneziad.service.in"
    "${CMAKE_CURRENT_BINARY_DIR}/amneziad.service"
    @ONLY
)

install(TARGETS amneziad amnezia-cli
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/amneziad.service"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/systemd/system"
)
if(AMNEZIA_HEADLESS_UPDATE_PUBLIC_KEY)
    install(FILES "${AMNEZIA_HEADLESS_UPDATE_PUBLIC_KEY}"
        DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}/amnezia"
        RENAME "update-public-key.pem"
        PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
endif()
