cmake_minimum_required(VERSION 3.25)
project(ManagedRouteSemanticContext LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_AUTOMOC ON)
find_package(Qt6 REQUIRED COMPONENTS Core Network Test)
find_package(Python3 REQUIRED COMPONENTS Interpreter)
get_filename_component(REPO "${CMAKE_CURRENT_LIST_DIR}/../../.." ABSOLUTE)
set(FIXTURE "${CMAKE_CURRENT_BINARY_DIR}/production_context.inc")
add_custom_command(OUTPUT "${FIXTURE}"
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_LIST_DIR}/extract.py" "${REPO}" "${FIXTURE}"
    DEPENDS "${REPO}/client/vpnConnection.cpp" "${REPO}/client/core/utils/networkUtilities.cpp"
            "${REPO}/client/tests/vpn_log_recovery/test_worker.cpp" extract.py production_helpers.py VERBATIM)
add_executable(managed_route_semantic_context test_context.cpp "${FIXTURE}")
set_source_files_properties("${FIXTURE}" PROPERTIES SKIP_AUTOMOC ON)
target_include_directories(managed_route_semantic_context PRIVATE "${REPO}/client" "${CMAKE_CURRENT_BINARY_DIR}")
target_link_libraries(managed_route_semantic_context PRIVATE Qt6::Core Qt6::Network Qt6::Test)
enable_testing()
add_test(NAME managed_route_semantic_context COMMAND managed_route_semantic_context)
