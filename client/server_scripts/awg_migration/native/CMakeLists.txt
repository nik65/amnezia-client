cmake_minimum_required(VERSION 3.16)
project(awg_migration_native LANGUAGES CXX)
if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux" OR NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "AWG server runtime requires 64-bit Linux descriptor semantics")
endif()
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED COMPONENTS Crypto)
find_package(SQLite3 REQUIRED)
find_path(JSON_C_INCLUDE_DIR NAMES json-c/json.h)
find_library(JSON_C_LIBRARY NAMES json-c)
find_path(RAPIDJSON_INCLUDE_DIR NAMES rapidjson/reader.h)
if(NOT JSON_C_INCLUDE_DIR OR NOT JSON_C_LIBRARY OR NOT RAPIDJSON_INCLUDE_DIR)
    message(FATAL_ERROR "Native AWG requires json-c and RapidJSON development headers; supply verified dependency paths")
endif()
function(awg_native_target target)
    target_compile_features(${target} PUBLIC cxx_std_17)
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Werror)
endfunction()
add_library(awg_feed_file feed_file.cpp)
awg_native_target(awg_feed_file)
target_include_directories(awg_feed_file PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
add_executable(awg_feed_probe feed_probe.cpp)
awg_native_target(awg_feed_probe)
target_link_libraries(awg_feed_probe PRIVATE awg_feed_file)
add_executable(awg_feed_server feed_server.cpp)
awg_native_target(awg_feed_server)
target_link_libraries(awg_feed_server PRIVATE awg_feed_file Threads::Threads OpenSSL::Crypto)
add_library(awg_ready_config ready_config.cpp)
awg_native_target(awg_ready_config)
target_include_directories(awg_ready_config PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
add_executable(awg_ready_config_check ready_config_check.cpp)
awg_native_target(awg_ready_config_check)
target_link_libraries(awg_ready_config_check PRIVATE awg_ready_config)

# Pure private config adapter shares the authenticated feed executable.
target_sources(awg_feed_server PRIVATE ready_config_runtime.cpp)
target_include_directories(awg_feed_server PRIVATE "${JSON_C_INCLUDE_DIR}")
target_link_libraries(awg_feed_server PRIVATE awg_ready_config "${JSON_C_LIBRARY}")

# Server-only components. Explicit native adapters are selected by reviewed callers;
# ordinary deployment remains Python until binary delivery/recovery are proven.
add_library(awg_planner_catalog automatic_plan.cpp trusted_image.cpp)
add_library(awg_policy policy.cpp)
add_library(awg_ready_attestation ready_attestation.cpp)
add_library(awg_transaction_journal transaction_journal.cpp)
add_library(awg_control_service control_service.cpp)
foreach(component IN ITEMS awg_planner_catalog awg_policy awg_ready_attestation awg_transaction_journal awg_control_service)
    awg_native_target(${component})
    target_include_directories(${component} PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}" "${JSON_C_INCLUDE_DIR}")
    target_link_libraries(${component} PUBLIC "${JSON_C_LIBRARY}")
endforeach()
target_include_directories(awg_policy SYSTEM PRIVATE "${RAPIDJSON_INCLUDE_DIR}")

target_link_libraries(awg_planner_catalog PUBLIC OpenSSL::Crypto)
target_include_directories(awg_planner_catalog SYSTEM PRIVATE "${RAPIDJSON_INCLUDE_DIR}")
target_link_libraries(awg_ready_attestation PUBLIC awg_ready_config OpenSSL::Crypto)
target_include_directories(awg_ready_attestation SYSTEM PRIVATE "${RAPIDJSON_INCLUDE_DIR}")
add_library(awg_bounded_docker bounded_docker.cpp)
awg_native_target(awg_bounded_docker)
target_include_directories(awg_bounded_docker PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
add_library(awg_ready_runtime ready_runtime.cpp)
awg_native_target(awg_ready_runtime)
target_include_directories(awg_ready_runtime SYSTEM PRIVATE "${RAPIDJSON_INCLUDE_DIR}")
target_link_libraries(awg_ready_runtime PUBLIC awg_ready_attestation awg_bounded_docker)
target_link_libraries(awg_feed_server PRIVATE awg_ready_runtime awg_bounded_docker)
add_library(awg_automatic_runtime automatic_runtime.cpp)
awg_native_target(awg_automatic_runtime)
target_include_directories(awg_automatic_runtime SYSTEM PRIVATE "${RAPIDJSON_INCLUDE_DIR}")
target_link_libraries(awg_automatic_runtime PUBLIC awg_planner_catalog awg_bounded_docker)
target_link_libraries(awg_feed_server PRIVATE awg_automatic_runtime)
add_library(awg_trusted_image_runtime trusted_image_runtime.cpp)
awg_native_target(awg_trusted_image_runtime)
target_link_libraries(awg_trusted_image_runtime PUBLIC awg_planner_catalog awg_bounded_docker)
target_link_libraries(awg_feed_server PRIVATE awg_trusted_image_runtime)
add_library(awg_config_generation config_generation.cpp config_generation_runtime.cpp)
awg_native_target(awg_config_generation)
target_include_directories(awg_config_generation SYSTEM PRIVATE "${RAPIDJSON_INCLUDE_DIR}")
target_include_directories(awg_config_generation PRIVATE "${JSON_C_INCLUDE_DIR}")
target_link_libraries(awg_config_generation PUBLIC awg_ready_config OpenSSL::Crypto "${JSON_C_LIBRARY}")
target_link_libraries(awg_feed_server PRIVATE awg_config_generation)
target_link_libraries(awg_transaction_journal PUBLIC OpenSSL::Crypto)
target_link_libraries(awg_control_service PUBLIC OpenSSL::Crypto SQLite::SQLite3)
add_library(awg_control_runtime control_runtime.cpp)
awg_native_target(awg_control_runtime)
target_include_directories(awg_control_runtime SYSTEM PRIVATE "${RAPIDJSON_INCLUDE_DIR}")
target_link_libraries(awg_control_runtime PUBLIC awg_control_service)
target_link_libraries(awg_feed_server PRIVATE awg_control_runtime)
# The delivered feed executable also hosts bounded native policy commands.
target_sources(awg_feed_server PRIVATE policy_runtime.cpp)
target_include_directories(awg_feed_server SYSTEM PRIVATE "${RAPIDJSON_INCLUDE_DIR}")
target_link_libraries(awg_feed_server PRIVATE awg_policy)

target_include_directories(awg_control_service SYSTEM PRIVATE "${RAPIDJSON_INCLUDE_DIR}")

# Pure topology core plus bounded read-only observations for explicit native callers.
add_library(awg_network_topology network_topology.cpp network_topology_runtime.cpp network_observer.cpp)
awg_native_target(awg_network_topology)
target_include_directories(awg_network_topology PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}" "${JSON_C_INCLUDE_DIR}")
target_include_directories(awg_network_topology SYSTEM PRIVATE "${RAPIDJSON_INCLUDE_DIR}")
target_link_libraries(awg_network_topology PUBLIC "${JSON_C_LIBRARY}" awg_bounded_docker)
target_link_libraries(awg_feed_server PRIVATE awg_network_topology)
# Fixed source-config observation adapter, private before listener setup.
add_library(awg_source_config_runtime source_config_runtime.cpp)
awg_native_target(awg_source_config_runtime)
target_include_directories(awg_source_config_runtime SYSTEM PRIVATE "${RAPIDJSON_INCLUDE_DIR}")
target_include_directories(awg_source_config_runtime PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}" "${JSON_C_INCLUDE_DIR}")
target_link_libraries(awg_source_config_runtime PUBLIC awg_ready_config awg_bounded_docker "${JSON_C_LIBRARY}")
target_link_libraries(awg_feed_server PRIVATE awg_source_config_runtime)
include(CTest)
if(BUILD_TESTING)
    find_package(Python3 COMPONENTS Interpreter REQUIRED)
    add_executable(awg_feed_file_tests test_feed_file.cpp)
    awg_native_target(awg_feed_file_tests)
    target_link_libraries(awg_feed_file_tests PRIVATE awg_feed_file)
    add_test(NAME awg_feed_file COMMAND awg_feed_file_tests)
    set_tests_properties(awg_feed_file PROPERTIES TIMEOUT 15)
    add_test(NAME awg_feed_http COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/test_feed_http.py" "$<TARGET_FILE:awg_feed_server>")
    set_tests_properties(awg_feed_http PROPERTIES TIMEOUT 40)
    add_test(NAME awg_feed_parity COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/test_feed_parity.py" "$<TARGET_FILE:awg_feed_probe>")
    set_tests_properties(awg_feed_parity PROPERTIES TIMEOUT 30)
    add_executable(awg_ready_config_tests test_ready_config.cpp)
    awg_native_target(awg_ready_config_tests)
    target_link_libraries(awg_ready_config_tests PRIVATE awg_ready_config)
    add_executable(awg_ready_config_probe ready_config_probe.cpp)
    awg_native_target(awg_ready_config_probe)
    target_link_libraries(awg_ready_config_probe PRIVATE awg_ready_config)
    add_test(NAME awg_ready_config COMMAND awg_ready_config_tests)
    add_test(NAME awg_ready_config_runtime COMMAND "${Python3_EXECUTABLE}" -B
        "${CMAKE_CURRENT_SOURCE_DIR}/test_native_config_runtime.py" "$<TARGET_FILE:awg_feed_server>")
    set_tests_properties(awg_ready_config_runtime PROPERTIES TIMEOUT 20)

    add_test(NAME awg_native_config_bridge
        COMMAND "${CMAKE_COMMAND}" -E env "AWG_CONFIG_TEST_BIN=$<TARGET_FILE:awg_feed_server>"
            "${Python3_EXECUTABLE}" -B -m unittest test_native_config_bridge -v)
    set_tests_properties(awg_native_config_bridge PROPERTIES
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/.." TIMEOUT 40)
    add_test(NAME awg_ready_config_parity COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/test_ready_config_parity.py" --probe "$<TARGET_FILE:awg_ready_config_probe>")
    set_tests_properties(awg_ready_config awg_ready_config_parity PROPERTIES TIMEOUT 30)

    add_executable(awg_automatic_plan_tests test_automatic_plan.cpp)
    target_link_libraries(awg_automatic_plan_tests PRIVATE awg_planner_catalog)
    add_executable(awg_automatic_plan_probe automatic_plan_probe.cpp)
    target_link_libraries(awg_automatic_plan_probe PRIVATE awg_planner_catalog)
    add_executable(awg_policy_tests test_policy.cpp)
    target_link_libraries(awg_policy_tests PRIVATE awg_policy)
    add_executable(awg_policy_probe policy_probe.cpp)
    target_link_libraries(awg_policy_probe PRIVATE awg_policy)
    add_executable(awg_policy_file_probe policy_file_probe.cpp)
    target_link_libraries(awg_policy_file_probe PRIVATE awg_policy)
    # Test-only interposers operate solely on explicitly named owned fixtures.
    # These libraries are never linked into or installed with runtime targets.
    add_library(awg_policy_fs_hook SHARED test_policy_fs_hook.cpp)
    target_link_libraries(awg_policy_fs_hook PRIVATE ${CMAKE_DL_LIBS})
    add_library(awg_ready_attestation_read_swap SHARED test_ready_attestation_read_swap.cpp)
    target_link_libraries(awg_ready_attestation_read_swap PRIVATE ${CMAKE_DL_LIBS})
    add_executable(awg_ready_attestation_probe test_ready_attestation_probe.cpp)
    target_link_libraries(awg_ready_attestation_probe PRIVATE awg_ready_attestation awg_planner_catalog)
    add_executable(awg_transaction_journal_tests test_transaction_journal.cpp)
    target_link_libraries(awg_transaction_journal_tests PRIVATE awg_transaction_journal)
    add_executable(awg_transaction_journal_probe transaction_journal_probe.cpp)
    target_link_libraries(awg_transaction_journal_probe PRIVATE awg_transaction_journal)
    add_executable(awg_control_probe test_control_probe.cpp)
    target_link_libraries(awg_control_probe PRIVATE awg_control_service)
    foreach(probe IN ITEMS awg_automatic_plan_tests awg_automatic_plan_probe awg_policy_tests awg_policy_probe
            awg_policy_file_probe awg_policy_fs_hook awg_ready_attestation_read_swap
            awg_ready_attestation_probe awg_transaction_journal_tests awg_transaction_journal_probe awg_control_probe)
        awg_native_target(${probe})
    endforeach()
    add_test(NAME awg_automatic_plan COMMAND awg_automatic_plan_tests)
    add_test(NAME awg_automatic_plan_parity COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/test_automatic_plan_parity.py" --probe "$<TARGET_FILE:awg_automatic_plan_probe>")
    add_test(NAME awg_policy COMMAND awg_policy_tests)
    add_test(NAME awg_policy_parity COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/test_policy_parity.py" --probe "$<TARGET_FILE:awg_policy_probe>")
    add_test(NAME awg_policy_filesystem COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/test_policy_filesystem.py" --probe "$<TARGET_FILE:awg_policy_file_probe>"
        --hook "$<TARGET_FILE:awg_policy_fs_hook>")
    add_test(NAME awg_ready_attestation_parity COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/test_ready_attestation_parity.py" --probe "$<TARGET_FILE:awg_ready_attestation_probe>"
        --swap-library "$<TARGET_FILE:awg_ready_attestation_read_swap>")
    add_test(NAME awg_transaction_journal COMMAND awg_transaction_journal_tests)
    add_test(NAME awg_transaction_journal_parity COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/test_transaction_journal_parity.py" "$<TARGET_FILE:awg_transaction_journal_probe>")
    add_test(NAME awg_control_canonical COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/test_control_parity.py" "$<TARGET_FILE:awg_control_probe>")
    add_test(NAME awg_control_dispatch COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/test_control_dispatch.py" "$<TARGET_FILE:awg_control_probe>" "$<TARGET_FILE:awg_feed_server>")
    add_executable(awg_control_runtime_tests test_control_runtime.cpp)
    awg_native_target(awg_control_runtime_tests)
    target_compile_options(awg_control_runtime_tests PRIVATE -UNDEBUG)
    target_link_libraries(awg_control_runtime_tests PRIVATE awg_control_runtime)
    add_test(NAME awg_control_runtime COMMAND awg_control_runtime_tests)
    set_tests_properties(awg_control_runtime PROPERTIES TIMEOUT 25)
    add_executable(awg_control_runtime_fixture test_control_runtime_fixture.cpp)
    awg_native_target(awg_control_runtime_fixture)
    target_link_libraries(awg_control_runtime_fixture PRIVATE awg_control_runtime)
    add_test(NAME awg_control_runtime_bridge
        COMMAND "${CMAKE_COMMAND}" -E env "AWG_CONTROL_TEST_BIN=$<TARGET_FILE:awg_control_runtime_fixture>"
            "${Python3_EXECUTABLE}" -B -m unittest test_native_control_runtime -v)
    set_tests_properties(awg_control_runtime_bridge PROPERTIES
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/.." TIMEOUT 45)
    add_executable(awg_automatic_runtime_tests test_automatic_runtime.cpp)
    awg_native_target(awg_automatic_runtime_tests)
    target_link_libraries(awg_automatic_runtime_tests PRIVATE awg_automatic_runtime)
    add_test(NAME awg_automatic_runtime COMMAND awg_automatic_runtime_tests)
    set_tests_properties(awg_automatic_runtime PROPERTIES TIMEOUT 30)
    add_library(awg_planner_read_swap SHARED test_automatic_plan_read_swap.cpp)
    awg_native_target(awg_planner_read_swap)
    target_link_libraries(awg_planner_read_swap PRIVATE ${CMAKE_DL_LIBS})
    add_test(NAME awg_automatic_plan_stability COMMAND "${Python3_EXECUTABLE}" -B
        "${CMAKE_CURRENT_SOURCE_DIR}/test_automatic_plan_stability.py"
        --probe "$<TARGET_FILE:awg_automatic_plan_probe>" --hook "$<TARGET_FILE:awg_planner_read_swap>")
    set_tests_properties(awg_automatic_plan_stability PROPERTIES TIMEOUT 30)
    add_executable(awg_ready_runtime_tests test_ready_runtime.cpp)
    awg_native_target(awg_ready_runtime_tests)
    target_compile_options(awg_ready_runtime_tests PRIVATE -UNDEBUG)
    target_link_libraries(awg_ready_runtime_tests PRIVATE awg_ready_runtime)
    add_test(NAME awg_ready_runtime COMMAND awg_ready_runtime_tests)
    set_tests_properties(awg_ready_runtime PROPERTIES TIMEOUT 30)
    add_executable(awg_ready_runtime_fixture test_ready_runtime_fixture.cpp ready_config_runtime.cpp)
    awg_native_target(awg_ready_runtime_fixture)
    target_link_libraries(awg_ready_runtime_fixture PRIVATE awg_ready_runtime awg_automatic_runtime awg_trusted_image_runtime awg_config_generation awg_control_runtime awg_network_topology)
    add_executable(awg_server_key_tests test_server_key.cpp)
    awg_native_target(awg_server_key_tests)
    target_include_directories(awg_server_key_tests PRIVATE "${JSON_C_INCLUDE_DIR}")
    target_link_libraries(awg_server_key_tests PRIVATE awg_config_generation)
    add_test(NAME awg_server_key COMMAND awg_server_key_tests)
    set_tests_properties(awg_server_key PROPERTIES TIMEOUT 20)
    add_test(NAME awg_server_key_bridge
        COMMAND "${CMAKE_COMMAND}" -E env "AWG_GENERATION_TEST_BIN=$<TARGET_FILE:awg_ready_runtime_fixture>"
            "${Python3_EXECUTABLE}" -B -m unittest test_native_server_key -v)
    set_tests_properties(awg_server_key_bridge PROPERTIES
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/.." TIMEOUT 45)
    add_executable(awg_peer_mapping_tests test_peer_mapping.cpp)
    awg_native_target(awg_peer_mapping_tests)
    target_include_directories(awg_peer_mapping_tests PRIVATE "${JSON_C_INCLUDE_DIR}")
    target_link_libraries(awg_peer_mapping_tests PRIVATE awg_config_generation)
    add_test(NAME awg_peer_mapping COMMAND awg_peer_mapping_tests)
    set_tests_properties(awg_peer_mapping PROPERTIES TIMEOUT 20)
    add_test(NAME awg_peer_mapping_bridge
        COMMAND "${CMAKE_COMMAND}" -E env "AWG_GENERATION_TEST_BIN=$<TARGET_FILE:awg_ready_runtime_fixture>"
            "${Python3_EXECUTABLE}" -B -m unittest test_native_peer_mapping -v)
    set_tests_properties(awg_peer_mapping_bridge PROPERTIES
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/.." TIMEOUT 45)
    add_executable(awg_config_generation_tests test_config_generation.cpp)
    awg_native_target(awg_config_generation_tests)
    target_compile_options(awg_config_generation_tests PRIVATE -UNDEBUG)
    target_link_libraries(awg_config_generation_tests PRIVATE awg_config_generation)
    add_test(NAME awg_config_generation COMMAND awg_config_generation_tests)
    set_tests_properties(awg_config_generation PROPERTIES TIMEOUT 20)
    add_executable(awg_trusted_image_runtime_tests test_trusted_image_runtime.cpp)
    awg_native_target(awg_trusted_image_runtime_tests)
    target_link_libraries(awg_trusted_image_runtime_tests PRIVATE awg_trusted_image_runtime)
    add_test(NAME awg_trusted_image_runtime COMMAND awg_trusted_image_runtime_tests)
    set_tests_properties(awg_trusted_image_runtime PROPERTIES TIMEOUT 30)
    add_executable(awg_trusted_image_transport_tests test_trusted_image_transport.cpp)
    awg_native_target(awg_trusted_image_transport_tests)
    target_link_libraries(awg_trusted_image_transport_tests PRIVATE awg_bounded_docker)
    foreach(image_transport_case IN ITEMS success exit os cap timeout eof)
        add_test(NAME awg_image_transport_${image_transport_case} COMMAND awg_trusted_image_transport_tests ${image_transport_case})
        set_tests_properties(awg_image_transport_${image_transport_case} PROPERTIES TIMEOUT 10)
    endforeach()
    add_test(NAME awg_generation_runtime_bridge
        COMMAND "${CMAKE_COMMAND}" -E env "AWG_GENERATION_TEST_BIN=$<TARGET_FILE:awg_ready_runtime_fixture>"
            "${Python3_EXECUTABLE}" -B -m unittest test_native_generation_runtime -v)
    set_tests_properties(awg_generation_runtime_bridge PROPERTIES
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/.." TIMEOUT 45)
    add_test(NAME awg_trusted_image_runtime_bridge
        COMMAND "${CMAKE_COMMAND}" -E env "AWG_IMAGE_TEST_BIN=$<TARGET_FILE:awg_ready_runtime_fixture>"
            "${Python3_EXECUTABLE}" -B -m unittest test_native_trusted_image_runtime -v)
    set_tests_properties(awg_trusted_image_runtime_bridge PROPERTIES
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/.." TIMEOUT 45)
    add_test(NAME awg_automatic_runtime_bridge
        COMMAND "${CMAKE_COMMAND}" -E env "AWG_AUTOMATIC_TEST_BIN=$<TARGET_FILE:awg_ready_runtime_fixture>"
            "${Python3_EXECUTABLE}" -B -m unittest test_native_automatic_runtime -v)
    set_tests_properties(awg_automatic_runtime_bridge PROPERTIES
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/.." TIMEOUT 45)
    add_test(NAME awg_ready_runtime_bridge
        COMMAND "${CMAKE_COMMAND}" -E env "AWG_READY_TEST_BIN=$<TARGET_FILE:awg_ready_runtime_fixture>"
            "AWG_READY_PRODUCTION_BIN=$<TARGET_FILE:awg_feed_server>"
            "${Python3_EXECUTABLE}" -B -m unittest test_native_ready_runtime -v)
    set_tests_properties(awg_ready_runtime_bridge PROPERTIES
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/.." TIMEOUT 45)

    add_test(NAME awg_control_wiring_bridge
        COMMAND "${CMAKE_COMMAND}" -E env "AWG_CONTROL_WIRING_TEST_BIN=$<TARGET_FILE:awg_ready_runtime_fixture>"
            "${Python3_EXECUTABLE}" -B -m unittest test_native_control_wiring -v)
    set_tests_properties(awg_control_wiring_bridge PROPERTIES
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/.." TIMEOUT 45)
    # Link-time interposers are test-only: these fixtures never execute Docker.
    add_executable(awg_bounded_docker_fd_tests test_bounded_docker_fd.cpp)
    awg_native_target(awg_bounded_docker_fd_tests)
    target_link_libraries(awg_bounded_docker_fd_tests PRIVATE awg_bounded_docker)
    target_link_options(awg_bounded_docker_fd_tests PRIVATE
        "-Wl,--wrap=open" "-Wl,--wrap=dup2" "-Wl,--wrap=fcntl" "-Wl,--wrap=execve")
    foreach(fd_case IN ITEMS none open-null dup2-stdin dup2-stderr dup2-stdout fcntl-getfl fcntl-setfl)
        add_test(NAME awg_bounded_docker_fd_${fd_case} COMMAND awg_bounded_docker_fd_tests ${fd_case})
        set_tests_properties(awg_bounded_docker_fd_${fd_case} PROPERTIES TIMEOUT 15)
    endforeach()
    add_executable(awg_policy_runtime_tests test_policy_runtime.cpp policy_runtime.cpp)
    awg_native_target(awg_policy_runtime_tests)
    target_include_directories(awg_policy_runtime_tests SYSTEM PRIVATE "${RAPIDJSON_INCLUDE_DIR}")
    target_link_libraries(awg_policy_runtime_tests PRIVATE awg_policy awg_bounded_docker)
    target_compile_options(awg_policy_runtime_tests PRIVATE -UNDEBUG)
    add_test(NAME awg_policy_runtime COMMAND awg_policy_runtime_tests)
    add_executable(awg_policy_process_cleanup_tests test_policy_process_cleanup.cpp policy_runtime.cpp)
    awg_native_target(awg_policy_process_cleanup_tests)
    target_include_directories(awg_policy_process_cleanup_tests SYSTEM PRIVATE "${RAPIDJSON_INCLUDE_DIR}")
    target_link_libraries(awg_policy_process_cleanup_tests PRIVATE awg_policy awg_bounded_docker)
    add_test(NAME awg_policy_process_group_cleanup COMMAND awg_policy_process_cleanup_tests)
    add_test(NAME awg_policy_process_parent_cleanup COMMAND awg_policy_process_cleanup_tests parent-only)
    set_tests_properties(awg_policy_process_group_cleanup awg_policy_process_parent_cleanup
        PROPERTIES TIMEOUT 15)
    add_test(NAME awg_policy_runtime_bridge
        COMMAND "${CMAKE_COMMAND}" -E env "AWG_POLICY_TEST_BIN=$<TARGET_FILE:awg_feed_server>"
            "${Python3_EXECUTABLE}" -B -m unittest test_native_policy_runtime -v)
    set_tests_properties(awg_policy_runtime_bridge PROPERTIES
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/.." TIMEOUT 30)
    add_test(NAME awg_native_feed_bridge COMMAND "${Python3_EXECUTABLE}" -B -m unittest test_native_feed -v)
    set_tests_properties(awg_native_feed_bridge PROPERTIES
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/.." TIMEOUT 30)
    set_tests_properties(awg_automatic_plan awg_automatic_plan_parity awg_policy awg_policy_parity awg_policy_filesystem
        awg_ready_attestation_parity awg_transaction_journal awg_transaction_journal_parity
        awg_control_canonical awg_control_dispatch PROPERTIES TIMEOUT 90)
endif()

if(BUILD_TESTING)
    add_executable(awg_network_topology_tests test_network_topology.cpp)
    awg_native_target(awg_network_topology_tests)
    target_link_libraries(awg_network_topology_tests PRIVATE awg_network_topology)
    add_test(NAME awg_network_topology COMMAND awg_network_topology_tests)
    set_tests_properties(awg_network_topology PROPERTIES TIMEOUT 15)
    add_test(NAME awg_network_topology_parity COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/test_network_topology_parity.py" "$<TARGET_FILE:awg_feed_server>")
    set_tests_properties(awg_network_topology_parity PROPERTIES TIMEOUT 90
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    add_test(NAME awg_native_network_bridge COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/../test_native_network_topology.py" -v)
    set_tests_properties(awg_native_network_bridge PROPERTIES TIMEOUT 90
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1;AWG_NETWORK_TEST_BIN=$<TARGET_FILE:awg_network_observer_fixture>;AWG_NETWORK_PRODUCTION_BIN=$<TARGET_FILE:awg_feed_server>")
endif()

if(BUILD_TESTING)
    add_test(NAME awg_network_topology_cli COMMAND "${Python3_EXECUTABLE}" -B
        "${CMAKE_CURRENT_SOURCE_DIR}/test_network_topology_cli.py" "$<TARGET_FILE:awg_feed_server>" -v)
    set_tests_properties(awg_network_topology_cli PROPERTIES TIMEOUT 30)
    add_test(NAME awg_prepare_legacy_topology COMMAND "${Python3_EXECUTABLE}" -B
        -m unittest test_prepare -v)
    set_tests_properties(awg_prepare_legacy_topology PROPERTIES TIMEOUT 30
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/..")
endif()

if(BUILD_TESTING)
    add_test(NAME awg_stopped_network_parity COMMAND "${Python3_EXECUTABLE}" -B
        "${CMAKE_CURRENT_SOURCE_DIR}/test_stopped_network_topology_parity.py" "$<TARGET_FILE:awg_feed_server>")
    set_tests_properties(awg_stopped_network_parity PROPERTIES TIMEOUT 90)
    add_test(NAME awg_native_stopped_network_bridge COMMAND "${Python3_EXECUTABLE}" -B
        -m unittest test_native_stopped_topology -v)
    set_tests_properties(awg_native_stopped_network_bridge PROPERTIES TIMEOUT 90
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/.."
        ENVIRONMENT "AWG_NETWORK_TEST_BIN=$<TARGET_FILE:awg_network_observer_fixture>;AWG_NETWORK_PRODUCTION_BIN=$<TARGET_FILE:awg_feed_server>")
endif()

if(BUILD_TESTING)
    add_executable(awg_network_observer_tests test_network_observer.cpp)
    awg_native_target(awg_network_observer_tests)
    target_link_libraries(awg_network_observer_tests PRIVATE awg_network_topology)
    add_test(NAME awg_network_observer COMMAND awg_network_observer_tests)
    set_tests_properties(awg_network_observer PROPERTIES TIMEOUT 30)
    # Test-only exact fake exec map; production JSON has no fixture controls.
    add_executable(awg_network_observer_fixture test_network_observer_fixture.cpp)
    awg_native_target(awg_network_observer_fixture)
    target_link_libraries(awg_network_observer_fixture PRIVATE awg_network_topology awg_source_config_runtime)
endif()

if(BUILD_TESTING)
    add_executable(awg_source_config_runtime_tests test_source_config_runtime.cpp)
    awg_native_target(awg_source_config_runtime_tests)
    target_link_libraries(awg_source_config_runtime_tests PRIVATE awg_source_config_runtime)
    add_test(NAME awg_source_config_runtime COMMAND awg_source_config_runtime_tests)
    set_tests_properties(awg_source_config_runtime PROPERTIES TIMEOUT 30)
    add_test(NAME awg_native_source_config_bridge COMMAND "${Python3_EXECUTABLE}" -B "${CMAKE_CURRENT_SOURCE_DIR}/../test_native_source_config.py" -v)
    set_tests_properties(awg_native_source_config_bridge PROPERTIES TIMEOUT 90
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1;AWG_SOURCE_CONFIG_TEST_BIN=$<TARGET_FILE:awg_network_observer_fixture>;AWG_SOURCE_CONFIG_PRODUCTION_BIN=$<TARGET_FILE:awg_feed_server>")
endif()

if(BUILD_TESTING)
    add_test(NAME awg_source_config_cli COMMAND "${Python3_EXECUTABLE}" -B "${CMAKE_CURRENT_SOURCE_DIR}/test_source_config_cli.py" "$<TARGET_FILE:awg_network_observer_fixture>" -v)
    set_tests_properties(awg_source_config_cli PROPERTIES TIMEOUT 30)
endif()

# Namespace-local read-only HTTP client; no fixture/endpoint options in production.
add_library(awg_routed_policy_epoch routed_policy_epoch.cpp)
awg_native_target(awg_routed_policy_epoch)
target_include_directories(awg_routed_policy_epoch SYSTEM PRIVATE "${RAPIDJSON_INCLUDE_DIR}")
target_link_libraries(awg_routed_policy_epoch PUBLIC awg_policy)
target_link_libraries(awg_feed_server PRIVATE awg_routed_policy_epoch)
if(BUILD_TESTING)
    add_executable(awg_routed_policy_epoch_tests test_routed_policy_epoch.cpp)
    awg_native_target(awg_routed_policy_epoch_tests)
    target_link_libraries(awg_routed_policy_epoch_tests PRIVATE awg_routed_policy_epoch)
    add_test(NAME awg_routed_policy_epoch COMMAND awg_routed_policy_epoch_tests)
    set_tests_properties(awg_routed_policy_epoch PROPERTIES TIMEOUT 20)
    add_executable(awg_routed_policy_epoch_transport_tests test_routed_policy_epoch_transport.cpp)
    awg_native_target(awg_routed_policy_epoch_transport_tests)
    target_link_libraries(awg_routed_policy_epoch_transport_tests PRIVATE awg_routed_policy_epoch)
    foreach(call IN ITEMS socket connect getsockopt poll send recv close)
        target_link_options(awg_routed_policy_epoch_transport_tests PRIVATE "-Wl,--wrap=${call}")
    endforeach()
    add_test(NAME awg_routed_policy_epoch_transport COMMAND awg_routed_policy_epoch_transport_tests)
    set_tests_properties(awg_routed_policy_epoch_transport PROPERTIES TIMEOUT 20)
    add_test(NAME awg_native_policy_epoch_bridge COMMAND "${Python3_EXECUTABLE}" -B
        -m unittest test_native_policy_epoch -v)
    set_tests_properties(awg_native_policy_epoch_bridge PROPERTIES
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/.." TIMEOUT 40
        ENVIRONMENT "AWG_POLICY_EPOCH_TEST_BIN=$<TARGET_FILE:awg_feed_server>")
    add_test(NAME awg_routed_policy_epoch_cli COMMAND "${Python3_EXECUTABLE}" -B
        "${CMAKE_CURRENT_SOURCE_DIR}/test_routed_policy_epoch_cli.py" "$<TARGET_FILE:awg_feed_server>")
    set_tests_properties(awg_routed_policy_epoch_cli PROPERTIES TIMEOUT 20)
endif()
