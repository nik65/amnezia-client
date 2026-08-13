cmake_minimum_required(VERSION 3.25)

set(AMNEZIA_FOCUSED_TEST_DIRS
    connection_health_probe
    ipc_server_process_security
    managed_route_policy
    operator_command
    privileged_ipc_security
    remote_log_sanitizer
    selfhosted_update_bootstrapper_path
    selfhosted_update_policy
)

foreach(test_dir IN LISTS AMNEZIA_FOCUSED_TEST_DIRS)
    add_subdirectory("${test_dir}")
endforeach()

if(WIN32)
    add_subdirectory(windows_privileged_pipe_reuse)
endif()

add_subdirectory(bounded_queued_snapshot)
add_subdirectory(managed_dns_convergence)
add_subdirectory(managed_route_reconcile)
add_subdirectory(remote_log_retry_privacy)
add_subdirectory(route_rule_matcher)
add_subdirectory(secure_qsettings_broker)
add_subdirectory(ssh_host_key_pin)

find_package(Python3 REQUIRED COMPONENTS Interpreter)
set(AMNEZIA_PYTHON_TEST_ENV
    "PYTHONDONTWRITEBYTECODE=1"
    "PYTHONUTF8=1"
)

add_test(
    NAME selfhosted_update_python_contracts
    COMMAND ${CMAKE_COMMAND} -E env ${AMNEZIA_PYTHON_TEST_ENV}
            ${Python3_EXECUTABLE} -m unittest
            deploy.selfhosted_updates.test_selfhosted_updates -v
)
add_test(
    NAME client_log_collector_python_contracts
    COMMAND ${CMAKE_COMMAND} -E env ${AMNEZIA_PYTHON_TEST_ENV}
            ${Python3_EXECUTABLE} -m unittest
            client.core.controllers.selfhosted.test_client_logs_collector -v
)
add_test(
    NAME privileged_ipc_python_contracts
    COMMAND ${CMAKE_COMMAND} -E env ${AMNEZIA_PYTHON_TEST_ENV}
            ${Python3_EXECUTABLE} -m unittest
            client.tests.privileged_ipc_security.test_security_source_contracts -v
)

set_tests_properties(
    selfhosted_update_python_contracts
    client_log_collector_python_contracts
    privileged_ipc_python_contracts
    PROPERTIES
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        TIMEOUT 900
)
