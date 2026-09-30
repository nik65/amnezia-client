cmake_minimum_required(VERSION 3.25)

project(WindowsErrorRouteContracts LANGUAGES NONE)

find_package(Python3 REQUIRED COMPONENTS Interpreter)

enable_testing()
add_test(
    NAME windows_error_route_contracts
    COMMAND ${Python3_EXECUTABLE} -B
            "${CMAKE_CURRENT_LIST_DIR}/test_windows_error_route_contracts.py" -v
)
set_tests_properties(windows_error_route_contracts PROPERTIES
    WORKING_DIRECTORY "${CMAKE_CURRENT_LIST_DIR}/../../.."
)
