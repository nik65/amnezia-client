cmake_minimum_required(VERSION 3.25)

project(ManagedRouteReconcileTests LANGUAGES NONE)

find_package(Python3 REQUIRED COMPONENTS Interpreter)

enable_testing()
add_test(
    NAME managed_route_reconcile
    COMMAND ${Python3_EXECUTABLE} -B
            "${CMAKE_CURRENT_LIST_DIR}/test_managed_route_reconcile.py" -v
)
set_tests_properties(managed_route_reconcile PROPERTIES
    WORKING_DIRECTORY "${CMAKE_CURRENT_LIST_DIR}/../../.."
)
