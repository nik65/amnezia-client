cmake_minimum_required(VERSION 3.25)

project(BoundedQueuedSnapshotTests LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

find_package(Qt6 REQUIRED COMPONENTS Core Test)
find_package(Python3 REQUIRED COMPONENTS Interpreter)

enable_testing()

set(CLIENT_ROOT "${CMAKE_CURRENT_LIST_DIR}/../..")

add_executable(bounded_queued_snapshot_tests
    tst_bounded_queued_snapshot.cpp
    "${CLIENT_ROOT}/core/utils/boundedQueuedSnapshot.h"
    "${CLIENT_ROOT}/core/utils/remoteLogBatchHealth.h"
)

target_include_directories(bounded_queued_snapshot_tests PRIVATE "${CLIENT_ROOT}")
target_link_libraries(bounded_queued_snapshot_tests PRIVATE Qt6::Core Qt6::Test)

if(MSVC)
    target_compile_options(bounded_queued_snapshot_tests PRIVATE /W4 /WX /permissive-)
else()
    target_compile_options(bounded_queued_snapshot_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()

add_test(NAME bounded_queued_snapshot COMMAND bounded_queued_snapshot_tests)
add_test(
    NAME threading_source_contracts
    COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_LIST_DIR}/test_threading_source_contracts.py"
)
set_tests_properties(threading_source_contracts PROPERTIES
    WORKING_DIRECTORY "${CLIENT_ROOT}/.."
)
