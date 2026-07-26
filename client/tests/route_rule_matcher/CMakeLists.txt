cmake_minimum_required(VERSION 3.25)

project(RouteRuleMatcherTests LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

find_package(Qt6 REQUIRED COMPONENTS Core Network Test)
find_package(Python3 REQUIRED COMPONENTS Interpreter)

enable_testing()

set(CLIENT_ROOT "${CMAKE_CURRENT_LIST_DIR}/../..")

add_executable(route_rule_matcher_tests
    tst_route_rule_matcher.cpp
    "${CLIENT_ROOT}/core/utils/routeRuleMatcher.cpp"
    "${CLIENT_ROOT}/core/utils/routeRuleMatcher.h"
)

target_include_directories(route_rule_matcher_tests PRIVATE "${CLIENT_ROOT}")
target_link_libraries(route_rule_matcher_tests PRIVATE Qt6::Core Qt6::Network Qt6::Test)

if(MSVC)
    target_compile_options(route_rule_matcher_tests PRIVATE /W4 /WX /permissive-)
else()
    target_compile_options(route_rule_matcher_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()

add_test(NAME route_rule_matcher COMMAND route_rule_matcher_tests)
add_test(
    NAME route_rule_matcher_source_contracts
    COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_LIST_DIR}/test_route_matcher_source_contracts.py"
)
set_tests_properties(route_rule_matcher_source_contracts PROPERTIES
    WORKING_DIRECTORY "${CLIENT_ROOT}/.."
)
