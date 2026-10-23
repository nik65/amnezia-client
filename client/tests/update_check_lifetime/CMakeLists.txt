cmake_minimum_required(VERSION 3.25)
project(AmneziaUpdateCheckLifetimeTests LANGUAGES CXX)
set(CMAKE_AUTOMOC ON)
find_package(Qt6 REQUIRED COMPONENTS Core Network)
find_package(Python3 REQUIRED COMPONENTS Interpreter)
get_filename_component(CLIENT_ROOT "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)
set(AUDIT_UPDATE_SOURCE "${CLIENT_ROOT}/core/controllers/updateController.cpp" CACHE FILEPATH "Actual update source under test")
set(AUDIT_BOOTSTRAP_SOURCE "${CLIENT_ROOT}/core/controllers/selfhosted/selfHostedUpdateBootstrapper.cpp" CACHE FILEPATH "Actual bootstrap completion source under test")
set(UPDATE_CHECK_ENABLE_ASAN OFF CACHE BOOL "Enable ASAN/LSAN on owned standalone fixture")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
    "${AUDIT_UPDATE_SOURCE}"
    "${AUDIT_BOOTSTRAP_SOURCE}"
    "${CLIENT_ROOT}/core/controllers/selfhosted/selfHostedUpdateBootstrapper.h"
    "${CMAKE_CURRENT_LIST_DIR}/generate_fixture.py")
set(GENERATED_SOURCE "${CMAKE_CURRENT_BINARY_DIR}/update_check_fixture.cpp")
execute_process(COMMAND "${Python3_EXECUTABLE}" -B "${CMAKE_CURRENT_LIST_DIR}/generate_fixture.py"
    "${CLIENT_ROOT}" "${GENERATED_SOURCE}"
    --update-source "${AUDIT_UPDATE_SOURCE}" --bootstrap-source "${AUDIT_BOOTSTRAP_SOURCE}"
    RESULT_VARIABLE GENERATED_STATUS)
if(NOT GENERATED_STATUS EQUAL 0)
    message(FATAL_ERROR "Cannot extract actual update-check methods/completion callback")
endif()
add_executable(update_check_lifetime_tests "${GENERATED_SOURCE}")
target_include_directories(update_check_lifetime_tests PRIVATE "${CLIENT_ROOT}")
target_link_libraries(update_check_lifetime_tests PRIVATE Qt6::Core Qt6::Network)
target_compile_features(update_check_lifetime_tests PRIVATE cxx_std_17)
if(MSVC)
    target_compile_options(update_check_lifetime_tests PRIVATE /W4 /WX /utf-8)
else()
    target_compile_options(update_check_lifetime_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
    if(UPDATE_CHECK_ENABLE_ASAN)
        target_compile_options(update_check_lifetime_tests PRIVATE -fsanitize=address -fno-omit-frame-pointer)
        target_link_options(update_check_lifetime_tests PRIVATE -fsanitize=address)
    endif()
endif()
include(CTest)
foreach(CASE IN ITEMS gateway-delayed-invalidated gateway-stale-success gateway-stale-error gateway-current
    manifest-exact manifest-overflow manifest-declared manifest-final-only manifest-destroy-owner
    manifest-destroy-reply manifest-leak metadata-exact metadata-overflow metadata-declared metadata-stale
    metadata-destroy-owner metadata-destroy-reply bootstrap-retry-delete bootstrap-exhausted-delete
    bootstrap-success-delete bootstrap-normal-retry bootstrap-normal-exhausted)
    add_test(NAME update_check_${CASE} COMMAND update_check_lifetime_tests "${CASE}")
    set_tests_properties(update_check_${CASE} PROPERTIES TIMEOUT 15)
endforeach()
