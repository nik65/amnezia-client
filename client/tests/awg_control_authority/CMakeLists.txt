cmake_minimum_required(VERSION 3.25)
project(AwgControlAuthorityTests LANGUAGES CXX)

enable_testing()
find_package(Python3 QUIET COMPONENTS Interpreter)
if(Python3_Interpreter_FOUND)
    add_test(NAME awg_authority_source_contract
        COMMAND "${Python3_EXECUTABLE}" -B "${CMAKE_CURRENT_LIST_DIR}/test_authority_source_contract.py")
    foreach(contract IN ITEMS cleanup probe_cleanup reconcile)
        add_test(NAME awg_${contract}_source_contract
            COMMAND "${Python3_EXECUTABLE}" -B "${CMAKE_CURRENT_LIST_DIR}/test_${contract}_source_contract.py")
    endforeach()
endif()

# Linux exercises the actual encrypted-file store; other platform storage needs
# its SecureQSettings/keychain integration lane rather than a fake backend.
if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    return()
endif()
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
find_package(Qt6 REQUIRED COMPONENTS Core)
find_package(OpenSSL REQUIRED COMPONENTS Crypto)
enable_testing()
add_executable(awg_control_authority_tests tst_awg_control_authority.cpp)
target_include_directories(awg_control_authority_tests PRIVATE "${CMAKE_CURRENT_LIST_DIR}/../..")
target_link_libraries(awg_control_authority_tests PRIVATE Qt6::Core OpenSSL::Crypto)
if(MSVC)
    target_compile_options(awg_control_authority_tests PRIVATE /W4 /WX)
else()
    target_compile_options(awg_control_authority_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()
add_test(NAME awg_control_authority COMMAND awg_control_authority_tests)
