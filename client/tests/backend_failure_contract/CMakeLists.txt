cmake_minimum_required(VERSION 3.25)

project(BackendFailureContractTests LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
find_package(Qt6 REQUIRED COMPONENTS Core)

enable_testing()

set(CLIENT_ROOT "${CMAKE_CURRENT_LIST_DIR}/../..")

add_executable(backend_failure_contract_tests
    tst_backend_failure_contract.cpp
    "${CLIENT_ROOT}/daemon/daemonerrors.h"
    "${CLIENT_ROOT}/core/utils/errorCodes.h"
    "${CLIENT_ROOT}/core/utils/selfhostedUpdatePolicy.h"
    "${CLIENT_ROOT}/core/protocols/wireGuardProtocol.h"
)

target_include_directories(backend_failure_contract_tests PRIVATE "${CLIENT_ROOT}")
target_link_libraries(backend_failure_contract_tests PRIVATE Qt6::Core)

if(MSVC)
    target_compile_options(backend_failure_contract_tests PRIVATE /W4 /WX)
else()
    target_compile_options(backend_failure_contract_tests PRIVATE -Wall -Wextra -Werror)
endif()

add_test(NAME backend_failure_contract COMMAND backend_failure_contract_tests)
