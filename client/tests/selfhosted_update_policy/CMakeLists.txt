cmake_minimum_required(VERSION 3.25)

project(SelfHostedUpdatePolicyTests LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
find_package(Qt6 REQUIRED COMPONENTS Core)

enable_testing()

set(CLIENT_ROOT "${CMAKE_CURRENT_LIST_DIR}/../..")

add_executable(selfhosted_update_policy_tests
    tst_selfhosted_update_policy.cpp
    "${CLIENT_ROOT}/core/utils/selfhostedUpdatePolicy.h"
    "${CLIENT_ROOT}/secureQSettings.h"
)

target_include_directories(selfhosted_update_policy_tests PRIVATE "${CLIENT_ROOT}")
target_link_libraries(selfhosted_update_policy_tests PRIVATE Qt6::Core)
target_compile_definitions(selfhosted_update_policy_tests PRIVATE QTKEYCHAIN_NO_EXPORT)
if(MSVC)
    target_compile_options(selfhosted_update_policy_tests PRIVATE /W4 /WX)
endif()

add_test(NAME selfhosted_update_policy COMMAND selfhosted_update_policy_tests)
