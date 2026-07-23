cmake_minimum_required(VERSION 3.25)

project(SelfHostedUpdateBootstrapperPathTests LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
find_package(Qt6 REQUIRED COMPONENTS Core)

enable_testing()

set(CLIENT_ROOT "${CMAKE_CURRENT_LIST_DIR}/../..")

add_executable(selfhosted_update_bootstrapper_path_tests
    tst_selfhosted_update_bootstrapper_path.cpp
    "${CLIENT_ROOT}/core/controllers/selfhosted/selfHostedUpdateBootstrapper.h"
)

target_include_directories(selfhosted_update_bootstrapper_path_tests PRIVATE "${CLIENT_ROOT}")
target_link_libraries(selfhosted_update_bootstrapper_path_tests PRIVATE Qt6::Core)
if(MSVC)
    target_compile_options(selfhosted_update_bootstrapper_path_tests PRIVATE /W4 /WX /permissive-)
else()
    target_compile_options(selfhosted_update_bootstrapper_path_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()

add_test(NAME selfhosted_update_bootstrapper_path COMMAND selfhosted_update_bootstrapper_path_tests)
