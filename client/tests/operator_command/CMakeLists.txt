cmake_minimum_required(VERSION 3.25)

project(OperatorCommandTests LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_AUTOMOC ON)

find_package(Qt6 REQUIRED COMPONENTS Core Network)

enable_testing()

set(CLIENT_ROOT "${CMAKE_CURRENT_LIST_DIR}/../..")

add_executable(operator_command_tests
    tst_operator_command.cpp
    "${CLIENT_ROOT}/core/utils/operatorCommand.h"
    "${CLIENT_ROOT}/../ipc/localpeerauthentication.cpp"
    "${CLIENT_ROOT}/../ipc/localpeerauthentication.h"
)

target_include_directories(operator_command_tests PRIVATE "${CLIENT_ROOT}" "${CLIENT_ROOT}/..")
target_link_libraries(operator_command_tests PRIVATE Qt6::Core Qt6::Network)

if(WIN32)
    target_sources(operator_command_tests PRIVATE
        "${CLIENT_ROOT}/../ipc/windowsprivilegedpipe.cpp"
        "${CLIENT_ROOT}/../ipc/windowsprivilegedpipe.h"
    )
    target_link_libraries(operator_command_tests PRIVATE Advapi32)
elseif(APPLE)
    find_library(LIB_PROC proc REQUIRED)
    target_link_libraries(operator_command_tests PRIVATE
        "-framework CoreFoundation"
        "-framework Security"
        ${LIB_PROC}
    )
endif()

if(MSVC)
    target_compile_options(operator_command_tests PRIVATE /W4 /WX /permissive-)
endif()

add_test(NAME operator_command COMMAND operator_command_tests)
