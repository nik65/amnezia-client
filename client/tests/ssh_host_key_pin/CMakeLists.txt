cmake_minimum_required(VERSION 3.25)

project(SshHostKeyPinTests LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Qt6 REQUIRED COMPONENTS Core Core5Compat Network)

enable_testing()

set(CLIENT_ROOT "${CMAKE_CURRENT_LIST_DIR}/../..")

add_executable(ssh_host_key_pin_tests
    tst_ssh_host_key_pin.cpp
    "${CLIENT_ROOT}/core/utils/selfhosted/sshHostKeyPin.cpp"
    "${CLIENT_ROOT}/core/utils/selfhosted/sshHostKeyPin.h"
    "${CLIENT_ROOT}/core/models/selfhosted/selfHostedAdminServerConfig.cpp"
    "${CLIENT_ROOT}/core/models/selfhosted/selfHostedAdminServerConfig.h"
)

target_include_directories(ssh_host_key_pin_tests PRIVATE "${CLIENT_ROOT}")
target_link_libraries(ssh_host_key_pin_tests PRIVATE Qt6::Core Qt6::Core5Compat Qt6::Network)
target_compile_definitions(ssh_host_key_pin_tests PRIVATE
    SELFHOSTED_SSH_TRUSTED_HOST="85.208.87.69"
    SELFHOSTED_SSH_TRUSTED_HOST_KEY_SHA256="SHA256:2UtHIoVd4Lft+s4E/LZlA8+reysEexYyhkt03rg8Rdg"
)

if(MSVC)
    target_compile_options(ssh_host_key_pin_tests PRIVATE /W4 /WX /permissive-)
else()
    target_compile_options(ssh_host_key_pin_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()

add_test(NAME ssh_host_key_pin COMMAND ssh_host_key_pin_tests)
