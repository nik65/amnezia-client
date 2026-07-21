cmake_minimum_required(VERSION 3.25)

project(IpcServerProcessSecurityTests LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(Qt6 REQUIRED COMPONENTS Core Core5Compat RemoteObjects)

enable_testing()

set(REPOSITORY_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../..")

add_executable(ipc_process_test_helper
    ipc_process_test_helper.cpp
)

add_executable(ipc_server_process_security_tests
    tst_ipc_server_process_security.cpp
    "${REPOSITORY_ROOT}/ipc/ipcserverprocess.h"
)
set_target_properties(ipc_server_process_security_tests PROPERTIES AUTOMOC ON)
target_include_directories(ipc_server_process_security_tests PRIVATE
    "${REPOSITORY_ROOT}/ipc"
    "${REPOSITORY_ROOT}/client"
    "${CMAKE_CURRENT_BINARY_DIR}"
)
target_link_libraries(ipc_server_process_security_tests PRIVATE
    Qt6::Core
    Qt6::Core5Compat
    Qt6::RemoteObjects
)
target_compile_definitions(ipc_server_process_security_tests PRIVATE
    IPC_PROCESS_TEST_HELPER_PATH="$<TARGET_FILE:ipc_process_test_helper>"
)
add_dependencies(ipc_server_process_security_tests ipc_process_test_helper)

qt_add_repc_sources(ipc_server_process_security_tests
    "${REPOSITORY_ROOT}/ipc/ipc_process_interface.rep"
)

if(MSVC)
    target_compile_options(ipc_process_test_helper PRIVATE /W4 /WX /permissive-)
    target_compile_options(ipc_server_process_security_tests PRIVATE /W4 /WX /permissive-)
else()
    target_compile_options(ipc_process_test_helper PRIVATE -Wall -Wextra -Werror)
    target_compile_options(ipc_server_process_security_tests PRIVATE -Wall -Wextra -Werror)
endif()

add_test(NAME ipc_server_process_security COMMAND ipc_server_process_security_tests)
