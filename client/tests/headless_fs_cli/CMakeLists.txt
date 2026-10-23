cmake_minimum_required(VERSION 3.25)
project(headless_fs_cli_contract LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC OFF)
include(CTest)
find_package(Qt6 REQUIRED COMPONENTS Core Network)
find_package(OpenSSL REQUIRED COMPONENTS Crypto)
find_package(Python3 REQUIRED COMPONENTS Interpreter)
get_filename_component(ROOT "${CMAKE_CURRENT_LIST_DIR}/../../.." ABSOLUTE)
add_subdirectory("${ROOT}/deploy/headless/native" native)
# Actual CLI/parser/wire encoder and actual filesystem dispatcher. No daemon,
# service, backend, shell, installer, or production endpoint is started.
add_executable(headless_cli_fs_contract
    "${ROOT}/headless/cli.cpp" "${ROOT}/headless/headlessProtocol.cpp"
    "${ROOT}/headless/rollbackCoordinator.cpp" "${ROOT}/headless/headlessUpdateManager.cpp"
    "${ROOT}/client/tests/headless_rollback_coordinator/runner_stub.cpp")
target_link_libraries(headless_cli_fs_contract PRIVATE headless_fs_core Qt6::Core Qt6::Network OpenSSL::Crypto)
target_include_directories(headless_cli_fs_contract PRIVATE "${ROOT}/headless" "${ROOT}/client")
target_compile_definitions(headless_cli_fs_contract PRIVATE AMNEZIA_HEADLESS_VERSION="5.0.3.14")
target_compile_options(headless_cli_fs_contract PRIVATE -Wall -Wextra -Wpedantic -Werror -Wno-missing-field-initializers)
add_test(NAME cli_fs_argv COMMAND ${Python3_EXECUTABLE}
    "${CMAKE_CURRENT_LIST_DIR}/test_cli_fs.py" "$<TARGET_FILE:headless_cli_fs_contract>")
