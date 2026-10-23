cmake_minimum_required(VERSION 3.25)
project(AmneziaConfigPayloadCodecTest LANGUAGES CXX)
set(CMAKE_AUTOMOC ON)
find_package(Qt6 REQUIRED COMPONENTS Core Test)
find_package(ZLIB REQUIRED)
add_executable(config_payload_codec_test
    tst_config_payload_codec.cpp
    ../../core/utils/configPayloadCodec.cpp)
target_include_directories(config_payload_codec_test PRIVATE ../../)
target_compile_features(config_payload_codec_test PRIVATE cxx_std_17)
if(MSVC)
    target_compile_options(config_payload_codec_test PRIVATE /W4 /WX /utf-8)
else()
    target_compile_options(config_payload_codec_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()
target_link_libraries(config_payload_codec_test PRIVATE Qt6::Core Qt6::Test ZLIB::ZLIB)
include(CTest)
add_test(NAME config_payload_codec COMMAND config_payload_codec_test)
set_tests_properties(config_payload_codec PROPERTIES TIMEOUT 30)

# Compile the actual pure data-import/file-reader methods with explicit inert
# protocol/version seams. This does not configure or build the application.
find_package(Python3 REQUIRED COMPONENTS Interpreter)
get_filename_component(AMNEZIA_CLIENT_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)
set(_integration_fixture "${CMAKE_CURRENT_BINARY_DIR}/integration_fixture.cpp")
execute_process(COMMAND "${Python3_EXECUTABLE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/generate_integration_fixture.py"
    "${AMNEZIA_CLIENT_ROOT}" "${_integration_fixture}"
    COMMAND_ERROR_IS_FATAL ANY)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/generate_integration_fixture.py"
    "${AMNEZIA_CLIENT_ROOT}/core/controllers/selfhosted/importController.cpp"
    "${AMNEZIA_CLIENT_ROOT}/core/controllers/selfhosted/importController.h"
    "${AMNEZIA_CLIENT_ROOT}/core/controllers/api/subscriptionController.cpp"
    "${AMNEZIA_CLIENT_ROOT}/core/controllers/api/subscriptionController.h"
    "${AMNEZIA_CLIENT_ROOT}/ui/controllers/importUiController.cpp")
add_executable(config_payload_integration_test "${_integration_fixture}"
    ../../core/utils/configPayloadCodec.cpp)
target_include_directories(config_payload_integration_test PRIVATE ../../)
target_compile_features(config_payload_integration_test PRIVATE cxx_std_17)
if(MSVC)
    target_compile_options(config_payload_integration_test PRIVATE /W4 /WX /utf-8)
else()
    target_compile_options(config_payload_integration_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()
target_link_libraries(config_payload_integration_test PRIVATE Qt6::Core ZLIB::ZLIB)
add_test(NAME config_payload_integration COMMAND config_payload_integration_test)
set_tests_properties(config_payload_integration PROPERTIES TIMEOUT 30)

set(_file_reader_fixture "${CMAKE_CURRENT_BINARY_DIR}/file_reader_fixture.cpp")
execute_process(COMMAND "${Python3_EXECUTABLE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/generate_file_reader_fixture.py"
    "${AMNEZIA_CLIENT_ROOT}" "${_file_reader_fixture}"
    COMMAND_ERROR_IS_FATAL ANY)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/generate_file_reader_fixture.py"
    "${AMNEZIA_CLIENT_ROOT}/ui/controllers/systemController.cpp"
    "${AMNEZIA_CLIENT_ROOT}/ui/controllers/systemController.h"
    "${AMNEZIA_CLIENT_ROOT}/ui/controllers/importUiController.cpp")
add_executable(config_file_reader_test "${_file_reader_fixture}")
target_include_directories(config_file_reader_test PRIVATE ../../)
target_compile_features(config_file_reader_test PRIVATE cxx_std_17)
if(MSVC)
    target_compile_options(config_file_reader_test PRIVATE /W4 /WX /utf-8)
else()
    target_compile_options(config_file_reader_test PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()
target_link_libraries(config_file_reader_test PRIVATE Qt6::Core)
add_test(NAME config_file_reader COMMAND config_file_reader_test)
set_tests_properties(config_file_reader PROPERTIES TIMEOUT 30)
