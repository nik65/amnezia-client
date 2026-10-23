cmake_minimum_required(VERSION 3.25)
project(ProtocolModelContract LANGUAGES CXX)
find_package(Qt6 REQUIRED COMPONENTS Core)
find_package(Python3 REQUIRED COMPONENTS Interpreter)
get_filename_component(CLIENT_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)
set(FIXTURE "${CMAKE_CURRENT_BINARY_DIR}/actual_models.cpp")
execute_process(COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/generate_fixture.py"
    "${CLIENT_ROOT}" "${FIXTURE}" COMMAND_ERROR_IS_FATAL ANY)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
    generate_fixture.py ../../core/models/protocols/awgProtocolConfig.cpp
    ../../core/models/protocols/wireGuardProtocolConfig.cpp
    ../../core/models/protocols/awgProtocolConfig.h ../../core/models/protocols/wireGuardProtocolConfig.h)
add_executable(protocol_model_contract_test test.cpp "${FIXTURE}")
target_include_directories(protocol_model_contract_test PRIVATE "${CLIENT_ROOT}")
target_compile_features(protocol_model_contract_test PRIVATE cxx_std_17)
target_link_libraries(protocol_model_contract_test PRIVATE Qt6::Core)
if(MSVC)
    target_compile_options(protocol_model_contract_test PRIVATE /W4 /WX /utf-8)
else()
    target_compile_options(protocol_model_contract_test PRIVATE -Wall -Wextra -Wpedantic -Werror
        -fsanitize=undefined -fno-sanitize-recover=undefined)
    target_link_options(protocol_model_contract_test PRIVATE -fsanitize=undefined)
endif()
include(CTest)
add_test(NAME protocol_model_defaults COMMAND protocol_model_contract_test defaults)
add_test(NAME protocol_model_packet_sizes COMMAND protocol_model_contract_test sizes)
set_tests_properties(protocol_model_defaults protocol_model_packet_sizes PROPERTIES TIMEOUT 30)
