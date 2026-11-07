cmake_minimum_required(VERSION 3.25)
project(ProtocolErrorOrder LANGUAGES CXX)
set(CMAKE_AUTOMOC ON)
find_package(Qt6 REQUIRED COMPONENTS Core)
find_package(Python3 REQUIRED COMPONENTS Interpreter)
get_filename_component(CLIENT_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../.." REALPATH)
execute_process(COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/generate.py" "${CLIENT_ROOT}" "${CMAKE_CURRENT_BINARY_DIR}/actual_setter.inc" COMMAND_ERROR_IS_FATAL ANY)
get_filename_component(PROTOCOL_ERROR_GENERATOR "${CMAKE_CURRENT_SOURCE_DIR}/generate.py" REALPATH)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
    "${CLIENT_ROOT}/core/protocols/vpnProtocol.cpp"
    "${CLIENT_ROOT}/vpnConnection.cpp"
    "${PROTOCOL_ERROR_GENERATOR}")
add_executable(protocol_error_order test.cpp "${CLIENT_ROOT}/core/utils/errorCodes.h")
target_include_directories(protocol_error_order PRIVATE "${CLIENT_ROOT}" "${CMAKE_CURRENT_BINARY_DIR}")
target_link_libraries(protocol_error_order PRIVATE Qt6::Core)
target_compile_features(protocol_error_order PRIVATE cxx_std_17)
enable_testing()
add_test(NAME protocol_error_order COMMAND protocol_error_order)
