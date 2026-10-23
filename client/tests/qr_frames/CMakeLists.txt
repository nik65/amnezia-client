cmake_minimum_required(VERSION 3.25)
project(AmneziaQrFrameTests LANGUAGES CXX)
set(CMAKE_AUTOMOC ON)
find_package(Qt6 REQUIRED COMPONENTS Core Test)
find_package(Python3 REQUIRED COMPONENTS Interpreter)
get_filename_component(AMNEZIA_CLIENT_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)
add_library(qr_frame_core
    "${AMNEZIA_CLIENT_ROOT}/core/utils/qrCodeUtils.cpp"
    "${AMNEZIA_CLIENT_ROOT}/3rd/qrcodegen/qrcodegen.cpp")
target_compile_features(qr_frame_core PUBLIC cxx_std_17)
target_include_directories(qr_frame_core PUBLIC
    "${AMNEZIA_CLIENT_ROOT}/core/utils" "${AMNEZIA_CLIENT_ROOT}/3rd/qrcodegen")
target_link_libraries(qr_frame_core PUBLIC Qt6::Core)
add_executable(qr_frames_test tst_qr_frames.cpp)
target_link_libraries(qr_frames_test PRIVATE qr_frame_core Qt6::Test)
set(_parser_fixture "${CMAKE_CURRENT_BINARY_DIR}/parser_fixture.cpp")
execute_process(COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/generate_parser_fixture.py"
    "${AMNEZIA_CLIENT_ROOT}/core/controllers/selfhosted/importController.cpp" "${_parser_fixture}"
    COMMAND_ERROR_IS_FATAL ANY)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
    "${AMNEZIA_CLIENT_ROOT}/core/controllers/selfhosted/importController.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/generate_parser_fixture.py")
add_executable(qr_parser_test "${_parser_fixture}")
target_link_libraries(qr_parser_test PRIVATE qr_frame_core)
include(CTest)
add_test(NAME qr_frames COMMAND qr_frames_test)
add_test(NAME qr_parser COMMAND qr_parser_test)
set_tests_properties(qr_frames qr_parser PROPERTIES TIMEOUT 20)
