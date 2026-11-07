cmake_minimum_required(VERSION 3.25)
project(xhttp_stream_settings_tests LANGUAGES CXX)

enable_testing()
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_AUTOMOC ON)
find_package(Qt6 REQUIRED COMPONENTS Core)
get_filename_component(REPO_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../.." ABSOLUTE)

# Link the current production generator and its real enum/default helpers.
# The configurator delegates here; its former extracted builder was removed.
add_executable(xhttp_stream_settings_tests
    tst_xhttp_stream_settings.cpp
    "${REPO_ROOT}/client/core/models/protocols/xrayProtocolConfig.cpp"
    "${REPO_ROOT}/client/core/protocols/protocolUtils.cpp"
    "${REPO_ROOT}/client/core/utils/protocolEnum.h")
target_include_directories(xhttp_stream_settings_tests PRIVATE "${REPO_ROOT}/client")
target_link_libraries(xhttp_stream_settings_tests PRIVATE Qt6::Core)
if(MSVC)
    target_compile_options(xhttp_stream_settings_tests PRIVATE /W4 /WX /wd4100 /permissive-)
else()
    target_compile_options(xhttp_stream_settings_tests PRIVATE -Wall -Wextra -Werror -Wno-unused-parameter)
endif()
add_test(NAME xhttp_stream_settings COMMAND xhttp_stream_settings_tests)
