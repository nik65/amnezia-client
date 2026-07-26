cmake_minimum_required(VERSION 3.25)

project(SecureQSettingsBrokerTests LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Qt6 REQUIRED COMPONENTS Core)

enable_testing()

set(CLIENT_ROOT "${CMAKE_CURRENT_LIST_DIR}/../..")

add_executable(secure_qsettings_broker_tests
    tst_secure_qsettings_broker.cpp
    "${CLIENT_ROOT}/secureQSettings.h"
)

target_include_directories(secure_qsettings_broker_tests PRIVATE "${CLIENT_ROOT}")
target_link_libraries(secure_qsettings_broker_tests PRIVATE Qt6::Core)

if(MSVC)
    target_compile_options(secure_qsettings_broker_tests PRIVATE /W4 /WX /permissive-)
else()
    target_compile_options(secure_qsettings_broker_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()

add_test(NAME secure_qsettings_broker COMMAND secure_qsettings_broker_tests)
