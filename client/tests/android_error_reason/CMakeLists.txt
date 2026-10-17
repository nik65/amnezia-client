cmake_minimum_required(VERSION 3.25)
project(AndroidErrorReasonTests LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
find_package(Qt6 REQUIRED COMPONENTS Core Test LinguistTools)
set(ERROR_REASON_RUSSIAN_QM "${CMAKE_CURRENT_BINARY_DIR}/android-error-reason-ru.qm")
add_custom_command(OUTPUT "${ERROR_REASON_RUSSIAN_QM}"
    COMMAND Qt6::lrelease "${CMAKE_CURRENT_LIST_DIR}/../../translations/amneziavpn_ru_RU.ts"
        -qm "${ERROR_REASON_RUSSIAN_QM}"
    DEPENDS ../../translations/amneziavpn_ru_RU.ts VERBATIM)
add_executable(android_error_reason_tests
    tst_android_error_reason.cpp
    ../../core/utils/errorStrings.cpp
    ../../core/utils/errorCodes.h
    "${ERROR_REASON_RUSSIAN_QM}")
target_compile_definitions(android_error_reason_tests PRIVATE
    ANDROID_ERROR_REASON_QM="${ERROR_REASON_RUSSIAN_QM}")
target_include_directories(android_error_reason_tests PRIVATE ../..)
target_link_libraries(android_error_reason_tests PRIVATE Qt6::Core Qt6::Test)
enable_testing()
add_test(NAME android_error_reason COMMAND android_error_reason_tests)
