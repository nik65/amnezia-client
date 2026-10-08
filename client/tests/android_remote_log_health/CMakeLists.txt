cmake_minimum_required(VERSION 3.25)
project(AndroidRemoteLogHealthTests LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_AUTOMOC ON)
find_package(Qt6 REQUIRED COMPONENTS Core Network Qml Test)
add_executable(android_remote_log_health_tests tst_android_remote_log_health.cpp
    ../../ui/controllers/remoteLogHealthUiController.cpp
    ../../ui/controllers/remoteLogHealthUiController.h
    ../../core/controllers/remoteLogUploader.h)
target_include_directories(android_remote_log_health_tests PRIVATE ../..)
target_link_libraries(android_remote_log_health_tests PRIVATE Qt6::Core Qt6::Network Qt6::Qml Qt6::Test)
enable_testing()
add_test(NAME android_remote_log_health COMMAND android_remote_log_health_tests)
