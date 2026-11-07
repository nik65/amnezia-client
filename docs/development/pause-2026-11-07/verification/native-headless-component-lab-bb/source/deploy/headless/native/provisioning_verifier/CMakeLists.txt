cmake_minimum_required(VERSION 3.16)
project(amnezia_native_provisioning_verifier LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)
find_package(ZLIB REQUIRED)

add_executable(amnezia-verify-provisioning-native
    src/verify_provisioning.cpp)
target_compile_options(amnezia-verify-provisioning-native PRIVATE
    -Wall -Wextra -Wpedantic -D_FORTIFY_SOURCE=2
    -fstack-protector-strong)
target_link_options(amnezia-verify-provisioning-native PRIVATE -pie)
target_link_libraries(amnezia-verify-provisioning-native PRIVATE
    OpenSSL::Crypto ZLIB::ZLIB)
