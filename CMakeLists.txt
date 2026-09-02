cmake_minimum_required(VERSION 3.25.0 FATAL_ERROR)

option(AMNEZIAVPN_BUILD_HEADLESS "Build the Ubuntu headless client" OFF)
if(AMNEZIAVPN_BUILD_HEADLESS AND (NOT UNIX OR APPLE OR ANDROID OR IOS))
    message(FATAL_ERROR "AMNEZIAVPN_BUILD_HEADLESS requires a native Ubuntu/Linux build")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(PROJECT AmneziaVPN)
set(AMNEZIAVPN_VERSION 5.0.1.13)

set(QT_CREATOR_SKIP_PACKAGE_MANAGER_SETUP ON CACHE BOOL "" FORCE)
set(CMAKE_PROJECT_TOP_LEVEL_INCLUDES
    ${CMAKE_SOURCE_DIR}/cmake/platform_settings.cmake
    ${CMAKE_SOURCE_DIR}/cmake/recipes_bootstrap.cmake
    ${CMAKE_SOURCE_DIR}/cmake/conan_provider.cmake
    CACHE STRING "" FORCE)

project(${PROJECT} VERSION ${AMNEZIAVPN_VERSION}
        DESCRIPTION "AmneziaVPN"
        HOMEPAGE_URL "https://amnezia.org/"
)

if(MSVC)
    add_compile_options($<$<COMPILE_LANGUAGE:C,CXX>:/MP>)
endif()

# trigger conan to kick off `conan install` globally
find_package(OpenSSL REQUIRED)
if (PREBUILTS_ONLY)
    return()
endif()

string(TIMESTAMP CURRENT_DATE "%Y-%m-%d")
set(RELEASE_DATE "${CURRENT_DATE}")

set(APP_MAJOR_VERSION ${CMAKE_PROJECT_VERSION_MAJOR}.${CMAKE_PROJECT_VERSION_MINOR}.${CMAKE_PROJECT_VERSION_PATCH})
# Keep the fork code monotonic beyond upstream 5.0.1.5 (2152).
set(APP_ANDROID_VERSION_CODE 2161)

# Branding defaults must load before any subproject configures version.h.in:
# APPLICATION_NAME / SERVICE_NAME / ORGANIZATION_NAME are expanded from
# CLIENT_* variables there, and both the client and the service targets
# consume the generated header. Without these defaults the placeholders
# expand to empty strings, which silently changes the QSettings identity
# (user data appears "reset") and breaks IPC trust with the privileged
# service (Error 103 AmneziaServiceNotRunning).
include(${CMAKE_CURRENT_LIST_DIR}/client/cmake/clientBrandingDefaults.cmake)
foreach(_branding_var IN ITEMS
        CLIENT_APPLICATION_NAME
        CLIENT_SERVICE_NAME
        CLIENT_ORGANIZATION_NAME)
    if("${${_branding_var}}" STREQUAL "")
        message(FATAL_ERROR "Required branding variable is empty: ${_branding_var}")
    endif()
endforeach()

if(${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
    set(MZ_PLATFORM_NAME "linux")
elseif(${CMAKE_SYSTEM_NAME} STREQUAL "Windows")
    set(MZ_PLATFORM_NAME "windows")
elseif(${CMAKE_SYSTEM_NAME} STREQUAL "Darwin")
    set(MZ_PLATFORM_NAME "macos")
elseif(${CMAKE_SYSTEM_NAME} STREQUAL "Android")
    set(MZ_PLATFORM_NAME "android")
elseif(${CMAKE_SYSTEM_NAME} STREQUAL "iOS")
    set(MZ_PLATFORM_NAME "ios")
elseif(${CMAKE_SYSTEM_NAME} STREQUAL "Emscripten")
    set(MZ_PLATFORM_NAME "wasm")
endif()

set(QT_BUILD_TOOLS_WHEN_CROSS_COMPILING ON)

if(APPLE AND NOT IOS)
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        set(AMN_PF_RULE_IDENTITY "user { root }")
    else()
        set(AMN_PF_RULE_IDENTITY "group { amnvpn }")
    endif()

    configure_file(
        "${CMAKE_SOURCE_DIR}/deploy/data/pf-templates/amn.400.allowPIA.conf.in"
        "${CMAKE_CURRENT_BINARY_DIR}/amn.400.allowPIA.conf"
        @ONLY
    )

    file(COPY_FILE
        "${CMAKE_CURRENT_BINARY_DIR}/amn.400.allowPIA.conf"
        "${CMAKE_SOURCE_DIR}/deploy/data/macos/pf/amn.400.allowPIA.conf"
        ONLY_IF_DIFFERENT
    )
endif()

add_subdirectory(client)

if(NOT IOS AND NOT ANDROID AND NOT MACOS_NE)
    add_subdirectory(service)
endif()

if ((LINUX AND NOT ANDROID) OR (APPLE AND NOT IOS AND NOT MACOS_NE) OR (WIN32))
    include(${CMAKE_SOURCE_DIR}/cmake/CPack.cmake)
endif()

# Focused regression targets intentionally remain opt-in so normal desktop and
# cross-platform release packaging is unchanged.  A native maintainer build can
# enable one aggregate CTest surface instead of configuring every standalone
# test directory by hand.
option(AMNEZIAVPN_BUILD_FOCUSED_TESTS "Build the native focused regression suite" OFF)
if(AMNEZIAVPN_BUILD_FOCUSED_TESTS)
    if(CMAKE_CROSSCOMPILING OR ANDROID OR IOS OR MACOS_NE)
        message(FATAL_ERROR "AMNEZIAVPN_BUILD_FOCUSED_TESTS requires a native desktop build")
    endif()
    enable_testing()
    add_subdirectory(client/tests)
endif()

if(AMNEZIAVPN_BUILD_HEADLESS)
    add_subdirectory(headless)
endif()
