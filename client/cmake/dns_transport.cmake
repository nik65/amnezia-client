# Optional, pinned Android transport component. This module never downloads or builds an APK.
function(amnezia_bundle_android_dns_transport target_name)
    set(AMNEZIA_DNSTT_ANDROID_CLIENT "$ENV{AMNEZIA_DNSTT_ANDROID_CLIENT}" CACHE FILEPATH
        "Pinned Android PIE libdnstt.so prepared by android/dnsTransport/build_client.ps1")
    if(NOT AMNEZIA_DNSTT_ANDROID_CLIENT)
        message(STATUS "DNS fallback executable not supplied; Android retains the primary transport")
        return()
    endif()
    get_filename_component(_binary "${AMNEZIA_DNSTT_ANDROID_CLIENT}" REALPATH)
    get_filename_component(_directory "${_binary}" DIRECTORY)
    if(NOT EXISTS "${_binary}" OR NOT EXISTS "${_directory}/dnstt-manifest.json")
        message(FATAL_ERROR "DNS fallback native component or manifest missing")
    endif()
    get_filename_component(_name "${_binary}" NAME)
    if(NOT _name STREQUAL "libdnstt.so")
        message(FATAL_ERROR "DNS fallback executable must be named libdnstt.so")
    endif()
    file(READ "${_directory}/dnstt-manifest.json" _manifest)
    # PowerShell 5 may write a UTF-8 BOM; JSON's first non-whitespace character must be '{'.
    string(ASCII 239 187 191 _utf8_bom)
    string(FIND "${_manifest}" "${_utf8_bom}" _bom_position)
    if(_bom_position EQUAL 0)
        string(SUBSTRING "${_manifest}" 3 -1 _manifest)
    endif()
    string(JSON _schema GET "${_manifest}" schema)
    string(JSON _abi GET "${_manifest}" abi)
    string(JSON _commit GET "${_manifest}" sourceCommit)
    string(JSON _sum GET "${_manifest}" sourceModuleSum)
    string(JSON _sha GET "${_manifest}" sha256)
    string(JSON _api GET "${_manifest}" minimumApi)
    string(JSON _page_alignment GET "${_manifest}" minimumPageAlignment)
    file(SHA256 "${_binary}" _actual_sha)
    if(NOT _schema EQUAL 1 OR NOT _abi STREQUAL CMAKE_ANDROID_ARCH_ABI OR NOT _api EQUAL 28
       OR NOT _page_alignment EQUAL 16384
       OR NOT _commit STREQUAL "0c5c52a57d899c05428c116898941761a2ed83c2"
       OR NOT _sum STREQUAL "h1:8i4tQWwBCrhsn6+c8fpjSIyaa+u0MOvdOa1FIxNOz6M="
       OR NOT _sha STREQUAL _actual_sha)
        message(FATAL_ERROR "DNS fallback native component identity/hash/ABI mismatch")
    endif()
    # This is a PIE process executable, not a JNI shared library. Qt registers
    # QT_ANDROID_EXTRA_LIBS in bundled_libs and System.load()s every entry at
    # startup. Copy this exact payload through the non-autoload resource path
    # instead, while retaining its .so name for Android nativeLibraryDir.
    set(_payload_directory "${CMAKE_CURRENT_BINARY_DIR}/android-dnstt/${CMAKE_ANDROID_ARCH_ABI}")
    file(MAKE_DIRECTORY "${_payload_directory}")
    set(_payload "${_payload_directory}/libdnstt.so")
    configure_file("${_binary}" "${_payload}" COPYONLY USE_SOURCE_PERMISSIONS)
    file(SHA256 "${_payload}" _payload_sha)
    if(NOT _payload_sha STREQUAL _sha)
        message(FATAL_ERROR "DNS fallback native component changed while staging")
    endif()
    set_property(TARGET ${target_name} APPEND PROPERTY QT_ANDROID_EXTRA_PLUGINS "${_payload_directory}")
    message(STATUS "Bundling pinned Android DNS transport for ${_abi}")
endfunction()
