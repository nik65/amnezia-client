include_guard(GLOBAL)

function(amnezia_runtime_dependency_directories output_variable)
    set(_amnezia_runtime_directories "${CONAN_RUNTIME_LIB_DIRS}")

    if(WIN32 AND MSVC)
        # Resolve and ship the redistributable selected for the target toolchain.
        set(CMAKE_INSTALL_SYSTEM_RUNTIME_LIBS_SKIP TRUE)
        include(InstallRequiredSystemLibraries)
        set(_amnezia_runtime_files "${CMAKE_INSTALL_SYSTEM_RUNTIME_LIBS}")
        set(_amnezia_crt_directories)
        foreach(_amnezia_runtime_file IN LISTS _amnezia_runtime_files)
            get_filename_component(_amnezia_runtime_directory
                "${_amnezia_runtime_file}" DIRECTORY)
            list(APPEND _amnezia_runtime_directories "${_amnezia_runtime_directory}")
            if(_amnezia_runtime_directory MATCHES "/Microsoft\\.VC[0-9]+\\.CRT$")
                list(APPEND _amnezia_crt_directories "${_amnezia_runtime_directory}")
            endif()
        endforeach()
        list(REMOVE_DUPLICATES _amnezia_crt_directories)

        # VS servicing releases can add DLLs beyond CMake's built-in file list.
        foreach(_amnezia_crt_directory IN LISTS _amnezia_crt_directories)
            file(GLOB _amnezia_crt_files LIST_DIRECTORIES FALSE
                "${_amnezia_crt_directory}/*.dll")
            list(APPEND _amnezia_runtime_files ${_amnezia_crt_files})
        endforeach()
        list(REMOVE_DUPLICATES _amnezia_runtime_files)
        list(REMOVE_DUPLICATES _amnezia_runtime_directories)

        get_property(_amnezia_runtime_install_registered GLOBAL
            PROPERTY AMNEZIA_WINDOWS_RUNTIME_INSTALL_REGISTERED)
        if(_amnezia_runtime_files AND NOT _amnezia_runtime_install_registered)
            install(PROGRAMS ${_amnezia_runtime_files}
                DESTINATION "${CMAKE_INSTALL_BINDIR}"
                COMPONENT AmneziaVPN)
            set_property(GLOBAL PROPERTY AMNEZIA_WINDOWS_RUNTIME_INSTALL_REGISTERED TRUE)
        endif()
    endif()

    set(${output_variable} "${_amnezia_runtime_directories}" PARENT_SCOPE)
endfunction()
