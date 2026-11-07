cmake_minimum_required(VERSION 3.25)

# The installed GUI runtime is shared by ordinary users. Keep the builder's
# private workspace permissions outside this public IFW component untouched.
if(NOT CMAKE_HOST_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "Linux runtime permission normalization requires Linux")
endif()
if(NOT DEFINED CPACK_TEMPORARY_DIRECTORY OR CPACK_TEMPORARY_DIRECTORY STREQUAL "")
    message(FATAL_ERROR "Missing CPack staging directory")
endif()
set(_runtime_root "${CPACK_TEMPORARY_DIRECTORY}/packages/AmneziaVPN/data")
if(NOT IS_DIRECTORY "${_runtime_root}" OR IS_SYMLINK "${_runtime_root}")
    message(FATAL_ERROR "Missing or linked public runtime staging directory")
endif()
file(REAL_PATH "${_runtime_root}" _runtime_real)
get_filename_component(_runtime_absolute "${_runtime_root}" ABSOLUTE)
if(NOT _runtime_real STREQUAL _runtime_absolute)
    message(FATAL_ERROR "Public runtime staging path has a linked ancestor")
endif()
file(GLOB_RECURSE _runtime_entries LIST_DIRECTORIES TRUE "${_runtime_root}/*")
list(PREPEND _runtime_entries "${_runtime_root}")
foreach(_entry IN LISTS _runtime_entries)
    if(IS_DIRECTORY "${_entry}" AND NOT IS_SYMLINK "${_entry}")
        file(CHMOD "${_entry}" PERMISSIONS
            OWNER_READ OWNER_WRITE OWNER_EXECUTE
            GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
    endif()
endforeach()
