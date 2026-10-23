find_program(XCRUN_COMMAND xcrun REQUIRED)

function(notarize_file file email team_id password)
    set(args
        --apple-id ${email}
        --team-id ${team_id}
        --password ${password}
        --wait
    )

    set(cmd ${XCRUN_COMMAND} notarytool submit ${args} ${file})

    # Do not print the invocation: it contains the notarization password.
    message(STATUS "Submitting package for notarization: ${file}")

    execute_process(COMMAND ${cmd}
        RESULT_VARIABLE result
        OUTPUT_VARIABLE output
        ERROR_VARIABLE error
    )
    # Tools may echo their invocation in either stream, even on success.
    if(NOT "${password}" STREQUAL "")
        string(REPLACE "${password}" "[REDACTED]" output "${output}")
        string(REPLACE "${password}" "[REDACTED]" error "${error}")
    endif()
    if(NOT "${output}" STREQUAL "")
        message(STATUS "${output}")
    endif()
    if(NOT result EQUAL 0)
        string(REPLACE "\n" "\n  " error "  ${error}")
        message(FATAL_ERROR "notarytool failed:\n${error}")
    elseif(NOT "${error}" STREQUAL "")
        message("${error}")
    endif()
endfunction()

function(staple_file file)
    set(cmd ${XCRUN_COMMAND} stapler staple ${file})

    list(JOIN cmd " " cmd_str)
    message(STATUS ${cmd_str})

    execute_process(COMMAND ${cmd}
        RESULT_VARIABLE result
        ERROR_VARIABLE error
    )
    if(NOT result EQUAL 0)
        string(REPLACE "\n" "\n  " error "  ${error}")
        message(FATAL_ERROR "stapler failed:\n${error}")
    endif()
endfunction()


function(notarize_and_staple_file file email team_id password)
    notarize_file("${file}" "${email}" "${team_id}" "${password}")
    staple_file("${file}")
endfunction()
