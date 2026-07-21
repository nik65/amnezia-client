@echo off
setlocal EnableExtensions DisableDelayedExpansion
set "AmneziaPath=%~dp0"

rem Define directories for logs
set "ORG_DIR=%AppData%\AmneziaVPN.ORG"
set "USER_APP_DIR=%ORG_DIR%\AmneziaVPN"
set "USER_LOG_DIR=%USER_APP_DIR%\log"
set "SYS_APP_DIR=%ProgramData%\AmneziaVPN"
set "SYS_LOG_DIR=%SYS_APP_DIR%\log"
set "SYS_LOG_FILE=%SYS_LOG_DIR%\AmneziaVPN-service.log"

rem Persistent WFP kill-switch filters survive the daemon by design. Remove
rem the Amnezia-owned generation before uninstalling its reconciler. Qt IFW
rem 4.7 lets users ignore a failed UNDOEXECUTE operation, so this script must
rem return only after cleanup succeeds. A retry keeps the recovery binary and
rem installation target in place.
:cleanup_firewall
if not exist "%AmneziaPath%AmneziaVPN-service.exe" (
    echo Firewall cleanup helper is missing; repair the installation and retry uninstall. 1>&2
    call :wait_before_retry
    goto cleanup_firewall
)

rem Disable the registered service before stopping it. This prevents SCM or a
rem concurrent client from restarting the reconciler between stop and cleanup.
sc config AmneziaVPN-service start= disabled >nul 2>&1
if errorlevel 1 (
    sc query AmneziaVPN-service >nul 2>&1
    if not errorlevel 1 (
        echo Unable to disable AmneziaVPN-service; retrying without removing files. 1>&2
        call :wait_before_retry
        goto cleanup_firewall
    )
)

taskkill /IM "AmneziaVPN.exe" /F >nul 2>&1
sc stop AmneziaWGTunnel$AmneziaVPN >nul 2>&1
sc stop AmneziaVPN-service >nul 2>&1
call :wait_for_service_stop
taskkill /IM "AmneziaVPN-service.exe" /F >nul 2>&1

"%AmneziaPath%AmneziaVPN-service.exe" cleanup-firewall
set "CleanupExitCode=%errorlevel%"
if "%CleanupExitCode%"=="0" goto cleanup_succeeded

if "%CleanupExitCode%"=="2" (
    echo Waiting for AmneziaVPN-service to reach the stopped state. 1>&2
) else (
    rem Cleanup failed after shutdown. Restore the reconciler while the
    rem installation is still intact, then make another bounded attempt.
    echo Persistent firewall cleanup failed; restoring the service before retry. 1>&2
    sc config AmneziaVPN-service start= auto >nul 2>&1
    sc start AmneziaVPN-service >nul 2>&1
)
call :wait_before_retry
goto cleanup_firewall

:cleanup_succeeded

rem Remove service registrations only after persistent policy cleanup succeeds.
:delete_main_service
sc delete AmneziaVPN-service
if errorlevel 1 (
    sc query AmneziaVPN-service >nul 2>&1
    if not errorlevel 1 (
        echo Unable to delete AmneziaVPN-service; retrying without removing files. 1>&2
        call :wait_before_retry
        goto delete_main_service
    )
)

:delete_tunnel_service
sc delete AmneziaWGTunnel$AmneziaVPN
if errorlevel 1 (
    sc query AmneziaWGTunnel$AmneziaVPN >nul 2>&1
    if not errorlevel 1 (
        echo Unable to delete the WireGuard tunnel service; retrying without removing files. 1>&2
        call :wait_before_retry
        goto delete_tunnel_service
    )
)

rem Delete the service log file under ProgramData
if exist "%SYS_LOG_FILE%" del /F /Q "%SYS_LOG_FILE%"
if exist "%SYS_LOG_DIR%" rmdir /S /Q "%SYS_LOG_DIR%"
rem Try to remove application dir if empty
rd "%SYS_APP_DIR%" 2>nul

rem Delete client logs under current user's AppData\Roaming (Organization\Application)
if exist "%USER_LOG_DIR%" rmdir /S /Q "%USER_LOG_DIR%"
rem Try to remove app and org directories if empty
rd "%USER_APP_DIR%" 2>nul
rd "%ORG_DIR%" 2>nul

exit /b 0

:wait_before_retry
rem timeout.exe fails immediately when Qt IFW redirects stdin. ping.exe keeps
rem the retry delay effective in both interactive and elevated QProcess runs.
"%SystemRoot%\System32\ping.exe" -n 6 127.0.0.1 >nul 2>&1
exit /b 0

:wait_for_service_stop
"%SystemRoot%\System32\ping.exe" -n 3 127.0.0.1 >nul 2>&1
exit /b 0
