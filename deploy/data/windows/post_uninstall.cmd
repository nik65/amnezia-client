@echo off
setlocal EnableExtensions DisableDelayedExpansion
set "AmneziaPath=%~dp0"
set "MaxCleanupAttempts=6"
set "MaxDeleteAttempts=6"
set "MaxDriverDeleteAttempts=6"
set "MaxServiceStopAttempts=15"
set "MaxRegistrationChecks=30"
set "CleanupAttempts=0"
set "MainDeleteAttempts=0"
set "TunnelDeleteAttempts=0"
set "DriverDeleteAttempts=0"
set "CleanupExitCode=not-run"
set "RecoveryActionsDisarmed=0"

rem Define directories for logs
set "ORG_DIR=%AppData%\AmneziaVPN.ORG"
set "USER_APP_DIR=%ORG_DIR%\AmneziaVPN"
set "USER_LOG_DIR=%USER_APP_DIR%\log"
set "SYS_APP_DIR=%ProgramData%\AmneziaVPN"
set "SYS_LOG_DIR=%SYS_APP_DIR%\log"
set "SYS_LOG_FILE=%SYS_LOG_DIR%\AmneziaVPN-service.log"
set "RECOVERY_ROOT=%ProgramFiles%\AmneziaVPN-Recovery"
set "RECOVERY_DIR=%RECOVERY_ROOT%\uninstall-recovery"
set "RECOVERY_STAGING_DIR=%RECOVERY_ROOT%\uninstall-recovery.staging"
set "FAILURE_RECEIPT=%RECOVERY_ROOT%\uninstall-cleanup-failed.txt"
set "EMERGENCY_MARKER=%RECOVERY_ROOT%\uninstall-recovery-required.txt"
set "RecoveryStatus=not-attempted"
set "RecoveryCopyExitCode=not-run"
set "RecoveryValidated=0"
set "RecoveryAclStatus=not-attempted"
set "RecoveryPathStatus=not-attempted"
set "EmergencyMarkerStatus=not-needed"
set "FailureReceiptStatus=not-needed"

rem Persistent WFP kill-switch filters survive the daemon by design. Remove
rem the Amnezia-owned generation before uninstalling its reconciler. Qt IFW
rem 4.7 can Ignore a failed UNDOEXECUTE operation. Keep this best-effort
rem cleanup bounded, record a durable failure receipt, and return instead of
rem leaving the uninstaller on an unbounded retry loop.
:cleanup_firewall
set /a CleanupAttempts+=1 >nul
if %CleanupAttempts% GTR %MaxCleanupAttempts% goto cleanup_failed

if not exist "%AmneziaPath%AmneziaVPN-service.exe" (
    set "CleanupExitCode=helper-missing"
    echo Firewall cleanup helper is missing; repair the installation and retry uninstall. 1>&2
    call :wait_before_retry
    goto cleanup_firewall
)

rem Disable the registered service before stopping it. This prevents SCM or a
rem concurrent client from restarting the reconciler between stop and cleanup.
rem Clear the configured restart/2000 failure actions first. start= disabled
rem does not cancel an SCM recovery action that was already armed by a forced
rem or late service exit.
call :clear_service_failure_actions AmneziaVPN-service
if errorlevel 1 (
    set "CleanupExitCode=main-service-failure-actions-still-enabled"
    echo Unable to disable AmneziaVPN-service recovery actions; retrying without removing files. 1>&2
    call :wait_before_retry
    goto cleanup_firewall
)
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
rem The persistent split-tunnel driver is a separate kernel service. Stop it
rem explicitly so old service binaries with a broken ControlService call can
rem still be removed by a repaired uninstaller.
sc stop AmneziaVPNSplitTunnel >nul 2>&1
call :wait_for_service_stop
if errorlevel 1 (
    rem A legacy service can ignore SERVICE_CONTROL_STOP. The recovery actions
    rem are already disabled, so this bounded exact-image fallback cannot arm
    rem an SCM restart while uninstall is deleting registrations.
    taskkill /IM "AmneziaVPN-service.exe" /F >nul 2>&1
    call :wait_for_service_stop
    if errorlevel 1 (
        set "CleanupExitCode=main-service-stop-timeout"
        echo AmneziaVPN-service did not stop after the bounded forced fallback. 1>&2
        call :wait_before_retry
        goto cleanup_firewall
    )
)

"%AmneziaPath%AmneziaVPN-service.exe" cleanup-firewall
set "CleanupExitCode=%errorlevel%"
if "%CleanupExitCode%"=="0" goto cleanup_succeeded

if "%CleanupExitCode%"=="2" (
    echo Waiting for AmneziaVPN-service to reach the stopped state. 1>&2
) else (
    echo Persistent firewall cleanup failed; retrying while the service remains disabled. 1>&2
)
call :wait_before_retry
goto cleanup_firewall

:cleanup_failed
set "CleanupFailureStage=cleanup-firewall"
goto cleanup_failure_cleanup

:cleanup_succeeded

rem cleanup-firewall calls WindowsSplitTunnel::removeForUninstall(), which
rem stops and deletes the Amnezia-owned driver. Only SCM's exact
rem ERROR_SERVICE_DOES_NOT_EXIST result proves that asynchronous deletion is
rem complete; access errors and unrelated failures remain fail-closed.
:verify_split_tunnel_driver_deleted
call :wait_for_service_absent AmneziaVPNSplitTunnel split-tunnel-driver-delete driver-registration-still-present
if errorlevel 1 goto cleanup_failure_cleanup

rem Remove service registrations only after persistent policy cleanup succeeds.
:delete_main_service
set /a MainDeleteAttempts+=1 >nul
sc delete AmneziaVPN-service
if errorlevel 1 (
    sc query AmneziaVPN-service >nul 2>&1
    if not errorlevel 1 (
        if %MainDeleteAttempts% GEQ %MaxDeleteAttempts% (
            echo Unable to delete AmneziaVPN-service after %MaxDeleteAttempts% attempts; aborting uninstall. 1>&2
            set "CleanupFailureStage=main-service-delete"
            set "CleanupExitCode=main-service-registration-still-present"
            goto cleanup_failure_cleanup
        )
        echo Unable to delete AmneziaVPN-service; retrying without removing files. 1>&2
        call :wait_before_retry
        goto delete_main_service
    )
)
call :wait_for_service_absent AmneziaVPN-service main-service-delete main-service-registration-still-present
if errorlevel 1 goto cleanup_failure_cleanup

:delete_tunnel_service
set /a TunnelDeleteAttempts+=1 >nul
sc delete AmneziaWGTunnel$AmneziaVPN
if errorlevel 1 (
    sc query AmneziaWGTunnel$AmneziaVPN >nul 2>&1
    if not errorlevel 1 (
        if %TunnelDeleteAttempts% GEQ %MaxDeleteAttempts% (
            echo Unable to delete the WireGuard tunnel service after %MaxDeleteAttempts% attempts; aborting uninstall. 1>&2
            set "CleanupFailureStage=wireguard-tunnel-service-delete"
            set "CleanupExitCode=wireguard-tunnel-registration-still-present"
            goto cleanup_failure_cleanup
        )
        echo Unable to delete the WireGuard tunnel service; retrying without removing files. 1>&2
        call :wait_before_retry
        goto delete_tunnel_service
    )
)
call :wait_for_service_absent AmneziaWGTunnel$AmneziaVPN wireguard-tunnel-service-delete wireguard-tunnel-registration-still-present
if errorlevel 1 goto cleanup_failure_cleanup

rem Delete stale recovery receipts only after proving that their parent is the
rem protected, non-reparse recovery root. Never follow a user-created junction
rem from an elevated uninstall.
call :prepare_recovery_root
if not "%RecoveryAclStatus%"=="ok" goto skip_stale_recovery_receipts
call :reject_reparse_point "%RECOVERY_ROOT%"
if not "%RecoveryPathStatus%"=="regular" goto skip_stale_recovery_receipts
call :reject_reparse_point "%FAILURE_RECEIPT%"
if "%RecoveryPathStatus%"=="regular" del /F /Q "%FAILURE_RECEIPT%"
call :reject_reparse_point "%EMERGENCY_MARKER%"
if "%RecoveryPathStatus%"=="regular" del /F /Q "%EMERGENCY_MARKER%"
:skip_stale_recovery_receipts

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

:cleanup_failure_cleanup
rem IFW may continue with Ignore after this script returns nonzero. Do not
rem restart a service whose TargetDir can then be removed. First preserve a
rem complete recovery bundle in a protected Program Files sibling, then leave
rem a text-only receipt in that protected root and deregister every
rem Amnezia-owned service on a best-effort basis instead.
echo Persistent cleanup failed at %CleanupFailureStage%; preparing recovery bundle before removing service registrations. 1>&2
call :create_recovery_bundle
if not "%RecoveryValidated%"=="1" call :write_emergency_marker
call :write_failure_receipt "%CleanupFailureStage%" "%CleanupExitCode%"
taskkill /IM "AmneziaVPN.exe" /F >nul 2>&1
sc stop AmneziaWGTunnel$AmneziaVPN >nul 2>&1
sc stop AmneziaVPNSplitTunnel >nul 2>&1
sc delete AmneziaWGTunnel$AmneziaVPN >nul 2>&1
sc delete AmneziaVPNSplitTunnel >nul 2>&1
if "%RecoveryActionsDisarmed%"=="1" (
    sc config AmneziaVPN-service start= disabled >nul 2>&1
    sc stop AmneziaVPN-service >nul 2>&1
    taskkill /IM "AmneziaVPN-service.exe" /F >nul 2>&1
    sc delete AmneziaVPN-service >nul 2>&1
) else (
    echo Main service recovery actions were not proven disabled; leaving its process and registration intact. 1>&2
)
exit /b 1

:create_recovery_bundle
rem The copied post_uninstall.cmd uses %~dp0, so the recovered helper and all
rem of its DLLs can be safely run again after IFW deletes TargetDir. Executable
rem recovery data must never be written below user-writable ProgramData. Create
rem and verify a protected Program Files sibling before the first copy. Stage
rem first so a valid bundle is never replaced by a partial source copy.
set "RecoveryStatus=starting"
set "RecoveryCopyExitCode=not-run"
set "RecoveryValidated=0"
call :prepare_recovery_root
if not "%RecoveryAclStatus%"=="ok" goto recovery_protected_root_unavailable
if not exist "%AmneziaPath%AmneziaVPN-service.exe" goto recovery_source_helper_missing
if not exist "%AmneziaPath%post_uninstall.cmd" goto recovery_source_script_missing
call :remove_recovery_directory "%RECOVERY_STAGING_DIR%"
if not "%RecoveryPathStatus%"=="removed" goto recovery_staging_unsafe
mkdir "%RECOVERY_STAGING_DIR%" >nul 2>&1
if not exist "%RECOVERY_STAGING_DIR%" goto recovery_staging_unavailable
call :reject_reparse_point "%RECOVERY_STAGING_DIR%"
if not "%RecoveryPathStatus%"=="regular" goto recovery_staging_unsafe
call :copy_recovery_tree "%AmneziaPath%" "%RECOVERY_STAGING_DIR%"
if not "%RecoveryCopyStatus%"=="ok" goto recovery_staging_copy_failed
if not exist "%RECOVERY_STAGING_DIR%\AmneziaVPN-service.exe" goto recovery_staging_helper_missing
if not exist "%RECOVERY_STAGING_DIR%\post_uninstall.cmd" goto recovery_staging_script_missing
call :remove_recovery_directory "%RECOVERY_DIR%"
if not "%RecoveryPathStatus%"=="removed" goto recovery_bundle_unsafe
call :mirror_recovery_tree "%RECOVERY_STAGING_DIR%" "%RECOVERY_DIR%"
if not "%RecoveryCopyStatus%"=="ok" goto recovery_bundle_copy_failed
call :reject_reparse_point "%RECOVERY_DIR%"
if not "%RecoveryPathStatus%"=="regular" goto recovery_bundle_unsafe
if not exist "%RECOVERY_DIR%\AmneziaVPN-service.exe" goto recovery_bundle_helper_missing
if not exist "%RECOVERY_DIR%\post_uninstall.cmd" goto recovery_bundle_script_missing
call :verify_recovery_acl
if not "%RecoveryAclStatus%"=="ok" goto recovery_acl_verification_failed
set "RecoveryStatus=validated"
set "RecoveryValidated=1"
exit /b 0

:recovery_source_helper_missing
set "RecoveryStatus=source-helper-missing"
exit /b 0
:recovery_source_script_missing
set "RecoveryStatus=source-script-missing"
exit /b 0
:recovery_protected_root_unavailable
set "RecoveryStatus=protected-root-%RecoveryAclStatus%"
exit /b 0
:recovery_acl_verification_failed
set "RecoveryStatus=acl-verification-failed"
exit /b 0
:recovery_staging_unsafe
set "RecoveryStatus=staging-directory-%RecoveryPathStatus%"
exit /b 0
:recovery_staging_unavailable
set "RecoveryStatus=staging-directory-unavailable"
exit /b 0
:recovery_staging_copy_failed
set "RecoveryStatus=staging-copy-failed"
exit /b 0
:recovery_staging_helper_missing
set "RecoveryStatus=staging-helper-missing"
exit /b 0
:recovery_staging_script_missing
set "RecoveryStatus=staging-script-missing"
exit /b 0
:recovery_bundle_copy_failed
set "RecoveryStatus=bundle-copy-failed"
exit /b 0
:recovery_bundle_unsafe
set "RecoveryStatus=bundle-directory-%RecoveryPathStatus%"
exit /b 0
:recovery_bundle_helper_missing
set "RecoveryStatus=bundle-helper-missing"
exit /b 0
:recovery_bundle_script_missing
set "RecoveryStatus=bundle-script-missing"
exit /b 0

:copy_recovery_tree
set "RecoveryCopyStatus=failed"
"%SystemRoot%\System32\robocopy.exe" "%~1" "%~2" /E /COPY:DAT /DCOPY:DAT /R:1 /W:1 /NFL /NDL /NJH /NJS >nul
set "RecoveryCopyExitCode=%errorlevel%"
if %RecoveryCopyExitCode% GEQ 8 exit /b 0
set "RecoveryCopyStatus=ok"
exit /b 0

:mirror_recovery_tree
set "RecoveryCopyStatus=failed"
"%SystemRoot%\System32\robocopy.exe" "%~1" "%~2" /MIR /COPY:DAT /DCOPY:DAT /R:1 /W:1 /NFL /NDL /NJH /NJS >nul
set "RecoveryCopyExitCode=%errorlevel%"
if %RecoveryCopyExitCode% GEQ 8 exit /b 0
set "RecoveryCopyStatus=ok"
exit /b 0

:prepare_recovery_root
rem Program Files is protected against directory creation by standard users.
rem Reject reparse points, remove inherited ACLs, grant only LocalSystem and
rem Administrators, then independently verify the resulting protected DACL.
set "RecoveryAclStatus=starting"
if not defined ProgramFiles goto recovery_root_path_unavailable
if not exist "%RECOVERY_ROOT%" mkdir "%RECOVERY_ROOT%" >nul 2>&1
if not exist "%RECOVERY_ROOT%" goto recovery_root_create_failed
"%SystemRoot%\System32\fsutil.exe" reparsepoint query "%RECOVERY_ROOT%" >nul 2>&1
if not errorlevel 1 goto recovery_root_reparse_point
"%SystemRoot%\System32\icacls.exe" "%RECOVERY_ROOT%" /inheritance:r >nul 2>&1
if errorlevel 1 goto recovery_root_acl_hardening_failed
"%SystemRoot%\System32\icacls.exe" "%RECOVERY_ROOT%" /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" >nul 2>&1
if errorlevel 1 goto recovery_root_acl_hardening_failed
call :verify_recovery_acl
exit /b 0

:recovery_root_path_unavailable
set "RecoveryAclStatus=path-unavailable"
exit /b 0
:recovery_root_create_failed
set "RecoveryAclStatus=create-failed"
exit /b 0
:recovery_root_reparse_point
set "RecoveryAclStatus=reparse-point-rejected"
exit /b 0
:recovery_root_acl_hardening_failed
set "RecoveryAclStatus=hardening-failed"
exit /b 0

:verify_recovery_acl
set "RecoveryAclStatus=verification-failed"
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$allowed=@('S-1-5-18','S-1-5-32-544'); $acl=Get-Acl -LiteralPath $env:RECOVERY_ROOT -ErrorAction Stop; $sids=@(); foreach($rule in $acl.Access){ if($rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow){ $sids += $rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } }; $bad=@($sids | Where-Object { $_ -notin $allowed }); $missing=@($allowed | Where-Object { $_ -notin $sids }); if((-not $acl.AreAccessRulesProtected) -or $bad.Count -ne 0 -or $missing.Count -ne 0){ exit 1 }; exit 0" >nul 2>&1
if errorlevel 1 exit /b 0
set "RecoveryAclStatus=ok"
exit /b 0

:remove_recovery_directory
set "RecoveryPathStatus=unsafe"
if not exist "%~1" goto recovery_directory_removed
"%SystemRoot%\System32\fsutil.exe" reparsepoint query "%~1" >nul 2>&1
if not errorlevel 1 exit /b 0
rmdir /S /Q "%~1" >nul 2>&1
if exist "%~1" goto recovery_directory_remove_failed
:recovery_directory_removed
set "RecoveryPathStatus=removed"
exit /b 0
:recovery_directory_remove_failed
set "RecoveryPathStatus=remove-failed"
exit /b 0

:reject_reparse_point
set "RecoveryPathStatus=unsafe"
"%SystemRoot%\System32\fsutil.exe" reparsepoint query "%~1" >nul 2>&1
if not errorlevel 1 exit /b 0
if not exist "%~1" goto recovery_path_missing
set "RecoveryPathStatus=regular"
exit /b 0
:recovery_path_missing
set "RecoveryPathStatus=missing"
exit /b 0

:write_emergency_marker
rem A failed bundle must never become an elevated arbitrary-file write. Use
rem only the already protected, non-reparse recovery root. If it is unsafe or
rem unavailable, record a fixed Windows event and emit stderr instead.
set "EmergencyMarkerStatus=not-written"
call :verify_recovery_acl
if not "%RecoveryAclStatus%"=="ok" goto emergency_marker_unavailable
call :reject_reparse_point "%RECOVERY_ROOT%"
if not "%RecoveryPathStatus%"=="regular" goto emergency_marker_unavailable
call :reject_reparse_point "%EMERGENCY_MARKER%"
if "%RecoveryPathStatus%"=="unsafe" goto emergency_marker_unavailable
> "%EMERGENCY_MARKER%" echo result=manual-recovery-required
>> "%EMERGENCY_MARKER%" echo recovery_status=%RecoveryStatus%
>> "%EMERGENCY_MARKER%" echo action=Install a fixed AmneziaVPN Windows package, then run its uninstaller elevated. Do not manually delete WFP rules or driver services.
if exist "%EMERGENCY_MARKER%" set "EmergencyMarkerStatus=protected-recovery-root"
if exist "%EMERGENCY_MARKER%" exit /b 0

:emergency_marker_unavailable
set "EmergencyMarkerStatus=event-log-only"
call :write_failure_event
echo EMERGENCY: recovery bundle is unavailable; reinstall a fixed AmneziaVPN package and run its uninstaller elevated. 1>&2
exit /b 0

:write_failure_receipt
rem Keep diagnostics beside the protected recovery bundle. Individual echo
rem commands avoid reparsing a user-selected install path inside a parenthesized
rem elevated cmd.exe block.
set "FailureReceiptStatus=not-written"
call :verify_recovery_acl
if not "%RecoveryAclStatus%"=="ok" goto failure_receipt_unavailable
call :reject_reparse_point "%RECOVERY_ROOT%"
if not "%RecoveryPathStatus%"=="regular" goto failure_receipt_unavailable
call :reject_reparse_point "%FAILURE_RECEIPT%"
if "%RecoveryPathStatus%"=="unsafe" goto failure_receipt_unavailable
> "%FAILURE_RECEIPT%" echo result=failed
>> "%FAILURE_RECEIPT%" echo stage=%~1
>> "%FAILURE_RECEIPT%" echo cleanup_exit_code=%~2
>> "%FAILURE_RECEIPT%" echo cleanup_attempts=%CleanupAttempts%
>> "%FAILURE_RECEIPT%" echo driver_delete_checks=%DriverDeleteAttempts%
>> "%FAILURE_RECEIPT%" echo recovery_status=%RecoveryStatus%
>> "%FAILURE_RECEIPT%" echo recovery_copy_exit_code=%RecoveryCopyExitCode%
>> "%FAILURE_RECEIPT%" echo recovery_validated=%RecoveryValidated%
>> "%FAILURE_RECEIPT%" echo recovery_acl_status=%RecoveryAclStatus%
>> "%FAILURE_RECEIPT%" echo emergency_marker_status=%EmergencyMarkerStatus%
if exist "%FAILURE_RECEIPT%" set "FailureReceiptStatus=protected-recovery-root"
if exist "%FAILURE_RECEIPT%" exit /b 0

:failure_receipt_unavailable
set "FailureReceiptStatus=event-log-only"
call :write_failure_event
exit /b 0

:write_failure_event
"%SystemRoot%\System32\eventcreate.exe" /T ERROR /ID 100 /L APPLICATION /SO AmneziaVPN /D "AmneziaVPN uninstall cleanup failed; reinstall a fixed package and run its uninstaller elevated." >nul 2>&1
exit /b 0

:clear_service_failure_actions
"%SystemRoot%\System32\sc.exe" failure "%~1" reset= 0 actions= "" >nul 2>&1
set "ServiceFailureActionsExitCode=%errorlevel%"
if "%ServiceFailureActionsExitCode%"=="0" (
    set "RecoveryActionsDisarmed=1"
    exit /b 0
)
"%SystemRoot%\System32\sc.exe" query "%~1" >nul 2>&1
set "ServiceQueryExitCode=%errorlevel%"
if "%ServiceQueryExitCode%"=="1060" (
    set "RecoveryActionsDisarmed=1"
    exit /b 0
)
exit /b 1

:wait_for_service_absent
set "WaitServiceName=%~1"
set "WaitFailureStage=%~2"
set "WaitFailureCode=%~3"
set "RegistrationChecks=0"
:wait_for_service_absent_loop
set /a RegistrationChecks+=1 >nul
"%SystemRoot%\System32\sc.exe" query "%WaitServiceName%" >nul 2>&1
set "ServiceQueryExitCode=%errorlevel%"
if "%ServiceQueryExitCode%"=="1060" exit /b 0
if not "%ServiceQueryExitCode%"=="0" if not "%ServiceQueryExitCode%"=="1072" (
    set "CleanupFailureStage=%WaitFailureStage%"
    set "CleanupExitCode=%WaitFailureCode%-query-%ServiceQueryExitCode%"
    exit /b 1
)
if %RegistrationChecks% GEQ %MaxRegistrationChecks% (
    set "CleanupFailureStage=%WaitFailureStage%"
    set "CleanupExitCode=%WaitFailureCode%"
    exit /b 1
)
call :wait_for_short_poll
goto wait_for_service_absent_loop

:wait_before_retry
rem timeout.exe fails immediately when Qt IFW redirects stdin. ping.exe keeps
rem the retry delay effective in both interactive and elevated QProcess runs.
"%SystemRoot%\System32\ping.exe" -n 6 127.0.0.1 >nul 2>&1
exit /b 0

:wait_for_service_stop
set "ServiceStopAttempts=0"
:wait_for_service_stop_loop
set /a ServiceStopAttempts+=1 >nul
"%SystemRoot%\System32\sc.exe" query AmneziaVPN-service >nul 2>&1
set "ServiceQueryExitCode=%errorlevel%"
if "%ServiceQueryExitCode%"=="1060" exit /b 0
if not "%ServiceQueryExitCode%"=="0" exit /b 1
"%SystemRoot%\System32\sc.exe" query AmneziaVPN-service 2>nul | "%SystemRoot%\System32\findstr.exe" /R /C:"STATE *: *1 " >nul
if not errorlevel 1 exit /b 0
if %ServiceStopAttempts% GEQ %MaxServiceStopAttempts% exit /b 1
call :wait_for_short_poll
goto wait_for_service_stop_loop

:wait_for_short_poll
"%SystemRoot%\System32\ping.exe" -n 2 127.0.0.1 >nul 2>&1
exit /b 0
