var requestToQuitFromApp = false;
var updaterCompleted = 0;
var desktopAppProcessRunning = false;
var appInstalledUninstallerPath = "C:/Program Files/AmneziaVPN/maintenancetool.exe";
var appInstalledUninstallerPath_x86 = "C:/Program Files (x86)/AmneziaVPN/maintenancetool.exe";
var windowsMainServicePrepared = false;
var windowsMainServiceConfigSnapshot = null;
var windowsUpgradeAdminRightsAcquired = false;
var windowsUpgradePrepareFailureReason = "";
var windowsMainServiceConfigSnapshotFailureReason = "";
var windowsUpgradeReplacementRequested = false;
var windowsUpgradeContinuationRequested = false;
var windowsUpgradeNextRequested = false;
var windowsUpgradeCommitRequested = false;
var windowsInstallerLogSession = "installer-" + new Date().getTime();
var windowsServiceUpgradeJournalPath = "C:/Program Files/AmneziaVPN-Recovery/upgrade-service-journal.json";

function writeWindowsInstallerLog(phase, detail)
{
    if (!runningOnWindows()) {
        return;
    }

    // Keep this diagnostic in the interactive user's local profile: the legacy
    // uninstaller intentionally removes the application and its log directory. The
    // arguments are reduced to a fixed phase plus a short sanitized value;
    // command output, configuration, addresses and credentials never enter
    // this journal. Logging is best-effort and must never affect installation.
    var safePhase = String(phase).replace(/[^A-Za-z0-9._-]/g, "-").substr(0, 64);
    var safeDetail = String(detail || "").replace(/[^A-Za-z0-9._:-]/g, "-").substr(0, 160);
    // Qt IFW expands every at-sign-delimited variable in installer.execute()
    // arguments. Keep the PowerShell payload completely free of that character
    // so array/hash syntax is not removed before PowerShell starts.
    var script = "& { param($Session,$Phase,$Detail) "
        + "$ErrorActionPreference='Stop'; try { "
        + "$Base=$env:LOCALAPPDATA; if ([string]::IsNullOrWhiteSpace($Base)) { $Base=Join-Path $env:USERPROFILE 'AppData/Local' }; "
        + "if ([string]::IsNullOrWhiteSpace($Base)) { return }; $Root=Join-Path $Base 'AmneziaVPN-InstallerLogs'; "
        + "if (Test-Path -LiteralPath $Root) { $RootItem=Get-Item -LiteralPath $Root -Force; if (-not $RootItem.PSIsContainer -or ($RootItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) { return } } "
        + "else { New-Item -ItemType Directory -Path $Root | Out-Null }; "
        + "$Path=Join-Path $Root ($Session+'.jsonl'); "
        + "$Files=[array](Get-ChildItem -LiteralPath $Root -File -Filter 'installer-*.jsonl' | Where-Object { -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) } | Sort-Object LastWriteTimeUtc -Descending); "
        + "$Files | Where-Object LastWriteTimeUtc -lt ([DateTime]::UtcNow.AddDays(-14)) | Remove-Item -Force -ErrorAction SilentlyContinue; "
        + "if (Test-Path -LiteralPath $Path) { $PathItem=Get-Item -LiteralPath $Path -Force; if ($PathItem.PSIsContainer -or ($PathItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $PathItem.Length -ge 256KB) { return } }; "
        + "$Record=New-Object System.Collections.Specialized.OrderedDictionary; $Record.Add('schema',1); $Record.Add('utc',[DateTime]::UtcNow.ToString('o')); $Record.Add('phase',$Phase); $Record.Add('detail',$Detail); "
        + "$Line=$Record | ConvertTo-Json -Compress; [IO.File]::AppendAllText($Path,$Line+[Environment]::NewLine,(New-Object Text.UTF8Encoding($false))); "
        + "$Files=[array](Get-ChildItem -LiteralPath $Root -File -Filter 'installer-*.jsonl' | Where-Object { -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) } | Sort-Object LastWriteTimeUtc -Descending); "
        + "if ($Files.Count -gt 20) { $Files | Select-Object -Skip 20 | Remove-Item -Force -ErrorAction SilentlyContinue }; "
        + "$Files=[array](Get-ChildItem -LiteralPath $Root -File -Filter 'installer-*.jsonl' | Where-Object { -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) } | Sort-Object LastWriteTimeUtc); "
        + "$Total=($Files | Measure-Object Length -Sum).Sum; "
        + "foreach ($File in $Files) { if ($Total -le 5MB) { break }; if ($File.FullName -eq $Path) { continue }; $Total-=$File.Length; Remove-Item -LiteralPath $File.FullName -Force -ErrorAction SilentlyContinue } "
        + "} catch { exit 97 } }";
    var result = installer.execute("C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
                                   ["-NoLogo", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden",
                                    "-Command", script,
                                    windowsInstallerLogSession, safePhase, safeDetail]);
    if (result.length < 2 || Number(result[1]) !== 0) {
        console.log("Windows installer journal write failed for phase " + safePhase);
    }
}

function continueWindowsUpgradeInstallation(source)
{
    if (!installer.isInstaller() || !runningOnWindows()
            || !windowsUpgradeContinuationRequested
            || windowsUpgradeNextRequested) {
        return false;
    }

    windowsUpgradeNextRequested = true;
    writeWindowsInstallerLog("continuation-next",
                             source + (gui.isButtonEnabled(buttons.NextButton)
                                       ? "-enabled" : "-disabled"));
    console.log("Continuing Windows installation after successful legacy uninstall");
    // Qt IFW invokes this callback while QWizard::restart() is entering the
    // Introduction page. Queue the click until that transition has returned.
    gui.clickButton(buttons.NextButton, 250);
    return true;
}

function commitWindowsUpgradeInstallation(source)
{
    if (!installer.isInstaller() || !runningOnWindows()
            || !windowsUpgradeContinuationRequested
            || windowsUpgradeCommitRequested) {
        return false;
    }

    windowsUpgradeCommitRequested = true;
    writeWindowsInstallerLog("continuation-commit",
                             source + (gui.isButtonEnabled(buttons.CommitButton)
                                       ? "-enabled" : "-disabled"));
    gui.clickButton(buttons.CommitButton, 250);
    return true;
}

function appName()
{
    return installer.value("Name");
}

function appExecutableFileName()
{
    if (runningOnWindows()) {
        return appName() + ".exe";
    } else {
        return appName();
    }
}

function appInstalled()
{
    if (runningOnWindows()) {
        // InstallerValue arguments can override RootDir. Never use it to select
        // an executable that this controller may launch.
        appInstalledUninstallerPath = "C:/Program Files/AmneziaVPN/maintenancetool.exe";
        appInstalledUninstallerPath_x86 = "C:/Program Files (x86)/AmneziaVPN/maintenancetool.exe";
    } else if (runningOnMacOS()){
        appInstalledUninstallerPath = "/Applications/" + appName() + ".app/maintenancetool.app/Contents/MacOS/maintenancetool";
    } else if (runningOnLinux()){
        appInstalledUninstallerPath = "/opt/" + appName() + "/maintenancetool";
    }

    return installer.fileExists(appInstalledUninstallerPath) || installer.fileExists(appInstalledUninstallerPath_x86);
}

function windowsLegacyMaintenanceToolProcessState()
{
    if (!runningOnWindows()) {
        return 0;
    }

    // Exit 1 from the unelevated maintenance-tool bootstrap is ambiguous: the
    // elevated child can still be applying undo operations. Probe executable
    // paths, not the global image name, so another product's Qt maintenance
    // tool cannot block this upgrade. Unknown probe results fail closed.
    var script = "& { param($Path64,$Path86) $ErrorActionPreference='Stop'; try { "
        + "$Expected64=[IO.Path]::GetFullPath($Path64); $Expected86=[IO.Path]::GetFullPath($Path86); "
        + "$Processes=[array](Get-Process -Name 'maintenancetool' -ErrorAction SilentlyContinue); "
        + "foreach ($Process in $Processes) { $ExecutablePath=$Process.Path; "
        + "if ([string]::IsNullOrWhiteSpace($ExecutablePath)) { exit 97 }; "
        + "$ExecutablePath=[IO.Path]::GetFullPath($ExecutablePath); "
        + "if ([string]::Equals($ExecutablePath,$Expected64,[StringComparison]::OrdinalIgnoreCase) "
        + "-or [string]::Equals($ExecutablePath,$Expected86,[StringComparison]::OrdinalIgnoreCase)) { exit 10 } }; "
        + "exit 0 } catch { exit 97 } }";
    var result = installer.execute("C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
                                   ["-NoLogo", "-NoProfile", "-NonInteractive",
                                    "-WindowStyle", "Hidden", "-Command", script,
                                    appInstalledUninstallerPath,
                                    appInstalledUninstallerPath_x86]);
    if (result.length < 2) {
        return -1;
    }
    var exitCode = Number(result[1]);
    if (exitCode === 10) {
        return 1;
    }
    return exitCode === 0 ? 0 : -1;
}

function waitForWindowsLegacyUninstaller()
{
    var removedQuiescentChecks = 0;
    var presentQuiescentChecks = 0;
    var uninstallerProcessState = -1;
    var oldInstallationPresent = true;
    var uninstallerPostcondition = "timeout-ambiguous";
    var lastLoggedWaitState = "";
    for (var i = 0; i < 1200; i++) {
        sleep(500);
        oldInstallationPresent = appInstalled();
        var waitState = "path-absent";
        if (!oldInstallationPresent) {
            // The legacy maintenance-tool path is the handoff barrier owned by
            // Qt IFW. An elevated child can make Process.Path unreadable even
            // after that path has been deleted, so an unknown process probe
            // must not keep a successfully removed installation in this
            // synchronous controller loop forever. The strict SCM and residue
            // gate below still has to pass before extraction can begin.
            removedQuiescentChecks++;
            presentQuiescentChecks = 0;
            uninstallerProcessState = -1;
        } else {
            removedQuiescentChecks = 0;
            uninstallerProcessState = windowsLegacyMaintenanceToolProcessState();
            if (uninstallerProcessState === 0) {
                presentQuiescentChecks++;
                waitState = "path-present-process-stopped";
            } else if (uninstallerProcessState === 1) {
                presentQuiescentChecks = 0;
                waitState = "path-present-process-running";
            } else {
                presentQuiescentChecks = 0;
                waitState = "path-present-process-unknown";
            }
        }
        if (waitState !== lastLoggedWaitState) {
            writeWindowsInstallerLog("legacy-uninstaller-wait", waitState);
            lastLoggedWaitState = waitState;
        }
        if (removedQuiescentChecks >= 4) {
            uninstallerPostcondition = "removed";
            break;
        }
        if (presentQuiescentChecks >= 20) {
            uninstallerPostcondition = "present-stopped";
            break;
        }
    }
    return {
        status: uninstallerPostcondition,
        processState: uninstallerProcessState,
        oldInstallationPresent: oldInstallationPresent
    };
}

function endsWith(str, suffix)
{
    return str.indexOf(suffix, str.length - suffix.length) !== -1;
}

function runningOnWindows()
{
    return (installer.value("os") === "win");
}

function runningOnMacOS()
{
    return (installer.value("os") === "mac");
}

function runningOnLinux()
{
    return ((installer.value("os") === "linux") || (installer.value("os") === "x11"));
}

function windowsServiceIsAbsent(serviceName)
{
    // This check runs in the outer offline installer before component archive
    // extraction.  ERROR_SERVICE_DOES_NOT_EXIST (1060) is the only result that
    // proves the previous kernel/service registration is gone.  Treat access
    // failures and every other result as unsafe instead of guessing.
    var systemSc = "C:/Windows/System32/sc.exe";
    var exitCode = -1;
    for (var attempt = 0; attempt < 150; ++attempt) {
        var result = installer.execute(systemSc, ["query", serviceName]);
        exitCode = Number(result[1]);
        if (exitCode === 1060) {
            return true;
        }
        // Service deletion is asynchronous. Exit 0 means SCM can still query
        // the old entry and 1072 means deletion is already pending; both may
        // become 1060 as soon as the last legacy process handle closes. Other
        // results (notably access denied) remain immediately fail-closed.
        if (exitCode !== 0 && exitCode !== 1072) {
            break;
        }
        sleep(100);
    }

    console.log("Previous Windows service cleanup is incomplete for "
                + serviceName + "; sc.exe exit code: " + exitCode);
    return false;
}

function windowsUpgradeCleanupIsComplete()
{
    var oldServiceNames = [
        "AmneziaVPN-service",
        "AmneziaVPNSplitTunnel",
        "AmneziaWGTunnel$AmneziaVPN"
    ];
    for (var index = 0; index < oldServiceNames.length; ++index) {
        if (!windowsServiceIsAbsent(oldServiceNames[index])) {
            return false;
        }
    }

    // A cleanup failure can be ignored by the legacy IFW uninstaller after it
    // writes a protected receipt.  Do not mistake that outer exit status for a
    // safe ABI transition.  Old executable/driver residues are also rejected
    // before the outer installer can create archive Extract operations.
    var forbiddenResidues = [
        "C:/Program Files/AmneziaVPN",
        "C:/Program Files/AmneziaVPN/maintenancetool.exe",
        "C:/Program Files (x86)/AmneziaVPN/maintenancetool.exe",
        "C:/Program Files/AmneziaVPN/AmneziaVPN-service.exe",
        "C:/Program Files (x86)/AmneziaVPN/AmneziaVPN-service.exe",
        "C:/Program Files (x86)/AmneziaVPN/AmneziaVPN.exe",
        "C:/Program Files/AmneziaVPN/mullvad-split-tunnel.sys",
        "C:/Program Files (x86)/AmneziaVPN/mullvad-split-tunnel.sys",
        "C:/Program Files/AmneziaVPN-Recovery/uninstall-cleanup-failed.txt",
        "C:/Program Files/AmneziaVPN-Recovery/uninstall-recovery-required.txt"
    ];
    var blockingResidue = "";
    for (var residueAttempt = 0; residueAttempt < 150; ++residueAttempt) {
        blockingResidue = "";
        for (var residueIndex = 0; residueIndex < forbiddenResidues.length; ++residueIndex) {
            if (installer.fileExists(forbiddenResidues[residueIndex])) {
                blockingResidue = forbiddenResidues[residueIndex];
                break;
            }
        }
        if (blockingResidue === "") {
            return true;
        }
        if (residueAttempt < 149) {
            sleep(100);
        }
    }
    console.log("Previous Windows cleanup residue blocks installation: "
                + blockingResidue);
    return false;
}

function ensureWindowsUpgradeAdminRights()
{
    if (installer.hasAdminRights()) {
        return true;
    }

    if (!installer.gainAdminRights() || !installer.hasAdminRights()) {
        windowsUpgradePrepareFailureReason = "administrator-approval-required";
        console.log("Unable to acquire administrator rights for the Windows service upgrade preflight");
        return false;
    }

    windowsUpgradeAdminRightsAcquired = true;
    return true;
}

function releaseWindowsUpgradeAdminRights()
{
    if (!windowsUpgradeAdminRightsAcquired) {
        return;
    }

    installer.dropAdminRights();
    windowsUpgradeAdminRightsAcquired = false;
}

function parseScOutputFields(output)
{
    var fields = {};
    var activeField = "";
    var lines = String(output || "").replace(/\r\n?/g, "\n").split("\n");
    for (var i = 0; i < lines.length; ++i) {
        var line = lines[i];
        var fieldMatch = line.match(/^\s*([^:]+?)\s*:\s*(.*)$/);
        if (fieldMatch) {
            var fieldName = fieldMatch[1].replace(/\s+/g, " ").trim().toUpperCase();
            if (Object.prototype.hasOwnProperty.call(fields, fieldName)) {
                return null;
            }
            fields[fieldName] = fieldMatch[2].trim();
            activeField = fieldName;
        } else if (activeField !== "" && line.trim() !== "") {
            fields[activeField] = fields[activeField] === ""
                ? line.trim()
                : fields[activeField] + " " + line.trim();
        }
    }
    return fields;
}

function scFieldsHaveOnly(fields, allowedFields)
{
    if (fields === null) {
        return false;
    }
    for (var fieldName in fields) {
        if (Object.prototype.hasOwnProperty.call(fields, fieldName)
                && allowedFields.indexOf(fieldName) < 0) {
            return false;
        }
    }
    return true;
}

function normalizeWindowsFailureActionsFlag(value)
{
    var normalized = String(value || "").trim().toUpperCase();
    if (normalized === "FALSE") {
        return "0";
    }
    if (normalized === "TRUE") {
        return "1";
    }
    return "";
}

function normalizeWindowsServiceImagePath(value)
{
    var imagePath = String(value || "").trim().replace(/\//g, "\\");
    if (imagePath.length >= 2 && imagePath.charAt(0) === '"'
            && imagePath.charAt(imagePath.length - 1) === '"') {
        imagePath = imagePath.substr(1, imagePath.length - 2).trim();
    }
    // The supported service has no arguments. Reject a quoted executable with
    // trailing arguments instead of trying to parse an attacker-controlled
    // command line in installer JavaScript.
    if (imagePath.indexOf('"') >= 0 || imagePath.indexOf(" ", imagePath.toLowerCase().lastIndexOf(".exe") + 4) >= 0) {
        return "";
    }
    return imagePath;
}

function windowsServiceIdentityMatches(identity, expectedStart, allowDisabled)
{
    if (identity === null || typeof identity !== "object"
            || String(identity.name || "") !== "AmneziaVPN-service"
            || Number(identity.serviceType) !== 16
            || Number(identity.errorControl) !== 1
            || (Number(identity.start) !== 2 && !(allowDisabled && Number(identity.start) === 4))
            || String(identity.startName || "") !== "LocalSystem") {
        return false;
    }
    var expectedDelayed = expectedStart === "delayed-auto" ? 1 : 0;
    if (Number(identity.delayedAutoStart) !== expectedDelayed) {
        return false;
    }
    var dependencies = String(identity.dependencies || "").split(",");
    dependencies = dependencies.filter(function(value) { return value !== ""; });
    dependencies.sort();
    if (dependencies.length !== 2 || dependencies[0].toUpperCase() !== "BFE"
            || dependencies[1].toUpperCase() !== "NSI") {
        return false;
    }
    var imagePath = normalizeWindowsServiceImagePath(identity.imagePath);
    var expected64 = "C:\\Program Files\\AmneziaVPN\\AmneziaVPN-service.exe";
    var expected86 = "C:\\Program Files (x86)\\AmneziaVPN\\AmneziaVPN-service.exe";
    return imagePath.toLowerCase() === expected64.toLowerCase()
        || imagePath.toLowerCase() === expected86.toLowerCase();
}

function windowsServiceIdentityFailureReason(identity, expectedStart, allowDisabled)
{
    if (identity === null || typeof identity !== "object") {
        return windowsMainServiceConfigSnapshotFailureReason || "identity-unavailable";
    }
    if (String(identity.name || "") !== "AmneziaVPN-service") {
        return "identity-name";
    }
    if (Number(identity.serviceType) !== 16) {
        return "identity-service-type";
    }
    if (Number(identity.errorControl) !== 1) {
        return "identity-error-control";
    }
    if (Number(identity.start) !== 2 && !(allowDisabled && Number(identity.start) === 4)) {
        return "identity-start-mode";
    }
    if (String(identity.startName || "") !== "LocalSystem") {
        return "identity-account";
    }
    if (Number(identity.delayedAutoStart) !== (expectedStart === "delayed-auto" ? 1 : 0)) {
        return "identity-delayed-auto";
    }
    var dependencies = String(identity.dependencies || "").split(",");
    dependencies = dependencies.filter(function(value) { return value !== ""; });
    dependencies.sort();
    if (dependencies.length !== 2 || dependencies[0].toUpperCase() !== "BFE"
            || dependencies[1].toUpperCase() !== "NSI") {
        return "identity-dependencies";
    }
    var imagePath = normalizeWindowsServiceImagePath(identity.imagePath);
    var expected64 = "C:\\Program Files\\AmneziaVPN\\AmneziaVPN-service.exe";
    var expected86 = "C:\\Program Files (x86)\\AmneziaVPN\\AmneziaVPN-service.exe";
    if (imagePath.toLowerCase() !== expected64.toLowerCase()
            && imagePath.toLowerCase() !== expected86.toLowerCase()) {
        return "identity-image-path";
    }
    return "identity-mismatch";
}

function queryWindowsMainServiceIdentity(serviceName)
{
    var script = "& { param($ServiceName) $ErrorActionPreference='Stop'; try { "
        + "$Service=Get-CimInstance -ClassName Win32_Service | Where-Object { $_.Name -ceq $ServiceName } | Select-Object -First 1; "
        + "if ($null -eq $Service) { exit 1060 }; "
        + "$Key='HKLM:\\SYSTEM\\CurrentControlSet\\Services\\'+$ServiceName; "
        + "$Reg=Get-ItemProperty -LiteralPath $Key; "
        + "$Deps=[array]$Reg.DependOnService; "
        + "$Record=New-Object System.Collections.Specialized.OrderedDictionary; "
        + "$Record.Add('name',[string]$Service.Name); $Record.Add('serviceType',[int]$Reg.Type); "
        + "$Record.Add('errorControl',[int]$Reg.ErrorControl); $Record.Add('start',[int]$Reg.Start); "
        + "$Record.Add('delayedAutoStart',([int]$Reg.DelayedAutoStart)); "
        + "$Record.Add('startName',[string]$Service.StartName); "
        + "$Record.Add('imagePath',[string]$Reg.ImagePath); "
        + "$Record.Add('dependencies',([string]::Join(',',($Deps | ForEach-Object { [string]$_ })))); "
        + "$Record | ConvertTo-Json -Compress; exit 0 } catch { exit 97 } }";
    var result = installer.execute("C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
                                   ["-NoLogo", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden",
                                    "-Command", script, serviceName]);
    var exitCode = result.length >= 2 ? Number(result[1]) : -1;
    if (exitCode !== 0) {
        windowsMainServiceConfigSnapshotFailureReason = "identity-query-exit-" + exitCode;
        return null;
    }
    try {
        return JSON.parse(String(result[0] || ""));
    } catch (error) {
        windowsMainServiceConfigSnapshotFailureReason = "identity-json-invalid";
        return null;
    }
}

function persistWindowsServiceUpgradeJournal(snapshot)
{
    // QIF embeds this command in Windows PowerShell 5.1.  Keep the journal
    // write compatible with its two-argument File.Move API: create the target
    // with Move when absent, and use File.Replace only after an ACL/reparse
    // check when an earlier journal exists.  There is no handle-bound rename
    // primitive exposed by IFW's JavaScript bridge, so the protected ACL gate
    // is repeated immediately before every privileged path operation.
    var script = "& { param($Path,$ServiceName,$Start,$Actions,$Flag,$FlagRaw) $ErrorActionPreference='Stop'; $Temp=''; $BackupPath=''; "
        + "$TestAcl={ param($Target,$Directory) try { $Item=Get-Item -LiteralPath $Target -Force; if ($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) { return $false }; $Acl=if ($Directory) { [IO.Directory]::GetAccessControl($Target) } else { [IO.File]::GetAccessControl($Target) }; if (-not $Acl.AreAccessRulesProtected) { return $false }; $Allowed='S-1-5-18','S-1-5-32-544','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'; $OwnerSid=(New-Object Security.Principal.NTAccount($Acl.Owner)).Translate([Security.Principal.SecurityIdentifier]).Value; if ($Allowed -notcontains $OwnerSid) { return $false }; $Dangerous=[Security.AccessControl.FileSystemRights]::WriteData -bor [Security.AccessControl.FileSystemRights]::AppendData -bor [Security.AccessControl.FileSystemRights]::CreateDirectories -bor [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor [Security.AccessControl.FileSystemRights]::WriteAttributes -bor [Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership; foreach ($Rule in $Acl.Access) { if ($Rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and ($Rule.FileSystemRights -band $Dangerous) -ne 0) { $Sid=$Rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value; if ($Allowed -notcontains $Sid) { return $false } } }; return $true } catch { return $false } }; "
        + "$Root=[IO.Path]::GetDirectoryName($Path); if (Test-Path -LiteralPath $Root) { if (-not [bool](& $TestAcl $Root $true)) { exit 92 } } else { New-Item -ItemType Directory -Path $Root | Out-Null; & 'C:\\Windows\\System32\\icacls.exe' $Root '/inheritance:r' | Out-Null; if ($LASTEXITCODE -ne 0) { exit 93 }; & 'C:\\Windows\\System32\\icacls.exe' $Root '/grant:r' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null; if ($LASTEXITCODE -ne 0 -or -not [bool](& $TestAcl $Root $true)) { exit 94 } }; "
        + "$Temp=$Path+'.tmp-'+[Guid]::NewGuid().ToString('N'); $Record=New-Object System.Collections.Specialized.OrderedDictionary; $Record.Add('schema',1); $Record.Add('serviceName',$ServiceName); $Record.Add('phase','prepared'); $Record.Add('start',$Start); $Record.Add('failureActions',$Actions); $Record.Add('failureActionsFlag',$Flag); $Record.Add('failureActionsFlagRaw',$FlagRaw); $Bytes=(New-Object Text.UTF8Encoding($false)).GetBytes($Record | ConvertTo-Json -Compress); $Stream=New-Object IO.FileStream($Temp,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None); try { $Stream.Write($Bytes,0,$Bytes.Length); $Stream.Flush($true) } finally { $Stream.Dispose() }; if (-not [bool](& $TestAcl $Temp $false)) { exit 95 }; if (Test-Path -LiteralPath $Path) { if (-not [bool](& $TestAcl $Path $false)) { exit 96 }; $BackupPath=$Path+'.bak-'+[Guid]::NewGuid().ToString('N'); [IO.File]::Replace($Temp,$Path,$BackupPath,$true); if (-not (Test-Path -LiteralPath $Path)) { exit 98 }; if (Test-Path -LiteralPath $BackupPath) { Remove-Item -LiteralPath $BackupPath -Force -ErrorAction Stop } } else { [IO.File]::Move($Temp,$Path) }; if (Test-Path -LiteralPath $Temp) { exit 98 }; if (-not [bool](& $TestAcl $Path $false)) { exit 99 }; exit 0 } catch { $CleanupOk=$true; if ($Temp -and (Test-Path -LiteralPath $Temp)) { try { Remove-Item -LiteralPath $Temp -Force -ErrorAction Stop } catch { $CleanupOk=$false } }; if ($BackupPath -and (Test-Path -LiteralPath $BackupPath)) { try { if (-not (Test-Path -LiteralPath $Path)) { [IO.File]::Move($BackupPath,$Path) } else { Remove-Item -LiteralPath $BackupPath -Force -ErrorAction Stop } } catch { $CleanupOk=$false } }; if (-not $CleanupOk) { exit 98 }; exit 97 } }";
    var result = installer.execute("C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
                                   ["-NoLogo", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden",
                                    "-Command", script, windowsServiceUpgradeJournalPath,
                                    "AmneziaVPN-service", snapshot.start, snapshot.failureActions,
                                    snapshot.failureActionsFlag, snapshot.failureActionsFlagRaw]);
    return result.length >= 2 && Number(result[1]) === 0;
}

function readWindowsServiceUpgradeJournal()
{
    if (!installer.fileExists(windowsServiceUpgradeJournalPath)) {
        return null;
    }
    var script = "& { param($Path) $ErrorActionPreference='Stop'; try { $Item=Get-Item -LiteralPath $Path -Force; $Root=Get-Item -LiteralPath ([IO.Path]::GetDirectoryName($Path)) -Force; if ($Item.PSIsContainer -or ($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or -not $Root.PSIsContainer -or ($Root.Attributes -band [IO.FileAttributes]::ReparsePoint)) { exit 91 }; $Acl=[IO.Directory]::GetAccessControl($Root.FullName); $Allowed='S-1-5-18','S-1-5-32-544','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'; $OwnerSid=(New-Object Security.Principal.NTAccount($Acl.Owner)).Translate([Security.Principal.SecurityIdentifier]).Value; if (-not $Acl.AreAccessRulesProtected -or $Allowed -notcontains $OwnerSid) { exit 92 }; $Dangerous=[Security.AccessControl.FileSystemRights]::WriteData -bor [Security.AccessControl.FileSystemRights]::AppendData -bor [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership; foreach ($Rule in $Acl.Access) { if ($Rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and ($Rule.FileSystemRights -band $Dangerous) -ne 0 -and $Allowed -notcontains $Rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value) { exit 92 } }; $FileAcl=[IO.File]::GetAccessControl($Item.FullName); if (-not $FileAcl.AreAccessRulesProtected) { exit 92 }; Get-Content -LiteralPath $Item.FullName -Raw; exit 0 } catch { exit 97 } }";
    var result = installer.execute("C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
                                   ["-NoLogo", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden",
                                    "-Command", script, windowsServiceUpgradeJournalPath]);
    if (result.length < 2 || Number(result[1]) !== 0) {
        return null;
    }
    try {
        return JSON.parse(String(result[0] || ""));
    } catch (error) {
        return null;
    }
}

function clearWindowsServiceUpgradeJournal()
{
    var script = "& { param($Path) $ErrorActionPreference='Stop'; try { if (-not (Test-Path -LiteralPath $Path)) { exit 0 }; $Item=Get-Item -LiteralPath $Path -Force; $Root=Get-Item -LiteralPath ([IO.Path]::GetDirectoryName($Path)) -Force; if ($Item.PSIsContainer -or ($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or ($Root.Attributes -band [IO.FileAttributes]::ReparsePoint)) { exit 91 }; $Acl=[IO.Directory]::GetAccessControl($Root.FullName); $Allowed='S-1-5-18','S-1-5-32-544','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'; $OwnerSid=(New-Object Security.Principal.NTAccount($Acl.Owner)).Translate([Security.Principal.SecurityIdentifier]).Value; if (-not $Acl.AreAccessRulesProtected -or $Allowed -notcontains $OwnerSid) { exit 92 }; $Dangerous=[Security.AccessControl.FileSystemRights]::WriteData -bor [Security.AccessControl.FileSystemRights]::AppendData -bor [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership; foreach ($Rule in $Acl.Access) { if ($Rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and ($Rule.FileSystemRights -band $Dangerous) -ne 0 -and $Allowed -notcontains $Rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value) { exit 92 } }; $FileAcl=[IO.File]::GetAccessControl($Item.FullName); if (-not $FileAcl.AreAccessRulesProtected) { exit 92 }; Remove-Item -LiteralPath $Item.FullName -Force; if (Test-Path -LiteralPath $Path) { exit 92 }; exit 0 } catch { exit 97 } }";
    var result = installer.execute("C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
                                   ["-NoLogo", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden",
                                    "-Command", script, windowsServiceUpgradeJournalPath]);
    return result.length >= 2 && Number(result[1]) === 0;
}

function queryWindowsMainServiceConfig(serviceName)
{
    if (!runningOnWindows()) {
        return null;
    }

    // SCM is authoritative for the service configuration. Only the exact
    // configuration emitted by the supported QIF install is round-tripped;
    // an unrecognised/custom configuration fails closed before any mutation.
    windowsMainServiceConfigSnapshotFailureReason = "";
    var systemSc = "C:/Windows/System32/sc.exe";
    var queryResult = installer.execute(systemSc, ["query", serviceName]);
    var configResult = installer.execute(systemSc, ["qc", serviceName]);
    var failureResult = installer.execute(systemSc, ["qfailure", serviceName]);
    var failureFlagResult = installer.execute(systemSc, ["qfailureflag", serviceName]);
    if (queryResult.length < 2 || Number(queryResult[1]) !== 0
            || configResult.length < 2 || Number(configResult[1]) !== 0
            || failureResult.length < 2 || Number(failureResult[1]) !== 0
            || failureFlagResult.length < 2 || Number(failureFlagResult[1]) !== 0) {
        windowsMainServiceConfigSnapshotFailureReason = "sc-query-exit-"
                + (queryResult.length < 2 ? "query" : Number(queryResult[1])) + "/"
                + (configResult.length < 2 ? "qc" : Number(configResult[1])) + "/"
                + (failureResult.length < 2 ? "qfailure" : Number(failureResult[1])) + "/"
                + (failureFlagResult.length < 2 ? "qfailureflag" : Number(failureFlagResult[1]));
        return null;
    }

    var configOutput = String(configResult[0] || "").replace(/\s+/g, " ").toUpperCase();
    // Preserve delayed automatic startup instead of silently normalizing it to
    // plain auto; every other SCM start mode is rejected before mutation.
    var startType = "";
    if (/START_TYPE\s*:\s*2\s+AUTO_START\s+\(DELAYED\)/.test(configOutput)) {
        startType = "delayed-auto";
    } else if (/START_TYPE\s*:\s*2\s+AUTO_START\b/.test(configOutput)) {
        startType = "auto";
    }
    var failureFields = parseScOutputFields(failureResult[0]);
    var failureFlagFields = parseScOutputFields(failureFlagResult[0]);
    var allowedFailureFields = [
        "SERVICE_NAME",
        "RESET_PERIOD (IN SECONDS)",
        "REBOOT_MESSAGE",
        "COMMAND_LINE",
        "FAILURE_ACTIONS"
    ];
    var allowedFailureFlagFields = ["SERVICE_NAME", "FAILURE_ACTIONS_ON_NONCRASH_FAILURES"];
    var expectedFailureActions =
        "RESTART -- DELAY = 2000 MILLISECONDS. RESTART -- DELAY = 2000 MILLISECONDS. "
        + "RESTART -- DELAY = 2000 MILLISECONDS.";
    var failureActions = failureFields === null ? ""
        : String(failureFields["FAILURE_ACTIONS"] || "")
              .replace(/\s+/g, " ").trim().toUpperCase();
    var resetPeriod = failureFields === null ? ""
        : String(failureFields["RESET_PERIOD (IN SECONDS)"] || "").trim().toUpperCase();
    var rebootMessage = failureFields === null ? "not-empty"
        : String(failureFields["REBOOT_MESSAGE"] || "");
    var commandLine = failureFields === null ? "not-empty"
        : String(failureFields["COMMAND_LINE"] || "");
    var failureActionsFlagRaw = failureFlagFields === null ? ""
        : String(failureFlagFields["FAILURE_ACTIONS_ON_NONCRASH_FAILURES"] || "").trim();
    var failureActionsFlag = normalizeWindowsFailureActionsFlag(failureActionsFlagRaw);
    var identity = queryWindowsMainServiceIdentity(serviceName);
    if (startType === ""
            || !windowsServiceIdentityMatches(identity, startType)
            || !scFieldsHaveOnly(failureFields, allowedFailureFields)
            || !scFieldsHaveOnly(failureFlagFields, allowedFailureFlagFields)
            || !Object.prototype.hasOwnProperty.call(failureFields || {}, "RESET_PERIOD (IN SECONDS)")
            || !Object.prototype.hasOwnProperty.call(failureFields || {}, "REBOOT_MESSAGE")
            || !Object.prototype.hasOwnProperty.call(failureFields || {}, "COMMAND_LINE")
            || !Object.prototype.hasOwnProperty.call(failureFields || {}, "FAILURE_ACTIONS")
            || !Object.prototype.hasOwnProperty.call(failureFlagFields || {}, "FAILURE_ACTIONS_ON_NONCRASH_FAILURES")
            || resetPeriod !== "100"
            || rebootMessage.trim() !== ""
            || commandLine.trim() !== ""
            || failureActions !== expectedFailureActions
            || failureActionsFlag === "") {
        if (windowsMainServiceConfigSnapshotFailureReason === "") {
            windowsMainServiceConfigSnapshotFailureReason = startType === ""
                    ? "unsupported-start-type"
                    : windowsServiceIdentityFailureReason(identity, startType, false);
        }
        return null;
    }

    return {
        start: startType,
        failureActions: "restart/2000/restart/2000/restart/2000",
        failureActionsFlag: failureActionsFlag,
        failureActionsFlagRaw: failureActionsFlagRaw
    };
}

function windowsMainServiceConfigMatches(left, right)
{
    return left !== null && right !== null
        && left.start === right.start
        && left.failureActions === right.failureActions
        && left.failureActionsFlag === right.failureActionsFlag
        && left.failureActionsFlagRaw === right.failureActionsFlagRaw;
}

function recoverWindowsServiceUpgradeJournalIfPresent()
{
    if (!installer.fileExists(windowsServiceUpgradeJournalPath)) {
        return true;
    }
    if (!ensureWindowsUpgradeAdminRights()) {
        return false;
    }
    var journal = readWindowsServiceUpgradeJournal();
    var expectedActions = "restart/2000/restart/2000/restart/2000";
    var expectedFlag = journal === null ? "" : normalizeWindowsFailureActionsFlag(journal.failureActionsFlagRaw);
    if (journal === null || Number(journal.schema) !== 1
            || String(journal.serviceName || "") !== "AmneziaVPN-service"
            || String(journal.phase || "") !== "prepared"
            || (journal.start !== "auto" && journal.start !== "delayed-auto")
            || String(journal.failureActions || "") !== expectedActions
            || String(journal.failureActionsFlag || "") !== expectedFlag
            || expectedFlag === "") {
        windowsUpgradePrepareFailureReason = "service-journal-invalid";
        console.log("Refusing to consume malformed protected Windows service upgrade journal");
        return false;
    }

    var systemSc = "C:/Windows/System32/sc.exe";
    var queryResult = installer.execute(systemSc, ["query", "AmneziaVPN-service"]);
    var queryExitCode = queryResult.length >= 2 ? Number(queryResult[1]) : -1;
    if (queryExitCode === 1060) {
        // The service is already gone. Clear only the journal; never recreate a
        // deleted service from stale installer state.
        var clearedMissing = clearWindowsServiceUpgradeJournal();
        if (!clearedMissing) {
            windowsUpgradePrepareFailureReason = "service-journal-clear-failed";
        }
        releaseWindowsUpgradeAdminRights();
        return clearedMissing;
    }
    if (queryExitCode !== 0) {
        windowsUpgradePrepareFailureReason = "service-journal-service-query-failed-" + queryExitCode;
        console.log("Unable to inspect the service named by the protected upgrade journal; sc.exe exit code: "
                    + queryExitCode);
        releaseWindowsUpgradeAdminRights();
        return false;
    }

    windowsMainServiceConfigSnapshot = {
        start: String(journal.start),
        failureActions: expectedActions,
        failureActionsFlag: expectedFlag,
        failureActionsFlagRaw: String(journal.failureActionsFlagRaw)
    };
    windowsMainServicePrepared = true;
    var restored = restoreWindowsMainServiceAfterAbortedUpgrade(true);
    if (!restored) {
        windowsUpgradePrepareFailureReason = "service-journal-restore-failed-"
                + (windowsMainServiceConfigSnapshotFailureReason || "unknown");
    }
    releaseWindowsUpgradeAdminRights();
    return restored;
}

function restoreWindowsMainServiceAfterAbortedUpgrade(allowMissingInstallation)
{
    if (!windowsMainServicePrepared) {
        return true;
    }
    if (windowsMainServiceConfigSnapshot === null) {
        windowsUpgradePrepareFailureReason = "service-config-snapshot-unavailable";
        return false;
    }

    var systemSc = "C:/Windows/System32/sc.exe";
    var serviceName = "AmneziaVPN-service";
    var queryResult = installer.execute(systemSc, ["query", serviceName]);
    var queryExitCode = queryResult.length >= 2 ? Number(queryResult[1]) : -1;
    if (queryExitCode === 1060) {
        // The old service was removed; there is no configuration left for the
        // cancellation path to restore. Never recreate a deleted service here.
        var clearedDeleted = clearWindowsServiceUpgradeJournal();
        windowsMainServicePrepared = false;
        windowsMainServiceConfigSnapshot = null;
        return clearedDeleted;
    }
    if (queryExitCode !== 0) {
        console.log("Unable to verify the old AmneziaVPN service before restoring its configuration; sc.exe exit code: "
                    + queryExitCode);
        return false;
    }
    var currentIdentity = queryWindowsMainServiceIdentity(serviceName);
    if (!windowsServiceIdentityMatches(currentIdentity, windowsMainServiceConfigSnapshot.start, true)) {
        windowsMainServiceConfigSnapshotFailureReason = windowsServiceIdentityFailureReason(
                currentIdentity, windowsMainServiceConfigSnapshot.start, true);
        console.log("Refusing to restore an untrusted AmneziaVPN service identity; reason: "
                    + windowsMainServiceConfigSnapshotFailureReason);
        return false;
    }
    // Never race the legacy maintenance tool. Its elevated child may still be
    // deleting the service or its files even after the bootstrap returned.
    if ((!allowMissingInstallation && !appInstalled())
            || windowsLegacyMaintenanceToolProcessState() !== 0) {
        console.log("Refusing to restore the old AmneziaVPN service while legacy cleanup is active or ambiguous");
        return false;
    }

    // sc config calls the SCM ChangeServiceConfig path; sc failure calls the
    // SCM recovery configuration path. Restore only the supported snapshot.
    var failureResult = installer.execute(
        systemSc,
        ["failure", serviceName, "reset=", "100", "actions=",
         windowsMainServiceConfigSnapshot.failureActions]);
    var failureFlagResult = installer.execute(
        systemSc,
        ["failureflag", serviceName, windowsMainServiceConfigSnapshot.failureActionsFlag]);
    var startResult = installer.execute(
        systemSc,
        ["config", serviceName, "start=", windowsMainServiceConfigSnapshot.start]);
    var failureExitCode = failureResult.length >= 2 ? Number(failureResult[1]) : -1;
    var failureFlagExitCode = failureFlagResult.length >= 2 ? Number(failureFlagResult[1]) : -1;
    var startExitCode = startResult.length >= 2 ? Number(startResult[1]) : -1;
    if (failureExitCode !== 0 || failureFlagExitCode !== 0 || startExitCode !== 0) {
        console.log("Unable to restore the previous AmneziaVPN service configuration through SCM; "
                    + "failure/failureflag/config exit codes: " + failureExitCode + "/"
                    + failureFlagExitCode + "/" + startExitCode);
        return false;
    }

    var restoredSnapshot = queryWindowsMainServiceConfig(serviceName);
    if (!windowsMainServiceConfigMatches(windowsMainServiceConfigSnapshot, restoredSnapshot)) {
        console.log("Previous AmneziaVPN service configuration did not verify after restoration");
        return false;
    }
    if (!clearWindowsServiceUpgradeJournal()) {
        console.log("Previous AmneziaVPN service was restored, but its durable upgrade journal could not be cleared");
        return false;
    }
    windowsMainServicePrepared = false;
    windowsMainServiceConfigSnapshot = null;
    return true;
}

function windowsUpgradePrepareFailureMessage()
{
    if (windowsUpgradePrepareFailureReason === "administrator-approval-required") {
        return qsTr("Administrator approval is required to prepare the existing AmneziaVPN Windows service for a safe upgrade. The upgrade did not start. Approve the Windows UAC prompt, then run this full offline installer again.");
    }
    if (windowsUpgradePrepareFailureReason === "service-deletion-pending") {
        return qsTr("The previous AmneziaVPN Windows service is still pending deletion after the bounded wait. The upgrade did not start. Restart Windows, then run this full offline installer again.");
    }
    return qsTr("The existing AmneziaVPN Windows service could not be prepared for a safe upgrade even with administrator rights. The upgrade did not start. Details: ")
        + windowsUpgradePrepareFailureReason;
}

function prepareWindowsMainServiceForUpgrade()
{
    // The full offline installer invokes the maintenance tool from the
    // currently installed package. Older uninstallers can force-terminate the
    // service while restart/2000 failure actions are still armed. Disarm that
    // recovery path in the outer, newer installer before handing control to
    // the legacy uninstaller. A fresh install restores the intended recovery
    // actions before it starts the newly registered service.
    var systemSc = "C:/Windows/System32/sc.exe";
    var serviceName = "AmneziaVPN-service";
    windowsMainServicePrepared = false;
    windowsMainServiceConfigSnapshot = null;
    windowsUpgradePrepareFailureReason = "";

    var queryResult = installer.execute(systemSc, ["query", serviceName]);
    var queryExitCode = Number(queryResult[1]);
    if (queryExitCode === 1060) {
        return true;
    }
    if (queryExitCode === 1072) {
        if (windowsServiceIsAbsent(serviceName)) {
            return true;
        }
        windowsUpgradePrepareFailureReason = "service-deletion-pending";
        return false;
    }
    if (queryExitCode !== 0) {
        windowsUpgradePrepareFailureReason = "service-query-failed-" + queryExitCode;
        console.log("Unable to query previous AmneziaVPN service; sc.exe exit code: "
                    + queryExitCode);
        return false;
    }

    // The controller runs before component operations request elevation. The
    // service DACL only grants SERVICE_CHANGE_CONFIG to administrators and
    // LocalSystem, so acquire Qt IFW's internal admin session before spawning
    // sc.exe. Keep it through the legacy uninstaller and rollback path.
    if (!ensureWindowsUpgradeAdminRights()) {
        return false;
    }

    // Re-query after the UAC round trip: another cleanup may have completed or
    // moved the registration into asynchronous deletion while consent was
    // pending.
    queryResult = installer.execute(systemSc, ["query", serviceName]);
    queryExitCode = Number(queryResult[1]);
    if (queryExitCode === 1060) {
        return true;
    }
    if (queryExitCode === 1072) {
        if (windowsServiceIsAbsent(serviceName)) {
            return true;
        }
        windowsUpgradePrepareFailureReason = "service-deletion-pending";
        return false;
    }
    if (queryExitCode !== 0) {
        windowsUpgradePrepareFailureReason = "elevated-service-query-failed-" + queryExitCode;
        console.log("Unable to query previous AmneziaVPN service after elevation; sc.exe exit code: "
                    + queryExitCode);
        return false;
    }

    windowsMainServiceConfigSnapshot = queryWindowsMainServiceConfig(serviceName);
    if (windowsMainServiceConfigSnapshot === null) {
        windowsUpgradePrepareFailureReason = "service-config-snapshot-unavailable";
        console.log("Unable to snapshot the previous AmneziaVPN service start/recovery configuration; reason: "
                    + windowsMainServiceConfigSnapshotFailureReason);
        return false;
    }
    if (!persistWindowsServiceUpgradeJournal(windowsMainServiceConfigSnapshot)) {
        windowsUpgradePrepareFailureReason = "service-journal-persist-failed";
        console.log("Unable to durably persist the previous AmneziaVPN service configuration before mutation");
        windowsMainServiceConfigSnapshot = null;
        return false;
    }
    // Set this before the first mutation so every partial failure has an
    // exact, verifiable rollback path.
    windowsMainServicePrepared = true;

    var failureResult = installer.execute(
        systemSc,
        ["failure", serviceName, "reset=", "0", "actions=", ""]);
    var failureExitCode = Number(failureResult[1]);
    if (failureExitCode !== 0) {
        var recoveryRestored = restoreWindowsMainServiceAfterAbortedUpgrade();
        windowsUpgradePrepareFailureReason = "recovery-disarm-failed-" + failureExitCode
                + (recoveryRestored ? "" : "-restore-failed");
        console.log("Unable to disarm previous AmneziaVPN service recovery; sc.exe exit code: "
                    + failureExitCode);
        return false;
    }

    var disableResult = installer.execute(
        systemSc,
        ["config", serviceName, "start=", "disabled"]);
    var disableExitCode = Number(disableResult[1]);
    if (disableExitCode !== 0) {
        var startRestored = restoreWindowsMainServiceAfterAbortedUpgrade();
        windowsUpgradePrepareFailureReason = "service-disable-failed-" + disableExitCode
                + (startRestored ? "" : "-restore-failed");
        console.log("Unable to disable previous AmneziaVPN service; sc.exe exit code: "
                    + disableExitCode);
        return false;
    }
    return true;
}

function sleep(milliseconds) {
    var currentTime = new Date().getTime();
    while (currentTime + milliseconds >= new Date().getTime()) {}
}

function raiseInstallerWindow()
{
    if (!runningOnMacOS()) {
        return;
    }

    var result = installer.execute("/bin/bash", ["-c", "ps -A | grep -m1 '" + appName() + "' | awk '{print $1}'"]);
    if (Number(result[0]) > 0) {
        var arg = 'tell application \"System Events\" ' +
                '\n      set frontmost of the first process whose unix id is ' + Number(result[0]) + ' to true ' +
                '\n      end tell' +
                '\n       ';
        installer.execute("osascript", ["-e", arg]);
    }
}

function appProcessIsRunning()
{
    if (runningOnWindows()) {
        var result = installer.execute("tasklist");
        if ( Number(result[1]) === 0 ) {
            if (result[0].indexOf(appExecutableFileName()) !== -1) {
                return true;
            }
        }
    } else {
        return checkProcessIsRunning("pgrep -x '" + appName() + "'")
    }

    return false;
}

function requestWindowsDesktopAppExit()
{
    if (!runningOnWindows() || !appProcessIsRunning()) {
        return true;
    }

    // Confirm VPN teardown through the authenticated operator endpoint before
    // asking the GUI to exit. Both supported legacy install roots are literals:
    // InstallerValue and environment overrides must not select executable code.
    var installedClientPaths = [
        "C:/Program Files/AmneziaVPN/AmneziaVPN.exe",
        "C:/Program Files (x86)/AmneziaVPN/AmneziaVPN.exe"
    ];
    var disconnectConfirmed = false;
    for (var clientIndex = 0; clientIndex < installedClientPaths.length; ++clientIndex) {
        var clientPath = installedClientPaths[clientIndex];
        if (!installer.fileExists(clientPath)) {
            continue;
        }
        var disconnectResult = installer.execute(clientPath, ["--disconnect", "--json"]);
        var disconnectReceipt = null;
        if (Number(disconnectResult[1]) === 0) {
            try {
                disconnectReceipt = JSON.parse(disconnectResult[0]);
            } catch (error) {
                console.log("AmneziaVPN disconnect returned an invalid JSON receipt");
            }
        }
        if (disconnectReceipt !== null
                && disconnectReceipt.schema === "amnezia.operator.disconnect.v1"
                && disconnectReceipt.ok === true
                && disconnectReceipt.completed === true
                && disconnectReceipt.state === "disconnected") {
            disconnectConfirmed = true;
            break;
        }
    }
    if (!disconnectConfirmed) {
        console.log("AmneziaVPN disconnect was not confirmed; refusing forced desktop shutdown");
        return false;
    }

    // taskkill without /F asks GUI processes to close and lets AmneziaVPN run
    // its ordinary application teardown after the VPN is already disconnected.
    var systemTaskkill = "C:/Windows/System32/taskkill.exe";
    console.log("Requesting graceful AmneziaVPN desktop shutdown");
    installer.execute(systemTaskkill, ["/IM", "AmneziaVPN.exe"]);
    for (var gracefulAttempt = 0; gracefulAttempt < 100; ++gracefulAttempt) {
        if (!appProcessIsRunning()) {
            return true;
        }
        sleep(100);
    }

    // A tray-only or wedged legacy client may not own a responsive top-level
    // window. Qt IFW scopes killProcess to an exact absolute executable path;
    // this fallback is allowed only after the disconnect command succeeded.
    console.log("Graceful AmneziaVPN shutdown timed out; applying exact-path fallback");
    for (var killIndex = 0; killIndex < installedClientPaths.length; ++killIndex) {
        if (installer.fileExists(installedClientPaths[killIndex])) {
            installer.killProcess(installedClientPaths[killIndex]);
        }
    }
    for (var forcedAttempt = 0; forcedAttempt < 50; ++forcedAttempt) {
        if (!appProcessIsRunning()) {
            return true;
        }
        sleep(100);
    }
    return !appProcessIsRunning();
}

function checkProcessIsRunning(arg)
{
    var cmdArgs = ["-c", arg];
    var result = installer.execute("/bin/bash", cmdArgs);
    var lines = result[0].trim().split(/\n+/);
    var resultArg1 = Number(lines[0])
    if (resultArg1 >= 2) {
        return true;
    }
    return false;
}

function requestToQuit(installer,gui)
{
    requestToQuitFromApp = true;

    installer.setDefaultPageVisible(QInstaller.IntroductionPage, false);
    installer.setDefaultPageVisible(QInstaller.TargetDirectory, false);
    installer.setDefaultPageVisible(QInstaller.ComponentSelection, false);
    installer.setDefaultPageVisible(QInstaller.LicenseCheck, false);
    installer.setDefaultPageVisible(QInstaller.StartMenuSelection, false);
    installer.setDefaultPageVisible(QInstaller.ReadyForInstallation, false);
    installer.setDefaultPageVisible(QInstaller.PerformInstallation, false);
    installer.setDefaultPageVisible(QInstaller.FinishedPage, false);

    gui.clickButton(buttons.NextButton);
    gui.clickButton(buttons.FinishButton);
    gui.clickButton(buttons.CancelButton);

    if (runningOnWindows()) {
        installer.setCancelled();
    }
}


Controller.prototype.PerformInstallationPageCallback = function()
{
    gui.clickButton(buttons.NextButton);
}

Controller.prototype.LicenseAgreementPageCallback = function()
{
    gui.clickButton(buttons.NextButton);
}

Controller.prototype.FinishedPageCallback = function ()
{
    if (desktopAppProcessRunning) {
        gui.clickButton(buttons.FinishButton);
    } else if (installer.isUpdater()) {
        installer.autoAcceptMessageBoxes();
        gui.clickButton(buttons.FinishButton);
    }
}

Controller.prototype.RestartPageCallback = function ()
{
    updaterCompleted = 1;
    gui.clickButton(buttons.FinishButton);
}

Controller.prototype.StartMenuDirectoryPageCallback = function()
{
    gui.clickButton(buttons.NextButton);
}

Controller.prototype.ComponentSelectionPageCallback = function()
{
    gui.clickButton(buttons.NextButton);
}

Controller.prototype.ReadyForInstallationPageCallback = function()
{
    if (commitWindowsUpgradeInstallation("ready-callback")) {
        return;
    }
    if (installer.isUpdater()) {
        gui.clickButton(buttons.CommitButton);
    }
}

function isSelfHostedAutomaticUpdate()
{
    // This is a UX hint supplied by the already verified self-hosted client
    // handoff. It does not bypass the Windows service, residue, ownership, or
    // artifact checks below; it only prevents the legacy replacement question
    // from turning a scheduled update into an interactive installation.
    var value = String(installer.value("AmneziaSelfHostedUpdate") || "").toLowerCase();
    return value === "true" || value === "1";
}

Controller.prototype.TargetDirectoryPageCallback = function ()
{
    var widget = gui.pageById(QInstaller.TargetDirectory);

    if (widget !== null) {
        widget.BrowseDirectoryButton.clicked.disconnect(onBrowseButtonClicked);
        widget.BrowseDirectoryButton.clicked.connect(onBrowseButtonClicked);

        gui.clickButton(buttons.NextButton);
    }
}

Controller.prototype.IntroductionPageCallback = function ()
{
    var widget = gui.currentPageWidget();
    if (installer.isUpdater() && updaterCompleted === 1) {
        gui.clickButton(buttons.FinishButton);
        gui.clickButton(buttons.CancelButton);
        return;
    }

    if (installer.isUninstaller()) {
        if (widget !== null) {
            widget.findChild("PackageManagerRadioButton").visible = false;
            widget.findChild("UpdaterRadioButton").visible = false;
        }
    }

    // A supported Windows upgrade is a full offline installer which has
    // already received explicit replacement consent and synchronously waited
    // for the legacy maintenance tool to finish. Continue that same workflow
    // instead of leaving the outer installer hidden behind the old
    // uninstaller and waiting for a second user action.
    if (continueWindowsUpgradeInstallation("introduction-callback")) {
        return;
    }

    if (installer.isUpdater()) {
        gui.clickButton(buttons.NextButton);
    }
}

onBrowseButtonClicked = function()
{
    var widget = gui.pageById(QInstaller.TargetDirectory);
    if (widget !== null) {
        if (runningOnWindows()) {
            // On Windows we are appending \<APP_NAME> if selected path don't ends with <APP_NAME>
            var targetDir = widget.TargetDirectoryLineEdit.text;
            if (! endsWith(targetDir, appName())) {
                targetDir = targetDir + "\\" + appName();
            }
            installer.setValue("TargetDir", targetDir);
            widget.TargetDirectoryLineEdit.setText(installer.value("TargetDir"));
        }
    }
}

onNextButtonClicked = function()
{
    var widget = gui.pageById(QInstaller.TargetDirectory);
    if (widget !== null) {
        installer.setValue("APP_BUNDLE_TARGET_DIR", widget.TargetDirectoryLineEdit.text);
    }
}

function Controller () {
    console.log("OS: %1, architecture: %2".arg(systemInfo.prettyProductName).arg(systemInfo.currentCpuArchitecture));

    if (runningOnWindows()) {
        if (appName() !== "AmneziaVPN") {
            throw new Error("Windows package Name must remain AmneziaVPN.");
        }
        // This package installs and starts a LocalSystem service. Qt IFW lets
        // callers replace predefined values on the command line, so do not
        // derive this security-sensitive path from ApplicationsDirX64,
        // RootDir, TargetDir, Name, or the process environment.
        installer.setValue("TargetDir", "C:\\Program Files\\AmneziaVPN");
    }

    // Qt IFW executes archive extraction before ordinary component Execute
    // operations.  A maintenance-tool update could therefore replace the
    // userspace service while the old split-tunnel driver ABI is still loaded.
    // The self-hosted client launches this full offline installer, whose
    // installer path removes the old installation first; keep the unsafe
    // maintenance-tool path fail-closed.
    if (runningOnWindows() && installer.isUpdater()) {
        QMessageBox.critical(
            "windows.driver.update.unsupported",
            appName(),
            qsTr("The Windows maintenance-tool updater cannot safely replace the split-tunnel driver. Download and run the full offline AmneziaVPN installer instead."));
        installer.setCancelled();
        return;
    }

    if (installer.isInstaller() || installer.isUpdater()) {
        console.log("Check if app already installed: " + appInstalled());
    }

    if (runningOnWindows()) {
        installer.setValue("AllUsers", "true");
    }

    if (runningOnWindows() && installer.isInstaller()
            && !recoverWindowsServiceUpgradeJournalIfPresent()) {
        writeWindowsInstallerLog("service-journal-recovery", windowsUpgradePrepareFailureReason);
        releaseWindowsUpgradeAdminRights();
        QMessageBox.critical(
            "windows.service.upgrade.journal.recovery.failed",
            appName(),
            qsTr("A previous AmneziaVPN Windows service upgrade did not complete safely. The installer stopped before changing files or services. Resolve the protected recovery state, then run this full offline installer again."));
        installer.setCancelled();
        return;
    }

    if (installer.isInstaller()) {
        if (runningOnWindows()) {
            writeWindowsInstallerLog("installer-start", "installer");
            installer.installationStarted.connect(function() {
                writeWindowsInstallerLog("installation-started", "1");
            });
            installer.installationFinished.connect(function() {
                writeWindowsInstallerLog("installation-finished", "1");
            });
            installer.installationInterrupted.connect(function() {
                writeWindowsInstallerLog("installation-interrupted", "1");
                if (runningOnWindows() && windowsMainServicePrepared) {
                    var restored = restoreWindowsMainServiceAfterAbortedUpgrade();
                    writeWindowsInstallerLog("service-preflight-restore",
                                             restored ? "complete" : "failed");
                }
            });
        }
        installer.setDefaultPageVisible(QInstaller.ComponentSelection, false);
        installer.setDefaultPageVisible(QInstaller.TargetDirectory, false);
        installer.setDefaultPageVisible(QInstaller.StartMenuDirectoryPage, false);
        installer.setDefaultPageVisible(QInstaller.LicenseCheck, false);

        if (runningOnMacOS()) {
            installer.setMessageBoxAutomaticAnswer("OverwriteTargetDirectory", QMessageBox.Yes);
        }

        if (appInstalled()) {
            writeWindowsInstallerLog("existing-install-detected", "1");
            // The verified self-hosted handoff suppresses only this legacy
            // replacement question. It never suppresses per-machine UAC or
            // the bounded service/process shutdown checks below.
            var automaticReplacement = isSelfHostedAutomaticUpdate();
            var replacementAccepted = automaticReplacement
                    || QMessageBox.Ok === QMessageBox.information("os.information", appName(),
                                                                   qsTr("The application is already installed.") + " " +
                                                                   qsTr("We need to remove the old installation first. Do you wish to proceed?"),
                                                                   QMessageBox.Ok | QMessageBox.Cancel);
            if (replacementAccepted) {

                if (runningOnWindows()) {
                    windowsUpgradeReplacementRequested = true;
                    writeWindowsInstallerLog("replacement-consent",
                                             automaticReplacement ? "automatic" : "accepted");
                }

                // The user has consented to replace the existing installation.
                // Only now may Windows disconnect and close the running client.
                isDesktopAppProcessRunningMessageLoop();
                if (requestToQuitFromApp === true) {
                    requestToQuit(installer, gui);
                    return;
                }

                if (appInstalled()) {
                    if (runningOnWindows() && !prepareWindowsMainServiceForUpgrade()) {
                        writeWindowsInstallerLog("service-preflight", windowsUpgradePrepareFailureReason);
                        releaseWindowsUpgradeAdminRights();
                        QMessageBox.critical(
                            "windows.service.upgrade.prepare.failed",
                            appName(),
                            windowsUpgradePrepareFailureMessage());
                        installer.setCancelled();
                        return;
                    }
                    if (runningOnWindows()) {
                        writeWindowsInstallerLog("service-preflight", "complete");
                    }
                    var installedUninstallers = [
                        appInstalledUninstallerPath_x86,
                        appInstalledUninstallerPath
                    ];
                    var availableUninstallers = [];
                    for (var uninstallerIndex = 0; uninstallerIndex < installedUninstallers.length;
                            ++uninstallerIndex) {
                        if (installer.fileExists(installedUninstallers[uninstallerIndex])) {
                            availableUninstallers.push(installedUninstallers[uninstallerIndex]);
                        }
                    }
                    if (availableUninstallers.length > 1) {
                        writeWindowsInstallerLog("legacy-uninstaller-selection", "multiple");
                        var duplicateProcessState = windowsLegacyMaintenanceToolProcessState();
                        if (windowsMainServicePrepared && duplicateProcessState === 0
                                && !restoreWindowsMainServiceAfterAbortedUpgrade()) {
                            QMessageBox.warning(
                                "windows.service.upgrade.restore.failed",
                                appName(),
                                qsTr("The previous AmneziaVPN installation remains, but its Windows service settings could not be fully restored. Restart Windows before using or upgrading it."));
                        }
                        releaseWindowsUpgradeAdminRights();
                        QMessageBox.critical(
                            "windows.upgrade.multiple.installations",
                            appName(),
                            qsTr("More than one previous AmneziaVPN maintenance tool was found. The upgrade did not start because running two uninstallers would be unsafe. Restart Windows, remove the duplicate installation, then run this full offline installer again."));
                        installer.setCancelled();
                        return;
                    }
                    if (availableUninstallers.length === 1) {
                        var uninstallerPath = availableUninstallers[0];
                        console.log("Starting uninstallation " + uninstallerPath);
                        writeWindowsInstallerLog("legacy-uninstaller-start", "1");
                        var resultArray = installer.execute(uninstallerPath);
                        var uninstallerExitCode = resultArray.length >= 2
                                ? Number(resultArray[1]) : -1;
                        console.log("Uninstaller bootstrap finished with code: " + uninstallerExitCode);
                        writeWindowsInstallerLog("legacy-uninstaller-exit", String(uninstallerExitCode));
                    }

                    // A legacy maintenance tool may return from its unelevated
                    // bootstrap process with code 1 while the elevated child is
                    // still removing files and services. The process exit code
                    // is therefore diagnostic only. Decide success from the
                    // bounded postcondition below. The legacy cleanup script
                    // has a multi-minute retry budget, so allow ten minutes.
                    // A genuine cancellation is recognized only after both the
                    // installed path and process state have remained quiescent;
                    // an active/unknown timeout must never re-arm the service.
                    var uninstallerOutcome = waitForWindowsLegacyUninstaller();
                    var uninstallerPostcondition = uninstallerOutcome.status;
                    if (uninstallerPostcondition !== "removed") {
                        writeWindowsInstallerLog("legacy-uninstaller-postcondition",
                                                 uninstallerPostcondition === "present-stopped"
                                                 ? "present-stopped" : "timeout-active");
                        console.log("Legacy uninstallation did not reach a verified quiescent removal state");
                        // Re-probe immediately before restoration. The
                        // synchronous journal write above must not leave a
                        // stale window in which a delayed elevated child can
                        // appear after the cached polling result.
                        var freshOldInstallationPresent = appInstalled();
                        var freshUninstallerProcessState = windowsLegacyMaintenanceToolProcessState();
                        var safeToRestoreOldService = uninstallerPostcondition === "present-stopped"
                                && freshUninstallerProcessState === 0
                                && freshOldInstallationPresent;
                        if (windowsMainServicePrepared && safeToRestoreOldService
                                && !restoreWindowsMainServiceAfterAbortedUpgrade()) {
                            QMessageBox.warning(
                                "windows.service.upgrade.restore.failed",
                                appName(),
                                qsTr("The previous AmneziaVPN installation remains, but its Windows service settings could not be fully restored. Restart Windows before using or upgrading it."));
                        }
                        releaseWindowsUpgradeAdminRights();
                        if (!safeToRestoreOldService) {
                            QMessageBox.critical(
                                "windows.upgrade.uninstaller.still.running",
                                appName(),
                                qsTr("The previous AmneziaVPN uninstaller is still active or could not be verified after the bounded wait. The old Windows service was left disabled to avoid racing the cleanup. Wait for removal to finish or restart Windows, then run this full offline installer again."));
                        }
                        installer.setCancelled();
                        return;
                    }
                    writeWindowsInstallerLog("legacy-uninstaller-postcondition", "removed");
                }

                raiseInstallerWindow();

            } else {
                console.log("Request to quit from user");
                installer.setCancelled();
                return;
            }
        }

        // The old uninstaller performs bounded cleanup and deletes the
        // split-tunnel kernel service.  Verify the SCM result before IFW can
        // extract the new driver.  This also rejects stale service remnants on
        // machines where the maintenance tool is already missing.
        if (runningOnWindows() && !windowsUpgradeCleanupIsComplete()) {
            writeWindowsInstallerLog("cleanup-verdict", "blocked");
            if (windowsMainServicePrepared) {
                var cleanupRestore = restoreWindowsMainServiceAfterAbortedUpgrade();
                writeWindowsInstallerLog("service-preflight-restore",
                                         cleanupRestore ? "complete" : "failed");
            }
            releaseWindowsUpgradeAdminRights();
            QMessageBox.critical(
                "windows.driver.cleanup.incomplete",
                appName(),
                qsTr("The previous AmneziaVPN Windows services were not fully removed. Restart Windows, then run the full offline installer again. No new files were installed."));
            installer.setCancelled();
            return;
        }
        if (runningOnWindows()) {
            writeWindowsInstallerLog("cleanup-verdict", "complete");
            if (!clearWindowsServiceUpgradeJournal()) {
                writeWindowsInstallerLog("service-journal-clear", "failed");
                releaseWindowsUpgradeAdminRights();
                QMessageBox.critical(
                    "windows.service.upgrade.journal.clear.failed",
                    appName(),
                    qsTr("The previous AmneziaVPN Windows service was removed, but its protected upgrade journal could not be cleared. No new files were installed. Run this full offline installer again after resolving the protected recovery state."));
                installer.setCancelled();
                return;
            }
            // The old service is now proven absent. Do not retain its snapshot
            // into the new product installation, where an interrupted later
            // operation must never overwrite the new service configuration.
            windowsMainServicePrepared = false;
            windowsMainServiceConfigSnapshot = null;
            releaseWindowsUpgradeAdminRights();
            if (windowsUpgradeReplacementRequested) {
                windowsUpgradeContinuationRequested = true;
                // IntroductionPageCallback owns the delayed Next click after
                // QWizard::restart() has entered a live, enabled page. Calling
                // it here would latch a request against a pre-restart button
                // and prevent the callback from retrying.
            }
        }

    } else if (installer.isUninstaller()) {
        // Qt IFW 4.7 exposes Retry and Ignore for a failed UNDOEXECUTE
        // operation; it cannot honor Cancel for this dialog. post_uninstall.cmd
        // owns the retry budget and saves a durable recovery bundle plus a
        // receipt before returning a failure. Choosing Ignore after that
        // bounded work prevents IFW itself from getting stuck forever.
        installer.setMessageBoxAutomaticAnswer("installationErrorWithIgnore", QMessageBox.Ignore);

        isDesktopAppProcessRunningMessageLoop();

        if (requestToQuitFromApp === true) {
            requestToQuit(installer, gui);
            return;
        }

    } else if (installer.isUpdater()) {
        installer.setMessageBoxAutomaticAnswer("cancelInstallation", QMessageBox.No);
        installer.installationFinished.connect(function() {
            gui.clickButton(buttons.NextButton);
        });
    }
}

isDesktopAppProcessRunningMessageLoop = function ()
{
    if (requestToQuitFromApp === true) {
        return;
    }

    if (installer.isUpdater()) {
        for (var i = 0; i < 400; i++) {
            desktopAppProcessRunning = appProcessIsRunning();
            if (!desktopAppProcessRunning) {
                break;
            }
        }
    }
    desktopAppProcessRunning = appProcessIsRunning();

    if (desktopAppProcessRunning && runningOnWindows()) {
        requestWindowsDesktopAppExit();
        desktopAppProcessRunning = appProcessIsRunning();
    }

    if (desktopAppProcessRunning) {
        if (isSelfHostedAutomaticUpdate()) {
            console.log("AmneziaVPN could not be closed automatically during a self-hosted update; cancelling without user interaction");
            installer.setCancelled();
            return;
        }
        var result = QMessageBox.warning("QMessageBox", appName() + " installer",
                                         appName() + " could not be closed automatically. Close the app and press \"Retry\" button to continue installation. Press \"Abort\" button to abort the installer and exit.",
                                         QMessageBox.Retry | QMessageBox.Abort);
        if (result === QMessageBox.Retry) {
            isDesktopAppProcessRunningMessageLoop();
        } else {
            requestToQuitFromApp = true;
            return;
        }
    }
}
