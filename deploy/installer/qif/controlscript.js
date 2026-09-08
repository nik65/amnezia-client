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

function isStrictWindowsServiceNumber(value)
{
    return typeof value === "number" && isFinite(value) && Math.floor(value) === value;
}

function windowsServiceIdentityMatches(identity, expectedStart, allowDisabled)
{
    if (identity === null || typeof identity !== "object"
            || (expectedStart !== "auto" && expectedStart !== "delayed-auto")
            || !isStrictWindowsServiceNumber(identity.serviceType)
            || !isStrictWindowsServiceNumber(identity.errorControl)
            || !isStrictWindowsServiceNumber(identity.start)
            || !isStrictWindowsServiceNumber(identity.delayedAutoStart)
            || String(identity.name || "") !== "AmneziaVPN-service"
            || identity.serviceType !== 16
            || identity.errorControl !== 1
            || (identity.start !== 2 && !(allowDisabled === true && identity.start === 4))
            || String(identity.startName || "") !== "LocalSystem") {
        return false;
    }
    var expectedDelayed = expectedStart === "delayed-auto" ? 1 : 0;
    if (identity.delayedAutoStart !== expectedDelayed) {
        return false;
    }
    if (typeof identity.dependencies !== "string") {
        return false;
    }
    var dependencies = identity.dependencies.split(",");
    if (dependencies.length !== 2 || dependencies[0] === "" || dependencies[1] === "") {
        return false;
    }
    dependencies = dependencies.map(function(value) { return value.toUpperCase(); });
    dependencies.sort();
    if (dependencies[0] !== "BFE" || dependencies[1] !== "NSI") {
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
    if (expectedStart !== "auto" && expectedStart !== "delayed-auto") {
        return "identity-expected-start";
    }
    if (String(identity.name || "") !== "AmneziaVPN-service") {
        return "identity-name";
    }
    if (!isStrictWindowsServiceNumber(identity.serviceType) || identity.serviceType !== 16) {
        return "identity-service-type";
    }
    if (!isStrictWindowsServiceNumber(identity.errorControl) || identity.errorControl !== 1) {
        return "identity-error-control";
    }
    if (!isStrictWindowsServiceNumber(identity.start)
            || (identity.start !== 2 && !(allowDisabled === true && identity.start === 4))) {
        return "identity-start-mode";
    }
    if (String(identity.startName || "") !== "LocalSystem") {
        return "identity-account";
    }
    if (!isStrictWindowsServiceNumber(identity.delayedAutoStart)
            || identity.delayedAutoStart !== (expectedStart === "delayed-auto" ? 1 : 0)) {
        return "identity-delayed-auto";
    }
    if (typeof identity.dependencies !== "string") {
        return "identity-dependencies";
    }
    var dependencies = identity.dependencies.split(",");
    if (dependencies.length !== 2 || dependencies[0] === "" || dependencies[1] === "") {
        return "identity-dependencies";
    }
    dependencies = dependencies.map(function(value) { return value.toUpperCase(); });
    dependencies.sort();
    if (dependencies[0] !== "BFE" || dependencies[1] !== "NSI") {
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

function queryWindowsMainServiceSnapshot(serviceName)
{
    // The payload is a compressed, source-embedded C# helper. Keeping the
    // helper here makes it available before extraction and avoids localized
    // `sc` text as well as separate CIM/registry/recovery races.
    var sourceGzipBase64 = "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";
    var script = "& { param($ServiceName) $ErrorActionPreference='Stop'; try { "
        + "$Bytes=[Convert]::FromBase64String('" + sourceGzipBase64 + "'); "
        + "$SnapshotInput=New-Object IO.MemoryStream(,$Bytes); $SnapshotGzip=New-Object IO.Compression.GzipStream($SnapshotInput,[IO.Compression.CompressionMode]::Decompress); "
        + "$SnapshotReader=New-Object IO.StreamReader($SnapshotGzip); $Source=$SnapshotReader.ReadToEnd(); $SnapshotReader.Dispose(); $SnapshotInput.Dispose(); "
        + "Add-Type -TypeDefinition $Source -Language CSharp; "
        + "[AmneziaServiceSnapshotNative]::Read($ServiceName) | ConvertTo-Json -Compress -Depth 8; exit 0 } catch { "
        + "$Code=97; if ($_.Exception -is [ComponentModel.Win32Exception]) { $Code=$_.Exception.NativeErrorCode }; "
        + "if ($Code -lt 1 -or $Code -gt 16384) { $Code=97 }; exit $Code } }";
    var result = installer.execute("C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
                                   ["-NoLogo", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden",
                                    "-Command", script, serviceName]);
    var exitCode = result.length >= 2 ? Number(result[1]) : -1;
    if (exitCode !== 0) {
        windowsMainServiceConfigSnapshotFailureReason = "identity-query-exit-" + exitCode;
        return null;
    }
    try {
        var snapshot = JSON.parse(String(result[0] || ""));
        if (snapshot === null || typeof snapshot !== "object" || Array.isArray(snapshot)) {
            windowsMainServiceConfigSnapshotFailureReason = "identity-json-invalid";
            return null;
        }
        return snapshot;
    } catch (error) {
        windowsMainServiceConfigSnapshotFailureReason = "identity-json-invalid";
        return null;
    }
}

function queryWindowsMainServiceIdentity(serviceName)
{
    var snapshot = queryWindowsMainServiceSnapshot(serviceName);
    if (snapshot === null) {
        return null;
    }
    return {
        name: snapshot.name,
        serviceType: snapshot.serviceType,
        errorControl: snapshot.errorControl,
        start: snapshot.start,
        delayedAutoStart: snapshot.delayedAutoStart,
        startName: snapshot.startName,
        imagePath: snapshot.imagePath,
        dependencies: snapshot.dependencies
    };
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

    // SCM is authoritative for the service configuration. The single native
    // helper returns identity and recovery data from QueryServiceConfig*;
    // no localized command output is parsed here.
    windowsMainServiceConfigSnapshotFailureReason = "";
    var snapshot = queryWindowsMainServiceSnapshot(serviceName);
    if (snapshot === null) {
        return null;
    }

    var identity = snapshot;
    // SCM start and delayed-auto fields are numeric values emitted by the
    // structured identity query. Reject every other representation and every
    // SCM start mode before accepting recovery settings.
    if (!isStrictWindowsServiceNumber(identity.start)) {
        windowsMainServiceConfigSnapshotFailureReason = windowsServiceIdentityFailureReason(
                identity, "auto", false);
        return null;
    }
    if (identity.start !== 2) {
        windowsMainServiceConfigSnapshotFailureReason = "unsupported-start-type";
        return null;
    }
    if (!isStrictWindowsServiceNumber(identity.delayedAutoStart)
            || (identity.delayedAutoStart !== 0 && identity.delayedAutoStart !== 1)) {
        windowsMainServiceConfigSnapshotFailureReason = "identity-delayed-auto";
        return null;
    }
    var startType = identity.delayedAutoStart === 1 ? "delayed-auto" : "auto";
    if (!windowsServiceIdentityMatches(identity, startType)) {
        windowsMainServiceConfigSnapshotFailureReason = windowsServiceIdentityFailureReason(
                identity, startType, false);
        return null;
    }
    var expectedFailureActions = "restart/2000/restart/2000/restart/2000";
    if (!isStrictWindowsServiceNumber(snapshot.failureResetPeriod)
            || snapshot.failureResetPeriod !== 100) {
        windowsMainServiceConfigSnapshotFailureReason = "failure-reset-period";
        return null;
    }
    if (!isStrictWindowsServiceNumber(snapshot.failureActionCount)
            || snapshot.failureActionCount !== 3
            || typeof snapshot.failureActionTypes !== "string"
            || snapshot.failureActionTypes !== "1/1/1"
            || typeof snapshot.failureActionDelays !== "string"
            || snapshot.failureActionDelays !== "2000/2000/2000") {
        windowsMainServiceConfigSnapshotFailureReason = "failure-actions";
        return null;
    }
    if (typeof snapshot.rebootMessage !== "string"
            || snapshot.rebootMessage.trim() !== "") {
        windowsMainServiceConfigSnapshotFailureReason = "failure-reboot-message";
        return null;
    }
    if (typeof snapshot.commandLine !== "string"
            || snapshot.commandLine.trim() !== "") {
        windowsMainServiceConfigSnapshotFailureReason = "failure-command-line";
        return null;
    }
    if (typeof snapshot.failureActions !== "string"
            || snapshot.failureActions !== expectedFailureActions) {
        windowsMainServiceConfigSnapshotFailureReason = "failure-actions";
        return null;
    }
    if (!isStrictWindowsServiceNumber(snapshot.failureActionsFlag)
            || (snapshot.failureActionsFlag !== 0 && snapshot.failureActionsFlag !== 1)
            || typeof snapshot.failureActionsFlagRaw !== "string"
            || snapshot.failureActionsFlagRaw !== (snapshot.failureActionsFlag === 1 ? "TRUE" : "FALSE")) {
        windowsMainServiceConfigSnapshotFailureReason = "failure-flag-value";
        return null;
    }

    return {
        start: startType,
        failureActions: snapshot.failureActions,
        failureActionsFlag: snapshot.failureActionsFlag === 1 ? "1" : "0",
        failureActionsFlagRaw: snapshot.failureActionsFlagRaw
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

function windowsServiceConfigSnapshotFailureDetail()
{
    var detail = String(windowsMainServiceConfigSnapshotFailureReason || "unknown");
    return /^[A-Za-z0-9][A-Za-z0-9._:-]{0,95}$/.test(detail) ? detail : "unknown";
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
                + windowsServiceConfigSnapshotFailureDetail();
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
                    + windowsServiceConfigSnapshotFailureDetail());
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
    if (windowsUpgradePrepareFailureReason === "service-config-snapshot-unavailable") {
        return qsTr("The existing AmneziaVPN Windows service could not be prepared for a safe upgrade even with administrator rights. The upgrade did not start. Details: ")
            + windowsServiceConfigSnapshotFailureDetail();
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
                    + windowsServiceConfigSnapshotFailureDetail());
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
