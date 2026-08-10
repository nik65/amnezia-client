var requestToQuitFromApp = false;
var updaterCompleted = 0;
var desktopAppProcessRunning = false;
var appInstalledUninstallerPath;
var appInstalledUninstallerPath_x86;
var windowsMainServicePrepared = false;
var windowsUpgradeAdminRightsAcquired = false;
var windowsUpgradePrepareFailureReason = "";
var windowsUpgradeReplacementRequested = false;
var windowsUpgradeContinuationRequested = false;
var windowsUpgradeNextRequested = false;
var windowsUpgradeCommitRequested = false;
var windowsInstallerLogSession = "installer-" + new Date().getTime();

function writeWindowsInstallerLog(phase, detail)
{
    if (!runningOnWindows()) {
        return;
    }

    // Keep this diagnostic in a protected sibling of TargetDir: the legacy
    // uninstaller intentionally removes the application and its log directory. The
    // arguments are reduced to a fixed phase plus a short sanitized value;
    // command output, configuration, addresses and credentials never enter
    // this journal. Logging is best-effort and must never affect installation.
    var safePhase = String(phase).replace(/[^A-Za-z0-9._-]/g, "-").substr(0, 64);
    var safeDetail = String(detail || "").replace(/[^A-Za-z0-9._:-]/g, "-").substr(0, 160);
    var script = "& { param($Root,$Session,$Phase,$Detail) "
        + "$ErrorActionPreference='Stop'; try { "
        + "if (Test-Path -LiteralPath $Root) { $RootItem=Get-Item -LiteralPath $Root -Force; if (-not $RootItem.PSIsContainer -or ($RootItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) { return } } "
        + "else { New-Item -ItemType Directory -Path $Root | Out-Null }; "
        + "& 'C:/Windows/System32/icacls.exe' $Root '/inheritance:r' '/grant:r' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null; if ($LASTEXITCODE -ne 0) { return }; "
        + "$Path=Join-Path $Root ($Session+'.jsonl'); "
        + "$Files=@(Get-ChildItem -LiteralPath $Root -File -Filter 'installer-*.jsonl' | Where-Object { -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) } | Sort-Object LastWriteTimeUtc -Descending); "
        + "$Files | Where-Object LastWriteTimeUtc -lt ([DateTime]::UtcNow.AddDays(-14)) | Remove-Item -Force -ErrorAction SilentlyContinue; "
        + "if ((Test-Path -LiteralPath $Path) -and (Get-Item -LiteralPath $Path).Length -ge 256KB) { return }; "
        + "$Line=[ordered]@{schema=1;utc=[DateTime]::UtcNow.ToString('o');phase=$Phase;detail=$Detail} | ConvertTo-Json -Compress; "
        + "Add-Content -LiteralPath $Path -Value $Line -Encoding UTF8; "
        + "$Files=@(Get-ChildItem -LiteralPath $Root -File -Filter 'installer-*.jsonl' | Where-Object { -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) } | Sort-Object LastWriteTimeUtc -Descending); "
        + "if ($Files.Count -gt 20) { $Files | Select-Object -Skip 20 | Remove-Item -Force -ErrorAction SilentlyContinue }; "
        + "$Files=@(Get-ChildItem -LiteralPath $Root -File -Filter 'installer-*.jsonl' | Where-Object { -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) } | Sort-Object LastWriteTimeUtc); "
        + "$Total=($Files | Measure-Object Length -Sum).Sum; "
        + "foreach ($File in $Files) { if ($Total -le 5MB) { break }; if ($File.FullName -eq $Path) { continue }; $Total-=$File.Length; Remove-Item -LiteralPath $File.FullName -Force -ErrorAction SilentlyContinue } "
        + "} catch { } }";
    installer.execute("C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
                      ["-NoLogo", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden",
                       "-Command", script,
                       "C:/Program Files/AmneziaVPN-InstallerLogs",
                       windowsInstallerLogSession, safePhase, safeDetail]);
}

function continueWindowsUpgradeInstallation(source)
{
    if (!installer.isInstaller() || !runningOnWindows()
            || !windowsUpgradeContinuationRequested
            || windowsUpgradeNextRequested) {
        return false;
    }

    windowsUpgradeNextRequested = true;
    writeWindowsInstallerLog("continuation-next", source);
    console.log("Continuing Windows installation after successful legacy uninstall");
    gui.clickButton(buttons.NextButton);
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
    writeWindowsInstallerLog("continuation-commit", source);
    gui.clickButton(buttons.CommitButton);
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
        "C:/Program Files/AmneziaVPN/mullvad-split-tunnel.sys",
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

    var failureResult = installer.execute(
        systemSc,
        ["failure", serviceName, "reset=", "0", "actions=", ""]);
    var failureExitCode = Number(failureResult[1]);
    if (failureExitCode !== 0) {
        windowsUpgradePrepareFailureReason = "recovery-disarm-failed-" + failureExitCode;
        console.log("Unable to disarm previous AmneziaVPN service recovery; sc.exe exit code: "
                    + failureExitCode);
        return false;
    }
    windowsMainServicePrepared = true;

    var disableResult = installer.execute(
        systemSc,
        ["config", serviceName, "start=", "disabled"]);
    var disableExitCode = Number(disableResult[1]);
    if (disableExitCode !== 0) {
        windowsUpgradePrepareFailureReason = "service-disable-failed-" + disableExitCode;
        console.log("Unable to disable previous AmneziaVPN service; sc.exe exit code: "
                    + disableExitCode);
        restoreWindowsMainServiceAfterAbortedUpgrade();
        return false;
    }
    return true;
}

function restoreWindowsMainServiceAfterAbortedUpgrade()
{
    // If the legacy maintenance tool is cancelled or fails before removing
    // the installed product, undo the outer preflight. Do not leave an
    // otherwise usable installation without automatic startup or recovery.
    var systemSc = "C:/Windows/System32/sc.exe";
    var serviceName = "AmneziaVPN-service";
    var failureResult = installer.execute(
        systemSc,
        ["failure", serviceName, "reset=", "100", "actions=",
         "restart/2000/restart/2000/restart/2000"]);
    var failureExitCode = Number(failureResult[1]);

    var startResult = installer.execute(
        systemSc,
        ["config", serviceName, "start=", "auto"]);
    var startExitCode = Number(startResult[1]);

    if (failureExitCode !== 0 || startExitCode !== 0) {
        console.log("Unable to restore the previous AmneziaVPN service after an aborted upgrade; "
                    + "failure/config exit codes: " + failureExitCode + "/" + startExitCode);
        return false;
    }
    windowsMainServicePrepared = false;
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
            if (QMessageBox.Ok === QMessageBox.information("os.information", appName(),
                                                           qsTr("The application is already installed.") + " " +
                                                           qsTr("We need to remove the old installation first. Do you wish to proceed?"),
                                                           QMessageBox.Ok | QMessageBox.Cancel)) {

                if (runningOnWindows()) {
                    windowsUpgradeReplacementRequested = true;
                    writeWindowsInstallerLog("replacement-consent", "accepted");
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
                    for (var uninstallerIndex = 0;
                            uninstallerIndex < installedUninstallers.length;
                            ++uninstallerIndex) {
                        var uninstallerPath = installedUninstallers[uninstallerIndex];
                        if (!installer.fileExists(uninstallerPath)) {
                            continue;
                        }
                        console.log("Starting uninstallation " + uninstallerPath);
                        writeWindowsInstallerLog("legacy-uninstaller-start", "1");
                        var resultArray = installer.execute(uninstallerPath);
                        console.log("Uninstaller finished with code: " + resultArray[1]);
                        writeWindowsInstallerLog("legacy-uninstaller-exit", String(Number(resultArray[1])));
                        if (Number(resultArray[1]) !== 0) {
                            console.log("Uninstallation aborted by user");
                            if (runningOnWindows() && windowsMainServicePrepared
                                    && appInstalled()
                                    && !restoreWindowsMainServiceAfterAbortedUpgrade()) {
                                QMessageBox.warning(
                                    "windows.service.upgrade.restore.failed",
                                    appName(),
                                    qsTr("The previous AmneziaVPN installation remains, but its Windows service settings could not be fully restored. Restart Windows before using or upgrading it."));
                            }
                            releaseWindowsUpgradeAdminRights();
                            installer.setCancelled();
                            return;
                        }
                    }

                    for (var i = 0; i < 300; i++) {
                        sleep(100);
                        if (!installer.fileExists(appInstalledUninstallerPath)
                                && !installer.fileExists(appInstalledUninstallerPath_x86)) {
                            break;
                        }
                    }
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
            releaseWindowsUpgradeAdminRights();
            if (windowsUpgradeReplacementRequested) {
                windowsUpgradeContinuationRequested = true;
                // Drive the transition from the same successful branch.  The
                // page callback remains an idempotent fallback, but no longer
                // owns the only handoff after the nested maintenance tool.
                continueWindowsUpgradeInstallation("cleanup-success");
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
