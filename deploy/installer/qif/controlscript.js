var requestToQuitFromApp = false;
var updaterCompleted = 0;
var desktopAppProcessRunning = false;
var appInstalledUninstallerPath;
var appInstalledUninstallerPath_x86;
var windowsMainServicePrepared = false;

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
    for (var residueIndex = 0; residueIndex < forbiddenResidues.length; ++residueIndex) {
        if (installer.fileExists(forbiddenResidues[residueIndex])) {
            console.log("Previous Windows cleanup residue blocks installation: "
                        + forbiddenResidues[residueIndex]);
            return false;
        }
    }
    return true;
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

    var queryResult = installer.execute(systemSc, ["query", serviceName]);
    var queryExitCode = Number(queryResult[1]);
    if (queryExitCode === 1060) {
        return true;
    }
    if (queryExitCode !== 0) {
        console.log("Unable to query previous AmneziaVPN service; sc.exe exit code: "
                    + queryExitCode);
        return false;
    }

    var failureResult = installer.execute(
        systemSc,
        ["failure", serviceName, "reset=", "0", "actions=", ""]);
    var failureExitCode = Number(failureResult[1]);
    if (failureExitCode !== 0) {
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
        installer.setDefaultPageVisible(QInstaller.ComponentSelection, false);
        installer.setDefaultPageVisible(QInstaller.TargetDirectory, false);
        installer.setDefaultPageVisible(QInstaller.StartMenuDirectoryPage, false);
        installer.setDefaultPageVisible(QInstaller.LicenseCheck, false);

        if (runningOnMacOS()) {
            installer.setMessageBoxAutomaticAnswer("OverwriteTargetDirectory", QMessageBox.Yes);
        }

        if (appInstalled()) {
            if (QMessageBox.Ok === QMessageBox.information("os.information", appName(),
                                                           qsTr("The application is already installed.") + " " +
                                                           qsTr("We need to remove the old installation first. Do you wish to proceed?"),
                                                           QMessageBox.Ok | QMessageBox.Cancel)) {

                // The user has consented to replace the existing installation.
                // Only now may Windows disconnect and close the running client.
                isDesktopAppProcessRunningMessageLoop();
                if (requestToQuitFromApp === true) {
                    requestToQuit(installer, gui);
                    return;
                }

                if (appInstalled()) {
                    if (runningOnWindows() && !prepareWindowsMainServiceForUpgrade()) {
                        QMessageBox.critical(
                            "windows.service.upgrade.prepare.failed",
                            appName(),
                            qsTr("The existing AmneziaVPN Windows service could not be prepared for a safe upgrade. The upgrade did not start. Restart Windows, then run this full offline installer again."));
                        installer.setCancelled();
                        return;
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
                        var resultArray = installer.execute(uninstallerPath);
                        console.log("Uninstaller finished with code: " + resultArray[1]);
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
            QMessageBox.critical(
                "windows.driver.cleanup.incomplete",
                appName(),
                qsTr("The previous AmneziaVPN Windows services were not fully removed. Restart Windows, then run the full offline installer again. No new files were installed."));
            installer.setCancelled();
            return;
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
