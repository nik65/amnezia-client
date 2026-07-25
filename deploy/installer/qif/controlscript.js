var requestToQuitFromApp = false;
var updaterCompleted = 0;
var desktopAppProcessRunning = false;
var appInstalledUninstallerPath;
var appInstalledUninstallerPath_x86;

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
    var result = installer.execute(systemSc, ["query", serviceName]);
    var exitCode = Number(result[1]);
    if (exitCode === 1060) {
        return true;
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

        isDesktopAppProcessRunningMessageLoop();

        if (requestToQuitFromApp === true) {
            requestToQuit(installer, gui);
            return;
        }

        if (runningOnMacOS()) {
            installer.setMessageBoxAutomaticAnswer("OverwriteTargetDirectory", QMessageBox.Yes);
        }

        if (appInstalled()) {
            if (QMessageBox.Ok === QMessageBox.information("os.information", appName(),
                                                           qsTr("The application is already installed.") + " " +
                                                           qsTr("We need to remove the old installation first. Do you wish to proceed?"),
                                                           QMessageBox.Ok | QMessageBox.Cancel)) {


                if (appInstalled()) {
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

    if (desktopAppProcessRunning) {
        var result = QMessageBox.warning("QMessageBox", appName() + " installer",
                                         appName() + " is active. Close the app and press \"Retry\" button to continue installation. Press \"Abort\" button to abort the installer and exit.",
                                         QMessageBox.Retry | QMessageBox.Abort);
        if (result === QMessageBox.Retry) {
            isDesktopAppProcessRunningMessageLoop();
        } else {
            requestToQuitFromApp = true;
            return;
        }
    }
}
