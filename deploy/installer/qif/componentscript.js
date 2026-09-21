
function appName()
{
    return installer.value("Name")
}

function serviceName()
{
    return runningOnWindows() ? "AmneziaVPN-service" : (appName() + "-service")
}

function appExecutableFileName()
{
    if (runningOnWindows()) {
        return "AmneziaVPN.exe";
    } else {
        return appName();
    }
}

function runningOnWindows()
{
    return (systemInfo.kernelType === "winnt");
}

function runningOnMacOS()
{
    return (systemInfo.kernelType === "darwin");
}

function runningOnLinux()
{
    return (systemInfo.kernelType === "linux");
}

function vcRuntimeIsInstalled()
{
    return (installer.findPath("msvcp140.dll", ["C:\\Windows\\System32\\"]).length !== 0)
}

// A Windows upgrade replaces the installed client binaries in place.  Qt IFW
// performs a component's archive Extract operations in the Unpack group before
// every other operation (IFW "Execution Groups" contract), so a stop operation
// added through addOperation()/addElevatedOperation() can never run early
// enough to matter: by the time it executes, the files of a live process have
// already been overwritten.  A running client keeps those DLLs mapped, executes
// replaced code and dies with an access violation (BEX64, 0xc0000005).  The
// shutdown therefore runs as a side effect of operation creation, which the
// framework performs before the Unpack group executes.
function windowsDesktopClientProcessIsRunning()
{
    // Absolute System32 path: no PATH, environment or InstallerValue lookup
    // selects the probe executable.
    var systemTasklist = "C:/Windows/System32/tasklist.exe"
    var result = installer.execute(systemTasklist, ["/FI", "IMAGENAME eq AmneziaVPN.exe", "/NH"])
    if (result.length < 2 || Number(result[1]) !== 0) {
        console.log("AmneziaVPN process probe failed; treating the desktop client as not running")
        return false
    }
    return (String(result[0]).indexOf("AmneziaVPN.exe") !== -1)
}

function stopWindowsDesktopClientBeforeUnpack()
{
    if (!runningOnWindows()) {
        return true
    }

    // A fresh install has no running client; that is not an error.
    if (!windowsDesktopClientProcessIsRunning()) {
        console.log("AmneziaVPN desktop client is not running; no shutdown before unpacking is required")
        return true
    }

    // Qt IFW 4.7 gainAdminRights() THROWS an Error (it never returns false)
    // for a command-line instance and when the elevated helper cannot be
    // started (packagemanagercore.cpp:3101-3114), and an exception raised from
    // createOperations() aborts the whole installation (scriptengine.cpp:541-546).
    // Elevation is optional here: the shipped installers are built from the
    // requireAdministrator base, so hasAdminRights() is already true for them.
    if (!installer.hasAdminRights() && !installer.isCommandLineInstance()
            && !installer.gainAdminRights()) {
        // Stopping a process of the interactive user does not require the
        // elevated helper; a denied request only narrows the fallback below.
        console.log("AmneziaVPN desktop shutdown continues without administrator rights")
    }

    // taskkill without /F asks the GUI process to close, exactly like the user
    // closing the window, so AmneziaVPN can run its ordinary teardown first.
    // The image name is a literal constant; the same primitive closes the
    // client in the Windows upgrade controller.
    var systemTaskkill = "C:/Windows/System32/taskkill.exe"
    console.log("Requesting AmneziaVPN desktop shutdown before the component archive is unpacked")
    installer.execute(systemTaskkill, ["/IM", "AmneziaVPN.exe"])

    // Bounded wait (about 10 s).  The pause is the same ping-based one-second
    // wait the uninstaller uses: no PATH lookup, no timeout.exe, no busy spin.
    var systemPing = "C:/Windows/System32/ping.exe"
    for (var gracefulAttempt = 0; gracefulAttempt < 10; ++gracefulAttempt) {
        if (!windowsDesktopClientProcessIsRunning()) {
            console.log("AmneziaVPN desktop client exited before the component archive was unpacked")
            return true
        }
        installer.execute(systemPing, ["-n", "2", "127.0.0.1"])
    }

    // The window-close request was not enough (a tray-only or wedged client
    // hides instead of exiting).  Qt IFW scopes killProcess to one exact
    // absolute executable path, so only the two literal install roots can be
    // stopped, and only those processes hold the DLLs about to be replaced.
    var installedClientPaths = [
        "C:/Program Files/AmneziaVPN/AmneziaVPN.exe",
        "C:/Program Files (x86)/AmneziaVPN/AmneziaVPN.exe"
    ]
    console.log("AmneziaVPN desktop shutdown timed out; applying the exact-path fallback")
    // installer.killProcess() answers true both for a matched process and for a
    // full-path match that found nothing (packagemanagercore.cpp:3276-3307), and
    // KDUpdater::killProcess() returns false even when the process left on its own
    // (installer/sysinfo_win.cpp:192-213): only the probe is evidence.  The close
    // request is therefore repeated while the teardown is awaited, and a client
    // that needs longer than ~5 s to release the tunnel/service is not classified
    // as wedged after the client has already been closed.
    var requestExactPathKill = function () {
        for (var killIndex = 0; killIndex < installedClientPaths.length; ++killIndex) {
            if (installer.fileExists(installedClientPaths[killIndex])) {
                installer.killProcess(installedClientPaths[killIndex])
            }
        }
    }
    requestExactPathKill()
    for (var forcedAttempt = 0; forcedAttempt < 30; ++forcedAttempt) {
        if (!windowsDesktopClientProcessIsRunning()) {
            console.log("AmneziaVPN desktop client exited before the component archive was unpacked")
            return true
        }
        if (forcedAttempt % 5 === 4) {
            requestExactPathKill()
        }
        installer.execute(systemPing, ["-n", "2", "127.0.0.1"])
    }

    console.log("AmneziaVPN desktop client is still running; refusing to replace its binaries")
    return false
}

function Component()
{
    component.loaded.connect(this, Component.prototype.componentLoaded);
    installer.installationFinished.connect(this, Component.prototype.installationFinishedPageIsShown);
    installer.finishButtonClicked.connect(this, Component.prototype.installationFinished);
}

Component.prototype.componentLoaded = function ()
{

}

Component.prototype.installationFinishedPageIsShown = function()
{
    if (installer.isInstaller() && installer.status === QInstaller.Success) {
        gui.clickButton(buttons.FinishButton);
    }
}

Component.prototype.createOperations = function()
{
    // Qt IFW runs archive Extract operations in the Unpack group before every
    // ordinary/elevated Execute operation.  A maintenance-tool updater cannot
    // therefore unload the v1.2 driver before replacing the v1.3 userspace
    // service.  Stop operation creation before the default Extract operation
    // is even registered; supported Windows upgrades use the full offline
    // installer and its uninstall-first controller path.
    if (runningOnWindows()
            && (installer.isUpdater() || component.updateRequested())) {
        installer.setCanceled();
        throw new Error("Windows split-tunnel driver updates require the full offline AmneziaVPN installer.");
    }

    // Close a running desktop client before the Unpack group replaces the
    // installed binaries: the framework runs this hook before any operation is
    // performed.  A non-running client is not an error; a client that cannot be
    // stopped cancels the installation instead of crashing it.
    if (runningOnWindows() && !stopWindowsDesktopClientBeforeUnpack()) {
        installer.setCanceled();
        throw new Error("AmneziaVPN could not be closed before the update. Close the application and run this installer again.");
    }

    component.createOperations();

    if (runningOnWindows()) {
        // Qt IFW accepts arbitrary command-line InstallerValue overrides.
        // Validate literal product identity and a protected TargetDir before
        // scheduling any elevated operation that executes extracted content.
        if (appName() !== "AmneziaVPN") {
            throw new Error("Windows package Name must remain AmneziaVPN.")
        }
        let protectedTargetDir = "C:\\Program Files\\AmneziaVPN"
        let selectedTargetDir = installer.value("TargetDir").replace(/\//g, '\\')
        if (selectedTargetDir.toLowerCase() !== protectedTargetDir.toLowerCase()) {
            throw new Error("Windows service installation requires C:\\Program Files\\AmneziaVPN as TargetDir.")
        }
        let pu_path = protectedTargetDir + "\\"
        let windowsPowerShell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
        let systemSc = "C:\\Windows\\System32\\sc.exe"
        let batchRunner = pu_path + "run_batch_file.ps1"
        let postUninstallScript = pu_path + "post_uninstall.cmd"
        let postInstallScript = pu_path + "post_install.cmd"

        component.addOperation("CreateShortcut", "@TargetDir@/" + appExecutableFileName(),
                               QDesktopServices.storageLocation(QDesktopServices.DesktopLocation) + "/" + appName() + ".lnk",
                               "workingDirectory=@TargetDir@", "iconPath=@TargetDir@\\" + appExecutableFileName(), "iconId=0");


        component.addElevatedOperation("CreateShortcut", "@TargetDir@/" + appExecutableFileName(),
                                       "C:/ProgramData/Microsoft/Windows/Start Menu/Programs/AmneziaVPN.lnk",
                                       "workingDirectory=@TargetDir@", "iconPath=@TargetDir@\\" + appExecutableFileName(), "iconId=0");

        if (!vcRuntimeIsInstalled()) {
            var vcRedistFileName = (systemInfo.currentCpuArchitecture.search("64") < 0) ? "vc_redist.x86.exe"
                                                                                       : "vc_redist.x64.exe";
            if (installer.findPath(vcRedistFileName, [installer.value("TargetDir").replace(/\//g, '\\')]).length !== 0) {
                component.addElevatedOperation("Execute", "@TargetDir@\\" + vcRedistFileName, "/install", "/quiet", "/norestart", "/log", "vc_redist.log");
            } else {
                console.log(vcRedistFileName + " is not bundled, relying on the application-local MSVC runtime");
            }
        } else {
            console.log("Microsoft Visual C++ Redistributable already installed");
        }

        // Keep the quotes inside binpath=.  Windows service ImagePath values
        // that point into Program Files must quote the executable path; passing
        // this as a distinct QProcess argument preserves the literal quotes
        // that sc.exe writes into the SCM configuration.
        let serviceImagePath = "\"" + pu_path + serviceName() + ".exe\""
        // Pass the runner and batch path as separate process arguments. The
        // runner verifies the protected directory and sanitizes the process
        // environment before cmd.exe sees the literal batch path.
        // Qt IFW 4.7 offers Retry and Ignore for a failed undo operation.
        // post_uninstall.cmd therefore owns a bounded retry budget. Before an
        // ignored failure returns, it copies a validated recovery bundle and
        // text receipt to a protected Program Files sibling instead of allowing
        // Qt IFW to retry forever.
        component.addElevatedOperation("Execute",
                                       [systemSc, "create", serviceName(), "binpath=", serviceImagePath,
                                         "start=", "auto", "depend=", "BFE/nsi"],
                                       "UNDOEXECUTE", ["{0,1060}", systemSc, "delete", serviceName()]);
        // Run product cleanup first during rollback/uninstall. If it fails and
        // IFW continues, the service-create undo above still deregisters the
        // LocalSystem service without executing more TargetDir content.
        component.addElevatedOperation("Execute", systemSc, "query", serviceName(),
	                                    "UNDOEXECUTE", windowsPowerShell, "-NoLogo", "-NoProfile",
                                       "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File",
                                       batchRunner, postUninstallScript);
										
        component.addElevatedOperation("Execute", windowsPowerShell, "-NoLogo", "-NoProfile",
                                       "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File",
                                       batchRunner, postInstallScript);
        // These are install operations rather than Finish-button callbacks so
        // headless/CLI installs leave the privileged service ready before the
        // installer reports success.  The service-create operation above owns
        // the bounded uninstall rollback if a later operation fails.
        component.addElevatedOperation("Execute", systemSc, "failure", serviceName(),
                                       "reset=", "100", "actions=",
                                       "restart/2000/restart/2000/restart/2000");
        component.addElevatedOperation("Execute", ["{0,1056}", systemSc, "start", serviceName()]);
    } else if (runningOnMacOS()) {
        component.addElevatedOperation("Execute", "@TargetDir@/post_install.sh", "UNDOEXECUTE", "@TargetDir@/post_uninstall.sh");
    } else if (runningOnLinux()) {
        component.addElevatedOperation("Execute", "bash", "@TargetDir@/post_install.sh", "UNDOEXECUTE", "bash", "@TargetDir@/post_uninstall.sh");
    }
}

Component.prototype.installationFinished = function()
{
    var command = "";
    var args = [];

    if ((installer.status === QInstaller.Success) && (installer.isInstaller() || installer.isUpdater())) {

        if (runningOnWindows()) {
            // Start the freshly installed client as the interactive user, never as
            // the elevated installer.
            //
            // The shipped Windows installer base is manifested requireAdministrator
            // (CPACK_IFW_INSTALLERBASE_EXECUTABLE -> dist/.build-tools/installerbase-require-admin.exe),
            // so this finish handler - and every process installer.executeDetached()
            // creates from it - runs with an enabled administrator token. Qt IFW 4.7
            // has no call that lowers that token: installer.dropAdminRights() only
            // deactivates the elevated helper server that installer.gainAdminRights()
            // started (PackageManagerCore::dropAdminRights() { RemoteClient::instance().setActive(false); }),
            // and installer.executeDetached() is a plain QProcess::startDetached()
            // performed by the installer itself.
            //
            // An elevated client is what produces error 103 after an upgrade: client
            // and service mutually verify the peer token against the ACL of
            // C:\Program Files\AmneziaVPN (executable and directory grant
            // BUILTIN\Administrators (F) and BUILTIN\Users only (RX)), so an
            // administrator peer is rejected as "Installed client is replaceable by
            // the local peer", the client never obtains the service interface and the
            // UI reports 103 (AmneziaServiceNotRunning, "Background service is not
            // running") until the user restarts the app.
            //
            // A medium-integrity process can only be created by a process that already
            // runs with the interactive user's token, so the client is started through
            // the interactive shell: Explorer runs as the logged-on user and launches
            // the executable exactly like a double click on the desktop shortcut. This
            // is safe because
            //   * the shell path is resolved from the running system, never pinned to
            //     one directory: the directory reported by the environment
            //     (SystemRoot, then windir) is combined with the shell's file name
            //     and confirmed with installer.fileExists(); only when that probe
            //     fails does the launch fall back to the literal
            //     C:\Windows\explorer.exe and then to the bare image name
            //     explorer.exe resolved through PATH.  The shell does not live
            //     under System32 on a stock Windows installation, so no branch may
            //     pin it there, and the client path is built from the installer's
            //     own TargetDir value, which controlscript.js pins to
            //     C:\Program Files\AmneziaVPN and createOperations() re-validates
            //     before any elevated operation runs;
            //   * that single path is the only argument and is passed as one argv
            //     element, so nothing can be interpolated into a command line;
            //   * the resulting process is a normal user process that cannot replace
            //     its own binaries, which is exactly what the service's anti-tamper
            //     check requires, and is the same launch the user performs manually.
            //
            // Candidate order for the shell executable.  Both probes are Q_INVOKABLE
            // calls offered by the installer object in Qt IFW 4.7 and are evaluated
            // before any process is created: installer.environmentVariable() returns
            // the environment value and an empty string for an unset variable
            // (packagemanagercore.cpp:3469), and installer.fileExists() is a
            // QFileInfo::exists() probe (packagemanagercore.cpp:1016).
            var explorerCandidates = [];
            var explorerEnvironmentNames = ["SystemRoot", "windir"];
            for (var explorerEnvironmentIndex = 0; explorerEnvironmentIndex < explorerEnvironmentNames.length; ++explorerEnvironmentIndex) {
                var explorerDirectory = String(installer.environmentVariable(explorerEnvironmentNames[explorerEnvironmentIndex])).replace(/\//g, "\\").replace(/\\+$/, "");
                if (explorerDirectory.length !== 0) {
                    var explorerFromEnvironment = explorerDirectory + "\\explorer.exe";
                    if (explorerCandidates.indexOf(explorerFromEnvironment) === -1) {
                        explorerCandidates.push(explorerFromEnvironment);
                    }
                }
            }
            // The default Windows directory is the documented shell location and
            // the fallback when the environment reports nothing usable.
            explorerCandidates.push("C:\\Windows\\explorer.exe");
            var windowsExplorer = "";
            for (var explorerCandidateIndex = 0; explorerCandidateIndex < explorerCandidates.length; ++explorerCandidateIndex) {
                var explorerCandidate = explorerCandidates[explorerCandidateIndex];
                var explorerCandidateExists = installer.fileExists(explorerCandidate);
                console.log("Interactive shell candidate " + explorerCandidate + " (exists " + explorerCandidateExists + ")");
                if (explorerCandidateExists && windowsExplorer.length === 0) {
                    windowsExplorer = explorerCandidate;
                }
            }
            if (windowsExplorer.length === 0) {
                // Nothing on disk matched a candidate: hand the launcher the bare
                // image name, which it resolves through PATH, instead of pinning a
                // path the probe has just reported missing.
                windowsExplorer = "explorer.exe";
            }
            console.log("Interactive shell selected for the client launch: " + windowsExplorer
                        + " (exists " + installer.fileExists(windowsExplorer) + ")");
            // Build the launch path from the resolved InstallerValue instead of a
            // literal '@TargetDir@' placeholder: executeDetached() does run
            // replaceVariables() on program/arguments/workingDirectory
            // (packagemanagercore.cpp:3446-3457), but the placeholder keeps the
            // launch dependent on that preprocessing and leaves the unresolved
            // string in the installer log.  The path is a single argv element and
            // Qt IFW quotes space-containing arguments itself, so it stays
            // unquoted; the resolved target directory is also the child's working
            // directory, so CreateProcess never inherits a stale caller directory.
            var resolvedTargetDir = String(installer.value("TargetDir")).replace(/\//g, "\\").replace(/\\+$/, "");
            command = resolvedTargetDir + "\\" + appExecutableFileName();
            console.log("Launching the installed client as the interactive user: " + command
                        + " (TargetDir " + installer.value("TargetDir") + ", exists " + installer.fileExists(command) + ")");
            processStatus = installer.executeDetached(windowsExplorer, [command], resolvedTargetDir);
            console.log("Started the client as the interactive user through " + windowsExplorer
                        + ": " + command + " (result " + processStatus + ")");
            return;
        }

        // Non-Windows installers keep the previous elevation behaviour: the client
        // is started from the installer process there, so the platform launch path
        // is unchanged.
        if (!installer.gainAdminRights()) {
            console.log("Fatal error! Cannot get admin rights!")
            return
        }

        if (runningOnMacOS()) {
            command = "/Applications/" + appName() + ".app/Contents/MacOS/" + appName();
        } else if (runningOnLinux()) {
            command = "@TargetDir@/client/" + appName();
        }

        installer.dropAdminRights()

        processStatus = installer.executeDetached(command, args, installer.value("TargetDir"));
    }
}
