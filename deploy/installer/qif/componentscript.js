
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
			if (systemInfo.currentCpuArchitecture.search("64") < 0) {
				component.addElevatedOperation("Execute", "@TargetDir@\\" + "vc_redist.x86.exe", "/install", "/quiet", "/norestart", "/log", "vc_redist.log");
			}
			else {
				component.addElevatedOperation("Execute", "@TargetDir@\\" + "vc_redist.x64.exe", "/install", "/quiet", "/norestart", "/log", "vc_redist.log");
			}

        } else {
            console.log("Microsoft Visual C++ 2017 Redistributable already installed");
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
                                       "UNDOEXECUTE", "{0,1060,1072}", systemSc, "delete", serviceName());
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
        component.addElevatedOperation("Execute", "{0,1056}", systemSc, "start", serviceName());
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

        if (!installer.gainAdminRights()) {
            console.log("Fatal error! Cannot get admin rights!")
            return
        }

        if (runningOnWindows()) {
            command = "@TargetDir@/" + appExecutableFileName()
        } else if (runningOnMacOS()) {
            command = "/Applications/" + appName() + ".app/Contents/MacOS/" + appName();
        } else if (runningOnLinux()) {
	    command = "@TargetDir@/client/" + appName();
        }

        installer.dropAdminRights()

        processStatus = installer.executeDetached(command, args, installer.value("TargetDir"));
    }
}
