[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string]$BatchPath
)

$ErrorActionPreference = "Stop"

$runnerRoot = [IO.Path]::GetFullPath($PSScriptRoot + [IO.Path]::DirectorySeparatorChar)
$resolvedBatchPath = [IO.Path]::GetFullPath($BatchPath)
$batchRoot = [IO.Path]::GetFullPath(
    [IO.Path]::GetDirectoryName($resolvedBatchPath) + [IO.Path]::DirectorySeparatorChar
)
if (-not $batchRoot.Equals($runnerRoot, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Batch file must be located beside the trusted runner."
}
if ($runnerRoot.Contains("%") -or $runnerRoot.Contains("!")) {
    throw "Install path must not contain shell expansion characters (% or !)."
}

$rootItem = Get-Item -LiteralPath $PSScriptRoot -Force -ErrorAction Stop
if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "Install directory must not be a reparse point."
}

$trustedWriterSids = @(
    "S-1-5-18",       # LocalSystem
    "S-1-5-32-544",  # Administrators
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464" # TrustedInstaller
)
# Avoid PowerShell module autoload here. Windows PowerShell 5.1 can fail to
# autoload Microsoft.PowerShell.Security when the script path contains shell
# metacharacters even though the path is passed literally. The .NET API reads
# the same directory security descriptor without that path-sensitive module
# loader.
$rootAcl = [IO.Directory]::GetAccessControl($PSScriptRoot)
$ownerAccount = [Security.Principal.NTAccount]::new($rootAcl.Owner)
$ownerSid = $ownerAccount.Translate([Security.Principal.SecurityIdentifier]).Value
if ($ownerSid -notin $trustedWriterSids) {
    throw "Install directory owner is not trusted."
}

$dangerousRights = [Security.AccessControl.FileSystemRights]::WriteData -bor
    [Security.AccessControl.FileSystemRights]::AppendData -bor
    [Security.AccessControl.FileSystemRights]::CreateDirectories -bor
    [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
    [Security.AccessControl.FileSystemRights]::WriteAttributes -bor
    [Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
    [Security.AccessControl.FileSystemRights]::Delete -bor
    [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
    [Security.AccessControl.FileSystemRights]::TakeOwnership
foreach ($rule in $rootAcl.Access) {
    if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
        ($rule.FileSystemRights -band $dangerousRights) -eq 0) {
        continue
    }
    $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
    if ($sid -notin $trustedWriterSids) {
        throw "Install directory is writable by an untrusted principal."
    }
}

$extension = [IO.Path]::GetExtension($resolvedBatchPath)
if ($extension -notin ".cmd", ".bat") {
    throw "Runner accepts only .cmd or .bat files."
}

$batchFile = Get-Item -LiteralPath $resolvedBatchPath -Force -ErrorAction Stop
if (($batchFile.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "Batch file must not be a reparse point."
}

# Elevated installers inherit the invoking process environment. Replace the
# security-sensitive well-known folder variables with values returned by the
# Windows known-folder API before the batch file uses them.
$windowsDirectory = [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
$programFilesDirectory = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
$programDataDirectory = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
if ([string]::IsNullOrWhiteSpace($windowsDirectory) -or
    [string]::IsNullOrWhiteSpace($programFilesDirectory) -or
    [string]::IsNullOrWhiteSpace($programDataDirectory)) {
    throw "Unable to resolve trusted Windows known folders."
}

$env:SystemRoot = $windowsDirectory
$env:windir = $windowsDirectory
$env:ProgramFiles = $programFilesDirectory
$env:ProgramData = $programDataDirectory
$env:ComSpec = [IO.Path]::Combine($windowsDirectory, "System32", "cmd.exe")
$env:Path = [IO.Path]::Combine($windowsDirectory, "System32") + ";" + $windowsDirectory
$env:PATHEXT = ".COM;.EXE;.BAT;.CMD"

$trustedWorkingDirectory = [IO.Path]::Combine($windowsDirectory, "System32")
Push-Location -LiteralPath $trustedWorkingDirectory
try {
    & $resolvedBatchPath
    $batchExitCode = $LASTEXITCODE
} finally {
    Pop-Location
}
exit $batchExitCode
