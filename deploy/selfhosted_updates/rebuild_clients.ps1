[CmdletBinding()]
param(
    [ValidateSet("windows", "linux", "android")]
    [string[]] $BuildPlatform = @("windows", "linux", "android"),
    [string[]] $RequirePlatform = @(
        "windows-x64",
        "linux-x64",
        "android-arm64-v8a"
    ),
    [int] $BuildJobs = 0,
    [string] $EnvFile = "",
    [string] $LogDir = "",
    [switch] $SkipPreflight,
    [switch] $NoBundleUpdatesInWindowsClient
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ScriptRoot = Split-Path -Parent $PSCommandPath
$RepoRoot = (Resolve-Path (Join-Path $ScriptRoot "..\..")).Path
$LocalReleaseScript = Join-Path $ScriptRoot "local_release.ps1"

if ([string]::IsNullOrWhiteSpace($EnvFile)) {
    $EnvFile = Join-Path $RepoRoot "dist\selfhosted-release-env.ps1"
}
if ([string]::IsNullOrWhiteSpace($LogDir)) {
    $LogDir = Join-Path $RepoRoot "dist\build-logs"
}

function Get-ProjectVersion {
    $cmakeLists = Get-Content -LiteralPath (Join-Path $RepoRoot "CMakeLists.txt") -Raw
    if ($cmakeLists -notmatch "set\(AMNEZIAVPN_VERSION\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\)") {
        throw "Could not read AMNEZIAVPN_VERSION from CMakeLists.txt"
    }
    return $Matches[1]
}

function Quote-PowerShellString([string] $Value) {
    return "'" + ($Value -replace "'", "''") + "'"
}

function Format-PowerShellStringArray([string[]] $Values) {
    return "@(" + (($Values | ForEach-Object { Quote-PowerShellString $_ }) -join ", ") + ")"
}

function New-LocalReleaseCommand([switch] $PreflightCommand) {
    $parts = @(
        ("& " + (Quote-PowerShellString $LocalReleaseScript)),
        ("-BuildPlatform " + (Format-PowerShellStringArray $BuildPlatform)),
        ("-RequirePlatform " + (Format-PowerShellStringArray $RequirePlatform))
    )
    if ($BuildJobs -gt 0) {
        $parts += @("-BuildJobs", [string] $BuildJobs)
    }
    if ($NoBundleUpdatesInWindowsClient) {
        $parts += "-NoBundleUpdatesInWindowsClient"
    }
    if ($PreflightCommand) {
        $parts += "-Preflight"
    }
    return ($parts -join " ")
}

function Invoke-LoggedPowerShell([string] $Label, [string] $Command) {
    New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $safeLabel = $Label -replace '[^A-Za-z0-9_.-]', '_'
    $stdoutPath = Join-Path $LogDir "${safeLabel}_${timestamp}.stdout.log"
    $stderrPath = Join-Path $LogDir "${safeLabel}_${timestamp}.stderr.log"

    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = "powershell.exe"
    $psi.WorkingDirectory = $RepoRoot
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Command))
    $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -EncodedCommand $encodedCommand"

    Write-Host ""
    Write-Host "==> $Label"
    Write-Host "stdout: $stdoutPath"
    Write-Host "stderr: $stderrPath"

    $process = [System.Diagnostics.Process]::Start($psi)
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    $process.WaitForExit()
    $stdoutTask.Wait()
    $stderrTask.Wait()

    Set-Content -LiteralPath $stdoutPath -Value $stdoutTask.Result -Encoding UTF8
    Set-Content -LiteralPath $stderrPath -Value $stderrTask.Result -Encoding UTF8

    if ($process.ExitCode -ne 0) {
        Write-Host ""
        Write-Host "Last stdout lines:"
        Get-Content -LiteralPath $stdoutPath -Tail 80 -ErrorAction SilentlyContinue
        Write-Host ""
        Write-Host "Last stderr lines:"
        Get-Content -LiteralPath $stderrPath -Tail 80 -ErrorAction SilentlyContinue
        throw "$Label failed with exit code $($process.ExitCode)"
    }

    return @{
        Stdout = $stdoutPath
        Stderr = $stderrPath
    }
}

if (-not (Test-Path -LiteralPath $EnvFile -PathType Leaf)) {
    throw "Release workstation env file is missing: $EnvFile. Run setup_release_workstation.ps1 first."
}

. $EnvFile

$version = Get-ProjectVersion
Write-Host "Version: $version"
Write-Host "Platforms: $($BuildPlatform -join ', ')"
if ($BuildJobs -gt 0) {
    Write-Host "Build jobs: $BuildJobs"
}

if (-not $SkipPreflight) {
    Invoke-LoggedPowerShell "selfhosted_preflight_$version" (New-LocalReleaseCommand -PreflightCommand) | Out-Null
}

$logs = Invoke-LoggedPowerShell "selfhosted_rebuild_$version" (New-LocalReleaseCommand)

Write-Host ""
Write-Host "==> Rebuild complete"
Write-Host "Artifacts: $(Join-Path $RepoRoot "dist\selfhosted-local-artifacts\$version")"
Write-Host "Manifest:  $(Join-Path $RepoRoot "dist\selfhosted-updates\$version")"
if (($BuildPlatform -contains "windows") -and -not $NoBundleUpdatesInWindowsClient) {
    Write-Host "Bundled Windows client: $(Join-Path $RepoRoot "dist\selfhosted-windows-client\$version\AmneziaVPN_${version}_windows_x64_selfhosted.exe")"
}
Write-Host "Build stdout: $($logs.Stdout)"
Write-Host "Build stderr: $($logs.Stderr)"
