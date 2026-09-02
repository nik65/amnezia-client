[CmdletBinding()]
param(
    [string] $Version = "",
    [ValidateSet("windows", "linux", "android", "headless")]
    [string[]] $BuildPlatform = @("windows", "linux", "android"),
    [string[]] $RequirePlatform = @(
        "windows-x64",
        "linux-x64",
        "android-arm64-v8a"
    ),
    [string] $ArtifactDir = "",
    [string] $OutDir = "",
    [string] $BaseUrl = $env:SELFHOSTED_UPDATE_BASE_URL,
    [string] $SyncHost = $(if ($env:SELFHOSTED_UPDATE_SYNC_HOST) { $env:SELFHOSTED_UPDATE_SYNC_HOST } else { "10.8.1.0" }),
    [string] $SshTrustedHost = $env:SELFHOSTED_SSH_TRUSTED_HOST,
    [string] $SshTrustedHostKeySha256 = $env:SELFHOSTED_SSH_TRUSTED_HOST_KEY_SHA256,
    [string] $PrivateKey = $env:SELFHOSTED_UPDATE_PRIVATE_KEY_PATH,
    [string] $PublicKeyBase64 = $env:SELFHOSTED_UPDATE_PUBLIC_KEY_PEM_BASE64,
    [string] $WslAndroidHome = $(if ($env:WSL_ANDROID_HOME) { $env:WSL_ANDROID_HOME } else { "" }),
    [string] $HeadlessOpenSslIncludeDir = $(if ($env:AMNEZIA_HEADLESS_OPENSSL_INCLUDE_DIR) { $env:AMNEZIA_HEADLESS_OPENSSL_INCLUDE_DIR } else { "" }),
    [string] $HeadlessOpenSslCryptoLibrary = $(if ($env:AMNEZIA_HEADLESS_OPENSSL_CRYPTO_LIBRARY) { $env:AMNEZIA_HEADLESS_OPENSSL_CRYPTO_LIBRARY } else { "" }),
    [ValidateSet(1, 2)]
    [int] $PayloadSchema = $(if ($env:SELFHOSTED_UPDATE_PAYLOAD_SCHEMA) { [int] $env:SELFHOSTED_UPDATE_PAYLOAD_SCHEMA } else { 1 }),
    [ValidateSet("stable", "canary", "emergency")]
    [string] $Channel = $(if ($env:SELFHOSTED_UPDATE_CHANNEL) { $env:SELFHOSTED_UPDATE_CHANNEL } else { "stable" }),
    [ValidateRange(0, 100)]
    [int] $RolloutPercentage = $(if ($env:SELFHOSTED_UPDATE_ROLLOUT_PERCENTAGE) { [int] $env:SELFHOSTED_UPDATE_ROLLOUT_PERCENTAGE } else { 100 }),
    [string] $CohortSaltId = $(if ($env:SELFHOSTED_UPDATE_COHORT_SALT_ID) { $env:SELFHOSTED_UPDATE_COHORT_SALT_ID } else { "fleet-v1" }),
    [string] $MinimumEligibleVersion = $(if ($env:SELFHOSTED_UPDATE_MINIMUM_ELIGIBLE_VERSION) { $env:SELFHOSTED_UPDATE_MINIMUM_ELIGIBLE_VERSION } else { "" }),
    [string] $MaximumEligibleVersion = $(if ($env:SELFHOSTED_UPDATE_MAXIMUM_ELIGIBLE_VERSION) { $env:SELFHOSTED_UPDATE_MAXIMUM_ELIGIBLE_VERSION } else { "" }),
    [ValidateRange(60, 86400)]
    [int] $HealthDeadlineSeconds = $(if ($env:SELFHOSTED_UPDATE_HEALTH_DEADLINE_SECONDS) { [int] $env:SELFHOSTED_UPDATE_HEALTH_DEADLINE_SECONDS } else { 600 }),
    [ValidateRange(0, 9007199254740991)]
    [long] $PolicyGeneration = $(if ($env:SELFHOSTED_UPDATE_POLICY_GENERATION) { [long] $env:SELFHOSTED_UPDATE_POLICY_GENERATION } else { 0 }),
    [string] $GeneratedAt = $(if ($env:SELFHOSTED_UPDATE_GENERATED_AT) { $env:SELFHOSTED_UPDATE_GENERATED_AT } else { "" }),
    [string] $ExpiresAt = $(if ($env:SELFHOSTED_UPDATE_EXPIRES_AT) { $env:SELFHOSTED_UPDATE_EXPIRES_AT } else { "" }),
    [ValidateRange(1, 8760)]
    [int] $PolicyValidForHours = $(if ($env:SELFHOSTED_UPDATE_POLICY_VALID_FOR_HOURS) { [int] $env:SELFHOSTED_UPDATE_POLICY_VALID_FOR_HOURS } else { 168 }),
    [string] $PreviousVersion = $(if ($env:SELFHOSTED_UPDATE_PREVIOUS_VERSION) { $env:SELFHOSTED_UPDATE_PREVIOUS_VERSION } else { "" }),
    [string[]] $RollbackArtifact = @(),
    [ValidateRange(0, 256)]
    [int] $BuildJobs = 0,
    [switch] $SkipBuild,
    [switch] $NoBundleUpdatesInWindowsClient,
    [switch] $Preflight
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ($RollbackArtifact.Count -eq 0 -and -not [string]::IsNullOrWhiteSpace($env:SELFHOSTED_UPDATE_ROLLBACK_ARTIFACTS)) {
    $RollbackArtifact = @($env:SELFHOSTED_UPDATE_ROLLBACK_ARTIFACTS -split ";" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
}

$ScriptRoot = Split-Path -Parent $PSCommandPath
$RepoRoot = (Resolve-Path (Join-Path $ScriptRoot "..\..")).Path

function Resolve-RepoPath([string] $Path) {
    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    }
    return [System.IO.Path]::GetFullPath((Join-Path $RepoRoot $Path))
}

function Write-Step([string] $Message) {
    Write-Host ""
    Write-Host "==> $Message"
}

function Assert-Command([string] $CommandName) {
    if (-not (Get-Command $CommandName -ErrorAction SilentlyContinue)) {
        throw "Required command is not available in PATH: $CommandName"
    }
}

function Assert-ExistingFile([string] $Path, [string] $Label) {
    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw "$Label is required"
    }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Label does not exist or is not a file: $Path"
    }
}

function Assert-SshHostKeyPinPair {
    $hasHost = -not [string]::IsNullOrWhiteSpace($SshTrustedHost)
    $hasPin = -not [string]::IsNullOrWhiteSpace($SshTrustedHostKeySha256)
    if (-not $hasHost -or -not $hasPin) {
        throw "SELFHOSTED_SSH_TRUSTED_HOST and SELFHOSTED_SSH_TRUSTED_HOST_KEY_SHA256 are both required for a local release build"
    }
    if ($SshTrustedHost -notmatch "^[A-Za-z0-9._:-]+$") {
        throw "SELFHOSTED_SSH_TRUSTED_HOST must be an exact hostname or IP without whitespace, scheme, path, or brackets"
    }
    if ($SshTrustedHostKeySha256.Length -ne 50 -or
        $SshTrustedHostKeySha256 -notmatch "^SHA256:[A-Za-z0-9+/]+$") {
        throw "SELFHOSTED_SSH_TRUSTED_HOST_KEY_SHA256 must be a canonical SHA256: fingerprint with 43 standard Base64 characters and no padding"
    }

    try {
        $encoded = $SshTrustedHostKeySha256.Substring(7)
        $decoded = [Convert]::FromBase64String($encoded + "=")
    } catch {
        throw "SELFHOSTED_SSH_TRUSTED_HOST_KEY_SHA256 is not strict standard Base64"
    }
    if ($decoded.Length -ne 32 -or
        ([Convert]::ToBase64String($decoded).TrimEnd([char]'=') -cne $encoded)) {
        throw "SELFHOSTED_SSH_TRUSTED_HOST_KEY_SHA256 must canonically encode exactly 32 SHA-256 bytes"
    }
}

function Resolve-BuildJobs {
    if ($BuildJobs -gt 0) {
        return $BuildJobs
    }
    if (-not [string]::IsNullOrWhiteSpace($env:AMNEZIA_BUILD_JOBS)) {
        $parsedJobs = 0
        if ([int]::TryParse($env:AMNEZIA_BUILD_JOBS, [ref] $parsedJobs) -and $parsedJobs -gt 0) {
            return $parsedJobs
        }
    }
    return [Math]::Max(1, [Environment]::ProcessorCount)
}

function Get-ProjectVersion {
    $cmakeLists = Get-Content -LiteralPath (Join-Path $RepoRoot "CMakeLists.txt") -Raw
    if ($cmakeLists -notmatch "set\(AMNEZIAVPN_VERSION\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\)") {
        throw "Could not read AMNEZIAVPN_VERSION from CMakeLists.txt"
    }
    return $Matches[1]
}

function Get-ProjectAndroidVersionCode {
    $cmakeLists = Get-Content -LiteralPath (Join-Path $RepoRoot "CMakeLists.txt") -Raw
    if ($cmakeLists -notmatch "set\(APP_ANDROID_VERSION_CODE\s+([0-9]+)\)") {
        throw "Could not read APP_ANDROID_VERSION_CODE from CMakeLists.txt"
    }
    $versionCode = [long] $Matches[1]
    if ($versionCode -lt 1 -or $versionCode -gt 2100000000) {
        throw "APP_ANDROID_VERSION_CODE must be from 1 to 2100000000: $versionCode"
    }
    return $versionCode
}

function Get-RequiredAndroidBuildToolsRevision {
    $androidCmake = Get-Content -LiteralPath (Join-Path $RepoRoot "client\cmake\android.cmake") -Raw
    if ($androidCmake -match "QT_ANDROID_SDK_BUILD_TOOLS_REVISION\s+([0-9]+(?:\.[0-9]+)+)") {
        return $Matches[1]
    }
    return "36.0.0"
}

function Assert-ReleaseInputs {
    Assert-ExistingFile $PrivateKey "SELFHOSTED_UPDATE_PRIVATE_KEY_PATH or -PrivateKey"
    if ([string]::IsNullOrWhiteSpace($PublicKeyBase64)) {
        throw "SELFHOSTED_UPDATE_PUBLIC_KEY_PEM_BASE64 or -PublicKeyBase64 is required"
    }
    if ([string]::IsNullOrWhiteSpace($BaseUrl)) {
        throw "SELFHOSTED_UPDATE_BASE_URL or -BaseUrl is required"
    }
    if ([string]::IsNullOrWhiteSpace($SyncHost)) {
        throw "SELFHOSTED_UPDATE_SYNC_HOST or -SyncHost is required"
    }
    if ($SyncHost -match "://|/") {
        throw "SELFHOSTED_UPDATE_SYNC_HOST must be a host or IP without scheme/path/CIDR: $SyncHost"
    }
    Assert-SshHostKeyPinPair
    Assert-SafeFleetPolicy
}

function Assert-SafeFleetPolicy {
    if ($PayloadSchema -eq 2 -and ($BuildPlatform -contains "headless")) {
        throw "Linux headless clients currently accept only payload schema 1; publish headless with -PayloadSchema 1 until schema-2 policy consumption is implemented."
    }
    $restrictivePolicyRequested = (
        $Channel -ne "stable" -or
        $RolloutPercentage -ne 100 -or
        $CohortSaltId -ne "fleet-v1" -or
        -not [string]::IsNullOrWhiteSpace($MinimumEligibleVersion) -or
        -not [string]::IsNullOrWhiteSpace($MaximumEligibleVersion) -or
        $HealthDeadlineSeconds -ne 600 -or
        $PolicyGeneration -ne 0 -or
        -not [string]::IsNullOrWhiteSpace($GeneratedAt) -or
        -not [string]::IsNullOrWhiteSpace($ExpiresAt) -or
        $PolicyValidForHours -ne 168 -or
        -not [string]::IsNullOrWhiteSpace($PreviousVersion) -or
        $RollbackArtifact.Count -gt 0
    )
    if ($PayloadSchema -eq 1 -and $restrictivePolicyRequested) {
        throw "Safe fleet rollout, eligibility, expiry, health, and rollback options require explicit -PayloadSchema 2. Schema 1 is restricted to stable 100%."
    }
    if ($PayloadSchema -eq 2 -and ($PolicyGeneration -le 0 -or $PolicyGeneration -gt 9007199254740991)) {
        throw "-PolicyGeneration must be a positive monotonic JSON-safe integer up to 9007199254740991 with -PayloadSchema 2"
    }
    if ([string]::IsNullOrWhiteSpace($PreviousVersion) -ne ($RollbackArtifact.Count -eq 0)) {
        throw "-PreviousVersion and at least one -RollbackArtifact platform=path must be supplied together"
    }
    foreach ($entry in $RollbackArtifact) {
        if ($entry -notmatch "^([^=]+)=(.+)$") {
            throw "-RollbackArtifact must be platform=path: $entry"
        }
        $rollbackPlatform = $Matches[1].Trim()
        $rollbackPath = $Matches[2]
        if ($rollbackPlatform -match "^(?i:android(?:-.+)?)$") {
            throw "Android rollback artifacts are unsupported because the package installer rejects ordinary lower-versionCode APKs: $rollbackPlatform"
        }
        Assert-ExistingFile $rollbackPath "Rollback artifact $rollbackPlatform"
    }
}

function Convert-ToWslPath([string] $Path) {
    Assert-Command "wsl.exe"
    $resolved = (Resolve-Path -LiteralPath $Path).Path
    $wslInputPath = $resolved.Replace("\", "/")
    $converted = & wsl.exe wslpath -a $wslInputPath
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($converted)) {
        throw "Failed to convert path to WSL path: $Path"
    }
    return $converted.Trim()
}

function Get-VersionSortKey([string] $Name) {
    $parts = @()
    foreach ($part in ($Name -split "[^0-9]+")) {
        if ($part -ne "") {
            $parts += "{0:D8}" -f [int] $part
        }
    }
    return $parts -join "."
}

function Resolve-LatestDirectory([string[]] $Roots, [string] $RelativePattern) {
    $matches = @()
    foreach ($root in $Roots) {
        if ([string]::IsNullOrWhiteSpace($root) -or -not (Test-Path -LiteralPath $root -PathType Container)) {
            continue
        }
        $matches += @(Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue |
            Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName $RelativePattern) })
    }
    if ($matches.Count -eq 0) {
        return ""
    }
    return ($matches | Sort-Object @{ Expression = { Get-VersionSortKey $_.Name } }, Name -Descending | Select-Object -First 1).FullName
}

function Resolve-LatestQtRootDirectory([string[]] $Roots) {
    $matches = @()
    foreach ($root in $Roots) {
        if ([string]::IsNullOrWhiteSpace($root) -or -not (Test-Path -LiteralPath $root -PathType Container)) {
            continue
        }
        foreach ($versionDir in @(Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue)) {
            $hasQtKit = @(Get-ChildItem -LiteralPath $versionDir.FullName -Directory -ErrorAction SilentlyContinue |
                Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName "lib\cmake\Qt6\qt.toolchain.cmake") } |
                Select-Object -First 1).Count -gt 0
            if ($hasQtKit) {
                $matches += $versionDir
            }
        }
    }
    if ($matches.Count -eq 0) {
        return ""
    }
    return ($matches | Sort-Object @{ Expression = { Get-VersionSortKey $_.Name } }, Name -Descending | Select-Object -First 1).FullName
}

function Resolve-QtInstallBase {
    if (-not [string]::IsNullOrWhiteSpace($env:QT_INSTALL_DIR)) {
        return (Resolve-Path -LiteralPath $env:QT_INSTALL_DIR).Path
    }
    if (Test-Path -LiteralPath "C:\Qt" -PathType Container) {
        return "C:\Qt"
    }
    return ""
}

function Resolve-QtRootPath {
    if (-not [string]::IsNullOrWhiteSpace($env:QT_ROOT_PATH)) {
        $explicitQtRoot = (Resolve-Path -LiteralPath $env:QT_ROOT_PATH).Path
        if (Test-Path -LiteralPath (Join-Path $explicitQtRoot "lib\cmake\Qt6\qt.toolchain.cmake") -PathType Leaf) {
            return (Split-Path -Parent $explicitQtRoot)
        }
        return $explicitQtRoot
    }
    $qtBase = Resolve-QtInstallBase
    if ([string]::IsNullOrWhiteSpace($qtBase)) {
        return ""
    }
    $roots = @($qtBase, (Join-Path $qtBase "Qt"))
    return Resolve-LatestQtRootDirectory $roots
}

function Resolve-AndroidShaderToolsLib([string] $QtRootPath) {
    $candidates = @()
    if (-not [string]::IsNullOrWhiteSpace($env:QT_ANDROID_SHADERTOOLS_LIB)) {
        $candidates += $env:QT_ANDROID_SHADERTOOLS_LIB
    }
    if (-not [string]::IsNullOrWhiteSpace($QtRootPath)) {
        $candidates += (Join-Path $QtRootPath "android_arm64_v8a\lib\libQt6ShaderTools_arm64-v8a.so")
        $candidates += (Join-Path $QtRootPath "android\lib\libQt6ShaderTools_arm64-v8a.so")
    }
    $qtBase = Resolve-QtInstallBase
    if (-not [string]::IsNullOrWhiteSpace($qtBase)) {
        $candidates += (Join-Path $qtBase "6.10.1\android_arm64_v8a\lib\libQt6ShaderTools_arm64-v8a.so")
        $candidates += (Join-Path $qtBase "6.10.1\android\lib\libQt6ShaderTools_arm64-v8a.so")
    }
    if (-not [string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
        $candidates += (Join-Path $env:USERPROFILE "Qt\6.10.1\android_arm64_v8a\lib\libQt6ShaderTools_arm64-v8a.so")
        $candidates += (Join-Path $env:USERPROFILE "Qt\6.10.1\android\lib\libQt6ShaderTools_arm64-v8a.so")
    }
    foreach ($candidate in $candidates) {
        if (-not [string]::IsNullOrWhiteSpace($candidate) -and (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }
    return ""
}

function Resolve-QifRootPath {
    if (-not [string]::IsNullOrWhiteSpace($env:QIF_ROOT_PATH)) {
        return (Resolve-Path -LiteralPath $env:QIF_ROOT_PATH).Path
    }
    $qtBase = Resolve-QtInstallBase
    if ([string]::IsNullOrWhiteSpace($qtBase)) {
        return ""
    }
    return Resolve-LatestDirectory @((Join-Path $qtBase "Tools\QtInstallerFramework")) "bin"
}

function Resolve-WslQifRootPath {
    if (-not [string]::IsNullOrWhiteSpace($env:WSL_QIF_ROOT_PATH)) {
        return $env:WSL_QIF_ROOT_PATH
    }
    $script = @'
for base in "$HOME/Qt" "$HOME/.local/Qt" "/opt/Qt"; do
    [ -d "$base" ] || continue
    match=$(find "$base" -maxdepth 6 -type f -path "*/bin/binarycreator" -print -quit 2>/dev/null || true)
    if [ -n "$match" ]; then
        dirname "$(dirname "$match")"
        exit 0
    fi
done
exit 1
'@
    $result = Invoke-WslBashOutput $script
    if ([string]::IsNullOrWhiteSpace($result)) {
        return ""
    }
    return $result.Trim()
}

function Assert-QtTargetKit([string] $QtRootPath, [string] $KitName) {
    $kitPath = Join-Path $QtRootPath $KitName
    $toolchainPath = Join-Path $kitPath "lib\cmake\Qt6\qt.toolchain.cmake"
    if (-not (Test-Path -LiteralPath $toolchainPath -PathType Leaf)) {
        throw "Qt kit '$KitName' is required under QT_ROOT_PATH for this local release: $toolchainPath"
    }
}

function Test-QtTargetKit([string] $QtRootPath, [string] $KitName) {
    $toolchainPath = Join-Path (Join-Path $QtRootPath $KitName) "lib\cmake\Qt6\qt.toolchain.cmake"
    return (Test-Path -LiteralPath $toolchainPath -PathType Leaf)
}

function Test-QtTargetModule([string] $QtRootPath, [string] $KitName, [string] $ModuleName) {
    $moduleConfigPath = Join-Path (Join-Path $QtRootPath $KitName) "lib\cmake\$ModuleName\${ModuleName}Config.cmake"
    return (Test-Path -LiteralPath $moduleConfigPath -PathType Leaf)
}

function Assert-QtTargetModule([string] $QtRootPath, [string] $KitName, [string] $ModuleName, [string] $InstallHint) {
    if (-not (Test-QtTargetModule $QtRootPath $KitName $ModuleName)) {
        throw "Qt kit '$KitName' is missing required module $ModuleName under QT_ROOT_PATH. $InstallHint"
    }
}

function Assert-AndroidQtKit([string] $QtRootPath) {
    $requiredModules = @("Qt6RemoteObjects", "Qt6Core5Compat")
    if (Test-QtTargetKit $QtRootPath "android") {
        foreach ($module in $requiredModules) {
            if (-not (Test-QtTargetModule $QtRootPath "android" $module)) {
                throw "Qt Android kit is missing required module $module under '$QtRootPath\android'. Install Android Qt module qtremoteobjects."
            }
        }
        return
    }
    $missing = @()
    $kit = "android_arm64_v8a"
    if (-not (Test-QtTargetKit $QtRootPath $kit)) {
        $missing += $kit
    } else {
        foreach ($module in $requiredModules) {
            if (-not (Test-QtTargetModule $QtRootPath $kit $module)) {
                $missing += "$kit/$module"
            }
        }
    }
    if ($missing.Count -gt 0) {
        throw "Qt Android arm64-v8a kit is required under QT_ROOT_PATH. Install either '$QtRootPath\android' or '$QtRootPath\android_arm64_v8a', including qtremoteobjects. Missing: $($missing -join ', ')"
    }
}

function Quote-Sh([string] $Value) {
    return "'" + $Value.Replace("'", "'\''") + "'"
}

function Invoke-External([string] $FilePath, [string[]] $Arguments, [string] $WorkingDirectory = $RepoRoot) {
    Write-Host ("+ {0} {1}" -f $FilePath, ($Arguments -join " "))
    Push-Location $WorkingDirectory
    try {
        & $FilePath @Arguments
        if ($LASTEXITCODE -ne 0) {
            throw "Command failed with exit code ${LASTEXITCODE}: $FilePath"
        }
    } finally {
        Pop-Location
    }
}

function Invoke-WslBash([string] $Script) {
    Assert-Command "wsl.exe"
    $tempScript = [System.IO.Path]::ChangeExtension([System.IO.Path]::GetTempFileName(), ".sh")
$prelude = @'
set -euo pipefail
export PATH="$HOME/.local/jdk-17/bin:$HOME/.local/bin:$PATH"
run_repo_build_sh() {
    local source_script="deploy/build.sh"
    if [ ! -f "$source_script" ]; then
        echo "Missing $source_script" >&2
        return 127
    fi
    local temp_script="${TMPDIR:-/tmp}/amnezia-build-sh-$$.sh"
    tr -d '\r' < "$source_script" > "$temp_script"
    bash "$temp_script" "$@"
    local status=$?
    rm -f "$temp_script"
    return "$status"
}
'@
    $scriptBody = ($prelude + "`n" + $Script) -replace "`r`n", "`n"
    [System.IO.File]::WriteAllText($tempScript, $scriptBody, [System.Text.UTF8Encoding]::new($false))
    try {
        $tempScriptWsl = Convert-ToWslPath $tempScript
        Invoke-External "wsl.exe" @("bash", $tempScriptWsl)
    } finally {
        Remove-Item -LiteralPath $tempScript -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-WslBashOutput([string] $Script) {
    Assert-Command "wsl.exe"
    $tempScript = [System.IO.Path]::ChangeExtension([System.IO.Path]::GetTempFileName(), ".sh")
    $scriptBody = ("set -euo pipefail`n" + $Script) -replace "`r`n", "`n"
    [System.IO.File]::WriteAllText($tempScript, $scriptBody, [System.Text.UTF8Encoding]::new($false))
    try {
        $tempScriptWsl = Convert-ToWslPath $tempScript
        $output = & wsl.exe bash $tempScriptWsl
        if ($LASTEXITCODE -ne 0) {
            return ""
        }
        return (($output | Out-String).Trim())
    } finally {
        Remove-Item -LiteralPath $tempScript -Force -ErrorAction SilentlyContinue
    }
}

function Copy-Artifact([string] $SourceRoot, [string] $Pattern, [string] $DestinationRoot, [switch] $Optional) {
    $matches = @(Get-ChildItem -LiteralPath $SourceRoot -Recurse -File -Filter $Pattern -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTimeUtc -Descending)
    if ($matches.Count -eq 0) {
        if ($Optional) {
            return
        }
        throw "Expected artifact not found under ${SourceRoot}: ${Pattern}"
    }
    New-Item -ItemType Directory -Force -Path $DestinationRoot | Out-Null
    Copy-Item -LiteralPath $matches[0].FullName -Destination (Join-Path $DestinationRoot $matches[0].Name) -Force
}

function Build-WindowsInstaller([string] $BundleDir) {
    $buildJobs = Resolve-BuildJobs
    $previousConanNoRemote = $env:CONAN_NO_REMOTE
    $previousPublicKeyBase64 = $env:SELFHOSTED_UPDATE_PUBLIC_KEY_PEM_BASE64
    $previousSyncHost = $env:SELFHOSTED_UPDATE_SYNC_HOST
    $previousSshTrustedHost = $env:SELFHOSTED_SSH_TRUSTED_HOST
    $previousSshTrustedHostKeySha256 = $env:SELFHOSTED_SSH_TRUSTED_HOST_KEY_SHA256
    $previousBundleDir = $env:SELFHOSTED_UPDATE_BUNDLE_DIR
    $previousBuildJobs = $env:AMNEZIA_BUILD_JOBS
    $previousCmakeBuildParallelLevel = $env:CMAKE_BUILD_PARALLEL_LEVEL
    $env:CONAN_NO_REMOTE = "1"
    $env:AMNEZIA_BUILD_JOBS = [string] $buildJobs
    $env:CMAKE_BUILD_PARALLEL_LEVEL = [string] $buildJobs
    $env:SELFHOSTED_UPDATE_PUBLIC_KEY_PEM_BASE64 = $PublicKeyBase64
    $env:SELFHOSTED_UPDATE_SYNC_HOST = $SyncHost
    $env:SELFHOSTED_SSH_TRUSTED_HOST = $SshTrustedHost
    $env:SELFHOSTED_SSH_TRUSTED_HOST_KEY_SHA256 = $SshTrustedHostKeySha256
    if ([string]::IsNullOrWhiteSpace($BundleDir)) {
        Remove-Item Env:\SELFHOSTED_UPDATE_BUNDLE_DIR -ErrorAction SilentlyContinue
    } else {
        $env:SELFHOSTED_UPDATE_BUNDLE_DIR = $BundleDir
    }
    try {
        Invoke-External "cmd.exe" @("/d", "/s", "/c", "`"$RepoRoot\deploy\build.bat`" --installer ifw -arch x64 --jobs $buildJobs")
    } finally {
        $env:CONAN_NO_REMOTE = $previousConanNoRemote
        $env:SELFHOSTED_UPDATE_PUBLIC_KEY_PEM_BASE64 = $previousPublicKeyBase64
        if ($null -eq $previousSyncHost) {
            Remove-Item Env:\SELFHOSTED_UPDATE_SYNC_HOST -ErrorAction SilentlyContinue
        } else {
            $env:SELFHOSTED_UPDATE_SYNC_HOST = $previousSyncHost
        }
        if ($null -eq $previousSshTrustedHost) {
            Remove-Item Env:\SELFHOSTED_SSH_TRUSTED_HOST -ErrorAction SilentlyContinue
        } else {
            $env:SELFHOSTED_SSH_TRUSTED_HOST = $previousSshTrustedHost
        }
        if ($null -eq $previousSshTrustedHostKeySha256) {
            Remove-Item Env:\SELFHOSTED_SSH_TRUSTED_HOST_KEY_SHA256 -ErrorAction SilentlyContinue
        } else {
            $env:SELFHOSTED_SSH_TRUSTED_HOST_KEY_SHA256 = $previousSshTrustedHostKeySha256
        }
        if ($null -eq $previousBuildJobs) {
            Remove-Item Env:\AMNEZIA_BUILD_JOBS -ErrorAction SilentlyContinue
        } else {
            $env:AMNEZIA_BUILD_JOBS = $previousBuildJobs
        }
        if ($null -eq $previousCmakeBuildParallelLevel) {
            Remove-Item Env:\CMAKE_BUILD_PARALLEL_LEVEL -ErrorAction SilentlyContinue
        } else {
            $env:CMAKE_BUILD_PARALLEL_LEVEL = $previousCmakeBuildParallelLevel
        }
        if ($null -eq $previousBundleDir) {
            Remove-Item Env:\SELFHOSTED_UPDATE_BUNDLE_DIR -ErrorAction SilentlyContinue
        } else {
            $env:SELFHOSTED_UPDATE_BUNDLE_DIR = $previousBundleDir
        }
    }
}

function Remove-UnsupportedAndroidArtifacts([string] $DestinationRoot, [string] $ReleaseVersion) {
    $unsupportedPatterns = @(
        "AmneziaVPN_${ReleaseVersion}.aab",
        "AmneziaVPN_${ReleaseVersion}_android9+_universal.apk",
        "AmneziaVPN_${ReleaseVersion}_android9+_armeabi-v7a.apk",
        "AmneziaVPN_${ReleaseVersion}_android9+_x86.apk",
        "AmneziaVPN_${ReleaseVersion}_android9+_x86_64.apk"
    )
    foreach ($pattern in $unsupportedPatterns) {
        Get-ChildItem -LiteralPath $DestinationRoot -Recurse -File -Filter $pattern -ErrorAction SilentlyContinue |
            Remove-Item -Force
    }
}

function Assert-AndroidSigningEnvironment {
    $required = @(
        "QT_ANDROID_KEYSTORE_PATH",
        "QT_ANDROID_KEYSTORE_ALIAS",
        "QT_ANDROID_KEYSTORE_STORE_PASS"
    )
    foreach ($name in $required) {
        if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($name))) {
            throw "Android local auto-update builds require $name. The APK must be signed with the same key as installed clients."
        }
    }
    Assert-ExistingFile $env:QT_ANDROID_KEYSTORE_PATH "QT_ANDROID_KEYSTORE_PATH"
}

function Assert-WslReady {
    Assert-Command "wsl.exe"
    $repoWsl = Convert-ToWslPath $RepoRoot
    Invoke-External "wsl.exe" @("bash", "-lc", "test -d $(Quote-Sh $repoWsl) && command -v bash >/dev/null")
}

function Assert-WslCommand([string] $CommandName) {
    $bashScript = 'export PATH="$HOME/.local/jdk-17/bin:$HOME/.local/bin:$PATH"; command -v ' + (Quote-Sh $CommandName) + ' >/dev/null'
    & wsl.exe bash -lc $bashScript
    if ($LASTEXITCODE -ne 0) {
        throw "Required command is not available inside WSL: $CommandName"
    }
}

function Resolve-WslAndroidHome {
    if (-not [string]::IsNullOrWhiteSpace($WslAndroidHome)) {
        $script = 'cd ' + (Quote-Sh $WslAndroidHome) + ' 2>/dev/null && pwd || printf %s ' + (Quote-Sh $WslAndroidHome)
        $resolved = & wsl.exe bash -lc $script
        if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($resolved)) {
            throw "Failed to resolve WSL_ANDROID_HOME: $WslAndroidHome"
        }
        return $resolved.Trim()
    }
    $wslHome = & wsl.exe bash -lc 'printf %s "$HOME"'
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($wslHome)) {
        throw "Failed to resolve WSL home directory for Android SDK"
    }
    return ($wslHome.TrimEnd("/") + "/Android/sdk")
}

function Test-WindowsJavaHome {
    if ([string]::IsNullOrWhiteSpace($env:JAVA_HOME)) {
        return $false
    }
    return (Test-Path -LiteralPath (Join-Path $env:JAVA_HOME "bin\java.exe") -PathType Leaf)
}

function Assert-JavaForWsl {
    & wsl.exe bash -lc 'export PATH="$HOME/.local/jdk-17/bin:$HOME/.local/bin:$PATH"; command -v java >/dev/null'
    if ($LASTEXITCODE -eq 0) {
        return
    }
    throw "Java must be available inside WSL. Run setup_release_workstation.ps1 -InstallMissing to install the user-local WSL JDK."
}

function Assert-WslAndroidSdkReady {
    $androidHomeWsl = Resolve-WslAndroidHome
    $requiredBuildTools = Get-RequiredAndroidBuildToolsRevision
    $script = @(
        ('test -d ' + (Quote-Sh $androidHomeWsl)),
        ('test -x ' + (Quote-Sh ($androidHomeWsl + "/build-tools/$requiredBuildTools/apksigner"))),
        ('test -n "$(find ' + (Quote-Sh ($androidHomeWsl + "/ndk")) + ' -path "*/toolchains/llvm/prebuilt/linux-x86_64/bin/clang" -executable -print -quit)"'),
        ('test -n "$(find ' + (Quote-Sh ($androidHomeWsl + "/ndk")) + ' -path "*/toolchains/llvm/prebuilt/linux-x86_64/bin/clang++" -executable -print -quit)"')
    ) -join "`n"
    try {
        Invoke-WslBash $script
    } catch {
        throw "Linux Android SDK/NDK is required inside WSL at $androidHomeWsl. Run setup_release_workstation.ps1 -InstallMissing or set WSL_ANDROID_HOME to a Linux Android SDK with build-tools and NDK."
    }
}

function Assert-WslQifReady {
    $wslQifRoot = Resolve-WslQifRootPath
    if ([string]::IsNullOrWhiteSpace($wslQifRoot)) {
        throw "Linux .run builds require Qt Installer Framework inside WSL. Run setup_release_workstation.ps1 -InstallMissing to install qt.tools.ifw.47, or set WSL_QIF_ROOT_PATH to a Linux IFW root containing bin/binarycreator."
    }
    $script = 'test -x ' + (Quote-Sh ($wslQifRoot.TrimEnd("/") + "/bin/binarycreator"))
    try {
        Invoke-WslBash $script
    } catch {
        throw "WSL_QIF_ROOT_PATH must point to a Linux Qt Installer Framework root containing bin/binarycreator: $wslQifRoot"
    }
}

function Assert-LocalReleasePrerequisites {
    Write-Step "Preflight local release prerequisites"
    Assert-Command "python"
    Assert-Command "cmd.exe"
    Assert-ReleaseInputs

    if ($BuildPlatform -contains "linux" -or $BuildPlatform -contains "android" -or $BuildPlatform -contains "headless") {
        Assert-WslReady
    }
    if ($BuildPlatform -contains "linux" -or $BuildPlatform -contains "android") {
        Assert-WslCommand "conan"
    }
    $qtRootPath = Resolve-QtRootPath
    if ($BuildPlatform -contains "linux" -or $BuildPlatform -contains "android") {
        if ([string]::IsNullOrWhiteSpace($qtRootPath)) {
            throw "QT_ROOT_PATH or QT_INSTALL_DIR must point to a Qt installation for Linux/Android local release builds"
        }
    }
    if ($BuildPlatform -contains "linux") {
        Assert-QtTargetKit $qtRootPath "gcc_64"
        Assert-QtTargetModule $qtRootPath "gcc_64" "Qt6RemoteObjects" "Install Qt module qtremoteobjects for linux desktop gcc_64."
        Assert-QtTargetModule $qtRootPath "gcc_64" "Qt6Core5Compat" "Install Qt module qt5compat for linux desktop gcc_64."
        $qifRootPath = Resolve-QifRootPath
        Assert-WslQifReady
    }
    if ($BuildPlatform -contains "android") {
        Assert-AndroidSigningEnvironment
        Assert-WslAndroidSdkReady
        Assert-JavaForWsl
        Assert-AndroidQtKit $qtRootPath
        Assert-QtTargetModule $qtRootPath "gcc_64" "Qt6RemoteObjectsTools" "Install Qt module qtremoteobjects for linux desktop gcc_64 host tools."
        Assert-QtTargetModule $qtRootPath "gcc_64" "Qt6Core5Compat" "Install Qt module qt5compat for linux desktop gcc_64 host tools."
        Convert-ToWslPath $env:QT_ANDROID_KEYSTORE_PATH | Out-Null
        if (-not [string]::IsNullOrWhiteSpace($env:QT_INSTALL_DIR)) {
            Convert-ToWslPath $env:QT_INSTALL_DIR | Out-Null
        }
    }
}

if ([string]::IsNullOrWhiteSpace($Version)) {
    $Version = Get-ProjectVersion
}

if ([string]::IsNullOrWhiteSpace($ArtifactDir)) {
    $ArtifactDir = Join-Path $RepoRoot "dist\selfhosted-local-artifacts\$Version"
}
if ([string]::IsNullOrWhiteSpace($OutDir)) {
    $OutDir = Join-Path $RepoRoot "dist\selfhosted-updates\$Version"
}
$ArtifactDir = Resolve-RepoPath $ArtifactDir
$OutDir = Resolve-RepoPath $OutDir

$bundlesUpdatesInWindowsClient = (-not $NoBundleUpdatesInWindowsClient) -and
    ($BuildPlatform -contains "windows")
if ($bundlesUpdatesInWindowsClient -and ($RequirePlatform -notcontains "windows-x64")) {
    throw "Bundled Windows update publisher requires the windows-x64 manifest artifact."
}

New-Item -ItemType Directory -Force -Path $ArtifactDir | Out-Null

if ($Preflight) {
    Assert-LocalReleasePrerequisites
    Write-Step "Preflight OK"
    return
}

Assert-ReleaseInputs

if (-not $SkipBuild) {
    $qtRootPath = Resolve-QtRootPath
    $qifRootPath = Resolve-QifRootPath
    $buildJobs = Resolve-BuildJobs
    Write-Step "Use parallel build jobs: $buildJobs"

    if ($BuildPlatform -contains "windows") {
        Write-Step "Build Windows x64 installer locally"
        Build-WindowsInstaller ""
        Copy-Artifact (Join-Path $RepoRoot "deploy\build") "AmneziaVPN_${Version}_windows_x64.exe" $ArtifactDir
        Copy-Artifact (Join-Path $RepoRoot "deploy\build") "AmneziaVPN_${Version}_windows_x64.msi" $ArtifactDir -Optional
    }

    if ($BuildPlatform -contains "linux") {
        Write-Step "Build Linux x64 installer locally through WSL"
        $repoWsl = Convert-ToWslPath $RepoRoot
        $buildWsl = "$repoWsl/deploy/build-linux"
        $linuxExports = @()
        if (-not [string]::IsNullOrWhiteSpace($qtRootPath)) {
            $linuxExports += "export QT_ROOT_PATH=$(Quote-Sh (Convert-ToWslPath $qtRootPath))"
        }
        $wslQifRootPath = Resolve-WslQifRootPath
        $linuxExports += "export QIF_ROOT_PATH=$(Quote-Sh $wslQifRootPath)"
        $linuxExports += "export AMNEZIA_BUILD_JOBS=$(Quote-Sh ([string] $buildJobs))"
        $linuxExports += "export CMAKE_BUILD_PARALLEL_LEVEL=$(Quote-Sh ([string] $buildJobs))"
        $linuxExports += "export MAKEFLAGS=$(Quote-Sh ("-j$buildJobs"))"
        $linuxExports += "export CONAN_NO_REMOTE=1"
        $linuxExports += "export SELFHOSTED_UPDATE_PUBLIC_KEY_PEM_BASE64=$(Quote-Sh $PublicKeyBase64)"
        $linuxExports += "export SELFHOSTED_UPDATE_SYNC_HOST=$(Quote-Sh $SyncHost)"
        $linuxExports += "export SELFHOSTED_SSH_TRUSTED_HOST=$(Quote-Sh $SshTrustedHost)"
        $linuxExports += "export SELFHOSTED_SSH_TRUSTED_HOST_KEY_SHA256=$(Quote-Sh $SshTrustedHostKeySha256)"
        Invoke-WslBash (("{0}; cd {1} && run_repo_build_sh --source {1} --build {2} --target linux --installer IFW --jobs {3}" -f ($linuxExports -join "; "), (Quote-Sh $repoWsl), (Quote-Sh $buildWsl), $buildJobs).TrimStart("; "))
        Copy-Artifact (Join-Path $RepoRoot "deploy\build-linux") "AmneziaVPN_${Version}_linux_x64.run" $ArtifactDir
    }

    if ($BuildPlatform -contains "android") {
        Write-Step "Build signed Android APKs locally through WSL"
        Assert-AndroidSigningEnvironment
        $repoWsl = Convert-ToWslPath $RepoRoot
        $keystoreWsl = Convert-ToWslPath $env:QT_ANDROID_KEYSTORE_PATH
        $androidHomeWsl = Resolve-WslAndroidHome
        $androidExports = @(
            "export QT_ANDROID_KEYSTORE_PATH=$(Quote-Sh $keystoreWsl)",
            "export QT_ANDROID_KEYSTORE_ALIAS=$(Quote-Sh $env:QT_ANDROID_KEYSTORE_ALIAS)",
            "export QT_ANDROID_KEYSTORE_STORE_PASS=$(Quote-Sh $env:QT_ANDROID_KEYSTORE_STORE_PASS)",
            "export ANDROID_HOME=$(Quote-Sh $androidHomeWsl)",
            "export ANDROID_SDK_ROOT=$(Quote-Sh $androidHomeWsl)",
            "export AMNEZIA_BUILD_JOBS=$(Quote-Sh ([string] $buildJobs))",
            "export CMAKE_BUILD_PARALLEL_LEVEL=$(Quote-Sh ([string] $buildJobs))",
            "export MAKEFLAGS=$(Quote-Sh ("-j$buildJobs"))",
            "export GRADLE_OPTS=$(Quote-Sh ("-Dorg.gradle.workers.max=$buildJobs"))",
            "export CONAN_NO_REMOTE=1",
            'export AWG_ANDROID_GRADLE_USER_HOME="$HOME/.cache/amnezia/awg-android-gradle"',
            "export SELFHOSTED_UPDATE_PUBLIC_KEY_PEM_BASE64=$(Quote-Sh $PublicKeyBase64)",
            "export SELFHOSTED_UPDATE_SYNC_HOST=$(Quote-Sh $SyncHost)",
            "export SELFHOSTED_SSH_TRUSTED_HOST=$(Quote-Sh $SshTrustedHost)",
            "export SELFHOSTED_SSH_TRUSTED_HOST_KEY_SHA256=$(Quote-Sh $SshTrustedHostKeySha256)"
        )
        if (-not [string]::IsNullOrWhiteSpace($env:QT_ANDROID_KEYSTORE_KEY_PASS)) {
            $androidExports += "export QT_ANDROID_KEYSTORE_KEY_PASS=$(Quote-Sh $env:QT_ANDROID_KEYSTORE_KEY_PASS)"
        }
        if (-not [string]::IsNullOrWhiteSpace($env:QT_INSTALL_DIR)) {
            $androidExports += "export QT_INSTALL_DIR=$(Quote-Sh (Convert-ToWslPath $env:QT_INSTALL_DIR))"
        }
        if (-not [string]::IsNullOrWhiteSpace($qtRootPath)) {
            $androidExports += "export QT_ROOT_PATH=$(Quote-Sh (Convert-ToWslPath $qtRootPath))"
        }
        $androidShaderToolsLib = Resolve-AndroidShaderToolsLib $qtRootPath
        if ([string]::IsNullOrWhiteSpace($androidShaderToolsLib)) {
            throw "Android Qt ShaderTools runtime library is required for Qt5Compat GraphicalEffects. Set QT_ANDROID_SHADERTOOLS_LIB to libQt6ShaderTools_arm64-v8a.so."
        }
        $androidExports += "export QT_ANDROID_SHADERTOOLS_LIB=$(Quote-Sh (Convert-ToWslPath $androidShaderToolsLib))"
        $awgAndroidSourceDir = Join-Path $RepoRoot ".tmp\awg-android-src"
        if (Test-Path -LiteralPath $awgAndroidSourceDir -PathType Container) {
            $androidExports += "export AWG_ANDROID_SOURCE_DIR=$(Quote-Sh (Convert-ToWslPath $awgAndroidSourceDir))"
        }
        & wsl.exe bash -lc 'export PATH="$HOME/.local/jdk-17/bin:$HOME/.local/bin:$PATH"; command -v java >/dev/null'
        if ($LASTEXITCODE -ne 0 -and (Test-WindowsJavaHome)) {
            $androidExports += "export JAVA_HOME=$(Quote-Sh (Convert-ToWslPath $env:JAVA_HOME))"
        }
        $androidExportScript = $androidExports -join "; "

        $androidScript = @(
            $androidExportScript,
            "cd $(Quote-Sh $repoWsl)",
            'mkdir -p "$AWG_ANDROID_GRADLE_USER_HOME" "$HOME/.conan2/p/t" && find "$HOME/.conan2/p/t" -mindepth 1 -maxdepth 1 -exec rm -rf {} +',
            'rename_artifact() { src="$1"; dst="$2"; if [ ! -f "$src" ]; then echo "Missing fresh Android artifact: $src" >&2; return 1; fi; rm -f "$dst"; mv -f "$src" "$dst"; }',
            'if [ -n "${JAVA_HOME:-}" ] && [ -f "$JAVA_HOME/bin/java.exe" ]; then windows_java_home="$JAVA_HOME"; java_shim_dir="$PWD/deploy/build/java-home-shim"; mkdir -p "$java_shim_dir/bin"; for tool in java javac keytool jar; do printf ''#!/bin/sh\nexec "%s/bin/%s.exe" "$@"\n'' "$windows_java_home" "$tool" > "$java_shim_dir/bin/$tool"; chmod +x "$java_shim_dir/bin/$tool"; done; export JAVA_HOME="$java_shim_dir"; export PATH="$JAVA_HOME/bin:$PATH"; fi',
            'sed -i ''s/\r$//'' client/android/gradlew && chmod +x client/android/gradlew',
            'build_dir=./deploy/build-android-arm64-v8a',
            'rm -f deploy/build-android-arm64-v8a/client/android-build/AmneziaVPN_*_android9+_arm64-v8a.apk',
            "run_repo_build_sh --target android --sign --abi arm64-v8a --build `"`$build_dir`" --jobs $buildJobs",
            "version=`$(grep CMAKE_PROJECT_VERSION:STATIC deploy/build-android-arm64-v8a/CMakeCache.txt | cut -d= -f2)",
            "cd deploy/build-android-arm64-v8a/client/android-build && rename_artifact AmneziaVPN.apk AmneziaVPN_`${version}_android9+_arm64-v8a.apk && cd - >/dev/null"
        ) -join "; "
        Invoke-WslBash $androidScript

        Copy-Artifact (Join-Path $RepoRoot "deploy\build-android-arm64-v8a") "AmneziaVPN_${Version}_android9+_arm64-v8a.apk" $ArtifactDir
    }

    if ($BuildPlatform -contains "headless") {
        Write-Step "Build Linux headless client locally through WSL"
        $repoWsl = Convert-ToWslPath $RepoRoot
        $artifactDirWsl = Convert-ToWslPath $ArtifactDir
        $headlessExports = @(
            "export AMNEZIA_BUILD_JOBS=$(Quote-Sh ([string] $buildJobs))",
            "export CMAKE_BUILD_PARALLEL_LEVEL=$(Quote-Sh ([string] $buildJobs))",
            "export MAKEFLAGS=-j$buildJobs"
        )
        if (-not [string]::IsNullOrWhiteSpace($HeadlessOpenSslIncludeDir)) {
            $headlessExports += "export AMNEZIA_HEADLESS_OPENSSL_INCLUDE_DIR=$(Quote-Sh $HeadlessOpenSslIncludeDir)"
        }
        if (-not [string]::IsNullOrWhiteSpace($HeadlessOpenSslCryptoLibrary)) {
            $headlessExports += "export AMNEZIA_HEADLESS_OPENSSL_CRYPTO_LIBRARY=$(Quote-Sh $HeadlessOpenSslCryptoLibrary)"
        }
        $headlessScript = ("{0}; cd {1} && bash deploy/headless/build_headless_release.sh {2} {3}" -f
            ($headlessExports -join "; "),
            (Quote-Sh $repoWsl),
            (Quote-Sh $Version),
            (Quote-Sh $artifactDirWsl))
    Invoke-WslBash $headlessScript
    Assert-ExistingFile (Join-Path $ArtifactDir "AmneziaHeadless_${Version}_linux_x64.tar.gz") "Linux headless update artifact"
    Assert-ExistingFile (Join-Path $ArtifactDir "AmneziaHeadless_${Version}_linux_x64_provisioning.tar.gz") "Linux headless provisioning bundle"
}
}

Remove-UnsupportedAndroidArtifacts $ArtifactDir $Version

Write-Step "Create and verify self-hosted update manifest"
if ([string]::IsNullOrWhiteSpace($PrivateKey)) {
    throw "SELFHOSTED_UPDATE_PRIVATE_KEY_PATH or -PrivateKey is required"
}
if ([string]::IsNullOrWhiteSpace($PublicKeyBase64)) {
    throw "SELFHOSTED_UPDATE_PUBLIC_KEY_PEM_BASE64 or -PublicKeyBase64 is required"
}
if ([string]::IsNullOrWhiteSpace($BaseUrl)) {
    throw "SELFHOSTED_UPDATE_BASE_URL or -BaseUrl is required"
}

$requiredArtifactNames = @{
    "windows-x64" = "AmneziaVPN_${Version}_windows_x64.exe"
    "linux-x64" = "AmneziaVPN_${Version}_linux_x64.run"
    "android-arm64-v8a" = "AmneziaVPN_${Version}_android9+_arm64-v8a.apk"
    "linux-headless-x64" = "AmneziaHeadless_${Version}_linux_x64.tar.gz"
}
$manifestArgs = @(
    "deploy/selfhosted_updates/make_manifest.py",
    "--version", $Version,
    "--base-url", $BaseUrl,
    "--private-key", $PrivateKey,
    "--public-key-base64", $PublicKeyBase64,
    "--out-dir", $OutDir,
    "--auto-install",
    "--payload-schema", [string] $PayloadSchema,
    "--channel", $Channel,
    "--rollout-percentage", [string] $RolloutPercentage,
    "--cohort-salt-id", $CohortSaltId,
    "--health-deadline-seconds", [string] $HealthDeadlineSeconds
)
$hasAndroidManifestArtifact = @(
    $RequirePlatform | Where-Object { $_ -match "^(?i:android(?:-.+)?)$" }
).Count -gt 0
if ($hasAndroidManifestArtifact) {
    $manifestArgs += @("--android-version-code", [string] (Get-ProjectAndroidVersionCode))
}
if ($PolicyGeneration -gt 0) {
    $manifestArgs += @("--policy-generation", [string] $PolicyGeneration)
}
if (-not [string]::IsNullOrWhiteSpace($MinimumEligibleVersion)) {
    $manifestArgs += @("--minimum-eligible-version", $MinimumEligibleVersion)
}
if (-not [string]::IsNullOrWhiteSpace($MaximumEligibleVersion)) {
    $manifestArgs += @("--maximum-eligible-version", $MaximumEligibleVersion)
}
if (-not [string]::IsNullOrWhiteSpace($GeneratedAt)) {
    $manifestArgs += @("--generated-at", $GeneratedAt)
}
if (-not [string]::IsNullOrWhiteSpace($ExpiresAt)) {
    $manifestArgs += @("--expires-at", $ExpiresAt)
} else {
    $manifestArgs += @("--policy-valid-for-hours", [string] $PolicyValidForHours)
}
if (-not [string]::IsNullOrWhiteSpace($PreviousVersion)) {
    $manifestArgs += @("--previous-version", $PreviousVersion)
}
foreach ($entry in $RollbackArtifact) {
    $manifestArgs += @("--rollback-artifact", $entry)
}
foreach ($platform in $RequirePlatform) {
    if (-not $requiredArtifactNames.ContainsKey($platform)) {
        throw "Unsupported local self-hosted release platform: $platform"
    }
    $artifactPath = Join-Path $ArtifactDir $requiredArtifactNames[$platform]
    Assert-ExistingFile $artifactPath "Self-hosted update artifact $platform"
    $manifestArgs += @("--require-platform", $platform)
    $manifestArgs += @("--artifact", "$platform=$artifactPath")
}

Invoke-External "python" $manifestArgs

if (-not $NoBundleUpdatesInWindowsClient -and ($BuildPlatform -contains "windows")) {
    Write-Step "Build Windows release client with bundled update payload"
    Build-WindowsInstaller $OutDir
    $adminInstallerDir = Join-Path $RepoRoot "dist\selfhosted-windows-client\$Version"
    New-Item -ItemType Directory -Force -Path $adminInstallerDir | Out-Null
    $adminInstallerSource = Join-Path $RepoRoot "deploy\build\AmneziaVPN_${Version}_windows_x64.exe"
    Assert-ExistingFile $adminInstallerSource "Bundled Windows release client"
    $adminInstallerTarget = Join-Path $adminInstallerDir "AmneziaVPN_${Version}_windows_x64_selfhosted.exe"
    Copy-Item -LiteralPath $adminInstallerSource -Destination $adminInstallerTarget -Force
    Write-Host "Bundled Windows release client: $adminInstallerTarget"
}

Write-Step "Done"
Write-Host "Artifacts: $ArtifactDir"
Write-Host "Manifest output: $OutDir"
