[CmdletBinding()]
param(
  [Parameter(Mandatory = $true, Position = 0)] [ValidateSet('probe','reinstall','update','service-health','interactive-start','interactive-status','interactive-collect')] [string] $Action,
  [Parameter(Mandatory = $true, Position = 1)] [ValidateSet('windows-x64')] [string] $Profile,
  [string] $RunId,
  [string] $ExpectedVersion,
  [string] $ExpectedSha256,
  [string] $ArtifactPath = 'C:\ProgramData\AmneziaLab\current.exe',
  [string] $ReceiptPath,
  [string] $InteractiveTaskName = 'AmneziaLab-InteractiveInstaller',
  [string] $TokenEvidencePath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

function Fail([string] $Message) { throw $Message }
function Assert-RunId {
  if ([string]::IsNullOrWhiteSpace($RunId) -or $RunId -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$') { Fail 'RunId is required and must be a bounded lab identifier' }
}
function Assert-ArtifactPath {
  $resolved = [IO.Path]::GetFullPath($ArtifactPath)
  if ($resolved -ne 'C:\ProgramData\AmneziaLab\current.exe') { Fail 'ArtifactPath must be the controller-owned QGA upload path' }
  if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) { Fail 'artifact was not uploaded through QGA' }
  return $resolved
}
function Get-TokenEvidence {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($identity)
  $isSystem = $identity.User -and $identity.User.Value -eq 'S-1-5-18'
  $isLabadmin = [bool]($identity.Name -match '(?i)(^|\\)labadmin$')
  $admin = $false
  try { $admin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } catch { $admin = $false }
  $explorer = @(Get-Process -Name explorer -ErrorAction SilentlyContinue | Select-Object -First 1)
  return [ordered]@{ name = [string]$identity.Name; user_sid = if ($identity.User) { [string]$identity.User.Value } else { '' }; is_system = [bool]$isSystem; is_labadmin = $isLabadmin; is_administrator = [bool]$admin; is_interactive = [bool]($isLabadmin -and [Environment]::UserInteractive); session_id = if ($explorer.Count -gt 0) { [int]$explorer[0].SessionId } else { -1 }; source = if ($isSystem) { 'qga-system' } else { 'guest-process' } }
}
function Get-ActiveUserProfile {
  $explorer = @(Get-Process -Name explorer -IncludeUserName -ErrorAction SilentlyContinue | Select-Object -First 1)
  if ($explorer.Count -eq 0 -or [string]::IsNullOrWhiteSpace($explorer[0].UserName)) { return $null }
  $userName = [string]$explorer[0].UserName; $leaf = $userName.Split('\')[-1]
  if ($leaf -ne 'labadmin') { return $null }
  $console = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
  if ($console.UserName -and [string]$console.UserName -notmatch '(?i)(^|\\)labadmin$') { return $null }
  $profile = Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue | Where-Object { $_.Loaded -and $_.LocalPath -and (Split-Path -Leaf $_.LocalPath) -eq $leaf } | Select-Object -First 1
  if ($null -eq $profile) { return $null }
  return [ordered]@{ user = $userName; path = [string]$profile.LocalPath; session_id = [int]$explorer[0].SessionId }
}
function Get-InstalledVersion {
  $components = 'C:\Program Files\AmneziaVPN\components.xml'
  if (Test-Path -LiteralPath $components -PathType Leaf) {
    $match = [regex]::Match((Get-Content -LiteralPath $components -Raw), '<Version>\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\s*</Version>', 'IgnoreCase')
    if ($match.Success) { return $match.Groups[1].Value }
  }
  $exe = 'C:\Program Files\AmneziaVPN\AmneziaVPN.exe'
  if (Test-Path -LiteralPath $exe -PathType Leaf) { $value = (Get-Item -LiteralPath $exe).VersionInfo.ProductVersion; if ($value -and $value -match '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+') { return $Matches[0] } }
  return ''
}
function Get-ServiceSnapshot {
  $service = Get-CimInstance Win32_Service -Filter "Name='AmneziaVPN-service'" -ErrorAction SilentlyContinue
  if ($null -eq $service) { return [ordered]@{ present = $false; name = 'AmneziaVPN-service' } }
  return [ordered]@{ present = $true; name = [string]$service.Name; state = [string]$service.State; start_mode = [string]$service.StartMode; start_name = [string]$service.StartName; path = [string]$service.PathName; process_id = [int]$service.ProcessId }
}
function Get-InstallerUserData([object] $activeProfile) {
  if ($null -eq $activeProfile) { return [ordered]@{ available = $false; reason = 'no-loaded-interactive-profile' } }
  $root = Join-Path $activeProfile.path 'AppData\Local\AmneziaVPN-InstallerLogs'
  $files = @(Get-ChildItem -LiteralPath $root -File -Filter 'installer-*.jsonl' -ErrorAction SilentlyContinue | Sort-Object LastWriteTimeUtc -Descending)
  $latest = if ($files.Count -gt 0) { $files[0] } else { $null }; $prefix = @()
  if ($null -ne $latest) { $prefix = @(Get-Content -LiteralPath $latest.FullName -TotalCount 20 -ErrorAction SilentlyContinue) }
  return [ordered]@{ available = $true; path = $root; latest = if ($latest) { $latest.Name } else { $null }; prefix = $prefix }
}
function Get-RecoveryState {
  $root = 'C:\Program Files\AmneziaVPN-Recovery'; $journal = Join-Path $root 'upgrade-service-journal.json'; $items = @()
  if (Test-Path -LiteralPath $root) {
    $items = @(Get-ChildItem -LiteralPath $root -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq 'upgrade-service-journal.json' -or $_.Name -like 'upgrade-service-journal.json.*' } | ForEach-Object { $acl = Get-Acl -LiteralPath $_.FullName -ErrorAction SilentlyContinue; [ordered]@{ name = $_.Name; length = [int64]$_.Length; reparse = [bool](($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0); owner = if ($acl) { [string]$acl.Owner } else { '' }; protected = if ($acl) { [bool]$acl.AreAccessRulesProtected } else { $false } } })
  }
  $rootAcl = Get-Acl -LiteralPath $root -ErrorAction SilentlyContinue
  return [ordered]@{ root = $root; root_exists = [bool](Test-Path -LiteralPath $root -PathType Container); journal_exists = [bool](Test-Path -LiteralPath $journal -PathType Leaf); root_owner = if ($rootAcl) { [string]$rootAcl.Owner } else { '' }; root_protected = if ($rootAcl) { [bool]$rootAcl.AreAccessRulesProtected } else { $false }; items = $items }
}
function Write-Receipt([object] $Assertion, [object] $Token, [object] $Steps) {
  if ([string]::IsNullOrWhiteSpace($ReceiptPath)) { $ReceiptPath = "C:\ProgramData\AmneziaLab\runs\$RunId\receipt.json" }
  $parent = Split-Path -Parent $ReceiptPath; New-Item -ItemType Directory -Force -Path $parent | Out-Null
  $receiptHash = if ($Assertion -and $Assertion.PSObject.Properties['artifact_sha256']) { [string]$Assertion.artifact_sha256 } else { '' }
  $receipt = [ordered]@{ schema = 1; run_id = $RunId; profile = $Profile; artifact = [IO.Path]::GetFileName($ArtifactPath); artifact_sha256 = $receiptHash; guest_marker = "amnezia-release-lab:${RunId}:${Profile}"; transport = 'qga'; origin = 'guest'; injected = $false; token = $Token; steps = @($Steps); assertion = $Assertion; observed_at = [DateTime]::UtcNow.ToString('o') }
  $tmp = "$ReceiptPath.tmp"; $receipt | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $tmp -Encoding UTF8; Move-Item -LiteralPath $tmp -Destination $ReceiptPath -Force
}
function Get-Assertion([string] $Artifact, [string] $BeforeHash, [string] $Context, [object] $Service, [object] $UserData, [object] $Recovery) {
  $afterHash = (Get-FileHash -LiteralPath $Artifact -Algorithm SHA256).Hash.ToLowerInvariant(); $afterVersion = Get-InstalledVersion
  if ($ExpectedSha256 -and $afterHash -ne $ExpectedSha256.ToLowerInvariant()) { Fail 'artifact hash changed after guest operation' }
  if ($ExpectedVersion -and $afterVersion -ne $ExpectedVersion) { Fail "installed version mismatch: expected $ExpectedVersion, observed $afterVersion" }
  return [ordered]@{ passed = $true; run_id = $RunId; profile = $Profile; action = $Action; artifact = [IO.Path]::GetFileName($Artifact); artifact_sha256 = $afterHash; artifact_sha256_before = $BeforeHash; expected_sha256 = $ExpectedSha256.ToLowerInvariant(); expected_version = $ExpectedVersion; installed_version = $afterVersion; execution_context = $Context; service = $Service; installer_userdata = $UserData; recovery = $Recovery; observed_at = [DateTime]::UtcNow.ToString('o') }
}

Assert-RunId
$token = Get-TokenEvidence; $steps = @()
try {
  $marker = 'C:\ProgramData\AmneziaLab\READY'
  if (-not (Test-Path -LiteralPath $marker -PathType Leaf)) { Fail 'guest readiness marker missing' }
  if (-not ((Get-Content -LiteralPath $marker -Raw) -match 'candidate_credentials=absent')) { Fail 'candidate credentials marker missing' }
  $activeProfile = Get-ActiveUserProfile; $userData = Get-InstallerUserData $activeProfile
  if ($Action -eq 'interactive-start') {
    if ($null -eq $activeProfile) { Fail 'interactive-start requires a logged-in guest labadmin session' }
    if ($InteractiveTaskName -notmatch '^[A-Za-z0-9._-]{1,100}$') { Fail 'interactive task name is invalid' }
    & "$env:SystemRoot\System32\schtasks.exe" /Run /TN $InteractiveTaskName 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail "interactive scheduled task could not be started: $LASTEXITCODE" }
    $steps += [ordered]@{ id = 'interactive-start'; passed = $true; task = $InteractiveTaskName; expected_ui = @('replacement confirmation or unattended handoff', 'Windows UAC consent', 'service-preflight result') }
    $assertion = [ordered]@{ passed = $true; status = 'launch-requested'; requested_by_token = $token; interactive_token = $false; interactive_evidence_required = $true; ui_coordinator_required = $true; expected_ui = $steps[0].expected_ui }
    Write-Receipt $assertion $token $steps; $assertion | ConvertTo-Json -Compress; exit 0
  }
  if ($Action -eq 'interactive-status') {
    $steps += [ordered]@{ id = 'interactive-status'; passed = $true; active_user = $activeProfile; token = $token; installer_userdata = $userData }
    $assertion = [ordered]@{ passed = $true; status = 'observed'; interactive_token = [bool](-not $token.is_system -and $token.is_interactive); ui_coordinator_required = $true; installer_userdata = $userData }
    Write-Receipt $assertion $token $steps; $assertion | ConvertTo-Json -Compress; exit 0
  }
  if ($Action -eq 'service-health') {
    $artifact = Assert-ArtifactPath; $artifactHash = (Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($ExpectedSha256 -and $artifactHash -ne $ExpectedSha256.ToLowerInvariant()) { Fail 'uploaded artifact hash differs from planned hash' }
    $service = Get-ServiceSnapshot; if (-not $service.present -or $service.state -ne 'Running') { Fail 'AmneziaVPN-service is not running' }
    $assertion = [ordered]@{ passed = $true; artifact_sha256 = $artifactHash; service = $service; installed_version = Get-InstalledVersion; execution_context = $token }; $steps += [ordered]@{ id = 'service-health'; passed = $true; artifact_sha256 = $artifactHash; service = $service }
    Write-Receipt $assertion $token $steps; $assertion | ConvertTo-Json -Compress; exit 0
  }
  if ($Action -eq 'probe') {
    $artifact = Assert-ArtifactPath; $beforeHash = (Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($ExpectedSha256 -and $beforeHash -ne $ExpectedSha256.ToLowerInvariant()) { Fail 'uploaded artifact hash differs from planned hash' }
    $service = Get-ServiceSnapshot; $recovery = Get-RecoveryState; $assertion = [ordered]@{ passed = $true; artifact_sha256 = $beforeHash; installed_version = Get-InstalledVersion; token = $token; service = $service; installer_userdata = $userData; recovery = $recovery }; $steps += [ordered]@{ id = 'probe'; passed = $true; artifact_sha256 = $beforeHash }
    Write-Receipt $assertion $token $steps; $assertion | ConvertTo-Json -Compress; exit 0
  }
  if ($Action -eq 'interactive-collect') {
    if (-not $TokenEvidencePath -or -not (Test-Path -LiteralPath $TokenEvidencePath -PathType Leaf)) { Fail 'interactive token evidence is required' }
    if ([string]::IsNullOrWhiteSpace($ExpectedSha256) -or $ExpectedSha256 -notmatch '^[0-9a-fA-F]{64}$' -or [string]::IsNullOrWhiteSpace($ExpectedVersion)) { Fail 'interactive collect requires expected artifact identity' }
    $evidence = Get-Content -LiteralPath $TokenEvidencePath -Raw | ConvertFrom-Json
    if ($evidence.run_id -ne $RunId -or $evidence.profile -ne $Profile -or $evidence.interactive_token -ne $true) { Fail 'interactive token evidence identity is invalid' }
    $artifact = Assert-ArtifactPath; $beforeHash = (Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash.ToLowerInvariant(); $assertion = Get-Assertion $artifact $beforeHash 'interactive-qmp-coordinated' (Get-ServiceSnapshot) $userData (Get-RecoveryState); $assertion.interactive_evidence = $evidence
    $steps += [ordered]@{ id = 'interactive-collect'; passed = $true; token_evidence = $TokenEvidencePath }; Write-Receipt $assertion $token $steps; $assertion | ConvertTo-Json -Compress; exit 0
  }
  $artifact = Assert-ArtifactPath
  if ([string]::IsNullOrWhiteSpace($ExpectedSha256) -or $ExpectedSha256 -notmatch '^[0-9a-fA-F]{64}$') { Fail 'ExpectedSha256 is required for installer operations' }
  if ([string]::IsNullOrWhiteSpace($ExpectedVersion) -or $ExpectedVersion -notmatch '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$') { Fail 'ExpectedVersion is required for installer operations' }
  if ($token.is_system) { $context = 'qga-system-unattended-smoke' } elseif ($token.is_interactive) { $context = 'interactive-guest-token' } else { Fail 'installer operation requires interactive guest token or explicit SYSTEM smoke lane' }
  $beforeHash = (Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash.ToLowerInvariant(); if ($beforeHash -ne $ExpectedSha256.ToLowerInvariant()) { Fail 'uploaded artifact hash differs from planned hash' }
  $beforeVersion = Get-InstalledVersion; $arguments = @('--accept-messages','--accept-licenses','--confirm-command','install','AmneziaSelfHostedUpdate=true'); $process = Start-Process -FilePath $artifact -ArgumentList $arguments -PassThru -Wait -WindowStyle Hidden
  if ($process.ExitCode -ne 0) { Fail "Windows installer exited with $($process.ExitCode)" }
  $assertion = Get-Assertion $artifact $beforeHash $context (Get-ServiceSnapshot) $userData (Get-RecoveryState); $assertion.interactive_passed = [bool]($token.is_interactive -and -not $token.is_system); $assertion.interactive_evidence_required = $true
  $steps += [ordered]@{ id = $Action; passed = $true; exit_code = [int]$process.ExitCode; before_version = $beforeVersion; after_version = $assertion.installed_version; execution_context = $context }; Write-Receipt $assertion $token $steps; $assertion | ConvertTo-Json -Compress; exit 0
} catch {
  $errorText = $_.Exception.Message; $failure = [ordered]@{ passed = $false; run_id = $RunId; profile = $Profile; action = $Action; error = $errorText; token = $token; observed_at = [DateTime]::UtcNow.ToString('o') }
  try { Write-Receipt $failure $token @([ordered]@{ id = $Action; passed = $false; error = $errorText }) } catch { }
  $failure | ConvertTo-Json -Compress; exit 1
}
