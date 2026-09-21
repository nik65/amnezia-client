[CmdletBinding()]
param(
  [Parameter(Mandatory = $true, Position = 0)] [ValidateSet('probe','reinstall','update','service-health','interactive-start','interactive-status','interactive-collect')] [string] $Action,
  [Parameter(Mandatory = $true, Position = 1)] [ValidateSet('windows-x64')] [string] $Profile,
  [string] $RunId,
  [string] $CaseId = 'default',
  [string] $ExpectedVersion,
  [string] $BaselineVersion,
  [string] $CandidateVersion,
  [string] $ExpectedSha256,
  [string] $ExpectedArtifactRole,
  [string] $ArtifactPath = 'C:\ProgramData\AmneziaLab\current.exe',
  [string] $ReceiptPath,
  [ValidateSet('qga','hyperv-powershell-direct')] [string] $Transport = 'qga',
  [string] $GuestMarkerPath = 'C:\ProgramData\AmneziaLab\run-marker.txt',
  [string] $GuestRoot,
  [string] $LauncherPath,
  [string] $LauncherSha256,
  [string] $InteractiveTaskName = 'AmneziaLab-InteractiveInstaller',
  [string] $TokenEvidencePath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

function Fail([string] $Message) { throw $Message }
function Write-Milestone([string] $Phase, [object] $Data = $null) {
  if ([string]::IsNullOrWhiteSpace($GuestRoot)) { return }
  $path = Join-Path $GuestRoot 'runner-milestones.jsonl'
  $record = [ordered]@{ schema = 1; run_id = $RunId; case_id = $CaseId; action = $Action; phase = $Phase; utc = [DateTime]::UtcNow.ToString('o'); data = $Data }
  try { Add-Content -LiteralPath $path -Value ($record | ConvertTo-Json -Compress -Depth 8) -Encoding UTF8 } catch { }
}
function Assert-RunId {
  if ([string]::IsNullOrWhiteSpace($RunId) -or $RunId -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$') { Fail 'RunId is required and must be a bounded lab identifier' }
  if ([string]::IsNullOrWhiteSpace($CaseId) -or $CaseId -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$') { Fail 'CaseId is required and must be bounded' }
}
function Get-ArtifactRole {
  if (-not [string]::IsNullOrWhiteSpace($ExpectedArtifactRole)) {
    if ($ExpectedArtifactRole -notin @('baseline','candidate')) { Fail 'ExpectedArtifactRole must be baseline or candidate' }
    return $ExpectedArtifactRole
  }
  if ($Action -eq 'reinstall') { return 'baseline' }
  return 'candidate'
}
function Assert-ArtifactPath {
  $resolved = [IO.Path]::GetFullPath($ArtifactPath)
  $qgaPath = 'C:\ProgramData\AmneziaLab\current.exe'
  $hypervPath = if ($GuestRoot) { Join-Path $GuestRoot 'current.exe' } else { "C:\ProgramData\AmneziaLab\runs\$RunId\$Profile\current.exe" }
  if (($Transport -eq 'qga' -and $resolved -ne $qgaPath) -or ($Transport -eq 'hyperv-powershell-direct' -and $resolved -ne $hypervPath)) { Fail 'ArtifactPath is outside the controller-owned guest path' }
  if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) { Fail 'controller-owned guest artifact is missing' }
  return $resolved
}
function Assert-GuestMarker {
  $resolved = [IO.Path]::GetFullPath($GuestMarkerPath)
  $expected = "amnezia-release-lab:${RunId}:${Profile}"
  if ($Transport -eq 'qga' -and $resolved -ne 'C:\ProgramData\AmneziaLab\run-marker.txt') { Fail 'QGA marker path is not controller-owned' }
  $expectedMarkerPath = if ($GuestRoot) { Join-Path $GuestRoot 'run-marker.txt' } else { "C:\ProgramData\AmneziaLab\runs\$RunId\$Profile\run-marker.txt" }
  if ($Transport -eq 'hyperv-powershell-direct' -and $resolved -ne $expectedMarkerPath) { Fail 'Hyper-V marker path is not run-scoped' }
  if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) { Fail 'guest run marker is missing' }
  $text = (Get-Content -LiteralPath $resolved -Raw).Trim()
  if ($text -notmatch "(?m)^$([regex]::Escape($expected))\s*$") { Fail 'guest run marker does not identify this run/profile' }
  if ($Transport -eq 'hyperv-powershell-direct' -and $text -notmatch "(?m)^case_id=$([regex]::Escape($CaseId))\s*$") { Fail 'guest run marker does not identify this Hyper-V case' }
  return $text
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
function Get-InstallerUserData([object] $activeProfile, [DateTime] $SinceUtc = [DateTime]::MinValue) {
  if ($null -eq $activeProfile) {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent(); $sid = if ($identity.User) { [string]$identity.User.Value } else { '' }
    $fallback = @(Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue | Where-Object { [string]$_.SID -eq $sid } | Select-Object -First 1)
    if ($fallback.Count -eq 1) { $activeProfile = [ordered]@{ path = [string]$fallback[0].LocalPath; user = [string]$identity.Name; session_id = [System.Diagnostics.Process]::GetCurrentProcess().SessionId } }
    else { return [ordered]@{ available = $false; reason = 'no-current-user-profile' } }
  }
  $root = Join-Path $activeProfile.path 'AppData\Local\AmneziaVPN-InstallerLogs'
  $files = @(Get-ChildItem -LiteralPath $root -File -Filter 'installer-*.jsonl' -ErrorAction SilentlyContinue | Sort-Object LastWriteTimeUtc -Descending)
  $latest = if ($files.Count -gt 0) { $files[0] } else { $null }; $prefix = @()
  if ($null -ne $latest) { $prefix = @(Get-Content -LiteralPath $latest.FullName -TotalCount 20 -ErrorAction SilentlyContinue) }
  return [ordered]@{ available = $true; path = $root; latest = if ($latest) { $latest.Name } else { $null }; last_write_time_utc = if ($latest) { $latest.LastWriteTimeUtc.ToString('o') } else { $null }; fresh = [bool]($latest -and $latest.LastWriteTimeUtc -gt $SinceUtc); prefix = $prefix }
}
function Stop-ProcessTree([int] $RootPid) {
  $children = @(Get-CimInstance Win32_Process -Filter "ParentProcessId=$RootPid" -ErrorAction SilentlyContinue)
  foreach ($child in $children) { Stop-ProcessTree ([int]$child.ProcessId) }
  try { Stop-Process -Id $RootPid -Force -ErrorAction SilentlyContinue } catch { }
}
function Invoke-CapturedProcess([string] $FilePath, [string[]] $Arguments, [string] $OutputRoot, [int] $TimeoutMilliseconds) {
  $stdoutPath = Join-Path $OutputRoot 'installer.stdout.log'; $stderrPath = Join-Path $OutputRoot 'installer.stderr.log'
  foreach ($argument in $Arguments) { if ([string]$argument -notmatch '^[A-Za-z0-9.=:_-]+$') { Fail 'installer argument is outside the safe token contract' } }
  function Write-NativeLog([string] $Path, [string] $Value) { $tmp="$Path.tmp"; [IO.File]::WriteAllText($tmp,$Value,(New-Object Text.UTF8Encoding($false))); Move-Item -LiteralPath $tmp -Destination $Path -Force }
  $clock=[Diagnostics.Stopwatch]::StartNew()
  $info = New-Object Diagnostics.ProcessStartInfo
  $info.FileName = $FilePath; $info.Arguments = ($Arguments -join ' '); $info.UseShellExecute = $false; $info.CreateNoWindow = $true; $info.RedirectStandardOutput = $true; $info.RedirectStandardError = $true
  $proc = New-Object Diagnostics.Process; $proc.StartInfo = $info
  try { if (-not $proc.Start()) { Fail 'Windows installer process did not start' } } catch { Fail "Windows installer process failed to start: $($_.Exception.Message)" }
  $stdoutTask = $proc.StandardOutput.ReadToEndAsync(); $stderrTask = $proc.StandardError.ReadToEndAsync()
  $started = $proc.StartTime.ToUniversalTime().ToString('o'); $pidValue = [int]$proc.Id
  if (-not $proc.WaitForExit($TimeoutMilliseconds)) { Stop-ProcessTree $pidValue; Write-NativeLog $stdoutPath '[capture timed out before stdout drain]'; Write-NativeLog $stderrPath '[capture timed out before stderr drain]'; Fail 'installer exceeded the bounded 15 minute timeout' }
  $proc.Refresh(); $rawExitCode = $proc.ExitCode
  if ($null -eq $rawExitCode) { Fail 'Windows installer exit code is unavailable after process completion' }
  $remaining=[Math]::Max(0,$TimeoutMilliseconds-[int]$clock.ElapsedMilliseconds)
  $drained=[Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($stdoutTask,$stderrTask),$remaining)
  $stdout=if($stdoutTask.IsCompleted){[string]$stdoutTask.GetAwaiter().GetResult()}else{'[stdout drain exceeded process deadline]'}
  $stderr=if($stderrTask.IsCompleted){[string]$stderrTask.GetAwaiter().GetResult()}else{'[stderr drain exceeded process deadline]'}
  Write-NativeLog $stdoutPath $stdout; Write-NativeLog $stderrPath $stderr
  if(-not $drained){Fail 'installer output drain exceeded the bounded process deadline'}
  return [ordered]@{ pid=$pidValue; start_time=$started; exit_code=[int]$rawExitCode; stdout_path=$stdoutPath; stderr_path=$stderrPath; stdout=$stdout; stderr=$stderr }
}
function Write-PendingInstallerRequest([string] $Artifact, [string] $ArtifactHash) {
  if ([string]::IsNullOrWhiteSpace($GuestRoot)) { Fail 'interactive Hyper-V request requires a guest case root' }
  if ([string]::IsNullOrWhiteSpace($LauncherPath) -or -not (Test-Path -LiteralPath $LauncherPath -PathType Leaf)) { Fail 'trusted limited launcher is missing' }
  $launcherHash = (Get-FileHash -LiteralPath $LauncherPath -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($launcherHash -ne $LauncherSha256.ToLowerInvariant()) { Fail 'trusted limited launcher hash differs from planned source' }
  $requestPath = Join-Path $GuestRoot 'pending-installer.json'
  $taskName = "AmneziaLab-Interactive-$RunId-$CaseId"; if($taskName.Length -gt 200){$taskName=$taskName.Substring(0,200)}
  if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) { Fail 'owned interactive task name already exists' }
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent(); $userId = [string]$identity.Name
  $taskAction = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$LauncherPath`" -RunId $RunId -CaseId $CaseId -GuestRoot `"$GuestRoot`" -ArtifactPath `"$Artifact`" -ArtifactSha256 $ArtifactHash -PendingPath `"$requestPath`""
  $taskPrincipal = New-ScheduledTaskPrincipal -UserId $userId -LogonType Interactive -RunLevel Limited
  $taskSettings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 20) -MultipleInstances IgnoreNew
  Register-ScheduledTask -TaskName $taskName -Action $taskAction -Principal $taskPrincipal -Settings $taskSettings -Description 'Amnezia release lab case-owned limited interactive installer' -ErrorAction Stop | Out-Null
  try { Start-ScheduledTask -TaskName $taskName -ErrorAction Stop } catch { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue; throw }
  $deadline = (Get-Date).AddSeconds(30); $request = $null
  do {
    if (Test-Path -LiteralPath $requestPath -PathType Leaf) { try { $request = Get-Content -LiteralPath $requestPath -Raw | ConvertFrom-Json } catch { $request = $null } }
    if ($null -ne $request -and [string]$request.run_id -eq $RunId -and [string]$request.case_id -eq $CaseId -and [string]$request.artifact_sha256 -eq $ArtifactHash.ToLowerInvariant() -and [string]$request.state -eq 'waiting') { break }
    Start-Sleep -Milliseconds 250
  } while ((Get-Date) -lt $deadline)
  if ($null -eq $request) { Fail 'limited launcher did not create a bound pending request' }
  return $request
}
function Remove-InteractiveTask {
  $taskName = "AmneziaLab-Interactive-$RunId-$CaseId"; if($taskName.Length -gt 200){$taskName=$taskName.Substring(0,200)}
  try { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue } catch { }
  return ($null -eq (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue))
}
function Get-RecoveryState {
  $root = 'C:\Program Files\AmneziaVPN-Recovery'; $journal = Join-Path $root 'upgrade-service-journal.json'; $items = @()
  if (Test-Path -LiteralPath $root) {
    $items = @(Get-ChildItem -LiteralPath $root -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq 'upgrade-service-journal.json' -or $_.Name -like 'upgrade-service-journal.json.*' } | ForEach-Object { $acl = Get-Acl -LiteralPath $_.FullName -ErrorAction SilentlyContinue; [ordered]@{ name = $_.Name; length = [int64]$_.Length; reparse = [bool](($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0); owner = if ($acl) { [string]$acl.Owner } else { '' }; protected = if ($acl) { [bool]$acl.AreAccessRulesProtected } else { $false } } })
  }
  $rootAcl = Get-Acl -LiteralPath $root -ErrorAction SilentlyContinue
  return [ordered]@{ root = $root; root_exists = [bool](Test-Path -LiteralPath $root -PathType Container); journal_exists = [bool](Test-Path -LiteralPath $journal -PathType Leaf); root_owner = if ($rootAcl) { [string]$rootAcl.Owner } else { '' }; root_protected = if ($rootAcl) { [bool]$rootAcl.AreAccessRulesProtected } else { $false }; items = $items }
}
function Get-MapValue([object] $Object, [string] $Name) {
  if ($null -eq $Object) { return $null }
  if ($Object -is [Collections.IDictionary] -and $Object.Contains($Name)) { return $Object[$Name] }
  $property = $Object.PSObject.Properties[$Name]
  if ($null -ne $property) { return $property.Value }
  return $null
}
function Write-Receipt([object] $Assertion, [object] $Token, [object] $Steps) {
  Write-Milestone 'write-receipt-before'
  if ([string]::IsNullOrWhiteSpace($ReceiptPath)) { $ReceiptPath = "C:\ProgramData\AmneziaLab\runs\$RunId\receipt.json" }
  $parent = Split-Path -Parent $ReceiptPath; New-Item -ItemType Directory -Force -Path $parent | Out-Null
  $hasArtifactHash = $Assertion -and (($Assertion -is [Collections.IDictionary] -and $Assertion.Contains('artifact_sha256')) -or ($null -ne $Assertion.PSObject.Properties['artifact_sha256']))
  $hasInteractivePassed = $Assertion -and (($Assertion -is [Collections.IDictionary] -and $Assertion.Contains('interactive_passed')) -or ($null -ne $Assertion.PSObject.Properties['interactive_passed']))
  $receiptHash = if ($hasArtifactHash) { [string]$Assertion['artifact_sha256'] } else { '' }
  $interactiveVerified = if ($hasInteractivePassed) { [bool]$Assertion['interactive_passed'] } else { $false }
  $artifactRole = Get-ArtifactRole
  $artifactSize = if (Test-Path -LiteralPath $ArtifactPath -PathType Leaf) { [int64](Get-Item -LiteralPath $ArtifactPath).Length } else { 0 }
  $artifactSource = if ($Transport -eq 'qga') { 'qga-upload' } else { 'hyperv-powershell-direct-stage' }
  $safeToken = [ordered]@{}; foreach($name in @('name','user_sid','is_system','is_labadmin','is_administrator','is_interactive','session_id','source')){$value=Get-MapValue $Token $name;if($null -ne $value){$safeToken[$name]=if($value -is [string] -or $value -is [bool] -or $value -is [int] -or $value -is [long]){$value}else{[string]$value}}}
  $safeAssertion = [ordered]@{}; foreach($name in @('passed','run_id','profile','action','artifact','artifact_sha256','artifact_sha256_before','expected_sha256','expected_version','installed_version','execution_context','interactive_passed','interactive_evidence_required')){$value=Get-MapValue $Assertion $name;if($null -ne $value){if($name -eq 'execution_context' -and ($value -is [Collections.IDictionary] -or $null -ne $value.PSObject.Properties['name'])){$safeContext=[ordered]@{};foreach($field in @('name','user_sid','is_system','is_labadmin','is_administrator','is_interactive','session_id','source')){$contextValue=Get-MapValue $value $field;if($null -ne $contextValue){$safeContext[$field]=$contextValue}};$safeAssertion[$name]=$safeContext}elseif($value -is [string] -or $value -is [bool] -or $value -is [int] -or $value -is [long]){$safeAssertion[$name]=$value}else{$safeAssertion[$name]=[string]$value}}}
  $safeService=Get-MapValue $Assertion 'service';if($null -ne $safeService){$safeAssertion['service']=[ordered]@{present=[bool](Get-MapValue $safeService 'present');name=[string](Get-MapValue $safeService 'name');state=[string](Get-MapValue $safeService 'state');start_mode=[string](Get-MapValue $safeService 'start_mode');process_id=[int](Get-MapValue $safeService 'process_id')}}
  $safeUserData=Get-MapValue $Assertion 'installer_userdata';if($null -ne $safeUserData){$safeAssertion['installer_userdata']=[ordered]@{available=[bool](Get-MapValue $safeUserData 'available');path=[string](Get-MapValue $safeUserData 'path');latest=[string](Get-MapValue $safeUserData 'latest');last_write_time_utc=[string](Get-MapValue $safeUserData 'last_write_time_utc');fresh=[bool](Get-MapValue $safeUserData 'fresh')}}
  $safeCompletion=Get-MapValue $Assertion 'installer_completion';if($null -ne $safeCompletion){$safeAssertion['installer_completion']=[ordered]@{state=[string](Get-MapValue $safeCompletion 'state');installer_pid=[int](Get-MapValue $safeCompletion 'installer_pid');installer_start_time=[string](Get-MapValue $safeCompletion 'installer_start_time');exit_code=[int](Get-MapValue $safeCompletion 'exit_code');completed_at=[string](Get-MapValue $safeCompletion 'completed_at');fresh_logs=[bool](Get-MapValue $safeCompletion 'fresh_logs')}}
  $safeEvidence=Get-MapValue $Assertion 'interactive_evidence';if($null -ne $safeEvidence){$safeAssertion['interactive_evidence']=[ordered]@{schema=[int](Get-MapValue $safeEvidence 'schema');run_id=[string](Get-MapValue $safeEvidence 'run_id');profile=[string](Get-MapValue $safeEvidence 'profile');vm_id=[string](Get-MapValue $safeEvidence 'vm_id');interactive_token=[bool](Get-MapValue $safeEvidence 'interactive_token');session_id=[int](Get-MapValue $safeEvidence 'session_id');explorer_pid=[int](Get-MapValue $safeEvidence 'explorer_pid');screenshot_sha256=[string](Get-MapValue $safeEvidence 'screenshot_sha256');action=[string](Get-MapValue $safeEvidence 'action')}}
  $safeSteps=@($Steps|ForEach-Object{$step=$_;[ordered]@{id=[string](Get-MapValue $step 'id');passed=[bool](Get-MapValue $step 'passed');exit_code=if($null -ne (Get-MapValue $step 'exit_code')){[int](Get-MapValue $step 'exit_code')}else{$null};before_version=[string](Get-MapValue $step 'before_version');after_version=[string](Get-MapValue $step 'after_version');artifact_sha256=[string](Get-MapValue $step 'artifact_sha256');fresh_logs=if($null -ne (Get-MapValue $step 'fresh_logs')){[bool](Get-MapValue $step 'fresh_logs')}else{$null}}})
  $canonicalGuestMarker = "amnezia-release-lab:${RunId}:${Profile}"
  Write-Milestone 'write-receipt-assemble-before'; $receipt = [ordered]@{ schema = 1; run_id = $RunId; profile = $Profile; case_id = $CaseId; artifact = [IO.Path]::GetFileName($ArtifactPath); artifact_sha256 = $receiptHash; artifact_size = $artifactSize; artifact_role = $artifactRole; artifact_source = [ordered]@{ transport = $Transport; kind = $artifactSource; hash_verified = [bool]($receiptHash -and $ExpectedSha256 -and $receiptHash -eq $ExpectedSha256.ToLowerInvariant()) }; baseline_version = $BaselineVersion; candidate_version = $CandidateVersion; guest_marker = $canonicalGuestMarker; guest_marker_readback = $GuestMarker; transport = $Transport; origin = 'guest'; injected = $false; interactive_verified = $interactiveVerified; token = $safeToken; steps = $safeSteps; assertion = $safeAssertion; observed_at = [DateTime]::UtcNow.ToString('o') }; Write-Milestone 'write-receipt-assemble-after'
  Write-Milestone 'write-receipt-json-before'; $receiptJson = $receipt | ConvertTo-Json -Depth 12; Write-Milestone 'write-receipt-json-after' ([ordered]@{ length = $receiptJson.Length })
  $tmp = "$ReceiptPath.tmp"; Write-Milestone 'write-receipt-file-before'; [IO.File]::WriteAllText($tmp,$receiptJson,(New-Object Text.UTF8Encoding($false))); Write-Milestone 'write-receipt-file-after' ([ordered]@{ path = $tmp; length = (Get-Item -LiteralPath $tmp).Length }); Move-Item -LiteralPath $tmp -Destination $ReceiptPath -Force
  Write-Milestone 'write-receipt-after' ([ordered]@{ receipt_path = $ReceiptPath; artifact_sha256 = $receiptHash; interactive_verified = $interactiveVerified })
}
function Get-Assertion([string] $Artifact, [string] $BeforeHash, [string] $Context, [object] $Service, [object] $UserData, [object] $Recovery) {
  $afterHash = (Get-FileHash -LiteralPath $Artifact -Algorithm SHA256).Hash.ToLowerInvariant(); $afterVersion = Get-InstalledVersion
  if ($ExpectedSha256 -and $afterHash -ne $ExpectedSha256.ToLowerInvariant()) { Fail 'artifact hash changed after guest operation' }
  if ($ExpectedVersion -and $afterVersion -ne $ExpectedVersion) { Fail "installed version mismatch: expected $ExpectedVersion, observed $afterVersion" }
  return [ordered]@{ passed = $true; run_id = $RunId; profile = $Profile; action = $Action; artifact = [IO.Path]::GetFileName($Artifact); artifact_sha256 = $afterHash; artifact_sha256_before = $BeforeHash; expected_sha256 = $ExpectedSha256.ToLowerInvariant(); expected_version = $ExpectedVersion; installed_version = $afterVersion; execution_context = $Context; service = $Service; installer_userdata = $UserData; recovery = $Recovery; observed_at = [DateTime]::UtcNow.ToString('o') }
}

Assert-RunId
$GuestMarker = Assert-GuestMarker
$token = Get-TokenEvidence; $steps = @()
try {
  $marker = 'C:\ProgramData\AmneziaLab\READY'
  if (-not (Test-Path -LiteralPath $marker -PathType Leaf)) { Fail 'guest readiness marker missing' }
  if (-not ((Get-Content -LiteralPath $marker -Raw) -match 'candidate_credentials=absent')) { Fail 'candidate credentials marker missing' }
  $activeProfile = Get-ActiveUserProfile; $userData = Get-InstallerUserData $activeProfile
  if ($Action -eq 'interactive-start') {
    if ($null -eq $activeProfile) { Fail 'interactive-start requires a logged-in guest labadmin session' }
    if ($InteractiveTaskName -notmatch '^[A-Za-z0-9._-]{1,100}$') { Fail 'interactive task name is invalid' }
    $artifact = Assert-ArtifactPath; $artifactHash = (Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash.ToLowerInvariant(); if ($ExpectedSha256 -and $artifactHash -ne $ExpectedSha256.ToLowerInvariant()) { Fail 'interactive artifact hash differs from expected' }
    $pending = Write-PendingInstallerRequest $artifact $artifactHash
    $steps += [ordered]@{ id = 'interactive-start'; passed = $true; task = $InteractiveTaskName; expected_ui = @('replacement confirmation or unattended handoff', 'Windows UAC consent', 'service-preflight result') }
    $assertion = [ordered]@{ passed = $true; status = 'launch-requested'; artifact_sha256 = [string]$pending.artifact_sha256; pending_request = $pending; requested_by_token = $token; interactive_token = $false; interactive_evidence_required = $true; ui_coordinator_required = $true; expected_ui = $steps[0].expected_ui }
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
    if (-not $evidence.PSObject.Properties['vm_id'] -or [string]::IsNullOrWhiteSpace([string]$evidence.vm_id)) { Fail 'interactive token evidence lacks the child VM binding' }
    $pendingPath = Join-Path $GuestRoot 'pending-installer.json'; $pending = $null; $deadline = (Get-Date).AddMinutes(15)
    do {
      if (Test-Path -LiteralPath $pendingPath -PathType Leaf) { try { $pending = Get-Content -LiteralPath $pendingPath -Raw | ConvertFrom-Json } catch { $pending = $null } }
      if ($pending -and [string]$pending.run_id -eq $RunId -and [string]$pending.case_id -eq $CaseId -and [string]$pending.artifact_sha256 -eq $ExpectedSha256.ToLowerInvariant() -and [string]$pending.state -in @('completed','timeout')) { break }
      Start-Sleep -Seconds 2
    } while ((Get-Date) -lt $deadline)
    if ($null -eq $pending -or [string]$pending.state -notin @('completed','timeout')) { Fail 'interactive installer did not publish bounded completion state' }
    if ([string]$pending.state -ne 'completed' -or [int]$pending.exit_code -ne 0) { Fail "interactive installer completion failed with state=$($pending.state), exit=$($pending.exit_code)" }
    $startedAt = [DateTime]::MinValue; if ($pending.PSObject.Properties['created_at']) { try { $startedAt = ([DateTime]::Parse([string]$pending.created_at)).ToUniversalTime() } catch { $startedAt = [DateTime]::MinValue } }
    $userData = Get-InstallerUserData $activeProfile $startedAt
    $artifact = Assert-ArtifactPath; $beforeHash = (Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash.ToLowerInvariant(); $assertion = Get-Assertion $artifact $beforeHash 'interactive-qmp-coordinated' (Get-ServiceSnapshot) $userData (Get-RecoveryState); $assertion.interactive_passed = [bool]($evidence.interactive_token -and -not $token.is_system); $assertion.interactive_evidence = $evidence; $assertion.installer_completion = [ordered]@{ state = [string]$pending.state; installer_pid = [int]$pending.installer_pid; installer_start_time = if($pending.PSObject.Properties['installer_start_time']){[string]$pending.installer_start_time}else{''}; exit_code = [int]$pending.exit_code; completed_at = [string]$pending.completed_at; fresh_logs = [bool]$userData.fresh }
    $steps += [ordered]@{ id = 'interactive-collect'; passed = $true; token_evidence = $TokenEvidencePath; exit_code = [int]$pending.exit_code; fresh_logs = [bool]$userData.fresh }
    if (-not (Remove-InteractiveTask)) { Fail 'owned interactive scheduled task remained after completion' }
    Write-Receipt $assertion $token $steps; $assertion | ConvertTo-Json -Compress; exit 0
  }
  $artifact = Assert-ArtifactPath
  if ([string]::IsNullOrWhiteSpace($ExpectedSha256) -or $ExpectedSha256 -notmatch '^[0-9a-fA-F]{64}$') { Fail 'ExpectedSha256 is required for installer operations' }
  if ([string]::IsNullOrWhiteSpace($ExpectedVersion) -or $ExpectedVersion -notmatch '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$') { Fail 'ExpectedVersion is required for installer operations' }
  if ($token.is_system) { $context = 'qga-system-unattended-smoke' } elseif ($token.is_interactive) { $context = 'interactive-guest-token' } elseif ($Transport -eq 'hyperv-powershell-direct' -and $token.is_labadmin -and $token.is_administrator) { $context = 'hyperv-psdirect-admin-smoke' } else { Fail 'installer operation requires interactive guest token, Hyper-V labadmin admin smoke, or explicit SYSTEM smoke lane' }
  $beforeHash = (Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash.ToLowerInvariant(); if ($beforeHash -ne $ExpectedSha256.ToLowerInvariant()) { Fail 'uploaded artifact hash differs from planned hash' }
  Write-Milestone 'installed-version-before'; $beforeVersion = Get-InstalledVersion; Write-Milestone 'installed-version-after' ([ordered]@{ version = $beforeVersion })
  $startedAt = [DateTime]::UtcNow; $arguments = @('--verbose','--accept-messages','--accept-licenses','--confirm-command','install','AmneziaSelfHostedUpdate=true'); Write-Milestone 'start-process-before' ([ordered]@{ path = $artifact; artifact_sha256 = $ExpectedSha256 })
  $captured = Invoke-CapturedProcess $artifact $arguments $GuestRoot 900000
  $installerStdout = [string]$captured.stdout_path; $installerStderr = [string]$captured.stderr_path; $installerExitCode = [int]$captured.exit_code
  Write-Milestone 'start-process-after' ([ordered]@{ pid = [int]$captured.pid; start_time = [string]$captured.start_time; path = $artifact })
  Write-Milestone 'wait-for-exit-after' ([ordered]@{ pid = [int]$captured.pid; exit_code = $installerExitCode })
  if ($installerExitCode -ne 0) {
    $nativeOutput = @(); foreach ($nativePath in @($installerStdout,$installerStderr)) { if (Test-Path -LiteralPath $nativePath -PathType Leaf) { $nativeOutput += @(Get-Content -LiteralPath $nativePath -Tail 40 -ErrorAction SilentlyContinue) } }
    $nativeTail = (($nativeOutput -join ' ') -replace '(?i)(password|token|secret|private[_-]?key|key)\s*[:=]\s*[^,; ]+','$1=<redacted>')
    if ($nativeTail.Length -gt 2000) { $nativeTail = $nativeTail.Substring($nativeTail.Length - 2000) }
    Fail "Windows installer exited with $installerExitCode; native output: $nativeTail"
  }
  Write-Milestone 'installer-userdata-before'; $userData = Get-InstallerUserData $activeProfile $startedAt; Write-Milestone 'installer-userdata-after' ([ordered]@{ fresh = [bool]$userData.fresh; latest = $userData.latest })
  # The outer QtIFW bundle does not write the thin updater's custom JSONL log.
  # Bind its success to the launched process, exit code, installed version and
  # running service instead; thin cases still require their native fresh log.
  $isOuterCase = $CaseId -like 'outer-*'
  if (-not $userData.fresh -and -not $isOuterCase) { Fail 'installer produced no fresh post-install log' }
  Write-Milestone 'service-snapshot-before'; $serviceSnapshot = Get-ServiceSnapshot; Write-Milestone 'service-snapshot-after' $serviceSnapshot
  if (-not $serviceSnapshot.present -or $serviceSnapshot.state -ne 'Running' -or [int]$serviceSnapshot.process_id -le 0) { Fail 'installed AmneziaVPN service is not running' }
  Write-Milestone 'assertion-before'; $assertion = Get-Assertion $artifact $beforeHash $context $serviceSnapshot $userData (Get-RecoveryState); Write-Milestone 'assertion-after' ([ordered]@{ installed_version = $assertion.installed_version; artifact_sha256 = $assertion.artifact_sha256 }); $assertion.interactive_passed = [bool]($token.is_interactive -and -not $token.is_system); $assertion.interactive_evidence_required = $true
  $assertion.installer_completion = [ordered]@{ state = 'completed'; installer_pid = [int]$captured.pid; installer_start_time = [string]$captured.start_time; exit_code = $installerExitCode; completed_at = [DateTime]::UtcNow.ToString('o'); fresh_logs = [bool]$userData.fresh }
  $steps += [ordered]@{ id = $Action; passed = $true; exit_code = $installerExitCode; before_version = $beforeVersion; after_version = $assertion.installed_version; execution_context = $context; fresh_logs = [bool]$userData.fresh }; Write-Receipt $assertion $token $steps; $assertion | ConvertTo-Json -Compress; exit 0
} catch {
  if ($Action -in @('interactive-start','interactive-collect')) { try { [void](Remove-InteractiveTask) } catch { } }
  $errorText = $_.Exception.Message; $failureHash = ''; $failureSize = 0; if(Test-Path -LiteralPath $ArtifactPath -PathType Leaf){try{$failureHash=(Get-FileHash -LiteralPath $ArtifactPath -Algorithm SHA256).Hash.ToLowerInvariant();$failureSize=[int64](Get-Item -LiteralPath $ArtifactPath).Length}catch{}}; $expectedFailureHash=[string]$ExpectedSha256; if([string]::IsNullOrWhiteSpace($failureHash)){$failureHash=$expectedFailureHash.ToLowerInvariant()}; $failure = [ordered]@{ passed = $false; run_id = $RunId; profile = $Profile; case_id = $CaseId; action = $Action; artifact = [IO.Path]::GetFileName($ArtifactPath); artifact_sha256 = $failureHash; artifact_sha256_before = $failureHash; expected_sha256 = $expectedFailureHash.ToLowerInvariant(); artifact_size = $failureSize; artifact_role = Get-ArtifactRole; baseline_version = $BaselineVersion; candidate_version = $CandidateVersion; guest_marker = "amnezia-release-lab:${RunId}:${Profile}"; error = $errorText; token = $token; observed_at = [DateTime]::UtcNow.ToString('o'); post_failure_baseline = [ordered]@{ installed_version = Get-InstalledVersion; service = Get-ServiceSnapshot; recovery = Get-RecoveryState } }
  try { Write-Receipt $failure $token @([ordered]@{ id = $Action; passed = $false; error = $errorText }) } catch { }
  $failure | ConvertTo-Json -Compress; exit 1
}
