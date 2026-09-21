param(
    [Parameter(Mandatory=$true)][ValidateSet('prepare','create','start','probe','install-baseline','test-update','collect','reset')][string]$Command,
    [string]$LabRoot = '',
    [string]$SdkRoot = '',
    [string]$RunId = '',
    [int]$ApiLevel = 35,
    [int]$AdbPort = 5041,
    [int]$EmulatorPort = 5580,
    [string]$GpuMode = 'swangle',
    [Parameter(ValueFromRemainingArguments=$true)][string[]]$Arguments = @(),
    [string]$ControllerReceiptPath = '',
    [string]$BaselineVersion = '',
    [string]$ReleaseVersion = '',
    [string]$ProductGo = '',
    [int]$ExpectedVersionCode = 0,
    [int]$ExpectedReleaseVersionCode = 0,
    [int]$FixtureHostPort = 0,
    [string]$ReleaseManifestPath = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$profileId = 'android-arm64-v8a'
$runId = if ($RunId) { $RunId } else { [string]$env:AMNEZIA_ANDROID_LAB_RUN_ID }
$labRoot = if ($LabRoot) { $LabRoot } else { [string]$env:AMNEZIA_ANDROID_WINDOWS_LAB_ROOT }
$sdkRoot = if ($SdkRoot) { $SdkRoot } else { [string]$env:AMNEZIA_ANDROID_WINDOWS_SDK_ROOT }
$apiLevel = if ($PSBoundParameters.ContainsKey('ApiLevel')) { $ApiLevel } elseif ($env:AMNEZIA_ANDROID_API_LEVEL) { [int]$env:AMNEZIA_ANDROID_API_LEVEL } else { 35 }
$adbPort = if ($PSBoundParameters.ContainsKey('AdbPort')) { $AdbPort } elseif ($env:AMNEZIA_ANDROID_ADB_PORT) { [int]$env:AMNEZIA_ANDROID_ADB_PORT } else { 5041 }
$emulatorPort = if ($PSBoundParameters.ContainsKey('EmulatorPort')) { $EmulatorPort } elseif ($env:AMNEZIA_ANDROID_EMULATOR_PORT) { [int]$env:AMNEZIA_ANDROID_EMULATOR_PORT } else { 5580 }
$gpuMode = if ($PSBoundParameters.ContainsKey('GpuMode')) { $GpuMode } elseif ($env:AMNEZIA_ANDROID_GPU_MODE) { [string]$env:AMNEZIA_ANDROID_GPU_MODE } else { 'swangle' }
$avdName = if ($env:AMNEZIA_ANDROID_AVD_NAME) { [string]$env:AMNEZIA_ANDROID_AVD_NAME } else { "amnezia-release-api$apiLevel-$runId" }
$serial = "emulator-$emulatorPort"
$imagePackage = "system-images;android-$apiLevel;google_apis;x86_64"
$runRoot = Join-Path $labRoot $runId
$proofRoot = Join-Path (Join-Path $labRoot 'proofs') $runId
$privateUserHome = Join-Path $labRoot 'user-home'
$avdHome = Join-Path $privateUserHome 'avd'
$workRoot = Join-Path $runRoot 'work'
$receiptRoot = Join-Path $runRoot 'receipts'
$ownershipPath = Join-Path $runRoot 'ownership.json'
$preflightPath = Join-Path $proofRoot 'native-preflight.json'
$probePath = Join-Path $proofRoot 'os-probe.json'
$environmentProofPath = Join-Path $proofRoot 'private-environment.json'
$controllerReceiptPath = if($ControllerReceiptPath){$ControllerReceiptPath}elseif($env:AMNEZIA_ANDROID_LAB_CONTROLLER_RECEIPT){[string]$env:AMNEZIA_ANDROID_LAB_CONTROLLER_RECEIPT}else{Join-Path $runRoot "receipts\controller\$runId\$profileId.json"}
$controllerBaselineReceiptPath = Join-Path (Split-Path -Parent $controllerReceiptPath) "$profileId-baseline.json"
$creationIntentPath = Join-Path $proofRoot 'creation-intent.json'
$runLockPath = Join-Path $runRoot '.native-run.lock'
$externalLockPath = Join-Path (Join-Path $labRoot 'locks') "$runId.lock"
$emulator = Join-Path $sdkRoot 'emulator\emulator.exe'
$qemu = Join-Path $sdkRoot 'emulator\qemu\windows-x86_64\qemu-system-x86_64-headless.exe'
$adb = Join-Path $sdkRoot 'platform-tools\adb.exe'
$avdManager = Join-Path $sdkRoot 'cmdline-tools\latest\bin\avdmanager.bat'
$systemImage = Join-Path $sdkRoot "system-images\android-$apiLevel\google_apis\x86_64"
$avdDir = Join-Path $avdHome "$avdName.avd"
$pidPath = Join-Path $workRoot 'emulator.pid'
$adbPidPath = Join-Path $workRoot 'adb-server.pid'
$guestMarkerPath = '/data/local/tmp/amnezia-release-lab-state-marker.txt'
$privateEmulatorHome = Join-Path $labRoot 'emulator-home'
$privateAdbKeys = Join-Path $workRoot 'adb-keys'

function Fail([string]$Message) { throw "android-lab-windows: $Message" }
function Assert-Path([string]$Path,[string]$Label) {
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { Fail "$Label is missing: $Path" }
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { Fail "$Label is a reparse point: $Path" }
}
function Assert-Root {
    if ([string]::IsNullOrWhiteSpace($runId) -or $runId -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$') { Fail 'run id is invalid' }
    if ([string]::IsNullOrWhiteSpace($labRoot) -or [string]::IsNullOrWhiteSpace($sdkRoot)) { Fail 'private Windows lab root and SDK root are required' }
    $resolved = [IO.Path]::GetFullPath($labRoot)
    $expectedParent = [IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'AmneziaReleaseLab'))
    $workspacePrivate = [IO.Path]::GetFullPath((Join-Path $env:USERPROFILE 'PycharmProjects'))
    $isWslRoot = $resolved -like '\\wsl$\*'
    if ($resolved -match '(?i)\\Temp(\\|$)' -or (-not $isWslRoot -and $resolved -notlike "$expectedParent\android-native*" -and $resolved -notlike "$workspacePrivate\android-release-lab-native*")) { Fail 'private Windows lab root is outside the dedicated private lab directories' }
    if (Test-Path -LiteralPath $resolved) { Assert-NoReparseTree $resolved }
    if (Test-Path -LiteralPath $sdkRoot) { Assert-NoReparseTree $sdkRoot }
    foreach($directory in @($resolved,$sdkRoot)) {
        if(-not (Test-Path -LiteralPath $directory -PathType Container)){continue}
        if($isWslRoot -and $directory -eq $resolved){continue}
        $acl = Get-Acl -LiteralPath $directory
        $userSid = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
        foreach($access in $acl.Access){$sid=$access.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value;if($access.AccessControlType -eq 'Allow' -and $sid -notin @($userSid,'S-1-5-18','S-1-5-32-544')){Fail "private directory ACL grants unexpected identity: $directory"}}
    }
    if ($adbPort -eq 5037 -or $adbPort -lt 5038 -or $adbPort -gt 5100) { Fail 'ADB port is not dedicated' }
    if ($emulatorPort -lt 5554 -or $emulatorPort -gt 5682 -or ($emulatorPort % 2) -ne 0) { Fail 'emulator port is invalid' }
    if ($gpuMode -notmatch '^(auto|host|software|lavapipe|swiftshader|swangle)$') { Fail 'GPU mode is not allowlisted' }
}
function Assert-NoReparseTree([string]$Path) {
    if(Test-Path -LiteralPath $Path) {
        $item=Get-Item -LiteralPath $Path -Force
        if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){Fail "private path is a reparse point: $Path"}
        if($item.PSIsContainer){foreach($child in Get-ChildItem -LiteralPath $Path -Force -Recurse){if($child.Attributes -band [IO.FileAttributes]::ReparsePoint){Fail "private child path is a reparse point: $($child.FullName)"}}}
    }
}
function Sha([string]$Path) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
function Tree-Sha([string]$Path) {
    $root = [IO.Path]::GetFullPath($Path)
    $lines = @()
    foreach($file in @(Get-ChildItem -LiteralPath $root -Recurse -File -Force | Sort-Object FullName)) {
        if($file.Attributes -band [IO.FileAttributes]::ReparsePoint){Fail "system image contains a reparse point: $($file.FullName)"}
        $relative = $file.FullName.Substring($root.Length).TrimStart([char]92,[char]47)
        $lines += "$relative|$($file.Length)|$(Sha $file.FullName)"
    }
    $bytes = [Text.Encoding]::UTF8.GetBytes(($lines -join "`n") + "`n")
    ([BitConverter]::ToString(([Security.Cryptography.SHA256]::Create()).ComputeHash($bytes))).Replace('-','').ToLowerInvariant()
}
function Acquire-RunLock {
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $externalLockPath) | Out-Null
    try { return [IO.File]::Open($externalLockPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None) }
    catch [IO.IOException] {
        try { $stale=[IO.File]::Open($externalLockPath,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None); $stale.Dispose(); [IO.File]::Delete($externalLockPath); return [IO.File]::Open($externalLockPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None) }
        catch { Fail "native run lock is already held: $externalLockPath" }
    }
}
function Set-PrivateEnvironment {
    New-Item -ItemType Directory -Force -Path $privateUserHome,$privateEmulatorHome,$privateAdbKeys | Out-Null
    $env:ANDROID_SDK_ROOT=$sdkRoot
    $env:ANDROID_HOME=$sdkRoot
    $env:ANDROID_USER_HOME=$privateUserHome
    $env:ANDROID_SDK_HOME=$privateUserHome
    $env:ANDROID_EMULATOR_HOME=$privateEmulatorHome
    $env:ANDROID_AVD_HOME=$avdHome
    $env:ADB_VENDOR_KEYS=$privateAdbKeys
    Remove-Item Env:ADB_SERVER_SOCKET -ErrorAction SilentlyContinue
}
function Write-PrivateJson([string]$Path,[object]$Value) {
    $parent = Split-Path -Parent $Path
    New-Item -ItemType Directory -Force -Path $parent | Out-Null
    if (Test-Path -LiteralPath $Path) { Fail "refusing to replace immutable native evidence: $Path" }
    $tmp = "$Path.$([guid]::NewGuid().ToString('N')).tmp"
    $json = ($Value | ConvertTo-Json -Depth 20) + [Environment]::NewLine
    [IO.File]::WriteAllText($tmp,$json,(New-Object Text.UTF8Encoding($false)))
    Move-Item -LiteralPath $tmp -Destination $Path
}
function Write-PrivateText([string]$Path,[string]$Value) {
    $parent = Split-Path -Parent $Path
    New-Item -ItemType Directory -Force -Path $parent | Out-Null
    if (Test-Path -LiteralPath $Path) { Fail "refusing to replace immutable native evidence: $Path" }
    $tmp = "$Path.$([guid]::NewGuid().ToString('N')).tmp"
    [IO.File]::WriteAllText($tmp,$Value,(New-Object Text.UTF8Encoding($false)))
    Move-Item -LiteralPath $tmp -Destination $Path
}
function Read-PrivateJson([string]$Path,[string]$Label) {
    Assert-Path $Path $Label
    try { return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json } catch { Fail "$Label is invalid JSON" }
}
function Invoke-Captured([string]$File,[string[]]$Arguments,[hashtable]$Environment=$null) {
    $old = @{}
    if ($null -ne $Environment) { foreach($key in $Environment.Keys) { $old[$key] = [Environment]::GetEnvironmentVariable($key); [Environment]::SetEnvironmentVariable($key,[string]$Environment[$key],'Process') } }
    try {
        $psi = [Diagnostics.ProcessStartInfo]::new()
        $psi.FileName=$File; $psi.UseShellExecute=$false; $psi.CreateNoWindow=$true; $psi.RedirectStandardOutput=$true; $psi.RedirectStandardError=$true
        $quote = { param($v); if([string]$v -notmatch '[\s"]'){return [string]$v}; return '"'+([string]$v).Replace('"','\\"')+'"' }
        $psi.Arguments = (@($Arguments | ForEach-Object { & $quote $_ }) -join ' ')
        $process=[Diagnostics.Process]::new(); $process.StartInfo=$psi
        if(-not $process.Start()){Fail "could not start command: $File"}
        $stdoutTask=$process.StandardOutput.ReadToEndAsync(); $stderrTask=$process.StandardError.ReadToEndAsync()
        if(-not $process.WaitForExit(120000)) { try{$process.Kill()}catch{}; throw "bounded command timeout: $File" }
        $process.WaitForExit(); $output=($stdoutTask.Result + [Environment]::NewLine + $stderrTask.Result).Trim()
        return [ordered]@{ exit_code=$process.ExitCode; output=$output }
    } finally {
        if ($null -ne $Environment) { foreach($key in $Environment.Keys) { [Environment]::SetEnvironmentVariable($key,$old[$key],'Process') } }
    }
}
function Invoke-Adb([string[]]$Arguments) { Invoke-Captured $adb (@('-L',"tcp:$adbPort") + $Arguments) }
function Parse-WindowsArgv([string]$CommandLine) {
    $tokens = @()
    foreach($match in [regex]::Matches($CommandLine,'"([^"]*)"|(\S+)')) { $tokens += if($match.Groups[1].Success){$match.Groups[1].Value}else{$match.Groups[2].Value} }
    return $tokens
}
function Find-OwnedProcess([string]$Path,[string[]]$RequiredArgs) {
    $full = [IO.Path]::GetFullPath($Path)
    @(Get-CimInstance Win32_Process -Filter "Name='$([IO.Path]::GetFileName($full))'" -ErrorAction SilentlyContinue | Where-Object {
        $argv = @(Parse-WindowsArgv ([string]$_.CommandLine))
        [string]$_.ExecutablePath -ieq $full -and @($RequiredArgs | Where-Object { $argv -notcontains $_ }).Count -eq 0
    } | Select-Object -First 1)
}
function Process-Identity([int]$ProcessId,[string]$Path,[string[]]$RequiredArgs,[string]$Label) {
    $p = Get-CimInstance Win32_Process -Filter "ProcessId=$ProcessId" -ErrorAction SilentlyContinue
    $argv = if($null -ne $p){@(Parse-WindowsArgv ([string]$p.CommandLine))}else{@()}
    if ($null -eq $p -or [string]$p.ExecutablePath -ine [IO.Path]::GetFullPath($Path) -or @($RequiredArgs | Where-Object { $argv -notcontains $_ }).Count -ne 0) { Fail "$Label identity is not owned" }
    $start = (Get-Process -Id $ProcessId -ErrorAction Stop).StartTime.ToUniversalTime().Ticks
    [ordered]@{ pid=$ProcessId; start_time_utc_ticks=$start; executable=[IO.Path]::GetFullPath($Path); executable_sha256=(Sha $Path); command_line=[string]$p.CommandLine }
}
function Prepare {
    Assert-Root; Set-PrivateEnvironment
    Assert-Path $emulator 'native emulator'
    Assert-Path $qemu 'native QEMU'
    Assert-Path $adb 'native ADB'
    Assert-Path $avdManager 'native avdmanager'
    if (-not (Test-Path -LiteralPath $systemImage -PathType Container)) { Fail "pinned x86_64 system image is missing: $imagePackage" }
    $accel = Invoke-Captured $emulator @('-accel-check')
    $record = [ordered]@{ schema=1; run_id=$runId; profile=$profileId; backend='android-windows'; sdk_root=$sdkRoot; emulator=$emulator; emulator_sha256=(Sha $emulator); qemu=$qemu; qemu_sha256=(Sha $qemu); adb=$adb; adb_sha256=(Sha $adb); avd_manager=$avdManager; avd_manager_sha256=(Sha $avdManager); image_package=$imagePackage; image_path=$systemImage; image_tree_sha256=(Tree-Sha $systemImage); gpu_mode=$gpuMode; adb_port=$adbPort; emulator_port=$emulatorPort; accel_check=$accel; captured_at=[DateTime]::UtcNow.ToString('o') }
    if ($accel.exit_code -ne 0 -or $accel.output -notmatch '(?i)WHPX.*(installed and usable|usable)') { Fail "WHPX accelerator check failed: $($accel.output)" }
    if (Test-Path -LiteralPath $preflightPath) {
        $existing = Read-PrivateJson $preflightPath 'native preflight receipt'
        if ($existing.sdk_root -ne $record.sdk_root -or $existing.image_path -ne $record.image_path -or $existing.image_tree_sha256 -ne $record.image_tree_sha256 -or $existing.avd_manager_sha256 -ne $record.avd_manager_sha256 -or $existing.emulator_sha256 -ne $record.emulator_sha256 -or $existing.qemu_sha256 -ne $record.qemu_sha256 -or $existing.adb_sha256 -ne $record.adb_sha256 -or $existing.image_package -ne $record.image_package -or $existing.accel_check.output -notmatch '(?i)WHPX.*(installed and usable|usable)') { Fail 'immutable native preflight receipt differs from current tools/image mapping' }
        return $existing
    }
    Write-PrivateJson $preflightPath $record
    $record
}
function Create-AVD {
    Assert-Root; $preflight = Prepare
    if(Test-Path -LiteralPath $ownershipPath) {
        $existingMarker=Read-PrivateJson $ownershipPath 'native ownership marker'
        if($existingMarker.state -eq 'created' -and $existingMarker.run_id -eq $runId -and $existingMarker.profile -eq $profileId -and $existingMarker.image_tree_sha256 -eq $preflight.image_tree_sha256 -and $existingMarker.config_sha256 -and $existingMarker.avd_name -eq $avdName){return $existingMarker}
        Fail 'native ownership marker already exists with a non-reusable state'
    }
    New-Item -ItemType Directory -Force -Path $avdHome,$runRoot,$workRoot,$receiptRoot | Out-Null
    Assert-NoReparseTree $runRoot
    if(Test-Path -LiteralPath (Join-Path $runRoot 'ownership.json')){Fail 'native ownership marker already exists; refusing duplicate owner'}
    Write-PrivateJson $creationIntentPath ([ordered]@{schema=1;run_id=$runId;profile=$profileId;backend='android-windows';avd_name=$avdName;image_package=$imagePackage;created_at=[DateTime]::UtcNow.ToString('o')})
    $env:ANDROID_AVD_HOME = $avdHome
    $configDir = Join-Path $avdHome "$avdName.avd"
    if (-not (Test-Path -LiteralPath $configDir -PathType Container)) {
        $env:ANDROID_AVD_HOME=$null; $env:ANDROID_SDK_HOME=$null; $env:ANDROID_USER_HOME=$privateUserHome
        try { $avdOutput = @('no') | & $avdManager create avd -n $avdName -k $imagePackage --force 2>&1; $avdCode = $LASTEXITCODE } catch { $avdOutput = @($_.Exception.Message); $avdCode = 1 }
        Set-PrivateEnvironment
        if ($avdCode -ne 0) {
            $partialConfig = Join-Path $configDir 'config.ini'; $validPartial = $false
            if(Test-Path -LiteralPath $partialConfig -PathType Leaf) { $partialText=Get-Content -LiteralPath $partialConfig -Raw; $validPartial=($partialText -match '(?m)^target=android-35\s*$' -and $partialText -match '(?m)^abi\.type=x86_64\s*$') }
            if (-not $validPartial) { Fail "avdmanager create failed: $(@($avdOutput) -join [Environment]::NewLine)" }
        }
    }
    $config = Join-Path $configDir 'config.ini'
    Assert-Path $config 'private AVD config'
    $ini = Join-Path $avdHome "$avdName.ini"
    if (-not (Test-Path -LiteralPath $ini -PathType Leaf)) {
        @("avd.ini.encoding=UTF-8", "path=$configDir", "path.rel=avd\$avdName.avd", "target=android-$apiLevel") | Set-Content -LiteralPath $ini -Encoding UTF8
    }
    $nonce = [guid]::NewGuid().ToString('D')
    $marker = [ordered]@{ schema=1; run_id=$runId; profile=$profileId; backend='android-windows'; transport='android-adapter'; origin='guest'; injected=$false; sdk_root=$sdkRoot; avd_home=$avdHome; avd_name=$avdName; serial=$serial; adb_port=$adbPort; emulator_port=$emulatorPort; image_package=$imagePackage; image_tree_sha256=$preflight.image_tree_sha256; avd_manager_sha256=$preflight.avd_manager_sha256; config_path=$config; config_sha256=(Sha $config); identity_nonce=$nonce; state='created'; created_at=[DateTime]::UtcNow.ToString('o') }
    Write-PrivateJson $ownershipPath $marker
    $marker
}
function Start-Emulator {
    Set-PrivateEnvironment
    $marker = Read-PrivateJson $ownershipPath 'native ownership marker'
    if ($marker.run_id -ne $runId -or $marker.profile -ne $profileId -or $marker.backend -ne 'android-windows') { Fail 'native ownership marker mismatch' }
    if ($marker.state -ne 'created') { Fail "refusing repeated native start for marker state '$($marker.state)'" }
    $logOut = Join-Path $workRoot 'emulator.stdout.log'; $logErr = Join-Path $workRoot 'emulator.stderr.log'
    $args = @('-avd',$avdName,'-sysdir',$systemImage,'-datadir',$avdDir,'-port',[string]$emulatorPort,'-no-window','-no-audio','-no-boot-anim','-no-snapshot','-no-snapshot-save','-gpu',$gpuMode,'-no-metrics','-accel','on','-qemu','-uuid',$marker.identity_nonce)
    $env:ANDROID_SDK_ROOT = $sdkRoot; $env:ANDROID_HOME = $sdkRoot; $env:ANDROID_AVD_HOME = $avdHome; $env:ANDROID_ADB_SERVER_PORT = [string]$adbPort
    $quotedArgs = (@($args | ForEach-Object { '"' + ([string]$_).Replace('"','\"') + '"' }) -join ' ')
    $cmdLine = "/d /c start `"`" /b `"$emulator`" $quotedArgs > `"$logOut`" 2> `"$logErr`""
    Start-Process -FilePath "$env:WINDIR\System32\cmd.exe" -ArgumentList $cmdLine -WindowStyle Hidden | Out-Null
    $emu = $null
    for($i=0;$i -lt 120;$i++){ Start-Sleep -Milliseconds 500; $emu = Find-OwnedProcess $emulator @('-avd',$avdName,'-port',[string]$emulatorPort); if($null -ne $emu){break} }
    if($null -eq $emu){ Fail "owned native emulator process did not appear; see $logErr" }
    $emuIdentity = Process-Identity ([int]$emu.ProcessId) $emulator @('-avd',$avdName,'-port',[string]$emulatorPort) 'emulator'
    $qemuProcess = $null
    for($i=0;$i -lt 30;$i++){ Start-Sleep -Milliseconds 200; $qemuProcess = Find-OwnedProcess $qemu @('-avd',$avdName,'-port',[string]$emulatorPort); if($null -ne $qemuProcess){break} }
    if($null -eq $qemuProcess){ Fail 'owned native QEMU process did not appear' }
    $qemuIdentity = Process-Identity ([int]$qemuProcess.ProcessId) $qemu @('-avd',$avdName,'-port',[string]$emulatorPort) 'QEMU'
    $adbResult = Invoke-Adb @('start-server')
    if($adbResult.exit_code -ne 0){ Fail "dedicated ADB start failed: $($adbResult.output)" }
    $adbProc = $null
    for($i=0;$i -lt 30;$i++){ Start-Sleep -Milliseconds 200; $adbProc = Find-OwnedProcess $adb @('-L',"tcp:$adbPort"); if($null -ne $adbProc){break} }
    if($null -eq $adbProc){ Fail 'dedicated ADB process did not appear' }
    $adbIdentity = Process-Identity ([int]$adbProc.ProcessId) $adb @('-L',"tcp:$adbPort") 'ADB server'
    $deadline = (Get-Date).AddSeconds(180)
    do { $state = Invoke-Adb @('-s',$serial,'get-state'); if($state.exit_code -eq 0 -and $state.output.Trim() -eq 'device'){break}; Start-Sleep -Seconds 2 } while((Get-Date) -lt $deadline)
    if($state.exit_code -ne 0 -or $state.output.Trim() -ne 'device'){Fail "owned emulator did not become online: $($state.output)"}
    $deadline = (Get-Date).AddSeconds(180)
    do { $boot = Invoke-Adb @('-s',$serial,'shell','getprop','sys.boot_completed'); if($boot.exit_code -eq 0 -and $boot.output.Trim() -match '(?m)^1$'){break}; Start-Sleep -Seconds 2 } while((Get-Date) -lt $deadline)
    if($boot.exit_code -ne 0 -or $boot.output.Trim() -notmatch '(?m)^1$'){Fail "owned emulator did not finish boot: $($boot.output)"}
    $guestMarker = "amnezia-release-lab:${runId}:${profileId}:$($marker.identity_nonce)"
    $mkdirMarker = Invoke-Adb @('-s',$serial,'shell','mkdir','-p','/data/local/tmp')
    if($mkdirMarker.exit_code -ne 0){Fail "guest marker directory creation failed: $($mkdirMarker.output)"}
    $localMarker = Join-Path $workRoot 'guest-marker.txt'; [IO.File]::WriteAllText($localMarker,$guestMarker,(New-Object Text.UTF8Encoding($false)))
    $writeMarker = Invoke-Adb @('-s',$serial,'push',$localMarker,$guestMarkerPath)
    if($writeMarker.exit_code -ne 0){Fail "guest run marker write failed: $($writeMarker.output)"}
    $marker | Add-Member -NotePropertyName emulator -NotePropertyValue $emuIdentity -Force
    $marker | Add-Member -NotePropertyName qemu -NotePropertyValue $qemuIdentity -Force
    $marker | Add-Member -NotePropertyName adb_server -NotePropertyValue $adbIdentity -Force
    $marker.state='running'; $marker | Add-Member -NotePropertyName started_at -NotePropertyValue ([DateTime]::UtcNow.ToString('o')) -Force
    $marker | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $ownershipPath -Encoding UTF8
    $marker
}
function Probe {
    Set-PrivateEnvironment
    $marker = Read-PrivateJson $ownershipPath 'native ownership marker'
    if($marker.run_id -ne $runId -or $marker.profile -ne $profileId -or $marker.state -ne 'running'){Fail 'native run marker is not bound to this run/profile'}
    if($marker.serial -ne $serial -or [int]$marker.emulator_port -ne $emulatorPort -or [int]$marker.adb_port -ne $adbPort){Fail 'native marker transport identity differs from the current invocation'}
    $emu = Process-Identity ([int]$marker.emulator.pid) $emulator @('-avd',$avdName,'-port',[string]$emulatorPort) 'emulator'
    if($emu.start_time_utc_ticks -ne [int64]$marker.emulator.start_time_utc_ticks){Fail 'emulator PID start identity changed'}
    $qemu = Process-Identity ([int]$marker.qemu.pid) $qemu @('-avd',$avdName,'-port',[string]$emulatorPort) 'QEMU'
    if($qemu.start_time_utc_ticks -ne [int64]$marker.qemu.start_time_utc_ticks){Fail 'QEMU PID start identity changed'}
    $adbIdentity = Process-Identity ([int]$marker.adb_server.pid) $adb @('-L',"tcp:$adbPort") 'ADB server'
    if($adbIdentity.start_time_utc_ticks -ne [int64]$marker.adb_server.start_time_utc_ticks){Fail 'ADB PID start identity changed'}
    $state = Invoke-Adb @('-s',$serial,'get-state')
    if($state.exit_code -ne 0 -or $state.output.Trim() -ne 'device'){Fail "owned emulator is not online: $($state.output)"}
    $boot = Invoke-Adb @('-s',$serial,'shell','getprop','sys.boot_completed')
    if($boot.exit_code -ne 0 -or $boot.output.Trim() -notmatch '(?m)^1$'){Fail "owned emulator has not completed boot: $($boot.output)"}
    $guestMarker = Invoke-Adb @('-s',$serial,'shell','cat',$guestMarkerPath)
    $expectedGuestMarker = "amnezia-release-lab:${runId}:${profileId}:$($marker.identity_nonce)"
    if($guestMarker.exit_code -ne 0 -or $guestMarker.output.Trim() -ne $expectedGuestMarker){Fail 'guest run marker does not identify this run/profile/nonce'}
    $uuid = Invoke-Adb @('-s',$serial,'shell','getprop','ro.boot.qemu.uuid')
    $abi = Invoke-Adb @('-s',$serial,'shell','getprop','ro.product.cpu.abilist')
    $bridge = Invoke-Adb @('-s',$serial,'shell','getprop','ro.dalvik.vm.native.bridge')
    $guestUuid = $uuid.output.Trim()
    $uuidSource = 'guest-property'
    if($guestUuid -eq 'unknown' -or [string]::IsNullOrWhiteSpace($guestUuid)) {
        $qemuArgv = @(Parse-WindowsArgv ([string]$qemu.command_line)); $uuidIndex = [Array]::IndexOf($qemuArgv,'-uuid')
        if($uuidIndex -lt 0 -or $uuidIndex + 1 -ge $qemuArgv.Count -or $qemuArgv[$uuidIndex + 1] -ne [string]$marker.identity_nonce){Fail 'guest QEMU UUID is missing and launch identity is not present'}
        $guestUuid = ''
        $uuidSource = 'owned-launch-argument'
    }
    $probe = [ordered]@{ schema=1; run_id=$runId; profile=$profileId; backend='android-windows'; transport='android-adapter'; origin='guest'; injected=$false; serial=$serial; avd_name=$avdName; emulator=$emu; qemu=$qemu; adb_server=$adbIdentity; guest_marker=$guestMarker.output.Trim(); qemu_uuid=$guestUuid; qemu_launch_uuid=[string]$marker.identity_nonce; qemu_uuid_source=$uuidSource; abi_list=$abi.output.Trim(); native_bridge=$bridge.output.Trim(); image_package=$imagePackage; gpu_mode=$gpuMode; marker=$marker; observed_at=[DateTime]::UtcNow.ToString('o') }
    $environmentProof = [ordered]@{schema=1;run_id=$runId;profile=$profileId;backend='android-windows';android_user_home=$privateUserHome;android_emulator_home=$privateEmulatorHome;android_avd_home=$avdHome;adb_vendor_keys=$privateAdbKeys;adb_server_socket_cleared=([string]::IsNullOrEmpty($env:ADB_SERVER_SOCKET));observed_at=[DateTime]::UtcNow.ToString('o')}
    if(-not $environmentProof.adb_server_socket_cleared){Fail 'inherited ADB_SERVER_SOCKET was not cleared'}
    if(Test-Path -LiteralPath $environmentProofPath) {
        $existingEnvironment = Read-PrivateJson $environmentProofPath 'immutable private environment proof'
        if($existingEnvironment.run_id -ne $runId -or $existingEnvironment.profile -ne $profileId -or [IO.Path]::GetFullPath([string]$existingEnvironment.android_avd_home) -ine [IO.Path]::GetFullPath($avdHome)){Fail 'immutable private environment proof differs from current environment'}
    } else { Write-PrivateJson $environmentProofPath $environmentProof }
    if(Test-Path -LiteralPath $probePath) {
        $existingProbe = Read-PrivateJson $probePath 'immutable native OS probe'
        if($existingProbe.run_id -ne $runId -or $existingProbe.profile -ne $profileId -or $existingProbe.serial -ne $serial -or $existingProbe.avd_name -ne $avdName){Fail 'immutable native OS probe differs from current ownership'}
        $existingProbe
    } else {
        Write-PrivateJson $probePath $probe
        $probe
    }
}
function Assert-ProductExecutionGo {
    if(($ProductGo -ne '1') -and ($env:AMNEZIA_ANDROID_NATIVE_PRODUCT_GO -ne '1')){Fail 'native Android product actions require explicit review GO'}
}
function Get-ArtifactProof([string]$Path,[string]$Role) {
    Assert-Path $Path "${Role} APK"
    [ordered]@{path=[IO.Path]::GetFullPath($Path);sha256=(Sha $Path);size=(Get-Item -LiteralPath $Path).Length;role=$Role}
}
function New-CommonProductReceipt([string]$Status,[string]$Role,[System.Collections.IDictionary]$Artifact,[object[]]$Steps) {
    $probe = Probe
    $marker = Read-PrivateJson $ownershipPath 'native ownership marker'
    [ordered]@{
        schema=1; run_id=$runId; profile=$profileId; artifact=$Artifact.path; artifact_sha256=$Artifact.sha256; artifact_size=[int64]$Artifact.size; artifact_role=$Role
        artifact_source=[ordered]@{transport='android-adapter';kind='native-windows-adb';hash_verified=$true;path=$Artifact.path}
        baseline_version=if($BaselineVersion){$BaselineVersion}else{$env:AMNEZIA_ANDROID_BASELINE_VERSION}; candidate_version=if($ReleaseVersion){$ReleaseVersion}else{$env:AMNEZIA_ANDROID_RELEASE_VERSION}
        guest_marker="amnezia-release-lab:${runId}:${profileId}"; nonce=[string]$marker.identity_nonce; transport='android-adapter'; origin='guest'; injected=$false; status=$Status
        device_identity=[ordered]@{avd=$probe.avd_name;serial=$probe.serial;pid=$probe.emulator.pid;processStarttime=$probe.emulator.start_time_utc_ticks;qemuUuid=$probe.qemu_uuid;launchUuid=$probe.qemu_launch_uuid;adbServerPid=$probe.adb_server.pid;adbServerStarttime=$probe.adb_server.start_time_utc_ticks;adbSocket="tcp:127.0.0.1:$($probe.marker.adb_port)"}
        steps=$Steps; observed_at=[DateTime]::UtcNow.ToString('o')
    }
}
function New-ProductEnvelope([object]$Receipt) {
    $liveProbe = Probe
    [ordered]@{schema=1;run_id=$runId;profile=$profileId;backend='android-windows';transport='android-adapter';origin='guest';injected=$false;native_probe=$liveProbe;product_receipt=$Receipt}
}
function Install-Baseline {
    Assert-ProductExecutionGo
    if($Arguments.Count -ne 1){Fail 'install-baseline requires exactly one APK path'}
    $probe = Probe
    $artifact = Get-ArtifactProof $Arguments[0] 'baseline'
    $launchBoundary = ((Invoke-Adb @('-s',$serial,'shell','date','+%m-%d_%H:%M:%S.000')).output.Trim() -replace '_',' ')
    if($launchBoundary -notmatch '^\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}$'){Fail 'guest launch log boundary is invalid'}
    $logcatClear = Invoke-Adb @('-s',$serial,'logcat','-b','all','-c')
    $result = Invoke-Adb @('-s',$serial,'install','-r',$artifact.path)
    if($result.exit_code -ne 0){Fail "baseline APK install failed: $($result.output)"}
    $launch = Invoke-Adb @('-s',$serial,'shell','monkey','-p','org.amnezia.vpn','1')
    if($launch.exit_code -ne 0){Fail "baseline app launch failed: $($launch.output)"}
    # A cold Qt launch can take several seconds after monkey returns. Wait
    # for the first owned PID before beginning the separate stability window;
    # an immediate empty pidof result is a launch diagnostic, not a proof of
    # failure.
    $initialPid = ''; $pidRead = $null; $pidWaitSeconds = 0
    while($pidWaitSeconds -lt 60 -and [string]::IsNullOrWhiteSpace($initialPid)) {
        $pidRead = Invoke-Adb @('-s',$serial,'shell','pidof','org.amnezia.vpn')
        $initialPid = $pidRead.output.Trim()
        if([string]::IsNullOrWhiteSpace($initialPid)){Start-Sleep -Seconds 1; $pidWaitSeconds++}
    }
    $pidStable = $pidRead -ne $null -and $pidRead.exit_code -eq 0 -and -not [string]::IsNullOrWhiteSpace($initialPid)
    for($second=0;$second -lt 60 -and $pidStable;$second++){Start-Sleep -Seconds 1;$currentPid=(Invoke-Adb @('-s',$serial,'shell','pidof','org.amnezia.vpn')).output.Trim();if($currentPid -ne $initialPid){$pidStable=$false}}
    $versionRead = Invoke-Adb @('-s',$serial,'shell','dumpsys','package','org.amnezia.vpn')
    $versionCode = if($versionRead.output -match 'versionCode=(\d+)'){$Matches[1]}else{''}
    $versionName = if($versionRead.output -match 'versionName=([^\s]+)'){$Matches[1]}else{''}
    if($ExpectedVersionCode -le 0 -or $versionCode -ne [string]$ExpectedVersionCode){$versionCodeMismatch=$true}else{$versionCodeMismatch=$false}
    $activityRead = Invoke-Adb @('-s',$serial,'shell','dumpsys','activity','activities')
    Write-PrivateText (Join-Path $proofRoot 'baseline-activity.txt') $activityRead.output
    $uiRemote = '/data/local/tmp/amnezia-release-lab-ui.xml'; $uiPath = Join-Path $proofRoot 'baseline-ui.xml'
    $uiDump = Invoke-Adb @('-s',$serial,'shell','uiautomator','dump','--compressed',$uiRemote)
    $uiSha = ''; $uiText = ''
    if($uiDump.exit_code -eq 0){$uiPull=Invoke-Adb @('-s',$serial,'pull',$uiRemote,$uiPath);if($uiPull.exit_code -eq 0 -and (Test-Path -LiteralPath $uiPath)){$uiText=Get-Content -LiteralPath $uiPath -Raw;$uiSha=Sha $uiPath}}
    # Package ownership and a resumed Activity alone can describe a black
    # Qt surface. Require a meaningful first-run control/root in UIAutomator.
    $uiVisible = $activityRead.exit_code -eq 0 -and $activityRead.output -match '(?m)(?:ResumedActivity|mFocusedApp).*org\.amnezia\.vpn/.AmneziaActivity' -and $uiText -match 'package="org\.amnezia\.vpn"' -and $uiText -match '(?:Let.s get started|AmneziaApplication\.mainWindow|BasicButtonType)'
    if($uiVisible){Start-Sleep -Seconds 5}
    # Keep the diagnostic screenshot in the immutable proof area because the
    # owned run root is deliberately removed by reset.
    $screenshot = Join-Path $proofRoot 'baseline-coldlaunch.png'; $remoteScreenshot='/data/local/tmp/amnezia-release-lab-baseline-coldlaunch.png'
    $screenshotSha = ''
    $shot = Invoke-Adb @('-s',$serial,'shell','screencap','-p',$remoteScreenshot)
    if($shot.exit_code -eq 0){$pull=Invoke-Adb @('-s',$serial,'pull',$remoteScreenshot,$screenshot);if($pull.exit_code -ne 0){$screenshot=''}else{$screenshotSha=Sha $screenshot}}
    # Capture from the pre-launch boundary so high volume framework logging
    # cannot evict the app's first process start or native crash from a tail.
    $logcat = Invoke-Adb @('-s',$serial,'logcat','-b','all','-d','-v','threadtime','-T',$launchBoundary)
    if($logcat.exit_code -ne 0){Fail "bounded launch log capture failed: $($logcat.output)"}
    $crashBuffer = Invoke-Adb @('-s',$serial,'logcat','-b','crash','-d')
    $crashText = $logcat.output
    Write-PrivateText (Join-Path $proofRoot 'baseline-logcat.txt') $crashText
    Write-PrivateText (Join-Path $proofRoot 'baseline-crashbuffer.txt') $crashBuffer.output
    $debuggerd = if(-not [string]::IsNullOrWhiteSpace($initialPid)){Invoke-Adb @('-s',$serial,'shell','debuggerd','-b',$initialPid)}else{[ordered]@{exit_code=1;output='no initial app PID'}}
    Write-PrivateText (Join-Path $proofRoot 'baseline-debuggerd.txt') $debuggerd.output
    $tombstones = Invoke-Adb @('-s',$serial,'shell','ls','-l','/data/tombstones')
    Write-PrivateText (Join-Path $proofRoot 'baseline-tombstones.txt') $tombstones.output
    $appPids = @([regex]::Matches($crashText,'(?im)(?:Start proc |am_proc_start: \[0,)(\d+)(?::org\.amnezia\.vpn|,\d+,org\.amnezia\.vpn)') | ForEach-Object {$_.Groups[1].Value} | Select-Object -Unique)
    $crashSignals = @(
        foreach($appPid in $appPids) {
            foreach($match in [regex]::Matches($crashText,"(?im)Process\s+$([regex]::Escape($appPid))\s+exited due to signal\s+(\d+)\s*\(([^)]*)\)")) {
                "pid=$appPid signal=$($match.Groups[1].Value) $($match.Groups[2].Value)"
            }
        }
        [regex]::Matches($crashText,'(?im)^.*org\.amnezia\.vpn.*(?:SIG(SEGV|ABRT|ILL)|FATAL EXCEPTION|backtrace).*$', [Text.RegularExpressions.RegexOptions]::Multiline) | ForEach-Object {$_.Value.Trim()}
    ) | Where-Object {$_} | Select-Object -Unique
    $launchPassed = $pidStable -and $versionCode -ne '' -and -not $versionCodeMismatch -and $uiVisible -and $crashSignals.Count -eq 0
    $steps=@([ordered]@{id='baseline-install';passed=$true;transport='android-adapter'},[ordered]@{id='baseline-launch';passed=$launchPassed;transport='android-adapter'},[ordered]@{id='baseline-ui';passed=$uiVisible;transport='android-adapter'})
    $receiptStatus = if($launchPassed){'baseline-install-pass'}else{'baseline-launch-failed'}
    $receipt=New-CommonProductReceipt $receiptStatus 'baseline' $artifact $steps
    $receipt | Add-Member -NotePropertyName diagnostic -NotePropertyValue ([ordered]@{cold_launch_wait_seconds=$pidWaitSeconds;cold_launch_stability_seconds=60;pid_initial=$initialPid;pid_stable=$pidStable;version_code=$versionCode;version_name=$versionName;ui_visible=$uiVisible;activity_path=(Join-Path $proofRoot 'baseline-activity.txt');ui_path=$uiPath;ui_sha256=$uiSha;debuggerd_path=(Join-Path $proofRoot 'baseline-debuggerd.txt');tombstones_path=(Join-Path $proofRoot 'baseline-tombstones.txt');crash_signals=$crashSignals;logcat_sha256=([BitConverter]::ToString(([Security.Cryptography.SHA256]::Create()).ComputeHash([Text.Encoding]::UTF8.GetBytes($crashText)))).Replace('-','').ToLowerInvariant();logcat_path=(Join-Path $proofRoot 'baseline-logcat.txt');crashbuffer_path=(Join-Path $proofRoot 'baseline-crashbuffer.txt');screenshot_path=$screenshot;screenshot_sha256=$screenshotSha}) -Force
    Write-PrivateJson (Join-Path $proofRoot 'baseline-receipt.json') $receipt
    Write-PrivateJson $controllerBaselineReceiptPath $receipt
    Write-PrivateJson (Join-Path $proofRoot 'baseline-controller-receipt.json') $receipt
    New-ProductEnvelope $receipt
}
function Get-UiDump([string]$Path) {
    $remote = "/data/local/tmp/amnezia-release-lab-ui-$runId.xml"
    $dump = Invoke-Adb @('-s',$serial,'shell','uiautomator','dump','--compressed',$remote)
    if($dump.exit_code -ne 0){return ''}
    $pull = Invoke-Adb @('-s',$serial,'pull',$remote,$Path)
    if($pull.exit_code -ne 0 -or -not (Test-Path -LiteralPath $Path)){return ''}
    Get-Content -LiteralPath $Path -Raw
}
function Tap-UiText([string]$Ui,[string]$Text) {
    $escaped = [regex]::Escape($Text)
    $pattern = '<node\b[^>]*text="' + $escaped + '"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"'
    $match = [regex]::Match($Ui,$pattern)
    if(-not $match.Success){return $false}
    $x = [int](([int]$match.Groups[1].Value + [int]$match.Groups[3].Value) / 2)
    $y = [int](([int]$match.Groups[2].Value + [int]$match.Groups[4].Value) / 2)
    $tap = Invoke-Adb @('-s',$serial,'shell','input','tap',[string]$x,[string]$y)
    $tap.exit_code -eq 0
}
function Wait-UiText([string]$Text,[string]$Path,[int]$TimeoutSeconds=45) {
    $deadline=(Get-Date).AddSeconds($TimeoutSeconds); $last=''
    $needle = 'text="' + [regex]::Escape($Text) + '"'
    do { $last=Get-UiDump $Path; if($last -and $last -match $needle){return $last}; Start-Sleep -Seconds 1 } while((Get-Date) -lt $deadline)
    return $last
}
function Configure-UpdateNetwork([string]$Endpoint,[int]$HostPort,[int]$AppUid) {
    if($Endpoint -notmatch '^10\.[0-9]{1,3}(\.[0-9]{1,3}){2}$' -or $HostPort -lt 1024 -or $HostPort -gt 65535 -or $AppUid -lt 10000){Fail 'native update fixture network identity is invalid'}
    $root=Invoke-Adb @('-s',$serial,'root')
    if($root.exit_code -ne 0){Fail "native emulator root is unavailable for fixture routing: $($root.output)"}
    $rule="iptables -t nat -A OUTPUT -d $Endpoint -p tcp --dport 17865 -j DNAT --to-destination 10.0.2.2:$HostPort; iptables -A OUTPUT -d 10.0.2.2 -p tcp --dport $HostPort -m owner --uid-owner $AppUid -j ACCEPT; iptables -A OUTPUT -d 10.0.2.2 -p tcp --dport $HostPort -j REJECT"
    $apply=Invoke-Adb @('-s',$serial,'shell',$rule)
    if($apply.exit_code -ne 0){Fail "native fixture routing setup failed: $($apply.output)"}
    $rule
}
function Restore-UpdateNetwork([string]$Endpoint,[int]$HostPort,[int]$AppUid) {
    $rule="iptables -t nat -D OUTPUT -d $Endpoint -p tcp --dport 17865 -j DNAT --to-destination 10.0.2.2:$HostPort 2>/dev/null || true; iptables -D OUTPUT -d 10.0.2.2 -p tcp --dport $HostPort -m owner --uid-owner $AppUid -j ACCEPT 2>/dev/null || true; iptables -D OUTPUT -d 10.0.2.2 -p tcp --dport $HostPort -j REJECT 2>/dev/null || true"
    Invoke-Adb @('-s',$serial,'shell',$rule) | Out-Null
}
function Read-FixtureRequestLog([string]$Endpoint,[string]$Nonce,[string]$OutPath,[string]$ExpectedManifestSha,[int64]$ExpectedManifestSize,[string]$ExpectedApkSha,[int64]$ExpectedApkSize) {
    $remote="/data/local/tmp/amnezia-release-lab-request-log-$runId.jsonl"
    $url="http://${Endpoint}:17865/__lab__/request-log?nonce=${Nonce}&run_id=${runId}"
    $read=Invoke-Adb @('-s',$serial,'shell','toybox','wget','-q','-O',$remote,$url)
    if($read.exit_code -ne 0){return $false}
    $pull=Invoke-Adb @('-s',$serial,'pull',$remote,$OutPath)
    if($pull.exit_code -ne 0 -or -not (Test-Path -LiteralPath $OutPath)){return $false}
    $manifest=$false; $apk=$false; $count=0
    foreach($line in @(Get-Content -LiteralPath $OutPath)) {
        if([string]::IsNullOrWhiteSpace($line)){continue}; $count++; if($count -gt 4096){Fail 'native fixture request log exceeds bounded records'}
        try{$row=$line|ConvertFrom-Json}catch{Fail 'native fixture request log contains invalid JSON'}
        if($row.run_id -ne $runId -or $row.attempt_nonce -ne $Nonce){Fail 'native fixture request log identity mismatch'}
        if($row.status -ne 200 -or $row.method -ne 'GET'){continue}
        if($row.path -eq '/manifest.json' -and $row.sha256 -eq $ExpectedManifestSha -and [int64]$row.bytes -eq $ExpectedManifestSize -and [int64]$row.content_length -eq $ExpectedManifestSize){$manifest=$true}
        elseif($row.path -match "^/files/artifacts/$([regex]::Escape($ExpectedApkSha))/.+" -and $row.sha256 -eq $ExpectedApkSha -and [int64]$row.bytes -eq $ExpectedApkSize -and [int64]$row.content_length -eq $ExpectedApkSize){$apk=$true}
        elseif($row.path -notmatch '^/healthz$'){Fail 'native fixture request log contains an unexpected successful path'}
    }
    $manifest -and $apk
}
function Test-Update {
    Assert-ProductExecutionGo
    if($Arguments.Count -ne 1){Fail 'test-update requires exactly one candidate APK path'}
    if([string]$env:AMNEZIA_ANDROID_FIXTURE_GUEST_ENDPOINT -notmatch '^10\.[0-9]{1,3}(\.[0-9]{1,3}){2}$' -or [string]$env:AMNEZIA_ANDROID_UPDATE_ATTEMPT_NONCE -notmatch '^[A-Za-z0-9._-]{16,128}$'){Fail 'candidate update requires the planned fixture endpoint and fresh attempt nonce'}
    if($FixtureHostPort -lt 1024 -or $FixtureHostPort -gt 65535){Fail 'candidate update requires the planned fixture host port'}
    Assert-Path $ReleaseManifestPath 'candidate signed manifest'
    $probe = Probe
    $artifact=Get-ArtifactProof $Arguments[0] 'candidate'
    $manifestSha=Sha $ReleaseManifestPath; $manifestSize=[int64](Get-Item -LiteralPath $ReleaseManifestPath).Length; $nonce=[string]$env:AMNEZIA_ANDROID_UPDATE_ATTEMPT_NONCE; $endpoint=[string]$env:AMNEZIA_ANDROID_FIXTURE_GUEST_ENDPOINT
    if($ExpectedReleaseVersionCode -le 0){Fail 'candidate update requires an exact expected release versionCode'}
    $packageDump=Invoke-Adb @('-s',$serial,'shell','dumpsys','package','org.amnezia.vpn')
    $uidMatch=[regex]::Match($packageDump.output,'userId=(\d+)'); if(-not $uidMatch.Success){Fail 'candidate update could not read the app UID'}; $appUid=[int]$uidMatch.Groups[1].Value
    $resetRemote="/data/local/tmp/amnezia-release-lab-attempt-reset-$runId.json"; $resetUrl="http://${endpoint}:17865/__lab__/attempt/reset?nonce=${nonce}&run_id=${runId}"
    $reset=Invoke-Adb @('-s',$serial,'shell','toybox','wget','-q','-O',$resetRemote,$resetUrl)
    if($reset.exit_code -ne 0){Fail "fixture attempt reset failed: $($reset.output)"}
    $resetRead=Invoke-Adb @('-s',$serial,'shell','cat',$resetRemote); if($resetRead.exit_code -ne 0 -or $resetRead.output -notmatch 'reset'){Fail 'fixture attempt reset receipt was not observed'}
    $networkConfigured=$false; $ui=''; $requests=$false; $candidateCode=''; $reason=''
    try {
        Configure-UpdateNetwork $endpoint $FixtureHostPort $appUid | Out-Null; $networkConfigured=$true
        $launch=Invoke-Adb @('-s',$serial,'shell','monkey','-p','org.amnezia.vpn','1')
        if($launch.exit_code -ne 0){$reason='candidate app launch failed'}else{
            $ui=Wait-UiText 'Update' (Join-Path $proofRoot 'update-ui.xml') 45
            if(-not $ui -or $ui -notmatch 'text="Update"'){$reason='app-update-ui-not-present'}
            elseif(-not (Tap-UiText $ui 'Update')){$reason='app-update-action-not-clickable'}
            else {
                $installerUi=Wait-UiText 'Install' (Join-Path $proofRoot 'update-installer-ui.xml') 45
                if(-not $installerUi -and -not ($installerUi -match 'text="Update"')){$reason='package-installer-ui-not-present'}
                elseif(-not (Tap-UiText $installerUi $(if($installerUi -match 'text="Install"'){'Install'}else{'Update'}))){$reason='package-installer-action-not-clickable'}
                else {
                    $done=Wait-UiText 'Done' (Join-Path $proofRoot 'update-done-ui.xml') 90
                    if(-not $done){$reason='package-installer-did-not-finish'}
                }
            }
        }
    } finally {
        if($networkConfigured){Restore-UpdateNetwork $endpoint $FixtureHostPort $appUid}
    }
    $requestLog=Join-Path $proofRoot 'update-request-log.jsonl'
    $requests=Read-FixtureRequestLog $endpoint $nonce $requestLog $manifestSha $manifestSize $artifact.sha256 ([int64]$artifact.size)
    $postDump=Invoke-Adb @('-s',$serial,'shell','dumpsys','package','org.amnezia.vpn')
    if($postDump.output -match 'versionCode=(\d+)'){$candidateCode=$Matches[1]}
    $updatePassed=$requests -and [string]$candidateCode -eq [string]$ExpectedReleaseVersionCode
    if($updatePassed){$reason=''}elseif(-not $reason){$reason='fixture-request-or-candidate-version-proof-missing'}
    $steps=@([ordered]@{id='app-selfhosted-update';passed=$updatePassed;transport='android-adapter';status=if($updatePassed){'observed'}else{$reason}},[ordered]@{id='candidate-version-readback';passed=([string]$candidateCode -eq [string]$ExpectedReleaseVersionCode);transport='android-adapter';status=if([string]$candidateCode -eq [string]$ExpectedReleaseVersionCode){'observed'}else{'pending'}})
    $receipt=New-CommonProductReceipt (if($updatePassed){'app-selfhosted-update-pass'}else{'app-selfhosted-update-pending'}) 'candidate' $artifact $steps
    $receipt | Add-Member -NotePropertyName update_diagnostic -NotePropertyValue ([ordered]@{fixture_endpoint=$endpoint;fixture_host_port=$FixtureHostPort;attempt_nonce=$nonce;manifest_sha256=$manifestSha;manifest_size=$manifestSize;candidate_version_code=$candidateCode;expected_release_version_code=$ExpectedReleaseVersionCode;reason=$reason;update_ui_path=(Join-Path $proofRoot 'update-ui.xml');request_log_path=$requestLog}) -Force
    Write-PrivateJson (Join-Path $proofRoot 'candidate-receipt.json') $receipt
    Write-PrivateJson $controllerReceiptPath $receipt
    New-ProductEnvelope $receipt
}
function Collect-Product {
    Assert-ProductExecutionGo
    $candidate=Join-Path $proofRoot 'candidate-receipt.json'
    if(-not (Test-Path -LiteralPath $candidate)){Fail 'candidate product receipt is missing'}
    New-ProductEnvelope (Read-PrivateJson $candidate 'candidate product receipt')
}
function Reset-Owned {
    Set-PrivateEnvironment
    if(Test-Path -LiteralPath $runRoot){Assert-NoReparseTree $runRoot}
    if(-not (Test-Path -LiteralPath $ownershipPath)) {
        if(-not (Test-Path -LiteralPath $creationIntentPath)){Fail 'native ownership marker and creation intent are both absent'}
        $intent = Read-PrivateJson $creationIntentPath 'native creation intent'
        if($intent.run_id -ne $runId -or $intent.profile -ne $profileId -or $intent.backend -ne 'android-windows'){Fail 'native creation intent identity mismatch'}
        $orphanAvd = Join-Path $avdHome "$avdName.avd"
        if(Test-Path -LiteralPath $orphanAvd){Assert-NoReparseTree $orphanAvd; [IO.Directory]::Delete($orphanAvd,$true)}
        if(Test-Path -LiteralPath $runRoot){[IO.Directory]::Delete($runRoot,$true)}
        [ordered]@{schema=1;run_id=$runId;profile=$profileId;backend='android-windows';transport='android-adapter';origin='guest';injected=$false;state='reset';reset_at=[DateTime]::UtcNow.ToString('o')}
        return
    }
    $marker = Read-PrivateJson $ownershipPath 'native ownership marker'
    if($marker.run_id -ne $runId -or $marker.profile -ne $profileId -or $marker.backend -ne 'android-windows'){Fail 'native ownership marker mismatch'}
    if([IO.Path]::GetFullPath([string]$marker.avd_home) -ine [IO.Path]::GetFullPath($avdHome) -or [IO.Path]::GetFullPath([string]$marker.sdk_root) -ine [IO.Path]::GetFullPath($sdkRoot)){Fail 'native marker root binding mismatch'}
    $avdName=[string]$marker.avd_name; $adbPort=[int]$marker.adb_port; $emulatorPort=[int]$marker.emulator_port
    # Older interrupted starts could persist the frontend port while the
    # native process command line recorded the effective port. Recover that
    # owned run from its immutable PID/start identity and run-specific AVD,
    # rather than failing cleanup or probing a second device.
    foreach($item in @(@{property='emulator'; path=$emulator; default=$emulatorPort},@{property='qemu'; path=$qemu; default=$emulatorPort})) {
        $stored = $marker.PSObject.Properties[$item.property]
        if($null -eq $stored){continue}
        $argv = @(Parse-WindowsArgv ([string]$stored.Value.command_line)); $portIndex=[Array]::IndexOf($argv,'-port')
        if($portIndex -lt 0 -or $portIndex+1 -ge $argv.Count -or $argv[$portIndex+1] -notmatch '^\d+$'){Fail "owned $($item.property) command line has no valid port"}
        if($item.property -eq 'emulator'){$emulatorPort=[int]$argv[$portIndex+1]}
        elseif([int]$argv[$portIndex+1] -ne $emulatorPort){Fail 'owned emulator and QEMU ports disagree'}
    }
    $storedAdb = $marker.PSObject.Properties['adb_server']
    if($null -ne $storedAdb){
        $adbArgv=@(Parse-WindowsArgv ([string]$storedAdb.Value.command_line)); $adbToken=@($adbArgv | Where-Object {$_ -match '^tcp:\d+$'} | Select-Object -First 1)
        if($adbToken.Count -eq 0){Fail 'owned ADB command line has no dedicated port'}
        $adbPort=[int](([string]$adbToken[0]) -replace '^tcp:','')
    }
    $serial="emulator-$emulatorPort"
    $processItems = @()
    foreach($itemSpec in @(@{id='emulator'; property='emulator'; path=$emulator; args=@('-avd',$avdName,'-port',[string]$emulatorPort)},@{id='qemu'; property='qemu'; path=$qemu; args=@('-avd',$avdName,'-port',[string]$emulatorPort)},@{id='adb'; property='adb_server'; path=$adb; args=@('-L',"tcp:$adbPort")})) {
        $itemProperty = $marker.PSObject.Properties[$itemSpec.property]
        if($null -ne $itemProperty) { $processItems += @{ id=$itemSpec.id; info=$itemProperty.Value; path=$itemSpec.path; args=$itemSpec.args } }
    }
    foreach($itemSpec in @(@{id='emulator'; path=$emulator; args=@('-avd',$avdName,'-port',[string]$emulatorPort)},@{id='qemu'; path=$qemu; args=@('-avd',$avdName,'-port',[string]$emulatorPort)},@{id='adb'; path=$adb; args=@('-L',"tcp:$adbPort")})) {
        if(@($processItems | Where-Object { $_.id -eq $itemSpec.id }).Count -ne 0) { continue }
        $discovered = Find-OwnedProcess $itemSpec.path $itemSpec.args
        if($null -ne $discovered) {
            $processItems += @{ id=$itemSpec.id; info=(Process-Identity ([int]$discovered.ProcessId) $itemSpec.path $itemSpec.args $itemSpec.id); path=$itemSpec.path; args=$itemSpec.args }
        }
    }
    foreach($item in $processItems){
        if($null -eq $item.info){continue}
        $p = Get-CimInstance Win32_Process -Filter "ProcessId=$([int]$item.info.pid)" -ErrorAction SilentlyContinue
        if($null -ne $p){
            $identity = Process-Identity ([int]$item.info.pid) $item.path $item.args $item.id
            if($identity.start_time_utc_ticks -ne [int64]$item.info.start_time_utc_ticks){Fail "$($item.id) PID was reused"}
            Stop-Process -Id ([int]$item.info.pid) -ErrorAction SilentlyContinue
        }
    }
    Start-Sleep -Seconds 2
    foreach($item in $processItems) { if($null -ne $item.info -and (Get-Process -Id ([int]$item.info.pid) -ErrorAction SilentlyContinue)){Fail 'owned process did not stop'} }
    $avdDir = Join-Path $avdHome "$avdName.avd"
    if(Test-Path -LiteralPath $avdDir){Assert-NoReparseTree $avdDir}
    if(Test-Path -LiteralPath $avdDir){[IO.Directory]::Delete($avdDir,$true)}
    if(Test-Path -LiteralPath $runRoot){[IO.Directory]::Delete($runRoot,$true)}
    [ordered]@{schema=1;run_id=$runId;profile=$profileId;backend='android-windows';transport='android-adapter';origin='guest';injected=$false;state='reset';reset_at=[DateTime]::UtcNow.ToString('o')}
}

Assert-Root
$lock = Acquire-RunLock
try {
    $result = switch($Command){
        'prepare' { Prepare }
        'create' { Create-AVD }
        'start' { Start-Emulator }
        'probe' { Probe }
        'reset' { Reset-Owned }
        'install-baseline' { Install-Baseline }
        'test-update' { Test-Update }
        'collect' { Collect-Product }
        default { Fail "$Command is intentionally disabled until the native OS proof is reviewed" }
    }
} catch {
    if($Command -eq 'start') {
        try { Reset-Owned | Out-Null }
        catch { try { Write-PrivateJson (Join-Path $proofRoot 'start-unsafe-recovery.json') ([ordered]@{schema=1;run_id=$runId;profile=$profileId;backend='android-windows';state='unsafe';error=$_.Exception.Message;observed_at=[DateTime]::UtcNow.ToString('o')}) } catch {} }
    }
    throw
} finally { $lock.Dispose(); try {[IO.File]::Delete($externalLockPath)}catch{} }
$result | ConvertTo-Json -Depth 30 -Compress
