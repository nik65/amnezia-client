[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('plan','status','create-child','start','stop','probe','precondition','prepare-interactive','stage','run','collect','diagnose-bootstrap-root','reset','ui-observe','ui-confirm','export-ui','app-window','seed-profile','relays-start','relays-stop','publish')]
    [string] $Action,
    [string] $RunId,
    [string] $CaseId = 'control',
    [ValidateSet('windows-x64')]
    [string] $Profile = 'windows-x64',
    [string] $ParentRoot = 'C:\ProgramData\AmneziaReleaseLab\hyperv\windows-x64',
    [string] $RunsRoot = 'C:\ProgramData\AmneziaReleaseLab\hyperv\runs',
    [string] $ArtifactPath,
    [string] $ArtifactSha256,
    [int64] $ArtifactSize = -1,
    [ValidateSet('baseline-thin','candidate-thin','baseline-outer','candidate-outer')]
    [string] $Stage,
    [ValidateSet('probe','reinstall','update','service-health','interactive-start','interactive-status','interactive-collect')]
    [string] $GuestAction,
    [string] $ExpectedSha256,
    [ValidateSet('baseline','candidate')]
    [string] $ExpectedArtifactRole,
    [string] $ExpectedVersion,
    [string] $BaselineVersion,
    [string] $CandidateVersion,
    [string] $RunnerPath,
    [string] $RunnerSha256,
    [string] $UiHelperPath,
    [string] $UiHelperSha256,
    [string] $LauncherPath,
    [string] $LauncherSha256,
    [string] $SeedHelperPath,
    [string] $SeedHelperSha256,
    [string] $SeedHost,
    [string] $SeedUser,
    [int] $SeedPort = -1,
    [string] $SeedFingerprint,
    [string] $AttemptNonce,
    [string] $ChildVmId,
    [string] $RelayHelperPath,
    [string] $RelaySupervisorPath,
    [string] $RelayGuestTaskPath,
    [string] $RelayHelperSha256,
    [int] $ExpectedConsentPid = -1,
    [string] $ExpectedConsentStartTime,
    [int] $ExpectedConsentSessionId = -1,
    [string] $ExpectedArtifactSha256,
    [string] $ExpectedScreenshotSha256,
    [string] $TokenEvidencePath,
    [switch] $CredentialStdin
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
Import-Module Microsoft.PowerShell.Utility -Force -ErrorAction Stop

function Fail([string] $Message) { throw "hyperv-adapter: $Message" }
function Full([string] $Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { Fail 'path is empty' }
    return [IO.Path]::GetFullPath($Path.TrimEnd('\'))
}
function Assert-Contained([string] $Path, [string] $Root, [string] $Label) {
    $full = Full $Path; $rootFull = Full $Root
    if ($full -ine $rootFull -and -not $full.StartsWith($rootFull + '\', [StringComparison]::OrdinalIgnoreCase)) { Fail "$Label is outside the owned root" }
    $cursor = New-Object IO.DirectoryInfo($full)
    while ($null -ne $cursor -and $cursor.FullName.Length -ge $rootFull.Length) {
        if (Test-Path -LiteralPath $cursor.FullName) {
            $item = Get-Item -LiteralPath $cursor.FullName -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { Fail "$Label has a reparse-point ancestor" }
        }
        if ($cursor.FullName -ieq $rootFull) { break }
        $cursor = $cursor.Parent
    }
    return $full
}
function Assert-NoReparse([string] $Path, [string] $Label) {
    $full = Full $Path
    $item = Get-Item -LiteralPath $full -Force -ErrorAction Stop
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { Fail "$Label is a reparse point" }
    $cursor = if ($item.PSIsContainer) { [IO.DirectoryInfo]$item.FullName } else { $item.Directory }
    while ($null -ne $cursor) {
        if (($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { Fail "$Label has a reparse-point ancestor" }
        $cursor = $cursor.Parent
    }
    return $item
}
function Assert-Directory([string] $Path, [string] $Label) {
    $full = Full $Path
    $allowed = Full 'C:\ProgramData\AmneziaReleaseLab\hyperv'
    if ($full -ine $allowed -and -not $full.StartsWith($allowed + '\', [StringComparison]::OrdinalIgnoreCase)) { Fail "$Label is outside the Hyper-V lab root" }
    if (Test-Path -LiteralPath $full) {
        if (-not (Test-Path -LiteralPath $full -PathType Container)) { Fail "$Label is not a directory" }
        Assert-NoReparse $full $Label | Out-Null
    }
    return $full
}
function Sha([string] $Path) { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant() }
function Test-HyperVOnState([object] $Value) {
    if ($null -eq $Value) { return $false }
    if ($Value -is [System.Enum] -or $Value -is [byte] -or $Value -is [sbyte] -or $Value -is [int16] -or $Value -is [uint16] -or $Value -is [int32] -or $Value -is [uint32] -or $Value -is [int64] -or $Value -is [uint64]) { return ([int64]$Value -eq 0) }
    return ([string]$Value -ieq 'On')
}
function Read-Json([string] $Path, [string] $Label) {
    Assert-NoReparse $Path $Label | Out-Null
    try { return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json } catch { Fail "$Label is invalid JSON" }
}
function Write-JsonNoClobber([string] $Path, [object] $Value) {
    if (Test-Path -LiteralPath $Path) { Fail "refusing to overwrite $Path" }
    $parent = Split-Path -Parent (Full $Path)
    New-Item -ItemType Directory -Force -Path $parent | Out-Null
    $Value | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $Path -Encoding UTF8
}
function Get-Parent([string] $Root) {
    $root = Assert-Directory $Root 'parent root'
    $markerPath = Join-Path $root '.owned-vm.json'
    $marker = Read-Json $markerPath 'sealed parent marker'
    if ($marker.schema -ne 1 -or $marker.backend -ne 'hyperv' -or $marker.profile -ne 'windows-x64' -or $marker.sealed -ne $true -or $marker.state -ne 'sealed') { Fail 'parent marker is not a sealed Hyper-V windows-x64 baseline' }
    try { $parentVm = @(Get-VM -Id ([guid]$marker.vm_id) -ErrorAction Stop); if ($parentVm.Count -ne 1) { Fail 'parent VM ID did not resolve uniquely' } } catch { Fail 'sealed parent VM is unavailable' }
    if ([string]$parentVm[0].State -ne 'Off') { Fail 'sealed parent VM must remain Off; refusing to boot or mutate the golden' }
    $vhd = Assert-Contained ([string]$marker.vhdx) $root 'sealed parent VHDX'
    $vhdItem = Assert-NoReparse $vhd 'sealed parent VHDX'
    $current = Sha $vhd
    if ($current -ne ([string]$marker.vhdx_sha256).ToLowerInvariant()) { Fail 'sealed parent VHDX hash differs from marker' }
    $info = Get-VHD -Path $vhd -ErrorAction Stop
    if (-not [string]::IsNullOrWhiteSpace([string]$info.ParentPath) -or [int64]$info.Size -ne 137438953472) { Fail 'sealed parent VHDX is not self-contained 128 GiB' }
    return [ordered]@{ marker = $marker; vm = $parentVm[0]; vhdx = $vhd; sha256 = $current; size = [int64]$vhdItem.Length }
}
function ChildRoot([string] $Root, [string] $Id) {
    if ([string]::IsNullOrWhiteSpace($Id) -or $Id -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$') { Fail 'RunId is invalid' }
    $runs = Assert-Directory $Root 'runs root'
    return Assert-Directory (Join-Path (Join-Path $runs $Id) 'windows-x64') 'child run root'
}
function Assert-CaseId([string] $Id) {
    if ($Id -notmatch '^(control|thin-clean|thin-upgrade|thin-reinstall|outer-clean|outer-upgrade|outer-reinstall|outer-interactive|publisher-clean)$') { Fail 'CaseId is not an allowlisted Hyper-V matrix case' }
    return $Id
}
function CaseRoot([string] $Root, [string] $Id, [string] $Case) {
    Assert-CaseId $Case | Out-Null
    if ([string]::IsNullOrWhiteSpace($Id) -or $Id -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$') { Fail 'RunId is invalid' }
    $base = Join-Path (Join-Path (Join-Path (Assert-Directory $Root 'runs root') $Id) 'windows-x64') 'cases'
    return Assert-Directory (Join-Path $base $Case) 'case root'
}
function Expected-ChildName([string] $Id, [string] $Case) {
    $bytes = [Text.Encoding]::UTF8.GetBytes("$Id|$Case")
    $hash = ([BitConverter]::ToString(([Security.Cryptography.SHA256]::Create()).ComputeHash($bytes))).Replace('-','').ToLowerInvariant().Substring(0,12)
    $slug = ($Id -replace '[^A-Za-z0-9._-]','_'); if ($slug.Length -gt 32) { $slug = $slug.Substring(0,32) }
    $name = "AmneziaLab-$slug-$Case-$hash"; if ($name.Length -gt 80) { $name = $name.Substring(0,80) }
    return $name
}
function Read-Child([string] $Root, [string] $Id, [string] $ParentRoot, [string] $Case) {
    $childRoot = CaseRoot $Root $Id $Case
    $markerPath = Join-Path $childRoot '.owned-child.json'
    $marker = Read-Json $markerPath 'owned child marker'
    if ($marker.schema -ne 1 -or $marker.backend -ne 'hyperv' -or $marker.profile -ne 'windows-x64' -or [string]$marker.run_id -ne $Id -or [string]$marker.case_id -ne $Case) { Fail 'owned child marker identity mismatch' }
    try { $vm = @(Get-VM -Id ([guid]$marker.vm_id) -ErrorAction Stop); if ($vm.Count -ne 1) { Fail 'owned child VM ID did not resolve uniquely' } } catch { Fail 'owned child VM is unavailable' }
    $parent = Get-Parent $ParentRoot
    if ([string]$marker.parent_sha256 -ne $parent.sha256 -or [string]$marker.parent_vhdx -ine $parent.vhdx -or [string]$marker.parent_vm_id -ne [string]$parent.vm.Id) { Fail 'owned child parent binding differs from sealed baseline' }
    $configuration = Verify-ChildConfig ([ordered]@{ root = $childRoot; marker = $marker; vm = $vm[0]; parent = $parent })
    return [ordered]@{ root = $childRoot; marker = $marker; vm = $vm[0]; parent = $parent; configuration = $configuration }
}
function Get-CredentialFromStdin {
    if (-not $CredentialStdin) { Fail 'PowerShell Direct actions require -CredentialStdin' }
    $plain = [Console]::In.ReadToEnd().TrimEnd("`r", "`n")
    if ([string]::IsNullOrWhiteSpace($plain) -or $plain.Length -gt 512) { Fail 'runtime guest credential is missing or too long' }
    $secure = New-Object System.Security.SecureString
    foreach ($character in $plain.ToCharArray()) { $secure.AppendChar($character) }
    $secure.MakeReadOnly()
    return [PSCredential]::new('.\labadmin', $secure)
}
function Get-PlainCredential([PSCredential] $Credential) {
    $ptr=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
}
function New-Session([object] $Child) {
    $credential = Get-CredentialFromStdin
    return New-PSSession -VMId ([guid]$Child.vm.Id) -Credential $credential -ErrorAction Stop
}
function Get-MsvmKeyboardMetadata([string] $VmId) {
    $class = Get-CimClass -Namespace 'root\virtualization\v2' -ClassName 'Msvm_Keyboard' -ErrorAction Stop
    $methodObjects = @($class.CimClassMethods)
    $methods = @($methodObjects | ForEach-Object { [string]$_.Name })
    $parameters = @($methodObjects | ForEach-Object { [ordered]@{ name=[string]$_.Name; parameters=@($_.Parameters | ForEach-Object { [string]$_.Name }) } })
    $instances = @(Get-CimInstance -Namespace 'root\virtualization\v2' -ClassName 'Msvm_Keyboard' -ErrorAction SilentlyContinue)
    return [ordered]@{ class_name='Msvm_Keyboard'; vm_id=$VmId; methods=$methods; method_parameters=$parameters; instance_count=$instances.Count; type_key_supported=($methods -contains 'TypeKey' -and $methods -contains 'PressKey' -and $methods -contains 'ReleaseKey') }
}
function Get-GuestConsentProof([object] $Child, [object] $Session) {
    $guestRoot="C:\ProgramData\AmneziaLab\runs\$($Child.marker.run_id)\windows-x64\$($Child.marker.case_id)"; $marker=Join-Path $guestRoot 'run-marker.txt'
    $expectedArtifact = $ExpectedArtifactSha256.ToLowerInvariant()
    $childVmId = [string]$Child.vm.Id
    return Invoke-Command -Session $Session -ScriptBlock {
        param($marker,$runId,$caseId,$vmId,$expectedPid,$expectedStart,$expectedSession,$expectedArtifact)
        if (-not (Test-Path -LiteralPath $marker -PathType Leaf)) { throw 'guest marker missing for UI observation' }
        $lines=@(Get-Content -LiteralPath $marker); if($lines -notcontains "amnezia-release-lab:${runId}:windows-x64" -or $lines -notcontains "case_id=$caseId" -or $lines -notcontains "vm_id=$vmId"){throw 'guest UI marker binding mismatch'}
        $requestPath=Join-Path (Split-Path -Parent $marker) 'pending-installer.json'
        if(-not(Test-Path -LiteralPath $requestPath -PathType Leaf)){throw 'guest pending installer request is missing'}
        $request=Get-Content -LiteralPath $requestPath -Raw | ConvertFrom-Json
        if([string]$request.state -notin @('waiting','running') -or [string]$request.run_id -ne $runId -or [string]$request.case_id -ne $caseId -or ([string]$request.artifact_sha256 -ne $expectedArtifact)){throw 'guest pending installer request is not bound to this artifact/case'}
        $consent=@(Get-CimInstance Win32_Process -Filter "Name='consent.exe'" -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -gt 0 -and $_.ExecutablePath -and ([IO.Path]::GetFullPath([string]$_.ExecutablePath) -ieq (Join-Path $env:SystemRoot 'System32\consent.exe')) })
        if($consent.Count -ne 1){throw 'System32 consent.exe is not observed in the expected guest session'}
        $p=$consent[0]; $owner=Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction Stop
        $sid=Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid -ErrorAction Stop
        if([string]$sid.Sid -ne 'S-1-5-18'){throw 'consent.exe is not running as SYSTEM'}
        if([int]$p.ProcessId -eq [int]$request.launcher_pid -or [int]$p.SessionId -ne [int]$request.launcher_session_id){throw 'consent.exe is not a distinct process bound to the pending installer session'}
        $launcher=@(Get-CimInstance Win32_Process -Filter "ProcessId=$([int]$request.launcher_pid)" -ErrorAction SilentlyContinue)
        if($launcher.Count -ne 1 -or [string]$launcher[0].CommandLine -notlike "*$([string]$request.launcher_path)*" -or [string]$launcher[0].CreationDate -ne [string]$request.launcher_start_time -or [int]$launcher[0].SessionId -ne [int]$request.launcher_session_id){throw 'limited launcher process is not bound to the pending installer request'}
        $launcherSid=Invoke-CimMethod -InputObject $launcher[0] -MethodName GetOwnerSid -ErrorAction Stop
        if([string]$launcherSid.Sid -eq 'S-1-5-18'){throw 'limited launcher unexpectedly runs as SYSTEM'}
        $installerPid=0; $installerPath=''
        if($request.PSObject.Properties['installer_pid'] -and [int]$request.installer_pid -gt 0){
            $installer=@(Get-CimInstance Win32_Process -Filter "ProcessId=$([int]$request.installer_pid)" -ErrorAction SilentlyContinue)
            if($installer.Count -ne 1 -or [IO.Path]::GetFullPath([string]$installer[0].ExecutablePath) -ine [IO.Path]::GetFullPath([string]$request.artifact_path)){throw 'installer process is not bound to the requested artifact'}
            $installerPid=[int]$installer[0].ProcessId; $installerPath=[string]$installer[0].ExecutablePath
        }
        if($expectedPid -ge 0 -and [int]$p.ProcessId -ne $expectedPid){throw 'consent PID changed'}
        if($expectedStart -and [string]$p.CreationDate -ne $expectedStart){throw 'consent start time changed'}
        if($expectedSession -ge 0 -and [int]$p.SessionId -ne $expectedSession){throw 'consent session changed'}
        [ordered]@{ run_id=$runId; case_id=$caseId; vm_id=$vmId; request_state=[string]$request.state; process_id=[int]$p.ProcessId; creation_time=[string]$p.CreationDate; session_id=[int]$p.SessionId; owner_user=[string]$owner.User; owner_sid=[string]$sid.Sid; consent_path=[string]$p.ExecutablePath; launcher_pid=[int]$request.launcher_pid; launcher_start_time=[string]$request.launcher_start_time; launcher_session_id=[int]$request.launcher_session_id; launcher_sid=[string]$launcherSid.Sid; installer_pid=$installerPid; installer_path=$installerPath; installer_start_time=if($request.PSObject.Properties['installer_start_time']){[string]$request.installer_start_time}else{''}; expected_consent=$true; interactive_token=$false }
    } -ArgumentList $marker,$Child.marker.run_id,$Child.marker.case_id,$childVmId,$ExpectedConsentPid,$ExpectedConsentStartTime,$ExpectedConsentSessionId,$expectedArtifact
}
function Verify-ChildConfig([object] $Child) {
    $vm = @(Get-VM -Id ([guid]$Child.vm.Id) -ErrorAction Stop)[0]
    if ([string]$vm.Id -ne [string]$Child.marker.vm_id -or [string]$vm.Name -ne [string]$Child.marker.vm_name -or [int]$vm.Generation -ne 2 -or [int]$vm.ProcessorCount -ne 4 -or [int64]$vm.MemoryStartup -ne 8589934592) { Fail 'child VM configuration readback mismatch' }
    $expectedConfigurationLocation = Join-Path (Join-Path $Child.root 'vm') ([string]$vm.Name)
    if (-not $vm.PSObject.Properties['ConfigurationLocation'] -or [string]::IsNullOrWhiteSpace([string]$vm.ConfigurationLocation) -or [string]$vm.ConfigurationLocation.TrimEnd('\') -ine $expectedConfigurationLocation.TrimEnd('\')) { Fail "child VM configuration location is missing or differs from owned case root (actual='$([string]$vm.ConfigurationLocation)', expected='$expectedConfigurationLocation')" }
    if (-not $vm.PSObject.Properties['AutomaticCheckpointsEnabled']) { Fail 'child automatic checkpoints state is missing' }
    if ([bool]$vm.AutomaticCheckpointsEnabled) { Fail 'child automatic checkpoints are enabled' }
    $adapters = @(Get-VMNetworkAdapter -VM $vm -ErrorAction Stop); if ($adapters.Count -ne 0) { Fail 'child VM has a network adapter' }
    $firmware = Get-VMFirmware -VM $vm -ErrorAction Stop
    if (-not (Test-HyperVOnState $firmware.SecureBoot) -or [string]$firmware.SecureBootTemplate -ne 'MicrosoftWindows') { Fail 'child Secure Boot readback mismatch' }
    $security = Get-VMSecurity -VM $vm -ErrorAction Stop
    if (-not $security.TpmEnabled) { Fail 'child vTPM is disabled' }
    $disk = @(Get-VMHardDiskDrive -VM $vm -ErrorAction Stop); if ($disk.Count -ne 1) { Fail 'child must have exactly one disk' }
    $diskPath = Assert-Contained ([string]$disk[0].Path) $Child.root 'child VHDX'
    if ($diskPath -ine [string]$Child.marker.child_vhdx) { Fail 'child disk path differs from marker' }
    $info = Get-VHD -Path $diskPath -ErrorAction Stop
    if ([string]$info.ParentPath -ine [string]$Child.marker.parent_vhdx -or [string]$info.VhdType -ine 'Differencing') { Fail 'child VHDX parent/type readback mismatch' }
    $dvds = @(Get-VMDvdDrive -VM $vm -ErrorAction Stop); if ($dvds.Count -ne 0) { Fail 'child VM has attached DVD media' }
    $keyProtector = Get-VMKeyProtector -VM $vm -ErrorAction Stop
    $keyPresent = if ($keyProtector -is [byte[]]) { $keyProtector.Length -gt 0 } elseif ($keyProtector.PSObject.Properties['KeyProtector']) { $null -ne $keyProtector.KeyProtector } else { $false }
    if (-not $keyPresent) { Fail 'child vTPM key protector is missing' }
    $firstBoot = @($firmware.BootOrder | Where-Object { $null -ne $_.Device -and -not [string]::IsNullOrWhiteSpace([string]$_.Device.Id) }) | Select-Object -First 1
    if ($null -eq $firstBoot -or $null -eq $firstBoot.Device -or [string]$firstBoot.Device.Id -ne [string]$disk[0].Id) { Fail 'child first boot device is not the owned VHDX' }
    return [ordered]@{ vm_id = [string]$vm.Id; state = [string]$vm.State; generation = [int]$vm.Generation; processors = [int]$vm.ProcessorCount; memory_bytes = [int64]$vm.MemoryStartup; network_adapter_count = $adapters.Count; secure_boot = (Test-HyperVOnState $firmware.SecureBoot); secure_boot_template = [string]$firmware.SecureBootTemplate; vtp_enabled = [bool]$security.TpmEnabled; key_protector_present = $keyPresent; dvd_count = $dvds.Count; first_boot_device_id = [string]$firstBoot.Device.Id; child_vhdx = $diskPath; parent_vhdx = [string]$info.ParentPath; vhd_type = [string]$info.VhdType }
}
function Get-ChildWorkerIdentity([object] $Vm) {
    $vmId = [string]$Vm.Id
    $systems = @(Get-CimInstance -Namespace 'root/virtualization/v2' -ClassName Msvm_ComputerSystem -Filter "Name='$vmId'" -ErrorAction SilentlyContinue)
    if ($systems.Count -ne 1 -or [int]$systems[0].ProcessID -le 0) { Fail 'owned Hyper-V VM metadata did not expose one worker PID' }
    $workers = @(Get-CimInstance Win32_Process -Filter "ProcessId=$([int]$systems[0].ProcessID)" -ErrorAction SilentlyContinue)
    if ($workers.Count -ne 1 -or [string]$workers[0].Name -ine 'vmwp.exe') { Fail 'owned Hyper-V VM metadata worker PID is not vmwp.exe' }
    return [ordered]@{ process_pid=[int]$systems[0].ProcessID; process_uuid=$vmId; process_start_time=[string]$workers[0].CreationDate; source='Msvm_ComputerSystem.ProcessID' }
}
function Emit([object] $Value) { $Value | ConvertTo-Json -Depth 30 -Compress }
function Assert-Artifact([string] $Path, [string] $ExpectedSha, [int64] $ExpectedSize) {
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { Fail 'artifact source is missing' }
    $item = Assert-NoReparse $Path 'artifact source'
    $sha = Sha $item.FullName
    if ($ExpectedSha -notmatch '^[0-9a-fA-F]{64}$' -or $sha -ne $ExpectedSha.ToLowerInvariant() -or ($ExpectedSize -ge 0 -and [int64]$item.Length -ne $ExpectedSize)) { Fail 'artifact source bytes differ from the planned digest/size' }
    return [ordered]@{ path = $item.FullName; sha256 = $sha; size = [int64]$item.Length }
}
function Invoke-Guest([object] $Child, [string] $GuestScript, [string] $GuestAction, [string] $ExpectedSha, [string] $ExpectedArtifactRole, [string] $ExpectedVersion, [string] $TokenEvidence, [string] $UiSource, [string] $LauncherSource) {
    $session = New-Session $Child
    try {
        $childRunId = [string]$Child.marker.run_id; $childCaseId = [string]$Child.marker.case_id; $childVmId = [guid]$Child.vm.Id
        $guestRoot = "C:\ProgramData\AmneziaLab\runs\$($Child.marker.run_id)\windows-x64\$($Child.marker.case_id)"
        $guestRunner = Join-Path $guestRoot 'release-lab.ps1'
        $guestArtifact = Join-Path $guestRoot 'current.exe'
        $guestReceipt = Join-Path $guestRoot 'receipt.json'
        $guestMarker = Join-Path $guestRoot 'run-marker.txt'
        $guestUi = Join-Path $guestRoot 'hyperv-ui-helper.ps1'
        $guestEvidence = Join-Path $guestRoot 'ui-evidence.json'
        $guestScreenshot = Join-Path $guestRoot 'ui-screenshot.png'
        $guestLauncher = Join-Path $guestRoot 'hyperv-interactive-launcher.ps1'
        $guestLauncherArgument = if($GuestAction -in @('interactive-start','interactive-collect')){$guestLauncher}else{$null}
        if ([string]::IsNullOrWhiteSpace($GuestScript) -or -not (Test-Path -LiteralPath $GuestScript -PathType Leaf)) { Fail 'guest runner source is missing' }
        Copy-Item -LiteralPath $GuestScript -Destination $guestRunner -ToSession $session -Force
        if (-not [string]::IsNullOrWhiteSpace($UiSource)) { Copy-Item -LiteralPath $UiSource -Destination $guestUi -ToSession $session -Force }
        if (-not [string]::IsNullOrWhiteSpace($LauncherSource)) { Copy-Item -LiteralPath $LauncherSource -Destination $guestLauncher -ToSession $session -Force }
        $remote = Invoke-Command -Session $session -ScriptBlock {
            param($root, $runner, $uiHelper, $uiEvidence, $uiScreenshot, $action, $runId, $caseId, $expectedVersion, $expectedArtifactRole, $baselineVersion, $candidateVersion, $expectedSha, $receipt, $artifact, $marker, $tokenPath, $vmId, $launcher, $launcherHash)
            if (-not (Test-Path -LiteralPath $runner -PathType Leaf)) { throw 'guest runner is missing' }
            function Invoke-InteractiveUiCapture {
                param([string]$Helper,[string]$Evidence,[string]$Screenshot,[string]$Id,[string]$Case,[string]$Vm)
                $explorer=@(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" | Where-Object { $_.SessionId -gt 0 } | Select-Object -First 1)
                if($explorer.Count -ne 1){throw 'interactive UI capture requires one logged-in Explorer session'}
                $owner=Invoke-CimMethod -InputObject $explorer[0] -MethodName GetOwner -ErrorAction Stop
                $userId=if([string]::IsNullOrWhiteSpace([string]$owner.Domain)){[string]$owner.User}else{"$($owner.Domain)\$($owner.User)"}
                $taskName="AmneziaLab-UiCapture-$Id-$Case"; if($taskName.Length -gt 200){$taskName=$taskName.Substring(0,200)}
                if(Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue){throw 'owned UI capture task already exists'}
                $args="-NoProfile -ExecutionPolicy Bypass -File `"$Helper`" -Action capture -RunId $Id -CaseId $Case -VmId $Vm -OutputPath `"$Evidence`" -ScreenshotPath `"$Screenshot`""
                $taskAction=New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument $args
                $taskPrincipal=New-ScheduledTaskPrincipal -UserId $userId -LogonType Interactive -RunLevel Limited
                $taskSettings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 5) -MultipleInstances IgnoreNew
                try {
                    Register-ScheduledTask -TaskName $taskName -Action $taskAction -Principal $taskPrincipal -Settings $taskSettings -Description 'Owned release-lab interactive UI evidence capture' -ErrorAction Stop | Out-Null
                    Start-ScheduledTask -TaskName $taskName -ErrorAction Stop
                    $deadline=(Get-Date).AddSeconds(30)
                    while((Get-Date)-lt $deadline -and -not(Test-Path -LiteralPath $Evidence -PathType Leaf)){Start-Sleep -Milliseconds 250}
                    if(-not(Test-Path -LiteralPath $Evidence -PathType Leaf)){throw 'interactive UI capture did not publish evidence before deadline'}
                    $text=[IO.File]::ReadAllText($Evidence)
                    if([string]::IsNullOrWhiteSpace($text)){throw 'interactive UI capture evidence is empty'}
                    return $text
                } finally {
                    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
                    if(Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue){throw 'interactive UI capture task remained after cleanup'}
                }
            }
            if ($action -eq 'interactive-collect') { $tokenPath = $uiEvidence; [void](Invoke-InteractiveUiCapture $uiHelper $uiEvidence $uiScreenshot $runId $caseId $vmId) }
            $runnerArgs=@($action,'windows-x64','-RunId',$runId,'-CaseId',$caseId,'-GuestRoot',$root,'-ExpectedVersion',$expectedVersion,'-ExpectedArtifactRole',$expectedArtifactRole,'-BaselineVersion',$baselineVersion,'-CandidateVersion',$candidateVersion,'-ExpectedSha256',$expectedSha,'-ArtifactPath',$artifact,'-ReceiptPath',$receipt,'-Transport','hyperv-powershell-direct','-GuestMarkerPath',$marker)
            if(-not [string]::IsNullOrWhiteSpace($tokenPath)){ $runnerArgs += @('-TokenEvidencePath',$tokenPath) }
            if(-not [string]::IsNullOrWhiteSpace($launcher)){ $runnerArgs += @('-LauncherPath',$launcher,'-LauncherSha256',$launcherHash) }
            $supervisorPath=Join-Path $root 'runner-supervisor.json'; $stdoutPath=Join-Path $root 'runner.stdout.log'; $stderrPath=Join-Path $root 'runner.stderr.log'
            $nestedArgs=@('-NoProfile','-ExecutionPolicy','Bypass','-File',$runner)+$runnerArgs
            $runnerProcess=Start-Process -FilePath powershell.exe -ArgumentList $nestedArgs -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath -PassThru -WindowStyle Hidden
            $runnerStart=[string]$runnerProcess.StartTime.ToUniversalTime().ToString('o'); $supervisor=[ordered]@{schema=1;run_id=$runId;case_id=$caseId;action=$action;artifact_sha256=$expectedSha;pid=[int]$runnerProcess.Id;start_time=$runnerStart;state='running';started_at=[DateTime]::UtcNow.ToString('o')}; $tmp="$supervisorPath.tmp"; $supervisor|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $tmp -Encoding UTF8; Move-Item -LiteralPath $tmp -Destination $supervisorPath -Force
            $runnerExitCode=$null; $runnerDeadline=(Get-Date).AddSeconds(900)
            do {
                Start-Sleep -Seconds 5
                $stillRunning=$null; try{$stillRunning=Get-Process -Id ([int]$runnerProcess.Id) -ErrorAction Stop}catch{$stillRunning=$null}
                if($null -eq $stillRunning){$runnerExitCode=[int]$runnerProcess.ExitCode;break}
            } while((Get-Date)-lt $runnerDeadline)
            if($null -ne $stillRunning){$supervisor.state='timeout';$supervisor.completed_at=[DateTime]::UtcNow.ToString('o');$tmp="$supervisorPath.tmp";$supervisor|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $tmp -Encoding UTF8;Move-Item -LiteralPath $tmp -Destination $supervisorPath -Force;throw 'guest runner exceeded bounded 900 second supervision deadline'}
            $supervisor.state=if($runnerExitCode -eq 0){'completed'}else{'failed'};$supervisor.exit_code=$runnerExitCode;$supervisor.completed_at=[DateTime]::UtcNow.ToString('o');$supervisor.receipt_present=[bool](Test-Path -LiteralPath $receipt -PathType Leaf);$tmp="$supervisorPath.tmp";$supervisor|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $tmp -Encoding UTF8;Move-Item -LiteralPath $tmp -Destination $supervisorPath -Force
            if ($runnerExitCode -ne 0) { throw "guest runner exited with ${runnerExitCode}" }
            if ($action -eq 'interactive-start') { [void](Invoke-InteractiveUiCapture $uiHelper $uiEvidence $uiScreenshot $runId $caseId $vmId) }
            $receiptText = [IO.File]::ReadAllText($receipt)
            $markerText = [IO.File]::ReadAllText($marker)
            $guestHash = (Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash.ToLowerInvariant()
            [ordered]@{ receipt = $receiptText; guest_marker = $markerText; guest_artifact_sha256 = $guestHash; guest_artifact_size = [int64](Get-Item -LiteralPath $artifact).Length; action = $action }
        } -ArgumentList $guestRoot, $guestRunner, $guestUi, $guestEvidence, $guestScreenshot, $GuestAction, $childRunId, $childCaseId, $ExpectedVersion, $ExpectedArtifactRole, $BaselineVersion, $CandidateVersion, $ExpectedSha, $guestReceipt, $guestArtifact, $guestMarker, $TokenEvidence, $childVmId, $guestLauncherArgument, $LauncherSha256
        return [ordered]@{ transport = 'hyperv-powershell-direct'; origin = 'guest'; injected = $false; vm_id = [string]$Child.vm.Id; parent_sha256 = [string]$Child.parent.sha256; readback = $remote }
    } finally { Remove-PSSession $session }
}

function Get-PublisherPrivateKey() {
    $encoded = [string]$env:AMNEZIA_LAB_PUBLISHER_KEY_B64
    if ([string]::IsNullOrWhiteSpace($encoded)) { Fail 'publisher key was not supplied through the runtime-only environment' }
    try { $bytes = [Convert]::FromBase64String($encoded); $value = [Text.Encoding]::UTF8.GetString($bytes) } catch { Fail 'publisher key environment value is not valid base64' }
    $env:AMNEZIA_LAB_PUBLISHER_KEY_B64 = $null
    if ($value -notmatch '-----BEGIN OPENSSH PRIVATE KEY-----' -or $value -notmatch '-----END OPENSSH PRIVATE KEY-----') { Fail 'publisher key is not an OpenSSH private key' }
    return $value
}

function Start-PublisherSeed([object] $Child) {
    if ([string]$Child.vm.State -ne 'Running') { Fail 'publisher profile seed requires a running child VM' }
    if ([string]::IsNullOrWhiteSpace($SeedHelperPath) -or -not (Test-Path -LiteralPath $SeedHelperPath -PathType Leaf)) { Fail 'publisher seed helper is missing' }
    if ($SeedHelperSha256 -notmatch '^[0-9a-fA-F]{64}$' -or (Sha $SeedHelperPath) -ne $SeedHelperSha256.ToLowerInvariant()) { Fail 'publisher seed helper hash differs from the planned helper' }
    if ([string]::IsNullOrWhiteSpace($AttemptNonce) -or $AttemptNonce -notmatch '^[0-9a-f]{48}$' -or [string]::IsNullOrWhiteSpace($SeedHost) -or $SeedHost -notmatch '^[0-9.]+$' -or [string]::IsNullOrWhiteSpace($SeedUser) -or $SeedUser -notmatch '^[A-Za-z0-9._-]{1,32}$' -or $SeedPort -lt 1 -or $SeedPort -gt 65535 -or $SeedFingerprint -notmatch '^SHA256:[A-Za-z0-9+/]{43}$') { Fail 'publisher seed endpoint or nonce is invalid' }
    $privateKey = Get-PublisherPrivateKey
    $session = New-Session $Child
    try {
        $root = "C:\ProgramData\AmneziaLab\runs\$RunId\windows-x64\$CaseId\publisher"
        $guestExe = Join-Path $root 'publisher_seed.exe'
        Invoke-Command -Session $session -ScriptBlock { param($path,$nonce); New-Item -ItemType Directory -Force -Path $path | Out-Null; Set-Content -LiteralPath (Join-Path $path 'attempt-nonce.txt') -Value $nonce -Encoding ASCII } -ArgumentList $root,$AttemptNonce | Out-Null
        Copy-Item -LiteralPath $SeedHelperPath -Destination $guestExe -ToSession $session -Force
        foreach ($name in @('Qt6Core.dll','icuuc.dll','msvcp140.dll','msvcp140_1.dll','msvcp140_2.dll','msvcp140_atomic_wait.dll','msvcp140_codecvt_ids.dll','vcruntime140.dll','vcruntime140_1.dll')) {
            $source = Join-Path 'C:\Program Files\AmneziaVPN' $name
            if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { Fail "publisher seed dependency is missing: $name" }
            Copy-Item -LiteralPath $source -Destination (Join-Path $root $name) -ToSession $session -Force
        }
        $result = Invoke-Command -Session $session -ScriptBlock {
            param($exe,$work,$hostName,$user,$port,$fingerprint,$key)
            $psi = [Diagnostics.ProcessStartInfo]::new(); $psi.FileName = $exe; $psi.WorkingDirectory = $work; $psi.Arguments = "$hostName $user $port $fingerprint"; $psi.UseShellExecute = $false; $psi.RedirectStandardInput = $true; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true
            $process = [Diagnostics.Process]::new(); $process.StartInfo = $psi; if (-not $process.Start()) { throw 'publisher seed helper did not start' }; $process.StandardInput.Write($key); $process.StandardInput.Close(); if (-not $process.WaitForExit(120000)) { try { $process.Kill() } catch {} ; throw 'publisher seed helper exceeded the bounded timeout' }
            [ordered]@{ exit_code=[int]$process.ExitCode; stdout=$process.StandardOutput.ReadToEnd(); stderr=$process.StandardError.ReadToEnd() }
        } -ArgumentList $guestExe,$root,$SeedHost,$SeedUser,$SeedPort,$SeedFingerprint,$privateKey
        if ([int]$result.exit_code -ne 0) { Fail "publisher seed helper exited with $($result.exit_code): $($result.stderr)" }
        return [ordered]@{ action='seed-profile'; passed=$true; transport='hyperv-powershell-direct'; origin='guest'; injected=$false; vm_id=[string]$Child.vm.Id; seed=$result }
    } finally { Remove-PSSession $session }
}

function Register-RelayServices([string] $RelayRootPath) {
    $script = Join-Path $PSScriptRoot 'hyperv_socket_relay.ps1'; if (-not (Test-Path -LiteralPath $script -PathType Leaf)) { Fail 'relay registry helper is missing' }
    $args = @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',$script,'-Action','register','-RelayRoot',$RelayRootPath,'-RunId',$RunId)
    $proc = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -Verb RunAs -WindowStyle Hidden -ArgumentList $args -Wait -PassThru
    if ($proc.ExitCode -ne 0) { Fail "relay registry registration failed with exit $($proc.ExitCode)" }
    try { $json = & (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $script -Action validate -RelayRoot $RelayRootPath -RunId $RunId | Out-String; return ($json | ConvertFrom-Json) } catch { Fail 'relay registry registration readback was invalid' }
}

function Unregister-RelayServices([string] $RelayRootPath) {
    $script = Join-Path $PSScriptRoot 'hyperv_socket_relay.ps1'
    $args = @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',$script,'-Action','unregister','-RelayRoot',$RelayRootPath,'-RunId',$RunId)
    $proc = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -Verb RunAs -WindowStyle Hidden -ArgumentList $args -Wait -PassThru
    if ($proc.ExitCode -ne 0) { Fail "relay registry unregistration failed with exit $($proc.ExitCode)" }
    try { $json = & (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $script -Action validate -RelayRoot $RelayRootPath -RunId $RunId | Out-String; return ($json | ConvertFrom-Json) } catch { Fail 'relay registry unregistration readback was invalid' }
}

function Wait-RelayReceipt([string] $Path) {
    $deadline = (Get-Date).AddSeconds(20); $last = ''
    do { if (Test-Path -LiteralPath $Path -PathType Leaf) { $last = [string](Get-Content -LiteralPath $Path | Select-Object -Last 1); if ($last -eq 'state=running') { return $true } }; Start-Sleep -Milliseconds 250 } while ((Get-Date) -lt $deadline)
    return $false
}

function Start-Relays([object] $Child) {
    if ([string]$Child.vm.State -ne 'Running') { Fail 'relay startup requires a running child VM' }
    if ($Child.vm.Id.ToString() -ne $Child.marker.vm_id) { Fail 'relay child VM ID differs from the owned marker' }
    if ([string]::IsNullOrWhiteSpace($ChildVmId) -or $ChildVmId -ine [string]$Child.vm.Id -or $AttemptNonce -notmatch '^[0-9a-f]{48}$') { Fail 'relay startup request is not bound to the owned child VM ID/nonce' }
    foreach ($value in @($RelayHelperPath,$RelaySupervisorPath,$RelayGuestTaskPath)) { if ([string]::IsNullOrWhiteSpace($value) -or -not (Test-Path -LiteralPath $value -PathType Leaf)) { Fail 'relay source path is missing' } }
    if ($RelayHelperSha256 -notmatch '^[0-9a-fA-F]{64}$' -or (Sha $RelayHelperPath) -ne $RelayHelperSha256.ToLowerInvariant()) { Fail 'relay helper hash differs from the frozen bytes' }
    $hostRoot = Join-Path (Join-Path 'C:\ProgramData\AmneziaReleaseLab\hyperv\runs' $RunId) 'relay'; New-Item -ItemType Directory -Force -Path $hostRoot | Out-Null
    $registry = Register-RelayServices $hostRoot
    $session = New-Session $Child
    $guestRoot = "C:\ProgramData\AmneziaLab\runs\$RunId\windows-x64\$CaseId\relay"; $guestRelay = Join-Path $guestRoot 'relay.exe'; $guestSupervisor = Join-Path $guestRoot 'supervisor.exe'; $guestTask = Join-Path $guestRoot 'guest-task.ps1'
    try {
        Invoke-Command -Session $session -ScriptBlock { param($path); New-Item -ItemType Directory -Force -Path $path | Out-Null } -ArgumentList $guestRoot | Out-Null
        Copy-Item -LiteralPath $RelayHelperPath -Destination $guestRelay -ToSession $session -Force; Copy-Item -LiteralPath $RelaySupervisorPath -Destination $guestSupervisor -ToSession $session -Force; Copy-Item -LiteralPath $RelayGuestTaskPath -Destination $guestTask -ToSession $session -Force
        $guest = @(); foreach ($channel in @('ssh','http')) {
            $lease = Join-Path $guestRoot "$channel.lease"; $receipt = Join-Path $guestRoot "$channel.receipt"
            $guest += Invoke-Command -Session $session -ScriptBlock { param($task,$ch,$id,$case,$vm,$sup,$relay,$leasePath,$receiptPath,$hash); & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $task -Action start -RunId $id -CaseId $case -Channel $ch -VmId $vm -SupervisorPath $sup -RelayPath $relay -OwnershipFile $leasePath -ReceiptPath $receiptPath -HelperSha256 $hash } -ArgumentList $guestTask,$channel,$RunId,$CaseId,$Child.vm.Id,$guestSupervisor,$guestRelay,$lease,$receipt,$RelayHelperSha256
        }
    } finally { Remove-PSSession $session }
    $host = @(); foreach ($channel in @('ssh','http')) {
        $lease = Join-Path $hostRoot "host-$channel.lease"; $receipt = Join-Path $hostRoot "host-$channel.receipt"; $args = @('--relay-exe',$RelayHelperPath,'--mode','host','--channel',$channel,'--vm-id',$Child.vm.Id.ToString('B'),'--run-id',$RunId,'--case-id',$CaseId,'--ownership-file',$lease,'--receipt-path',$receipt,'--helper-sha256',$RelayHelperSha256,'--ready-timeout-ms','15000')
        $process = Start-Process -FilePath $RelaySupervisorPath -Verb RunAs -ArgumentList $args -WindowStyle Hidden -PassThru
        if (-not (Wait-RelayReceipt $receipt)) { Fail "host $channel relay did not become ready" }
        $host += [ordered]@{ channel=$channel; pid=[int]$process.Id; lease=$lease; receipt=$receipt; running=(-not $process.HasExited) }
    }
    [ordered]@{ action='relays-start'; passed=$true; transport='hyperv-powershell-direct'; origin='guest'; injected=$false; run_id=$RunId; case_id=$CaseId; vm_id=[string]$Child.vm.Id; registry=$registry; guest=$guest; host=$host; host_network_mutation=$false }
}

function Stop-Relays([object] $Child) {
    $errors = @(); $hostRoot = Join-Path (Join-Path 'C:\ProgramData\AmneziaReleaseLab\hyperv\runs' $RunId) 'relay'; $guestRoot = "C:\ProgramData\AmneziaLab\runs\$RunId\windows-x64\$CaseId\relay"; $guestTask = Join-Path $guestRoot 'guest-task.ps1'; $guestStopped = $true; $hostStopped = $true
    if ([string]$Child.vm.State -eq 'Running') { $session = $null; try { $session = New-Session $Child; foreach ($channel in @('ssh','http')) { $lease=Join-Path $guestRoot "$channel.lease"; $receipt=Join-Path $guestRoot "$channel.receipt"; try { $answer=Invoke-Command -Session $session -ScriptBlock { param($task,$ch,$id,$case,$vm,$sup,$relay,$leasePath,$receiptPath,$hash); if (-not (Test-Path -LiteralPath $task -PathType Leaf)) { throw 'guest relay task is missing' }; & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $task -Action stop -RunId $id -CaseId $case -Channel $ch -VmId $vm -SupervisorPath $sup -RelayPath $relay -OwnershipFile $leasePath -ReceiptPath $receiptPath -HelperSha256 $hash } -ArgumentList $guestTask,$channel,$RunId,$CaseId,$Child.vm.Id,(Join-Path $guestRoot 'supervisor.exe'),(Join-Path $guestRoot 'relay.exe'),$lease,$receipt,$RelayHelperSha256; if ([string]$answer.terminal_state -ne 'state=stopped') { $guestStopped=$false } } catch { $guestStopped=$false; $errors += "guest ${channel}: $($_.Exception.Message)" } } } catch { $guestStopped=$false; $errors += "guest session: $($_.Exception.Message)" } finally { if ($null -ne $session) { Remove-PSSession $session -ErrorAction SilentlyContinue } } }
    foreach ($channel in @('ssh','http')) { $lease=Join-Path $hostRoot "host-$channel.lease"; if (Test-Path -LiteralPath $lease -PathType Leaf) { try { $stop=Start-Process -FilePath $RelaySupervisorPath -Verb RunAs -ArgumentList @('--stop','--run-id',$RunId,'--case-id',$CaseId,'--ownership-file',$lease) -WindowStyle Hidden -Wait -PassThru; if ($stop.ExitCode -ne 0) { throw "exit $($stop.ExitCode)" } } catch { $hostStopped=$false; $errors += "host ${channel}: $($_.Exception.Message)" } } }
    $registryStopped = $false
    if ($guestStopped -and $hostStopped) {
        try { [void](Unregister-RelayServices $hostRoot); $registryStopped=$true } catch { $errors += "registry: $($_.Exception.Message)" }
    } else {
        $errors += 'relay registry ownership retained because one or more relays did not stop'
    }
    if ($errors.Count -gt 0) { Fail ($errors -join '; ') }
    [ordered]@{ action='relays-stop'; passed=$true; relays_stopped=($guestStopped -and $hostStopped); relay_registry_unregistered=$registryStopped; host_network_mutation=$false; transport='hyperv-powershell-direct'; origin='guest'; injected=$false }
}

if ($Action -eq 'plan') {
    $parent = Get-Parent $ParentRoot
    Emit ([ordered]@{ schema = 1; backend = 'hyperv'; profile = 'windows-x64'; transport = 'hyperv-powershell-direct'; ready = $true; cases = @('thin-clean','thin-upgrade','thin-reinstall','outer-clean','outer-upgrade','outer-reinstall','outer-interactive','publisher-clean'); parent_vm_id = [string]$parent.vm.Id; parent_state = [string]$parent.vm.State; parent_vhdx = $parent.vhdx; parent_sha256 = $parent.sha256; child_root = (Full (Join-Path $RunsRoot 'RUN_ID\windows-x64\cases\CASE_ID')); host_network_mutation = $false; release_passed = $false; product_verified = $false })
    exit 0
}
if ($Action -eq 'create-child') {
    Assert-CaseId $CaseId | Out-Null
    $parent = Get-Parent $ParentRoot; $root = CaseRoot $RunsRoot $RunId $CaseId
    if ((Test-Path -LiteralPath $root -PathType Container) -and (@(Get-ChildItem -LiteralPath $root -Force).Count -gt 0)) { Fail 'child root already exists and is non-empty' }
    New-Item -ItemType Directory -Force -Path (Join-Path $root 'disk'),(Join-Path $root 'vm'),(Join-Path $root 'staging') | Out-Null
    $disk = Join-Path $root 'disk\child.vhdx'; $vmPath = Join-Path $root 'vm'
    $nameBytes=[Text.Encoding]::UTF8.GetBytes("$RunId|$CaseId"); $nameHash=([BitConverter]::ToString(([Security.Cryptography.SHA256]::Create()).ComputeHash($nameBytes))).Replace('-','').ToLowerInvariant().Substring(0,12)
    $runSlug=($RunId -replace '[^A-Za-z0-9._-]','_'); if($runSlug.Length -gt 32){$runSlug=$runSlug.Substring(0,32)}
    $name = "AmneziaLab-$runSlug-$CaseId-$nameHash"
    if ($name.Length -gt 80) { $name = $name.Substring(0,80) }
    if (Get-VM -Name $name -ErrorAction SilentlyContinue) { Fail 'child VM name already exists' }
    $vm=$null; $intentPath=Join-Path $root '.creation-intent.json'
    try {
    $intent=[ordered]@{schema=1; backend='hyperv'; profile='windows-x64'; run_id=$RunId; case_id=$CaseId; vm_id=''; vm_name=$name; child_vhdx=$disk; run_root=$root; parent_vhdx=$parent.vhdx; parent_sha256=$parent.sha256; state='creation-intent'; created_at=[DateTime]::UtcNow.ToString('o')}
    Write-JsonNoClobber $intentPath $intent
    New-VHD -Path $disk -ParentPath $parent.vhdx -Differencing -ErrorAction Stop | Out-Null
    $vm = New-VM -Name $name -Generation 2 -MemoryStartupBytes 8GB -VHDPath $disk -Path $vmPath -ErrorAction Stop
    $intent.vm_id=[string]$vm.Id; $intent.state='vm-created'; $intent.updated_at=[DateTime]::UtcNow.ToString('o')
    $intent | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $intentPath -Encoding UTF8
    Set-VMProcessor -VM $vm -Count 4
    Set-VM -VM $vm -AutomaticCheckpointsEnabled:$false
    Set-VMFirmware -VM $vm -EnableSecureBoot On -SecureBootTemplate MicrosoftWindows
    Set-VMKeyProtector -VM $vm -NewLocalKeyProtector
    Enable-VMTPM -VM $vm
    foreach ($adapter in @(Get-VMNetworkAdapter -VM $vm)) { Remove-VMNetworkAdapter -VMNetworkAdapter $adapter -Confirm:$false }
    foreach ($dvd in @(Get-VMDvdDrive -VM $vm)) { Remove-VMDvdDrive -VMDvdDrive $dvd -Confirm:$false }
    $ownedDiskDrive = @(Get-VMHardDiskDrive -VM $vm -ErrorAction Stop)
    if ($ownedDiskDrive.Count -ne 1) { Fail 'new child VM did not expose exactly one owned VHDX' }
    Set-VMFirmware -VM $vm -FirstBootDevice $ownedDiskDrive[0]
    $parentAfter = Get-Parent $ParentRoot
    if ($parentAfter.sha256 -ne $parent.sha256 -or $parentAfter.vhdx -ine $parent.vhdx -or [string]$parentAfter.vm.Id -ne [string]$parent.vm.Id) { Fail 'sealed parent changed during child creation' }
    $marker = [ordered]@{ schema = 1; backend = 'hyperv'; profile = 'windows-x64'; run_id = $RunId; case_id = $CaseId; vm_id = [string]$vm.Id; vm_name = $name; run_root = $root; child_vhdx = $disk; parent_vhdx = $parent.vhdx; parent_sha256 = $parentAfter.sha256; parent_sha256_before = $parent.sha256; parent_sha256_after = $parentAfter.sha256; parent_vm_id = [string]$parentAfter.vm.Id; transport = 'hyperv-powershell-direct'; state = 'created'; created_at = [DateTime]::UtcNow.ToString('o') }
    Write-JsonNoClobber (Join-Path $root '.owned-child.json') $marker
    Remove-Item -LiteralPath $intentPath -Force
    Emit ([ordered]@{ action = 'create-child'; child = $marker; parent_readback = [ordered]@{ before_sha256=$parent.sha256; after_sha256=$parentAfter.sha256; before_vm_id=[string]$parent.vm.Id; after_vm_id=[string]$parentAfter.vm.Id; before_vhdx=$parent.vhdx; after_vhdx=$parentAfter.vhdx }; configuration = (Verify-ChildConfig ([ordered]@{ root=$root; marker=[pscustomobject]$marker; vm=$vm; parent=$parentAfter })) })
    exit 0
    } catch {
        $original=$_.Exception.Message; $cleanup=@()
        if($null -ne $vm){try{Remove-VM -VM $vm -Force -Confirm:$false}catch{$cleanup += "Remove-VM: $($_.Exception.Message)"}}
        if(Test-Path -LiteralPath $disk -PathType Leaf){try{Remove-Item -LiteralPath $disk -Force}catch{$cleanup += "Remove child VHDX: $($_.Exception.Message)"}}
        if(Test-Path -LiteralPath $vmPath -PathType Container){try{Remove-Item -LiteralPath $vmPath -Recurse -Force}catch{$cleanup += "Remove child VM state: $($_.Exception.Message)"}}
        foreach($ownedDir in @((Join-Path $root 'disk'),(Join-Path $root 'staging'))){if(Test-Path -LiteralPath $ownedDir -PathType Container){try{Remove-Item -LiteralPath $ownedDir -Recurse -Force}catch{$cleanup += "Remove child directory: $($_.Exception.Message)"}}}
        if($cleanup.Count -eq 0 -and (Test-Path -LiteralPath $intentPath -PathType Leaf)){try{Remove-Item -LiteralPath $intentPath -Force}catch{$cleanup += "Remove creation intent: $($_.Exception.Message)"}}
        $markerPath = Join-Path $root '.owned-child.json'; if($cleanup.Count -eq 0 -and (Test-Path -LiteralPath $markerPath -PathType Leaf)){try{Remove-Item -LiteralPath $markerPath -Force}catch{$cleanup += "Remove owned child marker: $($_.Exception.Message)"}}
        $remaining=@(); if(Test-Path -LiteralPath $root -PathType Container){$remaining=@(Get-ChildItem -LiteralPath $root -Force | Select-Object -ExpandProperty Name)}
        if($cleanup.Count -gt 0 -or $remaining.Count -gt 0){$details=@($cleanup + @("remaining=$($remaining -join ',')")); Fail "$original; creation cleanup incomplete; preserve owned recovery path ${root}: $($details -join '; ')"}
        if(Test-Path -LiteralPath $root -PathType Container){Remove-Item -LiteralPath $root -Force}
        throw
    }
}
$child = $null
if ($Action -eq 'reset') {
    try { $child = Read-Child $RunsRoot $RunId $ParentRoot $CaseId }
    catch {
        $orphanRoot = CaseRoot $RunsRoot $RunId $CaseId
        $expectedName = Expected-ChildName $RunId $CaseId
        $nameLookupErrors = @()
        # Get-VM -Name rejects some long historical owned names as an invalid
        # parameter before it can return ObjectNotFound.  Enumerate and compare
        # exactly so absence recovery remains read-only and fail-closed.
        $namedVm = @(Get-VM -ErrorAction SilentlyContinue -ErrorVariable nameLookupErrors | Where-Object { $_.Name -ceq $expectedName })
        if (@($nameLookupErrors | Where-Object { [string]$_.FullyQualifiedErrorId -notmatch 'ObjectNotFound' -and [string]$_.Exception.Message -notmatch '(?i)did not find|not found' }).Count -gt 0) { throw $nameLookupErrors[0] }
        if (-not (Test-Path -LiteralPath $orphanRoot -PathType Container) -and $namedVm.Count -eq 0) {
            $orphanParent = Get-Parent $ParentRoot
            $orphanParentAfter = Get-Parent $ParentRoot
            Emit ([ordered]@{ action='reset'; run_id=$RunId; case_id=$CaseId; removed_child=$true; absence_proof=[ordered]@{ case_root_absent=$true; expected_vm_name=$expectedName; expected_vm_absent=$true }; parent_sha256_before=$orphanParent.sha256; parent_sha256_after=$orphanParentAfter.sha256; release_passed=$false }); exit 0
        }
        $intentPath = Join-Path $orphanRoot '.creation-intent.json'
        if ((Test-Path -LiteralPath $intentPath -PathType Leaf) -and -not (Test-Path -LiteralPath (Join-Path $orphanRoot '.owned-child.json') -PathType Leaf)) {
            $intent = Read-Json $intentPath 'creation intent'
            if ($intent.schema -ne 1 -or $intent.backend -ne 'hyperv' -or $intent.profile -ne 'windows-x64' -or [string]$intent.run_id -ne $RunId -or [string]$intent.case_id -ne $CaseId -or [string]$intent.vm_name -ne $expectedName -or [string]$intent.state -notin @('creation-intent','vm-created')) { throw 'creation intent identity mismatch' }
            $intentVmErrors=@(); $intentVm=@()
            if (-not [string]::IsNullOrWhiteSpace([string]$intent.vm_id)) { $intentVm=@(Get-VM -Id ([guid]$intent.vm_id) -ErrorAction SilentlyContinue -ErrorVariable intentVmErrors) }
            if (@($intentVmErrors | Where-Object { [string]$_.FullyQualifiedErrorId -notmatch 'ObjectNotFound' -and [string]$_.Exception.Message -notmatch '(?i)did not find|not found' }).Count -gt 0) { throw $intentVmErrors[0] }
            if ($intentVm.Count -ne 0 -or $namedVm.Count -ne 0) { throw 'creation intent still resolves to a VM; refusing absence cleanup' }
            Assert-NoReparse $orphanRoot 'creation intent root' | Out-Null
            foreach ($entry in @(Get-ChildItem -LiteralPath $orphanRoot -Force)) {
                if ($entry.Name -notin @('.creation-intent.json','disk','vm','staging')) { throw "creation intent root contains unexpected entry: $($entry.Name)" }
                Assert-NoReparse $entry.FullName 'creation intent resource' | Out-Null
            }
            $intentParent = Get-Parent $ParentRoot
            Remove-Item -LiteralPath $orphanRoot -Recurse -Force
            $intentParentAfter = Get-Parent $ParentRoot
            if ($intentParent.sha256 -ne $intentParentAfter.sha256) { throw 'sealed parent changed during creation-intent recovery' }
            Emit ([ordered]@{ action='reset'; run_id=$RunId; case_id=$CaseId; removed_child=$true; absence_proof=[ordered]@{ creation_intent_recovered=$true; expected_vm_name=$expectedName; expected_vm_absent=$true }; parent_sha256_before=$intentParent.sha256; parent_sha256_after=$intentParentAfter.sha256; release_passed=$false }); exit 0
        }
        # A failed create can leave only its owned marker after Hyper-V has
        # already removed the VM/disk. Recover that exact orphan through the
        # normal reset path; never infer ownership from an arbitrary root.
        $orphanMarkerPath = Join-Path $orphanRoot '.owned-child.json'
        if (-not (Test-Path -LiteralPath $orphanMarkerPath -PathType Leaf)) { throw }
        $orphan = Read-Json $orphanMarkerPath 'orphan child marker'
        if ($orphan.schema -ne 1 -or $orphan.backend -ne 'hyperv' -or $orphan.profile -ne 'windows-x64' -or [string]$orphan.run_id -ne $RunId -or [string]$orphan.case_id -ne $CaseId) { throw }
        $orphanVmError=@(); $orphanVm = @(Get-VM -Id ([guid]$orphan.vm_id) -ErrorAction SilentlyContinue -ErrorVariable orphanVmError)
        if(@($orphanVmError | Where-Object { [string]$_.FullyQualifiedErrorId -notmatch 'ObjectNotFound' -and [string]$_.Exception.Message -notmatch '(?i)did not find|not found' }).Count -gt 0){ throw $orphanVmError[0] }
        if ($orphanVm.Count -ne 0) { Fail 'orphan marker still resolves to a VM; refusing recovery deletion' }
        $orphanParent = Get-Parent $ParentRoot
        $orphanEntries = @(Get-ChildItem -LiteralPath $orphanRoot -Force | Select-Object -ExpandProperty Name)
        if (@($orphanEntries | Where-Object { $_ -ne '.owned-child.json' }).Count -ne 0) { Fail 'orphan child root contains resources; refusing recovery deletion' }
        Remove-Item -LiteralPath $orphanMarkerPath -Force
        Remove-Item -LiteralPath $orphanRoot -Force
        $orphanParentAfter = Get-Parent $ParentRoot
        if ($orphanParent.sha256 -ne $orphanParentAfter.sha256) { Fail 'sealed parent changed during orphan recovery reset' }
        Emit ([ordered]@{ action='reset'; run_id=$RunId; case_id=$CaseId; removed_child=$true; orphan_recovered=$true; parent_sha256_before=$orphanParent.sha256; parent_sha256_after=$orphanParentAfter.sha256; release_passed=$false }); exit 0
    }
}
if ($null -eq $child) { $child = Read-Child $RunsRoot $RunId $ParentRoot $CaseId }
if ($Action -eq 'seed-profile') {
    Emit (Start-PublisherSeed $child); exit 0
}
if ($Action -eq 'relays-start') {
    Emit (Start-Relays $child); exit 0
}
if ($Action -eq 'relays-stop') {
    Emit (Stop-Relays $child); exit 0
}
if ($Action -eq 'publish') {
    if ([string]$child.vm.State -ne 'Running') { Fail 'publisher CLI requires a running child VM' }
    $session = New-Session $child
    try {
        $remote = Invoke-Command -Session $session -ScriptBlock {
            param($id,$case,$nonce)
            $exe='C:\Program Files\AmneziaVPN\AmneziaVPN.exe'; $root="C:\ProgramData\AmneziaLab\runs\$id\windows-x64\$case"; $out=Join-Path $root 'publisher.stdout.log'; $err=Join-Path $root 'publisher.stderr.log'
            if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw 'installed AmneziaVPN.exe is missing' }
            if (-not (Test-Path -LiteralPath (Join-Path $root 'publisher\attempt-nonce.txt') -PathType Leaf) -or [string](Get-Content -LiteralPath (Join-Path $root 'publisher\attempt-nonce.txt') -Raw).Trim() -ne $nonce) { throw 'publisher attempt nonce marker is missing or mismatched' }
            Remove-Item -LiteralPath $out,$err -Force -ErrorAction SilentlyContinue
            $process=Start-Process -FilePath $exe -ArgumentList @('--publish-bundled-updates-once') -RedirectStandardOutput $out -RedirectStandardError $err -PassThru -WindowStyle Hidden
            if (-not $process.WaitForExit(900000)) { try { $process.Kill() } catch {} ; throw 'publisher CLI exceeded bounded 15 minute timeout' }
            $stdoutText=[string](Get-Content -LiteralPath $out -Raw -ErrorAction SilentlyContinue); $stderrText=[string](Get-Content -LiteralPath $err -Raw -ErrorAction SilentlyContinue); if($stdoutText.Length -gt 262144){$stdoutText=$stdoutText.Substring(0,262144)}; if($stderrText.Length -gt 262144){$stderrText=$stderrText.Substring(0,262144)}
            [ordered]@{ exit_code=[int]$process.ExitCode; stdout=$stdoutText; stderr=$stderrText; stdout_path=$out; stderr_path=$err }
        } -ArgumentList $RunId,$CaseId,$AttemptNonce
        Emit ([ordered]@{ action='publish'; passed=([int]$remote.exit_code -eq 0); transport='hyperv-powershell-direct'; origin='guest'; injected=$false; run_id=$RunId; case_id=$CaseId; vm_id=[string]$child.vm.Id; raw=$remote }); exit 0
    } finally { Remove-PSSession $session }
}
if ($Action -eq 'status') { Emit ([ordered]@{ action='status'; child=$child.marker; configuration=(Verify-ChildConfig $child); parent_sha256=$child.parent.sha256; release_passed=$false; product_verified=$false }); exit 0 }
if ($Action -eq 'start') {
    Verify-ChildConfig $child | Out-Null
    if ([string]$child.vm.State -ne 'Off') { Fail 'child VM must be Off before start' }
    Start-VM -VM $child.vm | Out-Null
    $running = @(Get-VM -Id ([guid]$child.vm.Id) -ErrorAction Stop)[0]
    if ([string]$running.State -ne 'Running') { Fail 'child VM did not reach Running state' }
    $worker=Get-ChildWorkerIdentity $running; $startMarker=[ordered]@{}; foreach($property in $child.marker.PSObject.Properties){$startMarker[$property.Name]=$property.Value}; $startMarker['state']='running'; $startMarker['process_pid']=$worker.process_pid; $startMarker['process_uuid']=$worker.process_uuid; $startMarker['process_start_time']=$worker.process_start_time; Emit ([ordered]@{ action='start'; child=$startMarker; worker=$worker; configuration=(Verify-ChildConfig $child); parent_sha256=(Get-Parent $ParentRoot).sha256 }); exit 0
}
if ($Action -eq 'stop') {
    if ([string]$child.vm.State -eq 'Running') { Stop-VM -VM $child.vm -TurnOff:$false -Force | Out-Null }
    $deadline=(Get-Date).AddSeconds(90); do { $stopped=@(Get-VM -Id ([guid]$child.vm.Id))[0]; if ([string]$stopped.State -eq 'Off'){break}; Start-Sleep -Seconds 1 } while((Get-Date)-lt $deadline)
    if ([string]$stopped.State -ne 'Off') { Fail 'child VM did not stop within bounded wait' }
    $child.marker.state='stopped'; Emit ([ordered]@{ action='stop'; child=$child.marker; configuration=(Verify-ChildConfig $child); parent_sha256=(Get-Parent $ParentRoot).sha256 }); exit 0
}
if ($Action -eq 'probe') {
    if ([string]$child.vm.State -ne 'Running') { Fail 'child VM must be Running for probe' }
    $childVmId = [string]$child.vm.Id
    $session=New-Session $child; try {
        $probe=Invoke-Command -Session $session -ScriptBlock {
            param($runId,$caseId,$vmId)
            $p='C:\ProgramData\AmneziaLab\READY'; if(-not(Test-Path -LiteralPath $p -PathType Leaf)){throw 'guest readiness marker missing'}
            $root="C:\ProgramData\AmneziaLab\runs\$runId\windows-x64\$caseId"; $marker=Join-Path $root 'run-marker.txt'; New-Item -ItemType Directory -Force -Path $root | Out-Null
            $expectedMarker = "amnezia-release-lab:${runId}:windows-x64`r`nbackend=hyperv`r`ncase_id=$caseId`r`nvm_id=$vmId`r`n"
            if(Test-Path -LiteralPath $marker -PathType Leaf){ if([IO.File]::ReadAllText($marker) -ne $expectedMarker){throw 'existing guest case marker does not match this run/case/VM'} } else { [IO.File]::WriteAllText($marker,$expectedMarker,(New-Object Text.ASCIIEncoding)) }
            [ordered]@{ readiness=[IO.File]::ReadAllText($p); guest_marker=[IO.File]::ReadAllText($marker) }
        } -ArgumentList $RunId,$CaseId,$childVmId
    } finally { Remove-PSSession $session }
    if ($probe.guest_marker -notmatch "(?m)^amnezia-release-lab:$([regex]::Escape($RunId)):windows-x64\s*$" -or $probe.guest_marker -notmatch "(?m)^case_id=$([regex]::Escape($CaseId))\s*$" -or $probe.guest_marker -notmatch "(?m)^vm_id=$([regex]::Escape($childVmId))\s*$") { Fail 'guest case marker readback is not bound to this run/case/VM' }
    $readiness=$probe.readiness
    if ($readiness -notmatch '(?m)^profile=windows-x64\s*$' -or $readiness -notmatch '(?m)^phase=ready\s*$' -or $readiness -notmatch '(?m)^candidate_credentials=absent\s*$') { Fail 'guest readiness marker is invalid' }
    Emit ([ordered]@{ action='probe'; transport='hyperv-powershell-direct'; origin='guest'; injected=$false; vm_id=[string]$child.vm.Id; parent_sha256=$child.parent.sha256; guest_marker=$probe.guest_marker; readiness_marker=$readiness }); exit 0
}
if ($Action -eq 'precondition') {
    if ([string]$child.vm.State -ne 'Running') { Fail 'child VM must be Running for precondition' }
    $childVmId = [string]$child.vm.Id
    $session=New-Session $child; try {
        $guestRoot="C:\ProgramData\AmneziaLab\runs\$RunId\windows-x64\$CaseId"; $guestMarker=Join-Path $guestRoot 'run-marker.txt'
        $proof=Invoke-Command -Session $session -ScriptBlock {
            param($marker,$id,$case,$vmid)
            if (-not (Test-Path -LiteralPath $marker -PathType Leaf)) { throw 'guest case marker missing' }
            $lines=@(Get-Content -LiteralPath $marker); if($lines -notcontains "amnezia-release-lab:${id}:windows-x64" -or $lines -notcontains "case_id=$case" -or $lines -notcontains "vm_id=$vmid"){throw 'guest case marker binding mismatch'}
            $service=Get-CimInstance Win32_Service -Filter "Name='AmneziaVPN-service'" -ErrorAction SilentlyContinue
            $components=Test-Path -LiteralPath 'C:\Program Files\AmneziaVPN\components.xml' -PathType Leaf
            $installRoot=Test-Path -LiteralPath 'C:\Program Files\AmneziaVPN' -PathType Container
            [ordered]@{ case_id=$case; run_id=$id; vm_id=$vmid; service_present=[bool]($null -ne $service); install_root_present=[bool]$installRoot; components_present=[bool]$components; clean=[bool]($null -eq $service -and -not $installRoot -and -not $components) }
        } -ArgumentList $guestMarker,$RunId,$CaseId,$childVmId
    } finally { Remove-PSSession $session }
    if ($proof.clean -ne $true) { Fail 'clean case precondition found installed product/service/components' }
    Emit ([ordered]@{ action='precondition'; proof=$proof; transport='hyperv-powershell-direct'; origin='guest'; injected=$false; vm_id=[string]$child.vm.Id; parent_sha256=$child.parent.sha256 }); exit 0
}
if ($Action -eq 'prepare-interactive') {
    if ([string]$child.vm.State -ne 'Running') { Fail 'child VM must be Running for interactive preparation' }
    $credential=Get-CredentialFromStdin; $plain=Get-PlainCredential $credential
    $session=New-PSSession -VMId ([guid]$child.vm.Id) -Credential $credential -ErrorAction Stop
    $before=$null; $after=$null; $restartError=$null; $rebootObserved=$false
    $cleanupReadback=$null; $cleanupError=$null; $cleanupAttempted=$false
    $cleanupGuest = {
        param($cleanupCredential,$runId,$caseId)
        $s=$null
        try {
            $s=New-PSSession -VMId ([guid]$child.vm.Id) -Credential $cleanupCredential -ErrorAction Stop
            Invoke-Command -Session $s -ScriptBlock {
                param($id,$case)
                $key='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'; New-ItemProperty -LiteralPath $key -Name AutoAdminLogon -PropertyType String -Value '0' -Force | Out-Null; Remove-ItemProperty -LiteralPath $key -Name DefaultPassword -ErrorAction SilentlyContinue; Remove-ItemProperty -LiteralPath $key -Name DefaultUserName -ErrorAction SilentlyContinue; Remove-ItemProperty -LiteralPath $key -Name DefaultDomainName -ErrorAction SilentlyContinue
                $taskName="AmneziaLab-Interactive-$id-$case"; Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
                $props=Get-ItemProperty -LiteralPath $key -ErrorAction Stop; $remainingTask=Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
                [ordered]@{ auto_admin_logon=[string]$props.AutoAdminLogon; default_password_present=($props.PSObject.Properties.Name -contains 'DefaultPassword'); task_present=($null -ne $remainingTask) }
            } -ArgumentList $runId,$caseId
        } finally { if($null -ne $s){Remove-PSSession $s -ErrorAction SilentlyContinue} }
    }
    try {
        $before=Invoke-Command -Session $session -ScriptBlock { $os=Get-CimInstance Win32_OperatingSystem; [ordered]@{ last_boot=[string]$os.LastBootUpTime; explorer_count=@(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" -ErrorAction SilentlyContinue).Count } }
        Invoke-Command -Session $session -ScriptBlock {
            param($password,$runId,$caseId)
            $marker="C:\ProgramData\AmneziaLab\runs\$runId\windows-x64\$caseId\run-marker.txt"
            if(-not(Test-Path -LiteralPath $marker -PathType Leaf)){throw 'guest case marker missing before autologon preparation'}
            $lines=@(Get-Content -LiteralPath $marker); if($lines -notcontains "amnezia-release-lab:${runId}:windows-x64" -or $lines -notcontains "case_id=$caseId"){throw 'guest marker binding mismatch before autologon preparation'}
            $key='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
            New-ItemProperty -LiteralPath $key -Name AutoAdminLogon -PropertyType String -Value '1' -Force | Out-Null
            New-ItemProperty -LiteralPath $key -Name DefaultUserName -PropertyType String -Value 'labadmin' -Force | Out-Null
            New-ItemProperty -LiteralPath $key -Name DefaultDomainName -PropertyType String -Value '.' -Force | Out-Null
            New-ItemProperty -LiteralPath $key -Name DefaultPassword -PropertyType String -Value $password -Force | Out-Null
            Restart-Computer -Force -Confirm:$false
        } -ArgumentList $plain,$RunId,$CaseId | Out-Null
    } catch { $restartError=$_.Exception }
    finally { Remove-PSSession $session -ErrorAction SilentlyContinue }
    $readinessError=$null
    try {
      $deadline=(Get-Date).AddMinutes(5); $after=$null; $reconnected=$null
      do {
        Start-Sleep -Seconds 2
        try {
            $reconnected=New-PSSession -VMId ([guid]$child.vm.Id) -Credential $credential -ErrorAction Stop
            $after=Invoke-Command -Session $reconnected -ScriptBlock { $os=Get-CimInstance Win32_OperatingSystem; $explorer=@(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -gt 0 }); [ordered]@{ last_boot=[string]$os.LastBootUpTime; explorer_count=$explorer.Count; explorer_sessions=@($explorer | ForEach-Object { [int]$_.SessionId }) } }
            Remove-PSSession $reconnected; $reconnected=$null
            if($after.explorer_count -gt 0){break}
        } catch { if($reconnected){Remove-PSSession $reconnected -ErrorAction SilentlyContinue; $reconnected=$null} }
      } while((Get-Date)-lt $deadline)
      if($null -eq $after -or $null -eq $before -or $after.last_boot -eq $before.last_boot -or [int]$after.explorer_count -lt 1){ $readinessError='guest autologon/session preparation did not prove reboot and Explorer readiness' } else { $rebootObserved=$true }
    } finally {
      $cleanupAttempted=$true
      try { $cleanupReadback=& $cleanupGuest $credential $RunId $CaseId } catch { $cleanupError=$_.Exception }
    }
    if($null -ne $readinessError){ if($null -ne $restartError){ throw $restartError }; Fail $readinessError }
    if($null -ne $cleanupError -or $null -eq $cleanupReadback -or [string]$cleanupReadback.auto_admin_logon -ne '0' -or $cleanupReadback.default_password_present -eq $true -or $cleanupReadback.task_present -eq $true){ if($null -ne $cleanupError){throw $cleanupError}; Fail 'guest interactive cleanup was not fully read back; preserving failed case' }
    Emit ([ordered]@{ action='prepare-interactive'; before=$before; after=$after; cleanup=$cleanupReadback; reboot_observed=$rebootObserved; transport='hyperv-powershell-direct'; origin='guest'; injected=$false; vm_id=[string]$child.vm.Id; parent_sha256=$child.parent.sha256; interactive_ready=$true }); exit 0
}
if ($Action -eq 'ui-observe') {
    if ([string]$child.vm.State -ne 'Running') { Fail 'child VM must be Running for UI observation' }
    if ($ExpectedArtifactSha256 -notmatch '^[0-9a-fA-F]{64}$') { Fail 'ui-observe requires the planned artifact SHA-256' }
    $keyboard=Get-MsvmKeyboardMetadata ([string]$child.vm.Id)
    $session=New-Session $child; try { $consent=Get-GuestConsentProof $child $session } finally { Remove-PSSession $session }
    Emit ([ordered]@{ action='ui-observe'; consent=$consent; keyboard=$keyboard; thumbnail_status='pending_provider_readback'; transport='hyperv-powershell-direct'; origin='guest'; injected=$false; vm_id=[string]$child.vm.Id; parent_sha256=$child.parent.sha256; interactive_verified=$false }); exit 0
}
if ($Action -eq 'ui-confirm') {
    if ([string]$child.vm.State -ne 'Running') { Fail 'child VM must be Running for UI confirmation' }
    if ($ExpectedArtifactSha256 -notmatch '^[0-9a-fA-F]{64}$') { Fail 'ui-confirm requires the planned artifact SHA-256' }
    $keyboard=Get-MsvmKeyboardMetadata ([string]$child.vm.Id)
    if (-not $keyboard.type_key_supported) { Fail 'Msvm_Keyboard TypeKey metadata is unavailable; refusing to synthesize UAC confirmation' }
    $session=New-Session $child; try { $consent=Get-GuestConsentProof $child $session } finally { Remove-PSSession $session }
    $keyboardInstance=@(Get-CimInstance -Namespace 'root\virtualization\v2' -ClassName 'Msvm_Keyboard' -ErrorAction Stop | Where-Object { [string]$_.SystemName -eq [string]$child.vm.Id })
    if ($keyboardInstance.Count -ne 1) { Fail 'Msvm_Keyboard is not uniquely bound to the owned VM ID' }
    $press=Invoke-CimMethod -InputObject $keyboardInstance[0] -MethodName PressKey -Arguments @{ KeyCode = 0x12 } -ErrorAction Stop
    if([int]$press.ReturnValue -ne 0){Fail "Msvm_Keyboard PressKey Alt failed with return $($press.ReturnValue)"}
    $type=Invoke-CimMethod -InputObject $keyboardInstance[0] -MethodName TypeKey -Arguments @{ KeyCode = 0x59 } -ErrorAction Stop
    if([int]$type.ReturnValue -ne 0){Fail "Msvm_Keyboard TypeKey Y failed with return $($type.ReturnValue)"}
    $release=Invoke-CimMethod -InputObject $keyboardInstance[0] -MethodName ReleaseKey -Arguments @{ KeyCode = 0x12 } -ErrorAction Stop
    if([int]$release.ReturnValue -ne 0){Fail "Msvm_Keyboard ReleaseKey Alt failed with return $($release.ReturnValue)"}
    Emit ([ordered]@{ action='ui-confirm'; consent=$consent; keyboard=$keyboard; keyboard_return=[ordered]@{press_alt=[int]$press.ReturnValue; type_y=[int]$type.ReturnValue; release_alt=[int]$release.ReturnValue}; fixed_key='Alt+Y'; transport='hyperv-powershell-direct'; origin='guest'; injected=$false; vm_id=[string]$child.vm.Id; parent_sha256=$child.parent.sha256; interactive_verified=$false }); exit 0
}
if ($Action -eq 'app-window') {
    if ([string]$child.vm.State -ne 'Running') { Fail 'child VM must be Running for app-window acceptance' }
    if ([string]::IsNullOrWhiteSpace($UiHelperPath) -or -not (Test-Path -LiteralPath $UiHelperPath -PathType Leaf) -or (Sha $UiHelperPath) -ne $UiHelperSha256.ToLowerInvariant()) { Fail 'app-window requires the planned UI helper hash' }
    if ($ExpectedVersion -notmatch '^[0-9]+(\.[0-9]+){2,3}$') { Fail 'app-window requires expected version' }
    $session=New-Session $child
    try {
        $guestRoot="C:\ProgramData\AmneziaLab\runs\$RunId\windows-x64\$CaseId"; $guestHelper=Join-Path $guestRoot 'hyperv-ui-helper.ps1'; $guestEvidence=Join-Path $guestRoot 'app-window-evidence.json'; $guestScreenshot=Join-Path $guestRoot 'app-window.png'
        Copy-Item -LiteralPath $UiHelperPath -Destination $guestHelper -ToSession $session -Force
        $evidenceText=Invoke-Command -Session $session -ScriptBlock {
            param($helper,$evidence,$screenshot,$id,$case,$vmid,$version)
            $marker=Join-Path (Split-Path -Parent $helper) 'run-marker.txt'; $lines=@(Get-Content -LiteralPath $marker)
            if($lines -notcontains "amnezia-release-lab:${id}:windows-x64" -or $lines -notcontains "case_id=$case" -or $lines -notcontains "vm_id=$vmid"){throw 'app-window marker binding mismatch'}
            $explorer=@(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'"|Where-Object{$_.SessionId-gt0}|Select-Object -First 1);if($explorer.Count-ne1){throw 'app-window requires one Explorer session'}
            $owner=Invoke-CimMethod -InputObject $explorer[0] -MethodName GetOwner -ErrorAction Stop;$user=if([string]::IsNullOrWhiteSpace([string]$owner.Domain)){[string]$owner.User}else{"$($owner.Domain)\$($owner.User)"}
            $task="AmneziaLab-AppWindow-$id-$case";if($task.Length-gt200){$task=$task.Substring(0,200)};if(Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue){throw 'app-window task already exists'}
            $args="-NoProfile -ExecutionPolicy Bypass -File `"$helper`" -Action launch-app -RunId $id -CaseId $case -VmId $vmid -ExpectedVersion $version -OutputPath `"$evidence`" -ScreenshotPath `"$screenshot`""
            $action=New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument $args;$principal=New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited;$settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 3) -MultipleInstances IgnoreNew
            try { Register-ScheduledTask -TaskName $task -Action $action -Principal $principal -Settings $settings -Description 'Owned release-lab app window acceptance'|Out-Null;Start-ScheduledTask -TaskName $task;$deadline=(Get-Date).AddSeconds(120);while((Get-Date)-lt$deadline-and-not(Test-Path -LiteralPath $evidence -PathType Leaf)){Start-Sleep -Milliseconds 500};if(-not(Test-Path -LiteralPath $evidence -PathType Leaf)){throw 'app-window evidence deadline exceeded'};[IO.File]::ReadAllText($evidence) } finally { Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue;if(Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue){throw 'app-window task remained after cleanup'} }
        } -ArgumentList $guestHelper,$guestEvidence,$guestScreenshot,$RunId,$CaseId,([string]$child.vm.Id),$ExpectedVersion
        $evidence=$evidenceText|ConvertFrom-Json;if($evidence.run_id-ne$RunId-or$evidence.case_id-ne$CaseId-or$evidence.vm_id-ne([string]$child.vm.Id)-or$evidence.interactive_token-ne$true-or$evidence.action-ne'launch-app'-or$evidence.app.visible-ne$true-or[int]$evidence.app.pid-le0-or[string]::IsNullOrWhiteSpace([string]$evidence.app.sha256)){Fail 'app-window evidence is incomplete or unbound'}
        $evidenceDir=Join-Path $child.root 'evidence';New-Item -ItemType Directory -Force -Path $evidenceDir|Out-Null;$hostPath=Join-Path $evidenceDir 'app-window.png';Copy-Item -LiteralPath $guestScreenshot -Destination $hostPath -FromSession $session -Force;$item=Assert-NoReparse $hostPath 'exported app screenshot';$sha=Sha $item.FullName;if($sha-ne[string]$evidence.screenshot_sha256-or[int64]$item.Length-le1024){Fail 'exported app-window screenshot differs or is empty'}
    } finally {Remove-PSSession $session}
    Emit ([ordered]@{action='app-window';evidence=$evidence;screenshot=[ordered]@{host_path=$item.FullName;sha256=$sha;size=[int64]$item.Length};transport='hyperv-powershell-direct';origin='guest';injected=$false;vm_id=[string]$child.vm.Id;parent_sha256=$child.parent.sha256});exit 0
}
if ($Action -eq 'export-ui') {
    if ([string]$child.vm.State -ne 'Running') { Fail 'child VM must be Running for UI export' }
    if ($ExpectedScreenshotSha256 -notmatch '^[0-9a-fA-F]{64}$') { Fail 'export-ui requires the planned screenshot SHA-256' }
    $guestPath="C:\ProgramData\AmneziaLab\runs\$RunId\windows-x64\$CaseId\ui-screenshot.png"
    $evidenceDir=Join-Path $child.root 'evidence'; New-Item -ItemType Directory -Force -Path $evidenceDir | Out-Null
    $hostPath=Join-Path $evidenceDir 'ui-screenshot.png'
    $session=New-Session $child
    try { Copy-Item -LiteralPath $guestPath -Destination $hostPath -FromSession $session -Force -ErrorAction Stop } finally { Remove-PSSession $session }
    $item=Assert-NoReparse $hostPath 'exported UI screenshot'; $sha=Sha $item.FullName
    if($sha -ne $ExpectedScreenshotSha256.ToLowerInvariant() -or [int64]$item.Length -le 1024){Fail 'exported UI screenshot bytes differ or are empty'}
    Emit ([ordered]@{action='export-ui';host_path=$item.FullName;sha256=$sha;size=[int64]$item.Length;transport='hyperv-powershell-direct';origin='guest';injected=$false;vm_id=[string]$child.vm.Id;parent_sha256=$child.parent.sha256});exit 0
}
if ($Action -eq 'stage') {
    if ($Stage -notmatch '^(baseline|candidate)-(thin|outer)$') { Fail 'stage is required' }
    $source=Assert-Artifact $ArtifactPath $ArtifactSha256 $ArtifactSize
    $staging=Join-Path $child.root 'staging'; New-Item -ItemType Directory -Force -Path $staging | Out-Null
    $destination=Join-Path $staging "$Stage.exe"
    if (Test-Path -LiteralPath $destination) { if ((Sha $destination) -ne $source.sha256) { Fail 'staging destination exists with different bytes' } } else { Copy-Item -LiteralPath $source.path -Destination $destination; if ((Sha $destination) -ne $source.sha256) { Fail 'staging copy hash differs' } }
    if ([string]$child.vm.State -ne 'Running') { Fail 'child VM must be Running before guest upload' }
    $childVmId = [string]$child.vm.Id
    $session=New-Session $child; try {
        $guestRoot="C:\ProgramData\AmneziaLab\runs\$RunId\windows-x64\$CaseId"; $guestArtifact=Join-Path $guestRoot 'current.exe'; $guestMarker=Join-Path $guestRoot 'run-marker.txt'
        Invoke-Command -Session $session -ScriptBlock { param($r,$m,$id,$case,$vmid); New-Item -ItemType Directory -Force -Path $r | Out-Null; Set-Content -LiteralPath $m -Value @("amnezia-release-lab:${id}:windows-x64","backend=hyperv","case_id=$case","vm_id=$vmid") -Encoding ASCII } -ArgumentList $guestRoot,$guestMarker,$RunId,$CaseId,$childVmId | Out-Null
        Copy-Item -LiteralPath $destination -Destination $guestArtifact -ToSession $session -Force
        $readback=Invoke-Command -Session $session -ScriptBlock { param($p); $i=Get-Item -LiteralPath $p; [ordered]@{ sha256=(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant(); size=[int64]$i.Length } } -ArgumentList $guestArtifact
        if ($readback.sha256 -ne $source.sha256 -or [int64]$readback.size -ne [int64]$source.size) { Fail 'guest artifact bytes differ from planned source' }
    } finally { Remove-PSSession $session }
    Emit ([ordered]@{ action='stage'; stage=$Stage; source=$source; destination=$destination; guest_artifact=$guestArtifact; guest=$readback; transport='hyperv-powershell-direct'; vm_id=[string]$child.vm.Id; parent_sha256=$child.parent.sha256; origin='guest'; injected=$false }); exit 0
}
if ($Action -eq 'run') {
    if ([string]::IsNullOrWhiteSpace($GuestAction) -or [string]::IsNullOrWhiteSpace($ExpectedSha256) -or [string]::IsNullOrWhiteSpace($ExpectedVersion)) { Fail 'run requires guest action, expected version and artifact hash' }
    if (-not (Test-Path -LiteralPath $RunnerPath -PathType Leaf)) { Fail 'runner source is missing' }
    if ((Sha $RunnerPath) -ne $RunnerSha256.ToLowerInvariant()) { Fail 'runner source hash differs from planned record' }
    $uiSource = $null
    $launcherSource = $null
    if ($GuestAction -in @('interactive-start','interactive-collect')) {
        if ([string]::IsNullOrWhiteSpace($UiHelperPath) -or -not (Test-Path -LiteralPath $UiHelperPath -PathType Leaf) -or (Sha $UiHelperPath) -ne $UiHelperSha256.ToLowerInvariant()) { Fail 'interactive Hyper-V action requires the planned UI helper hash' }
        $uiSource = $UiHelperPath
        if ([string]::IsNullOrWhiteSpace($LauncherPath) -or -not (Test-Path -LiteralPath $LauncherPath -PathType Leaf) -or (Sha $LauncherPath) -ne $LauncherSha256.ToLowerInvariant()) { Fail 'interactive Hyper-V action requires the planned limited launcher hash' }
        $launcherSource = $LauncherPath
    }
    $result=Invoke-Guest $child $RunnerPath $GuestAction $ExpectedSha256 $ExpectedArtifactRole $ExpectedVersion $TokenEvidencePath $uiSource $launcherSource
    try { $receipt = $result.readback.receipt | ConvertFrom-Json } catch { Fail 'guest receipt is not valid JSON' }
    if ($receipt.schema -ne 1 -or [string]$receipt.run_id -ne $RunId -or [string]$receipt.profile -ne 'windows-x64' -or [string]$receipt.transport -ne 'hyperv-powershell-direct' -or [string]$receipt.origin -ne 'guest' -or $receipt.injected -eq $true -or [string]$receipt.artifact_sha256 -ne $ExpectedSha256.ToLowerInvariant()) { Fail 'guest receipt identity or artifact proof is incomplete' }
    $steps = @($receipt.steps)
    if ($steps.Count -eq 0 -or @($steps | Where-Object { $_.passed -ne $true }).Count -ne 0) { Fail 'guest receipt has no fully passed assertions' }
    Emit ([ordered]@{ action='run'; result=$result; release_passed=$false; product_verified=$true; receipt_identity=[ordered]@{ run_id=[string]$receipt.run_id; profile=[string]$receipt.profile; artifact_sha256=[string]$receipt.artifact_sha256; steps=@($steps | ForEach-Object { [string]$_.id }) } }); exit 0
}
if ($Action -eq 'collect') {
    if ([string]$child.vm.State -ne 'Running') { Fail 'child VM must be Running for collect' }
    $session=New-Session $child; try {
        $guestRoot="C:\ProgramData\AmneziaLab\runs\$RunId\windows-x64\$CaseId"; $guestReceipt=Join-Path $guestRoot 'receipt.json'; $guestMarker=Join-Path $guestRoot 'run-marker.txt'; $guestArtifact=Join-Path $guestRoot 'current.exe'
        $readback=Invoke-Command -Session $session -ScriptBlock {
            param($receipt,$marker,$artifact,$runId)
            $receiptPresent=Test-Path -LiteralPath $receipt -PathType Leaf
            $receiptText=if($receiptPresent){[IO.File]::ReadAllText($receipt)}else{''}; $markerText=if(Test-Path -LiteralPath $marker -PathType Leaf){[IO.File]::ReadAllText($marker)}else{''}
            $guestHash=(Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash.ToLowerInvariant()
            $svc=Get-CimInstance Win32_Service -Filter "Name='AmneziaVPN-service'" -ErrorAction SilentlyContinue
            $guestRoot=Split-Path -Parent $receipt; $supervisorPath=Join-Path $guestRoot 'runner-supervisor.json'; $supervisorText=if(Test-Path -LiteralPath $supervisorPath -PathType Leaf){[IO.File]::ReadAllText($supervisorPath)}else{''}; $milestonePath=Join-Path $guestRoot 'runner-milestones.jsonl'; $milestoneText=if(Test-Path -LiteralPath $milestonePath -PathType Leaf){[IO.File]::ReadAllText($milestonePath)}else{''}; $pendingPath=Join-Path $guestRoot 'pending-installer.json'; $pendingText=if(Test-Path -LiteralPath $pendingPath -PathType Leaf){[IO.File]::ReadAllText($pendingPath)}else{''}; $outPath=Join-Path $guestRoot 'runner.stdout.log'; $errPath=Join-Path $guestRoot 'runner.stderr.log'; $nativeOutPath=Join-Path $guestRoot 'installer.stdout.log'; $nativeErrPath=Join-Path $guestRoot 'installer.stderr.log'; $redact={param($v);[regex]::Replace([string]$v,'(?i)(password|token|secret|private[_-]?key|key)\s*[:=]\s*[^,; ]+','$1=<redacted>')}; $outTail=if(Test-Path $outPath){@(Get-Content $outPath -Tail 40|ForEach-Object{&$redact $_})}else{@()}; $errTail=if(Test-Path $errPath){@(Get-Content $errPath -Tail 40|ForEach-Object{&$redact $_})}else{@()}; $nativeOut=if(Test-Path $nativeOutPath){@((Get-Content $nativeOutPath -Tail 300)|ForEach-Object{&$redact $_})}else{@()}; $nativeErr=if(Test-Path $nativeErrPath){@((Get-Content $nativeErrPath -Tail 300)|ForEach-Object{&$redact $_})}else{@()}
            $bootstrapRoot=Join-Path $guestRoot 'ifw-bootstrap-root'; $bootstrapOutPath=Join-Path $guestRoot 'bootstrap.stdout.log'; $bootstrapErrPath=Join-Path $guestRoot 'bootstrap.stderr.log'; $bootstrap=[ordered]@{present=(Test-Path -LiteralPath $bootstrapRoot -PathType Container);items=@(Get-ChildItem -LiteralPath $bootstrapRoot -Force -ErrorAction SilentlyContinue|ForEach-Object{$_.Name});stdout_tail=if(Test-Path $bootstrapOutPath){@(Get-Content $bootstrapOutPath -Tail 300|ForEach-Object{&$redact $_})}else{@()};stderr_tail=if(Test-Path $bootstrapErrPath){@(Get-Content $bootstrapErrPath -Tail 300|ForEach-Object{&$redact $_})}else{@()}}
            $os=Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue; $tz=Get-TimeZone -ErrorAction SilentlyContinue; $events=@(Get-WinEvent -FilterHashtable @{LogName='System';Id=41,1074,6005,6006;StartTime=(Get-Date).AddHours(-2)} -ErrorAction SilentlyContinue|Select-Object -First 20|ForEach-Object{[ordered]@{id=[int]$_.Id;time_utc=$_.TimeCreated.ToUniversalTime().ToString('o');provider=[string]$_.ProviderName}}); $logRoot='C:\Users\labadmin\AppData\Local\AmneziaVPN-InstallerLogs'; $installerLogs=@(Get-ChildItem -LiteralPath $logRoot -File -ErrorAction SilentlyContinue|Sort-Object LastWriteTimeUtc -Descending|Select-Object -First 3|ForEach-Object{[ordered]@{name=$_.Name;size=[int64]$_.Length;last_write_utc=$_.LastWriteTimeUtc.ToString('o');tail=@(Get-Content -LiteralPath $_.FullName -Tail 20 -ErrorAction SilentlyContinue|ForEach-Object{&$redact $_})}})
            [ordered]@{ receipt=$receiptText; receipt_present=[bool]$receiptPresent; guest_marker=$markerText; guest_artifact_sha256=$guestHash; guest_artifact_size=[int64](Get-Item -LiteralPath $artifact).Length; supervisor=$supervisorText; milestones=$milestoneText; pending_installer=$pendingText; stdout_tail=$outTail; stderr_tail=$errTail; native_installer_stdout_tail=$nativeOut; native_installer_stderr_tail=$nativeErr; bootstrap_diagnostic=$bootstrap; installer_logs=$installerLogs; guest_clock=[ordered]@{utc_now=[DateTime]::UtcNow.ToString('o');local_now=[DateTime]::Now.ToString('o');timezone_id=if($tz){[string]$tz.Id}else{''};timezone_display=if($tz){[string]$tz.DisplayName}else{''};last_boot=if($os){[string]$os.LastBootUpTime}else{''}}; system_events=$events; service=if($svc){[ordered]@{state=[string]$svc.State;pid=[int]$svc.ProcessId}}else{$null}; run_id=$runId }
        } -ArgumentList $guestReceipt,$guestMarker,$guestArtifact,$RunId
    } finally { Remove-PSSession $session }
    Emit ([ordered]@{ action='collect'; result=[ordered]@{ transport='hyperv-powershell-direct'; origin='guest'; injected=$false; vm_id=[string]$child.vm.Id; parent_sha256=$child.parent.sha256; readback=$readback }; release_passed=$false; product_verified=$false }); exit 0
}
if ($Action -eq 'diagnose-bootstrap-root') {
    if ([string]$child.vm.State -ne 'Running') { Fail 'child VM must be Running for bootstrap-root diagnostic' }
    if ([string]::IsNullOrWhiteSpace($ExpectedSha256) -or $ExpectedSha256 -notmatch '^[0-9a-f]{64}$') { Fail 'bootstrap-root diagnostic requires expected candidate hash' }
    $credential=Get-CredentialFromStdin; $session=New-PSSession -VMId ([guid]$child.vm.Id) -Credential $credential -ErrorAction Stop
    try {
        $proof=Invoke-Command -Session $session -ScriptBlock {
            param($id,$case,$vmid,$sha)
            $root="C:\ProgramData\AmneziaLab\runs\$id\windows-x64\$case"; $artifact=Join-Path $root 'current.exe'; $marker=Join-Path $root 'run-marker.txt'; $bootstrap=Join-Path $root 'ifw-bootstrap-root'; $stdout=Join-Path $root 'bootstrap.stdout.log'; $stderr=Join-Path $root 'bootstrap.stderr.log'
            if(-not(Test-Path $artifact -PathType Leaf)-or(Get-FileHash $artifact -Algorithm SHA256).Hash.ToLowerInvariant()-ne$sha){throw 'diagnostic artifact hash mismatch'}
            $markerLines=@(Get-Content -LiteralPath $marker);if($markerLines -notcontains "amnezia-release-lab:${id}:windows-x64" -or $markerLines -notcontains "case_id=$case" -or $markerLines -notcontains "vm_id=$vmid"){throw 'diagnostic guest binding mismatch'}
            if(Test-Path $bootstrap){throw 'diagnostic bootstrap root already exists'};New-Item -ItemType Directory $bootstrap|Out-Null
            $p=Start-Process -FilePath $artifact -ArgumentList @('--verbose','--root',$bootstrap,'--accept-messages','--accept-licenses','--confirm-command','install','AmneziaSelfHostedUpdate=true') -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru -WindowStyle Hidden
            if(-not$p.WaitForExit(900000)){Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue;throw 'diagnostic installer timeout'}
            $p.Refresh();$raw=$p.ExitCode;if($null-eq$raw){throw 'diagnostic exit code unavailable'}
            $components='C:\Program Files\AmneziaVPN\components.xml';$version='';if(Test-Path $components){$m=[regex]::Match([IO.File]::ReadAllText($components),'<Version>\s*([^<]+)');if($m.Success){$version=$m.Groups[1].Value}}
            $svc=Get-CimInstance Win32_Service -Filter "Name='AmneziaVPN-service'" -ErrorAction SilentlyContinue
            [ordered]@{run_id=$id;case_id=$case;vm_id=$vmid;artifact_sha256=$sha;bootstrap_root=$bootstrap;bootstrap_items=@(Get-ChildItem $bootstrap -Force -ErrorAction SilentlyContinue|ForEach-Object{$_.Name});exit_code=[int]$raw;installed_version=$version;service=if($svc){[ordered]@{state=[string]$svc.State;pid=[int]$svc.ProcessId}}else{$null};stdout_tail=@(Get-Content $stdout -Tail 120 -ErrorAction SilentlyContinue);stderr_tail=@(Get-Content $stderr -Tail 120 -ErrorAction SilentlyContinue)}
        } -ArgumentList $RunId,$CaseId,([string]$child.vm.Id),$ExpectedSha256
    } finally {Remove-PSSession $session}
    Emit ([ordered]@{action='diagnose-bootstrap-root';origin='guest';injected=$false;transport='hyperv-powershell-direct';product_verified=$false;release_passed=$false;proof=$proof});exit 0
}
if ($Action -eq 'reset') {
    $before=(Get-Parent $ParentRoot).sha256
    if ([string]$child.vm.State -eq 'Running') { Stop-VM -VM $child.vm -TurnOff:$false -Force | Out-Null }
    $deadline=(Get-Date).AddSeconds(90); do { $vm=@(Get-VM -Id ([guid]$child.vm.Id))[0]; if([string]$vm.State -eq 'Off'){break}; Start-Sleep -Seconds 1 } while((Get-Date)-lt $deadline)
    if ([string]$vm.State -ne 'Off') { Fail 'child VM did not stop during reset' }
    Remove-VM -VM $vm -Force -Confirm:$false
    if (Test-Path -LiteralPath $child.root -PathType Container) { Remove-Item -LiteralPath $child.root -Recurse -Force }
    $after=(Get-Parent $ParentRoot).sha256; if ($before -ne $after) { Fail 'sealed parent VHDX changed during child reset' }
    Emit ([ordered]@{ action='reset'; run_id=$RunId; removed_child=$true; parent_sha256_before=$before; parent_sha256_after=$after; release_passed=$false }); exit 0
}
Fail "unsupported action: $Action"
