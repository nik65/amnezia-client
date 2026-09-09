[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('plan','status','create-child','start','stop','probe','precondition','prepare-interactive','stage','run','collect','reset','ui-observe','ui-confirm')]
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
    [string] $ExpectedVersion,
    [string] $BaselineVersion,
    [string] $CandidateVersion,
    [string] $RunnerPath,
    [string] $RunnerSha256,
    [string] $UiHelperPath,
    [string] $UiHelperSha256,
    [string] $LauncherPath,
    [string] $LauncherSha256,
    [int] $ExpectedConsentPid = -1,
    [string] $ExpectedConsentStartTime,
    [int] $ExpectedConsentSessionId = -1,
    [string] $ExpectedArtifactSha256,
    [string] $TokenEvidencePath,
    [switch] $CredentialStdin
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

function Fail([string] $Message) { throw "hyperv-adapter: $Message" }
function Full([string] $Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { Fail 'path is empty' }
    return [IO.Path]::GetFullPath($Path.TrimEnd('\'))
}
function Assert-Contained([string] $Path, [string] $Root, [string] $Label) {
    $full = Full $Path; $rootFull = Full $Root
    if ($full -ine $rootFull -and -not $full.StartsWith($rootFull + '\', [StringComparison]::OrdinalIgnoreCase)) { Fail "$Label is outside the owned root" }
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
    if ($Id -notmatch '^(control|thin-clean|thin-upgrade|thin-reinstall|outer-clean|outer-upgrade|outer-reinstall)$') { Fail 'CaseId is not an allowlisted Hyper-V matrix case' }
    return $Id
}
function CaseRoot([string] $Root, [string] $Id, [string] $Case) {
    Assert-CaseId $Case | Out-Null
    if ([string]::IsNullOrWhiteSpace($Id) -or $Id -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$') { Fail 'RunId is invalid' }
    $base = Join-Path (Join-Path (Join-Path (Assert-Directory $Root 'runs root') $Id) 'windows-x64') 'cases'
    return Assert-Directory (Join-Path $base $Case) 'case root'
}
function Read-Child([string] $Root, [string] $Id, [string] $ParentRoot, [string] $Case) {
    $childRoot = CaseRoot $Root $Id $Case
    $markerPath = Join-Path $childRoot '.owned-child.json'
    $marker = Read-Json $markerPath 'owned child marker'
    if ($marker.schema -ne 1 -or $marker.backend -ne 'hyperv' -or $marker.profile -ne 'windows-x64' -or [string]$marker.run_id -ne $Id -or [string]$marker.case_id -ne $Case) { Fail 'owned child marker identity mismatch' }
    try { $vm = @(Get-VM -Id ([guid]$marker.vm_id) -ErrorAction Stop); if ($vm.Count -ne 1) { Fail 'owned child VM ID did not resolve uniquely' } } catch { Fail 'owned child VM is unavailable' }
    $parent = Get-Parent $ParentRoot
    if ([string]$marker.parent_sha256 -ne $parent.sha256 -or [string]$marker.parent_vhdx -ine $parent.vhdx) { Fail 'owned child parent binding differs from sealed baseline' }
    return [ordered]@{ root = $childRoot; marker = $marker; vm = $vm[0]; parent = $parent }
}
function Get-CredentialFromStdin {
    if (-not $CredentialStdin) { Fail 'PowerShell Direct actions require -CredentialStdin' }
    $plain = [Console]::In.ReadToEnd().TrimEnd("`r", "`n")
    if ([string]::IsNullOrWhiteSpace($plain) -or $plain.Length -gt 512) { Fail 'runtime guest credential is missing or too long' }
    $secure = ConvertTo-SecureString $plain -AsPlainText -Force
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
    $parameters = @($methodObjects | ForEach-Object { [ordered]@{ name=[string]$_.Name; parameters=@($_.Parameters.Keys) } })
    $instances = @(Get-CimInstance -Namespace 'root\virtualization\v2' -ClassName 'Msvm_Keyboard' -ErrorAction SilentlyContinue)
    return [ordered]@{ class_name='Msvm_Keyboard'; vm_id=$VmId; methods=$methods; method_parameters=$parameters; instance_count=$instances.Count; type_key_supported=($methods -contains 'TypeKey' -and $methods -contains 'PressKey' -and $methods -contains 'ReleaseKey') }
}
function Get-GuestConsentProof([object] $Child, [object] $Session) {
    $guestRoot="C:\ProgramData\AmneziaLab\runs\$($Child.marker.run_id)\windows-x64\$($Child.marker.case_id)"; $marker=Join-Path $guestRoot 'run-marker.txt'
    $expectedArtifact = $ExpectedArtifactSha256.ToLowerInvariant()
    return Invoke-Command -Session $Session -ScriptBlock {
        param($marker,$runId,$caseId,$vmId,$expectedPid,$expectedStart,$expectedSession,$expectedArtifact)
        if (-not (Test-Path -LiteralPath $marker -PathType Leaf)) { throw 'guest marker missing for UI observation' }
        $lines=@(Get-Content -LiteralPath $marker); if($lines -notcontains "amnezia-release-lab:${runId}:windows-x64" -or $lines -notcontains "case_id=$caseId" -or $lines -notcontains "vm_id=$vmId"){throw 'guest UI marker binding mismatch'}
        $requestPath=Join-Path (Split-Path -Parent $marker) 'pending-installer.json'
        if(-not(Test-Path -LiteralPath $requestPath -PathType Leaf)){throw 'guest pending installer request is missing'}
        $request=Get-Content -LiteralPath $requestPath -Raw | ConvertFrom-Json
        if([string]$request.state -ne 'waiting' -or [string]$request.run_id -ne $runId -or [string]$request.case_id -ne $caseId -or ([string]$request.artifact_sha256 -ne $expectedArtifact)){throw 'guest pending installer request is not bound to this artifact/case'}
        $consent=@(Get-CimInstance Win32_Process -Filter "Name='consent.exe'" -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -gt 0 -and $_.ExecutablePath -and ([IO.Path]::GetFullPath([string]$_.ExecutablePath) -ieq (Join-Path $env:SystemRoot 'System32\consent.exe')) })
        if($consent.Count -ne 1){throw 'System32 consent.exe is not observed in the expected guest session'}
        $p=$consent[0]; $owner=Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction Stop
        $sid=Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid -ErrorAction Stop
        if([string]$sid.Sid -ne 'S-1-5-18'){throw 'consent.exe is not running as SYSTEM'}
        if([int]$p.ProcessId -ne [int]$request.launcher_pid -or [int]$p.SessionId -ne [int]$request.launcher_session_id){throw 'consent.exe is not bound to the pending installer session'}
        if($expectedPid -ge 0 -and [int]$p.ProcessId -ne $expectedPid){throw 'consent PID changed'}
        if($expectedStart -and [string]$p.CreationDate -ne $expectedStart){throw 'consent start time changed'}
        if($expectedSession -ge 0 -and [int]$p.SessionId -ne $expectedSession){throw 'consent session changed'}
        [ordered]@{ run_id=$runId; case_id=$caseId; vm_id=$vmId; process_id=[int]$p.ProcessId; creation_time=[string]$p.CreationDate; session_id=[int]$p.SessionId; owner_user=[string]$owner.User; owner_sid=[string]$sid.Sid; consent_path=[string]$p.ExecutablePath; launcher_pid=[int]$request.launcher_pid; launcher_start_time=[string]$request.launcher_start_time; launcher_session_id=[int]$request.launcher_session_id; expected_consent=$true; interactive_token=$false }
    } -ArgumentList $marker,$Child.marker.run_id,$Child.marker.case_id,[string]$Child.vm.Id,$ExpectedConsentPid,$ExpectedConsentStartTime,$ExpectedConsentSessionId,$expectedArtifact
}
function Verify-ChildConfig([object] $Child) {
    $vm = @(Get-VM -Id ([guid]$Child.vm.Id) -ErrorAction Stop)[0]
    if ([string]$vm.Id -ne [string]$Child.marker.vm_id -or [int]$vm.Generation -ne 2 -or [int]$vm.ProcessorCount -ne 4 -or [int64]$vm.MemoryStartup -ne 8589934592) { Fail 'child VM configuration readback mismatch' }
    if ($vm.PSObject.Properties['AutomaticCheckpointsEnabled'] -and [bool]$vm.AutomaticCheckpointsEnabled) { Fail 'child automatic checkpoints are enabled' }
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
    $firstBoot = @($firmware.BootOrder) | Select-Object -First 1
    if ($null -eq $firstBoot -or $null -eq $firstBoot.Device -or [string]$firstBoot.Device.Id -ne [string]$disk[0].Id) { Fail 'child first boot device is not the owned VHDX' }
    return [ordered]@{ vm_id = [string]$vm.Id; state = [string]$vm.State; generation = [int]$vm.Generation; processors = [int]$vm.ProcessorCount; memory_bytes = [int64]$vm.MemoryStartup; network_adapter_count = $adapters.Count; secure_boot = (Test-HyperVOnState $firmware.SecureBoot); secure_boot_template = [string]$firmware.SecureBootTemplate; vtp_enabled = [bool]$security.TpmEnabled; key_protector_present = $keyPresent; dvd_count = $dvds.Count; first_boot_device_id = [string]$firstBoot.Device.Id; child_vhdx = $diskPath; parent_vhdx = [string]$info.ParentPath; vhd_type = [string]$info.VhdType }
}
function Emit([object] $Value) { $Value | ConvertTo-Json -Depth 30 -Compress }
function Assert-Artifact([string] $Path, [string] $ExpectedSha, [int64] $ExpectedSize) {
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { Fail 'artifact source is missing' }
    $item = Assert-NoReparse $Path 'artifact source'
    $sha = Sha $item.FullName
    if ($ExpectedSha -notmatch '^[0-9a-fA-F]{64}$' -or $sha -ne $ExpectedSha.ToLowerInvariant() -or ($ExpectedSize -ge 0 -and [int64]$item.Length -ne $ExpectedSize)) { Fail 'artifact source bytes differ from the planned digest/size' }
    return [ordered]@{ path = $item.FullName; sha256 = $sha; size = [int64]$item.Length }
}
function Invoke-Guest([object] $Child, [string] $GuestScript, [string] $GuestAction, [string] $ExpectedSha, [string] $ExpectedVersion, [string] $TokenEvidence, [string] $UiSource, [string] $LauncherSource) {
    $session = New-Session $Child
    try {
        $guestRoot = "C:\ProgramData\AmneziaLab\runs\$($Child.marker.run_id)\windows-x64\$($Child.marker.case_id)"
        $guestRunner = Join-Path $guestRoot 'release-lab.ps1'
        $guestArtifact = Join-Path $guestRoot 'current.exe'
        $guestReceipt = Join-Path $guestRoot 'receipt.json'
        $guestMarker = Join-Path $guestRoot 'run-marker.txt'
        $guestUi = Join-Path $guestRoot 'hyperv-ui-helper.ps1'
        $guestEvidence = Join-Path $guestRoot 'ui-evidence.json'
        $guestLauncher = Join-Path $guestRoot 'hyperv-interactive-launcher.ps1'
        if ([string]::IsNullOrWhiteSpace($GuestScript) -or -not (Test-Path -LiteralPath $GuestScript -PathType Leaf)) { Fail 'guest runner source is missing' }
        Copy-Item -LiteralPath $GuestScript -Destination $guestRunner -ToSession $session -Force
        if (-not [string]::IsNullOrWhiteSpace($UiSource)) { Copy-Item -LiteralPath $UiSource -Destination $guestUi -ToSession $session -Force }
        if (-not [string]::IsNullOrWhiteSpace($LauncherPath)) { Copy-Item -LiteralPath $LauncherPath -Destination $guestLauncher -ToSession $session -Force }
        $remote = Invoke-Command -Session $session -ScriptBlock {
            param($root, $runner, $uiHelper, $uiEvidence, $action, $runId, $caseId, $expectedVersion, $baselineVersion, $candidateVersion, $expectedSha, $receipt, $artifact, $marker, $tokenPath, $vmId, $launcher, $launcherHash)
            if (-not (Test-Path -LiteralPath $runner -PathType Leaf)) { throw 'guest runner is missing' }
            if ($action -eq 'interactive-collect') { & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $uiHelper -Action confirm -RunId $runId -VmId $vmId -OutputPath $uiEvidence | Out-Null; $tokenPath = $uiEvidence }
            & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $runner $action windows-x64 -RunId $runId -CaseId $caseId -GuestRoot $root -ExpectedVersion $expectedVersion -BaselineVersion $baselineVersion -CandidateVersion $candidateVersion -ExpectedSha256 $expectedSha -ArtifactPath $artifact -ReceiptPath $receipt -Transport hyperv-powershell-direct -GuestMarkerPath $marker -TokenEvidencePath $tokenPath -LauncherPath $launcher -LauncherSha256 $launcherHash | Out-Null
            if ($action -eq 'interactive-start') { & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $uiHelper -Action capture -RunId $runId -VmId $vmId -OutputPath $uiEvidence | Out-Null }
            $exitCode = $LASTEXITCODE
            if ($exitCode -ne 0) { throw "guest runner exited with $exitCode" }
            $receiptText = Get-Content -LiteralPath $receipt -Raw
            $markerText = Get-Content -LiteralPath $marker -Raw
            $guestHash = (Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash.ToLowerInvariant()
            [ordered]@{ receipt = $receiptText; guest_marker = $markerText; guest_artifact_sha256 = $guestHash; guest_artifact_size = [int64](Get-Item -LiteralPath $artifact).Length; action = $action }
        } -ArgumentList $guestRoot, $guestRunner, $guestUi, $guestEvidence, $GuestAction, [string]$Child.marker.run_id, [string]$Child.marker.case_id, $ExpectedVersion, $BaselineVersion, $CandidateVersion, $ExpectedSha, $guestReceipt, $guestArtifact, $guestMarker, $TokenEvidence, [guid]$Child.vm.Id, $guestLauncher, $LauncherSha256
        return [ordered]@{ transport = 'hyperv-powershell-direct'; origin = 'guest'; injected = $false; vm_id = [string]$Child.vm.Id; parent_sha256 = [string]$Child.parent.sha256; readback = $remote }
    } finally { Remove-PSSession $session }
}

if ($Action -eq 'plan') {
    $parent = Get-Parent $ParentRoot
    Emit ([ordered]@{ schema = 1; backend = 'hyperv'; profile = 'windows-x64'; transport = 'hyperv-powershell-direct'; ready = $true; cases = @('thin-clean','thin-upgrade','thin-reinstall','outer-clean','outer-upgrade','outer-reinstall'); parent_vm_id = [string]$parent.vm.Id; parent_state = [string]$parent.vm.State; parent_vhdx = $parent.vhdx; parent_sha256 = $parent.sha256; child_root = (Full (Join-Path $RunsRoot 'RUN_ID\windows-x64\cases\CASE_ID')); host_network_mutation = $false; release_passed = $false; product_verified = $false })
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
    New-VHD -Path $disk -ParentPath $parent.vhdx -Differencing -ErrorAction Stop | Out-Null
    $vm = New-VM -Name $name -Generation 2 -MemoryStartupBytes 8GB -VHDPath $disk -Path $vmPath -ErrorAction Stop
    $intent=[ordered]@{schema=1; backend='hyperv'; profile='windows-x64'; run_id=$RunId; case_id=$CaseId; vm_id=[string]$vm.Id; vm_name=$name; child_vhdx=$disk; run_root=$root; parent_vhdx=$parent.vhdx; parent_sha256=$parent.sha256; state='creation-intent'}
    Write-JsonNoClobber $intentPath $intent
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
    $marker = [ordered]@{ schema = 1; backend = 'hyperv'; profile = 'windows-x64'; run_id = $RunId; case_id = $CaseId; vm_id = [string]$vm.Id; vm_name = $name; run_root = $root; child_vhdx = $disk; parent_vhdx = $parent.vhdx; parent_sha256 = $parent.sha256; parent_vm_id = [string]$parent.vm.Id; transport = 'hyperv-powershell-direct'; state = 'created'; created_at = [DateTime]::UtcNow.ToString('o') }
    Write-JsonNoClobber (Join-Path $root '.owned-child.json') $marker
    Remove-Item -LiteralPath $intentPath -Force
    Emit ([ordered]@{ action = 'create-child'; child = $marker; configuration = (Verify-ChildConfig ([ordered]@{ root=$root; marker=[pscustomobject]$marker; vm=$vm; parent=$parent })) })
    exit 0
    } catch {
        $original=$_.Exception.Message; $cleanup=@()
        if($null -ne $vm){try{Remove-VM -VM $vm -Force -Confirm:$false}catch{$cleanup += "Remove-VM: $($_.Exception.Message)"}}
        if(Test-Path -LiteralPath $disk -PathType Leaf){try{Remove-Item -LiteralPath $disk -Force}catch{$cleanup += "Remove child VHDX: $($_.Exception.Message)"}}
        if(Test-Path -LiteralPath $vmPath -PathType Container){try{Remove-Item -LiteralPath $vmPath -Recurse -Force}catch{$cleanup += "Remove child VM state: $($_.Exception.Message)"}}
        foreach($ownedDir in @((Join-Path $root 'disk'),(Join-Path $root 'staging'))){if(Test-Path -LiteralPath $ownedDir -PathType Container){try{Remove-Item -LiteralPath $ownedDir -Recurse -Force}catch{$cleanup += "Remove child directory: $($_.Exception.Message)"}}}
        if($cleanup.Count -gt 0){Fail "$original; creation cleanup incomplete: $($cleanup -join '; ')"}
        if((Test-Path -LiteralPath $root -PathType Container) -and (@(Get-ChildItem -LiteralPath $root -Force).Count -eq 0)){Remove-Item -LiteralPath $root -Force}
        throw
    }
}
$child = Read-Child $RunsRoot $RunId $ParentRoot $CaseId
if ($Action -eq 'status') { Emit ([ordered]@{ action='status'; child=$child.marker; configuration=(Verify-ChildConfig $child); parent_sha256=$child.parent.sha256; release_passed=$false; product_verified=$false }); exit 0 }
if ($Action -eq 'start') {
    Verify-ChildConfig $child | Out-Null
    if ([string]$child.vm.State -ne 'Off') { Fail 'child VM must be Off before start' }
    Start-VM -VM $child.vm | Out-Null
    $running = @(Get-VM -Id ([guid]$child.vm.Id) -ErrorAction Stop)[0]
    if ([string]$running.State -ne 'Running') { Fail 'child VM did not reach Running state' }
    $child.marker.state = 'running'; Emit ([ordered]@{ action='start'; child=$child.marker; configuration=(Verify-ChildConfig $child); parent_sha256=(Get-Parent $ParentRoot).sha256 }); exit 0
}
if ($Action -eq 'stop') {
    if ([string]$child.vm.State -eq 'Running') { Stop-VM -VM $child.vm -TurnOff:$false -Force | Out-Null }
    $deadline=(Get-Date).AddSeconds(90); do { $stopped=@(Get-VM -Id ([guid]$child.vm.Id))[0]; if ([string]$stopped.State -eq 'Off'){break}; Start-Sleep -Seconds 1 } while((Get-Date)-lt $deadline)
    if ([string]$stopped.State -ne 'Off') { Fail 'child VM did not stop within bounded wait' }
    $child.marker.state='stopped'; Emit ([ordered]@{ action='stop'; child=$child.marker; configuration=(Verify-ChildConfig $child); parent_sha256=(Get-Parent $ParentRoot).sha256 }); exit 0
}
if ($Action -eq 'probe') {
    if ([string]$child.vm.State -ne 'Running') { Fail 'child VM must be Running for probe' }
    $session=New-Session $child; try { $probe=Invoke-Command -Session $session -ScriptBlock { $p='C:\ProgramData\AmneziaLab\READY'; if(-not(Test-Path -LiteralPath $p -PathType Leaf)){throw 'guest readiness marker missing'}; Get-Content -LiteralPath $p -Raw } } finally { Remove-PSSession $session }
    if ($probe -notmatch '(?m)^profile=windows-x64\s*$' -or $probe -notmatch '(?m)^phase=ready\s*$' -or $probe -notmatch '(?m)^candidate_credentials=absent\s*$') { Fail 'guest readiness marker is invalid' }
    Emit ([ordered]@{ action='probe'; transport='hyperv-powershell-direct'; origin='guest'; injected=$false; vm_id=[string]$child.vm.Id; parent_sha256=$child.parent.sha256; guest_marker=$probe }); exit 0
}
if ($Action -eq 'precondition') {
    if ([string]$child.vm.State -ne 'Running') { Fail 'child VM must be Running for precondition' }
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
        } -ArgumentList $guestMarker,$RunId,$CaseId,[string]$child.vm.Id
    } finally { Remove-PSSession $session }
    if ($proof.clean -ne $true) { Fail 'clean case precondition found installed product/service/components' }
    Emit ([ordered]@{ action='precondition'; proof=$proof; transport='hyperv-powershell-direct'; origin='guest'; injected=$false; vm_id=[string]$child.vm.Id; parent_sha256=$child.parent.sha256 }); exit 0
}
if ($Action -eq 'prepare-interactive') {
    if ([string]$child.vm.State -ne 'Running') { Fail 'child VM must be Running for interactive preparation' }
    $credential=Get-CredentialFromStdin; $plain=Get-PlainCredential $credential
    $session=New-PSSession -VMId ([guid]$child.vm.Id) -Credential $credential -ErrorAction Stop
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
    } catch { }
    Remove-PSSession $session
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
    if($null -eq $after -or $after.last_boot -eq $before.last_boot -or [int]$after.explorer_count -lt 1){Fail 'guest autologon/session preparation did not prove reboot and Explorer readiness'}
    $cleanupSession=New-PSSession -VMId ([guid]$child.vm.Id) -Credential $credential -ErrorAction Stop
    try { Invoke-Command -Session $cleanupSession -ScriptBlock { $key='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'; New-ItemProperty -LiteralPath $key -Name AutoAdminLogon -PropertyType String -Value '0' -Force | Out-Null; Remove-ItemProperty -LiteralPath $key -Name DefaultPassword -ErrorAction SilentlyContinue } | Out-Null } finally { Remove-PSSession $cleanupSession }
    Emit ([ordered]@{ action='prepare-interactive'; before=$before; after=$after; transport='hyperv-powershell-direct'; origin='guest'; injected=$false; vm_id=[string]$child.vm.Id; parent_sha256=$child.parent.sha256; interactive_ready=$true }); exit 0
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
if ($Action -eq 'stage') {
    if ($Stage -notmatch '^(baseline|candidate)-(thin|outer)$') { Fail 'stage is required' }
    $source=Assert-Artifact $ArtifactPath $ArtifactSha256 $ArtifactSize
    $staging=Join-Path $child.root 'staging'; New-Item -ItemType Directory -Force -Path $staging | Out-Null
    $destination=Join-Path $staging "$Stage.exe"
    if (Test-Path -LiteralPath $destination) { if ((Sha $destination) -ne $source.sha256) { Fail 'staging destination exists with different bytes' } } else { Copy-Item -LiteralPath $source.path -Destination $destination; if ((Sha $destination) -ne $source.sha256) { Fail 'staging copy hash differs' } }
    if ([string]$child.vm.State -ne 'Running') { Fail 'child VM must be Running before guest upload' }
    $session=New-Session $child; try {
        $guestRoot="C:\ProgramData\AmneziaLab\runs\$RunId\windows-x64\$CaseId"; $guestArtifact=Join-Path $guestRoot 'current.exe'; $guestMarker=Join-Path $guestRoot 'run-marker.txt'
        Invoke-Command -Session $session -ScriptBlock { param($r,$m,$id,$case,$vmid); New-Item -ItemType Directory -Force -Path $r | Out-Null; Set-Content -LiteralPath $m -Value @("amnezia-release-lab:${id}:windows-x64","backend=hyperv","case_id=$case","vm_id=$vmid") -Encoding ASCII } -ArgumentList $guestRoot,$guestMarker,$RunId,$CaseId,[string]$child.vm.Id | Out-Null
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
    $result=Invoke-Guest $child $RunnerPath $GuestAction $ExpectedSha256 $ExpectedVersion $TokenEvidencePath $uiSource $launcherSource
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
            if (-not (Test-Path -LiteralPath $receipt -PathType Leaf)) { throw 'guest receipt is missing' }
            $receiptText=Get-Content -LiteralPath $receipt -Raw; $markerText=Get-Content -LiteralPath $marker -Raw
            $guestHash=(Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash.ToLowerInvariant()
            [ordered]@{ receipt=$receiptText; guest_marker=$markerText; guest_artifact_sha256=$guestHash; guest_artifact_size=[int64](Get-Item -LiteralPath $artifact).Length; run_id=$runId }
        } -ArgumentList $guestReceipt,$guestMarker,$guestArtifact,$RunId
    } finally { Remove-PSSession $session }
    Emit ([ordered]@{ action='collect'; result=[ordered]@{ transport='hyperv-powershell-direct'; origin='guest'; injected=$false; vm_id=[string]$child.vm.Id; parent_sha256=$child.parent.sha256; readback=$readback }; release_passed=$false; product_verified=$false }); exit 0
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
