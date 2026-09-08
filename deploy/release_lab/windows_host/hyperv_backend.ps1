[CmdletBinding()]
param(
    [ValidateSet('plan','create','status','start','stop','finalize','collect')]
    [string] $Action = 'plan',
    [string] $VmName = 'AmneziaLab-Windows-x64',
    [string] $Iso,
    [string] $AnswerSeed,
    [string] $StateRoot = 'C:\ProgramData\AmneziaReleaseLab\hyperv\windows-x64',
    [switch] $AllowVmMutation,
    [PSCredential] $Credential,
    [string] $ReceiptPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

function Fail([string] $Message) { throw "hyperv-backend: $Message" }
function Is-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
function Assert-FeatureReady {
    $feature = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -ErrorAction SilentlyContinue
    if ($null -eq $feature -or [string]$feature.State -ne 'Enabled') { Fail 'Microsoft-Hyper-V-All is not Enabled; run the separate manual prerequisite and restart when appropriate' }
    if (-not (Get-Command Get-VM -ErrorAction SilentlyContinue)) { Fail 'Hyper-V PowerShell module is unavailable' }
}
function Get-FullPath([string] $Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { Fail 'path is empty' }
    return [IO.Path]::GetFullPath($Path.TrimEnd('\'))
}
function Assert-SafeDirectory([string] $Path) {
    $full = Get-FullPath $Path
    $allowedRoot = Get-FullPath 'C:\ProgramData\AmneziaReleaseLab\hyperv'
    if ($full -ne $allowedRoot -and -not $full.StartsWith($allowedRoot + '\', [StringComparison]::OrdinalIgnoreCase)) { Fail "state path is outside the Hyper-V lab root: $full" }
    $cursor = New-Object IO.DirectoryInfo($full)
    while ($null -ne $cursor) {
        if (Test-Path -LiteralPath $cursor.FullName) {
            $existing = Get-Item -LiteralPath $cursor.FullName -Force
            if (($existing.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { Fail "state ancestor is a reparse point: $($cursor.FullName)" }
            if ($cursor.FullName -ieq $full -and -not $existing.PSIsContainer) { Fail "state path is not a directory: $full" }
        }
        $cursor = $cursor.Parent
    }
    return $full
}
function Assert-SafeFile([string] $Path, [string] $Label) {
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { Fail "$Label is missing" }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { Fail "$Label is a reparse point" }
    $cursor = $item.Directory
    while ($null -ne $cursor) {
        if (($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { Fail "$Label has a reparse-point ancestor: $($cursor.FullName)" }
        $cursor = $cursor.Parent
    }
    return $item
}
function Assert-ContainedPath([string] $Path, [string] $Root, [string] $Label) {
    $full = Get-FullPath $Path
    $rootFull = Get-FullPath $Root
    if ($full -ne $rootFull -and -not $full.StartsWith($rootFull + '\', [StringComparison]::OrdinalIgnoreCase)) { Fail "$Label is outside the owned root" }
    return $full
}
function Get-InputRecord([string] $Path, [string] $Label, [string] $Expected) {
    $item = Assert-SafeFile $Path $Label
    $hash = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($Expected -and $hash -ne $Expected.ToLowerInvariant()) { Fail "$Label SHA-256 differs from the locked value" }
    return [ordered]@{ path = $item.FullName; sha256 = $hash; size = [int64]$item.Length }
}
function Copy-VerifiedInput([object] $Record, [string] $LeafName, [string] $Root, [string] $Label) {
    $destination = Join-Path (Join-Path $Root 'media') $LeafName
    Assert-ContainedPath $destination $Root "$Label destination" | Out-Null
    if (Test-Path -LiteralPath $destination) { Fail "$Label destination already exists; refusing overwrite" }
    Copy-Item -LiteralPath ([string]$Record.path) -Destination $destination
    $copied = Assert-SafeFile $destination $Label
    $hash = (Get-FileHash -LiteralPath $copied.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($hash -ne ([string]$Record.sha256).ToLowerInvariant()) {
        Remove-Item -LiteralPath $copied.FullName -Force
        Fail "$Label copy hash differs from source"
    }
    return [ordered]@{ path = $copied.FullName; sha256 = $hash; size = [int64]$copied.Length }
}
function Get-Marker([string] $Root) {
    $path = Join-Path $Root '.owned-vm.json'
    $item = Assert-SafeFile $path 'owned VM marker'
    $marker = Get-Content -LiteralPath $item.FullName -Raw | ConvertFrom-Json
    if ($marker.schema -ne 1 -or $marker.backend -ne 'hyperv' -or [string]::IsNullOrWhiteSpace([string]$marker.vm_id)) { Fail 'owned VM marker is invalid' }
    if ([string]$marker.state_root -ne $Root) { Fail 'owned VM marker root does not match the requested root' }
    try {
        $parsedId = [guid]$marker.vm_id
        if ($parsedId -eq [guid]::Empty) { Fail 'owned VM marker VM ID is empty' }
    } catch { Fail 'owned VM marker VM ID is not a GUID' }
    return $marker
}
function Assert-OwnedVm([object] $Marker) {
    $id = [guid]$Marker.vm_id
    $matches = @(Get-VM -Id $id -ErrorAction Stop)
    if ($matches.Count -ne 1) { Fail 'owned VM ID did not resolve to exactly one VM' }
    $vm = $matches[0]
    if ([string]$vm.Id -ne [string]$Marker.vm_id) { Fail 'resolved VM ID does not match the owned marker' }
    return $vm
}
function Get-FileEvidence([string] $Path, [string] $Root, [string] $Label) {
    $contained = Assert-ContainedPath $Path $Root $Label
    $item = Assert-SafeFile $contained $Label
    return [ordered]@{ path = $item.FullName; sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant(); size = [int64]$item.Length }
}
function Get-TpmEvidence([object] $Vm) {
    $result = [ordered]@{ available = $false; enabled = $false; key_protector_present = $false }
    if (Get-Command Get-VMSecurity -ErrorAction SilentlyContinue) {
        try {
            $security = Get-VMSecurity -VM $Vm -ErrorAction Stop
            $result.available = $true
            $result.enabled = [bool]$security.TpmEnabled
        } catch { $result.available = $false; $result.enabled = $false }
    }
    if (Get-Command Get-VMKeyProtector -ErrorAction SilentlyContinue) {
        try {
            $keyProtector = Get-VMKeyProtector -VM $Vm -ErrorAction Stop
            $result.key_protector_present = ($null -ne $keyProtector -and $null -ne $keyProtector.KeyProtector)
        } catch { $result.key_protector_present = $false }
    }
    return $result
}
function Get-VmEvidence([object] $Vm, [string] $Root) {
    $firmware = Get-VMFirmware -VM $Vm -ErrorAction Stop
    $disks = @(Get-VMHardDiskDrive -VM $Vm -ErrorAction Stop)
    $dvds = @(Get-VMDvdDrive -VM $Vm -ErrorAction Stop)
    $adapters = @(Get-VMNetworkAdapter -VM $Vm -ErrorAction Stop)
    $diskEvidence = @(
        foreach ($disk in $disks) {
            if ([string]::IsNullOrWhiteSpace([string]$disk.Path)) { Fail 'owned VM has a disk without a path' }
            Get-FileEvidence ([string]$disk.Path) $Root 'owned VHDX'
        }
    )
    $mediaEvidence = @(
        foreach ($dvd in $dvds) {
            if ([string]::IsNullOrWhiteSpace([string]$dvd.Path)) {
                [ordered]@{ path = $null; sha256 = $null }
            } else {
                Get-FileEvidence ([string]$dvd.Path) $Root 'attached Hyper-V media'
            }
        }
    )
    $firstBoot = $firmware.FirstBootDevice
    return [ordered]@{
        vm_id = [string]$Vm.Id
        state = [string]$Vm.State
        generation = [int]$Vm.Generation
        secure_boot_enabled = [bool]$firmware.SecureBoot
        secure_boot_template = [string]$firmware.SecureBootTemplate
        first_boot_device = if ($null -ne $firstBoot) { [string]$firstBoot.Path } else { $null }
        virtual_tpm = Get-TpmEvidence $Vm
        network_adapter_count = $adapters.Count
        vhdx = $diskEvidence
        media = $mediaEvidence
    }
}
function Assert-MediaCopies([object] $Marker, [string] $Root) {
    if ($null -eq $Marker.iso -or $null -eq $Marker.answer_seed) { Fail 'owned marker has no locked ISO/answer-seed records' }
    $iso = Get-FileEvidence ([string]$Marker.iso.path) $Root 'owned Windows ISO'
    $seed = Get-FileEvidence ([string]$Marker.answer_seed.path) $Root 'owned answer seed'
    if ([string]$iso.sha256 -ne ([string]$Marker.iso.sha256).ToLowerInvariant()) { Fail 'owned Windows ISO hash changed' }
    if ([string]$seed.sha256 -ne ([string]$Marker.answer_seed.sha256).ToLowerInvariant()) { Fail 'owned answer seed hash changed' }
    return [ordered]@{ iso = $iso; answer_seed = $seed }
}
function Assert-Configuration([object] $Evidence, [object] $Marker, [bool] $RequireAttachedMedia, [string] $Root) {
    if ($Evidence.generation -ne 2) { Fail 'Hyper-V generation readback is not 2' }
    if (-not $Evidence.secure_boot_enabled -or [string]$Evidence.secure_boot_template -ne 'MicrosoftWindows') { Fail 'Secure Boot/template readback is invalid' }
    if (-not $Evidence.virtual_tpm.enabled -or -not $Evidence.virtual_tpm.key_protector_present) { Fail 'vTPM/key-protector readback is invalid' }
    if ($Evidence.network_adapter_count -ne 0) { Fail 'owned Hyper-V VM has a network adapter' }
    $vhdxEvidence = @($Evidence.vhdx)
    if ($vhdxEvidence.Count -ne 1) { Fail 'owned Hyper-V VM must have exactly one VHDX' }
    $expectedVhd = Assert-ContainedPath ([string]$Marker.vhdx) $Root 'owned marker VHDX'
    if ([string]$vhdxEvidence[0].path -ine $expectedVhd) { Fail 'VHDX readback does not match the owned marker' }
    $copies = Assert-MediaCopies $Marker $Root
    $attachedPaths = @($Evidence.media | ForEach-Object { if ($_.path) { [string]$_.path } })
    if ($RequireAttachedMedia) {
        if ($attachedPaths.Count -ne 2 -or ($attachedPaths -notcontains [string]$copies.iso.path) -or ($attachedPaths -notcontains [string]$copies.answer_seed.path)) { Fail 'attached ISO/answer-seed readback does not match owned copies' }
        if ([string]$Evidence.first_boot_device -ine [string]$copies.iso.path) { Fail 'unsealed VM first-boot readback does not select the owned Windows ISO' }
    } elseif ($attachedPaths.Count -ne 0) {
        Fail 'sealed VM still has attached installation media'
    } elseif ([string]$Evidence.first_boot_device -ine $expectedVhd) {
        Fail 'sealed VM first-boot readback does not select the owned VHDX'
    }
    return [ordered]@{ configuration = $Evidence; owned_media = $copies }
}
function Assert-ReceiptPath([string] $Path, [string] $Root) {
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    $full = Assert-ContainedPath $Path $Root 'receipt path'
    $parent = Split-Path -Parent $full
    Assert-SafeDirectory $parent | Out-Null
    if (Test-Path -LiteralPath $full) {
        $item = Get-Item -LiteralPath $full -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $item.PSIsContainer) { Fail 'receipt path is unsafe or is a directory' }
        Fail "refusing to overwrite existing receipt: $full"
    }
    return $full
}
function Write-NoClobber([string] $Path, [string] $Text) {
    if (Test-Path -LiteralPath $Path) { Fail "refusing to overwrite existing file: $Path" }
    $parent = Split-Path -Parent ([IO.Path]::GetFullPath($Path))
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) { New-Item -ItemType Directory -Path $parent | Out-Null }
    Set-Content -LiteralPath $Path -Value $Text -Encoding UTF8
}
function Emit-Receipt([object] $Object, [string] $Path) {
    $json = $Object | ConvertTo-Json -Depth 12
    if ($Path) { Write-NoClobber $Path $json }
    Write-Output $json
}
function Wait-VMOff([object] $Vm) {
    $deadline = (Get-Date).AddSeconds(90)
    do {
        $current = @(Get-VM -Id ([guid]$Vm.Id) -ErrorAction Stop)[0]
        if ([string]$current.State -eq 'Off') { return $current }
        Start-Sleep -Seconds 1
    } while ((Get-Date) -lt $deadline)
    Fail 'owned VM did not reach Off state within the bounded shutdown wait'
}
function Invoke-GuestReadinessProbe([object] $Vm, [PSCredential] $GuestCredential) {
    if ($null -eq $GuestCredential) { Fail 'guest readiness probe requires a runtime PSCredential for guest labadmin' }
    if ([string]$GuestCredential.UserName -notmatch '(?i)(^|\\)labadmin$') { Fail 'credential must name the guest labadmin account' }
    $session = New-PSSession -VMId ([guid]$Vm.Id) -Credential $GuestCredential -ErrorAction Stop
    try {
        return Invoke-Command -Session $session -ScriptBlock {
            $markerPath = 'C:\ProgramData\AmneziaLab\READY'
            if (-not (Test-Path -LiteralPath $markerPath -PathType Leaf)) { throw 'guest readiness marker is missing' }
            $markerText = Get-Content -LiteralPath $markerPath -Raw
            $valid = ($markerText -match 'profile=windows-x64' -and $markerText -match 'phase=ready' -and $markerText -match 'candidate_credentials=absent')
            if (-not $valid) { throw 'guest readiness marker is invalid' }
            $os = Get-CimInstance -ClassName Win32_OperatingSystem
            [ordered]@{
                type = 'os-readiness-probe'
                computer = $env:COMPUTERNAME
                session_user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
                os_caption = [string]$os.Caption
                marker_observed = $true
                os_readiness_observed = $true
                guest_marker_trust = 'untrusted-mutable-guest-marker'
                guest_agent = 'not-used-hyperv'
                release_passed = $false
                product_verified = $false
            }
        }
    } finally { Remove-PSSession $session }
}

$resolvedRoot = Assert-SafeDirectory $StateRoot
$receiptFull = Assert-ReceiptPath $ReceiptPath $resolvedRoot
$expectedIso = 'a61adeab895ef5a4db436e0a7011c92a2ff17bb0357f58b13bbc4062e535e7b9'
$isoRecord = $null
$seedRecord = $null
if ($Action -eq 'create') {
    $isoRecord = Get-InputRecord $Iso 'Windows ISO' $expectedIso
    $seedRecord = Get-InputRecord $AnswerSeed 'answer seed' ''
}
$safeName = $VmName -replace '[^A-Za-z0-9._-]', '_'
if ($safeName -ne $VmName -or $safeName.Length -lt 1 -or $safeName.Length -gt 80) { Fail 'VM name is invalid' }
$plan = [ordered]@{
    schema = 2
    backend = 'hyperv'
    action = $Action
    vm_name = $safeName
    state_root = $resolvedRoot
    iso = $isoRecord
    answer_seed = $seedRecord
    generation = 2
    memory_bytes = 8589934592
    vcpus = 4
    disk_bytes = 137438953472
    secure_boot = 'MicrosoftWindows'
    virtual_tpm = $true
    network = 'no adapter; no physical/default switch binding'
    transport = 'PowerShell Direct via VMId'
    mutation_requested = [bool]$AllowVmMutation
    release_passed = $false
    product_verified = $false
    host_mutations = @('create/start/stop/finalize only after explicit -AllowVmMutation', 'no feature enable or reboot', 'no host VPN/routes/DNS/firewall changes')
}
if ($Action -eq 'plan') { Emit-Receipt $plan $receiptFull; exit 0 }
if (-not $AllowVmMutation) { Fail "action $Action requires explicit -AllowVmMutation" }
if (-not (Is-Administrator)) { Fail "action $Action requires an administrator token" }
Assert-FeatureReady

if ($Action -eq 'create') {
    $rootCreated = $false
    $markerWritten = $false
    $vm = $null
    $vhd = $null
    $ownedIso = $null
    $ownedSeed = $null
    $mediaCreated = $false
    $markerPath = Join-Path $resolvedRoot '.owned-vm.json'
    try {
        if (Test-Path -LiteralPath $resolvedRoot) {
            if (@(Get-ChildItem -LiteralPath $resolvedRoot -Force).Count -ne 0) { Fail 'state root is non-empty without a verified owned marker; refusing adoption or replacement' }
        } else {
            New-Item -ItemType Directory -Path $resolvedRoot | Out-Null
            $rootCreated = $true
        }
        $mediaDir = Join-Path $resolvedRoot 'media'
        New-Item -ItemType Directory -Path $mediaDir | Out-Null
        $mediaCreated = $true
        $ownedIso = Copy-VerifiedInput $isoRecord 'windows.iso' $resolvedRoot 'owned Windows ISO'
        $ownedSeed = Copy-VerifiedInput $seedRecord 'answer-seed.iso' $resolvedRoot 'owned answer seed'
        if (Get-VM -Name $safeName -ErrorAction SilentlyContinue) { Fail 'a VM with this name already exists' }
        $vhd = Join-Path $resolvedRoot "$safeName.vhdx"
        if (Test-Path -LiteralPath $vhd) { Fail 'VHDX already exists; refusing overwrite' }
        $vm = New-VM -Name $safeName -Generation 2 -MemoryStartupBytes 8GB -NewVHDPath $vhd -NewVHDSizeBytes 128GB
        $marker = [ordered]@{ schema = 1; backend = 'hyperv'; state = 'provisioning'; sealed = $false; vm_id = [string]$vm.Id; vm_name = $safeName; state_root = $resolvedRoot; iso = $ownedIso; answer_seed = $ownedSeed; vhdx = $vhd; generation = 2; secure_boot = 'MicrosoftWindows'; virtual_tpm = $true; network_adapter = $false; transport = 'PowerShell Direct via VMId'; created_at = [DateTime]::UtcNow.ToString('o') }
        Write-NoClobber $markerPath ($marker | ConvertTo-Json -Depth 10)
        $markerWritten = $true
        Set-VMProcessor -VM $vm -Count 4
        Set-VMFirmware -VM $vm -EnableSecureBoot On -SecureBootTemplate MicrosoftWindows
        $dvd = Add-VMDvdDrive -VM $vm -Path $ownedIso.path -Passthru
        $seedDvd = Add-VMDvdDrive -VM $vm -Path $ownedSeed.path -Passthru
        Set-VMFirmware -VM $vm -FirstBootDevice $dvd
        Set-VMKeyProtector -VM $vm -NewLocalKeyProtector
        Enable-VMTPM -VM $vm
        $adapters = @(Get-VMNetworkAdapter -VM $vm)
        foreach ($adapter in $adapters) { Remove-VMNetworkAdapter -VMNetworkAdapter $adapter -Confirm:$false }
        $evidence = Get-VmEvidence $vm $resolvedRoot
        $readback = Assert-Configuration $evidence ([pscustomobject]$marker) $true $resolvedRoot
        [void]$readback
        Emit-Receipt ([ordered]@{ type = 'hyperv-create-probe'; action = 'create'; vm_id = [string]$vm.Id; marker = $marker; configuration_readback = $evidence; release_passed = $false; product_verified = $false }) $receiptFull
    } catch {
        $original = $_.Exception.Message
        $cleanup = @()
        if ($null -ne $vm) { try { Remove-VM -VM $vm -Force -Confirm:$false } catch { $cleanup += "Remove-VM: $($_.Exception.Message)" } }
        if ($markerWritten -and (Test-Path -LiteralPath $markerPath -PathType Leaf)) {
            try {
                $ownedMarker = Get-Content -LiteralPath $markerPath -Raw | ConvertFrom-Json
                if ($null -ne $vm -and [string]$ownedMarker.vm_id -eq [string]$vm.Id) { Remove-Item -LiteralPath $markerPath -Force }
            } catch { $cleanup += "remove owned marker: $($_.Exception.Message)" }
        }
        $cleanupPaths = @($vhd)
        if ($null -ne $ownedIso) { $cleanupPaths += [string]$ownedIso.path }
        if ($null -ne $ownedSeed) { $cleanupPaths += [string]$ownedSeed.path }
        foreach ($path in $cleanupPaths) {
            if ($path -and (Test-Path -LiteralPath $path -PathType Leaf)) { try { Remove-Item -LiteralPath $path -Force } catch { $cleanup += "remove owned file ${path}: $($_.Exception.Message)" } }
        }
        $mediaDir = Join-Path $resolvedRoot 'media'
        if ($mediaCreated -and (Test-Path -LiteralPath $mediaDir -PathType Container)) {
            try { if (@(Get-ChildItem -LiteralPath $mediaDir -Force).Count -eq 0) { Remove-Item -LiteralPath $mediaDir } } catch { $cleanup += "remove empty media directory: $($_.Exception.Message)" }
        }
        if ($rootCreated -and (Test-Path -LiteralPath $resolvedRoot -PathType Container)) {
            try { if (@(Get-ChildItem -LiteralPath $resolvedRoot -Force).Count -eq 0) { Remove-Item -LiteralPath $resolvedRoot } } catch { $cleanup += "remove empty root: $($_.Exception.Message)" }
        }
        if ($cleanup.Count -gt 0) { Fail "$original; cleanup incomplete: $($cleanup -join '; ')" }
        throw
    }
    exit 0
}

$marker = Get-Marker $resolvedRoot
$owned = Assert-OwnedVm $marker
$copies = Assert-MediaCopies $marker $resolvedRoot
$evidence = Get-VmEvidence $owned $resolvedRoot
if ($Action -eq 'status') {
    Emit-Receipt ([ordered]@{ type = 'hyperv-status-probe'; action = 'status'; vm_id = [string]$owned.Id; configuration_readback = $evidence; owned_media = $copies; release_passed = $false; product_verified = $false }) $receiptFull
    exit 0
}
if ($Action -eq 'start') {
    $sealed = [bool]$marker.sealed
    $readback = Assert-Configuration $evidence $marker (-not $sealed) $resolvedRoot
    [void]$readback
    Start-VM -VM $owned | Out-Null
    $running = @(Get-VM -Id ([guid]$owned.Id) -ErrorAction Stop)[0]
    if ([string]$running.State -ne 'Running') { Fail 'Start-VM returned without a Running readback' }
    $after = Get-VmEvidence $running $resolvedRoot
    Emit-Receipt ([ordered]@{ type = 'hyperv-start-probe'; action = 'start'; vm_id = [string]$running.Id; state = [string]$running.State; configuration_readback = $after; release_passed = $false; product_verified = $false }) $receiptFull
    exit 0
}
if ($Action -eq 'stop') {
    Stop-VM -VM $owned -TurnOff:$false -Force | Out-Null
    $stopped = Wait-VMOff $owned
    $after = Get-VmEvidence $stopped $resolvedRoot
    Emit-Receipt ([ordered]@{ type = 'hyperv-stop-probe'; action = 'stop'; vm_id = [string]$stopped.Id; state = [string]$stopped.State; configuration_readback = $after; release_passed = $false; product_verified = $false }) $receiptFull
    exit 0
}
if ($Action -eq 'collect') {
    if ([string]$owned.State -ne 'Running') { Fail 'PowerShell Direct requires a running owned VM' }
    $beforeEvidence = Get-VmEvidence $owned $resolvedRoot
    Assert-Configuration $beforeEvidence $marker (-not [bool]$marker.sealed) $resolvedRoot | Out-Null
    $probe = Invoke-GuestReadinessProbe $owned $Credential
    $afterOwned = @(Get-VM -Id ([guid]$owned.Id) -ErrorAction Stop)[0]
    if ([string]$afterOwned.State -ne 'Running') { Fail 'owned VM stopped during the PowerShell Direct probe' }
    $afterEvidence = Get-VmEvidence $afterOwned $resolvedRoot
    Assert-Configuration $afterEvidence $marker (-not [bool]$marker.sealed) $resolvedRoot | Out-Null
    Emit-Receipt ([ordered]@{ type = 'os-readiness-probe'; action = 'collect'; vm_id = [string]$afterOwned.Id; configuration_readback_before = $beforeEvidence; configuration_readback_after = $afterEvidence; guest_probe = $probe; release_passed = $false; product_verified = $false }) $receiptFull
    exit 0
}
if ($Action -eq 'finalize') {
    if ([string]$owned.State -ne 'Running') { Fail 'finalize requires a running owned VM' }
    $probe = Invoke-GuestReadinessProbe $owned $Credential
    Stop-VM -VM $owned -TurnOff:$false -Force | Out-Null
    $stopped = Wait-VMOff $owned
    $dvds = @(Get-VMDvdDrive -VM $stopped)
    foreach ($dvd in $dvds) { Remove-VMDvdDrive -VM $stopped -ControllerNumber $dvd.ControllerNumber -ControllerLocation $dvd.ControllerLocation -Confirm:$false }
    $vhdDrives = @(Get-VMHardDiskDrive -VM $stopped)
    if ($vhdDrives.Count -ne 1) { Fail 'finalize requires exactly one VHDX for first-boot transition' }
    Set-VMFirmware -VM $stopped -FirstBootDevice $vhdDrives[0]
    $after = Get-VmEvidence $stopped $resolvedRoot
    $sealedReadback = Assert-Configuration $after $marker $false $resolvedRoot
    [void]$sealedReadback
    $marker | Add-Member -MemberType NoteProperty -Name sealed -Value $true -Force
    $marker | Add-Member -MemberType NoteProperty -Name state -Value 'sealed' -Force
    $marker | Add-Member -MemberType NoteProperty -Name os_probe -Value $probe -Force
    Set-Content -LiteralPath (Join-Path $resolvedRoot '.owned-vm.json') -Value ($marker | ConvertTo-Json -Depth 12) -Encoding UTF8
    Emit-Receipt ([ordered]@{ type = 'hyperv-finalize-probe'; action = 'finalize'; vm_id = [string]$stopped.Id; sealed = $true; configuration_readback = $after; guest_probe = $probe; release_passed = $false; product_verified = $false }) $receiptFull
    exit 0
}
Fail "unsupported action: $Action"
