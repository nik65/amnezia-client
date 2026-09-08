[CmdletBinding()]
param(
    [ValidateSet('plan','create','status','start','stop','finalize','collect')]
    [string] $Action = 'plan',
    [string] $VmName = 'AmneziaLab-Windows-x64',
    [string] $Iso,
    [string] $AnswerSeed,
    [string] $SeedNonce,
    [string] $BootstrapId,
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
function Is-HyperVAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    # Use the well-known SID so this remains independent of the localized
    # display name of the built-in Hyper-V Administrators group.
    $hyperVSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-578')
    return $principal.IsInRole($hyperVSid)
}
function Assert-FeatureReady {
    if (-not (Is-Administrator) -and -not (Is-HyperVAdministrator)) {
        Fail 'an administrator or enabled Hyper-V Administrators token is required'
    }
    try {
        Import-Module Hyper-V -ErrorAction Stop
        if (-not (Get-Command Get-VM -ErrorAction Stop)) { Fail 'Hyper-V PowerShell module is unavailable' }
        # This is a non-mutating management-plane probe. The online optional
        # feature query was removed because DISM requires full elevation even
        # when Hyper-V is already enabled and the caller is a Hyper-V admin.
        Get-VMHost -ErrorAction Stop | Out-Null
        Get-VM -ErrorAction Stop | Out-Null
    } catch {
        Fail "Hyper-V management plane is unavailable to this token: $($_.Exception.Message)"
    }
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
function Test-HyperVOnState([object] $Value) {
    # Microsoft.HyperV.PowerShell.OnOffState is On=0, Off=1. A boolean cast
    # therefore inverts the meaning and must never be used for this field.
    if ($null -eq $Value) { return $false }
    if ($Value -is [System.Enum] -or $Value -is [byte] -or $Value -is [sbyte] -or $Value -is [int16] -or $Value -is [uint16] -or $Value -is [int32] -or $Value -is [uint32] -or $Value -is [int64] -or $Value -is [uint64]) { return ([int64]$Value -eq 0) }
    return ([string]$Value -ieq 'On')
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
    if ($marker.schema -ne 1 -or $marker.backend -ne 'hyperv' -or $marker.profile -ne 'windows-x64' -or [string]::IsNullOrWhiteSpace([string]$marker.bootstrap_id) -or [string]$marker.bootstrap_id -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$' -or [string]$marker.seed_nonce -notmatch '^[a-f0-9]{32}$' -or [string]::IsNullOrWhiteSpace([string]$marker.vm_id)) { Fail 'owned VM marker is invalid' }
    if ([string]$marker.state_root -ne $Root) { Fail 'owned VM marker root does not match the requested root' }
    try {
        $parsedId = [guid]$marker.vm_id
        if ($parsedId -eq [guid]::Empty) { Fail 'owned VM marker VM ID is empty' }
    } catch { Fail 'owned VM marker VM ID is not a GUID' }
    return $marker
}
function Assert-HostOwnership([object] $Marker, [string] $ExpectedSeedNonce) {
    if ([string]$Marker.backend -ne 'hyperv' -or [string]$Marker.profile -ne 'windows-x64') { Fail 'host ownership record is not bound to the Hyper-V windows-x64 profile' }
    if ($Marker.PSObject.Properties['bootstrap_identity'] -and [string]$Marker.bootstrap_identity -and [string]$Marker.bootstrap_identity -ne 'golden-os-bootstrap') { Fail 'host ownership record is not a golden OS bootstrap identity' }
    if ($Marker.PSObject.Properties['product_run_marker'] -and [string]$Marker.product_run_marker -and [string]$Marker.product_run_marker -ne 'separate-future-product-run') { Fail 'host ownership record conflates bootstrap and product run identities' }
    if ($ExpectedSeedNonce) {
        if ($ExpectedSeedNonce -notmatch '^[a-f0-9]{32}$' -or [string]$Marker.seed_nonce -ne $ExpectedSeedNonce) { Fail 'host ownership seed nonce does not match the expected seed' }
    }
    return [ordered]@{ expected_profile = 'windows-x64'; backend = 'hyperv'; bootstrap_id = [string]$Marker.bootstrap_id; seed_nonce = [string]$Marker.seed_nonce; bootstrap_identity = 'golden-os-bootstrap' }
}
function Assert-OwnedVm([object] $Marker) {
    $id = [guid]$Marker.vm_id
    $matches = @(Get-VM -Id $id -ErrorAction Stop)
    if ($matches.Count -ne 1) { Fail 'owned VM ID did not resolve to exactly one VM' }
    $vm = $matches[0]
    if ([string]$vm.Id -ne [string]$Marker.vm_id) { Fail 'resolved VM ID does not match the owned marker' }
    return $vm
}
function Get-FileEvidence([string] $Path, [string] $Root, [string] $Label, [switch] $AllowLocked) {
    $contained = Assert-ContainedPath $Path $Root $Label
    $item = Assert-SafeFile $contained $Label
    try {
        $hash = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
        return [ordered]@{ path = $item.FullName; sha256 = $hash; size = [int64]$item.Length; locked = $false }
    } catch {
        if (-not $AllowLocked) { throw }
        return [ordered]@{ path = $item.FullName; sha256 = $null; size = [int64]$item.Length; locked = $true; hash_error = $_.Exception.Message }
    }
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
            if ($keyProtector -is [byte[]]) {
                $result.key_protector_present = ($keyProtector.Length -gt 0)
            } elseif ($null -ne $keyProtector -and $keyProtector.PSObject.Properties['KeyProtector']) {
                $result.key_protector_present = ($null -ne $keyProtector.KeyProtector)
            }
        } catch { $result.key_protector_present = $false }
    }
    return $result
}
function Get-VhdEvidence([object] $Disk, [string] $Root, [string] $ExpectedBase, [bool] $Running, [bool] $IncludeStoppedHash) {
    if ([string]::IsNullOrWhiteSpace([string]$Disk.Path)) { Fail 'owned VM has a disk without a path' }
    $currentPath = Assert-ContainedPath ([string]$Disk.Path) $Root 'owned VHDX'
    $currentItem = Assert-SafeFile $currentPath 'owned VHDX'
    $info = Get-VHD -Path $currentPath -ErrorAction Stop
    $terminalPath = $currentPath
    $parentChain = @()
    $seen = @($currentPath.ToLowerInvariant())
    while (-not [string]::IsNullOrWhiteSpace([string]$info.ParentPath)) {
        $parentPath = Assert-ContainedPath ([string]$info.ParentPath) $Root 'owned VHDX parent'
        if ($seen -contains $parentPath.ToLowerInvariant()) { Fail 'owned VHDX parent chain contains a cycle' }
        $seen += $parentPath.ToLowerInvariant()
        $parentChain += $parentPath
        Assert-SafeFile $parentPath 'owned VHDX parent' | Out-Null
        $terminalPath = $parentPath
        $info = Get-VHD -Path $parentPath -ErrorAction Stop
    }
    if ($ExpectedBase -and ([string]$terminalPath -ine (Get-FullPath $ExpectedBase))) { Fail 'owned VHDX parent chain does not terminate at the marker VHDX' }
    $hash = $null
    $hashState = if ($Running) { 'mutable-running-disk' } else { 'stopped-unsealed-disk' }
    if (-not $Running -and $IncludeStoppedHash -and $parentChain.Count -eq 0) {
        $hash = (Get-FileHash -LiteralPath $terminalPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
        $hashState = 'stopped-sealed-disk'
    }
    return [ordered]@{
        path = $currentPath
        sha256 = $hash
        sha256_state = $hashState
        file_size_bytes = [int64]$currentItem.Length
        virtual_capacity_bytes = [int64]$info.Size
        configured_size_bytes = [int64]$info.Size
        vhd_format = [string]$info.VhdFormat
        vhd_type = [string]$info.VhdType
        parent_path = if ($parentChain.Count -gt 0) { [string]$parentChain[0] } else { $null }
        parent_chain = @($parentChain)
        terminal_path = $terminalPath
        controller_number = [int]$Disk.ControllerNumber
        controller_location = [int]$Disk.ControllerLocation
    }
}
function Get-WindowsBootManagerEvidence([string] $FirmwarePath) {
    if ([string]::IsNullOrWhiteSpace($FirmwarePath)) { Fail 'firmware file boot source has no firmware path' }
    # Hyper-V emits an EFI device path. Validate the complete device prefix
    # and loader suffix; a friendly Description field is never trusted.
    $pattern = '(?i)^HD\(1,GPT,(?<partition_guid>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}),0x800,0x82000\)/\\EFI\\Microsoft\\Boot\\bootmgfw\.efi$'
    $match = [regex]::Match($FirmwarePath, $pattern)
    if (-not $match.Success) { Fail 'firmware file boot source is not the canonical Microsoft Windows Boot Manager device path' }
    return [ordered]@{ path = $FirmwarePath; partition_guid = $match.Groups['partition_guid'].Value.ToLowerInvariant() }
}
function Resolve-BootSource([object] $Source, [object[]] $Disks, [object[]] $Dvds) {
    $bootCode = $null
    if ($Source.PSObject.Properties['BootType']) { try { $bootCode = [int]$Source.BootType } catch { $bootCode = $null } }
    $bootName = switch ($bootCode) { 0 { 'Unknown' } 1 { 'Drive' } 2 { 'Network' } 3 { 'File' } default { 'Unsupported' } }
    $device = if ($Source.PSObject.Properties['Device']) { $Source.Device } else { $null }
    $deviceId = if ($device -and $device.PSObject.Properties['Id']) { [string]$device.Id } else { $null }
    $diskMatches = @($Disks | Where-Object { $deviceId -and ([string]$_.Id -eq $deviceId) })
    $dvdMatches = @($Dvds | Where-Object { $deviceId -and ([string]$_.Id -eq $deviceId) })
    if (($diskMatches.Count + $dvdMatches.Count) -gt 1) { Fail 'firmware boot source maps to multiple owned devices' }
    $mapped = if ($diskMatches.Count -eq 1) { $diskMatches[0] } elseif ($dvdMatches.Count -eq 1) { $dvdMatches[0] } else { $null }
    $firmware = $null
    if ($bootCode -eq 3) {
        $firmwarePath = if ($Source.PSObject.Properties['FirmwarePath']) { [string]$Source.FirmwarePath } else { $null }
        $firmware = Get-WindowsBootManagerEvidence $firmwarePath
    }
    return [ordered]@{
        boot_type = $bootCode
        boot_type_name = $bootName
        device_id = $deviceId
        device_type = if ($device) { [string]$device.GetType().FullName } else { $null }
        path = if ($mapped) { [string]$mapped.Path } else { $null }
        firmware_path = if ($firmware) { [string]$firmware.path } else { $null }
        firmware_partition_guid = if ($firmware) { [string]$firmware.partition_guid } else { $null }
        mapped_kind = if ($diskMatches.Count -eq 1) { 'owned-vhdx' } elseif ($dvdMatches.Count -eq 1) { 'owned-dvd' } else { $null }
    }
}
function Get-VmEvidence([object] $Vm, [string] $Root, [string] $ExpectedBase, [bool] $IncludeStoppedHash) {
    $firmware = Get-VMFirmware -VM $Vm -ErrorAction Stop
    $disks = @(Get-VMHardDiskDrive -VM $Vm -ErrorAction Stop)
    $dvds = @(Get-VMDvdDrive -VM $Vm -ErrorAction Stop)
    $adapters = @(Get-VMNetworkAdapter -VM $Vm -ErrorAction Stop)
    $running = ([string]$Vm.State -eq 'Running')
    $diskEvidence = @(
        foreach ($disk in $disks) { Get-VhdEvidence $disk $Root $ExpectedBase $running $IncludeStoppedHash }
    )
    $mediaEvidence = @(
        foreach ($dvd in $dvds) {
            if ([string]::IsNullOrWhiteSpace([string]$dvd.Path)) { [ordered]@{ path = $null; sha256 = $null } }
            else { Get-FileEvidence ([string]$dvd.Path) $Root 'attached Hyper-V media' }
        }
    )
    $sources = if ($firmware.PSObject.Properties['BootOrder']) { @($firmware.BootOrder) } else { @() }
    $bootEvidence = @($sources | ForEach-Object { Resolve-BootSource $_ $disks $dvds })
    $autoCheckpoints = if ($Vm.PSObject.Properties['AutomaticCheckpointsEnabled']) { [bool]$Vm.AutomaticCheckpointsEnabled } else { $null }
    return [ordered]@{
        vm_id = [string]$Vm.Id
        state = [string]$Vm.State
        generation = [int]$Vm.Generation
        secure_boot_enabled = if ($firmware.PSObject.Properties['SecureBoot']) { Test-HyperVOnState $firmware.SecureBoot } else { $false }
        secure_boot_template = [string]$firmware.SecureBootTemplate
        first_boot = if ($bootEvidence.Count -gt 0) { $bootEvidence[0] } else { $null }
        first_boot_device = if ($bootEvidence.Count -gt 0) { [string]$bootEvidence[0].path } else { $null }
        first_boot_device_id = if ($bootEvidence.Count -gt 0) { [string]$bootEvidence[0].device_id } else { $null }
        boot_order = $bootEvidence
        virtual_tpm = Get-TpmEvidence $Vm
        network_adapter_count = $adapters.Count
        automatic_checkpoints_enabled = $autoCheckpoints
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
    if (-not $Evidence.secure_boot_enabled -or [string]$Evidence.secure_boot_template -ne 'MicrosoftWindows') { Fail "Secure Boot/template readback is invalid (enabled=$($Evidence.secure_boot_enabled); template=$([string]$Evidence.secure_boot_template))" }
    if (-not $Evidence.virtual_tpm.enabled -or -not $Evidence.virtual_tpm.key_protector_present) { Fail "vTPM/key-protector readback is invalid (tpm_enabled=$($Evidence.virtual_tpm.enabled); key_protector_present=$($Evidence.virtual_tpm.key_protector_present))" }
    if ($Evidence.network_adapter_count -ne 0) { Fail 'owned Hyper-V VM has a network adapter' }
    if ($Evidence.PSObject.Properties['automatic_checkpoints_enabled'] -and $null -ne $Evidence.automatic_checkpoints_enabled -and $Evidence.automatic_checkpoints_enabled) { Fail 'owned Hyper-V VM has automatic checkpoints enabled' }
    $vhdxEvidence = @($Evidence.vhdx)
    if ($vhdxEvidence.Count -ne 1) { Fail 'owned Hyper-V VM must have exactly one VHDX' }
    if ($vhdxEvidence[0].controller_number -ne 0 -or $vhdxEvidence[0].controller_location -ne 0) { Fail 'owned Hyper-V VHDX must be on SCSI controller 0 location 0' }
    if ($vhdxEvidence[0].virtual_capacity_bytes -ne 137438953472) { Fail "owned Hyper-V VHDX virtual capacity is invalid: $($vhdxEvidence[0].virtual_capacity_bytes)" }
    $expectedVhd = Assert-ContainedPath ([string]$Marker.vhdx) $Root 'owned marker VHDX'
    if ([string]$vhdxEvidence[0].terminal_path -ine $expectedVhd) { Fail 'VHDX readback parent chain does not terminate at the owned marker' }
    if ([string]$vhdxEvidence[0].sha256_state -eq 'mutable-running-disk' -and $null -ne $vhdxEvidence[0].sha256) { Fail 'running VHDX must not be hashed' }
    $bootOrder = @($Evidence.boot_order)
    if ($bootOrder.Count -eq 0) { Fail 'Hyper-V firmware returned no boot sources' }
    foreach ($source in $bootOrder) {
        if ($source.boot_type -eq 0 -or $source.boot_type -eq 2 -or $source.boot_type -eq $null -or [string]$source.boot_type_name -eq 'Unsupported') { Fail "unsupported or unsafe firmware boot type: $($source.boot_type)" }
        if ($source.boot_type -eq 3 -and [string]::IsNullOrWhiteSpace([string]$source.firmware_partition_guid)) { Fail 'firmware file boot source did not parse a canonical partition GUID' }
        if ($source.boot_type -ne 3 -and [string]::IsNullOrWhiteSpace([string]$source.path)) { Fail 'non-file firmware boot source did not map to an owned device' }
        if ($source.path -and ([string]$source.path -ine [string]$expectedVhd) -and ([string]$source.path -ine [string]$Marker.iso.path) -and ([string]$source.path -ine [string]$Marker.answer_seed.path)) { Fail 'firmware boot source maps outside owned VHDX/media' }
    }
    $copies = Assert-MediaCopies $Marker $Root
    $attachedPaths = @($Evidence.media | ForEach-Object { if ($_.path) { [string]$_.path } })
    if ($RequireAttachedMedia) {
        if ($attachedPaths.Count -ne 2 -or ($attachedPaths -notcontains [string]$copies.iso.path) -or ($attachedPaths -notcontains [string]$copies.answer_seed.path)) { Fail 'attached ISO/answer-seed readback does not match owned copies' }
        if ($null -eq $Evidence.first_boot -or ([string]$Evidence.first_boot.path -ine [string]$copies.iso.path -and [string]$Evidence.first_boot.path -ine [string]$expectedVhd)) { Fail 'unsealed VM first-boot readback does not select the owned ISO/VHDX/Microsoft boot manager' }
    } elseif ($attachedPaths.Count -ne 0) {
        Fail 'sealed VM still has attached installation media'
    } elseif ($null -eq $Evidence.first_boot -or $Evidence.first_boot.boot_type -ne 1 -or [string]$Evidence.first_boot.mapped_kind -ne 'owned-vhdx' -or [string]$Evidence.first_boot.path -ine $expectedVhd) {
        Fail 'sealed VM first-boot readback does not select the owned VHDX drive'
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
function Seal-OwnedVhd([object] $Vm, [string] $Root, [string] $ExpectedBase) {
    if ([string]$Vm.State -ne 'Off') { Fail 'owned VHDX sealing requires an Off VM' }
    $snapshots = @()
    if (Get-Command Get-VMSnapshot -ErrorAction SilentlyContinue) { $snapshots = @(Get-VMSnapshot -VM $Vm -ErrorAction Stop) }
    foreach ($snapshot in $snapshots) {
        if ($snapshot.PSObject.Properties['VMId'] -and [string]$snapshot.VMId -ne [string]$Vm.Id) { Fail 'checkpoint ownership does not match the owned VM' }
        if (-not (Get-Command Remove-VMSnapshot -ErrorAction SilentlyContinue)) { Fail 'owned VM has checkpoints but Remove-VMSnapshot is unavailable' }
        Remove-VMSnapshot -VMSnapshot $snapshot -Confirm:$false
    }
    $drives = @(Get-VMHardDiskDrive -VM $Vm -ErrorAction Stop)
    if ($drives.Count -ne 1) { Fail 'owned VHDX sealing requires exactly one hard disk' }
    $drive = $drives[0]
    $base = Get-FullPath $ExpectedBase
    $current = Assert-ContainedPath ([string]$drive.Path) $Root 'owned VHDX'
    while ($true) {
        $info = Get-VHD -Path $current -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace([string]$info.ParentPath)) { break }
        $parent = Assert-ContainedPath ([string]$info.ParentPath) $Root 'owned VHDX parent'
        Assert-SafeFile $parent 'owned VHDX parent' | Out-Null
        Merge-VHD -Path $current -DestinationPath $parent -ErrorAction Stop
        $current = $parent
    }
    if ($current -ine $base) { Fail 'sealed VHDX chain does not terminate at the owned marker VHDX' }
    if ([string]$drive.Path -ine $base) {
        Set-VMHardDiskDrive -VMHardDiskDrive $drive -Path $base
    }
    $finalInfo = Get-VHD -Path $base -ErrorAction Stop
    if (-not [string]::IsNullOrWhiteSpace([string]$finalInfo.ParentPath)) { Fail 'sealed owned VHDX remains differencing' }
    if ([int64]$finalInfo.Size -ne 137438953472) { Fail 'sealed owned VHDX virtual capacity changed' }
    return $base
}
function Invoke-GuestReadinessProbe([object] $Vm, [PSCredential] $GuestCredential, [string] $ExpectedSeedNonce, [string] $ExpectedBootstrapId) {
    if ($null -eq $GuestCredential) { Fail 'guest readiness probe requires a runtime PSCredential for guest labadmin' }
    if ([string]$GuestCredential.UserName -notmatch '(?i)(^|\\)labadmin$') { Fail 'credential must name the guest labadmin account' }
    $session = New-PSSession -VMId ([guid]$Vm.Id) -Credential $GuestCredential -ErrorAction Stop
    try {
        return Invoke-Command -Session $session -ScriptBlock {
            $markerPath = 'C:\ProgramData\AmneziaLab\READY'
            if (-not (Test-Path -LiteralPath $markerPath -PathType Leaf)) { throw 'guest readiness marker is missing' }
            $markerText = Get-Content -LiteralPath $markerPath -Raw
            $expectedNonce = $using:ExpectedSeedNonce
            $expectedBootstrap = $using:ExpectedBootstrapId
            if ([string]::IsNullOrWhiteSpace($expectedNonce) -or $expectedNonce -notmatch '^[a-f0-9]{32}$') { throw 'expected Hyper-V seed nonce is missing or invalid' }
            if ([string]::IsNullOrWhiteSpace($expectedBootstrap) -or $expectedBootstrap -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$') { throw 'expected Hyper-V bootstrap identifier is missing or invalid' }
            $valid = ($markerText -match '(?m)^profile=windows-x64\s*$' -and $markerText -match '(?m)^backend=hyperv\s*$' -and $markerText -match "(?m)^bootstrap_id=$([regex]::Escape($expectedBootstrap))\s*$" -and $markerText -match '(?m)^phase=ready\s*$' -and $markerText -match "(?m)^seed_nonce=$([regex]::Escape($expectedNonce))\s*$" -and $markerText -match '(?m)^candidate_credentials=absent\s*$')
            if (-not $valid) { throw 'guest readiness marker is invalid' }
            $os = Get-CimInstance -ClassName Win32_OperatingSystem
            $currentVersion = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
            $displayVersion = [string]$currentVersion.DisplayVersion
            if ($displayVersion -ne '25H2') { throw "guest Windows DisplayVersion is not 25H2: $displayVersion" }
            # The Windows application channel is the only licensing channel
            # relevant to OS readiness. Keep the evidence deliberately
            # redacted: never emit a product key, full product ID, or SKU name.
            $windowsApplicationId = '55c92734-d682-4d71-983e-d6ec3f16059f'
            $editionId = [string]$currentVersion.EditionID
            $operatingSystemSku = [int]$os.OperatingSystemSKU
            if ($editionId -ne 'EnterpriseEval' -or $operatingSystemSku -ne 72) { throw "Windows installed edition/SKU is not EnterpriseEval/72: $editionId/$operatingSystemSku" }
            $installedWindowsSkus = @(
                Get-CimInstance -ClassName SoftwareLicensingProduct -Filter "ApplicationID='$windowsApplicationId'" -ErrorAction Stop |
                    Where-Object {
                        -not [bool]$_.LicenseIsAddon -and
                        [string]$_.LicenseFamily -eq 'EnterpriseEval' -and
                        [string]$_.Name -match '(?i)EnterpriseEval'
                    } |
                    ForEach-Object {
                        [ordered]@{
                            installed_sku = $true
                            partial_product_key_present = (-not [string]::IsNullOrWhiteSpace([string]$_.PartialProductKey))
                            license_status = [int]$_.LicenseStatus
                            evaluation_grace_minutes = [int64]$_.GracePeriodRemaining
                        }
                    }
            )
            $evaluationSku = @($installedWindowsSkus | Where-Object { $_.license_status -eq 1 -and $_.evaluation_grace_minutes -gt 0 })
            if ($evaluationSku.Count -eq 0) { throw 'Windows installed SKU is not licensed with positive evaluation grace remaining' }
            $evaluationGraceMinutes = [int64](($evaluationSku | ForEach-Object { [int64]$_['evaluation_grace_minutes'] } | Measure-Object -Maximum).Maximum)
            $licenseEvidence = [ordered]@{
                channel = 'windows'
                application_id_observed = 'windows-only'
                edition_id = $editionId
                operating_system_sku = $operatingSystemSku
                installed_sku_count = $installedWindowsSkus.Count
                licensed_with_evaluation_grace = $true
                evaluation_grace_minutes = $evaluationGraceMinutes
                other_licensed_channels_grace_zero_allowed = $true
            }
            $services = @(
                Get-Service -Name 'vmicvmsession','vmicshutdown','vmicguestinterface' -ErrorAction SilentlyContinue |
                    ForEach-Object { [ordered]@{ name = [string]$_.Name; status = [string]$_.Status; start_type = [string]$_.StartType } }
            )
            $labProfile = Join-Path $env:SystemDrive 'Users\labadmin'
            $labProfileExists = Test-Path -LiteralPath $labProfile -PathType Container
            if (-not $labProfileExists) { throw "labadmin profile is missing: $labProfile" }
            $vmicSession = @($services | Where-Object { [string]$_.name -ieq 'vmicvmsession' })
            if ($vmicSession.Count -ne 1 -or [string]$vmicSession[0].status -ine 'Running') { throw 'vmicvmsession is missing or not Running; PowerShell Direct readiness is unproven' }
            $disk0 = @(Get-Disk -Number 0 -ErrorAction SilentlyContinue)
            if ($disk0.Count -ne 1) { throw 'Windows Disk 0 is missing; disk mapping is unproven' }
            $disk0 = $disk0[0]
            [ordered]@{
                type = 'os-readiness-probe'
                computer = $env:COMPUTERNAME
                session_user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
                os_caption = [string]$os.Caption
                os_version = [string]$os.Version
                windows_display_version = $displayVersion
                license = $licenseEvidence
                actual_services = $services
                labadmin_profile = [ordered]@{ path = $labProfile; exists = $labProfileExists; current_user_is_administrator = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
                disk0 = [ordered]@{ number = [int]$disk0.Number; partition_style = [string]$disk0.PartitionStyle; operational_status = [string]$disk0.OperationalStatus; size_bytes = [int64]$disk0.Size }
                expected_profile = 'windows-x64'
                bootstrap_id = $expectedBootstrap
                seed_nonce = $expectedNonce
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
        if ([string]::IsNullOrWhiteSpace($SeedNonce) -or $SeedNonce -notmatch '^[a-f0-9]{32}$') { Fail 'create requires the verified Hyper-V answer-seed nonce' }
        if ([string]::IsNullOrWhiteSpace($BootstrapId) -or $BootstrapId -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$') { Fail 'create requires a bounded bootstrap identifier' }
        if (Get-VM -Name $safeName -ErrorAction SilentlyContinue) { Fail 'a VM with this name already exists' }
        $vhd = Join-Path $resolvedRoot "$safeName.vhdx"
        if (Test-Path -LiteralPath $vhd) { Fail 'VHDX already exists; refusing overwrite' }
        $vm = New-VM -Name $safeName -Generation 2 -MemoryStartupBytes 8GB -NewVHDPath $vhd -NewVHDSizeBytes 128GB
        $marker = [ordered]@{ schema = 1; backend = 'hyperv'; profile = 'windows-x64'; bootstrap_id = $BootstrapId; bootstrap_identity = 'golden-os-bootstrap'; product_run_marker = 'separate-future-product-run'; seed_nonce = $SeedNonce; state = 'provisioning'; sealed = $false; vm_id = [string]$vm.Id; vm_name = $safeName; state_root = $resolvedRoot; iso = $ownedIso; answer_seed = $ownedSeed; vhdx = $vhd; disk_bytes = 137438953472; generation = 2; secure_boot = 'MicrosoftWindows'; virtual_tpm = $true; network_adapter = $false; automatic_checkpoints_enabled = $false; transport = 'PowerShell Direct via VMId'; created_at = [DateTime]::UtcNow.ToString('o') }
        Write-NoClobber $markerPath ($marker | ConvertTo-Json -Depth 10)
        $markerWritten = $true
        Set-VMProcessor -VM $vm -Count 4
        Set-VM -VM $vm -AutomaticCheckpointsEnabled:$false
        $dvd = Add-VMDvdDrive -VM $vm -Path $ownedIso.path -Passthru
        $seedDvd = Add-VMDvdDrive -VM $vm -Path $ownedSeed.path -Passthru
        Set-VMFirmware -VM $vm -FirstBootDevice $dvd
        Set-VMFirmware -VM $vm -EnableSecureBoot On -SecureBootTemplate MicrosoftWindows
        Set-VMKeyProtector -VM $vm -NewLocalKeyProtector
        Enable-VMTPM -VM $vm
        $adapters = @(Get-VMNetworkAdapter -VM $vm)
        foreach ($adapter in $adapters) { Remove-VMNetworkAdapter -VMNetworkAdapter $adapter -Confirm:$false }
        $evidence = Get-VmEvidence $vm $resolvedRoot $vhd $false
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
$ownership = Assert-HostOwnership $marker $(if ($Action -eq 'collect' -or $Action -eq 'finalize') { $SeedNonce } else { $null })
$owned = Assert-OwnedVm $marker
$copies = Assert-MediaCopies $marker $resolvedRoot
$evidence = Get-VmEvidence $owned $resolvedRoot ([string]$marker.vhdx) $false
if ($Action -eq 'status') {
    Emit-Receipt ([ordered]@{ type = 'hyperv-status-probe'; action = 'status'; vm_id = [string]$owned.Id; host_ownership = $ownership; configuration_readback = $evidence; owned_media = $copies; release_passed = $false; product_verified = $false }) $receiptFull
    exit 0
}
if ($Action -eq 'start') {
    $sealed = [bool]$marker.sealed
    $readback = Assert-Configuration $evidence $marker (-not $sealed) $resolvedRoot
    [void]$readback
    Set-VM -VM $owned -AutomaticCheckpointsEnabled:$false
    $checkpointReadback = @(Get-VM -Id ([guid]$owned.Id) -ErrorAction Stop)[0]
    if ($checkpointReadback.PSObject.Properties['AutomaticCheckpointsEnabled'] -and [bool]$checkpointReadback.AutomaticCheckpointsEnabled) { Fail 'failed to disable automatic checkpoints before start' }
    Start-VM -VM $owned | Out-Null
    $running = @(Get-VM -Id ([guid]$owned.Id) -ErrorAction Stop)[0]
    if ([string]$running.State -ne 'Running') { Fail 'Start-VM returned without a Running readback' }
    $after = Get-VmEvidence $running $resolvedRoot ([string]$marker.vhdx) $false
    Emit-Receipt ([ordered]@{ type = 'hyperv-start-probe'; action = 'start'; vm_id = [string]$running.Id; state = [string]$running.State; host_ownership = $ownership; configuration_readback = $after; release_passed = $false; product_verified = $false }) $receiptFull
    exit 0
}
if ($Action -eq 'stop') {
    Stop-VM -VM $owned -TurnOff:$false -Force | Out-Null
    $stopped = Wait-VMOff $owned
    $after = Get-VmEvidence $stopped $resolvedRoot ([string]$marker.vhdx) $false
    Emit-Receipt ([ordered]@{ type = 'hyperv-stop-probe'; action = 'stop'; vm_id = [string]$stopped.Id; state = [string]$stopped.State; host_ownership = $ownership; configuration_readback = $after; release_passed = $false; product_verified = $false }) $receiptFull
    exit 0
}
if ($Action -eq 'collect') {
    if ([string]$owned.State -ne 'Running') { Fail 'PowerShell Direct requires a running owned VM' }
    $beforeEvidence = Get-VmEvidence $owned $resolvedRoot ([string]$marker.vhdx) $false
    Assert-Configuration $beforeEvidence $marker (-not [bool]$marker.sealed) $resolvedRoot | Out-Null
    $probe = Invoke-GuestReadinessProbe $owned $Credential $SeedNonce ([string]$marker.bootstrap_id)
    $afterOwned = @(Get-VM -Id ([guid]$owned.Id) -ErrorAction Stop)[0]
    if ([string]$afterOwned.State -ne 'Running') { Fail 'owned VM stopped during the PowerShell Direct probe' }
    $afterEvidence = Get-VmEvidence $afterOwned $resolvedRoot ([string]$marker.vhdx) $false
    Assert-Configuration $afterEvidence $marker (-not [bool]$marker.sealed) $resolvedRoot | Out-Null
    Emit-Receipt ([ordered]@{ type = 'os-readiness-probe'; action = 'collect'; vm_id = [string]$afterOwned.Id; host_ownership = $ownership; configuration_readback_before = $beforeEvidence; configuration_readback_after = $afterEvidence; guest_probe = $probe; release_passed = $false; product_verified = $false }) $receiptFull
    exit 0
}
if ($Action -eq 'finalize') {
    if ([string]$owned.State -ne 'Running') { Fail 'finalize requires a running owned VM' }
    $probe = Invoke-GuestReadinessProbe $owned $Credential $SeedNonce ([string]$marker.bootstrap_id)
    Stop-VM -VM $owned -TurnOff:$false -Force | Out-Null
    $stopped = Wait-VMOff $owned
    $dvds = @(Get-VMDvdDrive -VM $stopped -ErrorAction Stop)
    $expectedMediaPaths = @([string]$copies.iso.path, [string]$copies.answer_seed.path)
    $expectedSlots = @('0:1', '0:2')
    $actualMediaPaths = @()
    $actualSlots = @()
    foreach ($dvd in $dvds) {
        if (-not $dvd.PSObject.Properties['VMId'] -or [string]$dvd.VMId -ne [string]$stopped.Id) { Fail 'owned DVD drive VM ID does not match the owned VM' }
        if ([string]::IsNullOrWhiteSpace([string]$dvd.Path)) { Fail 'owned DVD drive has no attached media path' }
        $dvdPath = Assert-ContainedPath ([string]$dvd.Path) $resolvedRoot 'attached Hyper-V media'
        if ($expectedMediaPaths -notcontains $dvdPath) { Fail 'attached DVD media is outside the two owned media copies' }
        $slot = "$([int]$dvd.ControllerNumber):$([int]$dvd.ControllerLocation)"
        if ($expectedSlots -notcontains $slot -or $actualSlots -contains $slot) { Fail "owned DVD drive has an unexpected or duplicate controller slot: $slot" }
        $actualMediaPaths += $dvdPath
        $actualSlots += $slot
    }
    if ($dvds.Count -gt 2 -or @($actualMediaPaths | Sort-Object -Unique).Count -ne $dvds.Count -or @($actualSlots | Sort-Object -Unique).Count -ne $dvds.Count) { Fail 'finalize requires a uniquely slotted subset of the two owned DVD drives' }
    foreach ($dvd in $dvds) { Remove-VMDvdDrive -VMDvdDrive $dvd -Confirm:$false }
    if (@(Get-VMDvdDrive -VM $stopped -ErrorAction Stop).Count -ne 0) { Fail 'finalize did not remove all owned DVD drives' }
    $sealedBase = Seal-OwnedVhd $stopped $resolvedRoot ([string]$marker.vhdx)
    $vhdDrives = @(Get-VMHardDiskDrive -VM $stopped)
    if ($vhdDrives.Count -ne 1 -or [string]$vhdDrives[0].Path -ine $sealedBase) { Fail 'finalize did not leave exactly one self-contained owned VHDX' }
    Set-VMFirmware -VM $stopped -FirstBootDevice $vhdDrives[0]
    $marker | Add-Member -MemberType NoteProperty -Name sealed -Value $true -Force
    $marker | Add-Member -MemberType NoteProperty -Name state -Value 'sealed' -Force
    $after = Get-VmEvidence $stopped $resolvedRoot ([string]$marker.vhdx) $true
    $sealedReadback = Assert-Configuration $after $marker $false $resolvedRoot
    [void]$sealedReadback
    $marker | Add-Member -MemberType NoteProperty -Name vhdx_sha256 -Value ([string]$after.vhdx[0].sha256) -Force
    $marker | Add-Member -MemberType NoteProperty -Name os_probe -Value $probe -Force
    Set-Content -LiteralPath (Join-Path $resolvedRoot '.owned-vm.json') -Value ($marker | ConvertTo-Json -Depth 12) -Encoding UTF8
    Emit-Receipt ([ordered]@{ type = 'hyperv-finalize-probe'; action = 'finalize'; vm_id = [string]$stopped.Id; sealed = $true; host_ownership = $ownership; configuration_readback = $after; guest_probe = $probe; release_passed = $false; product_verified = $false }) $receiptFull
    exit 0
}
Fail "unsupported action: $Action"
