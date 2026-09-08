$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

function Assert-ProbeContract([object] $Receipt) {
    if ([string]$Receipt.type -ne 'os-readiness-probe') { throw 'probe type is not explicit' }
    if ($Receipt.release_passed -ne $false -or $Receipt.product_verified -ne $false) { throw 'probe can never be a release/product PASS' }
    if ([string]$Receipt.guest_marker_trust -ne 'untrusted-mutable-guest-marker') { throw 'guest marker trust was elevated' }
    if ($Receipt.PSObject.Properties.Name -contains 'os_ready') { throw 'mutable marker was promoted to trusted os_ready' }
    if ($Receipt.os_readiness_observed -ne $true) { throw 'observed readiness probe was lost' }
    if ([string]$Receipt.windows_display_version -ne '25H2') { throw 'Windows DisplayVersion evidence is not 25H2' }
    if ($Receipt.license.licensed_with_evaluation_grace -ne $true -or [int64]$Receipt.license.evaluation_grace_minutes -le 0) { throw 'Windows licensing evidence is missing or expired' }
    if ([string]$Receipt.expected_profile -ne 'windows-x64' -or [string]::IsNullOrWhiteSpace([string]$Receipt.bootstrap_id) -or [string]::IsNullOrWhiteSpace([string]$Receipt.seed_nonce)) { throw 'ownership binding evidence is incomplete' }
}

$good = [pscustomobject]@{
    type = 'os-readiness-probe'
    os_readiness_observed = $true
    guest_marker_trust = 'untrusted-mutable-guest-marker'
    windows_display_version = '25H2'
    license = [pscustomobject]@{ licensed_with_evaluation_grace = $true; evaluation_grace_minutes = 129599 }
    expected_profile = 'windows-x64'
    bootstrap_id = 'golden-bootstrap-01'
    seed_nonce = '0123456789abcdef0123456789abcdef'
    release_passed = $false
    product_verified = $false
}
Assert-ProbeContract $good

# Shape taken from the documented Hyper-V object cmdlets used by the backend.
$mockSecurity = [pscustomobject]@{ TpmEnabled = $true }
$mockKeyProtector = [byte[]](1,2,3,4)
$mockFirmware = [pscustomobject]@{ SecureBoot = 0; SecureBootTemplate = 'MicrosoftWindows'; BootOrder = @([pscustomobject]@{ BootType = 1; Device = [pscustomobject]@{ Id = 'disk-id' }; FirmwarePath = $null }) }
$mockDisk = [pscustomobject]@{ Id = 'disk-id'; Path = 'C:\ProgramData\AmneziaReleaseLab\hyperv\windows-x64\AmneziaLab-Windows-x64.vhdx'; ControllerNumber = 0; ControllerLocation = 0 }
$mockMedia = @([pscustomobject]@{ Path = 'C:\ProgramData\AmneziaReleaseLab\hyperv\windows-x64\media\windows.iso' }, [pscustomobject]@{ Path = 'C:\ProgramData\AmneziaReleaseLab\hyperv\windows-x64\media\answer-seed.iso' })
if ($mockSecurity.TpmEnabled -ne $true -or $mockKeyProtector.GetType().FullName -ne 'System.Byte[]' -or [int]$mockFirmware.SecureBoot -ne 0 -or $mockFirmware.SecureBootTemplate -ne 'MicrosoftWindows' -or [int]$mockFirmware.BootOrder[0].BootType -ne 1 -or $mockFirmware.BootOrder[0].Device.Id -ne $mockDisk.Id -or @($mockDisk).Count -ne 1 -or $mockDisk.ControllerNumber -ne 0 -or $mockDisk.ControllerLocation -ne 0 -or @($mockMedia).Count -ne 2) { throw 'documented Hyper-V mock object shape was not accepted' }

function Assert-MockWindowsBootManagerPath([string] $Path) {
    $pattern = '(?i)^HD\(1,GPT,(?<partition_guid>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}),0x800,0x82000\)/\\EFI\\Microsoft\\Boot\\bootmgfw\.efi$'
    $match = [regex]::Match($Path, $pattern)
    if (-not $match.Success) { throw 'firmware path fixture was not the canonical Microsoft Windows Boot Manager device path' }
    return [string]$match.Groups['partition_guid'].Value
}
$bootManagerPath = 'HD(1,GPT,01234567-89ab-cdef-0123-456789abcdef,0x800,0x82000)/\EFI\Microsoft\Boot\bootmgfw.efi'
if ((Assert-MockWindowsBootManagerPath $bootManagerPath) -ne '01234567-89ab-cdef-0123-456789abcdef') { throw 'firmware path partition GUID was not parsed' }
${backendPath} = Join-Path $PSScriptRoot 'hyperv_backend.ps1'
${backendText} = Get-Content -LiteralPath ${backendPath} -Raw
${definitionEnd} = ${backendText}.IndexOf('$resolvedRoot = Assert-SafeDirectory', [StringComparison]::Ordinal)
if (${definitionEnd} -lt 0) { throw 'backend function definition boundary is missing' }
Invoke-Expression ${backendText}.Substring(0, ${definitionEnd})
${resolvedFileBoot} = Resolve-BootSource ([pscustomobject]@{ BootType = 3; FirmwarePath = ${bootManagerPath} }) @(${mockDisk}) @()
if ([string]${resolvedFileBoot}.firmware_partition_guid -ne '01234567-89ab-cdef-0123-456789abcdef' -or $null -ne ${resolvedFileBoot}.path -or $null -ne ${resolvedFileBoot}.mapped_kind) { throw 'File boot source without Device was mapped or parsed incorrectly' }

foreach ($badBootManagerPath in @(
    'HD(2,GPT,01234567-89ab-cdef-0123-456789abcdef,0x800,0x82000)/\EFI\Microsoft\Boot\bootmgfw.efi',
    'HD(1,MBR,01234567-89ab-cdef-0123-456789abcdef,0x800,0x82000)/\EFI\Microsoft\Boot\bootmgfw.efi',
    'HD(1,GPT,01234567-89ab-cdef-0123-456789abcdef,0x801,0x82000)/\EFI\Microsoft\Boot\bootmgfw.efi',
    'HD(1,GPT,01234567-89ab-cdef-0123-456789abcdef,0x800,0x82000)/\EFI\Microsoft\Boot\winload.efi',
    'HD(1,GPT,not-a-guid,0x800,0x82000)/\EFI\Microsoft\Boot\bootmgfw.efi',
    'Description=Windows Boot Manager'
)) {
    $rejectedBootManagerPath = $false
    try { [void](Assert-MockWindowsBootManagerPath $badBootManagerPath) } catch { $rejectedBootManagerPath = $true }
    if (-not $rejectedBootManagerPath) { throw "invalid firmware path fixture was accepted: $badBootManagerPath" }
}

$unsafeBoot = [pscustomobject]@{ BootType = 2; Device = [pscustomobject]@{ Id = 'network-id' } }
if ([int]$unsafeBoot.BootType -ne 2) { throw 'network boot fixture is malformed' }
$unknownBoot = [pscustomobject]@{ BootType = 0; Device = [pscustomobject]@{ Id = 'unknown-id' } }
if ([int]$unknownBoot.BootType -ne 0) { throw 'unknown boot fixture is malformed' }

function Assert-MockOwnership([object] $Record, [string] $Nonce) {
    if ([string]$Record.backend -ne 'hyperv' -or [string]$Record.profile -ne 'windows-x64' -or [string]$Record.bootstrap_id -ne 'golden-bootstrap-01' -or [string]$Record.seed_nonce -ne $Nonce) { throw 'ownership fixture was accepted with the wrong backend/profile/bootstrap/nonce' }
}
$ownership = [pscustomobject]@{ backend = 'hyperv'; profile = 'windows-x64'; bootstrap_id = 'golden-bootstrap-01'; seed_nonce = '0123456789abcdef0123456789abcdef' }
Assert-MockOwnership $ownership $ownership.seed_nonce
$wrongNonceRejected = $false
try { Assert-MockOwnership $ownership 'fedcba9876543210fedcba9876543210' } catch { $wrongNonceRejected = $true }
if (-not $wrongNonceRejected) { throw 'wrong seed nonce was accepted' }
$wrongBackendRejected = $false
try { Assert-MockOwnership ([pscustomobject]@{ backend = 'qemu'; profile = 'windows-x64'; bootstrap_id = 'golden-bootstrap-01'; seed_nonce = $ownership.seed_nonce }) $ownership.seed_nonce } catch { $wrongBackendRejected = $true }
if (-not $wrongBackendRejected) { throw 'wrong backend was accepted' }

$badCapacity = [pscustomobject]@{ virtual_capacity_bytes = 137438953471; controller_number = 0; controller_location = 0 }
if ($badCapacity.virtual_capacity_bytes -eq 137438953472) { throw 'wrong VHDX capacity fixture was accepted' }

# Regression guard: Remove-VMDvdDrive accepts a VMDvdDrive resource object in
# its VMDvdDrive parameter set. Passing -VM with slot parameters is ambiguous
# on current Hyper-V and was the cause of the live finalize failure.
$removeDvd = Get-Command Remove-VMDvdDrive -ErrorAction Stop
$removeDvdObjectSet = @($removeDvd.ParameterSets | Where-Object { $_.Name -eq 'VMDvdDrive' })
if ($removeDvdObjectSet.Count -ne 1 -or @($removeDvdObjectSet[0].Parameters.Name) -notcontains 'VMDvdDrive') { throw 'Remove-VMDvdDrive VMDvdDrive parameter set is unavailable' }
$mockDvd = [pscustomobject]@{ VMId = '3ae51b2d-ce49-4ce5-901f-86b55be2190b'; Path = 'C:\ProgramData\AmneziaReleaseLab\hyperv\windows-x64\media\windows.iso'; ControllerNumber = 0; ControllerLocation = 1 }
function Assert-MockOwnedDvd([object] $Drive, [string] $VmId, [string[]] $MediaPaths, [string[]] $Slots) {
    if (-not $Drive.PSObject.Properties['VMId'] -or [string]$Drive.VMId -ne $VmId) { throw 'DVD mock VM ID was not bound' }
    if ($MediaPaths -notcontains [string]$Drive.Path) { throw 'DVD mock media path was not bound' }
    $slot = "$([int]$Drive.ControllerNumber):$([int]$Drive.ControllerLocation)"
    if ($Slots -notcontains $slot) { throw 'DVD mock controller slot was not bound' }
    return $Drive
}
[void](Assert-MockOwnedDvd $mockDvd '3ae51b2d-ce49-4ce5-901f-86b55be2190b' @($mockDvd.Path) @('0:1'))

function Assert-MockReadiness([object] $Probe) {
    if (-not $Probe.labadmin_profile_exists) { throw 'labadmin profile is missing' }
    if (-not $Probe.vmicvmsession_present -or [string]$Probe.vmicvmsession_status -ine 'Running') { throw 'vmicvmsession is missing or not Running' }
    if ([string]$Probe.windows_display_version -ne '25H2') { throw 'Windows DisplayVersion is not 25H2' }
    if (-not $Probe.disk0_exists) { throw 'Disk 0 is missing' }
}

function Assert-MockLicense([object[]] $Skus, [string] $EditionId, [int] $OperatingSystemSku) {
    if ($EditionId -ne 'EnterpriseEval' -or $OperatingSystemSku -ne 72) { throw 'Windows edition/SKU identity was not accepted' }
    $installed = @($Skus | Where-Object { $_.installed_sku -and -not $_.license_is_addon -and [string]$_.license_family -eq 'EnterpriseEval' -and [string]$_.product_name -match '(?i)EnterpriseEval' })
    $valid = @($installed | Where-Object { [int]$_.license_status -eq 1 -and [int64]$_.evaluation_grace_minutes -gt 0 })
    if ($valid.Count -eq 0) { throw 'Windows license gate accepted no positive evaluation grace' }
}
$licenseGood = [pscustomobject]@{ installed_sku = $true; partial_product_key_present = $false; license_is_addon = $false; license_family = 'EnterpriseEval'; product_name = 'Windows(R), EnterpriseEval edition'; license_status = 1; evaluation_grace_minutes = 129599 }
Assert-MockLicense @($licenseGood, [pscustomobject]@{ installed_sku = $true; partial_product_key_present = $false; license_is_addon = $false; license_family = 'EnterpriseEval'; product_name = 'Windows(R), EnterpriseEval edition'; license_status = 1; evaluation_grace_minutes = 0 }) 'EnterpriseEval' 72

# Exercise the exact OrderedDictionary-to-numeric aggregation used by the
# guest probe under Windows PowerShell 5.1.
function Get-MockEvaluationGrace([object[]] $Skus) {
    $valid = @($Skus | Where-Object { $_.license_status -eq 1 -and $_.evaluation_grace_minutes -gt 0 })
    if ($valid.Count -eq 0) { throw 'no positive evaluation grace in mock aggregation' }
    return [int64](($valid | ForEach-Object { [int64]$_['evaluation_grace_minutes'] } | Measure-Object -Maximum).Maximum)
}
$orderedPositive = [ordered]@{ license_status = 1; evaluation_grace_minutes = 129574 }
$orderedZero = [ordered]@{ license_status = 1; evaluation_grace_minutes = 0 }
if ((Get-MockEvaluationGrace @($orderedPositive, $orderedZero)) -ne 129574) { throw 'OrderedDictionary evaluation grace aggregation is incorrect' }
foreach ($badGraceSet in @(@([ordered]@{ license_status = 1; evaluation_grace_minutes = 0 }), @())) {
    $rejectedGrace = $false
    try { Get-MockEvaluationGrace $badGraceSet | Out-Null } catch { $rejectedGrace = $true }
    if (-not $rejectedGrace) { throw 'empty or expired OrderedDictionary grace set was accepted' }
}
foreach ($badLicense in @(
    @([pscustomobject]@{ installed_sku = $true; partial_product_key_present = $false; license_is_addon = $false; license_family = 'EnterpriseEval'; product_name = 'Windows(R), EnterpriseEval edition'; license_status = 1; evaluation_grace_minutes = 0 }),
    @([pscustomobject]@{ installed_sku = $true; partial_product_key_present = $false; license_is_addon = $true; license_family = 'EnterpriseEval'; product_name = 'Windows(R), EnterpriseEval edition'; license_status = 1; evaluation_grace_minutes = 129599 }),
    @([pscustomobject]@{ installed_sku = $true; partial_product_key_present = $false; license_is_addon = $false; license_family = 'Professional'; product_name = 'Windows(R), Professional edition'; license_status = 1; evaluation_grace_minutes = 129599 }),
    @()
)) {
    $rejectedLicense = $false
    try { Assert-MockLicense $badLicense 'EnterpriseEval' 72 } catch { $rejectedLicense = $true }
    if (-not $rejectedLicense) { throw 'invalid Windows license fixture was accepted' }
}
$readiness = [pscustomobject]@{ labadmin_profile_exists = $true; vmicvmsession_present = $true; vmicvmsession_status = 'Running'; windows_display_version = '25H2'; disk0_exists = $true }
Assert-MockReadiness $readiness
foreach ($badReadiness in @(
    [pscustomobject]@{ labadmin_profile_exists = $false; vmicvmsession_present = $true; vmicvmsession_status = 'Running'; windows_display_version = '25H2'; disk0_exists = $true },
    [pscustomobject]@{ labadmin_profile_exists = $true; vmicvmsession_present = $false; vmicvmsession_status = 'Running'; windows_display_version = '25H2'; disk0_exists = $true },
    [pscustomobject]@{ labadmin_profile_exists = $true; vmicvmsession_present = $true; vmicvmsession_status = 'Stopped'; windows_display_version = '25H2'; disk0_exists = $true },
    [pscustomobject]@{ labadmin_profile_exists = $true; vmicvmsession_present = $true; vmicvmsession_status = 'Running'; windows_display_version = '24H2'; disk0_exists = $true },
    [pscustomobject]@{ labadmin_profile_exists = $true; vmicvmsession_present = $true; vmicvmsession_status = 'Running'; windows_display_version = '25H2'; disk0_exists = $false }
)) {
    $rejectedReadiness = $false
    try { Assert-MockReadiness $badReadiness } catch { $rejectedReadiness = $true }
    if (-not $rejectedReadiness) { throw 'invalid readiness fixture was accepted' }
}

function Assert-MockSeedHelperMarker([string[]] $Lines, [string] $BootstrapId, [string] $SeedNonce) {
    foreach ($requiredLine in @('profile=windows-x64', 'backend=hyperv', "bootstrap_id=$BootstrapId", "seed_nonce=$SeedNonce")) {
        if ($Lines -notcontains $requiredLine) { throw "seed helper marker is missing: $requiredLine" }
    }
}
$helperLines = @('profile=windows-x64', 'backend=hyperv', 'bootstrap_id=golden-bootstrap-01', 'seed_nonce=0123456789abcdef0123456789abcdef')
Assert-MockSeedHelperMarker $helperLines 'golden-bootstrap-01' '0123456789abcdef0123456789abcdef'
foreach ($badHelperLines in @(
    @('profile=windows-x64', 'backend=hyperv', 'bootstrap_id=golden-bootstrap-01'),
    @('profile=windows-x64', 'backend=hyperv', 'seed_nonce=0123456789abcdef0123456789abcdef'),
    @('profile=windows-x64', 'backend=qemu', 'bootstrap_id=golden-bootstrap-01', 'seed_nonce=0123456789abcdef0123456789abcdef'),
    @('profile=windows-x64', 'backend=hyperv', 'bootstrap_id=golden-bootstrap-01', 'seed_nonce=wrong')
)) {
    $rejectedHelper = $false
    try { Assert-MockSeedHelperMarker $badHelperLines 'golden-bootstrap-01' '0123456789abcdef0123456789abcdef' } catch { $rejectedHelper = $true }
    if (-not $rejectedHelper) { throw 'invalid seed helper marker fixture was accepted' }
}

# Exercise only the marker gate with real cmd.exe in a temporary directory.
# The synthetic command never mounts a CD and never writes ProgramData.
$cmdProbeRoot = Join-Path ([IO.Path]::GetTempPath()) ('amnezia-hyperv-marker-' + [guid]::NewGuid().ToString('N'))
$cmdProbeScript = Join-Path $cmdProbeRoot 'marker-gate.cmd'
New-Item -ItemType Directory -Path $cmdProbeRoot | Out-Null
try {
    @'
@echo off
setlocal EnableExtensions EnableDelayedExpansion
set "AMNEZIA_LAB_SEED_FOUND="
set "MARKER=%~1\amnezia-lab-seed.txt"
if exist "%MARKER%" (
  findstr /X /C:"backend=hyperv" "%MARKER%" > nul
  if errorlevel 1 goto marker_done
  findstr /X /C:"profile=windows-x64" "%MARKER%" > nul
  if errorlevel 1 goto marker_done
  findstr /X /C:"bootstrap_id=golden-bootstrap-01" "%MARKER%" > nul
  if errorlevel 1 goto marker_done
  findstr /X /C:"seed_nonce=0123456789abcdef0123456789abcdef" "%MARKER%" > nul
  if errorlevel 1 goto marker_done
  set "AMNEZIA_LAB_SEED_FOUND=1"
)
:marker_done
if defined AMNEZIA_LAB_SEED_FOUND exit /b 0
exit /b 20
'@ | Set-Content -LiteralPath $cmdProbeScript -Encoding ASCII -NoNewline
    $markerPath = Join-Path $cmdProbeRoot 'amnezia-lab-seed.txt'
    $markerFixtures = @(
        $null,
        "backend=hyperv`r`nprofile=windows-x64`r`n",
        "backend=hyperv`r`nprofile=windows-x64`r`nbootstrap_id=golden-bootstrap-01`r`nseed_nonce=wrong`r`n",
        "backend=hyperv`r`nprofile=windows-x64`r`nbootstrap_id=golden-bootstrap-01`r`nseed_nonce=0123456789abcdef0123456789abcdef`r`n"
    )
    $expectedCodes = @(20, 20, 20, 0)
    for ($i = 0; $i -lt $markerFixtures.Count; $i++) {
        if ($markerFixtures[$i]) { Set-Content -LiteralPath $markerPath -Value $markerFixtures[$i] -Encoding ASCII -NoNewline }
        elseif (Test-Path -LiteralPath $markerPath) { Remove-Item -LiteralPath $markerPath -Force }
        & cmd.exe /d /c call "`"$cmdProbeScript`"" "`"$cmdProbeRoot`""
        if ($LASTEXITCODE -ne $expectedCodes[$i]) { throw "cmd.exe marker gate returned unexpected code for fixture ${i}: $LASTEXITCODE" }
    }
} finally {
    if (Test-Path -LiteralPath $cmdProbeRoot) { Remove-Item -LiteralPath $cmdProbeRoot -Recurse -Force }
}

$bad = [pscustomobject]@{
    type = 'os-readiness-probe'
    os_readiness_observed = $true
    guest_marker_trust = 'untrusted-mutable-guest-marker'
    release_passed = $true
    product_verified = $false
}
$rejected = $false
try { Assert-ProbeContract $bad } catch { $rejected = $true }
if (-not $rejected) { throw 'mock probe accepted a release_passed=true receipt' }

Write-Output 'MOCK_HYPERV_PROBE_CONTRACT_OK'
