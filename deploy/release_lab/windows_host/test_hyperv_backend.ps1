$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

function Assert-ProbeContract([object] $Receipt) {
    if ([string]$Receipt.type -ne 'os-readiness-probe') { throw 'probe type is not explicit' }
    if ($Receipt.release_passed -ne $false -or $Receipt.product_verified -ne $false) { throw 'probe can never be a release/product PASS' }
    if ([string]$Receipt.guest_marker_trust -ne 'untrusted-mutable-guest-marker') { throw 'guest marker trust was elevated' }
    if ($Receipt.PSObject.Properties.Name -contains 'os_ready') { throw 'mutable marker was promoted to trusted os_ready' }
    if ($Receipt.os_readiness_observed -ne $true) { throw 'observed readiness probe was lost' }
}

$good = [pscustomobject]@{
    type = 'os-readiness-probe'
    os_readiness_observed = $true
    guest_marker_trust = 'untrusted-mutable-guest-marker'
    release_passed = $false
    product_verified = $false
}
Assert-ProbeContract $good

# Shape taken from the documented Hyper-V object cmdlets used by the backend.
$mockSecurity = [pscustomobject]@{ TpmEnabled = $true }
$mockFirmware = [pscustomobject]@{ SecureBoot = $true; SecureBootTemplate = 'MicrosoftWindows'; FirstBootDevice = [pscustomobject]@{ Path = 'C:\ProgramData\AmneziaReleaseLab\hyperv\windows-x64\AmneziaLab-Windows-x64.vhdx' } }
$mockDisk = [pscustomobject]@{ Path = $mockFirmware.FirstBootDevice.Path }
$mockMedia = @([pscustomobject]@{ Path = 'C:\ProgramData\AmneziaReleaseLab\hyperv\windows-x64\media\windows.iso' }, [pscustomobject]@{ Path = 'C:\ProgramData\AmneziaReleaseLab\hyperv\windows-x64\media\answer-seed.iso' })
if ($mockSecurity.TpmEnabled -ne $true -or -not $mockFirmware.SecureBoot -or $mockFirmware.SecureBootTemplate -ne 'MicrosoftWindows' -or @($mockDisk).Count -ne 1 -or @($mockMedia).Count -ne 2) { throw 'documented Hyper-V mock object shape was not accepted' }

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
