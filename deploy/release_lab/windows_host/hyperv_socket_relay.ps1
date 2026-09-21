[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('validate','register','unregister')]
    [string] $Action,
    [string] $RelayRoot = 'C:\ProgramData\AmneziaReleaseLab\hyperv\relay',
    [string] $RunId
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$RegistryRoot = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization\GuestCommunicationServices'
$ServiceDefinitions = @(
    [ordered]@{ id = 'ssh'; guid = '{5f2f2a1e-9c3a-4fa9-8f4d-31e9960d7c31}'; element = 'AmneziaReleaseLab SSH relay'; host_port = 22222; guest_port = 22222 },
    [ordered]@{ id = 'http'; guid = '{6f3bdc8b-7b21-4df1-a3f5-6e4aaecf8f42}'; element = 'AmneziaReleaseLab HTTP relay'; host_port = 17865; guest_port = 17865 }
)

function Fail([string] $Message) { throw "hyperv-socket-relay: $Message" }

function Assert-FixedService([object] $Service) {
    if ([string]$Service.guid -notmatch '^\{[0-9a-fA-F-]{36}\}$') { Fail 'service GUID is not canonical' }
    if ([string]$Service.id -notin @('ssh','http')) { Fail 'service id is not allowlisted' }
    if ([int]$Service.host_port -notin @(22222,17865) -or [int]$Service.guest_port -notin @(22222,17865)) { Fail 'relay port is not fixed' }
}

function Read-OwnedService([object] $Service) {
    Assert-FixedService $Service
    $key = Join-Path $RegistryRoot $Service.guid.Trim('{}')
    if (-not (Test-Path -LiteralPath $key)) { return $null }
    $item = Get-ItemProperty -LiteralPath $key -ErrorAction Stop
    if ([string]$item.ElementName -ne [string]$Service.element) { Fail "existing service GUID $($Service.id) is not owned by this relay" }
    if (-not $item.PSObject.Properties['AmneziaReleaseLabOwnerRunId']) { Fail "service GUID $($Service.id) lacks the owned relay marker" }
    if ([string]$item.AmneziaReleaseLabOwnerRunId -ne $RunId) { Fail "service GUID $($Service.id) is owned by another run" }
    return $item
}

foreach ($service in $ServiceDefinitions) { Assert-FixedService $service }

if ($Action -eq 'validate') {
    $items = @($ServiceDefinitions | ForEach-Object {
        $existing = Read-OwnedService $_
        [ordered]@{ id = $_.id; guid = $_.guid; registered = ($null -ne $existing); host_port = $_.host_port; guest_port = $_.guest_port }
    })
    [ordered]@{ schema = 1; registry_root = $RegistryRoot; relay_root = $RelayRoot; services = $items; host_network_mutation = $false } | ConvertTo-Json -Depth 10 -Compress
    exit 0
}

if ($Action -eq 'register') {
    if ([string]::IsNullOrWhiteSpace($RunId) -or $RunId -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$') { Fail 'register requires a bounded run id' }
    New-Item -ItemType Directory -Force -Path $RelayRoot | Out-Null
    $created = @()
    try {
        foreach ($service in $ServiceDefinitions) {
            $key = Join-Path $RegistryRoot $service.guid.Trim('{}')
            $existing = Read-OwnedService $service
            if ($null -eq $existing) {
                New-Item -Path $key -Force | Out-Null
                # Track the key immediately; a later property failure must still
                # roll back this run's newly-created key.
                $created += $key
                New-ItemProperty -LiteralPath $key -Name ElementName -PropertyType String -Value $service.element -Force | Out-Null
                New-ItemProperty -LiteralPath $key -Name AmneziaReleaseLabOwnerRunId -PropertyType String -Value $RunId -Force | Out-Null
                New-ItemProperty -LiteralPath $key -Name AmneziaReleaseLabOwnerMarker -PropertyType String -Value (Join-Path $RelayRoot "registry-$RunId.lease") -Force | Out-Null
            }
        }
        Set-Content -LiteralPath (Join-Path $RelayRoot "registry-$RunId.lease") -Value @('schema=1',"run_id=$RunId",'state=registered') -Encoding ASCII
    } catch {
        foreach ($key in $created) { Remove-Item -LiteralPath $key -Recurse -Force -ErrorAction SilentlyContinue }
        Remove-Item -LiteralPath (Join-Path $RelayRoot "registry-$RunId.lease") -Force -ErrorAction SilentlyContinue
        throw
    }
    & $PSCommandPath -Action validate -RelayRoot $RelayRoot -RunId $RunId
    exit $LASTEXITCODE
}

if ([string]::IsNullOrWhiteSpace($RunId) -or $RunId -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$') { Fail 'unregister requires a bounded run id' }
foreach ($service in $ServiceDefinitions) {
    $existing = Read-OwnedService $service
    if ($null -ne $existing -and [string]$existing.AmneziaReleaseLabOwnerRunId -eq $RunId) {
        Remove-Item -LiteralPath (Join-Path $RegistryRoot $service.guid.Trim('{}')) -Recurse -Force
    }
}
Remove-Item -LiteralPath (Join-Path $RelayRoot "registry-$RunId.lease") -Force -ErrorAction SilentlyContinue
& $PSCommandPath -Action validate -RelayRoot $RelayRoot -RunId $RunId
exit $LASTEXITCODE
