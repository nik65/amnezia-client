[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $Iso,
    [Parameter(Mandatory = $true)] [string] $AnswerSeed,
    [string] $VmName = 'AmneziaLab-Windows-x64',
    [string] $OutputRoot = 'C:\ProgramData\AmneziaReleaseLab\hyperv\windows-x64'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
function Fail([string] $Message) { throw "prepare-hyperv-vm: $Message" }
if (-not (Test-Path -LiteralPath $Iso -PathType Leaf)) { Fail "Windows ISO not found: $Iso" }
if (-not (Test-Path -LiteralPath $AnswerSeed -PathType Leaf)) { Fail "answer seed not found: $AnswerSeed" }
$isoHash = (Get-FileHash -LiteralPath $Iso -Algorithm SHA256).Hash.ToLowerInvariant()
$seedHash = (Get-FileHash -LiteralPath $AnswerSeed -Algorithm SHA256).Hash.ToLowerInvariant()
$expectedIsoHash = 'a61adeab895ef5a4db436e0a7011c92a2ff17bb0357f58b13bbc4062e535e7b9'
if ($isoHash -ne $expectedIsoHash) { Fail "ISO SHA-256 mismatch: expected $expectedIsoHash got $isoHash" }
$safeName = $VmName -replace '[^A-Za-z0-9._-]', '_'
$vhd = Join-Path $OutputRoot "$safeName.vhdx"
$future = [ordered]@{
    schema = 1
    mode = 'read-only-definition-preview'
    vm_name = $safeName
    iso = [ordered]@{ path = [IO.Path]::GetFullPath($Iso); sha256 = $isoHash }
    answer_seed = [ordered]@{ path = [IO.Path]::GetFullPath($AnswerSeed); sha256 = $seedHash }
    generation = 2
    memory_bytes = 8589934592
    processors = 4
    disk_bytes = 137438953472
    vhdx = $vhd
    secure_boot = [ordered]@{ enabled = $true; template = 'MicrosoftWindows' }
    virtual_tpm = $true
    network = [ordered]@{ adapter = 'none-by-default'; physical_binding = $false; default_switch = $false; future_switch = 'private-only-if-explicitly-needed' }
    transport = 'PowerShell Direct'
    guest_user = 'labadmin'
    qemu_guest_agent = $false
    vm_created = $false
    vm_started = $false
    forbidden_actions = @('New-VM', 'New-VMSwitch', 'Start-VM', 'Enable-VMTPM', 'Add-VMNetworkAdapter', 'physical NIC binding')
    future_commands = @(
        "New-VM -Name '$safeName' -Generation 2 -MemoryStartupBytes 8GB -NewVHDPath '$vhd' -NewVHDSizeBytes 128GB",
        "Set-VMProcessor -VM (Get-VM -Id '<owned marker vm_id>') -Count 4",
        "Set-VMFirmware -VM (Get-VM -Id '<owned marker vm_id>') -EnableSecureBoot On -SecureBootTemplate MicrosoftWindows",
        "Enable-VMTPM -VM (Get-VM -Id '<owned marker vm_id>')",
        "Set-VMDvdDrive -VM (Get-VM -Id '<owned marker vm_id>') -Path '<verified-Windows-ISO>'",
        "New-PSSession -VMId '<owned marker vm_id>' -Credential (Get-Credential .\\labadmin)"
    )
}
Write-Output ($future | ConvertTo-Json -Depth 10)
