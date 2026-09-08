[CmdletBinding()]
param(
    [switch] $Enable,
    [switch] $PreviewCurrentOperatorHyperVAdministrators,
    [switch] $GrantCurrentOperatorHyperVAdministrators,
    [string] $ReceiptPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Is-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Fail([string] $Message) { throw "enable-hyperv: $Message" }

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$feature = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -ErrorAction SilentlyContinue
$product = (Get-ComputerInfo -Property WindowsProductName,WindowsVersion,OsBuildNumber -ErrorAction SilentlyContinue)
$currentOperator = [string]$identity.Name
$currentOperatorSid = if ($identity.User) { [string]$identity.User.Value } else { '' }
$isAdmin = Is-Administrator
$hyperVAdministratorsSid = 'S-1-5-32-578'
$hyperVGroup = $null
$groupMembers = @()
$groupError = $null
try {
    $hyperVGroup = Get-LocalGroup -SID ([Security.Principal.SecurityIdentifier]::new($hyperVAdministratorsSid)) -ErrorAction Stop
    $groupMembers = @(Get-LocalGroupMember -SID ([Security.Principal.SecurityIdentifier]::new($hyperVAdministratorsSid)) -ErrorAction Stop | ForEach-Object { [string]$_.Name })
} catch { $groupError = $_.Exception.Message }

$plan = [ordered]@{
    schema = 1
    mode = if ($Enable) { 'enable-requested' } else { 'read-only-plan' }
    current_operator = [ordered]@{ name = $currentOperator; sid = $currentOperatorSid }
    is_administrator = [bool]$isAdmin
    windows_product = if ($product) { [string]$product.WindowsProductName } else { '' }
    windows_version = if ($product) { [string]$product.WindowsVersion } else { '' }
    build = if ($product) { [string]$product.OsBuildNumber } else { '' }
    feature = if ($feature) { [ordered]@{ name = 'Microsoft-Hyper-V-All'; state = [string]$feature.State } } else { [ordered]@{ name = 'Microsoft-Hyper-V-All'; state = 'unavailable' } }
    restart_needed = $false
    group = [ordered]@{ sid = $hyperVAdministratorsSid; name = if ($hyperVGroup) { [string]$hyperVGroup.Name } else { $null }; members = $groupMembers; lookup_error = $groupError }
    host_mutations = @('Enable-WindowsOptionalFeature only when -Enable is explicit', 'optional current-operator group membership only when its explicit switch is used')
    forbidden_actions = @('Restart-Computer', 'WSL shutdown/configuration', 'VPN/service control', 'route/DNS/firewall changes', 'virtual switch or VM creation')
}

if ($GrantCurrentOperatorHyperVAdministrators) {
    if (-not $Enable) { Fail '-GrantCurrentOperatorHyperVAdministrators requires -Enable' }
    if (-not $isAdmin) { Fail 'an administrator token is required to change local group membership' }
    if ([string]::IsNullOrWhiteSpace($currentOperatorSid)) { Fail 'current operator SID is unavailable' }
    if ($null -eq $hyperVGroup) { $plan.group.grant_pending = 'group unavailable until Hyper-V feature completes and the user restarts manually' }
    elseif ($groupMembers -contains $currentOperator -or $groupMembers -contains $currentOperatorSid) { $plan.group.added_current_operator = 'already-member' }
    else {
        Add-LocalGroupMember -Group $hyperVGroup.Name -Member $currentOperatorSid -ErrorAction Stop
        $plan.group.added_current_operator = [ordered]@{ name = $currentOperator; sid = $currentOperatorSid }
    }
}
elseif ($PreviewCurrentOperatorHyperVAdministrators) {
    $plan.group.preview_add_current_operator = [ordered]@{ name = $currentOperator; sid = $currentOperatorSid }
    $plan.group.preview_command = if ($hyperVGroup) { "Add-LocalGroupMember -Group '$($hyperVGroup.Name)' -Member '$currentOperatorSid'" } else { "Resolve group SID $hyperVAdministratorsSid after Hyper-V is enabled, then add member SID $currentOperatorSid" }
}

if ($Enable) {
    if (-not $isAdmin) { Fail '-Enable must be run from an elevated PowerShell' }
    if ($product.WindowsProductName -notmatch '(?i)Pro|Enterprise|Education') { Fail 'Hyper-V host alternative requires a supported Windows Pro/Enterprise/Education edition' }
    $result = Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -All -NoRestart -ErrorAction Stop
    $restartProperty = $result.PSObject.Properties['RestartNeeded']
    $plan.enable_result = [ordered]@{ state = if ($result.PSObject.Properties['State']) { [string]$result.State } else { 'returned-without-state' }; restart_needed = if ($restartProperty) { [bool]$restartProperty.Value } else { $false } }
    $readback = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -ErrorAction Stop
    $plan.enable_readback = [string]$readback.State
    $plan.restart_needed = [bool]($plan.enable_result.restart_needed -or $readback.State -eq 'EnablePending')
}

$json = $plan | ConvertTo-Json -Depth 8
if ($ReceiptPath) {
    $parent = Split-Path -Parent ([IO.Path]::GetFullPath($ReceiptPath))
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) { New-Item -ItemType Directory -Path $parent | Out-Null }
    if (Test-Path -LiteralPath $ReceiptPath) { Fail "refusing to overwrite existing receipt: $ReceiptPath" }
    Set-Content -LiteralPath $ReceiptPath -Value $json -Encoding UTF8
}
Write-Output $json
