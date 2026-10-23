# Execute the real provisioning helper with all OS/file mutations mocked.
$ErrorActionPreference = 'Stop'
Import-Module Microsoft.PowerShell.Utility -Force
$helper = Join-Path $PSScriptRoot '..\guest_templates\windows11\hyperv-seed-helper.ps1.template'
$source = [IO.File]::ReadAllText([IO.Path]::GetFullPath($helper))
function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}
function Invoke-Case([string]$Mode, [bool]$ExpectReady, [bool]$ExpectFailure) {
    $state = @{ mode=$Mode; setCalled=$false; ready=$false; nonExpiring=$false; failed=$false }
    function Test-Path { param($LiteralPath, $PathType) return $true }
    function Get-Content {
        param($LiteralPath)
        return @('profile=windows-x64','backend=hyperv','bootstrap_id=__BOOTSTRAP_ID__','seed_nonce=__SEED_NONCE__')
    }
    function Get-LocalUser {
        param($Name, $ErrorAction)
        Assert-True ($Name -ceq 'labadmin') 'unexpected account lookup'
        [pscustomobject]@{ Enabled=($state.mode -ne 'disabled'); PasswordExpires=if($state.nonExpiring){$null}else{[DateTime]'2026-10-20'} }
    }
    function Set-LocalUser {
        param($Name, [bool]$PasswordNeverExpires, $ErrorAction)
        Assert-True ($Name -ceq 'labadmin' -and $PasswordNeverExpires) 'unexpected account mutation'
        $state.setCalled=$true
        if($state.mode -eq 'denied'){throw 'mock access denied'}
        if($state.mode -ne 'readback-fails'){$state.nonExpiring=$true}
    }
    function New-Item { param($ItemType, $Path, [switch]$Force) }
    function Set-Content {
        param($LiteralPath, $Encoding, [Parameter(ValueFromPipeline)]$Value)
        process {
            Assert-True ($LiteralPath -ceq 'C:\ProgramData\AmneziaLab\READY') 'unexpected readiness destination'
            Assert-True $state.nonExpiring 'READY before non-expiration readback'
            $state.ready=$true
        }
    }
    try { & ([scriptblock]::Create('$PSScriptRoot = "C:\mock-seed"' + "`n" + $source)) } catch { $state.failed=$true; if($Mode -eq 'ok'){throw} }
    Assert-True ($state.ready -eq $ExpectReady) "unexpected READY result for $Mode"
    Assert-True ($state.failed -eq $ExpectFailure) "unexpected failure result for $Mode"
    if($Mode -eq 'disabled'){Assert-True (-not $state.setCalled) 'disabled account was changed'}
}
Invoke-Case 'ok' $true $false
Invoke-Case 'denied' $false $true
Invoke-Case 'readback-fails' $false $true
Invoke-Case 'disabled' $false $true
'PASS: four provisioning account-lifetime cases; no OS/file mutation executed'
