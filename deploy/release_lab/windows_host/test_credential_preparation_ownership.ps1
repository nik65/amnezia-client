# Run the actual helper with read-only Hyper-V/filesystem calls mocked. No VM
# action, credential input or host mutation is available to these fixtures.
$ErrorActionPreference='Stop'
Import-Module Microsoft.PowerShell.Utility -Force
$source=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'credential_preparation.ps1'))
$vmId='11111111-1111-4111-8111-111111111111'
$run='credential-test'
$case='thin-clean'
$ownedRoot="C:\ProgramData\AmneziaReleaseLab\hyperv\runs\$run\windows-x64\cases\$case"
function Test-Rejection([string]$Mode,[string]$Expected){
    function Get-Item {param($LiteralPath) [pscustomobject]@{Attributes=[IO.FileAttributes]::Directory;Parent=$null}}
    function Get-Content {
        param($LiteralPath,[switch]$Raw)
        @{backend='hyperv';profile='windows-x64';run_id=$run;case_id=$case;vm_id=$vmId;
          parent_sha256=('a'*64);vm_name='owned';child_vhdx="$ownedRoot\disk\child.vhdx"} | ConvertTo-Json
    }
    function Get-VM {
        param($Id)
        [pscustomobject]@{Id=$vmId;State='Running';Name='owned';Generation=2;MemoryStartup=8589934592;
            ConfigurationLocation=if($Mode-eq 'foreign-config'){'C:\ForeignVM'}else{"$ownedRoot\vm\owned"}}
    }
    function Get-VMNetworkAdapter {param($VM) @()}
    function Get-VMHardDiskDrive {param($VM) [pscustomobject]@{Path='C:\ForeignVM\child.vhdx'}}
    $message=''
    try{& ([scriptblock]::Create($source)) -RunId $run -CaseId $case -VmId $vmId -ParentSha256 ('a'*64)}
    catch{$message=$_.Exception.Message}
    if($message-notmatch [regex]::Escape($Expected)){throw "wrong ownership rejection for ${Mode}: $message"}
}
Test-Rejection 'foreign-config' 'actual VM configuration escaped owned case root'
Test-Rejection 'foreign-disk' 'owned child disk mismatch'
'PASS: foreign actual VM configuration and disk rejected before reading private stdin'
