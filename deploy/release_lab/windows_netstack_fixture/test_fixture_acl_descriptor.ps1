$ErrorActionPreference='Stop';Set-StrictMode -Version 2
. (Join-Path $PSScriptRoot 'limited_interactive_controller.ps1')
function Assert($yes,[string]$why){if(-not$yes){throw $why}}
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
foreach($kind in @('Directory','File','Output')){
 $acl=New-FixtureSecurityDescriptor $sid $kind
 Assert $acl.AreAccessRulesProtected 'inheritance remains'
 Assert ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value-eq'S-1-5-32-544') 'owner differs'
 $rules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]));Assert ($rules.Count-eq4) 'unexpected rules'
 $user=@($rules|Where-Object{$_.IdentityReference.Value-eq$sid});Assert ($user.Count-eq1) 'user rule duplicate'
 $mask=if($kind-eq'Output'){0x000C0000}else{0x000D0116}
 Assert (([int]$user[0].FileSystemRights-band$mask)-eq0) 'replacement authority granted'
 Assert (@($rules|Where-Object{$_.IdentityReference.Value-eq'S-1-3-4'-and([int]$_.FileSystemRights-band0x000E0000)-eq0x00020000}).Count-eq1) 'owner implicit WRITE_DAC not suppressed'
 Assert (@($rules|Where-Object{$_.IsInherited}).Count-eq0) 'inherited ACE retained'
}
# Actual descriptor replacement must discard an explicit FullControl lab-user ACE.
$old=New-Object Security.AccessControl.DirectorySecurity
$old.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($sid)),'FullControl','Allow')))
$old.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($sid)),'ReadAndExecute','Allow')))
Assert (([int]@($old.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))[0].FileSystemRights-band0x000D0116)-ne0) 'legacy RED not reproduced'
# Only the owned namespace may be selected; use mocked metadata and record intended ACL calls.
$script:calls=@();$script:badMarker=$false;$script:redirect=$false
function Get-Item {param($LiteralPath,[switch]$Force) [pscustomobject]@{FullName=$LiteralPath;Attributes=$(if($script:redirect){[IO.FileAttributes]::ReparsePoint}else{[IO.FileAttributes]::Normal});PSIsContainer=($LiteralPath-notlike'*run-marker.txt')}}
function Get-Content {param($LiteralPath) if($script:badMarker){return @('foreign')} return @('amnezia-release-lab:unit-run:windows-x64','vm_id=11111111-1111-1111-1111-111111111111','case_id=outer-clean')}
function Set-OwnedFixtureAcl {param($Path,$UserSid,$Kind) $script:calls+=@([pscustomobject]@{path=$Path;sid=$UserSid;kind=$Kind})}
$root='C:\ProgramData\AmneziaLab\runs\unit-run\windows-x64\outer-clean\netstack-fixture'
Protect-OwnedFixtureNamespace $root 'unit-run' 'outer-clean' '11111111-1111-1111-1111-111111111111' $sid
Assert ($script:calls.Count-eq6) 'namespace scope differs'
Assert (@($script:calls|Where-Object{$_.path-eq'C:\ProgramData'-or$_.path-eq'C:\'}).Count-eq0) 'unsafe ancestor mutation'
foreach($scenario in @('foreignRoot','badMarker','redirect')){
 $script:calls=@();$script:badMarker=$scenario-eq'badMarker';$script:redirect=$scenario-eq'redirect';$failed=$false
 try{Protect-OwnedFixtureNamespace $(if($scenario-eq'foreignRoot'){'C:\foreign'}else{$root}) 'unit-run' 'outer-clean' '11111111-1111-1111-1111-111111111111' $sid}catch{$failed=$true}
 Assert $failed ('negative accepted '+$scenario);Assert ($script:calls.Count-eq0) 'mutation before authorization'
}
Write-Output 'PASS: 3 actual descriptors + legacy RED + owned scope + 3 deny-before-write namespace cases (8)'
