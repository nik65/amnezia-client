param([string]$Adapter=(Join-Path $PSScriptRoot 'hyperv_adapter.ps1'))
$ErrorActionPreference='Stop';Set-StrictMode -Version 2.0
# Load New-Object's module before defining mocks: autoload otherwise replaces
# this suite's Get-FileHash boundary on its first DirectorySecurity allocation.
Import-Module Microsoft.PowerShell.Utility -ErrorAction Stop
$tokens=$null;$errors=$null;$tree=[Management.Automation.Language.Parser]::ParseFile($Adapter,[ref]$tokens,[ref]$errors);if($errors.Count){throw 'adapter parse failed'}
$node=$tree.FindAll({param($n)$n-is[Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-eq'Stage-OwnedGuestRelayDependencies'},$true);if($node.Count-ne1){throw 'actual dependency stage function missing'}
. ([ScriptBlock]::Create($node[0].Extent.Text))
$RunId='run';$CaseId='publisher-clean';$vm='11111111-2222-3333-4444-555555555555';$root="C:\ProgramData\AmneziaLab\runs\$RunId\windows-x64\$CaseId\relay"
$script:guest=$false;$script:copied=@();$script:scenario='good';$script:afterCopy=$false;$script:aclApplied=$false
function Set-Acl {param($LiteralPath,$AclObject,$ErrorAction)
 if(-not$script:guest-or$LiteralPath-ine$root){throw 'ACL must target only the owned guest relay root'}
 if($script:scenario-eq'acl-failure'){throw 'inert ACL failure'}
 $rules=@($AclObject.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
 if(-not$AclObject.AreAccessRulesProtected-or$rules.Count-ne2){throw 'relay ACL must exclude inherited writable access'}
 $sids=@($rules|ForEach-Object{$_.IdentityReference.Value}|Sort-Object)
 if(($sids-join',')-cne'S-1-5-18,S-1-5-32-544'){throw 'unexpected relay ACL principal'}
 foreach($rule in $rules){if($rule.FileSystemRights-ne[Security.AccessControl.FileSystemRights]::FullControl-or$rule.AccessControlType-ne[Security.AccessControl.AccessControlType]::Allow-or$rule.InheritanceFlags-ne([Security.AccessControl.InheritanceFlags]::ContainerInherit-bor[Security.AccessControl.InheritanceFlags]::ObjectInherit)){throw 'relay ACL rights differ'}}
 $script:aclApplied=$true
}
function Invoke-Command {param($Session,$ScriptBlock,$ArgumentList);$script:guest=$true;try{& $ScriptBlock @ArgumentList}finally{$script:guest=$false}}
function Test-Path {param($LiteralPath);if(-not$script:guest){throw 'host filesystem read forbidden'};if($LiteralPath-match'\\relay\\[^\\]+\.dll$'){return $script:scenario-eq'existing-wrong'};return $true}
function Get-Item {param($LiteralPath,[switch]$Force,$ErrorAction);if(-not$script:guest){throw 'host installed file read forbidden'};if($script:scenario-eq'missing'-and$LiteralPath-like'*VCRUNTIME140_1.dll'){throw 'missing source DLL'};[pscustomobject]@{Attributes=$(if($script:scenario-eq'reparse'-and$LiteralPath-like'*AmneziaVPN*'){[IO.FileAttributes]::ReparsePoint}else{[IO.FileAttributes]::Normal});PSIsContainer=$false;Length=100}}
function Get-FileHash {param($LiteralPath,$Algorithm,$ErrorAction);if(-not$script:guest){throw 'host installed hash forbidden'};[pscustomobject]@{Hash=$(if(($script:scenario-eq'existing-wrong'-and$LiteralPath-like'*\relay\*')-or($script:scenario-eq'source-changed'-and$script:afterCopy-and$LiteralPath-like'*Program Files*')){'b'*64}else{'a'*64})}}
function Get-Content {param($LiteralPath,$ErrorAction);@("amnezia-release-lab:${RunId}:windows-x64",'backend=hyperv',"case_id=$CaseId",$(if($script:scenario-eq'marker'){'vm_id=foreign'}else{"vm_id=$vm"}))}
function New-Item {param($ItemType,$Path,[switch]$Force);if(-not$script:guest){throw 'host mutation forbidden'}}
function Copy-Item {param($LiteralPath,$Destination,$ErrorAction);if(-not$script:guest){throw 'host copy forbidden'};$script:copied+=@{source=$LiteralPath;destination=$Destination};$script:afterCopy=$true}
$cases=0
foreach($scenario in @('good','missing','reparse','existing-wrong','source-changed','marker','acl-failure')){
 $script:scenario=$scenario;$script:copied=@();$script:afterCopy=$false;$script:aclApplied=$false;$passed=$false
 try{$result=Stage-OwnedGuestRelayDependencies 'mock-session' $root $vm;$passed=$true}catch{if($scenario-eq'good'){throw}}
 if($passed-ne($scenario-eq'good')){throw "invalid DLL stage case accepted: $scenario"}
 if($passed){
  if(-not$script:aclApplied-or@($result.files).Count-ne3-or$result.host_installed_files_read-ne$false-or@($script:copied).Count-ne3){throw 'stage DLL count/readback differs'}
  $names=@($result.files|ForEach-Object{$_.name}|Sort-Object);if(($names-join',')-cne'MSVCP140.dll,VCRUNTIME140.dll,VCRUNTIME140_1.dll'){throw 'DLL allowlist differs'}
  foreach($record in $result.files){if($record.source-ine("C:\Program Files\AmneziaVPN\"+$record.name)-or$record.path-ine(Join-Path $root $record.name)-or$record.sha256-cne('a'*64)-or$record.size-ne100){throw 'DLL source/copy proof differs'}}
 }
 if($scenario-eq'acl-failure'-and$script:copied.Count-ne0){throw 'DLL copy occurred before ACL protection'}
 $cases++
}
"PASS $cases actual guest CRT staging cases; filesystem/session operations mocked, no host installed reads"
