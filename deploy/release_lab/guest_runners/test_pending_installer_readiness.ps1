[CmdletBinding()]
param([string]$SourcePath,[switch]$ExpectLegacy)
if(-not$SourcePath){$SourcePath=Join-Path $PSScriptRoot 'windows-release-lab.ps1'}
$ErrorActionPreference='Stop';Set-StrictMode -Version 2
Import-Module Microsoft.PowerShell.Utility -ErrorAction Stop
$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($SourcePath,[ref]$tokens,[ref]$errors);if($errors.Count){throw 'runner AST invalid'}
$fn=@($ast.FindAll({param($n)$n-is[Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-eq'Write-PendingInstallerRequest'},$true));if($fn.Count-ne1){throw 'actual pending function absent'};. ([scriptblock]::Create($fn[0].Extent.Text))
$GuestRoot='C:\owned-inert\case';$LauncherPath='C:\owned-inert\launcher.ps1';$LauncherSha256=('a'*64);$ArtifactHash=('b'*64);$RunId='unit-run';$CaseId='outer-clean'
function Fail([string]$Message){throw $Message}
function global:Get-FileHash {param($LiteralPath,$Algorithm) [pscustomobject]@{Hash=$LauncherSha256}}
function global:Get-ScheduledTask {param($TaskName,$ErrorAction) return $null}
function global:New-ScheduledTaskAction {param($Execute,$Argument) [pscustomobject]@{Execute=$Execute;Argument=$Argument}}
function global:New-ScheduledTaskPrincipal {param($UserId,$LogonType,$RunLevel) if($LogonType-ne'Interactive'-or$RunLevel-ne'Limited'){throw 'task token policy changed'};[pscustomobject]@{UserId=$UserId}}
function global:New-ScheduledTaskSettingsSet {param($ExecutionTimeLimit,$MultipleInstances) [pscustomobject]@{Limit=$ExecutionTimeLimit}}
function global:Register-ScheduledTask {param($TaskName,$Action,$Principal,$Settings,$Description,$ErrorAction) $script:registered++}
function global:Start-ScheduledTask {param($TaskName,$ErrorAction) $script:started++}
function global:Unregister-ScheduledTask {param($TaskName,$Confirm,$ErrorAction) throw 'unexpected cleanup path'}
function global:Start-Sleep {param($Milliseconds) if($Milliseconds-ne250){throw 'poll interval changed'};$script:slept++}
function global:Get-Date { $script:ticks+=10;return ([DateTime]'2026-01-01T00:00:00Z').AddSeconds($script:ticks) }
function global:Test-Path {param($LiteralPath,$PathType) if($LiteralPath-eq$LauncherPath){return $true};return $script:scenario-ne'missing'}
function global:Get-Content {param($LiteralPath,[switch]$Raw)
 $v=[ordered]@{run_id=$RunId;case_id=$CaseId;artifact_sha256=$ArtifactHash;state='waiting'}
 switch($script:scenario){'completed'{$v.state='completed'}'running'{$v.state='running'}'LaunchFailed'{$v.state='LaunchFailed'}'wrongrun'{$v.run_id='foreign'}'wrongcase'{$v.case_id='outer-upgrade'}'wronghash'{$v.artifact_sha256=('c'*64)}}
 return ($v|ConvertTo-Json -Compress)
}
$results=@()
foreach($scenario in @('completed','running','LaunchFailed','wrongrun','wrongcase','wronghash','missing','waiting')){
 $script:scenario=$scenario;$script:ticks=0;$script:slept=0;$script:registered=0;$script:started=0;$failed=$false;$result=$null
 try{$result=Write-PendingInstallerRequest 'C:\owned-inert\candidate.exe' $ArtifactHash}catch{$failed=$true;$capturedError=$_.Exception.Message+" STACK:"+$_.ScriptStackTrace}
 $expectedFailure=if($ExpectLegacy){$scenario-eq'missing'}else{$scenario-ne'waiting'}
 if($failed-ne$expectedFailure-or$script:registered-ne1-or$script:started-ne1){throw ('actual pending function outcome differs '+$scenario+' failed='+$failed+' registered='+$script:registered+' started='+$script:started+' error='+$capturedError)}
 if($scenario-eq'waiting'-and($script:slept-ne0-or$result.state-cne'waiting')){throw 'bound ready request did not return immediately'}
 if($scenario-ne'waiting'-and$script:slept-ne3){throw '30 second bounded timeout changed'}
 $results+=@([ordered]@{case=$scenario;rejected=$failed;legacy=[bool]$ExpectLegacy})
}
'PASS actual whole pending request function 8 cases; legacy='+[bool]$ExpectLegacy
