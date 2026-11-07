param([string]$Adapter=(Join-Path $PSScriptRoot 'hyperv_adapter.ps1'),[string]$Task=(Join-Path $PSScriptRoot 'hyperv_relay_guest_task.ps1'))
$ErrorActionPreference='Stop';Set-StrictMode -Version 2.0
$tokens=$null;$errors=$null;$tree=[Management.Automation.Language.Parser]::ParseFile($Adapter,[ref]$tokens,[ref]$errors);if($errors.Count){throw 'adapter parse failed'}
$node=$tree.FindAll({param($n)$n-is[Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-eq'Start-Relays'},$true);if($node.Count-ne1){throw 'actual start function missing'}
. ([ScriptBlock]::Create($node[0].Extent.Text))
$RunId='run';$CaseId='publisher-clean';$AttemptNonce='a'*48;$ChildVmId='11111111-2222-3333-4444-555555555555';$RelayHelperSha256='b'*64;$RelayHelperPath='C:\owned\relay.exe';$RelaySupervisorPath='C:\owned\supervisor.exe';$RelayGuestTaskPath='C:\owned\task.ps1'
$child=[pscustomobject]@{vm=[pscustomobject]@{State='Running';Id=[guid]$ChildVmId};marker=[pscustomobject]@{vm_id=$ChildVmId}}
$script:scenario='good';$script:startupCalls=0
function Fail {param($message);throw $message}
function Test-Path {param($LiteralPath,$PathType);return $true}
function Sha {param($p);return $RelayHelperSha256}
function New-Item {param($ItemType,[switch]$Force,$Path)}
function Register-RelayServices {param($root);@{owned=$true}}
function New-Session {param($child);return 'mock-session'}
function Remove-PSSession {param($Session,$ErrorAction)}
function Stage-OwnedGuestRelayDependencies {param($session,$root,$vm);@{files=@(1,2,3);host_installed_files_read=$false}}
function Copy-Item {param($LiteralPath,$Destination,$ToSession,[switch]$Force)}
function Invoke-Command {param($Session,$ScriptBlock,$ArgumentList);& $ScriptBlock @ArgumentList}
function Get-Item {param($LiteralPath);@{Length=0}}
function powershell.exe {
 $script:startupCalls++;$channel='';for($i=0;$i-lt$args.Count-1;$i++){if($args[$i]-ceq'-Channel'){$channel=$args[$i+1]}}
 $global:LASTEXITCODE=if($script:scenario-eq'nonzero'){17}else{0}
 if($script:scenario-eq'bad-json'){return 'not-json'}
 @{action='start';run_id=$(if($script:scenario-eq'foreign'){'foreign'}else{$RunId});case_id=$CaseId;vm_id=([guid]$ChildVmId).ToString('B');ready=$true;readiness=@{ready=$true;channel=$channel}}|ConvertTo-Json -Depth 5 -Compress
}
function Start-Process {param($FilePath,$Verb,$ArgumentList,$WindowStyle,[switch]$PassThru);[pscustomobject]@{Id=123;HasExited=$false}}
function Wait-RelayReceipt {param($path);return $true}
$cases=0
foreach($scenario in @('good','foreign','bad-json','nonzero')){
 $script:scenario=$scenario;$script:startupCalls=0;$passed=$false
 try{$result=Start-Relays $child;$passed=$true}catch{if($scenario-eq'good'){throw}}
 if($passed-ne($scenario-eq'good')){throw "invalid startup wire accepted: $scenario"}
 if($passed-and(@($result.guest).Count-ne2-or$result.passed-ne$true-or$script:startupCalls-ne2-or@($result.host).Count-ne2)){throw 'whole start result missing typed guest readiness'}
 $cases++
}
# Inspect and execute actual start branch with inert cmdlet mocks: one on-demand start, no trigger.
$tt=$null;$ee=$null;$taskTree=[Management.Automation.Language.Parser]::ParseFile($Task,[ref]$tt,[ref]$ee);if($ee.Count){throw 'task parse failed'}
$branch=$taskTree.FindAll({param($n)$n-is[Management.Automation.Language.IfStatementAst]-and$n.Clauses[0].Item1.Extent.Text-eq"`$Action -eq 'start'"},$true)
if($branch.Count-ne1){throw 'actual task start branch missing'}
$statements=@($branch[0].Clauses[0].Item2.Statements);if($statements[-1]-isnot[Management.Automation.Language.ExitStatementAst]){throw 'unexpected branch terminator'}
$body=[ScriptBlock]::Create(($statements[0..($statements.Count-2)]|ForEach-Object{$_.Extent.Text})-join"`n")
$Channel='http';$VmId=[guid]$ChildVmId;$TaskName='owned-task';$StopEventName='Local\owned';$RelayPath=$RelayHelperPath;$SupervisorPath=$RelaySupervisorPath;$OwnershipFile='C:\owned\http.lease';$ReceiptPath='C:\owned\http.receipt';$HelperSha256=$RelayHelperSha256
$script:registered=0;$script:started=0
function Get-ScheduledTask {param($TaskName,$ErrorAction);return $null}
function New-ScheduledTaskAction {param($Execute,$Argument);@{Execute=$Execute;Arguments=$Argument}}
function New-ScheduledTaskTrigger {throw 'delayed duplicate trigger is forbidden'}
function New-ScheduledTaskPrincipal {param($UserId,$LogonType,$RunLevel);@{UserId=$UserId}}
function Register-ScheduledTask {param($TaskName,$Action,$Principal,$Description);$script:registered++;if($Principal.UserId-cne'SYSTEM'){throw 'SYSTEM principal lost'}}
function Start-ScheduledTask {param($TaskName);$script:started++}
function Wait-OwnedGuestRelayReady {param($arguments);@{ready=$true;channel='http';processes=@(@{role='parent';pid=21;session_id=0;owner_sid='S-1-5-18'},@{role='relay';pid=22;session_id=0;owner_sid='S-1-5-18'})}}
$wire=@(& $body 3>&1);if($wire.Count-ne1-or($wire[0]|ConvertFrom-Json).ready-ne$true-or$script:registered-ne1-or$script:started-ne1){throw 'actual on-demand startup proof differs'}
$decoded=$wire[0]|ConvertFrom-Json;if(@($decoded.readiness.processes).Count-ne2-or$decoded.readiness.processes[0]-is[string]-or$decoded.readiness.processes[0].pid-ne21-or$decoded.readiness.processes[1].pid-ne22){throw 'nested readiness process JSON proof lost'}
"PASS $cases actual adapter startup wire cases + actual on-demand task branch; all process/task/session/network operations mocked"
