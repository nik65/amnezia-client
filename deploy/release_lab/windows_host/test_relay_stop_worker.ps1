# Actual SYSTEM stop worker/caller branches; all scheduling, IO and processes mocked.
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'test_relay_stop_idempotency.ps1')
$source=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'hyperv_relay_guest_task.ps1'))
$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseInput($source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'worker source parse failed'}
$caller=$ast.Find({param($n)$n-is[Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-eq'Invoke-GuestRelayStopWorker'},$true);Invoke-Expression $caller.Extent.Text
$branch=$ast.Find({param($n)$n-is[Management.Automation.Language.IfStatementAst]-and$n.Clauses[0].Item1.Extent.Text-eq"`$Mode-eq'guest-worker'"},$true)
$body=$branch.Clauses[0].Item2.Extent.Text;$body=$body.Substring(1,$body.Length-2).Replace('exit 0','return')
$script:workerBody=[scriptblock]::Create('param($Action,$Mode,$RunId,$CaseId,$Channel,[guid]$VmId,$SupervisorPath,$RelayPath,$OwnershipFile,$ReceiptPath,$HelperSha256,$SourceSha256,$StopAttempt)'+$body)
$script:workerSession=0;$script:workerTasks=@{};$script:workerRunCount=0;$script:producerSession=0
function Get-RelayStopSessionId{return $script:workerSession}
function New-ScheduledTaskAction {param($Execute,$Argument) [pscustomobject]@{Execute=$Execute;Arguments=$Argument}}
function New-ScheduledTaskPrincipal {param($UserId,$LogonType,$RunLevel) [pscustomobject]@{UserId=$UserId;LogonType=$LogonType;RunLevel=$RunLevel}}
function Register-ScheduledTask {param($TaskName,$Action,$Principal,$Description,$ErrorAction) if($script:workerTasks.ContainsKey($TaskName)){throw 'duplicate worker'};$script:workerTasks[$TaskName]=[pscustomobject]@{TaskName=$TaskName;Actions=@($Action);Principal=$Principal}}
function Start-ScheduledTask {param($TaskName,$ErrorAction)
 $script:workerRunCount++;$task=$script:workerTasks[$TaskName]
 Check ($task.Principal.UserId-eq'SYSTEM'-and$task.Principal.LogonType-eq'ServiceAccount') 'worker SYSTEM principal'
 $encoded=($task.Actions[0].Arguments-split' ')[-1];$command=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($encoded))
 $command=$command.Replace(("& '"+$PSCommandPath.Replace("'","''")+"'"),'& $script:workerBody').Replace("& ''",'& $script:workerBody')
 $script:elevated=$true
 try{&([scriptblock]::Create($command))|Out-Null}catch{$script:workerError=$_.Exception.Message}finally{$script:elevated=$false}
}
function Get-ScheduledTask {param($TaskName,$ErrorAction) if($script:workerTasks.ContainsKey($TaskName)){return $script:workerTasks[$TaskName]};return $script:scheduled}
function Unregister-ScheduledTask {param($TaskName,[switch]$Confirm,$ErrorAction) $script:unregisters++;[void]$script:workerTasks.Remove($TaskName)}
function Write-RelayStopResult {param($Path,$Value) $script:records[$Path]=($Value|ConvertTo-Json -Compress)}
function Get-Content {param($LiteralPath,$ErrorAction,$TotalCount,[switch]$Raw) if($Raw){return [string]$script:records[$LiteralPath]};return $script:records[$LiteralPath]}
function Get-CimInstance {param($ClassName,$Filter,$ErrorAction) $n=[int]($Filter-replace'ProcessId=','');if($script:live.ContainsKey($n)){[pscustomobject]@{SessionId=$script:producerSession;ExecutablePath=$(if($script:elevated){$script:live[$n][0]}else{$null})}}}
function Worker-Fixture {Reset-Guest;$script:SourceSha256='c'*64;$script:workerTasks=@{};$script:workerError='';$script:workerSession=0;$script:producerSession=0;$script:workerRunCount=0;$script:elevated=$false}
Worker-Fixture;&$guestStop|Out-Null;Check ($starts-eq1-and$workerRunCount-eq1-and$workerTasks.Count-eq0) 'actual SYSTEM worker stop and exact task cleanup'
Worker-Fixture;$script:workerSession=1;$caught=$false;try{&$guestStop|Out-Null}catch{$caught=$true};Check ($caught-and$starts-eq0-and$workerTasks.Count-eq1) 'wrong worker session fails and retains owned diagnostics task'
Worker-Fixture;$script:producerSession=2;$caught=$false;try{&$guestStop|Out-Null}catch{$caught=$true};Check ($caught-and$starts-eq0) 'wrong producer session rejected before signal'
Worker-Fixture;[void]$records.Remove($OwnershipFile);$caught=$false;try{&$guestStop|Out-Null}catch{$caught=$true};Check ($caught-and$workerError.Contains($OwnershipFile)-and$starts-eq0) 'missing lease exact path preserved in private result'
Write-Output '4 actual SYSTEM worker/caller cases PASS (all side effects mocked)'
