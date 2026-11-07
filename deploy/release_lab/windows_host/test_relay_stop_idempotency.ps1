param([string]$AdapterPath=(Join-Path $PSScriptRoot 'hyperv_adapter.ps1'),[string]$GuestTaskPath=(Join-Path $PSScriptRoot 'hyperv_relay_guest_task.ps1'))
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($AdapterPath,[ref]$tokens,[ref]$errors)
if($errors.Count){throw "adapter parse failed: $errors"}
foreach($name in @('Read-OwnedRelayRecord','Test-OwnedRelayStopped','Invoke-OwnedRelayStop','Invoke-ElevatedOwnedRelayStop','Stop-Relays')){
 $node=$ast.Find({param($n)$n-is[Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-eq$name},$true)
 if($null-eq$node){throw "missing actual function $name"};Invoke-Expression $node.Extent.Text
}
$script:RunId='ordinary-lab-run_42';$script:CaseId='publisher-clean';$script:RelayHelperSha256='a'*64
$script:RelaySupervisorPath='C:\owned\supervisor.exe';$script:RelayHelperPath='C:\owned\relay.exe'
$script:RelayGuestTaskPath='C:\owned\guest-task.ps1';$script:RelayGuestTaskSha256='c'*64;$script:elevated=$false;$script:taskTamper=$false;$script:elevationExit=0
function Sha {param($Path) if($script:taskTamper){return ('d'*64)};return $RelayGuestTaskSha256}

$script:vm=[guid]'079ea361-546a-4486-9d0b-a2a078b9d4cd';$script:root="C:\ProgramData\AmneziaReleaseLab\hyperv\runs\$RunId\relay"
$script:records=@{};$script:live=@{};$script:starts=0;$script:unregisters=0;$script:exit=0;$script:mutator=$null;$script:processRace=''
function Reset-Fixture {
 $script:records=@{};$script:live=@{};$script:starts=0;$script:unregisters=0;$script:exit=0;$script:mutator=$null;$script:processRace=''
 foreach($ch in @('ssh','http')){
  $service=if($ch-eq'ssh'){'{5f2f2a1e-9c3a-4fa9-8f4d-31e9960d7c31}'}else{'{6f3bdc8b-7b21-4df1-a3f5-6e4aaecf8f42}'}
  $base=@('schema=1',"run_id=$RunId","case_id=$CaseId","vm_id=$($vm.ToString('B'))","helper_sha256=$RelayHelperSha256","stop_event=Local\AmneziaReleaseLabRelayStop_${RunId}_${CaseId}",'parent_pid=111','parent_start=100')
  $script:records["$root\host-$ch.lease"]=$base+@('state=relay-authorized')
  $script:records["$root\host-$ch.receipt"]=$base+@('mode=host',"channel=$ch","service_guid=$service",'relay_pid=222','relay_start=200','state=running')
 }
 $script:live[111]=@($RelaySupervisorPath,100);$script:live[222]=@($RelayHelperPath,200)
}
function Get-Item {param($LiteralPath,[switch]$Force,$ErrorAction) if(-not$script:records.ContainsKey($LiteralPath)){throw 'missing record'};[pscustomobject]@{PSIsContainer=$false;Length=1024;Attributes=0;Parent=$null}}
function Get-Content {param($LiteralPath,$ErrorAction,$TotalCount) $script:records[$LiteralPath]}
function Get-FileHash {param($LiteralPath,$Algorithm,$ErrorAction) [pscustomobject]@{Hash=$(if($LiteralPath-eq$RelayHelperPath){$RelayHelperSha256}else{if($script:taskTamper){'d'*64}else{$RelayGuestTaskSha256}})}}
function Get-CimInstance {param($ClassName,$Filter,$ErrorAction) $n=[int]($Filter-replace'ProcessId=','');if($script:live.ContainsKey($n)){[pscustomobject]@{SessionId=0;ExecutablePath=$(if($script:elevated){$script:live[$n][0]}else{$null})}}}
function Get-Process {param($Id,$ErrorAction)
 if($script:processRace-ne''){
  $mode=$script:processRace;$script:processRace=''
  if($mode-ne'notfound-live'){$script:live.Remove([int]$Id)}
  if($mode-eq'access-denied'){throw [Management.Automation.ErrorRecord]::new([UnauthorizedAccessException]::new('inert denied'),'AccessDenied',[Management.Automation.ErrorCategory]::PermissionDenied,$Id)}
  throw [Management.Automation.ErrorRecord]::new([ArgumentException]::new('inert process exited'),'NoProcessFoundForGivenId',[Management.Automation.ErrorCategory]::ObjectNotFound,$Id)
 }
 [pscustomobject]@{StartTime=[datetime]::FromFileTimeUtc($script:live[[int]$Id][1])}}
function Start-Process {param($FilePath,$ArgumentList,$WindowStyle,[switch]$Wait,[switch]$PassThru,$Verb) if($FilePath-ne$RelaySupervisorPath){
 if($Verb-ne'RunAs'-or$ArgumentList[-2]-ne'-EncodedCommand'){throw 'expected elevated encoded wrapper'}
 if($script:elevationExit-ne0){return [pscustomobject]@{ExitCode=$script:elevationExit}}
 $command=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($ArgumentList[-1]))
 if(-not$command.Contains('-Mode host')-or-not$command.Contains('Get-FileHash')-or-not$command.Contains('-SourceSha256')){throw 'elevated wrapper omits source proof'}
 $script:elevated=$true
 try{ $command=$command.Replace("& 'C:\owned\guest-task.ps1'",'& $script:hostTaskBlock').Replace(';exit $LASTEXITCODE','');&([scriptblock]::Create($command))|Out-Null;return [pscustomobject]@{ExitCode=0} }finally{$script:elevated=$false}
 }
 $script:starts++;if($null-ne$script:mutator){&$script:mutator}else{foreach($p in @($script:records.Keys)){if($p.EndsWith('.receipt')){$script:records[$p]+='state=stopped'}};$script:live=@{}};[pscustomobject]@{ExitCode=$(if($starts-gt1){70}else{$script:exit})}}
function Start-Sleep {param($Milliseconds)}
function Test-Path {param($LiteralPath,$PathType) $script:records.ContainsKey($LiteralPath)}
function Unregister-RelayServices {param($Path) $script:unregisters++}
function Fail {param($Message)throw $Message}
function Check([bool]$Value,[string]$Label){if(-not$Value){throw "FAILED $Label"}}
function Host-Stop {Stop-Relays ([pscustomobject]@{vm=[pscustomobject]@{State='Off';Id=$vm}})}
function Reject([scriptblock]$Change,[string]$Label){Reset-Fixture;&$Change;$caught=$false;try{Host-Stop|Out-Null}catch{$caught=$true};Check $caught $Label;Check ($script:unregisters-eq0) "$Label registry retained"}
$guestSourceForHost=[IO.File]::ReadAllText((Resolve-Path $GuestTaskPath));$guestAstForHost=[Management.Automation.Language.Parser]::ParseInput($guestSourceForHost,[ref]$tokens,[ref]$errors)
$hostIf=$guestAstForHost.Find({param($n)$n-is[Management.Automation.Language.IfStatementAst]-and$n.Extent.Text.Contains('host relay stop task source/action binding differs')-and$n.Clauses[0].Item1.Extent.Text-eq"`$Mode-eq'host'"},$true)
if($null-eq$hostIf){throw 'actual host-mode task branch missing'}
$hostBody=$hostIf.Clauses[0].Item2.Extent.Text;$hostBody=$hostBody.Substring(1,$hostBody.Length-2).Replace('exit 0','return')
$script:hostTaskBlock=[scriptblock]::Create('param($Action,$Mode,$RunId,$CaseId,$Channel,$VmId,$SupervisorPath,$RelayPath,$OwnershipFile,$ReceiptPath,$HelperSha256,$SourceSha256)'+$hostBody)
$count=0
Reset-Fixture;$r=Host-Stop;Check ($r.relays_stopped-and$r.relay_registry_unregistered) 'whole function stop';Check ($script:starts-eq1) 'shared event skips second native stop';$count++
Reset-Fixture;$script:exit=70;$r=Host-Stop;Check $r.relays_stopped '70 only after exact stopped proof';$count++
Reset-Fixture;foreach($p in @($records.Keys)){if($p.EndsWith('.receipt')){$records[$p]+='state=stopped'}};$script:live=@{};$r=Host-Stop;Check ($starts-eq0) 'already stopped no native signal';$count++
Reject {$records["$root\host-http.receipt"]=$records["$root\host-http.receipt"]-replace'channel=http','channel=ssh'} 'foreign channel';$count++
Reject {$records["$root\host-ssh.lease"]=$records["$root\host-ssh.lease"]-replace'helper_sha256=.*',('helper_sha256='+('b'*64))} 'foreign hash';$count++
Reject {$records["$root\host-ssh.receipt"]+='state=failed'} 'failed terminal';$count++
Reject {$script:live[111]=@('C:\foreign.exe',100)} 'foreign process';$count++
Reject {$script:live[111]=@($RelaySupervisorPath,101)} 'reused PID';$count++
Reject {$script:exit=70;$script:mutator={}} '70 without terminal and absence';$count++
Reject {$script:exit=9} 'other native exit';$count++
Reject {$records["$root\host-ssh.receipt"]+='run_id=foreign'} 'duplicate identity';$count++
Reject {$script:mutator={foreach($p in @($records.Keys)){if($p.EndsWith('.receipt')){$records[$p]+='state=stopped'}}}} 'stopped with live PIDs';$count++
Reject {$records["$root\host-ssh.receipt"]=$records["$root\host-ssh.receipt"]-replace'vm_id=.*','vm_id={ffffffff-ffff-ffff-ffff-ffffffffffff}'} 'foreign VM';$count++
Reject {$records["$root\host-ssh.receipt"]=$records["$root\host-ssh.receipt"]-replace'service_guid=.*','service_guid={ffffffff-ffff-ffff-ffff-ffffffffffff}'} 'foreign service';$count++
Reject {$records.Remove("$root\host-ssh.receipt")} 'missing receipt';$count++
Reject {$records["$root\host-ssh.receipt"]+=('x'*4097)} 'oversized wire line';$count++
Reset-Fixture;foreach($p in @($records.Keys)){if($p.EndsWith('.receipt')){$records[$p]+='state=stopped'}};$script:live.Remove(222);$script:processRace='notfound-absent';$r=Host-Stop;Check ($r.relays_stopped-and$starts-eq0) 'CIM present then process exit proven by fresh CIM absence';$count++
Reject {$script:processRace='access-denied'} 'access denied cannot become absence proof';$count++
Reject {$script:processRace='notfound-live'} 'notfound with fresh live PID rejected';$count++

Reset-Fixture;$script:taskTamper=$true;$caught=$false;try{Host-Stop|Out-Null}catch{$caught=$true};$script:taskTamper=$false;Check ($caught-and$starts-eq0-and$unregisters-eq0) 'changed task source rejected before elevation'
Reset-Fixture;$script:elevationExit=5;$caught=$false;try{Host-Stop|Out-Null}catch{$caught=$true};$script:elevationExit=0;Check ($caught-and$unregisters-eq0) 'failed elevated wrapper retains registry'
Write-Output '2 elevated wrapper rejection cases PASS'

Write-Output "$count whole-function host cleanup cases PASS (all side effects mocked)"
function Invoke-GuestRelayStopWorker {Invoke-OwnedRelayStop 'guest' $Channel $RunId $CaseId $VmId $HelperSha256 $OwnershipFile $ReceiptPath $SupervisorPath $RelayPath}
$script:elevated=$true
$guestSource=[IO.File]::ReadAllText((Resolve-Path $GuestTaskPath))
$guestAst=[Management.Automation.Language.Parser]::ParseInput($guestSource,[ref]$tokens,[ref]$errors)
if($errors.Count){throw "guest task parse failed: $errors"}
$stopIf=$guestAst.Find({param($n)$n-is[Management.Automation.Language.IfStatementAst]-and$n.Clauses[0].Item1.Extent.Text-eq"`$Action -eq 'stop'"},$true)
if($null-eq$stopIf){throw 'actual guest stop branch missing'}
$body=$stopIf.Clauses[0].Item2.Extent.Text;$body=$body.Substring(1,$body.Length-2).Replace('exit 0','return')
$script:guestStop=[scriptblock]::Create($body)
function Get-ScheduledTask {param($TaskName,$ErrorAction) return $script:scheduled}
function Unregister-ScheduledTask {param($TaskName,[switch]$Confirm,$ErrorAction) $script:unregisters++}
function Reset-Guest {
 Reset-Fixture
 $script:guestRoot="C:\ProgramData\AmneziaLab\runs\$RunId\windows-x64\$CaseId\relay"
 $copy=@{};foreach($p in @($records.Keys)){$copy[$p.Replace($root,$guestRoot).Replace('host-','')]=$records[$p]-replace'mode=host','mode=guest'};$script:records=$copy
 $script:Channel='ssh';$script:VmId=$vm;$script:HelperSha256=$RelayHelperSha256;$script:OwnershipFile="$guestRoot\ssh.lease";$script:ReceiptPath="$guestRoot\ssh.receipt";$script:SupervisorPath=$RelaySupervisorPath;$script:RelayPath=$RelayHelperPath
 $script:TaskName="AmneziaReleaseLab-Relay-${RunId}-${CaseId}-${Channel}";$script:scheduled=$null
}
Reset-Guest;$r=(& $guestStop)|ConvertFrom-Json;Check ($r.terminal_state-eq'state=stopped') 'actual guest stop branch stopped';Check ($starts-eq1) 'guest native stop once'
$script:Channel='http';$script:OwnershipFile="$guestRoot\http.lease";$script:ReceiptPath="$guestRoot\http.receipt";$script:TaskName="AmneziaReleaseLab-Relay-${RunId}-${CaseId}-${Channel}";$r=(& $guestStop)|ConvertFrom-Json;Check ($starts-eq1) 'guest second shared event already stopped skips signal'
Reset-Guest;$script:scheduled=[pscustomobject]@{TaskName=$TaskName;Actions=@([pscustomobject]@{Execute='C:\foreign.exe';Arguments='foreign'})};$caught=$false;try{&$guestStop|Out-Null}catch{$caught=$true};Check ($caught-and$starts-eq0-and$unregisters-eq0) 'foreign scheduled task retained without signal'
Reset-Guest;$script:exit=70;$script:mutator={};$caught=$false;try{&$guestStop|Out-Null}catch{$caught=$true};Check ($caught-and$unregisters-eq0) 'guest70 without proof retains task'
Write-Output '4 actual guest stop branch cases PASS (all side effects mocked)'
