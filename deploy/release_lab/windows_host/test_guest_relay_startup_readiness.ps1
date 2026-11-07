param([string]$Task=(Join-Path $PSScriptRoot 'hyperv_relay_guest_task.ps1'))
$ErrorActionPreference='Stop';Set-StrictMode -Version 2.0
$tokens=$null;$errors=$null;$tree=[Management.Automation.Language.Parser]::ParseFile($Task,[ref]$tokens,[ref]$errors);if($errors.Count){throw 'task parse failed'}
$node=$tree.FindAll({param($n)$n-is[Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-eq'Wait-OwnedGuestRelayReady'},$true);if($node.Count-ne1){throw 'actual readiness function missing'}
. ([ScriptBlock]::Create($node[0].Extent.Text))
$scratch=Join-Path ([Environment]::GetEnvironmentVariable('TMPDIR')) ('relay-start-ready-'+[guid]::NewGuid().ToString('N'));[void](New-Item -ItemType Directory -Path $scratch)
$RunId='run';$CaseId='publisher-clean';$VmId=[guid]'11111111-2222-3333-4444-555555555555';$Channel='http';$TaskName='owned-task';$SupervisorPath='C:\owned\supervisor.exe';$RelayPath='C:\owned\relay.exe';$OwnershipFile=Join-Path $scratch 'http.lease';$ReceiptPath=Join-Path $scratch 'http.receipt';$HelperSha256='a'*64
$script:scenario='success';$script:poll=0
function Get-Process {param($Id,$ErrorAction);[pscustomobject]@{SessionId=1}}
function Get-ScheduledTask {param($TaskName,$ErrorAction);[pscustomobject]@{TaskName=$TaskName;State=$(if($script:scenario-eq'task-state'){'Ready'}else{'Running'});Actions=@([pscustomobject]@{Execute=$SupervisorPath;Arguments=$(if($script:scenario-eq'arguments'){'wrong'}else{'expected'})});Principal=[pscustomobject]@{UserId=$(if($script:scenario-eq'principal'){'other'}else{'SYSTEM'})}}}
function Get-ScheduledTaskInfo {param($TaskName,$ErrorAction);[pscustomobject]@{LastTaskResult=$(if($script:scenario-eq'dll-load-failure'){3221225781}else{267009})}}
function Test-Path {param($LiteralPath,$PathType);$script:poll++;if($script:scenario-eq'timeout'){return $false};if($script:scenario-eq'delayed'-and$script:poll-lt4){return $false};return $true}
function Test-OwnedRelayStopped {param($mode,$channel,$id,$case,$vm,$hash,$lease,$receipt,$supervisor,$relay);if($mode-cne'guest'-or$channel-cne'http'-or$id-cne$RunId-or$case-cne$CaseId-or$vm-ne$VmId-or$hash-cne$HelperSha256){throw 'readiness lost identity binding'};if($script:scenario-eq'foreign-record'){throw 'foreign record'};return $false}
function Read-OwnedRelayRecord {param($Path);if($script:scenario-eq'malformed-record'){throw 'malformed record'};@{state=$(if($script:scenario-eq'failed-record'){'failed'}else{'running'});parent_pid='21';relay_pid='22';parent_start='123';relay_start='456'}}
function Get-CimInstance {param($ClassName,$Filter,$ErrorAction);[pscustomobject]@{SessionId=$(if($script:scenario-eq'session'){1}else{0});ExecutablePath='C:\owned\helper.exe'}}
function Invoke-CimMethod {param($InputObject,$MethodName,$ErrorAction);[pscustomobject]@{ReturnValue=0;Sid=$(if($script:scenario-eq'owner'){'S-1-5-21-other'}else{'S-1-5-18'})}}
function Start-Sleep {param($Milliseconds)}
$cases=0
try {
 foreach($scenario in @('success','delayed','dll-load-failure','timeout','arguments','principal','foreign-record','malformed-record','failed-record','session','owner','task-state')){
  $script:scenario=$scenario;$script:poll=0;$passed=$false
  try{$result=Wait-OwnedGuestRelayReady 'expected';$passed=$true}catch{if($scenario-in@('success','delayed')){throw}}
  if($passed-ne($scenario-in@('success','delayed'))){throw "case $scenario did not reject invalid startup"}
  $raw=[IO.File]::ReadAllText((Join-Path $scratch 'startup-http.json'));$diagnostic=$raw|ConvertFrom-Json
  if($diagnostic.calling_session_id-ne1-or$diagnostic.ready-ne$passed){throw 'diagnostic readiness/session differs'}
  if($scenario-eq'dll-load-failure'-and$diagnostic.last_task_result-ne3221225781){throw 'loader failure LastTaskResult was lost'}
  if($passed-and(@($result.processes).Count-ne2-or@($result.processes|Where-Object{$_.session_id-ne0-or$_.owner_sid-cne'S-1-5-18'}).Count)){throw 'SYSTEM session zero proof missing'}
  $cases++
 }
 "PASS $cases actual readiness cases; all tasks/processes mocked, private bounded diagnostics retained per case"
}finally{if([IO.Path]::GetFullPath($scratch).StartsWith([IO.Path]::GetFullPath([Environment]::GetEnvironmentVariable('TMPDIR')))){Remove-Item -LiteralPath $scratch -Recurse -Force}}
