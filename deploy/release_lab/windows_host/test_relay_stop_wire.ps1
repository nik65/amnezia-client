# Inert full-function wire regression: only sibling adapter source is read.
$Adapter=Join-Path $PSScriptRoot 'hyperv_adapter.ps1'
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
function Load-StopFunction([string]$Path){
 $t=$null;$e=$null;$a=[Management.Automation.Language.Parser]::ParseFile($Path,[ref]$t,[ref]$e)
 if($e.Count){throw 'adapter AST parse failed'}
 $f=@($a.FindAll({param($n)$n-is[Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-eq'Stop-Relays'},$true))
 if($f.Count-ne1){throw 'unique actual Stop-Relays required'}
 return $f[0].Extent.Text
}
function Fail($message){throw $message}
$RunId='ordinary-release-lab_42';$CaseId='publisher-clean';$RelayHelperSha256='a'*64;$RelayGuestTaskSha256='c'*64;$RelaySupervisorPath='C:\owned\supervisor.exe';$RelayHelperPath='C:\owned\relay.exe'
$child=[pscustomobject]@{vm=[pscustomobject]@{State='Running';Id=[guid]'11111111-1111-1111-1111-111111111111'}}
function New-Session{param($Child);$script:sessions++;return 'inert-session'}
function Remove-PSSession{param($Session,$ErrorAction);$script:sessionRemoved++}
function Invoke-Command{param($Session,$ScriptBlock,$ArgumentList);if($Session-ne'inert-session'){throw 'foreign mocked session'};&$ScriptBlock @ArgumentList}
function Test-Path{param($LiteralPath,$PathType);return $true}
function Start-Process{param($FilePath,$Verb,$ArgumentList,$WindowStyle,[switch]$Wait,[switch]$PassThru);$script:hostStops++;if($FilePath-ne$RelaySupervisorPath-or$ArgumentList[0]-ne'--stop'){throw 'unexpected process command'};[pscustomobject]@{ExitCode=0}}
# The owned-stop process/receipt contract is tested separately by test_relay_stop_idempotency.
# This wire suite mocks that boundary while retaining the actual guest JSON parser.
function Invoke-ElevatedOwnedRelayStop{param($Channel,$Vm,$Lease,$Receipt);if($Channel-notin@('ssh','http')-or$Vm-ne$child.vm.Id-or$Lease-notlike"*\host-$Channel.lease"-or$Receipt-notlike"*\host-$Channel.receipt"){throw 'elevated owned-stop mocked contract differs'};$script:hostStops++}
function Unregister-RelayServices{param($RelayRootPath);$script:registryCalls++;return [ordered]@{unregistered=$true}}
function powershell.exe{
 $script:nativeCalls++
 $arg=@($args)
 function Value-After($Name){$i=[Array]::IndexOf($arg,$Name);if($i-lt0-or$i+1-ge$arg.Count){throw 'native invocation argument missing'};return [string]$arg[$i+1]}
 $ch=Value-After '-Channel';$id=Value-After '-RunId';$case=Value-After '-CaseId'
 if((Value-After '-Action')-ne'stop'-or$id-ne$RunId-or$case-ne$CaseId-or$ch-notin@('ssh','http')){throw 'native invocation identity differs'}
 $global:LASTEXITCODE=if($script:mode-eq'native-failed'){5}else{0}
 if($script:mode-eq'malformed'){return '{'}
 if($script:mode-eq'oversize'){return ('x'*65537)}
 $wire=[ordered]@{action='stop';task="AmneziaReleaseLab-Relay-${id}-${case}-${ch}";run_id=$id;case_id=$case;terminal_state='state=stopped';host_network_mutation=$false}
 if($script:mode-eq'missing'){$wire.Remove('terminal_state')}
 if($script:mode-eq'foreign-action'){$wire.action='start'}
 if($script:mode-eq'foreign-run'){$wire.run_id='foreign'}
 if($script:mode-eq'foreign-case'){$wire.case_id='foreign'}
 if($script:mode-eq'foreign-channel'){$wire.task="AmneziaReleaseLab-Relay-${id}-${case}-foreign"}
 if($script:mode-eq'failed-state'){$wire.terminal_state='state=failed'}
 if($script:mode-eq'unsafe-host'){$wire.host_network_mutation=$true}
 if($script:mode-eq'string-host'){$wire.host_network_mutation='false'}
 $json=$wire|ConvertTo-Json -Compress
 if($script:mode-eq'array'){return '['+$json+']'}
 return $json
}
function Invoke-Case([string]$Mode){
 $script:mode=$Mode;$script:nativeCalls=0;$script:hostStops=0;$script:registryCalls=0;$script:sessions=0;$script:sessionRemoved=0
 $failed=$false;$message='';$answer=$null
 try{$answer=@(Stop-Relays $child)}catch{$failed=$true;$message=$_.Exception.Message}
 [ordered]@{failed=$failed;message=$message;answer=$answer;nativeCalls=$script:nativeCalls;hostStops=$script:hostStops;registryCalls=$script:registryCalls;sessions=$script:sessions;sessionRemoved=$script:sessionRemoved}
}
Invoke-Expression (Load-StopFunction $Adapter)
$good=Invoke-Case 'valid'
if($good.failed-or$good.answer.Count-ne1-or$good.answer[0].action-ne'relays-stop'-or$good.answer[0].relays_stopped-ne$true-or$good.answer[0].relay_registry_unregistered-ne$true-or$good.nativeCalls-ne2-or$good.hostStops-ne2-or$good.registryCalls-ne1-or$good.sessions-ne1-or$good.sessionRemoved-ne1){throw 'fixed whole stop function lacks exact cleanup success'}
$checks=1
foreach($mode in @('malformed','missing','foreign-action','foreign-run','foreign-case','foreign-channel','failed-state','native-failed','oversize','array','unsafe-host','string-host')){
 $result=Invoke-Case $mode
 if(-not$result.failed-or$result.registryCalls-ne0-or$result.nativeCalls-ne2-or$result.hostStops-ne2-or$result.sessionRemoved-ne1-or$result.message-notmatch'registry ownership retained'){throw "invalid mode $mode did not retain registry ownership: $($result.message)"}
 $checks++
}
[ordered]@{status='PASS';newWholeFunctionCases=$checks;allRemoteProcessRegistrySideEffectsMocked=$true;guestUsed=$false;networkUsed=$false;originalGStderrRecovered=$false}|ConvertTo-Json -Compress
