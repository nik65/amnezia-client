param([Parameter(Mandatory=$true)][string]$Adapter,[Parameter(Mandatory=$true)][string]$Scratch)
$ErrorActionPreference='Stop';$t=$null;$e=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Adapter,[ref]$t,[ref]$e);if($e.Count){throw 'AST parse failed'}
$function=@($ast.FindAll({param($n)$n-is[Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-eq'Start-Relays'},$true));if($function.Count-ne1){throw 'unique function required'}
Invoke-Expression $function[0].Extent.Text
function Fail($message){throw $message}
function Sha($path){(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()}
function New-Item { $script:hostCalls++;return [pscustomobject]@{mocked=$true} }
function Register-RelayServices { $script:registryCalls++;return [ordered]@{registered=$true} }
function New-Session {return 'mock-session'}
function Remove-PSSession {}
function Stage-OwnedGuestRelayDependencies {return [ordered]@{files=@(1,2,3);host_installed_files_read=$false}}
function Invoke-Command {param($Session,$ScriptBlock,$ArgumentList);$script:guestCalls++;return [ordered]@{action='start';run_id=$RunId;case_id=$CaseId;vm_id=([guid]$ChildVmId).ToString('B');ready=$true;readiness=@{ready=$true;channel=$ArgumentList[1]}}}
function Copy-Item {param($LiteralPath,$Destination,$ToSession,[switch]$Force);if($ToSession-ne'mock-session'){throw 'copy must target mocked guest'};$script:copyCalls++}
function Start-Process {param($FilePath,$Verb,$ArgumentList,$WindowStyle,[switch]$PassThru);if($Verb-ne'RunAs'-or$WindowStyle-ne'Hidden'-or-not$PassThru){throw 'relay launch options changed'};$script:processCalls++;return [pscustomobject]@{Id=(100+$script:processCalls);HasExited=$false}}
function Wait-RelayReceipt {return $true}
$RunId='p17-1028-tcg-test';$CaseId='publisher-clean';$AttemptNonce='a'*48;$ChildVmId='11111111-1111-1111-1111-111111111111'
$child=[pscustomobject]@{vm=[pscustomobject]@{Id=[guid]$ChildVmId;State='Running'};marker=[pscustomobject]@{vm_id=$ChildVmId}}
$RelayHelperPath=Join-Path $Scratch 'relay.exe';$RelaySupervisorPath=Join-Path $Scratch 'supervisor.exe';$RelayGuestTaskPath=Join-Path $Scratch 'task.ps1'
foreach($path in @($RelayHelperPath,$RelaySupervisorPath,$RelayGuestTaskPath)){[IO.File]::WriteAllText($path,'inert fixture')}
$RelayHelperSha256=Sha $RelayHelperPath;$originalHost=$Host
$script:hostCalls=0;$script:registryCalls=0;$script:guestCalls=0;$script:copyCalls=0;$script:processCalls=0
$result=@(Start-Relays $child)
if($result.Count-ne1-or$result[0]-isnot[Collections.IDictionary]){throw 'single relay result object required'}
$r=$result[0]
if($r.action-ne'relays-start'-or$r.passed-ne$true-or$r.host_network_mutation-ne$false-or$r.host.Count-ne2-or$r.guest.Count-ne2-or$script:processCalls-ne2-or$script:copyCalls-ne3-or$script:registryCalls-ne1){throw 'relay shape/call count differs'}
if(-not[object]::ReferenceEquals($Host,$originalHost)){throw 'PowerShell host altered'}
$checks=1
foreach($mode in @('nonce','vm','hash')){
 $nonceBefore=$AttemptNonce;$vmBefore=$ChildVmId;$hashBefore=$RelayHelperSha256
 if($mode-eq'nonce'){$AttemptNonce='bad'};if($mode-eq'vm'){$ChildVmId='foreign'};if($mode-eq'hash'){$RelayHelperSha256='f'*64}
 $before=$script:processCalls;$failed=$false
 try{Start-Relays $child|Out-Null}catch{$failed=$true}
 if(-not$failed-or$script:processCalls-ne$before){throw 'invalid identity/hash accepted'}
 $AttemptNonce=$nonceBefore;$ChildVmId=$vmBefore;$RelayHelperSha256=$hashBefore;$checks++
}
[ordered]@{status='PASS';wholeFunctionCases=$checks;actualRelaysStarted=$false;actualRegistryChanged=$false;actualGuestUsed=$false}|ConvertTo-Json -Compress
