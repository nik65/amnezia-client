param([string]$TaskPath=(Join-Path $PSScriptRoot 'hyperv_relay_guest_task.ps1'),[ValidateSet('success','wrong-session','foreign-pid')][string]$Scenario='success')
# Invoke the COMPLETE source file. No target functions are injected or overridden.
# Only built-in IO/process/task command boundaries are inert mocks.
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$TaskPath=(Resolve-Path $TaskPath).Path;$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($TaskPath,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'whole guest task parse failed'}
foreach($name in @('Read-OwnedRelayRecord','Test-OwnedRelayStopped','Invoke-OwnedRelayStop','Write-RelayStopResult','Invoke-GuestRelayStopWorker','Get-RelayStopSessionId')){
 $nodes=@($ast.FindAll({param($n)$n-is[Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-eq$name},$true))
 if($nodes.Count-ne1-or$nodes[0].Parent-isnot[Management.Automation.Language.NamedBlockAst]-or$nodes[0].Parent.Parent-ne$ast){throw "function is not unique root-level source: $name"}
}
$global:id='ordinary-lab-run_42';$global:case='publisher-clean';$global:vm=[guid]'079ea361-546a-4486-9d0b-a2a078b9d4cd';$global:hash='a'*64;$global:pin='c'*64;$global:nativeStops=0
$global:root="C:\ProgramData\AmneziaLab\runs\$id\windows-x64\$case\relay";$global:lease="$root\ssh.lease";$global:receipt="$root\ssh.receipt";$global:sup="$root\supervisor.exe";$global:relay="$root\relay.exe"
$common=@('schema=1',"run_id=$id","case_id=$case","vm_id=$($vm.ToString('B'))","helper_sha256=$hash",'parent_pid=111','parent_start=100',"stop_event=Local\AmneziaReleaseLabRelayStop_${id}_${case}")
$global:records=@{};$global:records[$lease]=$common+@('state=relay-authorized');$global:records[$receipt]=$common+@('mode=guest','channel=ssh','service_guid={5f2f2a1e-9c3a-4fa9-8f4d-31e9960d7c31}','relay_pid=222','relay_start=200','state=running')
$global:live=@{111=@($sup,100);222=@($relay,200)};$global:files=@{}
function Test-Path {param($LiteralPath,$PathType) return ($LiteralPath-in@($sup,$relay)-or$global:records.ContainsKey($LiteralPath)-or$global:files.ContainsKey($LiteralPath))}
function Get-FileHash {param($LiteralPath,$Algorithm,$ErrorAction)
 foreach($name in @('Write-RelayStopResult','Invoke-GuestRelayStopWorker','Get-RelayStopSessionId')){if(-not(Get-Command -Name $name -CommandType Function -ErrorAction Stop)){throw 'target helper unavailable at actual entry branch'}}
 [pscustomobject]@{Hash=$(if($LiteralPath-eq$relay){$hash}else{$pin})}
}
function Get-Item {param($LiteralPath,[switch]$Force,$ErrorAction)
 if($LiteralPath-eq$root){return [pscustomobject]@{Attributes=0;Parent=$null}}
 if($global:records.ContainsKey($LiteralPath)){return [pscustomobject]@{PSIsContainer=$false;Length=1024;Attributes=0;Parent=$null}}
 if($global:files.ContainsKey($LiteralPath)){return [pscustomobject]@{PSIsContainer=$false;Length=$global:files[$LiteralPath].Length;Attributes=0;Parent=$null}}
 throw "unexpected mocked GetItem path $LiteralPath"
}
function Get-Content {param($LiteralPath,$TotalCount,$ErrorAction) return $global:records[$LiteralPath]}
function Get-CimInstance {param($ClassName,$Filter,$ErrorAction) $n=[int]($Filter-replace'ProcessId=','');if($global:live.ContainsKey($n)){[pscustomobject]@{SessionId=0;ExecutablePath=$(if($Scenario-eq'foreign-pid'){'C:\foreign.exe'}else{$global:live[$n][0]})}}}
function Get-Process {param($Id,$ErrorAction) if($Id-eq$PID){return [pscustomobject]@{SessionId=$(if($Scenario-eq'wrong-session'){1}else{0})}};[pscustomobject]@{StartTime=[datetime]::FromFileTimeUtc($global:live[[int]$Id][1])}}
function Start-Process {param($FilePath,$ArgumentList,$WindowStyle,[switch]$Wait,[switch]$PassThru,$Verb) if($FilePath-ne$sup){throw 'unexpected actual process request'};$global:nativeStops++;$global:records[$receipt]+='state=stopped';$global:live=@{};[pscustomobject]@{ExitCode=0}}
function Start-Sleep {param($Milliseconds)}
function New-Item {param($ItemType,$Path,$ErrorAction) if($ItemType-ne'File'-or$global:files.ContainsKey($Path)){throw 'not exclusive mocked file creation'};$global:files[$Path]=[byte[]]@()}
function Set-Content {param($LiteralPath,$Encoding,$Value,$ErrorAction) if($Encoding-ne'Byte'-or-not$global:files.ContainsKey($LiteralPath)){throw 'unexpected result byte write'};$global:files[$LiteralPath]=[byte[]]$Value}
function Move-Item {param($LiteralPath,$Destination,$ErrorAction) if($global:files.ContainsKey($Destination)){throw 'result overwrite'};$global:files[$Destination]=$global:files[$LiteralPath];$body=[Text.Encoding]::UTF8.GetString($global:files[$Destination]);Write-Output ('INERT_RESULT:'+($body|ConvertFrom-Json|ConvertTo-Json -Compress));Write-Output "INERT_STOPS:$global:nativeStops"}
& $TaskPath -Action stop -Mode guest-worker -RunId $id -CaseId $case -Channel ssh -VmId $vm -SupervisorPath $sup -RelayPath $relay -OwnershipFile $lease -ReceiptPath $receipt -HelperSha256 $hash -SourceSha256 $pin -StopAttempt ('d'*32)
