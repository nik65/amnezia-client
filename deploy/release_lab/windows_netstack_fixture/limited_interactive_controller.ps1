# Hash-bound LIMITED task controller; dot-source only after observer manifest verification.
# This descriptor factory has no filesystem/process/network side effects.
function New-FixtureSecurityDescriptor([string]$UserSid,[ValidateSet('Directory','File','Output')][string]$Kind){
 $directory=$Kind-ne'File'
 $acl=if($directory){New-Object Security.AccessControl.DirectorySecurity}else{New-Object Security.AccessControl.FileSecurity}
 $acl.SetAccessRuleProtection($true,$false)
 $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
 $inherit=if($directory){'ContainerInherit,ObjectInherit'}else{'None'}
 foreach($sid in @('S-1-5-18','S-1-5-32-544')){
  $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($sid)),'FullControl',$inherit,'None','Allow')))
 }
 $rights=if($Kind-eq'Output'){'Modify'}else{'ReadAndExecute'}
 $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($UserSid)),$rights,$inherit,'None','Allow')))
 # Suppress implicit owner WRITE_DAC even if a later high-created telemetry
 # file inherits a labadmin owner SID. Admin/SYSTEM explicit Full remains.
 $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier('S-1-3-4')),'ReadPermissions',$inherit,'None','Allow')))
 return $acl
}
function Set-OwnedFixtureAcl([string]$Path,[string]$UserSid,[ValidateSet('Directory','File','Output')][string]$Kind){
 $item=Get-Item -LiteralPath $Path -Force
 if(($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-ne0-or($Kind-eq'File')-eq[bool]$item.PSIsContainer){throw 'fixture ACL target type/reparse differs'}
 Set-Acl -LiteralPath $item.FullName -AclObject (New-FixtureSecurityDescriptor $UserSid $Kind)
}
function Assert-FixtureAncestorPaths([string]$Path){
 $cursor=[IO.Path]::GetFullPath($Path)
 while($true){
  $item=Get-Item -LiteralPath $cursor -Force
  if(($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-ne0){throw 'fixture ancestor redirected'}
  $parent=[IO.Directory]::GetParent($cursor);if($null-eq$parent){break};$cursor=$parent.FullName
 }
}
function Protect-OwnedFixtureNamespace([string]$Root,[string]$RunId,[string]$CaseId,[string]$VmId,[string]$UserSid){
 $base='C:\ProgramData\AmneziaLab'
 $expected="$base\runs\$RunId\windows-x64\$CaseId\netstack-fixture"
 if([IO.Path]::GetFullPath($Root)-ine$expected-or$RunId-notmatch'^[A-Za-z0-9][A-Za-z0-9_.-]{0,95}$'-or$CaseId-notin@('outer-clean','outer-upgrade')-or$VmId-notmatch'^[a-fA-F0-9-]{36}$'){throw 'owned fixture namespace differs'}
 $caseRoot=Split-Path -Parent $expected
 Assert-FixtureAncestorPaths $caseRoot
 $marker=Join-Path $caseRoot 'run-marker.txt';$item=Get-Item -LiteralPath $marker -Force
 if($item.PSIsContainer-or($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-ne0){throw 'fixture marker redirected'}
 $lines=@(Get-Content -LiteralPath $marker)
 if($lines-notcontains"amnezia-release-lab:${RunId}:windows-x64"-or$lines-notcontains"vm_id=$VmId"-or$lines-notcontains"case_id=$CaseId"){throw 'fixture marker does not authorize ACL scope'}
 # Only the existing required lab namespace components in this proven owned
 # disposable guest. Never mutate ProgramData,drive root or installed app ACLs.
 foreach($directory in @($base,"$base\runs","$base\runs\$RunId","$base\runs\$RunId\windows-x64",$caseRoot)){
  Set-OwnedFixtureAcl $directory $UserSid 'Directory'
 }
 Set-OwnedFixtureAcl $marker $UserSid 'File'
}

function StartLimitedGui([string]$root,$plan,[string]$arguments){
 $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;$session=[Diagnostics.Process]::GetCurrentProcess().SessionId
 $inputDir=Join-Path $root 'limited-input';$output=Join-Path $root 'limited-output'
 if((Test-Path -LiteralPath $inputDir)-or(Test-Path -LiteralPath $output)){throw 'fresh limited task paths required'}
 New-Item -ItemType Directory -Path $inputDir,$output|Out-Null
 Set-OwnedFixtureAcl $inputDir $sid 'Directory';Set-OwnedFixtureAcl $output $sid 'Output'
 Set-OwnedFixtureAcl $root $sid 'Directory'
 foreach($name in @('limited_interactive_runner.ps1','BoundedOperatorCapture.cs')){
  $source=Join-Path $root $name;$item=Get-Item -LiteralPath $source -Force
  if($item.PSIsContainer-or($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-ne0-or$item.Length-gt131072-or(Hash $source)-cne$plan.files.$name){throw 'limited task source differs'}
  $target=Join-Path $inputDir $name;$bytes=[IO.File]::ReadAllBytes($source)
  $stream=[IO.File]::Open($target,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
  try{$stream.Write($bytes,0,$bytes.Length)}finally{$stream.Dispose()}
  if((Hash $target)-cne$plan.files.$name){throw 'limited copied source differs'}
  Set-OwnedFixtureAcl $target $sid 'File'
 }
 $script=Join-Path $inputDir 'limited_interactive_runner.ps1'
 $limitedPlan=[ordered]@{run_id=$plan.run_id;case_id=$plan.case_id;vm_id=$plan.vm_id;nonce=$plan.nonce;task_token=$plan.task_token;user_sid=$sid;session_id=$session;app_sha256=$plan.installed_exe_sha256;gui_args=$arguments;operator_capture_sha256=$plan.files.'BoundedOperatorCapture.cs'}
 $planPath=Join-Path $inputDir 'plan.json';Write-NewJson $planPath $limitedPlan;Set-OwnedFixtureAcl $planPath $sid 'File';$sha=Hash $planPath
 $name="AmneziaLab-Limited-$($plan.run_id)-$($plan.case_id)";if(Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue){throw 'limited task exists'}
 $action=New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$script`" -InputRoot `"$inputDir`" -OutputRoot `"$output`" -PlanSha256 $sha"
 $principal=New-ScheduledTaskPrincipal -UserId 'labadmin' -LogonType Interactive -RunLevel Limited
 Register-ScheduledTask -TaskName $name -Action $action -Principal $principal -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Seconds 240))|Out-Null
 $script:limited=[ordered]@{task=$name;input=$inputDir;output=$output;sequence=1;plan=$plan;sid=$sid;session=$session;gui=$null}
 Start-ScheduledTask -TaskName $name
 $deadline=[DateTime]::UtcNow.AddSeconds(15);$started=Join-Path $output 'started.json'
 while(-not(Test-Path -LiteralPath $started)){if((Test-Path -LiteralPath (Join-Path $output 'failure.json'))-or[DateTime]::UtcNow-gt$deadline){throw 'limited GUI start/token proof failed'};Start-Sleep -Milliseconds 100}
 $proof=ReadLimitedJson $started
 if($proof.user_sid-cne$sid-or$proof.session_id-ne$session-or$proof.administrator_enabled-ne$false-or($proof.file_granted-band0x000D0116)-ne0-or($proof.directory_granted-band0x000D0156)-ne0){throw 'limited identity/write proof differs'}
 $access=$proof.fixture_access
 if($access.schema-ne1-or$access.actual_limited_accesscheck-ne$true-or$access.root-ine$root-or$access.input-ine$inputDir-or$access.output-ine$output-or@($access.protected).Count-lt14-or@($access.ancestors).Count-lt1){throw 'limited fixture access proof absent/unbound'}
 foreach($entry in @($access.protected)){$mask=if($entry.directory){0x000D0156}else{0x000D0116};if(($entry.granted-band$mask)-ne0){throw 'limited fixture access remains writable'}}
 foreach($entry in @($access.ancestors)){if(($entry.granted-band0x000D0040)-ne0){throw 'limited fixture ancestor replacement remains'}}
 $requiredProtected=@($root,$inputDir,(Join-Path $inputDir 'limited_interactive_runner.ps1'),(Join-Path $inputDir 'BoundedOperatorCapture.cs'),(Join-Path $inputDir 'plan.json'),(Join-Path (Split-Path -Parent $root) 'run-marker.txt'))+@('fixture.exe','product_observer.ps1','limited_interactive_controller.ps1','limited_interactive_runner.ps1','BoundedOperatorCapture.cs','profile-template.json','expected-routes.json','routes.json','config.json','observer-plan.json','ready.json','lease.json'|ForEach-Object{Join-Path $root $_})
 foreach($requiredPath in $requiredProtected){$matched=@($access.protected|Where-Object{$_.path-ieq$requiredPath});if($matched.Count-ne1){throw 'limited fixture required protected path absent/duplicated'}}
 $gui=Get-Process -Id ([int]$proof.gui.pid);if(-not(Same $proof.gui (Identity $gui))-or(Hash $gui.Path)-cne$plan.installed_exe_sha256-or$gui.SessionId-ne$session){throw 'limited GUI actual process differs'}
 $script:limited.gui=$proof.gui
 return $gui
}
function ReadLimitedJson([string]$path){
 $item=Get-Item -LiteralPath $path -Force;if($item.Length-gt131072-or($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-ne0){throw 'limited response bounds'}
 $v=Get-Content -LiteralPath $path -Raw|ConvertFrom-Json
 if($v.nonce-cne$script:limited.plan.nonce){throw 'limited response nonce differs'};return $v
}
function WriteLimitedRequest([string]$path,$value){
 $temporary=$path+'.tmp';Write-NewJson $temporary $value;[IO.File]::Move($temporary,$path)
}
function RequestLimited([string]$action){
 $l=$script:limited;$seq=$l.sequence;$l.sequence++
 WriteLimitedRequest (Join-Path $l.input ("request-{0:d3}.json"-f$seq)) ([ordered]@{sequence=$seq;nonce=$l.plan.nonce;task_token=$l.plan.task_token;action=$action})
 if($action-eq'close'){return}
 $path=Join-Path $l.output ("response-{0:d3}.json"-f$seq);$deadline=[DateTime]::UtcNow.AddSeconds(20)
 while(-not(Test-Path -LiteralPath $path)){if((Test-Path -LiteralPath (Join-Path $l.output 'failure.json'))-or[DateTime]::UtcNow-gt$deadline){throw 'limited status timed out'};Start-Sleep -Milliseconds 100}
 $v=ReadLimitedJson $path
 if($v.sequence-ne$seq-or$v.task_token-cne$l.plan.task_token-or$v.administrator_enabled-ne$false-or-not(Same $v.gui $l.gui)-or-not$v.capture_ok-or$v.native_exit-isnot[int]-or$v.native_exit-ne0){throw 'limited status binding/native exit differs'}
 $status=$v.stdout|ConvertFrom-Json;if($status.PSObject.Properties.Name-contains'result'){$status=$status.result}
 if($status.connected-ne$true-or$status.stateFresh-ne$true){throw 'limited product not freshly connected'};return $status
}
function CloseLimited {
 if($null-eq$script:limited){return}
 $initialTask=Get-ScheduledTask -TaskName $script:limited.task
 $brokerFailed=Test-Path -LiteralPath (Join-Path $script:limited.output 'failure.json')
 if($initialTask.State-eq'Running'-and-not$brokerFailed){RequestLimited 'close'}
 $deadline=[DateTime]::UtcNow.AddSeconds(45)
 do{$task=Get-ScheduledTask -TaskName $script:limited.task;if($task.State-ne'Running'){break};Start-Sleep -Milliseconds 100}while([DateTime]::UtcNow-lt$deadline)
 if($task.State-eq'Running'){throw 'limited task cleanup pending'}
 $info=Get-ScheduledTaskInfo -TaskName $script:limited.task;if($info.LastTaskResult-ne0){throw 'limited task failed'}
 if($brokerFailed){throw 'limited broker failed before close request'}
 $proof=ReadLimitedJson (Join-Path $script:limited.output 'cleanup.json');if($proof.task_token-cne$script:limited.plan.task_token-or$proof.disconnected_stateFresh-ne$true-or$proof.owned_gui_exited-ne$true-or$proof.graceful_application_quit-ne$false-or-not(Same $proof.gui $script:limited.gui)){throw 'limited cleanup proof differs'}
 Unregister-ScheduledTask -TaskName $script:limited.task -Confirm:$false
}
