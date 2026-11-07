# Definitions only. The tracked Hyper-V adapter must explicitly dispatch this
# fixed action after Read-Child verifies actual VM/disk/parent/NICnone ownership.
function Invoke-OwnedNetstackFixture {
 param($Child,[string]$RunId,[string]$CaseId,[string]$ManifestPath,[string]$ManifestSha256,[string]$ExpectedArtifactSha256)
 if([string]$Child.vm.State-ne 'Running' -or [string]$Child.marker.run_id-cne $RunId -or [string]$Child.marker.case_id-cne $CaseId -or [string]$Child.marker.vm_id-cne [string]$Child.vm.Id){throw 'fixture requires actual owned running child'}
 if((Get-FileHash -LiteralPath $ManifestPath -Algorithm SHA256).Hash.ToLowerInvariant()-cne $ManifestSha256){throw 'fixture manifest changed'}
 $manifest=Get-Content -LiteralPath $ManifestPath -Raw|ConvertFrom-Json
 if($manifest.schema-ne 1 -or $manifest.candidate_artifact_sha256-cne $ExpectedArtifactSha256){throw 'fixture candidate binding mismatch'}
 $names=[ordered]@{helper='fixture.exe';observer='product_observer.ps1';profile='profile-template.json';expected_routes='expected-routes.json';routes='routes.json';config='config.json';observer_plan='observer-plan.json';limited_runner='limited_interactive_runner.ps1';limited_controller='limited_interactive_controller.ps1';operator_capture='BoundedOperatorCapture.cs'}
 if(@(Compare-Object @($names.Keys|Sort-Object) @($manifest.files.PSObject.Properties.Name|Sort-Object)).Count-ne 0){throw 'fixture exact file set differs'}
 foreach($key in $names.Keys){$r=$manifest.files.$key;Assert-NoReparse $r.path 'fixture source'|Out-Null;if((Get-Item -LiteralPath $r.path).Length-ne $r.size -or (Get-FileHash -LiteralPath $r.path -Algorithm SHA256).Hash.ToLowerInvariant()-cne $r.sha256){throw 'fixture source bytes changed'}}
 $config=Get-Content -LiteralPath $manifest.files.config.path -Raw|ConvertFrom-Json
 $plan=Get-Content -LiteralPath $manifest.files.observer_plan.path -Raw|ConvertFrom-Json
 $vmid=[string]$Child.vm.Id
 if($config.run_id-cne $RunId -or $config.case_id-cne $CaseId -or $config.vm_id-cne $vmid -or $config.nonce-notmatch '^[0-9a-f]{48}$' -or $config.ttl_seconds-lt 120 -or $config.ttl_seconds-gt 300){throw 'fixture config ownership mismatch'}
 if($plan.run_id-cne $RunId -or $plan.case_id-cne $CaseId -or $plan.vm_id-cne $vmid -or $plan.nonce-cne $config.nonce -or $plan.task_token-notmatch '^[0-9a-f]{48}$' -or $plan.installed_exe_sha256-cne $manifest.installed_exe_sha256){throw 'fixture observer ownership mismatch'}
 $guestRoot="C:\ProgramData\AmneziaLab\runs\$RunId\windows-x64\$CaseId\netstack-fixture"
 if($config.marker-cne "C:\ProgramData\AmneziaLab\runs\$RunId\windows-x64\$CaseId\run-marker.txt" -or $config.routes-cne "$guestRoot\routes.json"){throw 'fixture canonical guest paths differ'}
 $session=New-Session $Child
 try {
  Invoke-Command -Session $session -ScriptBlock {
   param($root,$id,$case,$vm)
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

   if(Test-Path -LiteralPath $root){throw 'fixture attempt root already exists'}
   $user=Get-LocalUser -Name labadmin;$sid=$user.SID.Value
   Protect-OwnedFixtureNamespace $root $id $case $vm $sid
   [void](New-Item -ItemType Directory -Path $root)
   Set-OwnedFixtureAcl $root $sid 'Directory'
  } -ArgumentList $guestRoot,$RunId,$CaseId,$vmid|Out-Null
  foreach($key in $names.Keys){Copy-Item -LiteralPath $manifest.files.$key.path -Destination (Join-Path $guestRoot $names[$key]) -ToSession $session -ErrorAction Stop}
  $result=Invoke-Command -Session $session -ScriptBlock {
   param($root,$files,$mapping,$id,$case,$vm,$nonce,$token,$installed,$ttl)
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

   $sid=(Get-LocalUser -Name labadmin).SID.Value
   foreach($key in $mapping.Keys){$path=Join-Path $root $mapping[$key];$info=Get-Item -LiteralPath $path;if(($info.Attributes-band [IO.FileAttributes]::ReparsePoint)-ne 0 -or $info.Length-ne $files.$key.size -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()-cne $files.$key.sha256){throw 'fixture stage readback differs'};Set-OwnedFixtureAcl $path $sid 'File'}
   if((Get-FileHash -LiteralPath 'C:\Program Files\AmneziaVPN\AmneziaVPN.exe' -Algorithm SHA256).Hash.ToLowerInvariant()-cne $installed){throw 'installed GUI bytes differ'}
   $explorer=@(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'"|Where-Object{$_.SessionId-gt 0});if($explorer.Count-ne 1){throw 'exactly one interactive guest session required'}
   $owner=Invoke-CimMethod -InputObject $explorer[0] -MethodName GetOwner;if($owner.User-cne 'labadmin'){throw 'interactive guest account differs'}
   $helper=Start-Process -FilePath (Join-Path $root 'fixture.exe') -ArgumentList @('--config',("`""+(Join-Path $root 'config.json')+"`"")) -PassThru -WindowStyle Hidden
   $readyPath=Join-Path $root 'ready.json';$deadline=[DateTime]::UtcNow.AddSeconds(15)
   while(-not(Test-Path -LiteralPath $readyPath)){if($helper.HasExited -or [DateTime]::UtcNow-gt $deadline){throw 'fixture readiness timeout'};Start-Sleep -Milliseconds 100}
   $ready=Get-Content -LiteralPath $readyPath -Raw|ConvertFrom-Json;$actual=Get-Process -Id $helper.Id -ErrorAction Stop
   $start=($actual.StartTime.ToUniversalTime().Ticks-([DateTime]'1970-01-01T00:00:00Z').ToUniversalTime().Ticks)*100
   if($ready.pid-ne $helper.Id -or $ready.process_start_unix_ns-ne $start -or $ready.exe_sha256-cne $files.helper.sha256 -or $ready.run_id-cne $id -or $ready.case_id-cne $case -or $ready.vm_id-cne $vm -or $ready.nonce-cne $nonce){throw 'fixture PID creation/hash lease differs'}
   $ports=@([int]$ready.source_udp_port,[int]$ready.target_udp_port)
   if($ports[0]-eq $ports[1] -or $ports[0]-lt 1 -or $ports[1]-lt 1){throw 'invalid leased UDP ports'}
   foreach($port in $ports){$listeners=@(Get-NetUDPEndpoint -LocalPort $port);if($listeners.Count-ne 1 -or $listeners[0].LocalAddress-cne '127.0.0.1' -or $listeners[0].OwningProcess-ne $helper.Id){throw 'fixture UDP lease differs'}}
   $taskName="AmneziaLab-RouteFixture-$id-$case";if(Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue){throw 'observer task already exists'}
   $observer=Join-Path $root 'product_observer.ps1';$plan=Join-Path $root 'observer-plan.json'
   $action=New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$observer`" -PlanPath `"$plan`""
   $principal=New-ScheduledTaskPrincipal -UserId 'labadmin' -LogonType Interactive -RunLevel Highest
   Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Seconds 250))|Out-Null
   Start-ScheduledTask -TaskName $taskName
   # Never infer successful cleanup from the helper's own terminal.json.
   $deadline=[DateTime]::UtcNow.AddSeconds($ttl+20)
   while(-not $helper.HasExited){if([DateTime]::UtcNow-gt $deadline){throw 'fixture helper cleanup timeout; preserve owned guest'};Start-Sleep -Milliseconds 250}
   $task=Get-ScheduledTask -TaskName $taskName;$info=Get-ScheduledTaskInfo -TaskName $taskName
   if($task.State-eq 'Running' -or $info.LastTaskResult-ne 0){throw 'observer failed or still running; preserve guest'}
   if(@(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'"|Where-Object{$_.CommandLine-like "*$observer*"}).Count-ne 0){throw 'observer process still present'}
   if(@(Get-NetUDPEndpoint|Where-Object{$_.LocalPort-in $ports}).Count-ne 0){throw 'fixture UDP ports remain'}
   if(@(Get-Process -Id $helper.Id -ErrorAction SilentlyContinue).Count-ne 0){throw 'fixture helper PID remains'}
   $terminal=Get-Content -LiteralPath (Join-Path $root 'terminal.json') -Raw|ConvertFrom-Json
   if($terminal.pid-ne $helper.Id -or $terminal.process_start_unix_ns-ne $start -or $terminal.nonce-cne $nonce -or $terminal.run_id-cne $id -or $terminal.vm_id-cne $vm){throw 'terminal attempt binding differs'}
   $observation=Get-Content -LiteralPath (Join-Path $root 'observer.json') -Raw|ConvertFrom-Json
   if($observation.task_token-cne $token -or $observation.nonce-cne $nonce -or $observation.run_id-cne $id -or $observation.case_id-cne $case -or $observation.vm_id-cne $vm -or $observation.capability_observed-ne $true){throw 'observer transcript binding differs'}
   Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
   if(Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue){throw 'observer task remains'}
   [ordered]@{ready=$ready;terminal=$terminal;observation=$observation;cleanup=[ordered]@{helper_process_absent=$true;helper_udp_ports_absent=$true;observer_task_removed=$true;observer_process_absent=$true}}
  } -ArgumentList $guestRoot,$manifest.files,$names,$RunId,$CaseId,$vmid,$config.nonce,$plan.task_token,$manifest.installed_exe_sha256,$config.ttl_seconds
  return [ordered]@{action='netstack-fixture';run_id=$RunId;case_id=$CaseId;vm_id=$vmid;nonce=$config.nonce;task_token=$plan.task_token;parent_sha256=$Child.parent.sha256;candidate_artifact_sha256=$ExpectedArtifactSha256;manifest_sha256=$ManifestSha256;transport='hyperv-powershell-direct';origin='guest';injected=$false;production_journal=$false;migration_pass=$false;runtime_pass=$false;observation=$result.observation;lease=$result.ready;terminal=$result.terminal;cleanup=$result.cleanup}
 }finally{if($null-ne $session){Remove-PSSession $session}}
}
