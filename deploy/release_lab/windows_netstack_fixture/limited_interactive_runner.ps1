[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$InputRoot,[Parameter(Mandatory=$true)][string]$OutputRoot,[Parameter(Mandatory=$true)][string]$PlanSha256)
$ErrorActionPreference='Stop';Set-StrictMode -Version 2
$script:fixtureAccessFailure=$null
function Hash([string]$p){(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant()}
function WriteNew([string]$p,$v){$bytes=[Text.Encoding]::UTF8.GetBytes(($v|ConvertTo-Json -Depth 12 -Compress));$tmp=$p+'.tmp';$f=[IO.File]::Open($tmp,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$f.Write($bytes,0,$bytes.Length)}finally{$f.Dispose()};[IO.File]::Move($tmp,$p)}
function Identity($p){[ordered]@{pid=[int]$p.Id;start_ticks=$p.StartTime.ToUniversalTime().Ticks;exe=[string]$p.Path}}
function Same($a,$b){($a|ConvertTo-Json -Compress)-ceq($b|ConvertTo-Json -Compress)}
function InvokeLimitedOperator([ValidateSet('status','disconnect')][string]$kind,[int]$timeoutMs=18000){
 if($timeoutMs-lt1-or$timeoutMs-gt18000){throw 'operator timeout bound'}
 if((Hash $app)-cne$plan.app_sha256){throw 'limited operator image changed'}
 $arguments=if($kind-eq'status'){'--status --json'}else{'--disconnect --json'}
 $r=[BoundedOwnedOperator]::Run($app,$arguments,$timeoutMs,65536)
 if(-not$r.OwnedChildExited){throw 'owned operator child cleanup unconfirmed'}
 $valid=$r.Started-and$r.ExitCodeAvailable-and$r.DrainCompleted-and-not$r.TimedOut-and-not$r.OutputLimitExceeded-and[string]::IsNullOrEmpty($r.Failure)
 return [ordered]@{native_exit=$(if($r.ExitCodeAvailable){[int]$r.ExitCode}else{$null});native_exit_available=$r.ExitCodeAvailable;capture_ok=$valid;stdout=$r.Stdout;stderr=$r.Stderr;timed_out=$r.TimedOut;output_limit_exceeded=$r.OutputLimitExceeded;drain_completed=$r.DrainCompleted;capture_failure=$r.Failure;owned_operator_child_exited=$r.OwnedChildExited;operator_pid=$r.ProcessId;elapsed_ms=$r.ElapsedMilliseconds}
}

$gui=$null;$identity=$null;$plan=$null;$failed=$false;$disconnectCapture=$null;$statusCapture=$null;$statusSamples=0
try{
 $path=Join-Path $InputRoot 'plan.json';if((Hash $path)-cne$PlanSha256){throw 'limited plan hash differs'};$plan=Get-Content -LiteralPath $path -Raw|ConvertFrom-Json
 $who=[Security.Principal.WindowsIdentity]::GetCurrent();$principal=New-Object Security.Principal.WindowsPrincipal($who)
 if($who.User.Value-cne$plan.user_sid-or$who.Name-notmatch '\\labadmin$'-or[Diagnostics.Process]::GetCurrentProcess().SessionId-ne$plan.session_id-or$principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)){throw 'limited interactive token required'}
 $app='C:\Program Files\AmneziaVPN\AmneziaVPN.exe';if((Hash $app)-cne$plan.app_sha256){throw 'limited product bytes differ'}
 # AccessCheck includes owner implicit WRITE_DAC; do not infer safety solely
 # from a medium integrity label or Administrators being deny-only.
 Add-Type -TypeDefinition @"
using System;using System.Runtime.InteropServices;using System.Security.Principal;
public static class OwnedPathAccess {
 [StructLayout(LayoutKind.Sequential)]struct Mapping{public uint Read,Write,Execute,All;}
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode)]static extern uint GetNamedSecurityInfo(string p,int t,uint i,out IntPtr o,out IntPtr g,out IntPtr d,out IntPtr s,out IntPtr sd);
 [DllImport("advapi32.dll",SetLastError=true)]static extern bool DuplicateToken(IntPtr t,int l,out IntPtr v);
 [DllImport("advapi32.dll",SetLastError=true)]static extern bool AccessCheck(IntPtr sd,IntPtr token,uint desired,ref Mapping m,IntPtr p,ref uint n,out uint granted,out bool access);
 [DllImport("kernel32.dll")]static extern IntPtr LocalFree(IntPtr p);
 [DllImport("kernel32.dll")]static extern bool CloseHandle(IntPtr p);
 public static uint Granted(string path){IntPtr o,g,d,s,sd,t=IntPtr.Zero;uint n=4096,granted;bool access;IntPtr privileges=Marshal.AllocHGlobal((int)n);
  if(GetNamedSecurityInfo(path,1,7,out o,out g,out d,out s,out sd)!=0){Marshal.FreeHGlobal(privileges);throw new Exception("path ACL unavailable");}
  try{if(!DuplicateToken(WindowsIdentity.GetCurrent().Token,2,out t))throw new Exception("duplicate limited token");Mapping m=new Mapping{Read=0x120089,Write=0x120116,Execute=0x1200a0,All=0x1f01ff};if(!AccessCheck(sd,t,0x02000000,ref m,privileges,ref n,out granted,out access)||!access)throw new Exception("limited AccessCheck failed");return granted;}
  finally{if(t!=IntPtr.Zero)CloseHandle(t);LocalFree(sd);Marshal.FreeHGlobal(privileges);}}
}
"@
 $capturePath=Join-Path $InputRoot 'BoundedOperatorCapture.cs'
 $captureItem=Get-Item -LiteralPath $capturePath -Force
 if($captureItem.PSIsContainer-or($captureItem.Attributes-band[IO.FileAttributes]::ReparsePoint)-ne0-or$captureItem.Length-gt65536-or$plan.operator_capture_sha256-cnotmatch'^[0-9a-f]{64}$'-or(Hash $capturePath)-cne$plan.operator_capture_sha256){throw 'limited operator capture source differs'}
 Add-Type -TypeDefinition ([IO.File]::ReadAllText($capturePath))
 $fileRights=[OwnedPathAccess]::Granted($app);$dirRights=[OwnedPathAccess]::Granted((Split-Path -Parent $app))
 if(($fileRights-band0x000D0116)-ne0-or($dirRights-band0x000D0156)-ne0){throw 'limited token can replace product'}
 if(@(Get-Process -Name AmneziaVPN -ErrorAction SilentlyContinue).Count-ne0){throw 'fresh limited GUI required'}
 $fixtureRoot=Split-Path -Parent $InputRoot
 $canonical="C:\ProgramData\AmneziaLab\runs\$($plan.run_id)\windows-x64\$($plan.case_id)\netstack-fixture"
 if([IO.Path]::GetFullPath($fixtureRoot)-ine$canonical-or[IO.Path]::GetFullPath($InputRoot)-ine(Join-Path $canonical 'limited-input')-or[IO.Path]::GetFullPath($OutputRoot)-ine(Join-Path $canonical 'limited-output')){throw 'limited proof namespace differs'}
 $marker=Join-Path (Split-Path -Parent $fixtureRoot) 'run-marker.txt';$lines=@(Get-Content -LiteralPath $marker)
 if($lines-notcontains"amnezia-release-lab:$($plan.run_id):windows-x64"-or$lines-notcontains"case_id=$($plan.case_id)"-or$lines-notcontains"vm_id=$($plan.vm_id)"){throw 'limited actual guest marker differs'}
 function Measure-ProtectedFixturePath([string]$path,[bool]$directory){
  $item=Get-Item -LiteralPath $path -Force
  if([bool]$item.PSIsContainer-ne$directory-or($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-ne0){throw 'limited protected path redirected/type differs'}
  $granted=[OwnedPathAccess]::Granted($path);$mask=if($directory){0x000D0156}else{0x000D0116}
  if(($granted-band$mask)-ne0){$script:fixtureAccessFailure=[ordered]@{path=$item.FullName;granted=$granted;rejected_mask=$mask;directory=$directory;kind='protected-input-or-evidence'};throw 'limited token can write/replace fixture input or evidence'}
  $acl=Get-Acl -LiteralPath $path
  return [ordered]@{path=$item.FullName;directory=$directory;granted=$granted;owner_sid=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value;dacl_protected=$acl.AreAccessRulesProtected}
 }
 $fixtureProtected=@(Measure-ProtectedFixturePath $fixtureRoot $true;Measure-ProtectedFixturePath $InputRoot $true)
 foreach($file in @((Join-Path $InputRoot 'limited_interactive_runner.ps1'),(Join-Path $InputRoot 'BoundedOperatorCapture.cs'),(Join-Path $InputRoot 'plan.json'),$marker)+@('fixture.exe','product_observer.ps1','limited_interactive_controller.ps1','limited_interactive_runner.ps1','BoundedOperatorCapture.cs','profile-template.json','expected-routes.json','routes.json','config.json','observer-plan.json','ready.json','lease.json'|ForEach-Object{Join-Path $fixtureRoot $_})){$fixtureProtected+=@(Measure-ProtectedFixturePath $file $false)}
 $telemetryPath=Join-Path $fixtureRoot 'peer-telemetry.jsonl';if(Test-Path -LiteralPath $telemetryPath){$fixtureProtected+=@(Measure-ProtectedFixturePath $telemetryPath $false)}
 $fixtureAncestors=@();$cursor=[IO.Directory]::GetParent($fixtureRoot)
 while($null-ne$cursor){
  $item=Get-Item -LiteralPath $cursor.FullName -Force;if(-not$item.PSIsContainer-or($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-ne0){throw 'limited ancestor redirected'}
  $granted=[OwnedPathAccess]::Granted($item.FullName)
  # Existing outside ancestors may allow new siblings. Only replacement,
  # DELETE_CHILD and ownership/DACL authority threaten the existing chain.
  if(($granted-band0x000D0040)-ne0){$script:fixtureAccessFailure=[ordered]@{path=$item.FullName;granted=$granted;rejected_mask=0x000D0040;directory=$true;kind='ancestor-replacement'};throw 'limited token can replace an ancestor or its existing child'}
  $fixtureAncestors+=@([ordered]@{path=$item.FullName;granted=$granted;replacement_mask=0x000D0040})
  $cursor=$cursor.Parent
 }
 $outputGranted=[OwnedPathAccess]::Granted($OutputRoot)
 if(($outputGranted-band0x000C0000)-ne0-or($outputGranted-band2)-eq0){$script:fixtureAccessFailure=[ordered]@{path=$OutputRoot;granted=$outputGranted;rejected_mask=0x000C0000;directory=$true;kind='output-access'};throw 'limited output lacks intended bounded write or can rewrite DACL/owner'}
 $fixtureAccess=[ordered]@{schema=1;root=$fixtureRoot;input=$InputRoot;output=$OutputRoot;protected=@($fixtureProtected);ancestors=@($fixtureAncestors);output_granted=$outputGranted;actual_limited_accesscheck=$true}

 if(@(Get-Process -Name AmneziaVPN -ErrorAction SilentlyContinue).Count-ne0){throw 'fresh limited GUI required'}
 $gui=Start-Process -FilePath $app -ArgumentList ([string]$plan.gui_args) -PassThru -WindowStyle Normal
 $identityDeadline=[DateTime]::UtcNow.AddSeconds(2)
 do{$gui.Refresh();if($gui.HasExited){throw 'limited GUI exited before identity proof'};if($gui.Path-ieq$app-and$gui.SessionId-eq$plan.session_id){break};Start-Sleep -Milliseconds 20}while([DateTime]::UtcNow-lt$identityDeadline)
 if($gui.Path-ine$app-or$gui.SessionId-ne$plan.session_id){throw 'limited GUI path/session unavailable'};$identity=Identity $gui
 WriteNew (Join-Path $OutputRoot 'started.json') ([ordered]@{run_id=$plan.run_id;case_id=$plan.case_id;vm_id=$plan.vm_id;nonce=$plan.nonce;task_token=$plan.task_token;user_sid=$who.User.Value;session_id=[Diagnostics.Process]::GetCurrentProcess().SessionId;administrator_enabled=$false;file_granted=$fileRights;directory_granted=$dirRights;fixture_access=$fixtureAccess;gui=$identity})
 $deadline=[DateTime]::UtcNow.AddSeconds(190);$sequence=1
 while([DateTime]::UtcNow-lt$deadline){
  if($gui.HasExited){throw 'owned limited GUI exited'}
  $request=Join-Path $InputRoot ("request-{0:d3}.json"-f$sequence)
  if(-not(Test-Path -LiteralPath $request)){Start-Sleep -Milliseconds 100;continue}
  $item=Get-Item -LiteralPath $request;if($item.Length-gt4096-or($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-ne0){throw 'limited request invalid'}
  $q=Get-Content -LiteralPath $request -Raw|ConvertFrom-Json
  if($q.sequence-ne$sequence-or$q.nonce-cne$plan.nonce-or$q.task_token-cne$plan.task_token-or$q.action-notin@('status','close')){throw 'limited request binding differs'}
  if($q.action-eq'close'){break}
  # Every operator invocation inherits this verified limited token too.
  $capture=InvokeLimitedOperator 'status'
  $capture.sequence=$sequence;$capture.nonce=$plan.nonce;$capture.task_token=$plan.task_token;$capture.gui=$identity;$capture.administrator_enabled=$false
  WriteNew (Join-Path $OutputRoot ("response-{0:d3}.json"-f$sequence)) $capture
  $sequence++
 }
}catch{$failed=$true;if($null-ne$plan){try{WriteNew (Join-Path $OutputRoot 'failure.json') ([ordered]@{run_id=$plan.run_id;nonce=$plan.nonce;error_type=$_.Exception.GetType().FullName;error=$_.Exception.Message;fixture_access_failure=$script:fixtureAccessFailure;disconnect_capture=$disconnectCapture;last_status_capture=$statusCapture;status_samples=$statusSamples})}catch{}}}
finally{
 if($null-ne$gui){
  try{
   $gui.Refresh()
   if($gui.HasExited){throw 'owned GUI exited before disconnect proof'}
   if(-not(Same $identity (Identity $gui))-or$gui.SessionId-ne$plan.session_id-or(Hash $app)-cne$plan.app_sha256){throw 'owned GUI cleanup identity differs'}
   # Closing the QML window only hides it in the tray. Disconnect through the
   # same LIMITED token, verify fresh disconnected state, then terminate only
   # this exact disposable-guest GUI. This is not a graceful application quit.
   $disconnectCapture=InvokeLimitedOperator 'disconnect';$disconnectExit=$disconnectCapture.native_exit
   if(-not$disconnectCapture.capture_ok-or$disconnectExit-isnot[int]-or$disconnectExit-ne0){throw 'limited disconnect native result failed'}
   $disconnect=$disconnectCapture.stdout|ConvertFrom-Json;if($disconnect.PSObject.Properties.Name-contains'result'){$disconnect=$disconnect.result}
   if($disconnect.ok-ne$true-or$disconnect.completed-ne$true-or$disconnect.state-cne'disconnected'){throw 'limited disconnect not completed'}
   $fresh=$null;$statusCapture=$null;$statusSamples=0;$freshBudget=[Diagnostics.Stopwatch]::StartNew()
   do{
    $remaining=19000-[int]$freshBudget.ElapsedMilliseconds;if($remaining-le1000){break}
    $statusCapture=InvokeLimitedOperator 'status' ([Math]::Min(18000,$remaining-1000));$statusSamples++
    if($statusCapture.capture_ok-and$statusCapture.native_exit-is[int]-and$statusCapture.native_exit-eq0){
     try{$v=$statusCapture.stdout|ConvertFrom-Json;if($v.PSObject.Properties.Name-contains'result'){$v=$v.result};if($v.stateFresh-eq$true-and$v.connected-eq$false-and$v.state-ceq'disconnected'){$fresh=$v;break}}catch{$statusCapture.parse_error=$_.Exception.GetType().FullName}
    }
    Start-Sleep -Milliseconds 100
   }while($freshBudget.ElapsedMilliseconds-lt19000)
   if($null-eq$fresh){throw 'fresh disconnected state unconfirmed'}
   $gui.Refresh();if($gui.HasExited-or-not(Same $identity (Identity $gui))-or$gui.SessionId-ne$plan.session_id-or(Hash $app)-cne$plan.app_sha256){throw 'owned GUI changed before controlled termination'}
   WriteNew (Join-Path $OutputRoot 'cleanup-intent.json') ([ordered]@{nonce=$plan.nonce;gui=$identity;session_id=$plan.session_id;app_sha256=$plan.app_sha256;disconnect_native_exit=$disconnectExit;disconnected_stateFresh=$true;disconnect_capture=$disconnectCapture;last_status_capture=$statusCapture;status_samples=$statusSamples;graceful_application_quit=$false;action='controlled_owned_gui_termination_after_confirmed_disconnect'})
   $gui.Kill();if(-not$gui.WaitForExit(5000)){throw 'exact owned GUI termination incomplete'}
   WriteNew (Join-Path $OutputRoot 'cleanup.json') ([ordered]@{nonce=$plan.nonce;task_token=$plan.task_token;gui=$identity;disconnect_native_exit=$disconnectExit;disconnected_stateFresh=$true;disconnect_capture=$disconnectCapture;last_status_capture=$statusCapture;status_samples=$statusSamples;owned_gui_exited=$true;graceful_application_quit=$false})
  }catch{
   $failed=$true;try{WriteNew (Join-Path $OutputRoot 'cleanup-failure.json') ([ordered]@{nonce=$plan.nonce;error_type=$_.Exception.GetType().FullName;error=$_.Exception.Message;fixture_access_failure=$script:fixtureAccessFailure;disconnect_capture=$disconnectCapture;last_status_capture=$statusCapture;status_samples=$statusSamples})}catch{}
  }
 }
}
if($failed){exit 1}
