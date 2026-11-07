[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$RunId,
    [Parameter(Mandatory=$true)][string]$VmId,
    [Parameter(Mandatory=$true)][string]$AttemptNonce,
    [Parameter(Mandatory=$true)][string]$ManifestSha256,
    [Parameter(Mandatory=$true)][string]$HelperSha256,
    [Parameter(Mandatory=$true)][string]$CaptureSha256
)
$ErrorActionPreference='Stop';Set-StrictMode -Version 2
$script:nativeFailureRoot=$null
trap {
 $original=$_
 if($null-ne$script:nativeFailureRoot){
  try{
   $raw=[Text.Encoding]::UTF8.GetBytes(($original|Out-String));$sha=[Security.Cryptography.SHA256]::Create()
   try{$hash=[BitConverter]::ToString($sha.ComputeHash($raw)).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
   $head=if($raw.Length-gt32768){[byte[]]$raw[0..32767]}else{$raw}
   Native-WriteNew (Join-Path $script:nativeFailureRoot 'failure.json') ([ordered]@{schema=1;error_type=$original.Exception.GetType().FullName;original_size=$raw.Length;original_sha256=$hash;truncated=($raw.Length-gt32768);captured_utf8_b64=[Convert]::ToBase64String($head);release_passed=$false})
  }catch{}
 }
 exit 1
}

function Native-Hash([string]$Path){(Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()}
function Native-AssertRegular([string]$Path,[bool]$Directory=$false){
 $item=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
 if([bool]$item.PSIsContainer-ne$Directory-or($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-ne0){throw 'native-test path type/reparse differs'}
 return $item
}
function Native-AssertManifest($Plan){
 $required=@('schema','candidate_sha256','candidate_version','compile_source_commit','source_root','review_capsule','files')
 if(@($Plan.PSObject.Properties.Name).Count-ne$required.Count-or@($required|Where-Object{$Plan.PSObject.Properties.Name-notcontains$_}).Count-ne0-or$Plan.schema-cne'amnezia.native-windows-tests.v1'){throw 'native-test manifest shape'}
 if($Plan.candidate_sha256-cnotmatch'^[0-9a-f]{64}$'-or$Plan.candidate_version-cnotmatch'^\d+\.\d+\.\d+\.\d+$'-or$Plan.compile_source_commit-cnotmatch'^[0-9a-f]{40}$'){throw 'native-test manifest identity'}
 $expected=@('operator_command_tests.exe','privileged_ipc_security_tests.exe','selfhosted_update_policy_tests.exe','windows_privileged_pipe_reuse_tests.exe')
 $seen=@{};$exes=@();$total=0L;$rows=@($Plan.files)
 if($rows.Count-lt4-or$rows.Count-gt64){throw 'native-test file count'}
 foreach($row in $rows){
  if(@($row.PSObject.Properties.Name).Count-ne4-or@(@('name','source','sha256','size')|Where-Object{$row.PSObject.Properties.Name-notcontains$_}).Count-ne0){throw 'native-test file shape'}
  $name=[string]$row.name
  if($name-cnotmatch'^[A-Za-z0-9][A-Za-z0-9_.-]{0,119}$'-or$seen.ContainsKey($name)-or$row.sha256-cnotmatch'^[0-9a-f]{64}$'-or$row.size-isnot[long]-and$row.size-isnot[int]){throw 'native-test file identity'}
  if([int64]$row.size-le0-or[int64]$row.size-gt134217728-or[IO.Path]::GetFileName([string]$row.source)-cne$name){throw 'native-test source/size'}
  if($expected-ccontains$name){$exes+=,$name}elseif(-not$name.EndsWith('.dll',[StringComparison]::Ordinal)){throw 'native-test executable not allowlisted'}
  $seen[$name]=$true;$total+=[int64]$row.size
 }
 if($exes.Count-ne4-or@($expected|Where-Object{$exes-cnotcontains$_}).Count-ne0-or$total-gt536870912){throw 'native-test exact closure'}
 return $expected
}
function Native-AssertMarker([string]$Path,[string]$Id,[string]$GuestVm){
 [void](Native-AssertRegular $Path)
 $lines=@([IO.File]::ReadAllLines($Path))
 if($lines-notcontains"amnezia-release-lab:${Id}:windows-x64"-or$lines-notcontains'backend=hyperv'-or$lines-notcontains'case_id=control'-or$lines-notcontains"vm_id=$GuestVm"){throw 'native-test guest marker differs'}
}
function Native-AssertToken($Token){
 if($Token.local-ne$true-or$Token.interactive-ne$true-or$Token.network-ne$false-or$Token.system-ne$false-or$Token.administrator-ne$false-or$Token.same_explorer-ne$true-or$Token.session_id-le0){throw 'native-test limited LOCAL INTERACTIVE token required'}
}
function Native-CaptureResult([string]$Name,$Capture){
 $text=[string]$Capture.Stdout+"`n"+[string]$Capture.Stderr
 $summary=[regex]::Matches($text,'(?m)^PASS: ([1-9][0-9]*) assertions, 0 failures\r?$')
 $skips=[regex]::Matches($text,'\b(?:QSKIP|SKIP|Skipped)\b').Count
 $exitCode=$null;if($Capture.ExitCodeAvailable-eq$true-and$Capture.ExitCode-is[int]){$exitCode=[int]$Capture.ExitCode}
 $passed=$Capture.Started-eq$true-and$null-ne$exitCode-and$exitCode-eq0-and$Capture.DrainCompleted-eq$true-and$Capture.OwnedChildExited-eq$true-and$Capture.TimedOut-eq$false-and$Capture.OutputLimitExceeded-eq$false-and[string]$Capture.Failure-ceq''-and$summary.Count-eq1-and$skips-eq0-and-not[regex]::IsMatch($text,'(?m)^FAIL\b')
 return [ordered]@{name=$Name;native_exit=$exitCode;started=[bool]$Capture.Started;drain_completed=[bool]$Capture.DrainCompleted;owned_child_exited=[bool]$Capture.OwnedChildExited;timed_out=[bool]$Capture.TimedOut;output_limit_exceeded=[bool]$Capture.OutputLimitExceeded;capture_failure=[string]$Capture.Failure;skip_count=$skips;assertions=$(if($summary.Count-eq1){[int]$summary[0].Groups[1].Value}else{0});failures=$(if($passed){0}else{1});stdout_b64=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([string]$Capture.Stdout));stderr_b64=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([string]$Capture.Stderr));elapsed_ms=[int64]$Capture.ElapsedMilliseconds;files_unchanged=$false;passed=[bool]$passed}
}
function Native-WriteNew([string]$Path,$Value){
 $raw=[Text.Encoding]::UTF8.GetBytes(($Value|ConvertTo-Json -Depth 18 -Compress));$temporary=$Path+'.tmp'
 $file=[IO.File]::Open($temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
 try{$file.Write($raw,0,$raw.Length);$file.Flush($true)}finally{$file.Dispose()}
 [IO.File]::Move($temporary,$Path)
}

# Fixed path and real guest marker are mandatory before reading a manifest,
# loading capture code or starting any executable. No host-compatible mode.
if($RunId-cnotmatch'^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$'-or$VmId-cnotmatch'^[a-fA-F0-9-]{36}$'-or$AttemptNonce-cnotmatch'^[0-9a-f]{48}$'){throw 'native-test run/VM/nonce identity'}
foreach($pin in @($ManifestSha256,$HelperSha256,$CaptureSha256)){if($pin-cnotmatch'^[0-9a-f]{64}$'){throw 'native-test missing input pin'}}
$root="C:\ProgramData\AmneziaLab\runs\$RunId\windows-x64\control";$inputRoot=Join-Path $root 'native-tests-input';$outputRoot=Join-Path $root 'native-tests-output'
Native-AssertMarker (Join-Path $root 'run-marker.txt') $RunId $VmId
[void](Native-AssertRegular $inputRoot $true);[void](Native-AssertRegular $outputRoot $true)
$script:nativeFailureRoot=$outputRoot
if([IO.Path]::GetFullPath($MyInvocation.MyCommand.Path)-ine(Join-Path $inputRoot 'native_test_guest.ps1')-or(Native-Hash $MyInvocation.MyCommand.Path)-cne$HelperSha256){throw 'native-test helper path/hash differs'}
$manifestPath=Join-Path $inputRoot 'manifest.json';[void](Native-AssertRegular $manifestPath)
if((Get-Item -LiteralPath $manifestPath).Length-gt131072-or(Native-Hash $manifestPath)-cne$ManifestSha256){throw 'native-test manifest hash/bounds'}
$plan=[IO.File]::ReadAllText($manifestPath)|ConvertFrom-Json;$testNames=@(Native-AssertManifest $plan)
$identity=[Security.Principal.WindowsIdentity]::GetCurrent();$principal=New-Object Security.Principal.WindowsPrincipal($identity)
$explorers=@(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'"|Where-Object{$_.SessionId-gt0})
$sameExplorer=$false;$session=[Diagnostics.Process]::GetCurrentProcess().SessionId
if($explorers.Count-eq1-and$explorers[0].SessionId-eq$session){$owner=Invoke-CimMethod -InputObject $explorers[0] -MethodName GetOwnerSid -ErrorAction Stop;$sameExplorer=[string]$owner.Sid-ceq[string]$identity.User.Value}
$token=[ordered]@{local=$principal.IsInRole((New-Object Security.Principal.SecurityIdentifier('S-1-2-0')));interactive=$principal.IsInRole((New-Object Security.Principal.SecurityIdentifier('S-1-5-4')));network=$principal.IsInRole((New-Object Security.Principal.SecurityIdentifier('S-1-5-2')));system=($identity.User.Value-ceq'S-1-5-18');administrator=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);same_explorer=$sameExplorer;session_id=$session;user_sid=$identity.User.Value}
if($identity.Name-notmatch'\\labadmin$'){throw 'native tests require guest labadmin'};Native-AssertToken $token
Add-Type -TypeDefinition @'
using System;using System.Runtime.InteropServices;using System.Security.Principal;
public static class NativeTestPathAccess {
 [StructLayout(LayoutKind.Sequential)]struct Mapping{public uint Read,Write,Execute,All;}
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode)]static extern uint GetNamedSecurityInfo(string p,int t,uint i,out IntPtr o,out IntPtr g,out IntPtr d,out IntPtr s,out IntPtr sd);
 [DllImport("advapi32.dll",SetLastError=true)]static extern bool DuplicateToken(IntPtr t,int l,out IntPtr v);
 [DllImport("advapi32.dll",SetLastError=true)]static extern bool AccessCheck(IntPtr sd,IntPtr token,uint desired,ref Mapping m,IntPtr p,ref uint n,out uint granted,out bool access);
 [DllImport("kernel32.dll")]static extern IntPtr LocalFree(IntPtr p);
 [DllImport("kernel32.dll")]static extern bool CloseHandle(IntPtr p);
 public static uint Granted(string path){IntPtr o,g,d,s,sd,t=IntPtr.Zero;uint n=4096,granted;bool access;IntPtr privileges=Marshal.AllocHGlobal((int)n);
  if(GetNamedSecurityInfo(path,1,7,out o,out g,out d,out s,out sd)!=0){Marshal.FreeHGlobal(privileges);throw new Exception("native test ACL unavailable");}
  try{if(!DuplicateToken(WindowsIdentity.GetCurrent().Token,2,out t))throw new Exception("native test token unavailable");Mapping m=new Mapping{Read=0x120089,Write=0x120116,Execute=0x1200a0,All=0x1f01ff};if(!AccessCheck(sd,t,0x02000000,ref m,privileges,ref n,out granted,out access)||!access)throw new Exception("native test AccessCheck failed");return granted;}
  finally{if(t!=IntPtr.Zero)CloseHandle(t);LocalFree(sd);Marshal.FreeHGlobal(privileges);}}
}
'@
$paths=@($inputRoot,$manifestPath,$MyInvocation.MyCommand.Path,(Join-Path $inputRoot 'BoundedOperatorCapture.cs'),(Join-Path $root 'run-marker.txt'))
foreach($row in @($plan.files)){$paths+=,(Join-Path $inputRoot ([string]$row.name))}
foreach($path in $paths){
 $item=Get-Item -LiteralPath $path -Force;if(($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-ne0){throw 'native-test protected path redirected'}
 $mask=if($item.PSIsContainer){0x000D0156}else{0x000D0116}
 if(([NativeTestPathAccess]::Granted($path)-band$mask)-ne0){throw 'native-test inputs writable by limited token'}
}
$cursor=[IO.Directory]::GetParent($inputRoot)
while($null-ne$cursor){[void](Native-AssertRegular $cursor.FullName $true);if(([NativeTestPathAccess]::Granted($cursor.FullName)-band0x000D0040)-ne0){throw 'native-test ancestor allows replacement'};$cursor=$cursor.Parent}
$capturePath=Join-Path $inputRoot 'BoundedOperatorCapture.cs';[void](Native-AssertRegular $capturePath)
if((Get-Item -LiteralPath $capturePath).Length-gt65536-or(Native-Hash $capturePath)-cne$CaptureSha256){throw 'native-test capture input differs'}
# ScriptName is empty inside script scope; retain exact entry identity explicitly.
$script:nativeHelperPath=$MyInvocation.MyCommand.Path
function Native-CheckAllFiles {
 if((Native-Hash $manifestPath)-cne$ManifestSha256-or(Native-Hash $script:nativeHelperPath)-cne$HelperSha256-or(Native-Hash $capturePath)-cne$CaptureSha256){throw 'native-test helper input changed'}
 foreach($row in @($plan.files)){$path=Join-Path $inputRoot ([string]$row.name);$item=Native-AssertRegular $path;if($item.Length-ne[int64]$row.size-or(Native-Hash $path)-cne[string]$row.sha256){throw 'native-test staged file changed'}}
}
Native-CheckAllFiles
Add-Type -TypeDefinition ([IO.File]::ReadAllText($capturePath))
$receipt=[ordered]@{schema='amnezia.native-windows-tests-receipt.v1';run_id=$RunId;case_id='control';vm_id=$VmId;attempt_nonce=$AttemptNonce;manifest_sha256=$ManifestSha256;marker_verified=$true;token=$token;input_access_protected=$true;files_unchanged=$false;results=@();passed=$false;release_passed=$false}
$failed=$false
try{
 foreach($name in $testNames){
  Native-CheckAllFiles
  $capture=[BoundedOwnedOperator]::Run((Join-Path $inputRoot $name),'',18000,65536)
  $result=Native-CaptureResult $name $capture
  try{Native-CheckAllFiles;$result.files_unchanged=$true}catch{$result.passed=$false;$failed=$true}
  $receipt.results+=,$result
  Native-WriteNew (Join-Path $outputRoot ($name+'.capture.json')) $result
  if(-not$result.passed){$failed=$true}
  if(-not$capture.OwnedChildExited){throw 'native-test owned executable cleanup unconfirmed'}
 }
 Native-CheckAllFiles;$receipt.files_unchanged=$true
 $receipt.passed=(-not$failed-and$receipt.results.Count-eq4)
}finally{
 Native-WriteNew (Join-Path $outputRoot 'receipt.json') $receipt
}
if(-not$receipt.passed){exit 1}
exit 0
