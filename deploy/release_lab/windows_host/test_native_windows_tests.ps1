# Pure PowerShell5.1 boundary tests. Never dot-source the guest entrypoint,
# launch an executable/task/VM, read keys/credentials, or touch HKCU.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop';Set-StrictMode -Version 2
$helper=Join-Path $PSScriptRoot 'native_test_guest.ps1';$adapter=Join-Path $PSScriptRoot 'hyperv_adapter.ps1'
function Import-OnlyFunctions([string]$Path,[string[]]$Names){
 $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($Path,[ref]$tokens,[ref]$errors)
 if($errors.Count-ne0){throw 'PowerShell native-test source parse failed'}
 foreach($name in $Names){
  $found=@($ast.FindAll({param($n)$n-is[Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-ceq$name},$true))
  if($found.Count-ne1){throw 'native-test fixed pure function absent/ambiguous'}
  $parameters=@($found[0].Parameters|ForEach-Object{$_.Extent.Text}) -join ','
  $body=[string]$found[0].Body.Extent.Text
  $functionBody=[ScriptBlock]::Create(('param('+ $parameters +')'+"`n"+$body.Substring(1,$body.Length-2)))
  Set-Item -Path ('function:script:'+ $name) -Value $functionBody
 }
}
Import-OnlyFunctions $helper @('Native-AssertManifest','Native-AssertToken','Native-CaptureResult','Native-AssertRegular','Native-AssertMarker')
Import-OnlyFunctions $adapter @('Assert-NativeTestPe','Get-NativeBindingCloseout')
function Fail([string]$Message){throw $Message}
$script:checks=0
function Expect-Reject([scriptblock]$Body){$thrown=$false;try{&$Body|Out-Null}catch{$thrown=$true};if(-not$thrown){throw 'expected fail-closed rejection'};$script:checks++}
function Check([bool]$Condition){if(-not$Condition){throw 'native-test boundary assertion failed'};$script:checks++}
function Test-Manifest {
 $files=@();foreach($name in @('operator_command_tests.exe','privileged_ipc_security_tests.exe','selfhosted_update_policy_tests.exe','windows_privileged_pipe_reuse_tests.exe')){$files+=,[pscustomobject]@{name=$name;source=('C:\Owned\'+$name);sha256=('a'*64);size=100}}
 return [pscustomobject]@{schema='amnezia.native-windows-tests.v1';candidate_sha256=('b'*64);candidate_version='5.0.3.19';compile_source_commit=('c'*40);source_root='C:\Owned';review_capsule=[pscustomobject]@{path='C:\Owned\review.json';sha256=('d'*64);size=100};files=$files}
}
$manifest=Test-Manifest;Check (@(Native-AssertManifest $manifest).Count-eq4)
$manifest|Add-Member -NotePropertyName arbitraryCommand -NotePropertyValue 'forbidden';Expect-Reject {Native-AssertManifest $manifest}
$manifest=Test-Manifest;$manifest.files+=,[pscustomobject]@{name='AmneziaVPN.exe';source='C:\Owned\AmneziaVPN.exe';sha256=('a'*64);size=100};Expect-Reject {Native-AssertManifest $manifest}
$token=@{local=$true;interactive=$true;network=$false;system=$false;administrator=$false;same_explorer=$true;session_id=1}
Native-AssertToken $token;$script:checks++
foreach($field in @('local','interactive','same_explorer')){$copy=$token.Clone();$copy[$field]=$false;Expect-Reject {Native-AssertToken $copy}}
foreach($field in @('network','system','administrator')){$copy=$token.Clone();$copy[$field]=$true;Expect-Reject {Native-AssertToken $copy}}
function Test-Reparse {
 function Get-Item {param($LiteralPath,[switch]$Force,$ErrorAction);[pscustomobject]@{PSIsContainer=$false;Attributes=[IO.FileAttributes]::ReparsePoint}}
 Expect-Reject {Native-AssertRegular 'inert-no-filesystem-read'}
}
Test-Reparse
$capture=[pscustomobject]@{Started=$true;ExitCodeAvailable=$true;ExitCode=[int]0;DrainCompleted=$true;OwnedChildExited=$true;TimedOut=$false;OutputLimitExceeded=$false;Failure='';Stdout="PASS: 10 assertions, 0 failures`r`n";Stderr='';ElapsedMilliseconds=1}
Check ((Native-CaptureResult 'operator_command_tests.exe' $capture).passed)
foreach($field in @('ExitCodeAvailable','DrainCompleted','OwnedChildExited')){$copy=$capture.PSObject.Copy();$copy.$field=$false;Check (-not(Native-CaptureResult 'operator_command_tests.exe' $copy).passed)}
foreach($field in @('TimedOut','OutputLimitExceeded')){$copy=$capture.PSObject.Copy();$copy.$field=$true;Check (-not(Native-CaptureResult 'operator_command_tests.exe' $copy).passed)}
$copy=$capture.PSObject.Copy();$copy.Failure='refused capture path';Check (-not(Native-CaptureResult 'operator_command_tests.exe' $copy).passed)
$copy=$capture.PSObject.Copy();$copy.Stdout+="QSKIP unavailable`n";Check (-not(Native-CaptureResult 'operator_command_tests.exe' $copy).passed)
function Test-PostCaptureDrift {
 $script:nativeCloseoutChecks=0
 function Assert-Artifact {param($Path,$ExpectedSha,$ExpectedSize);$script:nativeCloseoutChecks++;if($Path-ceq'drift'){throw 'input changed after native capture'}}
 $closeout=Get-NativeBindingCloseout @([pscustomobject]@{path='exact';sha256=('a'*64);size=1},[pscustomobject]@{path='drift';sha256=('b'*64);size=1})
 Check (-not$closeout.unchanged);Check ($closeout.failed_input_count-eq1);Check ($script:nativeCloseoutChecks-eq2)
}
Test-PostCaptureDrift
$temp=Join-Path ([IO.Path]::GetTempPath()) ('amnezia-native-boundary-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temp|Out-Null
try{
 $marker=Join-Path $temp 'marker.txt';[IO.File]::WriteAllLines($marker,@('amnezia-release-lab:run:windows-x64','backend=hyperv','case_id=control','vm_id=11111111-1111-1111-1111-111111111111'))
 Native-AssertMarker $marker 'run' '11111111-1111-1111-1111-111111111111';$script:checks++
 Expect-Reject {Native-AssertMarker $marker 'run' '22222222-2222-2222-2222-222222222222'}
 $pe=Join-Path $temp 'inert-pe-header';$bytes=New-Object byte[] 128;$bytes[0]=0x4d;$bytes[1]=0x5a;$bytes[0x3c]=64;$bytes[64]=0x50;$bytes[65]=0x45;$bytes[68]=0x64;$bytes[69]=0x86;$bytes[86]=2
 [IO.File]::WriteAllBytes($pe,$bytes);Assert-NativeTestPe $pe $false;$script:checks++
 Expect-Reject {Assert-NativeTestPe $pe $true}
 $bytes[87]=0x20;[IO.File]::WriteAllBytes($pe,$bytes);Assert-NativeTestPe $pe $true;$script:checks++
 $bytes[68]=0x4c;$bytes[69]=1;[IO.File]::WriteAllBytes($pe,$bytes);Expect-Reject {Assert-NativeTestPe $pe $true}
}finally{
 if(-not([IO.Path]::GetFileName($temp)).StartsWith('amnezia-native-boundary-',[StringComparison]::Ordinal)){throw 'test cleanup escaped owned temporary directory'}
 Remove-Item -LiteralPath $temp -Recurse -Force
}
[ordered]@{schema=1;checks=$script:checks;passed=$true;runtime_acceptance=$false;vm_actions=$false;product_execution=$false}|ConvertTo-Json -Compress
