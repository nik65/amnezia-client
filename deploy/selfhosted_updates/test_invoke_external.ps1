param([ValidateSet('before','after')][string]$Expect='after')
$ErrorActionPreference='Stop'
$RepoRoot='C:/Users/ivano/PycharmProjects/amnezia-client'
$tokens=$null;$parseErrors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $RepoRoot 'deploy/selfhosted_updates/local_release.ps1'),[ref]$tokens,[ref]$parseErrors)
if($parseErrors.Count){throw 'Canonical release script does not parse'}
$node=$ast.Find({param($n) $n-is[Management.Automation.Language.FunctionDefinitionAst] -and $n.Name-eq'Invoke-External'},$true)
if($null-eq$node){throw 'Actual Invoke-External definition required'}
Invoke-Expression $node.Extent.Text
$cmd=Join-Path $env:WINDIR 'System32/cmd.exe'
$scratch='C:/Users/ivano/AppData/Local/hermes/cache/scratch'
$prefix=Join-Path $scratch ('amnezia-native-stderr-'+[guid]::NewGuid().ToString('N'))
$checks=0
function Check([bool]$Value,[string]$Message){if(-not$Value){throw $Message};$script:checks++}
function Probe([string]$Line){
 $failure=$null
 try { Invoke-External $cmd @('/d','/c',$Line) $scratch *> ($prefix+'.log') } catch { $failure=$_ }
 return $failure
}
$locationBefore=(Get-Location).Path
try {
 $failure=Probe 'echo harmless-stdout & exit /b 0'
 Check ($null-eq$failure) 'stdout-only native exit0 must pass'
 $failure=Probe 'echo harmless-stderr 1>&2 & exit /b 0'
 if($Expect-eq'before'){
  Check ($null-ne$failure -and $failure.FullyQualifiedErrorId-eq'NativeCommandError') 'Expected RED: PS5 stderr converted into NativeCommandError'
 } else {
  Check ($null-eq$failure) 'native exit0 with stderr must pass'
  Check ((Get-Content -LiteralPath ($prefix+'.log') -Raw)-match'harmless-stderr') 'real stderr must remain captured'
 }
 $failure=Probe 'echo. 1>&2 & exit /b 0'
 if($Expect-eq'before'){
  Check ($null-ne$failure) 'Expected RED: even blank stderr aborts the native call'
 } else {
  Check ($null-eq$failure) 'native exit0 with blank stderr must pass'
 }
 $failure=Probe 'exit /b 17'
 Check ($null-ne$failure -and $failure.Exception.Message-match'exit code 17') 'native exit17 without stderr must fail truthfully'
 $failure=Probe 'echo harmless-stderr 1>&2 & exit /b 17'
 if($Expect-eq'after'){
  Check ($null-ne$failure -and $failure.Exception.Message-match'exit code 17') 'native exit17 with stderr must retain actual native code'
 }
 Check ($ErrorActionPreference-eq'Stop') 'caller error policy must be restored'
 Check ((Get-Location).Path-eq$locationBefore) 'working directory must be restored'
 Write-Output ('NATIVE-STDERR '+$Expect+' PASS;checks='+$checks+';no installer/app/guest/network executed')
} finally {
 if(Test-Path -LiteralPath ($prefix+'.log')){Remove-Item -LiteralPath ($prefix+'.log') -Force}
}
