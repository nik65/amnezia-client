param([string]$AdapterPath=(Join-Path $PSScriptRoot 'hyperv_adapter.ps1'))
$ErrorActionPreference='Stop'
$t=$null;$e=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($AdapterPath,[ref]$t,[ref]$e);if($e){throw 'adapter parse failed'}
$f=@($ast.FindAll({param($n)$n-is[Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-ceq'Get-GuestConsentProof'},$true));if($f.Count-ne1){throw 'actual function missing'}
$test=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'test_pending_guard_diagnostic.ps1'))
$start=$test.IndexOf('$ExpectedArtifactSha256=');$end=$test.IndexOf('$cases=@(');if($start-lt0-or$end-le$start){throw 'reviewed inert mocks absent'};$mocks=$test.Substring($start,$end-$start)
$request=[ordered]@{state='completed';run_id='owned-run';case_id='outer-interactive';artifact_sha256=('a'*64);launcher_pid=44;launcher_session_id=1;launcher_path='C:\owned\launcher.ps1';launcher_start_time='launcher-created';installer_pid=$null;artifact_path='token=KEEP_PRIVATE';launch_error=@{stage='Start-Process';message='authorized private Start-Process text';native_error_code=1223}}
$json=($request|ConvertTo-Json -Depth 4 -Compress).Replace("'","''")
$results=@()
foreach($preference in @('Stop','Continue')){
 $program='$ErrorActionPreference='''+$preference+''';Set-StrictMode -Version 2' + "`n"+$f[0].Extent.Text+"`n"+$mocks+"`n"+'$script:mode=''completed'';$script:json='''+$json+''';try{Get-GuestConsentProof $Child ''inert-session''}catch{$script:originalError=$_;Write-Error -ErrorRecord $_ -ErrorAction Continue}'
 $engine=[PowerShell]::Create();$caught=$null
 try{
  [void]$engine.AddScript($program);try{$output=$engine.Invoke()}catch{$caught=$_}
  if($engine.Streams.Error.Count-ne1){throw 'expected exactly one original error record'}
  $record=$engine.Streams.Error[0];$original=$engine.Runspace.SessionStateProxy.GetVariable('originalError');if($record.FullyQualifiedErrorId-cne$original.FullyQualifiedErrorId-or$record.Exception.Message-cne$original.Exception.Message){throw 'errorstream bridge changed original record'}
  if($record.Exception.Message-cne'guest pending installer request is not bound to this artifact/case'-or$record.ErrorDetails.Message-notmatch'amnezia-pending-guard '-or$record.ErrorDetails.Message-match'KEEP_PRIVATE'){throw 'original exception/diagnostic identity differs'}
  $copy=[Management.Automation.PSSerializer]::Deserialize([Management.Automation.PSSerializer]::Serialize($record))
  if($copy.ErrorDetails_Message-cne$record.ErrorDetails.Message-or$copy.FullyQualifiedErrorId-cne$record.FullyQualifiedErrorId){throw 'PowerShell error serialization lost diagnostic or original FQID'}
  $results+=@([ordered]@{callerPreference=$preference;singleOriginalError=$true;serializedErrorDetails=$true;originalFQIDPreserved=$true;diagnosticChars=$record.ErrorDetails.Message.Length})
 }finally{$engine.Dispose()}
}
[ordered]@{actualPS=$PSVersionTable.PSVersion.ToString();actualSeparateRunspace=$true;cases=$results;networkRemotingEndpointStarted=$false;compilerUsed=$false}|ConvertTo-Json -Depth 5 -Compress
