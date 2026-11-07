param([string]$Scratch)
$Launcher=Join-Path $PSScriptRoot 'hyperv_interactive_launcher.ps1'
$ownedScratch=$null
if([string]::IsNullOrWhiteSpace($Scratch)) {
    $ownedScratch=Join-Path ([IO.Path]::GetTempPath()) ('amnezia-launcher-pure-'+[Guid]::NewGuid().ToString('N'))
    $Scratch=$ownedScratch
    New-Item -ItemType Directory -Path $Scratch -ErrorAction Stop|Out-Null
}
try {
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Launcher,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'launcher AST parse failed'}
$fn=@($ast.FindAll({param($n)$n-is[Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-eq'Write-LaunchFailurePending'},$true))
if($fn.Count-ne1){throw 'one failure writer required'}
Invoke-Expression $fn[0].Extent.Text
$try=@($ast.FindAll({param($n)$n-is[Management.Automation.Language.TryStatementAst]-and$n.Body.Extent.Text.Contains('$process = Start-Process -FilePath $ArtifactPath')},$true))
if($try.Count-ne1){throw 'one narrow actual launch try required'}
$launch=[scriptblock]::Create($try[0].Extent.Text)
$script:mode='success';$script:mockCalls=0
function Start-Process {
 [CmdletBinding()]param($FilePath,$ArgumentList,[switch]$PassThru,$WindowStyle)
 $script:mockCalls++
 if($FilePath-ne'C:\owned-fixture\current.exe'-or-not$PassThru-or$WindowStyle-ne'Normal'-or$ArgumentList.Count-ne5){throw 'launch options changed'}
 if($script:mode-eq'success'){return [pscustomobject]@{Id=321;StartTime=[DateTime]::UtcNow}}
 if($script:mode-eq'win32'){throw [ComponentModel.Win32Exception]::new(1460,'synthetic timeout')}
 if($script:mode-eq'nested'){throw [InvalidOperationException]::new('synthetic outer',[ComponentModel.Win32Exception]::new(1223,'synthetic cancel'))}
 throw [InvalidOperationException]::new(('x'*1000))
}
$ArtifactPath='C:\owned-fixture\current.exe';$checks=0
foreach($mode in @('success','win32','nested','non-native')){
 $script:mode=$mode;$script:mockCalls=0
 $PendingPath=Join-Path $Scratch ($mode+'.json')
 $request=[ordered]@{schema=1;run_id='owned-run';case_id='outer-interactive';state='waiting';artifact_sha256=('a'*64);launcher_pid=41;installer_pid=$null;created_at='2026-10-28T00:00:00Z'}
 $before=$request|ConvertTo-Json -Depth 8;[IO.File]::WriteAllText($PendingPath,$before)
 $caught=$null
 try{. $launch}catch{$caught=$_}
 if($script:mockCalls-ne1){throw 'mock launch count differs'}
 if($mode-eq'success'){
  if($null-ne$caught-or$process.Id-ne321-or[IO.File]::ReadAllText($PendingPath)-cne$before-or$request.state-ne'waiting'){throw 'normal launch behavior changed'}
 }else{
  if($null-eq$caught){throw 'original launch failure swallowed'}
  $read=Get-Content -LiteralPath $PendingPath -Raw|ConvertFrom-Json
  if($read.state-ne'launch-failed'-or$null-ne$read.installer_pid-or$read.run_id-ne'owned-run'-or$read.artifact_sha256-ne('a'*64)-or-not$read.completed_at){throw 'failed receipt identity/state differs'}
  if($read.launch_error.stage-ne'Start-Process'-or$read.launch_error.error_type.Length-gt256-or$read.launch_error.message.Length-gt512-or$read.launch_error.hresult-isnot[int]){throw 'failure fields not typed/bounded'}
  if($mode-eq'win32'-and$read.launch_error.native_error_code-ne1460){throw 'direct native error missing'}
  if($mode-eq'nested'-and$read.launch_error.native_error_code-ne1223){throw 'nested native error missing'}
  if($mode-eq'non-native'-and$null-ne$read.launch_error.native_error_code){throw 'invented native error code'}
  if($mode-eq'nested'-and$caught.Exception.Message-ne'synthetic outer'){throw 'original exception changed'}
  if(@(Get-ChildItem -LiteralPath $Scratch -Filter '*.tmp').Count-ne0){throw 'temporary failure receipt leaked'}
 }
 $checks++
}
# A failed persistence must not replace the original launch exception.
$script:mode='nested';$PendingPath=Join-Path $Scratch 'absent.json';$request=[ordered]@{state='waiting';installer_pid=$null};$caught=$null
try{. $launch}catch{$caught=$_}
if($null-eq$caught-or$caught.Exception.Message-ne'synthetic outer'-or(Test-Path -LiteralPath $PendingPath)){throw 'persistence failure replaced launch error or invented pending file'}
$checks++
[ordered]@{status='PASS';mockedLaunchCases=$checks;actualInstallerStarted=$false;actualGuestUsed=$false}|ConvertTo-Json -Compress

} finally {
    if($null-ne$ownedScratch-and[IO.Directory]::Exists($ownedScratch)) {
        $resolved=[IO.Path]::GetFullPath($ownedScratch)
        $temporaryRoot=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')+'\'
        if($resolved-cne[IO.Path]::GetFullPath($Scratch)-or-not$resolved.StartsWith($temporaryRoot,[StringComparison]::OrdinalIgnoreCase)-or[IO.Path]::GetFileName($resolved)-notmatch '^amnezia-launcher-pure-[0-9a-f]{32}$'){throw 'owned test scratch cleanup refused'}
        [IO.Directory]::Delete($resolved,$true)
    }
}
