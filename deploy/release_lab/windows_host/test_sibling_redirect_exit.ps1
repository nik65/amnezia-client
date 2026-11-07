param([string]$AdapterPath=(Join-Path $PSScriptRoot 'hyperv_adapter.ps1'),[ValidateSet('before','after','auto')][string]$Expect='after',[string]$ResultPath,[string]$ScratchRoot)
$ErrorActionPreference='Stop';Set-StrictMode -Version 2.0
$checks=New-Object Collections.ArrayList
function Add-Check([string]$Name,[string]$Kind,[scriptblock]$Body){
    $note='';$errorText='';$passed=$false
    try{$note=[string](& $Body);$passed=$true}catch{$errorText=$_.Exception.Message}
    [void]$checks.Add([ordered]@{name=$Name;kind=$Kind;passed=$passed;note=$note;error=$errorText})
}
function ShaFile([string]$Path){return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()}
if(-not(Test-Path -LiteralPath $AdapterPath -PathType Leaf)){throw 'adapter is missing'}
$AdapterPath=(Resolve-Path -LiteralPath $AdapterPath).Path
$source=[IO.File]::ReadAllText($AdapterPath)
$runnerStart='$runnerProcess=Start-Process -FilePath powershell.exe -ArgumentList $nestedArgs'
$runnerNullCast='if($null -eq $stillRunning){$runnerExitCode=[int]$runnerProcess.ExitCode;break}'
$diagnoseStart='$p=Start-Process -FilePath $artifact'
$diagnoseNullCheck="if(`$null-eq`$raw){throw 'diagnostic exit code unavailable'}"
$runnerGuard='$rawRunnerExit=$runnerProcess.ExitCode'
$diagnoseGuard='$null-eq$raw-or$raw-isnot[int]'
$cmd=Join-Path $env:SystemRoot 'System32\cmd.exe'
if([string]::IsNullOrWhiteSpace($ScratchRoot)){$ScratchRoot=[Environment]::GetEnvironmentVariable('TMPDIR')}
if(-not(Test-Path -LiteralPath $ScratchRoot -PathType Container)){throw 'scratch root is missing'}
$root=Join-Path ([IO.Path]::GetFullPath($ScratchRoot)) ('amnezia-sibling-exit-'+[guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $root)
function New-Case([string]$Name){$dir=Join-Path $root $Name;[void](New-Item -ItemType Directory -Path $dir);return $dir}
function Start-Probe([string]$Dir,[string]$Code,[bool]$Retain){
    $out=Join-Path $Dir "stdout-$([guid]::NewGuid().ToString('N')).log";$err=Join-Path $Dir "stderr-$([guid]::NewGuid().ToString('N')).log"
    $p=Start-Process -FilePath $cmd -ArgumentList @('/d','/c',"exit $Code") -RedirectStandardOutput $out -RedirectStandardError $err -PassThru -WindowStyle Hidden
    if($Retain){[void]$p.Handle}
    if(-not$p.WaitForExit(15000)){throw 'redirected probe child did not exit'}
    $p.Refresh();return $p.ExitCode
}
try{
Add-Check 'ps5-null-exit-mechanism' 'mechanism' {
    $raw=Start-Probe (New-Case 'mechanism') 17 $false
    if($null-ne$raw){throw "expected the PowerShell 5 redirected null exit defect, got '$raw'"}
    if([int]$raw-ne0){throw 'null exit did not cast to 0'}
    'redirected Start-Process loses ExitCode (null -> [int] 0) without a retained handle'
}
Add-Check 'retained-handle-truthful-exit' 'defect' {
    foreach($code in @(0,17)){
        $raw=Start-Probe (New-Case "retain$code") $code $true
        if($null-eq$raw-or$raw-isnot[int]-or$raw-ne$code){throw "retained handle exit$code differs: '$raw'"}
    }
    'retained Handle preserves truthful 0/17'
}
Add-Check 'diagnose-null-guard-behavior' 'defect' {
    $lost=Start-Probe (New-Case 'guard-lost') 17 $false
    $threw=$false
    try{if($null-eq$lost){throw 'diagnostic exit code unavailable'}}catch{$threw=$true}
    if(-not$threw){throw 'diagnostic null guard did not fire without a retained handle'}
    $kept=Start-Probe (New-Case 'guard-kept') 17 $true
    if($null-eq$kept-or$kept-isnot[int]-or$kept-ne17){throw 'diagnostic guard rejected a truthful retained exit'}
    'diagnose null guard fires today for every run; retention makes it truthful'
}
Add-Check 'source-patterns' 'source' {
    $runnerHandle=@([regex]::Matches($source,'\[void\]\$runnerProcess\.Handle')).Count
    $diagnoseHandle=@([regex]::Matches($source,'\[void\]\$p\.Handle')).Count
    $runnerState=if($source.Contains($runnerStart)-and$runnerHandle-eq1-and$source.Contains($runnerGuard)-and-not$source.Contains($runnerNullCast)){'after'}elseif($source.Contains($runnerStart)-and$runnerHandle-eq0-and$source.Contains($runnerNullCast)-and-not$source.Contains($runnerGuard)){'before'}else{'partial'}
    $diagnoseState=if($source.Contains($diagnoseStart)-and$diagnoseHandle-eq1-and$source.Contains($diagnoseGuard)){'after'}elseif($source.Contains($diagnoseStart)-and$diagnoseHandle-eq0-and$source.Contains($diagnoseNullCheck)-and-not$source.Contains($diagnoseGuard)){'before'}else{'partial'}
    if($runnerState-eq'partial'-or$diagnoseState-eq'partial'){throw "sibling source state is partial: runner=$runnerState diagnose=$diagnoseState"}
    if($Expect-ne'auto'-and($runnerState-ne$Expect-or$diagnoseState-ne$Expect)){throw "expected $Expect source state, found runner=$runnerState diagnose=$diagnoseState"}
    if($runnerState-eq'after'){
        $startIndex=$source.IndexOf($runnerStart);$handleIndex=$source.IndexOf('[void]$runnerProcess.Handle');$startTimeIndex=$source.IndexOf('$runnerStart=[string]$runnerProcess.StartTime')
        if($startIndex-lt0-or$handleIndex-le$startIndex-or($startTimeIndex-ge0-and$handleIndex-ge$startTimeIndex)){throw 'runner Handle retention is not between Start-Process and StartTime'}
    }
    if($diagnoseState-eq'after'){
        $startIndex=$source.IndexOf($diagnoseStart);$handleIndex=$source.IndexOf('[void]$p.Handle');$waitIndex=$source.IndexOf('WaitForExit(900000)',$startIndex)
        if($startIndex-lt0-or$handleIndex-le$startIndex-or($waitIndex-ge0-and$handleIndex-ge$waitIndex)){throw 'diagnose Handle retention is not immediately after Start-Process'}
    }
    "runner=$runnerState diagnose=$diagnoseState"
}
}catch{
    [void]$checks.Add([ordered]@{name='harness';kind='source';passed=$false;note='';error=$_.Exception.Message})
}
$failed=@($checks|Where-Object{-not[bool]$_.passed})
$summary=[ordered]@{schema=1;adapter=$AdapterPath;adapter_sha256=(ShaFile $AdapterPath);expect=$Expect;powershell=$PSVersionTable.PSVersion.ToString();console_code_page=[int][Console]::OutputEncoding.CodePage;checks=$checks;passed=($failed.Count-eq0);check_count=$checks.Count;failed_count=$failed.Count;generated_at=[DateTime]::UtcNow.ToString('o')}
if(-not[string]::IsNullOrWhiteSpace($ResultPath)){[IO.File]::WriteAllText($ResultPath,($summary|ConvertTo-Json -Depth 8),(New-Object Text.UTF8Encoding($false)))}
$full=[IO.Path]::GetFullPath($root);$parent=[IO.Path]::GetFullPath($ScratchRoot)
if(-not$parent.EndsWith([IO.Path]::DirectorySeparatorChar)){$parent=$parent+[IO.Path]::DirectorySeparatorChar}
if(-not$full.StartsWith($parent,[StringComparison]::OrdinalIgnoreCase)-or(Split-Path -Leaf $full)-notlike'amnezia-sibling-exit-*'){throw 'test cleanup path differs'}
Remove-Item -LiteralPath $full -Recurse -Force -ErrorAction SilentlyContinue
if($failed.Count-eq0){$verdict='PASS'}else{$verdict='FAIL'}
Write-Output ('SIBLING-TEST '+$verdict+';expect='+$Expect+';checks='+$checks.Count+';failed='+$failed.Count)
foreach($item in $failed){Write-Output ('FAILED '+$item.name+': '+$item.error)}
if($failed.Count){exit 1}
exit 0
