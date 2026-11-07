param([string]$FragmentPath=(Join-Path $PSScriptRoot 'hyperv_adapter.ps1'),[string]$ResultPath,[string]$ScratchRoot)
$ErrorActionPreference='Stop';Set-StrictMode -Version 2.0
$checks=New-Object Collections.ArrayList
function Add-Check([string]$Name,[string]$Kind,[scriptblock]$Body){
    $note='';$errorText='';$passed=$false
    try{$note=[string](& $Body);$passed=$true}catch{$errorText=$_.Exception.Message}
    [void]$checks.Add([ordered]@{name=$Name;kind=$Kind;passed=$passed;note=$note;error=$errorText})
}
function ShaFile([string]$Path){return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()}
function ShaBytes([byte[]]$Bytes){$sha=[Security.Cryptography.SHA256]::Create();try{return [BitConverter]::ToString($sha.ComputeHash($Bytes)).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}}
function HasKey([object]$Record,[string]$Name){if($Record-is[Collections.IDictionary]){return [bool]$Record.Contains($Name)};return (@($Record.PSObject.Properties.Name)-contains$Name)}
function Assert-Key([object]$Record,[string]$Name){if(-not(HasKey $Record $Name)){throw "record lacks $Name"}}
if(-not(Test-Path -LiteralPath $FragmentPath -PathType Leaf)){throw 'fragment is missing'}
$FragmentPath=(Resolve-Path -LiteralPath $FragmentPath).Path
$tokens=$null;$parseErrors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($FragmentPath,[ref]$tokens,[ref]$parseErrors)
if($parseErrors.Count){throw "fragment parse failed: $($parseErrors[0].Message)"}
$defs=@($ast.FindAll({param($node)$node-is[Management.Automation.Language.FunctionDefinitionAst]},$true)|Where-Object{$_.Name-in@('Invoke-OwnedPublisherProcess','New-PublisherCaptureRecord')})
if(-not($defs|Where-Object{$_.Name-eq'Invoke-OwnedPublisherProcess'})){throw 'fragment does not define Invoke-OwnedPublisherProcess'}
foreach($definition in $defs){Invoke-Expression $definition.Extent.Text}
$hasBinding=@((Get-Command Invoke-OwnedPublisherProcess).Parameters.Keys)-contains'RunId'
$hasRecord=@(Get-Command New-PublisherCaptureRecord -ErrorAction SilentlyContinue).Count-gt0
$RunId='run-50317-capture-v2';$CaseId='publisher-clean';$AttemptNonce=('a'*48)
$shaNonce=[Security.Cryptography.SHA256]::Create()
try{$ExpectedNonceSha=[BitConverter]::ToString($shaNonce.ComputeHash([Text.Encoding]::ASCII.GetBytes($AttemptNonce))).Replace('-','').ToLowerInvariant()}finally{$shaNonce.Dispose()}
$cmd=Join-Path $env:SystemRoot 'System32\cmd.exe'
$ps=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$NonAsciiMarker=-join([char[]](0x41F,0x440,0x438,0x432,0x435,0x442,0x2D,0x43C,0x438,0x440,0x2D,0x2713))
$Utf8Payload=[Text.Encoding]::UTF8.GetBytes($NonAsciiMarker)
$stdoutHead='STDOUT-HEAD-MARKER:';$stdoutTail=':STDOUT-TAIL-MARKER'
$stderrHead='STDERR-HEAD-MARKER:';$stderrTail=':STDERR-TAIL-MARKER'
$stdoutPayload=[Text.Encoding]::ASCII.GetBytes($stdoutHead+('A'*(300000-$stdoutHead.Length-$stdoutTail.Length))+$stdoutTail)
$stderrPayload=[Text.Encoding]::ASCII.GetBytes($stderrHead+('B'*(300000-$stderrHead.Length-$stderrTail.Length))+$stderrTail)
$stdoutSha=ShaBytes $stdoutPayload;$stderrSha=ShaBytes $stderrPayload;$utf8Sha=ShaBytes $Utf8Payload
$script300='$h=''STDOUT-HEAD-MARKER:'';$t='':STDOUT-TAIL-MARKER'';$g=''STDERR-HEAD-MARKER:'';$u='':STDERR-TAIL-MARKER'';'+
    '$ob=[Text.Encoding]::ASCII.GetBytes($h+(''A''*(300000-$h.Length-$t.Length))+$t);'+
    '$eb=[Text.Encoding]::ASCII.GetBytes($g+(''B''*(300000-$g.Length-$u.Length))+$u);'+
    '$o=[Console]::OpenStandardOutput();$e=[Console]::OpenStandardError();'+
    '$o.Write($ob,0,150000);$o.Flush();$e.Write($eb,0,150000);$e.Flush();$o.Write($ob,150000,150000);$o.Flush();$e.Write($eb,150000,150000);$e.Flush()'
$scriptUtf8='$m=-join([char[]](0x41F,0x440,0x438,0x432,0x435,0x442,0x2D,0x43C,0x438,0x440,0x2D,0x2713));'+
    '$b=[Text.Encoding]::UTF8.GetBytes($m);$o=[Console]::OpenStandardOutput();$o.Write($b,0,$b.Length);$o.Flush();'+
    '$e=[Console]::OpenStandardError();$e.Write($b,0,$b.Length);$e.Flush()'
$scriptSleep='[Threading.Thread]::Sleep(10000)'
function Encode([string]$Script){return '-NoProfile -NonInteractive -EncodedCommand '+[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Script))}
$args300=Encode $script300;$argsUtf8=Encode $scriptUtf8;$argsSleep=Encode $scriptSleep
if([string]::IsNullOrWhiteSpace($ScratchRoot)){$ScratchRoot=[Environment]::GetEnvironmentVariable('TMPDIR')}
if(-not(Test-Path -LiteralPath $ScratchRoot -PathType Container)){throw 'scratch root is missing'}
$root=Join-Path ([IO.Path]::GetFullPath($ScratchRoot)) ('amnezia-publisher-capture-v2-'+[guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $root)
function New-CaseDir([string]$Name){$dir=Join-Path $root $Name;[void](New-Item -ItemType Directory -Path $dir);return $dir}
function Invoke-UnderTest([string]$Name,[string]$File,[string]$Arguments,[int]$Timeout){
    $dir=New-CaseDir $Name;$out=Join-Path $dir 'publisher.stdout.log';$err=Join-Path $dir 'publisher.stderr.log'
    if($hasBinding){$record=Invoke-OwnedPublisherProcess $File $Arguments $out $err $RunId $CaseId $AttemptNonce $Timeout}
    else{$record=Invoke-OwnedPublisherProcess $File $Arguments $out $err $Timeout}
    return [pscustomobject]@{dir=$dir;out=$out;err=$err;record=$record}
}
try{
Add-Check 'binding-and-truthful-exit' 'defect' {
    if(-not$hasBinding){throw 'fragment does not accept run/case/attempt binding parameters'}
    foreach($code in @(0,17)){
        $case=Invoke-UnderTest "exit$code" $cmd "/d /c exit $code" 5000
        $r=$case.record
        Assert-Key $r 'run_id';Assert-Key $r 'case_id';Assert-Key $r 'attempt_nonce_sha256';Assert-Key $r 'capture_path'
        if($r.run_id-cne$RunId-or$r.case_id-cne$CaseId-or$r.attempt_nonce_sha256-cne$ExpectedNonceSha){throw "exit$code record binding differs"}
        if($r.exit_code-isnot[int]-or$r.exit_code-ne$code){throw "exit$code exit code not preserved"}
        if([bool]$r.passed-ne($code-eq0)){throw "exit$code passed flag differs"}
        $capturePath=Join-Path $case.dir 'publisher.capture.json'
        if(-not(Test-Path -LiteralPath $capturePath -PathType Leaf)){throw "exit$code capture record missing"}
        $text=[IO.File]::ReadAllText($capturePath)
        if($text.Contains($AttemptNonce)){throw 'capture record leaks the raw attempt nonce'}
        if($text-match'[^\x00-\x7F]'){throw 'capture record is not ASCII-safe for the host stdout bridge'}
        $persisted=$text|ConvertFrom-Json
        if($persisted.run_id-cne$RunId-or$persisted.case_id-cne$CaseId-or[int]$persisted.exit_code-ne$code){throw "exit$code persisted binding/exit differs"}
    }
    'exit 0/17 preserved with run/case/attempt binding'
}
Add-Check 'bounded-head-and-tail-300000' 'defect' {
    $case=Invoke-UnderTest 'dual300000' $ps $args300 20000
    $r=$case.record
    Assert-Key $r 'stdout_bytes';Assert-Key $r 'stderr_bytes';Assert-Key $r 'stdout_head_b64';Assert-Key $r 'stdout_tail_b64'
    if([long]$r.stdout_bytes-ne300000-or[long]$r.stderr_bytes-ne300000){throw "byte counts differ: $($r.stdout_bytes)/$($r.stderr_bytes)"}
    if(-not[bool]$r.stdout_truncated-or-not[bool]$r.stderr_truncated){throw 'truncation not reported'}
    $outBytes=[IO.File]::ReadAllBytes($case.out);$errBytes=[IO.File]::ReadAllBytes($case.err)
    if($outBytes.Length-ne300000-or$errBytes.Length-ne300000){throw "log byte length differs: $($outBytes.Length)/$($errBytes.Length)"}
    if((ShaBytes $outBytes)-cne$stdoutSha){throw 'stdout log is not byte-exact'}
    if((ShaBytes $errBytes)-cne$stderrSha){throw 'stderr log is not byte-exact'}
    $headBytes=[Convert]::FromBase64String([string]$r.stdout_head_b64)
    $tailBytes=[Convert]::FromBase64String([string]$r.stdout_tail_b64)
    $expectedHead=New-Object byte[] 65536;[Array]::Copy($stdoutPayload,0,$expectedHead,0,65536)
    $expectedTail=New-Object byte[] 65536;[Array]::Copy($stdoutPayload,$stdoutPayload.Length-65536,$expectedTail,0,65536)
    if((ShaBytes $headBytes)-cne(ShaBytes $expectedHead)){throw 'head window bytes differ'}
    if((ShaBytes $tailBytes)-cne(ShaBytes $expectedTail)){throw 'tail window bytes/ring order differ'}
    $head=[Text.Encoding]::ASCII.GetString($headBytes)
    $tail=[Text.Encoding]::ASCII.GetString($tailBytes)
    if(-not$head.StartsWith($stdoutHead)){throw 'head window is missing the head marker'}
    if(-not$tail.EndsWith($stdoutTail)){throw 'tail window is missing the tail marker'}
    if($head.Length-gt65536-or$tail.Length-gt65536){throw 'bounded window exceeded 65536 bytes per side'}
    if($head.Length+$tail.Length-gt131072){throw 'bounded window exceeded 131072 bytes per stream'}
    $errHead=[Text.Encoding]::ASCII.GetString([Convert]::FromBase64String([string]$r.stderr_head_b64))
    $errTail=[Text.Encoding]::ASCII.GetString([Convert]::FromBase64String([string]$r.stderr_tail_b64))
    if(-not$errHead.StartsWith($stderrHead)-or-not$errTail.EndsWith($stderrTail)){throw 'stderr head/tail window differs'}
    $expectedErrTail=New-Object byte[] 65536;[Array]::Copy($stderrPayload,$stderrPayload.Length-65536,$expectedErrTail,0,65536)
    if((ShaBytes ([Convert]::FromBase64String([string]$r.stderr_tail_b64)))-cne(ShaBytes $expectedErrTail)){throw 'stderr tail window bytes differ'}
    '300000 byte dual streams kept byte-exact on disk with 65536+65536 head/tail window'
}
Add-Check 'utf8-byte-exact' 'defect' {
    $case=Invoke-UnderTest 'utf8' $ps $argsUtf8 10000
    $r=$case.record
    Assert-Key $r 'stdout_head_b64';Assert-Key $r 'stdout_bytes'
    $bytes=[IO.File]::ReadAllBytes($case.out)
    if((ShaBytes $bytes)-cne$utf8Sha){throw 'stdout log bytes were transcoded'}
    if((ShaBytes ([IO.File]::ReadAllBytes($case.err)))-cne$utf8Sha){throw 'stderr log bytes were transcoded'}
    $head=[Convert]::FromBase64String([string]$r.stdout_head_b64)
    if((ShaBytes $head)-cne$utf8Sha){throw 'stdout head window bytes differ'}
    $decoded=[Text.Encoding]::UTF8.GetString($bytes)
    if($decoded-cne$NonAsciiMarker){throw "utf8 decode differs: $decoded"}
    'utf8 bytes preserved exactly and exposed without lossy decoding'
}
Add-Check 'timeout-returned-and-terminated' 'defect' {
    $watch=[Diagnostics.Stopwatch]::StartNew()
    $case=Invoke-UnderTest 'timeout' $ps $argsSleep 400
    $watch.Stop()
    $r=$case.record
    Assert-Key $r 'timed_out';Assert-Key $r 'capture_status';Assert-Key $r 'termination_confirmed'
    if(-not[bool]$r.timed_out){throw 'timeout not reported'}
    if([string]$r.capture_status-ne'timeout'){throw "capture status differs: $($r.capture_status)"}
    if(-not[bool]$r.termination_confirmed){throw 'timeout termination unconfirmed'}
    if([bool]$r.passed){throw 'timeout reported as passed'}
    if(@(Get-Process -Id ([int]$r.pid) -ErrorAction SilentlyContinue).Count-ne0){throw 'owned timeout process remained'}
    if($watch.ElapsedMilliseconds-gt15000){throw "timeout return exceeded bounded window: $($watch.ElapsedMilliseconds)ms"}
    $persisted=Get-Content -LiteralPath (Join-Path $case.dir 'publisher.capture.json') -Raw|ConvertFrom-Json
    if(-not[bool]$persisted.timed_out-or$persisted.capture_status-ne'timeout'){throw 'persisted record lost timeout metadata'}
    'timeout record returned and persisted before host exception cleanup'
}
Add-Check 'null-exit-metadata' 'defect' {
    if(-not$hasRecord){throw 'fragment has no record builder for null capture metadata'}
    $stub=[pscustomobject]@{Pid=4242;StartTime='2026-10-28T00:00:00.0000000Z';ExitCode=$null;TimedOut=$true;Status='timeout';TerminationConfirmed=$true;DrainCompleted=$true;StdoutBytes=12L;StderrBytes=0L;StdoutTruncated=$false;StderrTruncated=$false;StdoutHeadB64='';StdoutTailB64='';StderrHeadB64='';StderrTailB64='';Failure=''}
    $record=New-PublisherCaptureRecord $stub $RunId $CaseId $AttemptNonce (Join-Path $root 'n.stdout') (Join-Path $root 'n.stderr') (Join-Path $root 'n.capture.json')
    if($null-ne$record.exit_code){throw 'null exit code was coerced'}
    if([bool]$record.passed){throw 'null exit code reported as passed'}
    $json=$record|ConvertTo-Json -Compress
    if($json-notmatch'"exit_code":null'){throw 'serialized record does not preserve a null exit code'}
    if($record.run_id-cne$RunId-or$record.case_id-cne$CaseId-or$record.attempt_nonce_sha256-cne$ExpectedNonceSha){throw 'record binding differs'}
    $zero=[pscustomobject]@{Pid=1;StartTime='x';ExitCode=0;TimedOut=$false;Status='completed';TerminationConfirmed=$true;DrainCompleted=$true;StdoutBytes=0L;StderrBytes=0L;StdoutTruncated=$false;StderrTruncated=$false;StdoutHeadB64='';StdoutTailB64='';StderrHeadB64='';StderrTailB64='';Failure=''}
    $zeroRecord=New-PublisherCaptureRecord $zero $RunId $CaseId $AttemptNonce (Join-Path $root 'z.stdout') (Join-Path $root 'z.stderr') (Join-Path $root 'z.capture.json')
    if(-not[bool]$zeroRecord.passed){throw 'truthful exit 0 was not passed'}
    $seventeen=[pscustomobject]@{Pid=1;StartTime='x';ExitCode=17;TimedOut=$false;Status='completed';TerminationConfirmed=$true;DrainCompleted=$true;StdoutBytes=0L;StderrBytes=0L;StdoutTruncated=$false;StderrTruncated=$false;StdoutHeadB64='';StdoutTailB64='';StderrHeadB64='';StderrTailB64='';Failure=''}
    $seventeenRecord=New-PublisherCaptureRecord $seventeen $RunId $CaseId $AttemptNonce (Join-Path $root 's.stdout') (Join-Path $root 's.stderr') (Join-Path $root 's.capture.json')
    if([bool]$seventeenRecord.passed-or$seventeenRecord.exit_code-ne17){throw 'truthful exit 17 handling differs'}
    'null exit metadata preserved and truthful 0/17 retained'
}
Add-Check 'start-failure-metadata' 'defect' {
    $missing=Join-Path $root 'definitely-missing-publisher.exe'
    $case=Invoke-UnderTest 'missing-exe' $missing '--publish-bundled-updates-once' 5000
    $r=$case.record
    Assert-Key $r 'capture_status';Assert-Key $r 'capture_error'
    if([string]$r.capture_status-ne'capture-failed'){throw "start failure status differs: $($r.capture_status)"}
    if($null-ne$r.exit_code){throw 'start failure exit code was fabricated'}
    if([bool]$r.passed){throw 'start failure reported as passed'}
    if([string]::IsNullOrWhiteSpace([string]$r.capture_error)){throw 'start failure reason missing'}
    if(-not(Test-Path -LiteralPath (Join-Path $case.dir 'publisher.capture.json') -PathType Leaf)){throw 'start failure record not persisted'}
    'null launch metadata returned and persisted instead of throwing'
}
Add-Check 'record-persisted-readback' 'defect' {
    $case=Invoke-UnderTest 'persist17' $cmd '/d /c exit 17' 5000
    $r=$case.record
    $capturePath=Join-Path $case.dir 'publisher.capture.json'
    if(-not(Test-Path -LiteralPath $capturePath -PathType Leaf)){throw 'capture record missing'}
    $text=[IO.File]::ReadAllText($capturePath)
    $persisted=$text|ConvertFrom-Json
    foreach($name in @('run_id','case_id','attempt_nonce_sha256','exit_code','capture_status','timed_out','termination_confirmed','stdout_bytes','stdout_path','stderr_path','capture_path','passed')){Assert-Key $persisted $name}
    if($persisted.capture_path-cne$capturePath){throw 'capture path binding differs'}
    if($persisted.stdout_path-cne$case.out-or$persisted.stderr_path-cne$case.err){throw 'log path binding differs'}
    if([int]$persisted.exit_code-ne17-or[bool]$persisted.passed){throw 'persisted exit 17 differs'}
    if($text-notmatch'"schema":2'){throw 'capture schema differs'}
    'record persisted before host exception cleanup with run/case/attempt binding'
}
}catch{
    [void]$checks.Add([ordered]@{name='harness';kind='defect';passed=$false;note='';error=$_.Exception.Message})
}
$failed=@($checks|Where-Object{-not[bool]$_.passed})
$summary=[ordered]@{schema=1;fragment=$FragmentPath;fragment_sha256=(ShaFile $FragmentPath);powershell=$PSVersionTable.PSVersion.ToString();console_code_page=[int][Console]::OutputEncoding.CodePage;checks=$checks;passed=($failed.Count-eq0);check_count=$checks.Count;failed_count=$failed.Count;generated_at=[DateTime]::UtcNow.ToString('o')}
$json=$summary|ConvertTo-Json -Depth 8
if(-not[string]::IsNullOrWhiteSpace($ResultPath)){[IO.File]::WriteAllText($ResultPath,$json,(New-Object Text.UTF8Encoding($false)))}
$full=[IO.Path]::GetFullPath($root);$parent=[IO.Path]::GetFullPath($ScratchRoot)
if(-not$parent.EndsWith([IO.Path]::DirectorySeparatorChar)){$parent=$parent+[IO.Path]::DirectorySeparatorChar}
if(-not$full.StartsWith($parent,[StringComparison]::OrdinalIgnoreCase)-or(Split-Path -Leaf $full)-notlike'amnezia-publisher-capture-v2-*'){throw 'test cleanup path differs'}
Remove-Item -LiteralPath $full -Recurse -Force -ErrorAction SilentlyContinue
if($failed.Count-eq0){$verdict='PASS'}else{$verdict='FAIL'}
Write-Output ('CAPTURE-TEST '+$verdict+';checks='+$checks.Count+';failed='+$failed.Count)
foreach($item in $failed){Write-Output ('FAILED '+$item.name+': '+$item.error)}
if($failed.Count){exit 1}
exit 0
