# Pure capture-result predicate regression. No processes, guests, or application launched.
param([string]$Adapter=(Join-Path $PSScriptRoot 'hyperv_adapter.ps1'))
$ErrorActionPreference='Stop';Set-StrictMode -Version 2.0
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Adapter,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'adapter parse failed'}
$functions=@($ast.FindAll({param($n)$n-is[Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-eq'New-PublisherCaptureRecord'},$true))
if($functions.Count-ne1){throw 'unique capture record builder required'}
Invoke-Expression $functions[0].Extent.Text
function Fixture {
 [pscustomobject]@{Pid=1;StartTime='2026-10-28T20:00:00.0000000Z';ExitCode=0;TimedOut=$false;Status='completed';TerminationConfirmed=$true;DrainCompleted=$true;StdoutBytes=0L;StderrBytes=0L;StdoutTruncated=$false;StderrTruncated=$false;StdoutHeadB64='';StdoutTailB64='';StderrHeadB64='';StderrTailB64='';Failure=''}
}
$cases=0
foreach($mode in @('ok','drain-failed','termination-unconfirmed','capture-error','string-exit','null-exit','timeout')){
 $capture=Fixture
 if($mode-eq'drain-failed'){$capture.DrainCompleted=$false}
 if($mode-eq'termination-unconfirmed'){$capture.TerminationConfirmed=$false}
 if($mode-eq'capture-error'){$capture.Failure='inert file write failure'}
 if($mode-eq'string-exit'){$capture.ExitCode='0'}
 if($mode-eq'null-exit'){$capture.ExitCode=$null}
 if($mode-eq'timeout'){$capture.TimedOut=$true}
 $result=New-PublisherCaptureRecord $capture 'inert-run' 'publisher-clean' ('a'*48) 'stdout' 'stderr' 'capture'
 if([bool]$result.passed-ne($mode-eq'ok')){throw "invalid capture accepted: $mode"}
 if($mode-in@('string-exit','null-exit')-and$null-ne$result.exit_code){throw 'unavailable/non-integer exit was coerced'}
 $cases++
}
# Execute only the actual host diagnostic-write statements using an inert record.
# Raw stream windows belong in the controller's private POSIX archive, not the
# host case directory, which can inherit ProgramData read permissions.
$lines=[IO.File]::ReadAllLines($Adapter);$start=-1;$end=-1
for($i=0;$i-lt$lines.Length;$i++){
 if($lines[$i].TrimStart().StartsWith("`$hostCapture=''") ){$start=$i}
 if($start-ge0-and$lines[$i].TrimStart().StartsWith("Emit ([ordered]@{ action='publish'")){$end=$i;break}
}
if($start-lt0-or$end-le$start){throw 'actual host capture writer missing'}
$scratchRoot=[Environment]::GetEnvironmentVariable('TMPDIR')
if([string]::IsNullOrWhiteSpace($scratchRoot)){throw 'managed scratch root required'}
$leaf=Join-Path $scratchRoot ('amnezia-capture-metadata-'+[guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $leaf)
try {
 $child=[pscustomobject]@{root=$leaf}
 $remote=[pscustomobject]@{capture=[pscustomobject]@{schema=2;run_id='inert-run';case_id='publisher-clean';attempt_nonce_sha256='a'*64;pid=1;process_start_time='x';exit_code=0;capture_status='completed';timed_out=$false;termination_confirmed=$true;drain_completed=$true;stdout_bytes=12;stderr_bytes=0;stdout_truncated=$false;stderr_truncated=$false;passed=$true;stdout_head_b64='aW5lcnQ=';stdout_tail_b64='';stderr_head_b64='';stderr_tail_b64=''}}
 & ([scriptblock]::Create(($lines[$start..($end-1)]-join"`n")))
 $saved=[IO.File]::ReadAllText((Join-Path $leaf 'publisher.capture.json'))|ConvertFrom-Json
 foreach($name in @('stdout_head_b64','stdout_tail_b64','stderr_head_b64','stderr_tail_b64')){if(@($saved.PSObject.Properties.Name)-contains$name){throw 'host capture contains raw output'}}
 if($saved.run_id-cne'inert-run'-or$saved.exit_code-ne0){throw 'host capture metadata identity lost'}
 $cases++
} finally {Remove-Item -LiteralPath $leaf -Recurse -Force}
"PASS $cases capture completeness/private-host-metadata cases; no application or guest started"
