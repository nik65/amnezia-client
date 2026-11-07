$ErrorActionPreference='Stop';Set-StrictMode -Version 2
$source=Join-Path $PSScriptRoot 'product_observer.ps1';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$errors);if($errors.Count){throw 'observer AST invalid'}
foreach($name in @('Wait-FixtureIo','Write-FixtureBytes','Read-FixtureBytes')){$fn=@($ast.FindAll({param($n)$n-is[Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-eq$name},$true));if($fn.Count-ne1){throw 'actual source function ambiguous'};. ([scriptblock]::Create($fn[0].Extent.Text))}
$results=@()
$bytes=[Text.Encoding]::ASCII.GetBytes('complete-request')
$socket=[pscustomobject]@{sent=0};$socket|Add-Member ScriptMethod Send {param($data)$this.sent++;return 1}
[void]$socket.Send($bytes);if($socket.sent-ne1-or$bytes.Length-le1){throw 'old partial-send RED not reproduced'}
$stream=[pscustomobject]@{written=0};$stream|Add-Member ScriptMethod WriteAsync {param($data,$offset,$count)$this.written=$count;return [Threading.Tasks.Task]::Delay(0)}
Write-FixtureBytes $stream $bytes ([pscustomobject]@{ElapsedMilliseconds=0})
if($stream.written-ne$bytes.Length){throw 'whole-buffer write differs'}
$results+=@(@{case='old-unchecked-one-byte-RED/new-full-buffer-GREEN';passed=$true})
$memory=New-Object IO.MemoryStream(,[Text.Encoding]::ASCII.GetBytes('abc'))
try{$read=Read-FixtureBytes $memory ([pscustomobject]@{ElapsedMilliseconds=0}) 3;if([Text.Encoding]::ASCII.GetString($read)-cne'abc'){throw 'body differs'}}finally{$memory.Dispose()}
$results+=@(@{case='exact-body-and-eof';passed=$true})
$memory=New-Object IO.MemoryStream(,[Text.Encoding]::ASCII.GetBytes('abcd'));$caught=$false
try{try{$null=Read-FixtureBytes $memory ([pscustomobject]@{ElapsedMilliseconds=0}) 3}catch{$caught=$_.Exception.Message-like'*exceeds cap*'}}finally{$memory.Dispose()}
if(-not$caught){throw 'cap not rejected'};$results+=@(@{case='oversize-rejected';passed=$true})
$script:ticks=0;$clock=[pscustomobject]@{};$clock|Add-Member ScriptProperty ElapsedMilliseconds {$script:ticks+=2000;return $script:ticks}
$trickle=[pscustomobject]@{reads=0};$trickle|Add-Member ScriptMethod ReadAsync {param($buffer,$offset,$count)$this.reads++;$buffer[0]=65;$t=New-Object 'Threading.Tasks.TaskCompletionSource[int]';$t.SetResult(1);return $t.Task}
$caught=$false;try{$null=Read-FixtureBytes $trickle $clock 65536}catch{$caught=$_.Exception.Message-like'*global deadline*'}
if(-not$caught-or$trickle.reads-gt3){throw 'trickle escaped global deadline'}
$results+=@(@{case='fast-trickle-global-deadline';passed=$true;readCalls=$trickle.reads;simulatedElapsedMs=$script:ticks})
$watch=[Diagnostics.Stopwatch]::StartNew();$caught=$false
try{Wait-FixtureIo ([Threading.Tasks.Task]::Delay(100)) ([pscustomobject]@{ElapsedMilliseconds=9990}) 'test'}catch{$caught=$_.Exception.Message-like'*bounded IO timeout*'}
if(-not$caught-or$watch.ElapsedMilliseconds-gt500){throw 'remaining-budget bound differs'}
$results+=@(@{case='remaining-budget-bounds-wait';passed=$true;elapsedMs=$watch.ElapsedMilliseconds})
"$($results.Count) IO cases PASS"
