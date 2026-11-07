# Inert regression of the actual prepare-interactive readiness loop.
# No Hyper-V, guest, application, installer or network operation is executed.
$ErrorActionPreference='Stop'
$adapter=Join-Path $PSScriptRoot 'hyperv_adapter.ps1'
$source=[IO.File]::ReadAllText($adapter)
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseInput($source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'adapter parse failed'}
$loops=@($ast.FindAll({param($n) $n-is [Management.Automation.Language.DoWhileStatementAst] -and $n.Extent.Text.Contains('explorer_sessions=') -and $n.Extent.Text.Contains('$deadline')},$true))
if($loops.Count-ne 1){throw 'actual readiness loop extraction ambiguous'}
$actual=$loops[0].Extent.Text
function Test-Case([string]$Name,[string]$Program,[array]$Responses,[int]$ExpectedCalls,[bool]$ExpectedReady){
 $script:calls=0;$script:clock=0;$script:responses=$Responses
 $before=@{last_boot='boot-old'};$after=$null;$reconnected=$null
 $deadline=[datetime]'2026-10-22T00:00:03Z';$credential=$null
 $child=@{vm=@{Id='00000000-0000-0000-0000-000000000001'}}
 function Get-Date { $script:clock++; ([datetime]'2026-10-22T00:00:00Z').AddSeconds($script:clock) }
 function Start-Sleep {param($Seconds)}
 function New-PSSession {param($VMId,$Credential,$ErrorAction) 'inert-session'}
 function Remove-PSSession {param($Session,$ErrorAction)}
 function Invoke-Command {
  param($Session,$ScriptBlock)
  $script:calls++
  if($script:calls-gt 4){throw 'poll bound exceeded'}
  $script:responses[[Math]::Min($script:calls-1,$script:responses.Count-1)]
 }
 . ([scriptblock]::Create($Program))
 # Same readiness predicate as the production final guard, expressed positively.
 $ready=($null-ne $after -and $null-ne $before -and $after.last_boot-ne $before.last_boot -and [int]$after.explorer_count-ge 1)
 if($script:calls-ne $ExpectedCalls -or $ready-ne $ExpectedReady){throw "$Name unexpected readiness result"}
 [ordered]@{case=$Name;polls=$script:calls;ready=$ready;clock_checks=$script:clock}
}
$oldReady=@{last_boot='boot-old';explorer_count=1}
$newNoExplorer=@{last_boot='boot-new';explorer_count=0}
$newReady=@{last_boot='boot-new';explorer_count=1}
function Test-Four([string]$Program){
 Test-Case 'old-session-then-new-ready' $Program @($oldReady,$newReady) 2 $true
 Test-Case 'new-boot-awaits-explorer' $Program @($newNoExplorer,$newReady) 2 $true
 Test-Case 'immediately-ready' $Program @($newReady) 1 $true
 Test-Case 'stale-until-deadline' $Program @($oldReady) 3 $false
}
$results=@(Test-Four $actual)
[ordered]@{actual_loop_cases=$results;external_calls=$false} | ConvertTo-Json -Depth 6
