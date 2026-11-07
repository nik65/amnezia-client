# Pure regression of the actual adapter guard. Never invoke the full adapter or
# a Hyper-V command; only parse source and execute the extracted pure predicate.
$ErrorActionPreference='Stop'
$source=Join-Path $PSScriptRoot 'hyperv_adapter.ps1'
$tokens=$null;$errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'adapter PowerShell parse failed'}
$guards=@($ast.FindAll({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Assert-FixedChildMemory'},$true))
if($guards.Count-ne1){throw 'unique pure memory predicate required'}
function Fail([string]$message){throw $message}
Invoke-Expression $guards[0].Extent.Text
$count=0
Assert-FixedChildMemory ([pscustomobject]@{DynamicMemoryEnabled=$false;Startup=[long]8589934592});$count++
Assert-FixedChildMemory ([pscustomobject]@{DynamicMemoryEnabled=$false;Startup=[uint64]8589934592;Minimum=512MB;Maximum=1024GB});$count++
$negative=@(
 $null,
 [pscustomobject]@{},
 [pscustomobject]@{DynamicMemoryEnabled=$false},
 [pscustomobject]@{DynamicMemoryEnabled=$true;Startup=[long]8589934592},
 [pscustomobject]@{DynamicMemoryEnabled='False';Startup=[long]8589934592},
 [pscustomobject]@{DynamicMemoryEnabled=$false;Startup=$null},
 [pscustomobject]@{DynamicMemoryEnabled=$false;Startup='8589934592'},
 [pscustomobject]@{DynamicMemoryEnabled=$false;Startup=[double]8589934592},
 [pscustomobject]@{DynamicMemoryEnabled=$false;Startup=[long]4294967296}
)
foreach($value in $negative){
 $rejected=$false
 try{Assert-FixedChildMemory $value}catch{$rejected=$true}
 if(-not$rejected){throw 'unsafe memory configuration accepted'}
 $count++
}
$setters=@($ast.FindAll({param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Set-VMMemory'},$true))
if($setters.Count-ne1){throw 'unique memory setter required'}
$parameters=@($setters[0].CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.CommandParameterAst] } | ForEach-Object {$_.ParameterName})
if((($parameters|Sort-Object)-join ',') -cne 'DynamicMemoryEnabled,ErrorAction,StartupBytes,VM'){throw 'dynamic-only arguments reached static memory setter'}
if($setters[0].Extent.Text-cne 'Set-VMMemory -VM $vm -DynamicMemoryEnabled $false -StartupBytes 8GB -ErrorAction Stop'){throw 'static memory setter changed'}
$count++
$text=[IO.File]::ReadAllText($source)
if(-not$text.Contains("if (`$Action -notin @('reset','stop','relays-stop')) { `$fixedMemory = Get-VMMemory -VM `$vm -ErrorAction Stop; Assert-FixedChildMemory `$fixedMemory }")){throw 'ownership-preserving cleanup compatibility gate changed'}
$count++
if(-not$text.Contains('fixed_memory_readback = $(if ($null -ne $fixedMemory) { [ordered]@{ dynamic_memory_enabled = [bool]$fixedMemory.DynamicMemoryEnabled; startup_bytes = [int64]$fixedMemory.Startup } } else { $null }); ')){throw 'same-object actual readback missing'}
$count++
"PASS $count pure/static fixed-memory checks; no Hyper-V commands invoked"
