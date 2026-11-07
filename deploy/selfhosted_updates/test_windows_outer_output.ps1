param([string]$SourcePath=(Join-Path $PSScriptRoot 'local_release.ps1'))
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$path=[IO.Path]::GetFullPath($SourcePath)
$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors|Out-String)}
foreach($name in @('Resolve-RepoPath','Resolve-WindowsOuterOutputDirectory','Copy-WindowsOuterExclusive')){
 $fn=$ast.FindAll({param($n)$n-is[Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-eq$name},$true)
 if($fn.Count-ne1){throw 'Unique helper definition required'}
 . ([ScriptBlock]::Create($fn[0].Extent.Text))
}
$testBase=[IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$fixture=Join-Path $testBase ('amnezia-outer-test-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $fixture|Out-Null
$RepoRoot=$fixture;$Version='5.0.3.18';$checks=0
try {
function Assert-True([bool]$condition,[string]$reason){if(-not$condition){throw $reason};$script:checks++}
function Assert-Refused([ScriptBlock]$action){$failed=$false;try{&$action|Out-Null}catch{$failed=$true};Assert-True $failed 'Expected refusal'}
$legacy=Join-Path $RepoRoot 'dist/selfhosted-windows-client/5.0.3.18'
New-Item -ItemType Directory -Path $legacy -Force|Out-Null
$legacyFile=Join-Path $legacy 'AmneziaVPN_5.0.3.18_windows_x64_selfhosted.exe';[IO.File]::WriteAllText($legacyFile,'HISTORICAL_INERT_SENTINEL')
Assert-True ((Resolve-WindowsOuterOutputDirectory '')-eq$legacy) 'Default output changed'
$new=Join-Path $RepoRoot 'dist/diagnostics/new-attempt/outer'
Assert-True ((Resolve-WindowsOuterOutputDirectory $new)-eq[IO.Path]::GetFullPath($new)) 'Explicit output not selected'
$source=Join-Path $fixture 'inert-payload.bin';[IO.File]::WriteAllText($source,'NEW_INERT_PAYLOAD')
Copy-WindowsOuterExclusive $source $new
$target=Join-Path $new 'AmneziaVPN_5.0.3.18_windows_x64_selfhosted.exe'
Assert-True ([IO.File]::ReadAllText($target)-eq'NEW_INERT_PAYLOAD') 'Explicit copy did not bind new output'
Assert-True ([IO.File]::ReadAllText($legacyFile)-eq'HISTORICAL_INERT_SENTINEL') 'Historical output overwritten'
Assert-Refused {Copy-WindowsOuterExclusive $source $new}
Assert-True ([IO.File]::ReadAllText($target)-eq'NEW_INERT_PAYLOAD') 'Existing explicit output overwritten'
Assert-Refused {Resolve-WindowsOuterOutputDirectory $legacy}
Assert-Refused {Resolve-WindowsOuterOutputDirectory (Join-Path $RepoRoot '../escaped')}
Assert-Refused {Resolve-WindowsOuterOutputDirectory (Join-Path $testBase 'outside-fixture')}
Assert-Refused {Resolve-WindowsOuterOutputDirectory (Join-Path $RepoRoot 'dist/alias./outer')}
$real=Join-Path $RepoRoot 'real-dir';$alias=Join-Path $RepoRoot 'junction-alias'
New-Item -ItemType Directory -Path $real|Out-Null
New-Item -ItemType Junction -Path $alias -Target $real|Out-Null
Assert-Refused {Resolve-WindowsOuterOutputDirectory (Join-Path $alias 'outer')}
# AST source wiring covers packaging destination, lab input and status binding.
$text=[IO.File]::ReadAllText($path)
foreach($snippet in @('$adminInstallerDir = $resolvedWindowsOuterDir','$outerForLab = Join-Path $resolvedWindowsOuterDir','$originalOuterPath = Join-Path $resolvedWindowsOuterDir','Copy-WindowsOuterExclusive $adminInstallerSource $resolvedWindowsOuterDir')){Assert-True ($text.Contains($snippet)) 'Outer destination consumer not routed'}
Assert-True ($text.Contains('Copy-Item -LiteralPath $adminInstallerSource -Destination $adminInstallerTarget -Force')) 'Default legacy copy contract changed'
[ordered]@{status='PASS_INERT_FUNCTIONS_AND_AST';powershellVersion=$PSVersionTable.PSVersion.ToString();checks=$checks;fixture=$fixture;applicationExecuted=$false;buildExecuted=$false;historicalSentinelPreserved=$true}|ConvertTo-Json
} finally {
 if($alias -and (Test-Path -LiteralPath $alias)) {[IO.Directory]::Delete($alias)}
 $resolvedFixture=[IO.Path]::GetFullPath($fixture)
 $resolvedBase=[IO.Path]::GetFullPath($testBase).TrimEnd([char[]]'\/')+[IO.Path]::DirectorySeparatorChar
 if(-not$resolvedFixture.StartsWith($resolvedBase,[StringComparison]::OrdinalIgnoreCase) -or (Split-Path -Leaf $resolvedFixture)-notlike'amnezia-outer-test-*'){throw 'Owned fixture cleanup boundary mismatch'}
 if(Test-Path -LiteralPath $resolvedFixture){Remove-Item -LiteralPath $resolvedFixture -Recurse -Force}
}
