param([string]$RunnerPath = (Join-Path $PSScriptRoot 'windows-release-lab.ps1'), [string]$OutputDirectory)
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($RunnerPath,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Runner parse failed'}
foreach($name in @('Write-Receipt','Get-MapValue','Get-ArtifactRole')) {
 $nodes=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true))
 if($nodes.Count-ne1){throw "Expected exact function $name"}
 . ([scriptblock]::Create($nodes[0].Extent.Text))
}
function Write-Milestone {param($Phase,$Data)}
$owned=Join-Path ([IO.Path]::GetTempPath()) ('amnezia-receipt-action-'+[guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($owned)
try {
 $RunId='p17-action-regression';$CaseId='publisher-clean';$Profile='windows-x64'
 $Transport='hyperv-powershell-direct';$ExpectedArtifactRole='candidate'
 $BaselineVersion='5.0.3.16';$CandidateVersion='5.0.3.17'
 $GuestMarker="amnezia-release-lab:${RunId}:${Profile}`ncase_id=$CaseId"
 $ArtifactPath=Join-Path $owned 'current.exe';[IO.File]::WriteAllText($ArtifactPath,'inert-test-payload')
 $ExpectedSha256=(Get-FileHash $ArtifactPath).Hash.ToLowerInvariant()
 foreach($Action in @('reinstall','update')) {
  $ReceiptPath=Join-Path $owned "$Action.json"
  $assertion=[ordered]@{passed=$true;run_id=$RunId;profile=$Profile;action=$Action;artifact_sha256=$ExpectedSha256;expected_sha256=$ExpectedSha256;expected_version=$CandidateVersion;installed_version=$CandidateVersion}
  $wire=@(Write-Receipt $assertion ([ordered]@{is_system=$true}) @([ordered]@{id=$Action;passed=$true;exit_code=0}))
  if($wire.Count-ne0){throw 'Write-Receipt polluted pipeline'}
  $receipt=Get-Content $ReceiptPath -Raw|ConvertFrom-Json
  if($receipt.action-cne$Action-or$receipt.assertion.action-cne$Action-or$receipt.run_id-cne$RunId-or$receipt.artifact_sha256-cne$ExpectedSha256){throw 'Action/identity contract failed'}
  if($OutputDirectory){[IO.File]::Copy($ReceiptPath,(Join-Path $OutputDirectory "$Action.json"),$false)}
 }
 Write-Output 'PASS actual Write-Receipt reinstall/update; exact wire action and no pipeline output'
} finally {
 if([IO.Path]::GetDirectoryName($owned).TrimEnd('\')-ne[IO.Path]::GetTempPath().TrimEnd('\')-or[IO.Path]::GetFileName($owned)-notlike'amnezia-receipt-action-*'){throw 'Unsafe test cleanup'}
 Remove-Item -LiteralPath $owned -Recurse -Force
}
