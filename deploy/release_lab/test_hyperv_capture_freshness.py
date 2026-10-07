import os
import subprocess
import tempfile
import unittest
from pathlib import Path


@unittest.skipUnless(os.name == "nt", "PowerShell capture publication is Windows-only")
class CaptureFreshnessTests(unittest.TestCase):
    def test_actual_capture_functions_reject_stale_and_publish_paired_bytes(self):
        root = Path(__file__).parent
        script = r"""
param([string]$Adapter,[string]$Helper,[string]$Scratch)
$ErrorActionPreference='Stop'
function Load-Function($Path,$Name) {
 $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($Path,[ref]$tokens,[ref]$errors)
 if($errors.Count){throw 'production PowerShell parse failed'}
 $found=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $Name},$true))
 if($found.Count-ne1){throw 'function is missing or ambiguous'}
 return $found[0].Extent.Text
}
Invoke-Expression (Load-Function $Adapter 'New-UiCapturePaths')
Invoke-Expression (Load-Function $Adapter 'Invoke-InteractiveUiCapture')
$publisher=Load-Function $Helper 'Publish-UiCaptureEvidence'
Invoke-Expression $publisher
$first=New-UiCapturePaths $Scratch 'interactive-start'
$second=New-UiCapturePaths $Scratch 'interactive-collect'
$third=New-UiCapturePaths $Scratch 'interactive-collect'
if($first.evidence-eq$second.evidence-or$second.evidence-eq$third.evidence){throw 'capture outputs are reused'}
[IO.File]::WriteAllText($first.evidence,'{"stale":true}')
[IO.File]::WriteAllBytes($first.screenshot,[byte[]](1..2000|ForEach-Object{$_%256}))
function Get-CimInstance { return [pscustomobject]@{SessionId=1} }
function Invoke-CimMethod { return [pscustomobject]@{User='fixture';Domain='fixture'} }
function Get-ScheduledTask { return $null }
function New-ScheduledTaskAction { return @{} }
function New-ScheduledTaskPrincipal { return @{} }
function New-ScheduledTaskSettingsSet { return @{} }
function Register-ScheduledTask { }
function Unregister-ScheduledTask { }
function Start-ScheduledTask {
 $script:job=Start-Job -ScriptBlock {
  param($Publish,$Image,$Output)
  $ErrorActionPreference='Stop';Invoke-Expression $Publish;Start-Sleep -Milliseconds 350
  [IO.File]::WriteAllBytes($Image,[byte[]](1..2400|ForEach-Object{($_+13)%256}))
  $e=@{screenshot_path=$Image;screenshot_sha256=(Get-FileHash -LiteralPath $Image).Hash.ToLowerInvariant();action='capture';fresh=$true}
  Publish-UiCaptureEvidence $e $Output
 } -ArgumentList $publisher,$second.screenshot,$second.evidence
}
$clock=[Diagnostics.Stopwatch]::StartNew()
try {
 $text=Invoke-InteractiveUiCapture 'unused-helper' $second.evidence $second.screenshot 'fixture' 'case' 'fixture-vm'
 $e=$text|ConvertFrom-Json
 if($clock.ElapsedMilliseconds-lt300-or$e.fresh-ne$true){throw 'old output satisfied fresh wait'}
 if($e.screenshot_path-ne$second.screenshot-or$e.screenshot_sha256-ne(Get-FileHash -LiteralPath $second.screenshot).Hash.ToLowerInvariant()){throw 'published receipt and PNG mismatch'}
 if([IO.File]::ReadAllText($first.evidence)-ne'{"stale":true}'){throw 'historical evidence mutated'}
 Wait-Job $script:job|Out-Null;Receive-Job $script:job -ErrorAction Stop|Out-Null
 $rejected=$false;try{Publish-UiCaptureEvidence $e $second.evidence}catch{$rejected=$true};if(-not$rejected){throw 'duplicate publication accepted'}
 $e.screenshot_sha256='0'*64;$rejected=$false;try{Publish-UiCaptureEvidence $e $third.evidence}catch{$rejected=$true};if(-not$rejected-or(Test-Path -LiteralPath $third.evidence)){throw 'mismatched pair published'}
 'fresh delayed capture, immutable history, duplicate and byte mismatch rejection PASS'
}finally{if($script:job){Remove-Job $script:job -Force}}
"""
        with tempfile.TemporaryDirectory(prefix="amnezia-capture-") as directory:
            command = Path(directory) / "test.ps1"
            command.write_text(script, encoding="utf-8")
            result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(command), "-Adapter", str(root / "windows_host/hyperv_adapter.ps1"), "-Helper", str(root / "windows_host/hyperv_ui_helper.ps1"), "-Scratch", directory], capture_output=True, text=True, timeout=45)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("byte mismatch rejection PASS", result.stdout)


if __name__ == "__main__":
    unittest.main()
