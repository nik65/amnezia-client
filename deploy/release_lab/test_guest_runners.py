import os
import json
import shutil
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent


class GuestRunnerContractTests(unittest.TestCase):
    def setUp(self):
        self.windows = (ROOT / "guest_runners" / "windows-release-lab.ps1").read_text(encoding="utf-8")
        self.linux = (ROOT / "guest_runners" / "linux-release-lab.sh").read_text(encoding="utf-8")

    def test_windows_uses_real_service_and_exit_status(self):
        self.assertIn("AmneziaVPN-service", self.windows)
        self.assertIn("function Invoke-CapturedProcess", self.windows)
        self.assertIn("RedirectStandardOutput = $true", self.windows)
        self.assertIn("'--verbose'", self.windows)
        self.assertIn("$proc.WaitForExit($TimeoutMilliseconds)", self.windows)
        self.assertIn("Stop-ProcessTree $pidValue", self.windows)
        self.assertIn("installer exceeded the bounded 15 minute timeout", self.windows)
        self.assertIn("installer produced no fresh post-install log", self.windows)
        self.assertIn("$isOuterCase = $CaseId -like 'outer-*'", self.windows)
        self.assertIn("installed AmneziaVPN service is not running", self.windows)
        self.assertIn("$assertion.installer_completion", self.windows)
        self.assertIn("$installerExitCode -ne 0", self.windows)
        self.assertIn("$proc.Refresh()", self.windows)
        self.assertIn("$null -eq $rawExitCode", self.windows)
        self.assertNotIn("Get-Service -Name 'AmneziaVPN'", self.windows)
        self.assertIn("C:\\ProgramData\\AmneziaLab\\runs\\$RunId\\receipt.json", self.windows)

    @unittest.skipUnless(os.name == "nt" and shutil.which("powershell.exe"), "requires Windows PowerShell 5.1")
    def test_windows_captured_process_helper_is_behavioral_and_fail_closed(self):
        start = self.windows.index("function Stop-ProcessTree")
        end = self.windows.index("function Write-PendingInstallerRequest")
        functions = "function Fail([string] $Message) { throw $Message }\n" + self.windows[start:end]
        script = functions + r'''
$root=Join-Path $env:TEMP ('amnezia-capture-'+[guid]::NewGuid().ToString('n'));New-Item -ItemType Directory $root|Out-Null
try {
  $exitScript=Join-Path $root 'exit7.cmd';[IO.File]::WriteAllText($exitScript,"@echo off`r`necho OUT`r`necho ERR 1>&2`r`nexit /b 7`r`n")
  $timeoutScript=Join-Path $root 'timeout.cmd';[IO.File]::WriteAllText($timeoutScript,"@echo off`r`nping -n 10 127.0.0.1 >nul`r`n")
  $holdScript=Join-Path $root 'hold.cmd';[IO.File]::WriteAllText($holdScript,"@echo off`r`nstart `"`" /b ping -n 2 127.0.0.1`r`nexit /b 0`r`n")
  $r=Invoke-CapturedProcess $exitScript @() $root 5000
  if($r.exit_code-ne 7-or$r.stdout-notmatch'OUT'-or$r.stderr-notmatch'ERR'){throw 'capture mismatch'}
  try{Invoke-CapturedProcess 'Z:\definitely-missing-amnezia.exe' @() $root 500|Out-Null;throw 'failed launch accepted'}catch{if($_.Exception.Message-eq'failed launch accepted'){throw}}
  try{Invoke-CapturedProcess $timeoutScript @() $root 100|Out-Null;throw 'timeout accepted'}catch{if($_.Exception.Message-eq'timeout accepted'){throw}}
  try{Invoke-CapturedProcess $holdScript @() $root 150|Out-Null;throw 'held pipe accepted'}catch{if($_.Exception.Message-eq'held pipe accepted'){throw}}
  'CAPTURE_BEHAVIOR_OK'
}finally{Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue}
'''
        completed = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script], text=True, capture_output=True, timeout=20)
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        self.assertIn("CAPTURE_BEHAVIOR_OK", completed.stdout)

    def test_windows_requires_planned_artifact_identity_and_separates_system_lane(self):
        self.assertIn("ExpectedSha256 is required for installer operations", self.windows)
        self.assertIn("ExpectedVersion is required for installer operations", self.windows)
        self.assertIn("qga-system-unattended-smoke", self.windows)
        self.assertIn("interactive-qmp-coordinated", self.windows)
        self.assertIn("interactive token evidence is required", self.windows)
        self.assertIn("Register-ScheduledTask", self.windows)
        self.assertIn("New-ScheduledTaskPrincipal", self.windows)
        self.assertIn("Start-ScheduledTask", self.windows)
        self.assertIn("interactive-start", self.windows)

    def test_windows_receipt_projection_handles_native_ordered_objects(self):
        self.assertIn("Get-MapValue", self.windows)
        self.assertIn("safeAssertion", self.windows)
        self.assertIn("$name -eq 'execution_context'", self.windows)
        self.assertIn("$safeContext", self.windows)
        script = r'''
$ErrorActionPreference = 'Stop'
$tmp = Join-Path ([IO.Path]::GetTempPath()) ('amnezia-receipt-' + [guid]::NewGuid().ToString('N') + '.jsonl')
Set-Content -LiteralPath $tmp -Value @('{"phase":"start"}','{"phase":"finish"}') -Encoding UTF8
function Get-MapValue([object] $Object, [string] $Name) { if ($Object -is [Collections.IDictionary] -and $Object.Contains($Name)) { return $Object[$Name] }; $p=$Object.PSObject.Properties[$Name]; if ($null -ne $p) { return $p.Value }; return $null }
$prefix = @(Get-Content -LiteralPath $tmp -TotalCount 20 | ForEach-Object { [string]$_ })
$assertion = [ordered]@{ passed=$true; artifact_sha256=('a'*64); expected_version='5.0.1.39'; installed_version='5.0.1.39'; service=[ordered]@{present=$true;state='Running';process_id=123}; installer_userdata=[ordered]@{fresh=$true;latest='installer.jsonl';prefix=$prefix}; steps=@([ordered]@{id='reinstall';passed=$true}) }
$safe = [ordered]@{ passed=[bool](Get-MapValue $assertion 'passed'); artifact_sha256=[string](Get-MapValue $assertion 'artifact_sha256'); expected_version=[string](Get-MapValue $assertion 'expected_version'); installed_version=[string](Get-MapValue $assertion 'installed_version'); service=[ordered]@{present=[bool](Get-MapValue (Get-MapValue $assertion 'service') 'present');state=[string](Get-MapValue (Get-MapValue $assertion 'service') 'state');process_id=[int](Get-MapValue (Get-MapValue $assertion 'service') 'process_id')}; installer_userdata=[ordered]@{fresh=[bool](Get-MapValue (Get-MapValue $assertion 'installer_userdata') 'fresh');latest=[string](Get-MapValue (Get-MapValue $assertion 'installer_userdata') 'latest')} }
$sw=[Diagnostics.Stopwatch]::StartNew();$json=([ordered]@{schema=1;artifact_sha256=$safe.artifact_sha256;artifact_size=123;baseline_version='5.0.1.38';candidate_version='5.0.1.39';steps=@([ordered]@{id='reinstall';passed=$true});assertion=$safe}|ConvertTo-Json -Depth 12);$sw.Stop();Remove-Item -LiteralPath $tmp -Force
if($sw.Elapsed.TotalSeconds -ge 5 -or $json.Length -ge 100000 -or $safe.artifact_sha256.Length -ne 64 -or $safe.passed -ne $true -or $safe.service.state -ne 'Running' -or $safe.installer_userdata.fresh -ne $true){throw 'receipt projection contract failed'}
[ordered]@{seconds=$sw.Elapsed.TotalSeconds;json_length=$json.Length;prefix_type=$prefix[0].GetType().FullName;artifact_sha256_length=$safe.artifact_sha256.Length}|ConvertTo-Json -Compress
'''
        result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script], check=False, capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout)["artifact_sha256_length"], 64)

    def test_linux_uses_supported_qif_and_headless_entrypoints(self):
        self.assertIn("--accept-messages --accept-licenses --confirm-command install AmneziaSelfHostedUpdate=true", self.linux)
        self.assertNotIn("--root /opt/amnezia-release-lab", self.linux)
        self.assertIn("install_headless.sh", self.linux)
        self.assertIn("amneziad.service", self.linux)
        self.assertIn("status\\\":\\\"PENDING", self.linux)
        self.assertIn("headless upgrade requires the signed provisioning bundle", self.linux)
        self.assertIn("--baseline-version", self.linux)
        self.assertIn("--candidate-version", self.linux)
        self.assertIn("/tmp/amnezia-release-lab-marker", self.linux)
        self.assertIn("receipt path is outside the owned run/profile directory", self.linux)
        self.assertIn('amnezia-release-lab:${run_id}:${profile}', self.linux)
        self.assertNotIn('[[', self.linux)
        self.assertNotIn('< <(', self.linux)
        self.assertIn('artifact_size', self.linux)
        self.assertIn('artifact_role', self.linux)
        self.assertIn('artifact_source', self.linux)
        self.assertIn('observed_baseline_version', self.linux)
        self.assertIn('failure_log=$log', self.linux)

    def test_both_runners_require_explicit_run_and_hash_identity(self):
        for runner in (self.windows, self.linux):
            self.assertIn("ExpectedSha256", runner) if "ExpectedSha256" in runner else self.assertIn("--expected-sha256", runner)
            self.assertIn("guest_marker", runner)
            self.assertIn("transport", runner)
            self.assertIn("origin", runner)
            self.assertIn("injected", runner)
            self.assertIn("artifact_sha256", runner)
            self.assertIn("observed_at", runner)

    def test_linux_shell_parses(self):
        if os.name == "nt" or shutil.which("sh") is None:
            self.skipTest("POSIX sh syntax test requires a native Linux/WSL shell")
        result = subprocess.run(
            ["sh", "-n", str(ROOT / "guest_runners" / "linux-release-lab.sh")],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_linux_step_evidence_is_immutable_and_incarnation_bound(self):
        for token in (
            "steps_dir = path.parent / 'steps'",
            "os.O_EXCL",
            "raw_assertion",
            "guest_binding",
            "duplicate immutable guest step",
            "guest step order conflict",
            "short immutable failure step write",
        ):
            self.assertIn(token, self.linux)
        self.assertNotIn("steps_path.write_text", self.linux)

    def test_linux_service_health_raw_assertion_binds_tested_artifact_hash(self):
        branch = self.linux.split('if [ "$action" = service-health ]; then', 1)[1].split(
            'if [ "$action" = reinstall ]', 1
        )[0]
        self.assertIn('BEFORE="$before_hash"', branch)
        self.assertIn("'artifact_sha256_before':os.environ['BEFORE']", branch)
        self.assertIn('emit_receipt PASS "$assertion"', branch)

    def test_server_router_readiness_is_atomic_and_pinned(self):
        template = (ROOT / "guest_templates" / "server-router" / "user-data").read_text(encoding="utf-8")
        self.assertIn("docker.io/library/busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662", template)
        self.assertIn("runuser -u lab -- sudo -n true", template)
        self.assertIn("mktemp /var/lib/amnezia-lab/.READY.XXXXXX", template)
        self.assertIn("mv -f \"$tmp\" /var/lib/amnezia-lab/READY", template)


if __name__ == "__main__":
    unittest.main()
