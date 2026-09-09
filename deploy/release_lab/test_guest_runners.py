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
        self.assertIn("Start-Process -FilePath $artifact -ArgumentList $arguments -PassThru -WindowStyle Hidden", self.windows)
        self.assertIn("$process.WaitForExit(900000)", self.windows)
        self.assertIn("Stop-ProcessTree $process.Id", self.windows)
        self.assertIn("installer exceeded the bounded 15 minute timeout", self.windows)
        self.assertIn("installer produced no fresh post-install log", self.windows)
        self.assertIn("$process.ExitCode -ne 0", self.windows)
        self.assertNotIn("Get-Service -Name 'AmneziaVPN'", self.windows)
        self.assertIn("C:\\ProgramData\\AmneziaLab\\runs\\$RunId\\receipt.json", self.windows)

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
        result = subprocess.run(
            ["sh", "-n", str(ROOT / "guest_runners" / "linux-release-lab.sh")],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_server_router_readiness_is_atomic_and_pinned(self):
        template = (ROOT / "guest_templates" / "server-router" / "user-data").read_text(encoding="utf-8")
        self.assertIn("docker.io/library/busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662", template)
        self.assertIn("runuser -u lab -- sudo -n true", template)
        self.assertIn("mktemp /var/lib/amnezia-lab/.READY.XXXXXX", template)
        self.assertIn("mv -f \"$tmp\" /var/lib/amnezia-lab/READY", template)


if __name__ == "__main__":
    unittest.main()
