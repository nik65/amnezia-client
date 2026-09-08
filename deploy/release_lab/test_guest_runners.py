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
        self.assertIn("Start-Process -FilePath $artifact -ArgumentList $arguments -PassThru -Wait", self.windows)
        self.assertIn("$process.ExitCode -ne 0", self.windows)
        self.assertNotIn("Get-Service -Name 'AmneziaVPN'", self.windows)
        self.assertIn("C:\\ProgramData\\AmneziaLab\\runs\\$RunId\\receipt.json", self.windows)

    def test_windows_requires_planned_artifact_identity_and_separates_system_lane(self):
        self.assertIn("ExpectedSha256 is required for installer operations", self.windows)
        self.assertIn("ExpectedVersion is required for installer operations", self.windows)
        self.assertIn("qga-system-unattended-smoke", self.windows)
        self.assertIn("interactive-qmp-coordinated", self.windows)
        self.assertIn("interactive token evidence is required", self.windows)
        self.assertIn("schtasks.exe", self.windows)
        self.assertIn("interactive-start", self.windows)

    def test_linux_uses_supported_qif_and_headless_entrypoints(self):
        self.assertIn("--accept-messages --accept-licenses --confirm-command install AmneziaSelfHostedUpdate=true", self.linux)
        self.assertNotIn("--root /opt/amnezia-release-lab", self.linux)
        self.assertIn("install_headless.sh", self.linux)
        self.assertIn("amneziad.service", self.linux)
        self.assertIn("status\\\":\\\"PENDING", self.linux)
        self.assertIn("headless upgrade requires the signed provisioning bundle", self.linux)

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


if __name__ == "__main__":
    unittest.main()
