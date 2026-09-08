import json
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent
BACKEND = ROOT / "windows_host" / "hyperv_backend.ps1"


class HyperVBackendContractTests(unittest.TestCase):
    def setUp(self):
        self.source = BACKEND.read_text(encoding="utf-8")

    def test_powershell_51_parser_accepts_backend(self):
        command = (
            "$tokens=$null;$errors=$null;"
            f"[System.Management.Automation.Language.Parser]::ParseFile("
            f"'{BACKEND}',[ref]$tokens,[ref]$errors)|Out-Null;"
            "if($errors.Count){$errors|%%{$_.Message};exit 1}"
        )
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_mock_probe_contract_rejects_false_pass(self):
        result = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-File",
                str(ROOT / "windows_host" / "test_hyperv_backend.ps1"),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("MOCK_HYPERV_PROBE_CONTRACT_OK", result.stdout)

    def test_plan_is_read_only_and_has_probe_schema(self):
        result = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-File",
                str(BACKEND),
                "-Action",
                "plan",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        plan = json.loads(result.stdout)
        self.assertEqual(plan["backend"], "hyperv")
        self.assertEqual(plan["transport"], "PowerShell Direct via VMId")
        self.assertFalse(plan["release_passed"])
        self.assertFalse(plan["product_verified"])
        self.assertIn("no feature enable or reboot", plan["host_mutations"])

    def test_lifecycle_uses_owned_object_and_vm_id(self):
        self.assertIn("Start-VM -VM $owned", self.source)
        self.assertIn("Stop-VM -VM $owned", self.source)
        self.assertIn("New-PSSession -VMId ([guid]$Vm.Id)", self.source)
        self.assertNotIn("Start-VM -Name", self.source)
        self.assertNotIn("Stop-VM -Name", self.source)
        self.assertNotIn("New-PSSession -VMName", self.source)

    def test_readback_and_fail_closed_receipt_contract(self):
        for field in (
            "generation",
            "secure_boot_enabled",
            "secure_boot_template",
            "virtual_tpm",
            "key_protector_present",
            "network_adapter_count",
            "vhdx",
            "media",
        ):
            self.assertIn(field, self.source)
        self.assertIn("type = 'os-readiness-probe'", self.source)
        self.assertIn("Get-VMSecurity -VM $Vm", self.source)
        self.assertNotIn("Get-VMTPM", self.source)
        self.assertIn("configuration_readback_before", self.source)
        self.assertIn("configuration_readback_after", self.source)
        self.assertIn("must have exactly one VHDX", self.source)
        self.assertIn("first-boot readback does not select", self.source)
        self.assertIn("release_passed = $false", self.source)
        self.assertIn("product_verified = $false", self.source)
        self.assertIn("guest_marker_trust = 'untrusted-mutable-guest-marker'", self.source)

    def test_media_copy_path_and_partial_cleanup_are_guarded(self):
        self.assertIn("Copy-VerifiedInput", self.source)
        self.assertIn("Get-FileEvidence ([string]$Marker.iso.path)", self.source)
        self.assertIn("state root is non-empty without a verified owned marker", self.source)
        self.assertIn("cleanup incomplete", self.source)
        self.assertIn("Remove-VMDvdDrive -VM $stopped", self.source)
        self.assertIn("Set-VMFirmware -VM $stopped -FirstBootDevice $vhdDrives[0]", self.source)
        self.assertIn("Assert-ReceiptPath", self.source)


if __name__ == "__main__":
    unittest.main()
