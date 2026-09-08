import json
import subprocess
import unittest
from pathlib import Path
from xml.etree import ElementTree


ROOT = Path(__file__).resolve().parent
BACKEND = ROOT / "windows_host" / "hyperv_backend.ps1"
PROVISION = ROOT / "provision_windows_guest.ps1"
HELPER_TEMPLATE = ROOT / "guest_templates" / "windows11" / "hyperv-seed-helper.ps1.template"


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
        self.assertIn("Microsoft.HyperV.PowerShell.OnOffState is On=0, Off=1", self.source)
        self.assertIn("BootType", self.source)
        self.assertIn("$device.Id", self.source)
        self.assertIn("Get-WindowsBootManagerEvidence", self.source)
        self.assertIn("partition_guid", self.source)
        self.assertIn("firmware_partition_guid", self.source)
        self.assertIn("first_boot.boot_type -ne 1", self.source)
        self.assertIn("first_boot.mapped_kind -ne 'owned-vhdx'", self.source)
        self.assertIn("canonical Microsoft Windows Boot Manager device path", self.source)
        self.assertNotIn(".Description", self.source)
        self.assertIn("virtual_capacity_bytes", self.source)
        self.assertIn("parent_chain", self.source)
        self.assertIn("automatic_checkpoints_enabled", self.source)
        self.assertIn("windows_display_version", self.source)
        self.assertIn("Get-Service -Name 'vmicvmsession','vmicshutdown','vmicguestinterface'", self.source)
        self.assertIn("labadmin profile is missing", self.source)
        self.assertIn("vmicvmsession is missing or not Running", self.source)
        self.assertIn("Windows Disk 0 is missing", self.source)
        self.assertIn("golden-os-bootstrap", self.source)
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

    def test_runtime_accepts_hyperv_administrators_without_dism_probe(self):
        self.assertIn("S-1-5-32-578", self.source)
        self.assertIn("Is-HyperVAdministrator", self.source)
        self.assertIn("Get-VMHost -ErrorAction Stop", self.source)
        self.assertIn("Get-VM -ErrorAction Stop", self.source)
        self.assertNotIn("Get-WindowsOptionalFeature -Online", self.source)
        self.assertNotIn('requires an administrator token"', self.source)

    def test_media_copy_path_and_partial_cleanup_are_guarded(self):
        self.assertIn("Copy-VerifiedInput", self.source)
        self.assertIn("Get-FileEvidence ([string]$Marker.iso.path)", self.source)
        self.assertIn("state root is non-empty without a verified owned marker", self.source)
        self.assertIn("cleanup incomplete", self.source)
        self.assertIn("Remove-VMDvdDrive -VMDvdDrive $dvd", self.source)
        self.assertIn("Set-VMFirmware -VM $stopped -FirstBootDevice $vhdDrives[0]", self.source)
        self.assertIn("Assert-ReceiptPath", self.source)

    def test_finalize_removes_owned_dvd_resource_objects(self):
        self.assertIn("Get-VMDvdDrive -VM $stopped -ErrorAction Stop", self.source)
        self.assertIn("Remove-VMDvdDrive -VMDvdDrive $dvd", self.source)
        self.assertIn("$dvd.VMId", self.source)
        self.assertIn("ControllerLocation", self.source)
        self.assertIn("finalize requires a uniquely slotted subset of the two owned DVD drives", self.source)
        self.assertIn("$dvds.Count -gt 2", self.source)
        self.assertNotIn("Remove-VMDvdDrive -VM $stopped", self.source)

    def test_mutating_cmdlets_use_object_parameter_sets(self):
        self.assertIn("Set-VMHardDiskDrive -VMHardDiskDrive $drive -Path $base", self.source)
        self.assertNotIn("Set-VMHardDiskDrive -VM $Vm", self.source)
        self.assertIn("Remove-VMNetworkAdapter -VMNetworkAdapter $adapter", self.source)
        self.assertIn("Remove-VMSnapshot -VMSnapshot $snapshot", self.source)

    def test_guest_readiness_requires_redacted_windows_license_evidence(self):
        self.assertIn("SoftwareLicensingProduct", self.source)
        self.assertIn("55c92734-d682-4d71-983e-d6ec3f16059f", self.source)
        self.assertIn("PartialProductKey", self.source)
        self.assertIn("LicenseStatus", self.source)
        self.assertIn("GracePeriodRemaining", self.source)
        self.assertIn("EditionID", self.source)
        self.assertIn("OperatingSystemSKU", self.source)
        self.assertIn("LicenseFamily", self.source)
        self.assertIn("LicenseIsAddon", self.source)
        self.assertIn("license = $licenseEvidence", self.source)
        self.assertIn("Windows installed SKU is not licensed with positive evaluation grace remaining", self.source)
        self.assertIn("other_licensed_channels_grace_zero_allowed", self.source)
        self.assertIn("ForEach-Object { [int64]$_['evaluation_grace_minutes'] } | Measure-Object -Maximum", self.source)
        self.assertNotIn("Measure-Object -Property evaluation_grace_minutes", self.source)
        self.assertNotIn("Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.PartialProductKey) }", self.source)
        self.assertNotIn("product_id =", self.source)
        self.assertNotIn("product_key =", self.source)

    def test_hyperv_seed_and_iso_name_contract(self):
        provision = PROVISION.read_text(encoding="utf-8")
        helper = HELPER_TEMPLATE.read_text(encoding="utf-8")
        self.assertIn('helperName = "hyperv-seed-$seedNonce.ps1"', provision)
        self.assertIn('hyperv-seed-helper.ps1.template', provision)
        self.assertIn('helperTemplate.Replace', provision)
        self.assertIn("'profile=windows-x64'", helper)
        self.assertIn("'backend=hyperv'", helper)
        self.assertIn("'bootstrap_id=__BOOTSTRAP_ID__'", helper)
        self.assertIn("'seed_nonce=__SEED_NONCE__'", helper)
        self.assertNotIn('install-qga', helper.lower())
        max_bootstrap = 'b' * 96
        nonce = 'f' * 32
        launcher = f'cmd /c "for %D in (D E F G H I J K L M N O P Q R S T U V W X Y Z) do if exist %D:\\hyperv-seed-{nonce}.ps1 powershell.exe -NoProfile -ExecutionPolicy Bypass -File %D:\\hyperv-seed-{nonce}.ps1"'
        command_xml = ElementTree.fromstring(f'<CommandLine>{launcher}</CommandLine>')
        self.assertLessEqual(len(command_xml.text), 256)
        self.assertIn('CommandLine exceeds the Windows 1024-character limit', provision)
        self.assertIn('preferred 256-character limit', provision)
        self.assertIn('genisoimage -quiet -J -R -volid AMNEZIALAB', provision)
        self.assertIn('isoinfo -J -f', provision)
        self.assertIn('Autounattend\\.xml(?:;1)?', provision)
        self.assertIn('.txt(?:;1)?', provision)
        self.assertIn('nic = if ($Transport -eq \'hyperv\') { "none" } else { "e1000" }', provision)
        self.assertNotIn('backend-hyperv.txt', provision)

    def test_generated_helper_is_ps51_parseable_without_execution(self):
        helper = HELPER_TEMPLATE.read_text(encoding="utf-8")
        rendered = helper.replace('__SEED_NONCE__', 'f' * 32).replace('__BOOTSTRAP_ID__', 'golden-' + 'b' * 89)
        helper_path = ROOT / 'guest_templates' / 'windows11' / '.test-rendered-hyperv-helper.ps1'
        try:
            helper_path.write_text(rendered, encoding='utf-8')
            command = (
                "$tokens=$null;$errors=$null;"
                f"[System.Management.Automation.Language.Parser]::ParseFile('{helper_path}',[ref]$tokens,[ref]$errors)|Out-Null;"
                "if($errors.Count){$errors|%%{$_.Message};exit 1}"
            )
            result = subprocess.run(
                ['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', command],
                check=False, capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        finally:
            if helper_path.exists():
                helper_path.unlink()


if __name__ == "__main__":
    unittest.main()
