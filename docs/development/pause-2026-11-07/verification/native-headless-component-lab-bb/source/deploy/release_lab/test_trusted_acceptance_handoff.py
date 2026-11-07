"""Disposable signature/filesystem fixtures; never touch installed Amnezia."""
import base64
from pathlib import Path
import unittest
from unittest.mock import patch

from deploy.release_lab import trusted_acceptance_handoff as handoff
from deploy.release_lab import trusted_acquisition_export as authority
from deploy.release_lab import test_trusted_acquisition_export as fixtures


class HandoffTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.TrustedExportTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root, self.context = self.fixture.root, self.fixture.context

    def approval(self):
        exports = [self.fixture.envelope(target) for target in authority.PRODUCERS]
        def sign(_key, data): return base64.b64encode(self.fixture.key.sign(data)).decode()
        with patch.object(authority.make_manifest, "verify_public_key_matches_private"), \
             patch.object(authority.make_manifest, "verify_payload_signature"), \
             patch.object(authority.make_manifest, "sign_payload", side_effect=sign):
            value = authority.issue_full_acceptance(context=self.context, exports=exports, private_key="disposable-test-key")
        (self.context.bundle / "release-acceptance.json").write_bytes(authority.canonical(value))
        return value

    def test_genuine_client_approval_verified_without_private_key(self):
        value = self.approval()
        payload = authority.verify_full_acceptance(value, context=self.context)
        self.assertEqual(payload["version"], "5.0.3.14")

    def test_unsigned_status_is_not_approval(self):
        with self.assertRaises(authority.TrustedAcquisitionError):
            authority.verify_full_acceptance({"approvalIssued": True}, context=self.context)

    def test_prepare_copy_only_script_never_launches_app_installer_or_vpn(self):
        self.approval()
        destination = self.root / "manual-copy.ps1"
        result = handoff.prepare_copy_script(self.context, expected_client_sha256="a" * 64,
                    destination=destination, python_path=Path("C:/Python313/python.exe"))
        text = destination.read_text(encoding="utf-8-sig")
        self.assertIn("#Requires -RunAsAdministrator", text)
        self.assertIn("'verify-installed'", text)
        self.assertIn("'--copy-approval'", text)
        for forbidden in ("Start-Process", "Stop-Process", "taskkill", "netsh", "Restart-Service", "Stop-Service"):
            self.assertNotIn(forbidden, text)
        self.assertEqual(result["path"], str(destination))

    def test_missing_approval_does_not_create_handoff(self):
        destination = self.root / "manual-copy.ps1"
        with self.assertRaises(Exception):
            handoff.prepare_copy_script(self.context, expected_client_sha256="a" * 64,
                        destination=destination, python_path=Path("C:/Python313/python.exe"))
        self.assertFalse(destination.exists())

    def test_handoff_no_overwrite(self):
        path = self.root / "existing"
        path.write_bytes(b"preserve")
        with self.assertRaises(authority.TrustedAcquisitionError): handoff.write_new(path, b"replace")
        self.assertEqual(path.read_bytes(), b"preserve")

    def test_duplicate_json_refused(self):
        path = self.root / "duplicate.json"
        path.write_bytes(b'{"status":"pending","status":"PASS"}')
        with self.assertRaises(authority.TrustedAcquisitionError): handoff.read_json(path, 1024)

    def test_wrong_installed_directory_cannot_be_written(self):
        with patch.object(handoff, "file_record") as file, self.assertRaises(authority.TrustedAcquisitionError):
            handoff.verify_installed(self.context, installed_root="C:/unrelated", expected_client_sha256="a" * 64, copy_approval=True)
        file.assert_not_called()


if __name__ == "__main__": unittest.main()
