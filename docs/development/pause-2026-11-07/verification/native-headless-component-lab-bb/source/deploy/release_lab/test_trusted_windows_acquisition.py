"""Focused trust-boundary tests; no VM or installed application is accessed."""
import base64
import copy
import json
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from .trusted_windows_acquisition import WindowsLiveSession
from .trusted_acquisition_export import TrustedAcquisitionError


class WindowsSessionTests(unittest.TestCase):
    def setUp(self):
        self.session = WindowsLiveSession.__new__(WindowsLiveSession)
        self.session.run_id = "owned-run"
        self.session.expected = {"case-one", "outer-interactive"}
        self.session._captures, self.session._cleanup = {}, {}
        self.artifact = {"sha256": "a" * 64, "size": 123}
        self.run = {"profiles": {"windows-x64": {"hyperv_cases": {
            "case-one": {"vm_id": "owned-vm", "parent_sha256": "b" * 64}},
            "case_receipts": [{"case_id": "case-one", "service_health": {"ok": True}}]}},
            "baseline_version": "5.0.3.13", "candidate_version": "5.0.3.14"}
        self.session.controller = SimpleNamespace(get_run=Mock(return_value=self.run), hyperv_call=Mock())
        self.session._verify_inputs = Mock()
        self.raw = {"challenge": "c" * 64, "run_id": "owned-run", "case_id": "case-one",
                    "guest_artifact_sha256": "a" * 64, "guest_artifact_size": 123,
                    "receipt": '{"ok": true}',
                    "receipt_bytes_b64": base64.b64encode(b'{"ok": true}').decode()}
        self.result = {"transport": "hyperv-powershell-direct", "origin": "guest", "injected": False,
                       "vm_id": "owned-vm", "parent_sha256": "b" * 64, "readback": self.raw}
        self.session.controller.hyperv_call.return_value = {"result": self.result}

    def capture(self):
        with patch("deploy.release_lab.lab.windows_case_specs", return_value={"case-one": [("candidate", self.artifact)]}), \
                patch("deploy.release_lab.lab.validate_receipt") as validate, \
                patch("deploy.release_lab.trusted_windows_acquisition.secrets.token_hex", return_value="c" * 64):
            self.session.capture_windows_case("case-one")
            return validate

    def test_fresh_nonce_and_original_bytes_reach_existing_semantic_validator(self):
        validate = self.capture()
        validate.assert_called_once()
        self.assertEqual(self.session.controller.hyperv_call.call_args.kwargs["AttemptNonce"], "c" * 64)
        self.assertIn("case-one", self.session._captures)

    def test_identity_and_challenge_changes_fail_before_semantic_validation(self):
        for field, value in (("challenge", "d" * 64), ("run_id", "foreign"), ("case_id", "other"),
                             ("guest_artifact_sha256", "d" * 64), ("guest_artifact_size", 124)):
            original = copy.deepcopy(self.raw)
            self.raw[field] = value
            with self.subTest(field=field), self.assertRaises(TrustedAcquisitionError):
                self.capture()
            self.raw.clear()
            self.raw.update(original)
        self.assertFalse(self.session._captures)

    def test_changed_original_bytes_rejected(self):
        self.raw["receipt_bytes_b64"] = base64.b64encode(b'{"ok": false}').decode()
        with self.assertRaisesRegex(TrustedAcquisitionError, "bytes/readback"):
            self.capture()

    def test_capsule_failure_prevents_transport(self):
        self.session._verify_inputs.side_effect = TrustedAcquisitionError("source changed")
        with self.assertRaisesRegex(TrustedAcquisitionError, "source changed"):
            self.capture()
        self.session.controller.hyperv_call.assert_not_called()

    def test_cleanup_requires_capture_and_unchanged_parent(self):
        cleanup = {"run_id": "owned-run", "removed_child": True,
                   "parent_sha256_before": "b" * 64, "parent_sha256_after": "b" * 64}
        with self.assertRaises(TrustedAcquisitionError):
            self.session.record_windows_cleanup("case-one", cleanup)
        self.capture()
        cleanup["parent_sha256_after"] = "d" * 64
        with self.assertRaises(TrustedAcquisitionError):
            self.session.record_windows_cleanup("case-one", cleanup)
        cleanup["parent_sha256_after"] = "b" * 64
        self.session.record_windows_cleanup("case-one", cleanup)
        with self.assertRaises(TrustedAcquisitionError):
            self.session.record_windows_cleanup("case-one", cleanup)

    def test_missing_case_or_cleanup_cannot_finish(self):
        self.capture()
        with self.assertRaisesRegex(TrustedAcquisitionError, "complete live Windows matrix"):
            self.session.finish()


if __name__ == "__main__":
    unittest.main()
