import json
import os
import struct
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from unittest.mock import Mock
from types import SimpleNamespace

from deploy.release_lab import windows_credential_preparation as prep


def words(text, top=400):
    return [{"text": word, "left": 375, "top": top, "width": 60, "height": 12}
            for word in text.split()]


FORM = words("labadmin Password") + words("New password", 452) + words("Confirm password", 504)


class FakeController:
    def __init__(self, root):
        self.root = root

    def assert_mutation_context(self):
        pass

    def verify_preparation_capsule(self, run_id):
        pass


class SimulatedGuest(prep.GuestPreparation):
    def __init__(self, root, screens, existing_valid=False):
        super().__init__(FakeController(root), "run", "thin-clean",
                         {"vm_id": "owned-vm", "parent_sha256": "a" * 64})
        self.sequence, self.calls = list(screens), []
        self.existing_valid, self.did_change = existing_valid, False

    def call(self, action, **private):
        self.calls.append(action)
        if action == "authenticate":
            return {"authenticated": self.existing_valid or self.did_change,
                    "invalid_credential": not (self.existing_valid or self.did_change)}
        if action == "change":
            self.did_change = True
        return {}

    def capture(self, phase):
        return self.sequence.pop(0) if self.sequence else ("unknown", [])

    def expect(self, expected, phase, timeout=25):
        state, content = self.capture(phase)
        if state != expected:
            raise prep.lab.LabError("unrecognized screen")
        return content


class CredentialPreparationTests(unittest.TestCase):
    def test_screen_states_reject_password_error_and_unknown_accounts(self):
        self.assertEqual(prep.classify(words("labadmin Your password has expired and must be changed")), "expired")
        self.assertEqual(prep.classify(words("labadmin Your password has been changed")), "changed")
        self.assertEqual(prep.classify(FORM), "change")
        self.assertEqual(prep.classify(words("labadmin Password")), "login")
        self.assertEqual(prep.classify(words("labadmin The password is incorrect")), "unknown")
        self.assertEqual(prep.classify(words("Administrator Password")), "unknown")

    def test_change_geometry_clears_old_and_both_new_fields(self):
        value = prep.field_geometry(FORM, True)
        self.assertEqual(value, {"x": 495, "old_y": 406, "new_y": 458, "confirm_y": 510})
        with self.assertRaises(prep.lab.LabError):
            prep.field_geometry(FORM + words("New"), True)
        with self.assertRaises(prep.lab.LabError):
            prep.field_geometry(words("New", 10) + words("Confirm", 504), True)

    def test_unknown_login_does_not_type_any_credential(self):
        with tempfile.TemporaryDirectory() as root:
            guest = SimulatedGuest(Path(root), [("unknown", []), ("unknown", [])])
            with self.assertRaises(prep.lab.LabError):
                guest.prepare("known-old-password")
            self.assertNotIn("login", guest.calls)
            self.assertNotIn("change", guest.calls)

    def test_incorrect_password_never_triggers_change(self):
        with tempfile.TemporaryDirectory() as root:
            guest = SimulatedGuest(Path(root), [("login", words("labadmin Password")), ("unknown", [])])
            with self.assertRaises(prep.lab.LabError):
                guest.prepare("known-old-password")
            self.assertIn("login", guest.calls)
            self.assertNotIn("change", guest.calls)
            self.assertFalse((Path(root) / "credentials").exists())

    def test_console_control_characters_are_rejected_before_any_keyboard_action(self):
        with tempfile.TemporaryDirectory() as root:
            guest = SimulatedGuest(Path(root), [("login", words("labadmin Password"))])
            with self.assertRaisesRegex(prep.lab.LabError, "without control keys"):
                guest.prepare("known-password\nEnter")
            self.assertEqual(guest.calls, ["authenticate"])

    def test_existing_authentication_skips_console_and_private_file(self):
        with tempfile.TemporaryDirectory() as root:
            guest = SimulatedGuest(Path(root), [], existing_valid=True)
            path, receipt = guest.prepare("known-old-password")
            self.assertIsNone(path)
            self.assertFalse(receipt["changed"])
            self.assertEqual(guest.calls, ["authenticate"])

    def test_expired_flow_requires_confirmation_then_new_authentication(self):
        with tempfile.TemporaryDirectory() as root:
            guest = SimulatedGuest(Path(root), [
                ("login", words("labadmin Password")), ("expired", []),
                ("change", FORM), ("changed", []),
            ])
            with patch.object(prep, "read_credential", lambda path: path.read_text()):
                path, receipt = guest.prepare("known-old-password")
            self.assertEqual(guest.calls, ["authenticate", "login", "enter", "change", "enter", "authenticate"])
            self.assertTrue(receipt["changed"])
            self.assertFalse(receipt["release_passed"])
            if os.name == "posix":
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            text = json.dumps(receipt)
            self.assertNotIn("known-old-password", text)
            self.assertNotIn(path.read_text(), text)

    def test_malformed_thumbnail_is_rejected(self):
        with self.assertRaises(prep.lab.LabError):
            prep.rgb565_bmp(b"short")

    def test_focused_ocr_uses_reviewed_area_and_preserves_luminance(self):
        raw = bytearray(prep.WIDTH * prep.HEIGHT * 2)
        x, y = prep.OCR_CROP[0], prep.OCR_CROP[3] - 1
        offset = (y * prep.WIDTH + x) * 2
        raw[offset:offset + 2] = b"\xff\xff"
        value = prep.rgb565_bmp(bytes(raw), focused=True)
        self.assertEqual(struct.unpack_from("<ii", value, 18), (420, 275))
        self.assertEqual(value[54:57], b"\xff\xff\xff")
        self.assertEqual(value[57:60], b"\x00\x00\x00")

    def test_total_timeout_fails_before_launching_helper(self):
        with tempfile.TemporaryDirectory() as root:
            guest = prep.GuestPreparation(FakeController(Path(root)), "run", "thin-clean",
                                          {"vm_id": "vm", "parent_sha256": "a" * 64})
            guest.deadline = time.monotonic() - 1
            with patch.object(prep.subprocess, "run") as process:
                with self.assertRaisesRegex(prep.lab.LabError, "bounded deadline"):
                    guest.call("authenticate", credential="not-a-real-secret")
                process.assert_not_called()

    def test_capture_failure_still_invokes_real_canonical_reset(self):
        controller = object.__new__(prep.PreparedWindowsController)
        controller._active_credential_path = None
        controller._prepared_credentials = {}
        session = Mock()
        session.capture_windows_case.side_effect = prep.lab.LabError("capture failed")
        controller._trusted_acquisition_session = session
        controller.get_run = Mock(return_value={"profiles": {"windows-x64": {
            "case_receipts": [{"case_id": "thin-clean"}]}}})
        with patch.object(prep.BASE_CONTROLLER, "hyperv_call", return_value={"removed_child": True}) as reset:
            with self.assertRaisesRegex(prep.lab.LabError, "reset completed"):
                controller.hyperv_call("reset", run_id="run", CaseId="thin-clean")
            reset.assert_called_once_with("reset", run_id="run", credential=False, CaseId="thin-clean")
        session.record_windows_cleanup.assert_not_called()

    def test_failed_case_never_requests_live_pass_capture(self):
        controller = object.__new__(prep.PreparedWindowsController)
        controller._active_credential_path = None
        controller._prepared_credentials = {}
        controller._trusted_acquisition_session = Mock()
        controller.get_run = Mock(return_value={"profiles": {"windows-x64": {"case_receipts": []}}})
        with patch.object(prep.BASE_CONTROLLER, "hyperv_call", return_value={"removed_child": True}):
            controller.hyperv_call("reset", run_id="run", CaseId="thin-clean")
        controller._trusted_acquisition_session.capture_windows_case.assert_not_called()
        controller._trusted_acquisition_session.record_windows_cleanup.assert_not_called()

    def test_foreign_vm_response_is_rejected_and_secret_is_not_an_argument(self):
        with tempfile.TemporaryDirectory() as root:
            guest = prep.GuestPreparation(FakeController(Path(root)), "run", "thin-clean",
                                          {"vm_id": "owned", "parent_sha256": "a" * 64})
            reply = {"vm_id": "foreign", "run_id": "run", "case_id": "thin-clean",
                     "parent_sha256": "a" * 64, "action": "authenticate", "installer_started": False}
            with patch.object(prep.lab, "windows_path_for_wsl", return_value="C:/reviewed-helper.ps1"), \
                 patch.object(prep.subprocess, "run", return_value=SimpleNamespace(
                     returncode=0, stdout=json.dumps(reply).encode())) as process:
                with self.assertRaisesRegex(prep.lab.LabError, "binding differs"):
                    guest.call("authenticate", credential="private-known-credential")
                arguments = process.call_args.args[0]
                self.assertNotIn("private-known-credential", " ".join(arguments))

    def test_helper_error_cannot_disclose_private_input_or_stderr(self):
        with tempfile.TemporaryDirectory() as root:
            guest = prep.GuestPreparation(FakeController(Path(root)), "run", "thin-clean",
                                          {"vm_id": "owned", "parent_sha256": "a" * 64})
            with patch.object(prep.lab, "windows_path_for_wsl", return_value="C:/reviewed-helper.ps1"), \
                 patch.object(prep.subprocess, "run", return_value=SimpleNamespace(
                     returncode=1, stdout=b"", stderr=b"private-known-credential")):
                with self.assertRaises(prep.lab.LabError) as caught:
                    guest.call("authenticate", credential="private-known-credential")
            self.assertNotIn("private-known-credential", str(caught.exception))

    def test_changed_source_capsule_prevents_any_helper_process(self):
        with tempfile.TemporaryDirectory() as root:
            controller = FakeController(Path(root))
            controller.verify_preparation_capsule = Mock(side_effect=prep.lab.LabError("changed source"))
            guest = prep.GuestPreparation(controller, "run", "thin-clean",
                                          {"vm_id": "owned", "parent_sha256": "a" * 64})
            with patch.object(prep.subprocess, "run") as process:
                with self.assertRaisesRegex(prep.lab.LabError, "changed source"):
                    guest.call("login", credential="private-known-credential")
                process.assert_not_called()


if __name__ == "__main__":
    unittest.main()
