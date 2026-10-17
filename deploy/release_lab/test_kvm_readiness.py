"""KVM API availability guards; no test creates a VM or mutates a device."""
import errno
import json
from pathlib import Path
import stat
import tempfile
import types
import unittest
from unittest.mock import patch

from deploy.release_lab import lab


class KvmReadinessTests(unittest.TestCase):
    def probe(self, *, opened=42, open_error=None, mode=stat.S_IFCHR | 0o660,
              fstat_error=None, api=12, ioctl_error=None, close_error=None):
        ioctl = types.SimpleNamespace(ioctl=lambda *_: None)
        with patch.object(lab.os, "open", return_value=opened, side_effect=open_error) as opening, \
             patch.object(lab.os, "O_CLOEXEC", 0x80000, create=True), \
             patch.object(lab.os, "O_NOFOLLOW", 0x20000, create=True), \
             patch.object(lab.os, "fstat", return_value=types.SimpleNamespace(st_mode=mode), side_effect=fstat_error), \
             patch.object(lab.os, "close", side_effect=close_error) as closing, \
             patch.object(lab, "fcntl", ioctl), \
             patch.object(ioctl, "ioctl", return_value=api, side_effect=ioctl_error) as querying:
            result = lab.probe_kvm_readiness()
        return result, opening, querying, closing

    def test_api12_character_device_readwrite_same_context(self):
        result, opening, querying, closing = self.probe()
        self.assertTrue(result["ready"])
        self.assertEqual(result["api_version"], 12)
        self.assertEqual(result["path"], "/dev/kvm")
        self.assertEqual(result["uid"], getattr(lab.os, "geteuid", lambda: None)())
        flags = opening.call_args.args[1]
        self.assertEqual(flags & getattr(lab.os, "O_ACCMODE", 3), lab.os.O_RDWR)
        self.assertTrue(flags & 0x80000)
        self.assertTrue(flags & 0x20000)
        querying.assert_called_once_with(42, 0xAE00, 0)
        closing.assert_called_once_with(42)

    def test_open_enodev_eacces_enoent_eloop_fail_without_ioctl_or_close(self):
        for code in (errno.ENODEV, errno.EACCES, errno.ENOENT, errno.ELOOP):
            with self.subTest(code=code):
                result, _, querying, closing = self.probe(open_error=OSError(code, "device unavailable"))
                self.assertFalse(result["ready"])
                self.assertEqual(result["stage"], "open")
                self.assertEqual(result["errno"], code)
                querying.assert_not_called()
                closing.assert_not_called()

    def test_non_character_device_cannot_claim_kvm(self):
        result, _, querying, closing = self.probe(mode=stat.S_IFREG | 0o660)
        self.assertFalse(result["ready"])
        self.assertEqual(result["reason"], "kvm_not_character_device")
        querying.assert_not_called()
        closing.assert_called_once_with(42)

    def test_fstat_error_closes_the_open_descriptor(self):
        result, _, querying, closing = self.probe(fstat_error=OSError(errno.EIO, "bad device"))
        self.assertFalse(result["ready"])
        self.assertEqual(result["stage"], "fstat")
        self.assertEqual(result["errno"], errno.EIO)
        querying.assert_not_called()
        closing.assert_called_once_with(42)

    def test_ioctl_failure_closes_and_reports_errno(self):
        result, _, querying, closing = self.probe(ioctl_error=OSError(errno.ENOTTY, "not KVM"))
        self.assertFalse(result["ready"])
        self.assertEqual(result["stage"], "ioctl")
        self.assertEqual(result["errno"], errno.ENOTTY)
        querying.assert_called_once_with(42, 0xAE00, 0)
        closing.assert_called_once_with(42)

    def test_mismatched_or_noninteger_api_is_not_readiness(self):
        for api in (11, 0, -1, True, "12", b"12"):
            with self.subTest(api=api):
                result, _, _, closing = self.probe(api=api)
                self.assertFalse(result["ready"])
                self.assertEqual(result["reason"], "kvm_api_version_mismatch")
                closing.assert_called_once_with(42)

    def test_close_failure_never_reports_ready(self):
        result, _, _, closing = self.probe(close_error=OSError(errno.EIO, "close failed"))
        self.assertFalse(result["ready"])
        self.assertEqual(result["stage"], "close")
        self.assertEqual(result["errno"], errno.EIO)
        closing.assert_called_once_with(42)

    def test_platform_without_ioctl_is_structured_failure(self):
        with patch.object(lab, "fcntl", None), patch.object(lab.os, "open") as opening:
            result = lab.probe_kvm_readiness()
        self.assertFalse(result["ready"])
        self.assertEqual(result["reason"], "kvm_ioctl_unavailable")
        opening.assert_not_called()

    def test_platform_without_unix_attributes_returns_before_access(self):
        with patch.object(lab, "fcntl", None), patch.object(lab, "os", types.SimpleNamespace()):
            result = lab.probe_kvm_readiness()
        self.assertFalse(result["ready"])
        self.assertEqual(result["reason"], "kvm_ioctl_unavailable")

    def test_missing_required_open_flags_fails_before_open(self):
        for missing in ("O_CLOEXEC", "O_NOFOLLOW"):
            with self.subTest(missing=missing), patch.object(lab, "fcntl", types.SimpleNamespace()), \
                 patch.object(lab.os, missing, 0, create=True), patch.object(lab.os, "open") as opening:
                result = lab.probe_kvm_readiness()
            self.assertFalse(result["ready"])
            self.assertEqual(result["reason"], "kvm_required_open_flags_unavailable")
            opening.assert_not_called()

    def test_qemu_start_rejects_before_recovery_or_launch(self):
        failed = {"ready": False, "stage": "open", "errno": errno.ENODEV}
        run = {"dry_run": False, "windows_backend": "qemu"}
        with tempfile.TemporaryDirectory() as temp:
            controller = lab.LabController(Path(temp), test_mode=True)
            with patch.object(controller, "get_run", return_value=run), \
                 patch.object(lab, "validate_migration_wan"), \
                 patch.object(lab, "probe_kvm_readiness", return_value=failed), \
                 patch.object(controller, "_recover_qemu_spawn_intent") as recovery, \
                 patch.object(lab.subprocess, "Popen") as launch:
                with self.assertRaisesRegex(lab.LabError, "KVM"):
                    controller.start("failed-run", "linux-x64-gui")
            recovery.assert_not_called()
            launch.assert_not_called()
            self.assertFalse((Path(temp) / "runs").exists())
            self.assertFalse(controller.state_path.exists())

    def test_owned_dead_guest_reset_does_not_require_kvm(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            profile = root / "runs" / "failed-run" / "linux-x64-gui"
            profile.mkdir(parents=True)
            overlay = profile / "overlay.qcow2"
            overlay.write_bytes(b"owned disk")
            (profile / ".owned-overlay.json").write_text(json.dumps({
                "run_id": "failed-run", "profile": "linux-x64-gui", "overlay": str(overlay)}))
            run = {"profiles": {"linux-x64-gui": {"vm": None, "status": "created"}}}
            controller = lab.LabController(root, test_mode=True)
            with patch.object(controller, "get_run", return_value=run), \
                 patch.object(controller, "load_state", return_value={"runs": {"failed-run": run}}), \
                 patch.object(controller, "save_state"), \
                 patch.object(controller, "_recover_qemu_spawn_intent"), \
                 patch.object(lab, "probe_kvm_readiness", side_effect=AssertionError("cleanup must not probe KVM")):
                controller.reset("failed-run", "linux-x64-gui")
            self.assertFalse(overlay.exists())

    def test_preflight_uses_probe_and_test_mode_does_not_invent_device_pass(self):
        failed = {"ready": False, "path": "/dev/kvm", "stage": "open", "errno": errno.ENODEV, "uid": 999}
        with tempfile.TemporaryDirectory() as temp, patch.object(lab, "probe_kvm_readiness", return_value=failed) as probing:
            result = lab.LabController(Path(temp), test_mode=True).preflight(["linux-x64-gui"])
        probing.assert_called_once_with()
        self.assertEqual(result["checks"]["kvm"], failed)
        self.assertFalse(result["ready"])

    def test_windows_preflight_requires_kvm_only_for_qemu_backend(self):
        failed = {"ready": False, "stage": "open", "errno": errno.ENODEV}
        for backend in ("qemu", "hyperv"):
            with self.subTest(backend=backend), tempfile.TemporaryDirectory() as temp:
                controller = lab.LabController(Path(temp), test_mode=True, windows_backend=backend)
                with patch.object(lab, "probe_kvm_readiness", return_value=failed), \
                     patch.object(lab, "golden_readiness", return_value=(True, "sealed")), \
                     patch.object(controller, "hyperv_call", return_value={"ready": True}):
                    result = controller.preflight(["windows-x64"])
                self.assertEqual(result["ready"], backend == "hyperv")


if __name__ == "__main__":
    unittest.main()
