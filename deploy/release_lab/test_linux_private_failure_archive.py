"""Private failure archival fixtures; no guest/app/key operations."""
import base64
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import Mock
from unittest.mock import patch

from .lab import LabController, QgaGuestExecutionError
from .linux_live_acquisition import LinuxLiveProducer


@unittest.skipUnless(os.name == "posix", "Linux descriptor-relative private archive")
class PrivateFailureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.parent = self.root / "runs/run-1/linux-headless-x64"
        self.parent.mkdir(parents=True)
        self.controller = LabController(self.root)
        self.producer = LinuxLiveProducer(self.controller, "run-1", target="linux-headless")
        self.producer._start_attempted = True
        self.controller.get_run = Mock(return_value={"profiles": {"linux-headless-x64": {
            "vm": {"pid": 123}, "evidence_archive": {"already": True}}}})
        self.controller.archive_guest_evidence = Mock()
        self.controller.owned_vm = Mock()
        self.producer._wait_for_boot = Mock()
        self.response = {"return": {"exitcode": 7, "out-data": base64.b64encode(b"private stdout").decode(),
                                    "err-data": base64.b64encode(b"private stderr").decode()}}
        self.failure = QgaGuestExecutionError(self.response)
        self.producer._acquire_once = Mock(side_effect=self.failure)

    def test_original_nonzero_response_private_before_cleanup_even_with_ordinary_archive(self):
        def reset(*args):
            archive = self.producer._private_failure_archive
            raw = (archive / "response.private.json").read_bytes()
            self.assertEqual(json.loads(raw), self.response)
            metadata = json.loads((archive / "metadata.private.json").read_bytes())
            self.assertEqual(metadata["original_sha256"], hashlib.sha256(raw).hexdigest())
            self.assertFalse(metadata["truncated"])
            self.assertTrue(metadata["complete_response"])
            self.assertFalse(metadata["release_pass"])
        self.controller.reset = Mock(side_effect=reset)
        with self.assertRaises(QgaGuestExecutionError) as raised:
            self.producer.acquire(object())
        self.assertIs(raised.exception, self.failure)
        self.controller.reset.assert_called_once()
        self.controller.archive_guest_evidence.assert_not_called()
        self.assertNotIn("private stdout", str(self.failure))
        self.assertNotIn("private stderr", repr(self.failure))
        self.assertFalse(getattr(self.failure, "__notes__", []))

    def test_oversize_preserves_bounded_prefix_and_explicit_incomplete_status(self):
        response = {"return": {"exitcode": 1, "out-data": "a" * (2 * 1024 * 1024)}}
        failure = QgaGuestExecutionError(response)
        self.producer._archive_private_qga_failure(failure, "linux-headless-x64")
        archive = self.producer._private_failure_archive
        raw = (archive / "response.private.json").read_bytes()
        metadata = json.loads((archive / "metadata.private.json").read_bytes())
        self.assertEqual(len(raw), 1024 * 1024)
        self.assertTrue(metadata["truncated"])
        self.assertFalse(metadata["complete_response"])
        self.assertEqual(metadata["captured_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertGreater(metadata["original_size"], len(raw))

    @unittest.skipUnless(os.name == "posix", "POSIX private permission semantics")
    def test_permissions_are_owner_only_even_with_permissive_umask(self):
        previous = os.umask(0)
        try:
            self.producer._archive_private_qga_failure(self.failure, "linux-headless-x64")
        finally:
            os.umask(previous)
        archive = self.producer._private_failure_archive
        self.assertEqual(stat.S_IMODE(archive.stat().st_mode), 0o700)
        for entry in archive.iterdir():
            self.assertEqual(stat.S_IMODE(entry.stat().st_mode), 0o600)
            self.assertEqual(entry.stat().st_uid, os.getuid())

    def test_archive_failure_keeps_original_error_and_cleanup(self):
        self.producer._archive_private_qga_failure = Mock(side_effect=OSError("secret content"))
        self.controller.reset = Mock()
        with self.assertRaises(QgaGuestExecutionError) as raised:
            self.producer.acquire(object())
        self.assertIs(raised.exception, self.failure)
        self.controller.reset.assert_called_once()
        self.assertEqual(self.failure.__notes__, ["private QGA failure archive unavailable: OSError"])

    def test_archive_interrupt_keeps_original_error_and_cleanup(self):
        self.producer._archive_private_qga_failure = Mock(side_effect=KeyboardInterrupt())
        self.controller.reset = Mock()
        with self.assertRaises(QgaGuestExecutionError) as raised:
            self.producer.acquire(object())
        self.assertIs(raised.exception, self.failure)
        self.controller.reset.assert_called_once()
        self.assertEqual(self.failure.__notes__, ["private QGA failure archive unavailable: KeyboardInterrupt"])

    def test_directory_swap_to_symlink_cannot_redirect_private_writes(self):
        outside = self.root / "outside"
        outside.mkdir()
        original_open = os.open
        swapped = []
        def raced_open(path, flags, *args, **kwargs):
            if isinstance(path, str) and path.startswith("private-qga-failure-") and not swapped:
                directory = self.parent / path
                directory.rename(self.parent / (path + "-original"))
                directory.symlink_to(outside, target_is_directory=True)
                swapped.append(True)
            return original_open(path, flags, *args, **kwargs)
        with patch("deploy.release_lab.linux_live_acquisition.os.open", side_effect=raced_open):
            with self.assertRaises(OSError):
                self.producer._archive_private_qga_failure(self.failure, "linux-headless-x64")
        self.assertTrue(swapped)
        self.assertFalse(list(outside.iterdir()))

    def test_wrapped_typed_failure_is_preserved(self):
        wrapped = RuntimeError("semantic failed")
        wrapped.__cause__ = self.failure
        self.producer._archive_private_qga_failure(wrapped, "linux-headless-x64")
        self.assertTrue((self.producer._private_failure_archive / "response.private.json").is_file())

    def test_success_creates_no_failure_archive_or_extra_cleanup(self):
        result = {"actual": "success"}
        self.producer._acquire_once = Mock(return_value=result)
        self.controller.reset = Mock()
        self.assertIs(self.producer.acquire(object()), result)
        self.controller.reset.assert_not_called()
        self.assertFalse(list(self.parent.glob("private-qga-failure-*")))

    def test_untyped_failure_does_not_create_private_archive(self):
        self.producer._archive_private_qga_failure(RuntimeError("untyped"), "linux-headless-x64")
        self.assertFalse(list(self.parent.glob("private-qga-failure-*")))


if __name__ == "__main__":
    unittest.main()
