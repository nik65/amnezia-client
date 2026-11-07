"""Lifecycle failure tests do not execute guest or host product operations."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from deploy.release_lab.lab import LabController
from deploy.release_lab.linux_live_acquisition import LinuxLiveProducer
from deploy.release_lab.trusted_acquisition_export import TrustedAcquisitionError


class LinuxProducerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.controller = LabController(Path(self.temp.name))
        self.producer = LinuxLiveProducer(self.controller, "run-1", target="linux-headless")
        self.vm = {"pid": 123}
        self.controller.get_run = Mock(return_value={"profiles": {"linux-headless-x64": {"vm": self.vm}}})
        self.controller.owned_vm = Mock(return_value=self.vm)
        self.controller.archive_guest_evidence = Mock()
        self.controller.reset = Mock()
        self.producer._wait_for_boot = Mock(return_value=self.vm)
        self.primary = RuntimeError("real semantic failure")
        self.producer._acquire_once = Mock(side_effect=self.primary)
        self.producer._start_attempted = True

    def test_semantic_failure_archives_and_resets_only_proven_owned_guest(self):
        with self.assertRaisesRegex(RuntimeError, "real semantic failure"):
            self.producer.acquire(object())
        self.controller.archive_guest_evidence.assert_called_once_with("run-1", "linux-headless-x64", error=self.primary)
        self.controller.reset.assert_called_once_with("run-1", "linux-headless-x64")
        self.assertEqual(self.controller._mutation_lock_depth, 0)

    def test_lost_ownership_preserves_guest_and_primary_error(self):
        self.producer._wait_for_boot.side_effect = RuntimeError("PID replaced")
        with self.assertRaisesRegex(RuntimeError, "real semantic failure"):
            self.producer.acquire(object())
        self.controller.reset.assert_not_called()
        self.controller.archive_guest_evidence.assert_not_called()
        self.assertTrue(any("preserve guest" in note for note in self.primary.__notes__))

    def test_archive_failure_does_not_skip_owned_cleanup(self):
        self.controller.archive_guest_evidence.side_effect = OSError("archive failed")
        with self.assertRaisesRegex(RuntimeError, "real semantic failure"):
            self.producer.acquire(object())
        self.controller.reset.assert_called_once()
        self.assertTrue(any("archive unavailable" in note for note in self.primary.__notes__))

    def test_previously_archived_original_receipt_is_preserved(self):
        self.controller.get_run.return_value["profiles"]["linux-headless-x64"]["evidence_archive"] = "/owned/original.json"
        with self.assertRaises(RuntimeError): self.producer.acquire(object())
        self.controller.archive_guest_evidence.assert_not_called()
        self.controller.reset.assert_called_once()

    def test_cleanup_failure_keeps_primary_and_reports_preservation(self):
        self.controller.reset.side_effect = RuntimeError("cleanup failed")
        with self.assertRaisesRegex(RuntimeError, "real semantic failure"):
            self.producer.acquire(object())
        self.assertTrue(any("cleanup incomplete" in note for note in self.primary.__notes__))

    def test_no_guest_metadata_means_no_cleanup_operation(self):
        self.controller.get_run.return_value["profiles"]["linux-headless-x64"]["vm"] = None
        with self.assertRaises(RuntimeError): self.producer.acquire(object())
        self.controller.reset.assert_not_called()

    def test_arbitrary_controller_rejected_before_any_method_call(self):
        other = Mock()
        producer = LinuxLiveProducer(other, "run-1", target="linux-gui")
        with self.assertRaises(TrustedAcquisitionError): producer.acquire(object())
        other.mutation_session.assert_not_called()

    def test_freshness_rejection_never_resets_preexisting_guest(self):
        self.producer._start_attempted = False
        with self.assertRaisesRegex(RuntimeError, "real semantic failure"):
            self.producer.acquire(object())
        self.controller.reset.assert_not_called()

    def test_start_failure_after_spawn_intent_uses_canonical_guarded_recovery(self):
        self.controller.get_run.return_value["profiles"]["linux-headless-x64"]["vm"] = None
        path = self.controller._qemu_spawn_intent_path("run-1", "linux-headless-x64")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('{"owned fixture":true}')
        with self.assertRaisesRegex(RuntimeError, "real semantic failure"):
            self.producer.acquire(object())
        self.controller.reset.assert_called_once_with("run-1", "linux-headless-x64")


if __name__ == "__main__": unittest.main()
