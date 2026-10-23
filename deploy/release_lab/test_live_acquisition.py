"""Negative-boundary tests; synthetic transports never issue release approval."""
import base64
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from deploy.release_lab import live_acquisition as acquisition
from deploy.release_lab.lab import LabController, QmpClient


class LiveAcquisitionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.file = self.root / "candidate"
        self.file.write_bytes(b"candidate")
        record = {"path": str(self.file), "size": 9, "sha256": hashlib.sha256(b"candidate").hexdigest()}
        self.run = {"manifest": record, "outer_artifact": record,
                    "artifacts": {"linux-x64": record}, "baseline_artifacts": {"linux-x64": record},
                    "runner_records": {"linux-x64-gui": record}, "semantic_helper_records": {"helper": record}}
        self.vm = {"pid": 123, "uuid": "owned-uuid", "proc_start_time": "1234", "qga_socket": "/owned/qga"}
        self.controller = LabController(self.root)
        self.raw = b'{"partial":true}'
        identity = patch("deploy.release_lab.lab.assert_lab_identity")
        identity.start()
        self.addCleanup(identity.stop)

    def response(self, _exe, args, **kwargs):
        self.assertEqual(_exe, "/usr/bin/python3")
        self.assertEqual(args[:2], ["-c", acquisition.LINUX_CAPTURE])
        self.assertEqual(kwargs, {"timeout": 30})
        run, profile, nonce = args[2:]
        self.payload = {"nonce": nonce, "run_id": run, "profile": profile,
                        "path": f"/run/amnezia-release-lab/{run}/{profile}/receipt.json",
                        "sha256": hashlib.sha256(self.raw).hexdigest(), "size": len(self.raw),
                        "bytes_b64": base64.b64encode(self.raw).decode()}
        return {"exitcode": 0, "stdout": json.dumps(self.payload)}

    def acquire(self, response=None, binding=None):
        with self.controller.mutation_session("unit-test"), \
             patch.object(self.controller, "get_run", return_value=self.run), \
             patch.object(self.controller, "owned_vm", side_effect=binding or [self.vm, self.vm]), \
             patch("deploy.release_lab.lab.QgaClient.guest_exec_wait", side_effect=response or self.response):
            return acquisition.acquire_linux_receipt(self.controller, "run-1", "linux-x64-gui")

    def test_direct_acquisition_preserves_raw_bytes_without_accepting_partial_receipt(self):
        result = self.acquire()
        self.assertEqual(result["state"], "acquired-not-accepted")
        self.assertEqual(result["raw_receipt"], self.raw)
        self.assertNotIn("passed", result)
        self.assertNotIn("signature", result)
        self.assertIn("complete-platform-matrix", result["requires"])

    def test_fresh_random_challenge_each_acquisition(self):
        self.assertNotEqual(self.acquire()["challenge"], self.acquire()["challenge"])

    def test_replayed_response_is_rejected(self):
        first = self.acquire()
        def replay(exe, args, **kwargs):
            result = self.response(exe, args, **kwargs)
            self.payload["nonce"] = first["challenge"]
            result["stdout"] = json.dumps(self.payload)
            return result
        with self.assertRaisesRegex(acquisition.AcquisitionError, "challenge"):
            self.acquire(replay)

    def test_live_ownership_change_rejects_capture(self):
        with self.assertRaisesRegex(acquisition.AcquisitionError, "binding changed"):
            self.acquire(binding=[self.vm, {**self.vm, "proc_start_time": "reused"}])

    def test_candidate_changed_during_capture_rejected(self):
        def mutate(*args, **kwargs):
            result = self.response(*args, **kwargs)
            self.file.write_bytes(b"different")
            return result
        with self.assertRaisesRegex(acquisition.AcquisitionError, "bytes changed"):
            self.acquire(mutate)

    def test_wrong_transport_exit_rejected(self):
        with self.assertRaisesRegex(acquisition.AcquisitionError, "capture failed"):
            self.acquire(lambda *args, **kwargs: {"exitcode": True, "stdout": "{}"})

    def test_response_tampering_rejected(self):
        for field, value in (("size", True), ("sha256", "0" * 64), ("path", "/unowned"), ("bytes_b64", "!")):
            def tamper(exe, args, **kwargs):
                result = self.response(exe, args, **kwargs)
                self.payload[field] = value
                result["stdout"] = json.dumps(self.payload)
                return result
            with self.subTest(field=field), self.assertRaises(acquisition.AcquisitionError):
                self.acquire(tamper)

    def test_duplicate_response_keys_rejected(self):
        with self.assertRaisesRegex(acquisition.AcquisitionError, "duplicate"):
            acquisition._capture_response('{"nonce":"a","nonce":"b"}', "a", "run-1", "linux-x64-gui")

    def test_test_controller_rejected_before_transport(self):
        for mode in ("dry_run", "test_mode"):
            setattr(self.controller, mode, True)
            with self.subTest(mode=mode), self.assertRaisesRegex(acquisition.AcquisitionError, "production controller"):
                acquisition.acquire_linux_receipt(self.controller, "run-1", "linux-x64-gui")
            setattr(self.controller, mode, False)

    def test_missing_lock_rejected_before_transport(self):
        with self.assertRaisesRegex(acquisition.AcquisitionError, "mutation lock"):
            acquisition.acquire_linux_receipt(self.controller, "run-1", "linux-x64-gui")

    def test_android_and_path_traversal_run_rejected(self):
        with self.controller.mutation_session("unit-test"):
            for run, profile in (("../escape", "linux-x64-gui"), ("run-1", "android-arm64-v8a")):
                with self.subTest(profile=profile), self.assertRaises(acquisition.AcquisitionError):
                    acquisition.acquire_linux_receipt(self.controller, run, profile)

    def test_missing_planned_closure_rejected(self):
        del self.run["semantic_helper_records"]
        with self.assertRaisesRegex(acquisition.AcquisitionError, "closure missing"):
            self.acquire()

    def test_changed_controller_run_rejected(self):
        def change(*args, **kwargs):
            result = self.response(*args, **kwargs)
            self.run["candidate_version"] = "changed"
            return result
        with self.assertRaisesRegex(acquisition.AcquisitionError, "binding changed"):
            self.acquire(change)

    def test_slow_capture_rejected(self):
        with patch.object(acquisition.time, "monotonic", side_effect=[0, 36]), \
             self.assertRaisesRegex(acquisition.AcquisitionError, "freshness"):
            self.acquire()

    def test_oversized_capture_rejected_before_decoding(self):
        with self.assertRaisesRegex(acquisition.AcquisitionError, "response bounds"):
            acquisition._capture_response("x" * (acquisition.MAX_RESPONSE_BYTES + 1), "n", "run-1", "linux-x64-gui")

    def test_maximum_receipt_fits_actual_double_base64_qga_transport(self):
        self.raw = b"x" * acquisition.MAX_RECEIPT_BYTES
        response = self.response("/usr/bin/python3", ["-c", acquisition.LINUX_CAPTURE, "run-1", "linux-x64-gui", "n" * 64], timeout=30)
        raw_response = response["stdout"]
        acquisition._capture_response(raw_response, "n" * 64, "run-1", "linux-x64-gui")
        wire = (json.dumps({"return": {"exited": True, "exitcode": 0,
                    "out-data": base64.b64encode(raw_response.encode()).decode()}}) + "\n").encode()
        self.assertLess(len(wire), 1024 * 1024)
        class Connection:
            def __init__(self, data): self.data = data
            def recv(self, count):
                chunk, self.data = self.data[:count], self.data[count:]
                return chunk
        parsed = QmpClient._read_json(Connection(wire))
        self.assertTrue(parsed["return"]["exited"])


if __name__ == "__main__":
    unittest.main()
