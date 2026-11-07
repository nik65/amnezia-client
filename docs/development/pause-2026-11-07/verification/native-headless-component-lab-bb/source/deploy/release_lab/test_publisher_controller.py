import tempfile
import json
import unittest
from pathlib import Path
from unittest.mock import patch

try:
    from . import publisher_controller as pc
except ImportError:
    import publisher_controller as pc
ControllerPublisher = pc.ControllerPublisher
PublisherError = pc.PublisherError


class FakeController:
    def __init__(self, root, run):
        self.root = root; self.run = run; self.saved = None
    def get_run(self, run_id):
        return self.run
    def load_state(self):
        return {"runs": {self.run["run_id"]: self.run}}
    def save_state(self, state):
        self.saved = state


class HypervReceiptController:
    def __init__(self, run): self.run = run; self.calls = []
    def get_run(self, run_id): return self.run
    def hyperv_call(self, action, **kwargs):
        self.calls.append((action, kwargs))
        if action == "collect": return {"action":"collect"}
        return self.result


class FakeOps:
    def __init__(self, events, fail=None): self.events = events; self.fail = fail
    def _step(self, name, value):
        self.events.append(name)
        if self.fail == name: raise PublisherError(name + " failed")
        return value
    def start_server(self, run_id): return self._step("server", {"uuid":"server","qmp_socket":"qmp","qga_socket":"qga"})
    def start_child(self, run_id, case_id): return self._step("child", {"vm_id":"vm","parent_sha256":"a"*64,"process_pid":1,"process_uuid":"u","marker":"m"})
    def stage_outer(self, run_id, case_id, artifact): return self._step("stage", {"sha256":artifact["sha256"]})
    def run_outer_reinstall(self, run_id, case_id, artifact): return self._step("reinstall", {"passed":True})
    def seed_lab_profile(self, run_id, case_id, server, nonce): return self._step("seed", {})
    def start_relays(self, run_id, case_id, child, server, nonce): return self._step("relays", {})
    def publish_once(self, run_id, case_id): return self._step("publish", {"passed":True})
    def collect_readback(self, run_id, case_id, server, nonce): return self._step("readback", {"passed":True,"attempt_nonce":nonce,"raw_sources":{},"phase_receipts":{"prepare":{"passed":True,"run_id":run_id,"origin":"guest","transport":"qga"},"commit":{"passed":True,"run_id":run_id,"origin":"guest","transport":"qga"},"finalize":{"passed":True,"run_id":run_id,"origin":"guest","transport":"qga"}}})
    def cleanup(self, run_id, case_id): self.events.append("cleanup"); return {"child_reset":True,"server_reset":True,"relays_stopped":True,"relay_registry_unregistered":True,"ephemeral_key_removed":True}
    def recover_attempt(self, run_id, attempt): self.events.append("recover"); return {"child_reset":True}


class PublisherControllerTests(unittest.TestCase):
    def test_failure_always_runs_cleanup_after_first_phase(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = {"run_id":"r","lane":"release","outer_artifact":{"sha256":"a"*64},"manifest":{"sha256":"b"*64}}
            events=[]; publisher=ControllerPublisher(FakeController(Path(tmp),run), FakeOps(events, fail="seed"))
            with self.assertRaisesRegex(PublisherError, "seed failed"): publisher.run("r")
            self.assertEqual(events, ["server","child","stage","reinstall","relays","seed","cleanup"])

    def test_success_order_creates_controller_validation_after_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = {"run_id":"r","lane":"release","outer_artifact":{"sha256":"a"*64},"manifest":{"sha256":"b"*64}}
            events=[]; publisher=ControllerPublisher(FakeController(Path(tmp),run), FakeOps(events))
            with patch.object(pc, "validate_publication_evidence") as validate, patch.object(publisher, "_evidence", return_value={"ok":True}):
                publisher.run("r")
            self.assertEqual(events, ["server","child","stage","reinstall","relays","seed","publish","readback","cleanup"])
            validate.assert_called_once()

    def test_attempt_ledger_records_child_intent_before_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = {"run_id":"r","lane":"release","outer_artifact":{"sha256":"a"*64},"manifest":{"sha256":"b"*64}}
            events=[]; controller=FakeController(Path(tmp),run)
            publisher=ControllerPublisher(controller, FakeOps(events, fail="child"))
            with self.assertRaisesRegex(PublisherError, "child failed"): publisher.run("r")
            attempt = controller.saved["runs"]["r"]["publication_attempt"]
            self.assertEqual(attempt["state"], "failed-cleaned")
            self.assertEqual(attempt["phase"], "start-child")
            self.assertTrue(attempt["resources"]["child"]["intent"])

    def test_unfinished_attempt_is_recovered_before_new_nonce(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = {"run_id":"r","lane":"release","outer_artifact":{"sha256":"a"*64},"manifest":{"sha256":"b"*64},"publication_attempt":{"schema":1,"controller_created":True,"run_id":"r","case_id":"publisher-clean","attempt_nonce":"c"*48,"state":"active","resources":{"server":{"intent":True},"child":{"intent":True},"relays":{"intent":True},"key":{"intent":False}}}}
            events=[]; publisher=ControllerPublisher(FakeController(Path(tmp),run), FakeOps(events))
            with patch.object(pc, "validate_publication_evidence"), patch.object(publisher, "_evidence", return_value={"ok":True}):
                publisher.run("r")
            self.assertEqual(events[0], "recover")

    def test_windows_receipt_reads_nested_assertion_fields_and_role(self):
        run = {"run_id":"r","candidate_version":"5.0.1.39","baseline_version":"5.0.1.38"}
        controller = HypervReceiptController(run)
        receipt = {"schema":1,"run_id":"r","profile":"windows-x64","case_id":"publisher-clean","action":"reinstall","artifact":"current.exe","artifact_sha256":"a"*64,"artifact_size":123,"artifact_role":"candidate","baseline_version":"5.0.1.38","candidate_version":"5.0.1.39","guest_marker":"amnezia-release-lab:r:windows-x64","guest_marker_readback":"amnezia-release-lab:r:windows-x64\ncase_id=publisher-clean","transport":"hyperv-powershell-direct","origin":"guest","injected":False,"artifact_source":{"transport":"hyperv-powershell-direct","hash_verified":True},"steps":[{"id":"reinstall","passed":True}],"assertion":{"passed":True,"run_id":"r","profile":"windows-x64","action":"reinstall","artifact_sha256":"a"*64,"expected_sha256":"a"*64,"expected_version":"5.0.1.39","installed_version":"5.0.1.39"}}
        controller.result = {"result":{"transport":"hyperv-powershell-direct","origin":"guest","injected":False,"vm_id":"vm","readback":{"receipt":json.dumps(receipt)}}}
        ops = pc.ConcretePublisherOps(controller); ops._child_record={"vm_id":"vm"}
        result = ops.run_outer_reinstall("r", "publisher-clean", {"sha256":"a"*64,"size":123})
        self.assertTrue(result["passed"])
        self.assertEqual(controller.calls[0][1]["ExpectedArtifactRole"], "candidate")
        receipt["artifact_role"] = "baseline"
        controller.result = {"result":{"transport":"hyperv-powershell-direct","origin":"guest","injected":False,"vm_id":"vm","readback":{"receipt":json.dumps(receipt)}}}
        self.assertFalse(ops.run_outer_reinstall("r", "publisher-clean", {"sha256":"a"*64,"size":123})["passed"])

    def test_windows_runner_has_explicit_artifact_role_override(self):
        runner = (Path(__file__).parent / "guest_runners" / "windows-release-lab.ps1").read_text(encoding="utf-8")
        self.assertIn("$ExpectedArtifactRole", runner)
        self.assertIn("$artifactRole = Get-ArtifactRole", runner)
        self.assertIn("ExpectedArtifactRole must be baseline or candidate", runner)


if __name__ == "__main__": unittest.main()
