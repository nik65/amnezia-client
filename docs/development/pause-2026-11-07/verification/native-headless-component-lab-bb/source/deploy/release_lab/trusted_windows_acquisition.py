"""In-process live Windows matrix producer. No receipt-import entrypoint."""
from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path
import secrets

from .android_real_device_acquisition import file_record
from .trusted_acquisition_export import TrustedAcquisitionError, canonical, utc_now, utc_text


class WindowsLiveSession:
    def __init__(self, controller, run_id, context):
        from .windows_credential_preparation import PreparedWindowsController
        from .lab import windows_case_specs
        if type(controller) is not PreparedWindowsController or controller.dry_run or controller.test_mode:
            raise TrustedAcquisitionError("reviewed production Windows controller required")
        controller.assert_mutation_context()
        if controller._mutation_lock_fd is None or controller._mutation_lock_depth <= 0:
            raise TrustedAcquisitionError("live controller mutation lock required")
        controller.verify_acquisition_provenance(run_id)
        self.controller, self.run_id, self.context = controller, run_id, context
        run = controller.get_run(run_id)
        self.expected = set(windows_case_specs(run)) | {"outer-interactive"}
        self._captures, self._cleanup = {}, {}
        self.started = utc_text(utc_now())
        profile = run.get("profiles", {}).get("windows-x64", {})
        if profile.get("case_receipts") or profile.get("interactive_receipt") or profile.get("hyperv_cases"):
            raise TrustedAcquisitionError("trusted Windows acquisition requires a fresh matrix run")
        self._verify_inputs()

    def _verify_inputs(self):
        self.context.verify()
        self.controller.verify_acquisition_provenance(self.run_id)
        run = self.controller.get_run(self.run_id)
        if run.get("dry_run") or run.get("test_mode") or run.get("candidate_version") != self.context.version:
            raise TrustedAcquisitionError("Windows run is diagnostic/test or wrong version")
        for field, actual in (("manifest", self.context.manifest), ("outer_artifact", self.context.outer)):
            planned = run.get(field) or {}
            if (planned.get("sha256"), planned.get("size")) != (actual["sha256"], actual["size"]):
                raise TrustedAcquisitionError("Windows run release binding differs")
        for platform in self.context.manifest_payload["platforms"]:
            planned = run.get("artifacts", {}).get(platform) or {}
            actual = self.context.candidate(platform)
            if (planned.get("sha256"), planned.get("size")) != (actual["sha256"], actual["size"]):
                raise TrustedAcquisitionError("Windows run full artifact closure differs")
        for name in ("profile_records", "runner_records", "hyperv_records", "semantic_helper_records", "credential_preparation_capsule"):
            records = run.get(name)
            if not isinstance(records, dict) or not records:
                raise TrustedAcquisitionError("planned Windows source capsule missing")
            for record in records.values():
                if file_record(record["path"]) != record:
                    raise TrustedAcquisitionError("Windows source/helper changed after planning")

    def capture_windows_case(self, case_id):
        from .lab import validate_receipt, windows_case_specs
        if case_id not in self.expected or case_id in self._captures:
            raise TrustedAcquisitionError("unknown/duplicate live Windows case")
        self._verify_inputs()
        run = self.controller.get_run(self.run_id)
        profile = run["profiles"]["windows-x64"]
        case = (profile.get("hyperv_cases") or {}).get(case_id) or {}
        expected = run["outer_artifact"] if case_id == "outer-interactive" else windows_case_specs(run)[case_id][-1][1]
        nonce = secrets.token_hex(32)
        captured = self.controller.hyperv_call("collect", run_id=self.run_id, CaseId=case_id,
                                                credential=True, AttemptNonce=nonce)
        result = captured.get("result") or {}
        raw = result.get("readback") or {}
        if (result.get("transport") != "hyperv-powershell-direct" or result.get("origin") != "guest"
                or result.get("injected") is not False or result.get("vm_id") != case.get("vm_id")
                or result.get("parent_sha256") != case.get("parent_sha256")
                or raw.get("challenge") != nonce or raw.get("run_id") != self.run_id or raw.get("case_id") != case_id
                or raw.get("guest_artifact_sha256") != expected["sha256"] or raw.get("guest_artifact_size") != expected["size"]):
            raise TrustedAcquisitionError("live Windows challenge/guest/artifact binding mismatch")
        try:
            original = base64.b64decode(raw["receipt_bytes_b64"], validate=True)
            if not 0 < len(original) <= 512 * 1024:
                raise ValueError("receipt bounds")
            receipt = json.loads(original)
        except (ValueError, KeyError, TypeError) as error:
            raise TrustedAcquisitionError("original live Windows receipt missing") from error
        if original.decode("utf-8-sig") != raw.get("receipt"):
            raise TrustedAcquisitionError("Windows original bytes/readback differ")
        validate_receipt(receipt, run_id=self.run_id, profile_id="windows-x64", artifact=expected,
                         case_id=case_id, baseline_version=run["baseline_version"], candidate_version=run["candidate_version"], expected_role="candidate")
        stored = profile.get("interactive_receipt") if case_id == "outer-interactive" else next(
            (item.get("service_health") for item in profile.get("case_receipts", []) if item.get("case_id") == case_id), None)
        # Interactive controller adds verified screenshots to its receipt; the
        # original guest receipt remains the source for overlapping fields.
        if not isinstance(stored, dict) or any(stored.get(key) != value for key, value in receipt.items()):
            raise TrustedAcquisitionError("fresh guest receipt differs from controller step result")
        self._captures[case_id] = copy.deepcopy(captured)

    def record_windows_cleanup(self, case_id, result):
        if case_id not in self._captures or case_id in self._cleanup:
            raise TrustedAcquisitionError("cleanup lacks a unique live case capture")
        proof = self._captures[case_id]["result"]
        if (not isinstance(result, dict) or result.get("run_id") != self.run_id
                or result.get("removed_child") is not True
                or result.get("parent_sha256_before") != proof["parent_sha256"]
                or result.get("parent_sha256_after") != proof["parent_sha256"]):
            raise TrustedAcquisitionError("Windows owned cleanup proof differs")
        self._cleanup[case_id] = copy.deepcopy(result)

    def finish(self):
        from .lab import build_hyperv_matrix_aggregation, validate_hyperv_interactive_archives
        if set(self._captures) != self.expected or set(self._cleanup) != self.expected:
            raise TrustedAcquisitionError("complete live Windows matrix/cleanup required")
        self._verify_inputs()
        run = self.controller.get_run(self.run_id)
        profile = run["profiles"]["windows-x64"]
        matrix = build_hyperv_matrix_aggregation(run, profile, self.controller.root)
        validate_hyperv_interactive_archives(self.controller.root, profile.get("interactive_receipt") or {})
        provenance = {record["path"]: record for name in ("profile_records", "runner_records", "hyperv_records", "semantic_helper_records", "credential_preparation_capsule")
                      for record in run[name].values()}
        own = file_record(Path(__file__).absolute())
        provenance[own["path"]] = own
        return {"target": "windows", "runId": self.run_id, "profileId": "windows-x64",
                "startedAt": self.started, "completedAt": utc_text(utc_now()),
                "rawCapture": canonical({"live_cases": self._captures, "matrix": matrix,
                                           "interactive": profile["interactive_receipt"]}),
                "cleanupCapture": canonical(self._cleanup),
                "semantics": {"matrix": True, "interactive": True, "cleanup": True},
                "provenance": list(provenance.values())}


class WindowsLiveProducer:
    def __init__(self, controller, run_id):
        self.controller, self.run_id = controller, run_id
        self._used = False

    def acquire(self, context):
        if self._used:
            raise TrustedAcquisitionError("live producer is single-use")
        self._used = True
        controller = self.controller
        with controller.mutation_session("trusted-windows-acquisition"):
            session = WindowsLiveSession(controller, self.run_id, context)
            if getattr(controller, "_trusted_acquisition_session", None) is not None:
                raise TrustedAcquisitionError("another Windows acquisition session is active")
            controller._trusted_acquisition_session = session
            try:
                controller.run_steps(self.run_id, "windows-x64")
                controller.collect(self.run_id, "windows-x64")
                controller.archive_guest_evidence(self.run_id, "windows-x64")
                controller.reset(self.run_id, "windows-x64")
                return session.finish()
            finally:
                controller._trusted_acquisition_session = None
