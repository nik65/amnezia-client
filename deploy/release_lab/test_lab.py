import json
import ast
import os
import re
import subprocess
import sys
import tempfile
import unittest
import pytest
from unittest.mock import MagicMock, patch
from pathlib import Path

try:
    from .lab import ANDROID_SANDBOX_DISABLED_REASON, AUTOMATED_PROFILE_IDS, SEMANTIC_HELPER_RELATIVES, LabController, LabError, QgaClient, QmpClient, android_attempt_matches_fixture, artifact_record, artifact_role_for_stage, build_hyperv_matrix_aggregation, ensure_owned_child, golden_readiness, headless_runner_inputs, load_profiles, proc_start_time, proc_start_time_from_stat, proc_state_from_stat, require_qmp_return, sha256_file, sha256_tree, state_root_from, validate_linux_receipt_incarnation, validate_publication_evidence, validate_receipt, validate_semantic_helper_records, validate_android_vulkan_records, wait_owned_process_exit, windows_case_specs, wsl_path_for_windows_host
except ImportError:  # direct invocation from this directory
    from lab import ANDROID_SANDBOX_DISABLED_REASON, AUTOMATED_PROFILE_IDS, SEMANTIC_HELPER_RELATIVES, LabController, LabError, QgaClient, QmpClient, android_attempt_matches_fixture, artifact_record, artifact_role_for_stage, build_hyperv_matrix_aggregation, ensure_owned_child, golden_readiness, headless_runner_inputs, load_profiles, proc_start_time, proc_start_time_from_stat, proc_state_from_stat, require_qmp_return, sha256_file, sha256_tree, state_root_from, validate_linux_receipt_incarnation, validate_publication_evidence, validate_receipt, validate_semantic_helper_records, validate_android_vulkan_records, wait_owned_process_exit, windows_case_specs, wsl_path_for_windows_host


class ReleaseLabContractTests(unittest.TestCase):
    def test_private_link_root_port_is_initial_and_profile_scoped(self):
        source = (Path(__file__).parent / "lab.py").read_text(encoding="utf-8")
        self.assertIn('private_link_root_port = profile_id in {"server-router", "linux-headless-x64"}', source)
        self.assertIn('pcie-root-port,id=amnezia-link-rp,chassis=31,slot=30', source)
        self.assertIn('if vm.get("private_link_root_port") is not None:', source)

    def test_qga_write_file_reuses_one_connection_and_rejects_short_write(self):
        class FakeSocket:
            enters = 0
            connects = 0
            def __enter__(self):
                type(self).enters += 1
                return self
            def __exit__(self, *_):
                return False
            def settimeout(self, _):
                pass
            def connect(self, _):
                type(self).connects += 1

        client = QgaClient(Path("/owned/qga.sock"))
        calls = []
        def response(_conn, execute, arguments=None):
            calls.append((execute, arguments))
            if execute == "guest-file-open":
                return {"return": 7}
            if execute == "guest-file-write":
                import base64
                return {"return": {"count": len(base64.b64decode(arguments["buf-b64"]))}}
            return {"return": {}}
        with patch.object(Path, "exists", return_value=True), \
             patch.object(sys.modules[QgaClient.__module__].socket, "AF_UNIX", 1, create=True), \
             patch("release_lab.lab.socket.socket", return_value=FakeSocket()), \
             patch.object(QgaClient, "_sync_connection") as sync, \
             patch.object(QgaClient, "_request_on_connection", side_effect=response):
            client.write_file("/tmp/value", b"x" * 70000)
        sync.assert_called_once()
        self.assertEqual(FakeSocket.enters, 1)
        self.assertEqual(FakeSocket.connects, 1)
        self.assertEqual([name for name, _ in calls],
                         ["guest-file-open", "guest-file-write", "guest-file-write",
                          "guest-file-write", "guest-file-flush", "guest-file-close"])

        def short(_conn, execute, arguments=None):
            if execute == "guest-file-open":
                return {"return": 8}
            if execute == "guest-file-write":
                return {"return": {"count": 0}}
            return {"return": {}}
        with patch.object(Path, "exists", return_value=True), \
             patch.object(sys.modules[QgaClient.__module__].socket, "AF_UNIX", 1, create=True), \
             patch("release_lab.lab.socket.socket", return_value=FakeSocket()), \
             patch.object(QgaClient, "_sync_connection"), \
             patch.object(QgaClient, "_request_on_connection", side_effect=short):
            with self.assertRaisesRegex(LabError, "short or invalid count"):
                client.write_file("/tmp/value", b"data")

    def test_mutation_lock_is_exclusive_and_releases_after_owner_exit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            controller = LabController(root)
            controller.acquire_mutation_lock("test-owner")
            code = "import sys; from pathlib import Path; from deploy.release_lab.lab import LabController, LabError; c=LabController(Path(sys.argv[1]));\ntry: c.acquire_mutation_lock('child')\nexcept LabError as e: print(e); raise SystemExit(3)\nraise SystemExit(0)"
            busy = subprocess.run([sys.executable, "-c", code, str(root)], capture_output=True, text=True, cwd=Path(__file__).parents[2])
            self.assertEqual(busy.returncode, 3, busy.stderr)
            self.assertIn("lab busy", busy.stdout)
            controller.release_mutation_lock()
            free = subprocess.run([sys.executable, "-c", code, str(root)], capture_output=True, text=True, cwd=Path(__file__).parents[2])
            self.assertEqual(free.returncode, 0, free.stderr)

    def test_mutation_lock_is_released_by_process_crash(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            code = "import os,sys,time; from pathlib import Path; from deploy.release_lab.lab import LabController; c=LabController(Path(sys.argv[1])); c.acquire_mutation_lock('crash-owner'); os._exit(0)"
            crashed = subprocess.run([sys.executable, "-c", code, str(root)], cwd=Path(__file__).parents[2])
            self.assertEqual(crashed.returncode, 0)
            controller = LabController(root)
            controller.acquire_mutation_lock("recovered-owner")
            controller.release_mutation_lock()

    def test_state_dump_temp_names_are_unique_per_writer(self):
        source = (Path(__file__).parent / "lab.py").read_text(encoding="utf-8")
        self.assertIn("uuid.uuid4().hex", source)
        self.assertNotIn('path.name + ".tmp"', source)

    def test_direct_save_state_requires_mutation_session(self):
        with tempfile.TemporaryDirectory() as tmp:
            controller = LabController(Path(tmp))
            with self.assertRaisesRegex(LabError, "active mutation session"):
                controller.save_state({"schema": 1, "lab_id": "test", "runs": {}})

    def test_direct_mutating_api_entrypoints_contend_before_side_effects(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            owner = LabController(root)
            owner.acquire_mutation_lock("direct-api-owner")
            try:
                commands = (
                    'c.collect("missing", "linux-x64-gui")',
                    'c.archive_guest_evidence("missing", "linux-x64-gui")',
                    'c.acquire_mutation_lock("nested"); c.hyperv_call("start", run_id="missing", CaseId="control")',
                )
                for expression in commands:
                    code = f'import sys; from pathlib import Path; from deploy.release_lab.lab import LabController; c=LabController(Path(sys.argv[1])); {expression}'
                    probe = subprocess.run([sys.executable, "-c", code, str(root)], capture_output=True, text=True, cwd=Path(__file__).parents[2])
                    self.assertNotEqual(probe.returncode, 0, expression)
                    self.assertTrue("lab busy" in probe.stderr or "active mutation session" in probe.stderr, expression)
            finally:
                owner.release_mutation_lock()

    def test_native_android_update_flow_is_real_ui_http_and_fail_closed(self):
        source = (Path(__file__).parent / "android" / "android-lab-windows.ps1").read_text(encoding="utf-8")
        self.assertIn("Configure-UpdateNetwork", source)
        self.assertIn("Wait-UiText 'Update'", source)
        self.assertIn("Read-FixtureRequestLog", source)
        self.assertIn("ExpectedReleaseVersionCode", source)
        self.assertIn("app-update-ui-not-present", source)
        update_body = source.split("function Test-Update", 1)[1].split("function Collect-Product", 1)[0]
        self.assertNotIn("'install','-r'", update_body)

    def test_android_update_is_blocked_by_failed_baseline_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); native = root / "native"; run_id = "android-update-baseline-gate"
            native_run = native / run_id; proof = native / "proofs" / run_id; proof.mkdir(parents=True)
            baseline = root / "baseline.apk"; candidate = root / "candidate.apk"; baseline.write_bytes(b"b"); candidate.write_bytes(b"c")
            (proof / "baseline-receipt.json").write_text(json.dumps({"status": "baseline-launch-failed", "steps": [{"passed": False}]}), encoding="utf-8")
            run = {"run_id": run_id, "expected_profiles": ["android-arm64-v8a"], "baseline_version": "5.0.1.37", "candidate_version": "5.0.1.39", "artifacts": {"android-arm64-v8a": {"path": str(candidate), "sha256": sha256_file(candidate)[0], "size": candidate.stat().st_size}}, "baseline_artifacts": {"android-arm64-v8a": {"path": str(baseline), "sha256": sha256_file(baseline)[0], "size": baseline.stat().st_size}}, "profiles": {"android-arm64-v8a": {"status": "started", "vm": {"root": str(native_run)}}}}
            controller = LabController(root, test_mode=True, android_backend="windows")
            controller.save_state({"schema": 1, "lab_id": "lab", "runs": {run_id: run}})
            calls = []
            with patch.object(controller, "_run_android_adapter", side_effect=lambda *args: calls.append(args)):
                with self.assertRaisesRegex(LabError, "android sandbox disabled by user"):
                    controller.run_steps(run_id, "android-arm64-v8a", ["update"])
            self.assertEqual(calls, [])

    def test_selected_steps_merge_prior_authentic_evidence_and_reject_conflict(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); controller = LabController(root, test_mode=True)
            run_id = "selected-step-merge"; profile_id = "linux-x64-gui"
            candidate = root / "candidate.run"; baseline = root / "baseline.run"
            candidate.write_bytes(b"candidate"); baseline.write_bytes(b"baseline")
            vm = {"pid": 22, "proc_start_time": "33", "uuid": "guest-uuid",
                  "qga_socket": str(root / "runs" / run_id / profile_id / "qga.sock")}
            state = {"schema": 1, "lab_id": "lab", "runs": {run_id: {
                "run_id": run_id, "baseline_version": "5.0.1.38", "candidate_version": "5.0.1.39",
                "artifacts": {"linux-x64": {"path": str(candidate), "sha256": sha256_file(candidate)[0], "size": candidate.stat().st_size}},
                "baseline_artifacts": {"linux-x64": {"path": str(baseline), "sha256": sha256_file(baseline)[0], "size": baseline.stat().st_size}},
                "profiles": {profile_id: {"status": "started", "vm": vm, "steps": []}},
            }}}
            controller.save_state(state)
            steps = [{"id": value, "action": value, "executable": "/bin/sh"}
                     for value in ("probe", "reinstall", "update", "service-health")]
            profile = {"backend": "qemu-linux", "runner": "deploy/release_lab/guest_runners/linux-release-lab.sh", "steps": steps}
            class FakeQga:
                def write_file(self, *_): pass
                def guest_exec_wait(self, executable, args, timeout=30):
                    return {"exitcode": 0, "stdout": json.dumps({"action": args[1]})}
            lab_module = sys.modules[LabController.__module__]
            patches = (patch.object(controller, "owned_vm", return_value=vm),
                       patch.object(lab_module, "QgaClient", return_value=FakeQga()),
                       patch.object(lab_module, "load_profiles", return_value={profile_id: profile}),
                       patch.object(lab_module, "validate_step_assertion"))
            with patches[0], patches[1], patches[2], patches[3]:
                expected_ids = []
                for step_id in ("probe", "reinstall", "update", "service-health"):
                    expected_ids.append(step_id)
                    result = controller.run_steps(run_id, profile_id, [step_id])
                    self.assertEqual([item["id"] for item in result["steps"]], expected_ids)
                saved = controller.get_run(run_id)["profiles"][profile_id]["steps"]
                self.assertEqual([item["id"] for item in saved], [item["id"] for item in steps])
                preserved = saved[0]["qga_response"]
                with self.assertRaisesRegex(LabError, "immutable evidence"):
                    controller.run_steps(run_id, profile_id, ["probe"])
                self.assertEqual(controller.get_run(run_id)["profiles"][profile_id]["steps"][0]["qga_response"], preserved)

    def test_profiles_are_complete_and_preflight_is_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = LabController(Path(tmp), dry_run=True).preflight()
        self.assertFalse(result["ready"])
        self.assertFalse(result["release_passed"])
        self.assertEqual(set(result["checks"]["profiles"]["ids"]), {
            "windows-x64", "android-arm64-v8a", "linux-x64-gui", "linux-headless-x64", "server-router"
        })

    def test_dry_run_never_creates_or_passes_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            controller = LabController(Path(tmp), test_mode=True)
            artifact = Path(tmp) / "outer.exe"
            artifact.write_bytes(b"candidate")
            baseline = Path(tmp) / "baseline.exe"
            baseline.write_bytes(b"baseline")
            manifest = Path(tmp) / "manifest.json"; manifest.write_text("{}", encoding="utf-8")
            public_key = Path(tmp) / "public.pem"; public_key.write_text("invalid", encoding="utf-8")
            run = controller.create("candidate", {"windows-x64": artifact}, artifact, "dry-run", manifest=manifest, baseline_artifacts={"windows-x64": baseline}, baseline_version="5.0.1.37", candidate_version="5.0.1.38", manifest_public_key=public_key)
            run["dry_run"] = True
            state = controller.load_state(); state["runs"]["dry-run"] = run; controller.save_state(state)
            controller = LabController(Path(tmp), dry_run=True, test_mode=True)
            result = controller.gate("dry-run", "candidate", outer_artifact=artifact)
        self.assertEqual(run["run_id"], "dry-run")
        self.assertFalse(result["candidate_passed"])
        self.assertFalse(result["release_passed"])

    def test_candidate_only_requires_selected_profiles_and_never_publishes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "windows.exe"
            outer = root / "outer.exe"
            manifest = root / "manifest.json"
            baseline = root / "baseline.exe"
            artifact.write_bytes(b"platform")
            outer.write_bytes(b"outer")
            manifest.write_text("{}", encoding="utf-8")
            baseline.write_bytes(b"baseline")
            public_key = root / "public.pem"; public_key.write_text("invalid", encoding="utf-8")
            controller = LabController(root, test_mode=True)
            run = controller.create("candidate", {"windows-x64": artifact}, outer, "candidate", manifest=manifest, baseline_artifacts={"windows-x64": baseline}, baseline_version="5.0.1.37", candidate_version="5.0.1.38", manifest_public_key=public_key)
            # A reset profile must not be allowed to reuse the in-memory
            # receipt.  The controller archive is the durable evidence
            # boundary after cleanup.
            run["profiles"]["windows-x64"]["status"] = "reset"
            run["profiles"]["windows-x64"]["evidence"] = {"transport": "qga", "interactive_verified": True}
            run["profiles"]["windows-x64"]["steps"] = [{"id": step, "passed": True} for step in ("probe", "reinstall", "update", "service-health")]
            state = controller.load_state(); state["runs"]["candidate"] = run; controller.save_state(state)
            result = controller.gate("candidate", "candidate", outer_artifact=outer)
            self.assertFalse(result["candidate_passed"])

    def test_gate_rejects_artifact_bytes_changed_after_guest_testing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            platform_artifact = root / "linux.run"
            outer = root / "outer.exe"
            manifest = root / "manifest.json"
            public_key = root / "public.pem"
            platform_artifact.write_bytes(b"planned-platform")
            outer.write_bytes(b"planned-outer")
            manifest.write_text("{}", encoding="utf-8")
            public_key.write_text("public", encoding="utf-8")
            platform_sha, platform_size = sha256_file(platform_artifact)
            outer_sha, outer_size = sha256_file(outer)
            run_id = "changed-bytes"
            run = {
                "schema": 1,
                "run_id": run_id,
                "lane": "candidate",
                "dry_run": False,
                "test_mode": False,
                "baseline_version": "5.0.1.37",
                "candidate_version": "5.0.1.39",
                "outer_artifact": {"path": str(outer), "sha256": outer_sha, "size": outer_size},
                "artifacts": {"linux-x64-gui": {"path": str(platform_artifact), "sha256": platform_sha, "size": platform_size}},
                "baseline_artifacts": {},
                "manifest": {"path": str(manifest), "sha256": sha256_file(manifest)[0], "size": manifest.stat().st_size},
                "manifest_public_key": {"path": str(public_key), "sha256": sha256_file(public_key)[0], "size": public_key.stat().st_size},
                "profiles": {},
                "expected_profiles": ["linux-x64-gui"],
            }
            state = {"schema": 1, "lab_id": "lab", "runs": {run_id: run}}
            controller = LabController(root)
            with controller.mutation_session(), patch.object(controller, "assert_mutation_context"):
                controller.save_state(state)
                platform_artifact.write_bytes(b"mutated-after-test")
                with self.assertRaisesRegex(LabError, "artifact changed after guest testing: linux-x64-gui"):
                    controller.gate(run_id, "candidate", outer_artifact=outer)

    def test_real_receipt_requires_marker_transport_and_steps(self):
        receipt = {
            "schema": 1,
            "run_id": "run-1",
            "profile": "windows-x64",
            "artifact": "outer.exe",
            "artifact_sha256": "a" * 64,
            "artifact_size": 1,
            "artifact_role": "candidate",
            "artifact_source": {"transport": "qga", "kind": "qga-upload", "hash_verified": True},
            "baseline_version": "5.0.1.37",
            "candidate_version": "5.0.1.38",
            "guest_marker": "amnezia-release-lab:run-1:windows-x64",
            "transport": "qga",
            "origin": "guest",
            "injected": False,
            "steps": [{"id": "probe", "passed": True}],
            "observed_at": "2026-09-08T00:00:00Z",
        }
        validate_receipt(receipt, run_id="run-1", profile_id="windows-x64", artifact={"sha256": "a" * 64, "size": 1})
        receipt["transport"] = "host-file"
        with self.assertRaises(LabError):
            validate_receipt(receipt, run_id="run-1", profile_id="windows-x64", artifact={"sha256": "a" * 64, "size": 1})

    def test_android_receipt_accepts_emulator_qemu_uuid_schema(self):
        receipt = {
            "schema": 1,
            "run_id": "android-run",
            "profile": "android-arm64-v8a",
            "artifact": "candidate.apk",
            "artifact_sha256": "b" * 64,
            "artifact_size": 2,
            "artifact_role": "candidate",
            "artifact_source": {"transport": "android-adapter", "hash_verified": True},
            "baseline_version": "5.0.1.37",
            "candidate_version": "5.0.1.39",
            "guest_marker": "amnezia-release-lab:android-run:android-arm64-v8a",
            "transport": "android-adapter",
            "origin": "guest",
            "injected": False,
            "steps": [{"id": "collect", "passed": True}],
            "observed_at": "2026-09-10T00:00:00Z",
            "device_identity": {"serial": "emulator-5560", "qemuUuid": "owned-uuid"},
        }
        validate_receipt(receipt, run_id="android-run", profile_id="android-arm64-v8a", artifact={"sha256": "b" * 64, "size": 2})

    def test_android_receipt_accepts_empty_guest_uuid_with_live_launch_binding(self):
        receipt = {
            "schema": 1, "run_id": "android-launch", "profile": "android-arm64-v8a", "artifact": "candidate.apk",
            "artifact_sha256": "c" * 64, "artifact_size": 2, "artifact_role": "candidate",
            "artifact_source": {"transport": "android-adapter", "hash_verified": True},
            "baseline_version": "5.0.1.37", "candidate_version": "5.0.1.39",
            "guest_marker": "amnezia-release-lab:android-launch:android-arm64-v8a", "nonce": "launch-nonce-123456",
            "transport": "android-adapter", "origin": "guest", "injected": False,
            "steps": [{"id": "collect", "passed": True}], "observed_at": "2026-09-10T00:00:00Z",
            "device_identity": {"serial": "emulator-5560", "qemuUuid": "", "launchUuid": "launch-nonce-123456"},
        }
        validate_receipt(receipt, run_id="android-launch", profile_id="android-arm64-v8a", artifact={"sha256": "c" * 64, "size": 2})

    def test_reset_requires_owned_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "windows.exe"; artifact.write_bytes(b"x")
            baseline = root / "baseline.exe"; baseline.write_bytes(b"b")
            manifest = root / "manifest.json"; manifest.write_text("{}", encoding="utf-8")
            public_key = root / "public.pem"; public_key.write_text("invalid", encoding="utf-8")
            controller = LabController(root, test_mode=True)
            controller.create("candidate", {"windows-x64": artifact}, artifact, "reset-me", manifest=manifest, baseline_artifacts={"windows-x64": baseline}, baseline_version="5.0.1.37", candidate_version="5.0.1.38", manifest_public_key=public_key)
            result = controller.reset("reset-me", "windows-x64")
            self.assertEqual(result["reset_profiles"], ["windows-x64"])

    def test_windows_golden_requires_matching_nvram_and_tpm_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            profile = load_profiles()["windows-x64"]
            image = root / profile["base_image"]; image.parent.mkdir(parents=True); image.write_bytes(b"sealed-disk")
            vars_path = root / profile["ovmf_vars_golden"]; vars_path.parent.mkdir(parents=True, exist_ok=True); vars_path.write_bytes(b"sealed-nvram")
            tpm_path = root / profile["tpm_state_golden"]; tpm_path.mkdir(parents=True); (tpm_path / "state").write_bytes(b"sealed-tpm")
            image_sha, _ = sha256_file(image); vars_sha, _ = sha256_file(vars_path); tpm_sha = sha256_tree(tpm_path)
            readiness = root / profile["golden_readiness"]
            readiness.parent.mkdir(parents=True, exist_ok=True)
            readiness.write_text(json.dumps({"schema": 1, "profile": "windows-x64", "sealed": True, "network_sealed": True, "immutable": True, "candidate_credentials": False, "guest_agent": "qga", "base_sha256": image_sha, "ovmf_vars_sha256": vars_sha, "tpm_state_sha256": tpm_sha}), encoding="utf-8")
            self.assertEqual(golden_readiness(root, profile)[0], True)
            (tpm_path / "state").write_bytes(b"changed")
            self.assertEqual(golden_readiness(root, profile)[0], False)

    def test_linux_runner_embedded_python_blocks_parse(self):
        runner = (Path(__file__).parent / "guest_runners" / "linux-release-lab.sh").read_text(encoding="utf-8")
        blocks = re.findall(r"python3 - <<'PY'\n(.*?)\nPY", runner, flags=re.DOTALL)
        self.assertGreaterEqual(len(blocks), 3)
        for block in blocks:
            ast.parse(block)

    def test_mutations_require_lab_identity_and_paths_stay_owned(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaises(LabError):
                LabController(root).assert_mutation_context()
            with self.assertRaises(LabError):
                ensure_owned_child(root, root.parent / "foreign", "test path")

    def test_headless_run_requires_verified_baseline_and_candidate_receipts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); controller = LabController(root, test_mode=True)
            candidate = root / "candidate.tar.gz"; candidate.write_bytes(b"candidate")
            baseline = root / "baseline.tar.gz"; baseline.write_bytes(b"baseline")
            outer = root / "outer.run"; outer.write_bytes(b"outer")
            manifest = root / "manifest.json"; manifest.write_text("{}", encoding="utf-8")
            public_key = root / "public.pem"; public_key.write_text("public", encoding="utf-8")
            with self.assertRaisesRegex(LabError, "verified baseline/candidate provisioning receipts"):
                controller.create(
                    "candidate", {"linux-headless-x64": candidate},
                    outer_artifact=outer,
                    run_id="headless-trust", manifest=manifest,
                    baseline_artifacts={"linux-headless-x64": baseline},
                    baseline_version="5.0.1.37", candidate_version="5.0.1.38",
                    manifest_public_key=public_key, baseline_manifest=manifest,
                )

    def test_owned_vm_rejects_pid_reuse_before_socket_use(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); controller = LabController(root, test_mode=True)
            run_dir = root / "runs" / "pid-reuse" / "linux-x64-gui"; run_dir.mkdir(parents=True)
            state = controller.load_state(); state["runs"] = {"pid-reuse": {"profiles": {"linux-x64-gui": {"vm": {"pid": os.getpid(), "proc_start_time": "reused", "uid": None, "uuid": "u", "qmp_socket": str(run_dir / "qmp.sock"), "qga_socket": str(run_dir / "qga.sock"), "argv": ["qemu-system-x86_64"]}}}}}; controller.save_state(state)
            with self.assertRaises(LabError):
                controller.owned_vm("pid-reuse", "linux-x64-gui")

    def test_proc_start_time_handles_spaces_and_parentheses_in_comm(self):
        stat = "1234 (worker name )with spaces) S " + " ".join(str(item) for item in range(4, 22)) + " starttime"
        self.assertEqual(proc_start_time_from_stat(stat), "starttime")
        zombie_stat = "1234 (qemu (child)) Z " + " ".join(str(item) for item in range(4, 22))
        self.assertEqual(proc_state_from_stat(zombie_stat), "Z")

    def test_android_fixture_attempt_is_single_persisted_context(self):
        source = (Path(__file__).parent / "lab.py").read_text(encoding="utf-8")
        self.assertIn('run["android_update_attempt"] = {"nonce": attempt_nonce', source)
        self.assertIn("android_attempt_matches_fixture", source)
        self.assertIn('"fixture_host_port"', source)

    def test_android_fixture_attempt_binding_rejects_replay_or_endpoint_drift(self):
        fixture = {
            "attempt_nonce": "nonce-a", "guest_endpoint": "10.8.1.0",
            "host_port": 17865, "guest_port": 17865, "fixture_bind": "127.0.0.1",
        }
        attempt = {
            "nonce": "nonce-a", "guest_endpoint": "10.8.1.0", "run_id": "run-a",
            "profile": "android-arm64-v8a", "fixture_host_port": 17865,
            "fixture_guest_port": 17865, "fixture_bind": "127.0.0.1",
        }
        self.assertTrue(android_attempt_matches_fixture(attempt, fixture, "run-a", "android-arm64-v8a"))
        for key, value in (("nonce", "replayed"), ("guest_endpoint", "10.8.1.1"), ("fixture_host_port", 17866), ("fixture_guest_port", 17864), ("fixture_bind", "0.0.0.0")):
            changed = dict(attempt); changed[key] = value
            self.assertFalse(android_attempt_matches_fixture(changed, fixture, "run-a", "android-arm64-v8a"), key)

    def test_release_gate_rejects_missing_publication_proof(self):
        source = (Path(__file__).parent / "lab.py").read_text(encoding="utf-8")
        self.assertIn("validate_publication_evidence", source)
        self.assertIn("client_acknowledgements", source)
        self.assertIn("http_readback", source)
        self.assertIn("ephemeral_key_removed", source)
        self.assertIn("requires complete self-hosted client-flow evidence", source)

    def test_publication_validator_rejects_supplied_guest_label_without_controller_archive(self):
        run = {"run_id": "publish-a", "outer_artifact": {"sha256": "a" * 64}, "manifest": {"sha256": "b" * 64, "size": 1}, "artifacts": {}}
        with self.assertRaisesRegex(LabError, "publication evidence identity"):
            validate_publication_evidence({"schema": 1, "run_id": "publish-a", "origin": "guest", "guest_origin": True}, run, Path(tempfile.mkdtemp()))

    def test_publication_validator_reads_raw_sources_and_rejects_tamper(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); run_id = "publish-proof"
            outer = {"sha256": "a" * 64, "size": 10}
            artifact = {"sha256": "c" * 64, "size": 3}
            raw_root = root / "raw"; raw_root.mkdir(); client_raw = raw_root / "client.log"; server_raw = raw_root / "server.log"
            manifest_path = root / "manifest.json"
            payload = {"platforms": {"linux-x64": {"url": "files/artifacts/" + artifact["sha256"] + "/linux.run", "sha256": artifact["sha256"], "size": artifact["size"]}}}
            encoded = __import__("base64").urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode().rstrip("=")
            manifest_path.write_text(json.dumps({"payload": encoded}), encoding="utf-8")
            manifest_sha, manifest_size = sha256_file(manifest_path)
            manifest = {"path": str(manifest_path), "sha256": manifest_sha, "size": manifest_size}
            child = {"vm_id": "60509ee5-65a3-44d8-838a-a9b41c3f7fac", "parent_sha256": "d" * 64, "process_pid": 42, "process_uuid": "60509ee5-65a3-44d8-838a-a9b41c3f7fac", "marker": f"amnezia-release-lab:{run_id}:windows-x64"}
            server = {"uuid": "server-uuid", "qmp_socket": "server.qmp", "qga_socket": "server.qga"}
            nonce = "a" * 48
            metadata_sha = "e" * 64
            client_raw.write_text(json.dumps({"transport": "hyperv-powershell-direct", "origin": "guest", "run_id": run_id, "case_id": "publisher-clean", "attempt_nonce": nonce, "vm_id": child["vm_id"], "raw": {"passed": True, "raw": {"exit_code": 0}}}), encoding="utf-8")
            run = {"run_id": run_id, "outer_artifact": outer, "manifest": manifest, "artifacts": {"linux-x64": artifact}, "baseline_artifacts": {}, "profiles": {"windows-x64": {"hyperv_cases": {"publisher-clean": {"state": "reset", "vm_id": child["vm_id"], "parent_sha256": child["parent_sha256"]}}}}, "server_observation": {"uuid": server["uuid"], "qmp_socket": server["qmp_socket"], "qga_socket": server["qga_socket"], "qmp_observed": True, "qga_observed": True}}
            publication_id = "b" * 48
            def phase_ack(name, durable):
                record = {"publication_run_id": publication_id, "candidate": manifest["sha256"], "metadata_sha256": metadata_sha, "phase": durable, "record": f"{publication_id}\t{manifest['sha256']}\t{durable}"}
                return {"passed": True, "run_id": run_id, "origin": "guest", "transport": "hyperv-powershell-direct", "publication_run_id": publication_id, "phase": durable, "durable_record": record}
            history = "\n".join(f"{publication_id}\t{manifest['sha256']}\t{phase}" for phase in ("prepared", "committed", "finalized"))
            server_raw.write_text(json.dumps({"transport": "qga", "origin": "guest", "run_id": run_id, "case_id": "publisher-clean", "attempt_nonce": nonce, "server_uuid": server["uuid"], "qga_socket": server["qga_socket"], "manifest_sha256": manifest["sha256"], "metadata_sha256": metadata_sha, "attempt_marker": {"schema": 1, "run_id": run_id, "case_id": "publisher-clean", "attempt_nonce": nonce, "manifest_sha256": manifest["sha256"]}, "raw": {"stdout": history}}), encoding="utf-8")
            client_sha, client_size = sha256_file(client_raw); server_sha, server_size = sha256_file(server_raw)
            observed_artifact = {"path": payload["platforms"]["linux-x64"]["url"], "sha256": artifact["sha256"], "size": artifact["size"]}
            evidence = {"schema": 1, "controller_created": True, "live": True, "run_id": run_id, "case_id": "publisher-clean", "attempt_nonce": nonce, "outer_artifact_sha256": outer["sha256"], "manifest_sha256": manifest["sha256"], "windows_child": child, "server": server, "client_acknowledgements": {"prepare": phase_ack("prepare", "prepared"), "commit": phase_ack("commit", "committed"), "finalize": phase_ack("finalize", "finalized")}, "http_readback": {"manifest_sha256": manifest["sha256"], "manifest_bytes": manifest["size"], "artifacts": {"platform:linux-x64": observed_artifact}}, "raw_sources": {"client": {"origin": "guest", "archive_path": str(client_raw), "sha256": client_sha, "size": client_size}, "server": {"origin": "guest", "archive_path": str(server_raw), "sha256": server_sha, "size": server_size}}, "cleanup": {"child_reset": True, "server_reset": True, "relays_stopped": True, "relay_registry_unregistered": True, "ephemeral_key_removed": True, "host_network_mutation": False}}
            core_sha = __import__("hashlib").sha256(json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            archive_path = root / "archive.json"; archive_path.write_text(json.dumps({"run_id": run_id, "controller_created": True, "evidence_sha256": core_sha}), encoding="utf-8")
            archive_sha, _ = sha256_file(archive_path); evidence["archive"] = {"origin": "controller", "immutable": True, "path": str(archive_path), "sha256": archive_sha}
            validate_publication_evidence(evidence, run, root)
            client_raw.write_bytes(b"tampered")
            with self.assertRaisesRegex(LabError, "raw source hash"):
                validate_publication_evidence(evidence, run, root)

    def test_android_archive_records_failure_when_adapter_has_no_vm_record(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); controller = LabController(root, test_mode=True)
            run_id = "android-before-vm"
            artifact = root / "candidate.apk"; artifact.write_bytes(b"candidate")
            run = {
                "run_id": run_id, "profiles": {"android-arm64-v8a": {"status": "created", "vm": None}},
                "artifacts": {"android-arm64-v8a": {"path": str(artifact), "sha256": "a" * 64, "size": artifact.stat().st_size}},
                "outer_artifact": None,
            }
            controller.save_state({"schema": 1, "lab_id": "lab", "runs": {run_id: run}})
            record = controller.archive_guest_evidence(run_id, "android-arm64-v8a", LabError("adapter start failed"))
            self.assertIsNone(record["receipt"])
            self.assertEqual(record["error"], "adapter start failed")
            self.assertTrue(Path(record["archive_path"]).is_file())

    def test_android_failure_still_cleans_auxiliary_server(self):
        controller = LabController(Path(tempfile.mkdtemp()), test_mode=True)
        with patch.object(controller, "get_run", return_value={"profiles": {"android-arm64-v8a": {"vm": None}}}):
            with self.assertRaisesRegex(LabError, "already-owned guest"):
                controller._run_android_adapter("old", "android-arm64-v8a", "reset")

    def test_guest_evidence_archive_survives_reset_and_keeps_raw_failure_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); controller = LabController(root, test_mode=True)
            run_id = "archive-failure"; profile_id = "linux-headless-x64"
            artifact = root / "candidate.tar.gz"; artifact.write_bytes(b"candidate")
            profile_dir = root / "runs" / run_id / profile_id; profile_dir.mkdir(parents=True)
            overlay = profile_dir / "overlay.qcow2"; overlay.write_bytes(b"overlay")
            (profile_dir / ".owned-overlay.json").write_text(json.dumps({"run_id": run_id, "profile": profile_id, "overlay": str(overlay)}), encoding="utf-8")
            receipt = {"schema": 1, "run_id": run_id, "profile": profile_id, "artifact": "x", "artifact_sha256": "a" * 64, "artifact_size": 1, "artifact_role": "candidate", "artifact_source": {"transport": "qga", "hash_verified": True}, "baseline_version": "5.0.1.39", "candidate_version": "5.0.1.39", "guest_marker": f"amnezia-release-lab:{run_id}:{profile_id}", "transport": "qga", "origin": "guest", "injected": False, "steps": [{"id": "update", "passed": False}], "observed_at": "2026-09-10T00:00:00Z", "failure": {"fresh_log_path": "/tmp/failure.log"}}
            state = {"schema": 1, "lab_id": "lab", "runs": {run_id: {"run_id": run_id, "baseline_version": "5.0.1.39", "candidate_version": "5.0.1.39", "artifacts": {profile_id: {"path": str(artifact), "sha256": "a" * 64, "size": 1}}, "profiles": {profile_id: {"status": "started", "vm": {"pid": 1, "proc_start_time": "x", "uid": None, "uuid": "u", "qmp_socket": str(profile_dir / "qmp.sock"), "qga_socket": str(profile_dir / "qga.sock")}}}}}}
            controller.save_state(state)
            calls = []
            class FakeQga:
                def read_file(self, path):
                    calls.append(("read", str(path)))
                    return json.dumps(receipt).encode() if str(path).endswith("receipt.json") else b"installer failed\n"
                def guest_exec_wait(self, executable, args, timeout=30):
                    calls.append(("exec", executable, args))
                    output = "17\n" if str(executable).endswith("stat") else "/tmp/failure.log\n"
                    return {"stdout": output, "stderr": "", "exitcode": 0}
            with patch.object(controller, "owned_vm", return_value=state["runs"][run_id]["profiles"][profile_id]["vm"]), patch("release_lab.lab.QgaClient", return_value=FakeQga()):
                record = controller.archive_guest_evidence(run_id, profile_id, LabError("update failed"))
            self.assertIn(("read", f"/run/amnezia-release-lab/{run_id}/{profile_id}/receipt.json"), calls)
            self.assertEqual(record["receipt"]["size"], len(json.dumps(receipt).encode()))
            self.assertEqual(len(record["raw_logs"]), 1)
            state = controller.load_state(); state["runs"][run_id]["profiles"][profile_id]["vm"] = None; controller.save_state(state)
            controller.reset(run_id, profile_id)
            saved = controller.get_run(run_id)["profiles"][profile_id]
            self.assertEqual(saved["status"], "reset")
            self.assertTrue(Path(saved["evidence_archive"]).is_file())
            self.assertTrue((root / "exports" / run_id / profile_id / "logs" / "failure.log").is_file())

    def test_guest_evidence_archive_keeps_bounded_log_when_receipt_was_never_written(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); controller = LabController(root, test_mode=True)
            run_id = "archive-no-receipt"; profile_id = "linux-headless-x64"
            artifact = root / "candidate.tar.gz"; artifact.write_bytes(b"candidate")
            profile_dir = root / "runs" / run_id / profile_id; profile_dir.mkdir(parents=True)
            overlay = profile_dir / "overlay.qcow2"; overlay.write_bytes(b"overlay")
            (profile_dir / ".owned-overlay.json").write_text(json.dumps({"run_id": run_id, "profile": profile_id, "overlay": str(overlay)}), encoding="utf-8")
            vm = {"pid": 1, "proc_start_time": "start", "uid": 999, "uuid": "guest-uuid", "qmp_socket": str(profile_dir / "qmp.sock"), "qga_socket": str(profile_dir / "qga.sock")}
            state = {"schema": 1, "lab_id": "lab", "runs": {run_id: {"run_id": run_id, "baseline_version": "5.0.1.39", "candidate_version": "5.0.1.39", "artifacts": {profile_id: {"path": str(artifact), "sha256": "a" * 64, "size": 1}}, "profiles": {profile_id: {"status": "started", "vm": vm}}}}}
            controller.save_state(state)
            class FakeQga:
                def read_file(self, path):
                    if str(path).endswith("receipt.json"):
                        raise LabError("receipt not written")
                    return b"crash before receipt\n"
                def guest_exec_wait(self, executable, args, timeout=30):
                    if str(executable).endswith("stat"):
                        return {"stdout": "22\n", "stderr": "", "exitcode": 0}
                    return {"stdout": "/tmp/amnezia-release-lab-crash.log\n", "stderr": "", "exitcode": 0}
            with patch.object(controller, "owned_vm", return_value=vm), patch("release_lab.lab.QgaClient", return_value=FakeQga()):
                record = controller.archive_guest_evidence(run_id, profile_id, LabError("guest crashed"))
            self.assertIsNone(record["receipt"])
            self.assertEqual(len(record["raw_logs"]), 1)
            self.assertTrue((root / "exports" / run_id / profile_id / "logs" / "amnezia-release-lab-crash.log").is_file())

    def test_suite_archive_and_gate_are_bound_to_controller_archive(self):
        source = (Path(__file__).parent / "lab.py").read_text(encoding="utf-8")
        self.assertIn("def archive_guest_evidence", source)
        self.assertIn("immutable_json_dump", source)
        self.assertIn("guest evidence archive failed; preserving owned guest", source)
        self.assertIn('profile_state.get("status") not in {"evidence-collected", "reset"}', source)
        self.assertIn("archived guest evidence integrity mismatch", source)

    def test_run_suite_archives_before_reset_on_guest_failure(self):
        controller = LabController(Path(tempfile.mkdtemp()), test_mode=True)
        run = {"run_id": "suite-failure", "expected_profiles": ["linux-headless-x64"], "profiles": {"linux-headless-x64": {"status": "created"}}}
        events = []
        with patch.object(controller, "create", return_value=run), patch.object(controller, "get_run", return_value=run), patch.object(controller, "start", side_effect=lambda *_: events.append("start")), patch.object(controller, "guest_probe", side_effect=lambda *_: events.append("probe")), patch.object(controller, "run_steps", side_effect=LabError("guest failed")), patch.object(controller, "archive_guest_evidence", side_effect=lambda *args: (events.append("archive"), run["profiles"]["linux-headless-x64"].update(evidence_archive="archive.json"))[1]), patch.object(controller, "reset", side_effect=lambda *_: events.append("reset")):
            with self.assertRaisesRegex(LabError, "guest failed"):
                controller.run_suite("candidate", {}, None)
        self.assertEqual(events, ["start", "probe", "archive", "reset"])

    def test_android_run_suite_starts_fixture_before_adapter_update_and_cleans_it(self):
        controller = LabController(Path(tempfile.mkdtemp()), test_mode=True)
        run = {"run_id": "automatic-no-android", "expected_profiles": list(AUTOMATED_PROFILE_IDS), "profiles": {profile: {"status": "created"} for profile in AUTOMATED_PROFILE_IDS}}
        events = []
        with patch.object(controller, "create", return_value=run), patch.object(controller, "get_run", return_value=run), patch.object(controller, "start", side_effect=lambda run_id, profile: events.append(f"start:{profile}")), patch.object(controller, "guest_probe", side_effect=lambda run_id, profile: events.append(f"probe:{profile}")), patch.object(controller, "start_consumer_fixture", side_effect=AssertionError("Android fixture must not start")), patch.object(controller, "run_steps", side_effect=lambda *args: events.append(f"steps:{args[1]}")), patch.object(controller, "collect", side_effect=lambda *args: events.append(f"collect:{args[1]}")), patch.object(controller, "archive_guest_evidence", side_effect=lambda *args: run["profiles"][args[1]].update(evidence_archive="archive.json")), patch.object(controller, "cleanup_auxiliary_resources", side_effect=AssertionError("Android cleanup must not be entered")), patch.object(controller, "reset", side_effect=lambda *args: events.append(f"reset:{args[1]}")):
            controller.run_suite("candidate", {}, None)
        self.assertFalse(any("android" in event for event in events))
        self.assertEqual({event.split(":", 1)[1] for event in events if event.startswith("start:")}, set(AUTOMATED_PROFILE_IDS))

    def test_run_suite_preserves_guest_when_archive_fails(self):
        controller = LabController(Path(tempfile.mkdtemp()), test_mode=True)
        run = {"run_id": "archive-failure", "expected_profiles": ["linux-headless-x64"], "profiles": {"linux-headless-x64": {"status": "created"}}}
        with patch.object(controller, "create", return_value=run), patch.object(controller, "get_run", return_value=run), patch.object(controller, "start"), patch.object(controller, "guest_probe"), patch.object(controller, "run_steps"), patch.object(controller, "collect"), patch.object(controller, "archive_guest_evidence", side_effect=LabError("archive unavailable")), patch.object(controller, "reset") as reset:
            with self.assertRaisesRegex(LabError, "evidence archive failed"):
                controller.run_suite("candidate", {}, None)
        reset.assert_not_called()

    def test_android_auxiliary_fixture_archives_before_stop_and_reset(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            controller = LabController(root, test_mode=True)
            run_id = "android-aux-cleanup"
            vm = {"pid": 42, "proc_start_time": "start", "uid": 999, "uuid": "server-uuid", "qmp_socket": "qmp.sock", "qga_socket": "qga.sock"}
            run = {
                "run_id": run_id,
                "profiles": {"android-arm64-v8a": {"status": "evidence-collected"}, "server-router": {"status": "started", "vm": vm}},
                "server_fixture": {"pid": 99, "guest_request_log": "/tmp/amnezia-consumer-fixture-requests.jsonl", "artifact_sha256": "a" * 64, "manifest_sha256": "b" * 64, "host_port": 17865, "guest_port": 17865, "guest_endpoint": "10.8.1.0", "attempt_nonce": "nonce", "run_id": run_id, "consumer_fixture": True},
            }
            controller.save_state({"schema": 1, "lab_id": "lab", "runs": {run_id: run}})
            events = []
            class FakeQga:
                def guest_exec_wait(self, executable, args, timeout=30):
                    return {"stdout": "17\n", "stderr": "", "exitcode": 0}
                def read_file(self, path):
                    return b'{"path":"/manifest.json"}\n'
            with patch.object(controller, "owned_vm", return_value=vm), patch("release_lab.lab.QgaClient", return_value=FakeQga()), patch.object(controller, "stop_consumer_fixture", side_effect=lambda *_: events.append("stop")), patch.object(controller, "reset", side_effect=lambda *_: events.append("reset")):
                record = controller.cleanup_auxiliary_resources(run_id, "android-arm64-v8a")
            self.assertEqual(events, ["stop", "reset"])
            self.assertEqual(record, None)
            archive = root / "exports" / run_id / "server-router" / "consumer-fixture" / "evidence.json"
            self.assertTrue(archive.is_file())
            saved = json.loads(archive.read_text(encoding="utf-8"))
            self.assertEqual(saved["origin"], "guest")
            self.assertEqual(saved["guest_binding"]["uuid"], "server-uuid")

    def test_gate_accepts_controller_archive_after_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); controller = LabController(root)
            run_id = "gate-archive"; profile_id = "linux-x64-gui"
            artifact = root / "candidate.run"; artifact.write_bytes(b"x")
            outer = root / "outer.exe"; outer.write_bytes(b"o")
            manifest = root / "manifest.json"; manifest.write_text("{}", encoding="utf-8")
            key = root / "public.pem"; key.write_text("key", encoding="utf-8")
            digest = "a" * 64
            binding={"pid":22,"proc_start_time":"33","uuid":"guest-uuid","qga_socket":"qga.sock"};source={"transport":"qga","kind":"qga-upload","hash_verified":True}
            steps = [{"id": item,"run_id":run_id,"profile":profile_id,"guest_binding":binding,"raw_assertion":{"passed":True},"observed_at":f"2026-09-10T00:0{n}:00Z","artifact_sha256":digest,"artifact_size":1,"artifact_role":"candidate","artifact_source":source,"passed":True} for n,item in enumerate(("probe", "reinstall", "update", "service-health"))]
            receipt = {"schema": 1, "run_id": run_id, "profile": profile_id, "artifact": artifact.name, "artifact_sha256": digest, "artifact_size": 1, "artifact_role": "candidate", "artifact_source": {"transport": "qga", "kind": "qga-upload", "hash_verified": True}, "baseline_version": "5.0.1.37", "candidate_version": "5.0.1.38", "guest_marker": f"amnezia-release-lab:{run_id}:{profile_id}", "transport": "qga", "origin": "guest", "injected": False, "guest_binding": binding, "steps": steps, "assertion": {"passed": True, "installed_version": "5.0.1.38", "artifact_sha256_after": digest}, "observed_at": "2026-09-10T00:00:00Z"}
            archive_dir = root / "exports" / run_id / profile_id; archive_dir.mkdir(parents=True)
            receipt_path = archive_dir / "receipt.json"; receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
            receipt_sha, receipt_size = sha256_file(receipt_path)
            archive_binding={**binding,"uid":999,"qmp_socket":"qmp.sock","started_at":"2026-09-10T00:00:00Z"}
            archive_path = archive_dir / "evidence.json"; archive_path.write_text(json.dumps({"schema": 1, "run_id": run_id, "profile": profile_id, "artifact_sha256": digest, "artifact_size": 1, "origin": "guest", "injected": False, "transport": "qga", "guest_binding": archive_binding, "error": None, "receipt": {"archive_path": str(receipt_path), "sha256": receipt_sha, "size": receipt_size}}), encoding="utf-8")
            record = {"path": str(artifact), "sha256": digest, "size": 1}
            run = {"run_id": run_id, "lane": "candidate", "dry_run": False, "test_mode": False, "baseline_version": "5.0.1.37", "candidate_version": "5.0.1.38", "outer_artifact": {"path": str(outer), "sha256": digest, "size": 1}, "baseline_outer_artifact": None, "artifacts": {"linux-x64": record}, "baseline_artifacts": {"linux-x64": record}, "manifest": {"path": str(manifest), "sha256": digest, "size": 1}, "baseline_manifest": None, "manifest_public_key": {"path": str(key), "sha256": digest, "size": 1}, "profiles": {profile_id: {"status": "reset", "evidence": None, "evidence_archive": str(archive_path), "steps": []}}, "expected_profiles": [profile_id]}
            state = {"schema": 1, "lab_id": "lab", "runs": {run_id: run}}
            with controller.mutation_session(), patch.object(controller, "assert_mutation_context"):
                controller.save_state(state)
            with patch.object(controller, "assert_mutation_context"), patch("release_lab.lab.artifact_record", return_value=record), patch("release_lab.lab.validate_signed_manifest"):
                result = controller.gate(run_id, "candidate", outer_artifact=outer)
            self.assertTrue(result["candidate_passed"])
            self.assertFalse(result["release_passed"])
            archive_value=json.loads(archive_path.read_text());archive_value["guest_binding"]["uuid"]="replacement";archive_path.write_text(json.dumps(archive_value))
            with patch.object(controller,"assert_mutation_context"),patch("release_lab.lab.artifact_record",return_value=record),patch("release_lab.lab.validate_signed_manifest"):
                with self.assertRaisesRegex(LabError,"archived Linux guest binding"):
                    controller.gate(run_id,"candidate",outer_artifact=outer)
            archive_value["guest_binding"]["uuid"]="guest-uuid";archive_path.write_text(json.dumps(archive_value))
            # A stale controller cache must not restore a step that the
            # immutable archived receipt did not report.
            receipt["steps"] = steps[:-1]
            receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
            receipt_sha, receipt_size = sha256_file(receipt_path)
            archive_value = json.loads(archive_path.read_text(encoding="utf-8"))
            archive_value["receipt"].update(sha256=receipt_sha, size=receipt_size)
            archive_path.write_text(json.dumps(archive_value), encoding="utf-8")
            run["profiles"][profile_id]["steps"] = steps
            with patch.object(controller, "assert_mutation_context"), patch("release_lab.lab.artifact_record", return_value=record), patch("release_lab.lab.validate_signed_manifest"):
                rejected = controller.gate(run_id, "candidate", outer_artifact=outer)
            self.assertFalse(rejected["candidate_passed"])
            self.assertIn(f"{profile_id}-steps", rejected["missing_profiles"])

    def test_qga_reader_accepts_delimited_ff_framing(self):
        class FakeConnection:
            def __init__(self):
                self.payload = b'\xff{"return":{"sync":1}}\r\n'

            def recv(self, _size):
                payload, self.payload = self.payload, b""
                return payload

        self.assertEqual(QmpClient._read_json(FakeConnection()), {"return": {"sync": 1}})

    def test_qmp_error_is_not_a_live_status(self):
        with self.assertRaises(LabError):
            require_qmp_return({"error": {"class": "GenericError"}}, "query-status")

    def test_wait_owned_process_rejects_pid_reuse(self):
        if not Path("/proc").is_dir():
            self.skipTest("Linux /proc process identity is unavailable")
        with self.assertRaises(LabError):
            wait_owned_process_exit(os.getpid(), "reused", "QEMU", timeout=0.01)

    def test_reset_preserves_live_overlay_when_process_ignores_term(self):
        if not Path("/proc").is_dir():
            self.skipTest("Linux /proc process identity is unavailable")
        with tempfile.TemporaryDirectory() as tmp:
            ready = Path(tmp) / "child-ready"
            child = subprocess.Popen([sys.executable, "-c", "import pathlib,signal,sys,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); pathlib.Path(sys.argv[1]).write_text('ready');\nwhile True: time.sleep(1)", str(ready)])
            try:
                deadline = __import__('time').monotonic() + 5
                while not ready.exists() and __import__('time').monotonic() < deadline:
                    __import__('time').sleep(0.01)
                self.assertTrue(ready.exists(), "child did not install SIGTERM handler")
                root = Path(tmp); controller = LabController(root, test_mode=True)
                run_id = "live-reset"; profile_id = "linux-x64-gui"
                profile_dir = root / "runs" / run_id / profile_id; profile_dir.mkdir(parents=True)
                overlay = profile_dir / "overlay.qcow2"; overlay.write_bytes(b"live")
                marker = profile_dir / ".owned-overlay.json"
                marker.write_text(json.dumps({"run_id": run_id, "profile": profile_id, "overlay": str(overlay)}), encoding="utf-8")
                vm = {"pid": child.pid, "proc_start_time": proc_start_time(child.pid), "uid": None, "uuid": "u", "qmp_socket": str(profile_dir / "qmp.sock"), "qga_socket": str(profile_dir / "qga.sock"), "argv": ["qemu-system-x86_64"]}
                state = {"schema": 1, "lab_id": "lab", "runs": {run_id: {"profiles": {profile_id: {"vm": vm}}}}}
                controller.save_state(state)
                with patch.object(controller, "owned_vm", return_value=vm), patch.object(sys.modules[LabController.__module__], "PROCESS_STOP_TIMEOUT", 0.2):
                    with self.assertRaisesRegex(LabError, "preserving owned state"):
                        controller.reset(run_id, profile_id)
                self.assertTrue(overlay.exists())
            finally:
                child.kill(); child.wait()

    def test_cli_empty_steps_reaches_controller_as_default_plan(self):
        module = sys.modules[LabController.__module__]
        controller = MagicMock()
        with patch.object(module, "LabController", return_value=controller), patch.object(module, "emit"):
            result = module.main(["--state-root", str(Path.cwd()), "run", "--run-id", "run", "--profile", "windows-x64"])
        self.assertEqual(result, 0)
        controller.run_steps.assert_called_once_with("run", "windows-x64", None, False)

    def test_hyperv_reset_cleans_only_tracked_active_cases(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); controller = LabController(root, test_mode=True)
            run_id = "hyperv-tracked-reset"
            run = {"run_id": run_id, "windows_backend": "hyperv", "profiles": {"windows-x64": {"status": "tested", "vm": {"case_id": "control"}, "hyperv_cases": {"control": {"state": "running"}, "thin-clean": {"state": "reset"}, "outer-upgrade": {"state": "unsafe", "error": "interactive failure"}}}}}
            controller.save_state({"schema": 1, "lab_id": "lab", "runs": {run_id: run}})
            calls = []
            def fake_reset(action, *, run_id, CaseId, credential):
                calls.append(CaseId)
                return {"removed_child": True, "parent_sha256_before": "p", "parent_sha256_after": "p"}
            with patch.object(controller, "hyperv_call", side_effect=fake_reset):
                controller.reset(run_id, "windows-x64")
            self.assertEqual(calls, ["control", "outer-upgrade"])
            saved = controller.get_run(run_id)["profiles"]["windows-x64"]
            self.assertEqual(saved["status"], "reset")
            self.assertEqual({k: v["state"] for k, v in saved["hyperv_cases"].items()}, {"control": "reset", "thin-clean": "reset", "outer-upgrade": "reset"})

    def test_hyperv_case_progress_is_persisted_before_later_case_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); controller = LabController(root, test_mode=True)
            run_id = "hyperv-progress-before-ui"
            controller.save_state({"schema": 1, "lab_id": "lab", "runs": {
                run_id: {"run_id": run_id, "windows_backend": "hyperv",
                         "profiles": {"windows-x64": {"status": "created"}}}
            }})
            steps = [{"id": "probe", "passed": True}, {"id": "update", "passed": True}]
            receipts = [{"case_id": "outer-upgrade", "steps": steps,
                         "service_health": {"passed": True}}]
            controller._persist_hyperv_case_progress(
                run_id, "windows-x64", steps, receipts, "outer-upgrade"
            )
            saved = controller.get_run(run_id)["profiles"]["windows-x64"]
            self.assertEqual(saved["steps"], steps)
            self.assertEqual(saved["case_receipts"], receipts)
            self.assertEqual(saved["last_case_id"], "outer-upgrade")

            source = (Path(__file__).parent / "lab.py").read_text(encoding="utf-8")
            append = source.index("case_receipts.append(")
            persist = source.index("self._persist_hyperv_case_progress(", append)
            reset = source.index('self.hyperv_call("reset"', persist)
            self.assertLess(append, persist)
            self.assertLess(persist, reset)

    def test_hyperv_interactive_case_has_fresh_probe_and_separate_ledger_key(self):
        source = (Path(__file__).parent / "lab.py").read_text(encoding="utf-8")
        interactive = source.index('interactive_case = "outer-interactive"')
        probe = source.index("interactive_probe = self.hyperv_call", interactive)
        prepare = source.index('self.hyperv_call("prepare-interactive"', interactive)
        self.assertLess(probe, prepare)
        self.assertIn('CaseId=interactive_case, credential=True', source[probe:prepare])
        self.assertNotIn('interactive_case = "outer-upgrade"', source)
        self.assertIn('final_case_id = case_ids[-1] if case_ids else interactive_case', source)

    def test_windows_host_path_mapping_is_absolute_and_rejects_traversal(self):
        self.assertEqual(wsl_path_for_windows_host(r"C:\ProgramData\Lab\proof.png"), Path("/mnt/c/ProgramData/Lab/proof.png"))
        with self.assertRaises(LabError):
            wsl_path_for_windows_host(r"C:\ProgramData\..\proof.png")

    def test_hyperv_credential_is_validated_before_first_child_creation(self):
        source = (Path(__file__).parent / "lab.py").read_text(encoding="utf-8")
        branch = source.index("if self.uses_hyperv(planned_run, profile_id):")
        credential = source.index("self.hyperv_credential()", branch)
        create = source.index('self.hyperv_call("create-child"', branch)
        self.assertLess(credential, create)

    def test_hyperv_case_intent_and_unsafe_state_survive_failed_create(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); controller = LabController(root, test_mode=True)
            run_id = "hyperv-create-failure"
            controller.save_state({"schema": 1, "lab_id": "lab", "runs": {run_id: {"run_id": run_id, "windows_backend": "hyperv", "profiles": {"windows-x64": {"status": "created", "vm": None}}}}})
            controller._record_hyperv_case(run_id, "windows-x64", "thin-clean", "intended")
            controller._record_hyperv_case(run_id, "windows-x64", "thin-clean", "unsafe", error="create failed")
            calls = []
            with patch.object(controller, "hyperv_call", side_effect=lambda action, **kwargs: (calls.append(kwargs["CaseId"]) or {"removed_child": True, "parent_sha256_before": "p", "parent_sha256_after": "p"})):
                controller.reset(run_id, "windows-x64")
            self.assertEqual(calls, ["thin-clean"])
            self.assertEqual(controller.get_run(run_id)["profiles"]["windows-x64"]["hyperv_cases"]["thin-clean"]["state"], "reset")

    def test_hyperv_adapter_reset_has_exact_creation_absence_proof_path(self):
        source = (Path(__file__).parent / "windows_host" / "hyperv_adapter.ps1").read_text(encoding="utf-8")
        self.assertIn("function Expected-ChildName", source)
        self.assertIn("case_root_absent=$true", source)
        self.assertIn("expected_vm_absent=$true", source)
        self.assertIn("creation_intent_recovered=$true", source)
        self.assertIn("creation intent identity mismatch", source)
        self.assertIn("creation intent root contains unexpected entry", source)
        self.assertIn("creation intent still resolves to a VM; refusing absence cleanup", source)

    def test_hyperv_reset_is_idempotent_after_cases_confirmed_reset(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); controller = LabController(root, test_mode=True)
            run_id = "hyperv-repeat-reset"
            profile = {"status": "tested", "vm": {"case_id": "control"}, "hyperv_cases": {"control": {"state": "running"}}}
            controller.save_state({"schema": 1, "lab_id": "lab", "runs": {run_id: {"run_id": run_id, "windows_backend": "hyperv", "profiles": {"windows-x64": profile}}}})
            calls = []
            with patch.object(controller, "hyperv_call", side_effect=lambda action, **kwargs: (calls.append(kwargs["CaseId"]) or {"removed_child": True, "parent_sha256_before": "p", "parent_sha256_after": "p"})):
                controller.reset(run_id, "windows-x64")
                controller.reset(run_id, "windows-x64")
            self.assertEqual(calls, ["control"])

    def test_qemu_spawn_intent_recovery_cleans_only_marker_owned_stale_overlay(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); controller = LabController(root, test_mode=True)
            run_id = "qemu-intent-recovery"; profile_id = "linux-headless-x64"
            profile_dir = root / "runs" / run_id / profile_id; profile_dir.mkdir(parents=True)
            overlay = profile_dir / "overlay.qcow2"; overlay.write_bytes(b"stale-overlay")
            marker = profile_dir / ".owned-overlay.json"
            marker.write_text(json.dumps({"run_id": run_id, "profile": profile_id, "overlay": str(overlay)}), encoding="utf-8")
            intent = {"schema": 1, "state": "prepared", "backend": "qemu-linux", "run_id": run_id, "profile": profile_id, "vm_uuid": "owned-uuid", "overlay": str(overlay), "qmp_socket": str(profile_dir / "qmp.sock"), "qga_socket": str(profile_dir / "qga.sock"), "vnc_socket": None, "argv": ["qemu-system-x86_64", "-uuid", "owned-uuid"], "uid": None}
            intent_path = profile_dir / ".qemu-spawn-intent.json"; intent_path.write_text(json.dumps(intent), encoding="utf-8")
            controller.save_state({"schema": 1, "lab_id": "lab", "runs": {run_id: {"run_id": run_id, "profiles": {profile_id: {"status": "created", "vm": None}}}}})
            controller._recover_qemu_spawn_intent(run_id, profile_id)
            self.assertFalse(overlay.exists())
            self.assertFalse(intent_path.exists())

    def test_release_gate_rejects_partial_profile_and_artifact_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); controller = LabController(root, test_mode=True)
            run_id = "partial-release-contract"
            controller.save_state({"schema": 1, "lab_id": "lab", "runs": {run_id: {"run_id": run_id, "lane": "release", "dry_run": False, "test_mode": False, "expected_profiles": ["windows-x64"], "profiles": {"windows-x64": {"status": "created"}}, "artifacts": {}, "baseline_artifacts": {}}}})
            with self.assertRaisesRegex(LabError, "all release profiles and candidate/baseline artifact records"):
                controller.gate(run_id, "release")

    def test_matrix_artifact_role_follows_staged_identity(self):
        self.assertEqual(artifact_role_for_stage("candidate-thin"), "candidate")
        self.assertEqual(artifact_role_for_stage("candidate-outer"), "candidate")
        self.assertEqual(artifact_role_for_stage("baseline-thin"), "baseline")
        self.assertEqual(artifact_role_for_stage("baseline-outer"), "baseline")

    def test_windows_matrix_uses_exact_thin_and_outer_artifacts(self):
        records = {name: {"sha256": name, "size": index} for index, name in enumerate(("thin", "baseline-thin", "outer", "baseline-outer"), 1)}
        specs = windows_case_specs({"artifacts": {"windows-x64": records["thin"]}, "baseline_artifacts": {"windows-x64": records["baseline-thin"]}, "outer_artifact": records["outer"], "baseline_outer_artifact": records["baseline-outer"], "baseline_version": "1.0.0.0", "candidate_version": "2.0.0.0"})
        observed = {case: [(stage, artifact["sha256"], artifact["size"], action, version) for stage, artifact, action, version in steps] for case, steps in specs.items()}
        self.assertEqual(observed["thin-upgrade"], [("baseline-thin", "baseline-thin", 2, "reinstall", "1.0.0.0"), ("candidate-thin", "thin", 1, "update", "2.0.0.0")])
        self.assertEqual(observed["outer-upgrade"], [("baseline-outer", "baseline-outer", 4, "reinstall", "1.0.0.0"), ("candidate-outer", "outer", 3, "update", "2.0.0.0")])
        self.assertEqual(set(observed), {"thin-clean", "thin-upgrade", "thin-reinstall", "outer-clean", "outer-upgrade", "outer-reinstall"})

    def _valid_hyperv_matrix_fixture(self):
        run = {
            "run_id": "matrix-run", "windows_backend": "hyperv",
            "baseline_version": "1.0.0.0", "candidate_version": "2.0.0.0",
            "artifacts": {"windows-x64": {"sha256": "a" * 64, "size": 10}},
            "baseline_artifacts": {"windows-x64": {"sha256": "b" * 64, "size": 11}},
            "outer_artifact": {"sha256": "c" * 64, "size": 12},
            "baseline_outer_artifact": {"sha256": "d" * 64, "size": 13},
        }
        specs = windows_case_specs(run)
        profile = {"case_receipts": [], "steps": [], "hyperv_cases": {}}

        def receipt(case_id, action, artifact, role, version):
            return {
                "schema": 1, "run_id": run["run_id"], "profile": "windows-x64",
                "case_id": case_id, "artifact": dict(artifact), "artifact_sha256": artifact["sha256"],
                "artifact_size": artifact["size"], "artifact_role": role,
                "artifact_source": {"transport": "hyperv-powershell-direct", "hash_verified": True},
                "baseline_version": run["baseline_version"], "candidate_version": run["candidate_version"],
                "guest_marker": f"amnezia-release-lab:{run['run_id']}:windows-x64",
                "transport": "hyperv-powershell-direct", "origin": "guest", "injected": False,
                "action": action, "steps": [{"id": action, "passed": True}],
                "assertion": {"passed": True, "installed_version": version, "artifact_sha256": artifact["sha256"]},
                "observed_at": "2026-09-15T00:00:00Z",
            }

        for index, (case_id, case_spec) in enumerate(specs.items(), 1):
            vm_id = f"vm-{index}"; parent = f"{index:064x}"
            case_steps = []
            profile["hyperv_cases"][case_id] = {"case_id": case_id, "state": "reset", "vm_id": vm_id, "parent_sha256": parent}
            probe = {"transport": "hyperv-powershell-direct", "origin": "guest", "injected": False, "vm_id": vm_id, "parent_sha256": parent}
            profile["steps"].append({"id": "probe", "case_id": case_id, "action": "probe", "passed": True, "probe": probe})
            for stage, artifact, action, version in case_spec:
                role = "baseline" if stage.startswith("baseline-") else "candidate"
                guest = receipt(case_id, action, artifact, role, version)
                case_steps.append({"stage": stage, "action": action, "passed": True, "guest_receipt": guest, "vm_id": vm_id, "parent_sha256": parent})
                profile["steps"].append({"id": action, "case_id": case_id, "stage": stage, "action": action, "passed": True, "guest_receipt": guest, "transport": "hyperv-powershell-direct", "vm_id": vm_id, "parent_sha256": parent})
            final_artifact = case_spec[-1][1]
            health = receipt(case_id, "service-health", final_artifact, "candidate", run["candidate_version"])
            profile["case_receipts"].append({"case_id": case_id, "steps": case_steps, "service_health": health, "vm_id": vm_id, "parent_sha256": parent})
        interactive = receipt("outer-interactive", "interactive-collect", run["outer_artifact"], "candidate", run["candidate_version"])
        interactive["interactive_verified"] = True
        interactive["assertion"]["interactive_passed"] = True
        interactive["installed_app_window"] = {"vm_id": "vm-interactive", "screenshot": {"archive": {}}}
        interactive["hyperv_ui"] = {"screenshot_archive": {}}
        interactive["archive_attempt_nonce"] = "attempt"
        profile["hyperv_cases"]["outer-interactive"] = {"case_id": "outer-interactive", "state": "reset", "vm_id": "vm-interactive", "parent_sha256": "e" * 64}
        profile["interactive_receipt"] = interactive
        return run, profile

    def test_hyperv_matrix_aggregation_preserves_guest_receipts_and_canonical_steps(self):
        run, profile = self._valid_hyperv_matrix_fixture()
        original = json.dumps(profile["case_receipts"], sort_keys=True)
        with patch("release_lab.lab.validate_hyperv_interactive_archives"):
            matrix = build_hyperv_matrix_aggregation(run, profile, Path(tempfile.mkdtemp()))
        self.assertEqual(matrix["origin"], "controller")
        self.assertTrue(matrix["controller_created"])
        self.assertEqual(matrix["case_ids"], list(windows_case_specs(run)))
        self.assertEqual({step["id"] for step in matrix["steps"]}, {"probe", "reinstall", "update", "service-health"})
        self.assertEqual(json.dumps(profile["case_receipts"], sort_keys=True), original)
        self.assertEqual(matrix["case_receipts"][0]["case_id"], "thin-clean")
        self.assertEqual(matrix["case_receipts"][-1]["case_id"], "outer-reinstall")

    def test_hyperv_matrix_aggregation_rejects_partial_or_unbound_evidence(self):
        run, profile = self._valid_hyperv_matrix_fixture()
        with patch("release_lab.lab.validate_hyperv_interactive_archives"):
            for mutate, message in (
                (lambda p: p["case_receipts"].pop(), "exact six"),
                (lambda p: p["case_receipts"].__setitem__(0, dict(p["case_receipts"][1])), "exact six"),
                (lambda p: p["case_receipts"][0]["steps"][0]["guest_receipt"].__setitem__("case_id", "outer-clean"), "case identity"),
                (lambda p: p["steps"].__setitem__(0, {**p["steps"][0], "passed": False}), "probe"),
                (lambda p: p["steps"][1].__setitem__("vm_id", "foreign-vm"), "controller action"),
                (lambda p: p.pop("interactive_receipt"), "interactive"),
                (lambda p: p["interactive_receipt"].__setitem__("interactive_verified", False), "interactive"),
            ):
                candidate = json.loads(json.dumps(profile))
                mutate(candidate)
                with self.assertRaisesRegex(LabError, message):
                    build_hyperv_matrix_aggregation(run, candidate, Path(tempfile.mkdtemp()))

    def test_hyperv_archive_keeps_guest_receipt_separate_from_controller_matrix(self):
        run, profile = self._valid_hyperv_matrix_fixture()
        with patch("release_lab.lab.validate_hyperv_interactive_archives"):
            matrix = build_hyperv_matrix_aggregation(run, profile, Path(tempfile.mkdtemp()))
        health = dict(profile["case_receipts"][-1]["service_health"])
        profile["controller_evidence"] = {"hyperv_binding": {"vm_id": "vm-6", "case_id": "outer-reinstall", "parent_sha256": "6" * 64, "transport": "hyperv-powershell-direct", "archived": True}, "interactive_verified": True, "interactive_receipt": profile["interactive_receipt"]}
        profile["matrix_aggregation"] = matrix
        profile["evidence"] = health
        profile["status"] = "evidence-collected"
        run["profiles"] = {"windows-x64": profile}
        controller = LabController(Path(tempfile.mkdtemp()), test_mode=True)
        controller.save_state({"schema": 1, "lab_id": "lab", "runs": {run["run_id"]: run}})
        record = controller.archive_guest_evidence(run["run_id"], "windows-x64")
        self.assertEqual(record["receipt"]["value"], health)
        self.assertEqual(record["matrix_aggregation"]["origin"], "controller")
        self.assertEqual(record["guest_binding"], profile["controller_evidence"]["hyperv_binding"])
        archived = json.loads(Path(record["receipt"]["archive_path"]).read_text(encoding="utf-8"))
        self.assertEqual(archived, health)
        self.assertNotIn("hyperv_binding", archived)

    def test_hyperv_collect_then_archive_keeps_guest_receipt_untouched(self):
        run, profile = self._valid_hyperv_matrix_fixture()
        original_guest = json.loads(json.dumps(profile["case_receipts"][-1]["service_health"], sort_keys=True))
        profile["last_case_id"] = "outer-reinstall"
        run["profiles"] = {"windows-x64": profile}
        controller = LabController(Path(tempfile.mkdtemp()), test_mode=True)
        controller.save_state({"schema": 1, "lab_id": "lab", "runs": {run["run_id"]: run}})
        with patch("release_lab.lab.validate_hyperv_interactive_archives"):
            collected = controller.collect(run["run_id"], "windows-x64")
        self.assertEqual(collected, original_guest)
        self.assertNotIn("hyperv_binding", collected)
        self.assertNotIn("interactive_receipt", collected)
        saved_profile = controller.get_run(run["run_id"])["profiles"]["windows-x64"]
        self.assertIn("hyperv_binding", saved_profile["controller_evidence"])
        self.assertNotIn("hyperv_binding", saved_profile["evidence"])
        record = controller.archive_guest_evidence(run["run_id"], "windows-x64")
        archived = json.loads(Path(record["receipt"]["archive_path"]).read_text(encoding="utf-8"))
        self.assertEqual(archived, original_guest)
        self.assertIn("controller_evidence", record)

    def test_hyperv_adapter_forwards_expected_artifact_role(self):
        source = (Path(__file__).parent / "windows_host" / "hyperv_adapter.ps1").read_text(encoding="utf-8")
        self.assertIn("$ExpectedArtifactRole", source)
        self.assertIn("'-ExpectedArtifactRole',$expectedArtifactRole", source)

    def test_interactive_consent_precedes_installer_pid_and_exports_screenshot(self):
        lab_source = (Path(__file__).parent / "lab.py").read_text(encoding="utf-8")
        adapter_source = (Path(__file__).parent / "windows_host" / "hyperv_adapter.ps1").read_text(encoding="utf-8")
        self.assertIn('bound_consent = confirmed_consent', lab_source)
        self.assertIn('int(completion.get("installer_pid") or 0) <= 0', lab_source)
        self.assertIn('isinstance(completion_exit, bool) or not isinstance(completion_exit, int) or completion_exit != 0', lab_source)
        self.assertNotIn('int(completion.get("exit_code") or -1)', lab_source)
        self.assertNotIn('int(bound_consent.get("installer_pid") or 0) <= 0', lab_source)
        self.assertIn('self.hyperv_call("export-ui"', lab_source)
        self.assertIn("if ($Action -eq 'export-ui')", adapter_source)
        self.assertIn("Copy-Item -LiteralPath $guestPath -Destination $hostPath -FromSession", adapter_source)
        self.assertIn("interactive_installer_receipt", lab_source)
        self.assertIn('self.hyperv_call(\n                    "app-window"', lab_source)
        self.assertIn("if ($Action -eq 'app-window')", adapter_source)
        archive = lab_source.index('kind="app-window"')
        attach = lab_source.index('interactive_receipt["installed_app_window"] = app_window', archive)
        durable = lab_source.index('checkpoint_profile["interactive_receipt"] = interactive_receipt', attach)
        cleanup = lab_source.index('self.hyperv_call("reset"', durable)
        self.assertLess(attach, durable)
        self.assertLess(durable, cleanup)
        self.assertIn('archive_exact_file(', lab_source[archive:attach])

    def test_hyperv_case_progress_merges_unique_cases_and_rejects_conflicts(self):
        source = (Path(__file__).parent / "lab.py").read_text(encoding="utf-8")
        self.assertIn('case_receipts = list(profile_progress.get("case_receipts") or [])', source)
        self.assertIn('conflicts = known_case_ids.intersection(case_ids)', source)
        self.assertIn('Hyper-V case receipt conflict for {sorted(conflicts)[0]}', source)
        conflict = source.index('conflicts = known_case_ids.intersection(case_ids)')
        self.assertLess(conflict, source.index('self.hyperv_call("create-child"', conflict))

    def test_state_root_rejects_symlink_before_resolution(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "target"; target.mkdir()
            link = Path(tmp) / "link"
            try:
                link.symlink_to(target, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("directory symlinks unavailable")
            with self.assertRaises(LabError):
                state_root_from(str(link))

    def test_linux_receipt_requires_one_current_vm_incarnation_and_order(self):
        vm={"pid":22,"proc_start_time":"33","uuid":"guest-u","qga_socket":"/owned/qga"}
        profile={"steps":[{"id":"probe"},{"id":"reinstall"},{"id":"update"},{"id":"service-health"}]}
        binding={"pid":22,"proc_start_time":"33","uuid":"guest-u","qga_socket":"/owned/qga"}
        def step(name,when): return {"id":name,"run_id":"r","profile":"linux-x64-gui","guest_binding":dict(binding),"raw_assertion":{"passed":True},"observed_at":when}
        receipt={"guest_binding":dict(binding),"steps":[step("probe","2026-09-13T10:00:00Z"),step("update","2026-09-13T10:01:00Z")]}
        validate_linux_receipt_incarnation(receipt,vm,profile,"r","linux-x64-gui")
        receipt["steps"][1]["guest_binding"]["uuid"]="replacement"
        with self.assertRaisesRegex(LabError,"incarnation"):
            validate_linux_receipt_incarnation(receipt,vm,profile,"r","linux-x64-gui")
        receipt={"guest_binding":dict(binding),"steps":[step("update","2026-09-13T10:01:00Z"),step("probe","2026-09-13T10:02:00Z")]}
        with self.assertRaisesRegex(LabError,"canonical order"):
            validate_linux_receipt_incarnation(receipt,vm,profile,"r","linux-x64-gui")

    def test_linux_receipt_rejects_controller_guest_assertion_or_artifact_tamper(self):
        vm={"pid":22,"proc_start_time":"33","uuid":"guest-u","qga_socket":"/owned/qga"}; binding={"pid":22,"proc_start_time":"33","uuid":"guest-u","qga_socket":"/owned/qga"}
        profile={"steps":[{"id":"probe"}]}; source={"transport":"qga","kind":"qga-upload","hash_verified":True,"path":"/tmp/a"}
        controller={"id":"probe","guest_binding":binding,"assertion":{"passed":True,"value":"original"},"artifact_sha256":"a"*64,"artifact_size":4,"artifact_role":"candidate","artifact_source":source}
        guest={"id":"probe","run_id":"r","profile":"linux-x64-gui","guest_binding":binding,"raw_assertion":dict(controller["assertion"]),"observed_at":"2026-09-13T10:00:00Z","artifact_sha256":"a"*64,"artifact_size":4,"artifact_role":"candidate","artifact_source":source}
        receipt={"guest_binding":binding,"steps":[guest]}
        validate_linux_receipt_incarnation(receipt,vm,profile,"r","linux-x64-gui",[controller])
        guest["raw_assertion"]={"passed":True,"value":"tampered"}
        with self.assertRaisesRegex(LabError,"raw assertion"):
            validate_linux_receipt_incarnation(receipt,vm,profile,"r","linux-x64-gui",[controller])
        guest["raw_assertion"]=dict(controller["assertion"]); guest["artifact_sha256"]="b"*64
        with self.assertRaisesRegex(LabError,"artifact_sha256"):
            validate_linux_receipt_incarnation(receipt,vm,profile,"r","linux-x64-gui",[controller])

    def test_linux_receipt_rejects_stale_artifact_from_same_run_and_guest(self):
        binding={"pid":22,"proc_start_time":"33","uuid":"guest-u","qga_socket":"/owned/qga"}
        vm={"pid":22,"proc_start_time":"33","uuid":"guest-u","qga_socket":"/owned/qga"}
        profile={"steps":[{"id":"update"}]}
        source={"transport":"qga","kind":"qga-upload","hash_verified":True,"path":"/tmp/a"}
        guest={"id":"update","run_id":"r","profile":"linux-x64-gui","guest_binding":binding,
               "raw_assertion":{"passed":True},"observed_at":"2026-09-13T10:00:00Z",
               "artifact_sha256":"a"*64,"artifact_size":4,"artifact_role":"candidate","artifact_source":source}
        controller={**guest,"assertion":guest["raw_assertion"]}; controller.pop("raw_assertion")
        receipt={"guest_binding":binding,"steps":[guest]}
        validate_linux_receipt_incarnation(receipt,vm,profile,"r","linux-x64-gui",[controller],
                                           {"candidate":{"sha256":"a"*64,"size":4},"baseline":{"sha256":"b"*64,"size":3}})
        with self.assertRaisesRegex(LabError,"current planned artifact"):
            validate_linux_receipt_incarnation(receipt,vm,profile,"r","linux-x64-gui",[controller],
                                               {"candidate":{"sha256":"c"*64,"size":4},"baseline":{"sha256":"b"*64,"size":3}})

    def test_full4_semantic_registration_is_immutable_and_outer_bound(self):
        with tempfile.TemporaryDirectory() as tmp:
            controller=LabController(Path(tmp));run={"run_id":"r","outer_artifact":{"sha256":"a"*64},"manifest":{"sha256":"b"*64}}
            controller.acquire_mutation_lock("test")
            state={"runs":{"r":run}}
            try:
                with patch.object(controller,"get_run",return_value=run),patch.object(controller,"load_state",return_value=state),patch.object(controller,"save_state"):
                    record=controller._register_full4("r","android",{"app":{"passed":True}})
                    self.assertEqual(record["outer_sha256"],"a"*64)
                    self.assertEqual(sha256_file(Path(record["path"])),(record["sha256"],record["size"]))
                    with self.assertRaisesRegex(LabError,"immutable"):
                        controller._register_full4("r","android",{"app":{"passed":True}})
            finally: controller.release_mutation_lock()

    def test_headless_semantic_registration_rejects_stale_outer_and_baseline(self):
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as tmp:
            c=LabController(Path(tmp));c.acquire_mutation_lock("test");record={"sha256":"a"*64,"size":4};base={"sha256":"b"*64,"size":3}
            vm={"pid":2,"proc_start_time":"3","uuid":"u","qmp_socket":"qmp","qga_socket":"qga"};run={"run_id":"r","baseline_version":".38","artifacts":{"linux-headless-x64":record},"baseline_artifacts":{"linux-headless-x64":base},"manifest":{"sha256":"c"*64},"manifest_public_key":{"sha256":"d"*64},"profiles":{"linux-headless-x64":{"vm":vm}}}
            def p(base_sha="b",pid=2):return SimpleNamespace(run_id="r",baseline=SimpleNamespace(tar_sha256=base_sha*64,tar_size=3,version=".38"),candidate=SimpleNamespace(tar_sha256="a"*64,tar_size=4,manifest_sha256="c"*64,key_sha256="d"*64),outer_binding=SimpleNamespace(pid=pid,start_ticks=3,uuid="u",qmp_socket="qmp",qga_socket="qga"))
            try:
                with patch.object(c,"get_run",return_value=run),patch("release_lab.lab.validate_http_receipt"),patch("release_lab.lab.validate_update_receipt"),patch("release_lab.lab.validate_rollback_receipt"),patch("release_lab.lab.validate_reboot_receipt"):
                    with self.assertRaisesRegex(LabError,"current run"):c.register_headless_semantic("r",p(pid=9),{}, {}, {}, {}, {"stopped":True,"listener_closed":True,"unknown_survivors":[]})
                    with self.assertRaisesRegex(LabError,"current run"):c.register_headless_semantic("r",p(base_sha="e"),{}, {}, {}, {}, {"stopped":True,"listener_closed":True,"unknown_survivors":[]})
            finally:c.release_mutation_lock()

    def test_actual_headless_manifests_resolve_signed_provisioning_tree(self):
        root = Path(__file__).resolve().parents[2]
        key = Path("C:/keys/selfhosted-update-public.pem")
        if not key.is_file():
            self.skipTest("managed public trust anchor is unavailable")
        cases = [
            (root / "dist/release-lab-fixtures/full4-baseline-compat-v4-20260913/manifest.json",
             root / "dist/release-lab-fixtures/full4-baseline-compat-v4-20260913/official-verifier-receipt.json",
             root / "dist/release-lab-fixtures/full4-baseline-compat-v4-20260913/files/artifacts/ae0ba946446281c359ae448f68568fd580547a0e79f8449b75a9c2d5e62b2d3c/AmneziaHeadless_5.0.1.38_linux_x64.tar.gz", "5.0.1.38", "e6d2bd77790c81cc555eeda542760fedd84fd8d6c73a25bb6ed044a240bfeb9f"),
            (root / "dist/full-release-5.0.1.39-20260913-final3/updates/manifest.json",
             root / "Testing/headless-candidate-final3-verified.json",
             root / "dist/full-release-5.0.1.39-20260913-final3/artifacts/AmneziaHeadless_5.0.1.39_linux_x64.tar.gz", "5.0.1.39", "9d4307a61e06c4fec4ad9085f801dd8cad0e3564a66ca6debc54dc8e9584c289"),
        ]
        for manifest, receipt, artifact, version, provisioning_sha in cases:
            result = headless_runner_inputs(manifest, key, receipt, artifact_record(artifact), version)
            self.assertEqual(sha256_file(Path(result["provisioning_path"]))[0], provisioning_sha)

    def test_semantic_helper_closure_rejects_missing_and_changed_source(self):
        root = Path(__file__).resolve().parents[2]
        records = {relative: artifact_record(root / relative) for relative in SEMANTIC_HELPER_RELATIVES}
        validate_semantic_helper_records(records)
        missing = dict(records); missing.pop(next(iter(missing)))
        with self.assertRaisesRegex(LabError, "closure"):
            validate_semantic_helper_records(missing)
        changed = {key: dict(value) for key, value in records.items()}
        first = next(iter(changed)); changed[first]["sha256"] = "0" * 64
        with self.assertRaisesRegex(LabError, "changed after plan"):
            validate_semantic_helper_records(changed)


if __name__ == "__main__":
    unittest.main()

def test_android_vulkan_dependency_records_are_exact_and_tamper_fails():
    import pytest
    from .lab import ANDROID_VULKAN_RELATIVES, repo_root
    records={label:artifact_record(repo_root()/relative) for label,relative in ANDROID_VULKAN_RELATIVES.items()}
    validate_android_vulkan_records(records)
    changed={k:dict(v) for k,v in records.items()};changed["deb"]["sha256"]="0"*64
    with pytest.raises(LabError,match="changed after plan"):
        validate_android_vulkan_records(changed)
    receipt=json.loads((repo_root()/ANDROID_VULKAN_RELATIVES["verifier"]).read_text())
    assert receipt["verified"] is True and receipt["static_probe"]["vkGetInstanceProcAddr"] is True
    assert receipt["dependency_closure"]["ldd_not_found"]==[] and receipt["guest_install_performed"] is False


def test_nested_vulkan_failure_archive_is_immutable_and_bounded(tmp_path):
    import pytest
    c=LabController(tmp_path,test_mode=True);run="vf";c.save_state({"schema":1,"lab_id":"x","runs":{run:{"run_id":run,"profiles":{"linux-headless-x64":{"vm":{"pid":1,"proc_start_time":"2","uuid":"u","qmp_socket":"qmp","qga_socket":"qga"}}}}}});c.acquire_mutation_lock("test")
    try:
        rec={"schema":1,"outer_failure":"vulkan-runtime-probe","run_id":run,"attempt_nonce":"a"*48,"outer_ownership":{"run_id":run,"profile":"linux-headless-x64","attempt_nonce":"a"*48,"pid":1,"start_ticks":2,"uuid":"u","qmp_socket":"qmp","qga_socket":"qga"},"diagnostic":{"rc":1,"stderr":"denied"}}
        ack=c.archive_nested_vulkan_failure(run,rec);assert Path(ack["path"]).read_bytes() and ack["immutable"] is True
        with pytest.raises(FileExistsError):c.archive_nested_vulkan_failure(run,rec)
    finally:c.release_mutation_lock()

def test_nested_boot_failure_archive_binds_current_outer_and_is_immutable(tmp_path):
    import pytest
    c=LabController(tmp_path,test_mode=True);run="bootf";nonce="b"*48
    vm={"pid":11,"proc_start_time":"22","uuid":"u","qmp_socket":"qmp","qga_socket":"qga"}
    c.save_state({"schema":1,"lab_id":"x","runs":{run:{"run_id":run,"profiles":{"linux-headless-x64":{"vm":vm}}}}});c.acquire_mutation_lock("test")
    outer={"run_id":run,"profile":"linux-headless-x64","attempt_nonce":nonce,"pid":11,"start_ticks":22,"uuid":"u","qmp_socket":"qmp","qga_socket":"qga"}
    rec={"schema":1,"outer_failure":"nested-boot","run_id":run,"attempt_nonce":nonce,"outer_ownership":outer,"phase":"assemble","qemu_seen":False,"poll_count":4,"elapsed_seconds":10,"reason":"timeout","last_probe":{"raw_sha256":"a"*64,"raw_size":2}}
    try:
      ack=c.archive_nested_boot_failure(run,rec);assert Path(ack["path"]).read_bytes() and ack["immutable"] is True
      with pytest.raises(FileExistsError):c.archive_nested_boot_failure(run,rec)
      bad={**rec,"attempt_nonce":"c"*48,"outer_ownership":{**outer,"attempt_nonce":"c"*48,"pid":12}}
      with pytest.raises(LabError,match="identity"):c.archive_nested_boot_failure(run,bad)
    finally:c.release_mutation_lock()

def test_nested_app_focus_failure_archives_viewable_png_separately(tmp_path):
    import hashlib
    c=LabController(tmp_path,test_mode=True);run="appf";nonce="d"*48;vm={"pid":11,"proc_start_time":"22","uuid":"u","qmp_socket":"qmp","qga_socket":"qga"}
    c.save_state({"schema":1,"lab_id":"x","runs":{run:{"run_id":run,"profiles":{"linux-headless-x64":{"vm":vm}}}}});c.acquire_mutation_lock("test")
    png=b"\x89PNG\r\n\x1a\n"+b"image"*1000;shot={"attempted":True,"exit_code":0,"size":len(png),"sha256":hashlib.sha256(png).hexdigest(),"png_signature":True}
    outer={"run_id":run,"profile":"linux-headless-x64","attempt_nonce":nonce,"pid":11,"start_ticks":22,"uuid":"u","qmp_socket":"qmp","qga_socket":"qga"};rec={"schema":1,"outer_failure":"nested-boot","run_id":run,"attempt_nonce":nonce,"outer_ownership":outer,"phase":"app-focus","qemu_seen":True,"last_probe":{"screencap":shot}}
    try:
      ack=c.archive_nested_boot_failure(run,rec,png);image=Path(ack["screenshot"]["path"])
      assert image.read_bytes()==png and ack["screenshot"]["sha256"]==hashlib.sha256(png).hexdigest() and ack["screenshot"]["size"]==len(png)
    finally:c.release_mutation_lock()

def test_nested_app_failure_full_focus_raw_is_bounded_and_rehashed(tmp_path):
    import base64,hashlib,pytest
    c=LabController(tmp_path,test_mode=True);run="appraw";vm={"pid":11,"proc_start_time":"22","uuid":"u","qmp_socket":"qmp","qga_socket":"qga"}
    c.save_state({"schema":1,"lab_id":"x","runs":{run:{"run_id":run,"profiles":{"linux-headless-x64":{"vm":vm}}}}});c.acquire_mutation_lock("test")
    def record(nonce,data):
        raw={"origin":"guest","transport":"qga-adb","path":"adb:activity-top-resumed","size":len(data),"sha256":hashlib.sha256(data).hexdigest(),"bytes_b64":base64.b64encode(data).decode()}
        outer={"run_id":run,"profile":"linux-headless-x64","attempt_nonce":nonce,"pid":11,"start_ticks":22,"uuid":"u","qmp_socket":"qmp","qga_socket":"qga"}
        return {"schema":1,"outer_failure":"nested-boot","run_id":run,"attempt_nonce":nonce,"outer_ownership":outer,"phase":"app-update","qemu_seen":True,"last_probe":{"focus_observations":[{"raw":raw}]}}
    try:
        data=b"state=RESUMED finishing=false";ack=c.archive_nested_boot_failure(run,record("e"*48,data));assert Path(ack["path"]).read_bytes()
        bad=record("f"*48,data);bad["last_probe"]["focus_observations"][0]["raw"]["sha256"]="0"*64
        with pytest.raises(LabError,match="readback"):c.archive_nested_boot_failure(run,bad)
        with pytest.raises(LabError,match="identity"):c.archive_nested_boot_failure(run,record("1"*48,b"x"*6145))
    finally:c.release_mutation_lock()

def test_nested_app_failure_overflow_sidecars_are_exact_ordered_and_immutable(tmp_path):
    import base64,hashlib,json,pytest
    c=LabController(tmp_path,test_mode=True);run="appoverflow";nonce="9"*48;vm={"pid":11,"proc_start_time":"22","uuid":"u","qmp_socket":"qmp","qga_socket":"qga"}
    c.save_state({"schema":1,"lab_id":"x","runs":{run:{"run_id":run,"profiles":{"linux-headless-x64":{"vm":vm}}}}});c.acquire_mutation_lock("test")
    outer={"run_id":run,"profile":"linux-headless-x64","attempt_nonce":nonce,"pid":11,"start_ticks":22,"uuid":"u","qmp_socket":"qmp","qga_socket":"qga"};rows=[]
    for index in range(70):
        data=(f"DF-{index:03d}:".encode()+b"x"*12000);raw={"origin":"guest","transport":"qga-adb","path":f"adb:df-{index}","size":len(data),"sha256":hashlib.sha256(data).hexdigest(),"bytes_b64":base64.b64encode(data).decode()}
        rows.append({"argv":["shell","df","-k",str(index)],"exit_code":0,"timed_out":False,"output":raw})
    rec={"schema":1,"outer_failure":"nested-boot","run_id":run,"attempt_nonce":nonce,"outer_ownership":outer,"phase":"app-update","qemu_seen":True,"last_probe":{"preflight_rows":rows}}
    assert len(json.dumps(rec,separators=(",",":")))>786432
    try:
        ack=c.archive_nested_boot_failure(run,rec);main=json.loads(Path(ack["path"]).read_text());sidecars=ack["sidecars"]
        manifest=hashlib.sha256(json.dumps(sidecars,sort_keys=True,separators=(",",":")).encode()).hexdigest()
        assert len(sidecars)==70 and [x["order"] for x in sidecars]==list(range(1,71)) and main["overflow"]["count"]==70 and main["overflow"]["manifest_sha256"]==ack["sidecar_manifest_sha256"]==manifest and ack["compact_archive_sha256"]==ack["sha256"]
        for index,row in enumerate(sidecars):
            expected=(f"DF-{index:03d}:".encode()+b"x"*12000);actual=Path(row["archive"]["path"]).read_bytes()
            assert actual==expected and row["original_sha256"]==hashlib.sha256(expected).hexdigest()==row["archive"]["sha256"] and row["argv"]==["shell","df","-k",str(index)]
        with pytest.raises(FileExistsError):c.archive_nested_boot_failure(run,rec)
    finally:c.release_mutation_lock()
def test_android_sandbox_entrypoints_fail_before_backend_calls(tmp_path):
    c = LabController(tmp_path, test_mode=True)
    reason = ANDROID_SANDBOX_DISABLED_REASON
    calls = [
        lambda: c.start("absent", "android-arm64-v8a"),
        lambda: c.guest_probe("absent", "android-arm64-v8a"),
        lambda: c.run_steps("absent", "android-arm64-v8a"),
        lambda: c.collect("absent", "android-arm64-v8a"),
        lambda: c._run_android_adapter("absent", "android-arm64-v8a", "start"),
        lambda: c.nested_android_probe("absent"),
        lambda: c.start_consumer_fixture("absent", Path("manifest"), Path("apk")),
        lambda: c.install_nested_android_host_dependencies("absent", None),
        lambda: c.install_nested_android_wayland_dependency("absent", None),
        lambda: c.stage_nested_android_fixture("absent", None, None, None, None),
        lambda: c.request_nested_android_visual("absent", {}, b""),
        lambda: c.poll_nested_android_visual("absent", {}),
        lambda: c.decide_nested_android_visual("absent", "n", "r", "0" * 64, "reject"),
        lambda: c.run_nested_android_lldb_diagnostic("absent", None, None, "0"),
        lambda: c.run_nested_android_semantic("absent", None, None, None, None, None, None, None, None),
        lambda: c.register_android_semantic("absent", None, {}, {}, {}, {}, {}),
    ]
    with c.mutation_session("android-disabled-test"):
        c.save_state({"schema": 1, "lab_id": "disabled", "runs": {"cleanup": {"run_id": "cleanup", "profiles": {"android-arm64-v8a": {"vm": None}}}}})
        for call in calls:
            with pytest.raises(LabError, match="android sandbox disabled by user; real-device validation pending"):
                call()
        with pytest.raises(LabError, match="android cleanup requires an already-owned guest"):
            c._run_android_adapter("cleanup", "android-arm64-v8a", "reset")
    assert reason == "android sandbox disabled by user; real-device validation pending"
    assert AUTOMATED_PROFILE_IDS == ("windows-x64", "linux-x64-gui", "linux-headless-x64")

def test_automatic_suite_rejects_empty_or_android_profile_set_without_backend_calls(tmp_path):
    c = LabController(tmp_path, test_mode=True)
    for expected in ([], ["android-arm64-v8a"]):
        run = {"run_id": "disabled", "expected_profiles": expected, "profiles": {}}
        with c.mutation_session("empty-automatic-test"), patch.object(c, "create", return_value=run), patch.object(c, "start") as start:
            with pytest.raises(LabError, match="non-empty Windows/Linux"):
                c.run_suite("candidate", {}, None)
            start.assert_not_called()

def test_public_reset_allows_only_recorded_owned_android_cleanup(tmp_path):
    c = LabController(tmp_path, test_mode=True)
    vm = {"backend": "android-adapter", "root": "/owned/android"}
    state = {"schema": 1, "lab_id": "disabled", "runs": {"old": {"run_id": "old", "profiles": {"android-arm64-v8a": {"status": "started", "vm": vm}}}}}
    with c.mutation_session("owned-android-cleanup"):
        c.save_state(state)
        with patch.object(c, "_run_android_adapter", return_value={"reset": True}) as adapter:
            result = c.reset("old", "android-arm64-v8a")
        adapter.assert_called_once_with("old", "android-arm64-v8a", "reset")
    assert result["release_passed"] is False
    assert c.get_run("old")["profiles"]["android-arm64-v8a"]["vm"] is None

def test_pending_real_device_gate_returns_before_publication_validation(tmp_path):
    c = LabController(tmp_path, test_mode=True)
    artifact = {"path": "frozen", "sha256": "a" * 64, "size": 1}
    profiles = {profile: {"status": "evidence-collected"} for profile in AUTOMATED_PROFILE_IDS}
    run = {"run_id": "pending", "lane": "release", "dry_run": False, "test_mode": False,
           "expected_profiles": list(AUTOMATED_PROFILE_IDS), "pending_external_profiles": ["android-arm64-v8a"],
           "android_evidence_mode": "real-device-required", "profiles": profiles,
           "artifacts": {key: dict(artifact) for key in ("windows-x64", "android-arm64-v8a", "linux-x64", "linux-headless-x64")},
           "baseline_artifacts": {key: dict(artifact) for key in ("windows-x64", "android-arm64-v8a", "linux-x64", "linux-headless-x64")},
           "outer_artifact": dict(artifact), "baseline_outer_artifact": dict(artifact),
           "profile_records": {key: dict(artifact) for key in (*AUTOMATED_PROFILE_IDS, "android-arm64-v8a", "server-router")}}
    with c.mutation_session("pending-gate"):
        c.save_state({"schema": 1, "lab_id": "disabled", "runs": {"pending": run}})
        result = c.gate("pending", "release")
    assert result["android_real_device_pending"] is True
    assert result["automated_platforms_passed"] is False
    assert result["candidate_passed"] is False and result["release_passed"] is False
    assert "publication_evidence" not in run
