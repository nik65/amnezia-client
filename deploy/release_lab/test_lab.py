import json
import ast
import os
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

try:
    from .lab import LabController, LabError, QmpClient, ensure_owned_child, golden_readiness, load_profiles, proc_start_time, require_qmp_return, sha256_file, sha256_tree, state_root_from, validate_receipt, wait_owned_process_exit
except ImportError:  # direct invocation from this directory
    from lab import LabController, LabError, QmpClient, ensure_owned_child, golden_readiness, load_profiles, proc_start_time, require_qmp_return, sha256_file, sha256_tree, state_root_from, validate_receipt, wait_owned_process_exit


class ReleaseLabContractTests(unittest.TestCase):
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
            run["profiles"]["windows-x64"]["status"] = "evidence-collected"
            run["profiles"]["windows-x64"]["evidence"] = {"transport": "qga", "interactive_verified": True}
            run["profiles"]["windows-x64"]["steps"] = [{"id": step, "passed": True} for step in ("probe", "reinstall", "update", "service-health")]
            state = controller.load_state(); state["runs"]["candidate"] = run; controller.save_state(state)
            with self.assertRaises(LabError):
                controller.gate("candidate", "candidate", outer_artifact=outer)

    def test_real_receipt_requires_marker_transport_and_steps(self):
        receipt = {
            "schema": 1,
            "run_id": "run-1",
            "profile": "windows-x64",
            "artifact": "outer.exe",
            "artifact_sha256": "a" * 64,
            "baseline_version": "5.0.1.37",
            "candidate_version": "5.0.1.38",
            "guest_marker": "amnezia-release-lab:run-1:windows-x64",
            "transport": "qga",
            "steps": [{"id": "probe", "passed": True}],
            "observed_at": "2026-09-08T00:00:00Z",
        }
        validate_receipt(receipt, run_id="run-1", profile_id="windows-x64", artifact={"sha256": "a" * 64})
        receipt["transport"] = "host-file"
        with self.assertRaises(LabError):
            validate_receipt(receipt, run_id="run-1", profile_id="windows-x64", artifact={"sha256": "a" * 64})

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
            manifest = root / "manifest.json"; manifest.write_text("{}", encoding="utf-8")
            public_key = root / "public.pem"; public_key.write_text("public", encoding="utf-8")
            with self.assertRaisesRegex(LabError, "verified baseline/candidate provisioning receipts"):
                controller.create(
                    "candidate", {"linux-headless-x64": candidate},
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
        child = subprocess.Popen([sys.executable, "-c", "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(10)"])
        try:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); controller = LabController(root, test_mode=True)
                run_id = "live-reset"; profile_id = "linux-x64-gui"
                profile_dir = root / "runs" / run_id / profile_id; profile_dir.mkdir(parents=True)
                overlay = profile_dir / "overlay.qcow2"; overlay.write_bytes(b"live")
                marker = profile_dir / ".owned-overlay.json"
                marker.write_text(json.dumps({"run_id": run_id, "profile": profile_id, "overlay": str(overlay)}), encoding="utf-8")
                vm = {"pid": child.pid, "proc_start_time": proc_start_time(child.pid), "uid": None, "uuid": "u", "qmp_socket": str(profile_dir / "qmp.sock"), "qga_socket": str(profile_dir / "qga.sock"), "argv": ["qemu-system-x86_64"]}
                state = {"schema": 1, "lab_id": "lab", "runs": {run_id: {"profiles": {profile_id: {"vm": vm}}}}}
                controller.save_state(state)
                with patch.object(controller, "owned_vm", return_value=vm), patch("deploy.release_lab.lab.PROCESS_STOP_TIMEOUT", 0.2):
                    with self.assertRaisesRegex(LabError, "preserving owned state"):
                        controller.reset(run_id, profile_id)
                self.assertTrue(overlay.exists())
        finally:
            child.kill(); child.wait()

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


if __name__ == "__main__":
    unittest.main()
