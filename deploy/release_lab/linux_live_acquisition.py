"""Live Linux producer for the existing ordinary and semantic lab matrix."""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import secrets
import stat
from pathlib import Path
import time

from .android_real_device_acquisition import file_record
from .live_acquisition import acquire_linux_receipt
from .trusted_acquisition_export import TrustedAcquisitionError, canonical, utc_now, utc_text


class LinuxLiveProducer:
    def __init__(self, controller, run_id, *, target, expected_gui_binary_sha256=None):
        if target not in {"linux-gui", "linux-headless"}:
            raise TrustedAcquisitionError("Linux live target required")
        self.controller, self.run_id, self.target = controller, run_id, target
        self.binary_sha = expected_gui_binary_sha256
        self._used = False
        self._start_attempted = False
        self._gui_payload = None

    def _archive_private_qga_failure(self, primary, profile):
        """Preserve bounded transport bytes locally before any guest cleanup.

        This is diagnostic evidence only. Never include its contents in an
        exception, public progress output, or an acceptance result.
        """
        from .lab import QgaGuestExecutionError
        failure, seen = primary, set()
        while failure is not None and id(failure) not in seen and len(seen) < 16:
            seen.add(id(failure))
            if isinstance(failure, QgaGuestExecutionError):
                break
            failure = failure.__cause__ or failure.__context__
        if not isinstance(failure, QgaGuestExecutionError):
            return
        capture = failure.private_failure_capture()
        body = capture.pop("body")
        limit = QgaGuestExecutionError.PRIVATE_CAPTURE_LIMIT
        if (not isinstance(body, bytes) or len(body) > limit
                or capture.get("captured_size") != len(body)
                or capture.get("limit") != limit
                or type(capture.get("original_size")) is not int
                or capture["original_size"] < len(body)
                or capture.get("truncated") is not (capture["original_size"] > len(body))):
            raise TrustedAcquisitionError("invalid bounded private QGA capture")
        if not capture["truncated"] and hashlib.sha256(body).hexdigest() != capture.get("original_sha256"):
            raise TrustedAcquisitionError("private QGA capture digest differs")
        root = Path(self.controller.root).absolute()
        if Path(self.run_id).name != self.run_id or self.run_id in {".", ".."}:
            raise TrustedAcquisitionError("invalid private archive run identity")
        parent = root / "runs" / self.run_id / profile
        if os.name != "posix":
            raise TrustedAcquisitionError("private Linux archive requires POSIX directory descriptors")
        directory = parent / ("private-qga-failure-" + secrets.token_hex(16))
        metadata = {**capture, "captured_sha256": hashlib.sha256(body).hexdigest(),
                    "run_id": self.run_id, "profile_id": profile,
                    "release_pass": False, "complete_response": not capture["truncated"]}
        # Resolve every ancestor through held directory descriptors, never
        # through a check-then-use pathname. Renames or symlinks cannot redirect
        # private writes outside the originally opened run directory.
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        parent_fd = os.open(parent.anchor, flags)
        directory_fd = None
        try:
            for component in parent.parts[1:]:
                next_fd = os.open(component, flags, dir_fd=parent_fd)
                os.close(parent_fd)
                parent_fd = next_fd
            if os.fstat(parent_fd).st_uid != os.getuid():
                raise TrustedAcquisitionError("private archive parent ownership differs")
            os.mkdir(directory.name, 0o700, dir_fd=parent_fd)
            directory_fd = os.open(directory.name, flags, dir_fd=parent_fd)
            os.fchmod(directory_fd, 0o700)
            info = os.fstat(directory_fd)
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise TrustedAcquisitionError("private archive directory ownership/mode differs")
            for name, data in (("response.private.json", body), ("metadata.private.json", canonical(metadata))):
                descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                     0o600, dir_fd=directory_fd)
                with os.fdopen(descriptor, "wb") as stream:
                    os.fchmod(stream.fileno(), 0o600)
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
            os.fsync(directory_fd)
        finally:
            if directory_fd is not None:
                os.close(directory_fd)
            os.close(parent_fd)
        self._private_failure_archive = directory

    def _wait_for_boot(self, profile):
        """No guest execution while QGA boots; PID/argv/marker/QMP stay owned."""
        from .lab import LabError, QmpClient, proc_start_time, resolve_host_executable
        controller = self.controller
        run = copy.deepcopy(controller.get_run(self.run_id))
        binding = copy.deepcopy(run["profiles"][profile].get("vm"))
        if not isinstance(binding, dict):
            raise TrustedAcquisitionError("started guest identity missing")
        marker = controller.root / "runs" / self.run_id / profile / ".owned-overlay.json"
        marker_bytes = marker.read_bytes()
        plan = controller.root / "runs" / self.run_id / "execution-plan.json"
        plan_sha = run.get("execution_plan_sha256")
        reviewed_tcg = False
        if plan_sha:
            from . import tcg_mode, lab
            validated_plan = tcg_mode.load(controller, run, lab.repo_root())
            reviewed_tcg = (getattr(controller, "linux_acceleration", None) == "tcg"
                            and isinstance(validated_plan, dict) and validated_plan.get("acceleration") == "tcg"
                            and profile in validated_plan.get("profiles", {}))
            if not reviewed_tcg:
                raise TrustedAcquisitionError("reviewed explicit TCG plan required for boot gap")
        deadline = time.monotonic() + 180
        while True:
            # Ownership failures remain fatal, rather than retrying against a
            # PID or socket which may have been replaced during the boot gap.
            if controller.get_run(self.run_id) != run:
                raise TrustedAcquisitionError("run changed during guest boot")
            proc = Path("/proc") / str(binding["pid"])
            if proc.stat().st_uid != binding["uid"] or proc_start_time(binding["pid"]) != binding["proc_start_time"]:
                raise TrustedAcquisitionError("guest PID/start/UID changed during boot")
            expected = [resolve_host_executable(binding["argv"][0]), *binding["argv"][1:]]
            if proc.joinpath("cmdline").read_bytes().rstrip(b"\0").split(b"\0") != [value.encode() for value in expected]:
                raise TrustedAcquisitionError("guest argv changed during boot")
            if marker.is_symlink() or marker.read_bytes() != marker_bytes:
                raise TrustedAcquisitionError("guest overlay ownership marker changed")
            if plan_sha and (plan.is_symlink() or hashlib.sha256(plan.read_bytes()).hexdigest() != plan_sha):
                raise TrustedAcquisitionError("guest execution plan changed during boot")
            qmp = QmpClient(Path(binding["qmp_socket"]))
            try:
                uuid = qmp.request("query-uuid").get("return", {}).get("UUID")
            except (OSError, LabError):
                if time.monotonic() >= deadline:
                    raise
                time.sleep(1)
                continue
            if uuid != binding["uuid"]:
                raise TrustedAcquisitionError("guest QMP UUID changed during boot")
            try:
                proven = controller.owned_vm(self.run_id, profile)
                if proven != binding:
                    raise TrustedAcquisitionError("guest full ownership proof changed")
                return proven
            except TrustedAcquisitionError:
                raise
            except (LabError, OSError):
                # Only reviewed TCG runs with an explicit immutable plan may
                # wait through the extra QGA requirement in their owned_vm.
                if not reviewed_tcg or time.monotonic() >= deadline:
                    raise
                time.sleep(1)

    def _binding(self, context):
        from .lab import LabController
        controller = self.controller
        if type(controller) is not LabController or controller.dry_run or controller.test_mode:
            raise TrustedAcquisitionError("canonical live Linux controller required")
        controller.assert_mutation_context()
        if controller._mutation_lock_fd is None or controller._mutation_lock_depth <= 0:
            raise TrustedAcquisitionError("live controller mutation lock required")
        context.verify()
        run = controller.get_run(self.run_id)
        if run.get("dry_run") or run.get("test_mode") or run.get("automatic_migration_wan") is not None:
            raise TrustedAcquisitionError("diagnostic/test run cannot acquire release evidence")
        if run.get("candidate_version") != context.version:
            raise TrustedAcquisitionError("Linux version binding differs")
        for field, expected in (("manifest", context.manifest), ("outer_artifact", context.outer)):
            actual = run.get(field) or {}
            if (actual.get("sha256"), actual.get("size")) != (expected["sha256"], expected["size"]):
                raise TrustedAcquisitionError("Linux exact manifest/outer binding differs")
        for platform in context.manifest_payload["platforms"]:
            expected = context.candidate(platform)
            actual = run.get("artifacts", {}).get(platform) or {}
            if (actual.get("sha256"), actual.get("size")) != (expected["sha256"], expected["size"]):
                raise TrustedAcquisitionError("Linux full release artifact closure differs")
        for name in ("profile_records", "runner_records", "semantic_helper_records"):
            records = run.get(name)
            if not isinstance(records, dict) or not records:
                raise TrustedAcquisitionError("planned Linux source capsule missing")
            for record in records.values():
                if file_record(record["path"]) != record:
                    raise TrustedAcquisitionError("Linux source/helper changed after planning")
        return run

    def _visual(self, context):
        from . import linux_gui_driver
        from . import linux_gui_payload
        from .linux_gui_driver import LinuxGuiDriver
        from .linux_gui_visual_ack import validate_root_visual_ack
        from .lab import ensure_owned_child
        if getattr(self, '_gui_fixture', None) is not None:self._gui_fixture.continuous_alive()
        driver = LinuxGuiDriver(self.controller, self.run_id, self.binary_sha)
        driver.stage_and_launch()
        collect = driver.capture_and_collect()
        if getattr(self, '_gui_fixture', None) is not None:self._gui_fixture.continuous_alive()
        ack_path = ensure_owned_child(self.controller.root,
                driver.archive / "root-visual-ack.json", "root visual acknowledgement")
        # This is the existing explicit root visual review decision, not a
        # caller-provided acceptance receipt. Root must view these exact pixels.
        print(json.dumps({"event": "trusted-gui-visual-review", "run_id": self.run_id,
                          "collect": str(driver.archive / "collect.json"),
                          "png": collect["screenshot"]["archive_record"]["path"],
                          "attempt_nonce": driver.nonce, "ack_path": str(ack_path)}), flush=True)
        deadline = time.monotonic() + 30 * 60
        while not ack_path.exists():
            if time.monotonic() >= deadline:
                raise TrustedAcquisitionError("root visual acknowledgement deadline exceeded")
            self.controller.owned_vm(self.run_id, "linux-x64-gui")
            if getattr(self, '_gui_fixture', None) is not None:self._gui_fixture.inhibitor_alive()
            time.sleep(1)
        if ack_path.is_symlink() or not ack_path.is_file() or ack_path.stat().st_size > 128 * 1024:
            raise TrustedAcquisitionError("invalid root visual acknowledgement file")
        ack_bytes = ack_path.read_bytes()
        ack = json.loads(ack_bytes)
        validate_root_visual_ack(owned_root=self.controller.root, ack=ack, collect=collect)
        if getattr(self, '_gui_fixture', None) is not None:self._gui_fixture.continuous_alive()
        cleanup = driver.cleanup()
        if (cleanup.get("terminated") is not True or cleanup.get("attempt_nonce") != driver.nonce
                or cleanup.get("pid") != collect["process"]["pid"]
                or cleanup.get("start_ticks") != collect["process"]["start_ticks"]):
            raise TrustedAcquisitionError("GUI owned process cleanup differs")
        self.controller.register_linux_visual(self.run_id, ack, collect)
        raw = {name: base64.b64encode((driver.archive / (name + ".json")).read_bytes()).decode()
               for name in ("launch", "collect", "cleanup")}
        raw["root_visual_ack"] = base64.b64encode(ack_bytes).decode()
        raw["png"] = base64.b64encode(Path(collect["screenshot"]["archive_record"]["path"]).read_bytes()).decode()
        raw["inert_payload_derivation"] = self._gui_payload
        return raw, cleanup, [file_record(Path(linux_gui_driver.__file__).absolute()),
                             file_record(Path(linux_gui_payload.__file__).absolute()), *self._gui_payload["tools"]]

    def _acquire_once(self, context):
        from . import lab
        from .lab import validate_receipt
        if self._used:
            raise TrustedAcquisitionError("live producer is single-use")
        self._used = True
        controller = self.controller
        profile = "linux-x64-gui" if self.target == "linux-gui" else "linux-headless-x64"
        started = utc_text(utc_now())
        with controller.mutation_session("trusted-linux-acquisition"):
            run = self._binding(context)
            state = run.get("profiles", {}).get(profile, {})
            if state.get("steps") or state.get("evidence_archive") or state.get("evidence") or state.get("vm"):
                raise TrustedAcquisitionError("trusted Linux acquisition requires a fresh profile")
            if self.target == "linux-gui":
                from .linux_gui_payload import derive_gui_payload
                derived = derive_gui_payload(context.candidate("linux-x64"), context.version)
                if self.binary_sha is not None and self.binary_sha != derived["binary_sha256"]:
                    raise TrustedAcquisitionError("caller GUI digest differs from exact inert candidate payload")
                self.binary_sha = derived["binary_sha256"]
                self._gui_payload = derived
            self._start_attempted = True
            controller.start(self.run_id, profile)
            self._wait_for_boot(profile)
            controller.guest_probe(self.run_id, profile)
            gui_fixture = None
            gui_desktop = None
            if self.target == "linux-gui":
                from .linux_gui_fixture import LinuxGuiFixture
                gui_fixture = LinuxGuiFixture(controller, self.run_id)
                self._gui_fixture = gui_fixture
                gui_fixture.configure_before_login()
            if gui_fixture is not None:
                controller.run_steps(self.run_id, profile, selected=['probe'])
                gui_fixture.ensure_xres_dependency_after_probe()
                controller.run_steps(self.run_id, profile, selected=['reinstall', 'update', 'service-health'])
            else:
                controller.run_steps(self.run_id, profile)
            if gui_fixture is not None:
                gui_desktop = gui_fixture.wait_after_steps()
            controller.collect(self.run_id, profile)
            ordinary = acquire_linux_receipt(controller, self.run_id, profile)
            run = self._binding(context)
            artifact = run["artifacts"]["linux-x64" if self.target == "linux-gui" else "linux-headless-x64"]
            receipt = json.loads(ordinary["raw_receipt"])
            validate_receipt(receipt, run_id=self.run_id, profile_id=profile, artifact=artifact,
                             baseline_version=run["baseline_version"], candidate_version=run["candidate_version"], expected_role="candidate")
            # Headless semantic reboot intentionally clears guest /run. Preserve
            # the original ordinary receipt while that incarnation is still up.
            controller.archive_guest_evidence(self.run_id, profile)
            provenance = [file_record(Path(__file__).absolute()), file_record(Path(lab.__file__).absolute())]
            if self.target == "linux-gui":
                semantic, semantic_cleanup, helpers = self._visual(context)
                semantic["desktop_fixture_diagnostic"] = gui_desktop
                provenance.extend(gui_desktop["source_records"])
                provenance.extend(helpers)
                semantics = {"steps": True, "visual": True, "cleanup": True}
            else:
                from .linux_headless_driver import build_headless_driver
                driver = build_headless_driver(controller, self.run_id, context)
                semantic = driver.run()
                required = {"http", "update", "rollback", "reboot", "cleanup"}
                if not isinstance(semantic, dict) or not required.issubset(semantic):
                    raise TrustedAcquisitionError("complete existing headless semantics required")
                controller.register_headless_semantic(self.run_id, driver.plan,
                    semantic["http"], semantic["update"], semantic["rollback"], semantic["reboot"], semantic["cleanup"])
                semantic_cleanup = semantic["cleanup"]
                provenance.append(file_record(Path(__import__(driver.__class__.__module__, fromlist=["__file__"]).__file__).absolute()))
                semantics = {"steps": True, "update": True, "rollback": True, "reboot": True, "cleanup": True}
            self._binding(context)
            binding = controller.owned_vm(self.run_id, profile)
            if gui_fixture is not None:gui_fixture.close()
            reset = controller.reset(self.run_id, profile)
            current = controller.get_run(self.run_id)["profiles"][profile]
            overlay = controller.root / "runs" / self.run_id / profile / "overlay.qcow2"
            if (current.get("vm") is not None or overlay.exists()
                    or any(Path(binding[key]).exists() for key in ("qmp_socket", "qga_socket"))):
                raise TrustedAcquisitionError("Linux owned guest cleanup incomplete")
            self._binding(context)
            ordinary_json = {key: value for key, value in ordinary.items() if key != "raw_receipt"}
            run = controller.get_run(self.run_id)
            provenance.extend(record for name in ("profile_records", "runner_records", "semantic_helper_records") for record in run[name].values())
            provenance = list({record["path"]: record for record in provenance}.values())
            return {"target": self.target, "runId": self.run_id, "profileId": profile,
                    "startedAt": started, "completedAt": utc_text(utc_now()),
                    "rawCapture": canonical({"ordinary": ordinary_json,
                        "original_receipt": base64.b64encode(ordinary["raw_receipt"]).decode(), "semantic": semantic}),
                    "cleanupCapture": canonical({"semantic_cleanup": semantic_cleanup, "owned_reset": reset,
                        "overlay_absent": True, "qmp_absent": True, "qga_absent": True}),
                    "semantics": semantics, "provenance": provenance}

    def acquire(self, context):
        from .lab import LabController
        controller = self.controller
        if type(controller) is not LabController or controller.dry_run or controller.test_mode:
            raise TrustedAcquisitionError("canonical live Linux controller required")
        # Keep this outer lock held through failure cleanup as well. Nested
        # canonical operations cannot expose a gap to another controller run.
        with controller.mutation_session("trusted-linux-acquisition-lifecycle"):
            try:
                return self._acquire_once(context)
            except BaseException as primary:
                profile = "linux-x64-gui" if self.target == "linux-gui" else "linux-headless-x64"
                if not self._start_attempted:
                    raise
                try:
                    self._archive_private_qga_failure(primary, profile)
                except BaseException as private_archive_error:
                    primary.add_note("private QGA failure archive unavailable: " + type(private_archive_error).__name__)
                try:
                    state = controller.get_run(self.run_id).get("profiles", {}).get(profile, {})
                    if isinstance(state.get("vm"), dict):
                        self._wait_for_boot(profile)
                        if not state.get("evidence_archive"):
                            try:
                                controller.archive_guest_evidence(self.run_id, profile, error=primary)
                            except Exception as archive_error:
                                primary.add_note("failure evidence archive unavailable: " + type(archive_error).__name__)
                        # Only a fresh full owned_vm proof permits canonical
                        # cleanup. Lost ownership preserves the guest for review.
                        controller.owned_vm(self.run_id, profile)
                        fixture=getattr(self, '_gui_fixture', None)
                        if fixture is not None:
                            try:fixture.close()
                            except BaseException as fixture_cleanup_error:primary.add_note('owned GUI fixture cleanup: '+type(fixture_cleanup_error).__name__)
                        controller.reset(self.run_id, profile)
                    else:
                        intent = controller._qemu_spawn_intent_path(self.run_id, profile)
                        marker = controller.root / "runs" / self.run_id / profile / ".owned-overlay.json"
                        if intent.exists() or marker.exists():
                            # Canonical reset independently verifies and
                            # recovers only this fresh run's spawn ownership.
                            controller.reset(self.run_id, profile)
                except BaseException as cleanup_error:
                    primary.add_note("owned Linux failure cleanup incomplete; preserve guest: " + type(cleanup_error).__name__)
                raise
