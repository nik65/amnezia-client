"""Controller guard tests; these never execute a guest or product binary."""
import copy
import contextlib
import hashlib
import json
from pathlib import Path
import tempfile
import types
import sys
import unittest
from unittest.mock import patch

from deploy.release_lab import awg_migration_gui as gui
from deploy.release_lab.lab import LabError, artifact_record, build_parser


def listing(*blocks):
    return "7-Zip\nPath = outer.7z\n\n----------\n" + "\n\n".join(blocks) + "\n"


class ArchiveGuards(unittest.TestCase):
    def test_regular_members_and_directory(self):
        text = listing("Path = bin\nSize = 0\nAttributes = D\nFolder = +",
                       "Path = bin/AmneziaVPN\nSize = 15\nAttributes = A -rwxr-xr-x\nFolder = -")
        self.assertEqual(gui.parse_archive_listing(text), [{"name": "bin/AmneziaVPN", "size": 15}])

    def test_rejects_traversal_absolute_links_duplicate_and_unknown_size(self):
        rows = ["Path = ../escape\nSize = 1", "Path = /bin/escape\nSize = 1",
                "Path = C:/escape\nSize = 1", "Path = bin\\escape\nSize = 1",
                "Path = bin/./escape\nSize = 1",
                "Path = bin/link\nSize = 1\nHard Link = bin/AmneziaVPN",
                "Path = bin/file\nSize = -1", "Path = bin/file\nSize = 1073741825",
                "Path = bin/file", "Path = bin/file\nSize = 1\n\nPath = bin/file\nSize = 1"]
        for row in rows:
            with self.subTest(row=row), self.assertRaises(LabError):
                gui.parse_archive_listing(listing(row))

    def test_incomplete_listing_rejected(self):
        with self.assertRaises(LabError):
            gui.parse_archive_listing("Path = bin/AmneziaVPN\nSize = 100\n")

    def test_actual_qt_archive_symlink_is_explicit_metadata(self):
        row = "Path = lib/libQt6Widgets.so.6\nSize = 23\nAttributes = A lrwxrwxrwx\nEncrypted = -"
        self.assertEqual(gui.parse_archive_listing(listing(row)), [{"name": "lib/libQt6Widgets.so.6", "size": 23, "type": "symlink"}])

    def test_symlink_targets_bound_to_complete_product_closure(self):
        records = {name: {"sha256": "a" * 64, "size": 1} for name in gui.REQUIRED_PRODUCT}
        records["/opt/AmneziaVPN/lib/regular.so.1"] = {"sha256": "b" * 64, "size": 5}
        records["/opt/AmneziaVPN/lib/alias.so"] = {"type": "symlink", "target": "regular.so.1"}
        gui.validate_product_closure(records)
        for target in ("/etc/passwd", "../../../etc/passwd", "C:/escape", "bad\\name", "bad\x00name", "bad\nname", "missing.so", "alias.so"):
            bad = copy.deepcopy(records)
            bad["/opt/AmneziaVPN/lib/alias.so"]["target"] = target
            with self.subTest(target=target), self.assertRaises(LabError):
                gui.validate_product_closure(bad)
        records["/opt/AmneziaVPN/lib/alias.so/child"] = {"sha256": "c" * 64, "size": 1}
        with self.assertRaises(LabError):
            gui.validate_product_closure(records)


class InstallGuards(unittest.TestCase):
    def setUp(self):
        self.vm = {"pid": 5, "uuid": "owned", "proc_start_time": "123", "qga_socket": "/owned/qga", "qmp_socket": "/owned/qmp"}
        self.artifact = {"path": "/candidate.run", "sha256": "a" * 64, "size": 15}
        self.row = {"action": "update", "passed": True, "artifact_role": "candidate",
                    "artifact_sha256": self.artifact["sha256"], "artifact_size": 15,
                    "artifact_source": {"transport": "qga", "kind": "qga-upload", "hash_verified": True},
                    "guest_binding": {key: value for key, value in self.vm.items() if key != "qmp_socket"},
                    "qga_response": {"exitcode": 0},
                    "assertion": {"passed": True, "official_entrypoint": True, "installed_version": "5.0.3.11",
                                  "artifact_sha256_after": self.artifact["sha256"]}}
        self.planned = {"candidate_version": "5.0.3.11", "artifacts": {"linux-x64": self.artifact},
                        "profiles": {gui.PROFILE: {"steps": [self.row]}}}

    def test_same_real_installer_guest_binding_accepted(self):
        gui.installed_candidate(self.planned, self.vm)

    def test_wrong_guest_hash_version_source_and_outcome_rejected(self):
        mutations = [lambda p: p.update(dry_run=True), lambda p: p.update(test_mode=True),
                     lambda p: p.update(automatic_migration_wan={}),
                     lambda p: p["profiles"][gui.PROFILE].update(steps=[]),
                     lambda p: p["profiles"][gui.PROFILE]["steps"][0]["guest_binding"].update(uuid="another"),
                     lambda p: p["profiles"][gui.PROFILE]["steps"][0].update(artifact_sha256="b" * 64),
                     lambda p: p["profiles"][gui.PROFILE]["steps"][0]["assertion"].update(installed_version="5.0.3.10"),
                     lambda p: p["profiles"][gui.PROFILE]["steps"][0]["assertion"].update(official_entrypoint=False),
                     lambda p: p["profiles"][gui.PROFILE]["steps"][0]["qga_response"].update(exitcode=1),
                     lambda p: p["profiles"][gui.PROFILE]["steps"][0]["artifact_source"].update(kind="host-receipt")]
        for index, mutate in enumerate(mutations):
            value = copy.deepcopy(self.planned)
            mutate(value)
            with self.subTest(index=index), self.assertRaises(LabError):
                gui.installed_candidate(value, self.vm)

    def test_controller_rejects_dry_run_before_any_guest_or_bundle_read(self):
        for settings in ({"dry_run": True, "test_mode": False}, {"dry_run": False, "test_mode": True}):
            with self.subTest(settings=settings), self.assertRaises(LabError):
                gui.run(types.SimpleNamespace(**settings), "owned", Path("missing"), Path("receipt"),
                        devtool=Path("missing"), devtool_sha256="a" * 64,
                        seven_zip=Path("missing"), seven_zip_sha256="a" * 64)


class OfflinePayloadGuards(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.artifact = self.root / "candidate.run"
        self.artifact.write_bytes(b"signed-product-fixture")
        self.tool = self.root / "devtool"
        self.tool.write_bytes(b"pinned-inspector")
        self.tool_hash = hashlib.sha256(self.tool.read_bytes()).hexdigest()

    def inspect(self):
        return gui.inspect_payload(artifact_record(self.artifact), self.tool, self.tool_hash, self.tool, self.tool_hash)

    def fake_inspectors(self, args, **kwargs):
        if args[1] == "dump":
            archive = Path(args[3]) / "metadata/AmneziaVPN/data.7z"
            archive.parent.mkdir(parents=True)
            archive.write_bytes(b"archive-fixture")
            out = b""
        elif args[1] == "l":
            out = listing("Path = bin/AmneziaVPN\nSize = 3\nAttributes = A",
                          "Path = bin/AmneziaVPN-service\nSize = 4\nAttributes = A",
                          "Path = bin/amneziawg-go\nSize = 4\nAttributes = A").encode()
        else:
            out = b"gui" if args[-1] == "bin/AmneziaVPN" else b"svc!"
        return types.SimpleNamespace(returncode=0, stdout=out, stderr=b"")

    def test_expected_bytes_derived_from_inert_dump_and_stdout_members(self):
        with patch.object(gui.subprocess, "run", side_effect=self.fake_inspectors) as process:
            result = self.inspect()
        self.assertEqual(set(result["files"]), gui.REQUIRED_PRODUCT)
        self.assertEqual(result["artifactSha256"], artifact_record(self.artifact)["sha256"])
        self.assertTrue(all(call.args[0][0] == str(self.tool) for call in process.call_args_list))
        self.assertFalse(any(call.args[0][0] == str(self.artifact) for call in process.call_args_list))
        self.assertTrue(all("-so" in call.args[0] for call in process.call_args_list if call.args[0][1] == "x"))

    def test_changed_inspector_rejected_before_subprocess(self):
        self.tool.write_bytes(b"changed")
        with patch.object(gui.subprocess, "run") as process, self.assertRaises(LabError):
            self.inspect()
        process.assert_not_called()

    def test_member_size_mismatch_rejected(self):
        def short(args, **kwargs):
            value = self.fake_inspectors(args, **kwargs)
            if args[1] == "x":
                value.stdout = b""
            return value
        with patch.object(gui.subprocess, "run", side_effect=short), self.assertRaises(LabError):
            self.inspect()

    def test_duplicate_product_members_from_component_archives_rejected(self):
        def duplicates(args, **kwargs):
            value = self.fake_inspectors(args, **kwargs)
            if args[1] == "dump":
                (Path(args[3]) / "metadata/AmneziaVPN/second.7z").write_bytes(b"second")
            return value
        with patch.object(gui.subprocess, "run", side_effect=duplicates), self.assertRaises(LabError):
            self.inspect()


class EntrypointGuards(unittest.TestCase):
    def test_gui_scenario_explicit_controller_entry(self):
        command = build_parser().parse_args(["awg-gui-run", "--run-id", "owned", "--bundle", "fixture", "--output", "receipt",
                                            "--ifw-devtool", "devtool", "--ifw-devtool-sha256", "a" * 64,
                                            "--seven-zip", "7z", "--seven-zip-sha256", "b" * 64])
        self.assertEqual(command.command, "awg-gui-run")


class ReceiptAndInputGuards(unittest.TestCase):
    def test_nested_bundle_types_and_source_revision_fail_closed(self):
        fields = {"schema": gui.BUNDLE_SCHEMA, "files": {}, "seedBundleSha256": "a" * 64,
                  "sourceCommit": "a" * 40, "goReceipt": {}, "toolsReceipt": {}, "legacyReceipt": {}}
        variants = [None, [], {**fields, "files": None}, {**fields, "goReceipt": []},
                    {**fields, "sourceCommit": "not-a-revision"}]
        with tempfile.TemporaryDirectory() as temp:
            for value in variants:
                (Path(temp) / "bundle.json").write_text(json.dumps(value))
                with self.subTest(value=value), self.assertRaises(LabError):
                    gui.validate_bundle(Path(temp))

    def test_receipt_requires_exact_attempt_all_checks_unchanged_product_cleanup(self):
        plan = {"runId": "owned", "profile": gui.PROFILE, "marker": "marker", "uuid": "uuid", "attemptNonce": "nonce",
                "expectedProductFiles": {"/opt/AmneziaVPN/bin/AmneziaVPN": {"sha256": "a" * 64, "size": 3}}}
        receipt = {"schema": gui.SCHEMA, "origin": "guest", "transport": "qga", "injected": False, "passed": True,
                   **{key: plan[key] for key in ("runId", "profile", "marker", "uuid", "attemptNonce")},
                   "checks": {"proof": True, "cleanup": True}, "productFilesAfter": plan["expectedProductFiles"], "cleanupConfirmed": True}
        observer = types.SimpleNamespace(MANDATORY_CHECKS=("proof", "cleanup"))
        with patch.dict(sys.modules, {"deploy.release_lab.awg_migration_gui_observer": observer}):
            gui.validate_receipt(receipt, plan)
            changes = [{"origin": "host"}, {"injected": True}, {"attemptNonce": "older"}, {"checks": {"proof": True}},
                       {"checks": {"proof": True, "cleanup": False}}, {"cleanupConfirmed": False}, {"productFilesAfter": {}}]
            for change in changes:
                with self.subTest(change=change), self.assertRaises(LabError):
                    gui.validate_receipt({**receipt, **change}, plan)

    @unittest.skipIf(sys.platform == "win32", "Windows symlink creation depends on developer privilege")
    def test_symlink_and_ancestor_symlink_not_inputs(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "real").mkdir()
            (root / "real/file").write_bytes(b"data")
            (root / "link").symlink_to(root / "real", target_is_directory=True)
            with self.assertRaises(LabError):
                gui.regular(root / "link/file")


class StagingGuards(unittest.TestCase):
    def execute(self, *, corrupt_readback=False, change_source=False):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            guest_source = root / "guest.py"
            guest_source.write_bytes(b"pinned-guest")
            (root / "bundle.json").write_text("{}")
            (root / "golden.json").write_text(json.dumps({"base_sha256": "f" * 64}))
            manifest = root / "manifest"
            manifest.write_bytes(b"manifest")
            key = root / "public-key"
            key.write_bytes(b"key")
            artifact = root / "candidate.run"
            artifact.write_bytes(b"installer")
            vm = {"pid": 5, "uuid": "uuid", "proc_start_time": "123", "qmp_socket": "/owned/qmp", "qga_socket": "/owned/qga"}
            planned = {"candidate_version": "5.0.3.11", "artifacts": {"linux-x64": artifact_record(artifact)},
                       "manifest": artifact_record(manifest), "manifest_public_key": artifact_record(key)}
            state = {"runs": {"owned": planned}}
            controller = types.SimpleNamespace(dry_run=False, test_mode=False, root=root,
                mutation_session=lambda name: contextlib.nullcontext(), owned_vm=lambda run, profile: vm,
                get_run=lambda run: copy.deepcopy(state["runs"][run]), load_state=lambda: copy.deepcopy(state),
                save_state=lambda value: state.update(value))
            marker = "amnezia-release-lab:owned:" + gui.PROFILE
            storage = {"/tmp/amnezia-release-lab-marker": marker.encode()}
            effects = []
            def read_file(path):
                value = storage[path]
                return b"changed-guest" if corrupt_readback and path.endswith("/guest.py") else value
            def execute_guest(executable, args, **kwargs):
                effects.append((executable, args))
                if args[0] == "-c":
                    if change_source:
                        guest_source.write_bytes(b"source-replaced-after-setup")
                    return {"exitcode": 0, "stdout": "{}"}
                self.fail("unverified guest helper executed")
            qga = types.SimpleNamespace(read_file=read_file, write_file=lambda path, content: storage.update({path: content}), guest_exec_wait=execute_guest)
            qmp = types.SimpleNamespace(request=lambda name: {"return": {"status": "running"} if name == "query-status" else {"UUID": "uuid"}})
            contract = {"files": {"guest.py": gui.digest(b"pinned-guest")}}
            with contextlib.ExitStack() as stack:
                stack.enter_context(patch.object(gui, "validate_bundle", return_value=contract))
                stack.enter_context(patch.object(gui, "installed_candidate"))
                stack.enter_context(patch.object(gui, "validate_signed_manifest"))
                stack.enter_context(patch.object(gui, "inspect_payload", return_value={"files": {}}))
                stack.enter_context(patch.object(gui, "load_profiles", return_value={gui.PROFILE: {"nic": "none", "post_seal_wan": "disabled", "golden_readiness": "golden.json"}}))
                stack.enter_context(patch.object(gui, "golden_readiness", return_value=(True, "")))
                stack.enter_context(patch.object(gui, "QgaClient", return_value=qga))
                stack.enter_context(patch.object(gui, "QmpClient", return_value=qmp))
                with self.assertRaises(LabError):
                    gui.run(controller, "owned", root, root / "receipt.json", devtool=root, devtool_sha256="a" * 64,
                            seven_zip=root, seven_zip_sha256="b" * 64)
            self.assertEqual(len(effects), 1, "only the constant ownership/resource setup may run")
            self.assertEqual(state["runs"]["owned"]["awg_gui_scenario"]["status"], "processing")

    def test_changed_staged_readback_blocks_helper_execution(self):
        self.execute(corrupt_readback=True)

    def test_source_changed_after_root_setup_blocks_helper_execution(self):
        self.execute(change_source=True)


if __name__ == "__main__":
    unittest.main()
