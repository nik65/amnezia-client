"""Private pre-HTTP publisher diagnostics; QGA/HTTP are mocked, nothing is published.

These tests never start a guest, touch ADB, install an artifact, or reach the
network.  They assert that private evidence is preserved before cleanup can
reset the owned guest, that the pointer belongs to exactly one attempt nonce,
and that JSON escaping cannot silently discard a bounded capture.
"""
import base64
import hashlib
import io
import json
import os
import stat
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

try:
    from . import publisher_controller as module
except ImportError:
    import publisher_controller as module

try:
    from .test_publisher_controller import FakeController, FakeOps
except ImportError:
    from test_publisher_controller import FakeController, FakeOps

NONCE_A = "a" * 48
NONCE_B = "b" * 48
NONCE_C = "c" * 48
MANIFEST = {"size": 2, "sha256": "0" * 64}


def qga_stub(output=None, sync=True):
    """QGA stand-in that only records the calls it receives."""
    class Qga:
        calls = []

        def __init__(self, path, timeout=None):
            Qga.calls.append(("create", str(path), timeout))

        def sync(self):
            Qga.calls.append(("sync",))
            return sync

        def guest_exec_wait(self, command, args, timeout=None):
            Qga.calls.append(("exec", command, list(args), timeout))
            return dict(output or {"exitcode": 0, "stdout": "private-server-output", "stderr": ""})
    return Qga


class SnapshotPermissionsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="amnezia-pre-http-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        if os.name == "posix":
            self.root.chmod(0o700)

    def snapshot(self, value, label="client", nonce=NONCE_A, run_id="owned-run"):
        return module._private_publication_snapshot(self.root, run_id, "publisher-clean", nonce, label, value)

    @unittest.skipUnless(os.name == "posix", "private diagnostics require POSIX authority")
    def test_private_file_and_directory_modes_without_overwrite(self):
        first = self.snapshot({"private": "value"})
        second = self.snapshot({"private": "other"})
        self.assertEqual(first["status"], "preserved")
        self.assertEqual(second["status"], "preserved")
        self.assertNotEqual(first["path"], second["path"])
        path = Path(first["path"])
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(path.parent.parent.stat().st_mode), 0o700)
        self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["raw"], {"private": "value"})
        self.assertEqual(len(list(path.parent.glob("*.json"))), 2)

    @unittest.skipUnless(os.name == "posix", "private diagnostics require POSIX authority")
    def test_each_nonce_has_its_own_private_directory(self):
        first = self.snapshot({"attempt": "first"}, nonce=NONCE_A)
        second = self.snapshot({"attempt": "second"}, nonce=NONCE_B)
        self.assertEqual(first["status"], "preserved")
        self.assertEqual(second["status"], "preserved")
        for record, nonce, expected in ((first, NONCE_A, "first"), (second, NONCE_B, "second")):
            path = Path(record["path"])
            self.assertEqual(path.parent.parent.name, nonce)
            self.assertEqual(path.parent.name, "private-pre-http")
            binding = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(binding["attempt_nonce"], nonce)
            self.assertEqual(binding["diagnostic_only"], True)
            self.assertEqual(binding["label"], "client")
            self.assertEqual(binding["raw"], {"attempt": expected})

    @unittest.skipUnless(os.name == "posix", "private diagnostics require POSIX authority")
    def test_identity_and_path_parts_are_validated_before_writing(self):
        for kwargs in (
            {"nonce": "not-a-nonce"},
            {"nonce": "A" * 48},
            {"run_id": "../escape"},
            {"run_id": ""},
            {"label": "raw"},
        ):
            with self.subTest(**kwargs):
                arguments = {"value": {"private": "value"}, "label": "client", "nonce": NONCE_A, "run_id": "owned-run"}
                arguments.update(kwargs)
                record = module._private_publication_snapshot(self.root, arguments["run_id"], "publisher-clean", arguments["nonce"], arguments["label"], arguments["value"])
                self.assertEqual(record["status"], "unavailable-identity")
        self.assertEqual(list(self.root.glob("exports/**/*.json")), [])

    def test_windows_never_persists_unprotected_raw(self):
        with patch.object(module.os, "name", "nt"):
            result = self.snapshot({"private": "value"})
        self.assertEqual(result, {"status": "unavailable-platform"})
        self.assertEqual(list(self.root.iterdir()), [])


class EscapedAndOversizeSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="amnezia-pre-http-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        if os.name == "posix":
            self.root.chmod(0o700)

    def snapshot(self, value, label="server"):
        return module._private_publication_snapshot(self.root, "owned-run", "publisher-clean", NONCE_A, label, value)

    @unittest.skipUnless(os.name == "posix", "private diagnostics require POSIX authority")
    def test_escaped_json_beyond_one_mib_is_still_preserved(self):
        # The guest command bounds raw output to 262144 bytes, but control
        # characters escape to six ASCII bytes each in JSON.  The previous
        # fixed 1 MiB refusal discarded the entire capture at this size.
        value = {"exitcode": 0, "stdout": "\x01" * 262144, "stderr": "\u00e9" * 65536}
        record = self.snapshot(value)
        self.assertEqual(record["status"], "preserved")
        self.assertGreater(record["size"], 1048576)
        self.assertLessEqual(record["size"], module._PRIVATE_SNAPSHOT_MAX_BYTES)
        data = Path(record["path"]).read_bytes()
        self.assertEqual(len(data), record["size"])
        self.assertEqual(hashlib.sha256(data).hexdigest(), record["sha256"])
        self.assertEqual(json.loads(data)["raw"], value)
        self.assertFalse(record.get("truncated", False))

    @unittest.skipUnless(os.name == "posix", "private diagnostics require POSIX authority")
    def test_oversize_payload_keeps_bounded_head_and_tail(self):
        body = "HEAD" + "A" * (8 * 1024 * 1024) + "TAIL"
        value = {"exitcode": 0, "stdout": body, "stderr": ""}
        record = self.snapshot(value)
        self.assertEqual(record["status"], "preserved")
        self.assertIs(record["truncated"], True)
        self.assertLessEqual(record["size"], module._PRIVATE_SNAPSHOT_MAX_BYTES)
        self.assertGreater(record["full_size"], module._PRIVATE_SNAPSHOT_MAX_BYTES)
        data = Path(record["path"]).read_bytes()
        self.assertEqual(len(data), record["size"])
        self.assertEqual(hashlib.sha256(data).hexdigest(), record["sha256"])
        marker = json.loads(data)["raw"]["stdout"]["_snapshot_truncated"]
        self.assertEqual(marker["original_bytes"], len(body.encode("utf-8")))
        self.assertEqual(marker["original_sha256"], hashlib.sha256(body.encode("utf-8")).hexdigest())
        self.assertTrue(base64.b64decode(marker["head"]).startswith(b"HEAD"))
        self.assertTrue(base64.b64decode(marker["tail"]).endswith(b"TAIL"))

    @unittest.skipUnless(os.name == "posix", "private diagnostics require POSIX authority")
    def test_flat_oversize_text_keeps_no_unbounded_copy(self):
        record = self.snapshot({"exitcode": 0, "stdout": "x" * (module._PRIVATE_SNAPSHOT_MAX_BYTES * 3)})
        self.assertEqual(record["status"], "preserved")
        self.assertIs(record["truncated"], True)
        self.assertLessEqual(record["size"], module._PRIVATE_SNAPSHOT_MAX_BYTES)
        marker = json.loads(Path(record["path"]).read_text(encoding="utf-8"))["raw"]["stdout"]["_snapshot_truncated"]
        self.assertEqual(marker["label"], "string")
        self.assertEqual(marker["original_bytes"], module._PRIVATE_SNAPSHOT_MAX_BYTES * 3)


class ReadbackSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="amnezia-pre-http-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        if os.name == "posix":
            self.root.chmod(0o700)
        self.events = []
        self.ops = object.__new__(module.ConcretePublisherOps)
        self.ops.controller = types.SimpleNamespace(root=self.root, get_run=lambda _: {"manifest": MANIFEST})
        self.ops._attempt_nonce = NONCE_A
        self.ops._client_raw_nonce = NONCE_A
        self.ops._client_raw = {"action": "publish", "passed": True, "raw": {"exit_code": 0, "stdout": "private-client-output", "stderr": "private-client-error"}}
        self.qga = qga_stub()

    @unittest.skipUnless(os.name == "posix", "private diagnostics require POSIX authority")
    def test_connection_reset_preserves_client_and_server_before_cleanup(self):
        reset = ConnectionResetError(104, "inert reset")
        outer = self
        run = {"manifest": MANIFEST, "publication_attempt": {"phase": "readback"}}
        self.ops.controller.get_run = lambda _: run
        self.ops.controller.load_state = lambda: {"runs": {"owned-run": run}}
        self.ops.controller.save_state = lambda state: self.events.append("ledger-saved")

        class Opener:
            def open(self, *args, **kwargs):
                outer.events.append("http")
                records = list(outer.root.glob("exports/owned-run/publication/*/private-pre-http/*.json"))
                outer.assertEqual(len(records), 2)
                outer.assertIn("pre_http_diagnostics", run["publication_attempt"])
                outer.assertEqual(run["publication_attempt"]["pre_http_diagnostics"]["attempt_nonce"], NONCE_A)
                raise reset

        with patch.object(module, "QgaClient", self.qga), patch.object(module.urllib.request, "build_opener", return_value=Opener()):
            with self.assertRaises(ConnectionResetError) as caught:
                self.ops.collect_readback("owned-run", "publisher-clean", {"qga_socket": "inert"}, NONCE_A)
        self.assertIs(caught.exception, reset)
        self.assertLess(self.events.index("ledger-saved"), self.events.index("http"))
        records = [json.loads(path.read_text(encoding="utf-8")) for path in self.root.glob("exports/owned-run/publication/*/private-pre-http/*.json")]
        client = next(record for record in records if record["label"] == "client")
        server = next(record for record in records if record["label"] == "server")
        self.assertEqual(client["raw"], self.ops._client_raw)
        self.assertIs(type(client["raw"]["raw"]["exit_code"]), int)
        self.assertEqual(server["raw"]["stdout"], "private-server-output")
        self.assertTrue(all(record["attempt_nonce"] == NONCE_A and record["diagnostic_only"] is True for record in records))
        self.assertEqual(self.ops._pre_http_diagnostics["attempt_nonce"], NONCE_A)
        self.assertNotIn("private-client-output", json.dumps(self.ops._pre_http_diagnostics))

    @unittest.skipUnless(os.name == "posix", "private diagnostics require POSIX authority")
    def test_capture_is_fresh_for_each_nonce_and_never_reuses_a_pointer(self):
        first = self.ops._capture_pre_http_diagnostics("owned-run", "publisher-clean", {"qga_socket": "inert"}, NONCE_A)
        self.ops._client_raw = {"action": "publish", "passed": False, "raw": {"exit_code": 1, "stdout": "second-client-output"}}
        self.ops._client_raw_nonce = NONCE_B
        with patch.object(module, "QgaClient", qga_stub({"exitcode": 0, "stdout": "second-server-output", "stderr": ""})):
            second = self.ops._capture_pre_http_diagnostics("owned-run", "publisher-clean", {"qga_socket": "inert"}, NONCE_B)
        self.assertNotEqual(first["client"]["path"], second["client"]["path"])
        self.assertEqual(Path(first["client"]["path"]).parent.parent.name, NONCE_A)
        self.assertEqual(Path(second["client"]["path"]).parent.parent.name, NONCE_B)
        # A snapshot preserved by a previous attempt (publish_once) belongs to
        # that nonce and must never be re-attached to this attempt.
        stale = module._private_publication_snapshot(self.root, "owned-run", "publisher-clean", NONCE_A, "client", {"attempt": "stale"})
        self.assertEqual(stale["status"], "preserved")
        self.ops._publish_result_snapshot = stale
        self.ops._publish_result_snapshot_nonce = NONCE_A
        self.ops._client_raw = {"action": "publish", "raw": {"stdout": "stale-client-output"}}
        self.ops._client_raw_nonce = NONCE_A
        with patch.object(module, "QgaClient", qga_stub()):
            third = self.ops._capture_pre_http_diagnostics("owned-run", "publisher-clean", {"qga_socket": "inert"}, NONCE_C)
        self.assertNotEqual(third["client"]["path"], stale["path"])
        self.assertEqual(Path(third["client"]["path"]).parent.parent.name, NONCE_C)
        self.assertEqual(json.loads(Path(third["client"]["path"]).read_text(encoding="utf-8"))["raw"], {})
        self.assertEqual(first["attempt_nonce"], NONCE_A)
        self.assertEqual(second["attempt_nonce"], NONCE_B)
        self.assertEqual(third["attempt_nonce"], NONCE_C)
        self.assertEqual(json.loads(Path(second["client"]["path"]).read_text(encoding="utf-8"))["raw"]["raw"]["exit_code"], 1)
        self.assertEqual(self.ops._pre_http_diagnostics["attempt_nonce"], NONCE_C)
        self.assertEqual(len(list(self.root.glob("exports/owned-run/publication/*/private-pre-http/*.json"))), 7)

    def test_archival_failure_cannot_mask_original_http_failure(self):
        original = ConnectionResetError(104, "inert original")
        opener = types.SimpleNamespace(open=lambda *a, **k: (_ for _ in ()).throw(original))
        with patch.object(module.ConcretePublisherOps, "_capture_pre_http_diagnostics", side_effect=OSError("private failure")), \
             patch.object(module.urllib.request, "build_opener", return_value=opener):
            with self.assertRaises(ConnectionResetError) as caught:
                self.ops.collect_readback("owned-run", "publisher-clean", {"qga_socket": "inert"}, NONCE_A)
        self.assertIs(caught.exception, original)

    def test_snapshot_never_replaces_manifest_hash_gate(self):
        class Response(io.BytesIO):
            def geturl(self):
                return "http://127.0.0.1:17865/manifest.json"

        opener = types.SimpleNamespace(open=lambda *a, **k: Response(b"{}"))
        with patch.object(module, "QgaClient", self.qga), patch.object(module.urllib.request, "build_opener", return_value=opener):
            with self.assertRaisesRegex(module.PublisherError, "manifest bytes differ"):
                self.ops.collect_readback("owned-run", "publisher-clean", {"qga_socket": "inert"}, NONCE_A)

    @unittest.skipUnless(os.name == "posix", "owned readback executes from the POSIX lab host")
    def test_ambient_proxy_is_disabled_for_owned_readback(self):
        with patch.dict(os.environ, {"http_proxy": "http://inert-proxy.invalid:9", "no_proxy": ""}, clear=True):
            ambient = module.urllib.request.build_opener(module._NoRedirect)
            proxies = [handler for handler in ambient.handlers if isinstance(handler, module.urllib.request.ProxyHandler)]
            self.assertEqual(proxies[0].proxies.get("http"), "http://inert-proxy.invalid:9")
            observed = []

            def factory(*handlers):
                observed.extend(handlers)
                return types.SimpleNamespace(open=lambda *a, **k: (_ for _ in ()).throw(ConnectionResetError("inert")))

            with patch.object(module, "QgaClient", self.qga), patch.object(module.urllib.request, "build_opener", side_effect=factory):
                with self.assertRaises(ConnectionResetError):
                    self.ops.collect_readback("owned-run", "publisher-clean", {"qga_socket": "inert"}, NONCE_A)
            self.assertTrue(any(isinstance(handler, module.urllib.request.ProxyHandler) and handler.proxies == {} for handler in observed))
            self.assertIn(module._NoRedirect, observed)


class PublishFailureSnapshotTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix", "private diagnostics require POSIX authority")
    def test_invalid_or_unsuccessful_publish_is_preserved_before_cleanup(self):
        for invalid in (False, True):
            with self.subTest(invalid=invalid), tempfile.TemporaryDirectory(prefix="amnezia-publish-failure-") as tmp:
                root = Path(tmp)
                root.chmod(0o700)
                events = []
                run = {"run_id": "owned-run", "lane": "release", "outer_artifact": {"sha256": "a" * 64}, "manifest": {"sha256": "b" * 64}}
                controller = FakeController(root, run)
                result = {"action": "foreign" if invalid else "publish", "passed": False,
                          "transport": "hyperv-powershell-direct", "origin": "guest", "injected": False, "vm_id": "owned-vm",
                          "raw": {"exit_code": 2, "stdout": "private-nonzero-cli-output", "stderr": "private-nonzero-cli-error"}}
                controller.hyperv_call = lambda *a, **k: result
                outer = self

                class Ops(FakeOps):
                    _require_envelope = staticmethod(module.ConcretePublisherOps._require_envelope)
                    publish_once = module.ConcretePublisherOps.publish_once
                    _capture_pre_http_diagnostics = module.ConcretePublisherOps._capture_pre_http_diagnostics

                    def seed_lab_profile(self, run_id, case_id, server, nonce):
                        self._attempt_nonce = nonce

                    def cleanup(self, run_id, case_id):
                        paths = list(root.glob("exports/owned-run/publication/*/private-pre-http/*.json"))
                        outer.assertEqual(len(paths), 2)
                        outer.assertIn("pre_http_diagnostics", run["publication_attempt"])
                        records = [json.loads(path.read_text(encoding="utf-8")) for path in paths]
                        saved = next(record for record in records if record["label"] == "client")
                        outer.assertEqual(saved["raw"], result)
                        outer.assertIs(type(saved["raw"]["raw"]["exit_code"]), int)
                        outer.assertTrue(all(record["attempt_nonce"] == run["publication_attempt"]["attempt_nonce"] for record in records))
                        return super().cleanup(run_id, case_id)

                ops = Ops(events)
                ops.controller = controller
                ops._child_record = {"vm_id": "owned-vm"}
                ops._pre_http_diagnostics = {"diagnostic_only": True, "attempt_nonce": NONCE_B, "status": "stale"}
                with patch.object(module, "QgaClient", qga_stub()):
                    with self.assertRaises(module.PublisherError) as caught:
                        module.ControllerPublisher(controller, ops).run("owned-run")
                self.assertNotIn("private-nonzero", str(caught.exception))
                attempt = run["publication_attempt"]
                self.assertIn("pre_http_diagnostics", attempt)
                self.assertEqual(attempt["pre_http_diagnostics"].get("attempt_nonce"), attempt["attempt_nonce"])
                self.assertEqual(attempt["state"], "failed-cleaned")
                self.assertEqual(events[-1], "cleanup")
                self.assertNotEqual(attempt["pre_http_diagnostics"], {"diagnostic_only": True, "attempt_nonce": NONCE_B, "status": "stale"})

    @unittest.skipUnless(os.name == "posix", "private diagnostics require POSIX authority")
    def test_publish_transport_failure_is_preserved_before_cleanup(self):
        original = ConnectionResetError(104, "inert publish transport")
        with tempfile.TemporaryDirectory(prefix="amnezia-publish-transport-") as tmp:
            root = Path(tmp)
            root.chmod(0o700)
            events = []
            run = {"run_id": "owned-run", "lane": "release", "outer_artifact": {"sha256": "a" * 64}, "manifest": {"sha256": "b" * 64}}
            controller = FakeController(root, run)
            outer = self

            def hyperv_call(*args, **kwargs):
                if args and args[0] == "publish":
                    raise original
                raise AssertionError("unexpected adapter call")

            controller.hyperv_call = hyperv_call

            class Ops(FakeOps):
                _require_envelope = staticmethod(module.ConcretePublisherOps._require_envelope)
                publish_once = module.ConcretePublisherOps.publish_once
                _capture_pre_http_diagnostics = module.ConcretePublisherOps._capture_pre_http_diagnostics

                def seed_lab_profile(self, run_id, case_id, server, nonce):
                    self._attempt_nonce = nonce

                def cleanup(self, run_id, case_id):
                    paths = list(root.glob("exports/owned-run/publication/*/private-pre-http/*.json"))
                    outer.assertEqual(len(paths), 2)
                    outer.assertIn("pre_http_diagnostics", run["publication_attempt"])
                    records = [json.loads(path.read_text(encoding="utf-8")) for path in paths]
                    client = next(record for record in records if record["label"] == "client")
                    outer.assertEqual(client["raw"], {})
                    outer.assertTrue(all(record["attempt_nonce"] == run["publication_attempt"]["attempt_nonce"] for record in records))
                    outer.assertEqual(list(root.glob("exports/owned-run/publication/" + NONCE_A + "/*")), [])
                    return super().cleanup(run_id, case_id)

            ops = Ops(events)
            ops.controller = controller
            ops._child_record = {"vm_id": "owned-vm"}
            # A previous attempt's preserved snapshot must never be reused.
            ops._publish_result_snapshot = {"status": "preserved", "path": "/inert/previous-attempt/client.json"}
            ops._publish_result_snapshot_nonce = NONCE_A
            ops._client_raw = {"action": "publish", "raw": {"stdout": "stale-private-client-output"}}
            ops._client_raw_nonce = NONCE_A
            with patch.object(module, "QgaClient", qga_stub()):
                with self.assertRaises(ConnectionResetError) as caught:
                    module.ControllerPublisher(controller, ops).run("owned-run")
            self.assertIs(caught.exception, original)
            attempt = run["publication_attempt"]
            self.assertIn("pre_http_diagnostics", attempt)
            self.assertEqual(attempt["pre_http_diagnostics"].get("attempt_nonce"), attempt["attempt_nonce"])
            self.assertEqual(attempt["state"], "failed-cleaned")
            self.assertEqual(events[-1], "cleanup")


if __name__ == "__main__":
    unittest.main()
