"""Pure native-test admission/capture faults; no Windows, VM or product runs."""
import base64
import copy
import json
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from deploy.release_lab import lab, native_windows_tests as native
from deploy.release_lab.windows_credential_preparation import PreparedWindowsController


def manifest():
    return {'schema': native.SCHEMA, 'candidate_sha256': 'a' * 64,
            'candidate_version': '5.0.3.19', 'compile_source_commit': 'b' * 40,
            'source_root': r'C:\Owned\source',
            'review_capsule': {'path': r'C:\Owned\review.json', 'sha256': 'c' * 64, 'size': 100},
            'files': [{'name': name, 'source': 'C:\\Owned\\build\\' + name, 'sha256': 'd' * 64, 'size': 100}
                      for name in native.TESTS]}


def receipt():
    return {'schema': native.RECEIPT, 'run_id': 'native-test-run', 'case_id': 'control',
            'vm_id': '11111111-1111-1111-1111-111111111111', 'attempt_nonce': 'e' * 48,
            'manifest_sha256': 'f' * 64, 'marker_verified': True,
            'input_access_protected': True, 'files_unchanged': True, 'passed': True,
            'token': {'local': True, 'interactive': True, 'network': False, 'system': False,
                      'administrator': False, 'same_explorer': True, 'session_id': 1},
            'results': [{'name': name, 'native_exit': 0, 'started': True, 'drain_completed': True,
                         'owned_child_exited': True, 'timed_out': False, 'output_limit_exceeded': False,
                         'capture_failure': '', 'skip_count': 0, 'assertions': 10, 'failures': 0,
                         'files_unchanged': True, 'passed': True,
                         'stdout_b64': base64.b64encode(b'PASS: 10 assertions, 0 failures\r\n').decode(),
                         'stderr_b64': ''} for name in native.TESTS]}


def validate(value):
    return native.validate_receipt(value, run_id='native-test-run',
        vm_id='11111111-1111-1111-1111-111111111111', nonce='e' * 48, manifest_sha256='f' * 64)


class ManifestTests(unittest.TestCase):
    def test_fixed_manifest_accepts_four_roles_and_optional_dll(self):
        data = manifest()
        native.validate_manifest(data, candidate_sha256='a' * 64, version='5.0.3.19')
        data['files'].append({'name': 'Qt6Core.dll', 'source': r'C:\Owned\Qt6Core.dll', 'sha256': '1' * 64, 'size': 100})
        native.validate_manifest(data, candidate_sha256='a' * 64, version='5.0.3.19')

    def test_extra_executable_command_or_duplicate_is_refused(self):
        mutations = [lambda x: x.update(command='anything'),
                     lambda x: x['files'].append({'name': 'AmneziaVPN.exe', 'source': r'C:\Owned\AmneziaVPN.exe', 'sha256': '1' * 64, 'size': 100}),
                     lambda x: x['files'].append(copy.deepcopy(x['files'][0])),
                     lambda x: x['files'][0].update(arguments='--status'),
                     lambda x: x['files'].pop()]
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                data = manifest(); mutate(data)
                with self.assertRaises(ValueError): native.validate_manifest(data, candidate_sha256='a' * 64, version='5.0.3.19')

    def test_relative_unc_device_traversal_and_changed_identity_refused(self):
        for value in ('relative.exe', r'\\server\share\operator_command_tests.exe',
                      r'\\?\C:\Owned\operator_command_tests.exe', r'C:\Owned\..\operator_command_tests.exe'):
            data = manifest(); data['files'][0]['source'] = value
            with self.subTest(path=value), self.assertRaises(ValueError):
                native.validate_manifest(data, candidate_sha256='a' * 64, version='5.0.3.19')
        for key in ('candidate_sha256', 'candidate_version'):
            data = manifest(); data[key] = 'wrong'
            with self.subTest(key=key), self.assertRaises(ValueError):
                native.validate_manifest(data, candidate_sha256='a' * 64, version='5.0.3.19')

    def test_linked_capture_input_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source = root / 'source'; source.write_bytes(b'public')
            linked = root / 'linked'; linked.symlink_to(source)
            with self.assertRaises(ValueError): native._record(linked)


class ReceiptTests(unittest.TestCase):
    def test_original_nonvacuous_four_results(self):
        self.assertIs(validate(receipt())['passed'], True)

    def test_wrong_vm_marker_nonce_and_unproven_input_rejected(self):
        for field, value in (('vm_id', 'wrong'), ('attempt_nonce', 'wrong'), ('marker_verified', False),
                             ('input_access_protected', False), ('files_unchanged', False), ('passed', False)):
            data = receipt(); data[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError): validate(data)

    def test_network_missing_local_and_wrong_session_rejected(self):
        for field, value in (('network', True), ('local', False), ('interactive', False),
                             ('system', True), ('administrator', True), ('same_explorer', False), ('session_id', 0)):
            data = receipt(); data['token'][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError): validate(data)

    def test_native_exit_missing_capture_eof_timeout_and_truncation_rejected(self):
        for field, value in (('native_exit', None), ('native_exit', True), ('native_exit', 1), ('started', False),
                             ('drain_completed', False), ('owned_child_exited', False), ('timed_out', True),
                             ('output_limit_exceeded', True), ('capture_failure', 'refused output path'),
                             ('assertions', 0), ('skip_count', 1), ('files_unchanged', False), ('passed', False)):
            data = receipt(); data['results'][0][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError): validate(data)

    def test_fake_or_changed_stdout_and_skip_cannot_be_replaced_by_pass_boolean(self):
        for text in (b'', b'PASS: 0 assertions, 0 failures\n', b'PASS: 11 assertions, 0 failures\n',
                     b'PASS: 10 assertions, 0 failures\nQSKIP missing environment\n',
                     b'PASS: 10 assertions, 0 failures\nFAIL stale child\n'):
            data = receipt(); data['results'][0]['stdout_b64'] = base64.b64encode(text).decode()
            with self.subTest(text=text), self.assertRaises(ValueError): validate(data)


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        bridge = patch.object(lab, 'windows_path_for_wsl', side_effect=str)
        bridge.start(); self.addCleanup(bridge.stop)

    def _fixture(self, directory):
        root = Path(directory); (root / 'runs' / 'native-test-run').mkdir(parents=True)
        controller = object.__new__(PreparedWindowsController)
        controller.root = root; controller.dry_run = False; controller.test_mode = False
        controller._mutation_lock_fd = None; controller._mutation_lock_depth = 0
        run = {'dry_run': False, 'test_mode': False, 'windows_backend': 'hyperv', 'candidate_version': '5.0.3.19',
               'artifacts': {'windows-x64': {'sha256': 'a' * 64}},
               'profiles': {'windows-x64': {'vm': None}},
               'hyperv_records': {'adapter': native._record(lab.hyperv_adapter_source())}}
        controller.assert_mutation_context = Mock()
        controller.verify_acquisition_provenance = Mock()
        controller.get_run = Mock(return_value=run)
        controller.load_state = Mock(side_effect=lambda: {'runs': {'native-test-run': run}})
        controller.save_state = Mock()
        def start(*args): run['profiles']['windows-x64']['vm'] = {'vm_id': receipt()['vm_id']}
        controller.start = Mock(side_effect=start); controller.guest_probe = Mock()
        def reset(*args): run['profiles']['windows-x64'].update(vm=None, status='reset'); return {'reset': True}
        controller.reset = Mock(side_effect=reset)
        path = root / 'manifest.json'; path.write_text(json.dumps(manifest()))
        record = native._record(path); good = receipt(); good['manifest_sha256'] = record['sha256']
        # Nonce is deterministic only in this inert orchestration fixture.
        wire = {'transport': 'hyperv-powershell-direct', 'origin': 'guest', 'injected': False,
                'vm_id': good['vm_id'], 'host_bindings_unchanged': True, 'session_cleanup_confirmed': True,
                'session_cleanup_failure': '', 'receipt_parse_failure': '', 'receipt': good,
                'original': {'task_exit': 0, 'task_started': True, 'task_completed': True,
                             'task_removed': True, 'task_failure': ''}}
        raw = json.dumps(good).encode()
        wire['original'].update(receipt_bytes_b64=base64.b64encode(raw).decode(),
            captures=[{'name': 'receipt.json', 'size': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(), 'bytes_b64': base64.b64encode(raw).decode()}])
        controller.hyperv_call = Mock(side_effect=lambda action, **kwargs: wire if action == 'native-tests' else {})
        return controller, path, record, wire

    def test_task_nonzero_missing_completion_or_cleanup_preserved_before_reset(self):
        for field, value in (('task_exit', 1), ('task_exit', None), ('task_started', False),
                             ('task_completed', False), ('task_removed', False), ('task_failure', 'task failed')):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                controller, path, record, wire = self._fixture(directory)
                wire['original'][field] = value
                with patch.object(native.secrets, 'token_hex', return_value='e' * 48):
                    with self.assertRaises(lab.LabError):
                        native.acquire(controller, 'native-test-run', manifest_path=path, expected_manifest_sha256=record['sha256'])
                controller.reset.assert_called_once_with('native-test-run', 'windows-x64')
                capture = Path(directory) / 'runs/native-test-run/native-windows-tests-capture.json'
                self.assertEqual(json.loads(capture.read_bytes())['original'][field], value)

    def test_post_capture_input_drift_and_session_closeout_keep_original_before_reset(self):
        for field, value in (('host_bindings_unchanged', False), ('session_cleanup_confirmed', False),
                             ('session_cleanup_failure', 'transport closeout failed')):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                controller, path, record, wire = self._fixture(directory)
                wire[field] = value
                with patch.object(native.secrets, 'token_hex', return_value='e' * 48):
                    with self.assertRaises(lab.LabError):
                        native.acquire(controller, 'native-test-run', manifest_path=path, expected_manifest_sha256=record['sha256'])
                controller.reset.assert_called_once()
                capture = Path(directory) / 'runs/native-test-run/native-windows-tests-capture.json'
                original = json.loads(capture.read_bytes())
                self.assertEqual(original[field], value)
                self.assertEqual(original['receipt']['results'][0]['stdout_b64'], wire['receipt']['results'][0]['stdout_b64'])

    def test_native_fail_keeps_original_capture_and_canonical_reset(self):
        with tempfile.TemporaryDirectory() as directory:
            controller, path, record, wire = self._fixture(directory)
            wire['receipt']['results'][0]['native_exit'] = 1
            with patch.object(native.secrets, 'token_hex', return_value='e' * 48):
                with self.assertRaises(ValueError):
                    native.acquire(controller, 'native-test-run', manifest_path=path, expected_manifest_sha256=record['sha256'])
            controller.reset.assert_called_once()
            capture = Path(directory) / 'runs/native-test-run/native-windows-tests-capture.json'
            self.assertEqual(json.loads(capture.read_bytes())['receipt']['results'][0]['native_exit'], 1)

    def test_original_byte_drift_is_preserved_but_cannot_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            controller, path, record, wire = self._fixture(directory)
            wire['original']['captures'][0]['sha256'] = '0' * 64
            with patch.object(native.secrets, 'token_hex', return_value='e' * 48):
                with self.assertRaisesRegex(ValueError, 'bytes differ'):
                    native.acquire(controller, 'native-test-run', manifest_path=path, expected_manifest_sha256=record['sha256'])
            controller.reset.assert_called_once()
            saved = json.loads((Path(directory) / 'runs/native-test-run/native-windows-tests-capture.json').read_bytes())
            self.assertEqual(saved['original']['captures'][0]['sha256'], '0' * 64)

    def test_cleanup_failure_never_returns_native_success(self):
        with tempfile.TemporaryDirectory() as directory:
            controller, path, record, wire = self._fixture(directory)
            controller.reset.side_effect = lab.LabError('owned cleanup unconfirmed')
            with patch.object(native.secrets, 'token_hex', return_value='e' * 48):
                with self.assertRaisesRegex(lab.LabError, 'cleanup unconfirmed'):
                    native.acquire(controller, 'native-test-run', manifest_path=path, expected_manifest_sha256=record['sha256'])


if __name__ == '__main__': unittest.main()
