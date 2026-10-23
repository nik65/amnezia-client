"""Native control source selection and loaded-FD proof, with owned inert effects."""
import ast
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import prepare
from test_native_ready_runtime import PrepareHarness, TARGET_NAME

FIXTURE = os.environ.get('AWG_CONTROL_WIRING_TEST_BIN')
HASHES = {'service.py': 'a' * 64, 'target.py': 'b' * 64}


def target_nodes(start, end):
    nodes = ast.parse(Path(__file__).with_name('target.py').read_bytes()).body
    begin = next(i for i, node in enumerate(nodes)
                 if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == start for t in node.targets))
    finish = next(i for i in range(begin, len(nodes))
                  if isinstance(nodes[i], ast.Assign)
                  and any(isinstance(t, ast.Name) and t.id == end for t in nodes[i].targets))
    return compile(ast.Module(body=nodes[begin:finish + 1], type_ignores=[]), 'actual-target.py', 'exec')


class ControlSelection(unittest.TestCase):
    def test_actual_target_explicit_native_and_absent_legacy(self):
        for environment, enabled in [({}, False), ({'AMNEZIA_CONTROL_NATIVE_SHA256': 'c' * 64}, True)]:
            capture = mock.Mock(return_value=object())
            service = mock.Mock()
            namespace = {'os': os, 're': __import__('re'), 'Path': Path, 'scope': 'amnezia-awg',
                         'MigrationService': service,
                         'service_module': SimpleNamespace(NativeControl=SimpleNamespace(capture=capture))}
            with mock.patch.dict(os.environ, environment, clear=True):
                exec(target_nodes('native_control', 'service'), namespace)
            if enabled:
                capture.assert_called_once_with(Path('/app/awg-feed'), 'c' * 64)
            else:
                capture.assert_not_called()
            self.assertIs(service.call_args.kwargs['native'], capture.return_value if enabled else None)
            self.assertEqual(service.call_args.args, ('/migration', 'target', 'amnezia-awg'))

    def test_explicit_invalid_native_never_constructs_legacy_service(self):
        for value in ('', 'C' * 64, 'c' * 63, 'c' * 64 + '\0', 'c' * 64 + '\n'):
            namespace = {'os': SimpleNamespace(environ={'AMNEZIA_CONTROL_NATIVE_SHA256': value}),
                         're': __import__('re'), 'Path': Path, 'scope': 'amnezia-awg',
                         'MigrationService': mock.Mock(), 'service_module': mock.Mock()}
            with self.assertRaisesRegex(ValueError, '^native_control_invalid$'):
                exec(target_nodes('native_control', 'service'), namespace)
            namespace['MigrationService'].assert_not_called()
            namespace['service_module'].NativeControl.capture.assert_not_called()
        capture = mock.Mock(side_effect=ValueError('native_control_rejected'))
        namespace = {'os': os, 're': __import__('re'), 'Path': Path, 'scope': 'amnezia-awg',
                     'MigrationService': mock.Mock(),
                     'service_module': SimpleNamespace(NativeControl=SimpleNamespace(capture=capture))}
        with mock.patch.dict(os.environ, {'AMNEZIA_CONTROL_NATIVE_SHA256': 'c' * 64}, clear=True):
            with self.assertRaisesRegex(ValueError, '^native_control_rejected$'):
                exec(target_nodes('native_control', 'service'), namespace)
        namespace['MigrationService'].assert_not_called()

    def test_actual_target_receipt_preserves_two_source_hashes_and_adds_native_fd(self):
        class FakePath:
            def __init__(self, path):
                self.path = path
            def read_text(self):
                assert self.path == '/proc/self/stat'
                return ' '.join(['field'] * 21 + ['owned-start'])
        for enabled in (False, True):
            native = SimpleNamespace(receipt=lambda: {'sha256': 'c' * 64, 'fd': 11,
                                                     'protocol': 'control-json-v1'}) if enabled else None
            namespace = {'role': 'source', 'Path': FakePath, 'hashlib': hashlib,
                         'service_source': b'owned-service', 'target_source': b'owned-target',
                         'native_control': native}
            exec(target_nodes('receipt', 'path'), namespace)
            receipt = namespace['receipt']
            self.assertEqual(receipt['hashes'], {'service.py': hashlib.sha256(b'owned-service').hexdigest(),
                                                'target.py': hashlib.sha256(b'owned-target').hexdigest()})
            self.assertEqual(receipt['processStart'], 'owned-start')
            self.assertEqual(set(receipt), {'role', 'processStart', 'hashes', 'nativeControl'} if enabled
                             else {'role', 'processStart', 'hashes'})
            if enabled:
                self.assertEqual(receipt['nativeControl'], native.receipt())

    def test_capability_exact_private_request_and_strict_response(self):
        adapter = prepare.NativePolicy(b'owned-helper')
        expected = {'handled': False, 'status': 403, 'body': '', 'authenticate': False}
        with mock.patch.object(adapter, '_invoke', return_value=expected) as invoke:
            adapter.control_capability()
        args, kwargs = invoke.call_args
        self.assertEqual(json.loads(args[0]), {'role': 'target', 'scope': 'amnezia-awg',
            'path': '/native-control-capability', 'peerAddress': '127.0.0.1', 'body': '{}',
            'headers': {'content-length': '2'}, 'authenticatedClient': None})
        self.assertEqual(args[1:], ('--control-json', 4096, 'native_control_rejected', set()))
        self.assertEqual(kwargs, {'input_limit': 256 * 1024})
        invalid = [None, False, {}, dict(expected, handled=0), dict(expected, authenticate=0),
                   dict(expected, status=True), dict(expected, status=200), dict(expected, extra='bad')]
        for value in invalid:
            with mock.patch.object(adapter, '_invoke', return_value=value):
                with self.assertRaisesRegex(ValueError, '^native_control_rejected$'):
                    adapter.control_capability()


@unittest.skipUnless(hasattr(os, 'memfd_create'), 'Linux owned memfd proof required')
class LoadedNativeProof(unittest.TestCase):
    def test_legacy_probe_stays_exact_and_bad_metadata_rejects(self):
        self.assertEqual(prepare.control_loaded_probe('target', HASHES), prepare.CONTROL_LISTENER_PROBE)
        for role, hashes, sha in [('wrong', HASHES, 'c' * 64), ('target', {}, 'c' * 64),
                                  ('target', dict(HASHES, extra='x'), 'c' * 64),
                                  ('target', HASHES, ''), ('target', HASHES, 'C' * 64)]:
            with self.assertRaisesRegex(ValueError, '^native_control_rejected$'):
                prepare.control_loaded_probe(role, hashes, sha)

    def execute(self, *, receipt_change=None, sealed=True, data=b'owned-native-binary' * 8):
        fd = os.memfd_create('owned-control-proof', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        try:
            os.write(fd, data)
            os.fchmod(fd, 0o500)
            seals = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE
            if sealed:
                fcntl.fcntl(fd, fcntl.F_ADD_SEALS, seals)
            sha = hashlib.sha256(b'owned-native-binary' * 8).hexdigest()
            receipt = {'role': 'target', 'processStart': 'owned-start', 'hashes': dict(HASHES),
                       'nativeControl': {'sha256': sha, 'fd': fd, 'protocol': 'control-json-v1'}}
            if receipt_change:
                receipt_change(receipt)
            class FakePath:
                def __init__(self, path):
                    self.path = path
                def read_bytes(self):
                    assert self.path == '/proc/1/cmdline'
                    return b'python\0/migration/target.py\0'
                def read_text(self):
                    if self.path == '/migration/control-loaded-target.json':
                        return json.dumps(receipt)
                    if self.path == '/proc/1/stat':
                        return ' '.join(['field'] * 21 + ['owned-start'])
                    assert self.path == '/proc/net/tcp'
                    return 'header\n0: 00000000:46A2 00000000:0000 0A 0:0 0:0 0 0 0 777\n'
                def iterdir(self):
                    assert self.path == '/proc/1/fd'
                    return ['owned-socket-fd']
                def open(self, mode):
                    assert self.path == '/proc/1/fd/' + str(fd)
                    return Path('/proc/self/fd/' + str(fd)).open(mode)
            with mock.patch.dict(sys.modules, {'pathlib': SimpleNamespace(Path=FakePath)}), \
                 mock.patch.object(os, 'readlink', side_effect=lambda path: 'socket:[777]'):
                exec(prepare.control_loaded_probe('target', HASHES, sha), {})
        finally:
            os.close(fd)

    def test_actual_sealed_fd_and_source_receipt_are_required(self):
        self.execute()
        changes = [lambda r: r.update(role='source'), lambda r: r.update(processStart='stale'),
                   lambda r: r['hashes'].update({'target.py': 'c' * 64}),
                   lambda r: r['nativeControl'].update(sha256='d' * 64),
                   lambda r: r['nativeControl'].update(fd=True),
                   lambda r: r['nativeControl'].update(protocol='legacy'),
                   lambda r: r['nativeControl'].update(extra='bad')]
        for change in changes:
            with self.assertRaises((AssertionError, OSError)):
                self.execute(receipt_change=change)
        with self.assertRaises((AssertionError, OSError)):
            self.execute(sealed=False)
        with self.assertRaises((AssertionError, OSError)):
            self.execute(data=b'changed-owned-native' * 8)


class NativeMaintenanceHold(unittest.TestCase):
    def test_native_marker_rejects_before_ready_read_recipe_or_runner(self):
        from test_maintenance import MaintenanceEntryTests
        for marker in ('c' * 64, '', 0):
            fixture = MaintenanceEntryTests()
            fixture.setUp()
            try:
                fixture.journal.value['nativeFeedSha256'] = marker
                fixture.journal.save()
                (fixture.installed / 'ready.json').unlink()
                before = {str(path.relative_to(fixture.root)): path.read_bytes()
                          for path in fixture.root.rglob('*') if path.is_file()}
                with self.assertRaisesRegex(ValueError, '^native_feed_existing_generation_requires_maintenance$'):
                    fixture.invoke()
                after = {str(path.relative_to(fixture.root)): path.read_bytes()
                         for path in fixture.root.rglob('*') if path.is_file()}
                self.assertEqual(before, after)
                self.assertEqual(fixture.calls, [])
            finally:
                fixture.tearDown()


@unittest.skipUnless(FIXTURE, 'owned ready/helper fixture required')
class WholePrepareControlWiring(unittest.TestCase):
    def test_both_control_roles_mount_same_helper_readonly_and_require_actual_loaded_probes(self):
        raw = Path(FIXTURE).read_bytes()
        for automatic in (False, True):
            with tempfile.TemporaryDirectory() as directory:
                harness = PrepareHarness(Path(directory), raw)
                with mock.patch.object(prepare.NativePolicy, 'control_capability') as capability:
                    self.assertTrue(harness.execute(automatic)['prepared'])
                capability.assert_called_once_with()
                controls = [call for call in harness.calls if call[:2] == ('docker', 'run')
                            and call[-1] == '/migration/target.py']
                self.assertEqual(len(controls), 2)
                expected = str(Path(directory) / 'amnezia-awg/1/awg-feed') + ':/app/awg-feed:ro'
                for call in controls:
                    self.assertEqual(call.count(expected), 1)
                    self.assertEqual(call.count('AMNEZIA_CONTROL_NATIVE_SHA256=' + hashlib.sha256(raw).hexdigest()), 1)
                    self.assertEqual(call[call.index('--entrypoint') + 1], 'python')
                probes = [call for call in harness.calls if call[:2] == ('docker', 'exec')
                          and call[2] in (TARGET_NAME + '-control', TARGET_NAME + '-source-control')
                          and len(call) == 6 and 'F_GET_SEALS' in call[-1]]
                self.assertEqual(len(probes), 2)
                self.assertIn('control-loaded-target.json', probes[0][-1])
                self.assertIn('control-loaded-source.json', probes[1][-1])
                self.assertEqual(set(harness.journal.value['controlRecipe']), {'service.py', 'target.py'})

    def test_native_capability_failure_stops_before_any_prepare_effect(self):
        with tempfile.TemporaryDirectory() as directory:
            harness = PrepareHarness(Path(directory), Path(FIXTURE).read_bytes())
            with mock.patch.object(prepare.NativePolicy, 'control_capability',
                                   side_effect=ValueError('native_control_rejected')):
                with self.assertRaisesRegex(ValueError, '^native_control_rejected$'):
                    harness.execute(True)
            self.assertEqual(harness.calls, [])
            self.assertIsNone(harness.journal)
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_loaded_fd_failure_cannot_commit_ready(self):
        for suffix, activated in [('-control', False), ('-source-control', True)]:
            with tempfile.TemporaryDirectory() as directory:
                harness = PrepareHarness(Path(directory), Path(FIXTURE).read_bytes())
                original = harness.run
                def run(*args, **kwargs):
                    if args[:3] == ('docker', 'exec', TARGET_NAME + suffix) and 'F_GET_SEALS' in args[-1]:
                        raise subprocess.CalledProcessError(1, ['owned-control-proof'])
                    return original(*args, **kwargs)
                harness.run = run
                with mock.patch.object(prepare.NativePolicy, 'control_capability'):
                    with self.assertRaisesRegex(ValueError, 'control listener unavailable$'):
                        harness.execute(False)
                self.assertTrue(harness.journal.cleaned)
                self.assertNotEqual(harness.journal.value['phase'], 'ready')
                self.assertEqual(harness.activation, activated)


if __name__ == '__main__':
    unittest.main()
