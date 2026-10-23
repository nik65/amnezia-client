"""Owned-process config integration; all preparation/Docker effects are inert."""
import ast
import contextlib
import io
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
from ready_validation import parse_config

BINARY = os.environ.get('AWG_CONFIG_TEST_BIN')
BASE = ('[Interface]\nPrivateKey=' + 'A' * 43 + '=\nAddress=10.0.0.1/24\nListenPort=51820\n'
        '[Peer]\nPublicKey=' + 'B' * 43 + '=\nAllowedIPs=10.0.0.2/32\n').encode()


class BridgeProtocol(unittest.TestCase):
    def test_legacy_selection(self):
        self.assertIs(prepare.config_function(None), prepare.parse_config)

    def test_native_selection_does_not_fall_back(self):
        with mock.patch.object(prepare, 'parse_config', side_effect=AssertionError('legacy parser')):
            with self.assertRaisesRegex(ValueError, '^native_config_rejected$'):
                with mock.patch.object(prepare.NativePolicy, '_invoke', side_effect=ValueError('native_config_rejected')):
                    prepare.config_function(b'owned-inert-fixture')(BASE)

    def test_wrong_result_schema_is_rejected(self):
        invalid = [None, {}, {'interface': [], 'peers': [{}]},
                   {'interface': {}, 'peers': []}, {'interface': {'k': 2}, 'peers': [{}]},
                   {'interface': {}, 'peers': [None]},
                   {'interface': {}, 'peers': [{}], 'extra': True}]
        for value in invalid:
            with self.subTest(value_type=type(value).__name__):
                with mock.patch.object(prepare.NativePolicy, '_invoke', return_value=value):
                    with self.assertRaisesRegex(ValueError, '^native_config_rejected$'):
                        prepare.NativePolicy(b'owned-inert-fixture').parse_config(BASE)

    def test_malformed_helper_output_is_sanitized(self):
        original = subprocess.Popen
        for output, code in [(b'{"error":[]}', 2), (b'\xff', 0),
                             (b'{"error":"private-fixture"}', 2), (b'{"result":null}extra', 0)]:
            def child(argv, **kwargs):
                # Only the transport is under test; substitute an owned inert child.
                return original([sys.executable, '-B', '-c',
                                 f'import sys;sys.stdout.buffer.write({output!r});sys.exit({code})'], **kwargs)
            for action, expected in [(lambda a: a.mtu('1420'), 'native_policy_rejected'),
                                     (lambda a: a.parse_config(BASE), 'native_config_rejected')]:
                with self.subTest(code=code, expected=expected):
                    with mock.patch.object(prepare.subprocess, 'Popen', side_effect=child):
                        with self.assertRaisesRegex(ValueError, '^' + expected + '$'):
                            action(prepare.NativePolicy(b'owned-inert-fixture'))


@unittest.skipUnless(BINARY, 'standalone helper path required')
class ActualCapturedConfig(unittest.TestCase):
    def setUp(self):
        self.raw = Path(BINARY).read_bytes()

    def test_captured_bytes_unicode_nul_and_peer_order(self):
        inputs = [BASE,
                  BASE.replace(b'[Peer]', 'PostUp=данные😀\0quoted"\\tail\n[Peer]'.encode()),
                  BASE + ('[Peer]\nPublicKey=' + 'C' * 43 + '=\nAllowedIPs=10.0.0.3/32\n').encode()]
        for raw in inputs:
            expected = parse_config(raw)
            with mock.patch.object(prepare, 'parse_config', side_effect=AssertionError('legacy parser')):
                self.assertEqual(prepare.config_function(self.raw)(raw), expected)

    def test_expanded_json_crosses_old_output_cap(self):
        raw = BASE.replace(b'[Peer]', b'PostUp=' + b'\x01' * 220000 + b'\n[Peer]')
        self.assertGreater(len(json.dumps(parse_config(raw))), 1024 ** 2)
        self.assertEqual(prepare.config_function(self.raw)(raw), parse_config(raw))

    def test_rejection_boundaries_and_no_secret_errors(self):
        for raw, code in [(b'\xffprivate-fixture', 'invalid UTF-8'),
                          (b'private-fixture', 'configuration syntax'),
                          (b'X' * (1024 ** 2 + 1), 'native_config_rejected')]:
            with mock.patch.object(prepare, 'parse_config', side_effect=AssertionError('legacy parser')):
                with self.assertRaisesRegex(ValueError, '^' + code + '$'):
                    prepare.config_function(self.raw)(raw)

    def test_manual_and_automatic_prepare_use_native_before_effects(self):
        class ReachedSnapshot(Exception):
            pass
        for automatic in (False, True):
            with tempfile.TemporaryDirectory() as name:
                args = SimpleNamespace(source='amnezia-awg', automatic=automatic,
                    image='repo@sha256:' + 'c' * 64, host='fixture.test', port=23456, generation=1)
                run = mock.Mock(return_value=BASE)
                snapshot = mock.Mock(side_effect=ReachedSnapshot)
                journal = mock.Mock(side_effect=AssertionError('journal mutation'))
                with mock.patch.object(prepare, 'ROOT', Path(name)), \
                     mock.patch.object(prepare.os, 'geteuid', return_value=0), \
                     mock.patch.object(prepare, 'load_native_feed', return_value=self.raw), \
                     mock.patch.object(prepare, 'source_config_function', return_value=lambda runner, source: runner(
                         'docker', 'exec', source, 'cat', '/opt/amnezia/awg/' + ('wg0.conf' if source == 'amnezia-awg' else 'awg0.conf'))), \
                     mock.patch.object(prepare, 'run', run), \
                     mock.patch.object(prepare, 'policy_functions', return_value=(snapshot, None, None, None)), \
                     mock.patch.object(prepare, 'parse_config', side_effect=AssertionError('legacy parser')), \
                     mock.patch.object(prepare, 'Journal', journal):
                    with self.assertRaises(ReachedSnapshot):
                        prepare.prepare(args)
                self.assertEqual([], list(Path(name).iterdir()))
                journal.assert_not_called()
                run.assert_called_once_with('docker', 'exec', 'amnezia-awg', 'cat', '/opt/amnezia/awg/wg0.conf')
                snapshot.assert_called_once()
                self.assertEqual(snapshot.call_args.args[2], parse_config(BASE)[0])

    def test_actual_preflight_block_uses_native_without_journal(self):
        source = Path(prepare.__file__).read_text(encoding='utf8')
        main = next(n for n in ast.parse(source).body if isinstance(n, ast.If)
                    and isinstance(n.test, ast.Compare)
                    and isinstance(n.test.left, ast.Name) and n.test.left.id == '__name__')
        code = compile(ast.Module(body=main.body, type_ignores=[]), str(prepare.__file__), 'exec')
        with tempfile.TemporaryDirectory() as name:
            namespace = dict(vars(prepare), ROOT=Path(name),
                load_native_feed=lambda args: self.raw,
                source_config_function=lambda raw: lambda runner, source: runner(
                    'docker', 'exec', source, 'cat', '/opt/amnezia/awg/' + ('wg0.conf' if source == 'amnezia-awg' else 'awg0.conf')),
                run=mock.Mock(return_value=BASE),
                policy_functions=lambda raw: (lambda *a: {'mtu': 1420}, None, lambda: 'fixture-epoch', None),
                network_function=lambda raw: mock.Mock(),
                Journal=mock.Mock(side_effect=AssertionError('journal mutation')))
            with mock.patch.object(sys, 'argv', ['prepare.py', '--source', 'amnezia-awg',
                    '--host', 'fixture.test', '--preflight']), \
                 mock.patch.object(prepare.os, 'geteuid', return_value=0), \
                 mock.patch.object(prepare, 'parse_config', side_effect=AssertionError('legacy parser')), \
                 contextlib.redirect_stdout(io.StringIO()) as output:
                with self.assertRaises(SystemExit) as exit:
                    exec(code, namespace)
            self.assertEqual(exit.exception.code, 0)
            self.assertEqual(json.loads(output.getvalue()),
                             {'eligible': True, 'mtu': 1420, 'clientPolicyEpoch': 'fixture-epoch'})
            namespace['Journal'].assert_not_called()
            self.assertEqual([], list(Path(name).iterdir()))


if __name__ == '__main__':
    unittest.main()
