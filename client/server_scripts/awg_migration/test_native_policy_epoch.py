"""Policy epoch source wiring only: captured helper mock and FakeRunner, no Docker."""
import ast
import json
from pathlib import Path
import subprocess
import unittest
from unittest import mock

import prepare

HASH = 'sha256:' + 'a' * 64
EPOCH = {'revision': 14, 'contentSha256': HASH}


class FakeRunner:
    def __init__(self, output=b'', failure=None):
        self.calls = []
        self.output, self.failure = output, failure

    def __call__(self, *args):
        self.calls.append(args)
        if self.failure:
            raise self.failure
        return self.output


class PolicyEpochBridge(unittest.TestCase):
    def test_native_exact_same_collector_namespace_and_empty_output(self):
        runner = FakeRunner()
        prepare.check_collector_policy_epoch(runner, 'owned-control', EPOCH, b'captured-helper')
        self.assertEqual(runner.calls, [('docker', 'exec', 'owned-control', '/app/awg-feed',
                                        '--check-policy-epoch', '14', HASH)])

    def test_native_failures_are_sanitized_and_never_fall_back(self):
        for error in (subprocess.CalledProcessError(2, ['secret'], output=b'secret'),
                      subprocess.TimeoutExpired(['secret'], 5), OSError('secret')):
            runner = FakeRunner(failure=error)
            with self.assertRaisesRegex(ValueError, '^client_policy_feed_epoch_changed$'):
                prepare.check_collector_policy_epoch(runner, 'owned-control', EPOCH, b'captured-helper')
            self.assertEqual(len(runner.calls), 1)
            self.assertIn('/app/awg-feed', runner.calls[0])
            self.assertNotIn('python', runner.calls[0])

    def test_native_unexpected_stdout_fails_closed(self):
        for output in (b'\n', b'{}', b'secret', None, ''):
            with self.subTest(output=output), self.assertRaisesRegex(ValueError, '^client_policy_feed_epoch_changed$'):
                prepare.check_collector_policy_epoch(FakeRunner(output), 'owned-control', EPOCH, b'helper')

    def test_native_invalid_epoch_rejected_before_runner(self):
        invalid = (True, {}, {'revision': 14}, dict(EPOCH, extra=1),
                   dict(EPOCH, revision=True), dict(EPOCH, revision=0),
                   dict(EPOCH, revision=9007199254740992), dict(EPOCH, revision='14'),
                   dict(EPOCH, contentSha256=HASH.upper()), dict(EPOCH, contentSha256=HASH+'\n'),
                   dict(EPOCH, contentSha256=None))
        for value in invalid:
            runner = FakeRunner()
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, '^client_policy_feed_epoch_changed$'):
                prepare.check_collector_policy_epoch(runner, 'owned-control', value, b'helper')
            self.assertFalse(runner.calls)

    def test_revision_upper_bound_and_no_epoch_skip(self):
        runner = FakeRunner()
        prepare.check_collector_policy_epoch(runner, 'owned-control', dict(EPOCH, revision=9007199254740991), b'helper')
        self.assertEqual(runner.calls[0][-2], '9007199254740991')
        for helper in (None, b'helper'):
            runner = FakeRunner()
            prepare.check_collector_policy_epoch(runner, 'owned-control', None, helper)
            self.assertFalse(runner.calls)

    def test_legacy_probe_preserved_and_mismatch_rejected(self):
        runner = FakeRunner(json.dumps(EPOCH).encode())
        prepare.check_collector_policy_epoch(runner, 'owned-control', EPOCH, None)
        command = runner.calls[0]
        self.assertEqual(command[:5], ('docker', 'exec', 'owned-control', 'python', '-c'))
        self.assertIn('http://172.29.172.253:17864/rules.json', command[5])
        self.assertIn('timeout=5', command[5])
        with self.assertRaisesRegex(ValueError, '^client_policy_feed_epoch_changed$'):
            prepare.check_collector_policy_epoch(FakeRunner(b'{}'), 'owned-control', EPOCH, None)

    def test_captured_helper_capability_contract(self):
        adapter = prepare.NativePolicy(b'captured-helper')
        with mock.patch.object(adapter, '_invoke', return_value={'policyEpochVersion': 1}) as invoke:
            adapter.policy_epoch_capability()
        invoke.assert_called_once_with(b'', '--policy-epoch-capability', 4096,
            'native_policy_epoch_rejected', {'native_policy_epoch_rejected'}, input_limit=0)
        self.assertEqual(adapter.raw, b'captured-helper')

    def test_old_or_malformed_capability_rejected(self):
        adapter = prepare.NativePolicy(b'captured-helper')
        for value in (None, {}, {'policyEpochVersion': True}, {'policyEpochVersion': 0},
                      {'policyEpochVersion': 2}, {'policyEpochVersion': '1'},
                      {'policyEpochVersion': 1, 'extra': 1}):
            with self.subTest(value=value), mock.patch.object(adapter, '_invoke', return_value=value):
                with self.assertRaisesRegex(ValueError, '^native_policy_epoch_rejected$'):
                    adapter.policy_epoch_capability()
        with mock.patch.object(adapter, '_invoke', side_effect=ValueError('native_policy_epoch_rejected')):
            with self.assertRaisesRegex(ValueError, '^native_policy_epoch_rejected$'):
                adapter.policy_epoch_capability()

    def test_old_helper_rejects_prepare_before_any_mutating_work(self):
        from types import SimpleNamespace
        args = SimpleNamespace(source='amnezia-awg')
        invalid = (None, {}, {'policyEpochVersion': True}, {'policyEpochVersion': 0},
                   {'policyEpochVersion': 1, 'extra': 1}, ValueError('native_policy_epoch_rejected'))
        for response in invalid:
            with self.subTest(response=response), \
                 mock.patch.object(prepare.os, 'geteuid', return_value=0, create=True), \
                 mock.patch.object(prepare, 'load_native_feed', return_value=b'ownedhelper'), \
                 mock.patch.object(prepare.NativePolicy, 'control_capability'), \
                 mock.patch.object(prepare.NativePolicy, 'network_capability'), \
                 mock.patch.object(prepare.NativePolicy, 'source_config_capability'), \
                 mock.patch.object(prepare.NativePolicy, '_invoke') as invoke, \
                 mock.patch.object(prepare, 'Journal') as journal, \
                 mock.patch.object(prepare, 'run') as runner, \
                 mock.patch.object(prepare, 'config_function') as config, \
                 mock.patch.object(prepare, 'source_config_function') as source, \
                 mock.patch.object(prepare, 'network_function') as network, \
                 mock.patch.object(prepare, 'policy_functions') as policy:
                if isinstance(response, Exception):
                    invoke.side_effect = response
                else:
                    invoke.return_value = response
                with self.assertRaisesRegex(ValueError, '^native_policy_epoch_rejected$'):
                    prepare.prepare(args)
                invoke.assert_called_once_with(b'', '--policy-epoch-capability', 4096,
                    'native_policy_epoch_rejected', {'native_policy_epoch_rejected'}, input_limit=0)
                for untouched in (journal, runner, config, source, network, policy):
                    untouched.assert_not_called()

    def test_real_captured_helper_capability_without_network(self):
        import os
        binary = os.environ.get('AWG_POLICY_EPOCH_TEST_BIN')
        if not binary:
            self.skipTest('owned compiled helper not supplied')
        adapter = prepare.NativePolicy(Path(binary).read_bytes())
        adapter.policy_epoch_capability()

    def test_prepare_checks_capability_before_mutating_work(self):
        module = ast.parse(Path(prepare.__file__).read_bytes())
        function = next(n for n in module.body if isinstance(n, ast.FunctionDef) and n.name == 'prepare')
        calls = [n for n in ast.walk(function) if isinstance(n, ast.Call)]
        capability = next(n.lineno for n in calls if isinstance(n.func, ast.Attribute) and n.func.attr == 'policy_epoch_capability')
        journal = [n.lineno for n in calls if isinstance(n.func, ast.Name) and n.func.id == 'Journal']
        recovery = [n.lineno for n in calls if isinstance(n.func, ast.Attribute) and n.func.attr.startswith('recover')]
        self.assertTrue(journal and recovery)
        self.assertLess(capability, min(journal + recovery))
        wiring = [n for n in calls if isinstance(n.func, ast.Name) and n.func.id == 'check_collector_policy_epoch']
        self.assertEqual(len(wiring), 1)
        self.assertEqual([n.id for n in wiring[0].args], ['run', 'collector', 'epoch', 'native_feed'])


if __name__ == '__main__':
    unittest.main()
