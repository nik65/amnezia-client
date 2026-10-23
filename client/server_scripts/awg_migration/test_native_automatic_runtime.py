"""Actual captured C++ automatic adapters with owned files and fake process/socket IO."""
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import automatic
import prepare
from test_native_ready_runtime import PrepareHarness, SOURCE

FIXTURE = os.environ.get('AWG_AUTOMATIC_TEST_BIN')
IMAGE = 'repo@sha256:' + '9' * 64
HOST = 'fixture.test'


class SelectionAndProtocol(unittest.TestCase):
    def test_legacy_selection_remains_explicit(self):
        self.assertEqual(prepare.automatic_functions(None),
                         (automatic.occupied_udp_ports, automatic.plan, automatic.verify_port_available))

    def test_bad_inventory_result_rejected(self):
        adapter = prepare.NativePolicy(b'owned-test-bytes')
        for result in (None, {}, True, [True], [-1], [65536], [1.0], ['53'], [53, 53], [54, 53]):
            with self.subTest(result=result):
                with mock.patch.object(adapter, 'automatic_request', return_value=result):
                    with self.assertRaisesRegex(ValueError, '^native_automatic_rejected$'):
                        adapter.occupied_udp_ports(None)
        with mock.patch.object(adapter, 'automatic_request', return_value=[0, 53, 65535]):
            self.assertEqual(adapter.occupied_udp_ports(None), {0, 53, 65535})

    def test_malformed_plan_and_probe_success_rejected(self):
        adapter = prepare.NativePolicy(b'owned-test-bytes')
        good = {'host': HOST, 'image': IMAGE, 'port': 51821, 'generation': 1}
        malformed = [None, True, {}, dict(good, extra=True), dict(good, host='other.test'),
                     dict(good, image='other'), dict(good, port=True), dict(good, port=1023),
                     dict(good, port=65536), dict(good, generation=True),
                     dict(good, generation=0), dict(good, generation=9007199254740992)]
        for result in malformed:
            with self.subTest(result=result):
                with mock.patch.object(adapter, 'automatic_request', return_value=result):
                    with self.assertRaisesRegex(ValueError, '^native_automatic_rejected$'):
                        adapter.plan_automatic(Path('/owned-test'), 'amnezia-awg', HOST,
                                               IMAGE, SOURCE, 51820, set())
        for result in (False, 1, None, {}, 'true'):
            with mock.patch.object(adapter, 'automatic_request', return_value=result):
                with self.assertRaisesRegex(ValueError, '^native_automatic_rejected$'):
                    adapter.verify_automatic_port(51821)


@unittest.skipUnless(FIXTURE, 'owned standalone automatic fixture required')
class CapturedAutomatic(unittest.TestCase):
    def setUp(self):
        self.raw = Path(FIXTURE).read_bytes()
        self.adapter = prepare.NativePolicy(self.raw)

    def plan(self, root, raw=SOURCE, occupied=None):
        return self.adapter.plan_automatic(root, 'amnezia-awg', HOST, IMAGE, raw, 51820,
                                           set() if occupied is None else occupied)

    def ready_journal(self, root, port=51900):
        directory = root / 'amnezia-awg' / '1'
        directory.mkdir(parents=True)
        journal = {'phase': 'ready', 'request': {'host': HOST, 'image': IMAGE,
                    'port': port, 'generation': 1}, 'sourceDigest': hashlib.sha256(SOURCE).hexdigest()}
        path = directory / 'transaction.json'
        path.write_text(json.dumps(journal))
        return path, journal

    def test_actual_native_inventory_and_no_socket_python_fallback(self):
        with mock.patch.object(automatic, 'occupied_udp_ports', side_effect=AssertionError('Python fallback')), \
             mock.patch.object(automatic, 'verify_port_available', side_effect=AssertionError('Python fallback')):
            self.assertEqual(self.adapter.occupied_udp_ports(mock.Mock(side_effect=AssertionError('parent IO'))),
                             {53, 5454})
            self.adapter.verify_automatic_port(51821)

    def test_actual_plan_new_selection_large_private_escaped_config(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            self.assertEqual(self.plan(root), {'host': HOST, 'image': IMAGE, 'port': 51821, 'generation': 1})
            self.assertEqual(self.plan(root, occupied={51821, 51822})['port'], 51823)
            raw = SOURCE + b'#' + b'\x01' * 220000 + b'\0opaque'
            self.assertGreater(len(json.dumps({'raw': raw.decode()})), 1024 ** 2)
            self.assertEqual(self.plan(root, raw=raw)['port'], 51821)
            self.assertEqual(list(root.iterdir()), [])

    def test_existing_ready_plan_readonly_and_identity_drift(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            path, journal = self.ready_journal(root)
            before = path.read_bytes()
            self.assertEqual(self.plan(root, occupied={51900}), journal['request'])
            self.assertEqual(path.read_bytes(), before)
            with self.assertRaisesRegex(ValueError, '^migration_ready_drift$'):
                self.plan(root, raw=SOURCE + b'\n')

    def test_invalid_ready_journal_refused_no_fallback(self):
        for mutate in ('duplicate', 'NaN', 'extra-field', 'wrong-generation', 'symlink'):
            with self.subTest(mutate=mutate):
                with tempfile.TemporaryDirectory() as name:
                    root = Path(name)
                    path, journal = self.ready_journal(root)
                    if mutate == 'duplicate':
                        path.write_text(json.dumps(journal)[:-1] + ',"phase":"ready"}')
                    elif mutate == 'NaN':
                        path.write_text(json.dumps(journal)[:-1] + ',"extra":NaN}')
                    elif mutate == 'extra-field':
                        journal['request']['extra'] = True
                        path.write_text(json.dumps(journal))
                    elif mutate == 'wrong-generation':
                        journal['request']['generation'] = 2
                        path.write_text(json.dumps(journal))
                    else:
                        backing = root / 'owned-original.json'
                        path.rename(backing)
                        path.symlink_to(backing)
                    with mock.patch.object(automatic, 'plan', side_effect=AssertionError('Python fallback')):
                        with self.assertRaisesRegex(ValueError, '^migration_journal_conflict$'):
                            self.plan(root)

    def test_actual_whole_prepare_native_automatic_operation_order(self):
        with tempfile.TemporaryDirectory() as name:
            harness = PrepareHarness(Path(name), self.raw)
            actual_request = prepare.NativePolicy.automatic_request
            operations = []

            def observe(adapter, operation, **values):
                operations.append(operation)
                return actual_request(adapter, operation, **values)

            with mock.patch.object(prepare.NativePolicy, 'automatic_request', autospec=True, side_effect=observe):
                self.assertTrue(harness.execute(True)['prepared'])
            self.assertEqual(operations, ['inventory', 'plan', 'inventory', 'verify-port'])
            self.assertFalse(harness.journal.cleaned)
            self.assertEqual(harness.journal.value['phase'], 'ready')

    def test_native_failure_is_fatal_before_target_create(self):
        for fail_at in (1, 2, 3, 4):
            with self.subTest(fail_at=fail_at):
                with tempfile.TemporaryDirectory() as name:
                    harness = PrepareHarness(Path(name), self.raw)
                    actual_request = prepare.NativePolicy.automatic_request
                    operations = []

                    def observe(adapter, operation, **values):
                        operations.append(operation)
                        if len(operations) == fail_at:
                            raise ValueError('native_automatic_rejected')
                        return actual_request(adapter, operation, **values)

                    with mock.patch.object(prepare.NativePolicy, 'automatic_request', autospec=True, side_effect=observe):
                        with self.assertRaisesRegex(ValueError, '^native_automatic_rejected$'):
                            harness.execute(True)
                    self.assertEqual(len(operations), fail_at)
                    self.assertFalse(harness.activation)
                    # No target creation can be attempted before final inventory/probe.
                    self.assertFalse(any(call[:2] == ('docker', 'create') for call in harness.calls))
                    if fail_at <= 2:
                        self.assertIsNone(harness.journal)
                    else:
                        self.assertTrue(harness.journal.cleaned)
                        self.assertNotEqual(harness.journal.value['phase'], 'ready')


if __name__ == '__main__':
    unittest.main()
