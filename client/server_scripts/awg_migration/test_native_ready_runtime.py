"""Owned native readiness transport and actual prepare flow with inert effects."""
import ast
import base64
import copy
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import automatic
import prepare
import trusted_image

FIXTURE = os.environ.get('AWG_READY_TEST_BIN')
PRODUCTION = os.environ.get('AWG_READY_PRODUCTION_BIN')
A, B, C = (x * 43 + '=' for x in 'ABC')
TARGET_NAME = 'amnezia-awg-migration-1'
EPOCH = '2026-10-21T00:00:00.000000000Z'
PARAMETERS = {'Jc': '4', 'Jmin': '10', 'Jmax': '50', 'S1': '16', 'S2': '16',
              'S3': '16', 'S4': '16', 'H1': '1', 'H2': '2', 'H3': '3', 'H4': '4',
              'HeaderProtectionKey': base64.b64encode(b'c' * 32).decode(),
              'ContentPaddingAddition': '0', 'RekeyAfterTime': '120', 'RekeyTimeout': '5',
              'RejectAfterTime': '180', 'KeepaliveTimeout': '10',
              'MaxHandshakeAttempts': '20', 'RandomTrailers': '0', 'DisableCookies': '0'}
SOURCE = (f'[Interface]\nPrivateKey={A}\nAddress=10.0.0.1/24\nListenPort=51820\n'
          f'[Peer]\nPublicKey={B}\nPresharedKey={C}\nAllowedIPs=10.0.0.2/32\n').encode()
TARGET = SOURCE.replace(b'51820', b'51821').replace(b'[Peer]',
    ''.join(f'{k}={v}\n' for k, v in PARAMETERS.items()).encode() + b'[Peer]')
READY = {'targetContainer': TARGET_NAME, 'serverPublicKey': A, 'parameters': PARAMETERS}


class OwnedJournal:
    def __init__(self, identity='a' * 64, initial=None):
        self.value = copy.deepcopy(initial or {'owner': 'c' * 32, 'containers': {}})
        self.observed = {'Id': identity, 'Name': '/' + TARGET_NAME,
                         'Image': 'sha256:' + 'd' * 64,
                         'State': {'Running': True, 'StartedAt': EPOCH}}
        self.saves = []
        self.cleaned = False
        self.owned_calls = 0

    def owned(self, name):
        assert name == TARGET_NAME
        self.owned_calls += 1
        return copy.deepcopy(self.observed)

    def save(self, phase=None):
        if phase:
            self.value['phase'] = phase
        self.saves.append(copy.deepcopy(self.value))

    def plan(self, name, image):
        self.value['containers'][name] = {'image': image, 'id': None}
        self.save('creating')

    def record(self, name):
        self.value['containers'][name]['id'] = (self.observed['Id'] if name == TARGET_NAME
                                               else hashlib.sha256(name.encode()).hexdigest())
        self.save()

    def cleanup(self):
        # Deliberately inert: this asserts cleanup was requested, not real rollback.
        self.cleaned = True


def dump(port='51821'):
    return f'private\t{A}\t{port}\t0\n{B}\t{C}\t(none)\t10.0.0.2/32\t0\t0\t0\t0\n'.encode()


def showconf():
    return ''.join(f'{k}={v}\n' for k, v in PARAMETERS.items()
                   if k != 'ContentPaddingAddition').encode()


def legacy_runner(port='51821', config=None):
    def run(*args):
        assert args[:3] == ('docker', 'exec', 'a' * 64)
        if args[3:] == ('awg', 'show', 'awg0', 'dump'):
            return dump(port)
        if args[3:] == ('awg', 'showconf', 'awg0'):
            return showconf() if config is None else config
        if args[3:] == ('sh', '-c',
                'set -eu; engine=$(cat /migration/engine.pid); '
                'case "$engine" in ""|*[!0-9]*) exit 1;; esac; '
                'kill -0 "$engine"; sha256sum "/proc/$engine/exe"'):
            return (trusted_image.BINARY_SHA256 + '  /proc/100/exe\n').encode()
        raise AssertionError('unexpected inert command')
    return run


class CandidateLegacy(unittest.TestCase):
    def test_complete_checks_reject_wrong_port_parameters_and_short_rows(self):
        bad = [(legacy_runner(port='51822'), None),
               (legacy_runner(config=showconf().replace(b'Jc=4', b'Jc=99')), None),
               (legacy_runner(config=showconf().replace(b'RandomTrailers=0', b'RandomTrailers=1')), None)]
        for runner, unused in bad:
            check, pin = prepare.candidate_readiness(runner, OwnedJournal(), READY,
                                                     SOURCE, TARGET, None, False)
            self.assertEqual(pin['startedAt'], EPOCH)
            with self.assertRaisesRegex(ValueError, '^migration_ready_drift$'):
                check()
        for raw in (b'private\n' + dump().splitlines()[1] + b'\n',
                    dump().splitlines()[0] + b'\n' + (B + '\t' + C + '\t(none)\n').encode()):
            check, _ = prepare.candidate_readiness(lambda *a: raw, OwnedJournal(), READY,
                                                   SOURCE, TARGET, None, False)
            with self.assertRaisesRegex(ValueError, '^migration_ready_drift$'):
                check()

    def test_original_epoch_and_identity_are_not_renewed(self):
        for path, changed in [('Id', 'b' * 64), ('Image', 'sha256:' + 'e' * 64),
                              ('Name', '/amnezia-awg-migration-2'), ('StartedAt', EPOCH + 'changed')]:
            journal = OwnedJournal()
            check, pin = prepare.candidate_readiness(legacy_runner(), journal, READY,
                                                     SOURCE, TARGET, None, False)
            if path == 'StartedAt':
                journal.observed['State'][path] = changed
            else:
                journal.observed[path] = changed
            with self.assertRaisesRegex(ValueError, '^candidate_target_identity_changed$'):
                prepare.wait_candidate_ready(check)
            self.assertEqual(pin['startedAt'], EPOCH)

    def test_retryable_and_fatal_failures(self):
        retry = mock.Mock(side_effect=[ValueError('migration_ready_drift'),
                                       ValueError('native_ready_not_observed'), None])
        with mock.patch.object(prepare.time, 'sleep'):
            prepare.wait_candidate_ready(retry)
        self.assertEqual(retry.call_count, 3)
        for error in ('native_ready_rejected', 'native_ready_identity_drift',
                      'candidate_target_identity_changed'):
            check = mock.Mock(side_effect=ValueError(error))
            with self.assertRaisesRegex(ValueError, '^' + error + '$'):
                prepare.wait_candidate_ready(check)
            self.assertEqual(check.call_count, 1)
        check = mock.Mock(side_effect=ValueError('migration_ready_drift'))
        with mock.patch.object(prepare.time, 'sleep'):
            with self.assertRaisesRegex(ValueError, '^AWG3 readiness failed$'):
                prepare.wait_candidate_ready(check)
        self.assertEqual(check.call_count, 20)
        deadline = mock.Mock(side_effect=[0, 0, 61, 61])
        check = mock.Mock(side_effect=ValueError('migration_ready_drift'))
        with mock.patch.object(prepare.time, 'monotonic', deadline):
            with self.assertRaisesRegex(ValueError, '^AWG3 readiness failed$'):
                prepare.wait_candidate_ready(check)
        self.assertEqual(check.call_count, 1)


class CandidateNames(unittest.TestCase):
    def inspect_names(self, runner):
        # Execute the actual collision loop, with no preparation side effects.
        function = next(n for n in ast.parse(Path(prepare.__file__).read_bytes()).body
                        if isinstance(n, ast.FunctionDef) and n.name == 'prepare')
        loop = next(n for n in function.body if isinstance(n, ast.For)
                    and any(isinstance(v, ast.Constant) and v.value == 'container name collision'
                            for v in ast.walk(n)))
        namespace = {'run': runner, 'inspect_container': prepare.inspect_container,
                     'target': TARGET_NAME, 'collector': TARGET_NAME + '-control',
                     'subprocess': mock.Mock(run=mock.Mock(side_effect=AssertionError('direct bypass')))}
        exec(compile(ast.Module(body=[loop], type_ignores=[]), str(prepare.__file__), 'exec'), namespace)

    def test_only_explicit_absence_allows_preparation(self):
        runner = mock.Mock(side_effect=subprocess.CalledProcessError(1, ['owned-inert-docker'],
                                                                    stderr=b'No such container'))
        self.inspect_names(runner)
        self.assertEqual(runner.call_count, 5)

    def test_existing_container_rejects(self):
        with self.assertRaisesRegex(ValueError, '^container name collision$'):
            self.inspect_names(mock.Mock(return_value=b'[{"Id":"owned-fixture"}]'))

    def test_backend_and_malformed_output_do_not_mean_absence(self):
        unavailable = mock.Mock(side_effect=subprocess.CalledProcessError(1, ['owned-inert-docker'],
                                                                         stderr=b'Cannot connect to daemon'))
        with self.assertRaisesRegex(ValueError, '^ownership inspection unavailable$'):
            self.inspect_names(unavailable)
        with self.assertRaisesRegex(ValueError, '^invalid ownership inspection$'):
            self.inspect_names(mock.Mock(return_value=b'not-json'))


@unittest.skipUnless(FIXTURE, 'owned standalone ready fixture required')
class CapturedReady(unittest.TestCase):
    def setUp(self):
        self.raw = Path(FIXTURE).read_bytes()

    def check(self, mode='a', source=SOURCE, automatic=True):
        journal = OwnedJournal(mode * 64)
        with mock.patch.object(prepare, 'validate_ready_target', side_effect=AssertionError('Python fallback')):
            check, pin = prepare.candidate_readiness(mock.Mock(side_effect=AssertionError('parent Docker')),
                journal, READY, source, TARGET, self.raw, automatic)
            check()
        # One parent pin only; native pre/post identity checks use its bounded adapter.
        self.assertEqual(journal.owned_calls, 1)
        return pin

    def test_valid_control_and_private_large_escaped_input(self):
        self.assertEqual(self.check()['startedAt'], EPOCH)
        source = SOURCE.replace(b'[Peer]', b'PostUp=' + b'\x01' * 220000 + b'\0opaque\n[Peer]')
        self.assertGreater(len(json.dumps({'source': source.decode()})), 1024 ** 2)
        self.check(source=source, automatic=False)

    def test_native_rejections_do_not_fall_back(self):
        for mode, code in [('b', 'migration_ready_drift'), ('c', 'migration_ready_drift'),
                           ('d', 'migration_ready_drift'), ('e', 'native_ready_identity_drift'),
                           ('f', 'native_ready_not_observed')]:
            with self.assertRaisesRegex(ValueError, '^' + code + '$'):
                self.check(mode)

    def test_success_must_be_exact_boolean(self):
        pin = prepare.candidate_identity(OwnedJournal(), TARGET_NAME)
        for value in (False, 1, None, {}, 'true'):
            with mock.patch.object(prepare.NativePolicy, '_invoke', return_value=value):
                with self.assertRaisesRegex(ValueError, '^native_ready_rejected$'):
                    prepare.NativePolicy(self.raw).ready_target(SOURCE, TARGET,
                        dict(READY, targetContainer=pin['id']), pin, True)


@contextmanager
def mock_source_capability_and_server_key(derive, real):
    with mock.patch.object(prepare.NativePolicy, 'source_config_capability'), \
         mock.patch.object(prepare.NativePolicy, 'server_public_key', autospec=True,
             side_effect=lambda adapter, raw: derive(adapter, raw) if real else A):
        yield


class PrepareHarness:
    """Actual prepare body; every external operation is an inert argv recorder."""
    def __init__(self, root, raw, wrong_port=False, restart_at=None, native_server_key=False):
        self.root, self.raw = root, raw
        self.native_server_key = native_server_key
        self.wrong_port, self.restart_at = wrong_port, restart_at
        self.journal = None
        self.activation = False
        self.controls_ready = False
        self.calls = []

    def make_journal(self, directory, runner, initial):
        self.journal = OwnedJournal(initial=initial)
        return self.journal

    def run(self, *args, input=None):
        self.calls.append(args)
        if args[:2] == ('openssl', 'genpkey'):
            path = Path(args[args.index('-out') + 1])
            assert path.resolve().is_relative_to(self.root.resolve())
            path.write_bytes(b'owned-signing-fixture')
            return b''
        if args[:2] == ('openssl', 'pkey'):
            return b'owned-der-prefix' + b'p' * 32
        if args[:3] == ('docker', 'exec', 'amnezia-awg'):
            if args[3:] == ('cat', '/opt/amnezia/awg/wg0.conf'):
                if self.controls_ready and self.restart_at == 'before_activation':
                    self.journal.observed['State']['StartedAt'] = EPOCH + 'changed'
                return SOURCE
            if args[3:] == ('cat', '/proc/net/tcp'):
                return b'header\n'
        if args[:3] == ('docker', 'exec', '-i'):
            assert args[3] == 'amnezia-awg' and args[4:6] == ('sh', '-c')
            if 'pubkey' in args[6]:
                return (A + '\n').encode()
            assert 'iptables' in args[6]
            self.activation = True
            if self.restart_at == 'after_activation':
                self.journal.observed['State']['StartedAt'] = EPOCH + 'changed'
            return b''
        if args[:3] == ('docker', 'exec', 'a' * 64):
            return legacy_runner(port='51822' if self.wrong_port else '51821')(*args)
        if (args[:2] == ('docker', 'exec') and len(args) == 6
                and args[2] in (TARGET_NAME + '-control', TARGET_NAME + '-source-control')
                and args[3:5] == ('python', '-c')):
            self.controls_ready = True
            return b''
        if args[:5] == ('docker', 'image', 'inspect', '--format', '{{.Id}}'):
            return ('sha256:' + 'd' * 64 + '\n').encode()
        if args[:2] in (('docker', 'pull'), ('docker', 'create'), ('docker', 'build'), ('docker', 'run')):
            return b''
        raise AssertionError('unexpected inert operation: ' + repr(args[:4]))

    def networks(self, runner, source, binding=None):
        if binding is not None:
            binding['bridge'] = {'networkId': 'owned-network', 'interface': 'eth0', 'default': True}
        return ['--network', 'name=bridge,driver-opt=com.docker.network.endpoint.ifname=eth0,gw-priority=1']

    def execute(self, automatic_mode):
        derive_server_key = prepare.NativePolicy.server_public_key
        args = SimpleNamespace(source='amnezia-awg', automatic=automatic_mode,
            image='repo@sha256:' + '9' * 64, host='fixture.test', port=51821, generation=1,
            native_feed_sha256=hashlib.sha256(self.raw).hexdigest() if self.raw else '', preflight=False)
        snapshot = {'mtu': 1420, 'nat': [], 'filter': [], 'routes': [], 'egress': {}, 'dockerDns': False}
        with mock.patch.object(prepare, 'ROOT', self.root), \
             mock.patch.object(prepare.os, 'geteuid', return_value=0), \
             mock.patch.object(prepare, 'load_native_feed', return_value=self.raw), \
             mock_source_capability_and_server_key(derive_server_key, self.native_server_key), \
             mock.patch.object(prepare.NativePolicy, 'policy_epoch_capability'), \
             mock.patch.object(prepare, 'source_config_function', return_value=lambda runner, source: self.run(
                 'docker', 'exec', source, 'cat', '/opt/amnezia/awg/' + ('wg0.conf' if source == 'amnezia-awg' else 'awg0.conf'))), \
             mock.patch.object(prepare, 'run', self.run), \
             mock.patch.object(prepare, 'policy_functions', return_value=(lambda *a: snapshot, lambda s: '', lambda: None, None)), \
             mock.patch.object(prepare, 'network_function', return_value=self.networks), \
             mock.patch.object(prepare, 'start_target_networks', side_effect=lambda r, j, t, s, b, native=None: j.record(t)), \
             mock.patch.object(prepare, 'inspect_container', side_effect=lambda r, name:
                 {'Id': '1' * 64, 'State': {'StartedAt': EPOCH}} if name == 'amnezia-awg' else None), \
             mock.patch.object(prepare.subprocess, 'run', side_effect=AssertionError('direct subprocess bypass')), \
             mock.patch.object(prepare, 'Journal', side_effect=self.make_journal), \
             mock.patch.object(prepare.secrets, 'token_hex', return_value='c' * 32), \
             mock.patch.object(prepare.secrets, 'token_bytes', side_effect=AssertionError('Python generation fallback') if self.raw else lambda n: b'c' * n), \
             mock.patch.object(prepare.time, 'sleep'), \
             mock.patch.object(trusted_image, 'resolve_image', return_value=args.image,
                 side_effect=AssertionError('Python image fallback') if self.raw else None), \
             mock.patch.object(automatic, 'occupied_udp_ports', return_value=set(),
                 side_effect=AssertionError('Python inventory fallback') if self.raw else None), \
             mock.patch.object(automatic, 'verify_port_available',
                 side_effect=AssertionError('Python socket fallback') if self.raw else None), \
             mock.patch.object(automatic, 'plan', return_value={'image': args.image, 'port': 51821, 'generation': 1},
                 side_effect=AssertionError('Python planner fallback') if self.raw else None):
            return prepare.prepare(args)


class WholeLegacyPrepare(unittest.TestCase):
    def test_actual_manual_and_automatic_prepare_commit_only_pinned_epoch(self):
        for automatic_mode in (False, True):
            with tempfile.TemporaryDirectory() as name:
                harness = PrepareHarness(Path(name), None)
                self.assertTrue(harness.execute(automatic_mode)['prepared'])
                self.assertEqual(harness.journal.value['phase'], 'ready')
                self.assertEqual(harness.journal.value['targetEpoch'], EPOCH)
                self.assertTrue(harness.activation)
                self.assertFalse(harness.journal.cleaned)

    def test_wrong_port_and_epoch_drift_cannot_commit(self):
        for wrong_port, restart, activated in [(True, None, False),
                (False, 'before_activation', False), (False, 'after_activation', True)]:
            with tempfile.TemporaryDirectory() as name:
                harness = PrepareHarness(Path(name), None, wrong_port, restart)
                with self.assertRaises(ValueError):
                    harness.execute(False)
                self.assertTrue(harness.journal.cleaned)
                self.assertNotEqual(harness.journal.value['phase'], 'ready')
                self.assertEqual(harness.activation, activated)
                self.assertNotIn('targetEpoch', harness.journal.value)


@unittest.skipUnless(FIXTURE, 'owned standalone ready fixture required')
class WholeNativePrepare(unittest.TestCase):
    def test_identity_failure_before_or_after_activation_cannot_commit(self):
        for automatic_mode in (False, True):
            for fail_at, activated in ((2, False), (3, True)):
                with self.subTest(automatic=automatic_mode, fail_at=fail_at):
                    with tempfile.TemporaryDirectory() as name:
                        harness = PrepareHarness(Path(name), Path(FIXTURE).read_bytes())
                        actual_ready = prepare.NativePolicy.ready_target
                        observations = []

                        def observe(adapter, *args):
                            observations.append(harness.activation)
                            if len(observations) == fail_at:
                                raise ValueError('native_ready_identity_drift')
                            return actual_ready(adapter, *args)

                        with mock.patch.object(prepare, 'parse_config', side_effect=AssertionError('Python parser fallback')), \
                             mock.patch.object(prepare, 'validate_ready_target', side_effect=AssertionError('Python ready fallback')), \
                             mock.patch.object(prepare.NativePolicy, 'ready_target', autospec=True, side_effect=observe):
                            with self.assertRaisesRegex(ValueError, '^native_ready_identity_drift$'):
                                harness.execute(automatic_mode)
                        self.assertTrue(harness.journal.cleaned)
                        self.assertNotEqual(harness.journal.value['phase'], 'ready')
                        self.assertNotIn('targetEpoch', harness.journal.value)
                        self.assertEqual(harness.activation, activated)
                        self.assertEqual(observations, [False, False, True][:fail_at])
                        self.assertEqual(harness.journal.owned_calls, 1)

    def test_actual_native_manual_and_automatic_prepare(self):
        for automatic_mode in (False, True):
            with tempfile.TemporaryDirectory() as name:
                harness = PrepareHarness(Path(name), Path(FIXTURE).read_bytes())
                actual_ready = prepare.NativePolicy.ready_target
                observations = []
                def observe(adapter, *args):
                    observations.append(harness.activation)
                    return actual_ready(adapter, *args)
                with mock.patch.object(prepare, 'parse_config', side_effect=AssertionError('Python parser fallback')), \
                     mock.patch.object(prepare, 'validate_ready_target', side_effect=AssertionError('Python ready fallback')), \
                     mock.patch.object(prepare.NativePolicy, 'ready_target', autospec=True, side_effect=observe):
                    self.assertTrue(harness.execute(automatic_mode)['prepared'])
                self.assertEqual(harness.journal.value['targetEpoch'], EPOCH)
                self.assertFalse(harness.journal.cleaned)
                self.assertTrue(harness.activation)
                # Pin once; repeated identity/ready observations happen inside C++.
                self.assertEqual(harness.journal.owned_calls, 1)
                self.assertEqual(observations, [False, False, True])


if __name__ == '__main__':
    unittest.main()
