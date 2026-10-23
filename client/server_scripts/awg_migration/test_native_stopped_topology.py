"""Stopped-target pure metadata validation; all Docker actions are inert recorders."""
import copy
import json
import os
from pathlib import Path
import time
from types import SimpleNamespace
import unittest
from unittest import mock

import prepare
import test_native_network_topology as observer_fixtures

FIXTURE = os.environ.get('AWG_NETWORK_TEST_BIN')
IDENTITY = 'a' * 64
FAILURE = 'unsupported_source_network_topology'


def fixture(two=False):
    binding = {'bridge': {'networkId': 'b' * 64, 'interface': 'eth0', 'default': True}}
    if two:
        binding['amnezia-dns-net'] = {'networkId': 'd' * 64, 'interface': 'eth1', 'default': False}
    container = {'Id': IDENTITY,
        'State': {'Status': 'created', 'Pid': 0, 'Running': False, 'StartedAt': '0001-01-01T00:00:00Z'},
        'HostConfig': {'NetworkMode': 'bridge'},
        'NetworkSettings': {'Networks': {name: {'NetworkID': '',
            'DriverOpts': {'com.docker.network.endpoint.ifname': role['interface']},
            'GwPriority': int(role['default'])} for name, role in binding.items()}}}
    networks = {name: {'Id': role['networkId']} for name, role in binding.items()}
    return binding, container, networks


def runner(container, networks, events=None):
    def run(*args):
        if events is not None:
            events.append(args)
        # Pure fake responses for the parent orchestration's connect/start calls.
        if args[:3] == ('docker', 'network', 'connect') or args == ('docker', 'start', IDENTITY):
            return b''
        raise AssertionError('unexpected synthetic command: ' + repr(args))
    return run


def stopped_responses(container, networks):
    values = [(['docker', 'inspect', IDENTITY], json.dumps([container]))]
    values.extend((['docker', 'network', 'inspect', name], json.dumps([network]))
                  for name, network in sorted(networks.items()))
    return [{'args': args, 'output': output, 'status': 0, 'delayMs': 0} for args, output in values]


class StoppedProtocol(unittest.TestCase):
    def test_wrapper_explicit_native_and_absent_legacy_select_once(self):
        observe = mock.Mock()
        binding = fixture()[0]
        with mock.patch.object(prepare, 'legacy_verify_stopped_target_networks') as legacy, \
             mock.patch.object(prepare.NativePolicy, 'verify_stopped_networks') as native:
            prepare.verify_stopped_target_networks(observe, IDENTITY, binding)
            legacy.assert_called_once_with(observe, IDENTITY, binding)
            native.assert_not_called()
            prepare.verify_stopped_target_networks(observe, IDENTITY, binding, b'owned-helper')
            native.assert_called_once_with(observe, IDENTITY, binding)
            self.assertEqual(legacy.call_count, 1)

    def test_fixed_request_contains_identity_and_binding_without_python_observations(self):
        binding, container, networks = fixture(True)
        observe = mock.Mock(side_effect=AssertionError('Python observation fallback'))
        with mock.patch.object(prepare.NativePolicy, '_invoke', return_value=True) as invoke:
            prepare.NativePolicy(b'owned').verify_stopped_networks(observe, IDENTITY, binding)
        observe.assert_not_called()
        args, kwargs = invoke.call_args
        value = json.loads(args[0])
        self.assertEqual(value, {'op': 'stopped-snapshot', 'identity': IDENTITY, 'binding': binding})
        self.assertEqual(args[1:], ('--network-json', 16384, FAILURE, {FAILURE}))
        self.assertEqual(kwargs, {'input_limit': 8 * 1024 ** 2})

    def test_only_literal_true_response_is_accepted_without_fallback(self):
        binding, container, networks = fixture()
        for value in (None, False, 0, 1, 'true', [], {}, {'valid': True}):
            with self.subTest(response=repr(value)), \
                 mock.patch.object(prepare.NativePolicy, '_invoke', return_value=value), \
                 mock.patch.object(prepare, 'legacy_verify_stopped_target_networks', side_effect=AssertionError('legacy fallback')):
                with self.assertRaisesRegex(ValueError, '^' + FAILURE + '$'):
                    prepare.verify_stopped_target_networks(runner(container, networks), IDENTITY, binding, b'owned')

    def test_bad_binding_network_set_rejected_before_observations(self):
        observe = mock.Mock(side_effect=AssertionError('observation reached'))
        for binding in (None, [], {}, {'unknown': {}}, {'amnezia-dns-net': {}},
                        {'bridge': {}, 'unknown': {}}):
            with self.subTest(binding=repr(binding)):
                with self.assertRaisesRegex(ValueError, '^' + FAILURE + '$'):
                    prepare.NativePolicy(b'owned').verify_stopped_networks(observe, IDENTITY, binding)
        observe.assert_not_called()

    def test_invalid_identity_rejected_without_python_observation(self):
        binding = fixture()[0]
        observe = mock.Mock(side_effect=AssertionError('Python observation fallback'))
        with mock.patch.object(prepare.NativePolicy, '_invoke', side_effect=ValueError(FAILURE)):
            for identity in ('', 'a' * 63, 'A' * 64, None, 'amnezia-awg'):
                with self.subTest(identity=identity):
                    with self.assertRaisesRegex(ValueError, '^' + FAILURE + '$'):
                        prepare.NativePolicy(b'owned').verify_stopped_networks(observe, identity, binding)
        observe.assert_not_called()

    def test_rejected_helper_never_falls_back(self):
        binding, container, networks = fixture()
        with mock.patch.object(prepare.NativePolicy, '_invoke', side_effect=ValueError(FAILURE)) as invoke, \
             mock.patch.object(prepare, 'legacy_verify_stopped_target_networks', side_effect=AssertionError('legacy fallback')):
            with self.assertRaisesRegex(ValueError, '^' + FAILURE + '$'):
                prepare.verify_stopped_target_networks(runner(container, networks), IDENTITY, binding, b'owned')
        self.assertEqual(invoke.call_count, 1)


@unittest.skipUnless(FIXTURE and hasattr(os, 'memfd_create'), 'owned standalone network helper required')
class CapturedStoppedTopology(unittest.TestCase):
    def setUp(self):
        self.raw = Path(FIXTURE).read_bytes()

    def verify(self, binding, container, networks):
        responses = stopped_responses(container, networks)
        with observer_fixtures.observation_fixture(responses), \
             mock.patch.object(prepare, 'legacy_verify_stopped_target_networks', side_effect=AssertionError('legacy fallback')):
            prepare.verify_stopped_target_networks(
                mock.Mock(side_effect=AssertionError('Python observation fallback')), IDENTITY, binding, self.raw)

    def test_one_and_two_network_metadata_with_blank_or_matching_network_id(self):
        with observer_fixtures.observation_fixture([]) as trace:
            for identity in ('', 'source', 'amnezia-awg', 'a' * 63, 'A' * 64, None):
                with self.assertRaisesRegex(ValueError, '^' + FAILURE + '$'):
                    prepare.NativePolicy(self.raw).verify_stopped_networks(
                        mock.Mock(side_effect=AssertionError('Python observations')), identity, fixture()[0])
            self.assertEqual(observer_fixtures.observed_commands(trace), [])
        for two in (False, True):
            for empty_id in (False, True):
                binding, container, networks = fixture(two)
                if not empty_id:
                    for name, role in binding.items():
                        container['NetworkSettings']['Networks'][name]['NetworkID'] = role['networkId']
                before = copy.deepcopy(binding)
                self.verify(binding, container, networks)
                self.assertEqual(binding, before)

    def test_bad_stopped_metadata_is_rejected_fixed_and_without_mutating_binding(self):
        cases = ('identity', 'status', 'pid', 'pid_bool', 'running', 'running_int', 'started',
                 'network_mode', 'extra_network', 'missing_network', 'stale_global_id',
                 'stale_endpoint_id', 'driver_interface', 'driver_extra', 'priority', 'priority_bool',
                 'endpoint_ip', 'gateway', 'endpoint_id', 'ipv6', 'ipv6_gateway')
        for change in cases:
            binding, container, networks = fixture(True)
            endpoint = container['NetworkSettings']['Networks']['bridge']
            if change == 'identity': container['Id'] = 'b' * 64
            if change == 'status': container['State']['Status'] = 'exited'
            if change == 'pid': container['State']['Pid'] = 123
            if change == 'pid_bool': container['State']['Pid'] = False
            if change == 'running': container['State']['Running'] = True
            if change == 'running_int': container['State']['Running'] = 0
            if change == 'started': container['State']['StartedAt'] = '2026-10-21T00:00:00Z'
            if change == 'network_mode': container['HostConfig']['NetworkMode'] = 'host'
            if change == 'extra_network': container['NetworkSettings']['Networks']['unknown'] = {}
            if change == 'missing_network': container['NetworkSettings']['Networks'].pop('bridge')
            if change == 'stale_global_id': networks['bridge']['Id'] = 'replaced-id'
            if change == 'stale_endpoint_id': endpoint['NetworkID'] = 'replaced-id'
            if change == 'driver_interface': endpoint['DriverOpts']['com.docker.network.endpoint.ifname'] = 'eth1'
            if change == 'driver_extra': endpoint['DriverOpts']['unknown'] = 'value'
            if change == 'priority': endpoint['GwPriority'] = 0
            if change == 'priority_bool': endpoint['GwPriority'] = True
            if change == 'endpoint_ip': endpoint['IPAddress'] = '172.17.0.2'
            if change == 'gateway': endpoint['Gateway'] = '172.17.0.1'
            if change == 'endpoint_id': endpoint['EndpointID'] = 'assigned-id'
            if change == 'ipv6': endpoint['GlobalIPv6Address'] = 'fe80::1'
            if change == 'ipv6_gateway': endpoint['IPv6Gateway'] = 'fe80::2'
            before = copy.deepcopy(binding)
            with self.subTest(change=change):
                with self.assertRaisesRegex(ValueError, '^' + FAILURE + '$'):
                    self.verify(binding, container, networks)
            self.assertEqual(binding, before)

    def test_native_stopped_observation_failures_stop_before_next_command(self):
        for index in range(3):
            for failure in ('exit', 'cap', 'utf8', 'timeout'):
                binding, container, networks = fixture(True)
                responses = stopped_responses(container, networks)
                entry = responses[index]
                if failure == 'exit': entry['status'] = 1
                if failure == 'cap': entry['output'] = 'x' * (1024 ** 2 + 1)
                if failure == 'utf8':
                    entry.pop('output')
                    entry['outputHex'] = 'ff'
                if failure == 'timeout': entry['delayMs'] = 4000
                before = copy.deepcopy(binding)
                begin = time.monotonic()
                with self.subTest(index=index, failure=failure), observer_fixtures.observation_fixture(responses) as trace:
                    with self.assertRaisesRegex(ValueError, '^' + FAILURE + '$'):
                        prepare.NativePolicy(self.raw).verify_stopped_networks(
                            mock.Mock(side_effect=AssertionError('Python observation fallback')), IDENTITY, binding)
                    self.assertEqual(observer_fixtures.observed_commands(trace),
                                     [entry['args'] for entry in responses[:index + 1]])
                if failure == 'timeout':
                    self.assertGreaterEqual(time.monotonic() - begin, 2.5)
                    self.assertLess(time.monotonic() - begin, 8)
                self.assertEqual(binding, before)

    def start(self, *, two=False, invalid=False):
        binding, container, networks = fixture(two)
        if invalid:
            container['State']['Running'] = True
        events, reads = [], []
        observe = runner(container, networks, events)
        journal = SimpleNamespace(value={'containers': {'target': {'id': None}}})
        def record(name):
            events.append(('record', name))
            journal.value['containers'][name]['id'] = IDENTITY
        journal.record = record
        def read_network(run, source, output):
            reads.append(source)
            output.update(copy.deepcopy(binding))
        with observer_fixtures.observation_fixture(stopped_responses(container, networks)), \
             mock.patch.object(prepare, 'network_function', return_value=read_network) as selector, \
             mock.patch.object(prepare, 'legacy_verify_stopped_target_networks', side_effect=AssertionError('legacy fallback')):
            if invalid:
                with self.assertRaisesRegex(ValueError, '^' + FAILURE + '$'):
                    prepare.start_target_networks(observe, journal, 'target', 'source', binding, self.raw)
            else:
                prepare.start_target_networks(observe, journal, 'target', 'source', binding, self.raw)
        selector.assert_called_once_with(self.raw)
        self.assertEqual(events[0], ('record', 'target'))
        self.assertEqual(journal.value['containers']['target']['id'], IDENTITY)
        if two:
            self.assertEqual(events[1], ('docker', 'network', 'connect', '--driver-opt',
                'com.docker.network.endpoint.ifname=eth1', '--gw-priority', '0', 'amnezia-dns-net', IDENTITY))
        if invalid:
            self.assertNotIn(('docker', 'start', IDENTITY), events)
            self.assertEqual(reads, ['source'])
        else:
            self.assertEqual(events[-1], ('docker', 'start', IDENTITY))
            self.assertEqual(reads, ['source', 'source', IDENTITY])

    def test_actual_parent_record_verify_start_order_with_one_or_two_networks(self):
        for two in (False, True):
            self.start(two=two)

    def test_actual_parent_rejection_never_reaches_fake_start(self):
        for two in (False, True):
            self.start(two=two, invalid=True)


if __name__ == '__main__':
    unittest.main()
