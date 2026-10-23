"""Captured native observer with interposed Docker children; no real Docker/network."""
import ast
from contextlib import contextmanager
import copy
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock

import prepare
import test_prepare

FIXTURE = os.environ.get('AWG_NETWORK_TEST_BIN')
PRODUCTION = os.environ.get('AWG_NETWORK_PRODUCTION_BIN')
FAILURE = 'unsupported_source_network_topology'
SOURCE = 'amnezia-awg'


def fixture():
    values = test_prepare.NetworkTopologyTests().fixture()
    networks, endpoints, _, _ = values
    for name, identity in [('bridge', 'b' * 64), ('amnezia-dns-net', 'd' * 64)]:
        networks[name]['Id'] = endpoints[name]['NetworkID'] = identity
    return values


def runner(values=None, version='29.0.0'):
    return test_prepare.NetworkTopologyTests().runner(values or fixture(), version)


def good_result():
    return {'binding': {'bridge': {'networkId': 'b' * 64, 'interface': 'eth0', 'default': True}},
            'options': ['--network', 'name=bridge,driver-opt=com.docker.network.endpoint.ifname=eth0,gw-priority=1']}


def snapshot_responses(values, version='29.0.0'):
    networks, endpoints, addresses, routes = values
    identity = 'a' * 64
    records = [
        (['docker', 'version', '--format', '{{.Server.Version}}'], version),
        (['docker', 'inspect', SOURCE], json.dumps([{'Id': identity, 'NetworkSettings': {'Networks': endpoints}}])),
        (['docker', 'exec', identity, 'ip', '-j', '-4', 'address', 'show'], json.dumps(addresses)),
        (['docker', 'exec', identity, 'ip', '-j', '-4', 'route', 'show', 'default'], json.dumps(routes))]
    records.extend((['docker', 'network', 'inspect', name], json.dumps([networks[name]]))
                   for name in sorted(endpoints) if name in networks)
    return [{'args': args, 'output': output, 'status': 0, 'delayMs': 0} for args, output in records]


@contextmanager
def observation_fixture(responses):
    """Only the test executable reads this owned CWD file; production has no seam."""
    previous = os.getcwd()
    with tempfile.TemporaryDirectory(prefix='owned-network-observer-') as directory:
        directory = Path(directory)
        (directory / 'network-observer-fixture.json').write_text(json.dumps({'responses': responses}), encoding='utf8')
        try:
            os.chdir(directory)
            yield directory / 'network-observer-trace.jsonl'
        finally:
            os.chdir(previous)


def observed_commands(trace):
    return [json.loads(line) for line in trace.read_text().splitlines()] if trace.exists() else []


class NetworkProtocol(unittest.TestCase):
    def test_selector_and_explicit_wrapper_use_native_without_legacy(self):
        self.assertIs(prepare.network_function(None), prepare.source_network_options)
        selected = prepare.network_function(b'owned-helper')
        self.assertIsInstance(selected.__self__, prepare.NativePolicy)
        self.assertEqual(selected.__self__.raw, b'owned-helper')
        with mock.patch.object(prepare.NativePolicy, 'network_topology', return_value=['owned']) as native, \
             mock.patch.object(prepare, 'legacy_source_network_options', side_effect=AssertionError('legacy fallback')):
            binding = {}
            self.assertEqual(prepare.source_network_options(runner(), 'source', binding, native=b'owned'), ['owned'])
        self.assertEqual(native.call_args.args[1:], ('source', binding))

    def test_private_source_only_request_never_calls_python_runner(self):
        observe = mock.Mock(side_effect=AssertionError('Python observation fallback'))
        with mock.patch.object(prepare.NativePolicy, '_invoke', return_value=good_result()) as invoke:
            binding = {'existing': 'preserved'}
            result = prepare.NativePolicy(b'owned').network_topology(observe, SOURCE, binding)
        self.assertEqual(result, good_result()['options'])
        self.assertEqual(binding, dict(good_result()['binding'], existing='preserved'))
        args, kwargs = invoke.call_args
        self.assertEqual(json.loads(args[0]), {'op': 'snapshot', 'container': SOURCE})
        self.assertEqual(args[1:], ('--network-json', 16384, FAILURE, {FAILURE}))
        self.assertEqual(kwargs, {'input_limit': 8 * 1024 ** 2})
        observe.assert_not_called()

    def test_bad_network_set_response_never_calls_python_runner(self):
        for names in ([], ['unknown'], ['amnezia-dns-net'], ['bridge', 'unknown']):
            value = {'options': [], 'binding': {name: good_result()['binding']['bridge'] for name in names}}
            observe = mock.Mock(side_effect=AssertionError('Python observation fallback'))
            with self.subTest(shape=type(value).__name__), \
                 mock.patch.object(prepare.NativePolicy, '_invoke', return_value=value):
                with self.assertRaisesRegex(ValueError, '^' + FAILURE + '$'):
                    prepare.NativePolicy(b'owned').network_topology(observe, SOURCE)
            observe.assert_not_called()

    def test_malformed_result_never_partially_updates_binding(self):
        invalid = [None, False, {}, {'options': []}, {'binding': {}, 'options': []}]
        for field, value in [('options', None), ('options', ['unexpected']), ('binding', []),
                             ('binding', {'unknown': {}})]:
            current = good_result()
            current[field] = value
            invalid.append(current)
        for field, value in [('networkId', ''), ('networkId', 'x\0y'), ('networkId', 1),
                             ('networkId', 'x' * 1025), ('interface', 'eth2'), ('interface', []),
                             ('default', 1), ('default', False)]:
            current = good_result()
            current['binding']['bridge'][field] = value
            invalid.append(current)
        for operation in ('extra', 'missing'):
            current = good_result()
            if operation == 'extra':
                current['binding']['bridge']['extra'] = True
            else:
                current['binding']['bridge'].pop('networkId')
            invalid.append(current)
        current = good_result()
        current['extra'] = 'unexpected'
        invalid.append(current)
        for index, value in enumerate(invalid):
            binding = {'original': {'value': 'preserved'}}
            before = copy.deepcopy(binding)
            with self.subTest(case=index), \
                 mock.patch.object(prepare.NativePolicy, '_invoke', return_value=value), \
                 mock.patch.object(prepare, 'legacy_source_network_options', side_effect=AssertionError('legacy fallback')):
                with self.assertRaisesRegex(ValueError, '^' + FAILURE + '$'):
                    prepare.NativePolicy(b'owned').network_topology(runner(), 'source', binding)
            self.assertEqual(binding, before)

    def test_capability_exact_request_and_integer_version_only(self):
        adapter = prepare.NativePolicy(b'owned')
        with mock.patch.object(adapter, '_invoke', return_value={'observerVersion': 1}) as invoke:
            adapter.network_capability()
        args, kwargs = invoke.call_args
        self.assertEqual(json.loads(args[0]), {'op': 'capability'})
        self.assertEqual(args[1:], ('--network-json', 16384, FAILURE, {FAILURE}))
        self.assertEqual(kwargs, {'input_limit': 8 * 1024 ** 2})
        for value in (None, 1, {}, {'observerVersion': True}, {'observerVersion': '1'},
                      {'observerVersion': 2}, {'observerVersion': 1, 'extra': True}):
            with self.subTest(value=value), mock.patch.object(adapter, '_invoke', return_value=value):
                with self.assertRaisesRegex(ValueError, '^' + FAILURE + '$'):
                    adapter.network_capability()
        tree = ast.parse(Path(prepare.__file__).read_bytes())
        function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'prepare')
        conditional = next(n for n in function.body if isinstance(n, ast.If)
                           and ast.unparse(n.test) == 'native_feed is not None')
        capability = next(n for n in ast.walk(conditional) if isinstance(n, ast.Call)
                          and isinstance(n.func, ast.Attribute) and n.func.attr == 'network_capability')
        effects = [n for n in ast.walk(function) if isinstance(n, ast.Call)
                   and ((isinstance(n.func, ast.Name) and n.func.id == 'Journal')
                        or (isinstance(n.func, ast.Attribute) and n.func.attr in ('cleanup', 'mkdir')))]
        self.assertTrue(effects)
        self.assertLess(capability.lineno, min(n.lineno for n in effects))

    def test_native_rejection_does_not_retry_legacy(self):
        binding = {'old': 'preserved'}
        with mock.patch.object(prepare.NativePolicy, '_invoke', side_effect=ValueError(FAILURE)) as invoke, \
             mock.patch.object(prepare, 'legacy_source_network_options', side_effect=AssertionError('legacy fallback')):
            with self.assertRaisesRegex(ValueError, '^' + FAILURE + '$'):
                prepare.source_network_options(runner(), 'source', binding, native=b'owned')
        self.assertEqual(invoke.call_count, 1)
        self.assertEqual(binding, {'old': 'preserved'})


@unittest.skipUnless(FIXTURE and hasattr(os, 'memfd_create'), 'owned native topology helper required')
class CapturedTopology(unittest.TestCase):
    def setUp(self):
        self.raw = Path(FIXTURE).read_bytes()

    def check(self, values, version='29.0.0'):
        expected_binding, binding = {}, {}
        expected = prepare.legacy_source_network_options(runner(values, version), 'source', expected_binding)
        responses = snapshot_responses(values, version)
        observe = mock.Mock(side_effect=AssertionError('Python observation fallback'))
        with observation_fixture(responses) as trace, \
             mock.patch.object(prepare, 'legacy_source_network_options', side_effect=AssertionError('legacy fallback')):
            actual = prepare.network_function(self.raw)(observe, SOURCE, binding)
            self.assertEqual(observed_commands(trace), [entry['args'] for entry in responses])
        observe.assert_not_called()
        self.assertEqual(actual, expected)
        self.assertEqual(binding, expected_binding)

    def test_stock_and_both_dns_interface_default_variants(self):
        with observation_fixture([]) as trace:
            adapter = prepare.NativePolicy(self.raw)
            adapter.network_capability()
            for source in ('', 'source', '-option', 'a' * 63, 'A' * 64, 'amnezia-awg\0suffix'):
                with self.assertRaisesRegex(ValueError, '^' + FAILURE + '$'):
                    adapter.network_topology(mock.Mock(side_effect=AssertionError('Python observations')), source)
            self.assertEqual(observed_commands(trace), [])
        self.check(fixture())
        networks, endpoints, addresses, routes = fixture()
        addresses[0]['ifname'], addresses[1]['ifname'] = 'eth1', 'eth0'
        routes[0]['gateway'] = '172.17.0.1'
        self.check((networks, endpoints, addresses, routes))
        networks, endpoints, addresses, _ = fixture()
        del networks['amnezia-dns-net'], endpoints['amnezia-dns-net']
        addresses = [addresses[1]]
        addresses[0]['ifname'] = 'eth0'
        self.check((networks, endpoints, addresses, [{'dst': 'default', 'dev': 'eth0', 'gateway': '172.17.0.1'}]))

    def test_invalid_snapshots_return_fixed_error_without_partial_binding(self):
        for change in ('duplicate_ip', 'unknown_iface', 'extra_network', 'two_defaults',
                       'wrong_gateway', 'wrong_driver', 'wrong_id', 'old_version'):
            values = fixture()
            networks, endpoints, addresses, routes = values
            if change == 'duplicate_ip': addresses.append(copy.deepcopy(addresses[0]))
            if change == 'unknown_iface': addresses[0]['ifname'] = 'eth2'
            if change == 'extra_network': endpoints['unknown'] = {}
            if change == 'two_defaults': routes.append(copy.deepcopy(routes[0]))
            if change == 'wrong_gateway': routes[0]['gateway'] = '172.17.0.1'
            if change == 'wrong_driver': networks['bridge']['Driver'] = 'host'
            if change == 'wrong_id': endpoints['bridge']['NetworkID'] = 'wrong'
            binding = {'old': 'preserved'}
            with self.subTest(change=change), observation_fixture(snapshot_responses(
                    values, '27.5.1' if change == 'old_version' else '29.0.0')), \
                 mock.patch.object(prepare, 'legacy_source_network_options', side_effect=AssertionError('legacy fallback')):
                with self.assertRaisesRegex(ValueError, '^' + FAILURE + '$'):
                    prepare.NativePolicy(self.raw).network_topology(
                        mock.Mock(side_effect=AssertionError('Python observations')), SOURCE, binding)
            self.assertEqual(binding, {'old': 'preserved'})

    def test_native_observation_exit_cap_utf8_and_deadline_stop_before_next_command(self):
        for index in range(6):
            for failure in ('exit', 'cap', 'utf8', 'timeout'):
                responses = snapshot_responses(fixture())
                entry = responses[index]
                if failure == 'exit': entry['status'] = 1
                if failure == 'cap': entry['output'] = 'x' * (1024 ** 2 + 1)
                if failure == 'utf8':
                    entry.pop('output')
                    entry['outputHex'] = 'ff'
                if failure == 'timeout': entry['delayMs'] = 4000
                binding = {'old': 'preserved'}
                begin = time.monotonic()
                with self.subTest(index=index, failure=failure), observation_fixture(responses) as trace:
                    with self.assertRaisesRegex(ValueError, '^' + FAILURE + '$'):
                        prepare.NativePolicy(self.raw).network_topology(
                            mock.Mock(side_effect=AssertionError('Python observations')), SOURCE, binding)
                    self.assertEqual(observed_commands(trace), [entry['args'] for entry in responses[:index + 1]])
                if failure == 'timeout':
                    self.assertGreaterEqual(time.monotonic() - begin, 2.5)
                    self.assertLess(time.monotonic() - begin, 8)
                self.assertEqual(binding, {'old': 'preserved'})

    def test_actual_prepare_and_preflight_nodes_select_captured_native(self):
        # Execute only the actual topology-selection/read AST nodes, never the
        # surrounding prepare journal, container, listener, or control actions.
        tree = ast.parse(Path(prepare.__file__).read_bytes())
        function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'prepare')
        selector = next(n for n in function.body if isinstance(n, ast.Assign)
                        and isinstance(n.value, ast.Call) and isinstance(n.value.func, ast.Name)
                        and n.value.func.id == 'network_function')
        read = next(n for n in function.body if isinstance(n, ast.Assign)
                    and isinstance(n.value, ast.Call) and isinstance(n.value.func, ast.Name)
                    and n.value.func.id == 'read_network')
        from types import SimpleNamespace
        namespace = dict(prepare.__dict__, native_feed=self.raw,
                         run=mock.Mock(side_effect=AssertionError('Python observations')),
                         args=SimpleNamespace(source=SOURCE), network_binding={})
        with observation_fixture(snapshot_responses(fixture())), \
             mock.patch.object(prepare, 'legacy_source_network_options', side_effect=AssertionError('legacy fallback')):
            exec(compile(ast.Module(body=[selector, read], type_ignores=[]), 'actual-prepare-topology', 'exec'), namespace)
        self.assertIn('bridge', namespace['network_binding'])
        self.assertIsInstance(namespace['read_network'].__self__, prepare.NativePolicy)

        main = next(n for n in tree.body if isinstance(n, ast.If)
                    and isinstance(n.test, ast.Compare) and isinstance(n.test.left, ast.Name)
                    and n.test.left.id == '__name__')
        selector = next(n for n in ast.walk(main) if isinstance(n, ast.Assign)
                        and isinstance(n.value, ast.Call) and isinstance(n.value.func, ast.Name)
                        and n.value.func.id == 'network_function')
        preflight_read = next(n for n in ast.walk(main) if isinstance(n, ast.Expr)
                              and isinstance(n.value, ast.Call) and isinstance(n.value.func, ast.Name)
                              and n.value.func.id == 'read_network')
        namespace = dict(prepare.__dict__, captured_native=self.raw,
                         run=mock.Mock(side_effect=AssertionError('Python observations')),
                         args=SimpleNamespace(source=SOURCE))
        with observation_fixture(snapshot_responses(fixture())), \
             mock.patch.object(prepare, 'legacy_source_network_options', side_effect=AssertionError('legacy fallback')):
            exec(compile(ast.Module(body=[selector, preflight_read], type_ignores=[]), 'actual-preflight-topology', 'exec'), namespace)
        self.assertIsInstance(namespace['read_network'].__self__, prepare.NativePolicy)


@unittest.skipUnless(PRODUCTION and hasattr(os, 'memfd_create'), 'owned production helper required')
class SafeProductionObserver(unittest.TestCase):
    def test_production_capability_and_invalid_identifiers(self):
        adapter = prepare.NativePolicy(Path(PRODUCTION).read_bytes())
        # No valid snapshot is ever sent to production: capability is pure and
        # invalid request identifiers must be rejected before the first command.
        # Zero spawned commands for these same paths is separately checked with
        # the interposed native executable above; production has no trace seam.
        with observation_fixture([]):
            adapter.network_capability()
            for source in ('', 'source', '-option', 'a' * 63, 'A' * 64, 'amnezia-awg\0suffix'):
                with self.subTest(source=source):
                    with self.assertRaisesRegex(ValueError, '^' + FAILURE + '$'):
                        adapter.network_topology(mock.Mock(side_effect=AssertionError('Python observations')), source)


if __name__ == '__main__':
    unittest.main()
