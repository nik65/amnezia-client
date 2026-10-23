"""Native private source capture; owned execve fixtures never invoke real Docker."""
import ast
import json
import os
from pathlib import Path
from types import SimpleNamespace
import time
import unittest
from unittest import mock

import prepare
import test_native_network_topology as observer_fixtures

FIXTURE = os.environ.get('AWG_SOURCE_CONFIG_TEST_BIN')
PRODUCTION = os.environ.get('AWG_SOURCE_CONFIG_PRODUCTION_BIN')
FAILURE = 'native_source_config_rejected'
IDENTITY = 'a' * 64
RAW = (f'[Interface]\nPrivateKey={"A" * 43}=\nAddress=10.0.0.1/24\nListenPort=51820\n'
       f'[Peer]\nPublicKey={"B" * 43}=\nAllowedIPs=10.0.0.2/32\n').encode()


def source_responses(source='amnezia-awg', raw=RAW, final_identity=IDENTITY):
    inspect = ['docker', 'inspect', '--format', '{{.Id}}', source]
    config = '/opt/amnezia/awg/' + ('wg0.conf' if source == 'amnezia-awg' else 'awg0.conf')
    records = [{'args': inspect, 'output': IDENTITY + '\n', 'callIndex': 1, 'status': 0, 'delayMs': 0},
               {'args': ['docker', 'exec', IDENTITY, 'cat', config], 'outputHex': raw.hex(),
                'callIndex': 2, 'status': 0, 'delayMs': 0},
               {'args': inspect, 'output': final_identity + '\n', 'callIndex': 3, 'status': 0, 'delayMs': 0}]
    return records


def forbidden_runner():
    return mock.Mock(side_effect=AssertionError('Python source observation fallback'))


def direct_request(adapter, request):
    return adapter._invoke(json.dumps(request, separators=(',', ':')).encode(),
        '--source-config-json', 8 * 1024 ** 2, FAILURE, {FAILURE}, input_limit=8192)


class SourceConfigProtocol(unittest.TestCase):
    def test_legacy_selector_and_native_capture_selection(self):
        self.assertIs(prepare.source_config_function(None), prepare.legacy_source_config)
        selected = prepare.source_config_function(b'owned-helper')
        self.assertIsInstance(selected.__self__, prepare.NativePolicy)
        self.assertEqual(selected.__self__.raw, b'owned-helper')
        for source, filename in [('amnezia-awg', 'wg0.conf'), ('amnezia-awg2', 'awg0.conf')]:
            observe = mock.Mock(return_value=RAW)
            self.assertEqual(prepare.legacy_source_config(observe, source), RAW)
            observe.assert_called_once_with('docker', 'exec', source, 'cat', '/opt/amnezia/awg/' + filename)

    def test_private_request_contains_source_only_and_runner_is_never_used(self):
        for source in ('amnezia-awg', 'amnezia-awg2'):
            observe = forbidden_runner()
            adapter = prepare.NativePolicy(b'owned')
            with mock.patch.object(adapter, '_invoke', return_value={'raw': RAW.decode()}) as invoke:
                self.assertEqual(adapter.source_config(observe, source), RAW)
            args, kwargs = invoke.call_args
            self.assertEqual(json.loads(args[0]), {'op': 'read', 'source': source})
            self.assertEqual(args[1:], ('--source-config-json', 8 * 1024 ** 2, FAILURE, {FAILURE}))
            self.assertEqual(kwargs, {'input_limit': 8192})
            observe.assert_not_called()

    def test_invalid_source_rejects_before_helper_or_python_runner(self):
        adapter = prepare.NativePolicy(b'owned')
        observe = forbidden_runner()
        with mock.patch.object(adapter, '_invoke', side_effect=AssertionError('helper reached')):
            for source in (None, True, '', 'source', IDENTITY, 'amnezia-awg\0suffix', 'amnezia-awg\n'):
                with self.subTest(source=source):
                    with self.assertRaisesRegex(ValueError, '^' + FAILURE + '$'):
                        adapter.source_config(observe, source)
        observe.assert_not_called()

    def test_malformed_result_utf8_empty_and_raw_cap_fail_closed(self):
        values = (None, True, [], {}, {'other': RAW.decode()}, {'raw': RAW.decode(), 'extra': 1},
                  {'raw': None}, {'raw': RAW}, {'raw': 1}, {'raw': ''}, {'raw': '\ud800'},
                  {'raw': 'x' * (1024 ** 2 + 1)})
        for index, value in enumerate(values):
            with self.subTest(case=index), mock.patch.object(prepare.NativePolicy, '_invoke', return_value=value), \
                 mock.patch.object(prepare, 'legacy_source_config', side_effect=AssertionError('legacy fallback')):
                with self.assertRaisesRegex(ValueError, '^' + FAILURE + '$'):
                    prepare.source_config_function(b'owned')(forbidden_runner(), 'amnezia-awg')

    def test_native_failure_never_calls_legacy_capture(self):
        with mock.patch.object(prepare.NativePolicy, '_invoke', side_effect=ValueError(FAILURE)) as invoke, \
             mock.patch.object(prepare, 'legacy_source_config', side_effect=AssertionError('legacy fallback')):
            with self.assertRaisesRegex(ValueError, '^' + FAILURE + '$'):
                prepare.source_config_function(b'owned')(forbidden_runner(), 'amnezia-awg')
        self.assertEqual(invoke.call_count, 1)

    def test_capability_schema_integer_version_and_early_prepare_hook(self):
        adapter = prepare.NativePolicy(b'owned')
        with mock.patch.object(adapter, '_invoke', return_value={'sourceConfigVersion': 1}) as invoke:
            adapter.source_config_capability()
        args, kwargs = invoke.call_args
        self.assertEqual(json.loads(args[0]), {'op': 'capability'})
        self.assertEqual(args[1:], ('--source-config-json', 8 * 1024 ** 2, FAILURE, {FAILURE}))
        self.assertEqual(kwargs, {'input_limit': 8192})
        for value in (None, 1, {}, {'sourceConfigVersion': True}, {'sourceConfigVersion': '1'},
                      {'sourceConfigVersion': 2}, {'sourceConfigVersion': 1, 'extra': 1}):
            with self.subTest(value=value), mock.patch.object(adapter, '_invoke', return_value=value):
                with self.assertRaisesRegex(ValueError, '^' + FAILURE + '$'):
                    adapter.source_config_capability()
        tree = ast.parse(Path(prepare.__file__).read_bytes())
        function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'prepare')
        conditional = next(n for n in function.body if isinstance(n, ast.If)
                           and ast.unparse(n.test) == 'native_feed is not None')
        capability = next(n for n in ast.walk(conditional) if isinstance(n, ast.Call)
                          and isinstance(n.func, ast.Attribute) and n.func.attr == 'source_config_capability')
        effects = [n for n in ast.walk(function) if isinstance(n, ast.Call)
                   and ((isinstance(n.func, ast.Name) and n.func.id == 'Journal')
                        or (isinstance(n.func, ast.Attribute) and n.func.attr in ('cleanup', 'mkdir')))]
        self.assertTrue(effects)
        self.assertLess(capability.lineno, min(n.lineno for n in effects))


@unittest.skipUnless(FIXTURE and hasattr(os, 'memfd_create'), 'owned native source capture helper required')
class CapturedSourceConfig(unittest.TestCase):
    def setUp(self):
        self.raw = Path(FIXTURE).read_bytes()

    def read(self, source='amnezia-awg', raw=RAW):
        responses = source_responses(source, raw)
        observe = forbidden_runner()
        with observer_fixtures.observation_fixture(responses) as trace, \
             mock.patch.object(prepare, 'legacy_source_config', side_effect=AssertionError('legacy fallback')):
            actual = prepare.source_config_function(self.raw)(observe, source)
            self.assertEqual(observer_fixtures.observed_commands(trace), [record['args'] for record in responses])
        observe.assert_not_called()
        self.assertEqual(actual, raw)
        return actual

    def test_both_mapped_sources_preserve_exact_raw_unicode_nul_and_newline_bytes(self):
        with observer_fixtures.observation_fixture([]) as trace:
            adapter = prepare.NativePolicy(self.raw)
            adapter.source_config_capability()
            for source in ('', 'source', IDENTITY, 'amnezia-awg\0suffix', None, True):
                with self.assertRaisesRegex(ValueError, '^' + FAILURE + '$'):
                    direct_request(adapter, {'op': 'read', 'source': source})
            self.assertEqual(observer_fixtures.observed_commands(trace), [])
        variants = [RAW, RAW.replace(b'\n', b'\r\n'), RAW.replace(b'[Peer]',
            'PostUp=opaque\0hook\tзначение😀\n[Peer]'.encode()),
            RAW + b'PersistentKeepalive=one\0two\tthree\n']
        for source in ('amnezia-awg', 'amnezia-awg2'):
            for index, raw in enumerate(variants):
                with self.subTest(source=source, variant=index):
                    self.read(source, raw)

    def test_exact_raw_byte_cap_and_large_private_json_expansion(self):
        head = RAW.replace(b'[Peer]', b'PostUp=x\n[Peer]')
        raw = head.replace(b'PostUp=x', b'PostUp=' + b'\x01' * (1024 ** 2 - len(head) + 1))
        self.assertEqual(len(raw), 1024 ** 2)
        self.read(raw=raw)
        responses = source_responses(raw=raw + b'x')
        with observer_fixtures.observation_fixture(responses) as trace:
            with self.assertRaisesRegex(ValueError, '^' + FAILURE + '$'):
                prepare.NativePolicy(self.raw).source_config(forbidden_runner(), 'amnezia-awg')
            self.assertEqual(len(observer_fixtures.observed_commands(trace)), 2)

    def test_all_three_native_commands_fail_closed_on_exit_cap_utf8_or_deadline(self):
        for index in range(3):
            for failure in ('exit', 'cap', 'utf8', 'timeout'):
                responses = source_responses()
                record = responses[index]
                if failure == 'exit': record['status'] = 1
                if failure == 'cap':
                    record.pop('outputHex', None)
                    record['output'] = 'x' * ((128 if index != 1 else 1024 ** 2) + 1)
                if failure == 'utf8':
                    record.pop('output', None)
                    record['outputHex'] = 'ff'
                if failure == 'timeout': record['delayMs'] = 4000
                start = time.monotonic()
                with self.subTest(index=index, failure=failure), observer_fixtures.observation_fixture(responses) as trace:
                    with self.assertRaisesRegex(ValueError, '^' + FAILURE + '$'):
                        prepare.NativePolicy(self.raw).source_config(forbidden_runner(), 'amnezia-awg')
                    self.assertEqual(observer_fixtures.observed_commands(trace),
                                     [item['args'] for item in responses[:index + 1]])
                if failure == 'timeout':
                    self.assertGreaterEqual(time.monotonic() - start, 2.5)
                    self.assertLess(time.monotonic() - start, 8)

    def test_repeated_inspect_drift_and_malformed_pin_never_return_config(self):
        for final_id in ('b' * 64, '', 'a' * 63, 'A' * 64, IDENTITY + '\0suffix'):
            responses = source_responses(final_identity=final_id)
            with self.subTest(kind=repr(final_id)), observer_fixtures.observation_fixture(responses) as trace:
                with self.assertRaisesRegex(ValueError, '^' + FAILURE + '$'):
                    prepare.NativePolicy(self.raw).source_config(forbidden_runner(), 'amnezia-awg')
                self.assertEqual(len(observer_fixtures.observed_commands(trace)), 3)
        for pin in ('', 'a' * 63, 'A' * 64, IDENTITY + '\0suffix', IDENTITY + '\nextra'):
            responses = source_responses()
            responses[0]['output'] = pin
            with self.subTest(pin=repr(pin)), observer_fixtures.observation_fixture(responses) as trace:
                with self.assertRaisesRegex(ValueError, '^' + FAILURE + '$'):
                    prepare.NativePolicy(self.raw).source_config(forbidden_runner(), 'amnezia-awg')
                self.assertEqual(len(observer_fixtures.observed_commands(trace)), 1)

    def test_invalid_config_rejects_before_repeat_inspect(self):
        for raw in (b'', b'\xff', b'private-synthetic-invalid', RAW.replace(b'Address=', b'Unknown=')):
            with self.subTest(length=len(raw)), observer_fixtures.observation_fixture(source_responses(raw=raw)) as trace:
                with self.assertRaisesRegex(ValueError, '^' + FAILURE + '$'):
                    prepare.NativePolicy(self.raw).source_config(forbidden_runner(), 'amnezia-awg')
                self.assertEqual(len(observer_fixtures.observed_commands(trace)), 2)

    def test_actual_prepare_three_reads_and_main_preflight_call_select_native(self):
        # Evaluate only actual selector/read AST nodes; surrounding mutations,
        # control/authentication, PID1 and journal code are never executed.
        tree = ast.parse(Path(prepare.__file__).read_bytes())
        function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'prepare')
        main = next(n for n in tree.body if isinstance(n, ast.If)
                    and isinstance(n.test, ast.Compare) and isinstance(n.test.left, ast.Name)
                    and n.test.left.id == '__name__')
        for root, native_name, count in ((function, 'native_feed', 3), (main, 'captured_native', 1)):
            selector = next(n for n in ast.walk(root) if isinstance(n, ast.Assign)
                            and isinstance(n.value, ast.Call) and isinstance(n.value.func, ast.Name)
                            and n.value.func.id == 'source_config_function')
            reads = [n for n in ast.walk(root) if isinstance(n, ast.Call)
                     and isinstance(n.func, ast.Name) and n.func.id == 'read_source_config']
            self.assertEqual(len(reads), count)
            namespace = dict(prepare.__dict__, **{native_name: self.raw}, run=forbidden_runner(),
                             args=SimpleNamespace(source='amnezia-awg'))
            exec(compile(ast.Module(body=[selector], type_ignores=[]), 'actual-source-selector', 'exec'), namespace)
            self.assertIsInstance(namespace['read_source_config'].__self__, prepare.NativePolicy)
            for read in reads:
                with observer_fixtures.observation_fixture(source_responses()), \
                     mock.patch.object(prepare, 'legacy_source_config', side_effect=AssertionError('legacy fallback')):
                    self.assertEqual(eval(compile(ast.Expression(body=read), 'actual-source-read', 'eval'), namespace), RAW)


@unittest.skipUnless(PRODUCTION and hasattr(os, 'memfd_create'), 'owned production helper required')
class SafeProductionSourceConfig(unittest.TestCase):
    def test_only_capability_and_invalid_sources_are_sent_to_production(self):
        adapter = prepare.NativePolicy(Path(PRODUCTION).read_bytes())
        adapter.source_config_capability()
        for source in ('', 'source', IDENTITY, 'amnezia-awg\0suffix', None, True):
            with self.subTest(source=repr(source)):
                with self.assertRaisesRegex(ValueError, '^' + FAILURE + '$'):
                    adapter.source_config(forbidden_runner(), source)
                # Core source-name/type guards have been inspected and the same
                # requests prove zero children in the interposed test above.
                with self.assertRaisesRegex(ValueError, '^' + FAILURE + '$'):
                    direct_request(adapter, {'op': 'read', 'source': source})


if __name__ == '__main__':
    unittest.main()
