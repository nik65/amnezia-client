"""Pure config generation, private captured transport and inert prepare integration."""
import base64
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import prepare
from ready_validation import parse_config
from test_native_ready_runtime import PrepareHarness, SOURCE, PARAMETERS

FIXTURE = os.environ.get('AWG_GENERATION_TEST_BIN')


def result():
    interface = dict(PARAMETERS, PrivateKey='A' * 43 + '=', Address='10.0.0.1/24',
                     ListenPort='51821', MTU='1420')
    return {'parameters': dict(PARAMETERS), 'interface': interface,
            'config': '[Interface]\n', 'nativeConfig': '[Interface]\n'}


class GenerationProtocol(unittest.TestCase):
    def test_legacy_selection_and_fixed_private_native_request(self):
        self.assertIs(prepare.generation_function(None), prepare.legacy_generate_config)
        adapter = prepare.NativePolicy(b'owned-bytes')
        with mock.patch.object(adapter, '_invoke', return_value=result()) as invoke:
            self.assertEqual(adapter.generate_config(SOURCE, 51821, 1420)[0], PARAMETERS)
        args, kwargs = invoke.call_args
        self.assertEqual(json.loads(args[0]), {'source': SOURCE.decode(), 'port': 51821, 'mtu': 1420})
        self.assertEqual(args[1:], ('--generate-config-json', 16 * 1024 ** 2 + 1,
                                   'native_generation_rejected', set()))
        self.assertEqual(kwargs, {'input_limit': 8 * 1024 ** 2})

    def test_invalid_input_rejected_before_execution(self):
        bad = [(SOURCE, True, 1420), (SOURCE, 1023, 1420), (SOURCE, 65536, 1420),
               (SOURCE, 51821, True), (SOURCE, 51821, 575), (SOURCE, 51821, 9001),
               (SOURCE, 51821.0, 1420), (SOURCE, 51821, '1420'),
               (b'\xff', 51821, 1420), (b'x' * (1024 ** 2 + 1), 51821, 1420),
               (SOURCE.decode(), 51821, 1420)]
        with mock.patch.object(prepare.NativePolicy, '_invoke', side_effect=AssertionError('execution reached')):
            for values in bad:
                with self.subTest(types=tuple(type(v).__name__ for v in values)):
                    with self.assertRaisesRegex(ValueError, '^native_generation_rejected$'):
                        prepare.NativePolicy(b'owned').generate_config(*values)

    def test_malformed_response_and_output_caps_fail_closed(self):
        invalid = [None, True, [], {}, {'parameters': PARAMETERS}]
        for field, value in [('parameters', []), ('interface', []), ('config', None),
                             ('nativeConfig', ''), ('config', '\ud800'),
                             ('config', 'x' * (1024 ** 2 + 1))]:
            current = result()
            current[field] = value
            invalid.append(current)
        for field, key, value in [('parameters', 'Jc', 4), ('interface', 'PrivateKey', None),
                                  ('interface', 'ListenPort', '51822'), ('interface', 'MTU', '1500'),
                                  ('interface', 'Jc', '99')]:
            current = result()
            current[field][key] = value
            invalid.append(current)
        for field in ('parameters', 'interface'):
            for operation in ('extra', 'missing'):
                current = result()
                if operation == 'extra':
                    current[field]['extra'] = 'untrusted'
                else:
                    current[field].pop('Jc')
                invalid.append(current)
        for key in ('!', 'Yw==', base64.b64encode(b'c' * 33).decode(), '\ud800',
                    PARAMETERS['HeaderProtectionKey'][:-2] + 'N='):
            current = result()
            current['parameters']['HeaderProtectionKey'] = key
            current['interface']['HeaderProtectionKey'] = key
            invalid.append(current)
        for index, value in enumerate(invalid):
            with self.subTest(case=index):
                with mock.patch.object(prepare.NativePolicy, '_invoke', return_value=value):
                    with self.assertRaisesRegex(ValueError, '^native_generation_rejected$'):
                        prepare.NativePolicy(b'owned').generate_config(SOURCE, 51821, 1420)

    def test_legacy_keys_peers_and_native_boolean_serialization(self):
        with mock.patch.object(prepare.secrets, 'token_bytes', return_value=b'c' * 32):
            parameters, interface, quick, native = prepare.legacy_generate_config(SOURCE, 51821, 1420)
        self.assertEqual(parameters, PARAMETERS)
        self.assertEqual(parse_config(quick.encode())[0], interface)
        self.assertNotIn('Address =', native)
        self.assertNotIn('MTU =', native)
        text = prepare.native_config({'RandomTrailers': 'true', 'DisableCookies': 'false'}, [])
        self.assertIn('RandomTrailers = 1\n', text)
        self.assertIn('DisableCookies = 0\n', text)


@unittest.skipUnless(FIXTURE, 'owned standalone generation fixture required')
class CapturedGeneration(unittest.TestCase):
    def setUp(self):
        self.raw = Path(FIXTURE).read_bytes()

    def check(self, source=SOURCE, port=51821, mtu=1420):
        with mock.patch.object(prepare.secrets, 'token_bytes', return_value=b'c' * 32):
            expected = prepare.legacy_generate_config(source, port, mtu)
        with mock.patch.object(prepare, 'legacy_generate_config', side_effect=AssertionError('Python fallback')), \
             mock.patch.object(prepare, 'native_config', side_effect=AssertionError('Python serialization')), \
             mock.patch.object(prepare, 'parse_config', side_effect=AssertionError('Python parsing')), \
             mock.patch.object(prepare.secrets, 'token_bytes', side_effect=AssertionError('Python RNG')):
            actual = prepare.generation_function(self.raw)(source, port, mtu)
        self.assertEqual(actual[:2], expected[:2])
        self.assertEqual(parse_config(actual[2].encode()), parse_config(expected[2].encode()))
        # Ordering is deterministic in C++, but only peer order and field values are semantic.
        def native_parts(text):
            return [dict(line.split(' = ', 1) for line in section.splitlines() if ' = ' in line)
                    for section in text.split('\n[Peer]\n')]
        self.assertEqual(native_parts(actual[3]), native_parts(expected[3]))
        return actual

    def test_exact_defaults_hooks_discarded_and_source_identity_preserved(self):
        source = SOURCE.replace(b'[Peer]', b'PostUp=opaque\0hook\nPostDown=echo nope\nDNS=1.1.1.1\n'
                               b'SaveConfig=true\nI1=<b 1>\nJc=900\nHeaderProtectionKey=old\n[Peer]')
        actual = self.check(source)
        self.assertNotIn('PostUp', actual[2])
        self.assertNotIn('old', actual[2])

    def test_parameter_boundaries_and_noncanonical_source_keys(self):
        for port, mtu in [(1024, 576), (65535, 9000), (51821, 1420)]:
            self.check(SOURCE.replace(b'A' * 43, b'/' * 43), port, mtu)

    def test_peer_order_optional_fields_and_opaque_values(self):
        for keepalive in ('0', '25', 'odd=syntax', '1\t2\0opaque', '\\u0000'):
            source = SOURCE + ('PersistentKeepalive=' + keepalive + '\n').encode()
            source += (f'[Peer]\nPublicKey={"D" * 43}=\nAllowedIPs=10.0.0.3/32\n').encode()
            generated = self.check(source)
            self.assertEqual(parse_config(generated[2].encode())[1][0]['PersistentKeepalive'], keepalive)

    def test_large_escaped_request_and_two_large_private_outputs(self):
        source = SOURCE + b'PersistentKeepalive=1' + b'\x01' * 740000 + b'\0end\n'
        self.assertGreater(len(json.dumps({'source': source.decode()})), 1024 ** 2)
        actual = self.check(source)
        self.assertGreater(sum(len(json.dumps(value)) for value in actual[2:]), 8 * 1024 ** 2)

    def test_generated_config_limit_rejects_before_writing(self):
        # Valid source at1MiB, but generated defaults and spacing would push it over1MiB.
        head = SOURCE + b'PersistentKeepalive=1'
        source = head + b'x' * (1024 ** 2 - len(head) - 1) + b'\n'
        self.assertEqual(len(source), 1024 ** 2)
        parse_config(source)
        with self.assertRaisesRegex(ValueError, '^native_generation_rejected$'):
            prepare.NativePolicy(self.raw).generate_config(source, 51821, 1420)
        with tempfile.TemporaryDirectory() as directory:
            harness = PrepareHarness(Path(directory), self.raw)
            actual_run = harness.run

            def large_source(*args, **kwargs):
                if args == ('docker', 'exec', 'amnezia-awg', 'cat', '/opt/amnezia/awg/wg0.conf'):
                    return source
                return actual_run(*args, **kwargs)

            harness.run = large_source
            with self.assertRaisesRegex(ValueError, '^native_generation_rejected$'):
                harness.execute(True)
            self.assertTrue(harness.journal.cleaned)
            self.assertFalse((Path(directory) / 'amnezia-awg/1/awg0.conf').exists())
            self.assertFalse(any(call[:2] == ('docker', 'create') for call in harness.calls))

    def test_generation_failure_stops_before_target_creation_and_requests_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            harness = PrepareHarness(Path(directory), self.raw)
            with mock.patch.object(prepare.NativePolicy, 'generate_config',
                                   side_effect=ValueError('native_generation_rejected')):
                with self.assertRaisesRegex(ValueError, '^native_generation_rejected$'):
                    harness.execute(True)
            self.assertTrue(harness.journal.cleaned)
            self.assertFalse(harness.activation)
            self.assertNotEqual(harness.journal.value['phase'], 'ready')
            self.assertFalse((Path(directory) / 'amnezia-awg/1/awg0.conf').exists())
            self.assertFalse(any(call[:2] == ('docker', 'create') for call in harness.calls))

    def test_actual_rng_failure_cannot_return_partial_success_or_fall_back(self):
        actual_invoke = prepare.NativePolicy._invoke
        generated = []

        def fail_rng(adapter, payload, mode, *args, **kwargs):
            if mode == '--generate-config-json' and 'op' not in json.loads(payload):
                generated.append(True)
                mode = '--generate-config-rng-failure-json'
            return actual_invoke(adapter, payload, mode, *args, **kwargs)

        with tempfile.TemporaryDirectory() as directory:
            harness = PrepareHarness(Path(directory), self.raw)
            with mock.patch.object(prepare.NativePolicy, '_invoke', autospec=True, side_effect=fail_rng), \
                 mock.patch.object(prepare, 'legacy_generate_config', side_effect=AssertionError('Python fallback')):
                with self.assertRaisesRegex(ValueError, '^native_generation_rejected$'):
                    harness.execute(True)
            self.assertEqual(generated, [True])
            self.assertTrue(harness.journal.cleaned)
            self.assertFalse(harness.activation)
            self.assertFalse((Path(directory) / 'amnezia-awg/1/awg0.conf').exists())
            self.assertFalse(any(call[:2] == ('docker', 'create') for call in harness.calls))

    def test_actual_prepare_never_calls_legacy_generator(self):
        for automatic in (False, True):
            with tempfile.TemporaryDirectory() as directory:
                harness = PrepareHarness(Path(directory), self.raw)
                with mock.patch.object(prepare, 'legacy_generate_config', side_effect=AssertionError('legacy reached')), \
                     mock.patch.object(prepare, 'native_config', side_effect=AssertionError('legacy serializer reached')):
                    self.assertTrue(harness.execute(automatic)['prepared'])
                self.assertEqual(harness.journal.value['phase'], 'ready')
                config = Path(directory) / 'amnezia-awg/1/awg0.conf'
                self.assertEqual(config.stat().st_mode & 0o777, 0o600)
                self.assertEqual(parse_config(config.read_bytes())[0]['HeaderProtectionKey'],
                                 PARAMETERS['HeaderProtectionKey'])


if __name__ == '__main__':
    unittest.main()
