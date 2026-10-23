"""Isolated helper checks only; no Docker invocation or live epoch filesystem read."""
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock
sys.path.insert(0, str(Path(__file__).parent))
import prepare

class NativePolicyRuntime(unittest.TestCase):
    def test_legacy_selection(self):
        self.assertIs(prepare.policy_functions(None)[0], prepare.namespace_snapshot)

    def test_native_selection_and_no_secrets(self):
        adapter = prepare.NativePolicy(b'captured')
        with mock.patch.object(adapter, 'request', return_value={}) as request:
            adapter.snapshot(None, 'amnezia-awg', {'Address': '10.8.1.1/24', 'PrivateKey': 'private'}, 'wg0')
        self.assertEqual(request.call_args.kwargs['interface'], {'Address': '10.8.1.1/24'})
        self.assertNotIn('private', repr(request.call_args))

    @unittest.skipUnless(os.environ.get('AWG_POLICY_TEST_BIN'), 'isolated helper path required')
    def test_actual_cli_protocol(self):
        binary = os.environ['AWG_POLICY_TEST_BIN']
        for request, expected in [({'op': 'mtu', 'value': '1420'}, 0),
                                  ({'op': 'mtu', 'value': '9'}, 2),
                                  ({'op': 'epoch', 'responses': {}}, 2),
                                  ({'op': 'unknown'}, 2)]:
            result = subprocess.run([binary, '--policy-json'], input=json.dumps(request).encode(),
                                    capture_output=True, timeout=5)
            self.assertEqual(result.returncode, expected)
            self.assertEqual(result.stderr, b'')
            self.assertIsInstance(json.loads(result.stdout), dict)
        for raw in (b'{}x', b'[' + b' ' * 1024 ** 2):
            result = subprocess.run([binary, '--policy-json'], input=raw, capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 2)

    @unittest.skipUnless(os.environ.get('AWG_POLICY_TEST_BIN'), 'isolated helper path required')
    def test_exact_captured_elf_memfd(self):
        # This unit uses only the locally compiled helper; production capture retains static trust checks.
        raw = Path(os.environ['AWG_POLICY_TEST_BIN']).read_bytes()
        self.assertEqual(prepare.NativePolicy(raw).mtu('1420'), 1420)
        with self.assertRaises(ValueError):
            prepare.NativePolicy(raw).mtu('5')

if __name__ == '__main__':
    unittest.main()
