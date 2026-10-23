"""Pure native peer mapping and legacy contract parity; no Docker or network."""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import prepare
from ready_validation import parse_config
from test_native_ready_runtime import SOURCE, PrepareHarness

BIN = os.environ.get('AWG_GENERATION_TEST_BIN')

def legacy(raw, scope):
    _, peers = parse_config(raw)
    return {peer['PublicKey']: {'sourceIp': str(ipaddress.ip_interface(peer['AllowedIPs']).ip),
            'targetIp': str(ipaddress.ip_interface(peer['AllowedIPs']).ip),
            'clientAddress': peer['AllowedIPs'],
            'clientId': hashlib.sha256((scope + '\t' + peer['PublicKey']).encode()).hexdigest()}
            for peer in peers}

class Protocol(unittest.TestCase):
    def test_capability_exact_and_early(self):
        adapter = prepare.NativePolicy(b'owned')
        for bad in ({}, {'peerMappingVersion': True}, {'peerMappingVersion': 2}, {'peerMappingVersion': 1, 'extra': 0}):
            with mock.patch.object(adapter, '_invoke', return_value=bad):
                with self.assertRaisesRegex(ValueError, '^native_generation_rejected$'):
                    adapter.peer_mapping_capability()
        import inspect
        source = inspect.getsource(prepare.prepare)
        self.assertLess(source.index('.peer_mapping_capability()'), source.index('directory.mkdir('))

    def test_mapping_wire_and_no_fallback(self):
        adapter = prepare.NativePolicy(b'owned')
        expected = legacy(SOURCE, 'amnezia-awg')
        with mock.patch.object(adapter, '_invoke', return_value=expected) as call:
            self.assertEqual(adapter.peer_mapping(SOURCE, 'amnezia-awg'), expected)
        self.assertEqual(json.loads(call.call_args.args[0]), {'op':'peer-mapping', 'scope':'amnezia-awg','source':SOURCE.decode()})
        with mock.patch.object(adapter, '_invoke', side_effect=ValueError('native_generation_rejected')):
            with self.assertRaises(ValueError): adapter.peer_mapping(SOURCE, 'amnezia-awg')

    def test_invalid_mapping_response(self):
        adapter = prepare.NativePolicy(b'owned')
        for value in (None, True, [], {}, {'invalid': {}}, {'B'*43+'=': {'sourceIp':'x'}},
                      {'B'*43+'=': dict(next(iter(legacy(SOURCE,'amnezia-awg').values())), clientId=4)},
                      {'B'*43+'=': dict(next(iter(legacy(SOURCE,'amnezia-awg').values())), extra='x')}):
            with mock.patch.object(adapter, '_invoke', return_value=value):
                with self.assertRaisesRegex(ValueError, '^native_generation_rejected$'):
                    adapter.peer_mapping(SOURCE, 'amnezia-awg')

    def test_invalid_before_transport(self):
        adapter = prepare.NativePolicy(b'owned')
        with mock.patch.object(adapter, '_invoke', side_effect=AssertionError('transport')):
            for raw,scope in [(b'\xff','amnezia-awg'),(SOURCE,'unknown'),('text','amnezia-awg'),(b'x'*(1024**2+1),'amnezia-awg')]:
                with self.assertRaisesRegex(ValueError, '^native_generation_rejected$'): adapter.peer_mapping(raw,scope)

@unittest.skipUnless(BIN, 'compiled fixture required')
class NativeParity(unittest.TestCase):
    def setUp(self): self.adapter=prepare.NativePolicy(Path(BIN).read_bytes())
    def test_accepted_mapping_parity(self):
        self.adapter.peer_mapping_capability()
        for scope in ('amnezia-awg','amnezia-awg2'):
            for suffix in ('/32','/032','/255.255.255.255',''):
                raw=SOURCE.replace(b'/32',suffix.encode())
                with self.subTest(scope=scope,suffix=suffix):
                    self.assertEqual(self.adapter.peer_mapping(raw,scope),legacy(raw,scope))
    def test_multiple_peers_and_opaque_unrelated_fields(self):
        second = ('[Peer]\nPublicKey='+'D'*43+'=\nAllowedIPs=10.0.0.3/32\n').encode()
        raw = SOURCE + b'PersistentKeepalive=opaque\x00value\n' + second
        head, first = SOURCE.split(b'[Peer]', 1)
        reversed_raw = head + second + b'[Peer]' + first
        for scope in ('amnezia-awg','amnezia-awg2'):
            for value in (raw, reversed_raw, raw.replace(b'B'*43,b'/'*43)):
                self.assertEqual(self.adapter.peer_mapping(value,scope),legacy(value,scope))

    def test_duplicate_identity_address_and_empty_peers(self):
        head = SOURCE.split(b'[Peer]')[0]
        variants = [head,
            SOURCE + ('[Peer]\nPublicKey='+'B'*43+'=\nAllowedIPs=10.0.0.3/32\n').encode(),
            SOURCE + ('[Peer]\nPublicKey='+'D'*43+'=\nAllowedIPs=10.0.0.2/32\n').encode(),
            SOURCE + b'AllowedIPs=10.0.0.3/32\n']
        for raw in variants:
            with self.assertRaises((ValueError,KeyError)): legacy(raw,'amnezia-awg')
            with self.assertRaisesRegex(ValueError,'^native_generation_rejected$'):
                self.adapter.peer_mapping(raw,'amnezia-awg')

    def test_runtime_boundaries_bypass_bridge(self):
        def invoke(payload):
            return self.adapter._invoke(payload,'--generate-config-json',16*1024**2+1,
                'native_generation_rejected',set(),input_limit=8*1024**2)
        for payload in [b'{"op":"capability","op":"capability"}',
                        b'{"op":"capability","op\\u0000":"x"}',
                        b'{"op":"peer-mapping","scope":"amnezia-awg","source":"\xff"}',
                        json.dumps({'op':'peer-mapping','scope':'amnezia-awg','source':'x'*(1024**2+1)}).encode()]:
            with self.assertRaisesRegex(ValueError,'^native_generation_rejected$'): invoke(payload)

    def test_capability_failure_prevents_prepare_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            harness = PrepareHarness(Path(directory),self.adapter.raw)
            with mock.patch.object(prepare.NativePolicy,'peer_mapping_capability',
                                   side_effect=ValueError('native_generation_rejected')):
                with self.assertRaisesRegex(ValueError,'^native_generation_rejected$'):
                    harness.execute(True)
            self.assertEqual(list(Path(directory).iterdir()), [])
            self.assertFalse(harness.activation)
            self.assertFalse(any(call[:2] in (('docker','create'),('docker','start')) for call in harness.calls))

    def test_real_prepare_uses_native_mapping(self):
        with tempfile.TemporaryDirectory() as directory:
            harness = PrepareHarness(Path(directory), self.adapter.raw)
            actual = prepare.NativePolicy.peer_mapping
            calls = []
            def capture(adapter, raw, scope):
                calls.append((raw, scope))
                return actual(adapter, raw, scope)
            with mock.patch.object(prepare.NativePolicy, 'peer_mapping', autospec=True, side_effect=capture):
                self.assertTrue(harness.execute(True)['prepared'])
            self.assertEqual(calls, [(SOURCE, 'amnezia-awg')])

    def test_rejection_parity(self):
        for suffix in ('/0.0.0.0','/0','/1','/31','/33', '/255.0.255.0', '/32,10.0.0.20/32'):
            raw=SOURCE.replace(b'/32',suffix.encode())
            with self.subTest(suffix=suffix):
                with self.assertRaises((ValueError,KeyError)): legacy(raw,'amnezia-awg')
                with self.assertRaisesRegex(ValueError,'^native_generation_rejected$'): self.adapter.peer_mapping(raw,'amnezia-awg')

if __name__ == '__main__': unittest.main()
