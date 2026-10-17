"""Read-only target attestation tests; no Docker, preparation or control writes."""
import base64
import copy
import hashlib
import os
from pathlib import Path
import tempfile
import unittest

import ready_validation as validation
from trusted_image import BINARY_SHA256

PRIVATE = base64.b64encode(b'a' * 32).decode()
PUBLIC = base64.b64encode(b'b' * 32).decode()
PSK = base64.b64encode(b'c' * 32).decode()


class ExistingTargetValidationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.source = ('[Interface]\nPrivateKey = ' + PRIVATE + '\nAddress = 10.8.1.1/24\nListenPort = 51820\n'
                       '[Peer]\nPublicKey = ' + PUBLIC + '\nPresharedKey = ' + PSK + '\nAllowedIPs = 10.8.1.2/32\n').encode()
        self.parameters = {'HeaderProtectionKey': PSK, 'S1': '16', 'S2': '16', 'S3': '16', 'S4': '16',
                           'ContentPaddingAddition': '0', 'RandomTrailers': '0', 'DisableCookies': '0'}
        self.target = self.source.replace(b'51820', b'51821').replace(b'[Peer]', ''.join(k + ' = ' + v + '\n' for k,v in self.parameters.items()).encode() + b'[Peer]')
        (self.directory / 'awg0.conf').write_bytes(self.target)
        self.value = {'source': 'amnezia-awg2', 'sourceId': 'immutable-source', 'target': 'owned-target',
                      'sourceDigest': hashlib.sha256(self.source).hexdigest(),
                      'containers': {'owned-target': {'id': 'immutable-target'}},
                      'request': {'generation': 1, 'host': 'example.invalid', 'port': 51821}}
        self.ready = {'containerId': 'amnezia-awg2', 'targetContainer': 'owned-target', 'generation': 1,
                      'endpoint': 'example.invalid:51821', 'serverPublicKey': PUBLIC, 'parameters': self.parameters,
                      'peers': {PUBLIC: {'sourceIp': '10.8.1.2', 'targetIp': '10.8.1.2', 'clientAddress': '10.8.1.2/32'}}}
        self.dump = (PRIVATE + '\t' + PUBLIC + '\t51821\t0\n' + PUBLIC + '\t' + PSK + '\t(none)\t10.8.1.2/32\t0\t0\t0\t0\n').encode()
        self.accepted = ''.join(k + ' = ' + ('off' if k in ('RandomTrailers','DisableCookies') else v) + '\n' for k,v in self.parameters.items() if k != 'ContentPaddingAddition').encode()
        self.engine = (BINARY_SHA256 + '  /proc/42/exe\n').encode()
        self.calls = []
    def run_read(self, *args):
        self.calls.append(args)
        if args == ('docker','exec','immutable-source','cat','/opt/amnezia/awg/awg0.conf'): return self.source
        if args == ('docker','exec','immutable-target','cat','/migration/awg0.conf'): return self.target
        if args == ('docker','exec','immutable-target','awg','show','awg0','dump'): return self.dump
        if args == ('docker','exec','immutable-target','awg','showconf','awg0'): return self.accepted
        if args[:5] == ('docker','exec','immutable-target','sh','-c') and 'kill -0' in args[-1] and 'sha256sum' in args[-1]: return self.engine
        raise AssertionError('unexpected command')
    def validate(self):
        validation.validate_existing_target(self.directory,self.value,self.ready,self.run_read)
    @unittest.skipIf(os.name == 'nt', 'prepare operational module is POSIX')
    def test_prepare_reuses_actual_shared_validation_functions(self):
        import prepare
        self.assertIs(prepare.parse_config, validation.parse_config)
        self.assertIs(prepare.validate_ready_target, validation.validate_ready_target)

    def test_valid_existing_target_reads_only_immutable_ids(self):
        self.validate()
        self.assertEqual(len(self.calls),5)
        self.assertTrue(all(call[:2] == ('docker','exec') for call in self.calls))
        self.assertEqual((self.directory/'awg0.conf').read_bytes(),self.target)
    def test_source_digest_drift_fails_before_target_probe(self):
        self.value['sourceDigest'] = '0' * 64
        self.assertRaises(ValueError,self.validate)
        self.assertEqual(len(self.calls),1)
    def test_mounted_target_bytes_must_equal_reviewed_config(self):
        self.target += b'# changed\n'
        self.assertRaises(ValueError,self.validate)
        self.assertEqual(len(self.calls),2)
    def test_ready_mapping_or_endpoint_drift_is_rejected(self):
        original = copy.deepcopy(self.ready)
        for mutation in ('endpoint','mapping'):
            self.ready = copy.deepcopy(original)
            if mutation == 'endpoint': self.ready['endpoint'] = 'example.invalid:51822'
            else: self.ready['peers'][PUBLIC]['targetIp'] = '10.8.1.99'
            self.assertRaises(ValueError,self.validate)
    def test_native_peer_or_engine_drift_fails_closed(self):
        original = self.dump
        self.dump = self.dump.replace(b'10.8.1.2/32',b'10.8.1.3/32')
        self.assertRaises(ValueError,self.validate)
        self.dump = original
        self.engine = b'0000  /proc/42/exe\n'
        self.assertRaises(ValueError,self.validate)
    def test_missing_live_engine_proof_does_not_infer_manual_mode(self):
        self.engine = b''
        self.assertRaises(ValueError,self.validate)


if __name__ == '__main__': unittest.main()
