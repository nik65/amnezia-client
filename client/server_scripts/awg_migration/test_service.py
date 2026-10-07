"""Protocol regressions; no Docker, VPN, routes, SSH or live servers."""
import base64
import hashlib
import io
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
import service

PEER = base64.b64encode(bytes(range(32))).decode()
SERVER = base64.b64encode(bytes(reversed(range(32)))).decode()
CLIENT = hashlib.sha256(('amnezia-awg2\t' + PEER).encode()).hexdigest()
NONCE = 'n' * 43
FP = 'a' * 64


class Handler:
    def __init__(self, path, body, ip='10.8.1.2', headers=None):
        raw = json.dumps(body).encode()
        self.path = '/migration/v1/' + path
        self.headers = {'Content-Length': str(len(raw)), **(headers or {})}
        self.rfile, self.wfile = io.BytesIO(raw), io.BytesIO()
        self.client_address = (ip, 1234)
        self.status = None
        self.response_headers = {}

    def send_response(self, status): self.status = status
    def send_error(self, status): self.status = status
    def send_header(self, key, value): self.response_headers[key] = value
    def end_headers(self): pass
    def response(self): return json.loads(self.wfile.getvalue())


def signed(payload, directory):
    return {'payload': base64.b64encode(service.canonical(payload)).decode(),
            'signature': base64.b64encode(b's' * 64).decode()}


class MigrationServiceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.directory = Path(self.tmp.name)
        self.now = int(time.time())
        self.state = {'serverPublicKey': SERVER, 'containerId': 'amnezia-awg2',
                      'generation': 1, 'expiresAt': self.now + 3600,
                      'signingPublicKey': SERVER, 'endpoint': 'vpn.example:51822',
                      'parameters': {'HeaderProtectionKey': PEER, 'S1': '16', 'S2': '16', 'S3': '16', 'S4': '16'},
                      'challengeAddress': '172.29.172.251', 'challengePort': 18082,
                      'peers': {PEER: {'sourceIp': '10.8.1.2', 'targetIp': '10.8.1.2',
                                       'clientAddress': '10.8.1.2/32', 'clientId': CLIENT}}}
        (self.directory / 'ready.json').write_text(json.dumps(self.state))
        (self.directory / 'handshakes.tsv').write_text(PEER + '\t' + str(self.now))
        self.source = service.MigrationService(str(self.directory), 'source', 'amnezia-awg2')
        self.target = service.MigrationService(str(self.directory), 'target', 'amnezia-awg2')
        self.patch = patch('service.sign', side_effect=signed)
        self.patch.start()

    def tearDown(self):
        self.patch.stop()
        self.tmp.cleanup()

    def request(self, path, body, role=None, ip='10.8.1.2', headers=None, client=CLIENT):
        handler = Handler(path, body, ip, headers)
        (role or self.source).dispatch(handler, lambda: client)
        return handler

    def enroll(self):
        return self.request('bootstrap', {'schema': 1, 'peerPublicKey': PEER,
                                         'sourceFingerprint': FP, 'nonce': NONCE}).response()['grant']

    def offer(self, grant):
        return self.request('offer', {'schema': 1, 'peerPublicKey': PEER,
                                     'sourceFingerprint': FP, 'nonce': NONCE},
                            headers={'X-Amnezia-Migration-Grant': grant})

    def test_complete_candidate_proof_and_ack(self):
        grant = self.enroll()
        offer = self.offer(grant)
        self.assertEqual(200, offer.status)
        self.assertEqual('no-store', offer.response_headers['Cache-Control'])
        payload = json.loads(base64.b64decode(offer.response()['payload']))
        challenge = {'schema': 1, 'peerPublicKey': PEER, 'generation': 1,
                     'grant': grant, 'nonce': payload['challenge']['nonce']}
        receipt = self.request('challenge', challenge, role=self.target)
        self.assertEqual(200, receipt.status)
        ack = {'schema': 1, 'peerPublicKey': PEER, 'generation': 1, 'grant': grant,
               'challengeReceipt': receipt.response()}
        self.assertEqual(403, self.request('ack', ack).status)
        self.assertEqual(200, self.request('ack', ack, role=self.target).status)
        self.assertEqual(403, self.request('ack', ack, role=self.target, ip='10.8.1.3').status)

    def test_source_cannot_mint_candidate_receipt(self):
        grant = self.enroll()
        payload = json.loads(base64.b64decode(self.offer(grant).response()['payload']))
        body = {'schema': 1, 'peerPublicKey': PEER, 'generation': 1, 'grant': grant,
                'nonce': payload['challenge']['nonce']}
        self.assertEqual(403, self.request('challenge', body).status)

    def test_bootstrap_requires_peer_ip_and_scoped_client(self):
        body = {'schema': 1, 'peerPublicKey': PEER, 'sourceFingerprint': FP, 'nonce': NONCE}
        self.assertEqual(403, self.request('bootstrap', body, ip='172.17.0.1').status)
        self.assertEqual(403, self.request('bootstrap', body, client='b' * 64).status)
        self.assertEqual(403, self.request('bootstrap', body, role=self.target).status)

    def test_bound_fingerprint_and_generation_reject_replay(self):
        grant = self.enroll()
        body = {'schema': 1, 'peerPublicKey': PEER, 'sourceFingerprint': 'b' * 64, 'nonce': NONCE}
        self.assertEqual(403, self.request('offer', body, headers={'X-Amnezia-Migration-Grant': grant}).status)
        self.state['generation'] = 2
        (self.directory / 'ready.json').write_text(json.dumps(self.state))
        self.assertEqual(403, self.offer(grant).status)

    def test_expired_and_missing_grants(self):
        grant = self.enroll()
        self.assertEqual(403, self.offer('z' * 64).status)
        self.state['expiresAt'] = self.now - 1
        (self.directory / 'ready.json').write_text(json.dumps(self.state))
        self.assertEqual(403, self.offer(grant).status)

    def test_stale_candidate_handshake_rejected(self):
        grant = self.enroll()
        payload = json.loads(base64.b64decode(self.offer(grant).response()['payload']))
        (self.directory / 'handshakes.tsv').write_text(PEER + '\t' + str(self.now - 121))
        body = {'schema': 1, 'peerPublicKey': PEER, 'generation': 1, 'grant': grant,
                'nonce': payload['challenge']['nonce']}
        self.assertEqual(403, self.request('challenge', body, role=self.target).status)

    def test_duplicate_json_and_boolean_schema_rejected(self):
        body = {'schema': True, 'peerPublicKey': PEER, 'sourceFingerprint': FP, 'nonce': NONCE}
        self.assertEqual(403, self.request('bootstrap', body).status)
        with self.assertRaises(ValueError):
            service.unique_object([('schema', 1), ('schema', 2)])


if __name__ == '__main__':
    unittest.main()
