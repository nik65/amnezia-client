"""Native control business logic through private memfd; owned files/keys, no sockets."""
import base64
from contextlib import closing
import copy
import fcntl
import hashlib
from http.client import HTTPMessage
import io
import json
import os
from pathlib import Path
import sqlite3
import struct
import subprocess
import tempfile
import time
import unittest
from unittest import mock

import service
from test_service import Handler

FIXTURE = os.environ.get('AWG_CONTROL_TEST_BIN')
PEER = base64.b64encode(bytes(range(32))).decode()
CLIENT, FP, NONCE = 'c' * 64, 'a' * 64, 'n' * 43


class Protocol(unittest.TestCase):
    def test_auth_deferred_only_at_callback_and_at_most_two_passes(self):
        bridge = service.NativeControl()
        needed = {'handled': True, 'status': 403, 'body': '', 'authenticate': True}
        done = {'handled': True, 'status': 200, 'body': '{"ok":true}', 'authenticate': False}
        seen = []

        def invoke(request):
            seen.append(copy.deepcopy(request))
            return needed if len(seen) == 1 else done

        auth = mock.Mock(return_value=CLIENT)
        with mock.patch.object(bridge, '_invoke', side_effect=invoke):
            self.assertEqual(bridge.dispatch('source', 'amnezia-awg2', '/migration/v1/bootstrap',
                '10.8.1.2', {'content-length': '2'}, b'{}', auth), done)
        auth.assert_called_once_with()
        self.assertIsNone(seen[0]['authenticatedClient'])
        self.assertEqual(seen[1], dict(seen[0], authenticatedClient=CLIENT))
        with mock.patch.object(bridge, '_invoke', return_value=needed) as invoke:
            with self.assertRaisesRegex(ValueError, '^native_control_rejected$'):
                bridge.dispatch('source', 'amnezia-awg2', '/migration/v1/bootstrap',
                                '10.8.1.2', {}, b'{}', lambda: CLIENT)
            self.assertEqual(invoke.call_count, 2)

    def test_none_auth_preserves_already_sent_response(self):
        bridge = service.NativeControl()
        needed = {'handled': True, 'status': 403, 'body': '', 'authenticate': True}
        with mock.patch.object(bridge, '_invoke', return_value=needed) as invoke:
            self.assertIsNone(bridge.dispatch('source', 'amnezia-awg2', '/migration/v1/bootstrap',
                                             '10.8.1.2', {}, b'{}', lambda: None))
            self.assertEqual(invoke.call_count, 1)
        for client in ('', True, 'not-client', 'C' * 64):
            with mock.patch.object(bridge, '_invoke', return_value=needed):
                with self.assertRaisesRegex(ValueError, '^native_control_rejected$'):
                    bridge.dispatch('source', 'amnezia-awg2', '/migration/v1/bootstrap',
                                    '10.8.1.2', {}, b'{}', lambda: client)

    def test_native_failure_cannot_call_legacy_handle(self):
        native = mock.Mock(dispatch=mock.Mock(side_effect=ValueError('native_control_rejected')))
        control = service.MigrationService('/owned', 'source', 'amnezia-awg2', native=native)
        handler = Handler('bootstrap', {})
        with mock.patch.object(control, 'handle', side_effect=AssertionError('Python fallback')):
            self.assertTrue(control.dispatch(handler, lambda: CLIENT))
        self.assertEqual(handler.status, 403)

    def test_duplicate_framing_rejected_before_helper(self):
        native = mock.Mock(dispatch=mock.Mock(side_effect=AssertionError('helper reached')))
        control = service.MigrationService('/owned', 'source', 'amnezia-awg2', native=native)
        handler = Handler('bootstrap', {})
        headers = HTTPMessage()
        headers.add_header('Content-Length', '2')
        headers.add_header('content-length', '2')
        handler.headers = headers
        self.assertTrue(control.dispatch(handler, lambda: CLIENT))
        self.assertEqual(handler.status, 403)

    def test_capture_private_static_elf_and_missing_capability_fail_closed(self):
        # Synthetic static ELF exercises capture validation/sealing, never executes.
        raw = bytearray(4096)
        raw[:9] = b'\x7fELF\x02\x01\x01\x00\x00'
        struct.pack_into('<HHIQQ', raw, 16, 2, 62, 1, 0x400100, 64)
        struct.pack_into('<HHH', raw, 52, 64, 56, 1)
        struct.pack_into('<IIQQQQQQ', raw, 64, 1, 5, 0, 0x400000, 0, 4096, 4096, 4096)
        expected = hashlib.sha256(raw).hexdigest()
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / 'owned-helper'
            path.write_bytes(raw)
            path.chmod(0o755)
            with mock.patch.object(service.NativeControl, 'capability'):
                bridge = service.NativeControl.capture(path, expected, name)
            try:
                self.assertEqual(bridge.sha256, expected)
                self.assertEqual(os.pread(bridge.fd, len(raw), 0), raw)
                self.assertEqual(bridge.receipt()['protocol'], 'control-json-v1')
                with self.assertRaises(OSError):
                    os.pwrite(bridge.fd, b'x', 0)
            finally:
                bridge.close()
            with self.assertRaisesRegex(ValueError, '^native_control_rejected$'):
                service.NativeControl.capture(path, '0' * 64, name)
            path.chmod(0o777)
            with self.assertRaisesRegex(ValueError, '^native_control_rejected$'):
                service.NativeControl.capture(path, expected, name)
            path.chmod(0o755)
            with mock.patch.object(service.NativeControl, 'capability', side_effect=ValueError('native_control_rejected')):
                before = len(os.listdir('/proc/self/fd'))
                with self.assertRaisesRegex(ValueError, '^native_control_rejected$'):
                    service.NativeControl.capture(path, expected, name)
                self.assertEqual(len(os.listdir('/proc/self/fd')), before)


@unittest.skipUnless(FIXTURE, 'owned standalone control fixture required')
class CapturedControl(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.directory = Path(self.tmp.name)
        self.directory.chmod(0o700)
        self.now = int(time.time())
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'ED25519', '-out',
                        str(self.directory / 'signing.pem')], check=True, capture_output=True)
        (self.directory / 'signing.pem').chmod(0o600)
        public = subprocess.check_output(['openssl', 'pkey', '-in', str(self.directory / 'signing.pem'),
                                          '-pubout', '-outform', 'DER'])[-32:]
        self.state = {'serverPublicKey': PEER, 'containerId': 'amnezia-awg2', 'generation': 1,
            'expiresAt': self.now + 3600, 'signingPublicKey': base64.b64encode(public).decode(),
            'endpoint': 'vpn.example:51822', 'parameters': {'S1': '16'},
            'challengeAddress': '172.29.172.251', 'challengePort': 18082,
            'peers': {PEER: {'sourceIp': '10.8.1.2', 'targetIp': '10.8.1.2',
                             'clientAddress': '10.8.1.2/32', 'clientId': CLIENT}}}
        (self.directory / 'ready.json').write_text(json.dumps(self.state))
        (self.directory / 'handshakes.tsv').write_text(PEER + '\t' + str(self.now) + '\n')
        # Test-only dynamic ELF fixture is manually sealed here; production capture
        # is separately tested above and permits reviewed static ELF only.
        self.bridge = service.NativeControl()
        self.bridge.fd = os.memfd_create('owned-control-fixture', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        raw = Path(FIXTURE).read_bytes()
        with os.fdopen(os.dup(self.bridge.fd), 'wb') as stream:
            stream.write(raw)
        os.fchmod(self.bridge.fd, 0o500)
        fcntl.fcntl(self.bridge.fd, fcntl.F_ADD_SEALS,
                    fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE)
        self.bridge.directory = str(self.directory)
        self.bridge.sha256 = hashlib.sha256(raw).hexdigest()
        self.source = service.MigrationService(str(self.directory), 'source', 'amnezia-awg2', native=self.bridge)
        self.target = service.MigrationService(str(self.directory), 'target', 'amnezia-awg2', native=self.bridge)
        self.auth_calls = 0

    def tearDown(self):
        self.bridge.close()
        self.tmp.cleanup()

    def authenticate(self):
        self.auth_calls += 1
        return CLIENT

    def request(self, path, body, role=None, auth=None, headers=None):
        handler = Handler(path, body, headers=headers)
        with mock.patch.object(service.MigrationService, 'handle', side_effect=AssertionError('Python fallback')), \
             mock.patch.object(service, 'canonical', side_effect=AssertionError('Python canonicalization')), \
             mock.patch.object(service, 'sign', side_effect=AssertionError('Python signing')), \
             mock.patch.object(service, 'bootstrap_grant', side_effect=AssertionError('Python grants')):
            self.assertTrue((role or self.source).dispatch(handler, auth or self.authenticate))
        return handler

    def bootstrap(self, nonce=NONCE):
        return self.request('bootstrap', {'schema': 1, 'peerPublicKey': PEER,
            'sourceFingerprint': FP, 'nonce': nonce})

    def test_actual_all_five_routes_share_single_database_and_real_signatures(self):
        first = self.bootstrap()
        self.assertEqual(first.status, 200)
        self.assertEqual(self.auth_calls, 1)
        grant = first.response()['grant']
        retry = self.bootstrap()
        self.assertEqual(retry.response(), first.response())
        with closing(sqlite3.connect(self.directory / 'grants.sqlite3')) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM grants').fetchone()[0], 1)
            challenge = db.execute('SELECT challenge FROM grants').fetchone()[0]
        offered = self.request('offer', {'schema': 1, 'peerPublicKey': PEER, 'sourceFingerprint': FP,
            'nonce': NONCE}, headers={'X-Amnezia-Migration-Grant': grant})
        self.assertEqual(offered.status, 200)
        payload = json.loads(base64.b64decode(offered.response()['payload']))
        self.assertEqual(service.sign(payload, str(self.directory)), offered.response())
        proved = self.request('challenge', {'schema': 1, 'peerPublicKey': PEER, 'generation': 1,
            'grant': grant, 'nonce': challenge}, role=self.target)
        self.assertEqual(proved.status, 200)
        ack = {'schema': 1, 'peerPublicKey': PEER, 'generation': 1,
               'grant': grant, 'challengeReceipt': proved.response()}
        self.assertEqual(self.request('ack', ack, role=self.target).status, 200)
        self.assertEqual(self.auth_calls, 2)  # Both bootstrap requests only.
        renew = self.request('renew', dict(ack, nonce='r' * 43), role=self.target)
        self.assertEqual(renew.status, 200)
        self.assertEqual(self.auth_calls, 3)
        renewal_payload = json.loads(base64.b64decode(renew.response()['payload']))
        self.assertEqual(service.sign(renewal_payload, str(self.directory)), renew.response())
        self.assertEqual(self.request('renew', dict(ack, nonce='r' * 43), role=self.target).status, 403)
        with closing(sqlite3.connect(self.directory / 'grants.sqlite3')) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM grants').fetchone()[0], 2)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM renewalNonces').fetchone()[0], 1)
        self.assertEqual(renew.response_headers['Cache-Control'], 'no-store')
        self.assertEqual(int(renew.response_headers['Content-Length']), len(renew.wfile.getvalue()))

    def test_rejected_request_never_authenticates_and_auth_none_does_not_resume(self):
        request = {'schema': 1, 'peerPublicKey': PEER, 'sourceFingerprint': FP, 'nonce': NONCE}
        handler = Handler('bootstrap', request, ip='10.8.1.99')
        self.source.dispatch(handler, mock.Mock(side_effect=AssertionError('auth called before mapping')))
        self.assertEqual(handler.status, 403)
        self.assertFalse((self.directory / 'grants.sqlite3').exists())
        handler = Handler('bootstrap', request)
        def sent():
            handler.send_error(401)
            return None
        self.source.dispatch(handler, sent)
        self.assertEqual(handler.status, 401)
        self.assertEqual(handler.wfile.getvalue(), b'')
        with closing(sqlite3.connect(self.directory / 'grants.sqlite3')) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM sqlite_master WHERE name='grants'").fetchone()[0], 0)

    def test_capability_has_no_state_or_database_effect(self):
        (self.directory / 'ready.json').unlink()
        self.bridge.capability()
        self.assertFalse((self.directory / 'grants.sqlite3').exists())


if __name__ == '__main__':
    unittest.main()
