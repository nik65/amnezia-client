"""Pure configuration preservation tests; never invokes preparation/Docker."""
import base64
import importlib
import sys
import types
import subprocess
import unittest
from unittest.mock import patch

try:
    import fcntl
except ImportError:
    # Windows unit tests import only the pure parser; no fake operational receipt.
    with patch.dict(sys.modules, {'fcntl': types.ModuleType('fcntl')}):
        prepare = importlib.import_module('prepare')
else:
    import prepare

PRIVATE = base64.b64encode(b'a' * 32).decode()
PUBLIC = base64.b64encode(b'b' * 32).decode()
PSK = base64.b64encode(b'c' * 32).decode()


def config(peer=PUBLIC, address='10.8.1.2/32'):
    return ('[Interface]\nPrivateKey = ' + PRIVATE + '\nAddress = 10.8.1.1/24\nListenPort = 51820\n'
            'PostUp = iptables old-operator-hook\n[Peer]\nPublicKey = ' + peer +
            '\nPresharedKey = ' + PSK + '\nAllowedIPs = ' + address + '\n').encode()


class ConfigTests(unittest.TestCase):
    def test_native_uapi_config_preserves_identity_and_fresh_parameters(self):
        interface, peers = prepare.parse_config(config())
        interface.pop('PostUp')
        interface.update(MTU='1420', HeaderProtectionKey=PSK, S1='16', S2='17', S3='18', S4='19',
                         RandomTrailers='false', DisableCookies='true')
        text = prepare.native_config(interface, peers)
        self.assertNotIn('Address =', text)
        self.assertNotIn('MTU =', text)
        for field, value in [('PrivateKey', PRIVATE), ('PublicKey', PUBLIC), ('PresharedKey', PSK),
                             ('HeaderProtectionKey', PSK), ('S1', '16'), ('S2', '17'), ('S3', '18'), ('S4', '19')]:
            self.assertIn(field + ' = ' + value + '\n', text)
        self.assertIn('AllowedIPs = 10.8.1.2/32\n', text)
        self.assertIn('RandomTrailers = 0\n', text)
        self.assertIn('DisableCookies = 1\n', text)
        self.assertEqual('false', interface['RandomTrailers'])

    def test_only_dependency_fetch_and_owned_lock_contention_are_retryable(self):
        for command in (['docker', 'pull', 'pinned'], ['docker', 'build', 'private-context']):
            error = subprocess.CalledProcessError(1, command, output=b'private', stderr=b'secret')
            self.assertEqual('migration_dependency_unavailable', prepare.transient_failure_reason(error))
            self.assertEqual('migration_dependency_unavailable', prepare.transient_failure_reason(subprocess.TimeoutExpired(command, 180)))
        for command in (['docker', 'run', 'pinned'], ['docker', 'exec', 'source'], ['openssl', 'pkey'], 'docker build'):
            self.assertIsNone(prepare.transient_failure_reason(subprocess.CalledProcessError(1, command)))
        self.assertIsNone(prepare.transient_failure_reason(ValueError('trusted_image_unavailable')))
        self.assertEqual('migration_busy', prepare.transient_failure_reason(BlockingIOError()))

    def test_identity_and_psk_preserved(self):
        interface, peers = prepare.parse_config(config())
        self.assertEqual(PRIVATE, interface['PrivateKey'])
        self.assertEqual(PUBLIC, peers[0]['PublicKey'])
        self.assertEqual(PSK, peers[0]['PresharedKey'])
        self.assertEqual('10.8.1.2/32', peers[0]['AllowedIPs'])

    def test_ambiguous_or_foreign_routes_fail_closed(self):
        for address in ('10.8.1.0/24', '10.9.1.2/32', '10.8.1.1/32', '10.8.1.2/32, 10.8.1.3/32'):
            with self.subTest(address=address), self.assertRaises(ValueError):
                prepare.parse_config(config(address=address))

    def test_duplicate_peer_and_unknown_peer_fields_rejected(self):
        for suffix in (b'[Peer]\nPublicKey = ' + PUBLIC.encode() + b'\nAllowedIPs = 10.8.1.3/32\n',
                       b'Endpoint = evil.example:1\n'):
            with self.assertRaises(ValueError):
                prepare.parse_config(config() + suffix)


if __name__ == '__main__':
    unittest.main()
