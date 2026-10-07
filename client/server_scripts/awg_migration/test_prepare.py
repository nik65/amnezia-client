"""Pure configuration preservation tests; never invokes preparation/Docker."""
import base64
import importlib
import sys
import types
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
