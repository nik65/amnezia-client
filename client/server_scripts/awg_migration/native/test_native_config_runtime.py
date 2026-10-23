"""Private, owned-process config transport checks; no server/Docker/network access."""
import json
from pathlib import Path
import subprocess
import sys
import time
import unittest

BINARY = sys.argv.pop(1)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from ready_validation import parse_config

BASE = ('[Interface]\nPrivateKey=' + 'A' * 43 + '=\nAddress=10.0.0.1/24\nListenPort=51820\n'
        '[Peer]\nPublicKey=' + 'B' * 43 + '=\nAllowedIPs=10.0.0.2/32\n')


class ConfigRuntime(unittest.TestCase):
    def invoke(self, raw):
        result = subprocess.run([BINARY, '--config-json'], input=raw,
                                capture_output=True, timeout=10)
        self.assertEqual(result.stderr, b'')
        self.assertLessEqual(len(result.stdout), 8 * 1024 ** 2 + 1)
        return result.returncode, json.loads(result.stdout)

    def compatible(self, raw):
        interface, peers = parse_config(raw)
        code, value = self.invoke(raw)
        self.assertEqual(code, 0)
        self.assertEqual(value, {'result': {'interface': interface, 'peers': peers}})

    def test_basic_and_peer_order(self):
        self.compatible(BASE.encode())
        self.compatible((BASE + '[Peer]\nPublicKey=' + 'C' * 43
                         + '=\nAllowedIPs=10.0.0.3/32\n').encode())

    def test_unicode_nul_and_escaped_values(self):
        for text in ('quoted"\\path', 'данные😀', 'left\0right', '\x01middle\x02'):
            with self.subTest(value_kind=text[:1]):
                self.compatible(BASE.replace('[Peer]', 'PostUp=' + text + '\n[Peer]').encode())

    def test_output_expansion_and_input_boundary(self):
        raw = BASE.replace('[Peer]', 'PostUp=\x01\n[Peer]').encode()
        raw = raw.replace(b'\x01', b'\x01' * (1024 ** 2 - len(raw) + 1))
        self.assertEqual(len(raw), 1024 ** 2)
        self.compatible(raw)
        code, value = self.invoke(raw + b'X')
        self.assertEqual((code, value), (2, {'error': 'native_config_rejected'}))

    def test_malformed_config_errors_are_sanitized(self):
        cases = [
            (b'\xffprivate-fixture', 'invalid UTF-8'),
            (b'private-fixture', 'configuration syntax'),
            (BASE.replace('ListenPort=51820', 'ListenPort=51820\nListenPort=private-fixture').encode(),
             'duplicate configuration key'),
            (BASE.replace('AllowedIPs=10.0.0.2/32', 'AllowedIPs=private-fixture').encode(),
             'configuration address'),
            (BASE.replace('PublicKey=' + 'B' * 43 + '=', 'PublicKey=private-fixture').encode(),
             'peer identity'),
        ]
        for raw, error in cases:
            with self.subTest(error=error):
                self.assertEqual(self.invoke(raw), (2, {'error': error}))

    def test_input_deadline_without_eof(self):
        begin = time.monotonic()
        process = subprocess.Popen([BINARY, '--config-json'], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            process.stdin.write(b'[Interface]')
            process.stdin.flush()
            self.assertEqual(process.wait(timeout=10), 2)
            elapsed = time.monotonic() - begin
            self.assertGreaterEqual(elapsed, 4.5)
            self.assertLess(elapsed, 10)
            self.assertEqual(json.loads(process.stdout.read()), {'error': 'native_config_rejected'})
            self.assertEqual(process.stderr.read(), b'')
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            process.stdin.close()
            process.stdout.close()
            process.stderr.close()


if __name__ == '__main__':
    unittest.main()
