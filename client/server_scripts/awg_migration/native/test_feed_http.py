"""Black-box native HTTP tests on loopback and temporary local files only."""
import concurrent.futures
import hashlib
import http.client
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import sys
import tempfile
import threading
import unittest

BINARY = sys.argv.pop(1)


class FeedHttpTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='awg-native-http-')
        self.root = Path(self.temporary.name, 'public')
        (self.root / 'files' / 'nested').mkdir(parents=True)
        (self.root / 'manifest.json').write_bytes(b'{"version":"fixture"}')
        (self.root / 'rules.json').write_bytes(b'{"rules":[]}')
        self.package = bytes(range(256)) * 8200 + b'exact-end'
        (self.root / 'files' / 'nested' / 'client.apk').write_bytes(self.package)
        (self.root / 'files' / 'nested' / 'client.run').write_bytes(b'linux-installer-fixture')
        secret = Path(self.temporary.name, 'private.apk')
        secret.write_bytes(b'PRIVATE-MUST-NOT-APPEAR')
        (self.root / 'files' / 'leak.apk').symlink_to(secret)
        (self.root / 'files' / 'alias').symlink_to(secret.parent, target_is_directory=True)
        os.link(secret, self.root / 'files' / 'hard.apk')
        os.mkfifo(self.root / 'files' / 'pipe.apk')
        self.process = None
        self.start('updates')

    def start(self, mode):
        self.process = subprocess.Popen([BINARY, '--single', mode, str(self.root), '127.0.0.1', '0'],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        ready, _, _ = select.select([self.process.stdout], [], [], 5)
        self.assertTrue(ready, 'listener failed to start')
        self.port = json.loads(self.process.stdout.readline())['listening']

    def stop(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.communicate()
                self.fail('native worker shutdown did not finish')

    def tearDown(self):
        self.stop()
        self.temporary.cleanup()

    def request(self, path, method='GET'):
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=3)
        connection.request(method, path)
        response = connection.getresponse()
        data = response.read()
        result = response.status, dict(response.getheaders()), data
        connection.close()
        return result

    def raw(self, request):
        with socket.create_connection(('127.0.0.1', self.port), timeout=3) as client:
            client.sendall(request)
            client.shutdown(socket.SHUT_WR)
            result = bytearray()
            while True:
                try:
                    chunk = client.recv(16384)
                except ConnectionResetError:
                    # Closing a rejected request with unread body/pipeline bytes
                    # may reset TCP after the bounded error response was sent.
                    if result:
                        return bytes(result)
                    raise
                if not chunk:
                    return bytes(result)
                result += chunk

    def test_get_head_stream_exact_bytes_and_headers(self):
        status, headers, body = self.request('/manifest.json')
        self.assertEqual(200, status)
        self.assertEqual(b'{"version":"fixture"}', body)
        self.assertEqual('application/json', headers['Content-Type'])
        self.assertEqual('no-store', headers['Cache-Control'])
        status, headers, body = self.request('/files/nested/client.apk')
        self.assertEqual(200, status)
        self.assertEqual(len(self.package), int(headers['Content-Length']))
        self.assertEqual(hashlib.sha256(self.package).digest(), hashlib.sha256(body).digest())
        status, headers, body = self.request('/files/nested/client.apk', 'HEAD')
        self.assertEqual(200, status)
        self.assertEqual(str(len(self.package)), headers['Content-Length'])
        self.assertEqual(b'', body)
        for path in ['/manifest.json?cache=1', '/%6danifest.j%73on?cache=1']:
            status, headers, body = self.request(path)
            self.assertEqual(200, status)
            self.assertEqual('application/json', headers['Content-Type'])
            self.assertEqual(b'{"version":"fixture"}', body)
        self.assertEqual((200, b'linux-installer-fixture'),
                         (lambda r: (r[0], r[2]))(self.request('/files/nested/client.run')))

    def test_file_boundaries_not_disclosed(self):
        for path in ['/files/', '/signing.pem', '/files/leak.apk', '/files/alias/private.apk',
                     '/files/hard.apk', '/files/pipe.apk', '/files/%2e%2e/private.apk',
                     '/files/%252e%252e/private.apk', '/files/%00.apk', '/files/%ff.apk',
                     '/files/missing.apk', '/files/nested/client.run.bak']:
            with self.subTest(path=path):
                status, _, body = self.request(path)
                self.assertEqual(403, status)
                self.assertNotIn(b'PRIVATE', body)
        status, headers, body = self.request('/signing.pem', 'HEAD')
        self.assertEqual(403, status)
        self.assertNotEqual('0', headers['Content-Length'])
        self.assertEqual(b'', body)

    def test_malformed_requests_and_no_pipeline(self):
        cases = [b'GET /manifest.json HTTP/2.0\r\n\r\n',
                 b'GET /manifest.json HTTP/1.1\r\n Bad: value\r\n\r\n',
                 b'GET /manifest.json HTTP/1.1\r\nContent-Length: 1\r\n\r\nx',
                 b'GET /manifest.json HTTP/1.1\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n',
                 b'GET /manifest.json HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n',
                 b'GET /manifest.json HTTP/1.1\r\nHeader: value\x00\r\n\r\n']
        for case in cases:
            self.assertTrue(self.raw(case).startswith(b'HTTP/1.0 400 '))
        self.assertTrue(self.raw(b'POST /manifest.json HTTP/1.1\r\n\r\n').startswith(b'HTTP/1.0 501 '))
        oversized = b'GET /manifest.json HTTP/1.1\r\nX: ' + b'a' * 17000 + b'\r\n\r\n'
        # An overlong request may close before unread excess bytes are drained.
        with socket.create_connection(('127.0.0.1', self.port), timeout=3) as client:
            client.sendall(oversized)
            self.assertTrue(client.recv(512).startswith(b'HTTP/1.0 431 '))
        result = self.raw(b'GET /manifest.json HTTP/1.1\r\n\r\nGET /rules.json HTTP/1.1\r\n\r\n')
        self.assertEqual(1, result.count(b'HTTP/1.0 '))

    def test_parallel_disconnect_and_bounded_shutdown(self):
        def one(_):
            return self.request('/files/nested/client.apk')[0]
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            self.assertEqual([200] * 24, list(pool.map(one, range(24))))
        with socket.create_connection(('127.0.0.1', self.port), timeout=3) as client:
            client.sendall(b'GET /files/nested/client.apk HTTP/1.1\r\n\r\n')
        self.assertEqual(200, self.request('/manifest.json')[0])
        clients = [socket.create_connection(('127.0.0.1', self.port), timeout=3) for _ in range(24)]
        try:
            for client in clients:
                client.sendall(b'GET /manifest.json HTTP/1.1\r\nX: ')
            self.assertLessEqual(int(next(x.split(':')[1] for x in
                                         Path(f'/proc/{self.process.pid}/status').read_text().splitlines()
                                         if x.startswith('Threads:'))), 17)
            self.stop()
        finally:
            for client in clients:
                client.close()

    def test_explicit_serve_replaces_base_image_cmd(self):
        # No application/Docker execution: reserve/check this test-only listener
        # first and own every process that is subsequently terminated.
        with socket.socket() as reservation:
            try:
                reservation.bind(('0.0.0.0', 17865))
            except OSError:
                self.skipTest('fixed feed port already in use; never disturb its owner')
        environment = dict(os.environ, AMNEZIA_FEED_PORTS='17865')
        process = subprocess.Popen([BINARY, '--serve'], env=environment,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            ready, _, _ = select.select([process.stdout], [], [], 5)
            self.assertTrue(ready)
            line = process.stdout.readline()
            self.assertTrue(line, process.stderr.read() if process.poll() is not None else b'no startup receipt')
            self.assertEqual({'listening': 17865}, json.loads(line))
        finally:
            if process.poll() is None:
                process.terminate()
            process.communicate(timeout=3)

    def test_native_readiness_hash_and_fixed_path(self):
        expected = hashlib.sha256((self.root / 'manifest.json').read_bytes()).hexdigest()
        result = subprocess.run([BINARY, '--check-feed', 'updates', str(self.port), expected], capture_output=True, timeout=7)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(b'', result.stdout)
        for kind, digest in [('updates', '0' * 64), ('routing', expected), ('arbitrary', expected)]:
            result = subprocess.run([BINARY, '--check-feed', kind, str(self.port), digest], capture_output=True, timeout=7)
            self.assertNotEqual(0, result.returncode)

    def test_native_readiness_rejects_unframed_or_oversize_responses(self):
        body = b'{"fixture":true}'
        digest = hashlib.sha256(body).hexdigest()
        responses = [
            b'HTTP/1.0 200 OK\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body,
            b'HTTP/1.0 200 OK\r\n\r\n' + body,
            b'HTTP/1.0 200 OK\r\nContent-Length: 1048577\r\n\r\n',
            b'HTTP/1.0 200 OK\r\nContent-Length: 15\r\nContent-Length: 15\r\n\r\n' + body,
            b'HTTP/1.0 200 OK\r\nContent-Length: 15\r\nTransfer-Encoding: chunked\r\n\r\n' + body,
            b'HTTP/1.0 403 Forbidden\r\nContent-Length: 15\r\n\r\n' + body,
            b'HTTP/1.0 200 OK\r\nContent-Length: 999\r\n\r\n' + body,
            b'HTTP/1.0 200 OK\r\nContent-Length: -1\r\n\r\n',
            b'HTTP/1.0 200 OK\r\nX: ' + b'x' * 9000 + b'\r\nContent-Length: 0\r\n\r\n',
        ]
        for index, response in enumerate(responses):
            with self.subTest(index=index), socket.socket() as listener:
                listener.bind(('127.0.0.1', 0))
                listener.listen(1)
                listener.settimeout(7)
                port = listener.getsockname()[1]
                def serve():
                    try:
                        connection, _ = listener.accept()
                        with connection:
                            connection.recv(8192)
                            connection.sendall(response)
                    except OSError:
                        pass
                thread = threading.Thread(target=serve)
                thread.start()
                result = subprocess.run([BINARY, '--check-feed', 'updates', str(port), digest], capture_output=True, timeout=7)
                thread.join(timeout=8)
                self.assertFalse(thread.is_alive())
                self.assertEqual(index == 0, result.returncode == 0, result.stderr)

    def test_routing_only_and_no_default_ports_when_unrequested(self):
        self.stop()
        self.start('routing')
        self.assertEqual(200, self.request('/rules.json')[0])
        self.assertEqual(403, self.request('/manifest.json')[0])
        self.assertEqual(403, self.request('/files/nested/client.apk')[0])
        environment = dict(os.environ, AMNEZIA_FEED_PORTS='')
        result = subprocess.run([BINARY], env=environment, capture_output=True, timeout=3)
        self.assertEqual(2, result.returncode)
        self.assertNotIn(b'listening', result.stdout)


if __name__ == '__main__':
    unittest.main()
