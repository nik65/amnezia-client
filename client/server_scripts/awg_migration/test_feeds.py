"""Actual loopback HTTP negative tests; no VPN/container/server deployment."""
import os
from pathlib import Path
import tempfile
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import urlopen
from feeds import FeedServer, feed_mounts


class MountPlanTests(unittest.TestCase):
    def test_only_script_not_migration_private_directory_is_mounted(self):
        plan = feed_mounts('/opt/amnezia/awg-migration/amnezia-awg2/1')
        expected_script = str(Path('/opt/amnezia/awg-migration/amnezia-awg2/1') / 'feeds.py') + ':/app/feeds.py:ro'
        self.assertIn(expected_script, plan)
        self.assertFalse(any(':/migration' in part for part in plan))
        self.assertFalse(any('signing.pem' in part or 'awg0.conf' in part for part in plan))


@unittest.skipUnless(os.name == 'posix', 'production no-follow/dirfd HTTP fixture requires POSIX')
class FeedTransportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name, 'public')
        self.root.mkdir()
        (self.root / 'files').mkdir()
        (self.root / 'manifest.json').write_bytes(b'public manifest')
        (self.root / 'files' / 'client.apk').write_bytes(b'public signed package')
        self.secret = Path(self.tmp.name, 'signing.pem')
        self.secret.write_bytes(b'PRIVATE MUST NEVER APPEAR')
        Path(self.tmp.name, 'private.apk').write_bytes(b'PRIVATE MUST NEVER APPEAR')
        self.server = FeedServer(('127.0.0.1', 0), str(self.root), False)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = 'http://127.0.0.1:' + str(self.server.server_port)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.tmp.cleanup()

    def denied(self, path):
        with self.assertRaises(HTTPError) as raised: urlopen(self.url + path, timeout=2)
        self.assertEqual(403, raised.exception.code)
        self.assertNotIn(b'PRIVATE MUST NEVER APPEAR', raised.exception.read())

    def test_regular_manifest_package_served_without_directory_listing(self):
        with urlopen(self.url + '/manifest.json', timeout=2) as response:
            self.assertEqual(b'public manifest', response.read())
        with urlopen(self.url + '/files/client.apk', timeout=2) as response:
            self.assertEqual(b'public signed package', response.read())
        self.denied('/files/')

    def test_final_and_ancestor_symlinks_hardlinks_and_encoded_traversal_rejected(self):
        (self.root / 'files' / 'leak.apk').symlink_to(self.secret)
        (self.root / 'files' / 'alias').symlink_to(self.secret.parent, target_is_directory=True)
        os.link(self.secret, self.root / 'files' / 'hard.apk')
        for path in ('/files/leak.apk', '/files/alias/private.apk', '/files/hard.apk',
                     '/files/%2e%2e/signing.pem', '/files/%252e%252e/leak.apk', '/signing.pem'):
            self.denied(path)


if __name__ == '__main__': unittest.main()
