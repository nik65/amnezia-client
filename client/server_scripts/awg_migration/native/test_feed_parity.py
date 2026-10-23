"""Local differential contract fixtures; no HTTP listener or production access."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def main():
    specification = importlib.util.spec_from_file_location(
        'migration_feed_reference', Path(__file__).resolve().parents[1] / 'feeds.py')
    reference = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(reference)
    with tempfile.TemporaryDirectory(prefix='awg-feed-parity-') as temporary:
        root = Path(temporary, 'public')
        (root / 'files' / 'nested').mkdir(parents=True)
        (root / 'manifest.json').write_bytes(b'manifest')
        (root / 'rules.json').write_bytes(b'rules')
        for suffix in reference.PACKAGE_SUFFIXES:
            (root / 'files' / 'nested' / ('client' + suffix)).write_bytes(b'package')
        (root / 'files' / 'nested' / 'AmneziaVPN_test_android9+_arm64-v8a.apk').write_bytes(b'android fixture')
        secret = Path(temporary, 'private.apk')
        secret.write_bytes(b'private')
        (root / 'files' / 'leak.apk').symlink_to(secret)
        (root / 'files' / 'alias').symlink_to(secret.parent, target_is_directory=True)
        os.link(secret, root / 'files' / 'hard.apk')
        targets = ['/manifest.json', '/rules.json', '/manifest.json?q=1', '/rules.json#fragment',
                   '/%6danifest.json', '/', '/files/', '/signing.pem', '/files/leak.apk',
                   '/files/alias/private.apk', '/files/hard.apk', '/files/../private.apk',
                   '/files/%2e%2e/private.apk', '/files/%252e%252e/private.apk',
                   '/files/a%00.apk', '/files/%ff.apk', '/files/a%.apk', '/files/a%2.apk',
                   '/files/a\\b.apk', '/files//client.apk', '/files/nested/client.APK',
                   '/files/nested/missing.apk', '/files/nested/client.run.bak']
        targets += ['/files/nested/client' + suffix for suffix in reference.PACKAGE_SUFFIXES]
        targets += ['/files/nested/AmneziaVPN_test_android9+_arm64-v8a.apk',
                    '/files/nested/AmneziaVPN_test_android9%2B_arm64-v8a.apk',
                    '/files/nested/AmneziaVPN_test_android9%2b_arm64-v8a.apk?cache=1',
                    '/files/nested/AmneziaVPN_test_android9%252B_arm64-v8a.apk',
                    '/files/nested/AmneziaVPN_test_android9%2B_arm64-v8a.apk.bak']
        cases = 0
        for routing in (False, True):
            for target in targets:
                expected = {'accepted': False}
                try:
                    stream, size = reference.open_feed(str(root), target, routing)
                    stream.close()
                    expected = {'accepted': True, 'bytes': size}
                except (OSError, ValueError, UnicodeError):
                    pass
                process = subprocess.run([sys.argv[1], 'routing' if routing else 'updates',
                                          str(root), target], capture_output=True, timeout=2)
                actual = json.loads(process.stdout)
                if actual['accepted'] != expected['accepted'] or (
                        actual['accepted'] and actual['bytes'] != expected['bytes']):
                    raise AssertionError((routing, target, expected, actual))
                if process.returncode != (0 if expected['accepted'] else 1):
                    raise AssertionError('native exit code differs')
                cases += 1
        print(f'{cases} feed reference/native differential cases passed')


if __name__ == '__main__':
    main()
