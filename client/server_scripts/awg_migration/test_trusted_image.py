import json
import subprocess
import unittest
from trusted_image import IMAGE, IMAGE_ID, BINARY_SHA256, REPORTED_VERSION, resolve_image


class TrustedImageTests(unittest.TestCase):
    def runner(self, host=None, image=None, version=None, hashed=None, tools=b'ready'):
        self.calls = []
        def run(*args):
            self.calls.append(args)
            if args[1] == 'info':
                return json.dumps(host or {'OSType': 'linux', 'Architecture': 'x86_64'}).encode()
            if args[1:3] == ('image', 'inspect'):
                return json.dumps([image or {'Id': IMAGE_ID, 'Os': 'linux', 'Architecture': 'amd64', 'RepoDigests': [IMAGE]}]).encode()
            if '--version' in args:
                return (REPORTED_VERSION if version is None else version).encode()
            if 'sha256sum' in args:
                return (hashed or BINARY_SHA256 + '  /usr/bin/amneziawg-go').encode()
            if 'sh' in args:
                return tools
            return b''
        return run

    def test_catalog_identity_and_sandbox(self):
        self.assertEqual(resolve_image(self.runner()), IMAGE)
        for args in self.calls:
            if args[1] == 'run':
                for flag in ('--rm', '--read-only', '--cap-drop', '--security-opt', '--pids-limit'):
                    self.assertIn(flag, args)
                self.assertEqual(args[args.index('--network') + 1], 'none')
                self.assertNotIn('--device', args)
                self.assertNotIn('-v', args)

    def test_unsupported_host_never_pulls(self):
        for host in ({'OSType': 'windows', 'Architecture': 'amd64'},
                     {'OSType': 'linux', 'Architecture': 'aarch64'}):
            with self.assertRaisesRegex(ValueError, '^unsupported_server_architecture$'):
                resolve_image(self.runner(host=host))
            self.assertEqual(len(self.calls), 1)

    def test_wrong_content_or_version_fails_closed(self):
        cases = ({'image': {'Id': 'sha256:' + '0' * 64, 'Os': 'linux', 'Architecture': 'amd64'}},
                 {'hashed': '0' * 64 + '  /usr/bin/amneziawg-go'},
                 {'version': 'amneziawg-go 3.1.20260814'}, {'version': ''}, {'tools': b''})
        for case in cases:
            with self.assertRaisesRegex(ValueError, '^trusted_image_unavailable$'):
                resolve_image(self.runner(**case))

    def test_only_exact_registry_digest_cache_avoids_pull(self):
        image = {'Id': IMAGE_ID, 'Os': 'linux', 'Architecture': 'amd64', 'RepoDigests': [IMAGE]}
        resolve_image(self.runner(image=image))
        self.assertFalse(any(args[1] == 'pull' for args in self.calls))
        image['RepoDigests'] = []
        with self.assertRaisesRegex(ValueError, '^trusted_image_unavailable$'):
            resolve_image(self.runner(image=image))
        self.assertTrue(any(args[1] == 'pull' for args in self.calls))

    def test_containerd_manifest_identity_requires_exact_descriptor(self):
        manifest = IMAGE.rsplit('@', 1)[1]
        image = {'Id': manifest, 'Descriptor': {'digest': manifest}, 'Os': 'linux',
                 'Architecture': 'amd64', 'RepoDigests': [IMAGE]}
        self.assertEqual(resolve_image(self.runner(image=image)), IMAGE)
        image['Descriptor']['digest'] = 'sha256:' + '0' * 64
        with self.assertRaisesRegex(ValueError, '^trusted_image_unavailable$'):
            resolve_image(self.runner(image=image))

    def test_private_process_errors_are_sanitized(self):
        def run(*args):
            raise subprocess.CalledProcessError(1, args, output=b'private server output')
        with self.assertRaisesRegex(ValueError, '^trusted_image_unavailable$') as error:
            resolve_image(run)
        self.assertIsNone(error.exception.__cause__)

    def test_only_image_pull_transport_error_is_retryable(self):
        for failure in (subprocess.CalledProcessError(1, 'docker pull', output=b'private output'),
                        subprocess.TimeoutExpired('docker pull', 180), OSError('private transport output')):
            normal = self.runner()
            def run(*args):
                if args[1:3] == ('image', 'inspect'):
                    raise subprocess.CalledProcessError(1, args)
                if args[1] == 'pull':
                    raise failure
                return normal(*args)
            with self.assertRaisesRegex(ValueError, '^image_fetch_unavailable$') as error:
                resolve_image(run)
            self.assertIsNone(error.exception.__cause__)

    def test_probe_process_error_never_becomes_retryable(self):
        normal = self.runner()
        def run(*args):
            if args[1] == 'run':
                raise subprocess.CalledProcessError(1, args, output=b'private executable output')
            return normal(*args)
        with self.assertRaisesRegex(ValueError, '^trusted_image_unavailable$'):
            resolve_image(run)


if __name__ == '__main__':
    unittest.main()
