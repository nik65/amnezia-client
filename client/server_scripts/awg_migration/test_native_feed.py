"""Native feed caller tests: owned fixtures and fake argv, no Docker/system edits."""
import hashlib
import os
from pathlib import Path
import struct
import json
import prepare
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from prepare import check_feed, install_native_feed, load_native_feed, start_feed


def executable(machine=62):
    raw = bytearray(256)
    raw[:7] = b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HHIQQQIHHHHHH', raw, 16, 2, machine, 1, 0x400080, 64, 0, 0, 64, 56, 1, 0, 0, 0)
    struct.pack_into('<IIQQQQQQ', raw, 64, 1, 5, 0, 0x400000, 0, 256, 256, 4096)
    return bytes(raw)


class NativeFeedTests(unittest.TestCase):
    def test_absent_and_incomplete_selection(self):
        self.assertIsNone(load_native_feed(SimpleNamespace()))
        for args in (SimpleNamespace(native_feed='/fixture'),
                     SimpleNamespace(native_feed_sha256='a' * 64)):
            with self.assertRaisesRegex(ValueError, 'native_feed_invalid'):
                load_native_feed(args)

    def test_capture_validated_bytes_and_exclusive_install(self):
        if os.geteuid() != 0:
            self.skipTest('root-owned isolated fixture check')
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            source = root / 'input'
            raw = executable(183 if os.uname().machine == 'aarch64' else 62)
            source.write_bytes(raw)
            source.chmod(0o755)
            args = SimpleNamespace(native_feed=str(source), native_feed_sha256=hashlib.sha256(raw).hexdigest())
            captured = load_native_feed(args)
            source.write_bytes(b'changed after authenticated capture')
            directory = root / 'generation'
            directory.mkdir(mode=0o700)
            result = install_native_feed(directory, captured)
            self.assertEqual(raw, result.read_bytes())
            self.assertEqual(0o755, result.stat().st_mode & 0o777)
            with self.assertRaises(FileExistsError):
                install_native_feed(directory, captured)

    def test_static_elf_metadata_and_digest_rejections(self):
        if os.geteuid() != 0:
            self.skipTest('root-owned isolated fixture check')
        with tempfile.TemporaryDirectory() as name:
            source = Path(name) / 'input'
            good = executable(183 if os.uname().machine == 'aarch64' else 62)
            variants = []
            for offset, value in ((64, 2), (64, 3), (16, 3), (18, 9), (24, 0), (54, 0), (56, 0), (52, 0)):
                raw = bytearray(good)
                struct.pack_into('<Q' if offset == 24 else '<H', raw, offset, value)
                variants.append(bytes(raw))
            for offset, value in ((64 + 16, 0xffffffffffffffff), (64 + 48, 3),
                                  (64 + 8, 1), (64 + 16, 0x400001)):
                raw = bytearray(good)
                struct.pack_into('<Q', raw, offset, value)
                variants.append(bytes(raw))
            variants += [b'not an executable', good[:100]]
            for raw in variants:
                with self.subTest(header=raw[:80].hex()):
                    source.write_bytes(raw)
                    source.chmod(0o755)
                    args = SimpleNamespace(native_feed=str(source), native_feed_sha256=hashlib.sha256(raw).hexdigest())
                    with self.assertRaisesRegex(ValueError, 'native_feed_invalid'):
                        load_native_feed(args)
            source.write_bytes(good)
            source.chmod(0o755)
            args = SimpleNamespace(native_feed=str(source), native_feed_sha256='0' * 64)
            with self.assertRaisesRegex(ValueError, 'native_feed_invalid'):
                load_native_feed(args)
            args.native_feed_sha256 = hashlib.sha256(good).hexdigest()
            source.chmod(0o777)
            with self.assertRaisesRegex(ValueError, 'native_feed_invalid'):
                load_native_feed(args)
            source.chmod(0o755)
            os.link(source, source.with_name('hardlink'))
            with self.assertRaisesRegex(ValueError, 'native_feed_invalid'):
                load_native_feed(args)

    def test_fifo_and_symlink_refuse_without_read(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            os.mkfifo(root / 'fifo')
            (root / 'link').symlink_to(root / 'fifo')
            for path in (root / 'fifo', root / 'link'):
                with self.subTest(path=path), self.assertRaises((OSError, ValueError)):
                    load_native_feed(SimpleNamespace(native_feed=str(path), native_feed_sha256='0' * 64))

    def test_native_and_legacy_use_one_journal_and_fixed_mounts(self):
        for native in (None, Path('/owned/generation/awg-feed')):
            calls, journal_events = [], []
            journal = SimpleNamespace(plan=lambda *a: journal_events.append(('plan', *a)),
                                      record=lambda *a: journal_events.append(('record', *a)))
            start_feed(lambda *a: calls.append(a), journal, Path('/owned/generation'),
                       'target', 'owner', 'pinned-python-image', 'observed-image-id', ['17864', '17865'], native)
            self.assertEqual([('plan', 'target-feeds', 'observed-image-id'), ('record', 'target-feeds')], journal_events)
            args = calls[0]
            self.assertIn('container:target', args)
            self.assertIn('/opt/amnezia/server-routing-rules:/routing:ro', args)
            self.assertIn('/opt/amnezia/client-updates:/updates:ro', args)
            if native:
                self.assertEqual(('--entrypoint', '/app/awg-feed', 'pinned-python-image', '--serve'), args[-4:])
                self.assertIn('/owned/generation/awg-feed:/app/awg-feed:ro', args)
                self.assertNotIn('python', args)
                self.assertNotIn('/app/feeds.py', args)
            else:
                self.assertEqual(('--entrypoint', 'python', 'pinned-python-image', '/app/feeds.py'), args[-4:])

    def test_actual_prepare_refuses_existing_generation_before_recovery(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            generation = root / 'amnezia-awg' / '1'
            generation.mkdir(parents=True)
            state = generation / 'transaction.json'
            original = b'{"phase":"ready","owner":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}'
            state.write_bytes(original)
            args = SimpleNamespace(source='amnezia-awg', automatic=False,
                                   image='repo@sha256:' + 'c' * 64, host='fixture.test', port=23456,
                                   generation=1, preflight=False, native_feed='unused', native_feed_sha256='a' * 64)
            with patch.object(prepare, 'ROOT', root), patch.object(prepare.os, 'geteuid', return_value=0), \
                    patch.object(prepare, 'load_native_feed', return_value=b'authenticated fixture'), \
                    patch.object(prepare.NativePolicy, 'control_capability'), \
                    patch.object(prepare.NativePolicy, 'network_capability'), \
                    patch.object(prepare.NativePolicy, 'source_config_capability'), \
                    patch.object(prepare.NativePolicy, 'policy_epoch_capability'), \
                    patch.object(prepare.NativePolicy, 'peer_mapping_capability'), \
                    patch.object(prepare.NativePolicy, 'server_key_capability'), \
                    patch.object(prepare, 'source_config_function', return_value=lambda run, source: b'fixture'), \
                    patch.object(prepare, 'run', return_value=b'fixture'), \
                    patch.object(prepare, 'config_function', return_value=lambda raw: ({'ListenPort': '12345'}, [])), \
                    patch.object(prepare, 'Journal', side_effect=AssertionError('must not recover')):
                with self.assertRaisesRegex(ValueError, '^native_feed_existing_generation_requires_maintenance$'):
                    prepare.prepare(args)
            self.assertEqual(original, state.read_bytes())
            self.assertEqual(['transaction.json'], [path.name for path in generation.iterdir()])

    def test_native_readiness_has_no_python_fallback(self):
        calls = []
        self.assertTrue(check_feed(lambda *a: calls.append(a), 'target-feeds', '17864', 'a' * 64, True))
        self.assertEqual([('docker', 'exec', 'target-feeds', '/app/awg-feed', '--check-feed', 'routing', '17864', 'a' * 64)], calls)
        calls.clear()
        def fail(*args):
            calls.append(args)
            raise RuntimeError('native probe failed')
        with self.assertRaisesRegex(RuntimeError, 'native probe failed'):
            check_feed(fail, 'target-feeds', '17865', 'a' * 64, True)
        self.assertEqual(1, len(calls))
        self.assertNotIn('python', calls[0])


if __name__ == '__main__':
    unittest.main()
