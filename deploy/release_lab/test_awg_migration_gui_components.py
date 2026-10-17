"""Component tests only; never launch GUI, native backend or network commands."""
import hashlib
import base64
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import patch


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


observer = module('observer_test', 'awg_migration_gui_observer.py')
guest = module('guest_test', 'awg_migration_gui_guest.py')


class ObserverTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('pkg-config') and shutil.which('g++'), 'Qt6 compiler required')
    def test_actual_qt_settings_encoding_and_compact_hash(self):
        source = r'''
#include <QCoreApplication>
#include <QSettings>
#include <QJsonDocument>
#include <QCryptographicHash>
#include <QFile>
#include <cstdio>
int main(int argc, char **argv) {
 QCoreApplication app(argc, argv);
 const QByteArray raw = R"({"storageServerId":"owned-id","containers":[{"awg":{"last_config":"{\"psk_key\":\"fixture-only\",\"mtu\":\"1420\"}"}}],"z":true})";
 const auto object = QJsonDocument::fromJson(raw).object();
 const auto compact = QJsonDocument(object).toJson(QJsonDocument::Compact);
 QJsonArray array; array.append(object);
 QSettings settings(QString::fromLocal8Bit(argv[1]), QSettings::IniFormat);
 settings.setValue("Servers/serversList", QJsonDocument(array).toJson()); settings.sync();
 const auto hash = QCryptographicHash::hash(compact,QCryptographicHash::Sha256).toHex();
 std::printf("%s",hash.constData());
}
'''
        with tempfile.TemporaryDirectory(dir=Path.home()) as directory:
            base = Path(directory)
            (base / 'test.cpp').write_text(source.replace('#include <QFile>', '#include <QFile>\n#include <QJsonArray>\n#include <QJsonObject>'))
            flags = subprocess.check_output(['pkg-config', '--cflags', '--libs', 'Qt6Core'], text=True).split()
            subprocess.run(['g++', str(base / 'test.cpp'), '-o', str(base / 'probe'), *flags], check=True, capture_output=True)
            digest = subprocess.check_output([str(base / 'probe'), str(base / 'settings.conf')], text=True)
            import configparser
            parser = configparser.RawConfigParser(interpolation=None)
            parser.optionxform = str
            parser.read(base / 'settings.conf')
            profile = json.loads(observer.qt_bytearray(parser['Servers']['serversList']))[0]
            self.assertEqual(observer.canonical_hash(profile), digest)

    def test_qt_escapes_and_truncation(self):
        self.assertEqual(observer.qt_bytearray(r'@ByteArray([\n{\"x\":\"a\\b\"}\n])'), b'[\n{"x":"a\\b"}\n]')
        self.assertEqual(observer.qt_bytearray(r'"@ByteArray(\x41\0)"'), b'A\0')
        for value in ('plain', '@ByteArray(\\)', r'@ByteArray(\x)', r'@ByteArray(\q)'):
            with self.subTest(value=value), self.assertRaises(observer.ObservationError):
                observer.qt_bytearray(value)

    def test_profile_digest_rejects_non_fixture_numbers_and_orders_keys(self):
        self.assertEqual(observer.canonical_hash({'b': 2, 'a': 1}), hashlib.sha256(b'{"a":1,"b":2}').hexdigest())
        for value in ({'a': 1.5}, {'a': '\u044f'}):
            with self.assertRaises(observer.ObservationError):
                observer.canonical_hash(value)

    def test_authenticated_source_compatible_envelope(self):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        key, nonce = bytes(range(32)), bytes(range(12))
        plain = b'{"state":"staged","sourceHash":"fixture"}'
        envelope = b'AMG1' + nonce + AESGCM(key).encrypt(nonce, plain, None)
        self.assertEqual(observer.decrypt(envelope, key), plain)
        for corrupt in (envelope[:-1] + bytes([envelope[-1] ^ 1]), b'BAD1' + envelope[4:], envelope[:20]):
            with self.assertRaises(observer.ObservationError):
                observer.decrypt(corrupt, key)
        with self.assertRaises(observer.ObservationError):
            observer.decrypt(envelope, b'x' * 32)

    def test_public_receipt_does_not_contain_private_fields(self):
        private = {'profile': {'psk': 'NEVER-PRINT'}, 'profile_sha256': 'abc',
                   'journal': {'state': 'committed', 'candidateHash': 'abc',
                               'grant': 'NEVER-PRINT', 'nonce': 'NEVER-PRINT',
                               'challengeReceipt': {'secret': 'NEVER-PRINT'}}}
        summary = observer.public_summary(private)
        self.assertTrue(summary['candidate_matches'])
        self.assertNotIn('NEVER-PRINT', json.dumps(summary))

    @unittest.skipUnless(os.name == 'posix', 'Linux private-file ownership')
    def test_private_file_mode_symlink_size_and_uid(self):
        # A private directory below the actual user's non-writable home avoids
        # weakening the observer to accommodate world-writable /tmp ancestors.
        with tempfile.TemporaryDirectory(dir=Path.home()) as directory:
            path = Path(directory) / 'private'
            path.write_bytes(b'owned')
            path.chmod(0o600)
            self.assertEqual(observer.private_read(path, os.getuid()), b'owned')
            with self.assertRaises(observer.ObservationError):
                observer.private_read(path, os.getuid() + 1)
            with self.assertRaises(observer.ObservationError):
                observer.private_read(path, os.getuid(), 2)
            path.chmod(0o644)
            with self.assertRaises(observer.ObservationError):
                observer.private_read(path, os.getuid())
            path.chmod(0o600)
            alias = Path(directory) / 'alias'
            alias.symlink_to(path)
            with self.assertRaises(OSError):
                observer.private_read(alias, os.getuid())

    @unittest.skipUnless(os.name == 'posix', 'Linux directory ownership')
    def test_account_tree_refuses_escape_symlink_and_writable_directory(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as directory:
            home = Path(directory)
            child = home / 'child'
            child.mkdir(mode=0o700)
            observer.account_tree(child, home, os.getuid())
            child.chmod(0o777)
            with self.assertRaises(observer.ObservationError):
                observer.account_tree(child, home, os.getuid())
            with self.assertRaises(observer.ObservationError):
                observer.account_tree(home.parent, home, os.getuid())
            child.chmod(0o700)
            alias = home / 'alias'
            alias.symlink_to(child, target_is_directory=True)
            with self.assertRaises(observer.ObservationError):
                observer.account_tree(alias, home, os.getuid())


class GuestCompositionTests(unittest.TestCase):
    def test_actual_native_readback_rejects_wrong_parameters_and_stale_handshake(self):
        scenario = guest.Scenario.__new__(guest.Scenario)
        key = bytes(range(32))
        scenario.target = {'Jc': '4', 'HeaderProtectionKey': base64.b64encode(key).decode()}
        scenario.server_pub = base64.b64encode(key).decode()
        raw = b'jc=4\nheader_protection_key=' + key.hex().encode() + b'\npublic_key=' + key.hex().encode() + b'\nlast_handshake_time_sec=100\nrx_bytes=5\ntx_bytes=6\n\n'
        def evaluate(data, started):
            stream = unittest.mock.MagicMock()
            stream.__enter__.return_value = stream
            stream.recv.return_value = data
            with patch.object(guest.Path, 'lstat', return_value=SimpleNamespace(st_mode=stat.S_IFSOCK | 0o600, st_uid=0)), patch.object(guest.socket, 'socket', return_value=stream):
                return scenario.native_trial('peer', started)
        self.assertTrue(evaluate(raw, 99)['parametersMatch'])
        with self.assertRaises(RuntimeError):
            evaluate(raw, 101)
        with self.assertRaises(RuntimeError):
            evaluate(raw.replace(b'jc=4', b'jc=8'), 99)

    def test_import_is_owned_amnezia_profile_with_preserved_psk_routes_dns_mtu(self):
        value = guest.import_profile('private', 'peer', 'server', 'psk', 'id', 'token', {'Jc': '4'}, '10.244.0.2')
        self.assertEqual(value['defaultContainer'], 'amnezia-awg2')
        self.assertNotIn('userName', value)
        client = json.loads(value['containers'][0]['awg']['last_config'])
        self.assertNotIn('isThirdPartyConfig', client)
        self.assertEqual(client['psk_key'], 'psk')
        self.assertEqual(client['mtu'], '1420')
        self.assertEqual(client['allowed_ips'], ['172.29.172.251/32', '172.29.172.252/32'])
        self.assertEqual(value['dns1'], '172.29.172.251')

    def test_missing_signed_product_bindings_rejected_before_file_access(self):
        for value in ({}, {'/tmp/GUI': {'sha256': 'a', 'size': 1}}):
            with self.assertRaises(RuntimeError):
                guest.product_binding(value)

    def test_wrong_profile_rejected_before_commands(self):
        with patch.object(guest.os, 'geteuid', return_value=0), patch.object(guest, 'command') as command:
            with self.assertRaises(RuntimeError):
                guest.guard({'schema': guest.SCHEMA, 'profile': 'linux-headless-x64'})
            command.assert_not_called()


if __name__ == '__main__':
    unittest.main()
