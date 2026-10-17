"""Maintenance-only entry regressions using owned fake Docker inventory."""
import json
import subprocess
import unittest

import maintenance
from journal import Journal, digest
import test_control_maintenance as fixtures
import base64


class MaintenanceEntryTests(unittest.TestCase):
    hashes = fixtures.ControlMaintenanceTests.hashes
    def docker_run(self, *args):
        if args[:3] == ('docker', 'exec', 'target-id'):
            self.calls.append(args)
            if args[3:] == ('cat', '/migration/awg0.conf'):
                return (self.installed / 'awg0.conf').read_bytes()
            if args[3:] == ('awg', 'show', 'awg0', 'dump'):
                return (self.private + '\t' + self.server + '\t51822\t0\n' +
                        self.peer + '\t(none)\t(none)\t' + getattr(self, 'live_allowed', '10.8.1.2/32') +
                        '\t0\t0\t0\t0\n').encode()
            if args[3:] == ('awg', 'showconf', 'awg0'):
                return b'[Interface]\nS1 = 16\n'
            if args[3:5] == ('sh', '-c'):
                from trusted_image import BINARY_SHA256
                self.assertIn('engine.pid', args[5])
                self.assertIn('/proc/$engine/exe', args[5])
                return (BINARY_SHA256 + '  /proc/123/exe\n').encode()
            self.fail('unexpected target action ' + repr(args))
        return fixtures.ControlMaintenanceTests.docker_run(self, *args)

    def setUp(self):
        fixtures.ControlMaintenanceTests.setUp(self)
        self.installed = self.root / 'amnezia-awg2' / '1'
        self.installed.parent.mkdir()
        (self.root / 'installed').rename(self.installed)
        for value in self.objects.values():
            value['Mounts'][0]['Source'] = str(self.installed)
        self.journal = Journal(self.installed, self.docker_run, self.journal.value)
        self.journal.value['request'] = {'generation': 1, 'host': 'vpn.example', 'port': 51822}
        self.private = base64.b64encode(b'a' * 32).decode()
        self.server = base64.b64encode(b'b' * 32).decode()
        self.peer = base64.b64encode(b'c' * 32).decode()
        self.source_raw = ('[Interface]\nPrivateKey = ' + self.private + '\nAddress = 10.8.1.1/24\n'
                           'ListenPort = 51820\n[Peer]\nPublicKey = ' + self.peer +
                           '\nAllowedIPs = 10.8.1.2/32\n').encode()
        self.journal.value['sourceDigest'] = digest(self.source_raw)
        (self.installed / 'awg0.conf').write_bytes(
            self.source_raw.replace(b'ListenPort = 51820', b'ListenPort = 51822\nS1 = 16'))
        self.journal.save()
        self.ready = {'containerId': 'amnezia-awg2', 'generation': 1,
                      'targetContainer': 'migration', 'parameters': {'S1': '16'},
                      'serverPublicKey': self.server,
                      'endpoint': 'vpn.example:51822',
                      'peers': {self.peer: {'clientId': 'client', 'sourceIp': '10.8.1.2',
                                           'targetIp': '10.8.1.2', 'clientAddress': '10.8.1.2/32'}}}
        (self.installed / 'ready.json').write_text(json.dumps(self.ready))
        # Real durable database bytes represent protected ACK/grant state.
        import sqlite3
        dbpath = self.installed / 'grants.sqlite3'
        dbpath.unlink()
        with sqlite3.connect(dbpath) as db:
            db.execute('CREATE TABLE grants (peer TEXT, proved INTEGER, ack INTEGER)')
            db.execute('INSERT INTO grants VALUES (?,?,?)', ('peer', 1, 1))
        (self.root / '.prepare.lock').touch()

    tearDown = fixtures.ControlMaintenanceTests.tearDown

    def invoke(self, expected=None, **kwargs):
        expected = expected or digest((self.installed / 'transaction.json').read_bytes())
        return maintenance.maintain('amnezia-awg2', 1, expected,
            recipe_directory=self.recipe, root=self.root, runner=self.docker_run, **kwargs)

    def snapshot(self):
        return {name: (self.installed / name).read_bytes() for name in
                ('ready.json', 'awg0.conf', 'awg0.native.conf', 'signing.pem', 'start.sh', 'grants.sqlite3')}

    def test_actual_entry_updates_only_control_pair_and_owned_helpers(self):
        before = self.snapshot()
        self.invoke()
        self.assertEqual(before, self.snapshot())
        self.assertEqual(self.hashes(self.new), self.journal.control_hashes())
        self.assertEqual([('docker', 'restart', 'control-id'), ('docker', 'restart', 'source-control-id')],
                         [call for call in self.calls if call[1] == 'restart'])

    def test_stale_journal_cas_rejects_before_any_docker_action(self):
        with self.assertRaises(ValueError):
            self.invoke(expected='0' * 64)
        self.assertEqual([], self.calls)

    def test_invalid_request_cannot_select_or_create_another_generation(self):
        before = sorted(str(path.relative_to(self.root)) for path in self.root.rglob('*'))
        for source, generation, expected in (
                ('../foreign', 1, 'a' * 64), ('amnezia-awg2', True, 'a' * 64),
                ('amnezia-awg2', 0, 'a' * 64), ('amnezia-awg2', 1, 'A' * 64)):
            with self.subTest(source=source, generation=generation), self.assertRaises(ValueError):
                maintenance.maintain(source, generation, expected, root=self.root, runner=self.docker_run)
        self.assertEqual(before, sorted(str(path.relative_to(self.root)) for path in self.root.rglob('*')))
        self.assertEqual([], self.calls)

    def test_ready_generation_or_source_drift_rejected_before_docker(self):
        for change in ({'generation': 2}, {'containerId': 'amnezia-awg'}, {'targetContainer': 'foreign'}):
            (self.installed / 'ready.json').write_text(json.dumps({**self.ready, **change}))
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.invoke()
            self.assertEqual([], self.calls)

    def test_non_ready_journal_rejected_without_recovery(self):
        self.journal.value['phase'] = 'creating'
        self.journal.save()
        with self.assertRaises(ValueError):
            self.invoke()
        self.assertEqual([], self.calls)

    def test_pending_transaction_rejected_before_recovery(self):
        self.journal.value['controlMaintenance'] = {'unreviewed': True}
        self.journal.save()
        before = (self.installed / 'transaction.json').read_bytes()
        with self.assertRaises(ValueError):
            self.invoke()
        self.assertEqual(before, (self.installed / 'transaction.json').read_bytes())
        self.assertEqual([], self.calls)

    def test_missing_protected_configuration_rejected_without_repair(self):
        before = (self.installed / 'transaction.json').read_bytes()
        for name in ('awg0.conf', 'awg0.native.conf', 'signing.pem', 'start.sh', 'grants.sqlite3'):
            path = self.installed / name
            original = path.read_bytes()
            path.unlink()
            with self.subTest(name=name), self.assertRaises((ValueError, FileNotFoundError)):
                self.invoke()
            self.assertEqual(before, (self.installed / 'transaction.json').read_bytes())
            self.assertFalse(path.exists())
            self.assertFalse(any(call[1] == 'restart' for call in self.calls))
            path.write_bytes(original)

    def test_actual_entry_failure_rolls_back_bytes_and_preserves_ack(self):
        before = self.snapshot()
        self.fail_second = True
        with self.assertRaises(subprocess.CalledProcessError):
            self.invoke()
        self.assertEqual(before, self.snapshot())
        self.assertEqual(self.hashes(self.old), self.journal.control_hashes())
        self.assertTrue(all(self.objects[key]['State']['Running'] for key in ('control-id', 'source-control-id')))

    def test_foreign_helper_ownership_never_restarted(self):
        before = self.snapshot()
        self.objects['control-id']['Config']['Labels']['amnezia.migration.owner'] = 'foreign'
        with self.assertRaises(ValueError):
            self.invoke()
        self.assertEqual(before, self.snapshot())
        self.assertFalse(any(call[1] == 'restart' for call in self.calls))

    def test_actual_live_peer_drift_rejected_before_maintenance_writes(self):
        self.live_allowed = '10.8.1.3/32'
        before = self.snapshot()
        journal_before = (self.installed / 'transaction.json').read_bytes()
        with self.assertRaises(ValueError):
            self.invoke()
        self.assertEqual(before, self.snapshot())
        self.assertEqual(journal_before, (self.installed / 'transaction.json').read_bytes())
        self.assertEqual(self.hashes(self.old), self.journal.control_hashes())
        self.assertFalse(any(call[1] == 'restart' for call in self.calls))

    def test_prepare_lock_contention_rejects_without_docker_or_mutation(self):
        import fcntl
        before = self.snapshot()
        with open(self.root / '.prepare.lock', 'r+') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):
                self.invoke()
        self.assertEqual(before, self.snapshot())
        self.assertEqual([], self.calls)


if __name__ == '__main__':
    unittest.main()
