"""Independent maintenance isolation regressions. Fake Docker, real SQLite."""
import copy
from contextlib import closing
import json
import sqlite3
import subprocess
import unittest

import test_control_maintenance as fixtures


class JournalMaintenanceGuardTests(unittest.TestCase):
    setUp = fixtures.ControlMaintenanceTests.setUp
    tearDown = fixtures.ControlMaintenanceTests.tearDown
    hashes = fixtures.ControlMaintenanceTests.hashes
    docker_run = fixtures.ControlMaintenanceTests.docker_run

    def unchanged(self, before):
        self.assertEqual(before, (self.installed / 'transaction.json').read_bytes())
        self.assertEqual(self.hashes(self.old), self.journal.control_hashes())
        self.assertFalse(any(call[1] == 'restart' for call in self.calls))
        self.assertFalse((self.installed / '.control-maintenance').exists())

    def test_effective_role_scope_and_duplicate_environment_rejected_before_writes(self):
        original = copy.deepcopy(self.objects)
        cases = [
            ('control-id', ['AMNEZIA_MIGRATION_ROLE=source']),
            ('control-id', ['AMNEZIA_MIGRATION_SCOPE=amnezia-awg']),
            ('control-id', ['AMNEZIA_MIGRATION_ROLE=target', 'AMNEZIA_MIGRATION_ROLE=target']),
            ('source-control-id', []),
            ('source-control-id', ['AMNEZIA_MIGRATION_ROLE=source']),
            ('source-control-id', ['AMNEZIA_MIGRATION_ROLE=source', 'AMNEZIA_MIGRATION_SCOPE=amnezia-awg']),
            ('source-control-id', ['AMNEZIA_MIGRATION_ROLE=source', 'AMNEZIA_MIGRATION_SCOPE=amnezia-awg2', 'AMNEZIA_MIGRATION_SCOPE=amnezia-awg2']),
        ]
        before = (self.installed / 'transaction.json').read_bytes()
        for identity, environment in cases:
            with self.subTest(identity=identity, environment=environment):
                self.objects = copy.deepcopy(original)
                self.objects[identity]['Config']['Env'] = environment
                with self.assertRaisesRegex(ValueError, 'environment|role/scope'):
                    self.journal.maintain_controls(self.recipe)
                self.unchanged(before)

    def test_noop_requires_both_loaded_helpers_before_pin_or_save(self):
        for name, raw in self.old.items():
            (self.recipe / name).write_bytes(raw)
        before = (self.installed / 'transaction.json').read_bytes()
        actual = self.journal.run
        def reject_source(*args):
            if args[:3] == ('docker', 'exec', 'source-control-id') and 'control-loaded-source' in args[-1]:
                raise subprocess.CalledProcessError(1, args)
            return actual(*args)
        self.journal.run = reject_source
        with self.assertRaises(subprocess.CalledProcessError):
            self.journal.maintain_controls(self.recipe)
        self.unchanged(before)
        self.assertNotIn('controlRecipe', self.journal.value)

    def test_noop_validation_failure_is_byte_immutable(self):
        for name, raw in self.old.items():
            (self.recipe / name).write_bytes(raw)
        before = (self.installed / 'transaction.json').read_bytes()
        def reject(): raise ValueError('target engine drift')
        with self.assertRaisesRegex(ValueError, 'target engine drift'):
            self.journal.maintain_controls(self.recipe, validate=reject)
        self.unchanged(before)

    def test_manual_legacy_without_native_recipe_remains_supported(self):
        native = self.installed / 'awg0.native.conf'
        native.unlink()
        self.journal.maintain_controls(self.recipe)
        self.assertFalse(native.exists())
        self.assertEqual(self.hashes(self.new), self.journal.control_hashes())
        with self.assertRaisesRegex(ValueError, 'protected state missing'):
            self.journal.protected_control_state(require_native=True)

    def test_postactivation_validation_failure_rolls_back_only_helpers(self):
        def reject(): raise ValueError('native endpoint changed')
        with self.assertRaisesRegex(ValueError, 'native endpoint changed'):
            self.journal.maintain_controls(self.recipe, validate=reject)
        self.assertEqual(self.hashes(self.old), self.journal.control_hashes())
        self.assertEqual('rolled_back', self.journal.value['controlMaintenanceResult'])
        self.assertTrue(all(call[2] in ('control-id', 'source-control-id') for call in self.calls if call[1] == 'restart'))

    def test_concurrent_ack_survives_activation_failure_and_rollback(self):
        path = self.installed / 'grants.sqlite3'
        path.unlink()
        with closing(sqlite3.connect(path)) as db, db:
            db.execute('CREATE TABLE grants (peer TEXT PRIMARY KEY, proved INTEGER, ack INTEGER)')
            db.executemany('INSERT INTO grants VALUES (?, ?, ?)', [('selected', 1, 0), ('other-peer', 1, 1)])
        ready_before = (self.installed / 'ready.json').read_bytes()
        actual = self.journal.run
        changed = []
        def concurrent_ack(*args):
            result = actual(*args)
            if args[:3] == ('docker', 'restart', 'control-id') and not changed:
                with closing(sqlite3.connect(path)) as db, db:
                    db.execute('UPDATE grants SET ack=1 WHERE peer=?', ('selected',))
                changed.append(path.read_bytes())
            return result
        self.journal.run = concurrent_ack
        self.fail_second = True
        with self.assertRaises(subprocess.CalledProcessError):
            self.journal.maintain_controls(self.recipe)
        self.assertTrue(changed)
        self.assertEqual(changed[0], path.read_bytes())
        with closing(sqlite3.connect(path)) as db:
            self.assertEqual([('other-peer', 1, 1), ('selected', 1, 1)], db.execute('SELECT * FROM grants ORDER BY peer').fetchall())
        self.assertEqual(ready_before, (self.installed / 'ready.json').read_bytes())
        self.assertEqual(self.hashes(self.old), self.journal.control_hashes())


if __name__ == '__main__': unittest.main()
