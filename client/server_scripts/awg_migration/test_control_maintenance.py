"""Exercise real maintenance callbacks against an owned fake Docker inventory."""
import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from journal import Journal, CONTROL_FILES, digest, durable_bytes


class ControlMaintenanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.installed = self.root / 'installed'
        self.recipe = self.root / 'recipe'
        self.installed.mkdir()
        self.recipe.mkdir()
        self.old = {name: ('old ' + name).encode() for name in CONTROL_FILES}
        self.new = {name: ('new ' + name).encode() for name in CONTROL_FILES}
        for name in CONTROL_FILES:
            (self.installed / name).write_bytes(self.old[name])
            (self.recipe / name).write_bytes(self.new[name])
        for name in ('ready.json', 'awg0.conf', 'awg0.native.conf', 'signing.pem', 'start.sh', 'grants.sqlite3'):
            (self.installed / name).write_bytes(('protected ' + name).encode())
        self.calls, self.epoch = [], 0
        self.source_raw = b'unchanged legacy config'
        self.objects = {}
        for name, identity in [('amnezia-awg2', 'source-id'), ('migration', 'target-id'),
                               ('migration-control', 'control-id'), ('migration-source-control', 'source-control-id')]:
            self.objects[identity] = {'Id': identity, 'Name': '/' + name, 'Image': 'image',
                'Config': {'Labels': {'amnezia.migration.owner': 'a' * 32},
                           'Entrypoint': ['python'], 'Cmd': ['/migration/target.py']},
                'State': {'Running': True, 'StartedAt': 'epoch0'},
                'HostConfig': {'Privileged': False, 'NetworkMode': 'container:' + ('source-id' if name.endswith('source-control') else 'target-id')},
                'Mounts': [{'Type': 'bind', 'Source': str(self.installed), 'Destination': '/migration', 'RW': True},
                           {'Type': 'bind', 'Source': '/opt/amnezia/client-logs', 'Destination': '/logs', 'RW': False}]}
        entries = {self.objects[i]['Name'][1:]: {'id': i, 'image': 'image'}
                   for i in ('target-id', 'control-id', 'source-control-id')}
        self.journal = Journal(self.installed, self.docker_run, {'owner': 'a' * 32, 'phase': 'ready',
            'containers': entries, 'source': 'amnezia-awg2', 'sourceId': 'source-id',
            'target': 'migration', 'sourceEpoch': 'epoch0', 'targetEpoch': 'epoch0',
            'sourceDigest': digest(self.source_raw)})
        self.journal.save()
        self.baselines = patch('journal.CONTROL_BASELINES', (self.hashes(self.old),))
        self.baselines.start()
        self.fail_second = False
        self.bad_receipt = False
        self.not_listening = set()

    def tearDown(self):
        self.baselines.stop()
        self.tmp.cleanup()

    def hashes(self, raw):
        return {name: digest(value) for name, value in raw.items()}

    def docker_run(self, *args):
        self.calls.append(args)
        if args[:2] == ('docker', 'inspect'):
            return json.dumps([self.objects[args[2]]]).encode()
        if args[:2] == ('docker', 'restart'):
            identity = args[2]
            self.assertIn(identity, ('control-id', 'source-control-id'))
            self.epoch += 1
            self.objects[identity]['State'] = {'Running': True, 'StartedAt': 'epoch' + str(self.epoch)}
            if identity == 'source-control-id' and self.fail_second:
                self.fail_second = False
                self.objects[identity]['State']['Running'] = False
                self.not_listening.add(identity)
                raise subprocess.CalledProcessError(1, args)
            self.not_listening.discard(identity)
            return b''
        if args[:2] == ('docker', 'exec'):
            if args[3] == 'cat':
                return self.source_raw
            if args[2] in self.not_listening:
                raise subprocess.CalledProcessError(1, args)
            if 'control-loaded-' in args[-1]:
                if self.bad_receipt:
                    self.bad_receipt = False
                    raise subprocess.CalledProcessError(1, args)
                # Verify the production-generated probe carries actual new bytes.
                self.assertIn(repr(self.journal.control_hashes()), args[-1])
            return b''
        self.fail('unexpected Docker mutation ' + repr(args))

    def assert_old(self):
        self.assertEqual(self.hashes(self.old), self.journal.control_hashes())
        for name in ('ready.json', 'awg0.conf', 'awg0.native.conf', 'signing.pem', 'start.sh', 'grants.sqlite3'):
            self.assertEqual(('protected ' + name).encode(), (self.installed / name).read_bytes())
        self.assertFalse(any(c[1] in ('rm', 'start', 'stop') for c in self.calls))

    def test_ready_generation_activates_coherent_pair_only_in_control_helpers(self):
        self.journal.maintain_controls(self.recipe)
        self.assertEqual(self.hashes(self.new), self.journal.control_hashes())
        self.assertEqual(self.hashes(self.new), self.journal.value['controlRecipe'])
        self.assertNotIn('controlMaintenance', self.journal.value)
        self.assertEqual([('docker', 'restart', 'control-id'), ('docker', 'restart', 'source-control-id')],
                         [c for c in self.calls if c[1] == 'restart'])
        self.calls.clear()
        self.journal.maintain_controls(self.recipe)
        self.assertFalse(any(c[1] == 'restart' for c in self.calls))

    def test_second_helper_stopped_failure_restores_pair_and_both_processes(self):
        self.fail_second = True
        with self.assertRaises(subprocess.CalledProcessError):
            self.journal.maintain_controls(self.recipe)
        self.assert_old()
        self.assertTrue(all(self.objects[i]['State']['Running'] for i in ('control-id', 'source-control-id')))
        self.assertEqual('rolled_back', self.journal.value['controlMaintenanceResult'])

    def test_crash_after_first_swap_recovers_from_disk_before_retry(self):
        actual = durable_bytes
        writes = []
        def crash(path, raw):
            if path.parent == self.installed:
                writes.append(path.name)
                if len(writes) == 2:
                    raise KeyboardInterrupt('power loss')
            actual(path, raw)
        # Simulate process death: recovery callback cannot execute in this process.
        with patch('journal.durable_bytes', side_effect=crash), patch.object(self.journal, 'recover_control_maintenance', side_effect=[None, KeyboardInterrupt('dead')]):
            with self.assertRaises(KeyboardInterrupt):
                self.journal.maintain_controls(self.recipe)
        reopened = Journal(self.installed, self.docker_run)
        self.assertIn('controlMaintenance', reopened.value)
        reopened.recover_control_maintenance()
        self.assert_old()
        self.assertNotIn('controlMaintenance', reopened.value)

    def test_crash_after_both_swaps_before_processes_rolls_back(self):
        with patch.object(self.journal, 'restart_controls', side_effect=KeyboardInterrupt('power loss')):
            with self.assertRaises(KeyboardInterrupt):
                self.journal.maintain_controls(self.recipe)
        reopened = Journal(self.installed, self.docker_run)
        reopened.recover_control_maintenance()
        self.assert_old()

    def test_unknown_baseline_or_pinned_drift_never_overwritten(self):
        for pinned in (None, self.hashes(self.old)):
            self.journal.value['controlRecipe'] = pinned
            (self.installed / 'service.py').write_bytes(b'other administrator edit')
            with self.assertRaisesRegex(ValueError, 'unknown baseline'):
                self.journal.maintain_controls(self.recipe)
            self.assertFalse(any(c[1] == 'restart' for c in self.calls))

    def test_wrong_owner_mount_namespace_or_epoch_never_mutated(self):
        original = copy.deepcopy(self.objects)
        for field in ('owner', 'mount', 'network', 'epoch'):
            self.objects = copy.deepcopy(original)
            if field == 'owner':
                self.objects['control-id']['Config']['Labels']['amnezia.migration.owner'] = 'foreign'
            elif field == 'mount':
                self.objects['control-id']['Mounts'][0]['Source'] = '/foreign'
            elif field == 'network':
                self.objects['control-id']['HostConfig']['NetworkMode'] = 'host'
            else:
                self.objects['source-id']['State']['StartedAt'] = 'changed'
            with self.assertRaises(ValueError):
                self.journal.maintain_controls(self.recipe)
            self.assertFalse(any(c[1] == 'restart' for c in self.calls))

    def test_noop_baseline_pin_does_not_invent_loaded_receipt_support(self):
        for name in CONTROL_FILES:
            (self.recipe / name).write_bytes(self.old[name])
        self.journal.maintain_controls(self.recipe)
        self.assertFalse(self.journal.value.get('controlLoadedReceipt', False))
        for name in CONTROL_FILES:
            (self.recipe / name).write_bytes(self.new[name])
        self.fail_second = True
        with self.assertRaises(subprocess.CalledProcessError):
            self.journal.maintain_controls(self.recipe)
        self.assert_old()


if __name__ == '__main__':
    unittest.main()
