"""Crash/reboot reconciliation using immutable fake Docker identities, no daemon."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from journal import Journal

OWNER = 'a' * 32
IMAGE = 'sha256:' + 'b' * 64
NAME = 'amnezia-awg2-migration-1'


def container(name, identity, owner=OWNER, image=IMAGE, epoch='epoch1', running=True):
    return {'Id': identity, 'Name': '/' + name, 'Image': image,
            'Config': {'Labels': {'amnezia.migration.owner': owner}},
            'State': {'Running': running, 'StartedAt': epoch}}


class Docker:
    def __init__(self):
        self.objects, self.calls = {}, []

    def run(self, *args):
        self.calls.append(args)
        if args[1] == 'inspect':
            item = next((value for value in self.objects.values() if args[2] in (value['Id'], value['Name'][1:])), None)
            if item is None:
                raise subprocess.CalledProcessError(1, args, stderr=b'Error: No such object')
            return json.dumps([item]).encode()
        if args[1] == 'rm':
            self.objects = {key: value for key, value in self.objects.items() if value['Id'] != args[-1]}
        return b''


class JournalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.docker = Docker()
        self.docker.objects['source'] = container('amnezia-awg2', 'source-id', owner='not-ours')
        self.journal = Journal(self.tmp.name, self.docker.run,
            {'owner': OWNER, 'phase': 'preparing', 'containers': {}, 'source': 'amnezia-awg2',
             'sourceId': 'source-id', 'sourceIface': 'awg0', 'sourceRules': False,
             'target': NAME, 'sourceEpoch': 'epoch1', 'targetEpoch': 'epoch1'})
        self.journal.save()

    def tearDown(self): self.tmp.cleanup()

    def test_kill_after_create_before_id_record_recovers_owned_exact_id(self):
        self.journal.plan(NAME, IMAGE)
        self.docker.objects['target'] = container(NAME, 'owned-id')
        # Re-open the persisted journal as a new operator process would.
        recovered = Journal(self.tmp.name, self.docker.run)
        recovered.cleanup()
        self.assertIn(('docker', 'rm', '-f', 'owned-id'), self.docker.calls)
        self.assertNotIn(('docker', 'rm', '-f', 'source-id'), self.docker.calls)
        self.assertEqual('aborted', json.loads(Path(self.tmp.name, 'transaction.json').read_text())['phase'])

    def test_reused_name_or_changed_image_never_removed(self):
        self.journal.plan(NAME, IMAGE)
        for owner, image in (('c' * 32, IMAGE), (OWNER, 'sha256:' + 'd' * 64)):
            self.docker.objects['target'] = container(NAME, 'foreign-id', owner, image)
            with self.assertRaises(ValueError): self.journal.cleanup()
            self.assertFalse(any(call[1] == 'rm' for call in self.docker.calls))

    def test_same_ready_generation_is_idempotent(self):
        self.journal.plan(NAME, IMAGE)
        self.docker.objects['target'] = container(NAME, 'owned-id')
        self.journal.record(NAME)
        self.journal.save('ready')
        reopened = Journal(self.tmp.name, self.docker.run)
        reopened.recover_ready()
        reopened.recover_ready()
        self.assertFalse(any(call[1] in ('rm', 'restart', 'start') for call in self.docker.calls))

    def test_reboot_rejoins_owned_companion_without_touching_old_vpn(self):
        for name, identity in ((NAME, 'target-id'), (NAME + '-source-control', 'control-id')):
            self.journal.plan(name, IMAGE)
            self.docker.objects[name] = container(name, identity)
            self.journal.record(name)
        self.journal.save('ready')
        self.docker.objects['source']['State']['StartedAt'] = 'epoch2'
        self.journal.value['sourceRules'] = True
        self.journal.recover_ready()
        self.assertIn(('docker', 'restart', 'control-id'), self.docker.calls)
        self.assertNotIn(('docker', 'restart', 'source-id'), self.docker.calls)
        writes = [call[-1] for call in self.docker.calls if call[1] == 'exec']
        self.assertEqual(3, sum('|| iptables' in command for command in writes))
        self.assertEqual(3, sum(command.startswith('iptables ') and '||' not in command for command in writes))
        self.assertTrue(any('-C PREROUTING' in command and '--to-ports 18082' in command for command in writes))


if __name__ == '__main__': unittest.main()
