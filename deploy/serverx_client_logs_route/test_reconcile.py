"""Run on Linux/WSL: python3 -m unittest test_reconcile.py.

The script copy has fixed test paths, a private fake Docker executable and an
owned /proc fixture. Production has no environment/path override switch.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
SOURCE_IMAGE = 'sha256:7dc728e8183a86eac6b9f8033511d4c16a135dff1e8aed7946470376600a685a'
IMAGE = 'python:3.12-alpine@sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df'
LEGACY = 'e8cce8c8054edb8f8f4871725e81b3185df247ca7de7d863467568a70782e0e0'
ACTIVE = 'amnezia-client-logs-vpn-amnezia-awg2'


class ReconcileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='serverx-route-test-')
        self.addCleanup(self.temp.cleanup)
        self.p = Path(self.temp.name)
        self.root = self.p / 'data'
        self.root.mkdir(mode=0o700)
        (self.root / 'collector.py').write_text('# owned fixture\n')
        shutil.copyfile(HERE / 'fake_docker.py', self.p / 'docker')
        (self.p / 'docker').chmod(0o700)
        text = (HERE / 'reconcile.sh').read_text()
        text = text.replace('DOCKER=/usr/bin/docker', 'DOCKER=' + str(self.p / 'docker'))
        text = text.replace('PROC_ROOT=/proc', 'PROC_ROOT=' + str(self.p / 'proc'))
        text = text.replace('ROOT=/opt/amnezia/client-logs', 'ROOT=' + str(self.root))
        text = text.replace('REQUIRED_UID=0', 'REQUIRED_UID=' + str(os.getuid()))
        text = text.replace('a31814f2217aaea21c85b696cebac8442f4cfbb8c336f41497240147bca5e593', hashlib.sha256((self.root / 'collector.py').read_bytes()).hexdigest())
        self.script = self.p / 'reconcile.sh'
        self.script.write_text(text)
        source = {'Id': 'a' * 64, 'Name': '/amnezia-awg2', 'Image': SOURCE_IMAGE,
                  'State': {'Running': True, 'Paused': False, 'Pid': 111, 'StartedAt': 'source-started'}}
        collector = {'Id': LEGACY, 'Name': '/' + ACTIVE, 'Image': IMAGE.split('@')[1],
                     'State': {'Running': True, 'Pid': 222, 'StartedAt': 'collector-started'},
                     'Config': {'Image': IMAGE, 'Entrypoint': ['python'], 'Cmd': ['/data/collector.py'],
                                'Env': ['AMNEZIA_CLIENT_LOGS_BOOTSTRAP=1', 'AMNEZIA_CLIENT_LOGS_SCOPE=amnezia-awg2'], 'Labels': {}},
                     'HostConfig': {'NetworkMode': 'container:' + source['Id'], 'Privileged': False},
                     'Mounts': [{'Type': 'bind', 'Source': str(self.root), 'Destination': '/data', 'RW': True}]}
        self.s = {'containers': [source, collector], 'template': collector, 'rule': True, 'calls': [],
                  'public_key': 'VoMDtwx77g/WR/KtVi48vs94syeRflU7GHarWkeDFCE=', 'source_ns': 'net:[100]', 'active': ACTIVE}
        for pid in (111, 222):
            self.proc(pid, 'net:[100]')

    def proc(self, pid, ns):
        p = self.p / 'proc' / str(pid)
        (p / 'ns').mkdir(parents=True)
        (p / 'ns/net').symlink_to(ns)
        (p / 'fd').mkdir()
        (p / 'fd/3').symlink_to('socket:[12345]')
        (p / 'net').mkdir()
        (p / 'net/tcp').write_text('0: 00000000:45CA 00000000:0000 0A 0 0 0 0 0 12345\n')
        (p / 'cmdline').write_bytes(b'python\0/data/collector.py\0')

    def run_case(self, success=True):
        (self.p / 'state.json').write_text(json.dumps(self.s))
        r = subprocess.run(['/bin/bash', str(self.script)], capture_output=True, text=True, timeout=35)
        self.s = json.loads((self.p / 'state.json').read_text())
        self.assertEqual(r.returncode == 0, success, r.stdout + r.stderr)
        parent_ids = {'a' * 64, 'b' * 64, 'amnezia-awg2'}
        for call in self.s['calls']:
            if call[0] in ('restart', 'rename'):
                self.assertNotIn(call[1], parent_ids)
            if call[:2] == ['rm', '-f']:
                self.assertNotIn(call[2], parent_ids)
        return r

    def mutations(self):
        return [a for a in self.s['calls'] if a[0] in ('restart', 'run', 'rename', 'rm') or (a[0] == 'exec' and len(a) > 5 and a[5] in ('-A', '-D'))]

    def test_existing_rule_and_listener_are_idempotent(self):
        self.run_case()
        self.assertEqual(self.mutations(), [])

    def test_missing_rule_added_once(self):
        self.s['rule'] = False
        self.run_case()
        self.run_case()
        self.assertEqual(sum(a[0] == 'exec' and '-A' in a for a in self.s['calls']), 1)

    def test_parent_recreation_replaces_only_owned_sidecar(self):
        self.s['containers'][0]['Id'] = 'b' * 64
        self.s['rule'] = False
        self.run_case()
        mutations = self.mutations()
        self.assertEqual([a[0] for a in mutations], ['run', 'rm', 'rename', 'exec'])
        self.assertEqual(mutations[1], ['rm', '-f', LEGACY])
        c = next(c for c in self.s['containers'] if c['Name'] == '/' + ACTIVE)
        self.assertEqual(c['HostConfig']['NetworkMode'], 'container:' + 'b' * 64)
        self.run_case()
        self.assertEqual(sum(a[0] == 'run' for a in self.s['calls']), 1)

    def test_stale_namespace_restarts_collector_only(self):
        (self.p / 'proc/222/ns/net').unlink()
        (self.p / 'proc/222/ns/net').symlink_to('net:[old]')
        self.run_case()
        self.assertEqual(self.mutations(), [['restart', LEGACY]])

    def test_foreign_collector_not_adopted(self):
        self.s['containers'][1]['Id'] = 'd' * 64
        self.run_case(False)
        self.assertEqual(self.mutations(), [])

    def test_wrong_source_key_rejected(self):
        self.s['public_key'] = 'other-key'
        self.run_case(False)
        self.assertEqual(self.mutations(), [])

    def test_wrong_source_image_rejected(self):
        self.s['containers'][0]['Image'] = 'sha256:' + '0' * 64
        self.run_case(False)
        self.assertEqual(self.mutations(), [])

    def test_source_epoch_race_prevents_replacement(self):
        self.s['containers'][0]['Id'] = 'b' * 64
        self.s['race_at_key_read'] = 2
        self.run_case(False)
        self.assertEqual(self.mutations(), [])

    def test_collector_incarnation_change_rolls_back_own_rule(self):
        self.s['rule'] = False
        self.s['collector_restart_after_add'] = True
        self.run_case(False)
        self.assertFalse(self.s['rule'])
        self.assertEqual([a[5] for a in self.mutations()], ['-A', '-D'])

    def test_changed_collector_file_rejected(self):
        (self.root / 'collector.py').write_text('# changed\n')
        self.run_case(False)
        self.assertEqual(self.mutations(), [])

    def test_uncertain_add_never_guess_deletes_rule(self):
        self.s['rule'] = False
        self.s['uncertain_add'] = True
        self.run_case(False)
        self.assertTrue(self.s['rule'])
        self.assertEqual([a[5] for a in self.mutations()], ['-A'])

    def test_source_restart_after_add_never_deletes_new_epoch_rule(self):
        self.s['rule'] = False
        self.s['source_restart_after_add'] = True
        self.run_case(False)
        self.assertTrue(self.s['rule'])
        self.assertEqual([a[5] for a in self.mutations()], ['-A'])

    def test_concurrent_foreign_rule_survives_own_rollback(self):
        self.s['rule'] = False
        self.s['foreign_rule_after_add'] = True
        self.s['collector_restart_after_add'] = True
        self.run_case(False)
        self.assertTrue(self.s['rule'])
        deletes = [a for a in self.mutations() if a[5] == '-D']
        self.assertEqual(len(deletes), 1)
        self.assertIn('--comment', deletes[0])

    def test_foreign_candidate_rejected_before_any_mutation(self):
        c = json.loads(json.dumps(self.s['template']))
        c['Id'] = 'd' * 64
        c['Name'] = '/' + ACTIVE + '-route-candidate'
        self.s['containers'].append(c)
        self.run_case(False)
        self.assertEqual(self.mutations(), [])

    def test_bootstrap_scope_and_mount_are_required(self):
        self.s['containers'][1]['Config']['Env'].append('AMNEZIA_CLIENT_LOGS_BOOTSTRAP=0')
        self.run_case(False)
        self.assertEqual(self.mutations(), [])

    def test_orphan_valid_candidate_can_finish_activation(self):
        self.s['containers'] = [self.s['containers'][0]]
        c = json.loads(json.dumps(self.s['template']))
        c['Id'] = 'c' * 64
        c['Name'] = '/' + ACTIVE + '-route-candidate'
        c['Config']['Labels'] = {'org.amnezia.serverx-diagnostic-route': 'awg2-v1'}
        self.s['containers'].append(c)
        self.run_case()
        self.assertEqual(self.mutations(), [['rename', 'c' * 64, ACTIVE]])


if __name__ == '__main__':
    unittest.main()
