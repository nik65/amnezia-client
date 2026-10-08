import copy
import importlib.util
from pathlib import Path
import subprocess
import sys
import types
import json
import unittest
from unittest.mock import patch

if sys.platform == 'win32':
    sys.modules.setdefault('fcntl', types.SimpleNamespace())
spec = importlib.util.spec_from_file_location('collector_route', Path(__file__).with_name('collector_route.py'))
route = importlib.util.module_from_spec(spec)
spec.loader.exec_module(route)


class RouteTests(unittest.TestCase):
    def setUp(self):
        self.binding = {'schema': 1, 'scope': 'amnezia-awg2', 'sourceId': 'a' * 64, 'collectorId': 'b' * 64}
        self.source = {'Id': 'a' * 64, 'Name': '/amnezia-awg2',
                       'State': {'Running': True, 'Pid': 11, 'StartedAt': 'epoch1'}}
        self.collector = {'Id': 'b' * 64, 'Name': '/amnezia-client-logs-amnezia-awg2',
                          'State': {'Running': True, 'Pid': 12},
                          'Config': {'Image': route.IMAGE, 'Labels': {route.LABEL: 'amnezia-awg2'}},
                          'HostConfig': {'NetworkMode': 'container:' + 'a' * 64},
                          'Mounts': [{'Destination': '/data', 'Source': str(route.ROOT), 'RW': True}]}
        self.calls = []
        self.net = {'a' * 64: 'net1', 'b' * 64: 'net1'}
        self.present = True

    def run_reconcile(self, mutate=None):
        def command(args):
            self.calls.append(args)
            if args[:2] == ['docker', 'restart']:
                self.net['b' * 64] = 'net1'
                self.collector['State'] = {'Running': True, 'Pid': 13}
            if mutate:
                mutate(args)
            return b''
        with patch.object(route, 'inspect', side_effect=lambda key: copy.deepcopy(self.source if key == 'a' * 64 else self.collector)), \
             patch.object(route, 'namespace', side_effect=lambda obj: self.net[obj['Id']]), \
             patch.object(route, 'command', side_effect=command), \
             patch.object(route.subprocess, 'run', return_value=types.SimpleNamespace(returncode=0 if self.present else 1)):
            route.reconcile(self.binding)

    def test_existing_rule_no_restart_or_add(self):
        self.run_reconcile()
        self.assertFalse(any('-A' in call or 'restart' in call for call in self.calls))

    def test_namespace_recreation_restarts_only_owned_collector_and_restores_exact_rule(self):
        self.net['b' * 64] = 'oldnet'
        self.present = False
        self.run_reconcile()
        self.assertIn(['docker', 'restart', 'b' * 64], self.calls)
        adds = [call for call in self.calls if '-A' in call]
        self.assertEqual(len(adds), 1)
        self.assertEqual(adds[0][2], 'a' * 64)
        self.assertIn('17866', adds[0])
        self.assertFalse(any('-D' in call or '-F' in call for call in self.calls))

    def test_foreign_label_refuses_before_any_command(self):
        self.collector['Config']['Labels'] = {}
        with self.assertRaises(ValueError):
            self.run_reconcile()
        self.assertEqual(self.calls, [])

    def test_source_replacement_refuses(self):
        self.source['Id'] = 'c' * 64
        with self.assertRaises(ValueError):
            self.run_reconcile()
        self.assertEqual(self.calls, [])

    def test_final_source_epoch_drift_not_reported_healthy(self):
        def mutate(args):
            if '-C' in args:
                self.source['State']['StartedAt'] = 'epoch2'
        with self.assertRaisesRegex(ValueError, 'final namespace drift'):
            self.run_reconcile(mutate)

    def test_wrong_mount_and_network_refused(self):
        for field in ('mount', 'network'):
            with self.subTest(field=field):
                collector = copy.deepcopy(self.collector)
                if field == 'mount':
                    collector['Mounts'][0]['Source'] = '/foreign'
                else:
                    collector['HostConfig']['NetworkMode'] = 'bridge'
                with self.assertRaises(ValueError):
                    route.validate(self.source, collector, self.binding)

    def test_malformed_binding_refuses_before_inspect(self):
        self.binding['sourceId'] = 'invalid'
        with patch.object(route, 'inspect') as inspect:
            with self.assertRaises(ValueError):
                route.reconcile(self.binding)
            inspect.assert_not_called()

    def test_stopped_owned_collector_restarted(self):
        self.collector['State'] = {'Running': False, 'Pid': 0}
        self.net['b' * 64] = None
        self.run_reconcile()
        self.assertIn(['docker', 'restart', 'b' * 64], self.calls)

    def test_readback_failure_rolls_back_only_new_rule_in_same_epoch(self):
        self.present = False
        def mutate(args):
            if '-C' in args:
                raise subprocess.CalledProcessError(1, args)
        with self.assertRaises(subprocess.CalledProcessError):
            self.run_reconcile(mutate)
        deletes = [args for args in self.calls if '-D' in args]
        self.assertEqual(len(deletes), 1)
        self.assertEqual(deletes[0][2], 'a' * 64)

    def test_readback_failure_never_deletes_preexisting_rule(self):
        def mutate(args):
            if '-C' in args:
                raise subprocess.CalledProcessError(1, args)
        with self.assertRaises(subprocess.CalledProcessError):
            self.run_reconcile(mutate)
        self.assertFalse(any('-D' in args for args in self.calls))

    def test_wrong_image_refuses_before_commands(self):
        self.collector['Config']['Image'] = 'untrusted:latest'
        with self.assertRaises(ValueError):
            self.run_reconcile()
        self.assertEqual(self.calls, [])

    def publisher_guard(self, collector):
        source = Path(__file__).parents[2] / 'core/controllers/selfhosted/exportController.cpp'
        guard = source.read_text(encoding='utf-8').split("<<'ROUTE_GUARD'", 1)[1].split('\n', 1)[1].split('\nROUTE_GUARD', 1)[0]
        for key, value in {'__VPN_CONTAINER__': 'amnezia-awg2', '__TUNNEL_CONTAINER__': 'amnezia-client-logs-amnezia-awg2',
                           '__COLLECTOR_IMAGE__': route.IMAGE, '__HOST_DIRECTORY__': '/opt/amnezia/client-logs', '__CONTAINER_SCOPE__': 'amnezia-awg2'}.items():
            guard = guard.replace(key, value)
        def command(args, **kwargs):
            if args[1] == 'ps':
                value = b'amnezia-client-logs-amnezia-awg2\n'
            else:
                selected = copy.deepcopy(self.source if args[2] == 'amnezia-awg2' else collector)
                if 'Mounts' in selected:
                    selected['Mounts'][0]['Source'] = '/opt/amnezia/client-logs'
                value = json.dumps([selected]).encode()
            return types.SimpleNamespace(stdout=value)
        with patch.object(subprocess, 'run', side_effect=command):
            exec(compile(guard, '<publisher ownership guard>', 'exec'), {})

    def test_publisher_accepts_only_known_legacy_or_owned_collector(self):
        self.collector['Config'].update(Entrypoint=['python'], Cmd=['/data/collector.py'],
                                        Env=['AMNEZIA_CLIENT_LOGS_SCOPE=amnezia-awg2'])
        self.publisher_guard(self.collector)
        legacy = copy.deepcopy(self.collector)
        legacy['Config']['Labels'] = {}
        self.publisher_guard(legacy)
        for fault in ('scope', 'label', 'image', 'entrypoint', 'network'):
            candidate = copy.deepcopy(legacy)
            if fault == 'scope': candidate['Config']['Env'] = []
            elif fault == 'label': candidate['Config']['Labels'] = {route.LABEL: 'foreign'}
            elif fault == 'image': candidate['Config']['Image'] = 'foreign:latest'
            elif fault == 'entrypoint': candidate['Config']['Entrypoint'] = ['sh']
            else: candidate['HostConfig']['NetworkMode'] = 'container:' + 'c' * 64
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                self.publisher_guard(candidate)


if __name__ == '__main__':
    unittest.main()
