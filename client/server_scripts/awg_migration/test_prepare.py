"""Pure configuration preservation tests; never invokes preparation/Docker."""
import json
import copy
import base64
import importlib
import sys
import types
import subprocess
import unittest
from unittest.mock import patch

try:
    import fcntl
except ImportError:
    # Windows unit tests import only the pure parser; no fake operational receipt.
    with patch.dict(sys.modules, {'fcntl': types.ModuleType('fcntl')}):
        prepare = importlib.import_module('prepare')
else:
    import prepare

PRIVATE = base64.b64encode(b'a' * 32).decode()
PUBLIC = base64.b64encode(b'b' * 32).decode()
PSK = base64.b64encode(b'c' * 32).decode()


def config(peer=PUBLIC, address='10.8.1.2/32'):
    return ('[Interface]\nPrivateKey = ' + PRIVATE + '\nAddress = 10.8.1.1/24\nListenPort = 51820\n'
            'PostUp = iptables old-operator-hook\n[Peer]\nPublicKey = ' + peer +
            '\nPresharedKey = ' + PSK + '\nAllowedIPs = ' + address + '\n').encode()


class ConfigTests(unittest.TestCase):
    def test_native_uapi_config_preserves_identity_and_fresh_parameters(self):
        interface, peers = prepare.parse_config(config())
        interface.pop('PostUp')
        interface.update(MTU='1420', HeaderProtectionKey=PSK, S1='16', S2='17', S3='18', S4='19',
                         RandomTrailers='false', DisableCookies='true')
        text = prepare.native_config(interface, peers)
        self.assertNotIn('Address =', text)
        self.assertNotIn('MTU =', text)
        for field, value in [('PrivateKey', PRIVATE), ('PublicKey', PUBLIC), ('PresharedKey', PSK),
                             ('HeaderProtectionKey', PSK), ('S1', '16'), ('S2', '17'), ('S3', '18'), ('S4', '19')]:
            self.assertIn(field + ' = ' + value + '\n', text)
        self.assertIn('AllowedIPs = 10.8.1.2/32\n', text)
        self.assertIn('RandomTrailers = 0\n', text)
        self.assertIn('DisableCookies = 1\n', text)
        self.assertEqual('false', interface['RandomTrailers'])

    def test_only_dependency_fetch_and_owned_lock_contention_are_retryable(self):
        for command in (['docker', 'pull', 'pinned'], ['docker', 'build', 'private-context']):
            error = subprocess.CalledProcessError(1, command, output=b'private', stderr=b'secret')
            self.assertEqual('migration_dependency_unavailable', prepare.transient_failure_reason(error))
            self.assertEqual('migration_dependency_unavailable', prepare.transient_failure_reason(subprocess.TimeoutExpired(command, 180)))
        for command in (['docker', 'run', 'pinned'], ['docker', 'exec', 'source'], ['openssl', 'pkey'], 'docker build'):
            self.assertIsNone(prepare.transient_failure_reason(subprocess.CalledProcessError(1, command)))
        self.assertIsNone(prepare.transient_failure_reason(ValueError('trusted_image_unavailable')))
        self.assertEqual('migration_busy', prepare.transient_failure_reason(BlockingIOError()))

    def test_identity_and_psk_preserved(self):
        interface, peers = prepare.parse_config(config())
        self.assertEqual(PRIVATE, interface['PrivateKey'])
        self.assertEqual(PUBLIC, peers[0]['PublicKey'])
        self.assertEqual(PSK, peers[0]['PresharedKey'])
        self.assertEqual('10.8.1.2/32', peers[0]['AllowedIPs'])

    def test_ambiguous_or_foreign_routes_fail_closed(self):
        for address in ('10.8.1.0/24', '10.9.1.2/32', '10.8.1.1/32', '10.8.1.2/32, 10.8.1.3/32'):
            with self.subTest(address=address), self.assertRaises(ValueError):
                prepare.parse_config(config(address=address))

    def test_duplicate_peer_and_unknown_peer_fields_rejected(self):
        for suffix in (b'[Peer]\nPublicKey = ' + PUBLIC.encode() + b'\nAllowedIPs = 10.8.1.3/32\n',
                       b'Endpoint = evil.example:1\n'):
            with self.assertRaises(ValueError):
                prepare.parse_config(config() + suffix)




class NetworkTopologyTests(unittest.TestCase):
    def fixture(self):
        networks = {}
        endpoints = {}
        addresses = []
        for name, iface, subnet, ip, gateway in [('amnezia-dns-net', 'eth0', '172.29.172.0/24', '172.29.172.2', '172.29.172.1'), ('bridge', 'eth1', '172.17.0.0/16', '172.17.0.2', '172.17.0.1')]:
            prefix = int(subnet.split('/')[1])
            networks[name] = {'Name': name, 'Id': name+'-id', 'Driver': 'bridge', 'Scope': 'local', 'Internal': False, 'EnableIPv6': False, 'IPAM': {'Config': [{'Subnet': subnet, 'Gateway': gateway}]}}
            endpoints[name] = {'NetworkID': name+'-id', 'IPAddress': ip, 'Gateway': gateway, 'IPPrefixLen': prefix}
            addresses.append({'ifname': iface, 'addr_info': [{'family': 'inet', 'local': ip, 'prefixlen': prefix}]})
        routes = [{'dst': 'default', 'dev': 'eth0', 'gateway': '172.29.172.1'}]
        return networks, endpoints, addresses, routes

    def runner(self, values, version='29.0.0'):
        networks, endpoints, addresses, routes = values
        def run(*args):
            if args[:2] == ('docker', 'version'): return version.encode()
            if args[:2] == ('docker', 'inspect'): return json.dumps([{'NetworkSettings': {'Networks': endpoints}}]).encode()
            if args[:3] == ('docker', 'network', 'inspect'): return json.dumps([networks[args[3]]]).encode()
            if 'address' in args: return json.dumps(addresses).encode()
            if 'route' in args: return json.dumps(routes).encode()
            raise AssertionError(args)
        return run

    def test_observed_dns_default_eth0_not_assumed_bridge(self):
        binding = {}
        options = prepare.source_network_options(self.runner(self.fixture()), 'source', binding)
        self.assertEqual(binding['amnezia-dns-net'], {'networkId': 'amnezia-dns-net-id', 'interface': 'eth0', 'default': True})
        self.assertEqual(options, ['--network', 'name=amnezia-dns-net,driver-opt=com.docker.network.endpoint.ifname=eth0,gw-priority=1', '--network', 'name=bridge,driver-opt=com.docker.network.endpoint.ifname=eth1,gw-priority=0'])

    def test_stock_one_bridge_does_not_add_dns_network(self):
        networks, endpoints, addresses, routes = self.fixture()
        del networks['amnezia-dns-net']; del endpoints['amnezia-dns-net']
        addresses = [addresses[1]]; addresses[0]['ifname'] = 'eth0'
        routes = [{'dst': 'default', 'dev': 'eth0', 'gateway': '172.17.0.1'}]
        self.assertEqual(prepare.source_network_options(self.runner((networks, endpoints, addresses, routes)), 'source'), ['--network', 'name=bridge,driver-opt=com.docker.network.endpoint.ifname=eth0,gw-priority=1'])

    def test_standard_bridge_eth0_dns_eth1(self):
        networks, endpoints, addresses, routes = self.fixture()
        addresses[0]['ifname'] = 'eth1'; addresses[1]['ifname'] = 'eth0'
        routes[0]['gateway'] = '172.17.0.1'
        options = prepare.source_network_options(self.runner((networks, endpoints, addresses, routes)), 'source')
        self.assertIn('name=bridge,driver-opt=com.docker.network.endpoint.ifname=eth0,gw-priority=1', options)
        self.assertIn('name=amnezia-dns-net,driver-opt=com.docker.network.endpoint.ifname=eth1,gw-priority=0', options)

    def test_reject_ambiguous_unknown_incompatible_topology(self):
        for change in ('duplicate_ip', 'unknown_iface', 'extra_network', 'two_defaults', 'wrong_gateway', 'wrong_driver', 'wrong_id'):
            values = self.fixture()
            networks, endpoints, addresses, routes = values
            if change == 'duplicate_ip': addresses.append(copy.deepcopy(addresses[0]))
            if change == 'unknown_iface': addresses[0]['ifname'] = 'eth2'
            if change == 'extra_network': endpoints['unknown'] = {}
            if change == 'two_defaults': routes.append(copy.deepcopy(routes[0]))
            if change == 'wrong_gateway': routes[0]['gateway'] = '172.17.0.1'
            if change == 'wrong_driver': networks['bridge']['Driver'] = 'host'
            if change == 'wrong_id': endpoints['bridge']['NetworkID'] = 'wrong'
            with self.subTest(change=change), self.assertRaises(ValueError):
                prepare.source_network_options(self.runner(values), 'source')
        with self.assertRaises(ValueError):
            prepare.source_network_options(self.runner(self.fixture(), '27.5.1'), 'source')

class StoppedTargetNetworkTests(unittest.TestCase):
    def test_record_attach_identity_check_then_start(self):
        binding = {'bridge': {'networkId': 'bridge-id', 'interface': 'eth1', 'default': False}, 'amnezia-dns-net': {'networkId': 'dns-id', 'interface': 'eth0', 'default': True}}
        events = []
        journal = types.SimpleNamespace(value={'containers': {'target': {'id': None}}})
        def record(name):
            events.append(('record', name)); journal.value['containers'][name]['id'] = 'owned-id'
        journal.record = record
        def run(*args):
            events.append(args)
            if args[:2] == ('docker', 'inspect'):
                return json.dumps([{'Id': 'owned-id', 'State': {'Status': 'created', 'Pid': 0, 'Running': False, 'StartedAt': '0001-01-01T00:00:00Z'}, 'HostConfig': {'NetworkMode': 'bridge'}, 'NetworkSettings': {'Networks': {name: {'NetworkID': '', 'DriverOpts': {'com.docker.network.endpoint.ifname': role['interface']}, 'GwPriority': int(role['default'])} for name, role in binding.items()}}}]).encode()
            if args[:3] == ('docker', 'network', 'inspect'): return json.dumps([{'Id': binding[args[3]]['networkId']}]).encode()
            return b''
        def capture(run, source, observed): observed.update(binding)
        with patch.object(prepare, 'source_network_options', capture):
            prepare.start_target_networks(run, journal, 'target', 'source', binding)
        self.assertEqual(events[0], ('record', 'target'))
        self.assertEqual(events[1], ('docker', 'network', 'connect', '--driver-opt', 'com.docker.network.endpoint.ifname=eth0', '--gw-priority', '1', 'amnezia-dns-net', 'owned-id'))
        self.assertEqual(events[-1], ('docker', 'start', 'owned-id'))

    def test_replaced_network_identity_blocks_start(self):
        binding = {'bridge': {'networkId': 'original-id', 'interface': 'eth0', 'default': True}}
        journal = types.SimpleNamespace(value={'containers': {'target': {'id': None}}})
        journal.record = lambda name: journal.value['containers'][name].update(id='owned-id')
        calls = []
        def run(*args):
            calls.append(args)
            return json.dumps([{'NetworkSettings': {'Networks': {'bridge': {'NetworkID': 'replacement-id'}}}}]).encode()
        def capture(run, source, observed): observed.update(binding)
        with patch.object(prepare, 'source_network_options', capture), self.assertRaises(ValueError):
            prepare.start_target_networks(run, journal, 'target', 'source', binding)
        self.assertFalse(any(call[:2] == ('docker', 'start') for call in calls))

    def test_pending_metadata_requires_closed_created_state(self):
        binding = {'bridge': {'networkId': 'bridge-id', 'interface': 'eth0', 'default': True}}
        for variant in ('wrong_id', 'wrong_driver_opts', 'wrong_priority', 'running', 'pid', 'started', 'global_drift', 'extra_endpoint', 'partial_ip', 'poststart_role_drift'):
            journal = types.SimpleNamespace(value={'containers': {'target': {'id': None}}})
            journal.record = lambda name: journal.value['containers'][name].update(id='owned-id')
            metadata = {'Id': 'owned-id', 'State': {'Status': 'created', 'Pid': 0, 'Running': False, 'StartedAt': '0001-01-01T00:00:00Z'}, 'HostConfig': {'NetworkMode': 'bridge'}, 'NetworkSettings': {'Networks': {'bridge': {'NetworkID': '', 'DriverOpts': {'com.docker.network.endpoint.ifname': 'eth0'}, 'GwPriority': 1}}}}
            endpoint = metadata['NetworkSettings']['Networks']['bridge']
            if variant == 'wrong_id': endpoint['NetworkID'] = 'wrong'
            if variant == 'wrong_driver_opts': endpoint['DriverOpts'] = {'com.docker.network.endpoint.ifname': 'eth1'}
            if variant == 'wrong_priority': endpoint['GwPriority'] = 0
            if variant == 'running': metadata['State']['Status'] = 'running'; metadata['State']['Running'] = True
            if variant == 'pid': metadata['State']['Pid'] = 9
            if variant == 'started': metadata['State']['StartedAt'] = '2026-01-01T00:00:00Z'
            if variant == 'extra_endpoint': metadata['NetworkSettings']['Networks']['unknown'] = {}
            if variant == 'partial_ip': endpoint['IPAddress'] = '172.17.0.2'
            calls = []
            def run(*args):
                calls.append(args)
                if args[:2] == ('docker', 'inspect'): return json.dumps([metadata]).encode()
                if args[:3] == ('docker', 'network', 'inspect'): return json.dumps([{'Id': 'wrong' if variant == 'global_drift' else 'bridge-id'}]).encode()
                return b''
            def capture(run, source, observed):
                observed.update(binding)
                if source == 'owned-id' and variant == 'poststart_role_drift': observed['bridge'] = dict(binding['bridge'], interface='eth1')
            with self.subTest(variant=variant), patch.object(prepare, 'source_network_options', capture), self.assertRaises(ValueError):
                prepare.start_target_networks(run, journal, 'target', 'source', binding)
            if variant != 'poststart_role_drift':
                self.assertFalse(any(call[:2] == ('docker', 'start') for call in calls))

    def test_attach_failure_never_starts_and_owned_id_recorded(self):
        binding = {'amnezia-dns-net': {'networkId': 'dns-id', 'interface': 'eth0', 'default': True}}
        journal = types.SimpleNamespace(value={'containers': {'target': {'id': None}}})
        journal.record = lambda name: journal.value['containers'][name].update(id='owned-id')
        def run(*args): raise subprocess.CalledProcessError(125, args)
        with self.assertRaises(subprocess.CalledProcessError):
            prepare.start_target_networks(run, journal, 'target', 'source', binding)
        self.assertEqual(journal.value['containers']['target']['id'], 'owned-id')

if __name__ == '__main__':
    unittest.main()
