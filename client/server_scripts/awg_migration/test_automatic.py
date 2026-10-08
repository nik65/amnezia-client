"""Automatic allocation/retry tests; no Docker or server operations."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from automatic import occupied_udp_ports, plan, select_port


class AutomaticTests(unittest.TestCase):
    def test_host_udp_and_docker_nat_collisions(self):
        def run(*args):
            if args[0] == 'ss':
                return b'UNCONN 0 0 0.0.0.0:51821 0.0.0.0:*\nudp UNCONN 0 0 [::]:51822 [::]:*\n'
            if args == ('docker', 'ps', '-q'):
                return b'container-a\n'
            return json.dumps([{'NetworkSettings': {'Ports': {'51823/udp': [{'HostPort': '51823'}],
                                                            '51824/tcp': [{'HostPort': '51824'}]}}}]).encode()
        ports = occupied_udp_ports(run)
        self.assertEqual({51821, 51822, 51823}, ports)
        self.assertEqual(51825, select_port(ports, 51824))

    def test_initial_plan_and_unsupported_endpoint(self):
        with tempfile.TemporaryDirectory() as directory:
            result = plan(Path(directory), 'amnezia-awg2', 'vpn.example', 'pinned', b'source', 51820, {51821})
            self.assertEqual(51822, result['port'])
            self.assertEqual(1, result['generation'])
            with self.assertRaisesRegex(ValueError, 'migration_endpoint_unsupported'):
                plan(Path(directory), 'amnezia-awg2', '2001:db8::1', 'pinned', b'source', 51820, set())

    def test_ready_reuses_port_and_generation_and_rejects_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            generation = root / 'amnezia-awg2' / '1'
            generation.mkdir(parents=True)
            request = {'image': 'pinned', 'host': 'vpn.example', 'port': 51822, 'generation': 1}
            (generation / 'transaction.json').write_text(json.dumps({'phase': 'ready', 'request': request,
                'sourceDigest': hashlib.sha256(b'source').hexdigest()}))
            # Already-owned listener is expected occupied; no fresh allocation.
            self.assertEqual(request, plan(root, 'amnezia-awg2', 'vpn.example', 'pinned', b'source', 51820, {51822}))
            for host, image, raw in [('other.example', 'pinned', b'source'),
                                     ('vpn.example', 'changed', b'source'), ('vpn.example', 'pinned', b'changed')]:
                with self.assertRaisesRegex(ValueError, 'migration_ready_drift'):
                    plan(root, 'amnezia-awg2', host, image, raw, 51820, set())

    def test_incomplete_generation_one_retry_and_no_silent_rotation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            generation = root / 'amnezia-awg2' / '1'
            generation.mkdir(parents=True)
            (generation / 'transaction.json').write_text('{"phase":"creating"}')
            self.assertEqual(1, plan(root, 'amnezia-awg2', 'vpn.example', 'pinned', b'source', 51820, set())['generation'])
            generation.rename(generation.with_name('2'))
            with self.assertRaisesRegex(ValueError, 'migration_journal_conflict'):
                plan(root, 'amnezia-awg2', 'vpn.example', 'pinned', b'source', 51820, set())

    def test_exhausted_range_fails_closed(self):
        with self.assertRaisesRegex(ValueError, 'migration_udp_port_unavailable'):
            select_port(set(range(51821, 65536)), 51820)


if __name__ == '__main__':
    unittest.main()
