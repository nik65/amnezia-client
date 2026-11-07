import json
from pathlib import Path
import tempfile
import unittest
from .automatic_migration_fixture_network import POLICY, NETWORK, bind, validate


class FixtureNetworkTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.policy = self.root / 'policy.json'
        self.profile = self.root / 'server-router.json'
        self.ready = self.root / 'golden.json'
        self.marker = self.root / '.owned-overlay.json'
        self.policy.write_text(json.dumps(POLICY))
        self.profile.write_text('{"id":"server-router"}')
        self.ready.write_text(json.dumps({'base_sha256': 'a' * 64}))
        self.marker.write_text(json.dumps({'run_id': 'test-run', 'profile': 'server-router',
                                         'overlay': str(self.root / 'overlay.qcow2')}))
        import hashlib
        self.run = {'run_id': 'test-run', 'lane': 'publisher-diagnostic'}
        self.run['automatic_migration_wan'] = bind('test-run', 'publisher-diagnostic', self.policy,
            {'sha256': hashlib.sha256(self.profile.read_bytes()).hexdigest()}, 'a' * 64)

    def check(self, profile='server-router'):
        return validate(self.run, profile, self.policy, self.profile, self.ready, self.marker)

    def test_explicit_diagnostic_guest_egress_without_host_forward(self):
        self.assertTrue(self.check())
        self.assertIn('user,id=labnet,restrict=off', NETWORK)
        self.assertFalse(any('hostfwd' in item for item in NETWORK))

    def test_ordinary_product_lanes_and_unflagged_runs_unchanged(self):
        self.assertFalse(self.check('linux-headless-x64'))
        self.run.pop('automatic_migration_wan')
        self.assertFalse(self.check())

    def test_reject_release_lane_even_with_copied_record(self):
        self.run['lane'] = 'release'
        with self.assertRaises(ValueError): self.check()

    def test_run_profile_golden_policy_marker_tamper_rejected(self):
        for path in (self.profile, self.ready, self.policy, self.marker):
            original = path.read_bytes()
            path.write_text('{}')
            with self.assertRaises((ValueError, KeyError)): self.check()
            path.write_bytes(original)
        self.run['run_id'] = 'other-run'
        with self.assertRaises(ValueError): self.check()

    def test_symlink_marker_rejected(self):
        try:
            self.marker.unlink()
            self.marker.symlink_to(self.policy)
        except OSError:
            self.skipTest('symlink unavailable')
        with self.assertRaises(ValueError): self.check()


if __name__ == '__main__': unittest.main()
