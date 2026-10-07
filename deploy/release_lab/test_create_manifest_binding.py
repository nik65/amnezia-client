"""Hermetic create rejection before guest/state writes, using signed envelopes."""
import base64
import json
import pathlib
import tempfile
import unittest
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

REPO = pathlib.Path(__file__).resolve().parents[2]
try:
    from . import lab
except ImportError:
    import lab


class CreateManifestBindingTests(unittest.TestCase):
    def test_signed_manifest_missing_selected_linux_rejected_before_guest_state(self):
        self.reject_mismatch(candidate_platform='windows-x64')

    def test_signed_baseline_missing_selected_linux_rejected_before_guest_state(self):
        self.reject_mismatch(baseline_platform='windows-x64')

    def test_valid_signed_linux_scoped_manifests_create_only_test_owned_state(self):
        self.reject_mismatch(valid=True)

    def reject_mismatch(self, candidate_platform='linux-x64', baseline_platform='linux-x64', valid=False):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            artifact = root / 'candidate.run'; artifact.write_bytes(b'candidate installer fixture')
            baseline = root / 'baseline.run'; baseline.write_bytes(b'baseline installer fixture')
            outer = root / 'outer.exe'; outer.write_bytes(b'outer fixture')
            key = Ed25519PrivateKey.generate()
            public = root / 'public.pem'
            public.write_bytes(key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
            def manifest(name, version, platform, file):
                record = lab.artifact_record(file)
                payload = {'version': version, 'autoInstall': True, 'platforms': {platform: {'autoInstall': True, 'sha256': record['sha256'], 'size': record['size'], 'url': 'http://172.29.172.252:17865/fixture'}}}
                raw = json.dumps(payload, separators=(',', ':')).encode()
                envelope = {'schema': 'amnezia-selfhosted-update-v1', 'signatureAlgorithm': 'Ed25519', 'payload': base64.urlsafe_b64encode(raw).decode().rstrip('='), 'signature': base64.b64encode(key.sign(raw)).decode()}
                path = root / name; path.write_text(json.dumps(envelope))
                return path
            candidate_manifest = manifest('candidate.json', '5.0.3.5', candidate_platform, artifact)
            baseline_manifest = manifest('baseline.json', '5.0.3.4', baseline_platform, baseline)
            controller = lab.LabController(root / 'owned-lab', test_mode=True)
            with patch.object(controller, 'assert_mutation_context'), patch.object(lab, 'repo_root', return_value=REPO), patch.object(lab, 'profiles_root', return_value=REPO / 'deploy/release_lab/profiles'):
                kwargs = dict(run_id='missing-platform', baseline_artifacts={'linux-x64': baseline}, outer_artifact=outer, manifest=candidate_manifest, baseline_manifest=baseline_manifest, manifest_public_key=public, baseline_version='5.0.3.4', candidate_version='5.0.3.5')
                if valid:
                    controller.create('candidate', {'linux-x64': artifact}, **kwargs)
                else:
                    with self.assertRaisesRegex(lab.LabError, 'platform set does not exactly match'):
                        controller.create('candidate', {'linux-x64': artifact}, **kwargs)
            self.assertEqual((controller.root / 'runs' / 'missing-platform').exists(), valid)
            self.assertEqual(controller.state_path.exists(), valid)


if __name__ == '__main__':
    unittest.main()
