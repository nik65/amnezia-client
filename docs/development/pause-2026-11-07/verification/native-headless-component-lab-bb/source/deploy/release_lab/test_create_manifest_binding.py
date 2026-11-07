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


def write_signed_manifest(root, artifact, version, platform, *, extra=None, name='manifest.json'):
    key = Ed25519PrivateKey.generate()
    public = root / (name + '.public.pem')
    public.write_bytes(key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
    record = lab.artifact_record(artifact)
    payload = {'version': version, 'autoInstall': True, 'platforms': {platform: {'autoInstall': True, 'sha256': record['sha256'], 'size': record['size'], 'url': 'http://172.29.172.252:17865/fixture'}}}
    payload.update(extra or {})
    raw = json.dumps(payload, separators=(',', ':')).encode()
    envelope = {'schema': 'amnezia-selfhosted-update-v1', 'signatureAlgorithm': 'Ed25519', 'payload': base64.urlsafe_b64encode(raw).decode().rstrip('='), 'signature': base64.b64encode(key.sign(raw)).decode()}
    manifest = root / name; manifest.write_text(json.dumps(envelope))
    return manifest, public


def windows_openssl(test):
    """Use an actual local verifier for hermetic Windows tests, without bypassing crypto."""
    import os
    if os.name != 'nt':
        return
    executable = pathlib.Path('C:/Program Files/Git/usr/bin/openssl.exe')
    if not executable.is_file():
        test.skipTest('actual Windows OpenSSL verifier is unavailable')
    original = lab.resolve_host_executable
    resolver = patch.object(lab, 'resolve_host_executable', side_effect=lambda name: str(executable) if name == 'openssl' else original(name))
    resolver.start(); test.addCleanup(resolver.stop)


class CreateManifestBindingTests(unittest.TestCase):
    def setUp(self):
        windows_openssl(self)
    def test_signed_manifest_missing_selected_linux_rejected_before_guest_state(self):
        self.reject_mismatch(candidate_platform='windows-x64')

    def test_signed_baseline_missing_selected_linux_rejected_before_guest_state(self):
        self.reject_mismatch(baseline_platform='windows-x64')

    def test_valid_signed_linux_scoped_manifests_create_only_test_owned_state(self):
        self.reject_mismatch(valid=True)

    def test_full_signed_inventory_hyperv_metadata_create_with_unavailable_kvm(self):
        import errno
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            artifacts = {}; baseline = {}
            for platform in lab.RELEASE_PLATFORM_IDS:
                artifacts[platform] = root / (platform + '.candidate')
                baseline[platform] = root / (platform + '.baseline')
                artifacts[platform].write_bytes(('candidate-' + platform).encode())
                baseline[platform].write_bytes(('baseline-' + platform).encode())
            signing_key = Ed25519PrivateKey.generate()
            public = root / 'public.pem'
            public.write_bytes(signing_key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
            def signed_inventory(name, version, files):
                platforms = {}
                for platform, path in files.items():
                    record = lab.artifact_record(path)
                    platforms[platform] = {'autoInstall': True, 'sha256': record['sha256'],
                                           'size': record['size'], 'url': 'http://172.29.172.252:17865/fixture'}
                raw = json.dumps({'version': version, 'autoInstall': True, 'platforms': platforms}, separators=(',', ':')).encode()
                envelope = {'schema': 'amnezia-selfhosted-update-v1', 'signatureAlgorithm': 'Ed25519',
                            'payload': base64.urlsafe_b64encode(raw).decode().rstrip('='),
                            'signature': base64.b64encode(signing_key.sign(raw)).decode()}
                path = root / name; path.write_text(json.dumps(envelope))
                return path
            manifest = signed_inventory('candidate.json', '5.0.3.11', artifacts)
            old_manifest = signed_inventory('baseline.json', '5.0.3.10', baseline)
            outer = root / 'outer.exe'; outer.write_bytes(b'candidate outer')
            old_outer = root / 'old-outer.exe'; old_outer.write_bytes(b'baseline outer')
            receipt = root / 'headless.json'; receipt.write_text('{}')
            controller = lab.LabController(root / 'lab', test_mode=False, windows_backend='hyperv')
            ownership = self.enterContext(patch.object(lab, 'assert_lab_identity'))
            if not hasattr(lab.os, 'fchmod'):
                # POSIX ownership primitive only; retain the native Windows
                # mutation lock and the actual admission/signature path.
                self.enterContext(patch.object(lab.os, 'fchmod', create=True))
            failed = {'ready': False, 'stage': 'open', 'errno': errno.ENODEV}
            with patch.object(lab, 'probe_kvm_readiness', return_value=failed) as probing:
                run = controller.create('candidate', artifacts, outer, 'full-inventory', manifest,
                                        baseline, '5.0.3.10', '5.0.3.11', public,
                                        baseline_manifest=old_manifest, headless_baseline_receipt=receipt,
                                        headless_candidate_receipt=receipt, baseline_outer_artifact=old_outer)
            probing.assert_not_called()
            self.assertEqual(set(run['artifacts']), set(lab.RELEASE_PLATFORM_IDS))
            self.assertEqual(set(run['expected_profiles']), set(lab.AUTOMATED_PROFILE_IDS))
            self.assertFalse(any(controller.root.rglob('*.qcow2')))
            self.assertTrue(controller.state_path.is_file())
            state_before = controller.state_path.read_bytes()
            with patch.object(lab, 'probe_kvm_readiness', return_value=failed) as probing, \
                 patch.object(controller, '_recover_qemu_spawn_intent') as recovery, \
                 patch.object(lab, 'run_host') as host_command, \
                 patch.object(lab.subprocess, 'Popen') as launch:
                with self.assertRaisesRegex(lab.LabError, 'KVM API access unavailable'):
                    controller.start('full-inventory', 'linux-x64-gui')
            probing.assert_called_once_with()
            recovery.assert_not_called()
            host_command.assert_not_called()
            launch.assert_not_called()
            self.assertFalse(any(controller.root.rglob('*.qcow2')))
            self.assertFalse(any(controller.root.rglob('*.sock')))
            self.assertEqual(controller.state_path.read_bytes(), state_before)
            self.assertGreaterEqual(ownership.call_count, 2)

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
