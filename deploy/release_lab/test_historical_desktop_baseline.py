"""Historical baseline pinning tests with real Ed25519 verification in process."""
import base64
import hashlib
import json
import subprocess
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key

try:
    from . import lab
except ImportError:
    import lab


class HistoricalDesktopBaselineTests(unittest.TestCase):
    def setUp(self):
        stack = self.enterContext(ExitStack())
        archive = Path(stack.enter_context(tempfile.TemporaryDirectory()))
        metadata = archive / "metadata"
        metadata.mkdir()
        self.manifest = metadata / "manifest.json"
        self.archive_key = metadata / "selfhosted-update-public.pem"
        self.candidate_key = metadata / "candidate-public.pem"
        key = Ed25519PrivateKey.generate()
        self.archive_key.write_bytes(key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
        self.candidate_key.write_bytes(Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
        archived = {platform: (filename, len(platform.encode()))
                    for platform, (filename, _) in lab._HISTORICAL_DESKTOP_BASELINE_OTHER_ARTIFACTS.items()}
        stack.enter_context(patch.object(lab, "_HISTORICAL_DESKTOP_BASELINE_OTHER_ARTIFACTS", archived))
        names = {platform: filename for platform, (filename, _) in archived.items()}
        names.update({"windows-x64": "windows", "linux-x64": "linux"})
        self.paths = {platform: archive / filename for platform, filename in names.items()}
        for platform, path in self.paths.items():
            path.write_text(platform, encoding="utf-8")
        records = {platform: lab.artifact_record(path) for platform, path in self.paths.items()}
        self.desktop = {platform: records[platform] for platform in lab._HISTORICAL_DESKTOP_BASELINE_PLATFORMS}
        payload = json.dumps({"version": "5.0.3.18", "autoInstall": True, "platforms": {
            platform: {"sha256": record["sha256"], "size": record["size"], "autoInstall": True}
            for platform, record in records.items()
        }}).encode()
        self.manifest.write_text(json.dumps({
            "schema": "amnezia-selfhosted-update-v1", "signatureAlgorithm": "Ed25519",
            "payload": base64.urlsafe_b64encode(payload).decode().rstrip("="),
            "signature": base64.b64encode(key.sign(payload)).decode(),
        }), encoding="utf-8")
        stack.enter_context(patch.object(lab, "_HISTORICAL_DESKTOP_BASELINE_MANIFEST", hashlib.sha256(self.manifest.read_bytes()).hexdigest()))
        stack.enter_context(patch.object(lab, "_HISTORICAL_DESKTOP_BASELINE_KEY", hashlib.sha256(self.archive_key.read_bytes()).hexdigest()))
        stack.enter_context(patch.object(lab, "resolve_host_executable", return_value="fixture-openssl"))
        self.verifier = stack.enter_context(patch.object(lab.subprocess, "run", side_effect=self.verify))

    @staticmethod
    def verify(args, **kwargs):
        key = load_pem_public_key(Path(args[args.index("-inkey") + 1]).read_bytes())
        signature = Path(args[args.index("-sigfile") + 1]).read_bytes()
        payload = Path(args[args.index("-in") + 1]).read_bytes()
        try:
            key.verify(signature, payload)
        except InvalidSignature:
            return subprocess.CompletedProcess(args, 1, "", "invalid signature")
        return subprocess.CompletedProcess(args, 0, "", "")

    def check(self, **kwargs):
        options = {"lane": "candidate", "version": "5.0.3.18", "candidate_version": "5.0.3.19", "artifacts": self.desktop}
        lab.validate_baseline_manifest(self.manifest, self.candidate_key, **(options | kwargs))

    def test_authenticates_full_archive_with_independent_key(self):
        self.check()
        self.verifier.assert_called_once()

    def test_candidate_still_requires_exact_platform_set(self):
        with self.assertRaisesRegex(lab.LabError, "platform set"):
            lab.validate_signed_manifest(self.manifest, self.archive_key, version="5.0.3.18", artifacts=self.desktop)

    def test_never_used_for_release_headless_or_other_upgrade_versions(self):
        for overrides in (
            {"lane": "release"},
            {"candidate_version": "5.0.3.20"},
            {"artifacts": self.desktop | {"linux-headless-x64": lab.artifact_record(self.paths["linux-headless-x64"])}},
        ):
            with self.subTest(overrides=overrides), self.assertRaisesRegex(lab.LabError, "platform set"):
                self.check(**overrides)
        self.verifier.assert_not_called()

    def test_modified_envelope_does_not_get_the_historical_path(self):
        with self.manifest.open("ab") as stream:
            stream.write(b" ")
        with self.assertRaisesRegex(lab.LabError, "platform set"):
            self.check()

    def test_wrong_archived_key_rejected_even_if_candidate_key_is_available(self):
        self.archive_key.write_bytes(self.candidate_key.read_bytes())
        with self.assertRaisesRegex(lab.LabError, "pinned key"):
            self.check()

    def test_artifacts_for_unselected_platforms_are_verified(self):
        self.paths["android-arm64-v8a"].write_bytes(b"x" * len("android-arm64-v8a"))
        with self.assertRaisesRegex(lab.LabError, "metadata does not match.*android-arm64-v8a"):
            self.check()

    def test_wrong_size_extra_rejected_before_hashing(self):
        self.paths["android-arm64-v8a"].write_bytes(b"wrong size")
        with patch.object(lab, "artifact_record") as record:
            with self.assertRaisesRegex(lab.LabError, "size does not match.*android-arm64-v8a"):
                self.check()
            record.assert_not_called()

    def test_missing_extra_rejected_before_hashing(self):
        self.paths["android-arm64-v8a"].unlink()
        with patch.object(lab, "artifact_record") as record:
            with self.assertRaisesRegex(lab.LabError, "unavailable.*android-arm64-v8a"):
                self.check()
            record.assert_not_called()

    def test_directory_extra_rejected_before_hashing(self):
        artifact = self.paths["android-arm64-v8a"]
        artifact.unlink()
        artifact.mkdir()
        with patch.object(lab, "artifact_record") as record:
            with self.assertRaisesRegex(lab.LabError, "regular file.*android-arm64-v8a"):
                self.check()
            record.assert_not_called()

    def test_selected_bytes_not_replaced_by_archive_metadata(self):
        changed = self.desktop | {"windows-x64": self.desktop["windows-x64"] | {"sha256": "0" * 64}}
        with self.assertRaisesRegex(lab.LabError, "metadata does not match.*windows-x64"):
            self.check(artifacts=changed)

    def test_exact_pin_still_requires_valid_ed25519_signature(self):
        envelope = json.loads(self.manifest.read_bytes())
        envelope["signature"] = base64.b64encode(b"0" * 64).decode()
        self.manifest.write_text(json.dumps(envelope), encoding="utf-8")
        with patch.object(lab, "_HISTORICAL_DESKTOP_BASELINE_MANIFEST", hashlib.sha256(self.manifest.read_bytes()).hexdigest()):
            with self.assertRaisesRegex(lab.LabError, "Ed25519 verification failed"):
                self.check()
