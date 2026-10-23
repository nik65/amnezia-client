"""Compatibility and checksum closure of the optional native installer helper."""
import hashlib
import importlib.util
import io
import json
import base64
from pathlib import Path
import tarfile
import subprocess
import tempfile
import unittest

MODULE_PATH = Path(__file__).parents[1] / "selfhosted_updates/make_manifest.py"
SPEC = importlib.util.spec_from_file_location("native_helper_manifest", MODULE_PATH)
manifest = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(manifest)


class NativeHelperBundleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.archive = Path(self.temporary.name) / "fixture.tar.gz"
        self.package = {
            "schema": 2, "version": "9.9.9.9", "platform": "linux-headless-x64",
            "installModes": ["fresh", "upgrade"],
            "artifacts": ["amneziad", "amnezia-cli", "amneziad.service"],
            "service": "amneziad.service",
            "servicePaths": ["/etc/systemd/system/amneziad.service", "/run/systemd/system/amneziad.service",
                             "/usr/local/lib/systemd/system/amneziad.service", "/usr/lib/systemd/system/amneziad.service",
                             "/lib/systemd/system/amneziad.service"],
            "trustAnchor": "external-ed25519-sha256-receipt", "runtimeManifest": "runtime-dependencies.json",
            "checksums": "SHA256SUMS", "runtimeText": "runtime-dependencies.txt",
        }

    def write_bundle(self, native=False, *, omit=None, unreceipted=None, corrupt=None, helper_mode=0o755):
        names = manifest.HEADLESS_NATIVE_PROVISIONING_FILES if native else manifest.HEADLESS_PROVISIONING_FILES
        payloads = {name: (name + " fixture\n").encode() for name in names if name != "SHA256SUMS"}
        payloads["package-manifest.json"] = json.dumps(self.package).encode()
        payloads["SHA256SUMS"] = "".join(
            f"{hashlib.sha256(payloads[name]).hexdigest()}  {name}\n"
            for name in names if name not in {"SHA256SUMS", unreceipted}
        ).encode()
        if corrupt:
            payloads[corrupt] += b"tampered"
        if omit:
            del payloads[omit]
        with tarfile.open(self.archive, "w:gz") as archive:
            for name, payload in payloads.items():
                member = tarfile.TarInfo("headless-package/" + name)
                member.mode = helper_mode if name == manifest.HEADLESS_NATIVE_HELPER else 0o644
                member.size = len(payload)
                archive.addfile(member, io.BytesIO(payload))

    def test_legacy_bundle_is_still_accepted(self):
        self.write_bundle()
        self.assertEqual(manifest.inspect_headless_provisioning(self.archive)["files"],
                         list(manifest.HEADLESS_PROVISIONING_FILES))

    def test_native_helper_is_bound_to_exact_manifest_and_checksums(self):
        self.package["nativeHelper"] = manifest.HEADLESS_NATIVE_HELPER
        self.write_bundle(True)
        self.assertEqual(manifest.inspect_headless_provisioning(self.archive)["files"],
                         list(manifest.HEADLESS_NATIVE_PROVISIONING_FILES))

    def test_native_declaration_requires_helper_file(self):
        self.package["nativeHelper"] = manifest.HEADLESS_NATIVE_HELPER
        self.write_bundle(True, omit=manifest.HEADLESS_NATIVE_HELPER)
        with self.assertRaisesRegex(SystemExit, "unexpected file set"):
            manifest.inspect_headless_provisioning(self.archive)

    def test_undeclared_native_helper_is_rejected(self):
        self.write_bundle(True)
        with self.assertRaisesRegex(SystemExit, "unexpected file set"):
            manifest.inspect_headless_provisioning(self.archive)

    def test_foreign_helper_name_is_rejected(self):
        self.package["nativeHelper"] = "foreign-executable"
        self.write_bundle(True)
        with self.assertRaisesRegex(SystemExit, "exact package contract"):
            manifest.inspect_headless_provisioning(self.archive)

    def test_unreceipted_native_helper_is_rejected(self):
        self.package["nativeHelper"] = manifest.HEADLESS_NATIVE_HELPER
        self.write_bundle(True, unreceipted=manifest.HEADLESS_NATIVE_HELPER)
        with self.assertRaisesRegex(SystemExit, "does not cover the exact package"):
            manifest.inspect_headless_provisioning(self.archive)

    def test_changed_native_helper_is_rejected(self):
        self.package["nativeHelper"] = manifest.HEADLESS_NATIVE_HELPER
        self.write_bundle(True, corrupt=manifest.HEADLESS_NATIVE_HELPER)
        with self.assertRaisesRegex(SystemExit, "inner checksum mismatch"):
            manifest.inspect_headless_provisioning(self.archive)

    def test_non_executable_or_special_mode_helper_is_rejected(self):
        self.package["nativeHelper"] = manifest.HEADLESS_NATIVE_HELPER
        for mode in (0o644, 0o777, 0o4755):
            with self.subTest(mode=oct(mode)):
                self.write_bundle(True, helper_mode=mode)
                with self.assertRaisesRegex(SystemExit, "must have mode 0755"):
                    manifest.inspect_headless_provisioning(self.archive)

    def test_signed_native_bundle_verifies_without_running_helper(self):
        verifier_spec = importlib.util.spec_from_file_location(
            "native_bundle_verifier", Path(__file__).with_name("verify_provisioning_bundle.py")
        )
        verifier = importlib.util.module_from_spec(verifier_spec)
        verifier_spec.loader.exec_module(verifier)
        self.package["nativeHelper"] = manifest.HEADLESS_NATIVE_HELPER
        self.write_bundle(True)
        inner = manifest.inspect_headless_provisioning(self.archive)
        root = Path(self.temporary.name)
        private, public = root / "test-private.pem", root / "test-public.pem"
        openssl = manifest.openssl_command()
        for command in ([openssl, "genpkey", "-algorithm", "ED25519", "-out", str(private)],
                        [openssl, "pkey", "-in", str(private), "-pubout", "-out", str(public)]):
            subprocess.run(command, check=True, capture_output=True)
        payload = {
            "version": "9.9.9.9",
            "platforms": {"linux-headless-x64": {"sha256": "a" * 64, "size": 1,
                                                    "format": manifest.HEADLESS_ARTIFACT_FORMAT}},
            "headlessProvisioning": {
                "url": "files/artifacts/fixture/fixture.tar.gz", "format": manifest.HEADLESS_PROVISIONING_FORMAT,
                "sha256": manifest.sha256(self.archive), "size": self.archive.stat().st_size,
                "version": "9.9.9.9", "packageVersion": "9.9.9.9", "packageFiles": inner["files"],
                "packageManifestSha256": inner["packageManifestSha256"], "checksumsSha256": inner["checksumsSha256"],
            },
        }
        raw = json.dumps(payload, separators=(",", ":")).encode()
        signed = root / "fixture-manifest.json"
        signed.write_text(json.dumps({"schema": "amnezia-selfhosted-update-v1", "signatureAlgorithm": "Ed25519", "payload": manifest.b64url(raw),
                                      "signature": manifest.sign_payload(private, raw)}))
        receipt = verifier.verify_manifest_and_bundle(signed, public, self.archive, manifest.sha256(public))
        self.assertTrue(receipt["verified"])
        self.assertEqual(receipt["packageFiles"], list(manifest.HEADLESS_NATIVE_PROVISIONING_FILES))
        # The helper fixture contains plain text. Successful verification proves
        # the signed-bundle verifier inspected bytes without executing the helper.
        envelope = json.loads(signed.read_text())
        signature = bytearray(base64.b64decode(envelope["signature"]))
        signature[0] ^= 1
        envelope["signature"] = base64.b64encode(signature).decode()
        signed.write_text(json.dumps(envelope))
        with self.assertRaisesRegex(SystemExit, "signature verification failed"):
            verifier.verify_manifest_and_bundle(signed, public, self.archive, manifest.sha256(public))


if __name__ == "__main__":
    unittest.main()
