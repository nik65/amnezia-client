"""Real verify-only executable -> actual shell consumer role integration.

All packages are signed TEST DATA in an owned evidence directory. Packaged
installer/daemon/helper bytes are never executed; the standalone verifier is
the only product executable run. Host probes are explicitly mocked when the
extracted metadata consumer runs. This is not guest or release acceptance.
"""
import argparse
import base64
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shlex
import subprocess
import tarfile
import tempfile
import unittest


PARSER = argparse.ArgumentParser()
PARSER.add_argument("--binary", required=True, type=Path)
PARSER.add_argument("--evidence-root", required=True, type=Path)
OPTIONS = PARSER.parse_args()
BINARY = OPTIONS.binary.resolve(strict=True)
OPTIONS.evidence_root.mkdir(parents=True, exist_ok=True)
ATTEMPT = Path(tempfile.mkdtemp(prefix="native-role-", dir=OPTIONS.evidence_root))
ROOT = Path(__file__).resolve().parents[4]
SPEC = importlib.util.spec_from_file_location(
    "native_role_canonical_manifest", ROOT / "deploy/selfhosted_updates/make_manifest.py")
MANIFEST = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MANIFEST)
SOURCE = (ROOT / "deploy/headless/install_headless.sh").read_text(encoding="utf-8")
BASE_FILES = list(MANIFEST.HEADLESS_PROVISIONING_FILES)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class NativeRoleTests(unittest.TestCase):
    def setUp(self):
        self.root = ATTEMPT / self._testMethodName
        self.root.mkdir(mode=0o700)
        self.counter = 0

    def run_logged(self, args):
        self.counter += 1
        result = subprocess.run(args, capture_output=True, text=True, timeout=20, check=False)
        (self.root / f"command-{self.counter}.json").write_text(json.dumps({
            "argv": [str(arg) for arg in args], "exit": result.returncode,
            "stdout": result.stdout, "stderr": result.stderr}, indent=2) + "\n")
        return result

    def fixture(self, role, name="package", *, native_verifier=False):
        package = self.root / name
        package.mkdir(mode=0o700)
        metadata = {
            "schema": 2, "version": "9.9.9.9", "platform": "linux-headless-x64",
            "installModes": ["fresh", "upgrade"],
            "artifacts": ["amneziad", "amnezia-cli", "amneziad.service"],
            "service": "amneziad.service",
            "servicePaths": ["/etc/systemd/system/amneziad.service",
                             "/run/systemd/system/amneziad.service",
                             "/usr/local/lib/systemd/system/amneziad.service",
                             "/usr/lib/systemd/system/amneziad.service",
                             "/lib/systemd/system/amneziad.service"],
            "trustAnchor": "external-ed25519-sha256-receipt",
            "runtimeManifest": "runtime-dependencies.json", "checksums": "SHA256SUMS",
            "runtimeText": "runtime-dependencies.txt"}
        files = list(BASE_FILES)
        if role is not None:
            metadata["nativeHelper"] = role
        if role == "amnezia-headless-fs":
            files.append(role)
        # These fake command/package requirements must never be executed during
        # verify-only metadata validation; the production probe plan defers them.
        runtime = {
            "schema": 2, "distribution": "ubuntu", "architectures": ["amd64"],
            "releases": [{"versionId": "24.04", "codenames": ["noble"], "packages": [
                {"alternatives": ["inert-package-never-probed"], "minimum": "1",
                 "reason": "TEST DATA; validation must only emit a probe plan"}]}],
            "commands": {"required": ["inert-command-never-executed"], "backendModes": [
                {"mode": "TEST-DATA", "alternatives": ["inert-backend-never-executed"]}]}}
        marker = package / "PACKAGED_EXECUTABLE_WAS_RUN"
        executable_data = ("#!/bin/sh\nprintf unexpected-execution > "
                           + shlex.quote(str(marker)) + "\nexit 91\n").encode()
        if native_verifier:
            files.append("amnezia-verify-provisioning-native")
            metadata["nativeVerifier"] = {
                "path": "amnezia-verify-provisioning-native",
                "sha256": hashlib.sha256(executable_data).hexdigest(),
                "size": len(executable_data)}
        for member in files:
            if member != "SHA256SUMS":
                (package / member).write_bytes(b"TEST DATA " + member.encode() + b"\n")
        for member in ("install_headless.sh", "amneziad", "amnezia-cli"):
            (package / member).write_bytes(executable_data)
            (package / member).chmod(0o755)
        for extra in ("amnezia-headless-fs", "amnezia-verify-provisioning-native"):
            if extra in files:
                (package / extra).write_bytes(executable_data)
                (package / extra).chmod(0o755)
        (package / "package-manifest.json").write_text(json.dumps(metadata))
        (package / "runtime-dependencies.json").write_text(json.dumps(runtime))
        (package / "SHA256SUMS").write_text("".join(
            digest(package / member) + "  " + member + "\n"
            for member in files if member != "SHA256SUMS"))
        archive = self.root / (name + ".tar.gz")
        with tarfile.open(archive, "w:gz") as output:
            for member in files:
                data = (package / member).read_bytes()
                entry = tarfile.TarInfo("headless-package/" + member)
                entry.size = len(data)
                entry.mode = (package / member).stat().st_mode & 0o777
                output.addfile(entry, io.BytesIO(data))
        inner = MANIFEST.inspect_headless_provisioning(archive)
        private, public = self.root / (name + "-test-private.pem"), self.root / (name + "-test-public.pem")
        for args in (["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(private)],
                     ["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)]):
            result = self.run_logged(args)
            self.assertEqual(result.returncode, 0, result.stderr)
        payload = {"version": "9.9.9.9", "platforms": {"linux-headless-x64": {
            "sha256": "a" * 64, "size": 1, "format": MANIFEST.HEADLESS_ARTIFACT_FORMAT}},
            "headlessProvisioning": {
                "url": "files/artifacts/fixture/package.tar.gz",
                "format": MANIFEST.HEADLESS_PROVISIONING_FORMAT,
                "sha256": digest(archive), "size": archive.stat().st_size,
                "version": "9.9.9.9", "packageVersion": "9.9.9.9",
                "packageFiles": inner["files"],
                "packageManifestSha256": inner["packageManifestSha256"],
                "checksumsSha256": inner["checksumsSha256"]}}
        raw = json.dumps(payload, separators=(",", ":")).encode()
        signed = self.root / (name + "-signed.json")
        signed.write_text(json.dumps({"schema": "amnezia-selfhosted-update-v1",
            "signatureAlgorithm": "Ed25519", "payload": MANIFEST.b64url(raw),
            "signature": MANIFEST.sign_payload(private, raw)}))
        receipt = self.root / (name + "-verified.json")
        result = self.run_logged([str(BINARY), "--manifest", str(signed),
            "--public-key", str(public), "--expected-public-key-sha256", digest(public),
            "--provisioning", str(archive), "--receipt-out", str(receipt)])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(receipt.read_text())["verified"])
        self.assertFalse(marker.exists())
        arguments = ["--validate-package", "--package-root", str(package),
            "--receipt", str(receipt), "--public-key", str(public),
            "--ubuntu-id", "ubuntu", "--ubuntu-version-id", "24.04", "--ubuntu-codename", "noble",
            "--expected-public-key-sha256", digest(public),
            "--expected-package-manifest-sha256", inner["packageManifestSha256"],
            "--expected-checksums-sha256", inner["checksumsSha256"],
            "--expected-signed-manifest-sha256", digest(signed)]
        return package, arguments, marker

    def test_actual_native_role_output_reaches_shell_consumer(self):
        for role in (None, "amnezia-cli", "amnezia-headless-fs"):
            with self.subTest(role=role):
                package, arguments, marker = self.fixture(role, role or "none")
                output = self.root / ((role or "none") + "-metadata.json")
                result = self.run_logged([str(BINARY), *arguments, "--receipt-out", str(output)])
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("validated native helper role: " + (role or "none") + "\n", result.stdout)
                metadata = json.loads(output.read_text())
                self.assertEqual(metadata["nativeHelper"], role or "")
                self.assertIs(metadata["hostProbesExecuted"], False)
                self.assertIs(metadata["releaseAccepted"], False)
                start = SOURCE.index("y_consume_metadata() {\n")
                end = SOURCE.index("\n}\n", start) + len("\n}\n")
                script = '''set -eu
VERIFIER="$1"
shift
VALIDATE_ARGS=("$@")
y_validate_package() { "$VERIFIER" "${VALIDATE_ARGS[@]}"; }
y_probe_host() { printf '{"hostProbesPassed":true,"releaseAccepted":false}'; }
python3() { printf 'UNEXPECTED_PYTHON_FALLBACK' >&2; return 92; }
'''+ SOURCE[start:end] + '''
y_consume_metadata
printf 'CONSUMED|%s|%s\n' "$Y_PACKAGE_VERSION" "$Y_NATIVE_HELPER_KIND"
'''
                consumed = self.run_logged(["/bin/bash", "--noprofile", "--norc", "-c", script,
                                            "native-role-consumer", str(BINARY), *arguments])
                self.assertEqual(consumed.returncode, 0, consumed.stderr)
                self.assertEqual(consumed.stdout, "CONSUMED|9.9.9.9|" + (role or "") + "\n")
                self.assertNotIn("UNEXPECTED_PYTHON_FALLBACK", consumed.stderr)
                self.assertFalse(marker.exists(), "packaged TEST DATA must never execute")

    def test_signed_optional_verifier_membership_with_each_helper_variant(self):
        for role, count in ((None, 9), ("amnezia-cli", 9), ("amnezia-headless-fs", 10)):
            with self.subTest(role=role):
                name = role or "none"
                package, arguments, marker = self.fixture(role, name, native_verifier=True)
                output = self.root / (name + "-metadata.json")
                result = self.run_logged([str(BINARY), *arguments, "--receipt-out", str(output)])
                self.assertEqual(result.returncode, 0, result.stderr)
                metadata = json.loads(output.read_text())
                self.assertEqual(len(metadata["packageFiles"]), count)
                self.assertEqual(metadata["nativeVerifier"]["sha256"],
                                 digest(package / "amnezia-verify-provisioning-native"))
                self.assertEqual(metadata["nativeHelper"], role or "")
                self.assertFalse(marker.exists())

    def test_changed_optional_verifier_mode_cannot_emit_role(self):
        package, arguments, marker = self.fixture("amnezia-cli", native_verifier=True)
        (package / "amnezia-verify-provisioning-native").chmod(0o4755)
        self.assert_refused(arguments)
        self.assertFalse(marker.exists())

    def test_invalid_signature_cannot_create_verified_receipt(self):
        package, arguments, marker = self.fixture("amnezia-cli")
        signed = self.root / "package-signed.json"
        envelope = json.loads(signed.read_text())
        signature = bytearray(base64.b64decode(envelope["signature"]))
        signature[0] ^= 1
        envelope["signature"] = base64.b64encode(signature).decode()
        signed.write_text(json.dumps(envelope))
        public = self.root / "package-test-public.pem"
        output = self.root / "refused-signature-receipt.json"
        result = self.run_logged([str(BINARY), "--manifest", str(signed),
            "--public-key", str(public), "--expected-public-key-sha256", digest(public),
            "--provisioning", str(self.root / "package.tar.gz"), "--receipt-out", str(output)])
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("signature", result.stderr)
        self.assertFalse(output.exists())
        self.assertFalse(marker.exists())

    def test_invalid_pinned_receipt_cannot_emit_role(self):
        package, arguments, marker = self.fixture("amnezia-cli")
        index = arguments.index("--expected-checksums-sha256") + 1
        arguments[index] = "0" * 64
        self.assert_refused(arguments)
        self.assertFalse(marker.exists())

    def test_changed_authenticated_helper_bytes_cannot_emit_role(self):
        package, arguments, marker = self.fixture("amnezia-cli")
        with (package / "amnezia-cli").open("ab") as output:
            output.write(b"changed after signature and receipt verification\n")
        self.assert_refused(arguments)
        self.assertFalse(marker.exists())

    def test_special_helper_mode_cannot_emit_role(self):
        package, arguments, marker = self.fixture("amnezia-cli")
        (package / "amnezia-cli").chmod(0o4755)
        self.assert_refused(arguments)
        self.assertFalse(marker.exists())

    def assert_refused(self, arguments):
        output = self.root / "refused-metadata.json"
        result = self.run_logged([str(BINARY), *arguments, "--receipt-out", str(output)])
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("validated native helper role:", result.stdout)
        self.assertFalse(output.exists(), "a refused package must not create metadata authority")


if __name__ == "__main__":
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(NativeRoleTests))
    (ATTEMPT / "RESULT.json").write_text(json.dumps({
        "passed": result.wasSuccessful(), "tests": result.testsRun,
        "failures": len(result.failures), "errors": len(result.errors),
        "binarySha256": digest(BINARY),
        "scope": "real verifier + inert signed package + actual metadata shell consumer; host probes mocked",
        "releaseAccepted": False}, indent=2) + "\n")
    print("Evidence:", ATTEMPT)
    raise SystemExit(0 if result.wasSuccessful() else 1)
