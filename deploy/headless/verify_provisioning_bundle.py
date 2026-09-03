#!/usr/bin/env python3
"""Verify a headless provisioning bundle before an operator runs its installer.

This command is intentionally verify-only.  It never extracts or launches the
installer unless ``--run-installer`` is supplied explicitly.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
from contextlib import contextmanager
from pathlib import Path
from pathlib import PurePosixPath
from stat import S_ISREG

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "selfhosted_updates"))
from make_manifest import (  # noqa: E402
    HEADLESS_PROVISIONING_FORMAT,
    decode_manifest_envelope,
    inspect_headless_provisioning,
    openssl_command,
    validate_release_version,
    sha256,
)


SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def verify_signature(
    public_key: Path,
    payload: bytes,
    signature_base64: str,
    expected_public_key_sha256: str,
) -> None:
    if not public_key.is_file() or public_key.is_symlink():
        raise SystemExit("public key must be a regular file")
    if not SHA256_RE.fullmatch(expected_public_key_sha256):
        raise SystemExit("expected public-key fingerprint must be 64 hexadecimal characters")
    expected_public_key_sha256 = expected_public_key_sha256.lower()
    if sha256(public_key) != expected_public_key_sha256:
        raise SystemExit("public key fingerprint does not match the pinned expected fingerprint")
    try:
        signature = base64.b64decode(signature_base64, validate=True)
    except (ValueError, TypeError) as error:
        raise SystemExit("manifest signature is not valid base64") from error
    if len(signature) != 64:
        raise SystemExit("manifest signature is not a 64-byte Ed25519 signature")
    with tempfile.TemporaryDirectory(prefix="amnezia-provisioning-verify-") as temporary:
        temporary_path = Path(temporary)
        payload_path = temporary_path / "payload.json"
        signature_path = temporary_path / "payload.sig"
        payload_path.write_bytes(payload)
        signature_path.write_bytes(signature)
        openssl = openssl_command()
        try:
            subprocess.run(
                [openssl, "pkey", "-pubin", "-in", str(public_key), "-text", "-noout"],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                [
                    openssl, "pkeyutl", "-verify", "-pubin", "-inkey", str(public_key),
                    "-rawin",
                    "-in", str(payload_path), "-sigfile", str(signature_path),
                ],
                check=True,
                capture_output=True,
            )
        except subprocess.CalledProcessError as error:
            raise SystemExit("signed update manifest signature verification failed") from error


def _verify_manifest_and_bundle_copy(
    manifest_path: Path,
    public_key: Path,
    archive: Path,
    expected_public_key_sha256: str,
) -> dict[str, object]:
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise SystemExit("manifest must be a regular file")
    manifest_data = manifest_path.read_bytes()
    payload, payload_bytes, signature = decode_manifest_envelope(manifest_data)
    verify_signature(public_key, payload_bytes, signature, expected_public_key_sha256)
    version = validate_release_version(payload.get("version"))
    platforms = payload.get("platforms")
    provisioning = payload.get("headlessProvisioning")
    if (
        not isinstance(platforms, dict)
        or "linux-headless-x64" not in platforms
        or not isinstance(platforms["linux-headless-x64"], dict)
        or platforms["linux-headless-x64"].get("openExternal")
        or not isinstance(provisioning, dict)
        or set(provisioning) != {
            "url", "sha256", "size", "format", "version", "packageManifestSha256",
            "checksumsSha256", "packageVersion", "packageFiles",
        }
        or provisioning.get("format") != HEADLESS_PROVISIONING_FORMAT
        or provisioning.get("version") != version
        or provisioning.get("packageVersion") != version
    ):
        raise SystemExit("signed manifest does not contain an exact Linux headless provisioning contract")
    artifact = platforms["linux-headless-x64"]
    if (
        not isinstance(artifact.get("sha256"), str)
        or not isinstance(artifact.get("size"), int)
        or artifact["size"] <= 0
        or not isinstance(provisioning.get("sha256"), str)
        or not isinstance(provisioning.get("size"), int)
        or provisioning["size"] <= 0
    ):
        raise SystemExit("signed manifest contains invalid headless artifact metadata")
    if sha256(archive) != provisioning["sha256"] or archive.stat().st_size != provisioning["size"]:
        raise SystemExit("provisioning archive hash or size does not match the signed manifest")
    inner = inspect_headless_provisioning(archive, version)
    if (
        artifact.get("format") != "amnezia-headless-tar-v1"
        or not isinstance(provisioning.get("packageManifestSha256"), str)
        or not isinstance(provisioning.get("checksumsSha256"), str)
        or provisioning.get("packageFiles") != inner["files"]
    ):
        raise SystemExit("signed manifest contains invalid inner provisioning metadata")
    expected = {
        "packageManifestSha256": inner["packageManifestSha256"],
        "checksumsSha256": inner["checksumsSha256"],
        "packageVersion": inner["version"],
        "packageFiles": inner["files"],
    }
    for key, value in expected.items():
        if provisioning.get(key) != value:
            raise SystemExit(f"signed manifest inner provisioning receipt mismatch: {key}")
    return {
        "schema": 1,
        "tool": "amnezia-verify-provisioning-v1",
        "verified": True,
        "manifestSha256": hashlib.sha256(manifest_data).hexdigest(),
        "publicKeySha256": sha256(public_key),
        "archiveSha256": provisioning["sha256"],
        "archiveSize": provisioning["size"],
        "version": version,
        "packageVersion": inner["version"],
        "packageFiles": inner["files"],
        "packageManifestSha256": inner["packageManifestSha256"],
        "checksumsSha256": inner["checksumsSha256"],
    }


def _copy_regular_file_to_private_temp(source_path: Path, destination: Path, name: str) -> Path:
    """Copy one release input to a private temp directory exactly once.

    Verification and extraction must consume these immutable copies.  Reading
    the operator-facing paths again after signature/hash validation would make
    a same-name replacement a TOCTOU opportunity (and ``resolve()`` would hide
    a symlink at the argument boundary).  The fstat check also rejects a file
    that is replaced while it is being copied.
    """
    if source_path.is_symlink() or not source_path.is_file():
        raise SystemExit(f"{name} must be a regular file")
    try:
        before = source_path.stat()
        if not S_ISREG(before.st_mode):
            raise SystemExit(f"{name} must be a regular file")
        copied = destination / name
        with source_path.open("rb") as source, copied.open("xb") as target:
            opened = os.fstat(source.fileno())
            if not S_ISREG(opened.st_mode) or opened.st_size != before.st_size:
                raise SystemExit(f"{name} changed while it was being copied")
            shutil.copyfileobj(source, target, length=1024 * 1024)
            target.flush()
            os.fsync(target.fileno())
        if copied.stat().st_size != opened.st_size:
            raise SystemExit(f"private {name} copy has an unexpected size")
    except OSError as error:
        raise SystemExit(f"unable to copy {name} to the private verification directory") from error
    return copied


def _copy_archive_to_private_temp(archive: Path, destination: Path) -> Path:
    """Compatibility wrapper for callers that verify only an archive."""
    return _copy_regular_file_to_private_temp(archive, destination, "provisioning.tar.gz")


@contextmanager
def _verified_archive(
    manifest_path: Path,
    public_key: Path,
    archive: Path,
    expected_public_key_sha256: str,
):
    with tempfile.TemporaryDirectory(prefix="amnezia-provisioning-archive-") as temporary:
        private_root = Path(temporary)
        exact_manifest = _copy_regular_file_to_private_temp(
            manifest_path, private_root, "manifest.json"
        )
        exact_public_key = _copy_regular_file_to_private_temp(
            public_key, private_root, "update-public-key.pem"
        )
        exact_copy = _copy_archive_to_private_temp(archive, private_root)
        receipt = _verify_manifest_and_bundle_copy(
            exact_manifest, exact_public_key, exact_copy, expected_public_key_sha256
        )
        # Rehash every immutable copy immediately before any extraction.  The
        # signed manifest digest is deliberately computed from exact_manifest,
        # never from the mutable operator path.
        if (
            sha256(exact_manifest) != receipt["manifestSha256"]
            or sha256(exact_public_key) != receipt["publicKeySha256"]
            or sha256(exact_copy) != receipt["archiveSha256"]
            or exact_copy.stat().st_size != receipt["archiveSize"]
        ):
            raise SystemExit("private provisioning archive changed after verification")
        yield receipt, exact_copy


def verify_manifest_and_bundle(
    manifest_path: Path,
    public_key: Path,
    archive: Path,
    expected_public_key_sha256: str,
) -> dict[str, object]:
    with _verified_archive(manifest_path, public_key, archive, expected_public_key_sha256) as (receipt, _):
        return receipt


def extract_verified_bundle(archive: Path, destination: Path) -> Path:
    """Extract only the already-verified regular members (Python 3.10 safe).

    ``TarFile.extractall(filter=...)`` is a Python 3.12 API.  The headless
    provisioning helper is expected to run on Ubuntu 22.04/Python 3.10, so
    keep the traversal and file creation explicit after the exact archive
    contract has been checked by ``inspect_headless_provisioning``.
    """
    package_root = destination / "headless-package"
    package_root.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive, "r:gz") as tar:
        members = tar.getmembers()
        for member in members:
            if member.isdir() and member.name == "headless-package":
                continue
            path = PurePosixPath(member.name)
            if (not member.isreg() or path.is_absolute() or ".." in path.parts
                    or path.parts[:1] != ("headless-package",)
                    or len(path.parts) != 2 or member.name != str(path)):
                raise SystemExit(f"verified provisioning bundle has unsafe member: {member.name!r}")
            target = package_root / path.parts[1]
            target.parent.mkdir(parents=True, exist_ok=True)
            source = tar.extractfile(member)
            if source is None:
                raise SystemExit(f"verified provisioning bundle member is unreadable: {member.name!r}")
            with target.open("xb") as output:
                while True:
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    output.write(chunk)
            os.chmod(target, member.mode & 0o777)
    return package_root


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--expected-public-key-sha256", required=True)
    parser.add_argument("--provisioning", type=Path, required=True)
    parser.add_argument("--receipt-out", type=Path)
    parser.add_argument(
        "--run-installer", action="store_true",
        help="explicitly extract the already verified bundle and launch its installer",
    )
    parser.add_argument("--installer-arg", action="append", default=[])
    args = parser.parse_args()
    # Keep symlink identity visible to the regular-file checks.  The verifier
    # copies the exact bytes into a private directory before parsing them.
    manifest_path = args.manifest.expanduser()
    public_key = args.public_key.expanduser()
    archive = args.provisioning.expanduser()
    if args.receipt_out:
        receipt_path = args.receipt_out.expanduser().resolve()
    else:
        receipt_path = None
    if not args.run_installer:
        receipt = verify_manifest_and_bundle(
            manifest_path, public_key, archive, args.expected_public_key_sha256
        )
    else:
        with _verified_archive(
            manifest_path, public_key, archive, args.expected_public_key_sha256
        ) as (receipt, exact_archive):
            if receipt_path:
                receipt_path.parent.mkdir(parents=True, exist_ok=True)
                receipt_path.write_text(
                    json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n",
                    encoding="utf-8",
                )
                print(f"verified receipt: {receipt_path}")
            if not args.installer_arg:
                raise SystemExit("--run-installer requires at least one --installer-arg")
            with tempfile.TemporaryDirectory(prefix="amnezia-provisioning-run-") as temporary:
                package_root = extract_verified_bundle(exact_archive, Path(temporary))
                installer = package_root / "install_headless.sh"
                if not installer.is_file() or installer.is_symlink():
                    raise SystemExit("verified provisioning bundle has no regular installer")
                completed = subprocess.run([str(installer), *args.installer_arg], check=False)
                return completed.returncode
    if args.receipt_out:
        receipt_path.parent.mkdir(parents=True, exist_ok=True)
        receipt_path.write_text(json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
        print(f"verified receipt: {receipt_path}")
    if not args.run_installer:
        print(f"verified headless provisioning bundle: {receipt['version']}")
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
