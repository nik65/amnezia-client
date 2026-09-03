#!/usr/bin/env python3
"""Verify a headless provisioning bundle before an operator runs its installer.

This command is intentionally verify-only.  It never extracts or launches the
installer unless ``--run-installer`` is supplied explicitly.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import subprocess
import tarfile
import tempfile
from pathlib import Path
from pathlib import PurePosixPath

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "selfhosted_updates"))
from make_manifest import (  # noqa: E402
    HEADLESS_PROVISIONING_FORMAT,
    MAX_VERSION_COMPONENT,
    VERSION_RE,
    decode_manifest_envelope,
    inspect_headless_provisioning,
    is_canonical_release_version,
    sha256,
)


def verify_signature(public_key: Path, payload: bytes, signature_base64: str) -> None:
    if not public_key.is_file() or public_key.is_symlink():
        raise SystemExit("public key must be a regular file")
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
        try:
            subprocess.run(
                ["openssl", "pkey", "-pubin", "-in", str(public_key), "-text", "-noout"],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                [
                    "openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(public_key),
                    "-in", str(payload_path), "-sigfile", str(signature_path),
                ],
                check=True,
                capture_output=True,
            )
        except subprocess.CalledProcessError as error:
            raise SystemExit("signed update manifest signature verification failed") from error


def verify_manifest_and_bundle(manifest_path: Path, public_key: Path, archive: Path) -> dict[str, object]:
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise SystemExit("manifest must be a regular file")
    payload, payload_bytes, signature = decode_manifest_envelope(manifest_path.read_bytes())
    verify_signature(public_key, payload_bytes, signature)
    version = payload.get("version")
    platforms = payload.get("platforms")
    provisioning = payload.get("headlessProvisioning")
    if (
        not isinstance(version, str)
        or not VERSION_RE.fullmatch(version)
        or any(int(part) > MAX_VERSION_COMPONENT for part in version.split("."))
        or not isinstance(platforms, dict)
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
        "manifestSha256": sha256(manifest_path),
        "publicKeySha256": sha256(public_key),
        "archiveSha256": provisioning["sha256"],
        "archiveSize": provisioning["size"],
        "version": version,
        "packageVersion": inner["version"],
        "packageFiles": inner["files"],
        "packageManifestSha256": inner["packageManifestSha256"],
        "checksumsSha256": inner["checksumsSha256"],
    }


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
    parser.add_argument("--provisioning", type=Path, required=True)
    parser.add_argument("--receipt-out", type=Path)
    parser.add_argument(
        "--run-installer", action="store_true",
        help="explicitly extract the already verified bundle and launch its installer",
    )
    parser.add_argument("--installer-arg", action="append", default=[])
    args = parser.parse_args()
    receipt = verify_manifest_and_bundle(
        args.manifest.expanduser().resolve(),
        args.public_key.expanduser().resolve(),
        args.provisioning.expanduser().resolve(),
    )
    if args.receipt_out:
        receipt_path = args.receipt_out.expanduser().resolve()
        receipt_path.parent.mkdir(parents=True, exist_ok=True)
        receipt_path.write_text(json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
        print(f"verified receipt: {receipt_path}")
    if not args.run_installer:
        print(f"verified headless provisioning bundle: {receipt['version']}")
        return 0
    with tempfile.TemporaryDirectory(prefix="amnezia-provisioning-run-") as temporary:
        package_root = extract_verified_bundle(args.provisioning.expanduser().resolve(), Path(temporary))
        installer = package_root / "install_headless.sh"
        if not installer.is_file() or installer.is_symlink():
            raise SystemExit("verified provisioning bundle has no regular installer")
        if not args.installer_arg:
            raise SystemExit("--run-installer requires at least one --installer-arg")
        completed = subprocess.run([str(installer), *args.installer_arg], check=False)
        return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
