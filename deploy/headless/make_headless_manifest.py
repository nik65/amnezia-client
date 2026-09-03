#!/usr/bin/env python3
"""Create a signed manifest for the native Ubuntu headless artifacts.

The standalone helper is retained for compatibility, but a provisioning
bundle should always be supplied so the signed manifest binds the service unit
and installer to the published release.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import shutil
import sys
from pathlib import Path
from urllib.parse import quote, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "selfhosted_updates"))
from make_manifest import MAX_VERSION_COMPONENT, inspect_headless_provisioning, sign_payload


def version(value: str) -> str:
    parts = value.split(".")
    if len(parts) != 4 or any(not part.isdigit() or (len(part) > 1 and part[0] == "0") for part in parts):
        raise argparse.ArgumentTypeError("version must be canonical x.y.z.w")
    if any(int(part) > MAX_VERSION_COMPONENT for part in parts):
        raise argparse.ArgumentTypeError("version components exceed the client-compatible limit")
    return value


def base_url(value: str) -> str:
    parsed = urlparse(value.rstrip("/"))
    if (parsed.scheme not in {"http", "https"} or not parsed.netloc
        or not parsed.hostname or parsed.username or parsed.password
        or parsed.query or parsed.fragment):
        raise argparse.ArgumentTypeError("base URL must be an http(s) URL without credentials/query/fragment")
    try:
        port = parsed.port
    except ValueError as error:
        raise argparse.ArgumentTypeError("headless base URL must contain a valid TCP port") from error
    if port is None or not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("headless base URL port must be from 1 to 65535")
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        address = None
    if address is None:
        raise argparse.ArgumentTypeError(
            "headless base URL must use a literal IP compatible with the runtime pinning policy"
        )
    if parsed.scheme == "http":
        if not (address.is_private or address.is_loopback or address.is_link_local):
            raise argparse.ArgumentTypeError(
                "headless HTTP base URL must use a private, loopback, or link-local literal IP"
            )
    return value.rstrip("/")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True, type=version)
    parser.add_argument("--base-url", required=True, type=base_url)
    parser.add_argument("--private-key", required=True, type=Path)
    parser.add_argument("--artifact", required=True, type=Path)
    parser.add_argument("--provisioning", type=Path, required=True,
                        help="signed provisioning bundle for the same release")
    parser.add_argument("--out-dir", required=True, type=Path)
    parser.add_argument("--auto-install", action="store_true")
    args = parser.parse_args()

    artifact = args.artifact.expanduser().resolve()
    if not artifact.is_file():
        parser.error(f"artifact does not exist: {artifact}")
    private_key = args.private_key.expanduser().resolve()
    if not private_key.is_file():
        parser.error(f"private key does not exist: {private_key}")
    provisioning = args.provisioning.expanduser().resolve()
    if not provisioning.is_file():
        parser.error(f"provisioning bundle does not exist: {provisioning}")

    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    out_dir = args.out_dir.expanduser().resolve()
    files_dir = out_dir / "files" / "artifacts" / digest
    files_dir.mkdir(parents=True, exist_ok=True)
    target = files_dir / artifact.name
    shutil.copy2(artifact, target)
    if hashlib.sha256(target.read_bytes()).hexdigest() != digest:
        raise SystemExit("artifact changed while it was copied")

    payload = {
        "autoInstall": args.auto_install,
        "changelog": "",
        "platforms": {
            "linux-headless-x64": {
                "autoInstall": args.auto_install,
                "format": "amnezia-headless-tar-v1",
                "sha256": digest,
                "size": target.stat().st_size,
                "url": f"files/artifacts/{digest}/{quote(target.name, safe='')}"
            }
        },
        "releaseDate": "",
        "schema": 1,
        "version": args.version,
    }
    provisioning_receipt = inspect_headless_provisioning(provisioning, args.version)
    provisioning_digest = hashlib.sha256(provisioning.read_bytes()).hexdigest()
    provisioning_target = out_dir / "files" / "artifacts" / provisioning_digest / provisioning.name
    provisioning_target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(provisioning, provisioning_target)
    payload["headlessProvisioning"] = {
        "format": "amnezia-headless-provisioning-tar-v1",
        "sha256": provisioning_digest,
        "size": provisioning_target.stat().st_size,
        "url": f"files/artifacts/{provisioning_digest}/{quote(provisioning_target.name, safe='')}",
        "version": args.version,
        "packageManifestSha256": provisioning_receipt["packageManifestSha256"],
        "checksumsSha256": provisioning_receipt["checksumsSha256"],
        "packageVersion": provisioning_receipt["version"],
        "packageFiles": provisioning_receipt["files"],
    }
    payload_bytes = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    signature = base64.b64decode(sign_payload(private_key, payload_bytes))
    manifest = {
        "schema": "amnezia-selfhosted-update-v1",
        "signatureAlgorithm": "Ed25519",
        "payload": base64.urlsafe_b64encode(payload_bytes).decode().rstrip("="),
        "signature": base64.b64encode(signature).decode(),
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"manifest: {out_dir / 'manifest.json'}")
    print(f"artifact-sha256: {digest}")
    print(f"provisioning-package-manifest-sha256: {provisioning_receipt['packageManifestSha256']}")
    print(f"provisioning-checksums-sha256: {provisioning_receipt['checksumsSha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
