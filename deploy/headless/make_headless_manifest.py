#!/usr/bin/env python3
"""Create a signed manifest for the native Ubuntu headless artifact."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import shutil
import sys
from pathlib import Path
from urllib.parse import quote, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "selfhosted_updates"))
from make_manifest import sign_payload


def version(value: str) -> str:
    parts = value.split(".")
    if len(parts) != 4 or any(not part.isdigit() or (len(part) > 1 and part[0] == "0") for part in parts):
        raise argparse.ArgumentTypeError("version must be canonical x.y.z.w")
    return value


def base_url(value: str) -> str:
    parsed = urlparse(value.rstrip("/"))
    if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.username or parsed.password:
        raise argparse.ArgumentTypeError("base URL must be an http(s) URL without credentials")
    return value.rstrip("/")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True, type=version)
    parser.add_argument("--base-url", required=True, type=base_url)
    parser.add_argument("--private-key", required=True, type=Path)
    parser.add_argument("--artifact", required=True, type=Path)
    parser.add_argument("--out-dir", required=True, type=Path)
    parser.add_argument("--auto-install", action="store_true")
    args = parser.parse_args()

    artifact = args.artifact.expanduser().resolve()
    if not artifact.is_file():
        parser.error(f"artifact does not exist: {artifact}")
    private_key = args.private_key.expanduser().resolve()
    if not private_key.is_file():
        parser.error(f"private key does not exist: {private_key}")

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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
