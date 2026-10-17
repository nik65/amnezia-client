"""Test-only in-memory Ed25519 interoperability vectors for the C++ verifier.

No release key is read, no private key is serialized and no approval is issued.
The generated public key is passed only to the verifier's test executable.
"""
from __future__ import annotations

import base64
import copy
from datetime import datetime, timezone
import json
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import make_manifest


def generate_vector() -> dict[str, object]:
    key = Ed25519PrivateKey.generate()
    public = key.public_key()
    digest = "a" * 64
    payload = {
        "schema": 1, "policyId": "amnezia-release-full-v1",
        "manifestSha256": digest, "publisherSha256": digest,
        "version": "5.0.3.11", "androidVersionCode": 2197,
        "issuedAt": "2026-10-17T19:59:00Z", "expiresAt": "2026-10-17T21:00:00Z",
        "artifacts": [{"path": "files/artifacts/a/test", "sha256": digest, "size": 10}],
        "receipts": [{"platform": platform, "kind": "real-device" if platform == "android" else "owned-guest",
                      "runId": "test-run", "profileId": "test-profile", "receiptSha256": digest,
                      "cleanupSha256": digest, "status": "PASS"}
                     for platform in ("android", "linux", "windows")],
    }

    def sign(_path: Path, data: bytes) -> str:
        return base64.b64encode(key.sign(data)).decode("ascii")

    def verify(_path: Path, data: bytes, signature: str) -> None:
        public.verify(base64.b64decode(signature, validate=True), data)

    class FixtureClock(datetime):
        @classmethod
        def now(cls, tz=None):
            return cls(2026, 10, 17, 19, 59, 1, tzinfo=timezone.utc)

    # Use the production Python serializer/schema/signing-byte construction;
    # replace only key I/O with real in-memory Ed25519 operations and test time.
    with mock.patch.object(make_manifest, "datetime", FixtureClock), \
            mock.patch.object(make_manifest, "sign_payload", side_effect=sign), \
            mock.patch.object(make_manifest, "verify_payload_signature", side_effect=verify):
        envelope = make_manifest.acceptance_envelope(payload, Path("in-memory-test-key"))

    def encode_envelope(value: dict[str, object]) -> str:
        return base64.b64encode(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                           separators=(",", ":")).encode()).decode("ascii")

    def signed_negative(value: dict[str, object], domain: bytes, decode: bool):
        # Invalid policy cannot pass the production issuer's validation; sign
        # adversarial fixtures directly with this disposable test authority.
        data = domain + json.dumps(value, ensure_ascii=False, sort_keys=True,
                                   separators=(",", ":")).encode()
        negative = {"schema": make_manifest.RELEASE_ACCEPTANCE_SCHEMA,
                    "signatureAlgorithm": "Ed25519", "payload": make_manifest.b64url(data),
                    "signature": sign(Path(), data)}
        verify(Path(), data, negative["signature"])
        return {"envelopeBase64": encode_envelope(negative),
                "decodeExpected": decode, "policyExpected": False}

    expired = copy.deepcopy(payload)
    expired["expiresAt"] = "2026-10-17T19:59:30Z"
    changed_closure = copy.deepcopy(payload)
    changed_closure["artifacts"][0]["sha256"] = "b" * 64
    return {
        "publicKeyPemBase64": base64.b64encode(public.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)).decode("ascii"),
        "envelopeBase64": encode_envelope(envelope), "expectedPayload": payload,
        "negativeVectors": [signed_negative(payload, b"wrong-approval-domain\n", False),
                            signed_negative(expired, make_manifest.RELEASE_ACCEPTANCE_DOMAIN, True),
                            signed_negative(changed_closure, make_manifest.RELEASE_ACCEPTANCE_DOMAIN, True)],
    }


if __name__ == "__main__":
    print(json.dumps(generate_vector(), ensure_ascii=False, sort_keys=True, separators=(",", ":")))
