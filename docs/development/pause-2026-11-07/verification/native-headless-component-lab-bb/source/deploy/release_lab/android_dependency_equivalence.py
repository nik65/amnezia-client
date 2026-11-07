"""Explicit historical Android evidence reuse after headless-only repack.

Original acquisition signatures, observations and deadlines remain unchanged.
This module neither captures a device nor issues a replacement Android export.
"""
from __future__ import annotations

import copy
import hashlib
from pathlib import Path
from datetime import timedelta
import base64

from . import trusted_acquisition_export as authority
from .android_real_device_acquisition import file_record, PINNED_ADB
from .android_real_device_acceptance import PINNED_PLINK


def _expected_provenance():
    root = Path(__file__).absolute().parent
    return [file_record(path) for path in (
        root / "android_real_device_acceptance.py",
        root / "android_real_device_acquisition.py", PINNED_ADB, PINNED_PLINK,
        root / "trusted_acquisition_export.py")]


def _android_projection(payload):
    value = copy.deepcopy(payload)
    # No other branch, including global releasePolicy/rollback, is excluded.
    if "headlessProvisioning" not in value or "linux-headless-x64" not in value.get("platforms", {}):
        raise authority.TrustedAcquisitionError("complete headless branches required")
    del value["headlessProvisioning"]
    del value["platforms"]["linux-headless-x64"]
    return value


def verify_android_equivalence(envelope, *, original_context, context, original_envelope_bytes):
    """Verify the original context normally, then derive an explicit scoped proof."""
    if not isinstance(original_envelope_bytes, bytes) or original_envelope_bytes != authority.canonical(envelope):
        raise authority.TrustedAcquisitionError("exact original canonical Android envelope bytes required")
    # This is intentionally the unchanged normal verifier, with actual retained
    # old manifest/outer/full upload tree, not a forged current-context view.
    original = authority.verify_export(envelope, context=original_context)
    context.verify()
    derivation_producer = file_record(Path(__file__).absolute())
    if original["target"] != "android" or original["profileId"] != "android-real-device":
        raise authority.TrustedAcquisitionError("historical equivalence is real Android only")
    if (context.version != "5.0.3.14" or context.android_code != 2200
            or (original_context.version, original_context.android_code) != (context.version, context.android_code)):
        raise authority.TrustedAcquisitionError("historical Android version/code differs")
    for name in ("public_key_record", "publisher"):
        old, new = getattr(original_context, name), getattr(context, name)
        if (old["sha256"], old["size"]) != (new["sha256"], new["size"]):
            raise authority.TrustedAcquisitionError("historical Android key/publisher differs")
    old_payload, new_payload = original_context.manifest_payload, context.manifest_payload
    if authority.canonical(_android_projection(old_payload)) != authority.canonical(_android_projection(new_payload)):
        raise authority.TrustedAcquisitionError("non-headless manifest dependency changed")
    if authority.canonical(old_payload) == authority.canonical(new_payload) or original_context.binding() == context.binding():
        raise authority.TrustedAcquisitionError("headless repack equivalence requires an actual manifest delta")
    old_apk, new_apk = original_context.candidate("android-arm64-v8a"), context.candidate("android-arm64-v8a")
    if (old_apk["sha256"], old_apk["size"]) != (new_apk["sha256"], new_apk["size"]):
        raise authority.TrustedAcquisitionError("historical tested APK changed")
    expected = _expected_provenance()
    if sorted(original["provenance"], key=lambda r: r["path"]) != sorted(expected, key=lambda r: r["path"]):
        raise authority.TrustedAcquisitionError("all five original Android producer/tool pins must match")
    old_binding, new_binding = original_context.binding(), context.binding()
    proof = {
        "schema": "amnezia-android-headless-dependency-equivalence-v1",
        "observationKind": "original-historical-real-device-observation",
        "freshCapture": False,
        "originalEnvelope": copy.deepcopy(envelope),
        "originalEnvelopeSha256": hashlib.sha256(original_envelope_bytes).hexdigest(),
        "originalRunId": original["runId"], "originalProfileId": original["profileId"],
        "originalStartedAt": original["startedAt"], "originalCompletedAt": original["completedAt"],
        "originalIssuedAt": original["issuedAt"], "originalExpiresAt": original["expiresAt"],
        "originalRawCaptureSha256": original["rawCapture"]["sha256"],
        "originalCleanupCaptureSha256": original["cleanupCapture"]["sha256"],
        "originalBinding": old_binding, "currentBinding": new_binding,
        "equivalentAndroidArtifact": {"sha256": new_apk["sha256"], "size": new_apk["size"]},
        "headlessDelta": {name: {"old": old_payload[name], "new": new_payload[name]}
                          for name in ("headlessProvisioning",)},
        "headlessPlatformDelta": {"old": old_payload["platforms"]["linux-headless-x64"],
                                  "new": new_payload["platforms"]["linux-headless-x64"]},
        "producerPins": expected,
        "derivationProducer": derivation_producer,
    }
    # Hash/freshness fences cover the entire derivation, not only admission.
    current_original = authority.verify_export(envelope, context=original_context)
    context.verify()
    if (authority.canonical(current_original) != authority.canonical(original)
            or original_context.binding() != old_binding or context.binding() != new_binding
            or _expected_provenance() != expected
            or file_record(derivation_producer["path"]) != derivation_producer
            or original_envelope_bytes != authority.canonical(envelope)):
        raise authority.TrustedAcquisitionError("Android equivalence inputs changed during derivation")
    return original, proof


def prepare_equivalent_matrix(exports, *, original_context, context, original_android_bytes):
    """Return ordinary receipts plus a separate derivation proof; no signature."""
    if not isinstance(exports, list) or len(exports) != 4:
        raise authority.TrustedAcquisitionError("all four original signed platform exports required")
    verified, proof = {}, None
    for envelope in exports:
        if authority.canonical(envelope) == original_android_bytes:
            payload, derived = verify_android_equivalence(envelope, original_context=original_context,
                context=context, original_envelope_bytes=original_android_bytes)
            if proof is not None:
                raise authority.TrustedAcquisitionError("duplicate historical Android export")
            proof = derived
        else:
            payload = authority.verify_export(envelope, context=context)
        if payload["target"] in verified:
            raise authority.TrustedAcquisitionError("duplicate acquisition target")
        verified[payload["target"]] = payload
    if proof is None or set(verified) != set(authority.PRODUCERS):
        raise authority.TrustedAcquisitionError("complete matrix and explicit original Android evidence required")
    receipts = []
    for platform, targets in (("android", ["android"]), ("linux", ["linux-gui", "linux-headless"]), ("windows", ["windows"])):
        payloads = [verified[target] for target in targets]
        digest = hashlib.sha256(authority.canonical(proof if platform == "android" else payloads)).hexdigest()
        cleanup = hashlib.sha256(authority.canonical([p["cleanupCapture"] for p in payloads])).hexdigest()
        receipts.append({"platform": platform, "kind": "real-device" if platform == "android" else "owned-guest",
            "runId": payloads[0]["runId"] if len(payloads) == 1 else "linux-" + digest[:32],
            "profileId": payloads[0]["profileId"] if len(payloads) == 1 else "linux-gui-headless",
            "receiptSha256": digest, "cleanupSha256": cleanup, "status": "PASS"})
    receipts = authority.make_manifest.acceptance_receipts(receipts)
    expiry = min(authority._utc(p["expiresAt"]) for p in verified.values())
    return receipts, proof, expiry


def issue_equivalent_acceptance(exports, *, original_context, context, original_android_bytes, private_key):
    """Explicit issuer opt-in; original Android envelope is never re-signed."""
    receipts, proof, expiry = prepare_equivalent_matrix(exports, original_context=original_context,
        context=context, original_android_bytes=original_android_bytes)
    now = authority.utc_now()
    payload = {"schema": 1, "policyId": "amnezia-release-full-v1", "manifestSha256": context.manifest["sha256"],
        "publisherSha256": context.publisher["sha256"], "version": context.version, "androidVersionCode": context.android_code,
        "issuedAt": authority.utc_text(now), "expiresAt": authority.utc_text(min(now + timedelta(hours=1), expiry)),
        "artifacts": context.artifacts, "receipts": receipts}
    context.verify()
    original_context.verify()
    # Refresh all four signatures/deadlines and every equivalence input again
    # immediately before any real private-key access.
    checked_receipts, checked_proof, checked_expiry = prepare_equivalent_matrix(exports,
        original_context=original_context, context=context, original_android_bytes=original_android_bytes)
    if (checked_receipts != receipts or authority.canonical(checked_proof) != authority.canonical(proof)
            or checked_expiry != expiry or authority.utc_now() >= expiry):
        raise authority.TrustedAcquisitionError("equivalence matrix changed or expired before issuance")
    authority.make_manifest.verify_public_key_matches_private(base64.b64encode(context.public_key.read_bytes()).decode(), Path(private_key))
    return authority.make_manifest.acceptance_envelope(payload, Path(private_key)), proof
