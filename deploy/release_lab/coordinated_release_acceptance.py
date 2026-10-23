"""Explicit aggregate authority for distinct coordinated-headless evidence.

Original acquisition authorities and historical Android envelopes stay intact.
This module has no CLI and never captures a guest or publishes a release.
"""
from __future__ import annotations

import base64
import copy
import hashlib
from datetime import timedelta
from pathlib import Path

from . import trusted_acquisition_export as authority
from .android_dependency_equivalence import verify_android_equivalence


COORDINATED_TARGET = "linux-headless-coordinated"
COORDINATED_SEMANTICS = {"steps", "update", "candidateReboot", "coordinatedRollback", "heldReboot", "resume", "cleanup"}


def _verify_coordinated(envelope, *, context):
    from .coordinated_acquisition_contract import verify_export
    return verify_export(envelope, context=context)


def _digest(value):
    return hashlib.sha256(authority.canonical(value)).hexdigest()


def prepare_coordinated_matrix(*, context, windows_export, gui_export,
                               coordinated_headless_export, android_export,
                               original_android_context, original_android_bytes):
    """Verify four original signed observations; return summaries, proof, expiry."""
    context.verify()
    envelopes = [android_export, gui_export, coordinated_headless_export, windows_export]
    original_bytes = [authority.canonical(e) for e in envelopes]
    if len(set(original_bytes)) != 4:
        raise authority.TrustedAcquisitionError("four distinct role-specific exports required")
    windows = authority.verify_export(windows_export, context=context)
    gui = authority.verify_export(gui_export, context=context)
    if windows["target"] != "windows" or gui["target"] != "linux-gui":
        raise authority.TrustedAcquisitionError("ordinary Windows and GUI roles differ")
    android, android_proof = verify_android_equivalence(android_export,
        original_context=original_android_context, context=context,
        original_envelope_bytes=original_android_bytes)
    if android["target"] != "android":
        raise authority.TrustedAcquisitionError("original real Android role required")
    headless = _verify_coordinated(coordinated_headless_export, context=context)
    if (headless["target"] != COORDINATED_TARGET
            or set(headless["semantics"]) != COORDINATED_SEMANTICS
            or any(value is not True for value in headless["semantics"].values())):
        raise authority.TrustedAcquisitionError("distinct complete coordinated semantics required")
    payloads = [android, gui, headless, windows]
    for p in (windows, gui, headless):
        if authority.canonical(p["binding"]) != authority.canonical(context.binding()):
            raise authority.TrustedAcquisitionError("current full acquisition binding differs")
    expiry = min(authority._utc(p["expiresAt"]) for p in payloads)
    if expiry <= authority.utc_now():
        raise authority.TrustedAcquisitionError("source observation expired")
    receipts = []
    for platform, observations in (("android", [android]), ("linux", [gui, headless]), ("windows", [windows])):
        digest = _digest(android_proof if platform == "android" else observations)
        receipts.append({"platform": platform,
            "kind": "real-device" if platform == "android" else "owned-guest",
            "runId": observations[0]["runId"] if len(observations) == 1 else "linux-" + digest[:32],
            "profileId": observations[0]["profileId"] if len(observations) == 1 else "linux-gui-headless",
            "receiptSha256": digest,
            "cleanupSha256": _digest([p["cleanupCapture"] for p in observations]), "status": "PASS"})
    receipts = authority.make_manifest.acceptance_receipts(receipts)
    proof = {"schema": "amnezia-coordinated-release-derivation-v1",
        "binding": copy.deepcopy(context.binding()), "androidDerivation": android_proof,
        "observations": [{"target": p["target"], "originalEnvelopeSha256": hashlib.sha256(raw).hexdigest(),
                          "payload": copy.deepcopy(p)} for p, raw in zip(payloads, original_bytes)],
        "aggregateProducer": authority.file_record(Path(__file__).absolute())}
    context.verify()
    original_android_context.verify()
    if original_bytes != [authority.canonical(e) for e in envelopes]:
        raise authority.TrustedAcquisitionError("original export bytes changed during preparation")
    return receipts, proof, expiry


def issue_coordinated_acceptance(*, private_key, **inputs):
    """Explicit caller opt-in; verify complete evidence twice before key access."""
    receipts, proof, expiry = prepare_coordinated_matrix(**inputs)
    context = inputs["context"]
    snapshot = authority.canonical([receipts, proof, authority.utc_text(expiry)])
    checked, checked_proof, checked_expiry = prepare_coordinated_matrix(**inputs)
    if (snapshot != authority.canonical([checked, checked_proof, authority.utc_text(checked_expiry)])
            or authority.utc_now() >= expiry):
        raise authority.TrustedAcquisitionError("coordinated aggregate changed or expired before signing")
    now = authority.utc_now()
    payload = {"schema": 1, "policyId": "amnezia-release-full-v1",
        "manifestSha256": context.manifest["sha256"], "publisherSha256": context.publisher["sha256"],
        "version": context.version, "androidVersionCode": context.android_code,
        "issuedAt": authority.utc_text(now), "expiresAt": authority.utc_text(min(now + timedelta(hours=1), expiry)),
        "artifacts": copy.deepcopy(context.artifacts), "receipts": receipts}
    authority.make_manifest.verify_public_key_matches_private(
        base64.b64encode(context.public_key.read_bytes()).decode(), Path(private_key))
    envelope = authority.make_manifest.acceptance_envelope(payload, Path(private_key))
    authority.verify_full_acceptance(envelope, context=context)
    return envelope, proof
