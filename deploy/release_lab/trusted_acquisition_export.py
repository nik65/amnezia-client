"""Live producer exports and complete-matrix acceptance using one release key.

Only fixed repository producer classes can initiate an export. Imported files
are accepted only as previously signed, domain-separated acquisition exports;
unsigned PASS JSON is never an acquisition source. Producers must execute their
live capture, semantic validation and cleanup inside acquire(), before signing.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
from urllib.parse import unquote

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from deploy.selfhosted_updates import make_manifest
from .android_real_device_acquisition import file_record

SCHEMA = "amnezia-live-acquisition-v1"
DOMAIN = (SCHEMA + "\n").encode()
MAX_EXPORT_BYTES = 64 * 1024 * 1024
ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
SHA = re.compile(r"[0-9a-f]{64}")
PRODUCERS = {
    "windows": ("deploy.release_lab.trusted_windows_acquisition", "WindowsLiveProducer"),
    "linux-gui": ("deploy.release_lab.linux_live_acquisition", "LinuxLiveProducer"),
    "linux-headless": ("deploy.release_lab.linux_live_acquisition", "LinuxLiveProducer"),
    "android": ("deploy.release_lab.android_real_device_acceptance", "AndroidLiveProducer"),
}
SEMANTICS = {
    "windows": {"matrix", "interactive", "cleanup"},
    "linux-gui": {"steps", "visual", "cleanup"},
    "linux-headless": {"steps", "update", "rollback", "reboot", "cleanup"},
    "android": {"installedIdentity", "serviceIdentity", "vpnValidated", "realLogDelivery", "noFatal", "readonlyCloseout"},
}


class TrustedAcquisitionError(RuntimeError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0)


def utc_text(value):
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def _utc(text):
    try:
        value = datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError) as error:
        raise TrustedAcquisitionError("noncanonical acquisition UTC timestamp") from error
    if utc_text(value) != text:
        raise TrustedAcquisitionError("noncanonical acquisition UTC timestamp")
    return value


def _decode(text, *, url=False):
    if not isinstance(text, str):
        raise TrustedAcquisitionError("base64 field type")
    try:
        if url:
            if not re.fullmatch(r"[A-Za-z0-9_-]+", text):
                raise ValueError("base64url syntax")
            data = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
            if make_manifest.b64url(data) != text:
                raise ValueError("noncanonical base64url")
        else:
            data = base64.b64decode(text, validate=True)
            if base64.b64encode(data).decode() != text:
                raise ValueError("noncanonical base64")
        return data
    except ValueError as error:
        raise TrustedAcquisitionError("invalid acquisition base64") from error


def _json(data):
    try:
        return json.loads(data, object_pairs_hook=make_manifest.strict_json_object)
    except (ValueError, UnicodeDecodeError, SystemExit) as error:
        raise TrustedAcquisitionError("invalid/duplicate acquisition JSON") from error


def _public(path):
    key = load_pem_public_key(Path(path).read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise TrustedAcquisitionError("existing Ed25519 release key required")
    return key


@dataclass(frozen=True)
class AcquisitionContext:
    bundle: Path
    public_key: Path
    manifest: dict
    outer: dict
    publisher: dict
    artifacts: list
    version: str
    android_code: int
    manifest_payload: dict
    public_key_record: dict

    @classmethod
    def load(cls, *, bundle, outer, publisher, public_key):
        bundle = Path(bundle).absolute()
        manifest = file_record(bundle / "manifest.json")
        if manifest["size"] > 1024 * 1024:
            raise TrustedAcquisitionError("manifest exceeds client response bound")
        envelope = _json(Path(manifest["path"]).read_bytes())
        if (not isinstance(envelope, dict) or set(envelope) != {"schema", "signatureAlgorithm", "payload", "signature"}
                or envelope["schema"] != "amnezia-selfhosted-update-v1" or envelope["signatureAlgorithm"] != "Ed25519"):
            raise TrustedAcquisitionError("signed update manifest envelope required")
        payload_bytes = _decode(envelope["payload"], url=True)
        try:
            _public(public_key).verify(_decode(envelope["signature"]), payload_bytes)
        except InvalidSignature as error:
            raise TrustedAcquisitionError("manifest signature mismatch") from error
        payload = _json(payload_bytes)
        if (not isinstance(payload, dict) or not isinstance(payload.get("version"), str)
                or not make_manifest.VERSION_RE.fullmatch(payload["version"])):
            raise TrustedAcquisitionError("manifest version identity")
        platforms = payload.get("platforms")
        expected = {"windows-x64", "linux-x64", "linux-headless-x64", "android-arm64-v8a"}
        if not isinstance(platforms, dict) or set(platforms) != expected:
            raise TrustedAcquisitionError("complete release platform manifest required")
        code = platforms["android-arm64-v8a"].get("versionCode")
        if type(code) is not int or not 0 < code <= make_manifest.MAX_ANDROID_VERSION_CODE:
            raise TrustedAcquisitionError("Android manifest code")
        context = cls(bundle, Path(public_key).absolute(), manifest, file_record(outer), file_record(publisher),
                      make_manifest.acceptance_upload_closure(bundle), payload["version"], code, payload, file_record(public_key))
        context.verify()
        return context

    def candidate(self, platform):
        record = self.manifest_payload["platforms"][platform]
        return self._manifest_artifact(record)

    def _manifest_artifact(self, record):
        if (not isinstance(record, dict) or not isinstance(record.get("url"), str)
                or not isinstance(record.get("sha256"), str) or not SHA.fullmatch(record["sha256"])
                or type(record.get("size")) is not int or record["size"] <= 0):
            raise TrustedAcquisitionError("manifest artifact identity")
        path = self.bundle / unquote(record["url"])
        if not path.resolve().is_relative_to(self.bundle.resolve()):
            raise TrustedAcquisitionError("manifest artifact escaped bundle")
        actual = file_record(path)
        if actual["sha256"] != record["sha256"] or actual["size"] != record["size"]:
            raise TrustedAcquisitionError("manifest artifact bytes differ")
        return actual

    def verify(self):
        if (self.version != self.manifest_payload.get("version")
                or type(self.android_code) is not int
                or self.android_code != (self.manifest_payload.get("platforms", {}).get("android-arm64-v8a") or {}).get("versionCode")
                or Path(self.public_key).absolute() != Path(self.public_key_record["path"]).absolute()
                or (self.bundle / "manifest.json").absolute() != Path(self.manifest["path"]).absolute()):
            raise TrustedAcquisitionError("derived acceptance identity differs from signed source")
        for record in (self.manifest, self.outer, self.publisher, self.public_key_record):
            if file_record(record["path"]) != record:
                raise TrustedAcquisitionError("acceptance input bytes changed")
        current = _json(Path(self.manifest["path"]).read_bytes())
        if _json(_decode(current["payload"], url=True)) != self.manifest_payload:
            raise TrustedAcquisitionError("in-memory manifest identity changed")
        if make_manifest.acceptance_upload_closure(self.bundle) != self.artifacts:
            raise TrustedAcquisitionError("acceptance upload closure changed")
        advertised = list(self.manifest_payload["platforms"].values())
        if "headlessProvisioning" in self.manifest_payload:
            advertised.append(self.manifest_payload["headlessProvisioning"])
        rollback = (self.manifest_payload.get("releasePolicy") or {}).get("rollback") or {}
        advertised.extend((rollback.get("platforms") or {}).values())
        expected = []
        for record in advertised:
            self._manifest_artifact(record)
            expected.append({"path": unquote(record["url"]), "sha256": record["sha256"], "size": record["size"]})
        expected.sort(key=lambda value: value["path"])
        if expected != self.artifacts:
            raise TrustedAcquisitionError("signed advertised closure differs from complete upload tree")

    def binding(self):
        return {"version": self.version, "androidVersionCode": self.android_code,
                "manifestSha256": self.manifest["sha256"], "outerSha256": self.outer["sha256"],
                "publisherSha256": self.publisher["sha256"], "artifacts": self.artifacts}


def _blob(raw):
    if not isinstance(raw, bytes) or not 0 < len(raw) <= 32 * 1024 * 1024:
        raise TrustedAcquisitionError("original acquisition bytes required within bounds")
    return {"sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw), "bytes": base64.b64encode(raw).decode()}


def _check_blob(blob):
    if not isinstance(blob, dict) or set(blob) != {"sha256", "size", "bytes"}:
        raise TrustedAcquisitionError("original capture shape")
    raw = _decode(blob["bytes"])
    if type(blob["size"]) is not int or _blob(raw) != blob:
        raise TrustedAcquisitionError("original capture digest/size differs")
    return raw


def _validate_payload(payload, context, *, now):
    fields = {"schema", "target", "runId", "profileId", "issuedAt", "expiresAt", "startedAt", "completedAt",
              "binding", "semantics", "rawCapture", "cleanupCapture", "provenance"}
    if not isinstance(payload, dict) or set(payload) != fields or type(payload["schema"]) is not int or payload["schema"] != 1:
        raise TrustedAcquisitionError("exact acquisition payload schema required")
    target = payload["target"]
    if target not in SEMANTICS or payload["binding"] != context.binding():
        raise TrustedAcquisitionError("acquisition target or exact release binding differs")
    if any(not isinstance(payload[k], str) or not ID.fullmatch(payload[k]) for k in ("runId", "profileId")):
        raise TrustedAcquisitionError("acquisition run/profile identity")
    started, completed, issued, expires = map(_utc, (payload[k] for k in ("startedAt", "completedAt", "issuedAt", "expiresAt")))
    if not started <= completed <= issued <= now < expires <= issued + timedelta(hours=24) or issued - started > timedelta(hours=24):
        raise TrustedAcquisitionError("acquisition is stale, future, expired or out of order")
    semantics = payload["semantics"]
    if not isinstance(semantics, dict) or set(semantics) != SEMANTICS[target] or any(value is not True for value in semantics.values()):
        raise TrustedAcquisitionError("incomplete existing runtime/cleanup semantics")
    _check_blob(payload["rawCapture"])
    _check_blob(payload["cleanupCapture"])
    provenance = payload["provenance"]
    if not isinstance(provenance, list) or not provenance:
        raise TrustedAcquisitionError("producer provenance missing")
    names = set()
    for record in provenance:
        if (not isinstance(record, dict) or set(record) != {"path", "sha256", "size"}
                or not isinstance(record["path"], str) or record["path"] in names
                or not isinstance(record["sha256"], str) or not SHA.fullmatch(record["sha256"])
                or type(record["size"]) is not int or record["size"] <= 0):
            raise TrustedAcquisitionError("producer provenance shape")
        names.add(record["path"])
    return payload


def seal_live_export(producer, *, target, context, private_key):
    """Invoke a fixed live producer, then sign. There is no JSON proof input."""
    if target not in PRODUCERS:
        raise TrustedAcquisitionError("unsupported live producer")
    module_name, class_name = PRODUCERS[target]
    module = importlib.import_module(module_name)
    producer_class = getattr(module, class_name)
    if type(producer) is not producer_class:
        raise TrustedAcquisitionError("fixed repository live producer required")
    producer_record = file_record(Path(module.__file__).absolute())
    authority_record = file_record(Path(__file__).absolute())
    context.verify()
    # Do not dispatch an instance-supplied callable/plugin in place of the
    # fixed reviewed implementation. Constructor parameters select identities,
    # not executable acquisition code.
    result = producer_class.acquire(producer, context)
    expected = {"target", "runId", "profileId", "startedAt", "completedAt", "rawCapture", "cleanupCapture", "semantics", "provenance"}
    if not isinstance(result, dict) or set(result) != expected or result["target"] != target:
        raise TrustedAcquisitionError("live producer result contract")
    if file_record(producer_record["path"]) != producer_record or file_record(authority_record["path"]) != authority_record:
        raise TrustedAcquisitionError("producer/authority source changed during live acquisition")
    context.verify()
    now = utc_now()
    provenance = list(result["provenance"])
    for record in (producer_record, authority_record):
        if record not in provenance:
            provenance.append(record)
    for record in provenance:
        if file_record(record["path"]) != record:
            raise TrustedAcquisitionError("acquisition provenance changed")
    payload = {"schema": 1, "target": target, "runId": result["runId"], "profileId": result["profileId"],
               "startedAt": result["startedAt"], "completedAt": result["completedAt"], "issuedAt": utc_text(now),
               "expiresAt": utc_text(now + timedelta(hours=24)), "binding": context.binding(), "semantics": result["semantics"],
               "rawCapture": _blob(result["rawCapture"]), "cleanupCapture": _blob(result["cleanupCapture"]), "provenance": provenance}
    _validate_payload(payload, context, now=now)
    signed = DOMAIN + canonical(payload)
    if len(signed) > (MAX_EXPORT_BYTES - 2048) * 3 // 4:
        raise TrustedAcquisitionError("acquisition export exceeds bound")
    private_key = Path(private_key)
    make_manifest.verify_public_key_matches_private(base64.b64encode(context.public_key.read_bytes()).decode(), private_key)
    signature = make_manifest.sign_payload(private_key, signed)
    envelope = {"schema": SCHEMA, "signatureAlgorithm": "Ed25519", "payload": make_manifest.b64url(signed), "signature": signature}
    if len(canonical(envelope)) > MAX_EXPORT_BYTES:
        raise TrustedAcquisitionError("acquisition export exceeds bound")
    verify_export(envelope, context=context)
    return envelope


def verify_export(envelope, *, context):
    context.verify()
    if not isinstance(envelope, dict) or set(envelope) != {"schema", "signatureAlgorithm", "payload", "signature"} or envelope["schema"] != SCHEMA or envelope["signatureAlgorithm"] != "Ed25519":
        raise TrustedAcquisitionError("authenticated acquisition export required")
    if not isinstance(envelope["payload"], str) or len(envelope["payload"]) > MAX_EXPORT_BYTES:
        raise TrustedAcquisitionError("acquisition export exceeds bound")
    signed = _decode(envelope["payload"], url=True)
    if not signed.startswith(DOMAIN):
        raise TrustedAcquisitionError("acquisition signature domain mismatch")
    try:
        _public(context.public_key).verify(_decode(envelope["signature"]), signed)
    except InvalidSignature as error:
        raise TrustedAcquisitionError("acquisition signature mismatch") from error
    payload_bytes = signed[len(DOMAIN):]
    payload = _json(payload_bytes)
    if canonical(payload) != payload_bytes:
        raise TrustedAcquisitionError("noncanonical signed acquisition payload")
    return _validate_payload(payload, context, now=utc_now())


def full_matrix_receipts(envelopes, *, context):
    if not isinstance(envelopes, list) or len(envelopes) != 4:
        raise TrustedAcquisitionError("Windows, both Linux lanes and real Android exports required")
    context.verify()
    verified = {}
    for envelope in envelopes:
        payload = verify_export(envelope, context=context)
        if payload["target"] in verified:
            raise TrustedAcquisitionError("duplicate acquisition target")
        verified[payload["target"]] = payload
    if set(verified) != set(PRODUCERS):
        raise TrustedAcquisitionError("complete authenticated acquisition matrix required")
    receipts = []
    for platform, targets in (("android", ["android"]), ("linux", ["linux-gui", "linux-headless"]), ("windows", ["windows"])):
        proofs = [verified[target] for target in targets]
        digest = hashlib.sha256(canonical(proofs)).hexdigest()
        cleanup = hashlib.sha256(canonical([proof["cleanupCapture"] for proof in proofs])).hexdigest()
        receipts.append({"platform": platform, "kind": "real-device" if platform == "android" else "owned-guest",
                         "runId": proofs[0]["runId"] if len(proofs) == 1 else "linux-" + digest[:32],
                         "profileId": proofs[0]["profileId"] if len(proofs) == 1 else "linux-gui-headless",
                         "receiptSha256": digest, "cleanupSha256": cleanup, "status": "PASS"})
    return make_manifest.acceptance_receipts(receipts)


def issue_full_acceptance(*, context, exports, private_key):
    """Verify complete previously live-acquired exports before any key access."""
    receipts = full_matrix_receipts(exports, context=context)
    now = utc_now()
    source_expiry = min(_utc(verify_export(value, context=context)["expiresAt"]) for value in exports)
    payload = {"schema": 1, "policyId": "amnezia-release-full-v1", "manifestSha256": context.manifest["sha256"],
               "publisherSha256": context.publisher["sha256"], "version": context.version, "androidVersionCode": context.android_code,
               "issuedAt": utc_text(now), "expiresAt": utc_text(min(now + timedelta(hours=1), source_expiry)), "artifacts": context.artifacts, "receipts": receipts}
    context.verify()
    private_key = Path(private_key)
    make_manifest.verify_public_key_matches_private(base64.b64encode(context.public_key.read_bytes()).decode(), private_key)
    return make_manifest.acceptance_envelope(payload, private_key)


def verify_full_acceptance(envelope, *, context):
    """Passive check matching the client's full-v1 signature/binding policy."""
    context.verify()
    if (not isinstance(envelope, dict) or set(envelope) != {"schema", "signatureAlgorithm", "payload", "signature"}
            or envelope["schema"] != make_manifest.RELEASE_ACCEPTANCE_SCHEMA or envelope["signatureAlgorithm"] != "Ed25519"
            or len(canonical(envelope)) > 128 * 1024):
        raise TrustedAcquisitionError("client-compatible full acceptance envelope required")
    signed = _decode(envelope["payload"], url=True)
    if not signed.startswith(make_manifest.RELEASE_ACCEPTANCE_DOMAIN):
        raise TrustedAcquisitionError("full acceptance signature domain differs")
    try:
        _public(context.public_key).verify(_decode(envelope["signature"]), signed)
    except InvalidSignature as error:
        raise TrustedAcquisitionError("full acceptance signature mismatch") from error
    raw = signed[len(make_manifest.RELEASE_ACCEPTANCE_DOMAIN):]
    payload = _json(raw)
    fields = {"schema", "policyId", "manifestSha256", "publisherSha256", "version", "androidVersionCode",
              "issuedAt", "expiresAt", "artifacts", "receipts"}
    if (not isinstance(payload, dict) or set(payload) != fields or canonical(payload) != raw
            or type(payload["schema"]) is not int or payload["schema"] != 1
            or payload["policyId"] != "amnezia-release-full-v1"
            or payload["manifestSha256"] != context.manifest["sha256"]
            or payload["publisherSha256"] != context.publisher["sha256"]
            or payload["version"] != context.version or type(payload["androidVersionCode"]) is not int
            or payload["androidVersionCode"] != context.android_code or payload["artifacts"] != context.artifacts):
        raise TrustedAcquisitionError("full acceptance exact release binding differs")
    issued, expires = _utc(payload["issuedAt"]), _utc(payload["expiresAt"])
    if not issued <= utc_now() < expires <= issued + timedelta(hours=24):
        raise TrustedAcquisitionError("full acceptance expired, future or overlong")
    try:
        if make_manifest.acceptance_receipts(payload["receipts"]) != payload["receipts"]:
            raise TrustedAcquisitionError("full acceptance receipt order differs")
    except SystemExit as error:
        raise TrustedAcquisitionError("complete client acceptance receipt matrix required") from error
    return payload
