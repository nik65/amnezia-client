"""Disposable-key fixtures exercise authentication; no real release key is read."""
import base64
import copy
from dataclasses import replace
from datetime import timedelta
import hashlib
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from deploy.release_lab import trusted_acquisition_export as authority


class TrustedExportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.key = Ed25519PrivateKey.generate()
        self.public = self.root / "public.pem"
        self.public.write_bytes(self.key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
        self.bundle = self.root / "bundle"
        (self.bundle / "files").mkdir(parents=True)
        platforms = {}
        for platform in ("windows-x64", "linux-x64", "linux-headless-x64", "android-arm64-v8a"):
            path = self.bundle / "files" / platform
            path.write_bytes(platform.encode())
            platforms[platform] = {"url": "files/" + platform, "size": path.stat().st_size,
                                   "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        platforms["android-arm64-v8a"]["versionCode"] = 2200
        payload = authority.canonical({"version": "5.0.3.14", "platforms": platforms})
        envelope = {"schema": "amnezia-selfhosted-update-v1", "signatureAlgorithm": "Ed25519",
                    "payload": authority.make_manifest.b64url(payload), "signature": base64.b64encode(self.key.sign(payload)).decode()}
        (self.bundle / "manifest.json").write_bytes(authority.canonical(envelope))
        self.outer = self.root / "outer.exe"
        self.outer.write_bytes(b"outer")
        self.publisher = self.root / "publisher.sh"
        self.publisher.write_bytes(b"publisher")
        self.context = authority.AcquisitionContext.load(bundle=self.bundle, outer=self.outer,
                        publisher=self.publisher, public_key=self.public)

    def payload(self, target):
        now = authority.utc_now()
        return {"schema": 1, "target": target, "runId": "owned-run", "profileId": target,
                "startedAt": authority.utc_text(now - timedelta(seconds=2)), "completedAt": authority.utc_text(now - timedelta(seconds=1)),
                "issuedAt": authority.utc_text(now), "expiresAt": authority.utc_text(now + timedelta(hours=1)),
                "binding": self.context.binding(), "semantics": {key: True for key in authority.SEMANTICS[target]},
                "rawCapture": authority._blob(b"original live fixture bytes"), "cleanupCapture": authority._blob(b"original cleanup fixture"),
                "provenance": [authority.file_record(self.publisher)]}

    def envelope(self, target, mutate=None, domain=authority.DOMAIN, key=None):
        payload = self.payload(target)
        if mutate: mutate(payload)
        signed = domain + authority.canonical(payload)
        return {"schema": authority.SCHEMA, "signatureAlgorithm": "Ed25519",
                "payload": authority.make_manifest.b64url(signed), "signature": base64.b64encode((key or self.key).sign(signed)).decode()}

    def test_actual_signature_and_full_linux_aggregation(self):
        envelopes = [self.envelope(target) for target in authority.PRODUCERS]
        receipts = authority.full_matrix_receipts(envelopes, context=self.context)
        self.assertEqual([item["platform"] for item in receipts], ["android", "linux", "windows"])
        self.assertEqual(receipts[1]["profileId"], "linux-gui-headless")

    def test_missing_lane_and_duplicate_lane_refused(self):
        complete = [self.envelope(target) for target in authority.PRODUCERS]
        for items in (complete[:-1], complete[:-1] + [complete[0]]):
            with self.assertRaises(authority.TrustedAcquisitionError):
                authority.full_matrix_receipts(items, context=self.context)

    def test_unsigned_pass_and_wrong_signature_refused(self):
        for envelope in ({"status": "PASS"}, self.envelope("android", key=Ed25519PrivateKey.generate())):
            with self.assertRaises(authority.TrustedAcquisitionError):
                authority.verify_export(envelope, context=self.context)

    def test_update_signature_cannot_be_reused_as_acquisition(self):
        with self.assertRaisesRegex(authority.TrustedAcquisitionError, "domain"):
            authority.verify_export(self.envelope("android", domain=b"amnezia-release-acceptance-v1\n"), context=self.context)

    def test_wrong_manifest_artifact_outer_publisher_or_code_refused(self):
        for field, value in (("manifestSha256", "0" * 64), ("outerSha256", "0" * 64),
                             ("publisherSha256", "0" * 64), ("androidVersionCode", 2199), ("artifacts", [])):
            with self.subTest(field=field), self.assertRaises(authority.TrustedAcquisitionError):
                authority.verify_export(self.envelope("windows", lambda p: p["binding"].update({field: value})), context=self.context)

    def test_expired_future_or_out_of_order_refused(self):
        now = authority.utc_now()
        for field, value in (("issuedAt", now + timedelta(seconds=1)), ("expiresAt", now),
                             ("completedAt", now + timedelta(seconds=2)), ("startedAt", now - timedelta(days=2))):
            with self.subTest(field=field), self.assertRaises(authority.TrustedAcquisitionError):
                authority.verify_export(self.envelope("android", lambda p: p.update({field: authority.utc_text(value)})), context=self.context)

    def test_raw_or_cleanup_digest_tampering_refused(self):
        for field in ("rawCapture", "cleanupCapture"):
            with self.subTest(field=field), self.assertRaises(authority.TrustedAcquisitionError):
                authority.verify_export(self.envelope("linux-headless", lambda p: p[field].update(sha256="0" * 64)), context=self.context)

    def test_partial_runtime_semantics_refused(self):
        with self.assertRaisesRegex(authority.TrustedAcquisitionError, "semantics"):
            authority.verify_export(self.envelope("linux-gui", lambda p: p["semantics"].update(visual=False)), context=self.context)

    def test_changed_actual_bundle_refused_before_key_access(self):
        envelopes = [self.envelope(target) for target in authority.PRODUCERS]
        (self.bundle / "files/windows-x64").write_bytes(b"changed")
        with patch.object(authority.make_manifest, "sign_payload") as sign, self.assertRaises(authority.TrustedAcquisitionError):
            authority.issue_full_acceptance(context=self.context, exports=envelopes, private_key="not-read")
        sign.assert_not_called()

    def test_missing_authority_never_reads_or_signs_private_key(self):
        with patch.object(authority.make_manifest, "sign_payload") as sign, \
             patch.object(authority.make_manifest, "verify_public_key_matches_private") as match, \
             self.assertRaises(authority.TrustedAcquisitionError):
            authority.issue_full_acceptance(context=self.context, exports=[], private_key="not-read")
        sign.assert_not_called()
        match.assert_not_called()

    def test_arbitrary_producer_object_rejected_before_acquire(self):
        class FixedProducer: pass
        module = types.SimpleNamespace(AndroidLiveProducer=FixedProducer)
        other = types.SimpleNamespace(acquire=lambda context: self.fail("untrusted producer called"))
        with patch.object(authority.importlib, "import_module", return_value=module), \
             self.assertRaisesRegex(authority.TrustedAcquisitionError, "fixed repository"):
            authority.seal_live_export(other, target="android", context=self.context, private_key="not-read")

    def test_complete_verified_matrix_produces_cpp_compatible_full_v1_payload(self):
        envelopes = [self.envelope(target) for target in authority.PRODUCERS]
        def sign(_key, payload): return base64.b64encode(self.key.sign(payload)).decode()
        with patch.object(authority.make_manifest, "verify_public_key_matches_private"), \
             patch.object(authority.make_manifest, "verify_payload_signature"), \
             patch.object(authority.make_manifest, "sign_payload", side_effect=sign):
            result = authority.issue_full_acceptance(context=self.context, exports=envelopes, private_key="disposable-test-key")
        raw = authority._decode(result["payload"], url=True)
        self.key.public_key().verify(base64.b64decode(result["signature"]), raw)
        self.assertTrue(raw.startswith(authority.make_manifest.RELEASE_ACCEPTANCE_DOMAIN))
        payload = json.loads(raw[len(authority.make_manifest.RELEASE_ACCEPTANCE_DOMAIN):])
        self.assertEqual(payload["policyId"], "amnezia-release-full-v1")
        self.assertEqual(payload["version"], "5.0.3.14")
        self.assertEqual(payload["androidVersionCode"], 2200)
        self.assertEqual(len(payload["receipts"]), 3)

    def test_changed_public_key_and_unadvertised_upload_file_refused(self):
        original = self.public.read_bytes()
        self.public.write_bytes(b"changed")
        with self.assertRaises(authority.TrustedAcquisitionError): self.context.verify()
        self.public.write_bytes(original)
        (self.bundle / "files/unadvertised").write_bytes(b"extra")
        with self.assertRaises(authority.TrustedAcquisitionError):
            authority.AcquisitionContext.load(bundle=self.bundle, outer=self.outer, publisher=self.publisher, public_key=self.public)

    def test_final_approval_does_not_outlive_acquisition(self):
        expiry = authority.utc_text(authority.utc_now() + timedelta(minutes=5))
        envelopes = [self.envelope(target, lambda p: p.update(expiresAt=expiry)) for target in authority.PRODUCERS]
        with patch.object(authority.make_manifest, "verify_public_key_matches_private"), \
             patch.object(authority.make_manifest, "acceptance_envelope", side_effect=lambda payload, key: payload):
            payload = authority.issue_full_acceptance(context=self.context, exports=envelopes, private_key="disposable-test-key")
        self.assertEqual(payload["expiresAt"], expiry)

    def test_partial_fixed_producer_never_reaches_key_or_signer(self):
        result = self.payload("android")
        result = {key: result[key] for key in ("target", "runId", "profileId", "startedAt", "completedAt", "semantics", "provenance")}
        result.update(rawCapture=b"original", cleanupCapture=b"closeout")
        result["semantics"]["realLogDelivery"] = False
        class FixedProducer:
            def acquire(self, context): return copy.deepcopy(result)
        module = types.SimpleNamespace(AndroidLiveProducer=FixedProducer, __file__=str(self.publisher))
        with patch.object(authority.importlib, "import_module", return_value=module), \
             patch.object(authority.make_manifest, "sign_payload") as sign, \
             patch.object(authority.make_manifest, "verify_public_key_matches_private") as match, \
             self.assertRaisesRegex(authority.TrustedAcquisitionError, "semantics"):
            authority.seal_live_export(FixedProducer(), target="android", context=self.context, private_key="not-read")
        sign.assert_not_called()
        match.assert_not_called()

    def test_instance_callable_cannot_replace_fixed_live_implementation(self):
        result = self.payload("android")
        result = {key: result[key] for key in ("target", "runId", "profileId", "startedAt", "completedAt", "semantics", "provenance")}
        result.update(rawCapture=b"original", cleanupCapture=b"closeout")
        class FixedProducer:
            def acquire(self, context): return copy.deepcopy(result)
        producer = FixedProducer()
        producer.acquire = lambda context: self.fail("instance plugin invoked")
        module = types.SimpleNamespace(AndroidLiveProducer=FixedProducer, __file__=str(self.publisher))
        def sign(_key, payload): return base64.b64encode(self.key.sign(payload)).decode()
        with patch.object(authority.importlib, "import_module", return_value=module), \
             patch.object(authority.make_manifest, "verify_public_key_matches_private"), \
             patch.object(authority.make_manifest, "sign_payload", side_effect=sign):
            envelope = authority.seal_live_export(producer, target="android", context=self.context, private_key="disposable-test-key")
        self.assertEqual(authority.verify_export(envelope, context=self.context)["target"], "android")

    def test_mutated_derived_identity_and_key_path_rejected(self):
        for changes in ({"version": "9.9.9.9"}, {"android_code": 1}, {"android_code": True},
                        {"public_key": self.publisher}, {"bundle": self.root}):
            with self.subTest(changes=changes), self.assertRaisesRegex(authority.TrustedAcquisitionError, "derived acceptance identity"):
                replace(self.context, **changes).verify()


if __name__ == "__main__": unittest.main()
