"""Disposable signed fixtures only; no release key, device, network or guest."""
import base64
import copy
from datetime import timedelta
import hashlib
import json
from pathlib import Path
import shutil
import contextlib
import io
import sys
import unittest
from unittest.mock import patch

from . import android_dependency_equivalence as equivalent
from . import trusted_acquisition_export as authority
from . import test_trusted_acquisition_export as fixture_module


class AndroidEquivalenceTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixture_module.TrustedExportTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.f = self.fixture
        self.old_bundle = self.f.bundle
        self.old_payload = copy.deepcopy(self.f.context.manifest_payload)
        self.old_payload["platforms"]["android-arm64-v8a"]["autoInstall"] = True
        provision = self.old_bundle / "files/provisioning"
        provision.write_bytes(b"old provisioning")
        self.old_payload["headlessProvisioning"] = self.record(provision, self.old_bundle)
        self.save_manifest(self.old_bundle, self.old_payload)
        self.old = self.context(self.old_bundle, self.f.outer)
        self.f.context = self.old
        self.new_bundle = self.f.root / "new-bundle"
        shutil.copytree(self.old_bundle, self.new_bundle)
        self.new_payload = copy.deepcopy(self.old_payload)
        for name, data in (("linux-headless-x64", b"new native headless"), ("provisioning", b"new provisioning")):
            path = self.new_bundle / "files" / name
            path.write_bytes(data)
            if name == "provisioning": self.new_payload["headlessProvisioning"] = self.record(path, self.new_bundle)
            else: self.new_payload["platforms"][name] = self.record(path, self.new_bundle)
        self.save_manifest(self.new_bundle, self.new_payload)
        self.new_outer = self.f.root / "new-outer.exe"
        self.new_outer.write_bytes(b"new outer containing only changed headless payload")
        self.new = self.context(self.new_bundle, self.new_outer)
        self.pins = []
        for i in range(5):
            path = self.f.root / ("producer-pin-" + str(i))
            path.write_bytes(("reviewed tool " + str(i)).encode())
            self.pins.append(authority.file_record(path))
        self.pin_patch = patch.object(equivalent, "_expected_provenance", return_value=self.pins)
        self.pin_patch.start()
        self.addCleanup(self.pin_patch.stop)
        self.android = self.f.envelope("android", lambda p: p.update(profileId="android-real-device", provenance=self.pins))
        self.original_bytes = authority.canonical(self.android)

    def record(self, path, bundle):
        return {"url": path.relative_to(bundle).as_posix(), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "size": path.stat().st_size}

    def save_manifest(self, bundle, payload):
        raw = authority.canonical(payload)
        envelope = {"schema": "amnezia-selfhosted-update-v1", "signatureAlgorithm": "Ed25519",
                    "payload": authority.make_manifest.b64url(raw), "signature": base64.b64encode(self.f.key.sign(raw)).decode()}
        (bundle / "manifest.json").write_bytes(authority.canonical(envelope))

    def context(self, bundle, outer):
        return authority.AcquisitionContext.load(bundle=bundle, outer=outer, publisher=self.f.publisher, public_key=self.f.public)

    def verify(self, envelope=None, raw=None):
        return equivalent.verify_android_equivalence(envelope or self.android, original_context=self.old,
            context=self.new, original_envelope_bytes=self.original_bytes if raw is None else raw)

    def test_original_signature_context_and_timestamps_stay_unchanged(self):
        before = copy.deepcopy(self.android)
        original, proof = self.verify()
        self.assertEqual(self.android, before)
        self.assertEqual(proof["originalEnvelope"], before)
        self.assertEqual(proof["originalIssuedAt"], original["issuedAt"])
        self.assertEqual(proof["originalExpiresAt"], original["expiresAt"])
        self.assertFalse(proof["freshCapture"])
        self.assertEqual(proof["originalEnvelopeSha256"], hashlib.sha256(self.original_bytes).hexdigest())
        authority.verify_export(self.android, context=self.old)
        with self.assertRaises(authority.TrustedAcquisitionError):
            authority.verify_export(self.android, context=self.new)

    def test_current_other_three_lanes_and_original_android_aggregate_with_proof_digest(self):
        exports = [self.android] + [self.f.envelope(t, lambda p: p.update(binding=self.new.binding()))
                                   for t in ("windows", "linux-gui", "linux-headless")]
        receipts, proof, expiry = equivalent.prepare_equivalent_matrix(exports, original_context=self.old,
            context=self.new, original_android_bytes=self.original_bytes)
        self.assertEqual([r["platform"] for r in receipts], ["android", "linux", "windows"])
        self.assertEqual(receipts[0]["receiptSha256"], hashlib.sha256(authority.canonical(proof)).hexdigest())
        original = authority.verify_export(self.android, context=self.old)
        self.assertLessEqual(expiry, authority._utc(original["expiresAt"]))
        self.assertEqual(receipts[0]["runId"], original["runId"])

    def test_any_non_headless_manifest_change_rejected(self):
        for field in ("releasePolicy", "androidSetting", "version"):
            changed = copy.deepcopy(self.new_payload)
            changed[field] = ({"deployment":"changed"} if field == "releasePolicy" else "changed") if field != "version" else "5.0.3.15"
            self.save_manifest(self.new_bundle, changed)
            self.new = self.context(self.new_bundle, self.new_outer)
            with self.subTest(field=field), self.assertRaises(authority.TrustedAcquisitionError): self.verify()

    def test_android_descriptor_config_change_rejected(self):
        changed = copy.deepcopy(self.new_payload)
        changed["platforms"]["android-arm64-v8a"]["autoInstall"] = False
        self.save_manifest(self.new_bundle, changed)
        self.new = self.context(self.new_bundle, self.new_outer)
        with self.assertRaisesRegex(authority.TrustedAcquisitionError, "dependency changed"): self.verify()

    def test_bool_to_integer_config_change_is_not_exact_equality(self):
        changed = copy.deepcopy(self.new_payload)
        changed["platforms"]["android-arm64-v8a"]["autoInstall"] = 1
        self.save_manifest(self.new_bundle, changed)
        self.new = self.context(self.new_bundle, self.new_outer)
        with self.assertRaisesRegex(authority.TrustedAcquisitionError, "dependency changed"): self.verify()

    def test_different_publisher_rejected(self):
        publisher = self.f.root / "different-publisher.sh"
        publisher.write_bytes(b"different publisher")
        self.new = authority.AcquisitionContext.load(bundle=self.new_bundle,outer=self.new_outer,
            publisher=publisher, public_key=self.f.public)
        with self.assertRaisesRegex(authority.TrustedAcquisitionError,"key/publisher differs"): self.verify()

    def test_different_valid_manifest_signing_key_rejected(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        key = Ed25519PrivateKey.generate()
        public = self.f.root / "different-public.pem"
        public.write_bytes(key.public_key().public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo))
        raw = authority.canonical(self.new_payload)
        envelope = {"schema":"amnezia-selfhosted-update-v1","signatureAlgorithm":"Ed25519",
                    "payload":authority.make_manifest.b64url(raw),"signature":base64.b64encode(key.sign(raw)).decode()}
        (self.new_bundle/"manifest.json").write_bytes(authority.canonical(envelope))
        self.new = authority.AcquisitionContext.load(bundle=self.new_bundle,outer=self.new_outer,
            publisher=self.f.publisher,public_key=public)
        with self.assertRaisesRegex(authority.TrustedAcquisitionError,"key/publisher differs"): self.verify()

    def test_source_pin_change_during_proof_rejected(self):
        changed = [{**self.pins[0],"sha256":"0"*64}]+self.pins[1:]
        with patch.object(equivalent,"_expected_provenance",side_effect=[self.pins,changed]):
            with self.assertRaisesRegex(authority.TrustedAcquisitionError,"changed during derivation"):self.verify()

    def test_actual_old_input_mutation_during_proof_rejected(self):
        original_verify = authority.AcquisitionContext.verify
        calls = []
        def verify(context):
            if context is self.old:
                calls.append(True)
                if len(calls)==2:
                    (self.old_bundle/"files/linux-headless-x64").write_bytes(b"mutation during proof")
            return original_verify(context)
        with patch.object(authority.AcquisitionContext,"verify",new=verify):
            with self.assertRaises(authority.TrustedAcquisitionError):self.verify()

    def test_changed_apk_rejected_even_with_new_valid_manifest_signature(self):
        path = self.new_bundle / "files/android-arm64-v8a"
        path.write_bytes(b"different Android code")
        changed = copy.deepcopy(self.new_payload)
        changed["platforms"]["android-arm64-v8a"].update(self.record(path, self.new_bundle))
        self.save_manifest(self.new_bundle, changed)
        self.new = self.context(self.new_bundle, self.new_outer)
        with self.assertRaises(authority.TrustedAcquisitionError): self.verify()

    def test_original_context_file_mutation_rejected(self):
        (self.old_bundle / "files/linux-headless-x64").write_bytes(b"changed old tested input")
        with self.assertRaises(authority.TrustedAcquisitionError): self.verify()

    def test_wrong_target_or_incomplete_semantics_rejected(self):
        for target, mutate in (("windows", None), ("android", lambda p:p.update(semantics={})),
                               ("android", lambda p:p["cleanupCapture"].update(sha256="0"*64))):
            e = self.f.envelope(target, mutate)
            with self.assertRaises(authority.TrustedAcquisitionError): self.verify(e, authority.canonical(e))

    def test_source_pin_missing_extra_changed_or_wrong_path_rejected(self):
        for pins in (self.pins[:-1], self.pins + [self.pins[0]], [{**self.pins[0], "sha256":"0"*64}]+self.pins[1:],
                     [{**self.pins[0], "path":"/redirected/source"}]+self.pins[1:]):
            e=self.f.envelope("android", lambda p:p.update(profileId="android-real-device",provenance=pins))
            with self.assertRaises(authority.TrustedAcquisitionError): self.verify(e, authority.canonical(e))

    def test_expired_or_future_original_export_rejected(self):
        now=authority.utc_now()
        for field,value in (("expiresAt",now), ("issuedAt",now+timedelta(hours=1))):
            e=self.f.envelope("android", lambda p:p.update(profileId="android-real-device",provenance=self.pins,**{field:authority.utc_text(value)}))
            with self.assertRaises(authority.TrustedAcquisitionError): self.verify(e,authority.canonical(e))

    def test_envelope_tamper_and_noncanonical_original_bytes_rejected(self):
        e=copy.deepcopy(self.android);e["signature"]="A"*88
        with self.assertRaises(authority.TrustedAcquisitionError):self.verify(e,authority.canonical(e))
        with self.assertRaises(authority.TrustedAcquisitionError):self.verify(raw=self.original_bytes+b"\n")

    def test_missing_lane_refused_before_private_key_access(self):
        with patch.object(authority.make_manifest,"verify_public_key_matches_private") as read_key:
            with self.assertRaises(authority.TrustedAcquisitionError):
                equivalent.issue_equivalent_acceptance([self.android],original_context=self.old,context=self.new,
                    original_android_bytes=self.original_bytes,private_key="never-read")
            read_key.assert_not_called()

    def test_cli_opt_in_is_explicit_complete_and_issue_only(self):
        from . import trusted_acceptance_handoff as handoff
        common=["command","verify","--bundle","/unused/bundle","--outer","/unused/outer",
                "--publisher","/unused/publisher","--public-key","/unused/key"]
        for extra in (["--android-original-bundle","/unused/old"],
                      ["--android-original-bundle","/unused/old","--android-original-outer","/unused/oldouter",
                       "--android-original-export","/unused/export","--android-equivalence-proof-out","/unused/proof"]):
            with patch.object(sys,"argv",common+extra),patch.object(handoff.AcquisitionContext,"load") as load:
                with contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit) as raised:
                    handoff.main()
                self.assertEqual(raised.exception.code,2)
                load.assert_not_called()


if __name__ == "__main__": unittest.main()
