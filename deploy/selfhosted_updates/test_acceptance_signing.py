from __future__ import annotations

import base64
import copy
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest
import sys
from unittest import mock

import make_manifest as manifest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from deploy.release_lab.publication_acceptance import AcceptanceUnavailable, validate_publication_acceptance


class AcceptanceSigningTests(unittest.TestCase):
    def payload(self):
        now = datetime.now(timezone.utc).replace(microsecond=0)
        return {
            "schema": 1, "policyId": "amnezia-release-full-v1",
            "manifestSha256": "1" * 64, "publisherSha256": "2" * 64,
            "version": "5.0.3.11", "androidVersionCode": 2197,
            "issuedAt": (now - timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "expiresAt": (now + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "artifacts": [{"path": "files/artifacts/a/item", "sha256": "3" * 64, "size": 10}],
            "receipts": [{"platform": p, "kind": "real-device" if p == "android" else "owned-guest",
                          "runId": "owned-run", "profileId": p, "receiptSha256": "4" * 64,
                          "cleanupSha256": "5" * 64, "status": "PASS"}
                         for p in ("android", "linux", "windows")],
        }

    def test_signature_domain_and_exact_payload(self):
        payload = self.payload()
        with mock.patch.object(manifest, "sign_payload", return_value="signature") as sign, \
                mock.patch.object(manifest, "verify_payload_signature") as verify:
            envelope = manifest.acceptance_envelope(payload, Path("existing-key"))
        raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        sign.assert_called_once_with(Path("existing-key"), b"amnezia-release-acceptance-v1\n" + raw)
        verify.assert_called_once_with(Path("existing-key"), b"amnezia-release-acceptance-v1\n" + raw, "signature")
        self.assertEqual(base64.urlsafe_b64decode(envelope["payload"] + "=" * (-len(envelope["payload"]) % 4)), b"amnezia-release-acceptance-v1\n" + raw)
        self.assertEqual(set(envelope), {"schema", "signatureAlgorithm", "payload", "signature"})

    def test_missing_linux_or_phone_does_not_reach_signer(self):
        for platform in ("linux", "android"):
            payload = self.payload()
            payload["receipts"] = [r for r in payload["receipts"] if r["platform"] != platform]
            with mock.patch.object(manifest, "sign_payload") as sign, self.assertRaises(SystemExit):
                manifest.acceptance_envelope(payload, Path("existing-key"))
            sign.assert_not_called()

    def test_reject_untrusted_fields_wrong_kind_and_partial_policy(self):
        mutations = [lambda p: p.update(approved=True), lambda p: p.update(policyId="windows-only"),
                     lambda p: p["receipts"][0].update(kind="emulator"),
                     lambda p: p["receipts"][1].update(guestOwned=True),
                     lambda p: p["receipts"][2].update(cleanupSha256=""),
                     lambda p: p.update(schema=True), lambda p: p.update(androidVersionCode=True)]
        for mutate in mutations:
            payload = self.payload()
            mutate(payload)
            with mock.patch.object(manifest, "sign_payload") as sign, self.assertRaises(SystemExit):
                manifest.acceptance_envelope(payload, Path("existing-key"))
            sign.assert_not_called()

    def test_reject_future_expired_and_long_lifetime(self):
        now = datetime.now(timezone.utc)
        for issued, expires in ((now + timedelta(hours=1), now + timedelta(hours=2)),
                                (now - timedelta(hours=2), now - timedelta(hours=1)),
                                (now - timedelta(seconds=1), now + timedelta(hours=25))):
            payload = self.payload()
            payload["issuedAt"] = issued.strftime("%Y-%m-%dT%H:%M:%SZ")
            payload["expiresAt"] = expires.strftime("%Y-%m-%dT%H:%M:%SZ")
            with self.assertRaises(SystemExit):
                manifest.acceptance_envelope(payload, Path("existing-key"))

    def test_reject_artifact_traversal_duplicate_boolean_size(self):
        original = self.payload()
        for artifact in ({"path": "files/../escape", "sha256": "3" * 64, "size": 1},
                         {"path": "files/item", "sha256": "3" * 64, "size": True}):
            payload = copy.deepcopy(original)
            payload["artifacts"] = [artifact]
            with self.assertRaises(SystemExit):
                manifest.acceptance_envelope(payload, Path("existing-key"))
        payload = copy.deepcopy(original)
        payload["artifacts"] *= 2
        with self.assertRaises(SystemExit):
            manifest.acceptance_envelope(payload, Path("existing-key"))

    def test_full_upload_tree_includes_provisioning_and_rollback(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ("artifacts/hash/current", "provisioning/bundle", "rollback/1/old"):
                path = root / "files" / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"content")
            closure = manifest.acceptance_upload_closure(root)
            self.assertEqual([x["path"] for x in closure], ["files/artifacts/hash/current", "files/provisioning/bundle", "files/rollback/1/old"])
            self.assertTrue(all(x["size"] == 7 for x in closure))

    def test_duplicate_json_keys_rejected(self):
        with self.assertRaises(SystemExit):
            json.loads('{"schema":1,"schema":1}', object_pairs_hook=manifest.strict_json_object)

    def test_unsigned_pass_file_cannot_bootstrap_acquisition_authority(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "PASS.json"
            path.write_text('{"status":"PASS","guestOwned":true,"realDevice":true}')
            with self.assertRaisesRegex(AcceptanceUnavailable, "AUTHENTICATION_UNAVAILABLE"):
                validate_publication_acceptance(run_id="owned-run", state_root=Path(tmp),
                                                manifest_path=path, outer_artifact=path,
                                                public_key_path=path, source_authentication_path=path)

    def test_explicit_issuance_without_authority_never_reads_key_or_signs(self):
        with mock.patch.object(manifest, "sign_payload") as sign, self.assertRaisesRegex(SystemExit, "AUTHENTICATION_UNAVAILABLE"):
            manifest.issue_acceptance_main(["--run-id", "owned-run", "--state-root", "missing",
                                            "--manifest", "missing", "--outer-artifact", "missing",
                                            "--public-key", "missing"])
        sign.assert_not_called()


if __name__ == "__main__":
    unittest.main()
