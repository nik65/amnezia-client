import base64
import json
import unittest
from pathlib import Path

try:
    from .publisher_filemap import PublisherFileMapError, canonical_publisher_file_map, validate_observed_file_map
except ImportError:
    from publisher_filemap import PublisherFileMapError, canonical_publisher_file_map, validate_observed_file_map


class PublisherFileMapTests(unittest.TestCase):
    @staticmethod
    def current_payload():
        path = Path(__file__).parents[2] / "dist" / "full-release-5.0.1.39-20260913" / "updates" / "manifest.json"
        envelope = json.loads(path.read_text(encoding="utf-8"))
        encoded = envelope["payload"]
        return json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))

    @staticmethod
    def run_for(payload):
        artifacts = {
            platform: {"sha256": item["sha256"], "size": item["size"], "path": f"/frozen/{platform}"}
            for platform, item in payload["platforms"].items()
        }
        return {"artifacts": artifacts, "baseline_artifacts": {}}

    def test_current_manifest_maps_four_platforms_and_signed_provisioning(self):
        payload = self.current_payload()
        result = canonical_publisher_file_map(self.run_for(payload), payload)
        self.assertEqual(set(result), {
            "platform:windows-x64", "platform:android-arm64-v8a",
            "platform:linux-x64", "platform:linux-headless-x64", "headlessProvisioning",
        })
        self.assertEqual(result["headlessProvisioning"]["sha256"], "9d4307a61e06c4fec4ad9085f801dd8cad0e3564a66ca6debc54dc8e9584c289")
        validate_observed_file_map(result, {label: dict(item) for label, item in result.items()})

    def test_optional_rollback_is_bound_to_frozen_baseline(self):
        payload = self.current_payload(); run = self.run_for(payload)
        baseline = {"sha256": "a" * 64, "size": 17, "path": "/frozen/old.exe"}
        run["baseline_artifacts"]["windows-x64"] = baseline
        payload["releasePolicy"] = {"rollback": {"platforms": {"windows-x64": {
            "url": "files/artifacts/" + "a" * 64 + "/old.exe", "sha256": "a" * 64, "size": 17,
        }}}}
        result = canonical_publisher_file_map(run, payload)
        self.assertEqual(result["rollback:windows-x64"]["sha256"], baseline["sha256"])
        payload["releasePolicy"]["rollback"]["platforms"]["windows-x64"]["size"] = 18
        with self.assertRaisesRegex(PublisherFileMapError, "frozen plan"):
            canonical_publisher_file_map(run, payload)

    def test_rejects_missing_extra_or_mislabeled_http_records(self):
        payload = self.current_payload(); expected = canonical_publisher_file_map(self.run_for(payload), payload)
        for observed in (
            {k: v for k, v in expected.items() if k != "headlessProvisioning"},
            {**expected, "rollback:fake": {"path": "files/artifacts/x", "sha256": "a" * 64, "size": 1}},
            {("windows-x64" if k == "platform:windows-x64" else k): v for k, v in expected.items()},
        ):
            with self.assertRaisesRegex(PublisherFileMapError, "set is incomplete"):
                validate_observed_file_map(expected, observed)

    def test_rejects_bool_size_duplicate_path_and_changed_bytes(self):
        payload = self.current_payload(); run = self.run_for(payload)
        payload["platforms"]["windows-x64"]["size"] = True
        with self.assertRaisesRegex(PublisherFileMapError, "size"):
            canonical_publisher_file_map(run, payload)
        payload = self.current_payload(); run = self.run_for(payload)
        payload["headlessProvisioning"]["url"] = payload["platforms"]["linux-headless-x64"]["url"]
        with self.assertRaisesRegex(PublisherFileMapError, "duplicate"):
            canonical_publisher_file_map(run, payload)
        payload = self.current_payload(); expected = canonical_publisher_file_map(self.run_for(payload), payload)
        observed = {label: dict(item) for label, item in expected.items()}
        observed["platform:windows-x64"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(PublisherFileMapError, "bytes/path"):
            validate_observed_file_map(expected, observed)

    def test_controller_keeps_nonce_and_exact_eof_gates(self):
        source = (Path(__file__).parent / "publisher_controller.py").read_text(encoding="utf-8")
        self.assertIn('if response.read(1):', source)
        self.assertIn('if nonce != self._attempt_nonce', source)
        self.assertIn('attempt_nonce": nonce', source)


if __name__ == "__main__":
    unittest.main()
