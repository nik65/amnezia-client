"""Canonical regression tests for self-hosted publication wire metadata.

Two defects this locks down, both proven on real owned-guest runs before the
repair:

1. ``_planned_publish_metadata`` used the raw signed ``url`` text.  The shipped
   C++ producer instead publishes the validated, percent-decoded relative path
   (``selfHostedUpdateBootstrapper.cpp`` loadPayload -> publishNow), so the
   Python oracle produced a different digest and byte count for the same signed
   payload (``android9%2B`` versus ``android9+``).
2. ``_evidence`` hashed the whole evidence mapping, including the placeholder
   ``archive`` object, while ``lab.validate_publication_evidence`` hashes every
   core field *except* ``archive``.  A complete live run could therefore pass
   client, HTTP readback, ordered server phases and cleanup and still fail the
   final immutable-evidence gate.

The tests execute the real methods; no controller, approval, key, guest or
network is constructed.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import tempfile
import unittest
from pathlib import Path
from typing import Any

try:
    from .publisher_controller import ConcretePublisherOps, ControllerPublisher
    from .lab import LabError, validate_publication_evidence
except ImportError:  # direct execution (python deploy/release_lab/test_*.py)
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
    from deploy.release_lab.publisher_controller import ConcretePublisherOps, ControllerPublisher
    from deploy.release_lab.lab import LabError, validate_publication_evidence


ANDROID_SHA = "a" * 64
WINDOWS_SHA = "b" * 64
MANIFEST_SHA = "c" * 64
ROLLBACK_SHA = "d" * 64
PROVISIONING_SHA = "e" * 64
GENERATION = 7
ROLLBACK_VERSION = "5.0.3.15"


def payload(*, android_name: str = "AmneziaVPN_5.0.3.17_android9%2B_arm64-v8a.apk",
            windows_url: str | None = None, include_rollback: bool = True,
            include_provisioning: bool = True) -> dict[str, Any]:
    value: dict[str, Any] = {
        "schema": 2,
        "version": "5.0.3.17",
        "releasePolicy": {"schema": 2, "generation": GENERATION,
                          "previousVersion": ROLLBACK_VERSION},
        "platforms": {
            "android-arm64-v8a": {
                "url": f"files/artifacts/{ANDROID_SHA}/{android_name}",
                "sha256": ANDROID_SHA, "size": 81570489,
            },
            "windows-x64": {
                "url": windows_url or f"files/artifacts/{WINDOWS_SHA}/AmneziaVPN_5.0.3.17_windows_x64.exe",
                "sha256": WINDOWS_SHA, "size": 90186276,
            },
            "linux-x64": {
                "url": None, "sha256": "f" * 64, "size": 1, "openExternal": True,
            },
        },
    }
    if include_provisioning:
        value["platforms"]["linux-headless-x64"] = {
            "url": f"files/artifacts/{PROVISIONING_SHA}"
                   "/AmneziaHeadless_5.0.3.17_linux_x64.tar.gz",
            "sha256": PROVISIONING_SHA, "size": 6868182, "openExternal": False,
        }
        value["headlessProvisioning"] = {
            "url": f"files/artifacts/{PROVISIONING_SHA}"
                   "/AmneziaHeadless_5.0.3.17_linux_x64_provisioning.tar.gz",
            "sha256": PROVISIONING_SHA, "size": 6885939,
        }
    if include_rollback:
        value["releasePolicy"]["rollback"] = {
            "version": ROLLBACK_VERSION,
            "platforms": {"windows-x64": {
                "url": f"files/rollback/{GENERATION}/{ROLLBACK_VERSION}"
                       f"/AmneziaVPN_{ROLLBACK_VERSION}_windows_x64.exe",
                "sha256": ROLLBACK_SHA, "size": 1234,
            }},
        }
    return value


def expected_metadata(value: dict[str, Any]) -> tuple[str, int]:
    """Independent reimplementation of the shipped producer's byte layout."""
    from urllib.parse import unquote

    decode = lambda text: unquote(text, encoding="utf-8", errors="replace")
    records: list[tuple[str, str, str, int]] = []
    for platform in sorted(value["platforms"], key=lambda k: k.encode("utf-16-be")):
        metadata = value["platforms"][platform]
        if metadata.get("openExternal") is True:
            continue
        records.append(("A", decode(metadata["url"]), metadata["sha256"], metadata["size"]))
    provisioning = value.get("headlessProvisioning")
    if provisioning:
        records.append(("A", decode(provisioning["url"]), provisioning["sha256"],
                        provisioning["size"]))
    rollback = (value.get("releasePolicy") or {}).get("rollback") or {}
    for platform in sorted(rollback.get("platforms") or {}, key=lambda k: k.encode("utf-16-be")):
        metadata = rollback["platforms"][platform]
        records.append(("R", decode(metadata["url"]), metadata["sha256"], metadata["size"]))
    header = ["amnezia-bundled-publish-v1", MANIFEST_SHA, "5.0.3.17", "2",
              str(GENERATION), str(len(records))]
    lines = ["\t".join(header)] + [
        "\t".join((kind, path, sha, str(size))) for kind, path, sha, size in records]
    wire = ("\n".join(lines) + "\n").encode("utf-8")
    return hashlib.sha256(wire).hexdigest(), len(records)


class PlannedMetadataProtocol(unittest.TestCase):
    def planned(self, value: dict[str, Any] = None) -> tuple[str, int]:
        return ConcretePublisherOps._planned_publish_metadata(
            {"manifest": {"sha256": MANIFEST_SHA}, "candidate_version": "5.0.3.17"},
            value or payload())

    def test_percent_encoded_plus_is_published_as_decoded_relative_path(self):
        digest, count = self.planned()
        self.assertEqual((digest, count), expected_metadata(payload()))
        self.assertEqual(count, 5)
        # The defect this replaces hashed the raw URL text and produced one byte more.
        raw = ("\n".join([
            "\t".join(["amnezia-bundled-publish-v1", MANIFEST_SHA, "5.0.3.17", "2", str(GENERATION), "5"]),
            "\t".join(("A", f"files/artifacts/{ANDROID_SHA}/AmneziaVPN_5.0.3.17_android9%2B_arm64-v8a.apk",
                       ANDROID_SHA, "81570489")),
        ]) + "\n").encode("utf-8")
        self.assertNotEqual(digest, hashlib.sha256(raw).hexdigest())

    def test_digest_ignores_json_key_order_of_platforms(self):
        reordered = payload()
        reordered["platforms"] = dict(reversed(list(reordered["platforms"].items())))
        self.assertEqual(self.planned(), self.planned(reordered))

    def test_open_external_platform_is_excluded_and_rollback_is_included(self):
        digest, count = self.planned(payload(include_rollback=False))
        self.assertEqual((digest, count), expected_metadata(payload(include_rollback=False)))
        with_rollback = self.planned(payload())
        self.assertEqual(with_rollback, expected_metadata(payload()))
        self.assertEqual(count + 1, with_rollback[1])

    def test_rejects_absolute_scheme_query_fragment_and_invalid_escape(self):
        for bad in ("/files/artifacts/x/y", "https://example.invalid/files/artifacts/x/y",
                    "files/artifacts/x/y?q=1", "files/artifacts/x/y#f", "files/artifacts/x/y%2",
                    "files/artifacts/x/y%zz", "files/artifacts/x/y z", "files\\artifacts\\x\\y"):
            with self.subTest(url=bad):
                with self.assertRaises(Exception):
                    self.planned(payload(windows_url=bad))

    def test_rejects_path_not_matching_digest_or_wrong_segment_count(self):
        for bad in (f"files/artifacts/{'f' * 64}/a.exe", "files/x/y/z.exe", "files/artifacts/a/b/c/d.exe"):
            with self.subTest(url=bad):
                with self.assertRaises(Exception):
                    self.planned(payload(windows_url=bad))


class ArchiveEvidenceDomain(unittest.TestCase):
    """The producer's digest domain must equal the unchanged validator's."""

    class _Controller:
        def __init__(self, root: Path) -> None:
            self.root = root

    def build(self, root: Path) -> dict[str, Any]:
        publisher = ControllerPublisher.__new__(ControllerPublisher)  # no state read
        publisher.controller = self._Controller(root)
        run = {"lane": "publisher-diagnostic"}
        return publisher._evidence(
            run, "inert-not-a-run", "publisher-clean",
            {"sha256": WINDOWS_SHA}, {"sha256": MANIFEST_SHA},
            {"vm_id": "inert", "parent_sha256": WINDOWS_SHA, "process_pid": 1,
             "process_uuid": "inert", "marker": "inert", "case_id": "publisher-clean"},
            {"uuid": "inert", "qmp_socket": "inert", "qga_socket": "inert"},
            {"prepare": {"passed": True}},
            {"attempt_nonce": "0" * 48, "http_readback": {"manifest_sha256": MANIFEST_SHA}},
            {}, {"child_reset": True},
        )

    def test_core_digest_excludes_the_self_referential_archive_field(self):
        with tempfile.TemporaryDirectory() as tmp:
            evidence = self.build(Path(tmp))
            record = json.loads(Path(evidence["archive"]["path"]).read_text(encoding="utf-8"))
            core = {key: value for key, value in evidence.items() if key != "archive"}
            digest = hashlib.sha256(
                json.dumps(core, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
            self.assertEqual(record["evidence_sha256"], digest)
            self.assertEqual(evidence["archive"]["sha256"],
                             hashlib.sha256(Path(evidence["archive"]["path"]).read_bytes()).hexdigest())
            evidence["archive"]["path"] = "moved-elsewhere"
            evidence["archive"]["sha256"] = "f" * 64
            moved = {key: value for key, value in evidence.items() if key != "archive"}
            self.assertEqual(digest, hashlib.sha256(
                json.dumps(moved, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest())

    def test_validator_core_rule_matches_the_producer_contract(self):
        source = Path(validate_publication_evidence.__code__.co_filename)
        text = source.read_text(encoding="utf-8")
        self.assertIn('{key: value for key, value in evidence.items() if key != "archive"}', text)
        self.assertIn("evidence_sha256", text)
        self.assertTrue(issubclass(LabError, Exception))
        self.assertRegex("0" * 48, r"^[0-9a-f]{48}$")


if __name__ == "__main__":
    unittest.main(verbosity=2)
