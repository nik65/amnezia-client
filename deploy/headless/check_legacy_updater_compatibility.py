#!/usr/bin/env python3
"""Read-only legacy updater compatibility preflight, not release acceptance.

Uses the existing envelope decoder and pinned-key authenticator. It neither
signs metadata nor runs an installer. Unknown baseline source fails closed.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
from verify_provisioning_bundle import decode_manifest_envelope, verify_signature

LEGACY_18_SOURCE_SHA256 = '496b581a7754d8ec38a0162a9a1aef7fb5e187f9a8dcac6afc6c878f15cd6d55'
LEGACY_FILES = ('install_headless.sh', 'amneziad', 'amnezia-cli', 'amneziad.service',
                'package-manifest.json', 'runtime-dependencies.json',
                'runtime-dependencies.txt', 'SHA256SUMS')

def baseline_contract(source: bytes) -> tuple[str, ...]:
    if hashlib.sha256(source).hexdigest() != LEGACY_18_SOURCE_SHA256:
        raise SystemExit('Unknown baseline updater source; no compatibility inference allowed')
    return LEGACY_FILES

def validate_file_contract(payload: dict, expected: tuple[str, ...]) -> None:
    provisioning = payload.get('headlessProvisioning')
    actual = provisioning.get('packageFiles') if isinstance(provisioning, dict) else None
    if not isinstance(actual, list) or any(type(x) is not str for x in actual) or actual != list(expected):
        raise SystemExit('Baseline updater rejects provisioning packageFiles; signing alone cannot repair this contract')

def check(source: bytes, baseline: bytes, candidate: bytes, key: Path, key_sha256: str) -> dict:
    expected = baseline_contract(source)
    payloads = []
    for envelope in (baseline, candidate):
        payload, raw, signature = decode_manifest_envelope(envelope)
        verify_signature(key, raw, signature, key_sha256)
        payloads.append(payload)
    old, new = payloads
    if old.get('version') != '5.0.3.18':
        raise SystemExit('Recognized source contract requires exact 5.0.3.18 baseline')
    validate_file_contract(old, expected)
    validate_file_contract(new, expected)
    return {'scope': 'legacy provisioning-file contract preflight only',
            'baseline_version': old['version'], 'candidate_version': new.get('version'),
            'baseline_source_sha256': LEGACY_18_SOURCE_SHA256,
            'file_contract_compatible': True, 'runtime_tested': False,
            'release_acceptance': False,
            'remaining_checks': ['full signed package validation', 'version progression',
                                 'runtime ABI/dependencies', 'actual updater transaction and restart']}

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline-updater-source', type=Path, required=True)
    parser.add_argument('--baseline-manifest', type=Path, required=True)
    parser.add_argument('--candidate-manifest', type=Path, required=True)
    parser.add_argument('--public-key', type=Path, required=True)
    parser.add_argument('--expected-public-key-sha256', required=True)
    args = parser.parse_args()
    result = check(args.baseline_updater_source.read_bytes(), args.baseline_manifest.read_bytes(),
                   args.candidate_manifest.read_bytes(), args.public_key, args.expected_public_key_sha256)
    print(json.dumps(result, indent=2))
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
