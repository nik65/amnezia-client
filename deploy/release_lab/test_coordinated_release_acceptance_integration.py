"""Disposable signatures + actual verifiers; synthetic artifacts, never release proof."""
import base64
import copy
from dataclasses import replace
from datetime import timedelta
import hashlib
from unittest.mock import patch

import pytest

from deploy.release_lab import coordinated_release_acceptance as facade
from deploy.release_lab import coordinated_acquisition_contract as contract
from deploy.release_lab import trusted_acquisition_export as authority
from deploy.release_lab import android_dependency_equivalence as android
from deploy.release_lab import test_coordinated_acquisition_contract as fixture


def ordinary_envelope(payload, key):
    signed = authority.DOMAIN + authority.canonical(payload)
    return {'schema': authority.SCHEMA, 'signatureAlgorithm': 'Ed25519',
        'payload': authority.make_manifest.b64url(signed),
        'signature': base64.b64encode(key.sign(signed)).decode()}


@pytest.fixture
def matrix(tmp_path, monkeypatch, request):
    plan = fixture.f.plan()
    version = getattr(request, 'param', '5.0.3.14')
    plan = replace(plan, candidate=replace(plan.candidate, version=version),
                   baseline=replace(plan.baseline, version='5.0.3.13'))
    monkeypatch.setattr(fixture.f, 'plan', lambda: plan)
    sample = fixture.synthetic_signed_fixture(tmp_path, monkeypatch)
    # The contract fixture intentionally patches only physical context.verify:
    # no synthetic tar is represented as an installed/tested release artifact.
    monkeypatch.setattr(authority, 'utc_now', lambda: fixture.NOW)
    context = replace(sample['context'], android_code=2201 if version == '5.0.3.15' else 2200)
    payload = copy.deepcopy(context.manifest_payload)
    payload['version'] = context.version
    extra = []
    for name in ('android-arm64-v8a', 'windows-x64', 'linux-x64', 'provisioning'):
        path = tmp_path / ('fixture-' + name)
        path.write_bytes(('synthetic ' + name).encode())
        record = {'url': path.name, 'size': path.stat().st_size,
                  'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
        if name == 'provisioning':
            payload['headlessProvisioning'] = record
        else:
            payload['platforms'][name] = record
        if name == 'android-arm64-v8a':record['versionCode'] = context.android_code
        extra.append({'path': path.name, 'size': record['size'], 'sha256': record['sha256']})
    context = replace(context, manifest_payload=payload, artifacts=context.artifacts + extra)
    old_payload = copy.deepcopy(payload)
    old_payload['headlessProvisioning']['sha256'] = '7' * 64
    old_payload['platforms']['linux-headless-x64']['sha256'] = '8' * 64
    old = replace(context, manifest_payload=old_payload,
        manifest={**context.manifest, 'sha256': '9' * 64},
        outer={**context.outer, 'sha256': 'a' * 64})
    pins = []
    for i in range(5):
        path = tmp_path / ('test-producer-' + str(i));path.write_bytes(b'disposable tool fixture')
        pins.append(authority.file_record(path))
    monkeypatch.setattr(android, '_expected_provenance', lambda: pins)
    def old_export(target, source_context):
        value = copy.deepcopy(sample['payload'])
        value.update(target=target, profileId='android-real-device' if target == 'android' else target, binding=source_context.binding(),
            semantics=dict.fromkeys(authority.SEMANTICS[target], True), provenance=pins,
            rawCapture=authority._blob(b'original synthetic ordinary capture'),
            cleanupCapture=authority._blob(b'original synthetic ordinary cleanup'))
        return ordinary_envelope(value, sample['key'])
    headless = copy.deepcopy(sample['payload'])
    raw = copy.deepcopy(sample['raw'])
    raw['binding'] = context.binding();raw['registration']['binding'] = context.binding()
    headless.update(binding=context.binding(), rawCapture=authority._blob(authority.canonical(raw)))
    android_export = old_export('android', old)
    inputs = dict(context=context, original_android_context=old,
        original_android_bytes=authority.canonical(android_export), android_export=android_export,
        windows_export=old_export('windows', context), gui_export=old_export('linux-gui', context),
        coordinated_headless_export=fixture.resign(headless, sample['key']))
    return inputs, sample, headless


def test_actual_four_domain_verification_and_historical_dependency(matrix):
    inputs, sample, headless = matrix
    receipts, proof, expiry = facade.prepare_coordinated_matrix(**inputs)
    assert [r['platform'] for r in receipts] == ['android', 'linux', 'windows']
    assert proof['observations'][2]['payload'] == headless
    assert proof['androidDerivation']['freshCapture'] is False
    assert expiry == authority._utc(headless['expiresAt'])


@pytest.fixture
def fresh_matrix(matrix):
    inputs, sample, headless = matrix
    current = inputs['context']
    payload = authority.verify_export(inputs['android_export'], context=inputs['original_android_context'])
    payload['binding'] = current.binding()
    inputs['android_export'] = ordinary_envelope(payload, sample['key'])
    inputs.update(original_android_context=replace(current),
        original_android_bytes=authority.canonical(inputs['android_export']))
    return inputs, sample


@pytest.mark.parametrize('matrix', ['5.0.3.15'], indirect=True)
def test_actual_fresh_current_15_android_uses_normal_verifier(fresh_matrix):
    inputs, _ = fresh_matrix
    before = authority.canonical(inputs['android_export'])
    with patch.object(facade, 'verify_android_equivalence', side_effect=AssertionError('historical path')):
        receipts, proof, _ = facade.prepare_coordinated_matrix(**inputs)
    assert receipts[0]['kind'] == 'real-device'
    derived = proof['androidDerivation']
    assert derived['schema'] == 'amnezia-android-current-acquisition-derivation-v1'
    assert derived['freshCapture'] is True
    assert derived['originalEnvelopeSha256'] == hashlib.sha256(before).hexdigest()
    assert before == authority.canonical(inputs['android_export'])


@pytest.mark.parametrize('matrix', ['5.0.3.15'], indirect=True)
@pytest.mark.parametrize('mutation', ['signature', 'raw', 'cleanup', 'partial', 'false', 'expired',
    'binding', 'profile', 'target', 'bytes', 'original-manifest', 'original-payload', 'original-version'])
def test_fresh_current_android_rejects_invalid_inputs(fresh_matrix, mutation):
    inputs, sample = fresh_matrix
    payload = authority.verify_export(inputs['android_export'], context=inputs['context'])
    if mutation == 'signature':
        inputs['android_export']['signature'] = base64.b64encode(b'0' * 64).decode()
    elif mutation == 'bytes':
        inputs['original_android_bytes'] += b'\n'
    elif mutation.startswith('original-'):
        old = inputs['original_android_context']
        if mutation == 'original-manifest':
            old = replace(old, manifest={**old.manifest, 'sha256': '0' * 64})
        elif mutation == 'original-payload':
            changed = copy.deepcopy(old.manifest_payload); changed['version'] = 'forged'
            old = replace(old, manifest_payload=changed)
        else:
            old = replace(old, version='5.0.3.14', android_code=2200)
        inputs['original_android_context'] = old
    else:
        if mutation in ('raw', 'cleanup'):payload[mutation + 'Capture']['sha256'] = '0' * 64
        elif mutation == 'partial':payload['semantics'].pop(next(iter(payload['semantics'])))
        elif mutation == 'false':payload['semantics'][next(iter(payload['semantics']))] = False
        elif mutation == 'expired':payload['expiresAt'] = authority.utc_text(fixture.NOW - timedelta(seconds=1))
        elif mutation == 'binding':payload['binding']['outerSha256'] = '0' * 64
        elif mutation == 'profile':payload['profileId'] = 'android-emulator'
        elif mutation == 'target':
            payload['target'] = 'windows';payload['semantics'] = dict.fromkeys(authority.SEMANTICS['windows'], True)
        inputs['android_export'] = ordinary_envelope(payload, sample['key'])
    if mutation != 'bytes':inputs['original_android_bytes'] = authority.canonical(inputs['android_export'])
    with pytest.raises(authority.TrustedAcquisitionError):facade.prepare_coordinated_matrix(**inputs)


@pytest.mark.parametrize('mutation', ['domain', 'raw', 'cleanup', 'stage', 'binding'])
def test_actual_new_domain_rejects_forgery(matrix, mutation):
    inputs, sample, payload = matrix
    payload = copy.deepcopy(payload)
    if mutation == 'raw':payload['rawCapture']['sha256'] = '0' * 64
    elif mutation == 'cleanup':payload['cleanupCapture']['sha256'] = '0' * 64
    elif mutation == 'stage':payload['semantics']['heldReboot'] = False
    elif mutation == 'binding':payload['binding']['outerSha256'] = '0' * 64
    inputs['coordinated_headless_export'] = fixture.resign(payload, sample['key'],
        domain=authority.DOMAIN if mutation == 'domain' else contract.DOMAIN)
    with pytest.raises(authority.TrustedAcquisitionError):facade.prepare_coordinated_matrix(**inputs)


def test_actual_old_role_cannot_receive_new_domain(matrix):
    inputs, _, _ = matrix
    inputs['windows_export'] = copy.deepcopy(inputs['coordinated_headless_export'])
    inputs['windows_export']['untrusted-extra'] = True
    with pytest.raises(authority.TrustedAcquisitionError):facade.prepare_coordinated_matrix(**inputs)


def test_actual_expired_original_android_not_renewed(matrix):
    inputs, sample, _ = matrix
    original = authority.verify_export(inputs['android_export'], context=inputs['original_android_context'])
    original['expiresAt'] = authority.utc_text(fixture.NOW - timedelta(seconds=1))
    inputs['android_export'] = ordinary_envelope(original, sample['key'])
    inputs['original_android_bytes'] = authority.canonical(inputs['android_export'])
    with pytest.raises(authority.TrustedAcquisitionError):facade.prepare_coordinated_matrix(**inputs)


def test_synthetic_issue_matches_unchanged_passive_full_v1_verifier(matrix):
    inputs, sample, _ = matrix
    def memory_sign(payload, unused_private_path):
        # A synthetic approval exists only in memory, authenticated by this
        # disposable fixture key. No production key or private file is opened.
        raw = authority.make_manifest.RELEASE_ACCEPTANCE_DOMAIN + authority.canonical(payload)
        return {'schema': authority.make_manifest.RELEASE_ACCEPTANCE_SCHEMA,
            'signatureAlgorithm': 'Ed25519', 'payload': authority.make_manifest.b64url(raw),
            'signature': base64.b64encode(sample['key'].sign(raw)).decode()}
    with patch.object(authority.make_manifest, 'verify_public_key_matches_private') as key_gate, \
            patch.object(authority.make_manifest, 'acceptance_envelope', side_effect=memory_sign):
        envelope, proof = facade.issue_coordinated_acceptance(private_key='DISPOSABLE_IN_MEMORY_ONLY', **inputs)
    checked = authority.verify_full_acceptance(envelope, context=inputs['context'])
    assert checked['policyId'] == 'amnezia-release-full-v1'
    assert checked['artifacts'] == inputs['context'].artifacts
    assert [r['platform'] for r in checked['receipts']] == ['android', 'linux', 'windows']
    assert authority._utc(checked['expiresAt']) == fixture.NOW + timedelta(hours=1)
    assert proof['androidDerivation']['freshCapture'] is False
    key_gate.assert_called_once()
