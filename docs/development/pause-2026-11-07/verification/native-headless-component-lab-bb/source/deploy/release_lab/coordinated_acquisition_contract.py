"""Distinct coordinated headless acquisition contract.

No key generation, permit or imported legacy PASS conversion lives here.
Portable signed verification validates original evidence without requiring the
Linux producer's historical source paths to exist on the verifying workstation.
"""
from __future__ import annotations

import base64
from dataclasses import asdict
from datetime import timedelta
import hashlib
from pathlib import PurePosixPath

from cryptography.exceptions import InvalidSignature

from . import trusted_acquisition_export as trusted
from .headless_native_acceptance import (NativeUpdatePlan, OuterBinding, ReleaseBytes,
    Fixture, _common, _timestamp, receipt_sha256)
from .headless_coordinated_rollback_acceptance import validate_coordinated_rollback_chain
from .headless_coordinated_http_fixture import expected_sources_for_plan

SCHEMA = 'amnezia-coordinated-live-acquisition-v1'
DOMAIN = (SCHEMA + '\n').encode()
TARGET = 'linux-headless-coordinated'
PROFILE = 'linux-headless-x64'
CAPABILITY = 'headless-coordinated-rollback-with-pause-v1'
SEMANTICS = frozenset(('steps', 'update', 'candidateReboot', 'coordinatedRollback',
                       'heldReboot', 'resume', 'cleanup'))
REGISTRATION_SCHEMA = 'amnezia-headless-coordinated-registration-v1'
Error = trusted.TrustedAcquisitionError
canonical = trusted.canonical
utc_now = trusted.utc_now


def require(value, message):
    if not value:
        raise Error('coordinated acquisition: ' + message)


def exact(left, right):
    return canonical(left) == canonical(right)


def shape(value, fields, label):
    require(isinstance(value, dict) and set(value) == set(fields), label + ' fields')


def records(value):
    require(isinstance(value, list) and 0 < len(value) <= 2048, 'source records')
    names = set()
    for record in value:
        shape(record, ('path', 'sha256', 'size'), 'source record')
        path = record['path']
        require(isinstance(path, str) and 0 < len(path) < 4096 and '\x00' not in path
                and PurePosixPath(path).is_absolute() and '..' not in PurePosixPath(path).parts
                and str(PurePosixPath(path)) == path and path not in names, 'source path')
        require(isinstance(record['sha256'], str) and trusted.SHA.fullmatch(record['sha256'])
                and type(record['size']) is int and 0 <= record['size'] <= 64*1024*1024,
                'source digest/size')
        names.add(path)
    return value


def decode_capture(blob):
    trusted._check_blob(blob)
    data = trusted._decode(blob['bytes'])
    value = trusted._json(data)
    require(canonical(value) == data, 'noncanonical capture')
    return value


def native_plan(value):
    shape(value, ('run_id', 'case_id', 'attempt_nonce', 'created_at', 'outer_binding',
                  'baseline', 'candidate', 'fixture'), 'native plan')
    try:
        plan = NativeUpdatePlan(value['run_id'], value['case_id'], value['attempt_nonce'],
            value['created_at'], OuterBinding(**value['outer_binding']),
            ReleaseBytes(**value['baseline']), ReleaseBytes(**value['candidate']),
            Fixture(**value['fixture']))
        plan.validate()
    except (TypeError, ValueError, AttributeError) as error:
        raise Error('coordinated acquisition: native plan shape') from error
    require(exact(asdict(plan), value), 'native plan exact shape')
    return plan


def validate_coordinated_cleanup(plan, cleanup):
    """Validate actual original QGA cleanup stdout, not host success flags."""
    shape(cleanup, ('schema', 'operation', 'run_id', 'case_id', 'attempt_nonce',
        'origin', 'transport', 'injected', 'observed_at', 'outer_binding',
        'fixture_cleanup', 'raw_sources', 'preexisting_cleanup'), 'HTTP cleanup')
    _common(plan, cleanup, 'headless-coordinated-http-cleanup')
    shape(cleanup['raw_sources'], ('fixture_cleanup',), 'cleanup raw sources')
    raw = cleanup['raw_sources']['fixture_cleanup']
    shape(raw, ('origin', 'transport', 'path', 'exit_code', 'size', 'sha256', 'bytes_b64'), 'cleanup raw')
    require(raw['origin'] == 'guest' and raw['transport'] == 'qga'
        and raw['path'] == 'coordinated-http:cleanup' and type(raw['exit_code']) is int
        and raw['exit_code'] == 0 and type(raw['size']) is int and 0 < raw['size'] <= 65536,
        'cleanup original outcome')
    body = trusted._decode(raw['bytes_b64'])
    require(len(body) == raw['size'] and hashlib.sha256(body).hexdigest() == raw['sha256'],
        'cleanup original bytes')
    parsed = trusted._json(body)
    require(exact(parsed, cleanup['fixture_cleanup']), 'cleanup decoded original differs')
    expected = dict(schema='amnezia-coordinated-http-cleanup-v1', stopped=True,
        alias_removed=True, unit_removed=True, listener_closed=True, unknown_survivors=[],
        evidence_preserved=True, run_id=plan.run_id, attempt_nonce=plan.attempt_nonce,
        diagnosticOnly=True, releasePass=False)
    require(exact(parsed, expected), 'cleanup fixture did not close completely')
    previous = cleanup['preexisting_cleanup']
    shape(previous,('origin','transport','network_removed','update_profile_disabled',
        'baseline_binaries_preserved','netns','http_pid'),'preexisting cleanup')
    require(previous['origin'] == 'guest' and previous['transport'] == 'qga'
        and previous['network_removed'] is True and previous['update_profile_disabled'] is True
        and previous['baseline_binaries_preserved'] is True and isinstance(previous['netns'],str)
        and type(previous['http_pid']) is int and previous['http_pid'] > 1,
        'preexisting network cleanup')
    return cleanup


def derive_stage_hashes(ordinary_receipt_bytes, plan, semantic):
    """Derive each stage commitment from its actual raw object."""
    ordinary = trusted._json(ordinary_receipt_bytes)
    rollback = semantic['coordinated_rollback']
    stages = dict(steps=ordinary, update=semantic['update'],
        candidateReboot=semantic['candidate_reboot'],
        coordinatedRollback=rollback['raw_sources']['held_record'],
        heldReboot=rollback['held_reboot'], resume=rollback['raw_sources']['resumed_record'],
        cleanup=semantic['cleanup'])
    hashes = {name: hashlib.sha256(canonical(value)).hexdigest() for name, value in stages.items()}
    hashes['steps'] = hashlib.sha256(ordinary_receipt_bytes).hexdigest()
    for name in ('update','candidateReboot','heldReboot','cleanup'):
        hashes[name] = receipt_sha256(stages[name])
    hashes['coordinatedRollback'] = rollback['raw_sources']['held_record']['sha256']
    hashes['resume'] = rollback['raw_sources']['resumed_record']['sha256']
    return hashes


def _validate_evidence(payload, context):
    raw, closed = decode_capture(payload['rawCapture']), decode_capture(payload['cleanupCapture'])
    shape(raw, ('schema','runId','profileId','binding','capability','ordinary',
                'original_receipt','plan','semantic','registration'), 'raw capture')
    require(type(raw['schema']) is int and raw['schema'] == 1
        and raw['runId'] == payload['runId'] and raw['profileId'] == PROFILE
        and exact(raw['binding'], context.binding()) and raw['capability'] == CAPABILITY,
        'raw identity/binding/capability')
    plan = native_plan(raw['plan'])
    require(plan.run_id == payload['runId'], 'plan run')
    candidate = context.manifest_payload['platforms'][PROFILE]
    require(plan.candidate.version == context.version
        and plan.candidate.manifest_sha256 == context.manifest['sha256']
        and plan.candidate.manifest_size == context.manifest['size']
        and plan.candidate.tar_sha256 == candidate['sha256']
        and plan.candidate.tar_size == candidate['size']
        and plan.candidate.key_sha256 == context.public_key_record['sha256'], 'native release binding')
    semantic = raw['semantic']
    fields = {'capability','legacy_native_rollback_pass','trustedExport','http','update',
              'candidate_reboot','coordinated_rollback','validation','cleanup','preexisting'}
    # Some driver revisions also preserve the derived pins. They never select them.
    require(isinstance(semantic,dict) and set(semantic) in (fields, fields|{'expected_http_sources'}),
            'semantic fields')
    require(semantic['capability'] == 'headless-coordinated-rollback-with-pause'
        and semantic['legacy_native_rollback_pass'] is False and semantic['trustedExport'] is False,
        'legacy/native authority substitution')
    pins = expected_sources_for_plan(plan)
    if 'expected_http_sources' in semantic:
        require(exact(semantic['expected_http_sources'],pins), 'fixture source pins')
    validation = validate_coordinated_rollback_chain(plan, semantic['coordinated_rollback'],
        semantic['update'], semantic['candidate_reboot'], semantic['http'], expected_http_sources=pins)
    for name in ('rollback_process','resume_process'):
        slots=semantic['coordinated_rollback'].get(name,{}).get('uid_slots')
        require(isinstance(slots,list) and len(slots) == 4
            and all(type(value) is int and value == 0 for value in slots), 'coordinator root UID slots')
    require(exact(validation,semantic['validation']), 'derived semantic validation differs')
    validate_coordinated_cleanup(plan,semantic['cleanup'])
    from .headless_preexisting_fixture import (FixturePlan, BinaryIdentity,
        validate_connected, validate_baseline_owned)
    previous=semantic['preexisting']
    shape(previous,('plan','connected','baseline','network_cleanup'),'preexisting evidence')
    try:
        data=dict(previous['plan'])
        for name in ('cli','setup_daemon','legacy_daemon'):
            data[name]=BinaryIdentity(**data[name])
        preplan=FixturePlan(**data);preplan.validate()
    except (TypeError,ValueError,KeyError) as error:
        raise Error('coordinated acquisition: preexisting plan shape') from error
    require(exact(asdict(preplan),previous['plan']) and preplan.run_id == plan.run_id
        and preplan.profile == PROFILE and preplan.nonce == plan.attempt_nonce
        and preplan.setup_version == plan.candidate.version and preplan.legacy_version == plan.baseline.version
        and preplan.setup_daemon.sha256 == plan.candidate.amneziad_sha256
        and preplan.cli.sha256 == plan.candidate.cli_sha256
        and preplan.legacy_daemon.sha256 == plan.baseline.amneziad_sha256,'preexisting planned binaries')
    validate_connected(preplan,previous['connected'])
    validate_baseline_owned(preplan,previous['connected'],previous['baseline'])
    require(exact(previous['network_cleanup'],semantic['cleanup']['preexisting_cleanup'])
        and previous['network_cleanup']['netns'] == preplan.netns,'preexisting cleanup identity')
    original = trusted._decode(raw['original_receipt'])
    require(0 < len(original) <= 8*1024*1024, 'ordinary receipt bound')
    ordinary = trusted._json(original)
    from .lab import validate_receipt
    validate_receipt(ordinary,run_id=plan.run_id,profile_id=PROFILE,
        artifact={'sha256':candidate['sha256'],'size':candidate['size']},
        baseline_version=plan.baseline.version,candidate_version=plan.candidate.version,expected_role='candidate')
    require([step.get('id') for step in ordinary['steps']] == ['probe','reinstall','update','service-health'],
        'complete ordinary step matrix')
    require(isinstance(raw['ordinary'],dict) and raw['ordinary'].get('run_id') == plan.run_id
        and raw['ordinary'].get('profile') == PROFILE and raw['ordinary'].get('transport') == 'qga'
        and raw['ordinary'].get('state') == 'acquired-not-accepted', 'ordinary capture metadata')
    registration = raw['registration']
    shape(registration,('schema','runId','profileId','capability','binding','capabilityRecord',
        'executionPlanSha256','nativePlanSha256','stageHashes','sourceRecords','registeredAt'), 'registration')
    require(registration['schema'] == REGISTRATION_SCHEMA and registration['runId'] == plan.run_id
        and registration['profileId'] == PROFILE and registration['capability'] == CAPABILITY
        and exact(registration['binding'],context.binding())
        and registration['nativePlanSha256'] == hashlib.sha256(canonical(raw['plan'])).hexdigest()
        and exact(registration['stageHashes'],derive_stage_hashes(original,plan,semantic)), 'registration commitments')
    require(isinstance(registration['executionPlanSha256'],str)
        and trusted.SHA.fullmatch(registration['executionPlanSha256']), 'execution plan digest')
    sources = records(registration['sourceRecords'])
    require(all(record in payload['provenance'] for record in sources), 'source attestation provenance')
    cap = registration['capabilityRecord']
    records([cap])
    require(cap in sources and cap['path'].endswith('/runs/'+plan.run_id+'/headless-capability.json'),
            'protected capability source')
    started, completed = trusted._utc(payload['startedAt']), trusted._utc(payload['completedAt'])
    require(started <= _timestamp(plan.created_at,'native plan') <= completed
        and started <= trusted._utc(registration['registeredAt']) <= completed, 'plan/registration chronology')
    for value in (semantic['http'],semantic['update'],semantic['candidate_reboot'],
                  semantic['coordinated_rollback'],semantic['cleanup']):
        require(started <= _timestamp(value['observed_at'],'semantic stage') <= completed,
                'stage outside acquisition interval')
    shape(closed,('semantic_cleanup','owned_reset','overlay_absent','qmp_absent','qga_absent'), 'cleanup capture')
    require(exact(closed['semantic_cleanup'],semantic['cleanup'])
        and all(closed[name] is True for name in ('overlay_absent','qmp_absent','qga_absent')), 'owned cleanup')
    reset = closed['owned_reset']
    shape(reset,('run_id','reset_profiles','removed_overlays','release_passed'), 'owned reset')
    directory = PurePosixPath(plan.outer_binding.qmp_socket).parent
    require(directory.name == PROFILE and directory.parent.name == plan.run_id
        and directory.parent.parent.name == 'runs'
        and plan.outer_binding.qga_socket == str(directory/'qga.sock')
        and plan.outer_binding.qmp_socket == str(directory/'qmp.sock'), 'owned socket layout')
    require(exact(reset,dict(run_id=plan.run_id,reset_profiles=[PROFILE],
        removed_overlays=[str(directory/'overlay.qcow2')],release_passed=False)), 'owned reset result')
    return raw


def _validate_payload(payload,context,*,now):
    shape(payload,('schema','target','runId','profileId','startedAt','completedAt','issuedAt',
        'expiresAt','binding','semantics','rawCapture','cleanupCapture','provenance'),'payload')
    require(type(payload['schema']) is int and payload['schema'] == 1 and payload['target'] == TARGET
        and payload['profileId'] == PROFILE and isinstance(payload['runId'],str)
        and trusted.ID.fullmatch(payload['runId']) and exact(payload['binding'],context.binding()), 'payload binding')
    started,completed,issued,expires = (trusted._utc(payload[name]) for name in
        ('startedAt','completedAt','issuedAt','expiresAt'))
    require(started <= completed <= issued <= now < expires <= issued+timedelta(hours=24)
        and issued-started <= timedelta(hours=24), 'expired/future/out-of-order capture')
    require(isinstance(payload['semantics'],dict) and set(payload['semantics']) == SEMANTICS
        and all(value is True for value in payload['semantics'].values()), 'incomplete coordinated semantics')
    records(payload['provenance'])
    _validate_evidence(payload,context)
    return payload


def verify_export(envelope,*,context):
    """Verify a distinct signed export; never signs or imports legacy proofs."""
    require(type(context) is trusted.AcquisitionContext,'exact acquisition context')
    context.verify()
    shape(envelope,('schema','signatureAlgorithm','payload','signature'),'envelope')
    require(envelope['schema'] == SCHEMA and envelope['signatureAlgorithm'] == 'Ed25519'
        and len(canonical(envelope)) <= trusted.MAX_EXPORT_BYTES,'signature schema/bound')
    signed = trusted._decode(envelope['payload'],url=True)
    require(signed.startswith(DOMAIN),'signature domain')
    signature = trusted._decode(envelope['signature'])
    require(len(signature) == 64,'signature size')
    try:
        trusted._public(context.public_key).verify(signature,signed)
    except InvalidSignature as error:
        raise Error('coordinated acquisition: signature mismatch') from error
    body = signed[len(DOMAIN):]
    payload = trusted._json(body)
    require(canonical(payload) == body,'noncanonical signed payload')
    return _validate_payload(payload,context,now=utc_now())


def validate_coordinated_live_result(result,*,producer,context,plan,run_id,source_records,now=None):
    """Validate fixed producer output and physical source closure before any seal.

    This does not acquire or sign. The separate fixed issuer seam invokes the
    class itself, preserves pre/post source fences, and calls this validator
    before obtaining signing authority.
    """
    from .coordinated_linux_live_acquisition import CoordinatedLinuxLiveProducer
    from .android_real_device_acquisition import file_record
    require(type(producer) is CoordinatedLinuxLiveProducer,'fixed coordinated producer')
    require(type(context) is trusted.AcquisitionContext,'exact acquisition context')
    context.verify()
    shape(result,('target','runId','profileId','startedAt','completedAt','binding','capability',
        'rawCapture','cleanupCapture','semantics','provenance'),'live result')
    require(result['runId'] == run_id == producer.run_id and result['target'] == TARGET
        and result['capability'] == CAPABILITY and exact(result['binding'],context.binding()), 'live identity')
    now = now or utc_now()
    payload = {key:value for key,value in result.items() if key not in ('capability',)}
    payload.update(schema=1,issuedAt=trusted.utc_text(now),expiresAt=trusted.utc_text(now+timedelta(hours=24)),
        rawCapture=trusted._blob(result['rawCapture']),cleanupCapture=trusted._blob(result['cleanupCapture']))
    _validate_payload(payload,context,now=now)
    raw = decode_capture(payload['rawCapture'])
    require(exact(raw['plan'],asdict(plan)) and exact(raw['registration']['sourceRecords'],source_records),
        'live plan/source closure')
    records(source_records)
    for record in result['provenance']:
        require(file_record(record['path']) == record,'physical source changed')
    run = CoordinatedLinuxLiveProducer._binding(producer,context)
    require(run.get('execution_plan_sha256') == raw['registration']['executionPlanSha256']
        and exact(run.get('headless_capability_record'),raw['registration']['capabilityRecord']),
        'live protected selector/execution plan changed')
    context.verify()
    return payload


def seal_live_export(producer,*,context,private_key):
    """Acquire from the fixed live class before any signing-key access.

    Merely defining this seam does not authorize operational execution. Source
    tests may use disposable keys; real acquisition/signing remains separately
    gated by the owned controller and the caller's release authorization.
    """
    from .coordinated_linux_live_acquisition import CoordinatedLinuxLiveProducer
    from .lab import LabController
    require(type(producer) is CoordinatedLinuxLiveProducer,'fixed coordinated producer')
    controller=producer.controller
    require(type(controller) is LabController and not controller.dry_run and not controller.test_mode,
        'canonical live coordinated controller')
    # Retain the canonical ownership/mutation fence across capture, cleanup,
    # final revalidation and signing. The producer's own session nests here.
    with LabController.mutation_session(controller,'coordinated-acquisition-seal'):
        return _seal_inside_session(producer,context=context,private_key=private_key)


def _seal_inside_session(producer,*,context,private_key):
    from . import coordinated_linux_live_acquisition as producer_module
    from . import linux_live_acquisition, live_acquisition
    from .android_real_device_acquisition import file_record
    from pathlib import Path
    producer_class=producer_module.CoordinatedLinuxLiveProducer
    require(type(producer) is producer_class,'fixed coordinated producer')
    require(type(context) is trusted.AcquisitionContext,'exact acquisition context')
    context.verify()
    before=producer_class._binding(producer,context)
    require(before.get('headless_capability') == CAPABILITY,'explicit planned coordinated capability')
    protected=[file_record(Path(__file__).absolute()),file_record(Path(producer_module.__file__).absolute())]
    protected.extend(file_record(Path(module.__file__).absolute())
        for module in (linux_live_acquisition,trusted,live_acquisition))
    for name in ('profile_records','runner_records','semantic_helper_records'):
        protected.extend(before[name].values())
    protected.append(before['headless_capability_record'])
    protected=list({record['path']:record for record in protected}.values())
    for record in protected:
        require(file_record(record['path']) == record,'pre-acquisition source changed')
    result=producer_class.acquire(producer,context)
    for record in protected:
        require(file_record(record['path']) == record,'source changed during acquisition')
    raw=trusted._json(result['rawCapture'])
    plan=native_plan(raw['plan'])
    # All authority/producer records become part of the signed source attestation.
    result=dict(result,provenance=list(result['provenance']))
    for record in protected:
        if record not in result['provenance']:
            result['provenance'].append(record)
    payload=validate_coordinated_live_result(result,producer=producer,context=context,plan=plan,
        run_id=producer.run_id,source_records=raw['registration']['sourceRecords'])
    signed=DOMAIN+canonical(payload)
    require(len(signed) <= (trusted.MAX_EXPORT_BYTES-2048)*3//4,'signed export bound')
    context.verify()
    for record in protected:
        require(file_record(record['path']) == record,'source changed before signing')
    # This is deliberately the first access to the supplied private key path.
    private_key=Path(private_key)
    trusted.make_manifest.verify_public_key_matches_private(
        base64.b64encode(context.public_key.read_bytes()).decode(),private_key)
    signature=trusted.make_manifest.sign_payload(private_key,signed)
    envelope=dict(schema=SCHEMA,signatureAlgorithm='Ed25519',
        payload=trusted.make_manifest.b64url(signed),signature=signature)
    verify_export(envelope,context=context)
    return envelope
