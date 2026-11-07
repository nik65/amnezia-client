"""Canonical controller registration for the distinct coordinated capability."""
from __future__ import annotations
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path

CAPABILITY = 'headless-coordinated-rollback-with-pause-v1'
PROFILE = 'linux-headless-x64'


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def capability_payload(run):
    return {'schema': 1, 'run_id': run['run_id'], 'capability': CAPABILITY,
            'manifest_sha256': run['manifest']['sha256'], 'outer_sha256': run['outer_artifact']['sha256'],
            'candidate_artifacts': {key: {'sha256': item['sha256'], 'size': item['size']}
                                    for key, item in run['artifacts'].items()},
            'semantic_helpers': {key: {'sha256': item['sha256'], 'size': item['size']}
                                 for key, item in run['semantic_helper_records'].items()}}


def write_capability(controller, run):
    from .lab import artifact_record, ensure_owned_child
    path = ensure_owned_child(controller.root,
        controller.root / 'runs' / run['run_id'] / 'headless-capability.json', 'headless capability')
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(canonical(capability_payload(run))); stream.flush(); os.fsync(stream.fileno())
    return artifact_record(path)


def stage_hashes(semantic, ordinary_bytes):
    from .headless_native_acceptance import receipt_sha256
    receipt = semantic['coordinated_rollback']
    return {'steps': hashlib.sha256(ordinary_bytes).hexdigest(),
            'update': receipt_sha256(semantic['update']),
            'candidateReboot': receipt_sha256(semantic['candidate_reboot']),
            'coordinatedRollback': receipt['raw_sources']['held_record']['sha256'],
            'heldReboot': receipt_sha256(receipt['held_reboot']),
            'resume': receipt['raw_sources']['resumed_record']['sha256'],
            'cleanup': receipt_sha256(semantic['cleanup'])}


def register(controller, run_id, plan, semantic, context, ordinary_capture):
    from .lab import LabController, LabError, artifact_record, validate_receipt, validate_semantic_helper_records
    from .trusted_acquisition_export import AcquisitionContext
    from .linux_headless_driver import outer_binding
    from .headless_coordinated_http_fixture import expected_sources_for_plan
    from .headless_coordinated_rollback_acceptance import validate_coordinated_rollback_chain
    from .coordinated_acquisition_contract import validate_coordinated_cleanup
    if type(controller) is not LabController or controller.dry_run or controller.test_mode:
        raise LabError('canonical live coordinated controller required')
    controller.assert_mutation_context()
    if controller._mutation_lock_fd is None or controller._mutation_lock_depth <= 0:
        raise LabError('coordinated registration requires live mutation lock')
    if type(context) is not AcquisitionContext:
        raise LabError('exact release acquisition context required')
    context.verify(); run = controller.get_run(run_id)
    if run.get('headless_capability') != CAPABILITY or run.get('automatic_migration_wan') is not None:
        raise LabError('coordinated capability was not selected in immutable admission')
    selector = run.get('headless_capability_record') or {}
    if artifact_record(Path(selector.get('path', ''))) != selector:
        raise LabError('coordinated immutable selector changed')
    if canonical(json.loads(Path(selector['path']).read_bytes())) != canonical(capability_payload(run)):
        raise LabError('coordinated selector release/helper binding differs')
    if (run.get('manifest') != context.manifest or run.get('outer_artifact') != context.outer
            or run.get('candidate_version') != context.version):
        raise LabError('coordinated context differs from live run')
    validate_semantic_helper_records(run['semantic_helper_records'])
    for name, item in run['artifacts'].items():
        if artifact_record(Path(item['path'])) != item or item != context.candidate(name):
            raise LabError('coordinated complete artifact closure differs')
    vm = controller.owned_vm(run_id, PROFILE)
    plan.validate()
    candidate, baseline = run['artifacts']['linux-headless-x64'], run['baseline_artifacts']['linux-headless-x64']
    if (plan.run_id != run_id or plan.outer_binding != outer_binding(vm)
            or plan.candidate.version != run['candidate_version']
            or (plan.candidate.tar_sha256, plan.candidate.tar_size) != (candidate['sha256'], candidate['size'])
            or plan.candidate.manifest_sha256 != run['manifest']['sha256']
            or plan.candidate.manifest_size != run['manifest']['size']
            or plan.candidate.key_sha256 != run['manifest_public_key']['sha256']
            or (plan.baseline.tar_sha256, plan.baseline.tar_size) != (baseline['sha256'], baseline['size'])
            or plan.baseline.manifest_sha256 != run['baseline_manifest']['sha256']
            or plan.baseline.manifest_size != run['baseline_manifest']['size']
            or plan.baseline.key_sha256 != run['manifest_public_key']['sha256']
            or plan.baseline.version != run['baseline_version']):
        raise LabError('coordinated native plan differs from owned run')
    if (not isinstance(ordinary_capture, dict) or ordinary_capture.get('state') != 'acquired-not-accepted'
            or ordinary_capture.get('run_id') != run_id or ordinary_capture.get('profile') != PROFILE
            or ordinary_capture.get('binding') != vm or not isinstance(ordinary_capture.get('raw_receipt'), bytes)):
        raise LabError('original same-owned-guest ordinary acquisition required')
    ordinary_bytes = ordinary_capture['raw_receipt']
    validate_receipt(json.loads(ordinary_bytes), run_id=run_id, profile_id=PROFILE, artifact=candidate,
        baseline_version=run['baseline_version'], candidate_version=run['candidate_version'], expected_role='candidate')
    expected_sources = expected_sources_for_plan(plan)
    if canonical(semantic.get('expected_http_sources')) != canonical(expected_sources):
        raise LabError('coordinated fixture sources differ from reviewed runtime')
    validate_coordinated_rollback_chain(plan, semantic['coordinated_rollback'], semantic['update'],
        semantic['candidate_reboot'], semantic['http'], expected_http_sources=expected_sources)
    validate_coordinated_cleanup(plan, semantic['cleanup'])
    execution_sha = run.get('execution_plan_sha256')
    if not isinstance(execution_sha, str) or len(execution_sha) != 64:
        raise LabError('coordinated registration requires exact frozen execution plan')
    execution_path = controller.root / 'runs' / run_id / 'execution-plan.json'
    if execution_path.is_symlink() or hashlib.sha256(execution_path.read_bytes()).hexdigest() != execution_sha:
        raise LabError('coordinated execution plan changed')
    sources = [item for name in ('profile_records', 'runner_records', 'semantic_helper_records')
               for item in run[name].values()]
    sources.append(selector)
    sources = list({item['path']: item for item in sources}.values())
    registration = {'schema': 'amnezia-headless-coordinated-registration-v1', 'runId': run_id,
        'profileId': PROFILE, 'capability': CAPABILITY, 'binding': context.binding(),
        'capabilityRecord': selector, 'executionPlanSha256': execution_sha,
        'nativePlanSha256': hashlib.sha256(canonical(asdict(plan))).hexdigest(),
        'stageHashes': stage_hashes(semantic, ordinary_bytes), 'sourceRecords': sources,
        'registeredAt': datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')}
    controller._register_full4(run_id, 'headless-coordinated', {
        'registration': registration, 'plan': asdict(plan), 'semantic': semantic,
        'ordinary_receipt_sha256': hashlib.sha256(ordinary_bytes).hexdigest()})
    context.verify()
    if controller.owned_vm(run_id, PROFILE) != vm:
        raise LabError('coordinated guest binding changed during registration')
    return registration
