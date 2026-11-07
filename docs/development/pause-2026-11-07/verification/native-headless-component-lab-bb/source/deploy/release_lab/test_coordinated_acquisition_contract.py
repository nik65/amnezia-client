"""Synthetic signatures/guest-shaped evidence only; no runtime acceptance."""
import base64
from copy import deepcopy
from dataclasses import asdict, replace
from datetime import datetime, timezone
import hashlib

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from deploy.release_lab import coordinated_acquisition_contract as c
from deploy.release_lab import trusted_acquisition_export as t
from deploy.release_lab import test_headless_coordinated_rollback_acceptance as chain_fixture
from deploy.release_lab import test_headless_native_acceptance as f
from deploy.release_lab import test_headless_preexisting_fixture as prefixture
from deploy.release_lab.headless_coordinated_http_fixture import derive_endpoint, expected_sources_for_plan

NOW = datetime(2026,9,13,10,15,tzinfo=timezone.utc)


def resign(payload, key, *, domain=c.DOMAIN):
    body = domain+t.canonical(payload)
    return dict(schema=c.SCHEMA,signatureAlgorithm='Ed25519',
        payload=t.make_manifest.b64url(body),signature=base64.b64encode(key.sign(body)).decode())


def synthetic_signed_fixture(tmp_path, monkeypatch):
    """Return genuine disposable signature + full synthetic semantic chain.

    Context.verify alone is patched because release artifacts are synthetic;
    signature, domain, raw chain and cleanup validation remain real. Callers
    must not describe this fixture as physical guest or release acceptance.
    """
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
    public_path=tmp_path/'disposable-public.pem';public_path.write_bytes(public)
    p=f.plan();p=replace(p,attempt_nonce='1'*48,fixture=replace(p.fixture,nonce='1'*48))
    directory='/var/lib/amnezia-release-lab/runs/'+p.run_id+'/'+c.PROFILE
    p=replace(p, outer_binding=replace(p.outer_binding,qmp_socket=directory+'/qmp.sock',qga_socket=directory+'/qga.sock'),
        baseline=replace(p.baseline,key_sha256=hashlib.sha256(public).hexdigest()),
        candidate=replace(p.candidate,key_sha256=hashlib.sha256(public).hexdigest()),
        fixture=replace(p.fixture,endpoint=derive_endpoint(p.attempt_nonce),forward_routes=('10.0.0.0/8',)))
    monkeypatch.setattr(f,'plan',lambda:p)
    monkeypatch.setattr(chain_fixture,'PINS',expected_sources_for_plan(p))
    original_ledger=chain_fixture.ledger
    def rebound_ledger(plan,boots):
        value=original_ledger(plan,boots)
        address=plan.fixture.endpoint.split('://')[1].split(':')[0]
        rows=[t._json(line) for line in base64.b64decode(value['raw_ledger_bytes_base64']).splitlines()]
        for row in rows:row['address']=address
        for row in value['epochs']:row['address']=address
        body=b'\n'.join(t.canonical(row) for row in rows)+b'\n'
        value.update(raw_ledger_bytes_base64=base64.b64encode(body).decode(),raw_ledger_sha256=hashlib.sha256(body).hexdigest())
        return value
    monkeypatch.setattr(chain_fixture,'ledger',rebound_ledger)
    p,rollback,update,reboot,http=chain_fixture.chain.__wrapped__(monkeypatch)
    for name in ('rollback_process','resume_process'):
        rollback[name]['uid_slots']=[0,0,0,0]
    monkeypatch.setattr(t.AcquisitionContext,'verify',lambda self:None)
    monkeypatch.setattr(c,'utc_now',lambda:NOW)
    context=t.AcquisitionContext(bundle=tmp_path,public_key=public_path,
        manifest=dict(path=str(tmp_path/'manifest'),sha256=p.candidate.manifest_sha256,size=p.candidate.manifest_size),
        outer=dict(path=str(tmp_path/'outer'),sha256='1'*64,size=300),
        publisher=dict(path=str(tmp_path/'publisher'),sha256='2'*64,size=40),
        artifacts=[dict(path='files/headless.tar.gz',sha256=p.candidate.tar_sha256,size=p.candidate.tar_size)],
        version=p.candidate.version,android_code=2200,
        manifest_payload={'platforms':{c.PROFILE:dict(sha256=p.candidate.tar_sha256,size=p.candidate.tar_size)}},
        public_key_record=dict(path=str(public_path),sha256=hashlib.sha256(public).hexdigest(),size=len(public)))
    fixture_closed=dict(schema='amnezia-coordinated-http-cleanup-v1',stopped=True,alias_removed=True,
        unit_removed=True,listener_closed=True,unknown_survivors=[],evidence_preserved=True,
        run_id=p.run_id,attempt_nonce=p.attempt_nonce,diagnosticOnly=True,releasePass=False)
    body=t.canonical(fixture_closed)+b'\n'
    cleanup=dict(schema=1,operation='headless-coordinated-http-cleanup',run_id=p.run_id,case_id=p.case_id,
        attempt_nonce=p.attempt_nonce,origin='guest',transport='qga',injected=False,
        observed_at='2026-09-13T10:10:00Z',outer_binding=asdict(p.outer_binding),fixture_cleanup=fixture_closed,
        raw_sources={'fixture_cleanup':dict(origin='guest',transport='qga',path='coordinated-http:cleanup',
            exit_code=0,size=len(body),sha256=hashlib.sha256(body).hexdigest(),bytes_b64=base64.b64encode(body).decode())},
        preexisting_cleanup=dict(origin='guest',transport='qga',network_removed=True,
            update_profile_disabled=True,baseline_binaries_preserved=True,netns='temporary',http_pid=301))
    from deploy.release_lab.headless_preexisting_fixture import BinaryIdentity, build_contract, _sha
    preplan=replace(prefixture.plan(),run_id=p.run_id,nonce=p.attempt_nonce,
        owned_root='/var/lib/amnezia-release-lab/runs/'+p.run_id+'/fixture',
        cli=BinaryIdentity('/usr/local/bin/amnezia-cli',p.candidate.cli_sha256),
        setup_daemon=BinaryIdentity('/usr/local/bin/amneziad',p.candidate.amneziad_sha256),
        legacy_daemon=BinaryIdentity('/var/lib/amnezia-release-lab/artifacts/legacy-amneziad',p.baseline.amneziad_sha256),
        setup_version=p.candidate.version,legacy_version=p.baseline.version)
    monkeypatch.setattr(prefixture,'plan',lambda:preplan)
    connected=prefixture.connected();contract=build_contract(preplan,server_public_key=prefixture.KEY)
    cleanup['preexisting_cleanup']['netns']=preplan.netns
    def env(name,result):return dict(argv=contract['baseline_cli'][name],rc=0,stdout_sha256='d'*64,json={'result':result})
    status=dict(state='connected',activeProfile=preplan.profile_id+'-baseline',routing=dict(mode='only-forward',interface=preplan.wg_interface,recoveryRequired=False))
    pointer=lambda name:dict(path=preplan.owned_root+'/'+name,uid=0,gid=0,mode=384,size=10,sha256='a'*64)
    source=[{name:row[name] for name in ('path','uid','gid','mode','size','sha256')} for row in connected['managed_receipts']]
    retired=dict(schema=1,operation='headless-preexisting-retire-managed-receipts',source=source,
        archives=[dict(path=preplan.owned_root+'/retired-managed/'+row['path'].rsplit('/',1)[1],uid=0,gid=0,mode=384,size=row['size'],sha256=row['sha256']) for row in source],
        absence=[dict(path=row['path'],exists=False) for row in source],proof=pointer('managed-receipt-retirement.json'))
    baseline=dict(schema=1,operation='headless-preexisting-baseline-owned',origin='guest',transport='qga',connected_receipt_sha256=_sha(connected),
        baseline_config=dict(path=preplan.baseline_config_path,uid=0,gid=0,mode=384,size=32,sha256='a'*64,regular=True,symlink=False,
            basename=preplan.wg_interface+'.conf',interface=preplan.wg_interface,length=32,source='verified-fixture-config',table='off',verified=True),
        setup_disconnect=dict(state='disconnected',interface_absent=True,routes_clean=True,dns_clean=True,recovery_required=False,
            pre_disconnect_diagnostic=dict(schema=1,target={name:connected['daemon'][name] for name in ('pid','start_ticks','exe_sha256')},
                strace=dict(available=False,reason='strace-unavailable',scope=['execve','exit','exit_group','write'],duration_limit_seconds=30,shards=[]),
                state=pointer('state'),receipt=pointer('receipt'))),
        systemd_terminal=dict(MainPID='0',ActiveState='inactive',SubState='dead',Job=''),managed_receipt_retirement=retired,
        daemon=dict(pid=202,start_ticks=900,exe=preplan.legacy_daemon.path,exe_sha256=preplan.legacy_daemon.sha256,uid=0),
        cli={name:env(name,status if name in ('connect','status') else {}) for name in ('import','connect','status','doctor','list')},
        routed_probe=deepcopy(connected['routed_probe']))
    semantic=dict(capability='headless-coordinated-rollback-with-pause',legacy_native_rollback_pass=False,
        trustedExport=False,http=http,update=update,candidate_reboot=reboot,coordinated_rollback=rollback,
        preexisting=dict(plan=asdict(preplan),connected=connected,baseline=baseline,network_cleanup=cleanup['preexisting_cleanup']),
        validation=c.validate_coordinated_rollback_chain(p,rollback,update,reboot,http,
            expected_http_sources=expected_sources_for_plan(p)),cleanup=cleanup)
    ordinary=dict(schema=1,run_id=p.run_id,profile=c.PROFILE,baseline_version=p.baseline.version,
        candidate_version=p.candidate.version,transport='qga',origin='guest',injected=False,
        artifact='/tmp/candidate.tar.gz',observed_at='2026-09-13T09:59:30Z',
        guest_marker='amnezia-release-lab:'+p.run_id+':'+c.PROFILE,
        steps=[dict(id=name,passed=True) for name in ('probe','reinstall','update','service-health')],
        artifact_sha256=p.candidate.tar_sha256,artifact_size=p.candidate.tar_size,artifact_role='candidate',
        artifact_source=dict(transport='qga',hash_verified=True),
        assertion=dict(passed=True,installed_version=p.candidate.version,expected_version=p.candidate.version,
            artifact_sha256=p.candidate.tar_sha256))
    ordinary_bytes=t.canonical(ordinary)
    cap=dict(path='/var/lib/amnezia-release-lab/runs/'+p.run_id+'/headless-capability.json',sha256='3'*64,size=100)
    source=dict(path='/repo/deploy/release_lab/coordinated_linux_live_acquisition.py',sha256='4'*64,size=100)
    registration=dict(schema=c.REGISTRATION_SCHEMA,runId=p.run_id,profileId=c.PROFILE,capability=c.CAPABILITY,
        binding=context.binding(),capabilityRecord=cap,executionPlanSha256='5'*64,
        nativePlanSha256=hashlib.sha256(t.canonical(asdict(p))).hexdigest(),
        stageHashes=c.derive_stage_hashes(ordinary_bytes,p,semantic),sourceRecords=[cap,source],
        registeredAt='2026-09-13T10:11:00Z')
    raw=dict(schema=1,runId=p.run_id,profileId=c.PROFILE,binding=context.binding(),capability=c.CAPABILITY,
        ordinary=dict(run_id=p.run_id,profile=c.PROFILE,transport='qga',state='acquired-not-accepted'),
        original_receipt=base64.b64encode(ordinary_bytes).decode(),plan=asdict(p),semantic=semantic,registration=registration)
    closed=dict(semantic_cleanup=cleanup,owned_reset=dict(run_id=p.run_id,reset_profiles=[c.PROFILE],
        removed_overlays=[directory+'/overlay.qcow2'],release_passed=False),overlay_absent=True,qmp_absent=True,qga_absent=True)
    payload=dict(schema=1,target=c.TARGET,runId=p.run_id,profileId=c.PROFILE,
        startedAt='2026-09-13T09:59:00Z',completedAt='2026-09-13T10:12:00Z',issuedAt='2026-09-13T10:13:00Z',
        expiresAt='2026-09-14T10:13:00Z',binding=context.binding(),semantics={name:True for name in c.SEMANTICS},
        rawCapture=t._blob(t.canonical(raw)),cleanupCapture=t._blob(t.canonical(closed)),provenance=[cap,source])
    return dict(context=context,key=key,payload=payload,envelope=resign(payload,key),raw=raw,closed=closed,plan=p)


@pytest.fixture
def signed(tmp_path,monkeypatch):return synthetic_signed_fixture(tmp_path,monkeypatch)


def test_real_disposable_signature_complete_chain(signed):
    assert c.verify_export(signed['envelope'],context=signed['context']) == signed['payload']


@pytest.mark.parametrize('mutation',[
    lambda p:p.update(target='linux-headless'),
    lambda p:p['semantics'].update(rollback=True),
    lambda p:p['semantics'].pop('resume'),
    lambda p:p['semantics'].update(resume=1),
    lambda p:p.update(expiresAt='2026-09-13T10:14:00Z'),
    lambda p:p.update(completedAt='2026-09-13T10:16:00Z'),
    lambda p:p['binding'].update(androidVersionCode=2199),
    lambda p:p['provenance'][0].update(size=True),
])
def test_cross_shape_and_binding_rejected(signed,mutation):
    payload=deepcopy(signed['payload']);mutation(payload)
    with pytest.raises(Exception):c.verify_export(resign(payload,signed['key']),context=signed['context'])


def test_wrong_domain_and_signature(signed):
    with pytest.raises(c.Error,match='domain'):
        c.verify_export(resign(signed['payload'],signed['key'],domain=t.DOMAIN),context=signed['context'])
    key=Ed25519PrivateKey.generate()
    with pytest.raises(c.Error,match='signature'):
        c.verify_export(resign(signed['payload'],key),context=signed['context'])


@pytest.mark.parametrize('mutation',[
    lambda r:r['semantic'].update(legacy_native_rollback_pass=True),
    lambda r:r['semantic'].pop('candidate_reboot'),
    lambda r:r['semantic']['coordinated_rollback']['raw_sources']['held_record'].update(sha256='0'*64),
    lambda r:r['semantic']['cleanup']['raw_sources']['fixture_cleanup'].update(exit_code=1),
    lambda r:r['registration']['stageHashes'].update(resume='0'*64),
    lambda r:r['registration'].update(executionPlanSha256=True),
    lambda r:r['registration']['sourceRecords'].clear(),
    lambda r:r['plan']['candidate'].update(tar_size=201),
])
def test_signed_but_forged_raw_rejected(signed,mutation):
    raw=deepcopy(signed['raw']);mutation(raw)
    payload=deepcopy(signed['payload']);payload['rawCapture']=t._blob(t.canonical(raw))
    with pytest.raises(Exception):c.verify_export(resign(payload,signed['key']),context=signed['context'])


def test_cleanup_flags_cannot_substitute_original(signed):
    closed=deepcopy(signed['closed']);closed['owned_reset']['removed_overlays']=[]
    payload=deepcopy(signed['payload']);payload['cleanupCapture']=t._blob(t.canonical(closed))
    with pytest.raises(c.Error,match='reset'):c.verify_export(resign(payload,signed['key']),context=signed['context'])


def test_registration_stage_hashes_match_controller(signed):
    from deploy.release_lab.coordinated_headless_registration import stage_hashes
    original=t._decode(signed['raw']['original_receipt'])
    assert c.derive_stage_hashes(original,signed['plan'],signed['raw']['semantic']) == stage_hashes(signed['raw']['semantic'],original)


def test_unicode_stage_hashes_match_actual_registration(signed):
    from deploy.release_lab.coordinated_headless_registration import stage_hashes
    semantic=deepcopy(signed['raw']['semantic'])
    for stage in (semantic['update'],semantic['candidate_reboot'],
                  semantic['coordinated_rollback']['held_reboot'],semantic['cleanup']):
        stage['diagnostic_text']='Проверка очистки 日本語'
    original=t._decode(signed['raw']['original_receipt'])+b'\n'
    actual=c.derive_stage_hashes(original,signed['plan'],semantic)
    assert actual == stage_hashes(semantic,original)
    assert actual['steps'] == hashlib.sha256(original).hexdigest()
    assert actual['coordinatedRollback'] == semantic['coordinated_rollback']['raw_sources']['held_record']['sha256']
    assert actual['resume'] == semantic['coordinated_rollback']['raw_sources']['resumed_record']['sha256']


@pytest.mark.parametrize('mutation',[
    lambda r:r['semantic']['coordinated_rollback']['rollback_process'].update(uid_slots=[0,0,0,1]),
    lambda r:r['semantic']['coordinated_rollback']['resume_process'].update(uid_slots=[False,0,0,0]),
    lambda r:r['semantic']['preexisting']['connected']['wireguard'].update(rx_bytes=0),
    lambda r:r['semantic']['preexisting']['baseline']['setup_disconnect'].update(dns_clean=False),
    lambda r:r['semantic']['preexisting']['plan'].update(nonce='2'*48),
])
def test_root_identity_and_preexisting_cannot_be_skipped(signed,mutation):
    raw=deepcopy(signed['raw']);mutation(raw)
    payload=deepcopy(signed['payload']);payload['rawCapture']=t._blob(t.canonical(raw))
    with pytest.raises(Exception):c.verify_export(resign(payload,signed['key']),context=signed['context'])


def test_seam_rejects_foreign_producer_before_key_or_capture(signed):
    class Foreign:
        def acquire(self,context):raise AssertionError('foreign acquisition invoked')
    with pytest.raises(c.Error,match='fixed coordinated producer'):
        c.seal_live_export(Foreign(),context=signed['context'],private_key=object())


@pytest.mark.parametrize('changed_dependency',[None,'linux_live_acquisition.py',
    'trusted_acquisition_export.py','live_acquisition.py'])
def test_seam_fixed_dispatch_and_disposable_signature(signed,monkeypatch,changed_dependency):
    """Mock only live transport/files; real validator/signature remain active."""
    from deploy.release_lab.coordinated_linux_live_acquisition import CoordinatedLinuxLiveProducer
    from deploy.release_lab import android_real_device_acquisition as files
    from deploy.release_lab.lab import LabController
    from contextlib import contextmanager
    producer=object.__new__(CoordinatedLinuxLiveProducer);producer.run_id=signed['plan'].run_id
    producer.controller=LabController(signed['context'].bundle/'inert-lock')
    @contextmanager
    def session(self,owner):
        self._mutation_lock_fd=123;self._mutation_lock_depth+=1
        try:yield self
        finally:self._mutation_lock_depth-=1;self._mutation_lock_fd=None
    monkeypatch.setattr(LabController,'mutation_session',session)
    provenance=signed['payload']['provenance']
    cap=provenance[0]
    run=dict(headless_capability=c.CAPABILITY,headless_capability_record=cap,
        execution_plan_sha256='5'*64,profile_records={},runner_records={},semantic_helper_records={})
    monkeypatch.setattr(CoordinatedLinuxLiveProducer,'_binding',lambda self,context:run)
    calls=[]
    def acquire(self,context):
        calls.append('fixed-class')
        result={name:signed['payload'][name] for name in
            ('target','runId','profileId','startedAt','completedAt','binding','semantics','provenance')}
        return dict(result,capability=c.CAPABILITY,rawCapture=t.canonical(signed['raw']),cleanupCapture=t.canonical(signed['closed']))
    monkeypatch.setattr(CoordinatedLinuxLiveProducer,'acquire',acquire)
    producer.acquire=lambda context: (_ for _ in ()).throw(AssertionError('instance callable invoked'))
    mapping={record['path']:record for record in provenance}
    def file_record(path):
        path=str(path)
        normalized=path if path.startswith('/') else '/repo/'+path.replace('\\','/').rsplit('/',1)[-1]
        digest='8'*64 if calls and changed_dependency and normalized.rsplit('/',1)[-1] == changed_dependency else '9'*64
        return mapping.get(path,dict(path=normalized,sha256=digest,size=100))
    monkeypatch.setattr(files,'file_record',file_record)
    signing=[]
    monkeypatch.setattr(t.make_manifest,'verify_public_key_matches_private',lambda public,key:signing.append('key-check'))
    monkeypatch.setattr(t.make_manifest,'sign_payload',lambda path,body:signing.append('sign') or base64.b64encode(signed['key'].sign(body)).decode())
    if changed_dependency:
        with pytest.raises(c.Error,match='source changed during acquisition'):
            c.seal_live_export(producer,context=signed['context'],private_key='DISPOSABLE-MOCK-ONLY')
        assert calls == ['fixed-class'] and signing == []
        return
    envelope=c.seal_live_export(producer,context=signed['context'],private_key='DISPOSABLE-MOCK-ONLY')
    assert calls == ['fixed-class']
    assert c.verify_export(envelope,context=signed['context'])['target'] == c.TARGET


def test_real_binding_reached_under_real_inert_lock(signed,monkeypatch):
    """Actual binding and mutation_session, no VM or live state root access."""
    import os
    from deploy.release_lab import lab
    from deploy.release_lab.coordinated_linux_live_acquisition import CoordinatedLinuxLiveProducer
    root=signed['context'].bundle/'inert-ownership-test'
    root.mkdir()
    controller=lab.LabController(root)
    producer=CoordinatedLinuxLiveProducer(controller,signed['plan'].run_id)
    # Linux identity is mocked only for this new temporary inert root. The
    # canonical real binding's lock checks and physical lock are not replaced.
    monkeypatch.setattr(lab,'assert_lab_identity',lambda path:None if path == root else pytest.fail('foreign root'))
    if not hasattr(os,'fchmod'):
        monkeypatch.setattr(lab.os,'fchmod',lambda fd,mode:None,raising=False)
    seen=[]
    class ReachedBinding(Exception):pass
    def verify(self):
        assert controller._mutation_lock_fd is not None and controller._mutation_lock_depth > 0
        seen.append(controller._mutation_lock_depth)
        if len(seen) == 2:raise ReachedBinding()
    monkeypatch.setattr(t.AcquisitionContext,'verify',verify)
    with pytest.raises(ReachedBinding):
        c.seal_live_export(producer,context=signed['context'],private_key=object())
    assert seen == [1,1]
    assert controller._mutation_lock_fd is None and controller._mutation_lock_depth == 0
    assert controller.mutation_lock_path.is_file()
