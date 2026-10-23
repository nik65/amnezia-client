import hashlib
import io
import json
from pathlib import Path
from types import SimpleNamespace
import tarfile
from unittest.mock import Mock

import pytest
from .linux_headless_driver import (HeadlessDriverError,OwnedRebootCollector,PreparedHeadlessDriver,
    PROMOTE,FIXTURE_CLEANUP,read_release)
from .test_headless_native_acceptance import plan


def record(path):
    data=path.read_bytes();return {'path':str(path),'size':len(data),'sha256':hashlib.sha256(data).hexdigest()}


def archive(tmp_path,members):
    path=tmp_path/'update.tar.gz'
    with tarfile.open(path,'w:gz') as tar:
        for name,data,kind in members:
            member=tarfile.TarInfo(name);member.size=len(data);member.type=kind
            tar.addfile(member,io.BytesIO(data) if kind==tarfile.REGTYPE else None)
    manifest=tmp_path/'manifest.json';manifest.write_bytes(b'bound signed manifest fixture')
    return record(path),record(manifest)


def test_read_release_binds_exact_archive_and_binary_bytes(tmp_path):
    artifact,manifest=archive(tmp_path,[('amneziad',b'daemon',tarfile.REGTYPE),('amnezia-cli',b'cli',tarfile.REGTYPE)])
    release,blobs=read_release(artifact,manifest,'5.0.3.14','a'*64)
    assert release.tar_sha256==artifact['sha256']
    assert release.manifest_sha256==manifest['sha256']
    assert release.amneziad_sha256==hashlib.sha256(b'daemon').hexdigest()
    assert release.cli_size==3 and blobs['amnezia-cli']==b'cli'


@pytest.mark.parametrize('members',[
    [('amneziad',b'x',tarfile.REGTYPE)],
    [('amneziad',b'x',tarfile.REGTYPE),('amneziad',b'y',tarfile.REGTYPE)],
    [('../amneziad',b'x',tarfile.REGTYPE),('amnezia-cli',b'y',tarfile.REGTYPE)],
    [('amneziad',b'',tarfile.SYMTYPE),('amnezia-cli',b'y',tarfile.REGTYPE)],
    [('amneziad',b'',tarfile.REGTYPE),('amnezia-cli',b'y',tarfile.REGTYPE)],
])
def test_unsafe_or_noncanonical_update_archive_rejected(tmp_path,members):
    artifact,manifest=archive(tmp_path,members)
    with pytest.raises(HeadlessDriverError):read_release(artifact,manifest,'5.0.3.14','a'*64)


def test_changed_planned_archive_rejected_before_read(tmp_path):
    artifact,manifest=archive(tmp_path,[('amneziad',b'x',tarfile.REGTYPE),('amnezia-cli',b'y',tarfile.REGTYPE)])
    Path(artifact['path']).write_bytes(b'changed')
    with pytest.raises(HeadlessDriverError,match='identity changed'):read_release(artifact,manifest,'5.0.3.14','a'*64)


def test_corrected_driver_captures_candidate_before_rollback_and_cleans_before_reboot(tmp_path,monkeypatch):
    from . import linux_headless_driver as module
    calls=[];p=plan();state={'version':p.baseline.version}
    native=SimpleNamespace()
    def identity(release,label):
        calls.append(label);assert release.version==state['version'];return {'label':label}
    native.identity=identity
    native.cli_json=lambda *_:{}
    armed={'phase':None}
    class Observation:
        def __init__(self,native,phase,timeout,**kwargs):assert kwargs=={'failure_archive':tmp_path};self.phase=phase
        def __enter__(self):armed['phase']=self.phase;calls.append('arm-'+self.phase);return self
        def collect(self):return {}
        def __exit__(self,*a):armed['phase']=None
    monkeypatch.setattr(module,'PendingObservation',Observation)
    def stage_profile():
        assert armed['phase']=='restart_pending';calls.append('stage-profile');return {'profile_store':{}}
    native.stage_profile=stage_profile
    native.collect_update_pending=lambda:{}
    native.collect_update_stable=lambda:{}
    native.collect_rollback_pending=lambda:{}
    native.collect_rollback_stable=lambda:{}
    def wait(collector,ready,**kwargs):
        if collector is native.collect_update_stable:state['version']=p.candidate.version
        if collector is native.collect_rollback_stable:state['version']=p.baseline.version
        return {}
    native.wait_for=wait
    native.build_update_receipt=lambda **kw:{'kind':'update'}
    native.build_rollback_receipt=lambda **kw:{'kind':'rollback'}
    native.build_reboot_receipt=lambda **kw:{'kind':'reboot'}
    native.validate_fixture_cleanup=lambda x,y:x
    fixture=SimpleNamespace(prepare_and_connect=lambda:{},crash_and_restart=lambda *x:{},promote_systemd_baseline=lambda *_:None,boot_id=lambda _:'boot-before',disable_update_profile=lambda:calls.append('disable-updater') or {'disabled':True},cleanup=lambda *_:calls.append('fixture-cleanup') or {'network_removed':True})
    server=SimpleNamespace(start=lambda:None,reset=lambda:None,collect=lambda:{'http':True},stop=lambda _:calls.append('http-stop') or {'cleanup':True})
    def rollback(_):
        assert armed['phase']=='rollback_restart_pending';calls.append('trigger-rollback');assert calls.index('candidate-before')<calls.index('arm-rollback_restart_pending')<calls.index('trigger-rollback');return {'cli_process':{},'cli_response':{}}
    def reboot(*_):
        calls.append('reboot');assert calls.index('disable-updater')<calls.index('http-stop')<calls.index('fixture-cleanup')<calls.index('reboot')
        assert state['version']==p.baseline.version
        return {'boot_id_before':'old','boot_id_after':'new','after_raw':{},'raw_sources':{}}
    collector=SimpleNamespace(trigger_rollback=rollback,reboot_and_collect=reboot)
    for name in ('validate_update_receipt','validate_rollback_receipt','validate_reboot_receipt'):monkeypatch.setattr(module,name,lambda *x:None)
    driver=PreparedHeadlessDriver(p,native,server,fixture,collector,tmp_path)
    result=driver.run()
    assert set(result)=={'http','update','rollback','reboot','cleanup'}
    assert calls.index('candidate-before')<calls.index('trigger-rollback')<calls.index('baseline-after')
    assert result['http']=={'http':True}


def test_reboot_ownership_failure_is_not_swallowed_or_retried():
    p=plan();qga=Mock();qga.guest_exec.return_value={'pid':9}
    native=Mock();fence=Mock();fence.check.side_effect=HeadlessDriverError('QEMU PID changed')
    collector=OwnedRebootCollector(qga,p,native,lambda:p.outer_binding,process_fence=fence)
    collector.stage_persistent_marker=lambda:{'path':'marker','sha256':'a'*64,'size':1}
    with pytest.raises(HeadlessDriverError,match='PID changed'):collector.reboot_and_collect('old',p.baseline)
    qga.sync.assert_not_called();native.identity.assert_not_called()


@pytest.mark.parametrize('gap_kind',['os','lab'])
def test_reboot_retries_only_transport_gap_then_requires_full_proof(monkeypatch,gap_kind):
    from .lab import LabError
    p=plan();qga=Mock();qga.guest_exec.return_value={'pid':9};qga.sync.side_effect=[(OSError if gap_kind=='os' else LabError)('expected reboot gap'),True]
    qga.guest_exec_wait.return_value={'exitcode':0,'stdout':'new-boot'}
    native=Mock();native.raw_file.return_value={'sha256':'a'*64,'size':1};fence=Mock();fence.check.return_value=p.outer_binding
    checks=[];snapshot=lambda:checks.append('full') or p.outer_binding
    clock=[0]
    def sleep(seconds):clock[0]+=seconds
    collector=OwnedRebootCollector(qga,p,native,snapshot,process_fence=fence,clock=lambda:clock[0],sleep=sleep)
    collector.stage_persistent_marker=lambda:{'path':'marker','sha256':'a'*64,'size':1}
    result=collector.reboot_and_collect('old-boot',p.baseline)
    assert result['boot_id_after']=='new-boot' and fence.check.call_count==2
    assert len(checks)>=2
    native.identity.assert_called_once_with(p.baseline,'post-reboot')


def test_reboot_gap_does_not_authorize_guest_reads_after_lost_full_proof():
    p=plan();qga=Mock();qga.guest_exec.return_value={'pid':9};qga.sync.return_value=True;qga.guest_exec_wait.return_value={'exitcode':0,'stdout':'new-boot'}
    native=Mock();fence=Mock();fence.check.return_value=p.outer_binding
    snapshots=iter([p.outer_binding,SimpleNamespace(changed=True)])
    collector=OwnedRebootCollector(qga,p,native,lambda:next(snapshots),process_fence=fence)
    collector.stage_persistent_marker=lambda:{'path':'marker','sha256':'a'*64,'size':1}
    with pytest.raises(Exception,match='ownership changed'):collector.reboot_and_collect('old-boot',p.baseline)
    native.identity.assert_not_called()


def test_embedded_guest_programs_compile_and_preserve_baseline_binaries():
    compile(PROMOTE,'<owned-baseline-promotion>','exec');compile(FIXTURE_CLEANUP,'<owned-fixture-cleanup>','exec')
    assert 'setup-daemon.backup' in PROMOTE and 'pidfd_send_signal' in PROMOTE
    assert 'restart-guard' not in PROMOTE
    assert 'setup-daemon.backup' not in FIXTURE_CLEANUP and 'setup-cli.backup' not in FIXTURE_CLEANUP
    assert "['autoUpdate']=False" in FIXTURE_CLEANUP
