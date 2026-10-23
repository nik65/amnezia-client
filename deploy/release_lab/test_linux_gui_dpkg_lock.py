import base64,contextlib,hashlib,importlib.util,io,json,os,sys,time,types,unittest
from pathlib import Path
from unittest.mock import patch
import pytest
ROOT=Path(__file__).parent
spec=importlib.util.spec_from_file_location('dpkg_lock_subject',ROOT/'guest_helpers/linux_gui_xres_dependency.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

def test_actual_controlled_child_frontend_lock_then_success_retains_every_outcome(tmp_path):
    state=tmp_path/'counter';report={};owned=[]
    source='import pathlib,sys;p=pathlib.Path(sys.argv[1]);n=int(p.read_text()) if p.exists() else 0;p.write_text(str(n+1));sys.stderr.write("dpkg: error: dpkg frontend lock was locked by another process with pid "+sys.argv[2]+"\\n") if n==0 else None;print("installed") if n else None;sys.exit(2 if n==0 else 0)'
    result=m.install_with_lock_retry([sys.executable,'-c',source,str(state),str(os.getpid())],time.monotonic()+5,report,lambda:owned.append(True))
    assert result==b'installed\n' and len(report['packageInstallAttempts'])==2 and len(owned)==2
    first,last=report['packageInstallAttempts']
    assert first['exitcode']==2 and last['exitcode']==0
    assert first['lockHolder']['reportedPID']==os.getpid() and first['lockHolder']['identityObserved'] is True
    assert base64.b64decode(first['stderr_base64']).startswith(b'dpkg: error: dpkg frontend lock')

@pytest.mark.parametrize('code,message',[(1,'dpkg: error: dpkg frontend lock was locked by another process with pid123\n'),(2,'dpkg: error: corrupt archive\n')])
def test_actual_noncontention_child_error_is_immediate_not_retried(code,message):
    report={}
    with pytest.raises(RuntimeError,match='without retryable'):
        m.install_with_lock_retry([sys.executable,'-c','import sys;sys.stderr.write(sys.argv[1]);sys.exit(int(sys.argv[2]))',message,str(code)],time.monotonic()+5,report,lambda:None)
    assert len(report['packageInstallAttempts'])==1

def test_actual_contention_expiry_honors_existing_shorter_deadline():
    report={};start=time.monotonic()
    source='import sys;sys.stderr.write("dpkg: error: dpkg frontend lock was locked by another process with pid "+sys.argv[1]+"\\n");sys.exit(2)'
    with pytest.raises(RuntimeError,match='budget exhausted'):
        m.install_with_lock_retry([sys.executable,'-c',source,str(os.getpid())],start+.2,report,lambda:None)
    assert time.monotonic()-start<1.2 and len(report['packageInstallAttempts'])==1

def test_actual_output_flood_or_timeout_is_bounded_and_never_retries():
    for source in ['import os;os.write(1,b"x"*1000000)','import time;time.sleep(5)']:
        report={};start=time.monotonic()
        with pytest.raises(RuntimeError,match='output/deadline'):
            m.install_with_lock_retry([sys.executable,'-c',source],start+.15,report,lambda:None)
        assert len(report['packageInstallAttempts'])==1 and time.monotonic()-start<2
        row=report['packageInstallAttempts'][0]
        assert len(base64.b64decode(row['stdout_base64']))+len(base64.b64decode(row['stderr_base64']))<=8192

def test_ownership_loss_prevents_any_install_child():
    def lost():raise RuntimeError('ownership lost')
    with patch.object(m,'install_attempt') as command:
        with pytest.raises(RuntimeError,match='ownership lost'):m.install_with_lock_retry(['inert'],time.monotonic()+5,{},lost)
        command.assert_not_called()

def test_holder_missing_or_raced_is_gap_not_fabricated_identity():
    result=m.lock_holder(2**30)
    assert result['gaps'] and not result.get('identityObserved')

def test_existing_dependency_suite_against_actual_staged_helper():
    import deploy.release_lab
    canonical=Path(deploy.release_lab.__file__).parent/'test_linux_gui_xres_dependency.py'
    namespace={'__name__':'deploy.release_lab._dpkg_staged_tests','__package__':'deploy.release_lab','__file__':str(canonical)}
    exec(compile((ROOT/'test_linux_gui_xres_dependency.py').read_bytes(),str(canonical),'exec'),namespace)
    namespace['guest']=m
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(namespace['DependencyTests'])
    stream=io.StringIO();result=unittest.TextTestRunner(stream=stream).run(suite)
    assert result.wasSuccessful(),stream.getvalue()
    assert result.testsRun>=10
