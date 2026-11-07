import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace,ModuleType
from unittest.mock import Mock,patch
import pytest
import deploy.release_lab as package

@pytest.fixture
def tcg_mode(monkeypatch):
    # Inert adapter only. Runtime uses the separately verified execution copy.
    adapter=ModuleType('deploy.release_lab.tcg_mode');adapter.load=Mock()
    monkeypatch.setitem(sys.modules,adapter.__name__,adapter)
    monkeypatch.setattr(package,'tcg_mode',adapter,raising=False)
    return adapter

spec=importlib.util.spec_from_file_location('deploy.release_lab.staged_gui_driver',Path(__file__).parent/'linux_gui_driver.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

def driver(tmp_path,acceleration):
    d=m.LinuxGuiDriver.__new__(m.LinuxGuiDriver)
    d.controller=SimpleNamespace(linux_acceleration=acceleration);d.run={};d.run_id='test-run';d.nonce='a'*48
    d.script='/owned/helper.py';d.guest_root='/owned';d.binary_sha='a'*64;d.run['candidate_version']='5.0.3.14'
    d.artifact={'sha256':'b'*64};d.helper={'sha256':'c'*64};d.archive=tmp_path
    d._fence=Mock();d.qga=Mock()
    d.qga.guest_exec_wait.return_value={'exitcode':0,'stdout':json.dumps({'schema':'amnezia.release-lab.linux-gui-window.v1','phase':'launch','origin':'qga','injected':False,'run_id':d.run_id,'profile':m.PROFILE,'attempt_nonce':d.nonce})}
    return d

def test_tcg_explicit_softpipe_requires_actual_reviewed_plan(tmp_path,tcg_mode):
    d=driver(tmp_path,'tcg')
    with patch.object(tcg_mode,'load',return_value={'acceleration':'tcg','profiles':{m.PROFILE:{}}}) as load:d._execute('launch')
    assert d.qga.guest_exec_wait.call_args.args[1][-2:]==['--renderer-policy','softpipe']
    load.assert_called_once()

@pytest.mark.parametrize('acceleration',['kvm',None])
def test_non_tcg_default_renderer_untouched(tmp_path,acceleration,tcg_mode):
    d=driver(tmp_path,acceleration)
    with patch.object(tcg_mode,'load') as load:d._execute('launch')
    load.assert_not_called()
    assert '--renderer-policy' not in d.qga.guest_exec_wait.call_args.args[1]

@pytest.mark.parametrize('plan',[{},None,{'acceleration':'kvm','profiles':{m.PROFILE:{}}},{'acceleration':'tcg','profiles':{}}])
def test_invalid_tcg_plan_prevents_any_guest_command(tmp_path,plan,tcg_mode):
    d=driver(tmp_path,'tcg')
    with patch.object(tcg_mode,'load',return_value=plan):
        with pytest.raises(m.LinuxGuiDriverError):d._execute('launch')
    d.qga.guest_exec_wait.assert_not_called()

def test_missing_tcg_adapter_is_explicit_and_prevents_guest_command(tmp_path,monkeypatch):
    d=driver(tmp_path,'tcg')
    monkeypatch.delattr(package,'tcg_mode',raising=False)
    monkeypatch.setitem(sys.modules,'deploy.release_lab.tcg_mode',None)
    with pytest.raises(m.LinuxGuiDriverError,match='TCG adapter unavailable'):d._execute('launch')
    d.qga.guest_exec_wait.assert_not_called()

@pytest.mark.parametrize('case',['retained','ownership-lost','diagnostic-io','archive-io'])
def test_existing_primary_preservation_regressions_against_actual_staged_driver(tmp_path,monkeypatch,case):
    # Reuse existing contracts against this staged subject, not a mirrored driver.
    monkeypatch.setitem(sys.modules,'deploy.release_lab.linux_gui_driver',m)
    monkeypatch.setitem(sys.modules,m.__name__,m)
    monkeypatch.setattr(package,'linux_gui_driver',m,raising=False)
    path=Path(package.__file__).parent/'test_linux_gui_driver.py'
    oldspec=importlib.util.spec_from_file_location('deploy.release_lab._staged_failure_regressions',path)
    old=importlib.util.module_from_spec(oldspec);oldspec.loader.exec_module(old)
    if case=='retained':old.test_launch_failure_retains_private_snapshot_even_with_ordinary_archive(tmp_path,monkeypatch)
    elif case=='archive-io':old.test_private_archive_io_failure_never_replaces_launch_primary(tmp_path,monkeypatch)
    else:old.test_launch_diagnostic_failure_or_lost_ownership_preserves_primary(tmp_path,monkeypatch,case=='ownership-lost')
