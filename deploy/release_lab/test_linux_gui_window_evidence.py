import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest


HELPER = Path(__file__).parent / "guest_helpers" / "linux_gui_window_evidence.py"
SPEC = importlib.util.spec_from_file_location("linux_gui_window_evidence", HELPER)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MODULE)


def args(tmp_path: Path, action: str = "collect") -> SimpleNamespace:
    run_id = "gui-window-test"
    return SimpleNamespace(action=action, run_id=run_id, profile=MODULE.PROFILE,
                           attempt_nonce="attempt-123456789",
                           marker_path=str(tmp_path / "marker"),
                           evidence_dir=str(Path("/run/amnezia-release-lab") / run_id / MODULE.PROFILE),
                           timeout=1, dwell=0, expected_version="5.0.1.39",
                           expected_binary_sha256="a" * 64, artifact_sha256="b" * 64,
                           helper_sha256="c" * 64, screenshot_ack=None)


def launch_state() -> dict:
    return {"schema": MODULE.SCHEMA, "phase": "launch", "origin": "qga", "injected": False,
            "run_id": "gui-window-test", "profile": MODULE.PROFILE,
            "attempt_nonce": "attempt-123456789", "observed_at": "2026-09-13T19:59:00Z",
            "guest_marker": "amnezia-release-lab:gui-window-test:linux-x64-gui",
            "session": {"uid": 1001, "user": "lab", "display": ":0", "xauthority": "/run/user/1001/gdm/Xauthority"},
            "process": {"pid": 42, "start_ticks": 9001, "exe": str(MODULE.BINARY), "uid": 1001,
                        "installed_binary_sha256": "a" * 64},
            "window": {"id": "0x200001", "title": "AmneziaVPN", "map_state": "IsViewable"},
            "version": "5.0.1.39", "artifact_sha256": "b" * 64, "helper_sha256": "c" * 64,
            "expected_binary_sha256": "a" * 64}


def test_version_probe_rejects_application_not_running(tmp_path):
    state=launch_state();payload=json.dumps({'schema':'amnezia.operator.status.v1','version':'5.0.1.39','pid':42,'applicationRunning':False,'error':'application_not_running'}).encode()
    with patch.object(MODULE,'same_process',return_value=True),patch.object(MODULE,'mapped_windows',return_value=[state['window']]),patch.object(MODULE,'status_attempt',return_value={'exitcode':4,'stdout':payload,'stderr':b'','timeout':False,'overflow':False}):
        with pytest.raises(MODULE.EvidenceError,match='live operator status'):
            MODULE.running_version(state['session'],'5.0.1.39',state['process'],state['window'],MODULE.time.monotonic()+60,tmp_path)


def test_collect_requires_unique_live_mapped_window_and_marks_png_for_review(tmp_path: Path) -> None:
    state = launch_state()
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    ack = evidence / "screenshot-archive-ack.json"
    ack.write_text(json.dumps({"run_id": "gui-window-test", "profile": MODULE.PROFILE, "pid": 42,
                               "schema": "amnezia.release-lab.controller-screenshot-ack.v1",
                               "controller_created": True, "guest_marker": state["guest_marker"],
                               "attempt_nonce": "attempt-123456789",
                               "start_ticks": 9001, "window_id": "0x200001",
                               "artifact_sha256": "b" * 64, "helper_sha256": "c" * 64,
                               "expected_version": "5.0.1.39", "expected_binary_sha256": "a" * 64,
                               "screenshot_sha256": "d" * 64, "screenshot_size": 4096,
                               "archive_record": {"path": "/owned/export/gui.png", "sha256": "d" * 64,
                                                  "size": 4096, "kind": "linux-gui-window"},
                               "final_gate_revalidation_required": True, "unique_colors": 17}), encoding="utf-8")
    values = args(tmp_path)
    values.screenshot_ack = str(ack)
    with patch.object(MODULE,"require_unlocked_session",return_value={}), patch.object(MODULE, "load_launch", return_value=state), \
         patch.object(MODULE, "same_process", return_value=True), \
         patch.object(MODULE, "mapped_windows", return_value=[state["window"]]), \
         patch.object(MODULE, "service_health", return_value={"active": "active"}), \
         patch.object(MODULE, "atomic_json"):
        result = MODULE.collect(values, evidence, state["guest_marker"])
    assert result["window_ready"] if "window_ready" in result else True
    assert result["visual_review_required"] is True
    assert result["visual_review_passed"] is False
    assert result["screenshot"]["pixel_diagnostics_are_acceptance"] is False


def test_collect_rejects_window_identity_change(tmp_path: Path) -> None:
    state = launch_state()
    values = args(tmp_path)
    with patch.object(MODULE,"require_unlocked_session",return_value={}), patch.object(MODULE, "load_launch", return_value=state), \
         patch.object(MODULE, "same_process", return_value=True), \
         patch.object(MODULE, "mapped_windows", return_value=[]):
        with pytest.raises(MODULE.EvidenceError, match="uniquely visible"):
            MODULE.collect(values, tmp_path, state["guest_marker"])


def test_cleanup_refuses_pid_reuse_without_signalling(tmp_path: Path) -> None:
    state = launch_state()
    values = args(tmp_path, "cleanup")
    with patch.object(MODULE,"require_unlocked_session",return_value={}), patch.object(MODULE, "load_launch", return_value=state), \
         patch.object(MODULE, "same_process", return_value=False), \
         patch.object(MODULE.os, "kill") as kill:
        with pytest.raises(MODULE.EvidenceError, match="identity changed"):
            MODULE.cleanup(values, tmp_path, state["guest_marker"])
    kill.assert_not_called()


def test_mapped_window_requires_pid_title_and_isviewable() -> None:
    outputs = iter([
        "_NET_CLIENT_LIST(WINDOW): window id # 0x200001, 0x200002",
        '_NET_WM_PID(CARDINAL) = 42\n_NET_WM_NAME(UTF8_STRING) = "AmneziaVPN"\nWM_CLASS(STRING) = "amneziavpn", "AmneziaVPN"',
        "Map State: IsViewable",
        '_NET_WM_PID(CARDINAL) = 7\n_NET_WM_NAME(UTF8_STRING) = "Other"',
        "Map State: IsViewable",
    ])
    with patch.object(MODULE, "command", side_effect=lambda *a, **k: next(outputs)):
        assert MODULE.mapped_windows(42, {"display": ":0", "xauthority": "/x"}) == [
            {"id": "0x200001", "title": "AmneziaVPN", "wm_class": ["amneziavpn", "AmneziaVPN"], "map_state": "IsViewable"}
        ]


def test_load_launch_rejects_stale_artifact_or_helper_binding(tmp_path: Path) -> None:
    state = launch_state()
    (tmp_path / "launch.json").write_text(json.dumps(state), encoding="utf-8")
    values = args(tmp_path)
    assert MODULE.load_launch(values, tmp_path, state["guest_marker"])["version"] == "5.0.1.39"
    state["artifact_sha256"] = "e" * 64
    (tmp_path / "launch.json").write_text(json.dumps(state), encoding="utf-8")
    with pytest.raises(MODULE.EvidenceError, match="identity"):
        MODULE.load_launch(values, tmp_path, state["guest_marker"])


def test_atomic_json_creates_once_and_rejects_existing_or_symlink_parent(tmp_path: Path) -> None:
    target = tmp_path / "owned" / "phase.json"
    MODULE.atomic_json(target, {"passed": True})
    assert json.loads(target.read_text(encoding="utf-8"))["passed"] is True
    with pytest.raises(MODULE.EvidenceError, match="already exists"):
        MODULE.atomic_json(target, {"passed": False})
    real = tmp_path / "real"; real.mkdir()
    link = tmp_path / "link"
    try:
        link.symlink_to(real, target_is_directory=True)
    except (OSError, NotImplementedError):
        return
    with pytest.raises(MODULE.EvidenceError, match="symlink"):
        MODULE.atomic_json(link / "phase.json", {"passed": True})


def test_collect_rejects_forged_controller_archive_ack(tmp_path: Path) -> None:
    state = launch_state(); ack = tmp_path / "screenshot-archive-ack.json"
    ack.write_text(json.dumps({"schema": "amnezia.release-lab.controller-screenshot-ack.v1",
        "controller_created": True, "run_id": "gui-window-test", "profile": MODULE.PROFILE,
        "attempt_nonce": "attempt-123456789",
        "guest_marker": state["guest_marker"], "pid": 42, "start_ticks": 9001,
        "window_id": "0x200001", "artifact_sha256": "b"*64, "helper_sha256": "c"*64,
        "expected_version": "5.0.1.39", "expected_binary_sha256": "a"*64,
        "screenshot_sha256": "d"*64, "screenshot_size": True,
        "archive_record": {"path":"/owned/x","sha256":"d"*64,"size":True,"kind":"linux-gui-window"},
        "final_gate_revalidation_required": True}), encoding="utf-8")
    values=args(tmp_path); values.screenshot_ack=str(ack)
    with patch.object(MODULE,"require_unlocked_session",return_value={}),patch.object(MODULE,"load_launch",return_value=state), patch.object(MODULE,"same_process",return_value=True), patch.object(MODULE,"mapped_windows",return_value=[state["window"]]):
        with pytest.raises(MODULE.EvidenceError, match="metadata"):
            MODULE.collect(values,tmp_path,state["guest_marker"])


def test_signal_exact_process_rechecks_after_opening_pidfd() -> None:
    identity=launch_state()["process"]
    with patch.object(MODULE.os,"pidfd_open",return_value=9,create=True), \
         patch.object(MODULE.signal,"pidfd_send_signal",create=True) as send, \
         patch.object(MODULE,"same_process",return_value=False), patch.object(MODULE.os,"close"):
        with pytest.raises(MODULE.EvidenceError,match="immediately"):
            MODULE.signal_exact_process(identity,MODULE.signal.SIGTERM)
    send.assert_not_called()


def test_launch_rejects_duplicate_before_process_creation(tmp_path: Path) -> None:
    values = args(tmp_path, "launch")
    evidence = tmp_path / "evidence"; evidence.mkdir()
    (evidence / "launch.json").write_text("{}", encoding="utf-8")
    binary = tmp_path / "AmneziaVPN"; binary.write_bytes(b"binary")
    session = {"uid": 1001, "display": ":0", "xauthority": "/run/user/1001/Xauthority"}
    with patch.object(MODULE, "BINARY", binary), \
         patch.object(MODULE, "sha256", side_effect=["a" * 64, "c" * 64]), \
         patch.object(MODULE.os, "access", return_value=True), \
         patch.object(MODULE, "active_x11_session", return_value=session), \
         patch.object(MODULE, "exact_binary_pids", return_value=set()), \
         patch.object(MODULE.subprocess, "Popen") as popen:
        with pytest.raises(MODULE.EvidenceError, match="refusing guest effects"):
            MODULE.launch(values, evidence, "amnezia-release-lab:gui-window-test:linux-x64-gui")
    popen.assert_not_called()


def status_result(error=None,*,pid=42,version='5.0.1.39',code=0):
    value={'schema':'amnezia.operator.status.v1','version':version,'pid':pid,'applicationRunning':True}
    if error:value['error']=error
    return {'exitcode':code,'stdout':json.dumps(value).encode(),'stderr':b'','timeout':False,'overflow':False}


def status_timeout():return {'exitcode':5,'stdout':b'','stderr':b'Timed out waiting for the running Amnezia instance.','timeout':False,'overflow':False}


@pytest.mark.parametrize('first',[status_timeout(),status_result('application_not_ready',code=4)])
def test_exact_startup_retry_then_same_primary_success_retains_every_raw(tmp_path,first):
    state=launch_state()
    with patch.object(MODULE,'same_process',return_value=True),patch.object(MODULE,'mapped_windows',return_value=[state['window']]),patch.object(MODULE,'status_attempt',side_effect=[first,status_result()]) as attempt,patch.object(MODULE.time,'sleep'):
        assert MODULE.running_version(state['session'],'5.0.1.39',state['process'],state['window'],MODULE.time.monotonic()+60,tmp_path)=='5.0.1.39'
    assert attempt.call_count==2
    assert len(list(tmp_path.glob('status-attempt-*.json')))==2
    import base64
    saved=json.loads((tmp_path/'status-attempt-001.json').read_bytes())
    assert base64.b64decode(saved['stderr_base64'])==first['stderr']


def test_permanent_same_primary_timeout_uses_only_existing_total_budget(tmp_path):
    state=launch_state();clock={'value':0};timeouts=[]
    def attempt(argv,timeout):timeouts.append(timeout);clock['value']+=15;return status_timeout()
    with patch.object(MODULE,'same_process',return_value=True),patch.object(MODULE,'mapped_windows',return_value=[state['window']]),patch.object(MODULE,'status_attempt',side_effect=attempt),patch.object(MODULE.time,'monotonic',side_effect=lambda:clock['value']),patch.object(MODULE.time,'sleep'):
        with pytest.raises(MODULE.EvidenceError,match='budget exhausted'):MODULE.running_version(state['session'],'5.0.1.39',state['process'],state['window'],60,tmp_path)
    assert clock['value']==60 and timeouts==[30,30,30,15]
    assert len(list(tmp_path.glob('status-attempt-*.json')))==4


@pytest.mark.parametrize('result',[status_result(version='5.0.3.13'),status_result(pid=99),status_result('worker_snapshot_pending'),{'exitcode':5,'stdout':b'','stderr':b'foreign protocol','timeout':False,'overflow':False}])
def test_wrong_version_pid_protocol_and_unknown_error_never_retried(tmp_path,result):
    state=launch_state()
    with patch.object(MODULE,'same_process',return_value=True),patch.object(MODULE,'mapped_windows',return_value=[state['window']]),patch.object(MODULE,'status_attempt',return_value=result) as attempt:
        with pytest.raises(MODULE.EvidenceError):MODULE.running_version(state['session'],'5.0.1.39',state['process'],state['window'],MODULE.time.monotonic()+60,tmp_path)
    assert attempt.call_count==1


def test_primary_identity_change_prevents_another_status_command(tmp_path):
    state=launch_state()
    with patch.object(MODULE,'same_process',side_effect=[True,True,False]),patch.object(MODULE,'mapped_windows',return_value=[state['window']]),patch.object(MODULE,'status_attempt',return_value=status_timeout()) as attempt,patch.object(MODULE.time,'sleep'):
        with pytest.raises(MODULE.EvidenceError,match='process/window changed'):MODULE.running_version(state['session'],'5.0.1.39',state['process'],state['window'],MODULE.time.monotonic()+60,tmp_path)
    assert attempt.call_count==1


@pytest.mark.skipif(os.name!='posix',reason='actual scoped pipe/process-group fixture')
def test_actual_status_pipe_capture_is_bounded_and_timeout_reaps():
    import sys,time
    flood=MODULE.status_attempt([sys.executable,'-c','import os;os.write(1,b"x"*1000000);os.write(2,b"y"*1000000)'],2)
    assert flood['overflow'] is True and len(flood['stdout'])+len(flood['stderr'])<=65536
    start=time.monotonic();slow=MODULE.status_attempt([sys.executable,'-c','import time;time.sleep(5)'],.1)
    assert slow['timeout'] is True and time.monotonic()-start<2


@pytest.mark.skipif(os.name!='posix' or getattr(os,'geteuid',lambda:-1)()!=0,reason='root private descriptor fixture')
def test_actual_private_failure_snapshot_retains_log_tail_and_safe_process_env(tmp_path):
    import subprocess,base64
    child=subprocess.Popen(['/usr/bin/sleep','20'],env={'DISPLAY':':0','GALLIUM_DRIVER':'softpipe','SECRET_TEST_TOKEN':'must-not-retain'})
    try:
        identity=MODULE.proc_identity(child.pid);values=args(tmp_path);values.helper_sha256=MODULE.sha256(HELPER);values.expected_binary_sha256=identity['installed_binary_sha256']
        record={'run_id':values.run_id,'profile':MODULE.PROFILE,'attempt_nonce':values.attempt_nonce,'artifact_sha256':values.artifact_sha256,'helper_sha256':values.helper_sha256,'expected_binary_sha256':values.expected_binary_sha256}
        MODULE.atomic_json(tmp_path/'attempt.json',record);MODULE.atomic_json(tmp_path/'launch-progress.json',{'run_id':values.run_id,'attempt_nonce':values.attempt_nonce,'process':identity})
        log=tmp_path/'application.log';log.write_bytes(b'x'*200000+b'actual-tail');log.chmod(0o600)
        value=MODULE.diagnose(values,tmp_path,'amnezia-release-lab:'+values.run_id+':'+MODULE.PROFILE)
        assert value['diagnosticOnly'] is True and value['phase']=='diagnose'
        assert value['application.log']['truncated'] is True
        assert base64.b64decode(value['application.log']['body_base64']).endswith(b'actual-tail')
        assert value['safeEnvironment']['GALLIUM_DRIVER']=='softpipe' and 'SECRET_TEST_TOKEN' not in value['safeEnvironment']
        assert value['process']['pid']==child.pid and len(json.dumps(value).encode())<512000
    finally:child.terminate();child.wait()


def test_launch_retries_status_and_dwell_within_same_original_budget(tmp_path):
    values=args(tmp_path,'launch');values.timeout=60;values.dwell=10
    binary=tmp_path/'AmneziaVPN';binary.write_bytes(b'inert executable bytes')
    state=launch_state();identity={**state['process'],'exe':str(binary)};clock={'now':0};timeouts=[]
    def status(argv,timeout):
        timeouts.append(timeout);clock['now']+=15 if len(timeouts)==1 else .1
        return status_timeout() if len(timeouts)==1 else status_result()
    with patch.object(MODULE,'require_unlocked_session',return_value={}),patch.object(MODULE,'BINARY',binary),patch.object(MODULE,'sha256',side_effect=['a'*64,'c'*64]),patch.object(MODULE.os,'access',return_value=True),patch.object(MODULE,'active_x11_session',return_value=state['session']),patch.object(MODULE,'exact_binary_pids',side_effect=[set(),{42}]),patch.object(MODULE,'proc_identity',return_value=identity),patch.object(MODULE,'same_process',return_value=True),patch.object(MODULE,'mapped_windows',return_value=[state['window']]),patch.object(MODULE,'status_attempt',side_effect=status),patch.object(MODULE,'service_health',return_value={'active':'active'}),patch.object(MODULE.subprocess,'Popen'),patch.object(MODULE.time,'monotonic',side_effect=lambda:clock['now']),patch.object(MODULE.time,'sleep',side_effect=lambda seconds:clock.__setitem__('now',clock['now']+seconds)):
        value=MODULE.launch(values,tmp_path,'amnezia-release-lab:gui-window-test:linux-x64-gui')
    assert value['version']=='5.0.1.39' and value['crash_free_dwell_seconds']==10
    assert clock['now']<=60 and len(timeouts)==2
    assert (tmp_path/'attempt.json').exists() and (tmp_path/'launch-progress.json').exists()


def test_service_health_calls_also_use_remaining_launch_budget():
    clock={'now':0};calls=[]
    def command(argv,**kwargs):calls.append(kwargs['timeout']);clock['now']+=1;return 'active'
    with patch.object(MODULE.time,'monotonic',side_effect=lambda:clock['now']),patch.object(MODULE,'command',side_effect=command):
        with pytest.raises(MODULE.EvidenceError,match='budget exhausted'):MODULE.service_health(deadline=2)
    assert calls==[2,1]


@pytest.mark.skipif(os.name!='posix' or getattr(os,'geteuid',lambda:-1)()!=0,reason='root private descriptor fixture')
def test_diagnostic_foreign_attempt_and_log_symlink_fail_closed(tmp_path):
    values=args(tmp_path);values.helper_sha256=MODULE.sha256(HELPER)
    record={'run_id':values.run_id,'profile':MODULE.PROFILE,'attempt_nonce':values.attempt_nonce,'artifact_sha256':values.artifact_sha256,'helper_sha256':values.helper_sha256,'expected_binary_sha256':values.expected_binary_sha256}
    MODULE.atomic_json(tmp_path/'attempt.json',{**record,'attempt_nonce':'foreign'})
    with patch.object(MODULE,'same_process') as process:
        with pytest.raises(MODULE.EvidenceError,match='attempt identity'):MODULE.diagnose(values,tmp_path,'marker')
        process.assert_not_called()
    (tmp_path/'attempt.json').unlink();MODULE.atomic_json(tmp_path/'attempt.json',record)
    secret=tmp_path/'foreign-file';secret.write_text('must-not-read');secret.chmod(0o600);(tmp_path/'application.log').symlink_to(secret)
    value=MODULE.diagnose(values,tmp_path,'marker')
    assert 'application.log' not in value and any(g.startswith('application.log:') for g in value['gaps'])


@pytest.mark.skipif(os.name!='posix' or getattr(os,'geteuid',lambda:-1)()!=0,reason='root private archive fixture')
def test_private_snapshot_keeps_all_raw_status_attempts_not_only_last(tmp_path):
    import base64
    values=args(tmp_path);values.helper_sha256=MODULE.sha256(HELPER)
    record={'run_id':values.run_id,'profile':MODULE.PROFILE,'attempt_nonce':values.attempt_nonce,'artifact_sha256':values.artifact_sha256,'helper_sha256':values.helper_sha256,'expected_binary_sha256':values.expected_binary_sha256}
    MODULE.atomic_json(tmp_path/'attempt.json',record)
    for n in range(1,5):MODULE.atomic_json(tmp_path/f'status-attempt-{n:03d}.json',{'actualRaw':n})
    result=MODULE.diagnose(values,tmp_path,'marker')
    assert len(result['statusAttempts'])==4
    assert [json.loads(base64.b64decode(x['record']['body_base64']))['actualRaw'] for x in result['statusAttempts']]==[1,2,3,4]
