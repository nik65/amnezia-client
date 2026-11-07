import importlib.util
import json
import os
import time
from pathlib import Path
from unittest.mock import patch
import pytest

PATH=Path(__file__).parent/'guest_helpers/linux_gui_window_evidence.py'
spec=importlib.util.spec_from_file_location('staged_crash_helper',PATH)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

def binding():
    now=time.time_ns()//1000
    return {'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'pid':1234,'start_ticks':1001,'clock_ticks':100,'uid':1000,'exe':str(m.BINARY),
            'installed_binary_sha256':'a'*64,'launch_realtime_us':now-1_000_000,
            'launch_monotonic_us':10_000_000}

def record(b,kind):
    r={'_BOOT_ID':b['boot_id'].replace('-',''),'__MONOTONIC_TIMESTAMP':'11000000',
       '__REALTIME_TIMESTAMP':str(b['launch_realtime_us']+1000),'MESSAGE':'actual recorded stack'}
    if kind=='user':r.update(_PID=str(b['pid']),_UID='1000',_EXE=b['exe'])
    if kind=='coredump':r.update(COREDUMP_PID=str(b['pid']),COREDUMP_UID='1000',COREDUMP_EXE=b['exe'],COREDUMP_TIMESTAMP=str(b['launch_realtime_us']+500),COREDUMP_STACKTRACE='already recorded frames')
    if kind=='kernel':r['MESSAGE']='amnezia[1234]: segfault at actual instruction'
    return r

def response(*items):
    return {'exitcode':0,'timeout':False,'overflow':False,'stdout':b'\n'.join(json.dumps(i).encode() for i in items),'stderr':b''}

def test_actual_shape_fault_records_remain_bound_and_no_core_or_debugger():
    b=binding();calls=[]
    def cmd(argv,timeout,**kw):
        calls.append((argv,timeout,kw))
        return response(record(b,'user' if len(calls)==1 else 'kernel' if len(calls)==2 else 'coredump'))
    with patch.object(m,'status_attempt',side_effect=cmd):r=m.fault_records(b,time.monotonic()+10)
    assert r['gaps']==[] and r['coreTransferAttempted'] is False and r['debuggerInvoked'] is False
    assert r['queries']['coredump']['records'][0]['COREDUMP_STACKTRACE']=='already recorded frames'
    assert r['queries']['kernel']['records'][0]['attribution']=='kernel-message-PID-correlation-only'
    assert all(c[0][0]=='journalctl' and c[1]<=2 and c[2]['max_bytes']==32768 for c in calls)
    assert all('--boot='+b['boot_id'].replace('-','') in c[0] for c in calls)

@pytest.mark.parametrize('key,value',[('boot_id','0'*32),('pid',0),('uid',0),('exe','/foreign'),('launch_realtime_us',0),('start_ticks',0),('clock_ticks',0)])
def test_historical_binding_refusal_before_any_query(key,value):
    b={**binding(),key:value}
    with patch.object(m,'status_attempt') as cmd:
        with pytest.raises(m.EvidenceError):m.fault_records(b,time.monotonic()+10)
        cmd.assert_not_called()

@pytest.mark.parametrize('field,value',[('_BOOT_ID','0'*32),('_PID','999'),('_UID','0'),('_EXE','/foreign'),('__MONOTONIC_TIMESTAMP','1'),('__REALTIME_TIMESTAMP','1')])
def test_foreign_user_metadata_is_never_accepted(field,value):
    b=binding();item={**record(b,'user'),field:value}
    with patch.object(m,'status_attempt',side_effect=[response(item),response(),response()]):r=m.fault_records(b,time.monotonic()+10)
    assert 'user' not in r['queries'] and 'user:EvidenceError' in r['gaps']

@pytest.mark.parametrize('field,value',[('COREDUMP_PID','1'),('COREDUMP_UID','0'),('COREDUMP_EXE','/foreign'),('COREDUMP_TIMESTAMP','1')])
def test_foreign_coredump_metadata_is_never_accepted(field,value):
    b=binding();item={**record(b,'coredump'),field:value}
    with patch.object(m,'status_attempt',side_effect=[response(),response(),response(item)]):r=m.fault_records(b,time.monotonic()+10)
    assert 'coredump' not in r['queries'] and 'coredump:EvidenceError' in r['gaps']

def test_budget_missing_tool_and_truncated_output_explicit_not_pass():
    b=binding()
    raw={**response(),'overflow':True,'stdout':b'x'*32768}
    with patch.object(m,'status_attempt',side_effect=[FileNotFoundError(),raw,response()]):r=m.fault_records(b,time.monotonic()+10)
    assert 'user:FileNotFoundError' in r['gaps'] and 'kernel:command-incomplete' in r['gaps']
    assert r['queries']['kernel']['records']==[]
    with patch.object(m,'status_attempt') as cmd:r=m.fault_records(b,time.monotonic()-.1)
    cmd.assert_not_called();assert len(r['gaps'])==3

def test_kernel_unrelated_pid_not_attributed():
    b=binding();k={**record(b,'kernel'),'MESSAGE':'foreign[12345]: fault'}
    with patch.object(m,'status_attempt',side_effect=[response(),response(k),response()]):r=m.fault_records(b,time.monotonic()+10)
    assert r['queries']['kernel']['records']==[]

def test_default_renderer_unchanged_and_policy_bound_exact_fixture():
    with patch.object(m,'private_bytes') as read,patch.object(m,'command') as cmd:
        assert m.renderer_arguments('default',time.monotonic()+10)==[]
        read.assert_not_called();cmd.assert_not_called()
    import base64
    proof={'body_base64':base64.b64encode(b'[Service]\nEnvironment=GALLIUM_DRIVER=softpipe\n').decode()}
    with patch.object(m,'private_bytes',return_value=proof),patch.object(m,'command',return_value='GALLIUM_DRIVER=softpipe'):
        assert m.renderer_arguments('softpipe',time.monotonic()+10)==['GALLIUM_DRIVER=softpipe']
    with patch.object(m,'private_bytes',return_value={'body_base64':base64.b64encode(b'foreign').decode()}),patch.object(m,'command') as cmd:
        with pytest.raises(m.EvidenceError):m.renderer_arguments('softpipe',time.monotonic()+10)
        cmd.assert_not_called()

def test_status_receives_same_narrow_renderer_policy(tmp_path):
    identity={'pid':42,'start_ticks':123};session={'display':':0','xauthority':'/run/test'};window={}
    raw=response({'schema':'amnezia.operator.status.v1','version':'5.0.3.14','pid':42,'applicationRunning':True})
    with patch.object(m,'same_process',return_value=True),patch.object(m,'mapped_windows',return_value=[window]),patch.object(m,'status_attempt',return_value=raw) as cmd:
        assert m.running_version(session,'5.0.3.14',identity,window,time.monotonic()+10,tmp_path,['GALLIUM_DRIVER=softpipe'])=='5.0.3.14'
    assert cmd.call_args.args[0][-4:]==['GALLIUM_DRIVER=softpipe',str(m.BINARY),'--json','--status']

@pytest.mark.skipif(os.name!='posix',reason='real process safe-environment snapshot')
def test_actual_safe_renderer_environment_before_death_retains_no_secrets():
    import subprocess
    child=subprocess.Popen(['/usr/bin/sleep','5'],env={'GALLIUM_DRIVER':'softpipe','SECRET_TOKEN':'never-archive'})
    try:
        identity=m.proc_identity(child.pid);env=m.safe_process_environment(identity)
        assert env=={'GALLIUM_DRIVER':'softpipe'}
        maps=m.process_maps_snapshot(identity)
        import base64
        assert b'/usr/bin/sleep' in base64.b64decode(maps['body_base64'])
        assert maps['capturedSize']<=32768
        b=m.crash_binding(identity,{'realtime_us':time.time_ns()//1000,'monotonic_us':0})
        assert b['start_ticks']==identity['start_ticks'] and b['boot_id']==Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    finally:child.terminate();child.wait()


def test_death_during_maps_snapshot_does_not_return_stale_identity():
    identity=m.proc_identity(os.getpid())
    with patch.object(m,'same_process',side_effect=[True,True,False]):
        with pytest.raises(m.EvidenceError,match='during maps'):m.process_maps_snapshot(identity)


@pytest.mark.parametrize('env_failure',[False,True])
def test_actual_launch_progress_is_durable_before_status_even_if_environment_dies(tmp_path,env_failure):
    from types import SimpleNamespace
    import base64
    binary=tmp_path/'AmneziaVPN';binary.write_bytes(b'inert')
    args=SimpleNamespace(timeout=60,dwell=0,renderer_policy='softpipe',run_id='test-run',attempt_nonce='a'*48,expected_binary_sha256='a'*64,helper_sha256='c'*64,artifact_sha256='b'*64,expected_version='5.0.3.14')
    identity={'pid':42,'start_ticks':100,'uid':1000,'exe':str(binary),'installed_binary_sha256':'a'*64}
    session={'uid':1000,'display':':0','xauthority':'/owned/Xauthority'};window={'id':'0x1'}
    primary=m.EvidenceError('actual status failure')
    def status(*argv):
        progress=json.loads((tmp_path/'launch-progress.json').read_bytes())
        assert progress['process']==identity and progress['crash_binding']['pid']==42
        assert progress['mappedLibraries']['body_base64']==base64.b64encode(b'actual maps').decode()
        assert ('safeEnvironmentGap' in progress)==env_failure
        if not env_failure:assert progress['safeEnvironment']=={'GALLIUM_DRIVER':'softpipe'}
        assert argv[-1]==['GALLIUM_DRIVER=softpipe']
        raise primary
    with patch.object(m,'require_unlocked_session',return_value={}),patch.object(m,'BINARY',binary),patch.object(m,'sha256',side_effect=['a'*64,'c'*64]),patch.object(m.os,'access',return_value=True),patch.object(m,'active_x11_session',return_value=session),patch.object(m,'exact_binary_pids',side_effect=[set(),{42}]),patch.object(m,'proc_identity',return_value=identity),patch.object(m,'mapped_windows',return_value=[window]),patch.object(m,'renderer_arguments',return_value=['GALLIUM_DRIVER=softpipe']),patch.object(m,'safe_process_environment',side_effect=OSError('gone') if env_failure else None,return_value={'GALLIUM_DRIVER':'softpipe'}),patch.object(m,'process_maps_snapshot',return_value={'body_base64':base64.b64encode(b'actual maps').decode()}),patch.object(m.subprocess,'Popen') as spawn,patch.object(m,'running_version',side_effect=status):
        with pytest.raises(m.EvidenceError) as caught:m.launch(args,tmp_path,'owned marker')
    assert caught.value is primary
    assert spawn.call_args.args[0][-2:]==['GALLIUM_DRIVER=softpipe',str(binary)]


def test_fault_queries_share_original_deadline_not_per_query_budget():
    b=binding();clock={'now':0};calls=[]
    def command(argv,timeout,**kwargs):
        calls.append(timeout);clock['now']+=timeout;return response()
    with patch.object(m.time,'monotonic',side_effect=lambda:clock['now']),patch.object(m,'status_attempt',side_effect=command):r=m.fault_records(b,2)
    assert calls==[2] and clock['now']==2
    assert r['gaps']==['kernel:diagnostic-budget','coredump:diagnostic-budget']


def test_worst_case_all_channels_keep_primary_binding_and_explicit_omissions():
    import base64,hashlib
    def private(n):
        raw=b'x'*n
        return {'body_base64':base64.b64encode(raw).decode(),'size':n,'capturedSize':n,'sha256':hashlib.sha256(raw).hexdigest(),'truncated':False}
    process={'pid':1234,'start_ticks':1001,'uid':1000,'exe':str(m.BINARY)};b=binding()
    result={'schema':m.SCHEMA,'diagnosticOnly':True,'attempt':{'run_id':'own','attempt_nonce':'a'*48},'historicalProcess':process,'crashBinding':b,'gaps':[],
            'application.log':private(65536),'launch-progress.json':private(65536),
            'faultRecords':{'binding':b,'gaps':[],'queries':{'actual':{'MESSAGE':'x'*100000}}},
            'statusAttempts':[{'name':f'status-attempt-{i}.json','record':private(60000)} for i in range(4)],
            'maps':private(32768),'stack':private(8192),'cmdline':private(8192),'status':private(8192),'threads':[{'wchan':'x'*256} for _ in range(32)]}
    out=m.bounded_diagnostic_result(result)
    assert len(json.dumps(out).encode())<=512000
    assert out['historicalProcess']==process and out['crashBinding']==b and out['attempt']['run_id']=='own'
    assert base64.b64decode(out['application.log']['body_base64'])==b'x'*65536
    assert base64.b64decode(out['launch-progress.json']['body_base64'])==b'x'*65536
    assert out['faultRecords']['omitted'] is True and out['gaps']
    assert any(a['record'].get('bodyOmitted') for a in out['statusAttempts'])
