"""Independent mutation checks for the diagnostic fixture's original receipts.
No guest, process, socket, listener or adapter action is executed.
"""
import copy
from pathlib import Path
import pytest
from deploy.release_lab.windows_netstack_fixture_contract import validate_observed


def valid():
    binding = dict(run_id='review-run', case_id='outer-clean', vm_id='a32279c3-a500-4ed4-80ff-c3b72600e18c', nonce='a'*48, task_token='b'*48, parent_sha256='c'*64, artifact_sha256='d'*64, manifest_sha256='e'*64, helper_sha256='f'*64, routes_sha256='1'*64)
    common = {key: binding[key] for key in ('run_id','case_id','vm_id','nonce')}
    lease = dict(common, exe_sha256=binding['helper_sha256'], routes_sha256=binding['routes_sha256'], production_journal=False, runtime_pass=False, pid=231, process_start_unix_ns=1792260000000000000, source_udp_port=31001, target_udp_port=31002, ready=True)
    observation = dict(common, task_token=binding['task_token'], capability_observed=True, production_journal=False, migration_pass=False, runtime_pass=False, feed_sha256=binding['routes_sha256'], known_nonce_proved=True, gui_visible=True, route_shape='synthetic-windows-dataplane-v1', fixture_prefix_count=1266, native_before=dict(last_handshake_time_sec='1792260000',rx_bytes='10',tx_bytes='10'),native_after=dict(last_handshake_time_sec='1792260000',rx_bytes='20',tx_bytes='20'),before=dict(routes=['198.51.100.0/24'],**{name:dict(pid=100+i,start_ticks=1234567+i,exe='C:/owned/'+name+'.exe') for i,name in enumerate(('gui','service','tunnel'))}),after=dict(routes=['198.51.100.0/24'],**{name:dict(pid=100+i,start_ticks=1234567+i,exe='C:/owned/'+name+'.exe') for i,name in enumerate(('gui','service','tunnel'))}))
    result = dict(common, action='netstack-fixture', task_token=binding['task_token'], parent_sha256=binding['parent_sha256'], candidate_artifact_sha256=binding['artifact_sha256'], manifest_sha256=binding['manifest_sha256'], transport='hyperv-powershell-direct', origin='guest', injected=False, production_journal=False, migration_pass=False, runtime_pass=False, lease=lease, terminal=dict(lease, terminal_state='closed_by_owned_process'), observation=observation, cleanup={key:True for key in ('helper_process_absent','helper_udp_ports_absent','observer_task_removed','observer_process_absent')})
    return result,binding


@pytest.mark.parametrize('record', ['lease','terminal'])
@pytest.mark.parametrize('field,bad', [('run_id','old-run'),('case_id','outer-reinstall'),('vm_id','foreign'),('nonce','c'*48),('exe_sha256','0'*64),('routes_sha256','0'*64),('production_journal',True),('runtime_pass',True),('pid',True),('pid',0),('process_start_unix_ns',True),('process_start_unix_ns',0),('source_udp_port',True),('source_udp_port',0),('source_udp_port',65536),('target_udp_port',True),('target_udp_port',65536)])
def test_original_identity_mutations_rejected(record,field,bad):
    value,binding=valid()
    value[record][field]=bad
    with pytest.raises(ValueError):validate_observed(value,**binding)


@pytest.mark.parametrize('record', ['lease','terminal'])
def test_missing_originals_and_duplicate_ports_rejected(record):
    value,binding=valid()
    value.pop(record)
    with pytest.raises(ValueError):validate_observed(value,**binding)
    value,binding=valid()
    value[record]['target_udp_port']=value[record]['source_udp_port']
    with pytest.raises(ValueError):validate_observed(value,**binding)


@pytest.mark.parametrize('field', ['pid','process_start_unix_ns','source_udp_port','target_udp_port'])
def test_terminal_cannot_belong_to_different_process_or_port(field):
    value,binding=valid()
    value['terminal'][field]+=1
    with pytest.raises(ValueError):validate_observed(value,**binding)


@pytest.mark.parametrize('field,bad',[('migration_pass',True),('runtime_pass',True),('production_journal',True),('feed_sha256','0'*64),('task_token','stale'),('capability_observed',1)])
def test_observer_flags_and_feed_binding_rejected(field,bad):
    value,binding=valid()
    value['observation'][field]=bad
    with pytest.raises(ValueError):validate_observed(value,**binding)


def test_manifest_binding_and_no_input_rewrite():
    value,binding=valid()
    before=copy.deepcopy(value)
    assert validate_observed(value,**binding)==before
    assert value==before
    value['manifest_sha256']='0'*64
    with pytest.raises(ValueError):validate_observed(value,**binding)


@pytest.mark.parametrize('field,bad',[('known_nonce_proved',False),('gui_visible',False),('route_shape','logged-production-1263'),('fixture_prefix_count',1263),('fixture_prefix_count',True)])
def test_required_dataplane_shape_cannot_be_relabelled(field,bad):
    value,binding=valid()
    value['observation'][field]=bad
    with pytest.raises(ValueError):validate_observed(value,**binding)


@pytest.mark.parametrize('phase',['native_before','native_after'])
@pytest.mark.parametrize('field,bad',[('last_handshake_time_sec','0'),('last_handshake_time_sec',1),('rx_bytes','0'),('rx_bytes','-1'),('tx_bytes','1.5'),('tx_bytes','\u0661')])
def test_native_traffic_requires_positive_ascii_counters(phase,field,bad):
    value,binding=valid()
    value['observation'][phase][field]=bad
    with pytest.raises(ValueError):validate_observed(value,**binding)


@pytest.mark.parametrize('field',['rx_bytes','tx_bytes'])
def test_encrypted_counter_rollback_rejected(field):
    value,binding=valid()
    value['observation']['native_after'][field]='1'
    with pytest.raises(ValueError):validate_observed(value,**binding)


@pytest.mark.parametrize('process',['gui','service','tunnel'])
@pytest.mark.parametrize('field,bad',[('pid',True),('pid',0),('start_ticks',True),('start_ticks',0),('exe','')])
def test_equal_but_invalid_product_process_identity_rejected(process,field,bad):
    value,binding=valid()
    for phase in ('before','after'):value['observation'][phase][process][field]=bad
    with pytest.raises(ValueError):validate_observed(value,**binding)



def test_binding_keeps_source_bytes_and_uses_fresh_attempts(tmp_path):
    import hashlib,json
    from deploy.release_lab.windows_netstack_fixture_contract import FILES,bind_manifest
    sources=tmp_path/'sources';sources.mkdir()
    records={}
    for key,name in FILES.items():
        raw=json.dumps({'template':'unchanged'}).encode() if key in ('config','observer_plan') else (key+'-bytes').encode()
        path=sources/name;path.write_bytes(raw)
        records[key]=dict(path=str(path),size=len(raw),sha256=hashlib.sha256(raw).hexdigest())
    original={key:Path(record['path']).read_bytes() for key,record in records.items()}
    capsule=dict(schema=1,candidate_artifact_sha256='d'*64,installed_exe_sha256='c'*64,files=records)
    args=dict(run_id='review-run',case_id='outer-clean',vm_id='a32279c3-a500-4ed4-80ff-c3b72600e18c')
    first,sha,nonce,token=bind_manifest(capsule,tmp_path/'bound-a',**args)
    assert hashlib.sha256(first.read_bytes()).hexdigest()==sha
    bound=json.loads(first.read_bytes())
    config=json.loads(Path(bound['files']['config']['path']).read_bytes())
    plan=json.loads(Path(bound['files']['observer_plan']['path']).read_bytes())
    assert all(config[k]==v for k,v in args.items())
    assert config['nonce']==plan['nonce']==nonce and plan['task_token']==token
    assert config['routes_sha256']==records['routes']['sha256']
    assert plan['files']['routes.json']==records['routes']['sha256']
    assert all(Path(record['path']).read_bytes()==original[key] for key,record in records.items())
    _,_,next_nonce,next_token=bind_manifest(capsule,tmp_path/'bound-b',**args)
    assert nonce!=next_nonce and token!=next_token
    with pytest.raises(FileExistsError):bind_manifest(capsule,tmp_path/'bound-a',**args)

