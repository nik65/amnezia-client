"""Inert contracts only: no alias, service, guest or full control program runs."""
import ast,base64,copy,hashlib,json,os,pathlib,sys,time
from dataclasses import replace
from types import SimpleNamespace as NS
import pytest
from . import headless_coordinated_http_fixture as m
from .test_headless_native_acceptance import plan as original_plan,http

def plan():
 p=original_plan();endpoint=m.derive_endpoint(p.attempt_nonce);address=endpoint.split('//')[1].split(':')[0]
 return replace(p,fixture=replace(p.fixture,endpoint=endpoint,forward_routes=(address+'/32',)))

def test_endpoint_is_stable_private_nonloopback_and_nonce_bound():
 import ipaddress
 first=m.derive_endpoint('a'*48);second=m.derive_endpoint('b'*48);assert first==m.endpoint_for_nonce('a'*48);assert first!=second
 address=ipaddress.ip_address(first.split('//')[1].split(':')[0]);assert address.is_private and not address.is_loopback;assert first.endswith(':17866')
 for value in ['../outside','x',None,'a'*97]:
  with pytest.raises(m.CoordinatedHttpError):m.derive_endpoint(value)


def test_generated_programs_compile_and_unit_has_ordering_without_product_dropin():
 compile(m.wrapper_source(),'wrapper','exec');compile(m.control_source(),'control','exec')
 # Execute only function declarations with ordinary inert Python objects.
 tree=ast.parse(m.COMMON);scope={'pathlib':NS(Path=pathlib.PurePosixPath),'hashlib':hashlib,'re':__import__('re'),'json':json}
 exec(compile(ast.Module(body=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in ('config_paths','unit_bytes','blob')],type_ignores=[]),'unit-functions','exec'),scope)
 p=plan();cfg={'attempt_nonce':p.attempt_nonce,'endpoint':p.fixture.endpoint,'profile':'linux-headless-x64'};unit=scope['unit_bytes'](cfg)
 assert b'Before=amneziad.service' in unit.splitlines();assert b'Type=notify' in unit.splitlines();assert b'WantedBy=multi-user.target' in unit.splitlines();assert b'DropIn' not in unit;assert bytes([92,110]) not in unit
 assert m.unit_source(p.attempt_nonce)==unit
 assert scope['blob']({'x':1})==b'{"x":1}'+bytes([10])


def make(tmp_path,denied=False):
 p=plan();calls=[];responses=[]
 def check():
  calls.append('check')
  if denied:raise RuntimeError('ownership denied')
 def json_call(exe,args,timeout):
  assert exe=='/usr/bin/python3';calls.append(('guest',args[1],timeout))
  if args[1]==m.control_source():
   cfg=json.loads(args[2]);action=args[3];assert cfg['endpoint']==p.fixture.endpoint
   return {'action':action,'original':'private bytes'}
  return {'path':'/etc/amnezia/update-public-key.pem','sha256':p.candidate.key_sha256,'size':100,'uid':0,'gid':1000,'amnezia_gid':1000,'mode':416,'protected_ancestors':True,'regular':True,'same_fd_identity':True}
 native=NS(plan=p,_check=check,_exec=lambda *a: {'stdout':json.dumps(json_call(*a)),'stderr':'','exitcode':0})
 f=m.CoordinatedHeadlessHttpFixture(native,p,'/var/lib/amnezia-release-lab/fixture/manifest','/var/lib/amnezia-release-lab/fixture/artifact',archive_root=tmp_path/'archive')
 return f,calls

def test_inert_constructor_owned_calls_and_private_prevalidation(tmp_path):
 f,calls=make(tmp_path);assert calls==[]
 value=f.install();assert value['action']=='install';assert calls[0]=='check' and calls[-1]=='check'
 path=next((tmp_path/'archive').iterdir());record=json.loads(path.read_text());raw=base64.b64decode(record['bytes_base64']);assert json.loads(json.loads(raw)['stdout'])==value;assert record['sha256']==hashlib.sha256(raw).hexdigest()
 assert not record['truncated']
 if os.name=='posix':assert path.stat().st_mode&0o777==0o600

def test_ownership_denial_zero_guest_dispatch_and_no_archive(tmp_path):
 f,calls=make(tmp_path,True)
 with pytest.raises(RuntimeError,match='ownership'):f.install()
 assert calls==['check'];assert not (tmp_path/'archive').exists()


def test_existing_native_strict_http_validator_is_used_on_initial_epoch(tmp_path):
 f,_=make(tmp_path);p=f.plan;old=http();rows=[]
 for item in old['requests']:
  row=dict(item);row['observed_at']=__import__('datetime').datetime.fromisoformat(row['observed_at'].replace('Z','+00:00')).timestamp();rows.append(row)
 transcript={'rows':rows};f.ledger=lambda:{'epochs':[{'pid':40,'start_ticks':400,'transcript':transcript}]};f.trust={}
 result=f.collect();assert result['fixture']['listener']==p.fixture.endpoint;assert result['requests'][0]['path']==p.fixture.manifest_path
 rows[1]['sha256']='0'*64
 with pytest.raises(Exception):f.collect()

@pytest.mark.skipif(os.name!='posix',reason='actual bounded helper functions use POSIX pipes')
def test_actual_common_command_bounds_and_owned_child_timeout():
 scope={};exec(m.COMMON,scope)
 for argv in ([sys.executable,'-c','import os;os.write(1,b"x"*2000000)'],[sys.executable,'-c','import time;time.sleep(5)']):
  before=time.monotonic()
  with pytest.raises(RuntimeError):scope['command'](argv,.3)
  assert time.monotonic()-before<2

def test_core_boot_epoch_contract_does_not_reuse_server_main_or_old_log():
 # AST confirms the wrapper invokes unchanged H directly, never main/truncate.
 tree=ast.parse(m.WRAPPER_BODY);attrs=[n.func.attr for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute)]
 assert 'main' not in attrs;assert 'artifact_path' in attrs;assert 'ThreadingHTTPServer' in attrs
 assert m.WRAPPER_BODY.index("write_new(directory/'ready.json'")<m.WRAPPER_BODY.index("sock.sendall(b'READY=1')")
 assert "Before=amneziad.service" in m.COMMON;assert '/amneziad.service.d' not in m.COMMON
 assert "if any(a.get('local')==address for a in addresses()):raise" in m.COMMON
 assert "'preexisting':False" in m.COMMON
 assert "proofs[0].get('preexisting') is not False" in m.COMMON
 assert "address+'/32','dev','lo'" in m.COMMON


def common_functions():
 tree=ast.parse(m.COMMON);scope={'base64':base64,'hashlib':hashlib,'json':json,'os':os,'pathlib':pathlib,'re':__import__('re'),'stat':__import__('stat'),'time':time,'MAX':1048576}
 exec(compile(ast.Module(body=[n for n in tree.body if isinstance(n,ast.FunctionDef)],type_ignores=[]),'common-functions','exec'),scope);return scope

def test_alias_collision_refused_before_any_command_or_write(tmp_path):
 scope=common_functions();root=tmp_path;boot='11111111-1111-1111-1111-111111111111';identity={'boot_id':boot,'pid':77,'start_ticks':88};directory=root/'epochs'/(boot+'-77-88');cfg={'run_id':'run','attempt_nonce':'a'*48};calls=[]
 scope['config_paths']=lambda cfg:(root,'unit','10.254.1.2');scope['addresses']=lambda:[{'local':'10.254.1.2','prefixlen':32,'ifname':'lo'}];scope['command']=lambda *a:calls.append(a);scope['write_new']=lambda *a:calls.append(a)
 with pytest.raises(RuntimeError,match='already present'):scope['create_alias'](cfg,directory,identity)
 assert calls==[]

@pytest.mark.skipif(os.name!='posix' or getattr(os,'geteuid',lambda:1)()!=0,reason='protected root-owned temporary POSIX proof fixtures')
@pytest.mark.parametrize('fault',[None,'foreign','wrong-run','old-boot'])
def test_actual_owned_alias_proof_cleanup_only_own_mocked_address(fault):
 import tempfile
 with tempfile.TemporaryDirectory(prefix='coordinated-http-proof-',dir='/root') as temporary:
  root=pathlib.Path(temporary);(root/'epochs').mkdir(mode=0o700);boot='11111111-1111-1111-1111-111111111111';identity={'boot_id':boot,'pid':77,'start_ticks':88};directory=root/'epochs'/(boot+'-77-88');directory.mkdir(mode=0o700);cfg={'run_id':'run','attempt_nonce':'a'*48};aliases=[{'local':'10.99.1.1','prefixlen':24,'ifname':'eth0'}];commands=[];scope=common_functions();scope['config_paths']=lambda cfg:(root,'unit','10.254.1.2');scope['boot_id']=lambda:boot;scope['addresses']=lambda:list(aliases)
  def command(argv,*args):
   assert argv[:3] in (['/usr/sbin/ip','address','add'],['/usr/sbin/ip','address','del']);commands.append(argv)
   if argv[2]=='add':aliases.append({'local':'10.254.1.2','prefixlen':32,'ifname':'lo'})
   else:aliases[:]=[a for a in aliases if a['local']!='10.254.1.2']
  scope['command']=command
  if fault=='foreign':aliases.append({'local':'10.254.1.2','prefixlen':32,'ifname':'lo'})
  else:scope['create_alias'](cfg,directory,identity)
  if fault in ('wrong-run','old-boot'):
   proof=directory/'alias-owned.json';data=json.loads(proof.read_text());data['run_id' if fault=='wrong-run' else 'boot_id']='foreign';proof.write_text(json.dumps(data))
  before=len(commands)
  if fault:
   with pytest.raises(RuntimeError):scope['remove_alias'](cfg)
   assert len(commands)==before;assert any(a['local']=='10.254.1.2' for a in aliases)
  else:
   scope['remove_alias'](cfg);assert aliases==[{'local':'10.99.1.1','prefixlen':24,'ifname':'eth0'}];assert [c[2] for c in commands]==['add','del'];assert (directory/'alias-owned.json').exists()


def test_actual_daemon_readiness_observation_binds_raw_timestamps_and_pid():
 scope=common_functions();raw=b'MainPID=77\nActiveState=active\nSubState=running\nExecMainStartTimestampMonotonic=200\nActiveEnterTimestampMonotonic=250\nDropInPaths=\n'
 identity={'pid':77,'start_ticks':999,'boot_id':'11111111-1111-1111-1111-111111111111'};scope['command']=lambda *a:raw;scope['process_identity']=lambda pid:dict(identity)
 result=scope['daemon_snapshot'](100);assert result['pid']==77;assert result['properties']['ExecMainStartTimestampMonotonic']=='200';assert base64.b64decode(result['systemctl_bytes_base64'])==raw;assert result['systemctl_sha256']==hashlib.sha256(raw).hexdigest()
 assert scope['daemon_snapshot'](300) is None
 calls=[0]
 def changed(pid):calls[0]+=1;return {**identity,'start_ticks':calls[0]}
 scope['process_identity']=changed
 with pytest.raises(RuntimeError,match='identity changed'):scope['daemon_snapshot'](100)

@pytest.mark.skipif(os.name!='posix' or getattr(os,'geteuid',lambda:1)()!=0,reason='protected root-owned temporary evidence files')
def test_daemon_checkpoints_are_multiple_immutable_and_bind_actual_incarnation():
 import tempfile
 with tempfile.TemporaryDirectory(prefix='coordinated-daemon-proof-',dir='/root') as temporary:
  directory=pathlib.Path(temporary);scope=common_functions();boot='11111111-1111-1111-1111-111111111111';row={'boot_id':boot,'ready_monotonic_us':10};obs={'boot_id':boot,'pid':77,'start_ticks':99,'properties':{'MainPID':'77'},'systemctl_sha256':'a'*64,'observed_monotonic_us':100}
  scope['daemon_snapshot']=lambda ready:None;scope['record_daemon'](directory,row);assert list(directory.iterdir())==[]
  scope['daemon_snapshot']=lambda ready:dict(obs);scope['record_daemon'](directory,row);path=directory/'daemon-observation-77-99.json';original=path.read_bytes();obs['observed_monotonic_us']=200;scope['record_daemon'](directory,row);assert path.read_bytes()==original
  obs['pid']=88;obs['start_ticks']=100;obs['properties']={'MainPID':'88'};scope['record_daemon'](directory,row);assert len(list(directory.iterdir()))==2
  obs['properties']={'MainPID':'foreign'}
  with pytest.raises(RuntimeError,match='incarnation drift'):scope['record_daemon'](directory,row)
  obs['boot_id']='foreign'
  with pytest.raises(RuntimeError,match='boot changed'):scope['record_daemon'](directory,row)


def test_expected_source_pins_are_derived_independently_from_receipts(tmp_path):
 f,_=make(tmp_path);expected=m.expected_sources_for_plan(f.plan)
 assert f.expected_sources()==expected;assert expected['server_sha256']==hashlib.sha256(pathlib.Path(m.__file__).with_name('headless_native_fixture_server.py').read_bytes()).hexdigest();assert expected['wrapper_sha256']==hashlib.sha256(m.wrapper_source().encode()).hexdigest();assert expected['unit_sha256']==hashlib.sha256(m.unit_source(f.plan.attempt_nonce)).hexdigest()
 f.cfg['server_sha256']='0'*64;assert f.expected_sources()==expected


def test_cleanup_retains_exact_original_stdout_and_ownership_context(tmp_path):
 f,calls=make(tmp_path);raw={'schema':'amnezia-coordinated-http-cleanup-v1','stopped':True,'unit_removed':True,'alias_removed':True,'listener_closed':True,'unknown_survivors':[],'run_id':f.plan.run_id,'attempt_nonce':f.plan.attempt_nonce};stdout=json.dumps(raw,indent=2)+'\n'
 f.native._exec=lambda *a:{'stdout':stdout,'stderr':'','exitcode':0}
 result=f.cleanup();source=result['raw_sources']['fixture_cleanup'];assert base64.b64decode(source['bytes_b64'])==stdout.encode();assert source['size']==len(stdout.encode());assert source['sha256']==hashlib.sha256(stdout.encode()).hexdigest();assert source['exit_code']==0;assert source['path']=='coordinated-http:cleanup';assert result['fixture_cleanup']==raw;assert result['outer_binding']==__import__('dataclasses').asdict(f.plan.outer_binding)
