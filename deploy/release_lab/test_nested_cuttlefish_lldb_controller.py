import base64,hashlib,json,os,subprocess,sys,time,uuid
from types import SimpleNamespace
import pytest

from deploy.release_lab.lab import LabController,LabError
from deploy.release_lab.nested_cuttlefish_lldb import BUNDLE_ARCHIVE_NAME,BUNDLE_ARCHIVE_SHA256,BUNDLE_ARCHIVE_SIZE,BUNDLE_MANIFEST_SHA256,BUNDLE_MEMBERS
from deploy.release_lab.nested_cuttlefish_lldb_controller import LldbDiagnosticBundle,NestedAndroidLldbController,RUN_DRIVER
from deploy.release_lab.nested_cuttlefish_runner import ApkSpec,AssetSpec,InnerPlan,OuterOwnership

def make_plan():
 owner=OuterOwnership('release39','linux-headless-x64','a'*48,200,300,'12345678-1234-1234-1234-123456789abc','/var/lib/amnezia-release-lab/qmp','/var/lib/amnezia-release-lab/qga')
 token=hashlib.sha256(f'{owner.run_id}\0{owner.attempt_nonce}'.encode()).hexdigest()[:8];root=f'/var/lib/amnezia-release-lab/n/{token}'
 argv=(f'{root}/runtime/host/bin/launch_cvd',f'-instance_dir={root}/runtime/instance',f'-assembly_dir={root}/runtime/assembly',f'-system_image_dir={root}/runtime/images',f'-early_tmp_dir={root}/runtime/tmp','-vm_manager=qemu_cli','-device_external_network=slirp','-enable_tap_devices=false','-enable_modem_simulator=true','-start_gnss_proxy=false','-enable_host_bluetooth=false','-enable_host_nfc=false','-enable_host_uwb=false','-start_webrtc=false','-report_anonymous_usage_stats=n','-gpu_mode=guest_swiftshader','-adb_mode=vsock_half_tunnel','-run_adb_connector=true','-cpus=2','-memory_mb=4096','-vsock_guest_cid=37',f'-qemu_binary_dir={root}/runtime/qemu','-noresume')
 assets=(AssetSpec('h.tar.gz','/h',1,'1'*64),AssetSpec('i.zip','/i',1,'2'*64),AssetSpec('q.tar.gz','/q',1,'3'*64));apk=ApkSpec('c.apk','/c',2,'4'*64,'org.amnezia.vpn',39)
 return InnerPlan(owner,assets,apk,37,1000,launch_argv=argv,qemu_aarch64_sha256='5'*64)

def sb(pid=111,uid=10123,ticks=222):
 states=[{'state':x,'at_monotonic':float(i),**({'lldb_pid':pid} if x=='ATTACHED_STOPPED' else {})} for i,x in enumerate(('ATTACHED_STOPPED','POLICY_CONFIRMED','RUNNING','STOPPED_SIGSEGV','EVIDENCE_CAPTURED','CONTINUE_WITH_SIGNAL_PASS','EXITED_AFTER_PASS'))]
 return {'schema':1,'acceptance':False,'classification':'native-sigsegv','signal_claim':True,'stack_claim':True,'states':states,'identity':{'run_id':'release39','attempt_nonce':'a'*48,'package':'org.amnezia.vpn','pid':pid,'uid':uid,'start_ticks':ticks},'signal_policy':{'stop':True,'notify':True,'pass':True},'lldb_file':'/var/lib/amnezia-release-lab/n/dad5dd7f/runtime/diagnostics/lib/python3.10/site-packages/lldb/__init__.py','threads':[{'thread_id':7,'frames':[{'pc':4096}]}],'exit_status':11,'exit_description':'signal 11'}

def controller(events,archive_ok=True,timed_out=False):
 p=make_plan();asset=AssetSpec(BUNDLE_ARCHIVE_NAME,'/lldb',BUNDLE_ARCHIVE_SIZE,BUNDLE_ARCHIVE_SHA256);bundle=LldbDiagnosticBundle(asset,BUNDLE_MANIFEST_SHA256,BUNDLE_MEMBERS)
 bridge=SimpleNamespace(plan=p,qga=None)
 bridge.stage_additional_asset=lambda spec:{'guest_path':p.root+'/input/'+spec.name,'sha256':spec.sha256,'size':spec.size}
 def exec_json(path,args,timeout):
  if args[1].startswith('import hashlib,json,os,pathlib,stat'):return {'archive_sha256':asset.sha256,'archive_size':asset.size,'manifest_sha256':bundle.manifest_sha256,'member_count':bundle.manifest_members}
  driver=args[-1];return {'path':args[-2],'sha256':hashlib.sha256(driver.encode()).hexdigest(),'size':len(driver.encode())}
 bridge._exec_json=exec_json
 c=object.__new__(NestedAndroidLldbController);c.bridge=bridge;c.qga=None;c.plan=p;c.boot={};c.bundle=bundle;c.snapshot=lambda:p.ownership
 c.archive=lambda record:(events.append('archive') or ({'origin':'controller','immutable':True,'path':'x','sha256':'8'*64,'size':1} if archive_ok else {}))
 death=b'Fatal signal 11 (SIGSEGV), code 1, fault addr 0x0 in tid 111, pid 111 (org.amnezia.vpn)\nProcess org.amnezia.vpn (pid 111) has died\n';raw={'bytes_b64':base64.b64encode(death).decode()}
 c.diagnostic_deadline=None;c.capability_rows=[];c._record_capability=False
 c.native_collect=lambda *args:(events.append('collector') or {'schema':2,'expected_pid':111,'launch_epoch':'1726185600.000','sources':[{'label':'crash','output':raw},{'label':'all-since-launch','output':raw}]});c.adb='adb';c.serial='127.0.0.1:6520';c.server_pid=None;c.server_ticks=None;c.marker=None;c.marker_sha=None;c.forward=None;c.tracee=None;c.rooted=False;c.initial=None
 c._capability=lambda:{'supported':True}
 c._adb=lambda args,*a,**k:{'stdout':'127.0.0.1:6520 tcp:44691 tcp:44690\n'} if args==['forward','--list'] else {}
 c._identity=lambda:(111,10123,222)
 values=iter(('c1c0849dc507689428e127905e9fddcb220f6925b238bfb26e012cbad893b950  /data/local/tmp/server','4321','333'));c._shell=lambda *a,**k:next(values)
 payload=json.dumps(sb(),separators=(',',':')).encode();out=b'AMZ_LLDB_JSON:'+payload+b'\n';wrapper={'exit_code':124 if timed_out else 0,'timed_out':timed_out,'size':len(out),'sha256':hashlib.sha256(out).hexdigest(),'bytes_b64':base64.b64encode(out).decode()}
 c.observed_outer=[];c.cleanup_deadlines=[]
 c._outer=lambda *a,**k:(c.observed_outer.append((a,k)) or {'stdout':json.dumps(wrapper),'exitcode':0})
 c._cleanup=lambda deadline:(c.cleanup_deadlines.append(deadline) or events.append('cleanup') or {'deadline_seconds':60,'steps':[],'passed':True})
 return c

def test_diagnostic_archives_before_cleanup_and_only_fatal_calls_collector():
 events=[];c=controller(events);result=c.run(lambda:events.append('launch'),'1726185600.000')
 assert result['acceptance'] is False and events.index('archive')<events.index('cleanup')
 assert events.count('collector')==1 and result['native_crash']['expected_pid']==111

def test_timeout_never_calls_native_collector():
 events=[];result=controller(events,timed_out=True).run(lambda:None,'1726185600.000')
 assert result['sb']['classification']=='diagnostic-timeout' and 'collector' not in events

def test_delayed_child_timeout_receipt_keeps_transport_margin_and_same_cleanup_deadline(monkeypatch):
 monkeypatch.setattr('deploy.release_lab.nested_cuttlefish_lldb_controller.time.monotonic',lambda:100.0)
 events=[];c=controller(events,timed_out=True);result=c.run(lambda:None,'1726185600.000')
 args,kwargs=c.observed_outer[-1];child=float(args[1][-2]);outer=float(args[2])
 assert child==48.0 and outer==50.0 and outer-child==2.0
 assert c.cleanup_deadlines==[160.0] and result['sb']['classification']=='diagnostic-timeout'
 assert events.index('archive')<events.index('cleanup')

def test_actual_run_driver_returns_bounded_timeout_receipt_before_outer_margin():
 path=f'/tmp/amz-run-driver-{uuid.uuid4().hex}.log'
 runner=['wsl.exe','--','python3'] if os.name=='nt' else [sys.executable]
 child=['python3','-c','import time;time.sleep(2)']
 argv=[*runner,'-c',RUN_DRIVER,json.dumps(child),json.dumps({}),'2097152','0.2',path]
 started=time.monotonic()
 try:
  completed=subprocess.run(argv,capture_output=True,text=True,timeout=3,check=False)
 finally:
  cleanup=[*runner,'-c','import pathlib,sys;pathlib.Path(sys.argv[1]).unlink(missing_ok=True)',path]
  subprocess.run(cleanup,capture_output=True,timeout=3,check=False)
 elapsed=time.monotonic()-started
 assert completed.returncode==0 and elapsed<3
 receipt=json.loads(completed.stdout)
 assert receipt=={'exit_code':124,'timed_out':True,'size':0,'sha256':hashlib.sha256(b'').hexdigest(),'bytes_b64':''}

class CapabilityQga:
 def __init__(self,payload):self.payload=payload;self.calls=[]
 def guest_exec(self,path,args):self.calls.append(('exec',path,list(args)));return {'pid':77}
 def request(self,name,args):self.calls.append((name,dict(args)));return {'return':self.payload}

def raw_controller(payload):
 c=object.__new__(NestedAndroidLldbController);c.plan=make_plan();c.qga=CapabilityQga(payload);c.snapshot=lambda:c.plan.ownership;c.diagnostic_deadline=None;c.capability_rows=[];c._record_capability=True
 return c

def test_actual_failing_capability_command_retains_exact_bounded_receipt_without_launch_attach():
 out=b'unsupported\n';err=b'permission denied\n';c=raw_controller({'exited':True,'exitcode':23,'out-data':base64.b64encode(out).decode(),'err-data':base64.b64encode(err).decode()})
 row=c._outer_result('capability-probe','/bin/probe',['--exact','value'],2)
 assert row['argv']==['/bin/probe','--exact','value'] and row['rc']==23 and row['timed_out'] is False
 assert base64.b64decode(row['stdout']['prefix_b64'])==out and row['stdout']['prefix_sha256']==hashlib.sha256(out).hexdigest()
 assert base64.b64decode(row['stderr']['prefix_b64'])==err and row['stderr']['prefix_sha256']==hashlib.sha256(err).hexdigest()
 assert c.capability_rows==[row] and [x[0] for x in c.qga.calls]==['exec','guest-exec-status']

@pytest.mark.parametrize('payload,match',[
 ({'exited':True,'exitcode':True},'exit code malformed'),
 ({'exited':True,'exitcode':1,'out-data':'not base64'},'base64 malformed'),
 ({'exited':True,'exitcode':1,'out-data':base64.b64encode(b'x'*65537).decode()},'oversized'),
])
def test_capability_command_rejects_bool_malformed_and_oversize(payload,match):
 c=raw_controller(payload)
 with pytest.raises(Exception,match=match):c._outer_result('negative','/bin/probe',[],2)
 assert len(c.capability_rows)==1 and c.capability_rows[0]['argv']==['/bin/probe']

def test_missing_controller_ack_retains_owned_guest_without_cleanup():
 events=[]
 with pytest.raises(Exception) as caught:controller(events,archive_ok=False).run(lambda:None,'1726185600.000')
 assert getattr(caught.value,'retain_owned_evidence',False) is True and 'cleanup' not in events

def test_run_archives_partial_capability_failure_before_any_launch_or_attach():
 events=[];c=controller(events);partial={'label':'pre-root','argv':['adb','shell','id','-u'],'pid':77,'rc':23,'timed_out':False,'classification':'nonzero'};captured=[]
 c.capability_rows=[partial];c._capability=lambda:(_ for _ in ()).throw(RuntimeError('capability denied'));c.archive=lambda record:(captured.append(record) or {'origin':'controller','immutable':True,'path':'x','sha256':'8'*64,'size':1})
 with pytest.raises(RuntimeError,match='capability denied'):c.run(lambda:events.append('launch'),'1726185600.000')
 assert captured[0]['capability']['rows']==[partial] and 'launch' not in events and c.server_pid is None and c.rooted is False

def test_source_requires_root_domain_selinux_forward_and_acceptance_false_without_jdwp_wait():
 source=__import__('inspect').getsource(NestedAndroidLldbController)
 for token in ("u:r:su:s0","getenforce","forward","--remove","acceptance':False"):
  assert token in source
 assert 'set-debug-app' not in source and 'clear-debug-app' not in source and "'-w'" not in source

def test_controller_archive_is_acceptance_false_and_immutable(tmp_path):
 c=LabController(tmp_path,test_mode=True);run='release39';nonce='a'*48;vm={'pid':200,'proc_start_time':'300','uuid':'12345678-1234-1234-1234-123456789abc','qmp_socket':'/var/lib/amnezia-release-lab/qmp','qga_socket':'/var/lib/amnezia-release-lab/qga'}
 c.save_state({'schema':1,'lab_id':'x','runs':{run:{'run_id':run,'profiles':{'linux-headless-x64':{'vm':vm}}}}});c.acquire_mutation_lock('test')
 outer={'run_id':run,'profile':'linux-headless-x64','attempt_nonce':nonce,'pid':200,'start_ticks':300,'uuid':vm['uuid'],'qmp_socket':vm['qmp_socket'],'qga_socket':vm['qga_socket']}
 record={'schema':1,'operation':'nested-android-lldb-diagnostic','acceptance':False,'run_id':run,'attempt_nonce':nonce,'outer_ownership':outer}
 ack=c.archive_nested_lldb_diagnostic(run,record)
 assert ack['origin']=='controller' and ack['immutable'] is True and ack['size']>0
 bad=dict(record);bad['acceptance']=True
 with pytest.raises(LabError,match='identity'):c.archive_nested_lldb_diagnostic(run,bad)
