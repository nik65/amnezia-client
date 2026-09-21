import base64,hashlib,json,subprocess,uuid
from pathlib import Path
import pytest
from deploy.release_lab.nested_cuttlefish_host_dependencies import *

def plan(tmp_path):
 p=tmp_path/'bundle';p.write_bytes(b'x')
 verifier=Path(__file__).resolve().parents[2]/VERIFIER_REL
 return HostDependencyPlan(run_id='run',profile='linux-headless-x64',attempt_nonce='a'*48,runtime_uid=1000,outer={'pid':2},bundle_path=str(p),verifier_path=str(verifier))
class Q:
 def __init__(self,p):self.p=p;self.calls=[]
 def guest_exec_wait(self,path,args,timeout):
  self.calls.append((path,args,timeout))
  if args[1]==OS_PREFLIGHT:return {'exitcode':0,'stdout':json.dumps({'id':'ubuntu','version_id':'24.04','codename':'noble','arch':'x86_64'})}
  if args[1]==MKROOT:return {'exitcode':0,'stdout':json.dumps({'dev':1,'inode':2,'uid':0,'gid':0,'mode':0o700,'marker_sha256':hashlib.sha256(('a'*48+'\n').encode()).hexdigest()})}
  if args[1]==GROUP_PROVISION:
   files=[{'path':p,'before_sha256':'1'*64,'after_sha256':'2'*64} for p in ('/etc/group','/etc/gshadow')];commands=[{'argv':['/usr/sbin/groupadd','--system','cvdnetwork'],'exe_sha256':'3'*64,'exit_code':0,'stdout_size':0,'stderr_size':0},{'argv':['/usr/sbin/usermod','-aG','cvdnetwork','lab'],'exe_sha256':'4'*64,'exit_code':0,'stdout_size':0,'stderr_size':0}]
   return {'exitcode':0,'stdout':json.dumps({'schema':1,'uid':1000,'user':'lab','primary_gid':1000,'cvdnetwork_gid':999,'created':True,'member':True,'files':files,'commands':commands,'origin':'guest','transport':'qga','injected':False,'kvm_modified':False,'vhost_modified':False})}
  if args[1]==GROUP_PREFLIGHT:return {'exitcode':0,'stdout':json.dumps({'ready':True,'uid':1000,'user':'lab','primary_gid':1000,'cvdnetwork_gid':999,'kvm_gid':993,'resolved_groups':[999,1000],'preserved_supplementary_groups':[993,999],'kvm_membership_modified':False,'vhost_device_modified':False,'vhost_vsock':{'path':'/dev/vhost-vsock','dev':7,'inode':8,'uid':0,'gid':993,'mode':'0660','rdev':9,'char':True},'vhost_access':{'exit_code':0,'result':{'egid':1000,'euid':1000,'groups':[993,999],'read':True,'write':True}}})}
  if args[1]==CLEANUP:return {'exitcode':0,'stdout':''}
  if args[1]==CAP_OBSERVE:return {'exitcode':0,'stdout':json.dumps({'path':'/usr/lib/cuttlefish-common/bin/capability_query.py','sha256':CAP_SHA,'size':CAP_SIZE,'uid':0,'gid':0,'mode':0o755,'inode':3})}
  if args[1]==CAP_REMOVE:return {'exitcode':0,'stdout':''}
  if args[1]==INSTALL:
   rows=[x for x in validate_verifier(Path(self.p.verifier_path))['packages'] if x['package']!='cuttlefish-base'];root=f"/var/lib/amnezia-release-lab/deps/{'a'*48}"
   installed={x['package']:{'version':x['version'],'status':'ii '} for x in rows};unpack=['/usr/bin/dpkg','--unpack',*[root+'/files/'+x['file'] for x in rows]];configure=['/usr/bin/dpkg','--configure',*[x['package'] for x in rows]]
   parents=[{'component':x,'created':x in ('cuttlefish-common','bin'),'dev':1,'inode':10+i,'uid':0,'gid':0,'mode':0o755} for i,x in enumerate(('usr','lib','cuttlefish-common','bin'))]
   return {'exitcode':0,'stdout':json.dumps({'schema':1,'run_id':'run','attempt_nonce':'a'*48,'uid':1000,'primary_gid':1000,'bundle':{'sha256':BUNDLE_SHA,'size':BUNDLE_SIZE},'manifest':{'sha256':MANIFEST_SHA,'size':MANIFEST_SIZE},'runtime_package_count':54,'dpkg':{'pre_pending':[],'outside_allowlist':[],'changed_packages':list(installed),'installed':installed},'unpack':{'exit_code':0,'argv':unpack},'configure':{'exit_code':0,'argv':configure},'capability':{'path':'/usr/lib/cuttlefish-common/bin/capability_query.py','sha256':CAP_SHA,'size':CAP_SIZE,'uid':0,'gid':0,'mode':0o755,'inode':3,'parents':parents,'probe':{'exit_code':0,'argv':['/usr/bin/setpriv','--reuid=1000','--regid=1000','--clear-groups','/usr/lib/cuttlefish-common/bin/capability_query.py','qemu_cli']}},'origin':'guest','transport':'qga','injected':False})}
  return {'exitcode':0,'stdout':''}
 def write_file_from_path(self,*a,**k):self.calls.append(('write',a,k))
def test_exact_bundle_and_genuine_capability_flow(tmp_path):
 p=plan(tmp_path);q=Q(p);r=HostDependencyInstaller(q,p,lambda:p.outer,lambda run,x:{'origin':'controller','immutable':True},lambda run,x:{'origin':'controller','immutable':True}).install()
 assert r['runtime_package_count']==54 and any(x[0]=='write' for x in q.calls) and q.calls[-1][1][1]==CLEANUP
 assert next(i for i,x in enumerate(q.calls) if x[0]=='write')>next(i for i,x in enumerate(q.calls) if x[0]!="write" and x[1][1]==GROUP_PREFLIGHT)
 assert "'/usr/bin/dpkg','--unpack'" in INSTALL and "'--clear-groups'" in INSTALL
 assert 'cuttlefish-base' in INSTALL and CAP_SHA in INSTALL
def test_wrong_binding_and_bundle_rejected_before_qga(tmp_path):
 p=plan(tmp_path);q=Q(p)
 with pytest.raises(HostDependencyError,match='outer changed'):HostDependencyInstaller(q,p,lambda:{'pid':3},lambda run,x:{'origin':'controller','immutable':True},lambda run,x:{'origin':'controller','immutable':True}).install()
 assert q.calls==[]
 with pytest.raises(HostDependencyError,match='bundle'):HostDependencyPlan(run_id='run',profile='linux-headless-x64',attempt_nonce='a'*48,runtime_uid=1000,outer={'pid':2},bundle_path=str(tmp_path/'x'),verifier_path=p.verifier_path,bundle_sha256='0'*64).validate()

def test_signed_verifier_exact_package_set():
 p=Path(__file__).resolve().parents[2]/VERIFIER_REL;r=validate_verifier(p)
 assert len(r['packages'])==55 and r['ubuntu_signed_runtime']['package_count']==54
 assert r['google_signed_capability_source']['package']=='cuttlefish-base'

def test_failure_requires_controller_archive(tmp_path):
 p=plan(tmp_path);q=Q(p);q.guest_exec_wait=lambda *a,**k:{'exitcode':1,'stdout':'','stderr':'denied'};seen=[]
 with pytest.raises(HostDependencyError):HostDependencyInstaller(q,p,lambda:p.outer,lambda run,x:(seen.append(x) or {'origin':'controller','immutable':True}),lambda run,x:{'origin':'controller','immutable':True}).install()
 assert len(seen)==1 and seen[0]['verifier_sha256']==VERIFIER_SHA

def test_forged_installed_mapping_is_rejected_and_cleaned(tmp_path):
 p=plan(tmp_path);q=Q(p);original=q.guest_exec_wait;clean=[];removed=[]
 def call(path,args,timeout):
  value=original(path,args,timeout)
  if args[1]==INSTALL:
   row=json.loads(value['stdout']);row['dpkg']['installed']={f'p{i}':{} for i in range(54)};value['stdout']=json.dumps(row)
  if args[1]==CLEANUP:clean.append(True)
  if args[1]==CAP_REMOVE:removed.append(True)
  return value
 q.guest_exec_wait=call
 with pytest.raises(HostDependencyError,match='dpkg receipt'):HostDependencyInstaller(q,p,lambda:p.outer,lambda run,x:{'origin':'controller','immutable':True},lambda run,x:{'origin':'controller','immutable':True}).install()
 assert removed and clean
 cap_call=next(x for x in q.calls if x[0]!="write" and x[1][1]==CAP_REMOVE)
 assert cap_call[1][-6:]==['3',CAP_SHA,str(CAP_SIZE),'0','0',str(0o755)]
 assert "h.hexdigest(),n,st.st_uid,st.st_gid" in CAP_REMOVE

def test_minimal_group_receipt_rejected_before_transfer(tmp_path):
 p=plan(tmp_path);q=Q(p);original=q.guest_exec_wait
 def call(path,args,timeout):
  if args[1]==GROUP_PROVISION:return {'exitcode':0,'stdout':json.dumps({'schema':1,'uid':1000,'user':'lab','primary_gid':1000,'cvdnetwork_gid':999,'created':True,'member':True})}
  return original(path,args,timeout)
 q.guest_exec_wait=call
 with pytest.raises(HostDependencyError,match='provisioning receipt'):HostDependencyInstaller(q,p,lambda:p.outer,lambda run,x:{'origin':'controller','immutable':True},lambda run,x:{'origin':'controller','immutable':True}).install()
 assert not any(x[0]=='write' for x in q.calls)

def test_vhost_permission_failure_is_rejected_before_bundle_transfer(tmp_path):
 p=plan(tmp_path);q=Q(p);original=q.guest_exec_wait
 def call(path,args,timeout):
  value=original(path,args,timeout)
  if args[1]==GROUP_PREFLIGHT:
   row=json.loads(value['stdout']);row['ready']=False;row['vhost_access']['result']['write']=False;value['stdout']=json.dumps(row)
  return value
 q.guest_exec_wait=call
 with pytest.raises(HostDependencyError,match='kvm/vhost'):HostDependencyInstaller(q,p,lambda:p.outer,lambda run,x:{'origin':'controller','immutable':True},lambda run,x:{'origin':'controller','immutable':True}).install()
 assert not any(x[0]=='write' for x in q.calls)

def test_wrong_os_rejected_before_guest_mutation(tmp_path):
 p=plan(tmp_path);q=Q(p);original=q.guest_exec_wait
 def call(path,args,timeout):
  if args[1]==OS_PREFLIGHT:return {'exitcode':0,'stdout':json.dumps({'id':'ubuntu','version_id':'22.04','codename':'jammy','arch':'x86_64'})}
  return original(path,args,timeout)
 q.guest_exec_wait=call
 with pytest.raises(HostDependencyError,match='OS/architecture'):HostDependencyInstaller(q,p,lambda:p.outer,lambda run,x:{'origin':'controller','immutable':True},lambda run,x:{'origin':'controller','immutable':True}).install()
 assert not any(x[0]=='write' or x[1][1]==MKROOT for x in q.calls)

def test_archive_callbacks_require_bound_two_argument_contract(tmp_path):
 p=plan(tmp_path);q=Q(p)
 with pytest.raises(HostDependencyError,match='signature'):HostDependencyInstaller(q,p,lambda:p.outer,lambda record:{},lambda run,record:{})
 assert q.calls==[]

def test_actual_multiarch_dpkg_keys_normalize_to_signed_names():
 runtime_rows=[{'package':'libgcrypt20','architecture':'amd64'},{'package':'libwayland-server0','architecture':'amd64'}]
 before={'libgcrypt20:amd64':['old','un '],'libwayland-server0:amd64':['old','un ']};after={'libgcrypt20:amd64':['1.10.3','ii '],'libwayland-server0:amd64':['1.22.0','ii ']}
 changed_raw={k for k in set(before)|set(after) if before.get(k)!=after.get(k)}
 aliases={alias:x['package'] for x in runtime_rows for alias in (x['package'],x['package']+':'+x['architecture'])}
 assert {aliases[k] for k in changed_raw}=={'libgcrypt20','libwayland-server0'}
 assert "x['package']+':'+x['architecture']" in INSTALL
 assert any(k not in aliases for k in {'foreign-trigger:amd64'})

@pytest.mark.skipif(__import__('shutil').which('wsl.exe') is None,reason='WSL required for dirfd cleanup behavior')
def test_cleanup_allows_symlink_and_preserves_marker_on_prescan_failure():
 tag='amnezia-cleanup-'+uuid.uuid4().hex;nonce='a'*48;script=CLEANUP.replace("('var','lib','amnezia-release-lab','deps')",f"('tmp','{tag}','deps')")
 setup=f"""import os,pathlib,hashlib,json
p=pathlib.Path('/tmp/{tag}/deps/{nonce}');p.mkdir(parents=True,mode=0o700);(p/'.owner').write_text('{nonce}\\n');os.chmod(p/'.owner',0o600);(p/'regular').write_bytes(b'x');os.symlink('regular',p/'link');os.mkfifo(p/'fifo');s=p.stat();print(json.dumps([s.st_dev,s.st_ino,hashlib.sha256((p/'.owner').read_bytes()).hexdigest()]))"""
 def wsl(code,*args):
  encoded=base64.b64encode(code.encode()).decode();return subprocess.run(['wsl.exe','-u','root','python3','-c',"import base64;exec(base64.b64decode('"+encoded+"'))",*args],capture_output=True,text=True,timeout=20)
 made=wsl(setup);assert made.returncode==0,made.stderr;dev,ino,marker=json.loads(made.stdout)
 first=wsl(script,nonce,str(dev),str(ino),marker);assert first.returncode!=0
 check=wsl(f"import pathlib;print((pathlib.Path('/tmp/{tag}/deps/{nonce}')/'.owner').is_file())");assert check.stdout.strip()=='True'
 wsl(f"import os;os.unlink('/tmp/{tag}/deps/{nonce}/fifo')")
 second=wsl(script,nonce,str(dev),str(ino),marker);assert second.returncode==0,second.stderr
 gone=wsl(f"import pathlib;print(pathlib.Path('/tmp/{tag}/deps/{nonce}').exists())");assert gone.stdout.strip()=='False'
