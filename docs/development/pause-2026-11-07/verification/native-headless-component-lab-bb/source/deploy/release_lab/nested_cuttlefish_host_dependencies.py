"""Frozen Noble host dependency setup for nested Cuttlefish QEMU."""
from __future__ import annotations
from dataclasses import dataclass,asdict
from pathlib import Path,PurePosixPath
from typing import Any,Callable,Mapping
import hashlib,inspect,json,math,re,time
try: from .nested_cuttlefish_qga_bridge import GROUP_PROVISION,GROUP_PREFLIGHT
except ImportError: from nested_cuttlefish_qga_bridge import GROUP_PROVISION,GROUP_PREFLIGHT

class HostDependencyError(RuntimeError):pass
SHA=re.compile(r"[0-9a-f]{64}")
BUNDLE_SHA="fdd52aa85f128dd8ed834a0128f8e8cc2c45ddd45bdeacee0f10bb792b96fcb5";BUNDLE_SIZE=177141760
MANIFEST_SHA="50c4c208958c264102b0a79d3c44c9d5ad0843e0d9d0a19e08eaf940f594f58c";MANIFEST_SIZE=31370
CAP_SHA="916d0d759108899667805efb7fc33e9140c8e39d00163bf7109248f6ccb9f134";CAP_SIZE=1258
VERIFIER_REL="dist/release-lab-fixtures/android-cvd-host-dependencies-noble-amd64-20260913/verifier-receipt.json"
VERIFIER_SHA="742b5e27241e308995a4a245828a07aeff72928bb49a9f74db35a96212572fa6";VERIFIER_SIZE=21251
MKROOT=r'''import json,os,stat,sys
nonce=sys.argv[1];fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
for part in ('var','lib','amnezia-release-lab'):
 try:n=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
 except FileNotFoundError:
  if part!='amnezia-release-lab':raise
  os.mkdir(part,0o700,dir_fd=fd);n=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
 os.close(fd);fd=n;s=os.fstat(fd)
 if s.st_uid!=0 or (s.st_mode&0o022):raise SystemExit('unsafe dependency ancestry')
try:n=os.open('deps',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
except FileNotFoundError:os.mkdir('deps',0o700,dir_fd=fd);n=os.open('deps',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
os.close(fd);fd=n;s=os.fstat(fd)
if s.st_uid!=0 or (s.st_mode&0o022):raise SystemExit('unsafe dependency parent')
os.mkdir(nonce,0o700,dir_fd=fd);child=os.open(nonce,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);cs=os.fstat(child)
marker=(nonce+'\n').encode();m=os.open('.owner',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=child);os.write(m,marker);os.fsync(m);os.close(m);os.fsync(child)
print(json.dumps({'dev':cs.st_dev,'inode':cs.st_ino,'uid':cs.st_uid,'gid':cs.st_gid,'mode':cs.st_mode&0o777,'marker_sha256':__import__('hashlib').sha256(marker).hexdigest()}))
'''
CLEANUP=r'''import os,stat,sys,hashlib
nonce=sys.argv[1];dev=int(sys.argv[2]);ino=int(sys.argv[3]);marker=sys.argv[4];fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
for part in ('var','lib','amnezia-release-lab','deps'):
 n=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=n
parent=fd;child=os.open(nonce,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent);s=os.fstat(child)
if (s.st_dev,s.st_ino,s.st_uid,s.st_mode&0o777)!=(dev,ino,0,0o700):raise SystemExit('dependency root identity changed')
m=os.open('.owner',os.O_RDONLY|os.O_NOFOLLOW,dir_fd=child);b=os.read(m,128);os.close(m)
if hashlib.sha256(b).hexdigest()!=marker:raise SystemExit('dependency marker changed')
def purge(fd):
 for name in sorted(os.listdir(fd)):
  st=os.stat(name,dir_fd=fd,follow_symlinks=False)
  if stat.S_ISDIR(st.st_mode):
   sub=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);purge(sub);os.close(sub);os.rmdir(name,dir_fd=fd)
  elif stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode):os.unlink(name,dir_fd=fd)
  else:raise SystemExit('unsafe dependency cleanup entry')
 os.fsync(fd)
def scan(fd,root=False):
 for name in os.listdir(fd):
  st=os.stat(name,dir_fd=fd,follow_symlinks=False)
  if root and name=='.owner':
   if not stat.S_ISREG(st.st_mode):raise SystemExit('dependency marker type changed')
   continue
  if stat.S_ISDIR(st.st_mode):
   sub=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);scan(sub);os.close(sub)
  elif not (stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode)):raise SystemExit('unsafe dependency cleanup entry')
scan(child,True)
for name in sorted(x for x in os.listdir(child) if x!='.owner'):
 st=os.stat(name,dir_fd=child,follow_symlinks=False)
 if stat.S_ISDIR(st.st_mode):sub=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=child);purge(sub);os.close(sub);os.rmdir(name,dir_fd=child)
 else:os.unlink(name,dir_fd=child)
os.fsync(child);os.unlink('.owner',dir_fd=child);os.fsync(child);os.close(child);os.rmdir(nonce,dir_fd=parent);os.fsync(parent);os.close(parent)
'''
OS_PREFLIGHT=r'''import json,platform,pathlib
d={}
for line in pathlib.Path('/etc/os-release').read_text().splitlines():
 if '=' in line:
  k,v=line.split('=',1);d[k]=v.strip('"')
print(json.dumps({'id':d.get('ID'),'version_id':d.get('VERSION_ID'),'codename':d.get('VERSION_CODENAME'),'arch':platform.machine()}))
'''
CAP_REMOVE=r'''import os,sys,stat,hashlib
ino=int(sys.argv[1]);sha=sys.argv[2];size=int(sys.argv[3]);uid=int(sys.argv[4]);gid=int(sys.argv[5]);mode=int(sys.argv[6]);fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
for part in ('usr','lib','cuttlefish-common','bin'):
 n=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=n
f=os.open('capability_query.py',os.O_RDONLY|os.O_NOFOLLOW,dir_fd=fd);st=os.fstat(f);h=hashlib.sha256();n=0
while True:
 b=os.read(f,65536)
 if not b:break
 h.update(b);n+=len(b)
os.close(f)
if (st.st_ino,h.hexdigest(),n,st.st_uid,st.st_gid,st.st_mode&0o777)!=(ino,sha,size,uid,gid,mode) or not stat.S_ISREG(st.st_mode):raise SystemExit('capability identity changed')
os.unlink('capability_query.py',dir_fd=fd);os.fsync(fd);os.close(fd)
'''
CAP_OBSERVE=r'''import hashlib,json,os,pathlib,stat
p=pathlib.Path('/usr/lib/cuttlefish-common/bin/capability_query.py');s=p.stat(follow_symlinks=False)
if not stat.S_ISREG(s.st_mode):raise SystemExit('capability target not regular')
b=p.read_bytes();print(json.dumps({'path':str(p),'sha256':hashlib.sha256(b).hexdigest(),'size':len(b),'uid':s.st_uid,'gid':s.st_gid,'mode':s.st_mode&0o777,'inode':s.st_ino}))
'''

def _sha(p:Path)->tuple[str,int]:
 h=hashlib.sha256();n=0
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b);n+=len(b)
 return h.hexdigest(),n
def validate_verifier(path:Path)->dict:
 if _sha(path)!=(VERIFIER_SHA,VERIFIER_SIZE):raise HostDependencyError("signed-index verifier bytes changed")
 try:r=json.loads(path.read_text(encoding='utf-8'))
 except Exception as e:raise HostDependencyError("signed-index verifier unreadable") from e
 if r.get('validated') is not True or r.get('kind')!='android-cvd-host-dependency-signed-index-verifier':raise HostDependencyError("signed-index verifier invalid")
 rows=r.get('packages');
 if not isinstance(rows,list) or len(rows)!=55:raise HostDependencyError("signed package set invalid")
 keys=[(x.get('package'),x.get('version'),x.get('architecture'),x.get('file'),x.get('sha256'),x.get('size')) for x in rows if isinstance(x,Mapping)]
 if len(keys)!=55 or len(set(keys))!=55 or sum(x[0]!='cuttlefish-base' for x in keys)!=54:raise HostDependencyError("signed package set is not exact")
 if not any(x[0]=='cuttlefish-base' and x[1]=='1.57.0' and x[4]=='22a6b3d69ecbe15d22e6f2105dbca3572fb51f510f22d2f7244fa426999d963e' and x[5]==117904876 for x in keys):raise HostDependencyError("Google signed capability source missing")
 return r

@dataclass(frozen=True)
class HostDependencyPlan:
 run_id:str;profile:str;attempt_nonce:str;runtime_uid:int;outer:Mapping[str,Any];bundle_path:str;verifier_path:str;bundle_sha256:str=BUNDLE_SHA;bundle_size:int=BUNDLE_SIZE;verifier_sha256:str=VERIFIER_SHA;verifier_size:int=VERIFIER_SIZE
 def validate(self):
  if self.profile!="linux-headless-x64" or not self.run_id or not re.fullmatch(r"[0-9a-f]{48}",self.attempt_nonce) or self.runtime_uid<=0:raise HostDependencyError("invalid dependency plan binding")
  if self.bundle_sha256!=BUNDLE_SHA or self.bundle_size!=BUNDLE_SIZE or not Path(self.bundle_path).is_absolute():raise HostDependencyError("dependency bundle is not frozen")
  if self.verifier_sha256!=VERIFIER_SHA or self.verifier_size!=VERIFIER_SIZE or not Path(self.verifier_path).is_absolute():raise HostDependencyError("dependency verifier is not frozen")
  validate_verifier(Path(self.verifier_path))

INSTALL=r'''import hashlib,json,os,pathlib,pwd,subprocess,sys,tarfile
root=pathlib.Path(sys.argv[1]);archive=root/'bundle.tar';expected=sys.argv[2];uid=int(sys.argv[3]);run=sys.argv[4];nonce=sys.argv[5]
def sha(p):
 h=hashlib.sha256();n=0
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b);n+=len(b)
 return h.hexdigest(),n
if sha(archive)!=(expected,177141760):raise SystemExit('bundle mismatch')
out=root/'files';out.mkdir(mode=0o700)
with tarfile.open(archive,'r:') as tf:
 seen=set()
 for m in tf.getmembers():
  p=pathlib.PurePosixPath(m.name)
  if p.is_absolute() or '..' in p.parts or not m.isfile() or str(p) in seen:raise SystemExit('unsafe bundle')
  seen.add(str(p));dst=out/p;dst.parent.mkdir(parents=True,exist_ok=True)
  with tf.extractfile(m) as src,dst.open('xb') as d:
   for b in iter(lambda:src.read(1048576),b''):d.write(b)
manifest=json.loads((out/'bundle-manifest.json').read_text());mh,ms=sha(out/'bundle-manifest.json')
if (mh,ms)!=('50c4c208958c264102b0a79d3c44c9d5ad0843e0d9d0a19e08eaf940f594f58c',31370) or manifest.get('runtime_package_count')!=54:raise SystemExit('manifest mismatch')
expected_members={x['file'] for x in manifest['packages']}|{'bundle-manifest.json','bundle-receipt.json','offline-validation.json','resolved-packages.json'}
if seen!=expected_members:raise SystemExit('bundle member set mismatch')
for x in manifest['packages']:
 if sha(out/x['file'])!=(x['sha256'],x['size']):raise SystemExit('deb mismatch')
def cmd(a,t):
 p=subprocess.run(a,capture_output=True,timeout=t);return {'argv':a,'exit_code':p.returncode,'stdout_sha256':hashlib.sha256(p.stdout).hexdigest(),'stderr_sha256':hashlib.sha256(p.stderr).hexdigest(),'stdout_size':len(p.stdout),'stderr_size':len(p.stderr)}
def status():
 p=subprocess.run(['/usr/bin/dpkg-query','-W','-f=${binary:Package}\t${Version}\t${db:Status-Abbrev}\n'],capture_output=True,timeout=30)
 if p.returncode:raise SystemExit('dpkg status unavailable')
 return {x.split('\t')[0]:x.split('\t')[1:] for x in p.stdout.decode().splitlines() if x.count('\t')==2}
runtime_rows=[x for x in manifest['packages'] if x['package']!='cuttlefish-base'];runtime=[str(out/x['file']) for x in runtime_rows];names=[x['package'] for x in runtime_rows]
before=status();pending=[k for k,v in before.items() if len(v)==2 and v[1] not in ('ii ','un ')]
if pending:raise SystemExit('unrelated pending dpkg state')
unpack=cmd(['/usr/bin/dpkg','--unpack',*runtime],600)
if unpack['exit_code']:raise SystemExit('dpkg unpack failed')
configure=cmd(['/usr/bin/dpkg','--configure',*names],600)
if configure['exit_code']:raise SystemExit('dpkg configure failed')
after=status();changed_raw={k for k in set(before)|set(after) if before.get(k)!=after.get(k)}
aliases={alias:x['package'] for x in runtime_rows for alias in (x['package'],x['package']+':'+x['architecture'])}
outside=sorted(k for k in changed_raw if k not in aliases)
if outside:raise SystemExit('dpkg changed package outside signed allowlist')
changed={aliases[k] for k in changed_raw}
versions={}
for x in runtime_rows:
 keys=[k for k in (x['package'],x['package']+':'+x['architecture']) if k in after]
 if len(keys)!=1:raise SystemExit('installed package key ambiguous')
 value=after[keys[0]]
 if value!=[x['version'],'ii ']:raise SystemExit('installed package version/status mismatch')
 versions[x['package']]={'version':value[0],'status':value[1]}
cf=next(out.glob('cuttlefish-base_*.deb'));cfroot=root/'cuttlefish-base';cfroot.mkdir();expand=cmd(['/usr/bin/dpkg-deb','-x',str(cf),str(cfroot)],300)
src=cfroot/'usr/lib/cuttlefish-common/bin/capability_query.py';target=pathlib.Path('/usr/lib/cuttlefish-common/bin/capability_query.py')
if expand['exit_code'] or sha(src)!=('916d0d759108899667805efb7fc33e9140c8e39d00163bf7109248f6ccb9f134',1258):raise SystemExit('capability source mismatch')
fdroot=os.open('/',os.O_RDONLY|os.O_DIRECTORY);parents=[]
for part in ('usr','lib','cuttlefish-common','bin'):
 try:n=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fdroot);created=False
 except FileNotFoundError:
  if part not in ('cuttlefish-common','bin'):raise
  os.mkdir(part,0o755,dir_fd=fdroot);n=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fdroot);created=True
 os.close(fdroot);fdroot=n;s=os.fstat(fdroot)
 if s.st_uid!=0 or (s.st_mode&0o022):raise SystemExit('unsafe capability target ancestry')
 parents.append({'component':part,'created':created,'dev':s.st_dev,'inode':s.st_ino,'uid':s.st_uid,'gid':s.st_gid,'mode':s.st_mode&0o777})
fd=os.open('capability_query.py',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o755,dir_fd=fdroot)
with os.fdopen(fd,'wb') as f:f.write(src.read_bytes());f.flush();os.fsync(f.fileno())
ts=os.stat(target,follow_symlinks=False);os.fsync(fdroot);os.close(fdroot)
user=pwd.getpwuid(uid);probe=cmd(['/usr/bin/setpriv',f'--reuid={uid}',f'--regid={user.pw_gid}','--clear-groups',str(target),'qemu_cli'],30)
if probe['exit_code']:
 cur=os.stat(target,follow_symlinks=False)
 if cur.st_ino!=ts.st_ino:raise SystemExit('capability identity changed after failed probe')
 target.unlink();raise SystemExit('qemu capability failed')
print(json.dumps({'schema':1,'run_id':run,'attempt_nonce':nonce,'uid':uid,'primary_gid':user.pw_gid,'bundle':{'sha256':expected,'size':177141760},'manifest':{'sha256':mh,'size':ms},'runtime_package_count':54,'dpkg':{'pre_pending':pending,'changed_packages':sorted(changed),'outside_allowlist':[],'installed':versions},'unpack':unpack,'configure':configure,'capability':{'path':str(target),'sha256':sha(target)[0],'size':sha(target)[1],'uid':ts.st_uid,'gid':ts.st_gid,'mode':ts.st_mode&0o777,'inode':ts.st_ino,'parents':parents,'probe':probe},'origin':'guest','transport':'qga','injected':False},sort_keys=True,separators=(',',':')))
'''

class HostDependencyInstaller:
 def __init__(self,qga:Any,plan:HostDependencyPlan,outer_snapshot:Callable[[],Mapping[str,Any]],failure_archive:Callable[[str,Mapping[str,Any]],Mapping[str,Any]],success_archive:Callable[[str,Mapping[str,Any]],Mapping[str,Any]]):
  if not callable(failure_archive) or not callable(success_archive):raise HostDependencyError("dependency archive callbacks required")
  for callback in (failure_archive,success_archive):
   try:params=list(inspect.signature(callback).parameters.values())
   except (TypeError,ValueError) as e:raise HostDependencyError("dependency archive callback signature unavailable") from e
   if len(params)!=2 or any(x.kind not in (inspect.Parameter.POSITIONAL_ONLY,inspect.Parameter.POSITIONAL_OR_KEYWORD) for x in params):raise HostDependencyError("dependency archive callback signature invalid")
  self.qga=qga;self.p=plan;self.snap=outer_snapshot;self.archive=failure_archive;self.success_archive=success_archive;plan.validate()
 def install(self,timeout:int=1200)->dict:
  if isinstance(timeout,bool) or not isinstance(timeout,(int,float)) or not math.isfinite(timeout) or not 60<=timeout<=1800:raise HostDependencyError("invalid dependency timeout")
  if self.snap()!=self.p.outer:raise HostDependencyError("outer changed")
  root=f"/var/lib/amnezia-release-lab/deps/{self.p.attempt_nonce}";deadline=time.monotonic()+timeout
  root_id=None;cap_observed=None;success_durable=False;phase='preflight';last={}
  def left(cap:float)->float:
   value=deadline-self.clock() if hasattr(self,'clock') else deadline-time.monotonic()
   if value<=0:raise HostDependencyError("dependency deadline expired")
   return min(cap,value)
  def fence():
   if self.snap()!=self.p.outer:raise HostDependencyError("outer changed")
  try:
   phase='os-preflight';osraw=self.qga.guest_exec_wait('/usr/bin/python3',['-c',OS_PREFLIGHT],timeout=left(20));last=osraw
   if osraw.get('exitcode')!=0:raise HostDependencyError('guest OS preflight failed')
   try:os_receipt=json.loads(osraw.get('stdout',''))
   except Exception as e:raise HostDependencyError('guest OS preflight missing') from e
   if os_receipt!={'id':'ubuntu','version_id':'24.04','codename':'noble','arch':'x86_64'}:raise HostDependencyError('guest OS/architecture differs from signed dependency closure')
   fence();phase='mkdir';mk=self.qga.guest_exec_wait('/usr/bin/python3',['-c',MKROOT,self.p.attempt_nonce],timeout=left(30));last=mk
   if isinstance(mk.get('exitcode'),bool) or mk.get('exitcode')!=0:raise HostDependencyError("dependency root creation failed")
   try:root_id=json.loads(mk.get('stdout',''))
   except Exception as e:raise HostDependencyError('dependency root identity missing') from e
   expected_marker=hashlib.sha256((self.p.attempt_nonce+'\n').encode()).hexdigest()
   if any(isinstance(root_id.get(k),bool) or not isinstance(root_id.get(k),int) for k in ('dev','inode','uid','gid','mode')) or (root_id['uid'],root_id['mode'])!=(0,0o700) or root_id.get('marker_sha256')!=expected_marker:raise HostDependencyError('dependency root identity invalid')
   fence();phase='group-provision';group_provisioning=self.qga.guest_exec_wait('/usr/bin/python3',['-c',GROUP_PROVISION,str(self.p.runtime_uid)],timeout=left(90));last=group_provisioning
   if group_provisioning.get('exitcode')!=0:raise HostDependencyError('cvdnetwork provisioning failed')
   try:group_provisioning=json.loads(group_provisioning.get('stdout',''))
   except Exception as e:raise HostDependencyError('cvdnetwork provisioning receipt missing') from e
   commands=group_provisioning.get('commands');files=group_provisioning.get('files')
   if (group_provisioning.get('schema')!=1 or group_provisioning.get('uid')!=self.p.runtime_uid or group_provisioning.get('created') is not True
       or group_provisioning.get('member') is not True or group_provisioning.get('origin')!='guest' or group_provisioning.get('transport')!='qga'
       or group_provisioning.get('injected') is not False or group_provisioning.get('kvm_modified') is not False or group_provisioning.get('vhost_modified') is not False
       or not isinstance(files,list) or {x.get('path') for x in files if isinstance(x,Mapping)}!={'/etc/group','/etc/gshadow'}
       or any(not re.fullmatch(r'[0-9a-f]{64}',str(x.get(k,''))) for x in files for k in ('before_sha256','after_sha256'))
       or any(x.get('before_sha256')==x.get('after_sha256') for x in files)
       or not isinstance(commands,list) or [x.get('argv') for x in commands] != [['/usr/sbin/groupadd','--system','cvdnetwork'],['/usr/sbin/usermod','-aG','cvdnetwork',group_provisioning.get('user')]]
       or any(x.get('exit_code')!=0 or not SHA.fullmatch(str(x.get('exe_sha256',''))) or any(isinstance(x.get(k),bool) or not isinstance(x.get(k),int) or not 0<=x[k]<=4096 for k in ('stdout_size','stderr_size')) for x in commands)):
    raise HostDependencyError('cvdnetwork provisioning receipt invalid')
   fence();group_raw=self.qga.guest_exec_wait('/usr/bin/python3',['-c',GROUP_PREFLIGHT,str(self.p.runtime_uid)],timeout=left(30));last=group_raw
   if group_raw.get('exitcode')!=0:raise HostDependencyError('cvdnetwork preflight failed')
   try:group=json.loads(group_raw.get('stdout',''))
   except Exception as e:raise HostDependencyError('cvdnetwork preflight receipt missing') from e
   cvd_gid=group.get('cvdnetwork_gid');kvm_gid=group.get('kvm_gid');primary_gid=group.get('primary_gid');vhost=group.get('vhost_vsock')
   if (group.get('ready') is not True or group.get('uid')!=self.p.runtime_uid or isinstance(cvd_gid,bool) or not isinstance(cvd_gid,int) or cvd_gid<=0
       or isinstance(kvm_gid,bool) or not isinstance(kvm_gid,int) or kvm_gid<=0 or isinstance(primary_gid,bool) or not isinstance(primary_gid,int) or primary_gid<=0
       or group.get('preserved_supplementary_groups')!=sorted([cvd_gid,kvm_gid]) or cvd_gid not in group.get('resolved_groups',[])
       or group.get('user')!=group_provisioning.get('user') or primary_gid!=group_provisioning.get('primary_gid') or cvd_gid!=group_provisioning.get('cvdnetwork_gid')
       or group.get('kvm_membership_modified') is not False or group.get('vhost_device_modified') is not False or not isinstance(vhost,dict)
       or group.get('vhost_access',{}).get('exit_code')!=0 or group.get('vhost_access',{}).get('result')!={'egid':primary_gid,'euid':self.p.runtime_uid,'groups':sorted([cvd_gid,kvm_gid]),'read':True,'write':True} or vhost.get('path')!='/dev/vhost-vsock' or any(isinstance(vhost.get(k),bool) or not isinstance(vhost.get(k),int) or vhost[k]<=0 for k in ('dev','inode','rdev')) or vhost.get('uid')!=0 or vhost.get('gid')!=kvm_gid or vhost.get('mode')!='0660' or vhost.get('char') is not True):
    raise HostDependencyError('runtime uid/cvdnetwork/kvm/vhost binding invalid')
   fence();phase='transfer';left(timeout)
   self.qga.write_file_from_path(root+'/bundle.tar',Path(self.p.bundle_path),self.p.bundle_sha256,self.p.bundle_size,deadline=deadline,max_size=BUNDLE_SIZE)
   fence();phase='install';remaining=left(900)
   raw=self.qga.guest_exec_wait('/usr/bin/python3',['-c',INSTALL,root,self.p.bundle_sha256,str(self.p.runtime_uid),self.p.run_id,self.p.attempt_nonce],timeout=remaining);last=raw
   if isinstance(raw.get('exitcode'),bool) or raw.get('exitcode')!=0:raise HostDependencyError("dependency installer failed")
   try:r=json.loads(raw['stdout'])
   except Exception as e:raise HostDependencyError("dependency receipt missing") from e
   fence();observed_raw=self.qga.guest_exec_wait('/usr/bin/python3',['-c',CAP_OBSERVE],timeout=left(20));last=observed_raw
   if observed_raw.get('exitcode')!=0:raise HostDependencyError('capability target observation failed')
   try:cap_observed=json.loads(observed_raw.get('stdout',''))
   except Exception as e:raise HostDependencyError('capability target observation missing') from e
   if cap_observed.get('path')!='/usr/lib/cuttlefish-common/bin/capability_query.py' or cap_observed.get('sha256')!=CAP_SHA or cap_observed.get('size')!=CAP_SIZE or cap_observed.get('uid')!=0 or cap_observed.get('gid')!=0 or cap_observed.get('mode')!=0o755 or isinstance(cap_observed.get('inode'),bool) or not isinstance(cap_observed.get('inode'),int) or cap_observed.get('inode',0)<=0:raise HostDependencyError('capability target observation invalid')
   verifier=validate_verifier(Path(self.p.verifier_path));signed={(x['package'],x['version'],x['architecture'],x['file'],x['sha256'],x['size']) for x in verifier['packages']};runtime=[x for x in verifier['packages'] if x['package']!='cuttlefish-base']
   if r.get('origin')!='guest' or r.get('transport')!='qga' or r.get('injected') is not False or r.get('run_id')!=self.p.run_id or r.get('attempt_nonce')!=self.p.attempt_nonce or r.get('capability',{}).get('sha256')!=CAP_SHA:raise HostDependencyError("dependency receipt invalid")
   dpkg=r.get('dpkg') or {};installed=dpkg.get('installed')
   expected_installed={x['package']:{'version':x['version'],'status':'ii '} for x in runtime}
   changed=dpkg.get('changed_packages');allowed={x['package'] for x in runtime}
   if r.get('uid')!=self.p.runtime_uid or isinstance(r.get('primary_gid'),bool) or not isinstance(r.get('primary_gid'),int) or r.get('primary_gid',0)<=0 or r.get('os_preflight') not in (None,{'id':'ubuntu','version_id':'24.04','codename':'noble','arch':'x86_64'}) or dpkg.get('pre_pending')!=[] or dpkg.get('outside_allowlist')!=[] or not isinstance(changed,list) or len(changed)!=len(set(changed)) or not set(changed).issubset(allowed) or installed!=expected_installed or r.get('runtime_package_count')!=54 or r.get('bundle')!={'sha256':BUNDLE_SHA,'size':BUNDLE_SIZE} or r.get('manifest')!={'sha256':MANIFEST_SHA,'size':MANIFEST_SIZE}:raise HostDependencyError("dependency dpkg receipt invalid")
   expected_unpack=['/usr/bin/dpkg','--unpack',*[root+'/files/'+x['file'] for x in runtime]];expected_configure=['/usr/bin/dpkg','--configure',*[x['package'] for x in runtime]]
   for label in ('unpack','configure'):
    cmd=r.get(label) or {}
    if isinstance(cmd.get('exit_code'),bool) or cmd.get('exit_code')!=0 or cmd.get('argv')!=(expected_unpack if label=='unpack' else expected_configure):raise HostDependencyError("dependency command receipt invalid")
   probe=(r.get('capability') or {}).get('probe') or {}
   cap=r.get('capability') or {};expected_probe=['/usr/bin/setpriv',f'--reuid={self.p.runtime_uid}',f"--regid={r.get('primary_gid')}",'--clear-groups','/usr/lib/cuttlefish-common/bin/capability_query.py','qemu_cli']
   parents=cap.get('parents');parts=['usr','lib','cuttlefish-common','bin']
   if cap.get('path')!='/usr/lib/cuttlefish-common/bin/capability_query.py' or cap.get('size')!=CAP_SIZE or cap.get('uid')!=0 or cap.get('gid')!=0 or cap.get('mode')!=0o755 or isinstance(cap.get('inode'),bool) or not isinstance(cap.get('inode'),int) or cap.get('inode',0)<=0 or not isinstance(parents,list) or [x.get('component') for x in parents]!=parts or any(x.get('uid')!=0 or x.get('mode')&0o022 or (x.get('created') is True and x.get('component') not in ('cuttlefish-common','bin')) for x in parents) or isinstance(probe.get('exit_code'),bool) or probe.get('exit_code')!=0 or probe.get('argv')!=expected_probe:raise HostDependencyError("capability receipt invalid")
   r['signed_index_verifier']={'sha256':VERIFIER_SHA,'size':VERIFIER_SIZE,'package_set_sha256':hashlib.sha256(json.dumps(sorted(signed),separators=(',',':')).encode()).hexdigest(),'ubuntu_runtime_count':54,'google_capability_source':True}
   r['group_provisioning']=group_provisioning;r['group_preflight']=group;r['os_preflight']=os_receipt;r['outer']=dict(self.p.outer)
   phase='success-archive';ack=self.success_archive(self.p.run_id,r)
   if not isinstance(ack,Mapping) or ack.get('immutable') is not True or ack.get('origin')!='controller':raise HostDependencyError('dependency success archive rejected')
   success_durable=True
   r['controller_success_archive']=dict(ack)
   fence();phase='cleanup';clean=self.qga.guest_exec_wait('/usr/bin/python3',['-c',CLEANUP,self.p.attempt_nonce,str(root_id['dev']),str(root_id['inode']),root_id['marker_sha256']],timeout=20);last=clean
   if isinstance(clean.get('exitcode'),bool) or clean.get('exitcode')!=0:raise HostDependencyError('dependency success cleanup failed')
   fence()
   return r
  except BaseException as primary:
   full_stdout=str(last.get('stdout','')).encode() if isinstance(last,Mapping) else b'';full_stderr=str(last.get('stderr','')).encode() if isinstance(last,Mapping) else b'';raw_stdout=full_stdout[:4096];raw_stderr=full_stderr[:4096]
   record={'schema':1,'run_id':self.p.run_id,'profile':self.p.profile,'attempt_nonce':self.p.attempt_nonce,'outer':dict(self.p.outer),'bundle_sha256':BUNDLE_SHA,'verifier_sha256':VERIFIER_SHA,'phase':phase,'error_type':type(primary).__name__,'diagnostic':{'exitcode':last.get('exitcode') if isinstance(last,Mapping) and isinstance(last.get('exitcode'),int) and not isinstance(last.get('exitcode'),bool) else None,'stdout_size':len(full_stdout),'stdout_sha256':hashlib.sha256(full_stdout).hexdigest(),'stdout_excerpt_sha256':hashlib.sha256(raw_stdout).hexdigest(),'stdout_excerpt':raw_stdout.decode(errors='replace'),'stderr_size':len(full_stderr),'stderr_sha256':hashlib.sha256(full_stderr).hexdigest(),'stderr_excerpt_sha256':hashlib.sha256(raw_stderr).hexdigest(),'stderr_excerpt':raw_stderr.decode(errors='replace')},'recorded_at':time.time()}
   try:
    ack=self.archive(self.p.run_id,record)
    if not isinstance(ack,Mapping) or ack.get('immutable') is not True or ack.get('origin')!='controller':raise HostDependencyError('dependency failure archive rejected')
   except BaseException as archive_error:
    if hasattr(primary,'add_note'):primary.add_note(f'dependency failure archive also failed: {archive_error!r}')
   if root_id is not None:
    try:
     if cap_observed is not None and not success_durable:
      removed=self.qga.guest_exec_wait('/usr/bin/python3',['-c',CAP_REMOVE,str(cap_observed['inode']),cap_observed['sha256'],str(cap_observed['size']),str(cap_observed['uid']),str(cap_observed['gid']),str(cap_observed['mode'])],timeout=20)
      if removed.get('exitcode')!=0:raise HostDependencyError('capability rollback rejected')
     fence();clean=self.qga.guest_exec_wait('/usr/bin/python3',['-c',CLEANUP,self.p.attempt_nonce,str(root_id['dev']),str(root_id['inode']),root_id['marker_sha256']],timeout=20)
     if clean.get('exitcode')!=0:raise HostDependencyError('dependency failure cleanup rejected')
     fence()
    except BaseException as cleanup_error:
     if hasattr(primary,'add_note'):primary.add_note(f'dependency cleanup also failed: {cleanup_error!r}')
   raise
