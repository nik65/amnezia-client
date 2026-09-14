"""QGA transport bridge for the boot-only nested Cuttlefish contract.

The bridge has no host or guest discovery fallback. A caller must provide a
fresh outer ownership callback, and every QGA operation is fenced by it.
"""
from __future__ import annotations

import base64, hashlib, json, os, re, socket, time
from dataclasses import asdict
from pathlib import PurePosixPath
from typing import Any, BinaryIO, Callable, Mapping

try:
    from .nested_cuttlefish_runner import (AssetSpec, InnerPlan, MAX_CHUNK_SIZE,
        NestedCuttlefishError, build_cleanup_script, build_launch_script, iter_asset_chunks,
        transcript_sha256, validate_boot_receipt, validate_cleanup_receipt, validate_stage_receipt, _proc)
except ImportError:
    from nested_cuttlefish_runner import (AssetSpec, InnerPlan, MAX_CHUNK_SIZE,
        NestedCuttlefishError, build_cleanup_script, build_launch_script, iter_asset_chunks,
        transcript_sha256, validate_boot_receipt, validate_cleanup_receipt, validate_stage_receipt, _proc)

class NestedCuttlefishTransportError(NestedCuttlefishError): pass

GROUP_PROVISION = r'''
import grp,hashlib,json,os,pathlib,pwd,subprocess,sys
uid=int(sys.argv[1]); user=pwd.getpwuid(uid); files=[pathlib.Path('/etc/group'),pathlib.Path('/etc/gshadow')]
def digest(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def rows(p): return {x.split(':',1)[0]:x for x in p.read_text().splitlines() if x and ':' in x}
before_hash={str(p):digest(p) for p in files}; before_rows={str(p):rows(p) for p in files}; commands=[]
def fail(reason):
 print(json.dumps({'schema':1,'outer_failure':'cvdnetwork-provisioning','reason':reason,'uid':uid,'user':user.pw_name,'primary_gid':user.pw_gid,'files':[{'path':str(p),'before_sha256':before_hash[str(p)],'after_sha256':digest(p)} for p in files],'commands':commands,'origin':'guest','transport':'qga','injected':False},sort_keys=True,separators=(',',':'))); raise SystemExit
if any('cvdnetwork' in before_rows[str(p)] for p in files): fail('cvdnetwork-preexists-in-fresh-overlay')
def run(argv):
 exe=pathlib.Path(argv[0]); st=exe.stat()
 if not exe.is_file() or st.st_uid!=0 or st.st_mode&0o022: fail('unsafe-account-tool')
 proc=subprocess.run(argv,capture_output=True,timeout=30)
 commands.append({'argv':argv,'exe_sha256':hashlib.sha256(exe.read_bytes()).hexdigest(),'exit_code':proc.returncode,'stdout_sha256':hashlib.sha256(proc.stdout).hexdigest(),'stderr_sha256':hashlib.sha256(proc.stderr).hexdigest(),'stdout_size':len(proc.stdout),'stderr_size':len(proc.stderr)})
 if proc.returncode or len(proc.stdout)>4096 or len(proc.stderr)>4096: fail('account-tool-failed')
run(['/usr/sbin/groupadd','--system','cvdnetwork']); run(['/usr/sbin/usermod','-aG','cvdnetwork',user.pw_name]); group=grp.getgrnam('cvdnetwork')
after_rows={str(p):rows(p) for p in files}
for p in files:
 key=str(p)
 if {k:v for k,v in before_rows[key].items() if k!='cvdnetwork'}!={k:v for k,v in after_rows[key].items() if k!='cvdnetwork'}: fail('unrelated-account-records-changed')
resolved=sorted(set(os.getgrouplist(user.pw_name,user.pw_gid)))
if group.gr_gid<=0 or user.pw_name not in group.gr_mem or group.gr_gid not in resolved: fail('cvdnetwork-membership-not-effective')
print(json.dumps({'schema':1,'uid':uid,'user':user.pw_name,'primary_gid':user.pw_gid,'cvdnetwork_gid':group.gr_gid,'created':True,'member':True,'resolved_groups':resolved,'files':[{'path':str(p),'before_sha256':before_hash[str(p)],'after_sha256':digest(p)} for p in files],'commands':commands,'kvm_modified':False,'vhost_modified':False,'origin':'guest','transport':'qga','injected':False},sort_keys=True,separators=(',',':')))
'''

GROUP_PREFLIGHT = r'''
import grp,json,os,pathlib,pwd,stat,subprocess,sys
uid=int(sys.argv[1])
try:
 user=pwd.getpwuid(uid); group=grp.getgrnam('cvdnetwork');kvm=grp.getgrnam('kvm');device=pathlib.Path('/dev/vhost-vsock');ds=device.lstat()
except KeyError:
 print(json.dumps({'ready':False,'reason':'runtime-user-or-required-group-missing'})); raise SystemExit
except FileNotFoundError:
 print(json.dumps({'ready':False,'reason':'vhost-vsock-missing'})); raise SystemExit
groups=sorted(set(os.getgrouplist(user.pw_name,user.pw_gid)))
device_row={'path':str(device),'dev':ds.st_dev,'inode':ds.st_ino,'uid':ds.st_uid,'gid':ds.st_gid,'mode':format(ds.st_mode&0o777,'04o'),'rdev':ds.st_rdev,'char':stat.S_ISCHR(ds.st_mode)}
probe_code="import json,os,sys;print(json.dumps({'euid':os.geteuid(),'egid':os.getegid(),'groups':os.getgroups(),'read':os.access(sys.argv[1],os.R_OK),'write':os.access(sys.argv[1],os.W_OK)},sort_keys=True,separators=(',',':')))"
probe=subprocess.run(['/usr/bin/setpriv',f'--reuid={uid}',f'--regid={user.pw_gid}',f'--groups={group.gr_gid},{kvm.gr_gid}','/usr/bin/python3','-c',probe_code,str(device)],capture_output=True,text=True,timeout=20)
try:access=json.loads(probe.stdout)
except Exception:access={}
ready=uid>0 and group.gr_gid>0 and group.gr_gid in groups and kvm.gr_gid>0 and device_row['char'] and ds.st_uid==0 and ds.st_gid==kvm.gr_gid and (ds.st_mode&0o777)==0o660 and probe.returncode==0 and access=={'egid':user.pw_gid,'euid':uid,'groups':sorted([group.gr_gid,kvm.gr_gid]),'read':True,'write':True}
print(json.dumps({'ready':ready,'uid':uid,'user':user.pw_name,'primary_gid':user.pw_gid,
 'cvdnetwork_gid':group.gr_gid,'kvm_gid':kvm.gr_gid,'resolved_groups':groups,
 'preserved_supplementary_groups':sorted([group.gr_gid,kvm.gr_gid]) if ready else [],
 'kvm_membership_modified':False,'vhost_device_modified':False,'vhost_vsock':device_row,'vhost_access':{'argv':['/usr/bin/setpriv',f'--reuid={uid}',f'--regid={user.pw_gid}',f'--groups={group.gr_gid},{kvm.gr_gid}','/usr/bin/python3','-c','<bounded-os-access-probe>',str(device)],'exit_code':probe.returncode,'result':access}},sort_keys=True,separators=(',',':')))
'''

VULKAN_INSTALL = r'''
import ctypes,hashlib,json,os,pathlib,platform,resource,stat,subprocess,sys,tempfile
root=pathlib.Path(sys.argv[1]); deb=root/'input'/sys.argv[2]; expected_deb=sys.argv[3]; expected_deb_size=int(sys.argv[4]); expected_loader=sys.argv[5]; expected_size=int(sys.argv[6]); uid=int(sys.argv[7]); primary_gid=int(sys.argv[8]); cvd_gid=int(sys.argv[9])
def digest(p):
 h=hashlib.sha256(); n=0
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''): h.update(b); n+=len(b)
 return h.hexdigest(),n
if digest(deb)!=(expected_deb,expected_deb_size): raise SystemExit('Vulkan deb rehash failed')
osr={}
for line in pathlib.Path('/etc/os-release').read_text().splitlines():
 if '=' in line:
  k,v=line.split('=',1);osr[k]=v.strip('"')
if {k:osr.get(k) for k in ('ID','VERSION_ID','VERSION_CODENAME')}!={'ID':'ubuntu','VERSION_ID':'24.04','VERSION_CODENAME':'noble'} or platform.machine()!='x86_64': raise SystemExit('outer distro differs from frozen dependency')
libc=subprocess.run(['dpkg-query','-W','-f=${Version}','libc6'],text=True,capture_output=True,timeout=10)
if libc.returncode or not libc.stdout.startswith('2.39'): raise SystemExit('outer libc differs from Noble contract')
target=root/'runtime/private-libs'; unpack=root/'runtime/vulkan-deb-root'
if target.exists() or unpack.exists(): raise SystemExit('Vulkan dependency target already exists')
target.mkdir(mode=0o755);unpack.mkdir(mode=0o700)
subprocess.run(['/usr/bin/dpkg-deb','-x',str(deb),str(unpack)],check=True,timeout=30)
source=unpack/'usr/lib/x86_64-linux-gnu/libvulkan.so.1.3.275'; real=target/'libvulkan.so.1.3.275'; data=source.read_bytes()
if (hashlib.sha256(data).hexdigest(),len(data))!=(expected_loader,expected_size): raise SystemExit('Vulkan loader differs from frozen bytes')
fd=os.open(real,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o644)
try:
 view=memoryview(data)
 while view:
  n=os.write(fd,view)
  if n<=0: raise OSError('short Vulkan loader write')
  view=view[n:]
 os.fsync(fd)
finally: os.close(fd)
os.symlink(real.name,target/'libvulkan.so.1')
dfd=os.open(target,os.O_RDONLY|os.O_DIRECTORY);os.fsync(dfd);os.close(dfd)
if digest(real)!=(expected_loader,expected_size): raise SystemExit('installed Vulkan loader rehash failed')
env={**os.environ,'LD_LIBRARY_PATH':str(target)+':'+str(root/'runtime/qemu')+':'+str(root/'runtime/host/lib64')+':'+str(root/'runtime/host/lib')}
prefix=['/usr/bin/setpriv',f'--reuid={uid}',f'--regid={primary_gid}',f'--groups={cvd_gid}']
try: dlprobe=subprocess.run([*prefix,'/usr/bin/python3','-c','import ctypes,os,sys,json;x=ctypes.CDLL(sys.argv[1]);print(json.dumps({"euid":os.geteuid(),"egid":os.getegid(),"groups":os.getgroups(),"symbol":bool(ctypes.cast(x.vkGetInstanceProcAddr,ctypes.c_void_p).value)}))',str(target/'libvulkan.so.1')],env=env,capture_output=True,text=True,timeout=10)
except subprocess.TimeoutExpired: dlprobe=subprocess.CompletedProcess([],124,'','timeout')
try: ldd=subprocess.run([*prefix,'/usr/bin/ldd',str(target/'libvulkan.so.1')],env=env,capture_output=True,text=True,timeout=10)
except subprocess.TimeoutExpired: ldd=subprocess.CompletedProcess([],124,'','timeout')
ancestor_paths=(pathlib.Path('/var'),pathlib.Path('/var/lib'),root.parent.parent,root.parent,root,root/'runtime',target,target/'libvulkan.so.1')
try: access_probe=subprocess.run([*prefix,'/usr/bin/python3','-c','import json,os,sys;print(json.dumps({"euid":os.geteuid(),"egid":os.getegid(),"groups":os.getgroups(),"access":[{"path":p,"read":os.access(p,os.R_OK),"execute":os.access(p,os.X_OK)} for p in sys.argv[1:]]},sort_keys=True,separators=(",",":")))',*[str(p) for p in ancestor_paths]],env=env,capture_output=True,text=True,timeout=10)
except subprocess.TimeoutExpired: access_probe=subprocess.CompletedProcess([],124,'','timeout')
access=[]
for p in ancestor_paths:
 s=p.lstat();access.append({'path':str(p),'dev':s.st_dev,'inode':s.st_ino,'uid':s.st_uid,'gid':s.st_gid,'mode':format(s.st_mode&0o777,'04o'),'symlink':p.is_symlink()})
diagnostic={'rc':dlprobe.returncode,'stdout':dlprobe.stdout[-1024:],'stderr':dlprobe.stderr[-2048:],'ldd_rc':ldd.returncode,'ldd_stdout':ldd.stdout[-3072:],'ldd_stderr':ldd.stderr[-1024:],'access_probe_rc':access_probe.returncode,'access_probe_stdout':access_probe.stdout[-2048:],'access_probe_stderr':access_probe.stderr[-1024:],'access':access}
if dlprobe.returncode:
 print(json.dumps({'schema':1,'run_id':sys.argv[10],'attempt_nonce':sys.argv[11],'outer_failure':'vulkan-runtime-probe','diagnostic':diagnostic,'origin':'guest','transport':'qga','injected':False},sort_keys=True,separators=(',',':')));raise SystemExit
probe_dir=root/'runtime/graphics-probe';probe_dir.mkdir(mode=0o700);os.chown(probe_dir,uid,primary_gid)
probe_path=probe_dir/'availability.pbtxt'
pfd=os.open(probe_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
os.fchown(pfd,uid,primary_gid);os.fsync(pfd);probe_before=os.fstat(pfd);os.close(pfd)
def limit_output(): resource.setrlimit(resource.RLIMIT_FSIZE,(1048576,1048576))
with tempfile.TemporaryFile() as stdout,tempfile.TemporaryFile() as stderr:
 try: probe=subprocess.run([*prefix,str(root/'runtime/host/bin/graphics_detector'),str(probe_path)],env=env,stdout=stdout,stderr=stderr,timeout=20,preexec_fn=limit_output)
 except subprocess.TimeoutExpired: probe=subprocess.CompletedProcess([],124)
 stdout.seek(0);out=stdout.read(16385);stderr.seek(0);err=stderr.read(16385)
combined=out+err
probe_after=probe_path.lstat()
probe_identity={'path':str(probe_path),'kind':'regular','dev':probe_after.st_dev,'inode':probe_after.st_ino,'uid':probe_after.st_uid,'gid':probe_after.st_gid,'mode':format(probe_after.st_mode&0o777,'04o')}
probe_hash=hashlib.sha256();probe_size=0
with probe_path.open('rb') as pf:
 while True:
  chunk=pf.read(1048576)
  if not chunk: break
  probe_size+=len(chunk)
  if probe_size>1048576: break
  probe_hash.update(chunk)
probe_eof=probe_size<=1048576 and pf.closed
bad_probe=(len(out)>16384 or len(err)>16384 or probe.returncode!=0 or b'Assertion' in combined or b'vkGetInstanceProcAddr' in combined or not stat.S_ISREG(probe_after.st_mode) or probe_after.st_dev!=probe_before.st_dev or probe_after.st_ino!=probe_before.st_ino or probe_after.st_uid!=uid or probe_after.st_gid!=primary_gid or format(probe_after.st_mode&0o777,'04o')!='0600' or probe_size>1048576 or not probe_eof)
if bad_probe:
 diagnostic['graphics_detector']={'rc':probe.returncode,'output_sha256':hashlib.sha256(combined).hexdigest(),'output_size':len(combined),'stdout':out[-2048:].decode(errors='replace'),'stderr':err[-2048:].decode(errors='replace')}
 print(json.dumps({'schema':1,'run_id':sys.argv[10],'attempt_nonce':sys.argv[11],'outer_failure':'vulkan-runtime-probe','diagnostic':diagnostic,'origin':'guest','transport':'qga','injected':False},sort_keys=True,separators=(',',':')));raise SystemExit
print(json.dumps({'schema':1,'run_id':sys.argv[10],'attempt_nonce':sys.argv[11],'os':{'id':'ubuntu','version_id':'24.04','codename':'noble','arch':'amd64','libc6':libc.stdout},'deb':{'sha256':expected_deb,'size':expected_deb_size},'loader':{'path':str(real),'soname_path':str(target/'libvulkan.so.1'),'sha256':expected_loader,'size':expected_size,'uid':real.stat().st_uid,'mode':format(real.stat().st_mode&0o777,'04o'),'directory_uid':target.stat().st_uid,'directory_mode':format(target.stat().st_mode&0o777,'04o')},'dlopen':True,'vkGetInstanceProcAddr':True,'graphics_detector':{'exit_code':probe.returncode,'assertion':False,'uid':uid,'groups':[cvd_gid],'stdout_sha256':hashlib.sha256(out).hexdigest(),'stdout_size':len(out),'stderr_sha256':hashlib.sha256(err).hexdigest(),'stderr_size':len(err),'output_file':{**probe_identity,'sha256':probe_hash.hexdigest(),'size':probe_size,'eof':probe_eof}},'origin':'guest','transport':'qga','injected':False},sort_keys=True,separators=(',',':')))
'''

PRELAUNCH_CLEANUP = r'''
import json,os,pathlib,stat,sys
root=pathlib.PurePosixPath(sys.argv[1]); marker=sys.argv[2]; cgroup=pathlib.Path('/sys/fs/cgroup/amnezia-release-lab')/sys.argv[3]/sys.argv[4]; expected=json.loads(sys.argv[5])
parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
for part in root.parent.parts[1:]:
 child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent);os.close(parent);parent=child
fd=os.open(root.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent);s=os.fstat(fd);observed={'dev':s.st_dev,'inode':s.st_ino,'uid':s.st_uid,'gid':s.st_gid,'mode':format(s.st_mode&0o777,'04o')}
if any(observed.get(k)!=expected.get(k) for k in ('dev','inode','uid','gid')) or observed['mode'] not in ({expected.get('mode')}|({'0711'} if expected.get('mode')=='0700' else set())): raise SystemExit('prelaunch root identity changed')
mf=os.open('marker',os.O_RDONLY|os.O_NOFOLLOW,dir_fd=fd)
with os.fdopen(mf) as f:
 if f.read()!=marker: raise SystemExit('prelaunch marker changed')
if cgroup.exists() and cgroup.joinpath('cgroup.procs').read_text().split(): raise SystemExit('prelaunch cgroup unexpectedly populated')
def clear(d):
 for name in os.listdir(d):
  st=os.stat(name,dir_fd=d,follow_symlinks=False)
  if stat.S_ISDIR(st.st_mode):
   sub=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=d);clear(sub);os.close(sub);os.rmdir(name,dir_fd=d)
  else: os.unlink(name,dir_fd=d)
clear(fd);os.close(fd);os.rmdir(root.name,dir_fd=parent);os.close(parent);print(json.dumps({'removed':True,'observed_root_identity':observed}))
'''

class PersistentQgaChannel:
    """Streaming facade over the existing QgaClient persistent primitives."""
    def __init__(self, qga: Any, before_request: Callable[[],None]):
        self.qga=qga; self.before=before_request; self.sock=None
    def __enter__(self):
        self.before(); self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); self.sock.settimeout(self.qga.timeout)
        self.sock.connect(str(self.qga.socket_path)); self.qga._sync_connection(self.sock); return self
    def __exit__(self,*_):
        if self.sock: self.sock.close()
    def request(self,name:str,args:Mapping[str,Any])->dict:
        self.before()
        if not self.sock: raise NestedCuttlefishTransportError("persistent QGA channel is closed")
        result=self.qga._request_on_connection(self.sock,name,args)
        if not isinstance(result,dict) or "return" not in result: raise NestedCuttlefishTransportError(f"QGA {name} failed")
        return result

STAGE_PREP = r'''import json,os,pathlib,pwd,stat,subprocess,sys
root=pathlib.PurePosixPath(sys.argv[1]);marker=sys.argv[2];uid=int(sys.argv[3]);expected=pathlib.PurePosixPath('/var/lib/amnezia-release-lab/n')
if root.parent!=expected or len(root.name)!=8 or any(c not in '0123456789abcdef' for c in root.name):raise SystemExit('attempt root path invalid')
fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY);rows=[]
for part in ('var','lib'):
 n=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=n;s=os.fstat(fd)
 if s.st_uid!=0 or s.st_mode&0o022:raise SystemExit('unsafe fixed ancestry')
for part in ('amnezia-release-lab','n'):
 try:n=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
 except FileNotFoundError:os.mkdir(part,0o700,dir_fd=fd);n=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
 os.close(fd);fd=n;before=os.fstat(fd)
 if before.st_uid!=0 or before.st_gid!=0 or before.st_mode&0o022 or (before.st_mode&0o777) not in (0o700,0o711,0o755):raise SystemExit('unsafe owned ancestry')
 before_row={'path':str(expected.parent if part=='amnezia-release-lab' else expected),'dev':before.st_dev,'inode':before.st_ino,'uid':before.st_uid,'gid':before.st_gid,'mode':format(before.st_mode&0o777,'04o')}
 if (before.st_mode&0o777)!=0o711:os.fchmod(fd,0o711);os.fsync(fd)
 after=os.fstat(fd);after_row={'path':before_row['path'],'dev':after.st_dev,'inode':after.st_ino,'uid':after.st_uid,'gid':after.st_gid,'mode':format(after.st_mode&0o777,'04o')}
 if {k:before_row[k] for k in ('dev','inode','uid','gid')}!={k:after_row[k] for k in ('dev','inode','uid','gid')} or after_row['mode']!='0711':raise SystemExit('ancestry transition identity changed')
 rows.append({'before':before_row,'after':after_row})
os.mkdir(root.name,0o700,dir_fd=fd);child=os.open(root.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);cs=os.fstat(child)
os.mkdir('input',0o700,dir_fd=child);m=os.open('marker',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=child);raw=marker.encode();off=0
while off<len(raw):
 n=os.write(m,raw[off:])
 if n<=0: raise OSError('short marker write')
 off+=n
os.fsync(m);os.close(m);os.fsync(child);os.close(child);os.close(fd)
user=pwd.getpwuid(uid);code="import json,os,sys;print(json.dumps({'euid':os.geteuid(),'egid':os.getegid(),'groups':os.getgroups(),'paths':[{'path':p,'execute':os.access(p,os.X_OK)} for p in sys.argv[1:]]}))"
probe=subprocess.run(['/usr/bin/setpriv',f'--reuid={uid}',f'--regid={user.pw_gid}','--clear-groups','/usr/bin/python3','-c',code,str(expected.parent),str(expected)],capture_output=True,text=True,timeout=20)
try:p=json.loads(probe.stdout)
except Exception:raise SystemExit('runtime ancestry probe missing')
if probe.returncode or p.get('euid')!=uid or p.get('egid')!=user.pw_gid or p.get('groups')!=[] or [x.get('execute') for x in p.get('paths',[])]!=[True,True]:raise SystemExit('runtime cannot traverse owned ancestry')
print(json.dumps({'ancestry':rows,'attempt':{'dev':cs.st_dev,'inode':cs.st_ino,'uid':cs.st_uid,'gid':cs.st_gid,'mode':format(cs.st_mode&0o777,'04o')},'runtime_probe':p},sort_keys=True,separators=(',',':')))
'''

STAGE_VERIFY = r'''
import hashlib,json,os,pathlib,sys
plan=json.loads(sys.argv[1]); transcripts=json.loads(sys.argv[2]); extraction=json.loads(sys.argv[3])
root=pathlib.Path(plan['guest_root'])
if root.joinpath('marker').is_symlink() or root.joinpath('marker').read_text()!=plan['marker']: raise SystemExit('marker mismatch')
records=[]
for spec in plan['assets']:
 p=pathlib.Path(spec['guest_path']); st=p.lstat()
 if not p.is_file() or p.is_symlink() or st.st_size!=spec['size']: raise SystemExit('asset identity mismatch')
 h=hashlib.sha256()
 with p.open('rb') as stream:
  for chunk in iter(lambda:stream.read(1024*1024),b''): h.update(chunk)
 digest=h.hexdigest()
 if digest!=spec['sha256']: raise SystemExit('guest asset hash mismatch')
 tr=transcripts[spec['name']]
 records.append({**spec,'received_size':st.st_size,'guest_sha256':digest,'eof':True,
   'transfer':tr})
receipt={'schema':2,'operation':'nested-cuttlefish-stage','run_id':plan['run_id'],'profile':plan['profile'],
 'attempt_nonce':plan['attempt_nonce'],'marker':plan['marker'],'guest_root':plan['guest_root'],
 'outer_ownership':plan['outer_ownership'],'origin':'guest','transport':'qga','injected':False,
 'guest_root_identity':{'dev':root.stat().st_dev,'inode':root.stat().st_ino,'uid':root.stat().st_uid,'gid':root.stat().st_gid,'mode':format(root.stat().st_mode&0o777,'04o')},
 'guest_ancestry':plan['guest_ancestry'],
 'runtime_ownership':plan['runtime_ownership'],
 'assets':records,'extraction':extraction,'negotiated_chunk_size':plan['negotiated_chunk_size'],'passed':True}
print(json.dumps(receipt,sort_keys=True,separators=(',',':')))
'''

SAFE_EXTRACT = r'''
import json,os,pathlib,posixpath,shutil,stat,sys,tarfile,zipfile
root=pathlib.Path(sys.argv[1]); host=root/'runtime/host'; images=root/'runtime/images'; qemu=root/'runtime/qemu'
host_arc=root/'input'/sys.argv[2]; image_arc=root/'input'/sys.argv[3]; qemu_arc=root/'input'/sys.argv[4]
limit=4*1024*1024*1024
def safe_name(raw):
 p=pathlib.PurePosixPath(raw)
 if p.is_absolute() or not raw or any(x in ('','..') for x in p.parts): raise SystemExit('unsafe archive path')
 return str(p)
for target in (host,images,qemu):
 if target.exists(): raise SystemExit('extraction target already exists')
 target.mkdir(parents=True,mode=0o700)
with tarfile.open(host_arc,'r:gz') as tf:
 seen=set(); members={}; total=0
 for item in tf.getmembers():
  name=safe_name(item.name)
  if name in seen or item.islnk() or item.isdev() or item.isfifo() or getattr(item,'sparse',None): raise SystemExit('unsafe tar member')
  if item.issym(): safe_name(item.linkname)
  seen.add(name); members[name]=item; total+=item.size
  if total>limit: raise SystemExit('tar expansion bound exceeded')
 for name,item in members.items():
  if item.issym():
   target=posixpath.normpath(posixpath.join(posixpath.dirname(name),item.linkname))
   if target.startswith('../') or target=='..' or target not in members or not members[target].isfile(): raise SystemExit('unsafe tar symlink')
 # Members were fully validated above; extract individually for Ubuntu Python
 # 3.10, which has no tarfile extraction-filter keyword.
 for item in tf.getmembers(): tf.extract(item,host)
with tarfile.open(qemu_arc,'r:gz') as tf:
 seen=set(); total=0
 for item in tf.getmembers():
  name=safe_name(item.name)
  if name in seen or not item.isfile() or '/' in name: raise SystemExit('unsafe qemu bundle member')
  seen.add(name); total+=item.size
  if total>512*1024*1024: raise SystemExit('qemu bundle expansion bound exceeded')
 if 'qemu-system-aarch64' not in seen: raise SystemExit('qemu aarch64 binary missing')
 for item in tf.getmembers(): tf.extract(item,qemu)
with zipfile.ZipFile(image_arc) as zf:
 seen=set(); total=0
 for item in zf.infolist():
  name=safe_name(item.filename)
  mode=(item.external_attr>>16)&0xffff
  if name in seen or item.flag_bits&1 or stat.S_ISLNK(mode): raise SystemExit('unsafe zip member')
  seen.add(name); total+=item.file_size
  if total>limit or (item.compress_size and item.file_size/item.compress_size>1000): raise SystemExit('zip expansion bound exceeded')
 zf.extractall(images)
def tree(path):
 h=__import__('hashlib').sha256(); count=0
 for p in sorted(path.rglob('*')):
  if p.is_symlink():
   target=os.readlink(p); resolved=(p.parent/target).resolve()
   try: resolved.relative_to(path.resolve())
   except ValueError: raise SystemExit('extracted symlink escaped root')
   if not resolved.is_file(): raise SystemExit('extracted symlink target missing')
   h.update(str(p.relative_to(path)).encode()+b'\0'); h.update(b'L'+target.encode()); count+=1
  elif p.is_file():
   d=__import__('hashlib').sha256()
   with p.open('rb') as f:
    for chunk in iter(lambda:f.read(1024*1024),b''): d.update(chunk)
   h.update(str(p.relative_to(path)).encode()+b'\0'); h.update(d.digest()); count+=1
 return {'files':count,'tree_sha256':h.hexdigest()}
host_result=tree(host); image_result=tree(images); qemu_result=tree(qemu)
if not (host/'bin/launch_cvd').is_file() or not (host/'bin/stop_cvd').is_file() or not (host/'bin/adb').is_file(): raise SystemExit('host package layout incomplete')
for name in ('boot.img','super.img','vendor_boot.img','vbmeta.img'):
 if not (images/name).is_file(): raise SystemExit('ARM image layout incomplete')
qh=__import__('hashlib').sha256((qemu/'qemu-system-aarch64').read_bytes()).hexdigest()
print(json.dumps({'safe':True,'host':host_result,'images':image_result,'qemu':qemu_result,'qemu_aarch64_sha256':qh},sort_keys=True,separators=(',',':')))
'''

RUNTIME_OWNERSHIP = r'''import hashlib,json,os,pathlib,pwd,stat,subprocess,sys
root=pathlib.Path(sys.argv[1]);uid=int(sys.argv[2]);expected=sys.argv[3];root_expected=json.loads(sys.argv[4]);marker=sys.argv[5];qemu=root/'runtime/qemu/qemu-system-aarch64';user=pwd.getpwuid(uid);gid=user.pw_gid
fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);rs=os.fstat(fd)
observed={'dev':rs.st_dev,'inode':rs.st_ino,'uid':rs.st_uid,'gid':rs.st_gid,'mode':format(rs.st_mode&0o777,'04o')}
if observed!=root_expected or rs.st_uid!=0 or rs.st_mode&0o022:raise SystemExit('unsafe runtime root identity')
mf=os.open('marker',os.O_RDONLY|os.O_NOFOLLOW,dir_fd=fd);mb=os.read(mf,4096);os.close(mf)
if mb.decode()!=marker:raise SystemExit('runtime root marker changed')
dir_rows=[]
def open_owned(parent,name,path,allow_missing):
 try:d=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent);created=False
 except FileNotFoundError:
  if not allow_missing:raise
  os.mkdir(name,0o700,dir_fd=parent);d=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent);created=True
 ds=os.fstat(d)
 if ds.st_uid!=0 or ds.st_gid!=0 or ds.st_mode&0o022 or (ds.st_mode&0o777) not in (0o700,0o755):raise SystemExit('unsafe runtime directory identity')
 dir_rows.append({'path':str(path),'created':created,'dev':ds.st_dev,'inode':ds.st_ino,'uid':ds.st_uid,'gid':ds.st_gid,'mode':format(ds.st_mode&0o777,'04o')})
 return d
runtime_fd=open_owned(fd,'runtime',root/'runtime',False)
logs_fd=open_owned(fd,'logs',root/'logs',True);os.close(logs_fd)
for name in ('home','tmp','instance','assembly'):
 child=open_owned(runtime_fd,name,root/'runtime'/name,True);os.close(child)
os.close(runtime_fd)
def ident(p):
 s=p.lstat();return {'path':str(p),'dev':s.st_dev,'inode':s.st_ino,'uid':s.st_uid,'gid':s.st_gid,'mode':format(s.st_mode&0o777,'04o')}
root_before=ident(root);os.fchmod(fd,0o711);os.fsync(fd);root_after=ident(root)
if any(root_before[k]!=root_after[k] for k in ('path','dev','inode','uid','gid')) or root_after['mode']!='0711':raise SystemExit('runtime root traversal transition failed')
before=ident(qemu);h=hashlib.sha256(qemu.read_bytes()).hexdigest()
if h!=expected or not stat.S_ISREG(qemu.lstat().st_mode):raise SystemExit('QEMU identity changed before ownership')
for base in (root/'runtime',root/'logs'):
 for parent,dirs,files in os.walk(base,followlinks=False):
  for name in [*dirs,*files]:
   p=pathlib.Path(parent)/name;s=p.lstat()
   if not (stat.S_ISDIR(s.st_mode) or stat.S_ISREG(s.st_mode) or stat.S_ISLNK(s.st_mode)):raise SystemExit('unsafe runtime ownership entry')
   os.chown(p,uid,gid,follow_symlinks=False)
 os.chown(base,uid,gid,follow_symlinks=False)
for p in [root/'runtime'/x for x in ('home','tmp','instance','assembly')]+[root/'logs']:
 os.chmod(p,0o700,follow_symlinks=False)
os.fsync(fd);after=ident(qemu);os.close(fd)
if any(before[k]!=after[k] for k in ('path','dev','inode','mode')) or after['uid']!=uid or after['gid']!=gid or hashlib.sha256(qemu.read_bytes()).hexdigest()!=expected:raise SystemExit('QEMU identity changed during ownership')
code="import json,os,sys;print(json.dumps({'read':os.access(sys.argv[1],os.R_OK),'execute':os.access(sys.argv[1],os.X_OK)}))"
probe=subprocess.run(['/usr/bin/setpriv',f'--reuid={uid}',f'--regid={gid}','--clear-groups','/usr/bin/python3','-c',code,str(qemu)],capture_output=True,text=True,timeout=20)
try:access=json.loads(probe.stdout)
except Exception:access={}
write_code="import json,os,pathlib,sys;rows=[]\nfor raw in sys.argv[1:]:\n p=pathlib.Path(raw);q=p/'.amnezia-write-probe';fd=os.open(q,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);b=b'probe\\n';n=os.write(fd,b);os.fsync(fd);os.close(fd);n==len(b) or (_ for _ in ()).throw(OSError('short probe write'));os.unlink(q);rows.append({'path':raw,'write_delete':True})\nprint(json.dumps(rows,separators=(',',':')))"
mutable=[str(root/'runtime'/x) for x in ('home','tmp','instance','assembly')]+[str(root/'logs')]
wp=subprocess.run(['/usr/bin/setpriv',f'--reuid={uid}',f'--regid={gid}','--clear-groups','/usr/bin/python3','-c',write_code,*mutable],capture_output=True,text=True,timeout=20)
try:write_probes=json.loads(wp.stdout)
except Exception:write_probes=[]
print(json.dumps({'schema':1,'root':str(root),'root_before':root_before,'root_after':root_after,'directories':dir_rows,'runtime_uid':uid,'primary_gid':gid,'qemu_before':before,'qemu_after':after,'qemu_sha256':expected,'access_exit_code':probe.returncode,'access':access,'write_probe_exit_code':wp.returncode,'write_probes':write_probes,'origin':'guest','transport':'qga','injected':False},sort_keys=True,separators=(',',':')))
'''

BOOT_PROBE = r'''
import errno,hashlib,ipaddress,json,os,pathlib,re,stat,subprocess,sys,uuid
p=json.loads(sys.argv[1]); root=pathlib.Path(p['guest_root']); cg=pathlib.Path('/sys/fs/cgroup'+p['cgroup'])
def command(args):
 try: q=subprocess.run(args,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=3); rc=q.returncode; stdout=q.stdout; stderr=q.stderr
 except subprocess.TimeoutExpired as exc: rc=124; stdout=exc.stdout or ''; stderr=exc.stderr or ''
 if isinstance(stdout,bytes): stdout=stdout.decode(errors='replace')
 if isinstance(stderr,bytes): stderr=stderr.decode(errors='replace')
 return {'argv':args,'exit_code':rc,'stdout':stdout[:4096],'stdout_size':len(stdout),'stdout_sha256':hashlib.sha256(stdout.encode()).hexdigest(),'stderr':stderr[:4096],'stderr_size':len(stderr),'stderr_sha256':hashlib.sha256(stderr.encode()).hexdigest()}
def tail(name):
 q=root/'logs'/name
 try: return q.read_text(errors='replace')[-4096:]
 except OSError: return ''
try:
 ds=pathlib.Path('/dev/vhost-vsock').lstat();current_vhost={'path':'/dev/vhost-vsock','dev':ds.st_dev,'inode':ds.st_ino,'uid':ds.st_uid,'gid':ds.st_gid,'mode':format(ds.st_mode&0o777,'04o'),'rdev':ds.st_rdev,'char':stat.S_ISCHR(ds.st_mode)}
except OSError: current_vhost={}
if current_vhost!=p.get('vhost_vsock'):
 print(json.dumps({'ready':False,'fatal':True,'reason':'vhost-vsock-identity-changed','vhost_vsock':current_vhost}));raise SystemExit
if root.joinpath('marker').read_text()!=p['marker'] or not cg.joinpath('cgroup.procs').is_file():
 print(json.dumps({'ready':False,'fatal':p.get('qemu_seen') is True or p['poll_count']>=5,'reason':'containment-missing','qemu_seen':p.get('qemu_seen') is True,'logs':{'launch_stderr':tail('launch.stderr'),'adb_stderr':tail('adb.stderr')}})); raise SystemExit
pids=sorted({int(x) for x in cg.joinpath('cgroup.procs').read_text().split()})
if not pids:
 print(json.dumps({'ready':False,'fatal':p.get('qemu_seen') is True or p['poll_count']>=5,'reason':'owned-cgroup-empty','qemu_seen':p.get('qemu_seen') is True,'process_count':0,'cgroup':p['cgroup'],'processes':[],'logs':{'launch_stderr':tail('launch.stderr'),'adb_stderr':tail('adb.stderr')}})); raise SystemExit
def ident(pid):
 q=pathlib.Path('/proc')/str(pid); raw=q.joinpath('stat').read_text(); f=raw[raw.rfind(')')+2:].split(); cmd=q.joinpath('cmdline').read_bytes(); exe=q.joinpath('exe').resolve(strict=True)
 cgroups=[x.split(':',2)[-1] for x in q.joinpath('cgroup').read_text().splitlines() if x.startswith('0::')]
 status=q.joinpath('status').read_text(); uid=int(next(x for x in status.splitlines() if x.startswith('Uid:')).split()[1]); groups=[int(x) for x in next(x for x in status.splitlines() if x.startswith('Groups:')).split()[1:]]
 return {'pid':pid,'start_ticks':int(f[19]),'exe':str(exe),'exe_sha256':hashlib.sha256(exe.read_bytes()).hexdigest(),
  'uid':uid,'groups':groups,'state':f[0],'argv':[x.decode(errors='strict') for x in cmd.rstrip(b'\0').split(b'\0')],
  'cmdline_sha256':hashlib.sha256(cmd).hexdigest(),'cgroup':cgroups[0] if len(cgroups)==1 else ''}
processes=[]
for pid in pids:
 try: processes.append(ident(pid))
 except (OSError,UnicodeError,ValueError) as exc:
  try: current=sorted({int(x) for x in cg.joinpath('cgroup.procs').read_text().split()})
  except (OSError,ValueError) as reread:
   print(json.dumps({'ready':False,'fatal':True,'reason':'cgroup-reread-failed','failed_pid':pid,'operation':'process-identity','error_type':type(reread).__name__,'processes':processes,'cgroup':p['cgroup']})); raise SystemExit
  if isinstance(exc,OSError) and exc.errno in (errno.ENOENT,errno.ESRCH) and pid not in current and not (pathlib.Path('/proc')/str(pid)).exists(): continue
  print(json.dumps({'ready':False,'fatal':True,'reason':'process-identity-unreadable','failed_pid':pid,'operation':'process-identity','error_type':type(exc).__name__,'error_sha256':hashlib.sha256(str(exc).encode()).hexdigest(),'processes':processes,'cgroup':p['cgroup']})); raise SystemExit
try: current=sorted({int(x) for x in cg.joinpath('cgroup.procs').read_text().split()})
except (OSError,ValueError) as exc:
 print(json.dumps({'ready':False,'fatal':True,'reason':'cgroup-reread-failed','operation':'process-snapshot-finalize','error_type':type(exc).__name__,'processes':processes,'cgroup':p['cgroup']})); raise SystemExit
if current!=sorted(x['pid'] for x in processes):
 print(json.dumps({'ready':False,'fatal':False,'reason':'cgroup-changed-during-snapshot','member_pids':current,'processes':processes,'cgroup':p['cgroup']})); raise SystemExit
pids=current
def role(names):
 values=[x['pid'] for x in processes if pathlib.Path(x['exe']).name.lower() in names]
 return values[0] if len(values)==1 else None
roles={'assemble':role({'assemble_cvd'}),'cvd':role({'run_cvd'}),'adb':role({'adb'}),'qemu':role({'qemu-system-aarch64'})}
if roles['qemu'] is None or roles['adb'] is None:
 launch_pid=int((root/'session-leader.pid').read_text()) if (root/'session-leader.pid').is_file() else 0
 launcher_alive=any(x['pid']==launch_pid and x['state'] not in ('Z','X','x') for x in processes)
 launch_log=tail('launch.stderr')
 qemu_network_fatal='Failed to parse netmask' in launch_log or 'net=/255,host=' in launch_log
 exact_log_fatal=qemu_network_fatal or any(x in launch_log for x in ('Assertion getInstanceProcAddr failed','VM manager qemu_cli is not supported','Failed to get group id: cvdnetwork'))
 qemu_disappeared=p.get('qemu_seen') is True and roles['qemu'] is None
 assembly_alive=roles['assemble'] is not None
 valid_progress=assembly_alive or roles['cvd'] is not None or roles['qemu'] is not None
 assembly_stalled=(roles['qemu'] is None and p.get('assembly_elapsed_seconds',0)>=p.get('assembly_timeout_seconds',300))
 launcher_no_progress=(not p.get('assembly_seen') and not valid_progress and p.get('poll_count',0)>=30)
 assembly_vanished=(p.get('assembly_seen') is True and not assembly_alive and roles['cvd'] is None and roles['qemu'] is None)
 post_assembly_stalled=(p.get('assembly_seen') is True and not assembly_alive and roles['cvd'] is not None and roles['qemu'] is None and p.get('assembly_missing_polls',0)>=30)
 fatal=(not launcher_alive or exact_log_fatal or qemu_disappeared or launcher_no_progress or assembly_stalled or assembly_vanished or post_assembly_stalled)
 phase='qemu' if roles['qemu'] is not None else ('assemble' if assembly_alive else ('run-cvd' if roles['cvd'] is not None else 'launcher'))
 print(json.dumps({'ready':False,'fatal':fatal,
  'reason':'required-role-missing','launcher_pid':launch_pid,'launcher_alive':launcher_alive,
  'phase':phase,'valid_progress':valid_progress,'qemu_seen':p.get('qemu_seen') is True,'assembly_seen':p.get('assembly_seen') is True or assembly_alive,
  'qemu_network_fatal':qemu_network_fatal,'exact_log_fatal':exact_log_fatal,'qemu_disappeared':qemu_disappeared,
  'launcher_no_progress':launcher_no_progress,
  'assembly_elapsed_seconds':p.get('assembly_elapsed_seconds',0),'assembly_missing_polls':p.get('assembly_missing_polls',0),
  'processes':processes,'cgroup':p['cgroup'],'logs':{'launch_stderr':launch_log,'adb_stderr':tail('adb.stderr')}})); raise SystemExit
qemu=next(x for x in processes if x['pid']==roles['qemu']); netdev=[]; frontends=[]
for i,arg in enumerate(qemu['argv'][:-1]):
 if arg=='-netdev': netdev.append(qemu['argv'][i+1])
 if arg=='-device' and 'netdev=hostnet0' in qemu['argv'][i+1]: frontends.append(qemu['argv'][i+1])
if not netdev or any('net=/255' in x or 'host=,' in x for x in netdev):
 print(json.dumps({'ready':False,'fatal':True,'reason':'invalid-qemu-network-argv','phase':'qemu','qemu_seen':True,'network_argv':netdev})); raise SystemExit
hostnet0=[x for x in netdev if x.startswith('user,id=hostnet0,')]
if len(hostnet0)!=1:
 print(json.dumps({'ready':False,'fatal':True,'reason':'missing-hostnet0','phase':'qemu','qemu_seen':True,'network_argv':netdev})); raise SystemExit
parts=dict(x.split('=',1) for x in hostnet0[0].split(',')[2:] if '=' in x)
try:
 interface=ipaddress.ip_interface(parts['net']); gateway=ipaddress.ip_address(parts['host']); dns=ipaddress.ip_address(parts['dns'])
except (KeyError,ValueError):
 print(json.dumps({'ready':False,'fatal':True,'reason':'unparseable-hostnet0','phase':'qemu','qemu_seen':True,'network_argv':netdev})); raise SystemExit
if set(parts)!={'net','host','dns'} or interface.ip!=ipaddress.ip_address('10.0.2.15') or interface.network!=ipaddress.ip_network('10.0.2.0/24') or gateway!=ipaddress.ip_address('10.0.2.2') or dns!=ipaddress.ip_address('127.0.0.1'):
 print(json.dumps({'ready':False,'fatal':True,'reason':'unsafe-hostnet0','phase':'qemu','qemu_seen':True,'network_argv':netdev})); raise SystemExit
if len(frontends)!=1:
 print(json.dumps({'ready':False,'fatal':True,'reason':'missing-hostnet0-frontend','phase':'qemu','qemu_seen':True,'network_argv':netdev,'frontend_argv':frontends})); raise SystemExit
native={'schema':1,'records':[]}; config_paths=(root/'runtime/assembly/cuttlefish_config.json',root/'runtime/instance/assembly/cuttlefish_config.json',root/'runtime/instance/instances/cvd-1/cuttlefish_config.json')
try:
 adapter_raw=(root/'runtime/network-config-adapter.json').read_bytes(); adapter=json.loads(adapter_raw)
 if adapter.get('schema')!=2 or adapter.get('unique_target_writes')!=2 or adapter.get('alias')!={'path':str(root/'runtime/assembly'),'target':str(root/'runtime/instance/assembly')} or adapter.get('before_identical') is not True or adapter.get('after_identical') is not True or adapter.get('source_shape')!={'external_network_mode':'slirp','enable_modem_simulator':True,'ril_ipaddr':'','ril_gateway':'','ril_prefixlen':255,'ril_dns':''} or adapter.get('applied')!={'ril_ipaddr':'10.0.2.15','ril_gateway':'10.0.2.2','ril_prefixlen':24,'ril_dns':'10.0.2.3'}: raise ValueError('adapter receipt')
 native['adapter']={'path':str(root/'runtime/network-config-adapter.json'),'sha256':hashlib.sha256(adapter_raw).hexdigest(),'size':len(adapter_raw),'receipt':adapter}
 for path in config_paths:
  raw=path.read_bytes(); cfg=json.loads(raw); inst=cfg['instances']['1']
  if inst.get('external_network_mode')!='slirp' or inst.get('enable_modem_simulator') is not True or {k:inst.get(k) for k in ('ril_ipaddr','ril_gateway','ril_prefixlen','ril_dns')}!={'ril_ipaddr':'10.0.2.15','ril_gateway':'10.0.2.2','ril_prefixlen':24,'ril_dns':'10.0.2.3'}: raise ValueError('native network mode')
  native['records'].append({'path':str(path),'sha256':hashlib.sha256(raw).hexdigest(),'size':len(raw),'external_network_mode':'slirp','enable_modem_simulator':True,'ril_ipaddr':'10.0.2.15','ril_gateway':'10.0.2.2','ril_prefixlen':24,'ril_dns':'10.0.2.3'})
 if len({x['sha256'] for x in native['records']})!=1 or [x.get('path') for x in adapter['records']]!=[str(x) for x in config_paths] or any(x.get('order')!=i or x.get('target_order')!=(1 if i<3 else 2) for i,x in enumerate(adapter['records'],1)) or [x.get('after_sha256') for x in adapter['records']]!=[x['sha256'] for x in native['records']]: raise ValueError('adapter binding')
except (OSError,KeyError,TypeError,ValueError,json.JSONDecodeError) as exc:
 print(json.dumps({'ready':False,'fatal':True,'reason':'native-network-config-invalid','phase':'qemu','qemu_seen':True,'error_type':type(exc).__name__,'network_argv':netdev,'frontend_argv':frontends})); raise SystemExit
config_rows=[]; ports=[]
try:
 for item in native['records']:
  raw=pathlib.Path(item['path']).read_bytes(); cfg=json.loads(raw); inst=cfg['instances']['1']; fragment=cfg['fragments']['AdbConfigFragmentImpl']
  port=inst['adb_host_port']
  if isinstance(port,bool) or not isinstance(port,int) or not 1024<=port<=65535 or inst['adb_ip_and_port']!=f'0.0.0.0:{port}' or fragment!={'connector_enabled':True,'mode':['vsock_half_tunnel']}: raise ValueError('adb config binding')
  ports.append(port);config_rows.append({'path':item['path'],'sha256':hashlib.sha256(raw).hexdigest(),'size':len(raw),'adb_host_port':port,'adb_ip_and_port':inst['adb_ip_and_port']})
except (OSError,KeyError,TypeError,ValueError,json.JSONDecodeError) as exc:
 print(json.dumps({'ready':False,'fatal':True,'reason':'adb-config-binding-invalid','phase':'android-boot','qemu_seen':True,'error_type':type(exc).__name__,'processes':processes,'cgroup':p['cgroup']})); raise SystemExit
if len(set(ports))!=1:
 print(json.dumps({'ready':False,'fatal':True,'reason':'adb-config-port-ambiguous','phase':'android-boot','qemu_seen':True,'config_rows':config_rows,'processes':processes,'cgroup':p['cgroup']})); raise SystemExit
guest_port=ports[0]; endpoint=f'127.0.0.1:{guest_port}'
connectors=[x for x in processes if pathlib.Path(x['exe']).name=='adb_connector']
proxies=[]
for x in processes:
 if pathlib.Path(x['exe']).name!='socket_vsock_proxy': continue
 flags={a[2:].split('=',1)[0]:a[2:].split('=',1)[1] for a in x['argv'][1:] if a.startswith('--') and '=' in a}
 if flags.get('label')=='adb': proxies.append((x,flags))
if len(connectors)!=1 or connectors[0]['argv']!=[connectors[0]['exe'],f'--addresses=0.0.0.0:{guest_port}'] or len(proxies)!=1:
 print(json.dumps({'ready':False,'fatal':True,'reason':'adb-connector-binding-invalid','phase':'android-boot','qemu_seen':True,'endpoint':endpoint,'connector_count':len(connectors),'proxy_count':len(proxies),'config_rows':config_rows,'processes':processes,'cgroup':p['cgroup']})); raise SystemExit
proxy,proxy_flags=proxies[0]
if {k:proxy_flags.get(k) for k in ('server_type','server_tcp_port','client_type','client_vsock_port','client_vsock_id','label')}!={'server_type':'tcp','server_tcp_port':str(guest_port),'client_type':'vsock','client_vsock_port':'5555','client_vsock_id':str(p['vsock_cid']),'label':'adb'}:
 print(json.dumps({'ready':False,'fatal':True,'reason':'adb-vsock-proxy-binding-invalid','phase':'android-boot','qemu_seen':True,'endpoint':endpoint,'config_rows':config_rows,'processes':processes,'cgroup':p['cgroup']})); raise SystemExit
adb_binding={'endpoint':endpoint,'config_rows':config_rows,'connector_pid':connectors[0]['pid'],'proxy_pid':proxy['pid'],'connector_argv':connectors[0]['argv'],'proxy_argv':proxy['argv']}
adb=str(root/'runtime/host/bin/adb'); port=p['adb_endpoint'].rsplit(':',1)[1]
device_before=command([adb,'-P',port,'devices'])
if device_before['exit_code']!=0:
 print(json.dumps({'ready':False,'fatal':False,'reason':'adb-connect-command-failed','phase':'android-boot','qemu_seen':True,'adb_connection':{'endpoint':endpoint,'before':device_before,'binding':adb_binding},'processes':processes,'cgroup':p['cgroup']})); raise SystemExit
connect_probe=command([adb,'-P',port,'connect',endpoint])
if connect_probe['exit_code']!=0:
 print(json.dumps({'ready':False,'fatal':False,'reason':'adb-connect-command-failed','phase':'android-boot','qemu_seen':True,'adb_connection':{'endpoint':endpoint,'before':device_before,'connect':connect_probe,'binding':adb_binding},'processes':processes,'cgroup':p['cgroup']})); raise SystemExit
device_probe=command([adb,'-P',port,'devices']); adb_connection={'endpoint':endpoint,'before':device_before,'connect':connect_probe,'after':device_probe,'binding':adb_binding}
if device_probe['exit_code']!=0:
 print(json.dumps({'ready':False,'fatal':False,'reason':'adb-connect-command-failed','phase':'android-boot','qemu_seen':True,'adb_connection':adb_connection,'processes':processes,'cgroup':p['cgroup']})); raise SystemExit
lines=device_probe['stdout'].splitlines(); devices=[x.split()[0] for x in lines[1:] if x.strip().endswith('device')]
if devices!=[endpoint]:
 print(json.dumps({'ready':False,'fatal':len(devices)>1 or (len(devices)==1 and devices[0]!=endpoint),'reason':'adb-device-pending' if not devices else 'adb-device-ambiguous','phase':'android-boot','qemu_seen':True,'device_count':len(devices),'adb_connection':adb_connection,'processes':processes,'cgroup':p['cgroup']})); raise SystemExit
serial=endpoint
probes={}; abi_probe=command([adb,'-P',port,'-s',serial,'shell','getprop','ro.product.cpu.abi']);probes['abi']=abi_probe
if abi_probe['exit_code']!=0:
 print(json.dumps({'ready':False,'fatal':False,'reason':'adb-property-command-failed','phase':'android-boot','qemu_seen':True,'serial':serial.replace(':','_'),'adb_probes':probes,'processes':processes,'cgroup':p['cgroup']})); raise SystemExit
complete_probe=command([adb,'-P',port,'-s',serial,'shell','getprop','sys.boot_completed']);probes['boot_completed']=complete_probe
if complete_probe['exit_code']!=0:
 print(json.dumps({'ready':False,'fatal':False,'reason':'adb-property-command-failed','phase':'android-boot','qemu_seen':True,'serial':serial.replace(':','_'),'adb_probes':probes,'processes':processes,'cgroup':p['cgroup']})); raise SystemExit
boot_id_probe=command([adb,'-P',port,'-s',serial,'shell','cat','/proc/sys/kernel/random/boot_id']);probes['boot_id']=boot_id_probe
if boot_id_probe['exit_code']!=0:
 print(json.dumps({'ready':False,'fatal':False,'reason':'adb-property-command-failed','phase':'android-boot','qemu_seen':True,'serial':serial.replace(':','_'),'adb_probes':probes,'processes':processes,'cgroup':p['cgroup']})); raise SystemExit
abi=abi_probe['stdout'].strip(); complete=complete_probe['stdout'].strip(); boot_id=boot_id_probe['stdout'].strip()
if abi and abi!='arm64-v8a':
 print(json.dumps({'ready':False,'fatal':True,'reason':'unexpected-android-abi','phase':'android-boot','qemu_seen':True,'serial':serial.replace(':','_'),'abi':abi,'adb_probes':probes,'processes':processes,'cgroup':p['cgroup']})); raise SystemExit
if not abi or complete!='1' or not boot_id:
 print(json.dumps({'ready':False,'fatal':False,'reason':'android-boot-properties-pending','phase':'android-boot','qemu_seen':True,'serial':serial.replace(':','_'),'abi':abi,'boot_completed':complete,'adb_probes':probes,'processes':processes,'cgroup':p['cgroup']})); raise SystemExit
try: uuid.UUID(boot_id)
except ValueError:
 print(json.dumps({'ready':False,'fatal':True,'reason':'invalid-android-boot-id','phase':'android-boot','qemu_seen':True,'serial':serial.replace(':','_'),'boot_id_sha256':hashlib.sha256(boot_id.encode()).hexdigest(),'adb_probes':probes,'processes':processes,'cgroup':p['cgroup']})); raise SystemExit
network_commands={'link':['shell','ip','-details','link','show'],'address':['shell','ip','-4','addr','show'],'routes':['shell','ip','-4','route','show'],'endpoint_route':['shell','ip','-4','route','get','10.8.1.0'],'ril_state':['shell','getprop','init.svc.vendor.ril-daemon'],'ril_log':['shell','logcat','-d','-t','200','-v','threadtime','-b','main','-b','system','-b','events','RIL*:V','libcuttlefish-rild:V','init:I','*:S']}
network_evidence={name:command([adb,'-P',port,'-s',serial,*argv]) for name,argv in network_commands.items()}
def fail_network(reason):
 print(json.dumps({'ready':False,'fatal':True,'reason':reason,'phase':'android-network','qemu_seen':True,'network_argv':netdev,'frontend_argv':frontends,'native_config':native,'guest_network':network_evidence,'processes':processes,'cgroup':p['cgroup']}));raise SystemExit
if any(row['exit_code']!=0 for row in network_evidence.values()): fail_network('guest-network-capability-failed')
addr=network_evidence['address']['stdout']; routes=network_evidence['routes']['stdout']; route=network_evidence['endpoint_route']['stdout']
addresses=re.findall(r'\binet ([0-9.]+)/(\d+)',addr)
if not any(not ipaddress.ip_address(ip).is_loopback for ip,_ in addresses): fail_network('guest-nonloopback-ipv4-missing')
defaults=re.findall(r'(?m)^default(?: via ([0-9.]+))? dev (\S+)',routes)
if len(defaults)!=1 or not defaults[0][1] or not re.search(r'\bdev '+re.escape(defaults[0][1])+r'\b.*\bsrc ([0-9.]+)',route): fail_network('guest-default-or-endpoint-route-missing')
r={'schema':2,'operation':'nested-cuttlefish-boot','run_id':p['run_id'],'profile':p['profile'],'attempt_nonce':p['attempt_nonce'],
 'marker':p['marker'],'guest_root':p['guest_root'],'outer_ownership':p['outer_ownership'],'origin':'guest','transport':'qga','injected':False,
 'containment':{'kind':'cgroup-v2','path':p['cgroup'],'member_pids':pids,'stable_reads':p['stable_reads']},'processes':processes,'roles':{'cvd':roles['cvd'],'adb':roles['adb'],'qemu':roles['qemu']},
 'boot':{'abi':abi,'boot_completed':complete,'serial':serial.replace(':','_'),'boot_id':boot_id},'vsock_cid':p['vsock_cid'],
 'adb_endpoint':p['adb_endpoint'],'cvdnetwork_gid':p['cvdnetwork_gid'],'kvm_gid':p['kvm_gid'],'vhost_vsock':p['vhost_vsock'],'network':{'adb_listen':p['adb_endpoint'],'host_mutation':False,'host_mounts':[],'qemu_netdev_argv':netdev,'qemu_frontend_argv':frontends,'native_config':native,'guest_network':network_evidence,'adb_connection':adb_connection},'passed':True}
print(json.dumps(r,sort_keys=True,separators=(',',':')))
'''

FAILED_LAUNCH_CLEANUP = r'''
import hashlib,json,os,pathlib,signal,sys,time
p=json.loads(sys.argv[1]); expected=p['processes']; cg=pathlib.Path('/sys/fs/cgroup'+p['cgroup'])/'cgroup.procs'
def ident(item):
 q=pathlib.Path('/proc')/str(item['pid']); raw=q.joinpath('stat').read_text(); f=raw[raw.rfind(')')+2:].split(); cmd=q.joinpath('cmdline').read_bytes(); exe=q.joinpath('exe').resolve(strict=True)
 cgroups=[x.split(':',2)[-1] for x in q.joinpath('cgroup').read_text().splitlines() if x.startswith('0::')]
 status=q.joinpath('status').read_text(); uid=int(next(x for x in status.splitlines() if x.startswith('Uid:')).split()[1])
 return {'pid':item['pid'],'start_ticks':int(f[19]),'exe':str(exe),'exe_sha256':hashlib.sha256(exe.read_bytes()).hexdigest(),
  'uid':uid,'cmdline_sha256':hashlib.sha256(cmd).hexdigest(),'cgroup':cgroups[0] if len(cgroups)==1 else ''}
def check(item):
 cur=ident(item)
 for key in ('pid','start_ticks','exe','exe_sha256','uid','cmdline_sha256','cgroup'):
  if cur[key]!=item[key]: raise SystemExit('failed-launch identity changed: '+key)
 return cur
known={x['pid'] for x in expected}; actual={int(x) for x in cg.read_text().split()}
if actual!=known: raise SystemExit('failed-launch cgroup membership changed')
for item in sorted(expected,key=lambda x:x['pid'],reverse=True): check(item); os.kill(item['pid'],signal.SIGTERM)
deadline=time.monotonic()+10
while time.monotonic()<deadline:
 alive=[]
 for item in expected:
  try: alive.append(check(item))
  except (FileNotFoundError,ProcessLookupError): pass
 if not alive: print(json.dumps({'terminated_pids':sorted(known),'all_stopped':True})); raise SystemExit
 time.sleep(.1)
for item in expected:
 try: check(item); os.kill(item['pid'],signal.SIGKILL)
 except (FileNotFoundError,ProcessLookupError): pass
deadline=time.monotonic()+5
while time.monotonic()<deadline:
 if all(not (pathlib.Path('/proc')/str(x['pid'])).exists() for x in expected):
  print(json.dumps({'terminated_pids':sorted(known),'all_stopped':True})); raise SystemExit
 time.sleep(.1)
raise SystemExit('failed-launch owned process survived cleanup')
'''

class NestedCuttlefishQgaBridge:
    def __init__(self, qga: Any, plan: InnerPlan, outer_live_snapshot: Callable[[], Any],
                 *, clock: Callable[[], float]=time.monotonic, sleeper: Callable[[float],None]=time.sleep,
                 channel_factory: Callable[[Callable[[],None]],Any]|None=None,
                 failure_archive: Callable[[Mapping[str,Any]],Mapping[str,Any]]|None=None,
                 boot_failure_archive: Callable[[Mapping[str,Any]],Mapping[str,Any]]|None=None,
                 host_dependency_receipt: Mapping[str,Any]|None=None,
                 wayland_installer: Any|None=None, wayland_install_receipt: Mapping[str,Any]|None=None):
        plan.validate(); self.qga=qga; self.plan=plan; self.snapshot=outer_live_snapshot; self.clock=clock; self.sleep=sleeper
        self.channel_factory=channel_factory or (lambda check: PersistentQgaChannel(qga,check))
        self.failure_archive=failure_archive
        self.boot_failure_archive=boot_failure_archive
        self.host_dependency_receipt=dict(host_dependency_receipt) if isinstance(host_dependency_receipt,Mapping) else None
        self.wayland_installer=wayland_installer
        self.wayland_install_receipt=dict(wayland_install_receipt) if isinstance(wayland_install_receipt,Mapping) else None
        self.wayland_runtime_receipt=None
    def _check(self)->None:
        if self.snapshot()!=self.plan.ownership: raise NestedCuttlefishTransportError("outer ownership changed or is unavailable")
    def _request(self,name:str,args:Mapping[str,Any])->dict:
        self._check(); result=self.qga.request(name,dict(args))
        if not isinstance(result,Mapping) or "return" not in result: raise NestedCuttlefishTransportError(f"QGA {name} failed")
        return dict(result)
    def _exec_json(self,path:str,args:list[str],timeout:float)->dict:
        self._check(); result=self.qga.guest_exec_wait(path,args,timeout=timeout)
        try: value=json.loads(result.get("stdout",""))
        except (AttributeError,json.JSONDecodeError) as exc: raise NestedCuttlefishTransportError("guest command returned no JSON") from exc
        if not isinstance(value,dict): raise NestedCuttlefishTransportError("guest JSON is not an object")
        return value
    def _persistent_write(self,guest:str,source:BinaryIO,size:int,deadline:float,chunk_size:int)->tuple[dict,str]:
        digest=hashlib.sha256(); transcript_digest=hashlib.sha256(); chunk_count=0; offset=0
        with self.channel_factory(self._check) as channel:
            opened=channel.request("guest-file-open",{"path":guest,"mode":"w"})["return"]
            if not isinstance(opened,int) or isinstance(opened,bool): raise NestedCuttlefishTransportError("QGA returned no file handle")
            primary_error=None
            try:
                for chunk in iter_asset_chunks(source,expected_size=size,deadline_monotonic=deadline,chunk_size=chunk_size,now=self.clock):
                    row={k:v for k,v in chunk.items() if k!="data_b64"}
                    transcript_digest.update(json.dumps(row,sort_keys=True,separators=(",",":")).encode()+b"\n")
                    if chunk["eof"]: offset=chunk["offset"]; break
                    chunk_count+=1
                    data=base64.b64decode(chunk["data_b64"],validate=True); digest.update(data)
                    result=channel.request("guest-file-write",{"handle":opened,"buf-b64":chunk["data_b64"]})["return"]
                    write_count=result.get("count") if isinstance(result,Mapping) else None
                    if not isinstance(write_count,int) or isinstance(write_count,bool) or write_count!=chunk["size"]: raise NestedCuttlefishTransportError("QGA short write")
                channel.request("guest-file-flush",{"handle":opened})
            except BaseException as exc:
                primary_error=exc
                raise
            finally:
                try: channel.request("guest-file-close",{"handle":opened})
                except BaseException:
                    if primary_error is None: raise
        return {"chunk_count":chunk_count,"received_size":offset,"eof":True,"transcript_sha256":transcript_digest.hexdigest()},digest.hexdigest()
    def _negotiate_chunk_size(self,deadline:float)->int:
        guest=f"{self.plan.root}/input/.qga-frame-probe"
        for size in (256*1024,64*1024,32*1024):
            data=b"Q"*size
            try:
                transcript,digest=self._persistent_write(guest,__import__('io').BytesIO(data),size,deadline,size)
                proof=self._exec_json("/usr/bin/python3",["-c","import hashlib,json,pathlib,sys; p=pathlib.Path(sys.argv[1]); b=p.read_bytes(); print(json.dumps({'size':len(b),'sha256':hashlib.sha256(b).hexdigest()})); p.unlink()",guest],30)
                if proof.get("size")==size and proof.get("sha256")==digest and transcript.get("eof") is True: return size
            except (NestedCuttlefishError,OSError,ValueError):
                # A frame-size failure may fall back; an ownership change may
                # never be converted into a harmless negotiation miss.
                self._check()
                try: self._exec_json("/usr/bin/python3",["-c","import json,pathlib,sys; pathlib.Path(sys.argv[1]).unlink(missing_ok=True); print(json.dumps({'removed':True}))",guest],30)
                except NestedCuttlefishError: pass
        raise NestedCuttlefishTransportError("no QGA frame size passed exact probe/readback")
    def _stream(self,spec:AssetSpec,deadline:float,source:BinaryIO,chunk_size:int)->list[dict]:
        transcript,digest=self._persistent_write(f"{self.plan.root}/input/{spec.name}",source,spec.size,deadline,chunk_size)
        if digest!=spec.sha256: raise NestedCuttlefishTransportError("controller source hash differs from exact plan")
        return transcript
    def stage(self,open_source:Callable[[str],BinaryIO]=lambda p:open(p,"rb"))->dict:
        phase="ancestry-prep"; ancestry=None
        try:
            ancestry=self._exec_json("/usr/bin/python3",["-c",STAGE_PREP,self.plan.root,self.plan.marker,str(self.plan.runtime_uid)],30)
            phase="transfer";deadline=self.clock()+self.plan.transfer_timeout_seconds; transcripts={}; chunk_size=self._negotiate_chunk_size(deadline)
            specs=[*self.plan.assets,AssetSpec(self.plan.apk.name,self.plan.apk.source_path,self.plan.apk.size,self.plan.apk.sha256)]
            for spec in specs:
                with open_source(spec.source_path) as source: transcripts[spec.name]=self._stream(spec,deadline,source,chunk_size)
            phase="extract";extraction=self._exec_json("/usr/bin/python3",["-c",SAFE_EXTRACT,self.plan.root,self.plan.assets[0].name,self.plan.assets[1].name,self.plan.assets[2].name],300)
            if extraction.get("safe") is not True or extraction.get("qemu_aarch64_sha256") != self.plan.qemu_aarch64_sha256:raise NestedCuttlefishTransportError("guest extraction/QEMU identity did not pass")
            phase="runtime-ownership";runtime_ownership=self._exec_json("/usr/bin/python3",["-c",RUNTIME_OWNERSHIP,self.plan.root,str(self.plan.runtime_uid),self.plan.qemu_aarch64_sha256,json.dumps(ancestry["attempt"],separators=(",",":")),self.plan.marker],120)
            if (runtime_ownership.get("schema")!=1 or runtime_ownership.get("runtime_uid")!=self.plan.runtime_uid or runtime_ownership.get("qemu_sha256")!=self.plan.qemu_aarch64_sha256
                    or runtime_ownership.get("access_exit_code")!=0 or runtime_ownership.get("origin")!="guest" or runtime_ownership.get("transport")!="qga" or runtime_ownership.get("injected") is not False):raise NestedCuttlefishTransportError("runtime ownership preparation failed")
            if self.wayland_installer is not None:
                try:
                    from .nested_cuttlefish_wayland_dependency import WaylandDependencyInstaller
                except ImportError:
                    from nested_cuttlefish_wayland_dependency import WaylandDependencyInstaller
                if not isinstance(self.wayland_installer,WaylandDependencyInstaller) or self.wayland_install_receipt is None:raise NestedCuttlefishTransportError("Wayland dependency binding missing")
                qemu_path=f"{self.plan.root}/runtime/qemu/qemu-system-aarch64"
                self.wayland_runtime_receipt=self.wayland_installer.prove_runtime(self.wayland_install_receipt,qemu_path)
            phase="verify";stage_plan={"run_id":self.plan.ownership.run_id,"profile":self.plan.ownership.profile,"attempt_nonce":self.plan.ownership.attempt_nonce,
              "marker":self.plan.marker,"guest_root":self.plan.root,"outer_ownership":asdict(self.plan.ownership),"assets":[{**asdict(x),"guest_path":f"{self.plan.root}/input/{x.name}"} for x in specs],"guest_ancestry":ancestry,"runtime_ownership":runtime_ownership,"negotiated_chunk_size":chunk_size}
            receipt=self._exec_json("/usr/bin/python3",["-c",STAGE_VERIFY,json.dumps(stage_plan,separators=(",",":")),json.dumps(transcripts,separators=(",",":")),json.dumps(extraction,separators=(",",":"))],300)
            return validate_stage_receipt(self.plan,receipt)
        except BaseException as primary:
            failure={"schema":1,"outer_failure":"nested-boot","run_id":self.plan.ownership.run_id,"attempt_nonce":self.plan.ownership.attempt_nonce,"outer_ownership":asdict(self.plan.ownership),"phase":"stage-"+phase,"qemu_seen":False,"last_probe":{"ready":False,"stage_error":type(primary).__name__},"recorded_at":time.time()}
            archive_durable=False
            try:
                if not callable(self.boot_failure_archive):raise NestedCuttlefishTransportError("boot failure archive callback missing")
                ack=self.boot_failure_archive(failure)
                if not isinstance(ack,Mapping) or ack.get("origin")!="controller" or ack.get("immutable") is not True:raise NestedCuttlefishTransportError("stage failure archive rejected")
                archive_durable=True
            except BaseException as archive_error:
                if hasattr(primary,"add_note"):primary.add_note(f"stage failure archive also failed: {archive_error!r}")
            if archive_durable and isinstance(ancestry,Mapping):
                identity=ancestry.get("attempt")
                try:
                    if not isinstance(identity,Mapping) or set(identity)!={"dev","inode","uid","gid","mode"}:raise NestedCuttlefishTransportError("stage attempt identity unavailable for cleanup")
                    if any(not isinstance(identity.get(k),int) or isinstance(identity.get(k),bool) or identity[k]<0 for k in ("dev","inode","uid","gid")) or identity.get("mode")!="0700":raise NestedCuttlefishTransportError("stage attempt identity invalid for cleanup")
                    self._check()
                    removed=self._exec_json("/usr/bin/python3",["-c",PRELAUNCH_CLEANUP,self.plan.root,self.plan.marker,self.plan.ownership.run_id,self.plan.ownership.attempt_nonce,json.dumps(dict(identity),separators=(",",":"))],20)
                    if removed.get("removed") is not True:raise NestedCuttlefishTransportError("stage failure cleanup rejected")
                except BaseException as cleanup_error:
                    if hasattr(primary,"add_note"):primary.add_note(f"stage failure cleanup also failed: {cleanup_error!r}")
            elif isinstance(ancestry,Mapping) and hasattr(primary,"add_note"):
                primary.add_note(f"pending cleanup retained at {self.plan.root}; durable stage failure archive unavailable")
            raise

    def stage_additional_asset(self, spec: AssetSpec, open_source: Callable[[str], BinaryIO] = lambda p: open(p, "rb")) -> dict:
        """Stage one explicitly planned supplemental asset with the bounded QGA protocol."""
        spec.validate()
        if spec.name in {item.name for item in (*self.plan.assets, self.plan.apk)}:
            raise NestedCuttlefishTransportError("supplemental asset collides with the primary stage")
        deadline = self.clock() + self.plan.transfer_timeout_seconds
        chunk_size = self._negotiate_chunk_size(deadline)
        with open_source(spec.source_path) as source:
            transfer = self._stream(spec, deadline, source, chunk_size)
        guest_path = f"{self.plan.root}/input/{spec.name}"
        proof = self._exec_json("/usr/bin/python3", ["-c", "import hashlib,json,pathlib,sys;p=pathlib.Path(sys.argv[1]);b=p.read_bytes();print(json.dumps({'size':len(b),'sha256':hashlib.sha256(b).hexdigest()}))", guest_path], 60)
        if proof != {"size": spec.size, "sha256": spec.sha256}:
            raise NestedCuttlefishTransportError("supplemental guest asset rehash differs from plan")
        return {"name": spec.name, "guest_path": guest_path, "size": spec.size, "sha256": spec.sha256,
                "transfer": transfer, "guest_rehash": proof, "origin": "guest", "transport": "qga"}
    def launch_boot(self,stage_receipt:Mapping[str,Any])->dict:
        validate_stage_receipt(self.plan,stage_receipt); self._check()
        cleanup_identity=dict(stage_receipt["guest_root_identity"])
        group_provisioning=None
        def cleanup_prelaunch(primary:BaseException)->None:
            try:
                self._check(); removed=self._exec_json("/usr/bin/python3",["-c",PRELAUNCH_CLEANUP,self.plan.root,self.plan.marker,self.plan.ownership.run_id,self.plan.ownership.attempt_nonce,json.dumps(cleanup_identity,separators=(",",":"))],30)
                if removed.get("removed") is not True: raise NestedCuttlefishTransportError("prelaunch cleanup did not remove owned root")
            except BaseException as cleanup_error:
                if hasattr(primary,"add_note"):primary.add_note(f"prelaunch cleanup also failed: {cleanup_error!r}")
        try:
            group_provisioning=(self.host_dependency_receipt or {}).get("group_provisioning")
            if not isinstance(group_provisioning,Mapping):
                group_provisioning=self._exec_json("/usr/bin/python3",["-c",GROUP_PROVISION,str(self.plan.runtime_uid)],90)
            commands=group_provisioning.get("commands") if isinstance(group_provisioning,Mapping) else None
            files=group_provisioning.get("files") if isinstance(group_provisioning,Mapping) else None
            if (group_provisioning.get("schema")!=1 or group_provisioning.get("uid")!=self.plan.runtime_uid
                    or group_provisioning.get("created") is not True or group_provisioning.get("member") is not True
                    or group_provisioning.get("origin")!="guest" or group_provisioning.get("transport")!="qga" or group_provisioning.get("injected") is not False
                    or group_provisioning.get("kvm_modified") is not False or group_provisioning.get("vhost_modified") is not False
                    or not isinstance(files,list) or {x.get("path") for x in files if isinstance(x,Mapping)}!={"/etc/group","/etc/gshadow"}
                    or any(not re.fullmatch(r"[0-9a-f]{64}",str(x.get(k,""))) for x in files for k in ("before_sha256","after_sha256"))
                    or any(x.get("before_sha256")==x.get("after_sha256") for x in files)
                    or not isinstance(commands,list) or [x.get("argv") for x in commands] != [["/usr/sbin/groupadd","--system","cvdnetwork"],["/usr/sbin/usermod","-aG","cvdnetwork",group_provisioning.get("user")]]
                    or any(x.get("exit_code")!=0 or not re.fullmatch(r"[0-9a-f]{64}",str(x.get("exe_sha256","")))
                           or any(isinstance(x.get(k),bool) or not isinstance(x.get(k),int) or not 0<=x[k]<=4096 for k in ("stdout_size","stderr_size")) for x in commands)):
                raise NestedCuttlefishTransportError("guest cvdnetwork provisioning receipt invalid")
            group=self._exec_json("/usr/bin/python3",["-c",GROUP_PREFLIGHT,str(self.plan.runtime_uid)],30)
            cvd_gid=group.get("cvdnetwork_gid"); kvm_gid=group.get("kvm_gid"); primary_gid=group.get("primary_gid")
            if (group.get("ready") is not True or isinstance(cvd_gid,bool) or not isinstance(cvd_gid,int)
                    or isinstance(kvm_gid,bool) or not isinstance(kvm_gid,int) or kvm_gid<=0
                    or isinstance(primary_gid,bool) or not isinstance(primary_gid,int) or primary_gid<=0
                    or cvd_gid<=0 or group.get("preserved_supplementary_groups") != sorted([cvd_gid,kvm_gid])
                    or group.get("uid")!=group_provisioning.get("uid") or group.get("user")!=group_provisioning.get("user")
                    or primary_gid!=group_provisioning.get("primary_gid") or cvd_gid!=group_provisioning.get("cvdnetwork_gid")
                    or group.get("kvm_membership_modified") is not False or group.get("vhost_device_modified") is not False
                    or not isinstance(group.get("vhost_vsock"),Mapping) or group["vhost_vsock"].get("path")!="/dev/vhost-vsock"
                    or any(isinstance(group["vhost_vsock"].get(k),bool) or not isinstance(group["vhost_vsock"].get(k),int) or group["vhost_vsock"][k]<=0 for k in ("dev","inode","rdev"))
                    or group.get("vhost_access",{}).get("exit_code")!=0 or group.get("vhost_access",{}).get("result")!={"egid":primary_gid,"euid":self.plan.runtime_uid,"groups":sorted([cvd_gid,kvm_gid]),"read":True,"write":True}
                    or group["vhost_vsock"].get("uid")!=0 or group["vhost_vsock"].get("gid")!=kvm_gid or group["vhost_vsock"].get("mode")!="0660" or group["vhost_vsock"].get("char") is not True):
                raise NestedCuttlefishTransportError("runtime user lacks exact cvdnetwork-only group binding")
            vulkan=AssetSpec("libvulkan1_1.3.275.0-1build1_amd64.deb",self.plan.vulkan_deb_path,self.plan.vulkan_deb_size,self.plan.vulkan_deb_sha256)
            source_path=self.plan.vulkan_deb_path
            if os.name=="nt" and re.fullmatch(r"/mnt/[A-Za-z]/.+",source_path): source_path=source_path[5].upper()+":"+source_path[6:].replace("/",os.sep)
            staged_vulkan=self.stage_additional_asset(vulkan,lambda _path:open(source_path,"rb"))
            staged_vulkan["guest_root_identity"]=dict(cleanup_identity)
            dependency=self._exec_json("/usr/bin/python3",["-c",VULKAN_INSTALL,self.plan.root,vulkan.name,self.plan.vulkan_deb_sha256,str(self.plan.vulkan_deb_size),self.plan.vulkan_loader_sha256,str(self.plan.vulkan_loader_size),str(self.plan.runtime_uid),str(primary_gid),str(cvd_gid),self.plan.ownership.run_id,self.plan.ownership.attempt_nonce],90)
            expected_loader={"path":f"{self.plan.root}/runtime/private-libs/libvulkan.so.1.3.275","soname_path":f"{self.plan.root}/runtime/private-libs/libvulkan.so.1","sha256":self.plan.vulkan_loader_sha256,"size":self.plan.vulkan_loader_size,"uid":0,"mode":"0644","directory_uid":0,"directory_mode":"0755"}
            detector=dependency.get("graphics_detector") or {}
            if dependency.get("outer_failure"):
                failure={**dependency,"outer_ownership":asdict(self.plan.ownership),"guest_root_identity":dict(cleanup_identity)}
                if self.failure_archive is None: raise NestedCuttlefishTransportError("Vulkan failure archive callback missing")
                ack=self.failure_archive(failure)
                if (not isinstance(ack,Mapping) or ack.get("immutable") is not True or ack.get("origin")!="controller"
                    or not re.fullmatch(r"[0-9a-f]{64}",str(ack.get("sha256","")))
                    or isinstance(ack.get("size"),bool) or not isinstance(ack.get("size"),int) or ack["size"]<=0
                    or not isinstance(ack.get("path"),str) or not ack["path"]):
                    raise NestedCuttlefishTransportError("Vulkan failure archive acknowledgement invalid")
                raise NestedCuttlefishTransportError("guest Vulkan runtime dependency did not pass")
            output_file=detector.get("output_file") or {}
            if (dependency.get("loader")!=expected_loader or dependency.get("dlopen") is not True or dependency.get("vkGetInstanceProcAddr") is not True
                or detector.get("exit_code")!=0 or detector.get("assertion") is not False or detector.get("uid")!=self.plan.runtime_uid or detector.get("groups")!=[cvd_gid]
                or any(not re.fullmatch(r"[0-9a-f]{64}",str(detector.get(k,""))) for k in ("stdout_sha256","stderr_sha256"))
                or any(isinstance(detector.get(k),bool) or not isinstance(detector.get(k),int) or not 0<=detector[k]<=16384 for k in ("stdout_size","stderr_size"))
                or output_file.get("path")!=f"{self.plan.root}/runtime/graphics-probe/availability.pbtxt" or output_file.get("kind")!="regular"
                or output_file.get("uid")!=self.plan.runtime_uid or output_file.get("mode")!="0600" or output_file.get("eof") is not True
                or any(isinstance(output_file.get(k),bool) or not isinstance(output_file.get(k),int) or output_file[k]<=0 for k in ("dev","inode","gid"))
                or not re.fullmatch(r"[0-9a-f]{64}",str(output_file.get("sha256","")))
                or isinstance(output_file.get("size"),bool) or not isinstance(output_file.get("size"),int) or not 0<=output_file["size"]<=1048576):
                raise NestedCuttlefishTransportError("guest Vulkan runtime dependency did not pass")
            launch=self._exec_json("/usr/bin/python3",["-c","import json,pathlib,sys; p=pathlib.Path(sys.argv[1]); p.write_text(sys.argv[2]); p.chmod(0o700); print(json.dumps({'written':True}))",f"{self.plan.root}/launch.py",build_launch_script(self.plan)],30)
            if launch.get("written") is not True: raise NestedCuttlefishTransportError("guest launch script was not written")
        except BaseException as primary:
            try:
                record={"schema":1,"outer_failure":"nested-boot","run_id":self.plan.ownership.run_id,"attempt_nonce":self.plan.ownership.attempt_nonce,
                    "outer_ownership":asdict(self.plan.ownership),"phase":"group-provisioning","qemu_seen":False,"poll_count":0,"elapsed_seconds":0,
                    "reason":"prelaunch-prerequisite-failed","last_probe":{"group_provisioning":group_provisioning,"error_type":type(primary).__name__,"error_sha256":hashlib.sha256(str(primary).encode()).hexdigest()}}
                if self.boot_failure_archive is None: raise NestedCuttlefishTransportError("boot failure archive callback missing")
                ack=self.boot_failure_archive(record)
                if (not isinstance(ack,Mapping) or ack.get("origin")!="controller" or ack.get("immutable") is not True
                        or not isinstance(ack.get("path"),str) or not ack["path"] or not re.fullmatch(r"[0-9a-f]{64}",str(ack.get("sha256","")))
                        or isinstance(ack.get("size"),bool) or not isinstance(ack.get("size"),int) or ack["size"]<=0):
                    raise NestedCuttlefishTransportError("boot failure archive acknowledgement invalid")
            except BaseException as archive_error:
                if hasattr(primary,"add_note"):primary.add_note(f"prelaunch failure archive also failed: {archive_error!r}")
            cleanup_prelaunch(primary);raise
        # The trusted generated file is executed directly; no host shell is involved.
        self._check(); self.qga.guest_exec("/bin/sh",[f"{self.plan.root}/launch.py"])
        boot_started=self.clock();deadline=boot_started+self.plan.boot_timeout_seconds; previous=None; stable=0; poll_count=0;last_observed={}
        qemu_seen=False;assembly_seen=False;assembly_missing_polls=0;progress_key=None
        expected_cgroup=f"/amnezia-release-lab/{self.plan.ownership.run_id}/{self.plan.ownership.attempt_nonce}"
        def fail_boot(reason:str,observed:Mapping[str,Any],primary_error:BaseException|None=None)->None:
            raw=json.dumps(dict(observed),sort_keys=True,separators=(",",":"));logs=observed.get("logs") if isinstance(observed.get("logs"),Mapping) else {}
            probe_summary={k:observed.get(k) for k in ("ready","fatal","reason","phase","launcher_pid","launcher_alive","valid_progress","qemu_network_fatal","exact_log_fatal","qemu_disappeared","assembly_elapsed_seconds","assembly_missing_polls","roles","process_count","cgroup")}
            if isinstance(observed.get("probe_error"),Mapping):probe_summary["probe_error"]={k:observed["probe_error"].get(k) for k in ("type","sha256")}
            network_argv=observed.get("network_argv")
            if isinstance(network_argv,list):probe_summary["network_argv"]=[str(x)[:1024] for x in network_argv[:8]]
            probe_summary.update({"raw_sha256":hashlib.sha256(raw.encode()).hexdigest(),"raw_size":len(raw),"processes_sha256":hashlib.sha256(json.dumps(observed.get("processes",[]),sort_keys=True,separators=(",",":")).encode()).hexdigest(),
              "launch_stderr":str(logs.get("launch_stderr",''))[-2048:],"adb_stderr":str(logs.get("adb_stderr",''))[-1024:]})
            record={"schema":1,"outer_failure":"nested-boot","run_id":self.plan.ownership.run_id,
              "attempt_nonce":self.plan.ownership.attempt_nonce,"outer_ownership":asdict(self.plan.ownership),
              "phase":str(observed.get("phase") or "unknown"),"qemu_seen":qemu_seen,"poll_count":poll_count,
              "elapsed_seconds":max(0,self.clock()-boot_started),"reason":reason,"last_probe":probe_summary}
            primary=primary_error or NestedCuttlefishTransportError(f"nested launcher failed before boot: {json.dumps(record,sort_keys=True,separators=(',',':'))[:16384]}")
            if primary_error is not None and hasattr(primary,"add_note"):primary.add_note(f"nested boot probe failure: {json.dumps(record,sort_keys=True,separators=(',',':'))[:16384]}")
            archive_durable=False
            try:
                if self.boot_failure_archive is None: raise NestedCuttlefishTransportError("boot failure archive callback missing")
                ack=self.boot_failure_archive(record)
                if (not isinstance(ack,Mapping) or ack.get("origin")!="controller" or ack.get("immutable") is not True
                    or not isinstance(ack.get("path"),str) or not ack["path"] or not re.fullmatch(r"[0-9a-f]{64}",str(ack.get("sha256","")))
                    or isinstance(ack.get("size"),bool) or not isinstance(ack.get("size"),int) or ack["size"]<=0):
                    raise NestedCuttlefishTransportError("boot failure archive acknowledgement invalid")
                archive_durable=True
            except BaseException as archive_error:
                if hasattr(primary,"add_note"):primary.add_note(f"boot failure archive also failed: {archive_error!r}")
            processes=observed.get("processes")
            if archive_durable and isinstance(processes,list) and observed.get("cgroup")==expected_cgroup:
                try:
                    for item in processes:_proc(self.plan,"aux",item,expected_cgroup,cvd_gid,kvm_gid)
                    cleanup=self._exec_json("/usr/bin/python3",["-c",FAILED_LAUNCH_CLEANUP,json.dumps({"processes":processes,"cgroup":expected_cgroup},separators=(",",":"))],30)
                    if cleanup.get("all_stopped") is not True:raise NestedCuttlefishTransportError("failed-launch cleanup did not stop exact owned processes")
                except BaseException as cleanup_error:
                    if hasattr(primary,"add_note"):primary.add_note(f"failed-launch cleanup refused or failed: {cleanup_error!r}")
            elif not archive_durable and hasattr(primary,"add_note"):
                primary.add_note(f"pending cleanup retained because boot failure archive is not durable: cgroup={expected_cgroup} guest_root={self.plan.root}")
            raise primary
        while self.clock()<deadline:
            poll_count += 1
            payload={"run_id":self.plan.ownership.run_id,"profile":self.plan.ownership.profile,"attempt_nonce":self.plan.ownership.attempt_nonce,
              "marker":self.plan.marker,"guest_root":self.plan.root,"outer_ownership":asdict(self.plan.ownership),
              "cgroup":f"/amnezia-release-lab/{self.plan.ownership.run_id}/{self.plan.ownership.attempt_nonce}",
              "runtime_uid":self.plan.runtime_uid,"cvdnetwork_gid":cvd_gid,"kvm_gid":kvm_gid,"vhost_vsock":group["vhost_vsock"],"vsock_cid":self.plan.vsock_cid,"adb_endpoint":self.plan.adb_endpoint,"stable_reads":max(stable,2),"poll_count":poll_count,
              "qemu_seen":qemu_seen,"assembly_seen":assembly_seen,"assembly_missing_polls":assembly_missing_polls,
              "assembly_elapsed_seconds":max(0,self.clock()-boot_started),"assembly_timeout_seconds":min(300,self.plan.boot_timeout_seconds)}
            try:
                observed=self._exec_json("/usr/bin/python3",["-c",BOOT_PROBE,json.dumps(payload,separators=(",",":"))],30)
            except BaseException as probe_error:
                observed=dict(last_observed) if isinstance(last_observed,Mapping) else {}
                observed.update({"ready":False,"fatal":True,"reason":"boot-probe-transport-failed","phase":str(observed.get("phase") or "probe-transport"),"qemu_seen":qemu_seen,
                  "probe_error":{"type":type(probe_error).__name__,"sha256":hashlib.sha256(str(probe_error).encode()).hexdigest()}})
                fail_boot("boot-probe-transport-failed",observed,probe_error)
            last_observed=observed
            roles_observed=observed.get("roles") if isinstance(observed.get("roles"),Mapping) else {}
            if observed.get("qemu_seen") is True or roles_observed.get("qemu") is not None:qemu_seen=True
            if roles_observed.get("assemble") is not None:assembly_seen=True;assembly_missing_polls=0
            elif assembly_seen and roles_observed.get("qemu") is None:assembly_missing_polls+=1
            current_progress=(str(observed.get("phase") or "unknown"),str(observed.get("reason") or "unknown"),qemu_seen)
            if current_progress!=progress_key:
                print(json.dumps({"milestone":"nested-boot-progress","run_id":self.plan.ownership.run_id,"attempt_nonce":self.plan.ownership.attempt_nonce,"poll_count":poll_count,"phase":current_progress[0],"reason":current_progress[1],"qemu_seen":qemu_seen,"elapsed_seconds":max(0,self.clock()-boot_started)},sort_keys=True,separators=(",",":")),flush=True);progress_key=current_progress
            if observed.get("ready") is False:
                if observed.get("fatal") is True:
                    fail_boot(str(observed.get("reason") or "fatal-probe"),observed)
                stable=0; previous=None; self.sleep(1); continue
            members=observed.get("containment",{}).get("member_pids")
            stable=stable+1 if members==previous else 1; previous=members
            if stable>=2:
                observed["containment"]["stable_reads"]=stable
                prior_dependency=observed.get("runtime_dependency") if isinstance(observed.get("runtime_dependency"),Mapping) else {}
                observed["runtime_dependency"]={"group_provisioning":group_provisioning,"stage":staged_vulkan,"installed":dependency,"wayland_install":self.wayland_install_receipt or prior_dependency.get("wayland_install"),"wayland_runtime":self.wayland_runtime_receipt or prior_dependency.get("wayland_runtime")}
                return validate_boot_receipt(self.plan,observed)
            self.sleep(1)
        fail_boot("bounded-boot-timeout",last_observed)

    def cleanup(self, boot_receipt: Mapping[str, Any], timeout: int = 60) -> dict:
        """Stop only the exact boot-bound inner process set and prove absence."""
        boot = validate_boot_receipt(self.plan, boot_receipt)
        if isinstance(timeout, bool) or not isinstance(timeout, int) or not 40 <= timeout <= 120:
            raise NestedCuttlefishTransportError("cleanup timeout is invalid")
        self._check()
        result = self._exec_json("/usr/bin/python3", ["-c", build_cleanup_script(self.plan, boot)], timeout)
        expected = sorted(item["pid"] for item in boot["processes"])
        if result.get("terminated_pids") != expected or result.get("all_stopped") is not True or result.get("marker_removed") is not True:
            raise NestedCuttlefishTransportError("inner cleanup script returned incomplete evidence")
        probe = self._exec_json("/usr/bin/python3", ["-c", r'''import hashlib,json,pathlib,sys
root=pathlib.Path(sys.argv[1]); cg=pathlib.Path('/sys/fs/cgroup'+sys.argv[2]); pids=json.loads(sys.argv[3])
survivors=[p for p in pids if pathlib.Path('/proc',str(p)).exists()]
members=[]
try: members=[int(x) for x in cg.joinpath('cgroup.procs').read_text().split()]
except FileNotFoundError: pass
sockets=[]
if root.exists(): sockets=[str(p) for p in root.rglob('*') if p.is_socket()]
def summary(values):
 values=sorted(str(x) for x in values); raw=('\0'.join(values)).encode()
 return {'count':len(values),'sample':values[:32],'sha256':hashlib.sha256(raw).hexdigest()}
print(json.dumps({'survivors':survivors,'members':summary(members),'sockets':summary(sockets),'marker_exists':root.joinpath('marker').exists()}))''', self.plan.root, boot["containment"]["path"], json.dumps(expected, separators=(",", ":"))], 30)
        empty_summary={"count":0,"sample":[],"sha256":hashlib.sha256(b"").hexdigest()}
        expected_probe={"survivors":[],"members":empty_summary,"sockets":empty_summary,"marker_exists":False}
        if probe != expected_probe:
            bounded={k:probe.get(k) for k in ("survivors","members","sockets","marker_exists")}
            detail=json.dumps(bounded,sort_keys=True,separators=(",",":"))
            raise NestedCuttlefishTransportError(f"inner cleanup absence proof is incomplete: {detail[:4096]}")
        receipt = {
            "schema": 2, "operation": "nested-cuttlefish-cleanup",
            "run_id": self.plan.ownership.run_id, "profile": self.plan.ownership.profile,
            "attempt_nonce": self.plan.ownership.attempt_nonce, "marker": self.plan.marker,
            "guest_root": self.plan.root, "outer_ownership": asdict(self.plan.ownership),
            "origin": "guest", "transport": "qga", "injected": False,
            "terminated_pids": expected,
            "stopped_identities": [{"pid": item["pid"], "start_ticks": item["start_ticks"], "stopped": True} for item in boot["processes"]],
            "unknown_survivors": [], "owned_sockets_remaining": [],
            "all_stopped": True, "marker_removed": True, "passed": True,
        }
        return validate_cleanup_receipt(self.plan, receipt, boot)
