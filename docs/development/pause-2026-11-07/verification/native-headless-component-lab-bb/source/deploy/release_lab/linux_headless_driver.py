"""Concrete owned-guest wiring for the existing native headless validators.

This driver never signs or publishes. It keeps original guest observations and
uses the unchanged HTTP/update/rollback/reboot/cleanup validators. Preparation
is inert until the trusted controller calls it inside a live mutation session.
"""
from __future__ import annotations

import copy
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import tarfile
import time
from urllib.parse import urlparse

from .headless_native_acceptance import (Fixture, NativeUpdatePlan, OuterBinding, ReleaseBytes,
    UPDATE_STATE, validate_update_receipt, validate_rollback_receipt, validate_reboot_receipt)
from .headless_native_e2e_driver import HeadlessNativeE2EDriver, PreexistingQgaBridge, _state, capture_prevalidation, cleanup_server_after_failure, capture_server_reset_failure
from .headless_native_qga_adapter import HeadlessNativeQgaAdapter, HeadlessNativeQgaError
from .headless_native_http_fixture import HeadlessNativeHttpFixture
from .headless_native_reboot_collector import HeadlessNativeRebootCollector, SERVICE
from .headless_pending_observer import PendingObservation
from .headless_preexisting_fixture import BinaryIdentity, FixturePlan, validate_connected

PROFILE = 'linux-headless-x64'


class HeadlessDriverError(RuntimeError):
    pass


def _now():
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')


def _verified_record(record):
    path = Path(record['path'])
    if path.is_symlink() or not path.is_file() or path.stat().st_size != record['size']:
        raise HeadlessDriverError('planned file identity changed')
    with path.open('rb') as source: digest = hashlib.file_digest(source, 'sha256').hexdigest()
    if digest != record['sha256']: raise HeadlessDriverError('planned file hash changed')
    return path


def read_release(record, manifest_record, version, key_sha256):
    """Read only the exact two regular members of a hash-bound update archive."""
    path = _verified_record(record); _verified_record(manifest_record)
    blobs = {}
    with tarfile.open(path, 'r:gz') as archive:
        members = archive.getmembers()
        if len(members) != 2 or {x.name for x in members} != {'amneziad', 'amnezia-cli'}:
            raise HeadlessDriverError('update archive member set differs')
        for member in members:
            if not member.isreg() or not 0 < member.size <= 32 * 1024 * 1024:
                raise HeadlessDriverError('update archive member is unsafe')
            source = archive.extractfile(member)
            if source is None: raise HeadlessDriverError('update member unreadable')
            data = source.read(member.size + 1)
            if len(data) != member.size: raise HeadlessDriverError('update member size differs')
            blobs[member.name] = data
    _verified_record(record)
    release = ReleaseBytes(version, manifest_record['sha256'], manifest_record['size'],
        record['sha256'], record['size'], hashlib.sha256(blobs['amneziad']).hexdigest(), len(blobs['amneziad']),
        hashlib.sha256(blobs['amnezia-cli']).hexdigest(), len(blobs['amnezia-cli']), key_sha256)
    release.validate()
    return release, blobs


def outer_binding(vm):
    value = OuterBinding(vm['pid'], int(vm['proc_start_time']), vm['uuid'], vm['qmp_socket'], vm['qga_socket'])
    value.validate(); return value


class RebootOwnershipFence:
    """Read-only QEMU identity during the expected, explicit QGA reboot gap.

    No guest action or cleanup is permitted using this weaker transport state.
    Normal full owned_vm/QGA proof is mandatory immediately before reboot and
    again after QGA returns. PID/start/UID/argv/plan/marker/QMP remain checked
    throughout the bounded wait; ownership errors are never retryable.
    """
    def __init__(self, controller, run_id, binding):
        self.controller, self.run_id, self.binding = controller, run_id, copy.deepcopy(binding)
        self.run = copy.deepcopy(controller.get_run(run_id))
        directory = controller.root/'runs'/run_id/PROFILE
        self.marker = directory/'.owned-overlay.json'
        self.marker_bytes = self.marker.read_bytes()
        self.plan_path = controller.root/'runs'/run_id/'execution-plan.json'
        self.plan_sha = self.run.get('execution_plan_sha256')
        if not self.plan_sha or hashlib.sha256(self.plan_path.read_bytes()).hexdigest() != self.plan_sha:
            raise HeadlessDriverError('explicit execution plan required for reboot wait')

    def check(self):
        from .lab import QmpClient, proc_start_time, resolve_host_executable
        self.controller.assert_mutation_context()
        if self.controller._mutation_lock_depth <= 0 or self.controller._mutation_lock_fd is None:
            raise HeadlessDriverError('active mutation lock required')
        if self.controller.get_run(self.run_id) != self.run:
            raise HeadlessDriverError('run changed during reboot')
        vm = self.binding; proc = Path('/proc')/str(vm['pid'])
        if proc.stat().st_uid != vm['uid'] or proc_start_time(vm['pid']) != vm['proc_start_time']:
            raise HeadlessDriverError('QEMU PID/start/UID changed during reboot')
        actual = proc.joinpath('cmdline').read_bytes().rstrip(b'\0').split(b'\0')
        expected = [resolve_host_executable(vm['argv'][0]), *vm['argv'][1:]]
        if actual != [x.encode() for x in expected]: raise HeadlessDriverError('QEMU argv changed during reboot')
        if (self.marker.is_symlink() or self.marker.read_bytes() != self.marker_bytes
                or self.plan_path.is_symlink() or hashlib.sha256(self.plan_path.read_bytes()).hexdigest() != self.plan_sha):
            raise HeadlessDriverError('execution plan/overlay marker changed during reboot')
        qmp = QmpClient(Path(vm['qmp_socket']))
        if qmp.request('query-uuid').get('return', {}).get('UUID') != vm['uuid']:
            raise HeadlessDriverError('QMP UUID changed during reboot')
        if qmp.request('query-kvm').get('return', {}).get('enabled') is not False:
            raise HeadlessDriverError('TCG accelerator binding changed during reboot')
        return outer_binding(vm)


class OwnedRebootCollector(HeadlessNativeRebootCollector):
    def __init__(self, *args, process_fence, **kwargs):
        super().__init__(*args, **kwargs); self.process_fence = process_fence

    def reboot_and_collect(self, boot_id_before, expected, timeout=300):
        from .lab import LabError
        if type(timeout) is not int or not 0 < timeout <= 600: raise HeadlessDriverError('invalid reboot deadline')
        marker = self.stage_persistent_marker(); self._check()
        started = self.qga.guest_exec('/usr/bin/systemctl', ['reboot'])
        if type(started.get('pid')) is not int or started['pid'] <= 0: raise HeadlessDriverError('reboot request PID missing')
        deadline = self.clock() + timeout; after = ''
        while self.clock() < deadline:
            # Ownership failures remain fatal; only the expected QGA transport
            # unavailability is retried after this independent QMP proof.
            if self.process_fence.check() != self.plan.outer_binding:
                raise HeadlessDriverError('QEMU ownership changed during reboot')
            try:
                if self.qga.sync():
                    response = self.qga.guest_exec_wait('/usr/bin/cat', ['/proc/sys/kernel/random/boot_id'], timeout=min(10,max(1,deadline-self.clock())))
                    if response.get('exitcode') == 0: after = str(response.get('stdout','')).strip()
            except (OSError, socket.timeout, LabError, HeadlessNativeQgaError):
                pass
            if after and after != boot_id_before:
                self._check()  # full canonical QGA ownership before any reads
                break
            self.sleep(min(1,max(0,deadline-self.clock())))
        if not after or after == boot_id_before: raise HeadlessDriverError('bounded owned reboot/QGA wait expired')
        identity = self.native.identity(expected, 'post-reboot'); marker_after = self.native.raw_file(marker['path'])
        if (marker_after.get('sha256'),marker_after.get('size')) != (marker.get('sha256'),marker.get('size')):
            raise HeadlessDriverError('persistent marker changed across reboot')
        return {'boot_id_before':boot_id_before,'boot_id_after':after,'reboot_request_pid':started['pid'], 'after_raw':identity,
            'raw_sources':{'persistent_marker':marker_after,'service':self.native._json_record(SERVICE,[],'systemctl:amneziad.service'),
                'stable_state':self.native.raw_file(UPDATE_STATE), 'doctor':self.native.cli_json(['/usr/local/bin/amnezia-cli','--socket','/run/amnezia/amneziad.sock','--json','doctor'],'cli:doctor')}}


PROMOTE = r'''import hashlib,json,os,pathlib,signal,subprocess,sys,time
p=json.loads(sys.argv[1]);identity=json.loads(sys.argv[2]);cli_sha=sys.argv[3];root=pathlib.Path(p['owned_root'])
def exact(path,h):
 q=pathlib.Path(path)
 if q.is_symlink() or not q.is_file():raise RuntimeError('binary not regular')
 b=q.read_bytes()
 if hashlib.sha256(b).hexdigest()!=h:raise RuntimeError('binary hash mismatch')
 return b
def durable(path,data,mode):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
 with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
def replace(path,data):
 q=pathlib.Path(path);s=q.lstat();tmp=q.with_name(q.name+'.lab-promote');durable(tmp,data,s.st_mode&0o777);os.chown(tmp,s.st_uid,s.st_gid);os.replace(tmp,q);fd=os.open(q.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
dst=p['setup_daemon']['path'];cli=p['cli']['path'];old=exact(dst,p['setup_daemon']['sha256']);old_cli=exact(cli,p['cli']['sha256']);new=exact(p['legacy_daemon']['path'],p['legacy_daemon']['sha256']);new_cli=exact(root/'legacy/amnezia-cli',cli_sha)
proc=pathlib.Path('/proc')/str(identity['pid']);raw=proc.joinpath('stat').read_text();ticks=int(raw[raw.rfind(')')+2:].split()[19])
if ticks!=identity['start_ticks'] or hashlib.sha256(proc.joinpath('exe').read_bytes()).hexdigest()!=p['legacy_daemon']['sha256'] or hashlib.sha256(proc.joinpath('cmdline').read_bytes()).hexdigest()!=identity['cmdline_sha256']:raise RuntimeError('legacy identity changed')
durable(root/'setup-daemon.backup',old,0o600);durable(root/'setup-cli.backup',old_cli,0o600)
fd=os.pidfd_open(identity['pid'],0)
try:
 raw=proc.joinpath('stat').read_text()
 if (int(raw[raw.rfind(')')+2:].split()[19])!=identity['start_ticks'] or hashlib.sha256(proc.joinpath('exe').read_bytes()).hexdigest()!=p['legacy_daemon']['sha256'] or hashlib.sha256(proc.joinpath('cmdline').read_bytes()).hexdigest()!=identity['cmdline_sha256']):raise RuntimeError('legacy PID/exec changed')
 signal.pidfd_send_signal(fd,signal.SIGTERM)
finally:os.close(fd)
for _ in range(200):
 if not proc.exists() or proc.joinpath('stat').read_text().split(')',1)[1].split()[0]=='Z':break
 time.sleep(.05)
else:raise RuntimeError('legacy process survivor')
try:replace(dst,new);replace(cli,new_cli);subprocess.run(['systemctl','daemon-reload'],check=True);subprocess.run(['systemctl','start','amneziad.service'],check=True)
except BaseException:
 subprocess.run(['systemctl','stop','amneziad.service'],check=False);replace(dst,old);replace(cli,old_cli);raise
exact(dst,p['legacy_daemon']['sha256']);exact(cli,cli_sha)
print(json.dumps({'origin':'guest','transport':'qga','version':p['legacy_version'],'daemon_sha256':p['legacy_daemon']['sha256'],'cli_sha256':cli_sha,'backup_retained':True}))
'''


FIXTURE_CLEANUP = r'''import hashlib,json,os,pathlib,signal,stat,subprocess,sys,time
p=json.loads(sys.argv[1]);nonce=sys.argv[2];root=pathlib.Path(p['owned_root']);meta=json.loads((root/'fixture.json').read_text())
if meta['marker']!=(root/'marker').read_text().strip() or os.stat('/var/run/netns/'+p['netns']).st_ino!=meta['netns_inode']:raise RuntimeError('namespace ownership changed')
store=pathlib.Path('/var/lib/amnezia/profiles.json');s=store.lstat()
if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or stat.S_IMODE(s.st_mode)!=0o600:raise RuntimeError('profile store ownership changed')
value=json.loads(store.read_text());items=value.get('profiles') if isinstance(value,dict) else value
if not isinstance(items,list):raise RuntimeError('profile store shape')
matched=[x for x in items if isinstance(x,dict) and x.get('id')=='release-lab-'+nonce]
if len(matched)!=1 or matched[0].get('updateManifestUrl')!=p['native_manifest_url']:raise RuntimeError('owned update profile missing or changed')
matched[0]['autoUpdate']=False;tmp=store.with_name(store.name+'.lab-disable');fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
with os.fdopen(fd,'w') as f:json.dump(value,f,separators=(',',':'));f.flush();os.fsync(f.fileno())
os.replace(tmp,store);d=os.open(store.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(d);os.close(d)
result=subprocess.run(['/usr/local/bin/amnezia-cli','--socket',p['socket_path'],'--json','disconnect'],capture_output=True,text=True,check=True);result=json.loads(result.stdout)
if result.get('result',result).get('state')!='disconnected':raise RuntimeError('official disconnect failed')
subprocess.run(['systemctl','stop','amneziad.service'],check=True)
ident=meta['http'];proc=pathlib.Path('/proc')/str(ident['pid']);raw=proc.joinpath('stat').read_text()
if int(raw[raw.rfind(')')+2:].split()[19])!=ident['start_ticks'] or hashlib.sha256(proc.joinpath('cmdline').read_bytes()).hexdigest()!=ident['cmdline_sha256'] or hashlib.sha256(proc.joinpath('exe').read_bytes()).hexdigest()!=ident['exe_sha256']:raise RuntimeError('policy HTTP identity changed')
fd=os.pidfd_open(ident['pid'],0)
try:
 raw=proc.joinpath('stat').read_text()
 if int(raw[raw.rfind(')')+2:].split()[19])!=ident['start_ticks'] or hashlib.sha256(proc.joinpath('cmdline').read_bytes()).hexdigest()!=ident['cmdline_sha256'] or hashlib.sha256(proc.joinpath('exe').read_bytes()).hexdigest()!=ident['exe_sha256']:raise RuntimeError('policy HTTP PID/exec changed')
 signal.pidfd_send_signal(fd,signal.SIGTERM)
finally:os.close(fd)
for _ in range(100):
 if not proc.exists() or proc.joinpath('stat').read_text().split(')',1)[1].split()[0]=='Z':break
 time.sleep(.05)
else:raise RuntimeError('policy HTTP survivor')
subprocess.run(['/usr/sbin/ip','netns','del',p['netns']],check=True);subprocess.run(['/usr/sbin/ip','link','del',p['host_veth']],check=False,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
if pathlib.Path('/var/run/netns/'+p['netns']).exists() or pathlib.Path('/sys/class/net/'+p['host_veth']).exists():raise RuntimeError('namespace cleanup incomplete')
subprocess.run(['systemctl','start','amneziad.service'],check=True)
print(json.dumps({'origin':'guest','transport':'qga','network_removed':True,'update_profile_disabled':True,'baseline_binaries_preserved':True,'netns':p['netns'],'http_pid':ident['pid']}))
'''


DISABLE_UPDATE = r'''import json,os,pathlib,stat,subprocess,sys
nonce,url=sys.argv[1:];store=pathlib.Path('/var/lib/amnezia/profiles.json');s=store.lstat()
if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or stat.S_IMODE(s.st_mode)!=0o600:raise RuntimeError('profile store ownership changed')
value=json.loads(store.read_text());items=value.get('profiles') if isinstance(value,dict) else value
if not isinstance(items,list):raise RuntimeError('profile store shape')
owned=[x for x in items if isinstance(x,dict) and x.get('id')=='release-lab-'+nonce]
if len(owned)!=1 or owned[0].get('updateManifestUrl')!=url:raise RuntimeError('owned update profile changed')
owned[0]['autoUpdate']=False;temporary=store.with_name(store.name+'.lab-disable-before-http-stop');fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
with os.fdopen(fd,'w') as f:json.dump(value,f,separators=(',',':'));f.flush();os.fsync(f.fileno())
os.replace(temporary,store);d=os.open(store.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(d);os.close(d)
subprocess.run(['systemctl','restart','amneziad.service'],check=True)
print(json.dumps({'origin':'guest','transport':'qga','owned_update_profile_disabled':True,'profile_id':'release-lab-'+nonce}))
'''


PIN_STAGED_HELPER = r'''import hashlib,json,os,re,stat,sys
path,expected_sha,expected_size,nonce=sys.argv[1:]
if not re.fullmatch(r'[0-9a-f]{48}',nonce) or not re.fullmatch(r'[0-9a-f]{64}',expected_sha) or not expected_size.isdigit():raise SystemExit('helper binding syntax')
size=int(expected_size);parent_name='amnezia-headless-helper-'+nonce
if path!='/tmp/'+parent_name+'/helper.py' or not 0<size<=1048576:raise SystemExit('helper pinned path/size differs')
directory_flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW
root_fd=os.open('/',directory_flags);tmp_fd=parent_fd=helper_fd=None
def identity(value):return (value.st_dev,value.st_ino)
def same_parent():
 current_tmp=os.stat('tmp',dir_fd=root_fd,follow_symlinks=False)
 if not stat.S_ISDIR(current_tmp.st_mode) or identity(current_tmp)!=identity(os.fstat(tmp_fd)):raise SystemExit('tmp path changed')
 current=os.stat(parent_name,dir_fd=tmp_fd,follow_symlinks=False)
 if not stat.S_ISDIR(current.st_mode) or current.st_uid!=0 or stat.S_IMODE(current.st_mode)!=0o700 or identity(current)!=identity(os.fstat(parent_fd)):raise SystemExit('helper parent changed')
def same_path():
 same_parent();current=os.stat('helper.py',dir_fd=parent_fd,follow_symlinks=False)
 if not stat.S_ISREG(current.st_mode) or identity(current)!=identity(os.fstat(helper_fd)):raise SystemExit('helper path changed')
def verified_read():
 before=os.fstat(helper_fd)
 if not stat.S_ISREG(before.st_mode) or before.st_uid!=0 or before.st_nlink!=1 or before.st_size!=size:raise SystemExit('helper descriptor ownership/type/size differs')
 os.lseek(helper_fd,0,os.SEEK_SET);data=b''
 while len(data)<=size:
  chunk=os.read(helper_fd,min(65536,size+1-len(data)))
  if not chunk:break
  data+=chunk
 after=os.fstat(helper_fd)
 if (identity(before),before.st_size,before.st_uid,before.st_nlink,before.st_mtime_ns)!=(identity(after),after.st_size,after.st_uid,after.st_nlink,after.st_mtime_ns):raise SystemExit('helper changed during read')
 if len(data)!=size or hashlib.sha256(data).hexdigest()!=expected_sha:raise SystemExit('helper exact bytes differ')
 return after
try:
 root_stat=os.fstat(root_fd)
 if root_stat.st_uid!=0 or stat.S_IMODE(root_stat.st_mode)&0o022:raise SystemExit('root directory ownership differs')
 tmp_fd=os.open('tmp',directory_flags,dir_fd=root_fd);tmp_stat=os.fstat(tmp_fd)
 if tmp_stat.st_uid!=0 or (stat.S_IMODE(tmp_stat.st_mode)&0o022 and not tmp_stat.st_mode&stat.S_ISVTX):raise SystemExit('tmp directory ownership differs')
 parent_fd=os.open(parent_name,directory_flags,dir_fd=tmp_fd);parent_stat=os.fstat(parent_fd)
 if parent_stat.st_uid!=0 or stat.S_IMODE(parent_stat.st_mode)!=0o700:raise SystemExit('helper parent ownership/mode differs')
 same_parent()
 helper_fd=os.open('helper.py',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent_fd)
 verified_read();same_path()
 # Only this already verified original descriptor can be changed, never a
 # path reopened after verification. A swapped path is rejected again below.
 os.fchmod(helper_fd,0o600);os.fsync(helper_fd)
 after=verified_read();same_path()
 if stat.S_IMODE(after.st_mode)!=0o600:raise SystemExit('helper private mode readback differs')
 print(json.dumps({'sha256':expected_sha,'size':size,'mode':format(stat.S_IMODE(after.st_mode),'04o'),'uid':after.st_uid,'gid':after.st_gid,'device':after.st_dev,'inode':after.st_ino,'same_descriptor_verified':True}))
finally:
 for fd in (helper_fd,parent_fd,tmp_fd,root_fd):
  if fd is not None:os.close(fd)
'''


class PreparedPreexistingBridge(PreexistingQgaBridge):
    def __init__(self,*args,legacy_blobs,ownership_check,**kwargs):
        self.legacy_blobs,self.ownership_check=legacy_blobs,ownership_check
        self.ownership_check()
        super().__init__(*args,**kwargs)
        self.ownership_check()
        self.plan_path='/tmp/amnezia-headless-plan-'+self.plan.nonce+'.json'

    def _command(self,executable,args,timeout=120,capture_root=None,capture_name=None):
        self.ownership_check();response=self.qga.guest_exec_wait(executable,args,timeout=timeout);self.ownership_check()
        if capture_root is not None:capture_prevalidation(capture_root,capture_name,response)
        if type(response.get('exitcode')) is not int or response['exitcode']!=0:raise HeadlessDriverError('preexisting guest operation failed')
        return response

    def _run(self,action,*extra,timeout=120,capture_root=None):
        response=self._command('/usr/bin/python3',[self.script,action,'--plan',self.plan_path,*extra],timeout,capture_root,self.plan.nonce+'-'+action+'-response')
        result=json.loads(response['stdout'])
        if not isinstance(result,dict) or result.get('origin')!='guest' or result.get('transport')!='qga':raise HeadlessDriverError('preexisting guest receipt origin differs')
        return result

    def prepare_and_connect(self):
        self.ownership_check()
        observed=json.loads(self._command('/usr/bin/python3',['-c',PIN_STAGED_HELPER,self.script,self.script_sha,str(self.script_size),self.plan.nonce],30)['stdout'])
        if observed.get('sha256')!=self.script_sha or observed.get('size')!=self.script_size or observed.get('mode') not in ('0600','0700') or observed.get('uid')!=0:raise HeadlessDriverError('preexisting helper staging identity differs')
        self.qga.write_file(self.plan_path,(json.dumps(asdict(self.plan),sort_keys=True)+'\n').encode())
        self._run('prepare')
        self._command('/usr/bin/mkdir',['-m','0700',self.root+'/legacy'],20)
        for name,data in self.legacy_blobs.items():
            self.ownership_check()
            self.qga.write_file(self.root+'/legacy/'+name,data)
            self._command('/usr/bin/chmod',['0700',self.root+'/legacy/'+name],20)
        return validate_connected(self.plan,self._run('connect-collect','--deadline','90'))

    def promote_systemd_baseline(self,legacy):
        self.ownership_check()
        response=self.qga.guest_exec_wait('/usr/bin/python3',['-c',PROMOTE,json.dumps(asdict(self.plan)),json.dumps(legacy['daemon']),self.legacy_cli_sha256],timeout=120)
        self.ownership_check()
        if type(response.get('exitcode')) is not int or response['exitcode']!=0:raise HeadlessDriverError('baseline promotion failed')
        return json.loads(response['stdout'])

    def cleanup(self,active_receipt):
        self.ownership_check();payload={**asdict(self.plan),'netns':self.plan.netns,'host_veth':self.plan.host_veth,'native_manifest_url':self.native_manifest_url}
        response=self.qga.guest_exec_wait('/usr/bin/python3',['-c',FIXTURE_CLEANUP,json.dumps(payload),self.plan.nonce],timeout=120)
        self.ownership_check()
        if type(response.get('exitcode')) is not int or response['exitcode']!=0:raise HeadlessDriverError('owned fixture cleanup failed')
        value=json.loads(response['stdout'])
        if value.get('network_removed') is not True or value.get('baseline_binaries_preserved') is not True:raise HeadlessDriverError('fixture cleanup incomplete')
        return value

    def disable_update_profile(self):
        response=self._command('/usr/bin/python3',['-c',DISABLE_UPDATE,self.plan.nonce,self.native_manifest_url],120)
        value=json.loads(response['stdout'])
        if value.get('owned_update_profile_disabled') is not True or value.get('profile_id')!='release-lab-'+self.plan.nonce:raise HeadlessDriverError('owned updater profile not disabled')
        return value


class PreparedHeadlessDriver(HeadlessNativeE2EDriver):
    """Keep the old validators, correct event ordering and ephemeral lifecycle."""
    def run(self,*,update_timeout=600,rollback_timeout=600,reboot_timeout=300):
        self.plan.validate();http=None;server_started=False;fixture_started=False;primary=None
        try:
            connected=self.preexisting.prepare_and_connect();fixture_started=True
            archive=self._archive('preexisting-connected',connected)
            legacy=self.preexisting.crash_and_restart(connected,archive);self._archive('baseline-owned',legacy)
            self.preexisting.promote_systemd_baseline(legacy)
            before=self.native.identity(self.plan.baseline,'baseline-before');boot=self.preexisting.boot_id(legacy)
            doctor=self.native.cli_json(['/usr/local/bin/amnezia-cli','--socket','/run/amnezia/amneziad.sock','--json','doctor'],'cli:doctor')
            self.server.prevalidation_archive=self.archive_root;self.server.start();server_started=True;self.server.reset()
            with PendingObservation(self.native,'restart_pending',update_timeout,failure_archive=self.archive_root) as observation:
                staged=self.native.stage_profile()
                pending=observation.collect()
            stable=self.native.wait_for(self.native.collect_update_stable,lambda x:_state(x,'stable_state') in {'updated','no_update'},timeout=update_timeout,label='native update stable')
            after=self.native.identity(self.plan.candidate,'candidate-after');http=self.server.collect()
            update=self.native.build_update_receipt(before_raw=before,after_raw=after,boot_id=boot,raw_sources={'before_doctor':doctor,'profile_store':staged['profile_store'],**pending,**stable},http_receipt=http,observed_at=_now())
            capture_prevalidation(self.archive_root,self.plan.attempt_nonce+'-update',update);validate_update_receipt(self.plan,update,http);self._archive('update',update)
            # Capture the actual candidate before the rollback mutates its bytes.
            rb_before=self.native.identity(self.plan.candidate,'candidate-before')
            with PendingObservation(self.native,'rollback_restart_pending',rollback_timeout,failure_archive=self.archive_root) as observation:
                rb=self.collector.trigger_rollback(self.plan.candidate.cli_sha256)
                rb_pending=observation.collect()
            rb_stable=self.native.wait_for(self.native.collect_rollback_stable,lambda x:_state(x,'stable_state')=='rolled_back',timeout=rollback_timeout,label='rollback stable')
            rollback=self.native.build_rollback_receipt(before_raw=rb_before,after_raw=self.native.identity(self.plan.baseline,'baseline-after'),boot_id=boot,cli_process=rb['cli_process'],raw_sources={'cli_response':rb['cli_response'],**rb_pending,**rb_stable},update_receipt=update,observed_at=_now())
            capture_prevalidation(self.archive_root,self.plan.attempt_nonce+'-rollback',rollback);validate_rollback_receipt(self.plan,rollback,update);self._archive('rollback',rollback)
            # Network namespaces and fixture processes cannot survive a reboot.
            # Stop and prove their absence while they still have live identities.
            disabled=self.preexisting.disable_update_profile()
            cleanup=self.native.validate_fixture_cleanup(self.server.stop(http),http);server_started=False
            cleanup['update_profile_cleanup']=disabled
            cleanup['preexisting_cleanup']=self.preexisting.cleanup(rollback);fixture_started=False
            self._archive('fixture-cleanup',cleanup)
            observed=self.collector.reboot_and_collect(boot,self.plan.baseline,reboot_timeout)
            reboot=self.native.build_reboot_receipt(boot_id_before=observed['boot_id_before'],boot_id_after=observed['boot_id_after'],after_raw=observed['after_raw'],raw_sources=observed['raw_sources'],expected_release=self.plan.baseline,prior_receipt=rollback,observed_at=_now())
            capture_prevalidation(self.archive_root,self.plan.attempt_nonce+'-reboot',reboot);validate_reboot_receipt(self.plan,reboot,self.plan.baseline,rollback);self._archive('reboot',reboot)
            return {'http':http,'update':update,'rollback':rollback,'reboot':reboot,'cleanup':cleanup}
        except BaseException as error:
            primary=error
            capture_server_reset_failure(self.server,self.archive_root,self.plan.attempt_nonce,primary)
            try:self._archive('failure',{'error_type':type(error).__name__,'error':str(error),'observed_at':_now()})
            except BaseException as archive_error:error.add_note('failure archive failed: '+str(archive_error))
            raise
        finally:
            if primary is not None:
                if server_started:
                    try:cleanup_server_after_failure(self.server,http,primary)
                    except BaseException as error:primary.add_note('HTTP fixture cleanup failed: '+str(error))
                if fixture_started:
                    try:self.preexisting.cleanup({})
                    except BaseException as error:primary.add_note('preexisting fixture cleanup failed: '+str(error))



PROTECTED_INPUT_PROGRAM=r'''
import os,stat,json,hashlib,sys,re
operation,nonce,parent,expected_json,pins_json=sys.argv[1:]
if operation not in ('prepare','verify','cleanup') or not re.fullmatch('[0-9a-f]{48}',nonce):raise RuntimeError('fixed input operation/nonce')
expected=json.loads(expected_json);pins=json.loads(pins_json)
names=[nonce+'-manifest.json',nonce+'-candidate.tar.gz']
if set(expected)!=set(names):raise RuntimeError('exact fixture input set required')
if parent!='/var/lib/amnezia-release-lab/fixture':raise RuntimeError('fixed input parent')
def directory(path):
 fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:
  for part in path.strip('/').split('/'):
   new=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=new;s=os.fstat(fd)
   if s.st_uid!=0 or s.st_mode&0o022:raise RuntimeError('unsafe fixture ancestor')
  if stat.S_IMODE(os.fstat(fd).st_mode)!=0o700:raise RuntimeError('fixture parent must be private')
  return fd
 except BaseException:os.close(fd);raise
def identity(s):return [s.st_dev,s.st_ino,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode),s.st_nlink]
def checked(fd):
 s=os.fstat(fd)
 if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or stat.S_IMODE(s.st_mode)!=0o600 or s.st_nlink!=1:raise RuntimeError('unsafe fixture input')
 return s
parent_fd=directory(parent);parent_identity=identity(os.fstat(parent_fd));created={}
def fence():
 fresh=directory(parent)
 try:
  if identity(os.fstat(fresh))!=parent_identity:raise RuntimeError('fixture parent changed')
 finally:os.close(fresh)
try:
 if operation=='prepare':
  try:
   for name in names:
    fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent_fd)
    try:created[name]=identity(checked(fd));os.fsync(fd)
    finally:os.close(fd)
   os.fsync(parent_fd);fence()
  except BaseException as primary:
   for name,pin in created.items():
    try:
     current=os.stat(name,dir_fd=parent_fd,follow_symlinks=False)
     if identity(current)==pin:os.unlink(name,dir_fd=parent_fd)
    except BaseException as secondary:primary.add_note('Partial input cleanup unavailable: '+type(secondary).__name__)
   raise
  print(json.dumps({'parent':parent_identity,'files':created},separators=(',',':')))
 else:
  if pins.get('parent')!=parent_identity or set(pins.get('files',{}))!=set(names):raise RuntimeError('fixture ownership pins')
  for name in names:
   fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent_fd)
   try:
    before=checked(fd)
    if identity(before)!=pins['files'][name]:raise RuntimeError('fixture input inode changed')
    if operation=='verify':
     wanted=expected[name]
     if type(wanted['size']) is not int or before.st_size!=wanted['size']:raise RuntimeError('fixture input size')
     digest=hashlib.sha256();remaining=before.st_size
     while remaining:
      data=os.read(fd,min(65536,remaining))
      if not data:raise RuntimeError('fixture input short read')
      remaining-=len(data);digest.update(data)
     after=os.fstat(fd)
     if digest.hexdigest()!=wanted['sha256'] or (before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_size,after.st_mtime_ns,after.st_ctime_ns):raise RuntimeError('fixture input content changed')
    named=os.stat(name,dir_fd=parent_fd,follow_symlinks=False)
    if identity(named)!=identity(before):raise RuntimeError('fixture input path changed')
    fence()
    if operation=='cleanup':os.unlink(name,dir_fd=parent_fd)
   finally:os.close(fd)
  print(json.dumps({'verified':operation=='verify','cleaned':operation=='cleanup'}))
finally:os.close(parent_fd)
'''

def _write_protected_fixture_inputs(qga,owned,nonce,stage,inputs):
    expected={Path(path).name:{'size':len(data),'sha256':hashlib.sha256(data).hexdigest()} for path,data in inputs}
    def command(operation,pins):
        owned()
        result=qga.guest_exec_wait('/usr/bin/python3',['-c',PROTECTED_INPUT_PROGRAM,operation,nonce,stage,json.dumps(expected,separators=(',',':')),json.dumps(pins,separators=(',',':'))],timeout=120)
        owned()
        if type(result.get('exitcode')) is not int or result['exitcode']!=0:raise HeadlessDriverError('protected fixture input '+operation+' failed')
        return json.loads(result['stdout'])
    pins=command('prepare',{})
    try:
        for path,data in inputs:owned();qga.write_file(path,data);owned()
        command('verify',pins)
    except BaseException as primary:
        try:command('cleanup',pins)
        except BaseException as secondary:primary.add_note('Protected input cleanup unavailable: '+type(secondary).__name__)
        raise

def build_headless_driver(controller,run_id,context,*,protected_fixture_inputs=False):
    """Bind exact full manifests/artifacts and stage only into the owned guest."""
    from .lab import LabController,QgaClient,validate_signed_manifest
    from .trusted_acquisition_export import AcquisitionContext
    if type(controller) is not LabController or controller.dry_run or controller.test_mode or type(context) is not AcquisitionContext:
        raise HeadlessDriverError('live canonical controller/context required')
    controller.assert_mutation_context()
    if controller._mutation_lock_depth<=0 or controller._mutation_lock_fd is None:raise HeadlessDriverError('active mutation session required')
    context.verify();run=copy.deepcopy(controller.get_run(run_id));vm=copy.deepcopy(controller.owned_vm(run_id,PROFILE))
    if run['manifest']!=context.manifest or run['outer_artifact']!=context.outer or run['candidate_version']!=context.version:
        raise HeadlessDriverError('release context differs from live run')
    validate_signed_manifest(Path(run['manifest']['path']),context.public_key,version=run['candidate_version'],artifacts=run['artifacts'])
    validate_signed_manifest(Path(run['baseline_manifest']['path']),context.public_key,version=run['baseline_version'],artifacts=run['baseline_artifacts'])
    for record in [*run['artifacts'].values(),*run['baseline_artifacts'].values(),*run['semantic_helper_records'].values()]:_verified_record(record)
    baseline,legacy_blobs=read_release(run['baseline_artifacts']['linux-headless-x64'],run['baseline_manifest'],run['baseline_version'],context.public_key_record['sha256'])
    candidate,_=read_release(run['artifacts']['linux-headless-x64'],run['manifest'],run['candidate_version'],context.public_key_record['sha256'])
    def owned():
        context.verify()
        fresh=controller.owned_vm(run_id,PROFILE)
        if fresh!=vm or controller.get_run(run_id)!=run:raise HeadlessDriverError('live run/guest changed')
        return outer_binding(fresh)
    qga=QgaClient(Path(vm['qga_socket']));nonce=secrets.token_hex(24);guest_root='/var/lib/amnezia-release-lab/native-'+nonce
    uid_response=qga.guest_exec_wait('/usr/bin/id',['-u','lab'],timeout=20)
    if type(uid_response.get('exitcode')) is not int or uid_response['exitcode']!=0:raise HeadlessDriverError('guest lab user unavailable')
    uid=int(uid_response['stdout'].strip())
    fixture_plan=FixturePlan(run_id,PROFILE,nonce,secrets.token_hex(24),uid,guest_root,'/run/amnezia/amneziad.sock',BinaryIdentity('/usr/local/bin/amnezia-cli',candidate.cli_sha256),BinaryIdentity('/usr/local/bin/amneziad',candidate.amneziad_sha256),BinaryIdentity(guest_root+'/legacy/amneziad',baseline.amneziad_sha256),candidate.version,baseline.version)
    fixture_plan.validate();endpoint='http://'+fixture_plan.underlay_host+':17866'
    artifact_url=context.manifest_payload['platforms']['linux-headless-x64']['url']
    parsed=urlparse(artifact_url)
    if parsed.scheme or parsed.netloc or not parsed.path or parsed.query or parsed.fragment:raise HeadlessDriverError('headless artifact URL not relative')
    plan=NativeUpdatePlan(run_id,'native-headless',nonce,_now(),outer_binding(vm),baseline,candidate,Fixture(endpoint,(fixture_plan.underlay_host+'/32',),nonce,'/manifest.json','/'+parsed.path))
    plan.validate();native=HeadlessNativeQgaAdapter(qga,plan,owned)
    helper=run['semantic_helper_records']['deploy/release_lab/headless_preexisting_fixture_guest.py']
    helper_dir='/tmp/amnezia-headless-helper-'+nonce;owned();mkdir_helper=qga.guest_exec_wait('/usr/bin/mkdir',['-m','0700',helper_dir],timeout=20);owned()
    if type(mkdir_helper.get('exitcode')) is not int or mkdir_helper['exitcode']!=0:raise HeadlessDriverError('private guest helper directory unavailable')
    companion=run['semantic_helper_records']['deploy/release_lab/headless_preexisting_fixture.py'];qga.write_file(helper_dir+'/headless_preexisting_fixture.py',Path(companion['path']).read_bytes());owned()
    bridge=PreparedPreexistingBridge(qga,fixture_plan,Path(helper['path']),helper_dir+'/helper.py',legacy_blobs=legacy_blobs,ownership_check=owned)
    bridge.legacy_cli_sha256=baseline.cli_sha256
    bridge.native_manifest_url=endpoint+'/manifest.json'
    stage='/var/lib/amnezia-release-lab/fixture';owned();mkdir_result=qga.guest_exec_wait('/usr/bin/mkdir',['-p','-m','0700',stage],timeout=20);owned()
    if type(mkdir_result.get('exitcode')) is not int or mkdir_result['exitcode']!=0:raise HeadlessDriverError('fixture staging directory unavailable')
    manifest_guest=stage+'/'+nonce+'-manifest.json';artifact_guest=stage+'/'+nonce+'-candidate.tar.gz';log=stage+'/'+nonce+'-requests.jsonl'
    if type(protected_fixture_inputs) is not bool:raise HeadlessDriverError('protected fixture input option must be boolean')
    if protected_fixture_inputs:
        _write_protected_fixture_inputs(qga,owned,nonce,stage,[(manifest_guest,Path(run['manifest']['path']).read_bytes()),(artifact_guest,Path(run['artifacts']['linux-headless-x64']['path']).read_bytes())])
    else:
        qga.write_file(manifest_guest,Path(run['manifest']['path']).read_bytes());qga.write_file(artifact_guest,Path(run['artifacts']['linux-headless-x64']['path']).read_bytes())

    def server_snapshot():return {**vm,'proc_start_time':int(vm['proc_start_time'])} if owned() else None
    server=HeadlessNativeHttpFixture(qga,plan,server_snapshot(),server_snapshot,manifest_guest_path=manifest_guest,artifact_guest_path=artifact_guest,request_log=log)
    collector=OwnedRebootCollector(qga,plan,native,owned,process_fence=RebootOwnershipFence(controller,run_id,vm))
    archive=controller.root/'receipts'/run_id/'headless-native';archive.mkdir(parents=True,exist_ok=True)
    return PreparedHeadlessDriver(plan,native,server,bridge,collector,archive)
