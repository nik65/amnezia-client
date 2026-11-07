from __future__ import annotations

import hashlib
import inspect
import json
import math
import os
import re
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

SUPPLEMENT_SHA = "3b2a227cf05c5f104defc0f56c186c77f7fbf9d608177224c775cd4adb590845"
SUPPLEMENT_SIZE = 61440
DEB_NAME = "libwayland-server0_1.22.0-2.1build1_amd64.deb"
DEB_SHA = "edbfa4b6857691ae922cc768a753fab230eee9e956aa2ce4f2eaa8d9ad777dca"
DEB_SIZE = 33928
PACKAGE = "libwayland-server0"
VERSION = "1.22.0-2.1build1"
ARCH = "amd64"
VERIFIER_SHA = "6e2d61bd7996269ea2c69ac1d1d2349e2729cedc72d5ff14d189b231f25334b0"
VERIFIER_SIZE = 22252
SHA = re.compile(r"[0-9a-f]{64}")

MKROOT = r'''import hashlib,json,os,sys
nonce=sys.argv[1];fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
for part in ('var','lib','amnezia-release-lab'):
 n=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=n;s=os.fstat(fd)
 if s.st_uid!=0 or s.st_mode&0o022:raise SystemExit('unsafe Wayland ancestry')
try:n=os.open('wayland',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
except FileNotFoundError:os.mkdir('wayland',0o700,dir_fd=fd);n=os.open('wayland',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
os.close(fd);fd=n;s=os.fstat(fd)
if s.st_uid!=0 or s.st_mode&0o022:raise SystemExit('unsafe Wayland parent')
os.mkdir(nonce,0o700,dir_fd=fd);child=os.open(nonce,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);s=os.fstat(child)
b=(nonce+'\n').encode();m=os.open('.owner',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=child);os.write(m,b);os.fsync(m);os.close(m);os.fsync(child)
print(json.dumps({'dev':s.st_dev,'inode':s.st_ino,'uid':s.st_uid,'gid':s.st_gid,'mode':s.st_mode&0o777,'marker_sha256':hashlib.sha256(b).hexdigest()}))
'''

CLEANUP = r'''import hashlib,os,stat,sys
nonce=sys.argv[1];dev=int(sys.argv[2]);ino=int(sys.argv[3]);marker=sys.argv[4];fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
for part in ('var','lib','amnezia-release-lab','wayland'):
 n=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=n
child=os.open(nonce,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);s=os.fstat(child)
if (s.st_dev,s.st_ino,s.st_uid,s.st_mode&0o777)!=(dev,ino,0,0o700):raise SystemExit('Wayland root identity changed')
m=os.open('.owner',os.O_RDONLY|os.O_NOFOLLOW,dir_fd=child);b=os.read(m,128);os.close(m)
if hashlib.sha256(b).hexdigest()!=marker:raise SystemExit('Wayland marker changed')
allowed={'supplement.tar','libwayland-server0_1.22.0-2.1build1_amd64.deb','.owner'}
if set(os.listdir(child))-allowed:raise SystemExit('unexpected Wayland cleanup entry')
for name in ('supplement.tar','libwayland-server0_1.22.0-2.1build1_amd64.deb'):
 try:
  st=os.stat(name,dir_fd=child,follow_symlinks=False)
 except FileNotFoundError:continue
 if not stat.S_ISREG(st.st_mode):raise SystemExit('unsafe Wayland cleanup entry')
 os.unlink(name,dir_fd=child)
os.fsync(child);os.unlink('.owner',dir_fd=child);os.fsync(child);os.close(child);os.rmdir(nonce,dir_fd=fd);os.fsync(fd);os.close(fd)
'''


class WaylandDependencyError(RuntimeError):
    pass


def _sha(path: Path) -> tuple[str, int]:
    h = hashlib.sha256(); size = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk); size += len(chunk)
    return h.hexdigest(), size


def validate_wayland_verifier(path: Path) -> dict:
    if _sha(path)!=(VERIFIER_SHA,VERIFIER_SIZE):raise WaylandDependencyError("Wayland signed verifier bytes changed")
    try:value=json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:raise WaylandDependencyError("Wayland signed verifier unreadable") from exc
    rows=value.get("packages")
    if (value.get("validated") is not True or value.get("kind")!="android-cvd-host-and-wayland-dependency-signed-index-verifier"
            or not isinstance(rows,list) or len(rows)!=56 or (value.get("ubuntu_signed_runtime") or {}).get("package_count")!=55):
        raise WaylandDependencyError("Wayland signed verifier invalid")
    noble=next((x for x in value.get("inputs",[]) if x.get("label")=="noble"),{})
    if ((noble.get("gpgv") or {}).get("good_signature") is not True
            or (noble.get("packages") or {}).get("sha256")!="8f6f71ae839c8cba390a7643fcbbdacddb0bc7d12c1583a2dd80a1f8443a30e5"):
        raise WaylandDependencyError("Noble signed index binding missing")
    return value


@dataclass(frozen=True)
class WaylandDependencyPlan:
    run_id: str
    profile: str
    attempt_nonce: str
    runtime_uid: int
    outer: Mapping[str, Any]
    supplement_path: str
    verifier_path: str
    qemu_sha256: str

    def validate(self) -> None:
        if (not self.run_id or self.profile != "linux-headless-x64"
                or not re.fullmatch(r"[0-9a-f]{48}", self.attempt_nonce)
                or isinstance(self.runtime_uid, bool) or self.runtime_uid <= 0
                or not SHA.fullmatch(self.qemu_sha256)):
            raise WaylandDependencyError("invalid Wayland dependency binding")
        source = Path(self.supplement_path)
        if not source.is_absolute() or _sha(source) != (SUPPLEMENT_SHA, SUPPLEMENT_SIZE):
            raise WaylandDependencyError("Wayland supplement bytes changed")
        verifier = validate_wayland_verifier(Path(self.verifier_path))
        matches = [row for row in verifier["packages"] if row.get("package") == PACKAGE]
        if len(matches) != 1 or any(matches[0].get(k) != v for k, v in {
                "version": VERSION, "architecture": ARCH, "file": DEB_NAME,
                "sha256": DEB_SHA, "size": DEB_SIZE}.items()):
            raise WaylandDependencyError("signed Wayland package stanza differs")


INSTALL = r'''import hashlib,json,os,pathlib,subprocess,sys,tarfile
root=pathlib.Path(sys.argv[1]); archive=root/'supplement.tar'; run,nonce=sys.argv[2],sys.argv[3]
expected_members={'libwayland-server0_1.22.0-2.1build1_amd64.deb','supplement-manifest.json','install-order.txt','clean-ldd.txt','qemu-version.txt'}
def sha(p):
 h=hashlib.sha256();n=0
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b);n+=len(b)
 return h.hexdigest(),n
if sha(archive)!=('3b2a227cf05c5f104defc0f56c186c77f7fbf9d608177224c775cd4adb590845',61440):raise SystemExit('supplement hash mismatch')
with tarfile.open(archive,'r:') as tf:
 rows=tf.getmembers()
 if {x.name for x in rows}!=expected_members or any(not x.isfile() or x.name.startswith('/') or '..' in pathlib.PurePosixPath(x.name).parts for x in rows):raise SystemExit('supplement member set unsafe')
 member=tf.getmember('libwayland-server0_1.22.0-2.1build1_amd64.deb');src=tf.extractfile(member);data=src.read() if src else b''
deb=root/'libwayland-server0_1.22.0-2.1build1_amd64.deb';fd=os.open(deb,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);view=memoryview(data)
while view:
 written=os.write(fd,view)
 if written<=0:raise SystemExit('short Wayland deb write')
 view=view[written:]
os.fsync(fd);os.close(fd)
if sha(deb)!=('edbfa4b6857691ae922cc768a753fab230eee9e956aa2ce4f2eaa8d9ad777dca',33928):raise SystemExit('signed deb mismatch')
def status():
 p=subprocess.run(['/usr/bin/dpkg-query','-W','-f=${binary:Package}\t${Version}\t${db:Status-Abbrev}\n'],capture_output=True,timeout=30)
 if p.returncode:raise SystemExit('dpkg status unavailable')
 return {x.split('\t')[0]:x.split('\t')[1:] for x in p.stdout.decode().splitlines() if x.count('\t')==2}
before=status();p=subprocess.run(['/usr/bin/dpkg','--unpack',str(deb)],capture_output=True,timeout=120)
unpack={'argv':['/usr/bin/dpkg','--unpack',str(deb)],'exit_code':p.returncode,'stdout_sha256':hashlib.sha256(p.stdout).hexdigest(),'stderr_sha256':hashlib.sha256(p.stderr).hexdigest(),'stdout_size':len(p.stdout),'stderr_size':len(p.stderr)}
if p.returncode:raise SystemExit('Wayland unpack failed')
p=subprocess.run(['/usr/bin/dpkg','--configure','libwayland-server0'],capture_output=True,timeout=120)
configure={'argv':['/usr/bin/dpkg','--configure','libwayland-server0'],'exit_code':p.returncode,'stdout_sha256':hashlib.sha256(p.stdout).hexdigest(),'stderr_sha256':hashlib.sha256(p.stderr).hexdigest(),'stdout_size':len(p.stdout),'stderr_size':len(p.stderr)}
if p.returncode:raise SystemExit('Wayland configure failed')
after=status();changed_raw={k for k in set(before)|set(after) if before.get(k)!=after.get(k)};aliases={'libwayland-server0','libwayland-server0:amd64'}
if changed_raw-aliases:raise SystemExit('foreign dpkg delta')
keys=[k for k in aliases if k in after]
if len(keys)!=1 or after[keys[0]]!=['1.22.0-2.1build1','ii ']:raise SystemExit('Wayland final status mismatch')
print(json.dumps({'schema':1,'operation':'nested-wayland-install','run_id':run,'attempt_nonce':nonce,'origin':'guest','transport':'qga','injected':False,'supplement':{'sha256':'3b2a227cf05c5f104defc0f56c186c77f7fbf9d608177224c775cd4adb590845','size':61440},'package':{'name':'libwayland-server0','version':'1.22.0-2.1build1','architecture':'amd64','deb_sha256':'edbfa4b6857691ae922cc768a753fab230eee9e956aa2ce4f2eaa8d9ad777dca','deb_size':33928,'binary_key':keys[0],'status':'ii '},'changed_packages':sorted(changed_raw),'unpack':unpack,'configure':configure},sort_keys=True,separators=(',',':')))
'''

PROVE = r'''import hashlib,json,os,pwd,subprocess,sys
path,expected,uid,run_id,nonce,outer_raw=sys.argv[1],sys.argv[2],int(sys.argv[3]),sys.argv[4],sys.argv[5],sys.argv[6];p=os.path.realpath(path);outer=json.loads(outer_raw)
if p!=path or not os.path.isfile(p):raise SystemExit('QEMU path invalid')
needle='/runtime/qemu/'
if needle not in p:raise SystemExit('QEMU runtime root invalid')
root=p.split(needle,1)[0];ld=':'.join((root+'/runtime/private-libs',root+'/runtime/qemu',root+'/runtime/host/lib64',root+'/runtime/host/lib'))
def sha(x):
 h=hashlib.sha256();n=0
 with open(x,'rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b);n+=len(b)
 return h.hexdigest(),n
digest,size=sha(p)
if digest!=expected:raise SystemExit('QEMU hash mismatch')
u=pwd.getpwuid(uid);base=['/usr/bin/setpriv',f'--reuid={uid}',f'--regid={u.pw_gid}','--clear-groups'];env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':u.pw_dir,'LD_LIBRARY_PATH':ld}
def run_probe(argv,t):
 x=subprocess.run(base+argv,capture_output=True,timeout=t,env=env)
 if len(x.stdout)>1048576 or len(x.stderr)>1048576:raise SystemExit('QEMU probe output exceeds bound')
 text=x.stdout.decode(errors='replace');missing=[line.strip() for line in text.splitlines() if 'not found' in line]
 return {'argv':base+argv,'exit_code':x.returncode,'stdout_sha256':hashlib.sha256(x.stdout).hexdigest(),'stderr_sha256':hashlib.sha256(x.stderr).hexdigest(),'stdout_size':len(x.stdout),'stderr_size':len(x.stderr),'stdout_excerpt':text[:16384],'stderr_excerpt':x.stderr[:16384].decode(errors='replace'),'missing':missing,'dependency_count':sum('=>' in line for line in text.splitlines())}
ldd=run_probe(['/usr/bin/ldd',p],30)
if ldd['exit_code'] or ldd['missing'] or ldd['dependency_count']<=0:
 print(json.dumps({'schema':1,'operation':'nested-wayland-runtime-failure','run_id':run_id,'attempt_nonce':nonce,'outer':outer,'origin':'guest','transport':'qga','injected':False,'uid':uid,'primary_gid':u.pw_gid,'ld_library_path':ld,'qemu':{'path':p,'sha256':digest,'size':size},'acceptance':False,'probe_error':'QEMU dependency closure failed','ldd':ldd,'version':None},sort_keys=True,separators=(',',':')));raise SystemExit
version=run_probe([p,'-version'],30)
if version['exit_code'] or not (version['stdout_size'] or version['stderr_size']):
 print(json.dumps({'schema':1,'operation':'nested-wayland-runtime-failure','run_id':run_id,'attempt_nonce':nonce,'outer':outer,'origin':'guest','transport':'qga','injected':False,'uid':uid,'primary_gid':u.pw_gid,'ld_library_path':ld,'qemu':{'path':p,'sha256':digest,'size':size},'acceptance':False,'probe_error':'QEMU version probe failed','ldd':ldd,'version':version},sort_keys=True,separators=(',',':')));raise SystemExit
print(json.dumps({'schema':1,'operation':'nested-wayland-runtime-proof','run_id':run_id,'attempt_nonce':nonce,'outer':outer,'origin':'guest','transport':'qga','injected':False,'uid':uid,'primary_gid':u.pw_gid,'ld_library_path':ld,'qemu':{'path':p,'sha256':digest,'size':size},'ldd':ldd,'version':version},sort_keys=True,separators=(',',':')))
'''


def validate_install(plan: WaylandDependencyPlan, receipt: Mapping[str, Any]) -> dict:
    expected = {"name": PACKAGE, "version": VERSION, "architecture": ARCH,
                "deb_sha256": DEB_SHA, "deb_size": DEB_SIZE}
    package = receipt.get("package") if isinstance(receipt, Mapping) else None
    if (not isinstance(receipt, Mapping) or receipt.get("schema") != 1 or receipt.get("operation") != "nested-wayland-install"
            or receipt.get("run_id") != plan.run_id or receipt.get("attempt_nonce") != plan.attempt_nonce
            or receipt.get("outer") != dict(plan.outer)
            or receipt.get("origin") != "guest" or receipt.get("transport") != "qga" or receipt.get("injected") is not False
            or receipt.get("supplement") != {"sha256": SUPPLEMENT_SHA, "size": SUPPLEMENT_SIZE}
            or not isinstance(package, Mapping) or any(package.get(k) != v for k, v in expected.items())
            or package.get("binary_key") not in (PACKAGE, PACKAGE + ":" + ARCH) or package.get("status") != "ii "
            or any((receipt.get(x) or {}).get("exit_code") != 0 for x in ("unpack", "configure"))
            or any(x not in (PACKAGE, PACKAGE + ":" + ARCH) for x in receipt.get("changed_packages", []))):
        raise WaylandDependencyError("Wayland install receipt invalid")
    return dict(receipt)


def validate_runtime(plan: WaylandDependencyPlan, install: Mapping[str, Any], receipt: Mapping[str, Any], qemu_path: str) -> dict:
    validate_install(plan, install)
    qemu = receipt.get("qemu") if isinstance(receipt, Mapping) else None
    ldd=receipt.get("ldd") if isinstance(receipt,Mapping) else None;version=receipt.get("version") if isinstance(receipt,Mapping) else None
    gid=receipt.get("primary_gid") if isinstance(receipt,Mapping) else None
    base=["/usr/bin/setpriv",f"--reuid={plan.runtime_uid}",f"--regid={gid}","--clear-groups"]
    root=qemu_path.split("/runtime/qemu/",1)[0] if "/runtime/qemu/" in qemu_path else ""
    expected_ld=":".join((root+"/runtime/private-libs",root+"/runtime/qemu",root+"/runtime/host/lib64",root+"/runtime/host/lib"))
    def bounded(row:Any)->bool:
        return (isinstance(row,Mapping) and all(not isinstance(row.get(k),bool) and isinstance(row.get(k),int) and 0<=row[k]<=1024*1024 for k in ("stdout_size","stderr_size"))
                and len(str(row.get("stdout_excerpt","" )).encode())<=16384 and len(str(row.get("stderr_excerpt","" )).encode())<=16384
                and SHA.fullmatch(str(row.get("stdout_sha256",""))) is not None and SHA.fullmatch(str(row.get("stderr_sha256",""))) is not None)
    if (not isinstance(receipt, Mapping) or receipt.get("schema") != 1 or receipt.get("operation") != "nested-wayland-runtime-proof"
            or receipt.get("run_id") != plan.run_id or receipt.get("attempt_nonce") != plan.attempt_nonce
            or receipt.get("outer") != dict(plan.outer)
            or receipt.get("origin") != "guest" or receipt.get("transport") != "qga" or receipt.get("injected") is not False
            or receipt.get("uid") != plan.runtime_uid or isinstance(gid,bool) or not isinstance(gid,int) or gid<=0 or not isinstance(qemu, Mapping)
            or receipt.get("ld_library_path")!=expected_ld
            or qemu.get("path") != qemu_path or qemu.get("sha256") != plan.qemu_sha256
            or not bounded(ldd) or not bounded(version) or ldd.get("exit_code") != 0 or version.get("exit_code") != 0
            or ldd.get("argv")!=base+["/usr/bin/ldd",qemu_path] or version.get("argv")!=base+[qemu_path,"-version"]
            or not (version.get("stdout_size") or version.get("stderr_size"))
            or ldd.get("missing")!=[] or isinstance(ldd.get("dependency_count"),bool) or not isinstance(ldd.get("dependency_count"),int) or ldd.get("dependency_count",0)<=0
            or "not found" in str(ldd.get("stdout_excerpt", ""))):
        raise WaylandDependencyError("Wayland QEMU runtime proof invalid")
    return dict(receipt)


class WaylandDependencyInstaller:
    def __init__(self, qga: Any, plan: WaylandDependencyPlan, outer_snapshot: Callable[[], Mapping[str, Any]], failure_archive: Callable[[str, Mapping[str, Any]], Mapping[str, Any]], success_archive: Callable[[str, Mapping[str, Any]], Mapping[str, Any]]):
        if (not callable(failure_archive) or not callable(success_archive)
                or len(inspect.signature(failure_archive).parameters) != 2
                or len(inspect.signature(success_archive).parameters) != 2):
            raise WaylandDependencyError("Wayland archive callback signature invalid")
        self.qga, self.plan, self.snapshot = qga, plan, outer_snapshot
        self.failure_archive, self.success_archive = failure_archive, success_archive
        plan.validate()

    def _fence(self) -> None:
        if self.snapshot() != self.plan.outer:
            raise WaylandDependencyError("outer changed")

    def install(self, timeout: float = 300) -> dict:
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or not 60 <= timeout <= 600:
            raise WaylandDependencyError("invalid Wayland install timeout")
        self._fence(); deadline = time.monotonic() + timeout; root_id = None; archive_durable = False
        root = f"/var/lib/amnezia-release-lab/wayland/{self.plan.attempt_nonce}"
        try:
            made=self.qga.guest_exec_wait("/usr/bin/python3",["-c",MKROOT,self.plan.attempt_nonce],timeout=20)
            if made.get("exitcode")!=0:raise WaylandDependencyError("Wayland root creation failed")
            root_id=json.loads(made.get("stdout",""))
            if (not isinstance(root_id,Mapping) or root_id.get("uid")!=0 or root_id.get("mode")!=0o700
                    or any(isinstance(root_id.get(k),bool) or not isinstance(root_id.get(k),int) or root_id[k]<=0 for k in ("dev","inode"))):
                raise WaylandDependencyError("Wayland root identity invalid")
            self._fence()
            self.qga.write_file_from_path(root + "/supplement.tar", Path(self.plan.supplement_path), SUPPLEMENT_SHA, SUPPLEMENT_SIZE, deadline=deadline, max_size=SUPPLEMENT_SIZE)
            self._fence(); raw = self.qga.guest_exec_wait("/usr/bin/python3", ["-c", INSTALL, root, self.plan.run_id, self.plan.attempt_nonce], timeout=min(240, max(1, deadline-time.monotonic())))
            if isinstance(raw.get("exitcode"), bool) or raw.get("exitcode") != 0:
                raise WaylandDependencyError("Wayland install failed")
            receipt=json.loads(raw.get("stdout", ""));receipt["outer"]=dict(self.plan.outer)
            receipt=validate_install(self.plan,receipt);receipt["root_identity"]=dict(root_id)
            ack=self.success_archive(self.plan.run_id,receipt)
            if not isinstance(ack,Mapping) or ack.get("origin")!="controller" or ack.get("immutable") is not True:raise WaylandDependencyError("Wayland success archive rejected")
            archive_durable=True;receipt["controller_archive"]=dict(ack)
            clean=self.qga.guest_exec_wait("/usr/bin/python3",["-c",CLEANUP,self.plan.attempt_nonce,str(root_id["dev"]),str(root_id["inode"]),root_id["marker_sha256"]],timeout=20)
            if clean.get("exitcode")!=0:raise WaylandDependencyError("Wayland cleanup failed")
            self._fence();return receipt
        except BaseException as primary:
            record = {"schema": 1, "run_id": self.plan.run_id, "attempt_nonce": self.plan.attempt_nonce,
                      "outer": dict(self.plan.outer), "phase": "wayland-install", "error_type": type(primary).__name__, "recorded_at": time.time()}
            durable=False
            try:
                ack = self.failure_archive(self.plan.run_id, record)
                if not isinstance(ack, Mapping) or ack.get("origin") != "controller" or ack.get("immutable") is not True:
                    raise WaylandDependencyError("Wayland failure archive rejected")
                durable=True
            except BaseException as archive_error:
                if hasattr(primary, "add_note"): primary.add_note(f"Wayland archive also failed: {archive_error!r}")
            if durable and root_id is not None and not archive_durable:
                try:
                    self._fence();self.qga.guest_exec_wait("/usr/bin/python3",["-c",CLEANUP,self.plan.attempt_nonce,str(root_id["dev"]),str(root_id["inode"]),root_id["marker_sha256"]],timeout=20)
                except BaseException as cleanup_error:
                    if hasattr(primary,"add_note"):primary.add_note(f"Wayland cleanup also failed: {cleanup_error!r}")
            raise

    def prove_runtime(self, install_receipt: Mapping[str, Any], qemu_guest_path: str, timeout: float = 60) -> dict:
        validate_install(self.plan, install_receipt)
        if not qemu_guest_path.startswith("/var/lib/amnezia-release-lab/n/") or "/runtime/qemu/" not in qemu_guest_path:
            raise WaylandDependencyError("QEMU proof path outside owned runtime")
        diagnostic=None
        try:
            self._fence(); raw = self.qga.guest_exec_wait("/usr/bin/python3", ["-c", PROVE, qemu_guest_path, self.plan.qemu_sha256, str(self.plan.runtime_uid), self.plan.run_id, self.plan.attempt_nonce, json.dumps(dict(self.plan.outer),sort_keys=True,separators=(",",":"))], timeout=timeout)
            if isinstance(raw.get("exitcode"), bool) or raw.get("exitcode") != 0:
                raise WaylandDependencyError("Wayland QEMU runtime probe failed")
            diagnostic=json.loads(raw.get("stdout", ""))
            if diagnostic.get("operation")=="nested-wayland-runtime-failure":
                root=qemu_guest_path.split("/runtime/qemu/",1)[0];expected_ld=":".join((root+"/runtime/private-libs",root+"/runtime/qemu",root+"/runtime/host/lib64",root+"/runtime/host/lib"))
                qemu=diagnostic.get("qemu");ldd=diagnostic.get("ldd");gid=diagnostic.get("primary_gid")
                base=["/usr/bin/setpriv",f"--reuid={self.plan.runtime_uid}",f"--regid={gid}","--clear-groups"]
                def bounded(row:Any)->bool:
                    return (isinstance(row,Mapping) and not isinstance(row.get("exit_code"),bool) and isinstance(row.get("exit_code"),int) and all(not isinstance(row.get(k),bool) and isinstance(row.get(k),int) and 0<=row[k]<=1048576 for k in ("stdout_size","stderr_size"))
                            and len(str(row.get("stdout_excerpt","")).encode())<=16384 and len(str(row.get("stderr_excerpt","")).encode())<=16384
                            and SHA.fullmatch(str(row.get("stdout_sha256",""))) is not None and SHA.fullmatch(str(row.get("stderr_sha256",""))) is not None)
                error=diagnostic.get("probe_error");version=diagnostic.get("version")
                if (diagnostic.get("run_id")!=self.plan.run_id or diagnostic.get("attempt_nonce")!=self.plan.attempt_nonce or diagnostic.get("outer")!=dict(self.plan.outer)
                        or diagnostic.get("uid")!=self.plan.runtime_uid or isinstance(gid,bool) or not isinstance(gid,int) or gid<=0 or diagnostic.get("ld_library_path")!=expected_ld
                        or not isinstance(qemu,Mapping) or qemu.get("path")!=qemu_guest_path or qemu.get("sha256")!=self.plan.qemu_sha256 or isinstance(qemu.get("size"),bool) or not isinstance(qemu.get("size"),int) or qemu["size"]<=0
                        or not bounded(ldd) or ldd.get("argv")!=base+["/usr/bin/ldd",qemu_guest_path] or not isinstance(ldd.get("missing"),list) or any(not isinstance(x,str) for x in ldd["missing"])
                        or isinstance(ldd.get("dependency_count"),bool) or not isinstance(ldd.get("dependency_count"),int) or ldd["dependency_count"]<0
                        or diagnostic.get("acceptance") is not False or error not in ("QEMU dependency closure failed","QEMU version probe failed")
                        or (error=="QEMU dependency closure failed" and not (ldd.get("exit_code")!=0 or ldd["missing"] or ldd["dependency_count"]<=0))
                        or (error=="QEMU dependency closure failed" and version is not None)
                        or (error=="QEMU version probe failed" and (ldd.get("exit_code")!=0 or ldd["missing"] or ldd["dependency_count"]<=0 or not bounded(version) or version.get("argv")!=base+[qemu_guest_path,"-version"] or not (version.get("exit_code")!=0 or not (version.get("stdout_size") or version.get("stderr_size")))))):
                    raise WaylandDependencyError("Wayland failure diagnostic binding invalid")
                raise WaylandDependencyError(str(diagnostic.get("probe_error") or "Wayland QEMU runtime probe failed"))
            return validate_runtime(self.plan, install_receipt, diagnostic, qemu_guest_path)
        except BaseException as primary:
            record={"schema":1,"run_id":self.plan.run_id,"attempt_nonce":self.plan.attempt_nonce,"outer":dict(self.plan.outer),"phase":"wayland-runtime-proof","qemu_path":qemu_guest_path,"error_type":type(primary).__name__,"recorded_at":time.time()}
            if isinstance(diagnostic,Mapping):record["diagnostic"]=dict(diagnostic)
            try:
                ack=self.failure_archive(self.plan.run_id,record)
                if not isinstance(ack,Mapping) or ack.get("origin")!="controller" or ack.get("immutable") is not True:raise WaylandDependencyError("Wayland runtime failure archive rejected")
            except BaseException as archive_error:
                if hasattr(primary,"add_note"):primary.add_note(f"Wayland runtime archive also failed: {archive_error!r}")
            raise
