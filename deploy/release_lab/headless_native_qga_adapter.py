"""QGA execution adapter for native headless update acceptance.

This module returns observations, never acceptance booleans.  The controller
must validate them with ``headless_native_acceptance`` and an independently
owned server-fixture receipt.
"""
from __future__ import annotations

import base64, hashlib, json, time
from dataclasses import asdict
from typing import Any, Callable, Mapping

try:
    from .headless_native_acceptance import (FIXED_KEY, FIXED_SOCKET, FIXED_STORE,
        ROLLBACK_RECEIPT, UPDATE_JOURNAL, UPDATE_STATE, HeadlessAcceptanceError,
        NativeUpdatePlan, ReleaseBytes, receipt_sha256, validate_http_receipt,
        validate_update_receipt, validate_rollback_receipt, validate_reboot_receipt)
except ImportError:
    from headless_native_acceptance import (FIXED_KEY, FIXED_SOCKET, FIXED_STORE,
        ROLLBACK_RECEIPT, UPDATE_JOURNAL, UPDATE_STATE, HeadlessAcceptanceError,
        NativeUpdatePlan, ReleaseBytes, receipt_sha256, validate_http_receipt,
        validate_update_receipt, validate_rollback_receipt, validate_reboot_receipt)


class HeadlessNativeQgaError(HeadlessAcceptanceError): pass

READ_RAW = r'''import base64,hashlib,json,os,pathlib,stat,sys
p=pathlib.Path(sys.argv[1]); logical=sys.argv[2]
if not p.exists() or p.is_symlink() or not p.is_file(): raise SystemExit(4)
b=p.read_bytes(); s=p.stat()
print(json.dumps({'origin':'guest','transport':'qga','path':logical,'bytes_b64':base64.b64encode(b).decode(),'sha256':hashlib.sha256(b).hexdigest(),'size':len(b),'uid':s.st_uid,'gid':s.st_gid,'mode':format(stat.S_IMODE(s.st_mode),'04o')},separators=(',',':')))
'''
ABSENCE = r'''import base64,hashlib,json,pathlib,sys
p=pathlib.Path(sys.argv[1]); logical=sys.argv[2]; data=json.dumps({'exists':p.exists()},separators=(',',':')).encode()
print(json.dumps({'origin':'guest','transport':'qga','path':logical,'bytes_b64':base64.b64encode(data).decode(),'sha256':hashlib.sha256(data).hexdigest(),'size':len(data),'uid':0,'gid':0,'mode':'0600'},separators=(',',':')))
'''
IDENTITY = r'''import hashlib,json,pathlib,re,subprocess,sys
version,daemon_sha,daemon_size,cli_sha,cli_size=sys.argv[1:]
daemon=pathlib.Path('/usr/local/bin/amneziad'); cli=pathlib.Path('/usr/local/bin/amnezia-cli')
def exact(p,sha,size):
 b=p.read_bytes()
 if p.is_symlink() or len(b)!=int(size) or hashlib.sha256(b).hexdigest()!=sha: raise SystemExit('managed bytes')
exact(daemon,daemon_sha,daemon_size); exact(cli,cli_sha,cli_size)
p=subprocess.run([str(daemon),'--version'],text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=20)
found=re.search(r'\d+\.\d+\.\d+\.\d+',p.stdout)
if p.returncode or not found or found.group()!=version: raise SystemExit('managed version')
q=subprocess.run(['/usr/bin/systemctl','show','amneziad.service','-pMainPID','--value'],text=True,stdout=subprocess.PIPE,timeout=20)
pid=int(q.stdout.strip()); proc=pathlib.Path('/proc')/str(pid); raw=proc.joinpath('stat').read_text(); ticks=int(raw[raw.rfind(')')+2:].split()[19])
if proc.joinpath('exe').resolve(strict=True)!=daemon or hashlib.sha256(proc.joinpath('exe').read_bytes()).hexdigest()!=daemon_sha: raise SystemExit('live daemon bytes')
print(json.dumps({'version':version,'amneziad_sha256':daemon_sha,'amneziad_size':int(daemon_size),'cli_sha256':cli_sha,'cli_size':int(cli_size),'daemon_pid':pid,'daemon_start_ticks':ticks},separators=(',',':')))
'''
UNIT_PREFLIGHT = r'''import hashlib,json,os,pathlib,re,subprocess,sys
exe=pathlib.Path('/usr/local/bin/amneziad'); expected_sha=sys.argv[1]; expected_size=int(sys.argv[2]); require_pid=sys.argv[3]=='post'
if exe.is_symlink() or not exe.is_file(): raise SystemExit('daemon identity')
b=exe.read_bytes()
if len(b)!=expected_size or hashlib.sha256(b).hexdigest()!=expected_sha: raise SystemExit('daemon bytes')
def show(prop):
 p=subprocess.run(['/usr/bin/systemctl','show','amneziad.service','--property='+prop,'--value'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=20)
 if p.returncode: raise SystemExit('systemctl show')
 return p.stdout.strip()
unit=show('ExecStart')
paths=re.findall(r'(?:^|[ ;{])path=([^ ;}]+)',unit)
argv0=re.findall(r'argv\[\]=([^ ;}]+)',unit)
if paths!=[str(exe)] or argv0!=[str(exe)]: raise SystemExit('unit ExecStart')
pid=int(show('MainPID') or '0'); proc_sha=''
if require_pid:
 if pid<=1: raise SystemExit('daemon pid')
 proc=pathlib.Path('/proc')/str(pid)
 if proc.joinpath('exe').resolve(strict=True)!=exe: raise SystemExit('daemon proc exe')
 proc_sha=hashlib.sha256(proc.joinpath('exe').read_bytes()).hexdigest()
 if proc_sha!=expected_sha: raise SystemExit('daemon proc bytes')
print(json.dumps({'unit':'amneziad.service','exec_start_raw':unit,'exe':str(exe),'sha256':expected_sha,'size':expected_size,'main_pid':pid,'proc_exe_sha256':proc_sha},separators=(',',':')))
'''
STAGE = r'''import hashlib,json,os,pathlib,stat,sys
store=pathlib.Path(sys.argv[1]); key=pathlib.Path(sys.argv[2]); profile=json.loads(sys.argv[3]); expected=sys.argv[4]
if key.is_symlink() or not key.is_file() or hashlib.sha256(key.read_bytes()).hexdigest()!=expected: raise SystemExit('key mismatch')
if key.stat().st_uid!=0 or stat.S_IMODE(key.stat().st_mode)&0o022: raise SystemExit('key ownership')
items=[]
if store.exists():
 if store.is_symlink() or not store.is_file(): raise SystemExit('store identity')
 value=json.loads(store.read_bytes()); items=value.get('profiles',[]) if isinstance(value,dict) else value
 if not isinstance(items,list): raise SystemExit('store shape')
items=[x for x in items if not isinstance(x,dict) or x.get('id')!=profile['id']]; items.append(profile)
store.parent.mkdir(parents=True,exist_ok=True); tmp=store.with_name(store.name+'.native-new')
fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
with os.fdopen(fd,'wb') as f: f.write(json.dumps(items,separators=(',',':')).encode()); f.flush(); os.fsync(f.fileno())
os.chown(tmp,0,0); os.replace(tmp,store); os.chmod(store,0o600)
print(json.dumps({'stored':len(items)},separators=(',',':')))
'''

class HeadlessNativeQgaAdapter:
    def __init__(self, qga: Any, plan: NativeUpdatePlan, outer_live_snapshot: Callable[[], Any], *,
                 clock: Callable[[],float]=time.monotonic, sleeper: Callable[[float],None]=time.sleep):
        plan.validate(); self.qga=qga; self.plan=plan; self.snapshot=outer_live_snapshot; self.clock=clock; self.sleep=sleeper
    def _check(self):
        if self.snapshot()!=self.plan.outer_binding: raise HeadlessNativeQgaError("outer ownership changed")
    def _exec(self,path,args,timeout=30):
        self._check(); result=self.qga.guest_exec_wait(path,args,timeout=timeout)
        code = result.get("exitcode", result.get("exit_code")) if isinstance(result, Mapping) else None
        if not isinstance(code, int) or isinstance(code, bool) or code != 0: raise HeadlessNativeQgaError("guest command failed")
        return result
    def _json(self,path,args,timeout=30):
        result=self._exec(path,args,timeout)
        try: value=json.loads(result.get("stdout",""))
        except (TypeError,json.JSONDecodeError) as exc: raise HeadlessNativeQgaError("guest command returned invalid JSON") from exc
        return value
    def raw_file(self,path,logical=None): return self._json("/usr/bin/python3",["-c",READ_RAW,path,logical or path])
    def raw_absence(self,path):
        return self._json("/usr/bin/python3",["-c",ABSENCE,path,path+".absence"])
    def cli_json(self,argv,logical):
        result=self._exec(argv[0],argv[1:]); data=str(result.get("stdout","")).encode()
        json.loads(data)
        return {"origin":"guest","transport":"qga","path":logical,"bytes_b64":base64.b64encode(data).decode(),"sha256":hashlib.sha256(data).hexdigest(),"size":len(data),"uid":0,"gid":0,"mode":"0600"}
    def _json_record(self, script, args, logical, timeout=30):
        result=self._exec("/usr/bin/python3",["-c",script,*args],timeout); data=str(result.get("stdout","")).encode()
        try: json.loads(data)
        except (UnicodeDecodeError,json.JSONDecodeError) as exc: raise HeadlessNativeQgaError("guest evidence returned invalid JSON") from exc
        return {"origin":"guest","transport":"qga","path":logical,"bytes_b64":base64.b64encode(data).decode(),"sha256":hashlib.sha256(data).hexdigest(),"size":len(data),"uid":0,"gid":0,"mode":"0600"}
    def identity(self,release:ReleaseBytes,label:str):
        if label not in {"baseline-before","candidate-after","candidate-before","baseline-after","post-reboot"}: raise HeadlessNativeQgaError("identity label")
        return self._json_record(IDENTITY,[release.version,release.amneziad_sha256,str(release.amneziad_size),release.cli_sha256,str(release.cli_size)],"identity:"+label,60)
    @staticmethod
    def _identity_from_raw(value:Mapping[str,Any],label:str)->dict[str,Any]:
        if not isinstance(value,Mapping) or value.get("origin")!="guest" or value.get("transport")!="qga" or value.get("path")!="identity:"+label: raise HeadlessNativeQgaError("identity raw envelope binding")
        try: data=base64.b64decode(value.get("bytes_b64"),validate=True)
        except (TypeError,ValueError) as exc: raise HeadlessNativeQgaError("identity raw envelope encoding") from exc
        if isinstance(value.get("size"),bool) or value.get("size")!=len(data) or value.get("sha256")!=hashlib.sha256(data).hexdigest(): raise HeadlessNativeQgaError("identity raw envelope hash")
        try: parsed=json.loads(data)
        except (UnicodeDecodeError,json.JSONDecodeError) as exc: raise HeadlessNativeQgaError("identity raw JSON") from exc
        if not isinstance(parsed,dict): raise HeadlessNativeQgaError("identity raw JSON shape")
        return parsed
    def stage_profile(self):
        expected=[self.plan.baseline.amneziad_sha256,str(self.plan.baseline.amneziad_size)]
        before=self._json_record(UNIT_PREFLIGHT,[*expected,"pre"],"systemd:amneziad.service:baseline-preflight")
        built_profile={"id":f"release-lab-{self.plan.attempt_nonce}","name":"release-lab native updater","protocol":"wireguard","configPath":"/etc/amnezia/profiles/release-lab.conf","forwardRoutes":list(self.plan.fixture.forward_routes),"autoUpdate":True,"updateManifestUrl":self.plan.fixture.endpoint.rstrip('/')+self.plan.fixture.manifest_path,"updatePublicKeyPath":FIXED_KEY}
        self._json("/usr/bin/python3",["-c",STAGE,FIXED_STORE,FIXED_KEY,json.dumps(built_profile,separators=(",",":")),self.plan.candidate.key_sha256])
        self._exec("/usr/bin/systemctl",["restart","amneziad.service"],120)
        after=self._json_record(UNIT_PREFLIGHT,[*expected,"post"],"systemd:amneziad.service:baseline-after-restart")
        return {"baseline_preflight":before,"baseline_after_restart":after,"profile_store":self.raw_file(FIXED_STORE),"key":self.raw_file(FIXED_KEY),"list_profiles":self.cli_json(["/usr/local/bin/amnezia-cli","--socket",FIXED_SOCKET,"--json","list-profiles"],"cli:list-profiles")}
    def collect_update_pending(self): return {"pending_state":self.raw_file(UPDATE_STATE),"pending_journal":self.raw_file(UPDATE_JOURNAL)}
    def collect_update_stable(self): return {"stable_state":self.raw_file(UPDATE_STATE),"rollback_receipt":self.raw_file(ROLLBACK_RECEIPT),"retired_journal":self.raw_absence(UPDATE_JOURNAL),"after_doctor":self.cli_json(["/usr/local/bin/amnezia-cli","--socket",FIXED_SOCKET,"--json","doctor"],"cli:doctor")}
    def trigger_rollback(self):
        return {"cli_response":self.cli_json(["/usr/local/bin/amnezia-cli","--socket",FIXED_SOCKET,"--json","update-rollback"],"cli:update-rollback")}
    def collect_rollback_pending(self): return {"pending_state":self.raw_file(UPDATE_STATE),"pending_journal":self.raw_file(UPDATE_JOURNAL)}
    def collect_rollback_stable(self): return {"stable_state":self.raw_file(UPDATE_STATE),"retired_journal":self.raw_absence(UPDATE_JOURNAL),"after_doctor":self.cli_json(["/usr/local/bin/amnezia-cli","--socket",FIXED_SOCKET,"--json","doctor"],"cli:doctor")}
    def reboot(self,boot_id_before:str,timeout=180):
        self._check(); self.qga.guest_exec("/usr/bin/systemctl",["reboot"]); deadline=self.clock()+timeout
        while self.clock()<deadline:
            self._check()
            try:
                result=self.qga.guest_exec_wait("/usr/bin/cat",["/proc/sys/kernel/random/boot_id"],timeout=10)
                code=result.get("exitcode",result.get("exit_code")) if isinstance(result,Mapping) else None
                value=str(result.get("stdout","")).strip() if code == 0 and not isinstance(code,bool) else ""
                if value and value!=boot_id_before: return {"boot_id_before":boot_id_before,"boot_id_after":value}
            except Exception: pass
            self.sleep(1)
        raise HeadlessNativeQgaError("bounded reboot/QGA reconnect timed out")

    def wait_for(self, collect: Callable[[], Mapping[str, Any]],
                 ready: Callable[[Mapping[str, Any]], bool], *, timeout: float,
                 label: str) -> Mapping[str, Any]:
        """Poll QGA evidence under one total deadline and a fresh ownership check."""
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0 or timeout > 600:
            raise HeadlessNativeQgaError("invalid bounded wait timeout")
        deadline = self.clock() + timeout
        last: Mapping[str, Any] | None = None
        while self.clock() < deadline:
            self._check()
            value = collect()
            if not isinstance(value, Mapping):
                raise HeadlessNativeQgaError(f"{label} collector returned no mapping")
            last = value
            if ready(value):
                return value
            self.sleep(min(1.0, max(0.0, deadline - self.clock())))
        raise HeadlessNativeQgaError(f"bounded wait expired for {label}; last observation was not ready")

    def build_update_receipt(self, *, before_raw: Mapping[str, Any], after_raw: Mapping[str, Any],
                             boot_id: str, raw_sources: Mapping[str, Any],
                             http_receipt: Mapping[str, Any], observed_at: str) -> dict[str, Any]:
        validate_http_receipt(self.plan, http_receipt); before=self._identity_from_raw(before_raw,"baseline-before"); after=self._identity_from_raw(after_raw,"candidate-after")
        value = self._common_receipt("headless-native-update", observed_at)
        value.update({"before": dict(before), "after": dict(after), "boot_id_before": boot_id,
                      "boot_id_after": boot_id, "raw_sources": dict(raw_sources),
                      "http_receipt_sha256": receipt_sha256(http_receipt),
                      "fixed_key_path": FIXED_KEY,
                      "fixed_key_sha256": self.plan.candidate.key_sha256,
                      "verified_manifest_sha256": self.plan.candidate.manifest_sha256,
                      "verified_manifest_size": self.plan.candidate.manifest_size,
                      "passed": True})
        return validate_update_receipt(self.plan, value, http_receipt)

    def build_rollback_receipt(self, *, before_raw: Mapping[str, Any], after_raw: Mapping[str, Any],
                               boot_id: str, cli_process: Mapping[str, Any],
                               raw_sources: Mapping[str, Any], update_receipt: Mapping[str, Any],
                               observed_at: str) -> dict[str, Any]:
        before=self._identity_from_raw(before_raw,"candidate-before"); after=self._identity_from_raw(after_raw,"baseline-after"); value = self._common_receipt("headless-native-rollback", observed_at)
        value.update({"before": dict(before), "after": dict(after), "boot_id_before": boot_id,
                      "boot_id_after": boot_id, "cli_process": dict(cli_process),
                      "raw_sources": dict(raw_sources),
                      "update_receipt_sha256": receipt_sha256(update_receipt), "passed": True})
        return validate_rollback_receipt(self.plan, value, update_receipt)

    def build_reboot_receipt(self, *, boot_id_before: str, boot_id_after: str,
                             after_raw: Mapping[str, Any], raw_sources: Mapping[str, Any],
                             expected_release: ReleaseBytes, prior_receipt: Mapping[str, Any],
                             observed_at: str) -> dict[str, Any]:
        after=self._identity_from_raw(after_raw,"post-reboot"); value = self._common_receipt("headless-native-reboot", observed_at)
        value.update({"boot_id_before": boot_id_before, "boot_id_after": boot_id_after,
                      "after": dict(after), "raw_sources": dict(raw_sources),
                      "prior_receipt_sha256": receipt_sha256(prior_receipt), "passed": True})
        return validate_reboot_receipt(self.plan, value, expected_release, prior_receipt)

    def validate_fixture_cleanup(self, receipt: Mapping[str, Any], http_receipt: Mapping[str, Any]) -> dict[str, Any]:
        """Require exact fixture PID/start identity to be stopped with no listener left."""
        validate_http_receipt(self.plan, http_receipt)
        expected = {"schema": 1, "operation": "headless-native-fixture-cleanup",
                    "run_id": self.plan.run_id, "case_id": self.plan.case_id,
                    "attempt_nonce": self.plan.attempt_nonce, "origin": "server-fixture",
                    "transport": "qga", "injected": False,
                    "outer_binding": asdict(self.plan.outer_binding),
                    "http_receipt_sha256": receipt_sha256(http_receipt)}
        if any(receipt.get(k) != v for k, v in expected.items()):
            raise HeadlessNativeQgaError("fixture cleanup identity differs from the validated HTTP receipt")
        fixture = http_receipt.get("fixture") or {}
        if (isinstance(receipt.get("pid"), bool) or receipt.get("pid") != fixture.get("pid")
                or isinstance(receipt.get("start_ticks"), bool)
                or receipt.get("start_ticks") != fixture.get("start_ticks")
                or receipt.get("identity_rechecked") is not True
                or receipt.get("stopped") is not True or receipt.get("listener_closed") is not True
                or receipt.get("unknown_survivors") != []):
            raise HeadlessNativeQgaError("fixture cleanup is incomplete or ambiguous")
        return dict(receipt)

    def _common_receipt(self, operation: str, observed_at: str) -> dict[str, Any]:
        self._check()
        return {"schema": 1, "operation": operation, "run_id": self.plan.run_id,
                "case_id": self.plan.case_id, "attempt_nonce": self.plan.attempt_nonce,
                "origin": "guest", "transport": "qga", "injected": False,
                "outer_binding": asdict(self.plan.outer_binding), "observed_at": observed_at}
