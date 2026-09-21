#!/usr/bin/env python3
"""Guest-side executor for a compatibility-seeded headless deployment."""
from __future__ import annotations
import argparse, base64, errno, hashlib, json, os, pathlib, re, signal, socket, stat, subprocess, sys, time
from typing import Any

try: from headless_preexisting_fixture import BinaryIdentity,FixturePlan,build_contract,_sha
except ImportError: from deploy.release_lab.headless_preexisting_fixture import BinaryIdentity,FixturePlan,build_contract,_sha

class GuestError(RuntimeError): pass
class CliFailure(GuestError):
    def __init__(self, diagnostic:dict): self.diagnostic=diagnostic; super().__init__('CLI transaction failed')
class LegacyProcessFailure(GuestError):
    def __init__(self, diagnostic:dict): self.diagnostic=diagnostic; super().__init__('legacy process failed')
MAX_OUTPUT=1024*1024
MAX_LEGACY_LOG=4*1024*1024
MAX_CONFIG=64*1024

# Controller/QGA sequence (each stdout JSON is archived and rehashed before
# the next mutating action):
#   python3 headless_preexisting_fixture_guest.py prepare --plan PLAN
#   python3 headless_preexisting_fixture_guest.py connect-collect --plan PLAN --deadline 90
#   # archive connected JSON on the controller, re-stage its exact bytes plus
#   # an ack containing controller_archive_path/hash and the controller nonce
#   python3 headless_preexisting_fixture_guest.py crash --plan PLAN --ack ACK
#   python3 headless_preexisting_fixture_guest.py legacy-start --plan PLAN --connected CONNECTED --deadline 60
#   # after native update acceptance/rollback is archived:
#   python3 headless_preexisting_fixture_guest.py cleanup --plan PLAN --active-daemon FINAL_PHASE_RECEIPT

def run(argv:list[str],timeout:int=30,input_bytes:bytes|None=None,ok:bool=True)->dict:
    if timeout<1 or timeout>120: raise GuestError("invalid command timeout")
    p=subprocess.run(argv,input=input_bytes,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,check=False)
    if len(p.stdout)>MAX_OUTPUT or len(p.stderr)>MAX_OUTPUT: raise GuestError("command output exceeds bound")
    row={"argv":argv,"rc":p.returncode,"stdout":p.stdout.decode(errors="replace"),"stderr":p.stderr.decode(errors="replace"),"stdout_sha256":hashlib.sha256(p.stdout).hexdigest(),"stderr_sha256":hashlib.sha256(p.stderr).hexdigest()}
    if ok and p.returncode!=0: raise GuestError(f"command failed: {pathlib.Path(argv[0]).name} rc={p.returncode}")
    return row

def _safe_cli_value(value:object)->str:
    return value if isinstance(value,str) and len(value)<=160 and re.fullmatch(r"[A-Za-z0-9 _.,:;()'\-/]+",value) else "invalid"

def run_cli(argv:list[str],stage:str,root:pathlib.Path)->dict:
    if stage not in ('import','connect','disconnect','status','doctor','list'): raise GuestError('invalid CLI stage')
    row=run(argv,60,ok=False)
    if row['rc']==0:return row
    parsed={}
    for raw in (row['stdout'],row['stderr']):
        try:
            candidate=json.loads(raw)
            if isinstance(candidate,dict):parsed=candidate;break
        except (TypeError,json.JSONDecodeError):pass
    result=parsed.get('error',parsed) if isinstance(parsed,dict) else {}
    if not isinstance(result,dict):result={}
    safe={k:_safe_cli_value(result.get(k)) for k in ('error','code','message') if k in result}
    journal=run(['/usr/bin/journalctl','-u','amneziad.service','-n','40','--no-pager','--output=short-unix'],20,ok=False)
    keywords=sorted(set(re.findall(r'(?i)\b(error|failed|invalid|denied|permission|not found|unavailable|timeout)\b',journal['stdout']+journal['stderr'])))
    raw=json.dumps({'argv':argv,'stdout_b64':base64.b64encode(row['stdout'].encode()).decode(),'stderr_b64':base64.b64encode(row['stderr'].encode()).decode(),'journal_b64':base64.b64encode((journal['stdout']+journal['stderr']).encode()).decode()},sort_keys=True,separators=(',',':')).encode()
    raw_path=root/f'cli-failure-{stage}.protected.json';write_private(raw_path,raw)
    raise CliFailure({'stage':stage,'argv':argv,'rc':row['rc'],'stdout':{'size':len(row['stdout'].encode()),'sha256':row['stdout_sha256']},'stderr':{'size':len(row['stderr'].encode()),'sha256':row['stderr_sha256']},'parsed':safe or 'invalid','journal':{'size':len((journal['stdout']+journal['stderr']).encode()),'sha256':hashlib.sha256((journal['stdout']+journal['stderr']).encode()).hexdigest(),'excerpt_keywords':keywords[:8]},'protected_raw':file_id(str(raw_path))})

def load_plan(path:str)->FixturePlan:
    raw=json.loads(pathlib.Path(path).read_text()); b=lambda x:BinaryIdentity(**raw[x])
    p=FixturePlan(*(raw[k] for k in ("run_id","profile","nonce","controller_nonce","runtime_uid","owned_root","socket_path")),b("cli"),b("setup_daemon"),b("legacy_daemon"),raw["setup_version"],raw["legacy_version"]); p.validate(); return p

def secure_root(p:FixturePlan,create:bool=False)->pathlib.Path:
    root=pathlib.Path(p.owned_root)
    if create: root.mkdir(parents=True,mode=0o700,exist_ok=False)
    cur=root
    while str(cur)!="/":
        s=cur.lstat()
        if stat.S_ISLNK(s.st_mode) or s.st_uid!=0 or (s.st_mode&0o022): raise GuestError("owned path is unsafe")
        if str(cur)=="/var/lib/amnezia-release-lab": break
        cur=cur.parent
    return root

def file_id(path:str)->dict:
    p=pathlib.Path(path); s=p.lstat()
    if stat.S_ISLNK(s.st_mode) or not stat.S_ISREG(s.st_mode): raise GuestError("receipt path is not regular")
    data=p.read_bytes()
    return {"path":path,"uid":s.st_uid,"gid":s.st_gid,"mode":stat.S_IMODE(s.st_mode),"size":len(data),"sha256":hashlib.sha256(data).hexdigest()}

def _stage_config(plan:FixturePlan,path:str,data:bytes,interface:str)->dict:
    target=pathlib.PurePosixPath(path)
    if target.parent!=pathlib.PurePosixPath("/etc/amnezia/profiles") or target.name!=f"{interface}.conf" or len(data)>MAX_CONFIG:
        raise GuestError("config path/content is outside the verified fixture contract")
    parent=pathlib.Path(str(target.parent)); parent_stat=parent.lstat()
    if stat.S_ISLNK(parent_stat.st_mode) or not stat.S_ISDIR(parent_stat.st_mode) or parent_stat.st_uid!=0 or (stat.S_IMODE(parent_stat.st_mode)&0o022):
        raise GuestError("config root identity mismatch")
    try: text=data.decode("utf-8")
    except UnicodeDecodeError as exc: raise GuestError("baseline config is not valid UTF-8") from exc
    interface_section=False; table_off=False
    for line in text.splitlines():
        section=line.strip().lower()
        if section.startswith("[") and section.endswith("]"):
            interface_section=section=="[interface]"
        elif interface_section and line.strip()=="Table = off":
            table_off=True
    if not table_off: raise GuestError("baseline config must disable wg-quick route ownership")
    write_private(pathlib.Path(path),data)
    identity=file_id(path)
    if identity!={**identity,"uid":0,"gid":0,"mode":0o600} or identity["path"]!=path or identity["size"]!=len(data) or identity["sha256"]!=hashlib.sha256(data).hexdigest():
        raise GuestError("staged config identity mismatch")
    return {**identity,"regular":True,"symlink":False,"basename":target.name,"interface":interface,"length":len(data),"source":"verified-fixture-config","table":"off"}

def _baseline_config_meta(plan:FixturePlan,meta:dict)->dict:
    expected=build_contract(plan,server_public_key=str(meta["contract"]["wireguard"]["server_public_key"]))["baseline_config"]
    if not isinstance(meta,dict) or not isinstance(meta.get("baseline_config"),dict): raise GuestError("baseline config proof missing")
    row=meta["baseline_config"]
    if row.get("path")!=expected["path"] or row.get("basename")!=expected["basename"] or row.get("interface")!=expected["interface"] or row.get("length")!=row.get("size") or row.get("uid")!=0 or row.get("gid")!=0 or row.get("mode")!=0o600 or row.get("regular") is not True or row.get("symlink") is not False or not isinstance(row.get("sha256"),str) or len(row["sha256"])!=64:
        raise GuestError("baseline config proof mismatch")
    return row

def _verify_baseline_config(path:str,proof:dict)->dict:
    actual=file_id(path)
    for key in ("path","uid","gid","mode","size","sha256"):
        if actual.get(key)!=proof.get(key): raise GuestError("baseline config changed after staging")
    data=pathlib.Path(path).read_bytes(); interface_section=False; table_off=False
    try: text=data.decode("utf-8")
    except UnicodeDecodeError as exc: raise GuestError("baseline config encoding changed") from exc
    for line in text.splitlines():
        section=line.strip().lower()
        if section.startswith("[") and section.endswith("]"): interface_section=section=="[interface]"
        elif interface_section and line.strip()=="Table = off": table_off=True
    if not table_off or len(data)!=proof.get("length") or pathlib.PurePosixPath(path).name!=proof.get("basename"): raise GuestError("baseline config content/path validation failed")
    return {**proof,"verified":True}

def _open_legacy_log(root:pathlib.Path):
    path=root/'logs/legacy.log'; flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0)
    fd=os.open(path,flags,0o600); os.fchmod(fd,0o600); os.fchown(fd,0,0)
    return path,os.fdopen(fd,'wb',buffering=0)

def _private_file_id(path:pathlib.Path)->dict:
    s=path.lstat()
    if stat.S_ISLNK(s.st_mode) or not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_gid!=0 or stat.S_IMODE(s.st_mode)!=0o600 or s.st_size>MAX_LEGACY_LOG:
        raise GuestError('legacy log identity or size invalid')
    data=path.read_bytes()
    return {'path':str(path),'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode),'size':len(data),'sha256':hashlib.sha256(data).hexdigest()}

def _clean_managed_receipt(path:pathlib.Path,service_gid:int)->dict:
    expected_modes={'/var/lib/amnezia/managed-routes.json':0o600,
                    '/var/lib/amnezia/routing-controller.json':0o660}
    if str(path) not in expected_modes: raise GuestError('unexpected managed receipt path')
    s=path.lstat()
    if stat.S_ISLNK(s.st_mode) or not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_gid!=service_gid or stat.S_IMODE(s.st_mode)!=expected_modes[str(path)]:
        raise GuestError('managed receipt ownership or mode mismatch')
    data=path.read_bytes()
    try: value=json.loads(data)
    except (TypeError,json.JSONDecodeError) as exc: raise GuestError('managed receipt JSON invalid') from exc
    if path.name=='managed-routes.json':
        if set(value)!={'version','mode','interface','routes','bypassRoutes','criticalBypassRoutes','bypassRulePriority','fullRulePriority','dnsInterface','dnsServers','dnsDomains','postconditionDiagnostics','needsReapply'} or value!={**value,'version':2,'mode':'only-forward','interface':'','routes':[],'bypassRoutes':[],'criticalBypassRoutes':[],'bypassRulePriority':1001,'fullRulePriority':1100,'dnsInterface':'','dnsServers':[],'dnsDomains':[],'postconditionDiagnostics':{},'needsReapply':False}: raise GuestError('managed route receipt is not clean-retired state')
    else:
        if set(value)!={'version','activeProfile','activeInterface','policyRevision','policyContentHash','policySource','policyEndpoint','policyResolvedSites','policyLoaded','policyMetadata','routingDegraded','routingError','needsReapply','recoveryRequired'} or value!={**value,'version':2,'activeProfile':'','activeInterface':'','policyRevision':'','policyContentHash':'','policySource':'','policyEndpoint':'','policyResolvedSites':{},'policyLoaded':False,'policyMetadata':None,'routingDegraded':False,'routingError':'','needsReapply':False,'recoveryRequired':False}: raise GuestError('controller receipt is not clean-retired state')
    return file_id(str(path))

def _retirement_observe(path:pathlib.Path)->dict:
    try:
        s=path.lstat(); data=path.read_bytes()
        return {'path':str(path),'exists':True,'device':s.st_dev,'inode':s.st_ino,'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode),'size':len(data),'sha256':hashlib.sha256(data).hexdigest()}
    except FileNotFoundError: return {'path':str(path),'exists':False}

def _rollback_managed_receipts(root:pathlib.Path,retiring:list[tuple[pathlib.Path,pathlib.Path,dict,tuple[int,int]]],reason:str)->None:
    unresolved=[]
    for src,tmp,source,identity in reversed(retiring):
        try:
            if os.path.lexists(src):
                unresolved.append({'source':_retirement_observe(src),'retiring':_retirement_observe(tmp),'expected':source,'reason':'canonical-path-reappeared'}); continue
            if not os.path.lexists(tmp):
                unresolved.append({'source':_retirement_observe(src),'retiring':_retirement_observe(tmp),'expected':source,'reason':'retiring-path-missing'}); continue
            observed=file_id(str(tmp)); st=tmp.lstat()
            if observed.get('sha256')!=source.get('sha256') or (st.st_dev,st.st_ino)!=identity:
                unresolved.append({'source':_retirement_observe(src),'retiring':_retirement_observe(tmp),'expected':source,'reason':'retiring-identity-drift'}); continue
            os.rename(tmp,src); restored=src.lstat()
            if (restored.st_dev,restored.st_ino)!=identity or file_id(str(src)).get('sha256')!=source.get('sha256'):
                unresolved.append({'source':_retirement_observe(src),'retiring':_retirement_observe(tmp),'expected':source,'reason':'restore-readback-mismatch'})
        except BaseException:
            unresolved.append({'source':_retirement_observe(src),'retiring':_retirement_observe(tmp),'expected':source,'reason':'restore-exception'})
    if unresolved:
        recovery={'schema':1,'operation':'headless-preexisting-retire-managed-receipts-recovery','reason':reason[:160],'entries':unresolved}
        recovery_path=root/'managed-receipt-retirement-recovery.json'
        try: write_private(recovery_path,json.dumps(recovery,sort_keys=True,separators=(',',':')).encode())
        except BaseException: raise GuestError('managed receipt retirement rollback failed; protected recovery could not be written')
        raise GuestError('managed receipt retirement rollback incomplete; protected recovery written')

def _retire_clean_managed_receipts(p:FixturePlan,root:pathlib.Path,service_gid:int)->dict:
    source_paths=tuple(pathlib.Path(x) for x in p.managed_receipts)
    if {str(x) for x in source_paths}!={'/var/lib/amnezia/managed-routes.json','/var/lib/amnezia/routing-controller.json'}: raise GuestError('managed receipt set is not canonical')
    if any(os.stat(x).st_dev!=os.stat(root).st_dev for x in source_paths): raise GuestError('managed receipt archive crosses filesystems')
    sources=[_clean_managed_receipt(x,service_gid) for x in source_paths]
    archive_dir=root/'retired-managed'; archive_dir.mkdir(mode=0o700,exist_ok=False)
    archives=[]
    for source in sources:
        target=archive_dir/pathlib.Path(source['path']).name
        write_private(target,pathlib.Path(source['path']).read_bytes())
        archived=file_id(str(target))
        if archived['uid']!=0 or archived['gid']!=0 or archived['mode']!=0o600 or archived['size']!=source['size'] or archived['sha256']!=source['sha256']: raise GuestError('managed receipt archive readback mismatch')
        archives.append(archived)
    for source in sources:
        current=_clean_managed_receipt(pathlib.Path(source['path']),service_gid)
        if current!=source: raise GuestError('managed receipt changed before retirement')
    source_identity={source['path']:(pathlib.Path(source['path']).lstat().st_dev,pathlib.Path(source['path']).lstat().st_ino) for source in sources}
    retiring=[]
    try:
        for source in sources:
            src=pathlib.Path(source['path']); tmp=archive_dir/('.'+src.name+'.retiring')
            if os.path.lexists(tmp): raise GuestError('managed receipt retirement collision')
            os.rename(src,tmp); retiring.append((src,tmp,source,source_identity[source['path']]))
        for src,tmp,source,identity in retiring:
            if os.path.lexists(src) or not os.path.lexists(tmp) or file_id(str(tmp))['sha256']!=source['sha256'] or (tmp.lstat().st_dev,tmp.lstat().st_ino)!=identity: raise GuestError('managed receipt retirement identity mismatch')
        for _,tmp,_,_ in retiring: tmp.unlink()
    except BaseException as exc:
        _rollback_managed_receipts(root,retiring,str(exc))
        raise GuestError('managed receipt retirement aborted and rolled back') from exc
    absence=[{'path':source['path'],'exists':os.path.lexists(source['path'])} for source in sources]
    if any(row['exists'] for row in absence): raise GuestError('managed receipt retirement left source path')
    proof={'schema':1,'operation':'headless-preexisting-retire-managed-receipts','source':sources,'archives':archives,'absence':absence}
    proof_path=root/'managed-receipt-retirement.json'; write_private(proof_path,json.dumps(proof,sort_keys=True,separators=(',',':')).encode())
    return {'schema':1,'operation':'headless-preexisting-retire-managed-receipts','source':sources,'archives':archives,'absence':absence,'proof':file_id(str(proof_path))}

def _legacy_failure(stage:str,argv:list[str],proc:subprocess.Popen,log_path:pathlib.Path,log,*,timeout:bool=False,unit:dict|None=None,runtime:dict|None=None)->None:
    identity_drift=False
    try:
        if proc.poll() is None:
            try: exact_kill(proc_id(proc.pid))
            except FileNotFoundError: pass
            except GuestError: identity_drift=True
            if not identity_drift:
                try: proc.wait(timeout=5)
                except subprocess.TimeoutExpired: proc.kill(); proc.wait(timeout=5)
    finally:
        try: log.flush(); os.fsync(log.fileno())
        finally: log.close()
    diagnostic={'stage':stage,'argv':list(argv),'rc':proc.returncode,'timeout':bool(timeout),'log':_private_file_id(log_path)}
    if identity_drift: diagnostic['termination']='identity-drift'
    if unit is not None: diagnostic['unit']={key:str(unit.get(key,'')) for key in ('MainPID','ActiveState','SubState','Job')}
    if runtime is not None: diagnostic['runtime_branch']=str(runtime.get('branch',''))
    raise LegacyProcessFailure(diagnostic)

def _diagnostic_state(p:FixturePlan,identity:dict,root:pathlib.Path)->dict:
    journal=run(['/usr/bin/journalctl','-u','amneziad.service','-n','80','--no-pager','--output=short-unix'],20,ok=False)
    props={key:run(['/usr/bin/systemctl','show','-p',key,'--value','amneziad.service'],10,ok=False)['stdout'] for key in ('MainPID','ActiveState','SubState','Job')}
    managed=[]
    for path in p.managed_receipts:
        try: managed.append(file_id(path))
        except FileNotFoundError: managed.append({'path':path,'exists':False})
    state={'schema':1,'identity':{key:identity.get(key) for key in ('pid','start_ticks','exe','exe_sha256','uid','cmdline_sha256')},'service':props,'managed':managed,'journal':{'stdout_b64':base64.b64encode(journal['stdout'].encode()).decode(),'stderr_b64':base64.b64encode(journal['stderr'].encode()).decode(),'stdout_sha256':journal['stdout_sha256'],'stderr_sha256':journal['stderr_sha256']}}
    path=root/'pre-disconnect-state.protected.json';write_private(path,json.dumps(state,sort_keys=True,separators=(',',':')).encode());return file_id(str(path))

def _tracer_pid(pid:int)->int:
    raw=(pathlib.Path('/proc')/str(pid)/'status').read_text()
    return int(next(line for line in raw.splitlines() if line.startswith('TracerPid:')).split()[1])

def _stop_trace(proc:subprocess.Popen)->None:
    if proc.poll() is None:
        proc.terminate()
        try: proc.wait(timeout=5)
        except subprocess.TimeoutExpired: proc.kill();proc.wait(timeout=5)

def _pre_disconnect_diagnostic(p:FixturePlan,connected:dict,root:pathlib.Path,disconnect)->tuple[dict,dict]:
    identity=connected.get('daemon') if isinstance(connected,dict) else None
    if not isinstance(identity,dict) or any(key not in identity for key in ('pid','start_ticks','exe_sha256')): raise GuestError('connected daemon binding absent before disconnect')
    try: fresh=proc_id(int(identity['pid']))
    except (FileNotFoundError,OSError,ValueError,KeyError): fresh=dict(identity)
    if any(fresh.get(key)!=identity.get(key) for key in ('pid','start_ticks','exe','exe_sha256','uid','cmdline_sha256')): raise GuestError('connected daemon binding changed before disconnect')
    prefix=root/'pre-disconnect-strace';trace=None;reason='strace-unavailable';shards=[]
    if pathlib.Path('/usr/bin/strace').is_file() and pathlib.Path('/usr/bin/timeout').is_file():
        trace=subprocess.Popen(['/usr/bin/timeout','--signal=TERM','--kill-after=2','30','/usr/bin/strace','-ff','-f','-s','256','-e','trace=execve,exit,exit_group,write','-o',str(prefix),'-p',str(fresh['pid'])],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        for _ in range(100):
            try:
                if _tracer_pid(fresh['pid'])>0: reason='attached';break
            except (FileNotFoundError,StopIteration,ValueError): pass
            time.sleep(.1)
        else:
            _stop_trace(trace);trace=None;reason='ptrace-attach-unavailable'
        if trace is not None:
            rebound=proc_id(fresh['pid'])
            if any(rebound.get(key)!=fresh.get(key) for key in ('pid','start_ticks','exe','exe_sha256','uid','cmdline_sha256')):
                _stop_trace(trace);trace=None;reason='ptrace-identity-drift'
    diagnostic={'schema':1,'target':{key:fresh[key] for key in ('pid','start_ticks','exe_sha256')},'strace':{'available':trace is not None,'reason':reason,'scope':['execve','exit','exit_group','write'],'duration_limit_seconds':30}}
    failure=None;result=None
    try: result=disconnect()
    except BaseException as exc: failure=exc
    if trace is not None: _stop_trace(trace)
    for path in sorted(root.glob('pre-disconnect-strace*')):
        try:
            if path.is_symlink() or not path.is_file(): raise GuestError('invalid strace shard')
            os.chmod(path,0o600);shards.append(file_id(str(path)))
        except FileNotFoundError: pass
    diagnostic['strace']['shards']=shards
    diagnostic['state']=_diagnostic_state(p,fresh,root)
    receipt_path=root/'pre-disconnect-diagnostic.json';write_private(receipt_path,json.dumps(diagnostic,sort_keys=True,separators=(',',':')).encode());diagnostic['receipt']=file_id(str(receipt_path))
    if failure is not None:
        if isinstance(failure,CliFailure): failure.diagnostic['pre_disconnect']=diagnostic
        raise failure
    return result,diagnostic

def _legacy_connect_process_state(proc:subprocess.Popen,expected:dict)->dict:
    """Read the staged legacy daemon identity without ever adopting a new PID."""
    try:
        current=proc_id(int(expected['pid']))
    except FileNotFoundError:
        return {'exists':False,'returncode':proc.poll()}
    except OSError:
        return {'exists':'unknown','returncode':proc.poll(),'identity_read':'failed'}
    fields=('pid','start_ticks','exe','exe_sha256','uid','cmdline_sha256')
    if any(current.get(key)!=expected.get(key) for key in fields):
        return {'exists':True,'identity_drift':True,'expected':{key:expected.get(key) for key in fields}}
    return {'exists':True,'returncode':proc.poll(),'identity':{key:current.get(key) for key in fields},'state':current.get('state')}

def _legacy_connect_diagnostic(p:FixturePlan,proc:subprocess.Popen,root:pathlib.Path,log,connect)->tuple[dict,dict]:
    """Trace and retain one staged .37 connect attempt before cleanup can run."""
    expected=proc_id(proc.pid)
    if expected.get('uid')!=0 or expected.get('exe')!=p.legacy_daemon.path or expected.get('exe_sha256')!=p.legacy_daemon.sha256:
        raise GuestError('legacy connect daemon identity mismatch before trace')
    prefix=root/'legacy-connect-strace';trace=None;reason='strace-unavailable';shards=[]
    if pathlib.Path('/usr/bin/strace').is_file() and pathlib.Path('/usr/bin/timeout').is_file():
        trace=subprocess.Popen(['/usr/bin/timeout','--signal=TERM','--kill-after=2','30','/usr/bin/strace','-ff','-f','-s','256','-e','trace=execve,exit,exit_group,write','-o',str(prefix),'-p',str(expected['pid'])],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        for _ in range(100):
            try:
                if _tracer_pid(expected['pid'])>0: reason='attached';break
            except (FileNotFoundError,StopIteration,ValueError): pass
            time.sleep(.1)
        else:
            _stop_trace(trace);trace=None;reason='ptrace-attach-unavailable'
        if trace is not None:
            rebound=proc_id(expected['pid'])
            if any(rebound.get(key)!=expected.get(key) for key in ('pid','start_ticks','exe','exe_sha256','uid','cmdline_sha256')):
                _stop_trace(trace);trace=None;reason='ptrace-identity-drift'
    diagnostic={'schema':1,'stage':'baseline-handoff','target':{key:expected[key] for key in ('pid','start_ticks','exe_sha256','uid','cmdline_sha256')},'strace':{'available':trace is not None,'reason':reason,'scope':['execve','exit','exit_group','write'],'duration_limit_seconds':30}}
    failure=None;result=None
    try: result=connect()
    except BaseException as exc: failure=exc
    if trace is not None: _stop_trace(trace)
    for path in sorted(root.glob('legacy-connect-strace*')):
        try:
            if path.is_symlink() or not path.is_file(): raise GuestError('invalid legacy connect strace shard')
            os.chmod(path,0o600);shards.append(file_id(str(path)))
        except FileNotFoundError: pass
    diagnostic['strace']['shards']=shards
    if failure is not None:
        def bounded(argv):
            try: return run(argv,10,ok=False)
            except subprocess.TimeoutExpired: return {'argv':argv,'rc':-124,'stdout':'','stderr':'command timeout','stdout_sha256':hashlib.sha256(b'').hexdigest(),'stderr_sha256':hashlib.sha256(b'command timeout').hexdigest()}
        status_row=bounded([p.owned_root+'/legacy/amnezia-cli','--socket',p.socket_path,'--json','status'])
        diagnostic['status_after_timeout']={'argv':status_row['argv'],'rc':status_row['rc'],'stdout_b64':base64.b64encode(status_row['stdout'].encode()).decode(),'stderr_b64':base64.b64encode(status_row['stderr'].encode()).decode(),'stdout_sha256':status_row['stdout_sha256'],'stderr_sha256':status_row['stderr_sha256']}
        diagnostic['process_after_timeout']=_legacy_connect_process_state(proc,expected)
        status_state=''
        try:
            status_json=json.loads(status_row['stdout'])
            status_state=status_json.get('result',status_json).get('state','') if isinstance(status_json,dict) else ''
        except (TypeError,json.JSONDecodeError): pass
        process_state=diagnostic['process_after_timeout'];identity=process_state.get('identity') if isinstance(process_state,dict) else None
        target=diagnostic['target'];same_identity=isinstance(identity,dict) and process_state.get('exists') is True and process_state.get('identity_drift') is not True and all(identity.get(key)==target.get(key) for key in ('pid','start_ticks','exe_sha256','uid','cmdline_sha256'))
        if status_row['rc']==0 and status_state=='connected' and same_identity: diagnostic['classification']='late-connected'
        elif status_row['rc']==0 and status_state=='connected': diagnostic['classification']='identity-drift'
        elif process_state.get('exists') is False: diagnostic['classification']='daemon-exited-before-status'
        elif status_row['rc']!=0: diagnostic['classification']='status-unavailable-or-late'
        else: diagnostic['classification']='daemon-replied-not-connected'
        snapshots={}
        for name,argv in (
            ('ip_link',['/usr/sbin/ip','link','show']),
            ('ip_route',['/usr/sbin/ip','-N','route','show','table','51821']),
            ('ip_rule',['/usr/sbin/ip','rule','show']),
            ('ip_rule6',['/usr/sbin/ip','-6','rule','show']),
        ):
            row=bounded(argv);snapshots[name]={'argv':row['argv'],'rc':row['rc'],'stdout_b64':base64.b64encode(row['stdout'].encode()).decode(),'stderr_b64':base64.b64encode(row['stderr'].encode()).decode(),'stdout_sha256':row['stdout_sha256'],'stderr_sha256':row['stderr_sha256']}
        diagnostic['kernel_after_timeout']=snapshots
        managed=[]
        for path in p.managed_receipts:
            try: managed.append(file_id(path))
            except FileNotFoundError: managed.append({'path':path,'exists':False})
        diagnostic['managed_after_timeout']=managed
    try: log.flush();os.fsync(log.fileno())
    except (AttributeError,ValueError,OSError): pass
    diagnostic['log']=_private_file_id(root/'logs/legacy.log')
    receipt_path=root/'legacy-connect-diagnostic.protected.json';write_private(receipt_path,json.dumps(diagnostic,sort_keys=True,separators=(',',':')).encode());diagnostic['receipt']=file_id(str(receipt_path))
    if failure is not None:
        if isinstance(failure,CliFailure): failure.diagnostic['legacy_connect']=diagnostic
        raise failure
    return result,diagnostic

def proc_id(pid:int)->dict:
    q=pathlib.Path("/proc")/str(pid); raw=(q/"stat").read_text(); fields=raw[raw.rfind(")")+2:].split(); exe=(q/"exe").resolve(strict=True); cmd=(q/"cmdline").read_bytes(); status=(q/"status").read_text()
    return {"pid":pid,"start_ticks":int(fields[19]),"state":fields[0],"exe":str(exe),"exe_sha256":hashlib.sha256(exe.read_bytes()).hexdigest(),"uid":int(next(x for x in status.splitlines() if x.startswith("Uid:")).split()[1]),"cmdline_sha256":hashlib.sha256(cmd).hexdigest(),"argv":[x.decode() for x in cmd.rstrip(b"\0").split(b"\0")]}

def main_pid()->int:
    row=run(["/usr/bin/systemctl","show","-p","MainPID","--value","amneziad.service"]); pid=int(row["stdout"].strip())
    if pid<=1: raise GuestError("amneziad MainPID unavailable")
    return pid

def write_private(path:pathlib.Path,data:bytes)->None:
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),0o600)
    try:
        if os.write(fd,data)!=len(data): raise GuestError("short private write")
        os.fsync(fd)
    finally: os.close(fd)

def prepare(p:FixturePlan)->dict:
    if os.geteuid()!=0: raise GuestError("prepare requires root")
    for tool in ("/usr/sbin/ip","/usr/bin/wg","/usr/bin/wg-quick","/usr/bin/python3","/usr/bin/systemctl","/usr/bin/ping"):
        if not pathlib.Path(tool).is_file() or not os.access(tool,os.X_OK): raise GuestError("required tool missing: "+tool)
    root=secure_root(p,True); (root/"secrets").mkdir(0o700); (root/"public").mkdir(0o700); (root/"logs").mkdir(0o700)
    marker=f"amnezia-release-lab:{p.run_id}:headless-preexisting:{p.nonce}"; write_private(root/"marker",(marker+"\n").encode())
    server_key=run(["/usr/bin/wg","genkey"])["stdout"].strip(); client_key=run(["/usr/bin/wg","genkey"])["stdout"].strip()
    server_pub=run(["/usr/bin/wg","pubkey"],input_bytes=(server_key+"\n").encode())["stdout"].strip(); client_pub=run(["/usr/bin/wg","pubkey"],input_bytes=(client_key+"\n").encode())["stdout"].strip()
    contract=build_contract(p,server_public_key=server_pub); server_if=f"afxs{p.tag}"
    write_private(root/"secrets/server.key",(server_key+"\n").encode()); write_private(root/"secrets/client.key",(client_key+"\n").encode())
    policy=contract["policy"]["bytes"].encode(); write_private(root/"public/policy.json",policy)
    profile=json.dumps(contract["profile_document"],sort_keys=True,separators=(",",":")).encode(); write_private(root/"public/profile.json",profile)
    baseline_profile=json.dumps(contract["baseline_profile_document"],sort_keys=True,separators=(",",":")).encode(); write_private(root/"public/baseline-profile.json",baseline_profile)
    config=(f"[Interface]\nPrivateKey = {client_key}\nAddress = {p.tunnel_client}/30\n\n[Peer]\nPublicKey = {server_pub}\nEndpoint = {p.underlay_server}:51820\nAllowedIPs = 10.204.{p.octet}.0/30, {p.routed_test_prefix}\nPersistentKeepalive = 5\n").encode()
    cfg=pathlib.Path(p.config_path); cfg.parent.mkdir(parents=True,exist_ok=True); write_private(cfg,config)
    baseline_config=(f"[Interface]\nPrivateKey = {client_key}\nAddress = {p.tunnel_client}/30\nTable = off\n\n[Peer]\nPublicKey = {server_pub}\nEndpoint = {p.underlay_server}:51820\nAllowedIPs = 10.204.{p.octet}.0/30, {p.routed_test_prefix}\nPersistentKeepalive = 5\n").encode()
    baseline_config_meta=_stage_config(p,p.baseline_config_path,baseline_config,p.wg_interface)
    commands=[
      ["/usr/sbin/ip","netns","add",p.netns],["/usr/sbin/ip","link","add",p.host_veth,"type","veth","peer","name",p.peer_veth],
      ["/usr/sbin/ip","link","set",p.peer_veth,"netns",p.netns],["/usr/sbin/ip","addr","add",p.underlay_host+"/30","dev",p.host_veth],["/usr/sbin/ip","link","set",p.host_veth,"up"],
      ["/usr/sbin/ip","-n",p.netns,"link","set","lo","up"],["/usr/sbin/ip","-n",p.netns,"addr","add",p.underlay_server+"/30","dev",p.peer_veth],["/usr/sbin/ip","-n",p.netns,"link","set",p.peer_veth,"up"],
      ["/usr/sbin/ip","-n",p.netns,"link","add",server_if,"type","wireguard"],
      ["/usr/sbin/ip","netns","exec",p.netns,"/usr/bin/wg","set",server_if,"private-key",str(root/"secrets/server.key"),"listen-port","51820","peer",client_pub,"allowed-ips",p.tunnel_client+"/32"],
      ["/usr/sbin/ip","-n",p.netns,"addr","add",p.tunnel_server+"/30","dev",server_if],["/usr/sbin/ip","-n",p.netns,"addr","add",p.routed_test_server,"dev",server_if],["/usr/sbin/ip","-n",p.netns,"link","set",server_if,"up"]]
    completed=[]; proc=None
    try:
        for argv in commands: completed.append(run(argv))
        log=open(root/"logs/http.log","xb",buffering=0)
        proc=subprocess.Popen(["/usr/sbin/ip","netns","exec",p.netns,"/usr/bin/python3","-m","http.server","17865","--bind",p.routed_test_server.split('/',1)[0],"--directory",str(root/"public")],stdin=subprocess.DEVNULL,stdout=log,stderr=log,start_new_session=True)
        time.sleep(.25)
        if proc.poll() is not None: raise GuestError("policy HTTP server exited")
        ident=proc_id(proc.pid); meta={"marker":marker,"contract":contract,"contract_sha256":_sha(contract),"netns_inode":os.stat(f"/var/run/netns/{p.netns}").st_ino,"http":ident,"server_interface":server_if,"baseline_config":baseline_config_meta}
        write_private(root/"fixture.json",json.dumps(meta,sort_keys=True,separators=(",",":")).encode())
        return {"schema":1,"operation":"headless-preexisting-prepare","origin":"guest","transport":"qga","run_id":p.run_id,"profile":p.profile,"nonce":p.nonce,"contract":contract,"contract_sha256":_sha(contract),"netns_inode":meta["netns_inode"],"http":ident,"baseline_config":baseline_config_meta,"files":[file_id(str(root/"public/policy.json")),file_id(str(root/"public/profile.json")),file_id(str(root/"public/baseline-profile.json")),file_id(p.config_path),baseline_config_meta]}
    except BaseException:
        if proc is not None and proc.poll() is None:
            try:
                ident=proc_id(proc.pid); exact_kill(ident); wait_gone(ident)
            except (GuestError,OSError): pass
        run(["/usr/sbin/ip","netns","del",p.netns],ok=False); run(["/usr/sbin/ip","link","del",p.host_veth],ok=False); raise

def parse_cli(row:dict)->dict:
    try: row["json"]=json.loads(row["stdout"])
    except json.JSONDecodeError as e: raise GuestError("CLI did not return JSON") from e
    row.pop("stdout"); row.pop("stderr"); return row

def connect_collect(p:FixturePlan,deadline:int)->dict:
    import grp
    root=secure_root(p); meta=json.loads((root/"fixture.json").read_text()); c=meta["contract"]
    daemon=proc_id(main_pid())
    if daemon["exe"]!=p.setup_daemon.path or daemon["exe_sha256"]!=p.setup_daemon.sha256 or daemon["uid"]!=0: raise GuestError("setup daemon identity mismatch")
    cli={}; started=int(time.time())
    for key in ("import","connect"):
        cli[key]=parse_cli(run_cli(c["cli"][key],key,root))
    end=time.monotonic()+deadline; wg=None; status=None
    while time.monotonic()<end:
        status=parse_cli(run(c["cli"]["status"]))
        hs=run(["/usr/bin/wg","show",p.wg_interface,"latest-handshakes"],ok=False); tr=run(["/usr/bin/wg","show",p.wg_interface,"transfer"],ok=False)
        if hs["rc"]==tr["rc"]==0 and hs["stdout"].strip() and tr["stdout"].strip():
            hf=hs["stdout"].split(); tf=tr["stdout"].split()
            if len(hf)>=2 and len(tf)>=3: wg={"interface":p.wg_interface,"peer_public_key":hf[0],"latest_handshake":int(hf[-1]),"rx_bytes":int(tf[-2]),"tx_bytes":int(tf[-1])}
        result=status["json"].get("result",status["json"])
        if wg and wg["latest_handshake"]>=started and wg["rx_bytes"]>0 and wg["tx_bytes"]>0 and result.get("state")=="connected": break
        time.sleep(1)
    else: raise GuestError("bounded connected/handshake readiness expired")
    target=p.routed_test_server.split('/',1)[0]
    route_raw=run(["/usr/sbin/ip","-4","-j","route","get",target])
    route_rows=json.loads(route_raw["stdout"])
    route_get=[{k:x[k] for k in ("dst","dev","prefsrc","table") if k in x} for x in route_rows]
    if len(route_get)!=1 or route_get[0].get("dst")!=target or route_get[0].get("dev")!=p.wg_interface: raise GuestError("routed test route did not select product WireGuard interface")
    ping=run(["/usr/bin/ping","-n","-c","1","-W","3","-I",p.wg_interface,target],10)
    routed_probe={"target":target,"prefix":p.routed_test_prefix,"interface":p.wg_interface,"route_get":route_get,"traffic":{"argv":ping["argv"],"rc":ping["rc"],"stdout_sha256":ping["stdout_sha256"],"stderr_sha256":ping["stderr_sha256"],"verified":True}}
    cli["status"]=status
    for key in ("doctor","list"): cli[key]=parse_cli(run(c["cli"][key]))
    routes=[line for line in (run(["/usr/sbin/ip","-N","route","show","table","51821"])["stdout"]+"\n"+run(["/usr/sbin/ip","-6","-N","route","show","table","51821"])["stdout"]).splitlines() if line.strip()]
    rules=(run(["/usr/sbin/ip","rule","show"])["stdout"]+"\n"+run(["/usr/sbin/ip","-6","rule","show"])["stdout"]).splitlines()
    service_group={"name":"amnezia","gid":grp.getgrnam("amnezia").gr_gid}
    receipts=[]
    for path in p.managed_receipts:
        identity=file_id(path); identity.update({"regular":True,"symlink":False}); receipts.append(identity)
    if any(row["gid"]!=service_group["gid"] for row in receipts): raise GuestError("managed receipt service group mismatch")
    http_log=file_id(str(root/"logs/http.log")); raw=(root/"logs/http.log").read_text(errors="replace")
    if 'GET /policy.json HTTP/' not in raw or ' 200 ' not in raw: raise GuestError("policy HTTP GET readback absent")
    return {"schema":1,"operation":"headless-preexisting-connected","origin":"guest","transport":"qga","injected":False,"run_id":p.run_id,"profile":p.profile,"nonce":p.nonce,"contract_sha256":meta["contract_sha256"],"server_public_key":c["wireguard"]["server_public_key"],"daemon":daemon,"cli":cli,"connect_started_epoch":started,"collected_epoch":int(time.time()),"boot_id":pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),"wireguard":wg,"routed_probe":routed_probe,"kernel":{"table_51821":routes,"rules":rules},"service_group":service_group,"managed_receipts":receipts,"policy_http":{"path":"/policy.json","eof":True,"sha256":c["policy"]["sha256"],"log_sha256":http_log["sha256"]}}

def exact_kill(identity:dict)->None:
    fresh=proc_id(identity["pid"])
    for k in ("pid","start_ticks","exe","exe_sha256","uid","cmdline_sha256"):
        if fresh[k]!=identity[k]: raise GuestError("process identity changed before signal: "+k)
    os.kill(identity["pid"],getattr(signal,"SIGKILL",9))

def wait_gone(identity:dict,seconds:int=10)->None:
    end=time.monotonic()+seconds
    while time.monotonic()<end:
        try:
            fresh=proc_id(identity["pid"])
            if fresh["start_ticks"]!=identity["start_ticks"]: return
        except FileNotFoundError: return
        time.sleep(.05)
    raise GuestError("owned process did not disappear")

def remove_stale_control_socket(path:str,service_gid:int,managed_paths:tuple[str,...])->dict:
    p=pathlib.Path(path)
    if not p.is_absolute() or p.name in ("",".","..") or str(p.parent/p.name)!=path: raise GuestError("control socket path is not canonical")
    before=[file_id(x) for x in managed_paths]
    try: parent_fd=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    except FileNotFoundError:
        grand=p.parent.parent
        if str(grand)!="/run" or p.parent.name!="amnezia": raise GuestError("unexpected missing control socket parent")
        grand_fd=os.open(grand,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            gs=os.fstat(grand_fd)
            if not stat.S_ISDIR(gs.st_mode) or gs.st_uid!=0 or gs.st_gid!=0 or stat.S_IMODE(gs.st_mode)!=0o755: raise GuestError("runtime parent identity mismatch")
            try: os.stat(p.parent.name,dir_fd=grand_fd,follow_symlinks=False); raise GuestError("runtime directory appeared during clean transition")
            except FileNotFoundError: pass
            os.mkdir(p.parent.name,0o750,dir_fd=grand_fd);os.chown(p.parent.name,0,service_gid,dir_fd=grand_fd,follow_symlinks=False);os.chmod(p.parent.name,0o750,dir_fd=grand_fd,follow_symlinks=False)
            ds=os.stat(p.parent.name,dir_fd=grand_fd,follow_symlinks=False)
            if not stat.S_ISDIR(ds.st_mode) or ds.st_uid!=0 or ds.st_gid!=service_gid or stat.S_IMODE(ds.st_mode)!=0o750: raise GuestError("recreated runtime directory identity mismatch")
            child_fd=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try:
                try: os.stat(p.name,dir_fd=child_fd,follow_symlinks=False); raise GuestError("control socket appeared during clean transition")
                except FileNotFoundError: pass
            finally: os.close(child_fd)
        finally: os.close(grand_fd)
        after=[file_id(x) for x in managed_paths]
        if after!=before: raise GuestError("managed state changed during clean socket transition")
        return {"branch":"clean-absent","path":path,"socket":False,"symlink":False,"removed":False,"runtime_dir":{"path":str(p.parent),"uid":ds.st_uid,"gid":ds.st_gid,"mode":stat.S_IMODE(ds.st_mode),"device":ds.st_dev,"inode":ds.st_ino,"ctime_ns":ds.st_ctime_ns,"created":True},"managed_before":before,"managed_after":after}
    try:
        parent=os.fstat(parent_fd)
        if not stat.S_ISDIR(parent.st_mode) or parent.st_uid!=0 or parent.st_gid!=service_gid or stat.S_IMODE(parent.st_mode)!=0o750: raise GuestError("runtime directory identity mismatch")
        s=os.stat(p.name,dir_fd=parent_fd,follow_symlinks=False)
        def identity(value): return (value.st_dev,value.st_ino,value.st_ctime_ns,value.st_mode,value.st_uid,value.st_gid)
        if not stat.S_ISSOCK(s.st_mode) or s.st_uid!=0 or s.st_gid!=service_gid or stat.S_IMODE(s.st_mode)!=0o660: raise GuestError("stale control socket identity mismatch")
        probe=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);probe.settimeout(.25)
        try: result=probe.connect_ex(path)
        finally: probe.close()
        if result!=errno.ECONNREFUSED: raise GuestError("control socket is not proven stale")
        fresh=os.stat(p.name,dir_fd=parent_fd,follow_symlinks=False)
        if identity(fresh)!=identity(s) or not stat.S_ISSOCK(fresh.st_mode) or fresh.st_uid!=0 or fresh.st_gid!=service_gid or stat.S_IMODE(fresh.st_mode)!=0o660: raise GuestError("control socket identity changed before unlink")
        os.unlink(p.name,dir_fd=parent_fd)
        try: os.stat(p.name,dir_fd=parent_fd,follow_symlinks=False); raise GuestError("stale control socket removal incomplete")
        except FileNotFoundError: pass
        after=[file_id(x) for x in managed_paths]
        if after!=before: raise GuestError("managed state changed during stale socket removal")
    finally: os.close(parent_fd)
    return {"branch":"stale-removed","path":path,"uid":s.st_uid,"gid":s.st_gid,"mode":stat.S_IMODE(s.st_mode),"device":s.st_dev,"inode":s.st_ino,"ctime_ns":s.st_ctime_ns,"socket":True,"symlink":False,"connect_errno":result,"live_owner":False,"removed":True,"runtime_dir":{"path":str(p.parent),"uid":parent.st_uid,"gid":parent.st_gid,"mode":stat.S_IMODE(parent.st_mode),"device":parent.st_dev,"inode":parent.st_ino,"ctime_ns":parent.st_ctime_ns,"created":False},"managed_before":before,"managed_after":after}

def crash(p:FixturePlan,ack_path:str)->dict:
    ack=json.loads(pathlib.Path(ack_path).read_text()); root=secure_root(p)
    archive=str(ack.get("controller_archive_path",""))
    if ack.get("controller_nonce")!=p.controller_nonce or ack.get("durable_path","").startswith(p.owned_root+"/") is False or not archive.startswith("/var/lib/amnezia-release-lab/receipts/") or not re.fullmatch(r"[0-9a-f]{64}",str(ack.get("connected_receipt_sha256",""))) or ack.get("controller_archive_sha256")!=ack.get("connected_receipt_sha256"): raise GuestError("invalid controller archive ack")
    connected=json.loads(pathlib.Path(ack["durable_path"]).read_text())
    if _sha(connected)!=ack["connected_receipt_sha256"]: raise GuestError("durable connected receipt hash mismatch")
    dropin=pathlib.Path(f"/run/systemd/system/amneziad.service.d/90-amnezia-lab-{p.tag}.conf"); dropin.parent.mkdir(parents=True,exist_ok=True)
    content=b"[Service]\nRestart=no\n"; write_private(dropin,content); run(["/usr/bin/systemctl","daemon-reload"])
    effective=run(["/usr/bin/systemctl","show","-p","Restart","--value","amneziad.service"])["stdout"].strip()
    if effective!="no": raise GuestError("runtime Restart=no guard is not effective")
    ident=connected["daemon"]; exact_kill(ident); wait_gone(ident)
    time.sleep(.5)
    if run(["/usr/bin/systemctl","show","-p","MainPID","--value","amneziad.service"],ok=False)["stdout"].strip() not in ("","0"): raise GuestError("current daemon restarted after guarded crash")
    import grp
    stale_socket=remove_stale_control_socket(p.socket_path,grp.getgrnam("amnezia").gr_gid,p.managed_receipts)
    guard=file_id(str(dropin)); write_private(root/"restart-guard.json",json.dumps(guard,sort_keys=True,separators=(",",":")).encode())
    return {"schema":1,"operation":"headless-preexisting-crash","origin":"guest","transport":"qga","controller_nonce":p.controller_nonce,"connected_receipt_sha256":ack["connected_receipt_sha256"],"controller_archive_path":archive,"controller_archive_sha256":ack["controller_archive_sha256"],"restart_guard":guard,"stale_socket":stale_socket,"killed":ident,"observed_gone":True}

def legacy_start(p:FixturePlan,connected_path:str,deadline:int)->dict:
    connected=json.loads(pathlib.Path(connected_path).read_text()); before=[file_id(x) for x in p.managed_receipts]
    argv=[p.legacy_daemon.path,"--socket",p.socket_path,"--store","/var/lib/amnezia/profiles.json","--config-root","/etc/amnezia/profiles","--require-root-owned-config","--staging-root","/run/amnezia"]
    log_path,log=_open_legacy_log(pathlib.Path(p.owned_root)); proc=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=log,stderr=log,start_new_session=True)
    end=time.monotonic()+deadline; status=None
    while time.monotonic()<end:
        if proc.poll() is not None: _legacy_failure("legacy-start",argv,proc,log_path,log)
        try: status=parse_cli(run([p.cli.path,"--socket",p.socket_path,"--json","status"],10)); break
        except (GuestError,subprocess.TimeoutExpired): time.sleep(.5)
    if status is None: _legacy_failure("legacy-start",argv,proc,log_path,log,timeout=True)
    after=[file_id(x) for x in p.managed_receipts]
    if [(x["path"],x["sha256"]) for x in after]!=[(x["path"],x["sha256"]) for x in before]:
        exact_kill(proc_id(proc.pid)); raise GuestError("legacy start changed product-managed receipts")
    receipt={"schema":1,"operation":"headless-preexisting-legacy-start","origin":"guest","transport":"qga","connected_receipt_sha256":_sha(connected),"daemon":proc_id(proc.pid),"boot_id":pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),"started_epoch":int(time.time()),"unchanged_files":after,"status":status}
    log.close()
    write_private(pathlib.Path(p.owned_root)/"legacy.json",json.dumps(receipt,sort_keys=True,separators=(",",":")).encode())
    return receipt

def baseline_handoff(p:FixturePlan,connected_path:str,deadline:int)->dict:
    import grp
    root=secure_root(p);connected=json.loads(pathlib.Path(connected_path).read_text());meta=json.loads((root/"fixture.json").read_text());c=meta["contract"];baseline_config=_verify_baseline_config(p.baseline_config_path,_baseline_config_meta(p,meta))
    current_path=file_id(p.config_path)
    if current_path["path"]!=c["files"]["client_config"] or current_path["path"]==baseline_config["path"]: raise GuestError("current and baseline config identities collide")
    disconnected,pre_disconnect=_pre_disconnect_diagnostic(p,connected,root,lambda:parse_cli(run_cli([p.cli.path,"--socket",p.socket_path,"--json","disconnect"],"disconnect",root)));state=disconnected["json"].get("result",disconnected["json"]);routing=state.get("routing",{})
    if state.get("state")!="disconnected" or routing.get("recoveryRequired") is not False: raise GuestError("setup daemon disconnect failed")
    interface_absent=run(["/usr/sbin/ip","link","show","dev",p.wg_interface],ok=False)["rc"]!=0
    v4=run(["/usr/sbin/ip","-N","route","show","table","51821"],ok=False);v6=run(["/usr/sbin/ip","-6","-N","route","show","table","51821"],ok=False)
    routes_clean=not v4["stdout"].strip() and not v6["stdout"].strip()
    resolver=run(["/usr/bin/resolvectl","status"],ok=False);dns_clean=p.wg_interface not in resolver["stdout"]
    if not interface_absent or not routes_clean or not dns_clean: raise GuestError("setup daemon disconnect left owned network state")
    run(["/usr/bin/systemctl","stop","amneziad.service"],60)
    props={}
    for key in ("MainPID","ActiveState","SubState","Job"): props[key]=run(["/usr/bin/systemctl","show","-p",key,"--value","amneziad.service"])["stdout"].strip()
    if props!={"MainPID":"0","ActiveState":"inactive","SubState":"dead","Job":""}: raise GuestError("setup service did not reach graceful terminal")
    runtime=remove_stale_control_socket(p.socket_path,grp.getgrnam("amnezia").gr_gid,p.managed_receipts)
    if runtime.get("branch")!="clean-absent": raise GuestError("graceful stop did not remove runtime socket")
    managed_retirement=_retire_clean_managed_receipts(p,root,grp.getgrnam("amnezia").gr_gid)
    legacy_argv=[p.legacy_daemon.path,"--socket",p.socket_path,"--store","/var/lib/amnezia/profiles.json","--config-root","/etc/amnezia/profiles","--require-root-owned-config","--staging-root","/run/amnezia"]
    log_path,log=_open_legacy_log(root);proc=subprocess.Popen(legacy_argv,stdin=subprocess.DEVNULL,stdout=log,stderr=log,start_new_session=True)
    end=time.monotonic()+deadline;status=None
    while time.monotonic()<end:
        if proc.poll() is not None: _legacy_failure("baseline-handoff",legacy_argv,proc,log_path,log,unit=props,runtime=runtime)
        try: status=parse_cli(run(c["baseline_cli"]["status"],10));break
        except (GuestError,subprocess.TimeoutExpired):time.sleep(.5)
    if status is None:
        _legacy_failure("baseline-handoff",legacy_argv,proc,log_path,log,timeout=True,unit=props,runtime=runtime)
    cli={};started=int(time.time());legacy_connect_diagnostic=None
    for key in ("import","connect"):
        if key=="import":
            cli[key]=parse_cli(run_cli(c['baseline_cli'][key],key,root))
        else:
            cli[key],legacy_connect_diagnostic=_legacy_connect_diagnostic(
                p,proc,root,log,
                lambda:parse_cli(run_cli(c['baseline_cli'][key],key,root)))
    while time.monotonic()<end:
        status=parse_cli(run_cli(c["baseline_cli"]["status"],"status",root));hs=run(["/usr/bin/wg","show",p.wg_interface,"latest-handshakes"],ok=False);tr=run(["/usr/bin/wg","show",p.wg_interface,"transfer"],ok=False)
        result=status["json"].get("result",status["json"])
        if hs["rc"]==tr["rc"]==0 and result.get("state")=="connected" and hs["stdout"].strip() and tr["stdout"].strip():break
        time.sleep(1)
    else: _legacy_failure("baseline-handoff",legacy_argv,proc,log_path,log,timeout=True,unit=props,runtime=runtime)
    log.close()
    cli["status"]=status
    for key in ("doctor","list"):cli[key]=parse_cli(run_cli(c["baseline_cli"][key],key,root))
    target=p.routed_test_server.split('/',1)[0];route_rows=json.loads(run(["/usr/sbin/ip","-4","-j","route","get",target])["stdout"]);ping=run(["/usr/bin/ping","-n","-c","1","-W","3","-I",p.wg_interface,target],10)
    route_get=[{k:x[k] for k in ("dst","dev","prefsrc","table") if k in x} for x in route_rows]
    if len(route_get)!=1 or route_get[0].get("dev")!=p.wg_interface: raise GuestError("baseline routed route mismatch")
    receipt={"schema":1,"operation":"headless-preexisting-baseline-owned","origin":"guest","transport":"qga","connected_receipt_sha256":_sha(connected),"baseline_config":baseline_config,"setup_disconnect":{"state":"disconnected","interface_absent":interface_absent,"routes_clean":routes_clean,"dns_clean":dns_clean,"recovery_required":False,"cli":disconnected,"pre_disconnect_diagnostic":pre_disconnect},"systemd_terminal":props,"runtime_transition":runtime,"managed_receipt_retirement":managed_retirement,"daemon":proc_id(proc.pid),"cli":cli,"legacy_connect_diagnostic":legacy_connect_diagnostic,"connect_started_epoch":started,"boot_id":pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),"routed_probe":{"target":target,"prefix":p.routed_test_prefix,"interface":p.wg_interface,"route_get":route_get,"traffic":{"argv":ping["argv"],"rc":ping["rc"],"stdout_sha256":ping["stdout_sha256"],"stderr_sha256":ping["stderr_sha256"],"verified":True}}}
    write_private(root/"legacy.json",json.dumps(receipt,sort_keys=True,separators=(",",":")).encode());return receipt

def cleanup(p:FixturePlan,active_path:str="")->dict:
    root=secure_root(p); meta=json.loads((root/"fixture.json").read_text()); marker=(root/"marker").read_text().strip()
    if marker!=meta["marker"] or os.stat(f"/var/run/netns/{p.netns}").st_ino!=meta["netns_inode"]: raise GuestError("fixture namespace ownership changed")
    legacy_path=root/"legacy.json"
    if not legacy_path.is_file(): raise GuestError("legacy identity absent; refusing product/network cleanup")
    legacy=json.loads(legacy_path.read_text()); identity=legacy["daemon"]
    try: fresh=proc_id(identity["pid"])
    except FileNotFoundError:
        if not active_path: raise GuestError("post-update daemon receipt required for cleanup")
        active=json.loads(pathlib.Path(active_path).read_text())
        if (active.get("run_id"),active.get("profile"),active.get("nonce"))!=(p.run_id,p.profile,p.nonce) or not isinstance(active.get("daemon"),dict): raise GuestError("post-update daemon binding mismatch")
        identity=active["daemon"]; fresh=proc_id(identity["pid"])
        if identity.get("pid")!=main_pid() or identity.get("exe_sha256") not in (p.setup_daemon.sha256,p.legacy_daemon.sha256): raise GuestError("post-update daemon is not an exact planned binary")
    if any(fresh[k]!=identity[k] for k in ("pid","start_ticks","exe","exe_sha256","uid","cmdline_sha256")): raise GuestError("active daemon identity changed before cleanup")
    disconnected=parse_cli(run_cli([p.cli.path,"--socket",p.socket_path,"--json","disconnect"],"disconnect",root))
    result=disconnected["json"].get("result",disconnected["json"])
    if result.get("state")!="disconnected": raise GuestError("official product disconnect did not complete")
    exact_kill(identity); wait_gone(identity)
    http=meta["http"]
    try: exact_kill(http); wait_gone(http)
    except FileNotFoundError: pass
    run(["/usr/sbin/ip","netns","del",p.netns]); run(["/usr/sbin/ip","link","del",p.host_veth],ok=False)
    if pathlib.Path(f"/var/run/netns/{p.netns}").exists() or pathlib.Path(f"/sys/class/net/{p.host_veth}").exists(): raise GuestError("owned network cleanup incomplete")
    guard=json.loads((root/"restart-guard.json").read_text()); current=file_id(guard["path"])
    if current!=guard: raise GuestError("runtime restart guard identity changed")
    pathlib.Path(guard["path"]).unlink(); run(["/usr/bin/systemctl","daemon-reload"])
    return {"schema":1,"operation":"headless-preexisting-cleanup","origin":"guest","transport":"qga","netns":p.netns,"netns_inode":meta["netns_inode"],"http_pid":http["pid"],"legacy_pid":identity["pid"],"disconnect":disconnected,"network_removed":True,"secrets_retained_for_controller_archive":True}

def entry(argv:list[str]|None=None)->int:
    ap=argparse.ArgumentParser(); ap.add_argument("action",choices=("prepare","connect-collect","crash","legacy-start","baseline-handoff","cleanup")); ap.add_argument("--plan",required=True); ap.add_argument("--ack"); ap.add_argument("--connected"); ap.add_argument("--active-daemon"); ap.add_argument("--deadline",type=int,default=60); a=ap.parse_args(argv)
    if not 5<=a.deadline<=180: raise GuestError("deadline out of range")
    p=load_plan(a.plan)
    result=prepare(p) if a.action=="prepare" else connect_collect(p,a.deadline) if a.action=="connect-collect" else crash(p,a.ack or "") if a.action=="crash" else legacy_start(p,a.connected or "",a.deadline) if a.action=="legacy-start" else baseline_handoff(p,a.connected or "",a.deadline) if a.action=="baseline-handoff" else cleanup(p,a.active_daemon or "")
    print(json.dumps(result,sort_keys=True,separators=(",",":"))); return 0
if __name__=="__main__":
    try: raise SystemExit(entry())
    except LegacyProcessFailure as e: print(json.dumps({"error":"legacy-process-failed","diagnostic":e.diagnostic},sort_keys=True,separators=(",",":")),file=sys.stderr); raise SystemExit(1)
    except CliFailure as e: print(json.dumps({"error":"cli-transaction-failed","diagnostic":e.diagnostic},sort_keys=True,separators=(",",":")),file=sys.stderr); raise SystemExit(1)
    except (GuestError,OSError,ValueError,subprocess.TimeoutExpired) as e: print(json.dumps({"error":str(e)[:512]}),file=sys.stderr); raise SystemExit(1)
