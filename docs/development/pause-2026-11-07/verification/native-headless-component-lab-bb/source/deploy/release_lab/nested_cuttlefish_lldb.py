"""Bounded, non-acceptance LLDB diagnostics for the owned nested Android guest.

This module only defines the frozen runtime contract and the SB API driver.  The
controller remains responsible for ownership checks, ADB root/rebind, staging,
the single attach authorization, durable archival, and guarded cleanup.
"""
from __future__ import annotations

import hashlib, json, re
from dataclasses import dataclass
from typing import Mapping

SHA = re.compile(r"[0-9a-f]{64}")
NATIVE_PAYLOAD_SIZE = 203_987_176
PYTHON_TREE_REGULAR_FILES = 1_581
PYTHON_TREE_SYMLINKS = 7
PYTHON_TREE_SIZE = 33_810_978
PYTHON_TREE_MANIFEST_SHA256 = "e0feaeef1e0c017f3e0881952ff3c906c83b5085610ab452dbe48f0e26049aa8"
# libpython3.10.so.1.0 occurs in both sets, so count it once in the union.
BUNDLE_UNION_SIZE = NATIVE_PAYLOAD_SIZE + PYTHON_TREE_SIZE - 4_008_168
BUNDLE_ARCHIVE_NAME = "android-lldb-ndk-26.1.10909125-linux-x86_64.tar.gz"
BUNDLE_ARCHIVE_SIZE = 71_060_977
BUNDLE_ARCHIVE_SHA256 = "3d6c10a32d8bc29b9fc4746df6819d58de2ceeb1b97fc99694bcb8b06941e4d5"
BUNDLE_MANIFEST_SHA256 = "bd6cd5e444a5f61929b04e4c2a701ec9c415307fdd54e0f8fa5d40ac958d3207"
BUNDLE_MEMBERS = 1_599
BUNDLE_REGULAR_FILES = 1_591
BUNDLE_SYMLINKS = 8

NATIVE_FILES = (
 ("bin/lldb",290032,"09892f676beffb6a231623091bce1389efa33268efd1053c9f069b22b86e1004"),
 ("lib/liblldb.so.17.0.2",169006024,"55b6a098c3edf7b092c438798b0b88ed3904be1fe23fb9d0af1f2a68dd47fc48"),
 ("lib/x86_64-unknown-linux-gnu/libc++.so.1",2149112,"4fff38df56cac5fd2c58149d30b63e03ff114bcfed66ed8a5c9d13e691a7c5cc"),
 ("lib/x86_64-unknown-linux-gnu/libc++abi.so.1",513088,"35f4be1c4c8f4e901b527e12e417aa9998cc272087d168af50d1f58b950ff172"),
 ("python3/lib/libpython3.10.so.1.0",4008168,"5ed28adaeb1074a01f44880a7409e95213113a14741e397e120b1d4b2c774ffb"),
 ("lib/libedit.so.0",655328,"3d2ba14d9004b3c3a08fe67c72d7832824d373b381529818117441dec7ae7710"),
 ("lib/libform.so.6",95200,"3059651f3bbd69152636a876bd766638ff0e82a42bdcb7b01bd7d116ea0db590"),
 ("lib/libncurses.so.6",424064,"af5ee85d6e6f0afcb78a32fb8b633e0165cc1445b1558f3b91b28c74a27b158b"),
 ("lib/libpanel.so.6",14768,"f6381d3ee241f6290c6de3fa97be2087d1967d9aa890bb3e0021f5bbe418158e"),
 ("lib/libxml2.so.2",1656480,"cc61215881262770faf3363e7dbdbe04e8a41b0aa0bad3f0adf86a411cc05b72"),
 ("lib/clang/17/lib/linux/aarch64/lldb-server",25174912,"c1c0849dc507689428e127905e9fddcb220f6925b238bfb26e012cbad893b950"),
)

REQUIRED_SYMLINKS = {
 "lib/liblldb.so.17":"liblldb.so.17.0.2",
 "lib/liblldb.so":"liblldb.so.17",
 "python3/lib/libpython3.10.so":"libpython3.10.so.1.0",
 "lib/python3.10/site-packages/lldb/_lldb.cpython-310-x86_64-linux-gnu.so":"../../../liblldb.so",
}

class LldbDiagnosticError(RuntimeError): pass

@dataclass(frozen=True)
class LldbAttachPlan:
 run_id: str
 attempt_nonce: str
 package: str
 pid: int
 uid: int
 start_ticks: int
 connect_url: str
 staged_root: str
 deadline_seconds: int = 40
 cleanup_reserve_seconds: int = 20
 def validate(self) -> None:
  if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}",self.run_id) or not re.fullmatch(r"[0-9a-f]{48}",self.attempt_nonce):raise LldbDiagnosticError("run identity")
  if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+",self.package):raise LldbDiagnosticError("package")
  if any(isinstance(x,bool) or not isinstance(x,int) or x<=0 for x in (self.pid,self.uid,self.start_ticks)):raise LldbDiagnosticError("process identity")
  if not re.fullmatch(r"connect://127\.0\.0\.1:[1-9][0-9]{3,4}",self.connect_url):raise LldbDiagnosticError("non-loopback LLDB transport")
  if not re.fullmatch(r"/var/lib/amnezia-release-lab/n/[0-9a-f]{8}/runtime/diagnostics",self.staged_root):raise LldbDiagnosticError("staged root")
  if self.deadline_seconds!=40 or self.cleanup_reserve_seconds!=20 or self.deadline_seconds+self.cleanup_reserve_seconds!=60:raise LldbDiagnosticError("deadline")

def build_sb_driver(plan:LldbAttachPlan, deadline_monotonic:float|None=None)->str:
 """Return an LLDB command script using an explicit asynchronous SB event loop."""
 plan.validate()
 if deadline_monotonic is not None and (isinstance(deadline_monotonic,bool) or not isinstance(deadline_monotonic,(int,float)) or deadline_monotonic<=0):raise LldbDiagnosticError("absolute deadline")
 cfg=json.dumps({**plan.__dict__,"deadline_monotonic":deadline_monotonic},sort_keys=True,separators=(",",":"))
 # It is consumed by `lldb --batch -s`; all outcome data has one unique prefix.
 return """script
import json,lldb,os,time,traceback
cfg=json.loads(%r)
out={'schema':1,'acceptance':False,'classification':'diagnostic-failure','signal_claim':False,'stack_claim':False,'states':[],'identity':{k:cfg[k] for k in ('run_id','attempt_nonce','package','pid','uid','start_ticks')},'signal_policy':None,'lldb_file':getattr(lldb,'__file__',None)}
dbg=lldb.SBDebugger.Create()
proc=None
deadline=cfg['deadline_monotonic'] if cfg['deadline_monotonic'] is not None else time.monotonic()+cfg['deadline_seconds']
def state(name,**kw):out['states'].append({'state':name,'at_monotonic':time.monotonic(),**kw})
try:
 dbg.SetAsync(True)
 if not dbg.GetAsync():raise RuntimeError('lldb async mode rejected')
 root=os.path.realpath(cfg['staged_root'])+os.sep
 lf=os.path.realpath(out['lldb_file'] or '')
 if not lf.startswith(root):raise RuntimeError('lldb Python binding escaped staged bundle')
 target=dbg.CreateTarget('');connect_error=lldb.SBError();proc=target.ConnectRemote(dbg.GetListener(),cfg['connect_url'],'gdb-remote',connect_error)
 if not connect_error.Success() or not proc.IsValid():
  out['classification']='attach-denied';state('ATTACH_DENIED',error=connect_error.GetCString());raise RuntimeError('single gdbserver attach connection denied')
 state('ATTACHED_STOPPED',lldb_pid=proc.GetProcessID(),lldb_state=proc.GetState())
 sig=proc.GetUnixSignals();signo=11
 if not (sig.SetShouldStop(signo,True) and sig.SetShouldNotify(signo,True) and sig.SetShouldSuppress(signo,False)):raise RuntimeError('SIGSEGV policy rejected')
 policy={'stop':sig.GetShouldStop(signo),'notify':sig.GetShouldNotify(signo),'pass':not sig.GetShouldSuppress(signo)};out['signal_policy']=policy
 if policy!={'stop':True,'notify':True,'pass':True}:raise RuntimeError('SIGSEGV policy readback mismatch')
 state('POLICY_CONFIRMED',**policy)
 err=proc.Continue()
 if not err.Success():raise RuntimeError('continue failed: '+err.GetCString())
 state('RUNNING')
 listener=dbg.GetListener();event=lldb.SBEvent();segv_thread=None
 while time.monotonic()<deadline:
  wait=max(1,min(2,int(deadline-time.monotonic())))
  if not listener.WaitForEvent(wait,event):continue
  if not lldb.SBProcess.EventIsProcessEvent(event):continue
  ps=lldb.SBProcess.GetStateFromEvent(event)
  state('EVENT',lldb_state=ps)
  if ps==lldb.eStateStopped:
   matches=[]
   for thread in proc:
    if thread.GetStopReason()==lldb.eStopReasonSignal and thread.GetStopReasonDataCount()>0 and thread.GetStopReasonDataAtIndex(0)==signo:matches.append(thread)
   if len(matches)!=1:raise RuntimeError('stopped event is not unique SIGSEGV')
   segv_thread=matches[0];state('STOPPED_SIGSEGV',thread_id=segv_thread.GetThreadID());break
  if ps in (lldb.eStateExited,lldb.eStateDetached,lldb.eStateCrashed):raise RuntimeError('process ended before correlated SIGSEGV stop')
 if segv_thread is None:out['classification']='diagnostic-timeout';raise TimeoutError('bounded SIGSEGV wait expired')
 frames=[]
 for thread in list(proc)[:64]:
  row={'thread_id':thread.GetThreadID(),'stop_reason':thread.GetStopReason(),'frames':[]}
  for frame in list(thread)[:128]:
   pc=frame.GetPCAddress();module=pc.GetModule().GetFileSpec().GetFilename() if pc.IsValid() else None;function=frame.GetFunctionName()
   row['frames'].append({'index':frame.GetFrameID(),'pc':frame.GetPC(),'module':str(module)[:512] if module else None,'function':str(function)[:1024] if function else None})
  frames.append(row)
 crashing=next((x for x in frames if x['thread_id']==segv_thread.GetThreadID()),None);complete=crashing is not None and any(isinstance(x.get('pc'),int) and x['pc']>0 for x in crashing['frames'])
 out['signal_claim']=True;out['threads']=frames
 if complete:out['stack_claim']=True;out['classification']='native-sigsegv'
 else:out['classification']='capture-incomplete'
 state('EVIDENCE_CAPTURED',stack_complete=complete)
 err=proc.Continue()
 if not err.Success():raise RuntimeError('signal-pass continue failed: '+err.GetCString())
 state('CONTINUE_WITH_SIGNAL_PASS')
 while time.monotonic()<deadline:
  if listener.WaitForEvent(1,event) and lldb.SBProcess.EventIsProcessEvent(event):
   ps=lldb.SBProcess.GetStateFromEvent(event)
   if ps in (lldb.eStateExited,lldb.eStateCrashed):
    out['exit_status']=proc.GetExitStatus();out['exit_description']=str(proc.GetExitDescription() or '')[:1024];state('EXITED_AFTER_PASS',lldb_state=ps,exit_status=out['exit_status'],exit_description=out['exit_description']);break
 else:raise TimeoutError('signal delivery death not observed')
except BaseException as exc:
 out['error']={'type':type(exc).__name__,'sha256':__import__('hashlib').sha256(str(exc).encode()).hexdigest()}
finally:
 try:
  if proc is not None and proc.IsValid() and proc.GetState() not in (lldb.eStateExited,lldb.eStateDetached):proc.Detach();state('FINALLY_DETACHED')
 except BaseException as detach:out['detach_error']={'type':type(detach).__name__,'sha256':__import__('hashlib').sha256(str(detach).encode()).hexdigest()}
 lldb.SBDebugger.Destroy(dbg)
 encoded=json.dumps(out,sort_keys=True,separators=(',',':'))
 if len(encoded.encode())>2*1024*1024:
  out={k:v for k,v in out.items() if k!='threads'};out.update({'classification':'diagnostic-output-overflow','signal_claim':False,'stack_claim':False});encoded=json.dumps(out,sort_keys=True,separators=(',',':'))
 print('AMZ_LLDB_JSON:'+encoded)
quit()
""" % cfg

def build_diagnostic_entrypoint(plan:LldbAttachPlan,script_path:str)->dict:
 """Describe the exact owned-outer invocation; it is never a release step."""
 plan.validate()
 if not re.fullmatch(re.escape(plan.staged_root)+r"/evidence/lldb-[0-9a-f]{12}\.py",script_path):raise LldbDiagnosticError("driver path")
 root=plan.staged_root
 return {"schema":1,"operation":"nested-android-lldb-diagnostic","acceptance":False,
  "transport":{"controller":"qga","adb":"owned-outer-loopback","lldb":"owned-outer-to-inner-adb-forward","host_network_mutation":False},
  "timeout_seconds":60,"driver_deadline_seconds":plan.deadline_seconds,"cleanup_reserve_seconds":plan.cleanup_reserve_seconds,
  "argv":[f"{root}/bin/lldb","--batch","-s",script_path],
  "env":{"PYTHONDONTWRITEBYTECODE":"1","PYTHONNOUSERSITE":"1","PYTHONHOME":f"{root}/python3",
   "PYTHONPATH":f"{root}/lib/python3.10/site-packages",
   "LD_LIBRARY_PATH":f"{root}/lib:{root}/lib/x86_64-unknown-linux-gnu:{root}/python3/lib"},
  "output_limit":2*1024*1024,"single_attach":True}

def parse_sb_output(raw:bytes,plan:LldbAttachPlan|None=None)->dict:
 if len(raw)>2*1024*1024:raise LldbDiagnosticError("LLDB output exceeds 2 MiB")
 rows=[x for x in raw.decode("utf-8","replace").splitlines() if x.startswith("AMZ_LLDB_JSON:")]
 if len(rows)!=1:raise LldbDiagnosticError("unique SB receipt missing")
 try:value=json.loads(rows[0].split(":",1)[1])
 except json.JSONDecodeError as exc:raise LldbDiagnosticError("SB receipt JSON") from exc
 return validate_sb_receipt(value,plan)

def validate_sb_receipt(value:Mapping,plan:LldbAttachPlan|None=None)->dict:
 if not isinstance(value,Mapping) or value.get("schema")!=1 or value.get("acceptance") is not False:raise LldbDiagnosticError("receipt common")
 states=value.get("states");names=[x.get("state") for x in states] if isinstance(states,list) else []
 classification=value.get("classification")
 if classification=="native-sigsegv":
  required=("ATTACHED_STOPPED","POLICY_CONFIRMED","RUNNING","STOPPED_SIGSEGV","EVIDENCE_CAPTURED","CONTINUE_WITH_SIGNAL_PASS","EXITED_AFTER_PASS")
  positions=[]
  for name in required:
   try:positions.append(names.index(name,positions[-1]+1 if positions else 0))
   except ValueError as exc:raise LldbDiagnosticError("incomplete SIGSEGV state machine") from exc
  threads=value.get("threads")
  if value.get("signal_policy")!={"stop":True,"notify":True,"pass":True} or value.get("signal_claim") is not True or value.get("stack_claim") is not True or not isinstance(threads,list) or not threads or not any(any(isinstance(f.get("pc"),int) and f["pc"]>0 for f in t.get("frames",[])) for t in threads if isinstance(t,Mapping)):raise LldbDiagnosticError("SIGSEGV evidence")
  if value.get("exit_status")!=11:raise LldbDiagnosticError("fatal SIGSEGV exit status")
 elif classification=="capture-incomplete":
  if value.get("signal_claim") is not True or value.get("stack_claim") is not False:raise LldbDiagnosticError("capture-incomplete claim")
 elif classification in ("attach-denied","diagnostic-timeout","diagnostic-failure","diagnostic-output-overflow"):
  if value.get("stack_claim") is not False or "threads" in value:raise LldbDiagnosticError("false stack claim")
 else:raise LldbDiagnosticError("classification")
 identity=value.get("identity")
 if not isinstance(identity,Mapping) or any(isinstance(identity.get(k),bool) or not isinstance(identity.get(k),int) or identity[k]<=0 for k in ("pid","uid","start_ticks")):raise LldbDiagnosticError("identity")
 if plan is not None:
  plan.validate();expected={k:getattr(plan,k) for k in ("run_id","attempt_nonce","package","pid","uid","start_ticks")}
  if identity!=expected:raise LldbDiagnosticError("plan identity mismatch")
  attached=next((x for x in states if isinstance(x,Mapping) and x.get("state")=="ATTACHED_STOPPED"),None)
  if classification not in ("attach-denied","diagnostic-timeout","diagnostic-failure","diagnostic-output-overflow") and (not isinstance(attached,Mapping) or attached.get("lldb_pid")!=plan.pid):raise LldbDiagnosticError("remote PID mismatch")
  if not isinstance(value.get("lldb_file"),str) or not value["lldb_file"].startswith(plan.staged_root+"/"):raise LldbDiagnosticError("binding provenance")
 elif not isinstance(value.get("lldb_file"),str) or "/runtime/diagnostics/" not in value["lldb_file"]:raise LldbDiagnosticError("binding provenance")
 return dict(value)
