import hashlib
import json
import pytest
from urllib.parse import quote
from deploy.release_lab.nested_cuttlefish_app_executor import AppFixture,NestedAppExecutor,PNG_MAX,_parse_focus_text as producer_focus_parser
from deploy.release_lab.nested_cuttlefish_runner import ApkSpec,AssetSpec,InnerPlan,NestedCuttlefishError,OuterOwnership,receipt_sha,validate_app_update_receipt,_parse_focus_text as consumer_focus_parser
from deploy.release_lab.test_nested_cuttlefish_runner import wayland_dependency

def setup():
 o=OuterOwnership("run","linux-headless-x64","nonce-1234567890",2,3,"11111111-1111-1111-1111-111111111111","/var/lib/amnezia-release-lab/r/qmp","/var/lib/amnezia-release-lab/r/qga");root="/var/lib/amnezia-release-lab/n/"+hashlib.sha256(b"run\0nonce-1234567890").hexdigest()[:8]
 argv=(f"{root}/runtime/host/bin/launch_cvd",f"-instance_dir={root}/runtime/instance",f"-assembly_dir={root}/runtime/assembly",f"-system_image_dir={root}/runtime/images",f"-early_tmp_dir={root}/runtime/tmp","-vm_manager=qemu_cli","-device_external_network=slirp","-enable_tap_devices=false","-enable_modem_simulator=false","-start_gnss_proxy=false","-enable_host_bluetooth=false","-enable_host_nfc=false","-enable_host_uwb=false","-start_webrtc=false","-report_anonymous_usage_stats=n","-gpu_mode=guest_swiftshader","-adb_mode=vsock_half_tunnel","-run_adb_connector=true","-cpus=2","-memory_mb=4096","-vsock_guest_cid=37",f"-qemu_binary_dir={root}/runtime/qemu","-noresume")
 apk=ApkSpec("c.apk","/c",10,"c"*64,"org.amnezia.vpn",39);p=InnerPlan(o,(AssetSpec("h.tar.gz","/h",1,"a"*64),AssetSpec("i.zip","/i",1,"b"*64),AssetSpec("q.tar.gz","/q",1,"d"*64)),apk,37,1000,launch_argv=argv,qemu_aarch64_sha256="e"*64);b=ApkSpec("b.apk","/b",9,"f"*64,apk.package,38)
 so={"pid":22,"start_ticks":33,"uuid":"33333333-3333-3333-3333-333333333333","qmp_socket":"/srv/qmp","qga_socket":"/srv/qga"};fx=AppFixture("http://10.8.1.2:17865","run",o.attempt_nonce,"/manifest.json","1"*64,8,f"/files/artifacts/{apk.sha256}/{quote(apk.name,safe='-._~')}",40,400,"server-router","amnezia-release-lab:run:server-router",so);return p,b,fx
def boot(p):
 cg="/amnezia-release-lab/run/nonce-1234567890"
 def proc(n,pid):
  exe=f"{p.root}/runtime/{'qemu' if n=='qemu-system-aarch64' else 'host/bin'}/{n}";a=[exe,p.root]+(["guest-cid=37","-netdev","user,id=hostnet0,net=10.0.2.15/24,host=10.0.2.2,dns=127.0.0.1"] if n=='qemu-system-aarch64' else ["-P","5053"] if n=='adb' else [])
  if n=="adb_connector":a=[exe,"--addresses=0.0.0.0:6520"]
  if n=="socket_vsock_proxy":a=[exe,"--server_type=tcp","--server_tcp_port=6520","--client_type=vsock","--client_vsock_port=5555","--client_vsock_id=37","--label=adb"]
  return {"pid":pid,"start_ticks":pid+100,"exe":exe,"exe_sha256":"a"*64,"uid":1000,"groups":([42] if n=="adb" else [42,993]),"state":"S","argv":a,"cmdline_sha256":"b"*64,"cgroup":cg}
 ps=[proc("run_cvd",11),proc("adb",12),proc("qemu-system-aarch64",13),proc("adb_connector",14),proc("socket_vsock_proxy",15)];ril={"schema":1,"records":[{"path":path,"alias_target":path,"before_sha256":"2"*64,"after_sha256":"3"*64,"size":100,"ril_ipaddr":"10.0.2.15","ril_gateway":"10.0.2.2","ril_prefixlen":24,"ril_dns":"10.0.2.3"} for path in (f"{p.root}/runtime/assembly/cuttlefish_config.json",f"{p.root}/runtime/instance/assembly/cuttlefish_config.json",f"{p.root}/runtime/instance/instances/cvd-1/cuttlefish_config.json")]}
 detector={"exit_code":0,"assertion":False,"uid":p.runtime_uid,"groups":[42],"stdout_sha256":"0"*64,"stdout_size":0,"stderr_sha256":"1"*64,"stderr_size":128,"output_file":{"path":f"{p.root}/runtime/graphics-probe/availability.pbtxt","kind":"regular","dev":1,"inode":2,"uid":p.runtime_uid,"gid":p.runtime_uid,"mode":"0600","sha256":"967373415f2d0f0db2e7a8d28342096a9a40967dfd9c037257deadff94c0f354","size":26091,"eof":True}}
 installed={"run_id":p.ownership.run_id,"attempt_nonce":p.ownership.attempt_nonce,"origin":"guest","transport":"qga","injected":False,"loader":{"path":f"{p.root}/runtime/private-libs/libvulkan.so.1.3.275","soname_path":f"{p.root}/runtime/private-libs/libvulkan.so.1","sha256":p.vulkan_loader_sha256,"size":p.vulkan_loader_size,"uid":0,"mode":"0644","directory_uid":0,"directory_mode":"0755"},"dlopen":True,"vkGetInstanceProcAddr":True,"graphics_detector":detector}
 provision={"schema":1,"uid":p.runtime_uid,"user":"lab","primary_gid":p.runtime_uid,"cvdnetwork_gid":42,"created":True,"member":True,"resolved_groups":[42,p.runtime_uid],"files":[{"path":x,"before_sha256":"3"*64,"after_sha256":"4"*64} for x in ("/etc/group","/etc/gshadow")],"commands":[{"argv":a,"exe_sha256":"5"*64,"exit_code":0,"stdout_size":0,"stderr_size":0} for a in (["/usr/sbin/groupadd","--system","cvdnetwork"],["/usr/sbin/usermod","-aG","cvdnetwork","lab"])],"kvm_modified":False,"vhost_modified":False,"origin":"guest","transport":"qga","injected":False}
 result={"schema":2,"operation":"nested-cuttlefish-boot","run_id":"run","profile":"linux-headless-x64","attempt_nonce":p.ownership.attempt_nonce,"marker":p.marker,"guest_root":p.root,"origin":"guest","transport":"qga","injected":False,"outer_ownership":vars(p.ownership),"containment":{"kind":"cgroup-v2","path":cg,"member_pids":[11,12,13,14,15],"stable_reads":2},"processes":ps,"roles":{"cvd":11,"adb":12,"qemu":13},"boot":{"abi":"arm64-v8a","boot_completed":"1","serial":"127.0.0.1_6520","boot_id":"22222222-2222-2222-2222-222222222222"},"vsock_cid":37,"adb_endpoint":"127.0.0.1:5053","cvdnetwork_gid":42,"kvm_gid":993,"vhost_vsock":{"path":"/dev/vhost-vsock","dev":7,"inode":8,"uid":0,"gid":993,"mode":"0660","rdev":9,"char":True},"runtime_dependency":{"wayland_install":wayland_dependency(p,p.runtime_uid)[0],"wayland_runtime":wayland_dependency(p,p.runtime_uid)[1],"group_provisioning":provision,"stage":{"sha256":p.vulkan_deb_sha256,"size":p.vulkan_deb_size,"guest_root_identity":{"dev":1,"inode":2,"uid":0,"gid":0,"mode":"0711"}},"installed":installed},"network":{"adb_listen":"127.0.0.1:5053","host_mutation":False,"host_mounts":[],"qemu_netdev_argv":["user,id=hostnet0,net=10.0.2.15/24,host=10.0.2.2,dns=127.0.0.1"],"ril_config":ril},"passed":True}
 paths=[x["path"] for x in ril["records"]];adb=f"{p.root}/runtime/host/bin/adb";empty="List of devices attached\n";connected="List of devices attached\n127.0.0.1:6520\tdevice\n"
 def cmd(argv,out):return {"argv":argv,"exit_code":0,"stdout":out,"stdout_size":len(out),"stdout_sha256":hashlib.sha256(out.encode()).hexdigest(),"stderr":"","stderr_size":0,"stderr_sha256":hashlib.sha256(b"").hexdigest()}
 result["network"]["adb_connection"]={"endpoint":"127.0.0.1:6520","before":cmd([adb,"-P","5053","devices"],empty),"connect":cmd([adb,"-P","5053","connect","127.0.0.1:6520"],"connected"),"after":cmd([adb,"-P","5053","devices"],connected),"binding":{"endpoint":"127.0.0.1:6520","config_rows":[{"path":x,"sha256":"3"*64,"size":100,"adb_host_port":6520,"adb_ip_and_port":"0.0.0.0:6520"} for x in paths],"connector_pid":14,"proxy_pid":15,"connector_argv":ps[3]["argv"],"proxy_argv":ps[4]["argv"]}}
 return result
class Clock:
 def __init__(self):self.v=100
 def __call__(self):return self.v
class Q:
 def __init__(self):self.calls=[];self.request_timeouts=[];self.version=38;self.extra_version="";self.uid_output="package:org.amnezia.vpn uid:10123";self.focus="org.amnezia.vpn/MainActivity";self.focus_delay=0;self.splash_count=0;self.window_empty=False;self.activity_timeouts=0;self.policy_timeouts=0;self.ui_cat_timeouts=0;self.timeout_partial=b"partial activity output";self.big=False;self.evil=False;self.timeout=30;self.pending=None;self.close_error=False;self.read_error=False;self.locked=True;self.stubborn_lock=False;self.policy_raw=None;self.ui_actions=("Update","Install","Done");self.no_session=False
 def guest_exec_wait(self,path,args,timeout=30):
  self.calls.append((args,timeout))
  if path=="/usr/bin/python3" and "RLIMIT_FSIZE" in args[1]:
   argv=json.loads(args[2]);activity_timed=self.activity_timeouts>0 and argv[-2:]==["activity","top-resumed"];policy_timed=self.policy_timeouts>0 and argv[-2:]==["window","policy"];ui_timed=self.ui_cat_timeouts>0 and len(argv)>=2 and argv[-2]=="cat" and str(argv[-1]).endswith(".xml");timed=activity_timed or policy_timed or ui_timed
   if timed:
    if activity_timed:self.activity_timeouts-=1
    elif policy_timed:self.policy_timeouts-=1
    else:self.ui_cat_timeouts-=1
    self.pending=self.timeout_partial
   else:result=self.guest_exec_wait(argv[0],argv[1:],timeout);self.pending=str(result.get("stdout","")).encode()
   return {"exitcode":0,"stdout":json.dumps({"path":args[3],"size":len(self.pending),"sha256":hashlib.sha256(self.pending).hexdigest(),"rc":124 if timed else 0})}
  if path=="/usr/bin/python3":return {"exitcode":0,"stdout":json.dumps({"size":9,"sha256":"f"*64})}
  s=""
  if "install" in args:self.version=38;s="Success"
  elif args[-2:]==["window","policy"]:s=self.policy_raw if self.policy_raw is not None else f"KeyguardServiceDelegate:\n  showing={str(self.locked).lower()}\n  inputRestricted={str(self.locked).lower()}\n  simSecure=false\n  deviceHasKeyguard=true\n  enabled=true\n  bootCompleted=true"
  elif args[-2:]==["wm","dismiss-keyguard"]:
   if not self.stubborn_lock:self.locked=False
  elif args[-3:]==["input","keyevent","82"]:
   if not self.stubborn_lock:self.locked=False
  elif args[-2:]==["package","installs"]:s="Session 77:\n  mAppPackageName=org.amnezia.vpn\n  mFinalStatus=1\n" if self.version==39 and not self.no_session else ""
  elif args[-2:]==["activity","top-resumed"]:
   if self.focus_delay>0:self.focus_delay-=1;s="ACTIVITY MANAGER ACTIVITIES"
   else:
    package,component=self.focus.split("/",1);splash=self.splash_count>0
    if splash:self.splash_count-=1
    starting=(f"startingData=SplashScreenStartingData{{{package}}}\nstartingWindow=Window{{Splash Screen {package}}} startingDisplayed=true" if splash else "startingData=null")
    s=f"ACTIVITY MANAGER TOP-RESUMED\npackageName={package} processName={package}\napp=ProcessRecord{{37a499b 1234:{package}/u0a123}}\nIntent {{ cmp={package}/{component} }}\nmActivityComponent={package}/{component}\nstate=RESUMED finishing=false\nmVisibleRequested=true mVisible=true mClientVisible=true reportedVisible=true\nfirstWindowDrawn={str(not splash).lower()} reportedDrawn={str(not splash).lower()}\n{starting}"
  elif args[-2:]==["window","windows"]:
   if self.focus_delay>0 or self.window_empty:s="WINDOW MANAGER WINDOWS"
   else:s=f"mCurrentFocus=Window{{42 u0 {self.focus}}}"
  elif "pidof" in args:s="1234"
  elif "+%s.%3N" in args:s="1726185600.000"
  elif "logcat" in args:s=""
  elif args[-7:-1]==["shell","cmd","package","list","packages","-U"]:s=self.uid_output
  elif "dumpsys" in args:s=f"versionCode={self.version} minSdk=28 targetSdk=36"+self.extra_version
  elif "cat" in args:
   pkg="org.amnezia.vpn" if self.focus.startswith("org.amnezia") else "com.android.permissioncontroller"
   s="".join(f'<node package="{pkg}" text="{x}" bounds="[0,0][10,10]"/>' for x in self.ui_actions);s=s*((1<<20) if self.big else 1)
  elif "input" in args:self.focus="com.android.permissioncontroller/InstallActivity";self.version=39
  elif "monkey" in args:self.focus="evil.overlay/Popup" if self.evil else "org.amnezia.vpn/MainActivity"
  return {"exitcode":0,"stdout":s}
 def request(self,name,args):
  self.request_timeouts.append(self.timeout)
  if name=="guest-file-open":return {"return":7}
  if name=="guest-file-close":return {"error":{"class":"GenericError"}} if self.close_error else {"return":{}}
  if name=="guest-file-read" and self.read_error:return {"error":{"class":"GenericError"}}
  data=self.pending if self.pending is not None else (b"\x89PNG\r\n\x1a\nabc" if not self.big else b"x"*(PNG_MAX+1));self.pending=None
  return {"return":{"buf-b64":__import__('base64').b64encode(data).decode(),"eof":True}}
def archive_failure(record,screenshot=None):
 return {"origin":"controller","immutable":True,"path":"/archive/failure.json","sha256":hashlib.sha256(json.dumps(record,sort_keys=True).encode()).hexdigest(),"size":len(json.dumps(record))}
def fixture_for(fx,events,forged=False):
 def call(action,data,timeout):
  events.append((action,timeout));common={"schema":1,"run_id":fx.run_id,"profile":fx.profile,"attempt_nonce":fx.attempt_nonce,"marker":fx.marker,"origin":"guest","transport":"qga","injected":False,"outer_ownership":dict(fx.outer_ownership),"pid":fx.pid,"start_ticks":fx.start_ticks,"listener":fx.endpoint,"manifest_sha256":fx.manifest_sha256,"manifest_size":fx.manifest_size,"artifact_sha256":"c"*64,"artifact_size":10}
  if forged:common["origin"]="controller"
  if action=="start":return {**common,"ready":True,"identity_rechecked":True}
  if action=="reset":return {**common,"log_inode":5,"offset":0,"reset_token":"5"*48,"reset_at":100.0,"empty_sha256":hashlib.sha256(b"").hexdigest()}
  if action=="stop":return {**common,"identity_rechecked":True,"stopped":True,"listener_closed":True,"unknown_survivors":[],"request_log_sha256":"4"*64,"request_log_size":4}
  rows=[{"method":"GET","path":"/manifest.json","status":200,"sha256":"1"*64,"bytes":8,"content_length":8,"eof":True,"peer":"10.0.2.15","observed_at":101.0},{"method":"GET","path":fx.artifact_path,"status":200,"sha256":"c"*64,"bytes":10,"content_length":10,"eof":True,"peer":"10.0.2.15","observed_at":102.0}]
  reset={**common,"log_inode":5,"offset":0,"reset_token":"5"*48,"reset_at":100.0,"empty_sha256":hashlib.sha256(b"").hexdigest()};rs=receipt_sha(reset)
  return {**common,"requests":rows,"reset_receipt_sha256":rs,"reset_token":"5"*48,"log_inode":5,"start_offset":0,"transcript_sha256":receipt_sha({"reset_receipt_sha256":rs,"requests":rows}),"finished_at":103.0,"request_log_sha256":"4"*64,"request_log_size":4}
 return call
def make(forged=False):
 p,b,fx=setup();q=Q();ev=[];e=NestedAppExecutor(q,p,boot(p),b,fx,lambda:p.ownership,lambda:dict(fx.outer_ownership),fixture_for(fx,ev,forged),failure_archive=archive_failure,clock=Clock(),sleep=lambda _:None);return p,b,fx,q,ev,e
def test_happy_path_matches_semantic_validator_and_uses_proven_adb():
 p,b,fx,q,ev,e=make();e.install_baseline("/input/b.apk");r=e.run_update();validate_app_update_receipt(p,boot(p),r);assert all(c[0][:4]==["-P","5053","-s","127.0.0.1:6520"] for c in q.calls if c[0] and c[0][0]=="-P");assert ev[-1][0]=="stop"
def test_update_restart_waits_for_strict_drawn_visible_state_before_update_and_persistent_nonvisible_fails():
 p,b,fx,q,ev,e=make();e.install_baseline("/input/b.apk");q.splash_count=4;r=e.run_update();ready=r["ui"]["update_check_restart"]["readiness"]
 assert len(ready)==5 and ready[-1]["matches"][0]["visible"] is True and ready[-1]["matches"][0]["drawn"] is True
 calls=[x[0] for x in q.calls];last_ready=max(i for i,x in enumerate(calls) if x[-2:]==["activity","top-resumed"] and i<calls.index(next(x for x in calls if "uiautomator" in x)))
 assert last_ready<calls.index(next(x for x in calls if "uiautomator" in x))
 p,b,fx,q,ev,e=make();e.install_baseline("/input/b.apk");q.splash_count=100
 with pytest.raises(NestedCuttlefishError,match="foreground activity-top mismatch"):e.run_update()
 assert not any("uiautomator" in x[0] for x in q.calls)
@pytest.mark.parametrize("timed_label",["baseline-monkey","update-check-monkey","candidate-monkey"])
def test_single_monkey_timeout_is_never_retried_and_requires_strict_ready_postcondition(timed_label):
 p,b,fx,q,ev,e=make();original=e._capture_result;seen=0
 def timeout_after_action(argv,d,label,maximum,command_cap=None):
  nonlocal seen
  data,meta=original(argv,d,label,maximum,command_cap)
  if label==timed_label:seen+=1;meta={**meta,"rc":124}
  return data,meta
 e._capture_result=timeout_after_action
 if timed_label=="baseline-monkey":receipt=e.install_baseline("/input/b.apk");assert receipt["ui"]["launch_probe"]["timed_out"] is True
 else:
  e.install_baseline("/input/b.apk");receipt=e.run_update();row=receipt["ui"]["update_check_restart"]["monkey"] if timed_label=="update-check-monkey" else receipt["ui"]["launch_probe"];assert row["timed_out"] is True
 assert seen==1
 p,b,fx,q,ev,e=make();e.install_baseline("/input/b.apk");original=e._capture_result;seen=0
 def timeout_without_foreground(argv,d,label,maximum,command_cap=None):
  nonlocal seen
  data,meta=original(argv,d,label,maximum,command_cap)
  if label=="update-check-monkey":seen+=1;q.focus="com.android.launcher3/Home";meta={**meta,"rc":124}
  return data,meta
 e._capture_result=timeout_without_foreground
 with pytest.raises(NestedCuttlefishError,match="foreground activity-top mismatch"):e.run_update()
 assert seen==1
def test_fixture_path_uses_canonical_percent_encoding_and_rejects_raw_plus():
 p,b,fx=setup(); apk=ApkSpec("AmneziaVPN_5.0.1.39_android9+_arm64-v8a.apk",p.apk.source_path,p.apk.size,p.apk.sha256,p.apk.package,p.apk.version_code); p=InnerPlan(p.ownership,p.assets,apk,p.vsock_cid,p.runtime_uid,launch_argv=p.launch_argv,qemu_aarch64_sha256=p.qemu_aarch64_sha256)
 encoded=f"/files/artifacts/{apk.sha256}/AmneziaVPN_5.0.1.39_android9%2B_arm64-v8a.apk"
 good=AppFixture(fx.endpoint,fx.run_id,fx.attempt_nonce,fx.manifest_path,fx.manifest_sha256,fx.manifest_size,encoded,fx.pid,fx.start_ticks,fx.profile,fx.marker,fx.outer_ownership);good.validate(p)
 raw=AppFixture(fx.endpoint,fx.run_id,fx.attempt_nonce,fx.manifest_path,fx.manifest_sha256,fx.manifest_size,encoded.replace("%2B","+"),fx.pid,fx.start_ticks,fx.profile,fx.marker,fx.outer_ownership)
 with pytest.raises(NestedCuttlefishError,match="fixture paths"):raw.validate(p)
def test_candidate_direct_install_and_forged_fixture_fail():
 p,b,fx,q,ev,e=make();
 with pytest.raises(NestedCuttlefishError,match="forbidden"):e.install_baseline(f"{p.root}/input/{p.apk.name}")
 with pytest.raises(NestedCuttlefishError,match="provenance"):make(True)[-1].run_update()
def test_package_mismatch_exposes_bounded_candidate_diagnostic():
 p,b,fx,q,ev,e=make();q.version=37
 with pytest.raises(NestedCuttlefishError,match="package version/uid readback mismatch") as caught:e._package(38,e.clock()+30)
 message=str(caught.value);assert '"version_code_candidates":[37]' in message and '"user_id_candidates":[]' in message and '"sha256"' in message and len(message)<4600
@pytest.mark.parametrize("value",["package:other.app uid:10123","package:org.amnezia.vpn uid:0","package:org.amnezia.vpn uid:10123\npackage:org.amnezia.vpn uid:10124"])
def test_package_uid_lookup_rejects_wrong_or_multiple_rows(value):
 p,b,fx,q,ev,e=make();q.uid_output=value
 with pytest.raises(NestedCuttlefishError,match="package UID readback mismatch") as caught:e._package(38,e.clock()+30)
 assert '"sha256"' in str(caught.value) and len(str(caught.value))<4600
def test_package_version_rejects_duplicate_version_candidates():
 p,b,fx,q,ev,e=make();q.extra_version="\nversionCode=999"
 with pytest.raises(NestedCuttlefishError,match="package version/uid readback mismatch") as caught:e._package(38,e.clock()+30)
 assert '"version_code_candidates":[38,999]' in str(caught.value)
def test_cm_android16_installs_raw_replays_exact_historical_fields_without_app_substring_collision():
 from pathlib import Path
 raw=(Path(__file__).parent/"test_fixtures"/"android16_installs"/"installer-before.raw").read_bytes();assert len(raw)==2002 and hashlib.sha256(raw).hexdigest()=="c6005b716590e53b94cb82e27815bc308a007cbc4ee591c74362374149e16427"
 p,b,fx,q,ev,e=make();parsed=e._sessions(raw.decode("utf-8","replace"));assert parsed=={409819962:{"kind":"historical","package":"org.amnezia.vpn","final_status":1}}
 active="Active Session 9:\n  sizeBytes=1 appPackageName=n\n    ull appIcon=false\n"
 assert e._sessions(active)[9]=={"kind":"active","package":None,"final_status":None}
def test_primary_failure_still_stops_fixture():
 p,b,fx,q,ev,e=make();q.evil=True
 with pytest.raises(NestedCuttlefishError,match="foreground"):e.run_update()
 assert ev[-1][0]=="stop"
def test_locked_guest_is_dismissed_before_launch_and_still_locked_rejects():
 p,b,fx,q,ev,e=make();receipt=e.install_baseline("/input/b.apk");keyguard=receipt["ui"]["keyguard"]
 assert keyguard["before"]["showing"] is True and keyguard["after"]["showing"] is False
 assert [x["argv"] for x in keyguard["commands"]]==[["shell","wm","dismiss-keyguard"]] and keyguard["after_dismiss"]==keyguard["after"]
 p,b,fx,q,ev,e=make();q.stubborn_lock=True
 with pytest.raises(NestedCuttlefishError,match="remained locked"):e._unlock(e.clock()+90)
def test_keyguard_dismiss_polls_transient_state_and_unlocked_path_has_no_input():
 p,b,fx,q,ev,e=make();original=e._keyguard;states=iter([(True,True),(True,False),(False,False)])
 def transient(d):
  row=original(d);showing,restricted=next(states);row.update(showing=showing,input_restricted=restricted);return row
 e._keyguard=transient;receipt=e._unlock(e.clock()+90)
 assert receipt["after"]["showing"] is False and receipt["after"]["input_restricted"] is False
 p,b,fx,q,ev,e=make();q.locked=False;receipt=e._unlock(e.clock()+30)
 assert receipt["commands"]==[] and not any(args[-2:]==["wm","dismiss-keyguard"] or args[-3:]==["input","keyevent","82"] for args,_ in q.calls)
def test_keyguard_policy_timeout_retries_to_exact_state_and_all_timeout_archives_attempts():
 p,b,fx,q,ev,e=make();q.policy_timeouts=1;q.timeout_partial=b"";row=e._keyguard(e.clock()+60)
 assert [x["exit_code"] for x in row["attempts"]]==[124,0] and row["attempts"][-1]["raw"]==row["raw"]
 p,b,fx,q,ev,e=make();q.policy_timeouts=3;q.timeout_partial=b"";archived=[];e.failure_archive=lambda record,screenshot=None:(archived.append(record) or archive_failure(record,screenshot))
 with pytest.raises(NestedCuttlefishError):e._keyguard(e.clock()+60)
 attempts=archived[-1]["last_probe"]["keyguard_attempts"];assert len(attempts)==3 and all(x["exit_code"]==124 and x["timed_out"] is True for x in attempts)
def test_unlock_uses_menu_only_after_locked_intermediate_and_never_retries_timed_menu():
 p,b,fx,q,ev,e=make();original=e._capture_result
 def dismiss_stays_locked(argv,d,label,maximum,command_cap=None):
  result=original(argv,d,label,maximum,command_cap)
  if label=="keyguard-command" and argv[-2:]==["wm","dismiss-keyguard"]:q.locked=True
  return result
 e._capture_result=dismiss_stays_locked;receipt=e._unlock(e.clock()+150)
 assert receipt["after_dismiss"]["showing"] is True and [x["argv"] for x in receipt["commands"]]==[["shell","wm","dismiss-keyguard"],["shell","input","keyevent","82"]] and receipt["after"]["showing"] is False
 p,b,fx,q,ev,e=make();original=e._capture_result;menu_calls=0
 def timed_menu_but_unlocked(argv,d,label,maximum,command_cap=None):
  nonlocal menu_calls
  if label=="keyguard-command" and argv[-3:]==["input","keyevent","82"]:
   menu_calls+=1;q.locked=False;return b"",{"rc":124}
  result=original(argv,d,label,maximum,command_cap)
  if label=="keyguard-command" and argv[-2:]==["wm","dismiss-keyguard"]:q.locked=True
  return result
 e._capture_result=timed_menu_but_unlocked;receipt=e._unlock(e.clock()+150)
 assert menu_calls==1 and receipt["commands"][-1]["exit_code"]==124 and receipt["commands"][-1]["timed_out"] is True and receipt["after"]["showing"] is False
 p,b,fx,q,ev,e=make();original=e._capture_result;menu_calls=0
 def timed_menu_still_locked(argv,d,label,maximum,command_cap=None):
  nonlocal menu_calls
  if label=="keyguard-command" and argv[-3:]==["input","keyevent","82"]:
   menu_calls+=1;return b"",{"rc":124}
  result=original(argv,d,label,maximum,command_cap)
  if label=="keyguard-command" and argv[-2:]==["wm","dismiss-keyguard"]:q.locked=True
  return result
 e._capture_result=timed_menu_still_locked
 with pytest.raises(NestedCuttlefishError,match="remained locked"):e._unlock(e.clock()+150)
 assert menu_calls==1
 p,b,fx,q,ev,e=make();original=e._capture_result;menu_calls=0
 def no_menu_without_proof_reserve(argv,d,label,maximum,command_cap=None):
  nonlocal menu_calls
  result=original(argv,d,label,maximum,command_cap)
  if label=="keyguard-command" and argv[-2:]==["wm","dismiss-keyguard"]:
   q.locked=True;e.clock.v=d-62
  if label=="keyguard-command" and argv[-3:]==["input","keyevent","82"]:menu_calls+=1
  return result
 e._capture_result=no_menu_without_proof_reserve
 with pytest.raises(NestedCuttlefishError,match="insufficient deadline for menu"):e._unlock(e.clock()+150)
 assert menu_calls==0
def test_post_dismiss_policy_timeout_retries_within_original_deadline_and_archives_all_three():
 p,b,fx,q,ev,e=make();original=e._capture_result;seen=0
 def transient(argv,d,label,maximum,command_cap=None):
  nonlocal seen
  if label=="keyguard-policy":
   seen+=1
   if seen==2:e.clock.v+=10;return b"",{"rc":124}
  return original(argv,d,label,maximum,command_cap)
 e._capture_result=transient;receipt=e._unlock(e.clock()+100)
 assert [x["exit_code"] for x in receipt["after"]["attempts"]]==[124,0] and e.clock()<200
 p,b,fx,q,ev,e=make();original=e._capture_result;seen=0;archived=[];e.failure_archive=lambda record,screenshot=None:(archived.append(record) or archive_failure(record,screenshot))
 def exhausted(argv,d,label,maximum,command_cap=None):
  nonlocal seen
  if label=="keyguard-policy":
   seen+=1
   if seen>=2:e.clock.v+=10;return b"",{"rc":124}
  return original(argv,d,label,maximum,command_cap)
 e._capture_result=exhausted
 with pytest.raises(NestedCuttlefishError):e._unlock(e.clock()+100)
 attempts=archived[-1]["last_probe"]["keyguard_attempts"];assert len(attempts)==3 and all(x["exit_code"]==124 for x in attempts) and e.clock()<=200
def test_baseline_relock_after_slow_install_is_unlocked_adjacent_to_monkey():
 p,b,fx,q,ev,e=make();original=e._package
 def package(*args):
  result=original(*args);q.locked=True;return result
 e._package=package;receipt=e.install_baseline("/input/b.apk")
 assert receipt["ui"]["keyguard"]["before"]["showing"] is True and receipt["ui"]["keyguard"]["after"]["showing"] is False
 policy_indices=[i for i,(args,_) in enumerate(q.calls) if args[-2:]==["window","policy"]];monkey_index=next(i for i,(args,_) in enumerate(q.calls) if "monkey" in args)
 assert policy_indices[-1]<monkey_index and monkey_index-policy_indices[-1]<=3
def test_rejected_focus_archive_preserves_fixture_and_guest_evidence():
 p,b,fx,q,ev,e=make();q.evil=True;e.failure_archive=lambda record:(_ for _ in ()).throw(RuntimeError("archive unavailable"))
 with pytest.raises(NestedCuttlefishError,match="archive failed") as caught:e.run_update()
 assert getattr(caught.value,"retain_owned_evidence",False) is True and not any(x[0]=="stop" for x in ev)
def test_focus_poll_accepts_delayed_exact_package_and_rejects_persistent_other():
 p,b,fx,q,ev,e=make();q.focus_delay=2;q.window_empty=True;wid,uid,pkg,activity,rows=e._focus((p.apk.package,),e.clock()+30)
 assert (wid,uid,pkg,activity)==("1234","10123",p.apk.package,"MainActivity") and len(rows)==3 and len(rows[-1]["matches"])==1 and all(x["size"]>0 and len(x["sha256"])==64 for x in rows)
 assert all(x["pidof"]["output"]["path"]=="adb:focus-pidof" and x["lifecycle"]["output"]["path"]=="adb:focus-lifecycle" for x in rows)
 assert rows[0]["matches"]==[] and rows[0]["lifecycle"]["output"]["sha256"]==hashlib.sha256(b"").hexdigest()
 q.focus="com.android.systemui/Home"
 with pytest.raises(NestedCuttlefishError,match="foreground activity-top mismatch") as caught:e._focus((p.apk.package,),e.clock()+30)
 assert '"package":"com.android.systemui"' in str(caught.value) and len(str(caught.value))<4600
def test_focus_polls_actual_key_value_splash_until_drawn_and_rejects_persistent_splash():
 p,b,fx,q,ev,e=make();q.splash_count=1;wid,uid,pkg,activity,rows=e._focus((p.apk.package,),e.clock()+30)
 assert (wid,uid,pkg,activity)==("1234","10123",p.apk.package,"MainActivity") and len(rows)==2
 assert rows[0]["matches"][0]["drawn"] is False and rows[0]["matches"][0]["starting_displayed"] is True
 assert rows[1]["matches"][0]["drawn"] is True and rows[1]["matches"][0]["starting_displayed"] is False
 p,b,fx,q,ev,e=make();q.splash_count=9
 with pytest.raises(NestedCuttlefishError,match="foreground activity-top mismatch"):e._focus((p.apk.package,),e.clock()+30)
def test_splash_pid_change_remains_fatal_and_archives_each_lifecycle_snapshot():
 p,b,fx,q,ev,e=make();archived=[];e.failure_archive=lambda record,screenshot=None:(archived.append(record) or archive_failure(record,screenshot));original=e._capture_result
 activity=iter((
  "packageName=org.amnezia.vpn\napp=ProcessRecord{x 5548:org.amnezia.vpn/u0a123}\nmActivityComponent=org.amnezia.vpn/MainActivity\nstate=RESUMED finishing=false\nmVisibleRequested=true mVisible=true mClientVisible=true reportedVisible=false\nfirstWindowDrawn=false reportedDrawn=false\nstartingData=Splash{x}\nstartingWindow=Window{x} startingDisplayed=true",
  "packageName=org.amnezia.vpn\nmActivityComponent=org.amnezia.vpn/MainActivity\nstate=DESTROYED finishing=false\nmVisibleRequested=true mVisible=true mClientVisible=true reportedVisible=false\nfirstWindowDrawn=false reportedDrawn=false\nstartingData=Splash{x}\nstartingWindow=Window{x} startingDisplayed=true",
  "packageName=org.amnezia.vpn\napp=ProcessRecord{x 5716:org.amnezia.vpn/u0a123}\nmActivityComponent=org.amnezia.vpn/MainActivity\nstate=RESUMED finishing=false\nmVisibleRequested=true mVisible=true mClientVisible=true reportedVisible=false\nfirstWindowDrawn=false reportedDrawn=false\nstartingData=Splash{x}\nstartingWindow=Window{x} startingDisplayed=true"))
 lifecycle=iter((b"start 5548",b"am_proc_died 5548",b"start 5716"));pids=iter((b"5548",b"",b"5716"))
 def capture(argv,d,label,maximum,command_cap=None):
  if label=="activity-top":data=next(activity).encode()
  elif label=="focus-pidof":data=next(pids)
  elif label=="focus-lifecycle":data=next(lifecycle)
  else:return original(argv,d,label,maximum,command_cap)
  return data,{"rc":0}
 e._capture_result=capture
 with pytest.raises(NestedCuttlefishError,match="foreground activity-top mismatch"):e._focus((p.apk.package,),e.clock()+30,lifecycle_epoch="1726185600.000")
 probe=archived[-1]["last_probe"];assert probe["reason"]=="splash-process-changed" and len(probe["focus_observations"])==3
 assert [__import__('base64').b64decode(x["lifecycle"]["output"]["bytes_b64"]) for x in probe["focus_observations"]]==[b"start 5548",b"am_proc_died 5548",b"start 5716"]
def test_oversized_lifecycle_diagnostic_does_not_block_stable_pid_ready_and_is_retained():
 p,b,fx,q,ev,e=make();q.splash_count=1;original=e._capture_result;failed=False
 def capture(argv,d,label,maximum,command_cap=None):
  nonlocal failed
  if label=="focus-lifecycle" and not failed:
   failed=True;e.last_command={"argv":[e.adb,"-P","5053","-s",e.serial,*argv],"capture_metadata":{"path":f"{p.root}/evidence/oversize","exit_code":125,"timed_out":False,"size":70000,"sha256":"1"*64},"stdout":{"size":70000,"sha256":"1"*64,"bytes_b64":None,"excerpt_b64":"","excerpt_size":0,"excerpt_sha256":hashlib.sha256(b"").hexdigest(),"complete":False}}
   raise NestedCuttlefishError("bounded capture output exceeds limit")
  return original(argv,d,label,maximum,command_cap)
 e._capture_result=capture;wid,uid,pkg,activity,rows=e._focus((p.apk.package,),e.clock()+30,lifecycle_epoch="1726185600.000")
 assert wid=="1234" and len(rows)==2 and rows[0]["lifecycle"]["capture_error"]["type"]=="NestedCuttlefishError" and rows[1]["matches"][0]["drawn"] is True
def test_lifecycle_capture_error_failure_archive_retains_all_observations():
 p,b,fx,q,ev,e=make();q.splash_count=9;archived=[];e.failure_archive=lambda record,screenshot=None:(archived.append(record) or archive_failure(record,screenshot));original=e._capture_result;failed=False
 def capture(argv,d,label,maximum,command_cap=None):
  nonlocal failed
  if label=="focus-lifecycle" and not failed:
   failed=True;e.last_command={"argv":[e.adb,"-P","5053","-s",e.serial,*argv],"capture_transport":{"stdout":{"size":0,"sha256":hashlib.sha256(b"").hexdigest(),"bytes_b64":"","excerpt_b64":""},"stderr":{"size":0,"sha256":hashlib.sha256(b"").hexdigest(),"bytes_b64":"","excerpt_b64":""}}};raise NestedCuttlefishError("transport diagnostic failed")
  return original(argv,d,label,maximum,command_cap)
 e._capture_result=capture
 with pytest.raises(NestedCuttlefishError):e._focus((p.apk.package,),e.clock()+30,lifecycle_epoch="1726185600.000")
 history=archived[-1]["last_probe"]["focus_observations"];assert len(history)==3 and history[0]["lifecycle"]["capture_error"]["type"]=="NestedCuttlefishError" and all("raw" in x for x in history)
def test_ci_capture_replays_all_32_raw_bytes_through_both_production_parsers():
 from pathlib import Path
 root=Path(__file__).parent/"test_fixtures"/"android16_focus";manifest=json.loads((root/"raw-manifest.json").read_text())
 paths=sorted(root.glob("focus-observation-*.raw"));assert len(paths)==len(manifest)==32
 rows=[]
 for index,path in enumerate(paths):
  raw=path.read_bytes();entry=manifest[index];assert entry["index"]==index and entry["path"]==path.name and entry["size"]==len(raw) and entry["sha256"]==hashlib.sha256(raw).hexdigest()
  produced=producer_focus_parser(raw.decode("utf-8","replace"));consumed=consumer_focus_parser(raw.decode("utf-8","replace"));assert produced==consumed and len(produced)==1;rows.append(produced[0])
 ready=[i for i,row in enumerate(rows) if row["state"]=="RESUMED" and row["finishing"] is False and row["visible"] and row["drawn"] and not row["starting_displayed"]]
 assert ready==list(range(8,32)) and sum("startingData=null" not in paths[i].read_text(errors="replace") for i in range(32))==4
@pytest.mark.parametrize("state_line",["state=RESUMED finishing=true","state=RESUMED","state=RESUMED finishing=false\nstate=RESUMED finishing=false"])
def test_focus_rejects_finishing_missing_or_duplicate_state(state_line):
 p,b,fx,q,ev,e=make();original=q.guest_exec_wait
 def altered(path,args,timeout=30):
  result=original(path,args,timeout)
  if args[-2:]==["activity","top-resumed"]:result["stdout"]=result["stdout"].replace("state=RESUMED finishing=false",state_line)
  return result
 q.guest_exec_wait=altered
 with pytest.raises(NestedCuttlefishError,match="foreground activity-top mismatch"):e._focus((p.apk.package,),e.clock()+30)
def test_initial_draw_uses_remaining_baseline_deadline_beyond_old_45_seconds():
 p,b,fx=setup();q=Q();q.splash_count=3;ev=[];clock=Clock();original=q.guest_exec_wait
 def slow_draw(path,args,timeout=30):
  result=original(path,args,timeout)
  if args[-2:]==["activity","top-resumed"]:clock.v+=20
  return result
 q.guest_exec_wait=slow_draw;e=NestedAppExecutor(q,p,boot(p),b,fx,lambda:p.ownership,lambda:dict(fx.outer_ownership),fixture_for(fx,ev),failure_archive=archive_failure,clock=clock,sleep=lambda _:None)
 _,_,_,_,rows=e._focus((p.apk.package,),clock()+220,initial_draw=True)
 assert len(rows)==4 and rows[-1]["elapsed_ms"]>=60000 and rows[-1]["matches"][0]["drawn"] is True
def test_focus_rejects_key_value_record_without_explicit_starting_displayed():
 p,b,fx,q,ev,e=make();original=q.guest_exec_wait
 def missing(path,args,timeout):
  if args[-2:]==["activity","top-resumed"]:
   return {"exitcode":0,"stdout":"packageName=org.amnezia.vpn\napp=ProcessRecord{37a499b 1234:org.amnezia.vpn/u0a123}\nmActivityComponent=org.amnezia.vpn/MainActivity\nstate=RESUMED finishing=false\nmVisibleRequested=true mVisible=true mClientVisible=true reportedVisible=true\nfirstWindowDrawn=false reportedDrawn=false\nstartingData=SplashScreenStartingData{org.amnezia.vpn}\nstartingWindow=Window{Splash Screen org.amnezia.vpn}"}
  return original(path,args,timeout)
 q.guest_exec_wait=missing
 with pytest.raises(NestedCuttlefishError,match="foreground activity-top mismatch"):e._focus((p.apk.package,),e.clock()+30)
 def contradictory(path,args,timeout):
  if args[-2:]==["activity","top-resumed"]:
   return {"exitcode":0,"stdout":"packageName=org.amnezia.vpn\napp=ProcessRecord{37a499b 1234:org.amnezia.vpn/u0a123}\nmActivityComponent=org.amnezia.vpn/MainActivity\nstate=RESUMED finishing=false\nmVisibleRequested=true mVisible=true mClientVisible=true reportedVisible=true\nfirstWindowDrawn=true reportedDrawn=true\nstartingData=null\nstartingWindow=Window{Splash Screen org.amnezia.vpn} startingDisplayed=false"}
  return original(path,args,timeout)
 q.guest_exec_wait=contradictory
 with pytest.raises(NestedCuttlefishError,match="foreground activity-top mismatch"):e._focus((p.apk.package,),e.clock()+30)
 q=Q();e.qga=q;q.focus=p.apk.package+"/MainActivity";original=q.guest_exec_wait
 def conflicting(path,args,timeout=30):
  if args[-2:]==["activity","top-resumed"]:return {"exitcode":0,"stdout":"ACTIVITY org.amnezia.vpn/MainActivity 123 pid=1234 uid=10123\nACTIVITY com.android.systemui/Home 124 pid=999 uid=1000"}
  return original(path,args,timeout)
 q.guest_exec_wait=conflicting
 with pytest.raises(NestedCuttlefishError,match="ambiguous"):e._focus((p.apk.package,),e.clock()+30)
 q=Q();q.focus_delay=100;e.qga=q
 with pytest.raises(NestedCuttlefishError,match="foreground activity-top mismatch"):e._focus((p.apk.package,),e.clock()+30)
def test_baseline_budget_reserves_focus_after_slow_install_and_expiry_is_diagnostic():
 p,b,fx=setup();q=Q();ev=[];clock=Clock();original=q.guest_exec_wait
 def slow(path,args,timeout=30):
  if "install" in args:clock.v+=250
  return original(path,args,timeout)
 q.guest_exec_wait=slow;e=NestedAppExecutor(q,p,boot(p),b,fx,lambda:p.ownership,lambda:dict(fx.outer_ownership),fixture_for(fx,ev),failure_archive=archive_failure,clock=clock,sleep=lambda _:None)
 receipt=e.install_baseline("/input/b.apk");assert receipt["passed"] and receipt["ui"]["focus_observations"]
 e._capture_result=lambda *a,**k:(_ for _ in ()).throw(NestedCuttlefishError("total update deadline expired"))
 with pytest.raises(NestedCuttlefishError,match="foreground activity-top mismatch") as caught:e._focus((p.apk.package,),clock()+1)
 assert '"observation_count":0' in str(caught.value) and '"capture_error"' in str(caught.value)
def test_focus_inner_activity_timeout_retains_partial_and_later_poll_succeeds():
 p,b,fx,q,ev,e=make();q.window_empty=True;q.activity_timeouts=1;wid,uid,pkg,activity,rows=e._focus((p.apk.package,),e.clock()+30)
 assert len(rows)==2 and rows[0]["exit_code"]==124 and rows[0]["size"]==len(b"partial activity output") and rows[1]["matches"][-1]["package"]==p.apk.package
 q.activity_timeouts=100
 with pytest.raises(NestedCuttlefishError,match="foreground activity-top mismatch") as caught:e._focus((p.apk.package,),e.clock()+30)
 assert '"exit_code":124' in str(caught.value) and '"sha256"' in str(caught.value)
def test_focus_empty_inner_timeout_can_be_followed_by_success():
 p,b,fx,q,ev,e=make();q.window_empty=True;q.activity_timeouts=1;q.timeout_partial=b"";wid,uid,pkg,activity,rows=e._focus((p.apk.package,),e.clock()+30)
 assert rows[0]["exit_code"]==124 and rows[0]["size"]==0 and rows[1]["exit_code"]==0 and pkg==p.apk.package
def test_top_resumed_failure_archives_full_bounded_raw_and_screencap_before_cleanup():
 p,b,fx,q,ev,e=make();raw=("ACTIVITY MANAGER TOP-RESUMED (dumpsys activity top-resumed)\n"+"x"*3945).encode();png=b"\x89PNG\r\n\x1a\n"+b"pixels"*1000;records=[];original=q.guest_exec_wait;capture=e._capture_result
 def failure_output(path,args,timeout=30):
  if args[-2:]==["activity","top-resumed"]:return {"exitcode":0,"stdout":raw.decode()}
  return original(path,args,timeout)
 q.guest_exec_wait=failure_output
 def capture_with_png(args,*rest,**kwargs):
  if args[:3]==["exec-out","screencap","-p"]:return png,{"rc":0}
  return capture(args,*rest,**kwargs)
 e._capture_result=capture_with_png
 def archive(record,screenshot=None):
  assert screenshot==png;records.append(record);ev.append(("archive",record["phase"]));ack=archive_failure(record);ack["screenshot"]={"path":"/archive/focus.png","sha256":hashlib.sha256(png).hexdigest(),"size":len(png)};return ack
 e.failure_archive=archive
 with pytest.raises(NestedCuttlefishError,match="foreground activity-top mismatch"):e._focus((p.apk.package,),e.clock()+30)
 e._stop(e.clock()+30)
 probe=records[0]["last_probe"]
 assert __import__('base64').b64decode(probe["top_resumed_raw"]["bytes_b64"])==raw
 assert probe["top_resumed_raw"]["size"]==len(raw) and probe["top_resumed_raw"]["sha256"]==hashlib.sha256(raw).hexdigest()
 archived_raw=probe["focus_observations"][0]["raw"]
 assert __import__('base64').b64decode(archived_raw["bytes_b64"])==raw and archived_raw["size"]==len(raw) and archived_raw["sha256"]==hashlib.sha256(raw).hexdigest()
 assert probe["screencap"]["size"]==len(png) and probe["screencap"]["sha256"]==hashlib.sha256(png).hexdigest() and len(json.dumps(records[0],separators=(",",":")))<524288 and ev[-2][0]=="archive" and ev[-1][0]=="stop"
def test_oversized_ui_is_rejected_and_cleanup_runs():
 p,b,fx,q,ev,e=make();q.big=True
 with pytest.raises(NestedCuttlefishError,match="app precondition failed"):e.run_update()
 assert ev[-1][0]=="stop"
def test_outer_change_after_call_fails_closed():
 p,b,fx=setup();q=Q();ev=[];calls=[0]
 def snap():calls[0]+=1;return p.ownership if calls[0]<4 else OuterOwnership(p.ownership.run_id,p.ownership.profile,p.ownership.attempt_nonce,99,3,p.ownership.uuid,p.ownership.qmp_socket,p.ownership.qga_socket)
 e=NestedAppExecutor(q,p,boot(p),b,fx,snap,lambda:dict(fx.outer_ownership),fixture_for(fx,ev),failure_archive=archive_failure)
 with pytest.raises(NestedCuttlefishError,match="ownership"):e.run_update()
def test_total_deadline_reaches_every_callback():
 p,b,fx=setup();q=Q();ev=[];clock=Clock()
 def slow(action,data,timeout):clock.v+=200;return fixture_for(fx,ev)(action,data,timeout)
 e=NestedAppExecutor(q,p,boot(p),b,fx,lambda:p.ownership,lambda:dict(fx.outer_ownership),slow,failure_archive=archive_failure,clock=clock)
 with pytest.raises(NestedCuttlefishError,match="app precondition failed"):e.run_update(60)
 assert ev[-1][0]=="stop"
def test_authoritative_server_snapshot_cannot_be_callback_echo():
 p,b,fx=setup();q=Q();ev=[];foreign={**dict(fx.outer_ownership),"pid":999}
 e=NestedAppExecutor(q,p,boot(p),b,fx,lambda:p.ownership,lambda:foreign,fixture_for(fx,ev),failure_archive=archive_failure)
 with pytest.raises(NestedCuttlefishError,match="fixture outer ownership"):e.run_update()
def test_stale_read_log_cursor_is_rejected_and_stopped():
 p,b,fx=setup();q=Q();ev=[];base=fixture_for(fx,ev)
 def stale(action,data,timeout):
  r=base(action,data,timeout)
  if action=="read-log":r["log_inode"]=999
  return r
 e=NestedAppExecutor(q,p,boot(p),b,fx,lambda:p.ownership,lambda:dict(fx.outer_ownership),stale,failure_archive=archive_failure,clock=Clock(),sleep=lambda _:None)
 with pytest.raises(NestedCuttlefishError,match="app precondition failed"):e.run_update()
 assert ev[-1][0]=="stop"
def test_qga_request_timeout_is_reduced_to_remaining_deadline():
 p,b,fx,q,ev,e=make();q.timeout=999;e.install_baseline("/input/b.apk");e.run_update()
 assert q.timeout==999 and q.request_timeouts and max(q.request_timeouts)<=30
def test_qga_close_error_is_not_silently_accepted():
 p,b,fx,q,ev,e=make();q.close_error=True
 with pytest.raises(NestedCuttlefishError,match="app precondition failed"):e.run_update()
def test_qga_read_primary_error_is_preserved_when_close_also_fails():
 p,b,fx,q,ev,e=make();q.read_error=True;q.close_error=True
 with pytest.raises(NestedCuttlefishError,match="guest-file-read") as caught:e._read_file("/owned",e.clock()+30,20)
 assert any("close also failed" in note for note in caught.value.__notes__)

def test_ambiguous_keyguard_archives_full_raw_and_png_before_cleanup():
 p,b,fx,q,ev,e=make();q.policy_raw="policy-header\n"+("x"*3900);events=[]
 original=e._capture_result;png=b"\x89PNG\r\n\x1a\nkeyguard"
 def capture(args,*rest,**kwargs):
  if args[:3]==["exec-out","screencap","-p"]:return png,{"rc":0}
  return original(args,*rest,**kwargs)
 e._capture_result=capture
 def archive(record,screenshot=None):
  events.append(("archive",record,screenshot));return {"origin":"controller","immutable":True,"path":"/archive/keyguard.json","sha256":"a"*64,"size":123,"screenshot":{"path":"/archive/keyguard.png","sha256":hashlib.sha256(screenshot).hexdigest(),"size":len(screenshot)}}
 e.failure_archive=archive
 with pytest.raises(NestedCuttlefishError,match="app precondition failed") as caught:e.install_baseline("/input/b.apk")
 probe=events[0][1]["last_probe"];raw=probe["keyguard_raw"]
 assert events[0][0]=="archive" and raw["size"]==len(q.policy_raw) and __import__('base64').b64decode(raw["bytes_b64"]).decode()==q.policy_raw
 assert events[0][2].startswith(b"\x89PNG") and getattr(caught.value,"archive_durable",False) is True

def test_completion_open_fallback_uses_one_shared_polling_loop():
 p,b,fx,q,ev,e=make();q.ui_actions=("Update","Install","Open")
 e.install_baseline("/input/b.apk");receipt=e.run_update()
 assert receipt["ui"]["completion_action"]=="Open"
 p,b,fx,q,ev,e=make();q.ui_actions=("Update","Install","Done","Open");q.focus="com.android.permissioncontroller/InstallActivity"
 action,_=e._tap_any(("Open","Done"),("com.android.packageinstaller","com.google.android.packageinstaller","com.android.permissioncontroller"),e.clock()+250);assert action=="Open"
 p,b,fx,q,ev,e=make();q.ui_actions=("Done","Done");q.focus="com.android.permissioncontroller/InstallActivity"
 with pytest.raises(NestedCuttlefishError,match="ambiguous"):e._tap_any(("Open","Done"),("com.android.packageinstaller","com.google.android.packageinstaller","com.android.permissioncontroller"),e.clock()+150)
def test_ui_xml_cat_timeout_retries_pair_and_all_timeout_archives_every_attempt():
 allowed=("com.android.packageinstaller","com.google.android.packageinstaller","com.android.permissioncontroller")
 p,b,fx,q,ev,e=make();q.focus="com.android.permissioncontroller/InstallActivity";q.ui_actions=("Open",);q.ui_cat_timeouts=1;q.timeout_partial=b""
 action,_=e._tap_any(("Open","Done"),allowed,e.clock()+250);assert action=="Open"
 attempts=e.ui_capture_history[-1]["attempts"];assert [x["cat"]["exit_code"] for x in attempts]==[124,0] and all(x["dump"]["exit_code"]==0 for x in attempts)
 p,b,fx,q,ev,e=make();q.focus="com.android.permissioncontroller/InstallActivity";q.ui_actions=("Open",);q.ui_cat_timeouts=3;q.timeout_partial=b"";archived=[];e.failure_archive=lambda record,screenshot=None:(archived.append(record) or archive_failure(record,screenshot))
 with pytest.raises(NestedCuttlefishError):e._tap_any(("Open","Done"),allowed,e.clock()+60)
 probe=archived[-1]["last_probe"];attempts=probe["ui_capture_observations"][-1]["attempts"];assert len(attempts)==3 and all(x["dump"]["exit_code"]==0 and x["cat"]["exit_code"]==124 for x in attempts)
 assert probe["fixture_log"]["request_log_sha256"]=="4"*64 and probe["fixture_log"]["request_log_size"]==4
def test_ui_xml_non_timeout_dump_or_cat_failure_never_retries_or_uses_stale_xml():
 p,b,fx,q,ev,e=make();calls=[]
 def dump_failed(argv,d,label,maximum,command_cap=None):calls.append(label);return b"dump failed",{"rc":1}
 e._capture_result=dump_failed
 with pytest.raises(NestedCuttlefishError,match="UI dump command failed"):e._ui_xml("/data/local/tmp/amz-nonce.xml",e.clock()+30,"ui-update")
 assert calls==["ui-update-dump"] and not any("input" in argv for argv,_ in q.calls)
 p,b,fx,q,ev,e=make();calls=[]
 def cat_failed(argv,d,label,maximum,command_cap=None):
  calls.append(label);return (b"dump ok",{"rc":0}) if label.endswith("-dump") else (b'<node package="org.amnezia.vpn" text="Update" bounds="[0,0][1,1]"/>',{"rc":1})
 e._capture_result=cat_failed
 with pytest.raises(NestedCuttlefishError,match="UI XML command failed"):e._ui_xml("/data/local/tmp/amz-nonce.xml",e.clock()+30,"ui-update")
 assert calls==["ui-update-dump","ui-update-cat"] and not any("input" in argv for argv,_ in q.calls)

def test_update_restarts_check_and_unknown_sources_is_diagnostic_only():
 p,b,fx,q,ev,e=make();e.install_baseline("/input/b.apk");q.ui_actions=("Update","Settings");records=[]
 def archive(record,screenshot=None):records.append(record);return archive_failure(record,screenshot)
 e.failure_archive=archive
 with pytest.raises(NestedCuttlefishError,match="app precondition failed"):e.run_update()
 probe=records[0]["last_probe"];xml=probe["ui_xml"];assert probe["reason"]=="unknown-sources-settings-unverified" and __import__('base64').b64decode(xml["bytes_b64"])
 flat=" ".join(" ".join(call[0]) for call in q.calls);assert "force-stop org.amnezia.vpn" in flat and "appops" not in flat and "grant" not in flat and "locksettings" not in flat

@pytest.mark.parametrize("kind",["nonzero","transport","transport-bool","metadata-bool","malformed","wrong-path","oversize","hash-mismatch","timeout"])
def test_capture_failure_retains_exact_metadata_without_arbitrary_path_read(kind):
 p,b,fx,q,ev,e=make();original=q.guest_exec_wait;reads=[];original_read=e._read_file
 def tracked(path,d,limit):reads.append(path);return original_read(path,d,limit)
 e._read_file=tracked
 def injected(path,args,timeout=30):
  if path=="/usr/bin/python3" and "RLIMIT_FSIZE" in args[1]:
   if kind=="malformed":return {"exitcode":0,"stdout":"{"}
   data=b"0123456789abcdefX" if kind=="oversize" else b"capture-output";q.pending=data;expected=args[3];rc=True if kind=="metadata-bool" else (124 if kind=="timeout" else (9 if kind=="nonzero" else 0));sha=("0"*64 if kind=="hash-mismatch" else hashlib.sha256(data).hexdigest())
   return {"exitcode":False if kind=="transport-bool" else (7 if kind=="transport" else 0),"stdout":json.dumps({"path":"/untrusted/path" if kind=="wrong-path" else expected,"size":len(data),"sha256":sha,"rc":rc})}
  return original(path,args,timeout)
 q.guest_exec_wait=injected
 with pytest.raises(NestedCuttlefishError):e._capture(["shell","dumpsys","package","installs"],e.clock()+30,"failure-retention",16,10)
 assert e.last_command["argv"][-4:]==["shell","dumpsys","package","installs"] and "capture_transport" in e.last_command
 if kind=="malformed":assert "capture_metadata" not in e.last_command and reads==[]
 elif kind=="wrong-path":assert "capture_metadata" not in e.last_command and reads==[]
 elif kind=="oversize":assert e.last_command["stdout"]["complete"] is False and e.last_command["stdout"]["excerpt_size"]==17
 else:
  assert e.last_command["capture_metadata"]["exit_code"]==(True if kind=="metadata-bool" else (124 if kind=="timeout" else (9 if kind=="nonzero" else 0))) and reads

def test_nonfocus_update_failure_archives_before_stop_and_bad_ack_retains():
 p,b,fx,q,ev,e=make();baseline=e.install_baseline("/input/b.apk");q.no_session=True;order=[]
 original=e.fixture_call
 def fixture(action,payload,timeout):
  if action=="stop":order.append("stop")
  return original(action,payload,timeout)
 e.fixture_call=fixture
 def archive(record,screenshot=None):
  order.append("archive");probe=record["last_probe"];assert record["phase"]=="app-update" and probe["reason"]=="update-exception"
  assert probe["focus_observations"][:len(baseline["ui"]["focus_observations"])]==baseline["ui"]["focus_observations"] and all(__import__('base64').b64decode(x["raw"]["bytes_b64"]) for x in probe["focus_observations"])
  return archive_failure(record,screenshot)
 e.failure_archive=archive
 with pytest.raises(NestedCuttlefishError,match="app precondition failed"):e.run_update()
 assert order[:2]==["archive","stop"]
 p,b,fx,q,ev,e=make();q.no_session=True;e.failure_archive=lambda *_:(_ for _ in ()).throw(RuntimeError("archive unavailable"))
 with pytest.raises(NestedCuttlefishError,match="archive failed") as caught:e.run_update()
 assert "stop" not in [x[0] for x in ev] and getattr(caught.value,"retain_owned_evidence",False) is True
