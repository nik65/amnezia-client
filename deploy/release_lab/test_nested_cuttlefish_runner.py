from __future__ import annotations
import base64, hashlib, io, json, shlex, subprocess, sys, shutil
from dataclasses import replace
import pytest
try:
    from nested_cuttlefish_runner import (MAX_CHUNK_SIZE,ApkSpec,AssetSpec,InnerPlan,NestedCuttlefishError,
        OuterOwnership,build_cleanup_script,build_launch_script,build_stage_plan,iter_asset_chunks,
        transcript_sha256,validate_app_update_receipt,validate_boot_receipt,validate_cleanup_receipt,
        validate_runtime_receipt,validate_stage_receipt)
except ImportError:
    from deploy.release_lab.nested_cuttlefish_runner import (MAX_CHUNK_SIZE,ApkSpec,AssetSpec,InnerPlan,
        NestedCuttlefishError,OuterOwnership,build_cleanup_script,build_launch_script,build_stage_plan,
        iter_asset_chunks,transcript_sha256,validate_app_update_receipt,validate_boot_receipt,
        validate_cleanup_receipt,validate_runtime_receipt,validate_stage_receipt)

def plan()->InnerPlan:
    owner=OuterOwnership("run-1","linux-headless-x64","nonce-1",123,456,"11111111-1111-1111-1111-111111111111",
        "/var/lib/amnezia-release-lab/runs/run-1/qmp.sock","/var/lib/amnezia-release-lab/runs/run-1/qga.sock")
    root="/var/lib/amnezia-release-lab/n/"+hashlib.sha256(b"run-1\0nonce-1").hexdigest()[:8]
    argv=(f"{root}/runtime/host/bin/launch_cvd",f"-instance_dir={root}/runtime/instance",
        f"-assembly_dir={root}/runtime/assembly",f"-system_image_dir={root}/runtime/images",
        f"-early_tmp_dir={root}/runtime/tmp","-vm_manager=qemu_cli","-device_external_network=slirp",
        "-enable_tap_devices=false","-enable_modem_simulator=false","-start_gnss_proxy=false",
        "-enable_host_bluetooth=false","-enable_host_nfc=false","-enable_host_uwb=false",
        "-start_webrtc=false","-report_anonymous_usage_stats=n",
        "-gpu_mode=guest_swiftshader","-adb_mode=vsock_half_tunnel","-run_adb_connector=true",
        "-cpus=2","-memory_mb=4096","-vsock_guest_cid=37",f"-qemu_binary_dir={root}/runtime/qemu","-noresume")
    return InnerPlan(owner,(AssetSpec("host.tar.gz","/assets/host.tar.gz",3,"a"*64),
        AssetSpec("arm64.zip","/assets/arm64.zip",4,"b"*64),AssetSpec("qemu.tar.gz","/assets/qemu.tar.gz",6,"d"*64)),
        ApkSpec("candidate.apk","/artifacts/candidate.apk",5,"c"*64,"org.amnezia.vpn",2187),37,999,launch_argv=argv,qemu_aarch64_sha256="e"*64)

def test_actual_frozen_release_apk_basenames_are_safe_and_accepted():
    baseline=ApkSpec("AmneziaVPN_5.0.1.38_android9+_arm64-v8a.apk","/frozen/AmneziaVPN_5.0.1.38_android9+_arm64-v8a.apk",75_000_000,"8"*64,"org.amnezia.vpn",2186)
    candidate=ApkSpec("AmneziaVPN_5.0.1.39_android9+_arm64-v8a.apk","/frozen/AmneziaVPN_5.0.1.39_android9+_arm64-v8a.apk",76_000_000,"9"*64,"org.amnezia.vpn",2187)
    baseline.validate();candidate.validate()

@pytest.mark.parametrize("name",[
    "../AmneziaVPN_5.0.1.39_android9+_arm64-v8a.apk",
    "dir/AmneziaVPN_5.0.1.39_android9+_arm64-v8a.apk",
    "dir\\AmneziaVPN_5.0.1.39_android9+_arm64-v8a.apk",
    "AmneziaVPN_5.0.1.39_android9+_arm64-v8a.apk\x00",
    "AmneziaVPN_5.0.1.39_android9+_arm64-v8a\n.apk",
])
def test_apk_basename_still_rejects_traversal_separators_and_controls(name):
    with pytest.raises(NestedCuttlefishError,match="APK identity"):
        ApkSpec(name,"/frozen/app.apk",1,"9"*64,"org.amnezia.vpn",2187).validate()

def base(op:str)->dict:
    p=plan(); return {"schema":2,"operation":op,"run_id":"run-1","profile":"linux-headless-x64",
        "attempt_nonce":"nonce-1","marker":p.marker,"guest_root":p.root,"outer_ownership":vars(p.ownership),
        "origin":"guest","transport":"qga","injected":False,"passed":True}

def chunked(data:bytes)->list[dict]:
    return list(iter_asset_chunks(io.BytesIO(data),expected_size=len(data),deadline_monotonic=10,now=lambda:0))

def stage()->dict:
    result=base("nested-cuttlefish-stage"); records=[]
    specs=[*plan().assets,AssetSpec(plan().apk.name,plan().apk.source_path,plan().apk.size,plan().apk.sha256)]
    for spec,data in zip(specs,(b"aaa",b"bbbb",b"dddddd",b"ccccc")):
        chunks=chunked(data); records.append({"name":spec.name,"guest_path":f"{plan().root}/input/{spec.name}",
          "size":spec.size,"received_size":spec.size,"sha256":spec.sha256,"guest_sha256":spec.sha256,"eof":True,
          "transfer":{"chunk_count":len(chunks)-1,"received_size":spec.size,"eof":True,
                      "transcript_sha256":transcript_sha256(chunks)}})
    result["guest_root_identity"]={"dev":1,"inode":2,"uid":0,"gid":0,"mode":"0711"};paths=["/var/lib/amnezia-release-lab","/var/lib/amnezia-release-lab/n"]
    result["guest_ancestry"]={"ancestry":[{"before":{"path":q,"dev":10+i,"inode":20+i,"uid":0,"gid":0,"mode":"0700" if i==0 else "0755"},"after":{"path":q,"dev":10+i,"inode":20+i,"uid":0,"gid":0,"mode":"0711"}} for i,q in enumerate(paths)],"attempt":{"dev":1,"inode":2,"uid":0,"gid":0,"mode":"0700"},"runtime_probe":{"euid":plan().runtime_uid,"egid":999,"groups":[],"paths":[{"path":q,"execute":True} for q in paths]}}
    p=plan();qp=f"{p.root}/runtime/qemu/qemu-system-aarch64";result["runtime_ownership"]={"schema":1,"root":p.root,"root_before":{"path":p.root,"dev":1,"inode":2,"uid":0,"gid":0,"mode":"0700"},"root_after":{"path":p.root,"dev":1,"inode":2,"uid":0,"gid":0,"mode":"0711"},"directories":[{"path":f"{p.root}/runtime","created":False,"dev":1,"inode":5,"uid":0,"gid":0,"mode":"0700"},{"path":f"{p.root}/logs","created":True,"dev":1,"inode":6,"uid":0,"gid":0,"mode":"0700"}]+[{"path":f"{p.root}/runtime/{name}","created":True,"dev":1,"inode":7+i,"uid":0,"gid":0,"mode":"0700"} for i,name in enumerate(("home","tmp","instance","assembly"))],"runtime_uid":p.runtime_uid,"primary_gid":999,"qemu_before":{"path":qp,"dev":3,"inode":4,"uid":0,"gid":0,"mode":"0755"},"qemu_after":{"path":qp,"dev":3,"inode":4,"uid":p.runtime_uid,"gid":999,"mode":"0755"},"qemu_sha256":p.qemu_aarch64_sha256,"access_exit_code":0,"access":{"read":True,"execute":True},"write_probe_exit_code":0,"write_probes":[{"path":f"{p.root}/runtime/{name}","write_delete":True} for name in ("home","tmp","instance","assembly")]+[{"path":f"{p.root}/logs","write_delete":True}],"origin":"guest","transport":"qga","injected":False};result["assets"]=records; return result

def process(name:str,pid:int)->dict:
    exe=f"{plan().root}/runtime/{'qemu' if name=='qemu-system-aarch64' else 'host/bin'}/{name}"
    argv=[exe,plan().root]
    if name=="adb": argv += ["-P","5053"]
    if name=="qemu-system-aarch64": argv += ["-device","vhost-vsock-pci,guest-cid=37"]
    if name=="adb_connector": argv=[exe,"--addresses=0.0.0.0:6520"]
    if name=="socket_vsock_proxy": argv=[exe,"--server_type=tcp","--server_tcp_port=6520","--client_type=vsock","--client_vsock_port=5555","--client_vsock_id=37","--label=adb"]
    return {"pid":pid,"start_ticks":1000+pid,"exe":exe,"exe_sha256":hashlib.sha256(name.encode()).hexdigest(),
      "uid":999,"state":"S","argv":argv,"cmdline_sha256":hashlib.sha256("\0".join(argv).encode()).hexdigest(),
      "groups":([4242] if name=="adb" else [993,4242]),"cgroup":"/amnezia-release-lab/run-1/nonce-1"}

def wayland_dependency(p:InnerPlan,gid:int=999)->tuple[dict,dict]:
    install={"schema":1,"operation":"nested-wayland-install","run_id":p.ownership.run_id,"attempt_nonce":p.ownership.attempt_nonce,"outer":vars(p.ownership),"origin":"guest","transport":"qga","injected":False,"supplement":{"sha256":"3b2a227cf05c5f104defc0f56c186c77f7fbf9d608177224c775cd4adb590845","size":61440},"package":{"name":"libwayland-server0","version":"1.22.0-2.1build1","architecture":"amd64","deb_sha256":"edbfa4b6857691ae922cc768a753fab230eee9e956aa2ce4f2eaa8d9ad777dca","deb_size":33928,"binary_key":"libwayland-server0:amd64","status":"ii "},"changed_packages":["libwayland-server0:amd64"],"unpack":{"exit_code":0},"configure":{"exit_code":0}}
    q=f"{p.root}/runtime/qemu/qemu-system-aarch64";ld=":".join((f"{p.root}/runtime/private-libs",f"{p.root}/runtime/qemu",f"{p.root}/runtime/host/lib64",f"{p.root}/runtime/host/lib"));base=["/usr/bin/setpriv",f"--reuid={p.runtime_uid}",f"--regid={gid}","--clear-groups"]
    def row(argv,out):return {"argv":argv,"exit_code":0,"stdout_sha256":hashlib.sha256(out.encode()).hexdigest(),"stderr_sha256":hashlib.sha256(b"").hexdigest(),"stdout_size":len(out),"stderr_size":0,"stdout_excerpt":out,"stderr_excerpt":"","missing":[],"dependency_count":1}
    runtime={"schema":1,"operation":"nested-wayland-runtime-proof","run_id":p.ownership.run_id,"attempt_nonce":p.ownership.attempt_nonce,"outer":vars(p.ownership),"origin":"guest","transport":"qga","injected":False,"uid":p.runtime_uid,"primary_gid":gid,"ld_library_path":ld,"qemu":{"path":q,"sha256":p.qemu_aarch64_sha256,"size":10},"ldd":row(base+["/usr/bin/ldd",q],"libwayland-server.so.0 => /lib/x"),"version":row(base+[q,"-version"],"QEMU 8.2")}
    return install,runtime

def boot()->dict:
    p=plan();result=base("nested-cuttlefish-boot")
    procs=[process("run_cvd",201),process("adb",202),process("qemu-system-aarch64",203),process("kernel_log_monitor",204),process("adb_connector",205),process("socket_vsock_proxy",206)]
    result.update({"containment":{"kind":"cgroup-v2","path":"/amnezia-release-lab/run-1/nonce-1",
        "member_pids":[201,202,203,204,205,206],"stable_reads":2},"processes":procs,
        "roles":{"cvd":201,"adb":202,"qemu":203},"boot":{"abi":"arm64-v8a","boot_completed":"1",
        "serial":"127.0.0.1_6520","boot_id":"22222222-2222-2222-2222-222222222222"},
        "vsock_cid":37,"adb_endpoint":"127.0.0.1:5053","cvdnetwork_gid":4242,"kvm_gid":993,"vhost_vsock":{"path":"/dev/vhost-vsock","dev":7,"inode":8,"uid":0,"gid":993,"mode":"0660","rdev":9,"char":True},
        "runtime_dependency":{"wayland_install":wayland_dependency(p)[0],"wayland_runtime":wayland_dependency(p)[1],"group_provisioning":{"schema":1,"uid":p.runtime_uid,"user":"lab","primary_gid":999,"cvdnetwork_gid":4242,"created":True,"member":True,"resolved_groups":[999,4242],"files":[{"path":x,"before_sha256":"3"*64,"after_sha256":"4"*64} for x in ("/etc/group","/etc/gshadow")],"commands":[{"argv":a,"exe_sha256":"5"*64,"exit_code":0,"stdout_size":0,"stderr_size":0} for a in (["/usr/sbin/groupadd","--system","cvdnetwork"],["/usr/sbin/usermod","-aG","cvdnetwork","lab"])],"kvm_modified":False,"vhost_modified":False,"origin":"guest","transport":"qga","injected":False},"stage":{"sha256":p.vulkan_deb_sha256,"size":p.vulkan_deb_size,"guest_root_identity":{"dev":1,"inode":2,"uid":0,"gid":0,"mode":"0711"}},"installed":{"run_id":p.ownership.run_id,"attempt_nonce":p.ownership.attempt_nonce,"origin":"guest","transport":"qga","injected":False,"loader":{"path":f"{p.root}/runtime/private-libs/libvulkan.so.1.3.275","soname_path":f"{p.root}/runtime/private-libs/libvulkan.so.1","sha256":p.vulkan_loader_sha256,"size":p.vulkan_loader_size,"uid":0,"mode":"0644","directory_uid":0,"directory_mode":"0755"},"dlopen":True,"vkGetInstanceProcAddr":True,"graphics_detector":{"exit_code":0,"assertion":False,"uid":p.runtime_uid,"groups":[4242],"stdout_sha256":"0"*64,"stdout_size":0,"stderr_sha256":"1"*64,"stderr_size":0,"output_file":{"path":f"{p.root}/runtime/graphics-probe/availability.pbtxt","kind":"regular","dev":1,"inode":2,"uid":p.runtime_uid,"gid":1000,"mode":"0600","sha256":"2"*64,"size":26091,"eof":True}}}},
        "network":{"adb_listen":"127.0.0.1:5053","host_mutation":False,"host_mounts":[],"qemu_netdev_argv":["user,id=hostnet0,net=10.0.2.15/24,host=10.0.2.2,dns=127.0.0.1"],"ril_config":{"schema":1,"records":[{"path":path,"before_sha256":"2"*64,"after_sha256":"3"*64,"size":100,"alias_target":path,"ril_ipaddr":"10.0.2.15","ril_gateway":"10.0.2.2","ril_prefixlen":24,"ril_dns":"10.0.2.3"} for path in (f"{plan().root}/runtime/assembly/cuttlefish_config.json",f"{plan().root}/runtime/instance/assembly/cuttlefish_config.json",f"{plan().root}/runtime/instance/instances/cvd-1/cuttlefish_config.json")]}}})
    paths=[x["path"] for x in result["network"]["ril_config"]["records"]];adb=f"{p.root}/runtime/host/bin/adb";empty="List of devices attached\n";connected="List of devices attached\n127.0.0.1:6520\tdevice\n"
    def cmd(argv,out): return {"argv":argv,"exit_code":0,"stdout":out,"stdout_size":len(out),"stdout_sha256":hashlib.sha256(out.encode()).hexdigest(),"stderr":"","stderr_size":0,"stderr_sha256":hashlib.sha256(b"").hexdigest()}
    result["network"]["adb_connection"]={"endpoint":"127.0.0.1:6520","before":cmd([adb,"-P","5053","devices"],empty),"connect":cmd([adb,"-P","5053","connect","127.0.0.1:6520"],"connected"),"after":cmd([adb,"-P","5053","devices"],connected),"binding":{"endpoint":"127.0.0.1:6520","config_rows":[{"path":x,"sha256":"3"*64,"size":100,"adb_host_port":6520,"adb_ip_and_port":"0.0.0.0:6520"} for x in paths],"connector_pid":205,"proxy_pid":206,"connector_argv":procs[4]["argv"],"proxy_argv":procs[5]["argv"]}}
    return result

def app()->dict:
    b=boot(); result=base("nested-cuttlefish-app-update"); result["boot_binding_sha256"]=hashlib.sha256(json.dumps(b,sort_keys=True,separators=(",",":")).encode()).hexdigest()
    result["package_installer"]={"package":"org.amnezia.vpn","version_code":2187,"artifact_sha256":"c"*64,
      "artifact_size":5,"download_sha256":"c"*64,"session_id":7,"status":"STATUS_SUCCESS","method":"PackageInstaller","snapshot_argv":["shell","dumpsys","package","installs"]}
    result["http"]={"fixture_nonce":"fixture-1","manifest_sha256":"f"*64,"requests":[
      {"path":"/manifest.json","method":"GET","status":200,"eof":True,"bytes":100,"sha256":"f"*64},
      {"path":f"/files/artifacts/{'c'*64}/candidate.apk","method":"GET","status":200,"eof":True,"bytes":5,"sha256":"c"*64}]}
    result["ui"]={"package":"org.amnezia.vpn","activity":"MainActivity","window_id":"activity-top:301","window_title":"AmneziaVPN",
      "package_pid":301,"package_uid":10123,"version_code":2187,"screenshot_sha256":"1"*64,"completion_action":"Done"}
    focus_line="packageName=org.amnezia.vpn\napp=ProcessRecord{37a499b 301:org.amnezia.vpn/u0a123}\nmActivityComponent=org.amnezia.vpn/MainActivity\nstate=RESUMED finishing=false\nmVisibleRequested=true mVisible=true mClientVisible=true reportedVisible=true\nfirstWindowDrawn=true reportedDrawn=true\nstartingData=null"
    focus_bytes=focus_line.encode();focus_raw={"origin":"guest","transport":"qga-adb","path":"adb:activity-top-resumed","size":len(focus_bytes),"sha256":hashlib.sha256(focus_bytes).hexdigest(),"bytes_b64":base64.b64encode(focus_bytes).decode()}
    epoch="1726185600.000";empty_raw={"origin":"guest","transport":"qga-adb","size":0,"sha256":hashlib.sha256(b"").hexdigest(),"bytes_b64":""}
    pidof={"argv":["shell","pidof","org.amnezia.vpn"],"exit_code":0,"timed_out":False,"output":{**empty_raw,"path":"adb:focus-pidof"}}
    lifecycle_argv=["shell","logcat","-d","-T",epoch,"-t","200","-v","threadtime","-b","main","-b","system","-b","events","-b","crash","ActivityManager:I","ActivityTaskManager:I","AndroidRuntime:E","lmkd:I","lowmemorykiller:I","*:S"]
    lifecycle={"argv":lifecycle_argv,"exit_code":0,"timed_out":False,"output":{**empty_raw,"path":"adb:focus-lifecycle"}}
    result["ui"]["focus_observations"]=[{"argv":["shell","dumpsys","activity","top-resumed"],"exit_code":0,"timed_out":False,"size":len(focus_line),"sha256":hashlib.sha256(focus_line.encode()).hexdigest(),"raw":focus_raw,"relevant_lines":focus_line,"matches":[{"package":"org.amnezia.vpn","component":"MainActivity","pid":301,"uid":10123,"format":"key-value","state":"RESUMED","finishing":False,"visible":True,"drawn":True,"starting_displayed":False}],"elapsed_ms":100,"pidof":pidof,"lifecycle":lifecycle,"logcat":None}]
    empty=hashlib.sha256(b"").hexdigest();result["ui"]["launch_probe"]={"argv":["shell","monkey","-p","org.amnezia.vpn","1"],"exit_code":0,"timed_out":False,"output":{"origin":"guest","transport":"qga-adb","path":"adb:candidate-monkey","size":0,"sha256":empty,"bytes_b64":""}}
    def raw(path,value):
      data=value.encode();return {"origin":"guest","transport":"qga-adb","path":path,"size":len(data),"sha256":hashlib.sha256(data).hexdigest(),"bytes_b64":base64.b64encode(data).decode()}
    result["package_installer"]["session_evidence"]={"before":raw("adb:dumpsys-package-installs",""),"after":[raw("adb:dumpsys-package-installs","Session 7:\n  mAppPackageName=org.amnezia.vpn\n  mFinalStatus=1\n")]}
    policy=["shell","dumpsys","window","policy"]
    before_raw=raw("adb:keyguard-policy","KeyguardServiceDelegate:\n  showing=true\n  inputRestricted=true\n  simSecure=false");after_raw=raw("adb:keyguard-policy","KeyguardServiceDelegate:\n  showing=false\n  inputRestricted=false\n  simSecure=false")
    middle={"argv":policy,"showing":True,"input_restricted":True,"raw":before_raw,"attempts":[{"exit_code":0,"timed_out":False,"raw":before_raw}]}
    guard={"before":{"argv":policy,"showing":True,"input_restricted":True,"raw":before_raw,"attempts":[{"exit_code":0,"timed_out":False,"raw":before_raw}]},"after_dismiss":middle,"commands":[{"argv":["shell","wm","dismiss-keyguard"],"exit_code":0,"timed_out":False,"raw":raw("adb:keyguard-command","")},{"argv":["shell","input","keyevent","82"],"exit_code":0,"timed_out":False,"raw":raw("adb:keyguard-command","")}],"after":{"argv":policy,"showing":False,"input_restricted":False,"raw":after_raw,"attempts":[{"exit_code":0,"timed_out":False,"raw":after_raw}]},"passed":True}
    result["ui"]["keyguard"]=[{"phase":x,"receipt":json.loads(json.dumps(guard))} for x in ("installer-monkey","update-tap","install-tap","completion-tap","launch-monkey")]
    result["timeout_seconds"]=300
    result["ui"]["update_check_restart"]={"force_stop":{"argv":["shell","am","force-stop","org.amnezia.vpn"],"exit_code":0,"output":raw("adb:update-check-force-stop","")},"keyguard":json.loads(json.dumps(guard)),"monkey":{"argv":["shell","monkey","-p","org.amnezia.vpn","1"],"exit_code":0,"timed_out":False,"output":raw("adb:update-check-monkey","")},"readiness":json.loads(json.dumps(result["ui"]["focus_observations"]))}
    remote="/data/local/tmp/amz-nonce-1.xml";result["ui"]["ui_capture_observations"]=[{"label":"ui-update","remote":remote,"attempts":[{"dump":{"argv":["shell","uiautomator","dump","--compressed",remote],"exit_code":0,"timed_out":False,"output":raw("adb:ui-dump","")},"cat":{"argv":["shell","cat",remote],"exit_code":0,"timed_out":False,"output":raw("adb:ui-xml",'<node package="com.android.permissioncontroller" text="Update" bounds="[0,0][1,1]"/>')}}]}]
    result["ui"]["package_state"]={"version_code":2187,"uid":10123,"dumpsys":{"argv":["shell","dumpsys","package","org.amnezia.vpn"],"exit_code":0,"output":raw("adb:dumpsys-package","versionCode=2187 minSdk=28 targetSdk=36")},"uid_lookup":{"argv":["shell","cmd","package","list","packages","-U","org.amnezia.vpn"],"exit_code":0,"output":raw("adb:cmd-package-list-U","package:org.amnezia.vpn uid:10123")}}
    result["logcat"]={"started_at":epoch,"finished_at":"2026-09-13T00:00:10Z","sha256":"2"*64,"crashes":[]}
    return result

def test_stream_is_size_deadline_offset_and_eof_bound():
    data=b"x"*(MAX_CHUNK_SIZE+17); rows=chunked(data)
    assert [x["offset"] for x in rows]==[0,MAX_CHUNK_SIZE,len(data)]
    assert base64.b64decode(rows[0]["data_b64"])==data[:MAX_CHUNK_SIZE]
    with pytest.raises(NestedCuttlefishError,match="before expected"): list(iter_asset_chunks(io.BytesIO(b"x"),expected_size=2,deadline_monotonic=9,now=lambda:0))
    with pytest.raises(NestedCuttlefishError,match="exceeds"): list(iter_asset_chunks(io.BytesIO(b"xx"),expected_size=1,deadline_monotonic=9,now=lambda:0))
    with pytest.raises(NestedCuttlefishError,match="deadline"): list(iter_asset_chunks(io.BytesIO(b"x"),expected_size=1,deadline_monotonic=0,now=lambda:1))

def test_stage_requires_exact_apk_path_hash_order_transcript():
    assert validate_stage_receipt(plan(),stage())["passed"]
    for mutate in (lambda x:x["assets"][3].update(guest_sha256="9"*64),lambda x:x["assets"][0]["transfer"].update(received_size=1),lambda x:x["assets"][1].update(guest_path="/tmp/x"),lambda x:x["guest_ancestry"]["ancestry"][0]["after"].update(inode=999),lambda x:x["guest_ancestry"]["runtime_probe"]["paths"][0].update(execute=False),lambda x:x["guest_root_identity"].update(mode="0700"),lambda x:x["guest_ancestry"]["attempt"].update(inode=999),lambda x:x["runtime_ownership"]["root_before"].update(inode=999),lambda x:x["runtime_ownership"]["root_after"].update(inode=999)):
        value=stage(); mutate(value)
        with pytest.raises(NestedCuttlefishError): validate_stage_receipt(plan(),value)

def test_exact_plan_uses_real_reviewed_flags_and_guest_cgroup():
    value=build_stage_plan(plan()); script=build_launch_script(plan())
    assert len(plan().root+"/runtime/tmp/cf_avd_999/cvd-1/grpc_socket/GnssGrpcProxyServer.sock") <= 107
    assert value["host_mounts"]==[] and value["host_network_mutation"] is False
    assert "device_external_network=slirp" in script and "enable_tap_devices=false" in script
    assert "enable_modem_simulator=false" in script and "start_gnss_proxy=false" in script
    assert "/runtime/host/bin/assemble_cvd" in script and "exec " in script and "/runtime/host/bin/run_cvd\n" in script
    assert "run_cvd --daemon" not in script
    assert "ril_ipaddr" in script and "10.0.2.15" in script and "ril_gateway" in script and "10.0.2.2" in script
    assert "unexpected generated RIL config" in script and "runtime/ril-config-receipt.json" in script
    assert "root/'ril-config-receipt.json'" not in script
    assert "/sys/fs/cgroup/amnezia-release-lab" in script and "cgroup.procs" in script
    assert 'chmod 0711 "$root"' not in script and 'install -d -m 0700 "$HOME"' not in script
    assert "runtime-directory-identity" in script
    assert " timeout " not in script
    assert 'setsid ' in script
    p=plan(); bad=InnerPlan(p.ownership,p.assets,p.apk,37,999,launch_argv=p.launch_argv+("-wifi_tap_name=tap0",))
    with pytest.raises(NestedCuttlefishError,match="canonical"): build_stage_plan(bad)
    daemon=replace(p,launch_argv=p.launch_argv+("-daemon",))
    with pytest.raises(NestedCuttlefishError,match="noncanonical"): build_stage_plan(daemon)

def test_config_patch_groups_parent_symlink_alias_before_mutation(tmp_path):
    p=plan(); root=tmp_path/'n'; runtime=root/'runtime'; (runtime/'assembly').mkdir(parents=True); (runtime/'instances'/'cvd-1').mkdir(parents=True)
    try:(runtime/'instance').symlink_to('.',target_is_directory=True)
    except (OSError,NotImplementedError):pytest.skip('directory symlinks unavailable')
    raw=(json.dumps({'instances':{'1':{'external_network_mode':'slirp','ril_ipaddr':'','ril_gateway':'','ril_prefixlen':255,'ril_dns':''}}})+'\n').encode()
    (runtime/'assembly'/'cuttlefish_config.json').write_bytes(raw); (runtime/'instances'/'cvd-1'/'cuttlefish_config.json').write_bytes(raw)
    script=build_launch_script(p); start=script.index('/usr/bin/python3 -c ',script.index('assemble_cvd')); end=script.index('\nexec ',start); argv=shlex.split(script[start:end])
    code=argv[2].replace('os.O_NOFOLLOW',"getattr(os,'O_NOFOLLOW',0)").replace('os.fchown(f.fileno(),s.st_uid,s.st_gid);','').replace("d=os.open(target.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(d);os.close(d)",'')
    subprocess.run([sys.executable,'-c',code,str(root)],check=True)
    logical=(runtime/'assembly'/'cuttlefish_config.json',runtime/'instance'/'assembly'/'cuttlefish_config.json',runtime/'instance'/'instances'/'cvd-1'/'cuttlefish_config.json')
    assert len({x.read_bytes() for x in logical})==1
    receipt=json.loads((root/'runtime'/'ril-config-receipt.json').read_text())
    assert len(receipt['records'])==3
    assert receipt['records'][0]['alias_target']==receipt['records'][1]['alias_target']
    assert receipt['records'][2]['alias_target']!=receipt['records'][0]['alias_target']

def test_config_receipt_is_written_by_real_uid1000_below_root0711():
    if sys.platform != "win32" or not shutil.which("wsl.exe"):
        pytest.skip("requires WSL uid1000 permission semantics")
    p=plan();script=build_launch_script(p);start=script.index('/usr/bin/python3 -c ',script.index('assemble_cvd'));end=script.index('\nexec ',start);code=shlex.split(script[start:end])[2]
    wrapper=r'''import base64,json,os,pathlib,shutil,sys,tempfile
assert os.getuid()==1000
root=pathlib.Path(tempfile.mkdtemp(prefix='ril-receipt-'));runtime=root/'runtime';os.chmod(root,0o711)
for rel in ('assembly','instance/assembly','instance/instances/cvd-1'):(runtime/rel).mkdir(parents=True,exist_ok=True)
os.chmod(runtime,0o700)
raw=(json.dumps({'instances':{'1':{'external_network_mode':'slirp','ril_ipaddr':'','ril_gateway':'','ril_prefixlen':255,'ril_dns':''}}})+'\n').encode()
for rel in ('assembly/cuttlefish_config.json','instance/assembly/cuttlefish_config.json','instance/instances/cvd-1/cuttlefish_config.json'):(runtime/rel).write_bytes(raw)
try:
 sys.argv=['patch',str(root)];exec(compile(base64.b64decode(sys.argv_saved).decode(),'patch','exec'))
 receipt=runtime/'ril-config-receipt.json';print(json.dumps({'uid':receipt.stat().st_uid,'mode':oct(receipt.stat().st_mode&0o777),'old':(root/'ril-config-receipt.json').exists()}))
finally:shutil.rmtree(root)
'''.replace('sys.argv_saved',repr(base64.b64encode(code.encode()).decode()))
    row=json.loads(subprocess.run(['wsl.exe','python3','-c',wrapper],check=True,capture_output=True,text=True).stdout)
    assert row=={'uid':1000,'mode':'0o600','old':False}

def test_boot_is_only_boot_and_requires_complete_stable_cgroup_inventory():
    assert validate_boot_receipt(plan(),boot())["passed"]
    symlink_exec=boot(); symlink_exec["processes"][0]["exe"]=f"{plan().root}/runtime/host/bin/cvd_internal_start"
    assert validate_boot_receipt(plan(),symlink_exec)["passed"]
    assert validate_runtime_receipt(plan(),boot())["operation"]=="nested-cuttlefish-boot"
    value=boot(); value["containment"]["member_pids"].append(999)
    with pytest.raises(NestedCuttlefishError,match="membership"): validate_boot_receipt(plan(),value)
    changed=boot();changed["runtime_dependency"]["group_provisioning"]["files"][0]["after_sha256"]=changed["runtime_dependency"]["group_provisioning"]["files"][0]["before_sha256"]
    with pytest.raises(NestedCuttlefishError,match="dependency"): validate_boot_receipt(plan(),changed)
    value=boot(); value["processes"][0]["uid"]=0
    with pytest.raises(NestedCuttlefishError): validate_boot_receipt(plan(),value)
    value=boot(); value["network"]["qemu_netdev_argv"]=["user,id=hostnet0,net=/255,host=,dns=127.0.0.1"]
    with pytest.raises(NestedCuttlefishError,match="network argv"): validate_boot_receipt(plan(),value)
    value=boot(); value["network"]["qemu_netdev_argv"]=["user,id=hostnet0,net=10.0.2.99/24,host=10.0.2.2,dns=10.0.2.3"]
    with pytest.raises(NestedCuttlefishError,match="hostnet0"): validate_boot_receipt(plan(),value)

def test_app_pass_needs_exact_apk_http_packageinstaller_ui_and_logcat():
    assert validate_app_update_receipt(plan(),boot(),app())["passed"]

def test_cm_android16_installs_raw_replays_through_consumer_field_bound_parser():
    from pathlib import Path
    raw_bytes=(Path(__file__).parent/"test_fixtures"/"android16_installs"/"installer-before.raw").read_bytes();assert len(raw_bytes)==2002 and hashlib.sha256(raw_bytes).hexdigest()=="c6005b716590e53b94cb82e27815bc308a007cbc4ee591c74362374149e16427"
    value=app();data=value["package_installer"]["session_evidence"];data["before"]={"origin":"guest","transport":"qga-adb","path":"adb:dumpsys-package-installs","size":len(raw_bytes),"sha256":hashlib.sha256(raw_bytes).hexdigest(),"bytes_b64":base64.b64encode(raw_bytes).decode()}
    assert validate_app_update_receipt(plan(),boot(),value)["passed"]
    active=b"Active Session 7:\n  sizeBytes=5 appPackageName=n\n    ull appIcon=false\n";active_row={"origin":"guest","transport":"qga-adb","path":"adb:dumpsys-package-installs","size":len(active),"sha256":hashlib.sha256(active).hexdigest(),"bytes_b64":base64.b64encode(active).decode()}
    value=app();value["package_installer"]["session_evidence"]["after"].insert(0,active_row);assert validate_app_update_receipt(plan(),boot(),value)["passed"]
    value=app();empty_sha=hashlib.sha256(b"").hexdigest();template=value["ui"]["focus_observations"][0];timeout={"argv":["shell","dumpsys","activity","top-resumed"],"exit_code":124,"timed_out":True,"size":0,"sha256":empty_sha,"raw":{"origin":"guest","transport":"qga-adb","path":"adb:activity-top-resumed","size":0,"sha256":empty_sha,"bytes_b64":""},"relevant_lines":"","matches":[],"elapsed_ms":0,"pidof":template["pidof"],"lifecycle":template["lifecycle"],"logcat":None};value["ui"]["focus_observations"].insert(0,timeout)
    assert validate_app_update_receipt(plan(),boot(),value)["passed"]
    value["ui"]["focus_observations"][0]["timed_out"]=False
    with pytest.raises(NestedCuttlefishError,match="foreground observation"):validate_app_update_receipt(plan(),boot(),value)
    value=app();value["ui"]["keyguard"][-1]["receipt"]["after"]["showing"]=True
    with pytest.raises(NestedCuttlefishError,match="keyguard"):validate_app_update_receipt(plan(),boot(),value)
    value=app();value["ui"]["update_check_restart"]["force_stop"]["argv"][-1]="other.package"
    with pytest.raises(NestedCuttlefishError,match="restart"):validate_app_update_receipt(plan(),boot(),value)
    value=app();value["ui"]["update_check_restart"]["readiness"][-1]["matches"][0]["visible"]=False
    with pytest.raises(NestedCuttlefishError,match="semantic evidence|readiness phase"):validate_app_update_receipt(plan(),boot(),value)
    value=app();value["ui"]["update_check_restart"]["monkey"].update(exit_code=124,timed_out=True);value["ui"]["launch_probe"].update(exit_code=124,timed_out=True)
    assert validate_app_update_receipt(plan(),boot(),value)["passed"]
    value["ui"]["launch_probe"]["timed_out"]=False
    with pytest.raises(NestedCuttlefishError,match="launch command"):validate_app_update_receipt(plan(),boot(),value)
    def session_row(text):
        data=text.encode();return {"origin":"guest","transport":"qga-adb","path":"adb:dumpsys-package-installs","size":len(data),"sha256":hashlib.sha256(data).hexdigest(),"bytes_b64":base64.b64encode(data).decode()}
    value=app();pending="Active Session 7:\n  appPackageName = org.amnezia.vpn\n";value["package_installer"]["session_evidence"]["after"].insert(0,session_row(pending));assert validate_app_update_receipt(plan(),boot(),value)["passed"]
    value=app();duplicate="Session 7:\n  mAppPackageName=org.amnezia.vpn\n  mFinalStatus=1\nSession 7:\n  mAppPackageName=org.amnezia.vpn\n  mFinalStatus=1\n";value["package_installer"]["session_evidence"]["after"]=[session_row(duplicate)]
    with pytest.raises(NestedCuttlefishError,match="ambiguous"):validate_app_update_receipt(plan(),boot(),value)
    value=app();foreign="Active Child Session 8:\n  appPackageName = other.package\nSession 7:\n  mAppPackageName=org.amnezia.vpn\n  mFinalStatus=1\n";value["package_installer"]["session_evidence"]["after"]=[session_row(foreign)]
    with pytest.raises(NestedCuttlefishError,match="foreign"):validate_app_update_receipt(plan(),boot(),value)
    for mutation in ("string-bool","extra-key","oversized"):
        value=app();row=value["ui"]["keyguard"][0]["receipt"]["before"]
        if mutation=="string-bool":row["showing"]="true"
        elif mutation=="extra-key":row["secure"]=False
        else:
            data=("showing=true\ninputRestricted=true\n"+("x"*6145)).encode()
            row["raw"]={"origin":"guest","transport":"qga-adb","path":"adb:keyguard-policy","size":len(data),"sha256":hashlib.sha256(data).hexdigest(),"bytes_b64":base64.b64encode(data).decode()}
        with pytest.raises(NestedCuttlefishError,match="keyguard"):validate_app_update_receipt(plan(),boot(),value)
    value=app();value["ui"]["focus_observations"][-1]["matches"].append({"package":"com.android.launcher3","component":".Launcher","pid":201,"uid":10101,"format":"key-value","state":"RESUMED","finishing":False,"visible":True,"drawn":True,"starting_displayed":False})
    with pytest.raises(NestedCuttlefishError,match="activity-top"):validate_app_update_receipt(plan(),boot(),value)
    def replace_focus(row,text):
        data=text.encode();row["relevant_lines"]=text;row["size"]=len(data);row["sha256"]=hashlib.sha256(data).hexdigest();row["raw"].update(size=len(data),sha256=row["sha256"],bytes_b64=base64.b64encode(data).decode())
    value=app();row=value["ui"]["focus_observations"][-1];replace_focus(row,row["relevant_lines"].replace("startingData=null","startingData=SplashScreenStartingData{org.amnezia.vpn}\nstartingWindow=Window{Splash Screen org.amnezia.vpn}"))
    with pytest.raises(NestedCuttlefishError,match="activity-top semantic"):validate_app_update_receipt(plan(),boot(),value)
    value=app();row=value["ui"]["focus_observations"][-1];replace_focus(row,row["relevant_lines"]+"\nstartingWindow=Window{Splash Screen org.amnezia.vpn} startingDisplayed=false")
    with pytest.raises(NestedCuttlefishError,match="activity-top semantic"):validate_app_update_receipt(plan(),boot(),value)
    for state_line in ("state=RESUMED finishing=true","state=RESUMED","state=RESUMED finishing=false\nstate=RESUMED finishing=false"):
        value=app();row=value["ui"]["focus_observations"][-1];replace_focus(row,row["relevant_lines"].replace("state=RESUMED finishing=false",state_line))
        with pytest.raises(NestedCuttlefishError,match="activity-top semantic"):validate_app_update_receipt(plan(),boot(),value)
    for group,key,bad in (("package_installer","artifact_sha256","9"*64),("package_installer","method","adb install"),
      ("http","fixture_nonce",""),("ui","window_id",""),("logcat","crashes",["FATAL EXCEPTION"])):
        value=app(); value[group][key]=bad
        with pytest.raises(NestedCuttlefishError): validate_app_update_receipt(plan(),boot(),value)
    value=app();value["ui"]["package_state"]["uid"]=10124
    with pytest.raises(NestedCuttlefishError,match="package state"):validate_app_update_receipt(plan(),boot(),value)
    value=app();value["ui"]["package_state"]["uid_lookup"]["argv"][-1]="other.app"
    with pytest.raises(NestedCuttlefishError,match="package state"):validate_app_update_receipt(plan(),boot(),value)
    value=app();raw=value["ui"]["package_state"]["dumpsys"]["output"];data=b"versionCode=2187\nversionCode=999";raw.update(size=len(data),sha256=hashlib.sha256(data).hexdigest(),bytes_b64=base64.b64encode(data).decode())
    with pytest.raises(NestedCuttlefishError,match="version evidence"):validate_app_update_receipt(plan(),boot(),value)

def test_boot_accepts_persistent_qemu_and_adb_after_run_cvd_parent_exits():
    value=boot();cvd=value["roles"]["cvd"];value["roles"]["cvd"]=None
    value["processes"]=[x for x in value["processes"] if x["pid"]!=cvd]
    value["containment"]["member_pids"].remove(cvd)
    assert validate_boot_receipt(plan(),value)["roles"]=={"cvd":None,"adb":202,"qemu":203}
    for missing in ("adb","qemu"):
        bad=json.loads(json.dumps(value));pid=bad["roles"][missing];bad["roles"][missing]=None
        bad["processes"]=[x for x in bad["processes"] if x["pid"]!=pid];bad["containment"]["member_pids"].remove(pid)
        with pytest.raises(NestedCuttlefishError):validate_boot_receipt(plan(),bad)

def test_cleanup_rechecks_exact_identity_before_term_and_kill():
    script=build_cleanup_script(plan(),boot())
    assert "check(item); os.kill(item['pid'],signal.SIGTERM)" in script
    assert "check(item); os.kill(item['pid'],signal.SIGKILL)" in script
    assert "actual!=known" in script and "cgroup.procs" in script
    assert "os.fwalk('.',topdown=True,follow_symlinks=False,dir_fd=root_fd)" in script
    assert "stat.S_ISSOCK" in script and "os.O_NOFOLLOW" in script and "os.unlink(name,dir_fd=pfd)" in script
    assert script.index("owned socket identity changed") < script.index("os.unlink('marker',dir_fd=root_fd)")
    assert script.index("owned root identity changed before cleanup") < script.index("os.kill(item['pid'],signal.SIGTERM)")

def test_cleanup_receipt_requires_every_typed_stopped_identity_no_survivors():
    expected=sorted(x["pid"] for x in boot()["processes"]);receipt=base("nested-cuttlefish-cleanup"); receipt.update({"terminated_pids":expected,
      "stopped_identities":[{"pid":x,"stopped":True} for x in expected],"unknown_survivors":[],
      "owned_sockets_remaining":[],"all_stopped":True,"marker_removed":True})
    assert validate_cleanup_receipt(plan(),receipt,boot())["passed"]
    receipt["terminated_pids"]=[201,202,203,True]
    with pytest.raises(NestedCuttlefishError): validate_cleanup_receipt(plan(),receipt,boot())

@pytest.mark.parametrize("field",["dev","inode"])
def test_boot_rejects_zero_guest_root_identity(field):
    value=boot();value["runtime_dependency"]["stage"]["guest_root_identity"][field]=0
    with pytest.raises(NestedCuttlefishError):validate_boot_receipt(plan(),value)

def test_failed_launch_accepts_only_exact_hash_bound_dash_launcher_wrapper():
    from deploy.release_lab.nested_cuttlefish_runner import NOBLE_DASH_SHA256,_proc
    p=plan();cg=f"/amnezia-release-lab/{p.ownership.run_id}/{p.ownership.attempt_nonce}"
    assert p.trusted_shell_sha256==NOBLE_DASH_SHA256=="86d31f6fb799e91fa21bad341484564510ca287703a16e9e46c53338776f4f42"
    item={"pid":777,"start_ticks":888,"exe":"/usr/bin/dash","exe_sha256":p.trusted_shell_sha256,
          "uid":p.runtime_uid,"groups":[993,4242],"state":"S","argv":["/bin/sh",f"{p.root}/runtime/start-cvd.sh"],
          "cmdline_sha256":"a"*64,"cgroup":cg}
    assert _proc(p,"aux",item,cg,4242,993)==777
    for key,value in (("exe_sha256","0"*64),("argv",["/bin/sh","/tmp/foreign.sh"]),("exe","/usr/bin/python3")):
        bad=dict(item);bad[key]=value
        with pytest.raises(NestedCuttlefishError):_proc(p,"aux",bad,cg,4242,993)

def test_receipts_reject_host_injection_wrong_outer_and_unowned_socket():
    value=boot(); value["injected"]=True
    with pytest.raises(NestedCuttlefishError): validate_boot_receipt(plan(),value)
    value=boot(); value["outer_ownership"]={**value["outer_ownership"],"pid":999}
    with pytest.raises(NestedCuttlefishError): validate_boot_receipt(plan(),value)
    p=plan(); owner=OuterOwnership(p.ownership.run_id,p.ownership.profile,p.ownership.attempt_nonce,123,456,p.ownership.uuid,"/tmp/qmp","/tmp/qga")
    with pytest.raises(NestedCuttlefishError): InnerPlan(owner,p.assets,p.apk,37,999,launch_argv=p.launch_argv).validate()

def test_boot_rejects_missing_or_forged_vulkan_dependency():
    p=plan(); good=boot()
    for mutate in (
        lambda r:r.pop("runtime_dependency"),
            lambda r:r["runtime_dependency"]["installed"]["loader"].update(sha256="0"*64),
            lambda r:r["runtime_dependency"]["installed"]["graphics_detector"]["output_file"].update(size=True),
            lambda r:r["runtime_dependency"]["installed"]["graphics_detector"]["output_file"].update(size=1048577),
            lambda r:r["runtime_dependency"]["installed"]["graphics_detector"]["output_file"].update(kind="symlink"),
            lambda r:r["runtime_dependency"]["installed"]["graphics_detector"].update(assertion=True),
    ):
        candidate=json.loads(json.dumps(good));mutate(candidate)
        with pytest.raises(NestedCuttlefishError,match="Vulkan|Wayland"):
            validate_boot_receipt(p,candidate)

def test_boot_rejects_minimal_or_environment_drifted_wayland_proof():
    p=plan();good=boot()
    mutations=(
        lambda r:r["runtime_dependency"].update(wayland_install={"operation":"nested-wayland-install","run_id":p.ownership.run_id,"attempt_nonce":p.ownership.attempt_nonce}),
        lambda r:r["runtime_dependency"]["wayland_runtime"].update(outer={**vars(p.ownership),"pid":999}),
        lambda r:r["runtime_dependency"]["wayland_runtime"].update(ld_library_path="/tmp/foreign"),
        lambda r:r["runtime_dependency"]["wayland_runtime"]["ldd"].update(missing=["late.so => not found"]),
    )
    for mutate in mutations:
        candidate=json.loads(json.dumps(good));mutate(candidate)
        with pytest.raises(NestedCuttlefishError,match="Wayland"):
            validate_boot_receipt(p,candidate)
