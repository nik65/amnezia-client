from __future__ import annotations
import base64, hashlib, io, json, subprocess, sys, tarfile, zipfile
from dataclasses import asdict
import pytest

from deploy.release_lab.nested_cuttlefish_qga_bridge import (BOOT_PROBE,FAILED_LAUNCH_CLEANUP,GROUP_PREFLIGHT,GROUP_PROVISION,PRELAUNCH_CLEANUP,RUNTIME_OWNERSHIP,SAFE_EXTRACT,STAGE_PREP,STAGE_VERIFY,VULKAN_INSTALL,
    NestedCuttlefishQgaBridge,NestedCuttlefishTransportError)
from deploy.release_lab.nested_cuttlefish_runner import (ApkSpec,AssetSpec,InnerPlan,OuterOwnership,transcript_sha256)
from deploy.release_lab.test_nested_cuttlefish_runner import wayland_dependency

def make_plan()->InnerPlan:
    owner=OuterOwnership("bridge-1","linux-headless-x64","nonce-1",123,456,"11111111-1111-1111-1111-111111111111",
      "/var/lib/amnezia-release-lab/runs/bridge-1/qmp.sock","/var/lib/amnezia-release-lab/runs/bridge-1/qga.sock")
    root="/var/lib/amnezia-release-lab/n/"+hashlib.sha256(b"bridge-1\0nonce-1").hexdigest()[:8]
    argv=(f"{root}/runtime/host/bin/launch_cvd",f"-instance_dir={root}/runtime/instance",f"-assembly_dir={root}/runtime/assembly",
      f"-system_image_dir={root}/runtime/images",f"-early_tmp_dir={root}/runtime/tmp","-vm_manager=qemu_cli",
      "-device_external_network=slirp","-enable_tap_devices=false","-enable_modem_simulator=false",
      "-start_gnss_proxy=false","-enable_host_bluetooth=false","-enable_host_nfc=false","-enable_host_uwb=false",
      "-start_webrtc=false","-report_anonymous_usage_stats=n",
      "-gpu_mode=guest_swiftshader","-adb_mode=vsock_half_tunnel","-run_adb_connector=true","-cpus=2","-memory_mb=4096","-vsock_guest_cid=37",f"-qemu_binary_dir={root}/runtime/qemu","-noresume")
    payloads={"/host":b"host-package","/image":b"arm-image","/qemu":b"qemu-bundle","/apk":b"candidate-apk"}
    return InnerPlan(owner,(AssetSpec("host.tar.gz","/host",len(payloads["/host"]),hashlib.sha256(payloads["/host"]).hexdigest()),
      AssetSpec("arm64.zip","/image",len(payloads["/image"]),hashlib.sha256(payloads["/image"]).hexdigest()),
      AssetSpec("qemu.tar.gz","/qemu",len(payloads["/qemu"]),hashlib.sha256(payloads["/qemu"]).hexdigest())),
      ApkSpec("candidate.apk","/apk",len(payloads["/apk"]),hashlib.sha256(payloads["/apk"]).hexdigest(),"org.amnezia.vpn",2187),37,999,launch_argv=argv,qemu_aarch64_sha256="e"*64)

PAYLOADS={"/host":b"host-package","/image":b"arm-image","/qemu":b"qemu-bundle","/apk":b"candidate-apk"}

def boot_receipt(plan:InnerPlan)->dict:
    cgroup=f"/amnezia-release-lab/{plan.ownership.run_id}/{plan.ownership.attempt_nonce}"
    def proc(name,pid):
      exe=f"{plan.root}/runtime/{'qemu' if name=='qemu-system-aarch64' else 'host/bin'}/{name}"; argv=[exe,plan.root]
      if name=="adb": argv += ["-P","5053"]
      if name=="qemu-system-aarch64": argv += ["guest-cid=37"]
      if name=="adb_connector": argv=[exe,"--addresses=0.0.0.0:6520"]
      if name=="socket_vsock_proxy": argv=[exe,"--server_type=tcp","--server_tcp_port=6520","--client_type=vsock","--client_vsock_port=5555","--client_vsock_id=37","--label=adb"]
      return {"pid":pid,"start_ticks":1000+pid,"exe":exe,"exe_sha256":hashlib.sha256(name.encode()).hexdigest(),"uid":999,
        "groups":([4242] if name=="adb" else [993,4242]),"state":"S","argv":argv,"cmdline_sha256":hashlib.sha256("\0".join(argv).encode()).hexdigest(),"cgroup":cgroup}
    processes=[proc("run_cvd",201),proc("adb",202),proc("qemu-system-aarch64",203),proc("adb_connector",204),proc("socket_vsock_proxy",205)]
    provision={"schema":1,"uid":plan.runtime_uid,"user":"lab","primary_gid":999,"cvdnetwork_gid":4242,"created":True,"member":True,"resolved_groups":[999,4242],"files":[{"path":x,"before_sha256":"3"*64,"after_sha256":"4"*64} for x in ("/etc/group","/etc/gshadow")],"commands":[{"argv":a,"exe_sha256":"5"*64,"exit_code":0,"stdout_size":0,"stderr_size":0} for a in (["/usr/sbin/groupadd","--system","cvdnetwork"],["/usr/sbin/usermod","-aG","cvdnetwork","lab"])],"kvm_modified":False,"vhost_modified":False,"origin":"guest","transport":"qga","injected":False}
    way_i,way_r=wayland_dependency(plan,1000);dependency={"wayland_install":way_i,"wayland_runtime":way_r,"group_provisioning":provision,"stage":{"sha256":plan.vulkan_deb_sha256,"size":plan.vulkan_deb_size,"guest_root_identity":{"dev":1,"inode":2,"uid":0,"gid":0,"mode":"0711"}},"installed":{"run_id":plan.ownership.run_id,"attempt_nonce":plan.ownership.attempt_nonce,"origin":"guest","transport":"qga","injected":False,"loader":{"path":f"{plan.root}/runtime/private-libs/libvulkan.so.1.3.275","soname_path":f"{plan.root}/runtime/private-libs/libvulkan.so.1","sha256":plan.vulkan_loader_sha256,"size":plan.vulkan_loader_size,"uid":0,"mode":"0644","directory_uid":0,"directory_mode":"0755"},"dlopen":True,"vkGetInstanceProcAddr":True,"graphics_detector":{"exit_code":0,"assertion":False,"uid":plan.runtime_uid,"groups":[4242],"stdout_sha256":"0"*64,"stdout_size":0,"stderr_sha256":"1"*64,"stderr_size":0,"output_file":{"path":f"{plan.root}/runtime/graphics-probe/availability.pbtxt","kind":"regular","dev":1,"inode":2,"uid":plan.runtime_uid,"gid":1000,"mode":"0600","sha256":"2"*64,"size":26091,"eof":True}}}}
    result={"schema":2,"operation":"nested-cuttlefish-boot","run_id":plan.ownership.run_id,"profile":plan.ownership.profile,
      "attempt_nonce":plan.ownership.attempt_nonce,"marker":plan.marker,"guest_root":plan.root,"outer_ownership":asdict(plan.ownership),
      "origin":"guest","transport":"qga","injected":False,"passed":True,"containment":{"kind":"cgroup-v2","path":cgroup,
      "member_pids":[201,202,203,204,205],"stable_reads":2},"processes":processes,"roles":{"cvd":201,"adb":202,"qemu":203},
      "boot":{"abi":"arm64-v8a","boot_completed":"1","serial":"127.0.0.1_6520","boot_id":"22222222-2222-2222-2222-222222222222"},
      "vsock_cid":37,"adb_endpoint":"127.0.0.1:5053","cvdnetwork_gid":4242,"kvm_gid":993,"vhost_vsock":{"path":"/dev/vhost-vsock","dev":7,"inode":8,"uid":0,"gid":993,"mode":"0660","rdev":9,"char":True},"vhost_access":{"exit_code":0,"result":{"egid":999,"euid":999,"groups":[993,4242],"read":True,"write":True}},"runtime_dependency":dependency,"network":{"adb_listen":"127.0.0.1:5053","host_mutation":False,"host_mounts":[],"qemu_netdev_argv":["user,id=hostnet0,net=10.0.2.15/24,host=10.0.2.2,dns=127.0.0.1"],"ril_config":{"schema":1,"records":[{"path":path,"before_sha256":"2"*64,"after_sha256":"3"*64,"size":100,"alias_target":path,"ril_ipaddr":"10.0.2.15","ril_gateway":"10.0.2.2","ril_prefixlen":24,"ril_dns":"10.0.2.3"} for path in (f"{plan.root}/runtime/assembly/cuttlefish_config.json",f"{plan.root}/runtime/instance/assembly/cuttlefish_config.json",f"{plan.root}/runtime/instance/instances/cvd-1/cuttlefish_config.json")]}}}
    paths=[x["path"] for x in result["network"]["ril_config"]["records"]];adb=f"{plan.root}/runtime/host/bin/adb";empty="List of devices attached\n";connected="List of devices attached\n127.0.0.1:6520\tdevice\n"
    def cmd(argv,out): return {"argv":argv,"exit_code":0,"stdout":out,"stdout_size":len(out),"stdout_sha256":hashlib.sha256(out.encode()).hexdigest(),"stderr":"","stderr_size":0,"stderr_sha256":hashlib.sha256(b"").hexdigest()}
    result["network"]["adb_connection"]={"endpoint":"127.0.0.1:6520","before":cmd([adb,"-P","5053","devices"],empty),"connect":cmd([adb,"-P","5053","connect","127.0.0.1:6520"],"connected"),"after":cmd([adb,"-P","5053","devices"],connected),"binding":{"endpoint":"127.0.0.1:6520","config_rows":[{"path":x,"sha256":"3"*64,"size":100,"adb_host_port":6520,"adb_ip_and_port":"0.0.0.0:6520"} for x in paths],"connector_pid":204,"proxy_pid":205,"connector_argv":processes[3]["argv"],"proxy_argv":processes[4]["argv"]}}
    return result

def ancestry(plan:InnerPlan)->dict:
    paths=["/var/lib/amnezia-release-lab","/var/lib/amnezia-release-lab/n"]
    rows=[]
    for i,path in enumerate(paths):
      before={"path":path,"dev":10+i,"inode":20+i,"uid":0,"gid":0,"mode":"0700" if i==0 else "0755"};rows.append({"before":before,"after":{**before,"mode":"0711"}})
    return {"ancestry":rows,"attempt":{"dev":1,"inode":2,"uid":0,"gid":0,"mode":"0700"},"runtime_probe":{"euid":plan.runtime_uid,"egid":999,"groups":[],"paths":[{"path":p,"execute":True} for p in paths]}}

class FakeChannel:
    def __init__(self,owner,max_write,short=False): self.owner=owner; self.max=max_write; self.short=short; self.handle=9
    def __enter__(self): self.owner.sessions+=1; return self
    def __exit__(self,*_): pass
    def request(self,name,args):
      self.owner.checks+=1; self.owner.calls.append(name)
      if name=="guest-file-open": self.owner.files[args["path"]]=bytearray(); self.owner.current=args["path"]; return {"return":self.handle}
      if name=="guest-file-write":
        data=base64.b64decode(args["buf-b64"])
        if len(data)>self.max: raise NestedCuttlefishTransportError("frame too large")
        self.owner.files[self.owner.current].extend(data); count=len(data)-1 if self.short else len(data)
        return {"return":{"count":count}}
      return {"return":{}}

class FakeQga:
    socket_path="/unused"
    def __init__(self,plan,max_write=64*1024,short=False):
      self.plan=plan; self.max_write=max_write; self.short=short; self.sessions=0; self.checks=0; self.calls=[]; self.codes=[]; self.files={}; self.current=""; self.boot_calls=0
    def channel(self,check): return FakeChannel(self,self.max_write,self.short)
    def request(self,*_): raise AssertionError("payload chunks must not use reconnecting QgaClient.request")
    def guest_exec(self,path,args): self.calls.append("guest-exec"); return {"pid":77}
    def guest_exec_wait(self,path,args,timeout):
      self.calls.append("guest-exec-wait"); code=args[1] if len(args)>1 and args[0]=="-c" else ""
      self.codes.append(code)
      if code==GROUP_PROVISION: return {"stdout":json.dumps(boot_receipt(self.plan)["runtime_dependency"]["group_provisioning"])}
      if code==STAGE_PREP: return {"stdout":json.dumps(ancestry(self.plan))}
      if "p.read_bytes" in code and ".qga-frame-probe" in args[-1]:
        data=bytes(self.files[args[-1]]); self.files.pop(args[-1],None)
        return {"stdout":json.dumps({"size":len(data),"sha256":hashlib.sha256(data).hexdigest()})}
      if "p.read_bytes" in code:
        data=bytes(self.files[args[-1]]); return {"stdout":json.dumps({"size":len(data),"sha256":hashlib.sha256(data).hexdigest()})}
      if "removed" in code: self.files.pop(args[-1],None); return {"stdout":json.dumps({"removed":True})}
      if code==SAFE_EXTRACT: return {"stdout":json.dumps({"safe":True,"host":{"files":3,"tree_sha256":"a"*64},"images":{"files":4,"tree_sha256":"b"*64},"qemu":{"files":8,"tree_sha256":"d"*64},"qemu_aarch64_sha256":"e"*64})}
      if code==RUNTIME_OWNERSHIP: return {"stdout":json.dumps({"schema":1,"root":self.plan.root,"directories":[{"path":f"{self.plan.root}/runtime","created":False,"dev":1,"inode":5,"uid":0,"gid":0,"mode":"0700"},{"path":f"{self.plan.root}/logs","created":True,"dev":1,"inode":6,"uid":0,"gid":0,"mode":"0700"}]+[{"path":f"{self.plan.root}/runtime/{name}","created":True,"dev":1,"inode":7+i,"uid":0,"gid":0,"mode":"0700"} for i,name in enumerate(("home","tmp","instance","assembly"))],"runtime_uid":self.plan.runtime_uid,"primary_gid":1000,"root_before":{"path":self.plan.root,"dev":1,"inode":2,"uid":0,"gid":0,"mode":"0700"},"root_after":{"path":self.plan.root,"dev":1,"inode":2,"uid":0,"gid":0,"mode":"0711"},"qemu_before":{"path":f"{self.plan.root}/runtime/qemu/qemu-system-aarch64","dev":3,"inode":4,"uid":0,"gid":0,"mode":"0755"},"qemu_after":{"path":f"{self.plan.root}/runtime/qemu/qemu-system-aarch64","dev":3,"inode":4,"uid":self.plan.runtime_uid,"gid":1000,"mode":"0755"},"qemu_sha256":self.plan.qemu_aarch64_sha256,"access_exit_code":0,"access":{"read":True,"execute":True},"write_probe_exit_code":0,"write_probes":[{"path":f"{self.plan.root}/runtime/{name}","write_delete":True} for name in ("home","tmp","instance","assembly")]+[{"path":f"{self.plan.root}/logs","write_delete":True}],"origin":"guest","transport":"qga","injected":False})}
      if code==STAGE_VERIFY:
        p=json.loads(args[2]); transcripts=json.loads(args[3]); extraction=json.loads(args[4]); records=[]
        for spec in p["assets"]:
          tr=transcripts[spec["name"]]; records.append({**spec,"received_size":spec["size"],"guest_sha256":spec["sha256"],"eof":True,
            "transfer":tr})
        receipt={"schema":2,"operation":"nested-cuttlefish-stage","run_id":p["run_id"],"profile":p["profile"],"attempt_nonce":p["attempt_nonce"],
          "marker":p["marker"],"guest_root":p["guest_root"],"outer_ownership":p["outer_ownership"],"origin":"guest","transport":"qga",
          "injected":False,"guest_root_identity":{"dev":1,"inode":2,"uid":0,"gid":0,"mode":"0711"},"guest_ancestry":p["guest_ancestry"],"runtime_ownership":p["runtime_ownership"],"assets":records,"extraction":extraction,"negotiated_chunk_size":p["negotiated_chunk_size"],"passed":True}
        return {"stdout":json.dumps(receipt)}
      if "written" in code: return {"stdout":json.dumps({"written":True})}
      if code==GROUP_PREFLIGHT: return {"stdout":json.dumps({"ready":True,"uid":999,"user":"lab","primary_gid":999,"cvdnetwork_gid":4242,"kvm_gid":993,"resolved_groups":[999,4242],"preserved_supplementary_groups":[993,4242],"kvm_membership_modified":False,"vhost_device_modified":False,"vhost_vsock":{"path":"/dev/vhost-vsock","dev":7,"inode":8,"uid":0,"gid":993,"mode":"0660","rdev":9,"char":True},"vhost_access":{"exit_code":0,"result":{"egid":999,"euid":999,"groups":[993,4242],"read":True,"write":True}}})}
      if code==VULKAN_INSTALL: return {"stdout":json.dumps(boot_receipt(self.plan)["runtime_dependency"]["installed"])}
      if code==PRELAUNCH_CLEANUP: return {"stdout":json.dumps({"removed":True})}
      if code==BOOT_PROBE:
        self.boot_calls+=1
        if self.boot_calls==1: return {"stdout":json.dumps({"ready":False})}
        return {"stdout":json.dumps(boot_receipt(self.plan))}
      raise AssertionError("unexpected guest command")

def bridge(fake:FakeQga,snap=None,clock=lambda:0):
    return NestedCuttlefishQgaBridge(fake,fake.plan,snap or (lambda:fake.plan.ownership),clock=clock,sleeper=lambda _:None,channel_factory=fake.channel)

def opener(path): return io.BytesIO(PAYLOADS[path])

def test_stage_negotiates_persistent_frame_once_per_file_and_returns_guest_receipt():
    plan=make_plan(); fake=FakeQga(plan,max_write=64*1024); receipt=bridge(fake).stage(opener)
    assert receipt["negotiated_chunk_size"]==64*1024
    assert fake.sessions==6  # failed 256K probe, 64K probe, and four payload files
    assert fake.calls.count("guest-file-open")==6 and fake.checks>=fake.calls.count("guest-file-write")
    assert all(bytes(fake.files[f"{plan.root}/input/{x.name}"])==PAYLOADS[x.source_path] for x in [*plan.assets,plan.apk])

def test_short_write_is_fail_closed_and_never_becomes_stage_receipt():
    plan=make_plan(); fake=FakeQga(plan,short=True)
    with pytest.raises(NestedCuttlefishTransportError): bridge(fake).stage(opener)

def test_stage_transfer_failure_archives_before_exact_attempt_cleanup():
    plan=make_plan();fake=FakeQga(plan,short=True);events=[];original=fake.guest_exec_wait
    def wait(path,args,timeout):
      if len(args)>1 and args[1]==PRELAUNCH_CLEANUP:events.append("cleanup")
      return original(path,args,timeout)
    fake.guest_exec_wait=wait
    def archive(record):
      assert events==[] and record["phase"]=="stage-transfer";events.append("archive")
      return {"origin":"controller","immutable":True}
    b=NestedCuttlefishQgaBridge(fake,plan,lambda:plan.ownership,channel_factory=fake.channel,boot_failure_archive=archive)
    with pytest.raises(NestedCuttlefishTransportError):b.stage(opener)
    assert events==["archive","cleanup"] and PRELAUNCH_CLEANUP in fake.codes

def test_stage_failure_replacement_refuses_cleanup_after_archive():
    plan=make_plan();fake=FakeQga(plan,short=True);events=[];original=fake.guest_exec_wait
    def wait(path,args,timeout):
      if len(args)>1 and args[1]==PRELAUNCH_CLEANUP:
        events.append("cleanup-refused");raise NestedCuttlefishTransportError("prelaunch root identity changed")
      return original(path,args,timeout)
    fake.guest_exec_wait=wait
    def archive(_):events.append("archive");return {"origin":"controller","immutable":True}
    b=NestedCuttlefishQgaBridge(fake,plan,lambda:plan.ownership,channel_factory=fake.channel,boot_failure_archive=archive)
    with pytest.raises(NestedCuttlefishTransportError) as caught:b.stage(opener)
    assert events==["archive","cleanup-refused"]
    assert any("identity changed" in note for note in getattr(caught.value,"__notes__",[]))

@pytest.mark.parametrize("archive",[
  lambda _:{"origin":"controller","immutable":False},
  lambda _:(_ for _ in ()).throw(OSError("archive unavailable")),
])
def test_stage_failure_without_durable_archive_retains_pending_root(archive):
    plan=make_plan();fake=FakeQga(plan,short=True)
    b=NestedCuttlefishQgaBridge(fake,plan,lambda:plan.ownership,channel_factory=fake.channel,boot_failure_archive=archive)
    with pytest.raises(NestedCuttlefishTransportError) as caught:b.stage(opener)
    assert PRELAUNCH_CLEANUP not in fake.codes
    notes=getattr(caught.value,"__notes__",[])
    assert any("archive" in note for note in notes) and any("pending cleanup retained" in note for note in notes)

def test_outer_ownership_is_revalidated_before_transport():
    plan=make_plan(); fake=FakeQga(plan); calls=0
    def changed():
      nonlocal calls; calls+=1
      return plan.ownership if calls<3 else OuterOwnership(plan.ownership.run_id,plan.ownership.profile,plan.ownership.attempt_nonce,999,456,plan.ownership.uuid,plan.ownership.qmp_socket,plan.ownership.qga_socket)
    with pytest.raises(NestedCuttlefishTransportError,match="ownership changed"): bridge(fake,changed).stage(opener)

def test_launch_boot_polls_guest_evidence_to_two_stable_reads_and_returns_boot_only():
    plan=make_plan(); fake=FakeQga(plan); b=bridge(fake); stage=b.stage(opener); result=b.launch_boot(stage)
    assert result["operation"]=="nested-cuttlefish-boot" and "package_installer" not in result
    assert fake.boot_calls==3 and fake.calls.count("guest-exec")==1

def test_safe_extractor_contract_rejects_archive_escape_and_special_members():
    for required in ("name in seen","unsafe tar member","item.isdev()","item.isfifo()","item.flag_bits&1","stat.S_ISLNK","expansion bound"):
      assert required in SAFE_EXTRACT
    assert "host_mount" not in SAFE_EXTRACT and "mount " not in SAFE_EXTRACT

def test_runtime_ownership_is_bound_before_any_mutation():
    assert "if observed!=root_expected" in RUNTIME_OWNERSHIP
    assert "mb.decode()!=marker" in RUNTIME_OWNERSHIP
    assert "os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)" in RUNTIME_OWNERSHIP
    assert RUNTIME_OWNERSHIP.index("if observed!=root_expected") < RUNTIME_OWNERSHIP.index("os.fchmod(fd,0o711)")
    assert RUNTIME_OWNERSHIP.index("O_NOFOLLOW,dir_fd=fd") < RUNTIME_OWNERSHIP.index("os.fchmod(fd,0o711)")

def test_runtime_ownership_real_fresh_extract_layout_creates_logs():
    wrapper='''import base64,hashlib,json,os,pathlib,sys,tempfile
r=pathlib.Path(tempfile.mkdtemp(prefix="rt-own-"));r.chmod(0o700);(r/"marker").write_text("marker");q=r/"runtime/qemu/qemu-system-aarch64";q.parent.mkdir(parents=True,mode=0o700);q.write_bytes(b"#!/bin/sh\\nexit 0\\n");q.chmod(0o755);s=r.stat();expected={"dev":s.st_dev,"inode":s.st_ino,"uid":s.st_uid,"gid":s.st_gid,"mode":"0700"};code=base64.b64decode(sys.argv[1]).decode();sys.argv=["own",str(r),"1000",hashlib.sha256(q.read_bytes()).hexdigest(),json.dumps(expected),"marker"] ;exec(code)
'''
    result=subprocess.run(["wsl.exe","-u","root","python3","-c",wrapper,base64.b64encode(RUNTIME_OWNERSHIP.encode()).decode()],capture_output=True,text=True)
    if result.returncode==127:pytest.skip("WSL unavailable")
    assert result.returncode==0,result.stderr
    value=json.loads(result.stdout);assert value["directories"][0]["created"] is False and all(x["created"] is True for x in value["directories"][1:])
    assert [x["path"].rsplit("/",1)[-1] for x in value["directories"]]==["runtime","logs","home","tmp","instance","assembly"]
    assert value["root_after"]["mode"]=="0711" and value["access"]=={"read":True,"execute":True}
    assert value["write_probe_exit_code"]==0 and all(x["write_delete"] is True for x in value["write_probes"])

def test_safe_extractor_accepts_only_internal_symlink_to_regular_member(tmp_path):
    root=tmp_path/"nested"; inputs=root/"input"; inputs.mkdir(parents=True)
    host=inputs/"host.tar.gz"
    with tarfile.open(host,"w:gz") as tf:
      for name,data in (("bin/cvd_internal_start",b"start"),("bin/cvd_internal_stop",b"stop"),("bin/adb",b"adb")):
        info=tarfile.TarInfo(name); info.size=len(data); tf.addfile(info,io.BytesIO(data))
      for name,target in (("bin/launch_cvd","cvd_internal_start"),("bin/stop_cvd","cvd_internal_stop")):
        info=tarfile.TarInfo(name); info.type=tarfile.SYMTYPE; info.linkname=target; tf.addfile(info)
    images=inputs/"images.zip"
    with zipfile.ZipFile(images,"w") as zf:
      for name in ("boot.img","super.img","vendor_boot.img","vbmeta.img"): zf.writestr(name,b"image")
    qemu=inputs/"qemu.tar.gz"
    with tarfile.open(qemu,"w:gz") as tf:
      data=b"qemu"; info=tarfile.TarInfo("qemu-system-aarch64"); info.size=len(data); info.mode=0o755; tf.addfile(info,io.BytesIO(data))
    result=subprocess.run([sys.executable,"-c",SAFE_EXTRACT,str(root),host.name,images.name,qemu.name],text=True,capture_output=True)
    assert result.returncode==0, result.stderr
    receipt=json.loads(result.stdout)
    assert receipt["safe"] is True and (root/"runtime/host/bin/launch_cvd").resolve().name=="cvd_internal_start"

    bad_root=tmp_path/"bad"; (bad_root/"input").mkdir(parents=True)
    with tarfile.open(bad_root/"input/host.tar.gz","w:gz") as tf:
      info=tarfile.TarInfo("bin/launch_cvd"); info.type=tarfile.SYMTYPE; info.linkname="../../escape"; tf.addfile(info)
    with zipfile.ZipFile(bad_root/"input/images.zip","w") as zf: zf.writestr("boot.img",b"x")
    with tarfile.open(bad_root/"input/qemu.tar.gz","w:gz") as tf:
      data=b"qemu"; info=tarfile.TarInfo("qemu-system-aarch64"); info.size=len(data); tf.addfile(info,io.BytesIO(data))
    bad=subprocess.run([sys.executable,"-c",SAFE_EXTRACT,str(bad_root),"host.tar.gz","images.zip","qemu.tar.gz"],text=True,capture_output=True)
    assert bad.returncode!=0 and "unsafe" in bad.stderr

def test_two_gib_transfer_receipt_is_compact_and_bounded():
    summary={"chunk_count":(2*1024*1024*1024)//(64*1024),"received_size":2*1024*1024*1024,
             "eof":True,"transcript_sha256":"a"*64}
    encoded=json.dumps({"large.img":summary},separators=(",",":"))
    assert len(encoded)<512 and summary["chunk_count"]==32768

def test_compact_transfer_counts_chunks_not_last_write_bytes():
    plan=make_plan(); fake=FakeQga(plan,max_write=64*1024); b=bridge(fake)
    data=b"x"*(64*1024+7)
    summary,digest=b._persistent_write("/guest/multi",io.BytesIO(data),len(data),10,64*1024)
    assert summary["chunk_count"]==2 and summary["received_size"]==len(data)
    assert digest==hashlib.sha256(data).hexdigest()

def test_launch_uses_supported_loopback_listener_and_exact_qemu_dir():
    from deploy.release_lab.nested_cuttlefish_runner import build_launch_script
    script=build_launch_script(make_plan())
    assert "-L tcp:localhost:5053 server nodaemon" in script
    assert "ADB_SERVER_SOCKET=tcp:localhost:5053" in script
    assert "tcp:127.0.0.1:5053 server" not in script
    assert f"-qemu_binary_dir={make_plan().root}/runtime/qemu" in script
    assert '--groups "$cvd_gid,$kvm_gid"' in script and '--groups "$cvd_gid"' in script and "--clear-groups" not in script
    assert "vhost-vsock-identity" in script and "test -w /dev/vhost-vsock" in script
    assert "getent group cvdnetwork" in script
    assert 'str(os.getpid())' in script and 'os.execvp(a[0],a)' in script
    assert 'printf \'%s\\n\' "$$" >"$cgroup/cgroup.procs"' not in script
    assert '"$root/adb.pid"' in script

def test_boot_probe_keeps_cgroup_separate_from_supplementary_groups_and_failed_cleanup_rechecks_identity():
    assert "groupadd','--system','cvdnetwork" in GROUP_PROVISION
    assert "usermod','-aG','cvdnetwork'" in GROUP_PROVISION
    assert "cvdnetwork-preexists-in-fresh-overlay" in GROUP_PROVISION
    assert "unrelated-account-records-changed" in GROUP_PROVISION
    assert "'cgroup':cgroups[0] if len(cgroups)==1 else ''" in BOOT_PROBE
    assert "'cgroup':groups[0]" not in BOOT_PROBE
    assert "'processes':processes" in BOOT_PROBE and "'launcher_alive':launcher_alive" in BOOT_PROBE
    assert "Failed to parse netmask" in BOOT_PROBE and "qemu_disappeared" in BOOT_PROBE
    assert "assembly_stalled" in BOOT_PROBE and "post_assembly_stalled" in BOOT_PROBE
    assert "if roles['qemu'] is None or roles['adb'] is None:" in BOOT_PROBE
    assert BOOT_PROBE.index("if roles['qemu'] is None or roles['adb'] is None:") < BOOT_PROBE.index("sys.boot_completed")
    assert "runtime/ril-config-receipt.json" in BOOT_PROBE
    assert "stale legacy receipt path" in BOOT_PROBE
    for field in ("start_ticks","exe_sha256","cmdline_sha256","cgroup"):
      assert field in FAILED_LAUNCH_CLEANUP
    assert "actual!=known" in FAILED_LAUNCH_CLEANUP

def test_boot_probe_without_run_cvd_executes_adb_property_gate(tmp_path,capsys):
    import errno
    import ipaddress
    import pathlib
    import types
    import uuid
    root=tmp_path
    (root/"runtime").mkdir()
    config={"instances":{"1":{"adb_host_port":6520,"adb_ip_and_port":"0.0.0.0:6520"}},"fragments":{"AdbConfigFragmentImpl":{"connector_enabled":True,"mode":["vsock_half_tunnel"]}}}
    config_paths=[]
    for i in range(3):
      q=root/f"config-{i}.json";q.write_text(json.dumps(config));config_paths.append(q)
    ril={"records":[{"path":str(q),"ril_ipaddr":"10.0.2.15","ril_gateway":"10.0.2.2","ril_prefixlen":24,"ril_dns":"10.0.2.3"} for q in config_paths]}
    (root/"runtime/ril-config-receipt.json").write_text(json.dumps(ril))
    calls=[]
    def output(args):
      calls.append(args)
      if args[-1]=="devices": return "List of devices attached\n" if not any(x[-2:]==["connect","127.0.0.1:6520"] for x in calls[:-1]) else "List of devices attached\n127.0.0.1:6520\tdevice"
      if args[-2:]==["connect","127.0.0.1:6520"]: return "connected to 127.0.0.1:6520"
      if args[-2:]==["getprop","ro.product.cpu.abi"]: return "arm64-v8a"
      if args[-2:]==["getprop","sys.boot_completed"]: return "1"
      if args[-3:]==["shell","cat","/proc/sys/kernel/random/boot_id"]: return "11111111-2222-4333-8444-555555555555"
      raise AssertionError(args)
    def command(args):
      value=output(args)
      return {"argv":args,"exit_code":0,"stdout":value,"stdout_size":len(value),"stdout_sha256":hashlib.sha256(value.encode()).hexdigest(),"stderr":"","stderr_size":0,"stderr_sha256":hashlib.sha256(b"").hexdigest()}
    captured=[
      {"pid":202,"argv":[str(root/"runtime/host/bin/adb")],"exe":str(root/"runtime/host/bin/adb")},
      {"pid":203,"argv":[str(root/"runtime/qemu/qemu-system-aarch64"),"-netdev","user,id=hostnet0,net=10.0.2.15/24,host=10.0.2.2,dns=127.0.0.1","-netdev","user,id=hostnet1,net=10.0.1.1/24,dns=8.8.4.4"],"exe":str(root/"runtime/qemu/qemu-system-aarch64")},
      {"pid":204,"argv":[str(root/"runtime/host/bin/adb_connector"),"--addresses=0.0.0.0:6520"],"exe":str(root/"runtime/host/bin/adb_connector")},
      {"pid":205,"argv":[str(root/"runtime/host/bin/socket_vsock_proxy"),"--server_type=tcp","--server_tcp_port=6520","--client_type=vsock","--client_vsock_port=5555","--client_vsock_id=37","--label=adb"],"exe":str(root/"runtime/host/bin/socket_vsock_proxy")},
    ]
    payload={"run_id":"run","profile":"linux-headless","attempt_nonce":"n","marker":"m","guest_root":str(root),
      "outer_ownership":{},"cgroup":"/owned","stable_reads":2,"vsock_cid":37,"adb_endpoint":"127.0.0.1:5053",
      "cvdnetwork_gid":988,"kvm_gid":993,"vhost_vsock":{}}
    class Cgroup:
      def joinpath(self,*_): return self
      def read_text(self): return "202\n203\n204\n205\n"
    class Gone:
      def __truediv__(self,_): return self
      def exists(self): return False
    real_path=pathlib.Path
    paths=types.SimpleNamespace(Path=lambda first,*rest: Gone() if str(first)=="/proc" else real_path(first,*rest))
    def identify(pid):
      if pid==201: raise FileNotFoundError(errno.ENOENT,"vanished",str(pid))
      return next(x for x in captured if x["pid"]==pid)
    scope={"pids":[201,202,203,204,205],"ident":identify,"cg":Cgroup(),"pathlib":paths,"hashlib":hashlib,
      "errno":errno,"p":payload,"root":real_path(root),"command":command,"ipaddress":ipaddress,"uuid":uuid,"json":json}
    exec(BOOT_PROBE[BOOT_PROBE.index("processes=[]"):],scope)
    receipt=json.loads(capsys.readouterr().out)
    assert receipt["passed"] is True and receipt["roles"]=={"cvd":None,"adb":202,"qemu":203}
    assert receipt["network"]["adb_connection"]["endpoint"]=="127.0.0.1:6520"
    assert receipt["network"]["adb_connection"]["before"]["stdout"]=="List of devices attached\n"
    assert any(x[-2:]==["getprop","sys.boot_completed"] for x in calls)

def test_boot_probe_stable_unreadable_cgroup_member_is_explicit_fatal(capsys):
    import errno
    import pathlib
    import types
    class Cgroup:
      def joinpath(self,*_): return self
      def read_text(self): return "201\n"
    class Present:
      def __truediv__(self,_): return self
      def exists(self): return True
    paths=types.SimpleNamespace(Path=lambda first,*rest: Present() if str(first)=="/proc" else pathlib.Path(first,*rest))
    def unreadable(_): raise PermissionError(errno.EACCES,"denied")
    start=BOOT_PROBE.index("processes=[]"); end=BOOT_PROBE.index("def role(names):")
    with pytest.raises(SystemExit):
      exec(BOOT_PROBE[start:end],{"pids":[201],"ident":unreadable,"cg":Cgroup(),"pathlib":paths,"hashlib":hashlib,"errno":errno,"json":json,"p":{"cgroup":"/owned"}})
    row=json.loads(capsys.readouterr().out)
    assert row["fatal"] is True and row["reason"]=="process-identity-unreadable" and row["failed_pid"]==201

def test_boot_probe_command_timeout_is_structured_and_uses_three_seconds():
    import types
    seen=[]
    def hung(args,**kwargs):seen.append(kwargs["timeout"]);raise subprocess.TimeoutExpired(args,kwargs["timeout"],output=b"partial",stderr=b"late")
    fake=types.SimpleNamespace(run=hung,PIPE=subprocess.PIPE,TimeoutExpired=subprocess.TimeoutExpired)
    scope={"subprocess":fake,"hashlib":hashlib};start=BOOT_PROBE.index("def command(args):");end=BOOT_PROBE.index("def tail(name):")
    exec(BOOT_PROBE[start:end],scope);row=scope["command"](["adb","shell","getprop"])
    assert seen==[3] and row["exit_code"]==124 and row["stdout"]=="partial" and row["stderr"]=="late"

def test_boot_probe_rejects_proxy_config_mismatch_before_adb_connect(tmp_path,capsys):
    config={"instances":{"1":{"adb_host_port":6520,"adb_ip_and_port":"0.0.0.0:6520"}},"fragments":{"AdbConfigFragmentImpl":{"connector_enabled":True,"mode":["vsock_half_tunnel"]}}}
    paths=[]
    for i in range(3):q=tmp_path/f"c{i}.json";q.write_text(json.dumps(config));paths.append(str(q))
    ril={"records":[{"path":x} for x in paths]};root=tmp_path
    connector={"pid":4,"exe":str(tmp_path/"adb_connector"),"argv":[str(tmp_path/"adb_connector"),"--addresses=0.0.0.0:6520"]}
    proxy={"pid":5,"exe":str(tmp_path/"socket_vsock_proxy"),"argv":[str(tmp_path/"socket_vsock_proxy"),"--server_type=tcp","--server_tcp_port=6520","--client_type=vsock","--client_vsock_port=5555","--client_vsock_id=99","--label=adb"]}
    start=BOOT_PROBE.index("config_rows=[]");end=BOOT_PROBE.index("adb=str(root/'runtime/host/bin/adb')")
    with pytest.raises(SystemExit):
      exec(BOOT_PROBE[start:end],{"ril":ril,"root":root,"processes":[connector,proxy],"pathlib":__import__('pathlib'),"hashlib":hashlib,"json":json,"p":{"cgroup":"/owned","vsock_cid":37}})
    row=json.loads(capsys.readouterr().out)
    assert row["reason"]=="adb-vsock-proxy-binding-invalid" and row["fatal"] is True

def test_launch_boot_fails_fast_on_empty_owned_cgroup():
    plan=make_plan(); fake=FakeQga(plan)
    original=fake.guest_exec_wait
    def failing(path,args,timeout):
      if len(args)>1 and args[1]==BOOT_PROBE:
        payload=json.loads(args[2]); return {"stdout":json.dumps({"ready":False,"fatal":payload["poll_count"]>=2,"reason":"owned-cgroup-empty","process_count":0})}
      return original(path,args,timeout)
    fake.guest_exec_wait=failing
    with pytest.raises(NestedCuttlefishTransportError,match="owned-cgroup-empty"):
      bridge(fake).launch_boot(bridge(fake).stage(opener))

def test_network_binding_failure_archive_keeps_bounded_qemu_argv():
    plan=make_plan();fake=FakeQga(plan);original=fake.guest_exec_wait;archived=[]
    argv="user,id=hostnet0,net=10.0.2.15/24,host=10.0.2.2,dns=127.0.0.1"
    def mismatch(path,args,timeout):
      if len(args)>1 and args[1]==BOOT_PROBE:
        return {"stdout":json.dumps({"ready":False,"fatal":True,"reason":"qemu-config-binding-mismatch","phase":"qemu","network_argv":[argv],"processes":[]})}
      return original(path,args,timeout)
    fake.guest_exec_wait=mismatch
    b=NestedCuttlefishQgaBridge(fake,plan,lambda:plan.ownership,channel_factory=fake.channel,
      boot_failure_archive=lambda record:(archived.append(record) or {"origin":"controller","immutable":True,"path":"/owned/boot.json","sha256":"a"*64,"size":2}))
    with pytest.raises(NestedCuttlefishTransportError,match="qemu-config-binding-mismatch"):
      b.launch_boot(b.stage(opener))
    assert archived[0]["last_probe"]["network_argv"]==[argv]

def test_launch_boot_treats_live_assemble_as_progress_then_fails_if_seen_qemu_disappears():
    plan=make_plan();fake=FakeQga(plan);original=fake.guest_exec_wait;polls=[]
    def stateful(path,args,timeout):
      if len(args)>1 and args[1]==BOOT_PROBE:
        payload=json.loads(args[2]);polls.append(payload)
        if len(polls)==1:
          return {"stdout":json.dumps({"ready":False,"fatal":False,"reason":"required-role-missing","phase":"assemble","roles":{"assemble":1569,"cvd":None,"adb":1566,"qemu":None},"processes":[]})}
        if len(polls)==2:
          return {"stdout":json.dumps({"ready":False,"fatal":False,"reason":"required-role-missing","phase":"qemu","roles":{"assemble":None,"cvd":1570,"adb":1566,"qemu":1600},"processes":[]})}
        return {"stdout":json.dumps({"ready":False,"fatal":payload["qemu_seen"],"reason":"required-role-missing","phase":"run-cvd","roles":{"assemble":None,"cvd":1570,"adb":1566,"qemu":None},"qemu_disappeared":payload["qemu_seen"],"processes":[]})}
      return original(path,args,timeout)
    fake.guest_exec_wait=stateful
    with pytest.raises(NestedCuttlefishTransportError,match="qemu_disappeared"):
      bridge(fake).launch_boot(bridge(fake).stage(opener))
    assert polls[0]["qemu_seen"] is False and polls[0]["assembly_seen"] is False
    assert polls[1]["assembly_seen"] is True and polls[1]["assembly_missing_polls"]==0
    assert polls[2]["qemu_seen"] is True and polls[2]["assembly_missing_polls"]==0

def test_boot_probe_transport_error_archives_then_cleans_and_preserves_primary():
    plan=make_plan();fake=FakeQga(plan);original=fake.guest_exec_wait;events=[];calls=[0]
    def transport(path,args,timeout):
      if len(args)>1 and args[1]==BOOT_PROBE:
        calls[0]+=1
        if calls[0]==1:
          row=boot_receipt(plan);row.update(ready=False,fatal=False,reason="android-boot-properties-pending",phase="android-boot",qemu_seen=True,cgroup=row["containment"]["path"]);return {"stdout":json.dumps(row)}
        raise RuntimeError("qga-timeout-marker")
      if len(args)>1 and args[1]==FAILED_LAUNCH_CLEANUP:events.append("cleanup");return {"stdout":json.dumps({"terminated_pids":[],"all_stopped":True})}
      return original(path,args,timeout)
    fake.guest_exec_wait=transport
    def archive(record):
      assert record["reason"]=="boot-probe-transport-failed" and record["last_probe"]["probe_error"]["type"]=="RuntimeError"
      events.append("archive");return {"origin":"controller","immutable":True,"path":"/owned/boot.json","sha256":"a"*64,"size":2}
    b=NestedCuttlefishQgaBridge(fake,plan,lambda:plan.ownership,sleeper=lambda _:None,channel_factory=fake.channel,boot_failure_archive=archive)
    with pytest.raises(RuntimeError,match="qga-timeout-marker"):b.launch_boot(b.stage(opener))
    assert events==["archive","cleanup"]

@pytest.mark.parametrize("archive",[lambda _:(_ for _ in ()).throw(OSError("archive-down")),lambda _:{"origin":"controller","immutable":False}])
def test_boot_probe_transport_error_retains_state_without_durable_archive(archive):
    plan=make_plan();fake=FakeQga(plan);original=fake.guest_exec_wait;calls=[0];cleanup=[]
    def transport(path,args,timeout):
      if len(args)>1 and args[1]==BOOT_PROBE:
        calls[0]+=1
        if calls[0]==1:
          row=boot_receipt(plan);row.update(ready=False,fatal=False,reason="android-boot-properties-pending",phase="android-boot",qemu_seen=True,cgroup=row["containment"]["path"]);return {"stdout":json.dumps(row)}
        raise RuntimeError("qga-timeout-marker")
      if len(args)>1 and args[1]==FAILED_LAUNCH_CLEANUP:cleanup.append(True);return {"stdout":json.dumps({"all_stopped":True})}
      return original(path,args,timeout)
    fake.guest_exec_wait=transport;b=NestedCuttlefishQgaBridge(fake,plan,lambda:plan.ownership,sleeper=lambda _:None,channel_factory=fake.channel,boot_failure_archive=archive)
    with pytest.raises(RuntimeError,match="qga-timeout-marker") as caught:b.launch_boot(b.stage(opener))
    assert cleanup==[] and any("pending cleanup retained" in x for x in caught.value.__notes__)

def test_boot_timeout_archives_last_assembly_probe_before_exact_cleanup():
    from dataclasses import replace
    p=replace(make_plan(),boot_timeout_seconds=60);fake=FakeQga(p);stage=bridge(fake).stage(opener);events=[];now=[0.0]
    original=fake.guest_exec_wait;cgroup=f"/amnezia-release-lab/{p.ownership.run_id}/{p.ownership.attempt_nonce}"
    def waiting(path,args,timeout):
      if len(args)>1 and args[1]==BOOT_PROBE:
        return {"stdout":json.dumps({"ready":False,"fatal":False,"reason":"required-role-missing","phase":"assemble","roles":{"assemble":1569,"cvd":None,"adb":1566,"qemu":None},"processes":[],"cgroup":cgroup,"logs":{"launch_stderr":"assembling","adb_stderr":""}})}
      if len(args)>1 and args[1]==FAILED_LAUNCH_CLEANUP:events.append("cleanup");return {"stdout":json.dumps({"terminated_pids":[],"all_stopped":True})}
      return original(path,args,timeout)
    fake.guest_exec_wait=waiting
    def archive(record):
      assert events==[] and record["reason"]=="bounded-boot-timeout" and record["phase"]=="assemble"
      assert record["last_probe"]["raw_size"]>0 and len(record["last_probe"]["raw_sha256"])==64
      events.append("archive");return {"origin":"controller","immutable":True,"path":"/owned/boot.json","sha256":"a"*64,"size":2}
    b=NestedCuttlefishQgaBridge(fake,p,lambda:p.ownership,clock=lambda:now[0],sleeper=lambda _:now.__setitem__(0,61),channel_factory=fake.channel,boot_failure_archive=archive)
    with pytest.raises(NestedCuttlefishTransportError,match="bounded-boot-timeout"):b.launch_boot(stage)
    assert events==["archive","cleanup"]

def test_launch_boot_rejects_missing_cvdnetwork_membership_before_launch():
    plan=make_plan(); fake=FakeQga(plan); original=fake.guest_exec_wait
    def missing(path,args,timeout):
      if len(args)>1 and args[1]==GROUP_PREFLIGHT:
        return {"stdout":json.dumps({"ready":False,"reason":"runtime-user-or-cvdnetwork-missing"})}
      return original(path,args,timeout)
    fake.guest_exec_wait=missing
    stage=bridge(fake).stage(opener)
    with pytest.raises(NestedCuttlefishTransportError,match="cvdnetwork-only"):
     bridge(fake).launch_boot(stage)
    assert PRELAUNCH_CLEANUP in fake.codes
    assert "guest-exec" not in fake.calls

def test_group_provisioning_failure_is_archived_before_prelaunch_cleanup():
    p=make_plan();fake=FakeQga(p);original=fake.guest_exec_wait;events=[]
    def wait(path,args,timeout):
      if len(args)>1 and args[1]==GROUP_PROVISION:
        return {"stdout":json.dumps({"schema":1,"outer_failure":"cvdnetwork-provisioning","reason":"account-tool-failed","uid":p.runtime_uid,"user":"lab","primary_gid":999,"files":[{"path":"/etc/group","before_sha256":"1"*64,"after_sha256":"2"*64},{"path":"/etc/gshadow","before_sha256":"3"*64,"after_sha256":"4"*64}],"commands":[{"argv":["/usr/sbin/groupadd","--system","cvdnetwork"],"exe_sha256":"5"*64,"exit_code":1,"stdout_size":0,"stderr_size":12}],"origin":"guest","transport":"qga","injected":False})}
      if len(args)>1 and args[1]==PRELAUNCH_CLEANUP:events.append("cleanup")
      return original(path,args,timeout)
    fake.guest_exec_wait=wait
    def archive(record):
      assert events==[] and record["phase"]=="group-provisioning" and record["last_probe"]["group_provisioning"]["reason"]=="account-tool-failed";events.append("archive")
      return {"origin":"controller","immutable":True,"path":"/owned/group-failure.json","sha256":"f"*64,"size":10}
    b=NestedCuttlefishQgaBridge(fake,p,lambda:p.ownership,channel_factory=fake.channel,boot_failure_archive=archive)
    with pytest.raises(NestedCuttlefishTransportError,match="provisioning receipt invalid"):b.launch_boot(b.stage(opener))
    assert events==["archive","cleanup"]


def test_public_cleanup_preserves_exact_boot_identity_and_proves_absence(monkeypatch):
    plan=make_plan(); qga=FakeQga(plan); bridge=NestedCuttlefishQgaBridge(qga,plan,lambda:plan.ownership,sleeper=lambda _:None)
    boot=boot_receipt(plan); expected=sorted(x["pid"] for x in boot["processes"]); calls=[]
    def execute(path,args,timeout):
      calls.append((path,args,timeout))
      if len(calls)==1:return {"terminated_pids":expected,"all_stopped":True,"marker_removed":True}
      empty={"count":0,"sample":[],"sha256":hashlib.sha256(b"").hexdigest()}
      return {"survivors":[],"members":empty,"sockets":empty,"marker_exists":False}
    monkeypatch.setattr(bridge,"_exec_json",execute)
    receipt=bridge.cleanup(boot)
    assert receipt["terminated_pids"]==expected and receipt["unknown_survivors"]==[]
    assert [x["pid"] for x in receipt["stopped_identities"]]==expected

def test_public_cleanup_rejects_remaining_socket(monkeypatch):
    plan=make_plan();bridge=NestedCuttlefishQgaBridge(FakeQga(plan),plan,lambda:plan.ownership,sleeper=lambda _:None);boot=boot_receipt(plan)
    expected=sorted(x["pid"] for x in boot["processes"]);empty={"count":0,"sample":[],"sha256":hashlib.sha256(b"").hexdigest()};socket_path=plan.root+"/adb.sock";values=iter(({"terminated_pids":expected,"all_stopped":True,"marker_removed":True},{"survivors":[],"members":empty,"sockets":{"count":1,"sample":[socket_path],"sha256":hashlib.sha256(socket_path.encode()).hexdigest()},"marker_exists":False}))
    monkeypatch.setattr(bridge,"_exec_json",lambda *a,**k:next(values))
    with pytest.raises(NestedCuttlefishTransportError,match="absence") as caught:bridge.cleanup(boot)
    assert '"count":1' in str(caught.value) and socket_path in str(caught.value) and len(str(caught.value))<4600

def test_cleanup_rejects_forged_stage_root_identity_before_guest_mutation(monkeypatch):
    plan=make_plan();bridge=NestedCuttlefishQgaBridge(FakeQga(plan),plan,lambda:plan.ownership,sleeper=lambda _:None);boot=boot_receipt(plan)
    boot["runtime_dependency"]["stage"]["guest_root_identity"]["inode"]=999
    called=[]
    def reject(*args,**kwargs):
      called.append(args);assert '"inode":999' in args[1][1];raise NestedCuttlefishTransportError("owned root identity changed before cleanup")
    monkeypatch.setattr(bridge,"_exec_json",reject)
    with pytest.raises(NestedCuttlefishTransportError,match="identity changed"):bridge.cleanup(boot)
    assert len(called)==1

def test_supplemental_stage_requires_guest_rehash(monkeypatch):
    plan=make_plan();bridge=NestedCuttlefishQgaBridge(FakeQga(plan),plan,lambda:plan.ownership);spec=AssetSpec("baseline.apk","/baseline",3,hashlib.sha256(b"old").hexdigest())
    monkeypatch.setattr(bridge,"_negotiate_chunk_size",lambda d:32768);monkeypatch.setattr(bridge,"_stream",lambda *a,**k:{"chunk_count":1,"received_size":3,"eof":True,"transcript_sha256":"a"*64})
    monkeypatch.setattr(bridge,"_exec_json",lambda *a,**k:{"size":3,"sha256":spec.sha256})
    result=bridge.stage_additional_asset(spec,lambda p:io.BytesIO(b"old"));assert result["guest_rehash"]["sha256"]==spec.sha256
    monkeypatch.setattr(bridge,"_exec_json",lambda *a,**k:{"size":3,"sha256":"0"*64})
    with pytest.raises(NestedCuttlefishTransportError,match="rehash"):bridge.stage_additional_asset(spec,lambda p:io.BytesIO(b"old"))


def test_vulkan_prelaunch_contract_is_bounded_hash_bound_and_private():
    assert "RLIMIT_FSIZE" in VULKAN_INSTALL and "timeout=20" in VULKAN_INSTALL
    assert "vkGetInstanceProcAddr" in VULKAN_INSTALL and "dpkg-deb" in VULKAN_INSTALL
    assert "runtime/private-libs" in VULKAN_INSTALL and "usr/lib/x86_64-linux-gnu/libvulkan.so.1.3.275" in VULKAN_INSTALL
    assert "mesa-vulkan" not in VULKAN_INSTALL and "vulkan-icd" not in VULKAN_INSTALL

def test_vulkan_probe_failure_preserves_primary_and_cleans_owned_prelaunch_root():
    p=make_plan();fake=FakeQga(p);original=fake.guest_exec_wait
    def fail(path,args,timeout):
        if len(args)>1 and args[1]==VULKAN_INSTALL: raise NestedCuttlefishTransportError("real probe failed")
        return original(path,args,timeout)
    fake.guest_exec_wait=fail;b=bridge(fake);stage=b.stage(opener)
    with pytest.raises(NestedCuttlefishTransportError,match="real probe failed"):
        b.launch_boot(stage)
    assert PRELAUNCH_CLEANUP in fake.codes and fake.calls.count("guest-exec")==0

def test_prelaunch_cleanup_refuses_replacement_outer_and_preserves_primary():
    p=make_plan();fake=FakeQga(p);original=fake.guest_exec_wait;live=[p.ownership]
    replacement=OuterOwnership(p.ownership.run_id,p.ownership.profile,p.ownership.attempt_nonce,999,p.ownership.start_ticks,p.ownership.uuid,p.ownership.qmp_socket,p.ownership.qga_socket)
    def fail(path,args,timeout):
        if len(args)>1 and args[1]==VULKAN_INSTALL:
            live[0]=replacement;raise NestedCuttlefishTransportError("real probe failed")
        return original(path,args,timeout)
    fake.guest_exec_wait=fail;b=bridge(fake,lambda:live[0]);stage=b.stage(opener)
    with pytest.raises(NestedCuttlefishTransportError,match="real probe failed") as caught:
        b.launch_boot(stage)
    assert PRELAUNCH_CLEANUP not in fake.codes
    assert any("ownership changed" in note for note in getattr(caught.value,"__notes__",[]))


def test_prelaunch_cleanup_rejects_same_path_replacement_with_copied_marker(tmp_path):
    import os, shutil
    if os.name != "nt" or not shutil.which("wsl.exe"):
        pytest.skip("requires WSL openat/O_NOFOLLOW semantics")
    parent=tmp_path/"owned"; root=parent/"attempt"; root.mkdir(parents=True)
    marker="run-1:nonce-1"; (root/"marker").write_text(marker)
    converted="/mnt/"+root.drive[0].lower()+"/"+root.as_posix().split(":/",1)[1]
    probe="import json,os,sys;s=os.stat(sys.argv[1]);print(json.dumps({'dev':s.st_dev,'inode':s.st_ino,'uid':s.st_uid,'mode':format(s.st_mode&0o777,'04o')}))"
    expected=json.loads(subprocess.run(["wsl.exe","python3","-c",probe,converted],capture_output=True,text=True,check=True).stdout)
    old=parent/"old"; root.rename(old); root.mkdir(); (root/"marker").write_text(marker); (root/"keep").write_text("replacement")
    wrapper='import base64,sys; code=base64.b64decode(sys.argv[1]).decode(); sys.argv=["cleanup",sys.argv[2],sys.argv[3],sys.argv[4],sys.argv[5],base64.b64decode(sys.argv[6]).decode()]; exec(code)'
    result=subprocess.run(["wsl.exe","python3","-c",wrapper,base64.b64encode(PRELAUNCH_CLEANUP.encode()).decode(),converted,marker,"run-1","nonce-1",base64.b64encode(json.dumps(expected,separators=(",",":")).encode()).decode()],capture_output=True,text=True)
    assert result.returncode != 0 and "identity changed" in result.stderr
    assert root.is_dir() and (root/"keep").read_text()=="replacement"


def test_vulkan_failure_is_archived_before_identity_bound_cleanup():
    p=make_plan(); fake=FakeQga(p); events=[]
    original=fake.guest_exec_wait
    def wait(path,args,timeout):
        if len(args)>1 and args[1]==VULKAN_INSTALL:
            return {"stdout":json.dumps({"schema":1,"run_id":p.ownership.run_id,"attempt_nonce":p.ownership.attempt_nonce,"outer_failure":"vulkan-runtime-probe","diagnostic":{"rc":1,"stderr":"Permission denied"},"origin":"guest","transport":"qga","injected":False})}
        if len(args)>1 and args[1]==PRELAUNCH_CLEANUP: events.append("cleanup")
        return original(path,args,timeout)
    fake.guest_exec_wait=wait
    def archive(record):
        assert events==[] and record["guest_root_identity"]["mode"]=="0711";events.append("archive")
        return {"origin":"controller","immutable":True,"path":"/owned/failure.json","sha256":"f"*64,"size":10}
    b=NestedCuttlefishQgaBridge(fake,p,lambda:p.ownership,clock=lambda:0,sleeper=lambda _:None,channel_factory=fake.channel,failure_archive=archive)
    with pytest.raises(NestedCuttlefishTransportError,match="Vulkan runtime"): b.launch_boot(b.stage(opener))
    assert events==["archive","cleanup"]


def test_launch_reuses_staged_root_transition_without_second_chmod():
    p=make_plan();fake=FakeQga(p);events=[];scripts=[];original=fake.guest_exec_wait
    def wait(path,args,timeout):
        if len(args)>1 and args[0]=="-c": scripts.append(args[1])
        if len(args)>1 and args[1]==PRELAUNCH_CLEANUP:events.append("cleanup")
        return original(path,args,timeout)
    fake.guest_exec_wait=wait
    result=bridge(fake).launch_boot(bridge(fake).stage(opener))
    assert result["passed"] is True
    assert scripts.count(RUNTIME_OWNERSHIP)==1
    assert not any("attempt root identity changed before access transition" in script for script in scripts)

def test_graphics_detector_failures_emit_same_archivable_bounded_envelope():
    assert "diagnostic['graphics_detector']" in VULKAN_INSTALL
    assert "outer_failure':'vulkan-runtime-probe'" in VULKAN_INSTALL
    assert "except subprocess.TimeoutExpired: probe=subprocess.CompletedProcess([],124)" in VULKAN_INSTALL
