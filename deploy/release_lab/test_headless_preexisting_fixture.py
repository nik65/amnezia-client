import hashlib
from copy import deepcopy
from pathlib import Path
import pytest

from deploy.release_lab.headless_preexisting_fixture import (BinaryIdentity,FixtureError,FixturePlan,
    _validate_baseline_config,build_contract,crash_authorization,validate_baseline_owned,validate_connected,validate_crash_transition,validate_legacy_start,_sha)

def plan():
    return FixturePlan("compat-run","linux-headless-x64","1"*48,"2"*48,1000,
      "/var/lib/amnezia-release-lab/runs/compat-run/fixture","/run/amnezia/amneziad.sock",
      BinaryIdentity("/usr/bin/amnezia-cli","a"*64),BinaryIdentity("/usr/bin/amneziad","b"*64),
      BinaryIdentity("/var/lib/amnezia-release-lab/artifacts/amneziad-5.0.1.38","c"*64),"5.0.1.39","5.0.1.38")

KEY="A"*43+"="

def connected():
    p=plan(); c=build_contract(p,server_public_key=KEY)
    def env(key,result): return {"argv":c["cli"][key],"rc":0,"stdout_sha256":hashlib.sha256(key.encode()).hexdigest(),"json":{"result":result}}
    routing={"mode":"all-except","interface":p.wg_interface,"routeTable":51821,"recoveryRequired":False,"activeProfile":p.profile_id}
    status={"state":"connected","activeProfile":p.profile_id,"routing":routing}
    managed=[{"path":path,"regular":True,"symlink":False,"uid":0,"gid":988,"mode":384 if path.endswith("managed-routes.json") else 432,"size":100,"sha256":hashlib.sha256(path.encode()).hexdigest()} for path in p.managed_receipts]
    return {"schema":1,"operation":"headless-preexisting-connected","origin":"guest","transport":"qga","injected":False,
      "run_id":p.run_id,"profile":p.profile,"nonce":p.nonce,"contract_sha256":_sha(c),"server_public_key":KEY,
      "daemon":{"pid":101,"start_ticks":500,"exe":p.setup_daemon.path,"exe_sha256":p.setup_daemon.sha256,"uid":0},
      "cli":{"import":env("import",{}),"connect":env("connect",status),"status":env("status",status),"doctor":env("doctor",{}),"list":env("list",{})},
      "connect_started_epoch":1000,"collected_epoch":1010,"boot_id":"11111111-1111-1111-1111-111111111111",
      "wireguard":{"interface":p.wg_interface,"peer_public_key":KEY,"latest_handshake":1005,"rx_bytes":12,"tx_bytes":34},
      "routed_probe":{"target":p.routed_test_server.split('/',1)[0],"prefix":p.routed_test_prefix,"interface":p.wg_interface,"route_get":[{"dst":p.routed_test_server.split('/',1)[0],"dev":p.wg_interface}],"traffic":{"argv":["/usr/bin/ping","-n","-c","1","-W","3","-I",p.wg_interface,p.routed_test_server.split('/',1)[0]],"rc":0,"stdout_sha256":"e"*64,"stderr_sha256":"f"*64,"verified":True}},
      "kernel":{"table_51821":[f"0.0.0.0/1 dev {p.wg_interface} proto 186",f"128.0.0.0/1 dev {p.wg_interface} proto bgp",f"::/1 dev {p.wg_interface} proto 186",f"8000::/1 dev {p.wg_interface} proto bgp"],"rules":["100: from all lookup 51821","101: from all lookup 51821"]},
      "service_group":{"name":"amnezia","gid":988},"managed_receipts":managed,"policy_http":{"path":"/policy.json","eof":True,"sha256":c["policy"]["sha256"]}}

def test_contract_is_guest_local_and_uses_exact_product_cli():
    p=plan(); c=build_contract(p,server_public_key=KEY)
    assert c["network"]["kind"]=="guest-local-netns" and c["network"]["host_network_mutation"] is False
    assert c["cli"]["import"]==[p.cli.path,"--socket",p.socket_path,"--json","import",f"{p.owned_root}/public/profile.json"]
    assert c["cli"]["connect"][-2:]==["connect",p.profile_id]
    assert c["cli"]["list"][-1]=="list-profiles"
    assert c["profile_document"]["routingMode"]=="all-except"
    assert c["baseline_profile_document"]["id"]==p.profile_id+"-baseline" and c["baseline_profile_document"]["routingMode"]=="only-forward" and c["baseline_profile_document"]["serverRulesUrl"]==""
    assert c["profile_document"]["configPath"]==p.config_path
    assert c["baseline_profile_document"]["configPath"]==p.baseline_config_path and c["baseline_profile_document"]["configPath"]!=p.config_path
    assert c["baseline_config"]=={"path":p.baseline_config_path,"basename":f"{p.wg_interface}.conf","interface":p.wg_interface,"max_size":65536,"table":"off"}
    assert c["baseline_cli"]["connect"][-1]==p.profile_id+"-baseline"
    assert all(argv[0]==f"{p.owned_root}/legacy/amnezia-cli" for argv in c["baseline_cli"].values())
    assert c["profile_document"]["serverRulesUrl"].startswith(f"http://{p.routed_test_server.split('/',1)[0]}:")
    assert c["profile_document"]["forwardRoutes"]==[p.routed_test_prefix]
    assert p.tunnel_server not in p.routed_test_prefix and p.routed_test_prefix!=f"10.204.{p.octet}.0/30"
    assert all(len(x)<=15 for x in (p.netns,p.host_veth,p.peer_veth,p.wg_interface))
    assert all("--json" in argv for argv in c["cli"].values())
    parser=(Path(__file__).resolve().parents[2]/"headless"/"cli.cpp").read_text()
    for command in ("status","list-profiles","doctor","connect","disconnect","import","export","update-rollback"):
      assert command in parser
    backend=(Path(__file__).resolve().parents[2]/"headless"/"vpnBackend.cpp").read_text()
    assert 'QStringLiteral("Table = off\\n")' in backend and "QRegularExpression::MultilineOption" in backend
    assert c["baseline_profile_document"]["forwardRoutes"]==[p.routed_test_prefix]
    assert c["wireguard"]["allowed_ips"]=="0.0.0.0/0, ::/0"

def test_connected_requires_real_product_status_handshake_kernel_and_receipts():
    assert validate_connected(plan(),connected())["operation"]=="headless-preexisting-connected"
    mutations=[lambda x:x["wireguard"].update(rx_bytes=0),lambda x:x["kernel"]["table_51821"].pop(),
      lambda x:x["cli"]["status"]["json"]["result"]["routing"].update(mode="only-forward"),
      lambda x:x["cli"]["status"]["json"]["result"]["routing"].update(recoveryRequired=True),
      lambda x:x["managed_receipts"][0].update(mode=420),lambda x:x["policy_http"].update(eof=False),
      lambda x:x["managed_receipts"][1].update(gid=999),lambda x:x["managed_receipts"][0].update(symlink=True),
      lambda x:x.pop("routed_probe"),lambda x:x["routed_probe"].update(interface="wrong0"),
      lambda x:x["routed_probe"]["route_get"][0].update(dev="wrong0"),lambda x:x["routed_probe"]["traffic"].update(rc=1)]
    for mutate in mutations:
      value=deepcopy(connected()); mutate(value)
      with pytest.raises(FixtureError): validate_connected(plan(),value)

def test_baseline_config_staging_binds_declared_interface_basename_and_rejects_wrong_path():
    p=plan(); c=build_contract(p,server_public_key=KEY)
    staged={"path":p.baseline_config_path,"uid":0,"gid":0,"mode":384,"size":32,"sha256":"a"*64,
      "regular":True,"symlink":False,"basename":f"{p.wg_interface}.conf","interface":p.wg_interface,
      "length":32,"source":"verified-fixture-config","table":"off","verified":True}
    assert _validate_baseline_config(p,c,staged)["basename"]==p.wg_interface+".conf"
    for mutation in (lambda x:x.update(path=p.config_path),lambda x:x.update(basename="compat.conf"),lambda x:x.update(length=31),lambda x:x.update(symlink=True)):
      value=deepcopy(staged); mutation(value)
      with pytest.raises(FixtureError): _validate_baseline_config(p,c,value)

def test_crash_requires_controller_archive_ack_and_exact_process_identity():
    value=connected(); digest=_sha(value); p=plan()
    action=crash_authorization(p,value,durable_path=f"{p.owned_root}/evidence/connected.json",durable_sha256=digest,controller_nonce=p.controller_nonce)
    assert action["signal"]=="SIGKILL" and action["pid"]==101 and action["revalidate_immediately"] is True
    with pytest.raises(FixtureError): crash_authorization(p,value,durable_path=f"{p.owned_root}/evidence/connected.json",durable_sha256="9"*64,controller_nonce=p.controller_nonce)

def crash_receipt(before):
    managed=[{k:x[k] for k in ("path","uid","gid","mode","size","sha256")} for x in before["managed_receipts"]]
    return {"schema":1,"operation":"headless-preexisting-crash","origin":"guest","transport":"qga",
      "controller_nonce":plan().controller_nonce,"connected_receipt_sha256":_sha(before),"observed_gone":True,
      "killed":deepcopy(before["daemon"]),"restart_guard":{"uid":0,"mode":384,"size":24,"sha256":"9"*64},
      "stale_socket":{"branch":"stale-removed","path":plan().socket_path,"socket":True,"symlink":False,"uid":0,"gid":988,"mode":432,
        "runtime_dir":{"path":"/run/amnezia","uid":0,"gid":988,"mode":488,"device":7,"inode":300,"ctime_ns":123450,"created":False},
        "device":7,"inode":321,"ctime_ns":123456,"connect_errno":111,"live_owner":False,"removed":True,"managed_before":managed,"managed_after":deepcopy(managed)}}

def test_crash_transition_requires_dead_exact_socket_inode_and_preserved_managed_state():
    before=connected(); receipt=crash_receipt(before)
    assert validate_crash_transition(plan(),before,receipt)["stale_socket"]["removed"] is True
    mutations=[lambda x:x["stale_socket"].update(live_owner=True),lambda x:x["stale_socket"].update(connect_errno=0),
      lambda x:x["stale_socket"].update(uid=1),lambda x:x["stale_socket"].update(mode=384),
      lambda x:x["stale_socket"].update(inode=0),lambda x:x["stale_socket"]["managed_after"][0].update(sha256="8"*64),
      lambda x:x["killed"].update(pid=999),lambda x:x["restart_guard"].update(mode=420)]
    for mutate in mutations:
      value=deepcopy(receipt); mutate(value)
      with pytest.raises(FixtureError): validate_crash_transition(plan(),before,value)
    clean=deepcopy(receipt);clean["stale_socket"]={"branch":"clean-absent","path":plan().socket_path,"socket":False,"symlink":False,"removed":False,"runtime_dir":{**receipt["stale_socket"]["runtime_dir"],"created":True},"managed_before":deepcopy(receipt["stale_socket"]["managed_before"]),"managed_after":deepcopy(receipt["stale_socket"]["managed_after"])}
    assert validate_crash_transition(plan(),before,clean)["stale_socket"]["branch"]=="clean-absent"
    clean["stale_socket"]["runtime_dir"]["mode"]=493
    with pytest.raises(FixtureError): validate_crash_transition(plan(),before,clean)

def test_legacy_start_binds_same_boot_chronology_and_unchanged_product_receipts():
    p=plan(); before=connected()
    receipt={"schema":1,"operation":"headless-preexisting-legacy-start","origin":"guest","transport":"qga",
      "connected_receipt_sha256":_sha(before),"daemon":{"pid":202,"start_ticks":900,"exe":p.legacy_daemon.path,"exe_sha256":p.legacy_daemon.sha256,"uid":0},
      "boot_id":before["boot_id"],"started_epoch":before["collected_epoch"]+1,
      "unchanged_files":[{"path":x["path"],"sha256":x["sha256"]} for x in before["managed_receipts"]],
      "status":{"rc":0,"stdout_sha256":"d"*64,"json":{"result":{"state":"connected"}}}}
    assert validate_legacy_start(p,before,receipt)["daemon"]["pid"]==202
    receipt["unchanged_files"][0]["sha256"]="e"*64
    with pytest.raises(FixtureError): validate_legacy_start(p,before,receipt)

def test_baseline_handoff_requires_graceful_cleanup_and_distinct_only_forward_owner():
    p=plan();before=connected();contract=build_contract(p,server_public_key=KEY)
    def env(key,result): return {"argv":contract["baseline_cli"][key],"rc":0,"stdout_sha256":hashlib.sha256(key.encode()).hexdigest(),"json":{"result":result}}
    routing={"mode":"only-forward","interface":p.wg_interface,"recoveryRequired":False}
    status={"state":"connected","activeProfile":p.profile_id+"-baseline","routing":routing}
    cli={"import":env("import",{}),"connect":env("connect",status),"status":env("status",status),"doctor":env("doctor",{}),"list":env("list",{})}
    pointer=lambda name:{"path":f"{p.owned_root}/{name}","uid":0,"gid":0,"mode":384,"size":10,"sha256":"a"*64}
    diagnostic={"schema":1,"target":{"pid":101,"start_ticks":500,"exe_sha256":p.setup_daemon.sha256},"strace":{"available":False,"reason":"strace-unavailable","scope":["execve","exit","exit_group","write"],"duration_limit_seconds":30,"shards":[]},"state":pointer("pre-disconnect-state.protected.json"),"receipt":pointer("pre-disconnect-diagnostic.json")}
    source=[{key:x[key] for key in ("path","uid","gid","mode","size","sha256")} for x in before["managed_receipts"]]
    archives=[{"path":f"{p.owned_root}/retired-managed/{Path(x['path']).name}","uid":0,"gid":0,"mode":384,"size":x["size"],"sha256":x["sha256"]} for x in source]
    retirement={"schema":1,"operation":"headless-preexisting-retire-managed-receipts","source":source,"archives":archives,"absence":[{"path":x["path"],"exists":False} for x in source],"proof":pointer("managed-receipt-retirement.json")}
    receipt={"schema":1,"operation":"headless-preexisting-baseline-owned","origin":"guest","transport":"qga","connected_receipt_sha256":_sha(before),"baseline_config":{"path":p.baseline_config_path,"uid":0,"gid":0,"mode":384,"size":32,"sha256":"a"*64,"regular":True,"symlink":False,"basename":f"{p.wg_interface}.conf","interface":p.wg_interface,"length":32,"source":"verified-fixture-config","table":"off","verified":True},
      "setup_disconnect":{"state":"disconnected","interface_absent":True,"routes_clean":True,"dns_clean":True,"recovery_required":False,"pre_disconnect_diagnostic":diagnostic},
      "systemd_terminal":{"MainPID":"0","ActiveState":"inactive","SubState":"dead","Job":""},"managed_receipt_retirement":retirement,
      "daemon":{"pid":202,"start_ticks":900,"exe":p.legacy_daemon.path,"exe_sha256":p.legacy_daemon.sha256,"uid":0},"cli":cli,
      "routed_probe":{"target":p.routed_test_server.split('/',1)[0],"prefix":p.routed_test_prefix,"interface":p.wg_interface,"route_get":[{"dst":p.routed_test_server.split('/',1)[0],"dev":p.wg_interface}],"traffic":{"argv":["/usr/bin/ping","-n","-c","1","-W","3","-I",p.wg_interface,p.routed_test_server.split('/',1)[0]],"rc":0,"stdout_sha256":"a"*64,"stderr_sha256":"b"*64,"verified":True}}}
    assert validate_baseline_owned(p,before,receipt)["daemon"]["pid"]==202
    for mutation in (lambda x:x["setup_disconnect"].update(interface_absent=False),lambda x:x["setup_disconnect"].update(dns_clean=False),lambda x:x["systemd_terminal"].update(ActiveState="failed"),lambda x:x["managed_receipt_retirement"]["source"][0].update(sha256="f"*64),lambda x:x["managed_receipt_retirement"]["archives"][0].update(path="/tmp/foreign.json"),lambda x:x["managed_receipt_retirement"]["absence"][1].update(exists=True),lambda x:x["cli"]["status"]["json"]["result"]["routing"].update(mode="all-except"),lambda x:x["routed_probe"].update(target="10.0.0.1"),lambda x:x["routed_probe"]["route_get"][0].update(dev="wrong0"),lambda x:x["routed_probe"]["traffic"].update(argv=["/usr/bin/ping"]),lambda x:x["routed_probe"]["traffic"].update(stdout_sha256="bad")):
      value=deepcopy(receipt);mutation(value)
      with pytest.raises(FixtureError):validate_baseline_owned(p,before,value)

def test_plan_rejects_unowned_legacy_and_short_nonce():
    p=plan()
    with pytest.raises(FixtureError): FixturePlan(p.run_id,p.profile,"short",p.controller_nonce,p.runtime_uid,p.owned_root,p.socket_path,p.cli,p.setup_daemon,p.legacy_daemon,p.setup_version,p.legacy_version).validate()
    with pytest.raises(FixtureError): FixturePlan(p.run_id,p.profile,p.nonce,p.controller_nonce,p.runtime_uid,p.owned_root,p.socket_path,p.cli,p.setup_daemon,BinaryIdentity("/tmp/legacy","c"*64),p.setup_version,p.legacy_version).validate()
