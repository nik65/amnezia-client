"""Plan and validate an authentic pre-existing headless deployment fixture.

This module is transport-free.  A lab controller must execute its fixed argv
inside an owned disposable guest and return raw guest evidence.  It never
creates routes or claims that a daemon/update passed by itself.
"""
from __future__ import annotations

import hashlib, ipaddress, json, re
from dataclasses import asdict, dataclass
from pathlib import PurePosixPath
from typing import Mapping

SHA = re.compile(r"[0-9a-f]{64}")
TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
NONCE = re.compile(r"[0-9a-f]{48}")
OWNED = PurePosixPath("/var/lib/amnezia-release-lab")
CONFIG_ROOT = PurePosixPath("/etc/amnezia/profiles")

class FixtureError(RuntimeError): pass

def _sha(value: object) -> str:
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()).hexdigest()

def _under(path: str, root: PurePosixPath) -> bool:
    p=PurePosixPath(path)
    try: p.relative_to(root)
    except ValueError: return False
    return p.is_absolute() and p!=root

@dataclass(frozen=True)
class BinaryIdentity:
    path: str; sha256: str
    def validate(self, *, legacy: bool=False) -> None:
        if not PurePosixPath(self.path).is_absolute() or not SHA.fullmatch(self.sha256): raise FixtureError("invalid binary identity")
        if legacy and not _under(self.path,OWNED): raise FixtureError("legacy binary must be staged below owned lab root")

@dataclass(frozen=True)
class FixturePlan:
    run_id: str; profile: str; nonce: str; controller_nonce: str; runtime_uid: int
    owned_root: str; socket_path: str
    cli: BinaryIdentity; setup_daemon: BinaryIdentity; legacy_daemon: BinaryIdentity
    setup_version: str; legacy_version: str
    @property
    def tag(self)->str: return hashlib.sha256(f"{self.run_id}\0{self.nonce}".encode()).hexdigest()[:8]
    @property
    def profile_id(self)->str: return f"compat-{self.tag}"
    @property
    def netns(self)->str: return f"amnfx-{self.tag}"
    @property
    def host_veth(self)->str: return f"afxh{self.tag}"
    @property
    def peer_veth(self)->str: return f"afxn{self.tag}"
    @property
    def wg_interface(self)->str: return f"afxw{self.tag}"
    @property
    def octet(self)->int: return 16 + int(self.tag[:2],16)%200
    @property
    def underlay_host(self)->str: return f"10.203.{self.octet}.1"
    @property
    def underlay_server(self)->str: return f"10.203.{self.octet}.2"
    @property
    def tunnel_server(self)->str: return f"10.204.{self.octet}.1"
    @property
    def tunnel_client(self)->str: return f"10.204.{self.octet}.2"
    @property
    def routed_test_prefix(self)->str: return f"10.205.{self.octet}.0/24"
    @property
    def routed_test_server(self)->str: return f"10.205.{self.octet}.1/24"
    @property
    def config_path(self)->str: return f"/etc/amnezia/profiles/{self.profile_id}.conf"
    @property
    def baseline_config_path(self)->str: return f"/etc/amnezia/profiles/{self.wg_interface}.conf"
    @property
    def managed_receipts(self)->tuple[str,str]: return ("/var/lib/amnezia/managed-routes.json","/var/lib/amnezia/routing-controller.json")
    def validate(self)->None:
        if not TOKEN.fullmatch(self.run_id) or self.profile!="linux-headless-x64" or not NONCE.fullmatch(self.nonce) or not NONCE.fullmatch(self.controller_nonce): raise FixtureError("invalid run/profile/nonce binding")
        if self.runtime_uid<=0 or not _under(self.owned_root,OWNED) or self.socket_path!="/run/amnezia/amneziad.sock": raise FixtureError("invalid guest ownership paths")
        self.cli.validate(); self.setup_daemon.validate(); self.legacy_daemon.validate(legacy=True)
        if self.setup_daemon.sha256==self.legacy_daemon.sha256 or not self.setup_version or not self.legacy_version: raise FixtureError("setup and legacy identities are not distinct")
        routed=ipaddress.ip_network(self.routed_test_prefix); tunnel=ipaddress.ip_network(f"10.204.{self.octet}.0/30")
        if ipaddress.ip_interface(self.routed_test_server).ip not in routed or routed.overlaps(tunnel): raise FixtureError("routed policy topology is not isolated")
        for name in (self.netns,self.host_veth,self.peer_veth,self.wg_interface):
            if len(name)>15: raise FixtureError("kernel name too long")
        baseline=PurePosixPath(self.baseline_config_path)
        if baseline.parent!=CONFIG_ROOT or baseline.name!=f"{self.wg_interface}.conf" or len(str(baseline))>255:
            raise FixtureError("baseline config path is not interface-bound")

def build_contract(plan:FixturePlan, *, server_public_key:str)->dict:
    plan.validate()
    if not re.fullmatch(r"[A-Za-z0-9+/]{43}=",server_public_key): raise FixtureError("invalid WireGuard public key")
    policy={"serverExcept":{}}
    profile={"id":plan.profile_id,"name":f"compatibility seeded {plan.tag}","protocol":"wireguard",
      "configPath":plan.config_path,"forwardRoutes":[plan.routed_test_prefix],"interfaceName":plan.wg_interface,
      "routingMode":"all-except","serverRulesUrl":f"http://{plan.routed_test_server.split('/',1)[0]}:17865/policy.json","autoConnect":False,"autoUpdate":False}
    baseline_profile={**profile,"id":plan.profile_id+"-baseline","name":f"baseline owned {plan.tag}","configPath":plan.baseline_config_path,"routingMode":"only-forward","serverRulesUrl":""}
    cli=lambda *args:[plan.cli.path,"--socket",plan.socket_path,"--json",*args]
    baseline_cli=lambda *args:[f"{plan.owned_root}/legacy/amnezia-cli","--socket",plan.socket_path,"--json",*args]
    return {"schema":1,"operation":"headless-preexisting-fixture","binding":asdict(plan),"marker":f"amnezia-release-lab:{plan.run_id}:headless-preexisting:{plan.nonce}",
      "network":{"kind":"guest-local-netns","netns":plan.netns,"host_veth":plan.host_veth,"peer_veth":plan.peer_veth,
        "underlay":f"10.203.{plan.octet}.0/30","underlay_host":plan.underlay_host,"underlay_server":plan.underlay_server,
        "tunnel":f"10.204.{plan.octet}.0/30","tunnel_server":plan.tunnel_server,"tunnel_client":plan.tunnel_client,"routed_test_prefix":plan.routed_test_prefix,"routed_test_server":plan.routed_test_server,"udp_port":51820,"http_port":17865,"host_network_mutation":False},
      "files":{"client_config":plan.config_path,"baseline_client_config":plan.baseline_config_path,"server_private_key":f"{plan.owned_root}/secrets/server.key","client_private_key":f"{plan.owned_root}/secrets/client.key","policy":f"{plan.owned_root}/public/policy.json","profile":f"{plan.owned_root}/public/profile.json","baseline_profile":f"{plan.owned_root}/public/baseline-profile.json","mode":384},
      "baseline_config":{"path":plan.baseline_config_path,"basename":PurePosixPath(plan.baseline_config_path).name,"interface":plan.wg_interface,"max_size":65536,"table":"off"},
      "wireguard":{"server_public_key":server_public_key,"endpoint":f"{plan.underlay_server}:51820","allowed_ips":"0.0.0.0/0, ::/0"},
      "policy":{"bytes":json.dumps(policy,sort_keys=True,separators=(",",":")),"sha256":_sha(policy)},"profile_document":profile,"baseline_profile_document":baseline_profile,
      "cli":{"import":cli("import",f"{plan.owned_root}/public/profile.json"),"connect":cli("connect",plan.profile_id),"status":cli("status"),"doctor":cli("doctor"),"list":cli("list-profiles")},
      "baseline_cli":{"import":baseline_cli("import",f"{plan.owned_root}/public/baseline-profile.json"),"connect":baseline_cli("connect",plan.profile_id+"-baseline"),"status":baseline_cli("status"),"doctor":baseline_cli("doctor"),"list":baseline_cli("list-profiles")},
      "required_tools":["/usr/sbin/ip","/usr/bin/wg","/usr/bin/wg-quick","/usr/bin/python3","/usr/bin/ping"],"managed_receipts":list(plan.managed_receipts)}

def _proc(expected:BinaryIdentity, value:object, uid:int)->None:
    if not isinstance(value,Mapping): raise FixtureError("process evidence missing")
    if value.get("exe")!=expected.path or value.get("exe_sha256")!=expected.sha256 or value.get("uid")!=uid: raise FixtureError("process binary/uid mismatch")
    if isinstance(value.get("pid"),bool) or not isinstance(value.get("pid"),int) or value["pid"]<=1 or isinstance(value.get("start_ticks"),bool) or not isinstance(value.get("start_ticks"),int) or value["start_ticks"]<=0: raise FixtureError("process identity incomplete")

def _validate_baseline_config(plan:FixturePlan,contract:Mapping,row:object)->dict:
    keys={"path","uid","gid","mode","size","sha256","regular","symlink","basename","interface","length","source","table","verified"}
    if not isinstance(row,Mapping) or set(row)!=keys: raise FixtureError("baseline config staging proof incomplete")
    expected=contract.get("baseline_config")
    if not isinstance(expected,Mapping) or row.get("path")!=plan.baseline_config_path or row.get("path")!=expected.get("path") or row.get("basename")!=f"{plan.wg_interface}.conf" or row.get("basename")!=expected.get("basename") or row.get("interface")!=plan.wg_interface or row.get("uid")!=0 or row.get("gid")!=0 or row.get("mode")!=0o600 or row.get("regular") is not True or row.get("symlink") is not False or row.get("source")!="verified-fixture-config" or row.get("table")!="off" or row.get("verified") is not True: raise FixtureError("baseline config staging identity invalid")
    if isinstance(row.get("size"),bool) or not isinstance(row.get("size"),int) or row["size"]<=0 or row["size"]>expected.get("max_size",0) or row.get("length")!=row.get("size") or not SHA.fullmatch(str(row.get("sha256",""))): raise FixtureError("baseline config staging size/hash invalid")
    return dict(row)

def validate_connected(plan:FixturePlan, receipt:Mapping)->dict:
    contract=build_contract(plan,server_public_key=str(receipt.get("server_public_key","")))
    if receipt.get("schema")!=1 or receipt.get("operation")!="headless-preexisting-connected" or receipt.get("origin")!="guest" or receipt.get("transport")!="qga" or receipt.get("injected") is not False: raise FixtureError("non-guest receipt")
    if receipt.get("contract_sha256")!=_sha(contract) or receipt.get("run_id")!=plan.run_id or receipt.get("profile")!=plan.profile or receipt.get("nonce")!=plan.nonce: raise FixtureError("fixture binding mismatch")
    _proc(plan.setup_daemon,receipt.get("daemon"),0)
    cli=receipt.get("cli")
    if not isinstance(cli,Mapping) or set(cli)!={"import","connect","status","doctor","list"}: raise FixtureError("raw CLI envelopes incomplete")
    for key,row in cli.items():
        if not isinstance(row,Mapping) or row.get("argv")!=contract["cli"][key] or row.get("rc")!=0 or not SHA.fullmatch(str(row.get("stdout_sha256",""))) or not isinstance(row.get("json"),Mapping): raise FixtureError("CLI evidence invalid")
    status=cli["status"]["json"].get("result",cli["status"]["json"]); routing=status.get("routing",{}) if isinstance(status,Mapping) else {}
    if status.get("state")!="connected" or status.get("activeProfile")!=plan.profile_id or routing.get("mode")!="all-except" or routing.get("interface")!=plan.wg_interface or routing.get("routeTable")!=51821 or routing.get("recoveryRequired") is not False or routing.get("activeProfile")!=plan.profile_id: raise FixtureError("product did not report connected all-except")
    wg=receipt.get("wireguard")
    if not isinstance(wg,Mapping) or wg.get("interface")!=plan.wg_interface or wg.get("peer_public_key")!=receipt.get("server_public_key") or not isinstance(wg.get("latest_handshake"),int) or wg["latest_handshake"]<receipt.get("connect_started_epoch",0) or min(wg.get("rx_bytes",0),wg.get("tx_bytes",0))<=0: raise FixtureError("real WireGuard exchange not proven")
    probe=receipt.get("routed_probe"); target=plan.routed_test_server.split('/',1)[0]
    expected_ping=["/usr/bin/ping","-n","-c","1","-W","3","-I",plan.wg_interface,target]
    route_get=probe.get("route_get",[]) if isinstance(probe,Mapping) else []
    traffic=probe.get("traffic",{}) if isinstance(probe,Mapping) else {}
    if not isinstance(probe,Mapping) or probe.get("target")!=target or probe.get("prefix")!=plan.routed_test_prefix or probe.get("interface")!=plan.wg_interface or len(route_get)!=1 or route_get[0].get("dst")!=target or route_get[0].get("dev")!=plan.wg_interface or traffic.get("argv")!=expected_ping or traffic.get("rc")!=0 or traffic.get("verified") is not True or not SHA.fullmatch(str(traffic.get("stdout_sha256",""))) or not SHA.fullmatch(str(traffic.get("stderr_sha256",""))): raise FixtureError("routed product traffic not proven")
    kernel=receipt.get("kernel")
    routes=kernel.get("table_51821",[]) if isinstance(kernel,Mapping) else []
    rules=kernel.get("rules",[]) if isinstance(kernel,Mapping) else []
    if len(routes)!=4 or any("proto 186" not in x and "proto bgp" not in x for x in routes) or not all(any(prefix in x and f"dev {plan.wg_interface}" in x for x in routes) for prefix in ("0.0.0.0/1","128.0.0.0/1","::/1","8000::/1")): raise FixtureError("exact product full-tunnel routes missing")
    if len([x for x in rules if "lookup 51821" in x])<2: raise FixtureError("product policy rules missing")
    files=receipt.get("managed_receipts")
    if not isinstance(files,list) or {x.get("path") for x in files if isinstance(x,Mapping)}!=set(plan.managed_receipts): raise FixtureError("managed receipt set incomplete")
    group=receipt.get("service_group")
    if not isinstance(group,Mapping) or set(group)!={"name","gid"} or group.get("name")!="amnezia" or isinstance(group.get("gid"),bool) or not isinstance(group.get("gid"),int) or group["gid"]<=0: raise FixtureError("service group identity invalid")
    expected_modes={"/var/lib/amnezia/managed-routes.json":384,"/var/lib/amnezia/routing-controller.json":432}
    for row in files:
        if row.get("regular") is not True or row.get("symlink") is not False or row.get("uid")!=0 or row.get("gid")!=group["gid"] or row.get("mode")!=expected_modes.get(row.get("path")) or row.get("size",0)<=0 or not SHA.fullmatch(str(row.get("sha256",""))): raise FixtureError("managed receipt identity invalid")
    if receipt.get("policy_http",{}).get("path")!="/policy.json" or receipt.get("policy_http",{}).get("eof") is not True or receipt.get("policy_http",{}).get("sha256")!=contract["policy"]["sha256"]: raise FixtureError("policy readback missing")
    return dict(receipt)

def crash_authorization(plan:FixturePlan, connected:Mapping, *, durable_path:str, durable_sha256:str, controller_nonce:str)->dict:
    validated=validate_connected(plan,connected)
    if controller_nonce!=plan.controller_nonce or not _under(durable_path,OWNED) or not SHA.fullmatch(durable_sha256) or durable_sha256!=_sha(validated): raise FixtureError("controller archive ack does not bind connected receipt")
    daemon=validated["daemon"]
    return {"schema":1,"action":"kill-setup-daemon","signal":"SIGKILL","pid":daemon["pid"],"start_ticks":daemon["start_ticks"],"exe":daemon["exe"],"exe_sha256":daemon["exe_sha256"],"uid":0,"connected_receipt_sha256":durable_sha256,"durable_path":durable_path,"controller_nonce":controller_nonce,"revalidate_immediately":True}

def validate_crash_transition(plan:FixturePlan,connected:Mapping,receipt:Mapping)->dict:
    validated=validate_connected(plan,connected); digest=_sha(validated)
    if receipt.get("schema")!=1 or receipt.get("operation")!="headless-preexisting-crash" or receipt.get("origin")!="guest" or receipt.get("transport")!="qga" or receipt.get("controller_nonce")!=plan.controller_nonce or receipt.get("connected_receipt_sha256")!=digest or receipt.get("observed_gone") is not True: raise FixtureError("crash transition binding invalid")
    stale=receipt.get("stale_socket"); service_gid=validated["service_group"]["gid"]
    killed=receipt.get("killed")
    if not isinstance(killed,Mapping) or any(killed.get(k)!=validated["daemon"].get(k) for k in ("pid","start_ticks","exe","exe_sha256","uid","cmdline_sha256")): raise FixtureError("killed daemon identity mismatch")
    runtime=stale.get("runtime_dir") if isinstance(stale,Mapping) else None
    if not isinstance(runtime,Mapping) or runtime.get("path")!="/run/amnezia" or runtime.get("uid")!=0 or runtime.get("gid")!=service_gid or runtime.get("mode")!=488 or any(isinstance(runtime.get(k),bool) or not isinstance(runtime.get(k),int) or runtime[k]<=0 for k in ("device","inode","ctime_ns")): raise FixtureError("runtime directory evidence invalid")
    branch=stale.get("branch")
    if branch=="stale-removed":
        if stale.get("path")!=plan.socket_path or stale.get("socket") is not True or stale.get("symlink") is not False or stale.get("uid")!=0 or stale.get("gid")!=service_gid or stale.get("mode")!=432 or stale.get("connect_errno")!=111 or stale.get("live_owner") is not False or stale.get("removed") is not True or runtime.get("created") is not False or any(isinstance(stale.get(k),bool) or not isinstance(stale.get(k),int) or stale[k]<=0 for k in ("device","inode","ctime_ns")): raise FixtureError("stale socket removal evidence invalid")
    elif branch=="clean-absent":
        if stale.get("path")!=plan.socket_path or stale.get("socket") is not False or stale.get("symlink") is not False or stale.get("removed") is not False or runtime.get("created") is not True: raise FixtureError("clean socket transition evidence invalid")
    else: raise FixtureError("socket transition branch invalid")
    keys=("path","uid","gid","mode","size","sha256")
    normalize=lambda rows:[{k:x.get(k) for k in keys} for x in rows] if isinstance(rows,list) and all(isinstance(x,Mapping) for x in rows) else None
    before=normalize(stale.get("managed_before")); after=normalize(stale.get("managed_after")); expected=normalize(validated["managed_receipts"])
    if before is None or before!=after or before!=expected: raise FixtureError("managed state changed during stale socket removal")
    guard=receipt.get("restart_guard")
    if not isinstance(guard,Mapping) or guard.get("uid")!=0 or guard.get("mode")!=384 or guard.get("size",0)<=0 or not SHA.fullmatch(str(guard.get("sha256",""))): raise FixtureError("restart guard identity invalid")
    return dict(receipt)

def validate_legacy_start(plan:FixturePlan, connected:Mapping, receipt:Mapping)->dict:
    connected_sha=_sha(validate_connected(plan,connected))
    if receipt.get("schema")!=1 or receipt.get("operation")!="headless-preexisting-legacy-start" or receipt.get("origin")!="guest" or receipt.get("transport")!="qga" or receipt.get("connected_receipt_sha256")!=connected_sha: raise FixtureError("legacy receipt binding mismatch")
    _proc(plan.legacy_daemon,receipt.get("daemon"),0)
    if receipt.get("boot_id")!=connected.get("boot_id") or receipt.get("started_epoch",0)<=connected.get("collected_epoch",0): raise FixtureError("legacy process chronology invalid")
    before=receipt.get("unchanged_files")
    expected={x["path"]:x["sha256"] for x in connected["managed_receipts"]}
    if not isinstance(before,list) or {x.get("path"):x.get("sha256") for x in before if isinstance(x,Mapping)}!=expected: raise FixtureError("legacy start changed product receipts")
    raw=receipt.get("status")
    if not isinstance(raw,Mapping) or raw.get("rc")!=0 or not SHA.fullmatch(str(raw.get("stdout_sha256",""))) or not isinstance(raw.get("json"),Mapping): raise FixtureError("legacy raw status missing")
    return dict(receipt)

def validate_managed_receipt_retirement(plan:FixturePlan, connected:Mapping, retirement:Mapping)->dict:
    if not isinstance(retirement,Mapping) or retirement.get("schema")!=1 or retirement.get("operation")!="headless-preexisting-retire-managed-receipts": raise FixtureError("managed receipt retirement evidence missing")
    gid=connected.get("service_group",{}).get("gid") if isinstance(connected.get("service_group"),Mapping) else None
    expected_modes={plan.managed_receipts[0]:384,plan.managed_receipts[1]:432}
    sources=retirement.get("source"); archives=retirement.get("archives"); absence=retirement.get("absence")
    if not isinstance(sources,list) or len(sources)!=2 or {x.get("path") for x in sources if isinstance(x,Mapping)}!=set(plan.managed_receipts): raise FixtureError("retired source set mismatch")
    if not isinstance(archives,list) or len(archives)!=2 or {x.get("path") for x in archives if isinstance(x,Mapping)}!={f"{plan.owned_root}/retired-managed/managed-routes.json",f"{plan.owned_root}/retired-managed/routing-controller.json"}: raise FixtureError("retired archive set mismatch")
    for row in sources:
        if not isinstance(row,Mapping) or set(row)!={"path","uid","gid","mode","size","sha256"} or row.get("uid")!=0 or row.get("gid")!=gid or row.get("mode")!=expected_modes.get(row.get("path")) or not isinstance(row.get("size"),int) or row.get("size")<=0 or not SHA.fullmatch(str(row.get("sha256",""))): raise FixtureError("retired source identity invalid")
    for row in archives:
        if not isinstance(row,Mapping) or set(row)!={"path","uid","gid","mode","size","sha256"} or not _under(str(row.get("path","")),PurePosixPath(plan.owned_root+"/retired-managed")) or row.get("uid")!=0 or row.get("gid")!=0 or row.get("mode")!=384 or not isinstance(row.get("size"),int) or row.get("size")<=0 or not SHA.fullmatch(str(row.get("sha256",""))): raise FixtureError("retired archive identity invalid")
    if any(next((a.get("sha256") for a in archives if isinstance(a,Mapping) and a.get("path")==f"{plan.owned_root}/retired-managed/{PurePosixPath(s['path']).name}"),None)!=s.get("sha256") for s in sources): raise FixtureError("retired archive hash mismatch")
    if not isinstance(absence,list) or len(absence)!=2 or {x.get("path") for x in absence if isinstance(x,Mapping)}!=set(plan.managed_receipts) or any(x.get("exists") is not False for x in absence if isinstance(x,Mapping)): raise FixtureError("retired source absence incomplete")
    proof=retirement.get("proof")
    if not isinstance(proof,Mapping) or set(proof)!={"path","uid","gid","mode","size","sha256"} or not _under(str(proof.get("path","")),PurePosixPath(plan.owned_root)) or proof.get("uid")!=0 or proof.get("gid")!=0 or proof.get("mode")!=384 or not isinstance(proof.get("size"),int) or proof.get("size")<=0 or not SHA.fullmatch(str(proof.get("sha256",""))): raise FixtureError("retired proof identity invalid")
    return dict(retirement)

def validate_baseline_owned(plan:FixturePlan,connected:Mapping,receipt:Mapping)->dict:
    prior=validate_connected(plan,connected);contract=build_contract(plan,server_public_key=prior["server_public_key"])
    if receipt.get("schema")!=1 or receipt.get("operation")!="headless-preexisting-baseline-owned" or receipt.get("origin")!="guest" or receipt.get("transport")!="qga" or receipt.get("connected_receipt_sha256")!=_sha(prior): raise FixtureError("baseline handoff binding invalid")
    _validate_baseline_config(plan,contract,receipt.get("baseline_config"))
    transition=receipt.get("setup_disconnect"); terminal=receipt.get("systemd_terminal")
    if not isinstance(transition,Mapping) or transition.get("state")!="disconnected" or transition.get("interface_absent") is not True or transition.get("routes_clean") is not True or transition.get("dns_clean") is not True or transition.get("recovery_required") is not False: raise FixtureError("setup disconnect cleanup invalid")
    diagnostic=transition.get("pre_disconnect_diagnostic"); target=connected.get("daemon") if isinstance(connected,Mapping) else None
    if not isinstance(diagnostic,Mapping) or not isinstance(target,Mapping) or diagnostic.get("schema")!=1 or diagnostic.get("target")!={key:target.get(key) for key in ("pid","start_ticks","exe_sha256")}: raise FixtureError("pre-disconnect diagnostic binding invalid")
    trace=diagnostic.get("strace"); pointer_keys=("path","uid","gid","mode","size","sha256")
    def private_pointer(value:object)->bool:
        return isinstance(value,Mapping) and set(value)==set(pointer_keys) and isinstance(value.get("path"),str) and value["path"].startswith(plan.owned_root+"/") and value.get("uid")==value.get("gid")==0 and value.get("mode")==0o600 and isinstance(value.get("size"),int) and value["size"]>0 and re.fullmatch(r"[0-9a-f]{64}",str(value.get("sha256",""))) is not None
    if not isinstance(trace,Mapping) or trace.get("reason") not in ("attached","strace-unavailable","ptrace-attach-unavailable","ptrace-identity-drift") or trace.get("available") is not (trace.get("reason")=="attached") or trace.get("scope")!=["execve","exit","exit_group","write"] or trace.get("duration_limit_seconds")!=30 or not isinstance(trace.get("shards"),list) or any(not private_pointer(x) for x in trace["shards"]): raise FixtureError("pre-disconnect strace evidence invalid")
    if not private_pointer(diagnostic.get("state")) or not private_pointer(diagnostic.get("receipt")): raise FixtureError("pre-disconnect protected state missing")
    if not isinstance(terminal,Mapping) or terminal.get("MainPID")!="0" or terminal.get("ActiveState")!="inactive" or terminal.get("SubState")!="dead" or terminal.get("Job") not in ("",None): raise FixtureError("graceful service terminal invalid")
    validate_managed_receipt_retirement(plan,connected,receipt.get("managed_receipt_retirement"))
    _proc(plan.legacy_daemon,receipt.get("daemon"),0)
    cli=receipt.get("cli")
    if not isinstance(cli,Mapping) or set(cli)!={"import","connect","status","doctor","list"}: raise FixtureError("baseline CLI evidence incomplete")
    for key,row in cli.items():
        if not isinstance(row,Mapping) or row.get("argv")!=contract["baseline_cli"][key] or row.get("rc")!=0 or not SHA.fullmatch(str(row.get("stdout_sha256",""))) or not isinstance(row.get("json"),Mapping): raise FixtureError("baseline CLI evidence invalid")
    status=cli["status"]["json"].get("result",cli["status"]["json"]);routing=status.get("routing",{})
    if status.get("state")!="connected" or status.get("activeProfile")!=plan.profile_id+"-baseline" or routing.get("mode")!="only-forward" or routing.get("interface")!=plan.wg_interface or routing.get("recoveryRequired") is not False: raise FixtureError("baseline did not own only-forward state")
    probe=receipt.get("routed_probe",{});traffic=probe.get("traffic",{}) if isinstance(probe,Mapping) else {};target=plan.routed_test_server.split('/',1)[0]
    route_get=probe.get("route_get",[]) if isinstance(probe,Mapping) else [];expected_ping=["/usr/bin/ping","-n","-c","1","-W","3","-I",plan.wg_interface,target]
    if probe.get("target")!=target or probe.get("interface")!=plan.wg_interface or probe.get("prefix")!=plan.routed_test_prefix or len(route_get)!=1 or route_get[0].get("dst")!=target or route_get[0].get("dev")!=plan.wg_interface or traffic.get("argv")!=expected_ping or traffic.get("rc")!=0 or traffic.get("verified") is not True or not SHA.fullmatch(str(traffic.get("stdout_sha256",""))) or not SHA.fullmatch(str(traffic.get("stderr_sha256",""))): raise FixtureError("baseline routed traffic missing")
    return dict(receipt)
