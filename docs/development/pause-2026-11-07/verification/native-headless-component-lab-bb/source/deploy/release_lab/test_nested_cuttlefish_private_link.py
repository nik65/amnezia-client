import hashlib,json
from pathlib import Path
import pytest
from deploy.release_lab.nested_cuttlefish_private_link import *
from deploy.release_lab import nested_cuttlefish_private_link as private_link_module

def binding(profile,pid):
 return {"run_id":"run","profile":profile,"marker":f"amnezia-release-lab:run:{profile}","pid":pid,"start_ticks":pid*10,"uid":999,"uuid":profile,"qmp_socket":"/qmp/"+profile,"qga_socket":"/qga/"+profile}
def plan():
 data=b"manifest"
 return PrivateLinkPlan("run","a"*48,"lnk","/var/lib/amnezia-release-lab/runs/run/n/l.sock","server-router","linux-headless-x64",binding("server-router",2),binding("linux-headless-x64",3),"02:aa:00:00:00:01","02:aa:00:00:00:02","172.31.40.1/30","172.31.40.2/30","http://10.8.1.0:17865",[HttpObject("/manifest.json",hashlib.sha256(data).hexdigest(),len(data))])
class Qmp:
 def __init__(self,fail=None):self.fail=fail;self.calls=[]
 def request(self,c,a):
  self.calls.append((c,a))
  if self.fail==c:return {"error":{"class":"GenericError"}}
  if c=="query-pci":return {"return":[{"bus":0,"devices":[{"bus":0,"slot":7,"qdev_id":"amnezia-link-rp","class_info":{"class":1540,"desc":"PCI bridge"}}]}]}
  if c=="qom-list":return {"return":[{"name":"type","type":"string"}]}
  if c=="qom-get":return {"return":31 if a["property"]=="chassis" else 30}
  return {"return":{}}
class Qga:
 def guest_exec_wait(self,exe,args,timeout):
  code=args[1]
  if "default routes did not reach" in code:
   routes=[{"family":"6","dst":"default","gateway":"fe80::2","dev":"enp0s2","protocol":"ra","metric":100,"pref":"medium"}] if args[2]=="true" else []
   interfaces=[{"dev":"enp0s2","mac":"52:54:00:12:34:56","configured":True,"address_ready":True,"address_json":[]}] if args[2]=="true" else []
   return {"exitcode":0,"stdout":json.dumps({"stable":True,"sample_count":4,"poll_count":6,"routes":routes,"interfaces":interfaces,"raw_samples":[]})}
  if "10-amnezia-" in code:
   path,mac,action=args[2:5]
   content=PrivateQemuLink._policy_bytes(mac);bound={"path":path,"mac":mac,"sha256":hashlib.sha256(content).hexdigest(),"size":len(content),"dev":1,"inode":2,"uid":0,"mode":"0644"}
   routes=[{"family":"6","dst":"default","gateway":"fe80::2","dev":"enp0s2","protocol":"ra","metric":100,"pref":"medium"}] if path.endswith('-server.network') else []
   if action=="install":return {"exitcode":0,"stdout":json.dumps({**bound,"default_routes":routes,"default_routes_raw":routes,"installed":True})}
   return {"exitcode":0,"stdout":json.dumps({**bound,"removed":True,"default_routes":routes,"default_routes_raw":routes,"defaults_unchanged":True})}
  if "urllib.request" in code:return {"exitcode":0,"stdout":json.dumps({"method":"GET","path":"/manifest.json","status":200,"sha256":plan().http_objects[0].sha256,"bytes":8,"content_length":"8","eof":True,"observed_at":1})}
  if "application mapping postcondition" in code:
   mac,role,action,application,gateway,defaults=args[2:8]
   return {"exitcode":0,"stdout":json.dumps({"role":role,"action":action,"ifname":"eth1","mac":mac,"application_address":application,"gateway":gateway,"default_routes":json.loads(defaults),"addresses":[],"application_routes":[],"present":action=="up"})}
  if "'/usr/bin/ping'" in code:
   address,dev,source,peer=args[2:6];return {"exitcode":0,"stdout":json.dumps({"address":address,"device":dev,"source":source,"peer_mac":peer,"exit_code":0,"route_get":[{"dst":address,"dev":dev,"prefsrc":source,"flags":[],"uid":0,"cache":[]}],"neighbors":[{"dst":address,"lladdr":peer,"state":["REACHABLE"]}],"verified":True,"observed_at":1789300800.7876742})}
  address=args[3];ip,prefix=address.split('/');network=str(__import__('ipaddress').ip_interface(address).network)
  defaults=[{"family":"6","dst":"default","gateway":"fe80::2","dev":"enp0s2","protocol":"ra","metric":100,"pref":"medium"}] if args[2].endswith(':01') else []
  return {"exitcode":0,"stdout":json.dumps({"ifname":"eth1","ifindex":4,"mac":args[2],"address":address,"action":args[4],"ip_json":[{"ifname":"eth1","addr_info":[{"family":"inet","local":ip,"prefixlen":int(prefix)}]}],"connected_routes":[{"family":"4","dst":network,"dev":"eth1"}],"default_routes":defaults,"routes_raw":defaults})}
class BadHttpQga(Qga):
 def guest_exec_wait(self,exe,args,timeout):
  value=super().guest_exec_wait(exe,args,timeout)
  if "urllib.request" in args[1]:value["stdout"]=json.dumps({"status":200,"sha256":"0"*64,"bytes":8,"eof":True})
  return value
def harness(change=False,fail=None):
 p=plan(); state={"exists":False,"owned_parent":True}
 def sock(_):return dict(state)
 sq,oq=Qmp(fail),Qmp()
 def remove(_,expected):
  assert expected.get("is_socket") is True;state.update(exists=False);return {"removed":True}
 link=PrivateQemuLink(p,sq,oq,Qga(),Qga(),lambda:binding("server-router",99) if change else p.server_binding,lambda:p.outer_binding,sock,remove)
 orig=link._qmp
 def qmp(*a,**k):
  value=orig(*a,**k)
  if a[1]=="netdev_add" and a[0]=="server":state.update(exists=True,is_socket=True,inode=44,listener_pid=2,listener_start_ticks="20")
  return value
 link._qmp=qmp
 return link,sq,oq
def test_happy_start_probe_cleanup_exact_qmp_order():
 link,sq,oq=harness(); receipt=link.start_and_probe();assert receipt["ready"] is True and receipt["http"][0]["sha256"]==plan().http_objects[0].sha256
 assert receipt["application_links"]["server"]["application_address"]=="10.8.1.0/32"
 assert receipt["application_links"]["outer"]["gateway"]=="172.31.40.1"
 clean=link.cleanup();assert clean["clean"] is True
 assert [x[0] for x in sq.calls]==["query-pci","qom-list","qom-get","qom-get","netdev_add","device_add","device_del","netdev_del"]
 assert sq.calls[4][1]=={"type":"stream","id":"lnk-s","addr":{"type":"unix","path":plan().socket_path},"server":True}
 assert sq.calls[5][1]["bus"]=="amnezia-link-rp"
 assert oq.calls[4][1]["server"] is False and oq.calls[4][1]["addr"]=={"type":"unix","path":plan().socket_path}
 assert oq.calls[5][1]["bus"]=="amnezia-link-rp"
def test_identity_change_blocks_before_mutation():
 link,sq,_=harness(change=True)
 with pytest.raises(PrivateLinkError,match="ownership changed"):link.start_and_probe()
 assert sq.calls==[]
def test_qmp_error_rejected_and_cleanup_attempted():
 link,sq,_=harness(fail="device_add")
 with pytest.raises(PrivateLinkError,match="device_add failed"):link.start_and_probe()
 assert any(x[0]=="netdev_del" for x in sq.calls)
def test_path_and_endpoint_fail_closed():
 p=plan(); object.__setattr__(p,"socket_path","/var/lib/amnezia-release-lab/runs/run/n/../escape")
 with pytest.raises(PrivateLinkError,match="unsafe QEMU"):p.validate()
 p=plan();object.__setattr__(p,"endpoint","http://127.0.0.1:17865")
 with pytest.raises(PrivateLinkError,match="endpoint"):p.validate()
def test_guest_deadline_rejected_before_transport():
 link,_,_=harness()
 with pytest.raises(PrivateLinkError,match="deadline expired"):link._guest("outer","",[],0)
def test_bad_http_receipt_cannot_claim_link_ready():
 link,_,_=harness();link.oqga=BadHttpQga()
 with pytest.raises(PrivateLinkError,match="HTTP receipt binding") as failure:link.start_and_probe()
 assert link.last_failure["phase"]=="http" and link.last_failure["expected"]["path"]=="/manifest.json"
 assert '"observed"' in str(failure.value) and '"qmp_transcript"' in str(failure.value)

def test_http_failure_archive_precedes_qmp_cleanup():
 link,sq,_=harness();link.oqga=BadHttpQga();events=[]
 original=sq.request
 def request(command,args):events.append("cleanup" if command in {"device_del","netdev_del"} else command);return original(command,args)
 sq.request=request
 def archive(record):
  assert not any(x=="cleanup" for x in events);events.append("archive")
  return {"origin":"controller","immutable":True,"path":"/owned/failure.json","sha256":"f"*64,"size":123}
 link.failure_archive=archive
 with pytest.raises(PrivateLinkError) as failure:link.start_and_probe()
 assert events.index("archive")<events.index("cleanup") and link.last_failure["archive"]["immutable"] is True
 assert any("failure archive" in note for note in getattr(failure.value,"__notes__",[]))
def test_qga_missing_exitcode_and_malformed_link_are_rejected():
 link,_,_=harness();link.sqga=type("Missing",(),{"guest_exec_wait":lambda *_a,**_k:{"stdout":"{}"}})()
 with pytest.raises(PrivateLinkError,match="QGA server command failed"):link.start_and_probe()

def test_missing_or_wrong_root_port_blocks_before_netdev_mutation():
 link,sq,_=harness()
 original=sq.request
 sq.request=lambda c,a: {"return":[]} if c=="query-pci" else original(c,a)
 with pytest.raises(PrivateLinkError,match="root port missing"):link.start_and_probe()
 assert not any(c in {"netdev_add","device_add"} for c,_ in sq.calls)

def test_wrong_qom_slot_blocks_before_netdev_mutation():
 link,sq,_=harness(); original=sq.request
 sq.request=lambda c,a: {"return":29} if c=="qom-get" and a["property"]=="slot" else original(c,a)
 with pytest.raises(PrivateLinkError,match="slot differs"):link.start_and_probe()
 assert not any(c in {"netdev_add","device_add"} for c,_ in sq.calls)

def test_route_flap_timeout_blocks_before_qmp_mutation():
 link,sq,_=harness();base=link.sqga
 class Flap(Qga):
  def guest_exec_wait(self,exe,args,timeout):
   if "default routes did not reach" in args[1]:return {"exitcode":1,"stdout":"","stderr":"default routes did not reach configured stable baseline"}
   return base.guest_exec_wait(exe,args,timeout)
 link.sqga=Flap()
 with pytest.raises(PrivateLinkError,match="QGA server command failed"):link.start_and_probe()
 assert not any(c in {"netdev_add","device_add"} for c,_ in sq.calls)

def test_stability_probe_is_dual_stack_and_one_deadline_for_all_interfaces():
 source=private_link_module._DEFAULT_STABLE
 assert "for family in ('-4','-6')" in source
 assert "deadline=time.monotonic()+float(sys.argv[3])" in source
 assert "timeout=max(.1,min(2,left))" in source
 assert "if p.name in default_devs:" in source
 assert "time.sleep(min(.5,left))" in source

def test_neighbor_scoped_command_allows_missing_dev_but_rejects_wrong_present_dev():
 link,_,_=harness();assert link.start_and_probe()["ping"]["neighbors"][0].get("dev") is None;link.cleanup()
 link,_,_=harness();base=link.oqga
 class Wrong(Qga):
  def guest_exec_wait(self,exe,args,timeout):
   raw=base.guest_exec_wait(exe,args,timeout)
   if "'/usr/bin/ping'" in args[1]:
    value=json.loads(raw["stdout"]);value["neighbors"][0]["dev"]="wrong0";value["verified"]=False;raw["stdout"]=json.dumps(value)
   return raw
 link.oqga=Wrong()
 with pytest.raises(PrivateLinkError,match="QGA outer command failed|ping failed"):link.start_and_probe()

def test_failed_neighbor_state_cannot_claim_connectivity():
 link,_,_=harness();base=link.oqga
 class Failed(Qga):
  def guest_exec_wait(self,exe,args,timeout):
   raw=base.guest_exec_wait(exe,args,timeout)
   if "'/usr/bin/ping'" in args[1]:
    value=json.loads(raw["stdout"]);value["neighbors"][0]["state"]=["FAILED"];value["verified"]=False;raw["stdout"]=json.dumps(value);raw["exitcode"]=1
   return raw
 link.oqga=Failed()
 with pytest.raises(PrivateLinkError,match="QGA outer command failed"):link.start_and_probe()

def test_application_host_route_spelling_and_partial_failure_are_transactional():
 assert "ipaddress.ip_network(x['dst'],strict=False)==app.network" in private_link_module._APPLICATION_ROUTE
 link,_,_=harness();events=[];original=link._guest
 def guest(role,code,args,timeout):
  value=original(role,code,args,timeout)
  if code==private_link_module._APPLICATION_ROUTE:
   events.append((role,args[2]))
   if role=="outer" and args[2]=="up":value["present"]=False
  return value
 link._guest=guest
 link.failure_archive=lambda record:(events.append(("archive",record["phase"])) or {"origin":"controller","immutable":True,"path":"/owned/failure.json","sha256":"f"*64,"size":123})
 with pytest.raises(PrivateLinkError,match="outer application mapping"):link.start_and_probe()
 assert events.index(("archive","application-mapping"))<events.index(("outer","down"))
 assert ("server","down") in events

def test_application_mapping_archive_rejection_preserves_partial_link():
 link,_,_=harness();events=[];original=link._guest
 def guest(role,code,args,timeout):
  value=original(role,code,args,timeout)
  if code==private_link_module._APPLICATION_ROUTE:
   events.append((role,args[2]))
   if role=="server" and args[2]=="up":value["present"]=False
  return value
 link._guest=guest;link.failure_archive=lambda _:{"immutable":False}
 with pytest.raises(PrivateLinkError) as caught:link.start_and_probe()
 assert not any(action=="down" for _,action in events)
 assert any("cleanup pending" in note for note in getattr(caught.value,"__notes__",[]))

@pytest.mark.parametrize("field,value",[("ip_json",[]),("connected_routes",[]),("address","172.31.40.9/30")])
def test_wrong_interface_route_or_address_cannot_claim_ready(field,value):
 link,_,_=harness();base=link.sqga
 class Bad(Qga):
  def guest_exec_wait(self,exe,args,timeout):
   raw=base.guest_exec_wait(exe,args,timeout)
   if "ipaddress" in args[1] and args[4]=="up":
    receipt=json.loads(raw["stdout"]);receipt[field]=value;raw["stdout"]=json.dumps(receipt)
   return raw
 link.sqga=Bad()
 with pytest.raises(PrivateLinkError,match="receipt binding|address/route proof"):link.start_and_probe()
