"""Owned, guest-only Ethernet link between two release-lab QEMU guests.

The controller supplies already ownership-checked QMP/QGA transports and live
snapshot callbacks.  This module never creates a host interface or changes a
host route; QEMU's socket netdev carries Ethernet frames over one owned Unix
socket and addresses exist only inside the two guests.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import re
import time
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any, Callable, Mapping, Sequence


class PrivateLinkError(RuntimeError):
    pass


_ID = re.compile(r"[a-z][a-z0-9-]{2,31}")
_NONCE = re.compile(r"[0-9a-f]{48}")
_SHA = re.compile(r"[0-9a-f]{64}")


def _binding(value: Mapping[str, Any], profile: str, run_id: str) -> dict[str, Any]:
    start = value.get("start_ticks", value.get("proc_start_time"))
    out = {"run_id": value.get("run_id"), "profile": value.get("profile"),
           "marker": value.get("marker"), "pid": value.get("pid"),
           "start_ticks": str(start), "uid": value.get("uid"),
           "uuid": value.get("uuid"), "qmp_socket": value.get("qmp_socket"),
           "qga_socket": value.get("qga_socket")}
    if (out["run_id"] != run_id or out["profile"] != profile
            or out["marker"] != f"amnezia-release-lab:{run_id}:{profile}"
            or isinstance(out["pid"], bool) or not isinstance(out["pid"], int) or out["pid"] <= 1
            or not out["start_ticks"].isdigit() or int(out["start_ticks"]) <= 0
            or isinstance(out["uid"], bool) or not isinstance(out["uid"], int) or out["uid"] < 0
            or any(not isinstance(out[k], str) or not out[k] for k in ("uuid", "qmp_socket", "qga_socket"))):
        raise PrivateLinkError(f"invalid {profile} ownership binding")
    return out


@dataclass(frozen=True)
class HttpObject:
    path: str
    sha256: str
    size: int

    def validate(self) -> None:
        if not self.path.startswith("/") or ".." in PurePosixPath(self.path).parts:
            raise PrivateLinkError("unsafe HTTP path")
        if not _SHA.fullmatch(self.sha256) or isinstance(self.size, bool) or self.size <= 0:
            raise PrivateLinkError("invalid HTTP object binding")


@dataclass(frozen=True)
class PrivateLinkPlan:
    run_id: str
    attempt_nonce: str
    link_id: str
    socket_path: str
    server_profile: str
    outer_profile: str
    server_binding: Mapping[str, Any]
    outer_binding: Mapping[str, Any]
    server_mac: str
    outer_mac: str
    server_address: str
    outer_address: str
    endpoint: str
    http_objects: Sequence[HttpObject]
    root_port_id: str = "amnezia-link-rp"
    application_address: str = "10.8.1.0/32"

    def validate(self) -> None:
        if not _ID.fullmatch(self.run_id) or not _NONCE.fullmatch(self.attempt_nonce) or not _ID.fullmatch(self.link_id):
            raise PrivateLinkError("invalid link identity")
        if self.server_profile != "server-router" or self.outer_profile != "linux-headless-x64":
            raise PrivateLinkError("invalid link roles")
        if self.root_port_id != "amnezia-link-rp":
            raise PrivateLinkError("invalid private-link root port")
        _binding(self.server_binding, self.server_profile, self.run_id)
        _binding(self.outer_binding, self.outer_profile, self.run_id)
        root = PurePosixPath("/var/lib/amnezia-release-lab/runs") / self.run_id
        sock = PurePosixPath(self.socket_path)
        if not sock.is_absolute() or ".." in sock.parts or root not in sock.parents or len(self.socket_path.encode()) >= 100:
            raise PrivateLinkError("unsafe QEMU link socket")
        if len({self.server_mac.lower(), self.outer_mac.lower()}) != 2 or any(not re.fullmatch(r"02:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}", x) for x in (self.server_mac, self.outer_mac)):
            raise PrivateLinkError("invalid private MACs")
        s, o = ipaddress.ip_interface(self.server_address), ipaddress.ip_interface(self.outer_address)
        if s.version != 4 or s.network.prefixlen != 30 or o.network != s.network or s.ip == o.ip or not s.ip.is_private:
            raise PrivateLinkError("private link must use one private /30")
        app = ipaddress.ip_interface(self.application_address)
        if app.version != 4 or app.network.prefixlen != 32 or str(app.ip) != "10.8.1.0" or app.ip in s.network:
            raise PrivateLinkError("application endpoint address binding")
        expected = f"http://{app.ip}:17865"
        if self.endpoint != expected or not self.http_objects:
            raise PrivateLinkError("fixture endpoint binding")
        for item in self.http_objects:
            item.validate()


_GUEST_LINK = r'''import ipaddress,json,pathlib,subprocess,sys
mac,address,action=sys.argv[1:4];expected_routes=json.loads(sys.argv[4]) if len(sys.argv)>4 else None
matches=[]
for p in pathlib.Path('/sys/class/net').iterdir():
 try:
  if p.joinpath('address').read_text().strip().lower()==mac.lower(): matches.append(p.name)
 except OSError: pass
if len(matches)!=1: raise SystemExit('MAC interface cardinality')
name=matches[0]
def run(argv):
 r=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=10)
 if r.returncode: raise SystemExit(json.dumps({'argv':argv,'rc':r.returncode,'stderr':r.stderr[-2048:]}))
 return r.stdout
keys=('family','dst','gateway','dev','table','protocol','metric','pref')
def routes():
 raw=[]
 for family in ('-4','-6'):
  raw.extend([{**x,'family':family[1:]} for x in json.loads(run(['/usr/sbin/ip',family,'-j','route','show','table','all']))])
 return raw,[{k:x[k] for k in keys if k in x} for x in raw if x.get('dst')=='default']
routes_before,defaults_before=routes()
if action=='up':
 network=ipaddress.ip_interface(address).network
 all_addr=json.loads(run(['/usr/sbin/ip','-j','address','show']))
 for row in all_addr:
  for item in row.get('addr_info',[]):
   if item.get('family')=='inet' and ipaddress.ip_address(item['local']) in network: raise SystemExit('private subnet/address collision')
 for route in routes_before:
  dst=route.get('dst')
  if dst and dst!='default':
   try:
    candidate=ipaddress.ip_network(dst,strict=False)
    if candidate.version==network.version and candidate.overlaps(network): raise SystemExit('private subnet/route collision')
   except ValueError: raise SystemExit('unparseable existing route')
 run(['/usr/sbin/ip','link','set','dev',name,'up']);run(['/usr/sbin/ip','address','add',address,'dev',name])
elif action=='down':
 raw=run(['/usr/sbin/ip','-j','address','show','dev',name]); rows=json.loads(raw)
 present=any(x.get('local')==address.split('/')[0] and x.get('prefixlen')==int(address.split('/')[1]) for x in rows[0].get('addr_info',[]))
 if not present: raise SystemExit('owned address missing before cleanup')
 if defaults_before!=expected_routes: raise SystemExit('default routes changed before cleanup')
 run(['/usr/sbin/ip','address','del',address,'dev',name]);run(['/usr/sbin/ip','link','set','dev',name,'down'])
else: raise SystemExit('action')
routes_after,defaults_after=routes();network=str(ipaddress.ip_interface(address).network);connected=[x for x in routes_after if x.get('family')=='4' and x.get('dst')==network and x.get('dev')==name]
if defaults_after!=defaults_before: raise SystemExit('private link changed default routes')
raw=run(['/usr/sbin/ip','-j','address','show','dev',name]);print(json.dumps({'ifname':name,'ifindex':int(pathlib.Path('/sys/class/net',name,'ifindex').read_text()),'mac':mac.lower(),'address':address,'action':action,'ip_json':json.loads(raw),'connected_routes':connected,'default_routes':defaults_after,'routes_raw':routes_after},separators=(',',':')))
'''

_APPLICATION_ROUTE = r'''import ipaddress,json,pathlib,subprocess,sys
mac,role,action,application,gateway,expected_defaults=sys.argv[1:7];expected_defaults=json.loads(expected_defaults)
if role not in ('server','outer') or action not in ('up','down'): raise SystemExit('application route action')
app=ipaddress.ip_interface(application)
if app.version!=4 or app.network.prefixlen!=32 or str(app.ip)!='10.8.1.0': raise SystemExit('application address')
matches=[]
for p in pathlib.Path('/sys/class/net').iterdir():
 try:
  if p.joinpath('address').read_text().strip().lower()==mac.lower(): matches.append(p.name)
 except OSError: pass
if len(matches)!=1: raise SystemExit('MAC interface cardinality')
name=matches[0]
def run(argv):
 r=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=10)
 if r.returncode: raise SystemExit(json.dumps({'argv':argv,'rc':r.returncode,'stderr':r.stderr[-2048:]}))
 return r.stdout
keys=('family','dst','gateway','dev','table','protocol','metric','pref')
def state():
 addresses=json.loads(run(['/usr/sbin/ip','-j','address','show','dev',name]));routes=[]
 for family in ('-4','-6'): routes.extend([{**x,'family':family[1:]} for x in json.loads(run(['/usr/sbin/ip',family,'-j','route','show','table','all']))])
 defaults=[{k:x[k] for k in keys if k in x} for x in routes if x.get('dst')=='default']
 app_addresses=[x for row in addresses for x in row.get('addr_info',[]) if x.get('family')=='inet' and x.get('local')==str(app.ip) and x.get('prefixlen')==32]
 def is_app_route(x):
  if x.get('family')!='4' or not isinstance(x.get('dst'),str): return False
  try:return ipaddress.ip_network(x['dst'],strict=False)==app.network
  except ValueError:return False
 app_routes=[{k:x[k] for k in keys if k in x} for x in routes if is_app_route(x)]
 return addresses,routes,defaults,app_addresses,app_routes
before=state()
if before[2]!=expected_defaults: raise SystemExit('default routes changed before application mapping')
if action=='up':
 if before[3] or before[4]: raise SystemExit('application address/route collision')
 if role=='server': run(['/usr/sbin/ip','address','add',application,'dev',name])
 else:
  if str(ipaddress.ip_address(gateway))=='0.0.0.0': raise SystemExit('gateway')
  run(['/usr/sbin/ip','route','add',str(app.network),'via',gateway,'dev',name])
else:
 if role=='server':
  if len(before[3])>1: raise SystemExit('owned application address ambiguous')
  if before[3]: run(['/usr/sbin/ip','address','del',application,'dev',name])
 else:
  exact=[x for x in before[4] if x.get('gateway')==gateway and x.get('dev')==name]
  if len(exact)>1: raise SystemExit('owned application route ambiguous')
  if exact: run(['/usr/sbin/ip','route','del',str(app.network),'via',gateway,'dev',name])
after=state()
if after[2]!=expected_defaults: raise SystemExit('application mapping changed default routes')
present=(len(after[3])==1) if role=='server' else (len([x for x in after[4] if x.get('gateway')==gateway and x.get('dev')==name])==1)
if present!=(action=='up'): raise SystemExit('application mapping postcondition')
print(json.dumps({'role':role,'action':action,'ifname':name,'mac':mac.lower(),'application_address':application,'gateway':gateway,'default_routes':after[2],'addresses':after[0],'application_routes':after[4],'present':present},separators=(',',':')))
'''

_PING = r'''import json,subprocess,sys,time
address,dev,source,peer_mac=sys.argv[1:5];r=subprocess.run(['/usr/bin/ping','-n','-c','1','-W','5','-I',dev,address],capture_output=True,text=True,timeout=8)
route=subprocess.run(['/usr/sbin/ip','-j','route','get',address],capture_output=True,text=True,timeout=5);neigh=subprocess.run(['/usr/sbin/ip','-j','neigh','show','to',address,'dev',dev],capture_output=True,text=True,timeout=5)
routes=json.loads(route.stdout) if route.returncode==0 else [];neighbors=json.loads(neigh.stdout) if neigh.returncode==0 else []
def states(x):
 value=x.get('state');return [value] if isinstance(value,str) else value if isinstance(value,list) and all(isinstance(v,str) for v in value) else []
allowed={'REACHABLE','STALE','DELAY','PROBE','PERMANENT'}
ok=(r.returncode==0 and len(routes)==1 and routes[0].get('dev')==dev and routes[0].get('prefsrc')==source and any(x.get('dst')==address and x.get('dev') in (None,dev) and x.get('lladdr','').lower()==peer_mac and states(x) and set(states(x))<=allowed for x in neighbors))
print(json.dumps({'address':address,'device':dev,'source':source,'peer_mac':peer_mac,'exit_code':r.returncode,'route_get':routes,'neighbors':neighbors,'verified':ok,'observed_at':time.time()},separators=(',',':')));raise SystemExit(0 if ok else 1)
'''

_HTTP = r'''import hashlib,json,sys,time,urllib.error,urllib.request
base,path,expected,size=sys.argv[1],sys.argv[2],sys.argv[3],int(sys.argv[4]);h=hashlib.sha256();n=0
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
try:r=opener.open(base+path,timeout=10)
except urllib.error.HTTPError as exc:r=exc
with r:
 status=r.status; headers=dict(r.headers.items());limit=size if status==200 else 4096
 while True:
  b=r.read(65536)
  if not b: break
  n+=len(b)
  if n>limit: raise SystemExit('HTTP body exceeds bounded size')
  h.update(b)
print(json.dumps({'method':'GET','path':path,'status':status,'sha256':h.hexdigest(),'bytes':n,'content_length':headers.get('Content-Length'),'content_type':headers.get('Content-Type'),'eof':True,'observed_at':time.time()},separators=(',',':')))
'''

_NETWORKD_POLICY = r'''import hashlib,json,os,pathlib,re,stat,subprocess,sys
path=pathlib.PurePosixPath(sys.argv[1]);mac=sys.argv[2].lower();action=sys.argv[3];expected=json.loads(sys.argv[4]) if len(sys.argv)>4 else None
if path.parent!=pathlib.PurePosixPath('/run/systemd/network') or not re.fullmatch(r'10-amnezia-[0-9a-f]{48}-(server|outer)\.network',path.name): raise SystemExit('unsafe networkd policy path')
content=('[Match]\nMACAddress='+mac+'\n\n[Network]\nDHCP=no\nIPv6AcceptRA=no\nLinkLocalAddressing=no\nDNSDefaultRoute=no\nDefaultRouteOnDevice=no\n').encode()
digest=hashlib.sha256(content).hexdigest();parent=os.open(str(path.parent),os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
def defaults():
 raw=[]
 for family in ('-4','-6'):
  r=subprocess.run(['/usr/sbin/ip',family,'-j','route','show','table','all'],capture_output=True,text=True,timeout=10)
  if r.returncode: raise SystemExit('default route snapshot failed')
  raw.extend([{**x,'family':family[1:]} for x in json.loads(r.stdout) if x.get('dst')=='default'])
 keys=('family','dst','gateway','dev','table','protocol','metric','pref')
 return [{k:x[k] for k in keys if k in x} for x in raw],raw
if action=='install':
 before,before_raw=defaults();fd=os.open(path.name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644,dir_fd=parent)
 try:
  view=memoryview(content)
  while view:
   n=os.write(fd,view)
   if n<=0: raise OSError('short policy write')
   view=view[n:]
  os.fsync(fd);s=os.fstat(fd)
 finally: os.close(fd)
 os.fsync(parent);reload=subprocess.run(['/usr/bin/networkctl','reload'],capture_output=True,text=True,timeout=10)
 if reload.returncode:
  now=os.stat(path.name,dir_fd=parent,follow_symlinks=False)
  if (now.st_dev,now.st_ino)!=(s.st_dev,s.st_ino): raise SystemExit('networkd reload failed and policy identity changed')
  os.unlink(path.name,dir_fd=parent);os.fsync(parent);raise SystemExit('networkd reload failed; owned policy removed')
 out={'path':str(path),'mac':mac,'sha256':digest,'size':len(content),'dev':s.st_dev,'inode':s.st_ino,'uid':s.st_uid,'mode':format(s.st_mode&0o777,'04o'),'default_routes':before,'default_routes_raw':before_raw,'installed':True}
elif action=='remove':
 if not isinstance(expected,dict): raise SystemExit('policy removal binding missing')
 fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=parent);s=os.fstat(fd);data=b''
 while True:
  b=os.read(fd,65536)
  if not b: break
  data+=b
 os.close(fd)
 observed={'path':str(path),'mac':mac,'sha256':hashlib.sha256(data).hexdigest(),'size':len(data),'dev':s.st_dev,'inode':s.st_ino,'uid':s.st_uid,'mode':format(s.st_mode&0o777,'04o')}
 if any(observed.get(k)!=expected.get(k) for k in observed): raise SystemExit('networkd policy identity changed')
 os.unlink(path.name,dir_fd=parent);os.fsync(parent);reload=subprocess.run(['/usr/bin/networkctl','reload'],capture_output=True,text=True,timeout=10)
 if reload.returncode: raise SystemExit('networkd cleanup reload failed')
 after,after_raw=defaults();out={**observed,'removed':True,'default_routes':after,'default_routes_raw':after_raw,'defaults_unchanged':after==expected.get('default_routes')}
else: raise SystemExit('policy action')
os.close(parent);print(json.dumps(out,separators=(',',':')))
'''

_DEFAULT_STABLE = r'''import json,pathlib,subprocess,sys,time
require_default=sys.argv[1]=='true';forbidden_mac=sys.argv[2].lower();deadline=time.monotonic()+float(sys.argv[3]);samples=[];stable=[];interfaces=[];keys=('family','dst','gateway','dev','table','protocol','metric','pref')
def run(argv):
 left=deadline-time.monotonic()
 if left<=0: raise SystemExit('default route stability deadline expired')
 return subprocess.run(argv,capture_output=True,text=True,timeout=max(.1,min(2,left)))
while time.monotonic()<deadline:
 raw=[]
 for family in ('-4','-6'):
  r=run(['/usr/sbin/ip',family,'-j','route','show','table','all'])
  if r.returncode: raise SystemExit('default route snapshot failed')
  raw.extend([{**x,'family':family[1:]} for x in json.loads(r.stdout) if x.get('dst')=='default'])
 routes=[{k:x[k] for k in keys if k in x} for x in raw];bound=[];default_devs={}
 for row in routes:
  dev=row.get('dev')
  if not isinstance(dev,str) or not dev: raise SystemExit('default route lacks interface')
  mac=pathlib.Path('/sys/class/net',dev,'address').read_text().strip().lower()
  if mac==forbidden_mac: raise SystemExit('future private MAC already owns a default route')
  bound.append({'route':row,'dev':dev,'mac':mac});default_devs.setdefault(dev,set()).add(row['family'])
 interfaces=[]
 for p in pathlib.Path('/sys/class/net').iterdir():
  if p.name=='lo': continue
  mac=p.joinpath('address').read_text().strip().lower()
  if mac==forbidden_mac: raise SystemExit('future private MAC already exists')
  item={'dev':p.name,'mac':mac,'default_families':sorted(default_devs.get(p.name,set())),'configured':None,'address_ready':None,'address_json':[]}
  if p.name in default_devs:
   status=run(['/usr/bin/networkctl','status','--no-pager',p.name]);addr=run(['/usr/sbin/ip','-j','address','show','dev',p.name]);addr_rows=json.loads(addr.stdout) if addr.returncode==0 else []
   info=[x for row in addr_rows for x in row.get('addr_info',[])];families=default_devs[p.name]
   item.update(configured=status.returncode==0 and '(configured)' in status.stdout,address_ready=all(any(x.get('family')==('inet' if f=='4' else 'inet6') and x.get('scope')!='host' for x in info) for f in families),address_json=addr_rows)
  interfaces.append(item)
 ready=(not require_default or (bound and all(any(i['dev']==x['dev'] and i['configured'] is True and i['address_ready'] is True for i in interfaces) for x in bound)))
 stable=stable+[bound] if ready and (not stable or bound==stable[-1]) else ([bound] if ready else [])
 samples.append({'raw':raw,'semantic':bound})
 if len(stable)>=4: break
 left=deadline-time.monotonic()
 if left>0: time.sleep(min(.5,left))
if len(stable)<4: raise SystemExit('default routes did not reach configured stable baseline')
print(json.dumps({'stable':True,'sample_count':len(stable),'poll_count':len(samples),'routes':[x['route'] for x in stable[-1]],'interfaces':interfaces,'raw_samples':samples[-4:]},separators=(',',':')))
'''


class PrivateQemuLink:
    def __init__(self, plan: PrivateLinkPlan, server_qmp: Any, outer_qmp: Any,
                 server_qga: Any, outer_qga: Any,
                 server_snapshot: Callable[[], Mapping[str, Any]],
                 outer_snapshot: Callable[[], Mapping[str, Any]],
                 socket_snapshot: Callable[[str], Mapping[str, Any]],
                 remove_owned_socket: Callable[[str, Mapping[str, Any]], Mapping[str, Any]],
                 *, failure_archive: Callable[[Mapping[str,Any]],Mapping[str,Any]]|None=None, clock=time.monotonic, sleep=time.sleep):
        plan.validate(); self.p = plan; self.sqmp = server_qmp; self.oqmp = outer_qmp
        self.sqga = server_qga; self.oqga = outer_qga; self.ss = server_snapshot; self.os = outer_snapshot
        self.sock = socket_snapshot; self.remove_socket = remove_owned_socket; self.clock = clock; self.sleep = sleep
        self.failure_archive = failure_archive
        self.events: list[dict[str, Any]] = []; self.added: list[tuple[str, str]] = []; self.devices: set[tuple[str, str]] = set(); self.socket_live: Mapping[str, Any] | None = None
        self.server_link: Mapping[str, Any] | None = None; self.outer_link: Mapping[str, Any] | None = None
        self.application_links: dict[str, Mapping[str, Any]] = {}
        self.policies: dict[str, Mapping[str, Any]] = {}
        self.route_baselines: dict[str, Mapping[str, Any]] = {}
        self.last_failure: Mapping[str, Any] | None = None
        self.last_guest_failure: Mapping[str, Any] | None = None
        self.sb = _binding(plan.server_binding, plan.server_profile, plan.run_id)
        self.ob = _binding(plan.outer_binding, plan.outer_profile, plan.run_id)

    def _check(self) -> None:
        if _binding(self.ss(), self.p.server_profile, self.p.run_id) != self.sb or _binding(self.os(), self.p.outer_profile, self.p.run_id) != self.ob:
            raise PrivateLinkError("QEMU ownership changed")

    @staticmethod
    def _policy_bytes(mac: str) -> bytes:
        return (f"[Match]\nMACAddress={mac.lower()}\n\n[Network]\nDHCP=no\nIPv6AcceptRA=no\nLinkLocalAddressing=no\n"
                "DNSDefaultRoute=no\nDefaultRouteOnDevice=no\n").encode()

    def _qmp(self, role: str, execute: str, arguments: Mapping[str, Any]) -> Any:
        self._check(); q = self.sqmp if role == "server" else self.oqmp
        raw = q.request(execute, arguments); self._check()
        if not isinstance(raw, Mapping) or "error" in raw or "return" not in raw:
            raise PrivateLinkError(f"QMP {role} {execute} failed: {raw!r}")
        self.events.append({"role": role, "execute": execute, "arguments": dict(arguments), "response": dict(raw)})
        return raw["return"]

    def _root_port(self, role: str) -> None:
        pci = self._qmp(role, "query-pci", {})
        if not isinstance(pci, list):
            raise PrivateLinkError(f"QMP {role} PCI inventory is invalid")
        devices = [device for bus in pci if isinstance(bus, Mapping) for device in bus.get("devices", []) if isinstance(device, Mapping)]
        matches = [device for device in devices if device.get("qdev_id") == self.p.root_port_id]
        if (len(matches) != 1 or matches[0].get("bus") != 0
                or not isinstance(matches[0].get("class_info"), Mapping)
                or matches[0]["class_info"].get("class") != 1540):
            raise PrivateLinkError(f"QMP {role} private-link root port missing")
        qom = self._qmp(role, "qom-list", {"path": f"/machine/peripheral/{self.p.root_port_id}"})
        if not isinstance(qom, list) or not qom:
            raise PrivateLinkError(f"QMP {role} private-link root port QOM identity missing")
        chassis = self._qmp(role, "qom-get", {"path": f"/machine/peripheral/{self.p.root_port_id}", "property": "chassis"})
        if isinstance(chassis, bool) or chassis != 31:
            raise PrivateLinkError(f"QMP {role} private-link root port chassis differs")
        slot = self._qmp(role, "qom-get", {"path": f"/machine/peripheral/{self.p.root_port_id}", "property": "slot"})
        if isinstance(slot, bool) or slot != 30:
            raise PrivateLinkError(f"QMP {role} private-link root port slot differs")

    def _guest(self, role: str, code: str, args: list[str], timeout: float) -> dict[str, Any]:
        if isinstance(timeout, bool) or not isinstance(timeout, (int,float)) or not math.isfinite(timeout) or timeout <= 0:
            raise PrivateLinkError("private-link deadline expired")
        self.last_guest_failure=None;self._check(); q = self.sqga if role == "server" else self.oqga
        raw = q.guest_exec_wait("/usr/bin/python3", ["-c", code, *args], timeout=max(1, int(timeout))); self._check()
        if (not isinstance(raw, Mapping) or isinstance(raw.get("exitcode"), bool)
                or raw.get("exitcode") != 0):
            stdout=str(raw.get("stdout","")) if isinstance(raw,Mapping) else "";stderr=str(raw.get("stderr","")) if isinstance(raw,Mapping) else ""
            self.last_guest_failure={"role":role,"exit_code":raw.get("exitcode") if isinstance(raw,Mapping) else None,
                "stdout_size":len(stdout.encode()),"stdout_sha256":hashlib.sha256(stdout.encode()).hexdigest(),"stdout_excerpt":stdout[-4096:],
                "stderr_size":len(stderr.encode()),"stderr_sha256":hashlib.sha256(stderr.encode()).hexdigest(),"stderr_excerpt":stderr[-4096:]}
            raise PrivateLinkError(f"QGA {role} command failed")
        try: value = json.loads(raw.get("stdout", ""))
        except Exception as exc: raise PrivateLinkError(f"QGA {role} receipt missing") from exc
        if not isinstance(value, dict): raise PrivateLinkError("QGA receipt shape")
        return value

    @staticmethod
    def _link_receipt(value: Mapping[str, Any], mac: str, address: str, action: str) -> None:
        if (value.get("mac") != mac or value.get("address") != address or value.get("action") != action
                or not isinstance(value.get("ifname"),str) or not value["ifname"]
                or isinstance(value.get("ifindex"),bool) or not isinstance(value.get("ifindex"),int) or value["ifindex"]<=0
                or not isinstance(value.get("ip_json"),list) or not isinstance(value.get("connected_routes"),list) or not isinstance(value.get("default_routes"),list)):
            raise PrivateLinkError("guest private-link receipt binding")
        ip=ipaddress.ip_interface(address); rows=value["ip_json"]
        addresses=[item for row in rows if isinstance(row,Mapping) and row.get("ifname")==value["ifname"] for item in row.get("addr_info",[]) if isinstance(item,Mapping)]
        connected=[row for row in value["connected_routes"] if isinstance(row,Mapping)]
        if action=="up" and (not any(item.get("family")=="inet" and item.get("local")==str(ip.ip) and item.get("prefixlen")==ip.network.prefixlen for item in addresses)
                or len(connected)!=1 or connected[0].get("dst")!=str(ip.network) or connected[0].get("dev")!=value["ifname"]):
            raise PrivateLinkError("guest private-link address/route proof")

    def start_and_probe(self, timeout: float = 60) -> dict[str, Any]:
        if isinstance(timeout, bool) or not isinstance(timeout,(int,float)) or not math.isfinite(timeout) or timeout <= 0 or timeout > 300: raise PrivateLinkError("invalid deadline")
        end = self.clock() + timeout; self._check()
        self._root_port("server"); self._root_port("outer")
        before = self.sock(self.p.socket_path)
        if before.get("exists") is not False or before.get("owned_parent") is not True: raise PrivateLinkError("link socket precondition")
        sid, oid = self.p.link_id + "-s", self.p.link_id + "-o"
        try:
            for role,mac in (("server",self.p.server_mac),("outer",self.p.outer_mac)):
                left=end-self.clock();stable=self._guest(role,_DEFAULT_STABLE,["true" if role=="server" else "false",mac,str(max(.1,min(20,left)))],left)
                if (stable.get("stable") is not True or stable.get("sample_count")!=4
                        or not isinstance(stable.get("routes"),list) or not isinstance(stable.get("interfaces"),list)
                        or (role=="server" and (not stable["routes"] or not any(isinstance(x,Mapping) and x.get("configured") is True and x.get("address_ready") is True and isinstance(x.get("address_json"),list) for x in stable["interfaces"])) )):
                    raise PrivateLinkError(f"{role} default-route baseline is not stable")
                self.route_baselines[role]=stable
                policy_path=f"/run/systemd/network/10-amnezia-{self.p.attempt_nonce}-{role}.network"
                policy=self._guest(role,_NETWORKD_POLICY,[policy_path,mac,"install"],end-self.clock())
                policy_bytes=self._policy_bytes(mac)
                if (policy.get("path")!=policy_path or policy.get("mac")!=mac or policy.get("installed") is not True
                        or policy.get("uid")!=0 or policy.get("mode")!="0644"
                        or policy.get("sha256")!=hashlib.sha256(policy_bytes).hexdigest() or policy.get("size")!=len(policy_bytes)
                        or isinstance(policy.get("dev"),bool) or not isinstance(policy.get("dev"),int) or policy["dev"]<=0
                        or isinstance(policy.get("inode"),bool) or not isinstance(policy.get("inode"),int) or policy["inode"]<=0
                        or not isinstance(policy.get("default_routes"),list)):
                    raise PrivateLinkError(f"{role} networkd policy receipt binding")
                if policy["default_routes"]!=stable["routes"]:
                    raise PrivateLinkError(f"{role} default routes changed while installing policy")
                self.policies[role]=policy
            addr={"type":"unix","path":self.p.socket_path}
            self._qmp("server", "netdev_add", {"type":"stream","id":sid,"addr":addr,"server":True}); self.added.append(("server", sid))
            self._qmp("server", "device_add", {"driver":"virtio-net-pci","id":sid,"netdev":sid,"mac":self.p.server_mac,"bus":self.p.root_port_id}); self.devices.add(("server",sid))
            self._qmp("outer", "netdev_add", {"type":"stream","id":oid,"addr":addr,"server":False}); self.added.append(("outer", oid))
            self._qmp("outer", "device_add", {"driver":"virtio-net-pci","id":oid,"netdev":oid,"mac":self.p.outer_mac,"bus":self.p.root_port_id}); self.devices.add(("outer",oid))
            socket_live = self.sock(self.p.socket_path); self.socket_live = dict(socket_live)
            if (socket_live.get("exists") is not True or socket_live.get("is_socket") is not True
                    or isinstance(socket_live.get("inode"),bool) or not isinstance(socket_live.get("inode"),int) or socket_live["inode"]<=0
                    or socket_live.get("listener_pid")!=self.sb["pid"] or str(socket_live.get("listener_start_ticks"))!=self.sb["start_ticks"]):
                raise PrivateLinkError("owned link socket missing")
            sr = self._guest("server", _GUEST_LINK, [self.p.server_mac,self.p.server_address,"up"], end-self.clock());self._link_receipt(sr,self.p.server_mac,self.p.server_address,"up");self.server_link=sr
            ore = self._guest("outer", _GUEST_LINK, [self.p.outer_mac,self.p.outer_address,"up"], end-self.clock());self._link_receipt(ore,self.p.outer_mac,self.p.outer_address,"up");self.outer_link=ore
            server_ip=str(ipaddress.ip_interface(self.p.server_address).ip);outer_ip=str(ipaddress.ip_interface(self.p.outer_address).ip)
            for role,mac,link in (("server",self.p.server_mac,sr),("outer",self.p.outer_mac,ore)):
                try:
                    mapped=self._guest(role,_APPLICATION_ROUTE,[mac,role,"up",self.p.application_address,server_ip,json.dumps(link["default_routes"],separators=(',',':'))],end-self.clock())
                    self.application_links[role]=mapped
                    if (mapped.get("role")!=role or mapped.get("action")!="up" or mapped.get("mac")!=mac or mapped.get("application_address")!=self.p.application_address
                            or mapped.get("gateway")!=server_ip or mapped.get("present") is not True or mapped.get("default_routes")!=link["default_routes"]):
                        raise PrivateLinkError(f"{role} application mapping receipt binding")
                except BaseException as mapping_error:
                    self.last_failure={"schema":1,"operation":"nested-private-qemu-link-failure","run_id":self.p.run_id,"attempt_nonce":self.p.attempt_nonce,
                        "phase":"application-mapping","role":role,"application_address":self.p.application_address,"gateway":server_ip,
                        "link_identity":{"server":{k:sr.get(k) for k in ("ifname","ifindex","mac","address","default_routes")},"outer":{k:ore.get(k) for k in ("ifname","ifindex","mac","address","default_routes")}},
                        "guest_failure":dict(self.last_guest_failure) if isinstance(self.last_guest_failure,Mapping) else None,
                        "error_type":type(mapping_error).__name__,"error_sha256":hashlib.sha256(str(mapping_error).encode()).hexdigest(),"qmp_transcript":self.events.copy()}
                    raise
            ping=self._guest("outer",_PING,[server_ip,str(ore["ifname"]),outer_ip,self.p.server_mac],end-self.clock())
            if (ping.get("address")!=server_ip or ping.get("device")!=ore["ifname"] or ping.get("source")!=outer_ip
                    or ping.get("peer_mac")!=self.p.server_mac or ping.get("exit_code")!=0 or ping.get("verified") is not True
                    or not isinstance(ping.get("route_get"),list) or not isinstance(ping.get("neighbors"),list)):
                raise PrivateLinkError("outer-to-server private-link ping failed")
            probes=[]
            for x in self.p.http_objects:
                probe=self._guest("outer", _HTTP, [self.p.endpoint,x.path,x.sha256,str(x.size)], end-self.clock())
                try: content_length=int(probe.get("content_length",-1))
                except (TypeError,ValueError): content_length=-1
                if (probe.get("method")!="GET" or probe.get("path")!=x.path or probe.get("status")!=200
                        or probe.get("sha256")!=x.sha256 or probe.get("bytes")!=x.size or probe.get("eof") is not True
                        or isinstance(probe.get("content_length"),bool) or content_length!=x.size):
                    diagnostic={k:probe.get(k) for k in ("method","path","status","sha256","bytes","content_length","content_type","eof","observed_at")}
                    self.last_failure={"schema":1,"operation":"nested-private-qemu-link-failure","run_id":self.p.run_id,
                        "attempt_nonce":self.p.attempt_nonce,"phase":"http","expected":{"path":x.path,"sha256":x.sha256,"size":x.size},
                        "observed":diagnostic,"ping":ping,"qmp_transcript":self.events.copy()}
                    raise PrivateLinkError("outer HTTP receipt binding: "+json.dumps(self.last_failure,sort_keys=True,separators=(",",":")))
                probes.append(probe)
            return {"schema":1,"operation":"nested-private-qemu-link","run_id":self.p.run_id,"attempt_nonce":self.p.attempt_nonce,
                    "origin":"guest","transport":"qmp-qga","injected":False,"server_ownership":self.sb,"outer_ownership":self.ob,
                    "socket":socket_live,"route_baselines":dict(self.route_baselines),"networkd_policies":dict(self.policies),"server_link":sr,"outer_link":ore,"application_links":dict(self.application_links),"ping":ping,"http":probes,"qmp_transcript":self.events.copy(),"ready":True}
        except BaseException as primary:
            archive_durable=False
            if self.last_failure is not None and self.failure_archive is not None:
                try:
                    archive=self.failure_archive(self.last_failure)
                    if (not isinstance(archive,Mapping) or archive.get("origin")!="controller" or archive.get("immutable") is not True
                            or not _SHA.fullmatch(str(archive.get("sha256",""))) or isinstance(archive.get("size"),bool) or not isinstance(archive.get("size"),int) or archive["size"]<=0):
                        raise PrivateLinkError("controller failure archive acknowledgement invalid")
                    self.last_failure={**self.last_failure,"archive":dict(archive)}
                    archive_durable=True
                    if hasattr(primary,"add_note"):primary.add_note("private-link failure archive: "+json.dumps(archive,sort_keys=True,separators=(",",":")))
                except BaseException as archive_error:
                    if hasattr(primary,"add_note"):primary.add_note(f"private-link failure archive also failed: {archive_error!r}")
            if self.last_failure is None or archive_durable:
                try: self.cleanup(min(30, max(1, end-self.clock())))
                except BaseException as cleanup: primary.add_note(f"private-link cleanup also failed: {cleanup}")
            else:
                if hasattr(primary,"add_note"):primary.add_note("private-link cleanup pending because no durable controller failure archive")
            raise

    def cleanup(self, timeout: float = 30) -> dict[str, Any]:
        end=self.clock()+timeout; errors=[]; application_cleanup={}
        server_ip=str(ipaddress.ip_interface(self.p.server_address).ip)
        for role,mac,link in (("outer",self.p.outer_mac,self.outer_link),("server",self.p.server_mac,self.server_link)):
            if link is None: continue
            try:
                value=self._guest(role,_APPLICATION_ROUTE,[mac,role,"down",self.p.application_address,server_ip,json.dumps(link.get("default_routes"),separators=(',',':'))],end-self.clock())
                if value.get("role")!=role or value.get("action")!="down" or value.get("present") is not False or value.get("default_routes")!=link.get("default_routes"):raise PrivateLinkError("application mapping cleanup proof")
                application_cleanup[role]=value
            except BaseException as e:errors.append(f"{role} application mapping: {e}")
        for role,mac,address,receipt in (("outer",self.p.outer_mac,self.p.outer_address,self.outer_link),("server",self.p.server_mac,self.p.server_address,self.server_link)):
            if receipt is None: continue
            try:
                value=self._guest(role,_GUEST_LINK,[mac,address,"down",json.dumps(receipt.get("default_routes"),separators=(',',':'))],end-self.clock())
                self._link_receipt(value,mac,address,"down")
            except BaseException as e:errors.append(f"{role} address: {e}")
        for role,nid in reversed(self.added):
            if (role,nid) in self.devices:
                try:self._qmp(role,"device_del",{"id":nid})
                except BaseException as e:errors.append(f"{role} device: {e}")
            while True:
                try:self._qmp(role,"netdev_del",{"id":nid});break
                except BaseException as e:
                    if self.clock()>=end:errors.append(f"{role} netdev: {e}");break
                    self.sleep(.1)
        for role in ("outer","server"):
            policy=self.policies.get(role)
            if policy is None: continue
            try:
                value=self._guest(role,_NETWORKD_POLICY,[str(policy["path"]),str(policy["mac"]),"remove",json.dumps(policy,separators=(",",":"))],end-self.clock())
                if value.get("removed") is not True or value.get("defaults_unchanged") is not True:
                    raise PrivateLinkError(f"{role} networkd cleanup/default-route proof failed")
            except BaseException as e:errors.append(f"{role} networkd policy: {e}")
        final=self.sock(self.p.socket_path)
        if final.get("exists") is True:
            if self.socket_live is None: errors.append("unbound QEMU socket remains")
            else:
                try:
                    removed=self.remove_socket(self.p.socket_path,self.socket_live);self._check()
                    if removed.get("removed") is not True or self.sock(self.p.socket_path).get("exists") is not False:errors.append("owned QEMU socket removal failed")
                except BaseException as e:errors.append(f"owned QEMU socket removal: {e}")
        final=self.sock(self.p.socket_path)
        if errors: raise PrivateLinkError("; ".join(errors))
        return {"schema":1,"operation":"nested-private-qemu-link-cleanup","run_id":self.p.run_id,"attempt_nonce":self.p.attempt_nonce,
                "server_ownership":self.sb,"outer_ownership":self.ob,"application_cleanup":application_cleanup,"socket":final,"qmp_transcript":self.events.copy(),"clean":True}
