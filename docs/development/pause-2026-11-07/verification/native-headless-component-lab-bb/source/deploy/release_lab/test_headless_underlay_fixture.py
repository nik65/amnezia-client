"""Inert tests for the guest-local underlay required by all-except semantics."""
import json
from pathlib import Path
import pytest
from deploy.release_lab import headless_preexisting_fixture_guest as guest
from deploy.release_lab.headless_preexisting_fixture import FixturePlan,BinaryIdentity,build_contract

def plan():
 return FixturePlan('underlay-test','linux-headless-x64','1'*48,'2'*48,1000,'/var/lib/amnezia-release-lab/underlay-test','/run/amnezia/amneziad.sock',BinaryIdentity('/usr/local/bin/amnezia-cli','a'*64),BinaryIdentity('/usr/local/bin/amneziad','b'*64),BinaryIdentity('/var/lib/amnezia-release-lab/old/amneziad','c'*64),'5.0.3.14','5.0.3.13')

def test_sealed_fixture_advertises_isolated_default_on_supported_underlay():
 p=plan();p.validate();assert p.host_veth.startswith('en') and len(p.host_veth)<=15
 network=build_contract(p,server_public_key='A'*43+'=')['network']
 assert network['kind']=='guest-local-netns' and network['host_network_mutation'] is False
 assert network['default_route']=={'gateway':p.underlay_server,'dev':p.host_veth,'metric':42750,'protocol':'static'}

@pytest.mark.parametrize('changes',[{'dev':'eth-foreign'},{'gateway':'192.0.2.1'},{'metric':True},{'metric':1},{'protocol':'dhcp'},{'dst':'192.0.2.0/24'}])
def test_wrong_default_identity_is_not_accepted(monkeypatch,changes):
 p=plan();row={'dst':'default','gateway':p.underlay_server,'dev':p.host_veth,'metric':42750,'protocol':'static',**changes}
 monkeypatch.setattr(guest,'_main_defaults',lambda:[row])
 with pytest.raises(guest.GuestError,match='identity'):guest._verify_underlay_default(p)

@pytest.mark.parametrize('rows',[[],[{},{}]])
def test_missing_or_ambiguous_default_denied(monkeypatch,rows):
 monkeypatch.setattr(guest,'_main_defaults',lambda:rows)
 with pytest.raises(guest.GuestError,match='missing or ambiguous'):guest._verify_underlay_default(plan())

def test_exact_kernel_default_readback(monkeypatch):
 p=plan();calls=[]
 def run(argv):
  calls.append(argv);return {'stdout':json.dumps([{'dst':'default','gateway':p.underlay_server,'dev':p.host_veth,'metric':42750,'protocol':'static'}])}
 monkeypatch.setattr(guest,'run',run)
 assert guest._verify_underlay_default(p)['dev']==p.host_veth
 assert calls==[['/usr/sbin/ip','-4','-j','route','show','table','main','default']]

def test_foreign_default_stops_before_fixture_creation(monkeypatch):
 monkeypatch.setattr(guest.os,'geteuid',lambda:0,raising=False);monkeypatch.setattr(Path,'is_file',lambda _:True);monkeypatch.setattr(guest.os,'access',lambda *a:True)
 monkeypatch.setattr(guest,'_main_defaults',lambda:[{'dst':'default','dev':'foreign'}])
 monkeypatch.setattr(guest,'secure_root',lambda *a:pytest.fail('must not create fixture'))
 with pytest.raises(guest.GuestError,match='empty main default'):guest.prepare(plan())

@pytest.mark.parametrize('failure_index',[0,1])
def test_creation_failure_never_deletes_unowned_namespace_or_link(tmp_path,monkeypatch,failure_index):
 p=plan();root=tmp_path/'fixture';root.mkdir();calls=[]
 monkeypatch.setattr(guest.os,'geteuid',lambda:0,raising=False);monkeypatch.setattr(Path,'is_file',lambda _:True);monkeypatch.setattr(guest.os,'access',lambda *a:True)
 monkeypatch.setattr(guest,'_main_defaults',lambda:[]);monkeypatch.setattr(Path,'exists',lambda _:False)
 monkeypatch.setattr(guest,'secure_root',lambda *a:root);monkeypatch.setattr(guest,'write_private',lambda *a:None);monkeypatch.setattr(guest,'_stage_config',lambda *a:{})
 original=Path.mkdir
 def mkdir(path,*a,**k):
  if str(path).startswith('/etc/amnezia'):return
  return original(path,*a,**k)
 monkeypatch.setattr(Path,'mkdir',mkdir)
 def run(argv,*a,**k):
  calls.append(argv)
  if argv[:3]==['/usr/sbin/ip','netns','add'] and failure_index==0:raise guest.GuestError('existing namespace race')
  if argv[:3]==['/usr/sbin/ip','link','add'] and failure_index==1:raise guest.GuestError('existing veth race')
  return {'stdout':'A'*43+'=\n','rc':0}
 monkeypatch.setattr(guest,'run',run)
 with pytest.raises(guest.GuestError,match='race'):guest.prepare(p)
 deletes=[a for a in calls if a[:3] in (['/usr/sbin/ip','netns','del'],['/usr/sbin/ip','link','del'])]
 assert deletes==([] if failure_index==0 else [['/usr/sbin/ip','netns','del',p.netns]])

@pytest.mark.parametrize('http_failed',[False,True])
def test_prepare_builds_and_reads_back_one_owned_isolated_default(tmp_path,monkeypatch,http_failed):
 p=plan();root=tmp_path/'fixture';root.mkdir();calls=[];defaults=[]
 monkeypatch.setattr(guest.os,'geteuid',lambda:0,raising=False);monkeypatch.setattr(Path,'is_file',lambda _:True);monkeypatch.setattr(guest.os,'access',lambda *a:True)
 monkeypatch.setattr(guest,'_main_defaults',lambda:list(defaults));monkeypatch.setattr(Path,'exists',lambda _:False)
 monkeypatch.setattr(guest,'secure_root',lambda *a:root);monkeypatch.setattr(guest,'write_private',lambda *a:None);monkeypatch.setattr(guest,'_stage_config',lambda *a:{'source':'verified'})
 monkeypatch.setattr(guest,'file_id',lambda path:{'path':path});monkeypatch.setattr(guest,'proc_id',lambda pid:{'pid':pid})
 original_mkdir=Path.mkdir
 def mkdir(path,*a,**k):
  if str(path).startswith('/etc/amnezia'):return
  return original_mkdir(path,*a,**k)
 monkeypatch.setattr(Path,'mkdir',mkdir)
 def run(argv,*a,**k):
  calls.append(argv)
  if argv[:5]==['/usr/sbin/ip','-4','route','add','default']:defaults.append({'dst':'default','gateway':p.underlay_server,'dev':p.host_veth,'metric':42750,'protocol':'static'})
  if argv==['/usr/sbin/ip','link','del',p.host_veth]:defaults.clear()
  return {'stdout':'A'*43+'=\n','rc':0}
 monkeypatch.setattr(guest,'run',run);monkeypatch.setattr(guest.time,'sleep',lambda _:None)
 class Process:
  pid=999
  def poll(self):return 1 if http_failed else None
 monkeypatch.setattr(guest.subprocess,'Popen',lambda *a,**k:Process())
 original_stat=guest.os.stat
 def stat(path,*a,**k):
  if str(path)==f'/var/run/netns/{p.netns}':return type('S',(),{'st_ino':123})()
  return original_stat(path,*a,**k)
 monkeypatch.setattr(guest.os,'stat',stat)
 if http_failed:
  with pytest.raises(guest.GuestError,match='HTTP server exited'):guest.prepare(p)
  assert not defaults
 else:
  receipt=guest.prepare(p);assert receipt['underlay_default']==receipt['contract']['network']['default_route']
 command=['/usr/sbin/ip','-4','route','add','default','via',p.underlay_server,'dev',p.host_veth,'metric','42750','proto','static']
 assert calls.count(command)==1
 assert calls.index(command)>calls.index(['/usr/sbin/ip','-n',p.netns,'link','set',p.peer_veth,'up'])
 assert not any('replace' in argv for argv in calls)
