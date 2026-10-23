"""Differential tests: owned temporary journals and exact fake process responses only.
No Docker, socket binding, network, service, product or system inventory commands.
"""
import argparse,copy,hashlib,importlib.util,json,subprocess,tempfile
from pathlib import Path
parser=argparse.ArgumentParser();parser.add_argument('--probe',required=True);args=parser.parse_args()
base=Path(__file__).resolve().parent.parent
def load(name):
 spec=importlib.util.spec_from_file_location(name,base/(name+'.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
auto=load('automatic');trusted=load('trusted_image');count=0
class Fake:
 def __init__(self,responses):self.responses=responses;self.pos=0;self.calls=[]
 def __call__(self,*a):
  self.calls.append(list(a));r=self.responses[self.pos];self.pos+=1
  assert list(a)==r['args'],(a,r['args'])
  failure=r.get('failure')
  if failure=='exit':raise subprocess.CalledProcessError(1,a,output=b'private fake output')
  if failure=='timeout':raise subprocess.TimeoutExpired(a,1,output=b'private fake output')
  if failure=='os':raise OSError('private fake output')
  if failure:raise RuntimeError('private fake output')
  if 'output_hex' in r:
   value=r['output_hex']
   assert len(value)%2==0 and len(value)<=2*1024*1024 and all(c in '0123456789abcdefABCDEF'for c in value)
   assert 'output'not in r
   return bytes.fromhex(value)
  return r['output'].encode()
def compare(fixture,python):
 global count
 f=Fake(fixture.get('responses',[]))
 try:expected={'ok':True,'value':python(f)}
 except Exception as e:expected={'ok':False,'error':str(e)}
 result=subprocess.run([args.probe],input=json.dumps(fixture),text=True,capture_output=True,check=True);actual=json.loads(result.stdout)
 assert {k:v for k,v in actual.items()if k!='calls'}==expected,(fixture,expected,actual)
 assert actual['calls']==f.calls,(fixture,f.calls,actual['calls'])
 count+=1
with tempfile.TemporaryDirectory(prefix='awg-planner-parity-')as temp:
 root=Path(temp)
 def request(mode='first',host='vpn.example',image='pinned',raw='source'):
  for p in (root/'amnezia-awg2').glob('*/transaction.json')if(root/'amnezia-awg2').exists()else[]:p.unlink()
  if(root/'amnezia-awg2').exists():
   for p in (root/'amnezia-awg2').iterdir():p.rmdir()
  body={'phase':'ready','sourceDigest':hashlib.sha256(b'source').hexdigest(),'request':{'host':'vpn.example','image':'pinned','port':51822,'generation':1}}
  if mode!='first':
   d=root/'amnezia-awg2'/('2'if mode=='partial2'else'1');d.mkdir(parents=True,exist_ok=True)
   if mode!='missing':(d/'transaction.json').write_text(json.dumps({'phase':'creating'}if mode.startswith('partial')else body))
   if mode=='multi':
    d=root/'amnezia-awg2/2';d.mkdir();(d/'transaction.json').write_text(json.dumps(body))
  f={'mode':'automatic','root':str(root),'source':'amnezia-awg2','host':host,'image':image,'raw':raw,'sourcePort':51820,'occupied':[51821,51822]}
  compare(f,lambda _:auto.plan(root,'amnezia-awg2',host,image,raw.encode(),51820,{51821,51822}))
 for mode in ['first','partial1','partial2','missing','ready','multi']:request(mode)
 request('ready',host='other.example');request('ready',image='changed');request('ready',raw='changed');request(host='2001:db8::1');request(host='bad name')
 # The complete journal grammar must reject ambiguous/non-JSON state before reuse.
 valid={'phase':'ready','sourceDigest':hashlib.sha256(b'source').hexdigest(),'request':{'host':'vpn.example','image':'pinned','port':51822,'generation':1}}
 raw=json.dumps(valid,separators=(',',':'))
 malformed=[raw.replace('"phase":"ready"','"phase":"creating","phase":"ready"'),
            raw.replace('"phase":"ready"','"phase":"creating","ph\\u0061se":"ready"'),
            raw.replace('"request":','"request":{},"request":'),
            raw.replace('"port":51822','"port":60000,"port":51822'),
            raw.replace('"sourceDigest":','"sourceDigest":"wrong","sourceDigest":')]
 malformed += [raw[:-1]+',"ignored":'+v+'}'for v in['NaN','Infinity','-Infinity']]
 d=root/'amnezia-awg2/1';d.mkdir(parents=True,exist_ok=True)
 for body in malformed:
  (d/'transaction.json').write_text(body)
  f={'mode':'automatic','root':str(root),'source':'amnezia-awg2','host':'vpn.example','image':'pinned','raw':'source','sourcePort':51820,'occupied':[51821]}
  compare(f,lambda _:auto.plan(root,'amnezia-awg2','vpn.example','pinned',b'source',51820,{51821}))
# UDP inventory runners: both ss layouts, Docker NAT, absent/null/tcp publications.
for ss,ids,inspection in [
 ('UNCONN 0 0 0.0.0.0:51821 0.0.0.0:*\nudp UNCONN 0 0 [::]:51822 [::]:*\n','aaaaaaaaaaaa\n',[{'NetworkSettings':{'Ports':{'51823/udp':[{'HostPort':'51823'}],'51824/tcp':[{'HostPort':'51824'}]}}}]),
 ('UNCONN 0 0 0.0.0.0:51821 0.0.0.0:*\n','',[]),
 ('udp6 UNCONN 0 0 [::]:51822 [::]:*\n','aaaaaaaaaaaa\n',[{'NetworkSettings':{'Ports':None}}]),
 ('','aaaaaaaaaaaa\n',[{'NetworkSettings':{'Ports':{'53/udp':None}}}])]:
 responses=[{'args':['ss','-H','-uan'],'output':ss},{'args':['docker','ps','-q'],'output':ids}]
 if ids:responses.append({'args':['docker','inspect',*ids.split()],'output':json.dumps(inspection)})
 compare({'mode':'inventory','responses':responses},lambda f:sorted(auto.occupied_udp_ports(f)))
# Opaque inspect text may contain literal backslash-u0000; only decoded NUL is denied.
strict_count=0
for key,value,strict in [('opaque',r'literal\u0000',False),(r'key\u0000','value',False),
                         ('opaque','decoded\0value',True),('decoded\0key','value',True)]:
 inspection=[{'Config':{key:value},'NetworkSettings':{'Ports':{'5454/udp':[{'HostPort':'5454'}]}}}]
 responses=[{'args':['ss','-H','-uan'],'output':'UNCONN 0 0 0.0.0.0:53 0.0.0.0:*\n'},
            {'args':['docker','ps','-q'],'output':'aaaaaaaaaaaa\n'},
            {'args':['docker','inspect','aaaaaaaaaaaa'],'output':json.dumps(inspection)}]
 fixture={'mode':'inventory','responses':responses}
 if strict:
  result=subprocess.run([args.probe],input=json.dumps(fixture),text=True,capture_output=True,check=True)
  actual=json.loads(result.stdout)
  assert actual=={'ok':False,'error':'udp_inventory_unavailable','calls':[r['args']for r in responses]},actual
  strict_count+=1
 else:compare(fixture,lambda f:sorted(auto.occupied_udp_ports(f)))
I=trusted.IMAGE;M=I.split('@')[1]
sandbox=['docker','run','--rm','--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges:true','--pids-limit','32','--memory','64m','--cpus','1']
tools='set -eu; for tool in awg awg-quick amneziawg-go iptables ip sleep mv cat cut sha256sum; do command -v "$tool" >/dev/null; done; printf ready'
image={'Id':trusted.IMAGE_ID,'RepoDigests':[I],'Os':'linux','Architecture':'amd64'}
def catalog(**options):
 item=copy.deepcopy(options.get('image',image));host=options.get('host',{'OSType':'linux','Architecture':'x86_64'})
 rows=[{'args':['docker','info','--format','{{json .}}'],'output':json.dumps(host)}]
 if host.get('OSType')!='linux'or host.get('Architecture')not in['amd64','x86_64']:return rows
 cached={'args':['docker','image','inspect',I],'output':json.dumps([item])}
 if options.get('cacheMissing'):cached={'args':cached['args'],'failure':'exit'}
 rows.append(cached)
 valid=trusted.identity_matches(item)and item.get('Os')=='linux'and item.get('Architecture')=='amd64'
 if options.get('cacheMissing')or not valid:
  pull={'args':['docker','pull','--platform','linux/amd64',I],'output':''}
  if options.get('pullFailure'):pull={'args':pull['args'],'failure':options['pullFailure']}
  rows.append(pull)
  if options.get('pullFailure'):return rows
 rows.append({'args':['docker','image','inspect',I],'output':json.dumps([item])})
 if not trusted.identity_matches(item)or item.get('Os')!='linux'or item.get('Architecture')!='amd64':return rows
 hashed={'args':sandbox+['--entrypoint','sha256sum',I,'/usr/bin/amneziawg-go'],'output':options.get('hash',trusted.BINARY_SHA256+'  /usr/bin/amneziawg-go')}
 if options.get('probeFailure'):hashed={'args':hashed['args'],'failure':options['probeFailure']}
 rows.append(hashed)
 if options.get('probeFailure')or hashed['output'].strip()!=trusted.BINARY_SHA256+'  /usr/bin/amneziawg-go':return rows
 version=options.get('version',trusted.REPORTED_VERSION);rows.append({'args':sandbox+['--entrypoint','/usr/bin/amneziawg-go',I,'--version'],'output':version})
 if version.strip()!=trusted.REPORTED_VERSION:return rows
 rows.append({'args':sandbox+['--entrypoint','sh',I,'-c',tools],'output':options.get('tools','ready')});return rows
cases=[{}, {'cacheMissing':True},{'host':{'OSType':'windows','Architecture':'amd64'}},{'host':{'OSType':'linux','Architecture':'aarch64'}},{'hash':'wrong'},{'version':'wrong'},{'version':''},{'tools':'ready\n'},{'image':{**image,'Id':M,'Descriptor':{'digest':M}}},{'image':{**image,'Id':M,'Descriptor':{'digest':'wrong'}}},{'image':{**image,'RepoDigests':[]}},{'image':{**image,'Architecture':'arm64'}}]
cases += [{'cacheMissing':True,'pullFailure':k}for k in['exit','timeout','os','other']]
cases += [{'probeFailure':k}for k in['exit','timeout','os']]
# Python is the semantic reference for Unicode strip, not the C++ implementation.
whitespace=[chr(cp)for cp in range(0x110000)if chr(cp).isspace()]
assert len(whitespace)==29
for space in whitespace:
 cases += [{'hash':space+trusted.BINARY_SHA256+'  /usr/bin/amneziawg-go'+space},
           {'version':space+trusted.REPORTED_VERSION+space},{'tools':space+'ready'+space}]
cases += [{'hash':''.join(whitespace)},{'version':''.join(whitespace)},
          {'hash':'\u200b'+trusted.BINARY_SHA256+'  /usr/bin/amneziawg-go'},
          {'version':'\u200b'+trusted.REPORTED_VERSION}]
for c in cases:compare({'mode':'trusted','responses':catalog(**c)},trusted.resolve_image)
# Invalid bytes cannot be expressed as UTF-8 JSON strings; only this test probe
# accepts an explicit hex output field. Production runtime has no such option.
for invalid in [b'\xff',b'\x80',b'\xc0\xaf',b'\xe2\x82',b'\xed\xa0\x80',b'\xf4\x90\x80\x80']:
 for position in (3,4,5):
  for suffix in (False,True):
   responses=catalog()[:position+1]
   last=responses[-1];valid=last.pop('output').encode()
   last['output_hex']=(valid+invalid if suffix else invalid+valid).hex()
   compare({'mode':'trusted','responses':responses},trusted.resolve_image)
print(f'plannerDifferentialCases={count} nativeStrictCases={strict_count} passed=true liveDockerCommands=0 udpBindings=0')
