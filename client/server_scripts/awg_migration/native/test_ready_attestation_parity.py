"""Synthetic differential attestation; FakeRunner only, no Docker subprocesses."""
import argparse, copy, hashlib, importlib.util, json, os, pathlib, subprocess, sys, tempfile
p=argparse.ArgumentParser();p.add_argument('--probe',required=True);p.add_argument('--swap-library');args=p.parse_args()
base=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(base))
spec=importlib.util.spec_from_file_location('oracle',base/'ready_validation.py');oracle=importlib.util.module_from_spec(spec);spec.loader.exec_module(oracle)
from trusted_image import BINARY_SHA256
A='A'*43+'=';B='B'*43+'=';C='C'*43+'='
source=f'[Interface]\nPrivateKey={A}\nAddress=10.0.0.1/24\nListenPort=51820\n[Peer]\nPublicKey={B}\nPresharedKey={C}\nAllowedIPs=10.0.0.2/32\n'
target=source.replace('51820','51821').replace('[Peer]','Jc=4\nRandomTrailers=1\nDisableCookies=0\nContentPaddingAddition=0\n[Peer]')
ready=dict(containerId='amnezia-awg',targetContainer='target',generation=1,endpoint='example:51821',serverPublicKey=A,parameters=dict(Jc='4',RandomTrailers='1',DisableCookies='0',ContentPaddingAddition='0'),peers={B:dict(sourceIp='10.0.0.2',targetIp='10.0.0.2',clientAddress='10.0.0.2/32')})
engine='set -eu; engine=$(cat /migration/engine.pid); case "$engine" in ""|*[!0-9]*) exit 1;; esac; kill -0 "$engine"; sha256sum "/proc/$engine/exe"'
def answer(command,output):return dict(args=command,output=output)
def fixture():
 return dict(source=source,target=target,ready=copy.deepcopy(ready),automatic=True,existing=False,answers=[answer(['docker','exec','target','awg','show','awg0','dump'],f'private\t{A}\t51821\t0\n{B}\t{C}\t(none)\t10.0.0.2/32\t0\t0\t0\t0\n'),answer(['docker','exec','target','awg','showconf','awg0'],'Jc = 4\nRandomTrailers = on\nDisableCookies = false\n'),answer(['docker','exec','target','sh','-c',engine],BINARY_SHA256+'  /proc/100/exe\n')])
class Runner:
 def __init__(self,f):self.answers=iter(f['answers'])
 def __call__(self,*command):
  item=next(self.answers);assert list(command)==item['args'],(command,item['args']);return bytes.fromhex(item['output_hex']) if 'output_hex' in item else item['output'].encode()
def py(f):
 try:
  run=Runner(f)
  if f['existing']:oracle.validate_existing_target(f['directory'],f['value'],f['ready'],run)
  else:oracle.validate_ready_target(run,f['ready'],*oracle.parse_config(f['source'].encode()),*oracle.parse_config(f['target'].encode()),f['automatic'])
  return True
 except Exception:return False
def check(f,strict=False):
 expected=py(f);r=subprocess.run([args.probe],input=json.dumps(f).encode(),capture_output=True);actual=r.returncode==0
 if strict:assert expected and not actual,(r.stdout,r.stderr)
 else:assert actual==expected,(expected,r.stdout,r.stderr)
cases=[fixture()]
for kind in ['key','address','peer','param','port','server','psk','route','missing','extra','boolean','padding','hash','hashwords']:
 f=fixture()
 if kind=='key':f['target']=f['target'].replace('PrivateKey='+A,'PrivateKey='+C)
 elif kind=='address':f['target']=f['target'].replace('10.0.0.1/24','10.0.0.3/24')
 elif kind=='peer':f['target']=f['target'].replace('PresharedKey='+C,'PresharedKey='+A)
 elif kind=='param':f['ready']['parameters']['Jc']='5'
 elif kind=='port':f['answers'][0]['output']=f['answers'][0]['output'].replace('51821','51822')
 elif kind=='server':f['ready']['serverPublicKey']=C
 elif kind=='psk':f['answers'][0]['output']=f['answers'][0]['output'].replace(C,A)
 elif kind=='route':f['answers'][0]['output']=f['answers'][0]['output'].replace('10.0.0.2/32','10.0.0.3/32')
 elif kind=='missing':f['answers'][0]['output']=f['answers'][0]['output'].splitlines()[0]+'\n'
 elif kind=='extra':f['answers'][0]['output']+='x\ty\tz\tw\n'
 elif kind=='boolean':f['answers'][1]['output']=f['answers'][1]['output'].replace('on','off')
 elif kind=='padding':f['ready']['parameters']['ContentPaddingAddition']='1'
 elif kind=='hash':f['answers'][2]['output']='0'*64+'  /proc/100/exe\n'
 elif kind=='hashwords':f['answers'][2]['output']+=' extra'
 cases.append(f)
f=fixture();f['automatic']=False;f['answers']=f['answers'][:2];cases.append(f)
# Private command output must retain Python's strict UTF-8 decoding contract,
# including ignored fields. output_hex belongs only to this FakeRunner probe.
for index in range(3):
 for raw_bytes in [b'ASCII', 'данные😀'.encode(), b'\0', b'\xff', b'\x80',
                   b'\xc0\xaf', b'\xe2\x82', b'\xed\xa0\x80', b'\xf4\x90\x80\x80']:
  f=fixture();item=f['answers'][index];output=item.pop('output').encode()
  if index==0:output=output.replace(b'private',b'private'+raw_bytes)
  elif index==1:output+=b'ignored = '+raw_bytes+b'\n'
  else:output=output.replace(b'/proc/100/exe',b'/proc/'+raw_bytes+b'/exe')
  item['output_hex']=output.hex();cases.append(f)
for f in cases:check(f)
strict=fixture();strict['answers'][1]['output']+='Jc = 4\n';check(strict,True)
with tempfile.TemporaryDirectory() as d:
 path=pathlib.Path(d)/'awg0.conf';path.write_text(target)
 f=fixture();f.update(existing=True,directory=d,value=dict(source='amnezia-awg',target='target',containers={'target':{'id':'target'}},request=dict(generation=1,host='example',port=51821),sourceId='source-id',sourceDigest=hashlib.sha256(source.encode()).hexdigest()))
 f['answers']=[answer(['docker','exec','source-id','cat','/opt/amnezia/awg/wg0.conf'],source),answer(['docker','exec','target','cat','/migration/awg0.conf'],target)]+f['answers'];check(f)
 for category in ['digest','generation','endpoint','peerip','targetraw','mapping','source','port']:
  g=copy.deepcopy(f)
  if category=='digest':g['value']['sourceDigest']='0'*64
  elif category=='generation':g['ready']['generation']=2
  elif category=='endpoint':g['ready']['endpoint']='other:51821'
  elif category=='peerip':g['ready']['peers'][B]['sourceIp']='10.0.0.3'
  elif category=='targetraw':g['answers'][1]['output']+='\n'
  elif category=='mapping':g['ready']['peers']={}
  elif category=='source':g['value']['source']='unsupported'
  elif category=='port':g['value']['request']['port']=51822
  check(g)
 path.unlink();os.symlink('missing',path);check(f)
 path.unlink();original=pathlib.Path(d)/'real';original.write_text(target);os.link(original,path);check(f,True)
 # Persisted generations are positive exact JSON integers; Python alone does not enforce this schema.
 for generation in [False, True, 0, -1, '1', 1.0, 9007199254740992]:
  g=copy.deepcopy(f);g['ready']['generation']=generation;g['value']['request']['generation']=generation
  # Restore a regular file for each stricter boundary check.
  if path.exists() or path.is_symlink():path.unlink()
  path.write_text(target);check(g,True)
 g=copy.deepcopy(f);g['ready']['generation']=9007199254740991;g['value']['request']['generation']=9007199254740991;check(g)
 with tempfile.TemporaryDirectory() as outer:
  real=pathlib.Path(outer)/'real';nested=real/'nested';nested.mkdir(parents=True);(nested/'awg0.conf').write_text(target)
  alias=pathlib.Path(outer)/'alias';alias.symlink_to(real,target_is_directory=True)
  g=copy.deepcopy(f);g['directory']=str(alias/'nested');check(g,True)
  g['directory']=str(nested);check(g)
  g['directory']=str(nested)+'/../nested';check(g,True)
if args.swap_library:
 with tempfile.TemporaryDirectory() as outer:
  actual=pathlib.Path(outer)/'actual';actual.mkdir();(actual/'awg0.conf').write_text(target)
  g=copy.deepcopy(f);g['directory']=str(actual)
  env=dict(os.environ,LD_PRELOAD=args.swap_library,OWNED_ATTESTATION_SWAP_DIR=str(actual))
  result=subprocess.run([args.probe],input=json.dumps(g).encode(),capture_output=True,env=env,timeout=5)
  assert (actual/'awg0.conf').read_text()=='replacement-invalid-config\n'
  assert result.returncode==1 and result.stdout==b'ERR\n',(result.returncode,result.stdout,result.stderr)
print(f'PASS: {len(cases)+23+bool(args.swap_library)} synthetic parity/strict-boundary cases; no live commands')
