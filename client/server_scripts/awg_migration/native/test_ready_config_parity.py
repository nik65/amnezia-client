"""Differential pure-parser tests; --probe must point to the native stdin probe.
No network, Docker, application or VPN operations are performed.
"""
import argparse, importlib.util, ipaddress, subprocess
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--probe',required=True);a=p.parse_args()
spec=importlib.util.spec_from_file_location('oracle',Path(__file__).resolve().parents[1]/'ready_validation.py');oracle=importlib.util.module_from_spec(spec);spec.loader.exec_module(oracle)
A='A'*43+'=';B='B'*43+'=';C='C'*43+'='
base=f'[Interface]\nPrivateKey={A}\nAddress=10.0.0.1/24\n[Peer]\nPublicKey={B}\nAllowedIPs=10.0.0.2/32\n'
def py(raw):
 try:return ('OK',oracle.parse_config(raw))
 except UnicodeDecodeError:return ('ERR','invalid UTF-8')
 except KeyError:return ('ERR','missing field')
 except (ipaddress.AddressValueError,ipaddress.NetmaskValueError):return ('ERR','configuration address')
 except ValueError as e:
  code=str(e)
  explicit={'duplicate interface','configuration syntax','duplicate configuration key','missing identity','unknown interface key','only IPv4 isolation supported','unsupported peer field','peer identity','PSK','ambiguous peer route','duplicate peer address'}
  return ('ERR',code if code in explicit else 'configuration address')
def native(raw):
 r=subprocess.run([a.probe],input=raw,capture_output=True);lines=r.stdout.decode().splitlines()
 if lines and lines[0].startswith('ERR\t'):return ('ERR',lines[0].split('\t')[1])
 assert r.returncode==0 and lines[0]=='OK',r.stderr
 interface={};peers=[];cur=interface
 for line in lines[1:]:
  bits=line.split('\t')
  if bits[0]=='P':cur={};peers.append(cur)
  else:cur[bytes.fromhex(bits[1]).decode()]=bytes.fromhex(bits[2]).decode()
 return ('OK',(interface,peers))
cases=[base,'',base.replace('[Interface]','[Interface]\n[Interface]'),base+'[Interface]\n',base+'NoEquals\n',base+'[Unknown]\n',base+'[Peer]\n',base.replace('Address=10.0.0.1/24\n',''),base.replace('AllowedIPs=10.0.0.2/32\n',''),base+'PresharedKey=bad\n',base+'Endpoint=host:123\n',base.replace('Address=','Oops=foo\nAddress='),base+'[Peer]\nPublicKey='+C+'\nAllowedIPs=10.0.0.2/32\n',base+'[Peer]\nPublicKey='+B+'\nAllowedIPs=10.0.0.3/32\n']
for key in ['PrivateKey','PublicKey']:
 old=A if key=='PrivateKey' else B
 for v in ['', 'A'*42+'=', 'A'*44+'=', '!'*43+'=', 'a'*43+'=', '/'*43+'=', 'A'*43+'==']:
  cases.append(base.replace(key+'='+old,key+'='+v))
for address in ['10.0.0.1','10.0.0.1/0','10.0.0.1/032','10.0.0.1/255.255.255.0','10.0.0.1/0.0.0.255','10.0.0.1/255.0.255.0','010.0.0.1/24','300.0.0.1/24','10.0.0.1/','10.0.0.1/33','::1/128','2001:db8::1/64','bad::bad::bad/32','fe80::1%eth0/64']:
 cases.append(base.replace('10.0.0.1/24',address))
for route in ['10.0.0.2','10.0.0.2/32','10.0.0.2/31','10.0.0.1/32','10.0.1.2/32','0.0.0.0/32','::1/128','garbage','10.0.0.2,10.0.0.3','10.0.0.2/255.255.255.255']:
 cases.append(base.replace('10.0.0.2/32',route))
for key in oracle.PARAMS+('MTU','PostUp','PostDown','SaveConfig','DNS','ListenPort','I1','I2','I3','I4','I5'):
 cases.append(base.replace('Address=',key+'=arbitrary preserved value = yes\nAddress='))
for separator in ['\r\n','\r','\v','\f','\x1c','\x85','\u2028','\u2029']:
 cases.append(base.replace('\n',separator))
for space in [' ','\t','\x1f','\u00a0','\u1680','\u2007','\u202f','\u3000']:
 cases.append('\n'.join(space+x+space for x in base.splitlines()))
cases += [base.replace('PostUp','PostUp'),base.replace('Address=', 'PostUp=echo café\nAddress=')]
cases += [base.replace('10.0.0.1/24','::1\x00junk'),
          base.replace('10.0.0.2/32','::1\x00junk')]
for address_field in ('10.0.0.1/24','10.0.0.2/32'):
 for scoped in ('::1%zone\x00suffix','::1%\x00'):
  cases.append(base.replace(address_field,scoped))
for opaque_field in ('PostUp','DNS'):
 cases.append(base.replace('Address=',opaque_field+'=prefix\x00suffix\nAddress='))
rawcases=[x.encode() for x in cases]+[b'\xff',base.encode()+b'\xc0\x80',base.encode()+b'\xed\xa0\x80']
for n,raw in enumerate(rawcases):
 expected=py(raw);actual=native(raw)
 assert expected==actual,f'case {n}: expected {expected[0:1]+(expected[1] if expected[0]=="ERR" else "parsed map",)}, actual {actual}'
print(f'parse_config Python/native parity: {len(rawcases)} cases passed')
