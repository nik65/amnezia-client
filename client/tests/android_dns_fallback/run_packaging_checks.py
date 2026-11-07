"""Configure an INTERFACE-only fixture, never the app, to exercise actual component admission."""
from pathlib import Path
import argparse,json,os,subprocess
p=argparse.ArgumentParser();p.add_argument('--component',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
root=Path(__file__).resolve().parents[3];a.output.mkdir(parents=True,exist_ok=True)
component=a.component.resolve();manifest=json.loads(component.with_name('dnstt-manifest.json').read_text(encoding='utf-8-sig'))
source=a.output/'source';source.mkdir(exist_ok=True)
(source/'CMakeLists.txt').write_text('cmake_minimum_required(VERSION 3.25)\nproject(DnsPackagingFixture NONE)\nadd_library(fixture INTERFACE)\nset(CMAKE_ANDROID_ARCH_ABI arm64-v8a)\ninclude("'+(root/'client/cmake/dns_transport.cmake').as_posix()+'")\namnezia_bundle_android_dns_transport(fixture)\n')
checks=0
for name,field,value,expected in [('valid',None,None,True),('utf8-bom',None,None,True),('invalid-prefix',None,None,False),('wrong-hash','sha256','0'*64,False),('wrong-abi','abi','x86_64',False),('wrong-commit','sourceCommit','0'*40,False),('wrong-api','minimumApi',21,False),('four-kib-pages','minimumPageAlignment',4096,False),('missing-page-proof','minimumPageAlignment',None,False)]:
 directory=a.output/name;directory.mkdir(exist_ok=True);target=directory/'libdnstt.so'
 if not target.exists():os.link(component,target)
 current=dict(manifest)
 if field:
  if value is None:current.pop(field,None)
  else:current[field]=value
 prefix='\ufeff' if name=='utf8-bom' else ('invalid-prefix' if name=='invalid-prefix' else '')
 (directory/'dnstt-manifest.json').write_text(prefix+json.dumps(current),encoding='utf8')
 result=subprocess.run(['cmake','-S',str(source),'-B',str(directory/'build'),'-DAMNEZIA_DNSTT_ANDROID_CLIENT='+str(target.resolve())],capture_output=True,text=True,timeout=30)
 (directory/'configure.log').write_text(result.stdout+result.stderr,encoding='utf8')
 assert (result.returncode==0)==expected,(name,result.stdout,result.stderr)
 checks+=1
print(f'{checks} actual CMake packaging identity/hash/ABI checks passed; no app build')
