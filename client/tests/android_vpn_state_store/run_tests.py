"""Compile the exact store method with inert storage; no Android/Gradle/device."""
from pathlib import Path
import argparse,hashlib,json,os,subprocess
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--source',type=Path);a=p.parse_args()
root=Path(__file__).resolve().parents[3];source=a.source or root/'client/android/src/org/amnezia/vpn/VpnState.kt';a.output.mkdir(parents=True,exist_ok=True)
text=source.read_text(encoding='utf8');marker='    suspend fun store(f: (vpnState: VpnState) -> VpnState) {';start=text.index(marker);at=start+len(marker);depth=1;quote=False;escape=False
while depth:
 c=text[at]
 if quote:
  if escape:escape=False
  elif c=='\\':escape=True
  elif c=='"':quote=False
 else:
  if c=='"':quote=True
  elif c=='{':depth+=1
  elif c=='}':depth-=1
 at+=1
method=text[start:at]
if 'catch (e: CancellationException)' in method:
 assert 'import kotlinx.coroutines.CancellationException' in text, 'missing production cancellation import'
template=Path(__file__).with_name('Fixture.kt.in').read_text(encoding='utf8');actual=a.output/'ActualStore.kt';actual.write_text(template.replace('// ACTUAL_STORE_METHOD',method),encoding='utf8')
cache=Path.home()/'.gradle/caches/modules-2/files-2.1'
def jar(group,name,version):
 hits=list((cache/group/name/version).glob('*/*.jar'));assert len(hits)==1,(group,name,version);return hits[0]
stdlib=jar('org.jetbrains.kotlin','kotlin-stdlib','2.1.0');coroutines=jar('org.jetbrains.kotlinx','kotlinx-coroutines-core-jvm','1.6.4');annotations=jar('org.jetbrains','annotations','13.0')
compiler=[jar('org.jetbrains.kotlin','kotlin-compiler-embeddable','2.1.0'),stdlib,jar('org.jetbrains.kotlin','kotlin-script-runtime','2.1.0'),jar('org.jetbrains.kotlin','kotlin-reflect','1.6.10'),jar('org.jetbrains.intellij.deps','trove4j','1.0.20200330'),annotations,coroutines]
java=Path.home()/'devtools/jdk-17/bin/java.exe';cp=os.pathsep.join(map(str,[stdlib,annotations,coroutines]));target=a.output/'actual-store-tests.jar'
commands=[[str(java),'-cp',os.pathsep.join(map(str,compiler)),'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler','-no-stdlib','-no-reflect','-classpath',cp,'-d',str(target),str(actual)],[str(java),'-cp',str(target)+os.pathsep+cp,'ActualStoreKt']]
(a.output/'commands.json').write_text(json.dumps(commands,indent=2)+'\n');(a.output/'source.json').write_text(json.dumps({'path':str(source),'sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'methodSha256':hashlib.sha256(method.encode()).hexdigest()},indent=2)+'\n')
for command,log in zip(commands,['compile.log','test.log']):
 with (a.output/log).open('w',encoding='utf8') as f:r=subprocess.run(command,stdout=f,stderr=subprocess.STDOUT,timeout=60)
 print(log,'exit',r.returncode)
 if r.returncode:raise SystemExit(r.returncode)
