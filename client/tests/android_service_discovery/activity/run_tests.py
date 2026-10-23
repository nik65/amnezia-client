from pathlib import Path
import sys,subprocess,os
root=Path(__file__).resolve().parents[4];out=Path(sys.argv[1]);out.mkdir(parents=True,exist_ok=True)
subprocess.run([sys.executable,'-B',str(Path(__file__).with_name('generate_fixture.py')),str(root),str(out)]+sys.argv[2:],check=True)
cache=Path.home()/'.gradle/caches/modules-2/files-2.1'
def jar(g,n,v):
 hits=list((cache/g/n/v).glob('*/*.jar'));assert len(hits)==1;return hits[0]
stdlib=jar('org.jetbrains.kotlin','kotlin-stdlib','2.1.0');annotations=jar('org.jetbrains','annotations','13.0');coroutines=jar('org.jetbrains.kotlinx','kotlinx-coroutines-core-jvm','1.6.4')
compiler=[jar('org.jetbrains.kotlin','kotlin-compiler-embeddable','2.1.0'),stdlib,jar('org.jetbrains.kotlin','kotlin-script-runtime','2.1.0'),jar('org.jetbrains.kotlin','kotlin-reflect','1.6.10'),jar('org.jetbrains.intellij.deps','trove4j','1.0.20200330'),annotations,coroutines]
java=Path.home()/'devtools/jdk-17/bin/java.exe';cp=os.pathsep.join(map(str,[stdlib,annotations,coroutines]));target=out/'activity-discovery.jar'
sources=[root/'client/android/protocolApi/src/main/kotlin/NativeSessionBinding.kt',root/'client/android/src/org/amnezia/vpn/ServiceDiscoveryWire.kt',out/'ActualActivityDiscovery.kt']
with (out/'compile.log').open('w',encoding='utf-8') as log:r=subprocess.run([str(java),'-cp',os.pathsep.join(map(str,compiler)),'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler','-no-stdlib','-no-reflect','-classpath',cp,'-d',str(target)]+list(map(str,sources)),stdout=log,stderr=subprocess.STDOUT,timeout=60)
print('compile',r.returncode)
if r.returncode:sys.exit(r.returncode)
with (out/'test.log').open('w',encoding='utf-8') as log:r=subprocess.run([str(java),'-cp',str(target)+os.pathsep+cp,'ActualActivityDiscoveryKt',str(out)],stdout=log,stderr=subprocess.STDOUT,timeout=30)
print('jvm',r.returncode);sys.exit(r.returncode)
