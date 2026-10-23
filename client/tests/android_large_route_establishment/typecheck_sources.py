"""Compile actual protocol/WG sources against public SDK; no Gradle/APK build."""
from pathlib import Path
import argparse,hashlib,json,os,subprocess
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True)
p.add_argument('--sdk',type=Path,default=Path.home()/'Android/Sdk/platforms/android-36/android.jar')
a=p.parse_args();a.output.mkdir(parents=True,exist_ok=True)
root=Path(__file__).resolve().parents[3]; cache=Path.home()/'.gradle/caches/modules-2/files-2.1'
def jar(g,n,v):return next((cache/g/n/v).glob('*/*.jar'))
stdlib=jar('org.jetbrains.kotlin','kotlin-stdlib','2.1.0'); annotations=jar('org.jetbrains','annotations','13.0'); coro=jar('org.jetbrains.kotlinx','kotlinx-coroutines-core-jvm','1.6.4')
compiler=[jar('org.jetbrains.kotlin','kotlin-compiler-embeddable','2.1.0'),stdlib,jar('org.jetbrains.kotlin','kotlin-script-runtime','2.1.0'),jar('org.jetbrains.kotlin','kotlin-reflect','1.6.10'),jar('org.jetbrains.intellij.deps','trove4j','1.0.20200330'),annotations,coro]
cp=[stdlib,annotations,coro,a.sdk]
cp+=list((cache/'androidx.annotation/annotation-jvm').glob('*/*/*.jar'))[-1:]
for name in ['utils','protocolApi','wireguard','awg']:
 cp += list((root/'client/android'/name/'build/intermediates/compile_library_classes_jar/release').glob('*/classes.jar'))
sources = list((root/'client/android/protocolApi/src/main/kotlin').glob('*.kt')) + list((root/'client/android/wireguard/src/main/kotlin/org/amnezia/vpn/protocol/wireguard').glob('*.kt'))
subprocess.run([str(Path.home()/'devtools/jdk-17/bin/java.exe'),'-cp',os.pathsep.join(map(str,compiler)),'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler','-jvm-target','17','-no-stdlib','-no-reflect','-classpath',os.pathsep.join(map(str,cp)),'-d',str(a.output/'typecheck.jar'),*map(str,sources)],check=True,timeout=60)
(a.output/'INPUTS.json').write_text(json.dumps([{'path':str(x),'sha256':hashlib.sha256(x.read_bytes()).hexdigest()} for x in sources+cp],indent=2))


