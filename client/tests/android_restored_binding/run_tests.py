"""Owned Kotlin/JVM tests only; never invoke Gradle or an Android application."""
from pathlib import Path
import argparse,os,subprocess,json
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--wire-source',type=Path);p.add_argument('--activity-source',type=Path);a=p.parse_args()
root=Path(__file__).resolve().parents[3];cache=Path.home()/'.gradle/caches/modules-2/files-2.1';a.output.mkdir(parents=True,exist_ok=True)
def jar(group,name,version):
 hits=list((cache/group/name/version).glob('*/*.jar'));assert len(hits)==1,(group,name,version);return hits[0]
stdlib=jar('org.jetbrains.kotlin','kotlin-stdlib','2.1.0')
compiler=[jar('org.jetbrains.kotlin','kotlin-compiler-embeddable','2.1.0'),stdlib,jar('org.jetbrains.kotlin','kotlin-script-runtime','2.1.0'),jar('org.jetbrains.kotlin','kotlin-reflect','1.6.10'),jar('org.jetbrains.intellij.deps','trove4j','1.0.20200330'),jar('org.jetbrains','annotations','13.0'),jar('org.jetbrains.kotlinx','kotlinx-coroutines-core-jvm','1.6.4')]
java=Path.home()/'devtools/jdk-17/bin/java.exe';sep=os.pathsep
sources=[root/'client/android/protocolApi/src/main/kotlin/NativeSessionBinding.kt',Path(__file__).with_name('NativeSessionBindingTest.kt')]
extra=Path(__file__).with_name('generate_source_fixture.py')
if extra.exists():
 subprocess.run([os.sys.executable,'-B',str(extra),str(root),str(a.output),str(a.wire_source or root/'client/android/wireguard/src/main/kotlin/org/amnezia/vpn/protocol/wireguard/Wireguard.kt'),str(a.activity_source or root/'client/android/src/org/amnezia/vpn/AmneziaActivity.kt')],check=True)
 sources += [a.output/name for name in ['ActualNative.kt','ActualJson.kt','ActualAndroid.kt','ActualService.kt','ActualActivity.kt']]
target=a.output/'native-session-tests.jar';cp=sep.join(map(str,[stdlib,compiler[-2],compiler[-1]]))
cmd=[str(java),'-cp',sep.join(map(str,compiler)),'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler','-no-stdlib','-no-reflect','-classpath',cp,'-d',str(target)]+list(map(str,sources))
with (a.output/'compile.log').open('w',encoding='utf-8') as f:r=subprocess.run(cmd,stdout=f,stderr=subprocess.STDOUT,timeout=60)
print('kotlinc_exit',r.returncode)
if r.returncode:raise SystemExit(r.returncode)
with (a.output/'test.log').open('w',encoding='utf-8') as f:r=subprocess.run([str(java),'-cp',str(target)+sep+cp,'NativeSessionBindingTestKt',str(a.output/'kotlin-snapshots.jsonl')],stdout=f,stderr=subprocess.STDOUT,timeout=30)
print('jvm_exit',r.returncode)
if r.returncode:raise SystemExit(r.returncode)
with (a.output/'wiring.log').open('w',encoding='utf-8') as f:r=subprocess.run([os.sys.executable,'-B',str(Path(__file__).with_name('test_wiring.py'))],stdout=f,stderr=subprocess.STDOUT)
print('wiring_exit',r.returncode)
raise SystemExit(r.returncode)
