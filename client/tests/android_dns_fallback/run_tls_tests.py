"""Only actual portable Kotlin TLS helper + local loopback TLS fixtures; no Android/Gradle/app build."""
from pathlib import Path
import argparse,subprocess,os
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--tls-source',type=Path);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=True)
root=Path(__file__).resolve().parents[3];cache=Path.home()/'.gradle/caches/modules-2/files-2.1'
def jar(g,n,v):
 hits=list((cache/g/n/v).glob('*/*.jar'));assert len(hits)==1;return hits[0]
stdlib=jar('org.jetbrains.kotlin','kotlin-stdlib','2.1.0');annotations=jar('org.jetbrains','annotations','13.0')
compiler=[jar('org.jetbrains.kotlin','kotlin-compiler-embeddable','2.1.0'),stdlib,jar('org.jetbrains.kotlin','kotlin-script-runtime','2.1.0'),jar('org.jetbrains.kotlin','kotlin-reflect','1.6.10'),jar('org.jetbrains.intellij.deps','trove4j','1.0.20200330'),annotations,jar('org.jetbrains.kotlinx','kotlinx-coroutines-core-jvm','1.8.1')]
jdk=Path.home()/'devtools/jdk-17/bin';store=a.output/'fixture.p12'
if not store.exists():
 with (a.output/'keytool.log').open('w') as log:subprocess.run([str(jdk/'keytool.exe'),'-genkeypair','-alias','local-fixture','-keyalg','RSA','-keysize','2048','-validity','2','-dname','CN=localhost','-ext','SAN=dns:localhost','-storetype','PKCS12','-keystore',str(store),'-storepass','fixture-only','-keypass','fixture-only','-noprompt'],stdout=log,stderr=subprocess.STDOUT,check=True)
target=a.output/'tls-tests.jar';cp=os.pathsep.join(map(str,[stdlib,annotations]))
with (a.output/'compile.log').open('w') as log:r=subprocess.run([str(jdk/'java.exe'),'-cp',os.pathsep.join(map(str,compiler)),'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler','-no-stdlib','-no-reflect','-classpath',cp,'-d',str(target),str(a.tls_source or root/'client/android/src/org/amnezia/vpn/DnsVlessTls.kt'),str(Path(__file__).with_name('DnsVlessTlsTest.kt'))],stdout=log,stderr=subprocess.STDOUT,timeout=60)
print('tls_compile',r.returncode)
if r.returncode:raise SystemExit(r.returncode)
with (a.output/'test.log').open('w') as log:r=subprocess.run([str(jdk/'java.exe'),'-cp',str(target)+os.pathsep+cp,'org.amnezia.vpn.DnsVlessTlsTestKt',str(store)],stdout=log,stderr=subprocess.STDOUT,timeout=40)
print('tls_jvm',r.returncode);raise SystemExit(r.returncode)
