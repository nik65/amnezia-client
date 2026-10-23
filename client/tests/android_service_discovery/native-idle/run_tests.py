"""Standalone actual native guard/close fixture. No Android or Gradle invocation."""
from pathlib import Path
import argparse,os,subprocess,json,hashlib
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--wire-source',type=Path);a=p.parse_args()
root=Path(__file__).resolve().parents[4];a.output.mkdir(parents=True,exist_ok=True)
wire=a.wire_source or root/'client/android/wireguard/src/main/kotlin/org/amnezia/vpn/protocol/wireguard/Wireguard.kt'
s=wire.read_text(encoding='utf-8');start=s.index('    private fun turnOffVpn() {');end=s.index('    override fun readNativeIdleObservation()' if '    override fun readNativeIdleObservation()' in s else '    override fun readRestoredSessionBinding()',start);close=s[start:end]
protect_start=s.index('        if (sockets.isEmpty() || sockets.any { !protect(it) }) {');protect_end=s.index('        launchStatusJob()',protect_start);protect=s[protect_start:protect_end]
fixture="""import org.amnezia.vpn.protocol.*
object GoBackend { var absent=true; fun awgTurnOff(h:Int){};fun awgGetConfig(h:Int):String?=if(absent)null else "still-active";fun awgGetSocketV4(h:Int)=if(absent)-1 else 9;fun awgGetSocketV6(h:Int)=-1 }
class Cancel {fun cancel(){}}
class VpnStartException(s:String):RuntimeException(s)
class Actual {val nativeSessionGuard=NativeSessionGuard();var tunnelHandle=4;var statusJobGeneration=0;var statusJob:Cancel?=null;var cleanedNonce="";var migrationConnectionNonce="nonce";init {nativeSessionGuard.replacedNativeHandle();nativeSessionGuard.activate(null)};
"""+close+"""
fun close()=nativeSessionGuard.locked {turnOffVpn()}
fun protectFailure(sockets:List<Int>,protect:(Int)->Boolean)=nativeSessionGuard.locked {
"""+protect+"""
}
fun observation()=nativeSessionGuard.idleObservation(tunnelHandle>=0)
}
fun main(){
 var checks=0; fun yes(v:Boolean){check(v);checks++}
 val g=NativeSessionGuard();yes(g.idleObservation(false).isAbsent);yes(g.idleObservation(true).state==NativeIdleState.ACTIVE)
 g.replacedNativeHandle();yes(!g.idleObservation(false).isAbsent)
 val id=NativeSessionIdentity("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb","cccccccc-cccc-cccc-cccc-cccccccccccc")
 g.activate(NativeSessionDescriptor(id,"server","AWG"));val active=g.idleObservation(true);yes(active.state==NativeIdleState.ACTIVE)
 g.beginCleanup();yes(!g.idleObservation(false).isAbsent);yes(g.cleanupIdentity()==null)
 g.confirmedCleanup();val retired=g.idleObservation(false);yes(retired.isAbsent);yes(retired.retiredIdentity==id);yes(retired.generation>active.generation)
 g.replacedNativeHandle();yes(!g.idleObservation(false).isAbsent);yes(g.cleanupIdentity()==null)
 val actual=Actual();val beforeClose=actual.observation().generation;GoBackend.absent=false;actual.close();yes(actual.tunnelHandle<0);yes(!actual.observation().isAbsent);yes(actual.observation().generation>beforeClose);yes(actual.observation().state==NativeIdleState.UNKNOWN)
 val clean=Actual();GoBackend.absent=true;clean.close();yes(clean.observation().state==NativeIdleState.VERIFIED_RETIRED)
 // Both initialized owners matter: a second uncertain backend cannot be hidden by a retired first.
 yes(!listOf(clean.observation(),actual.observation()).all{it.isAbsent})
 val protected=Actual();GoBackend.absent=true;try{protected.protectFailure(emptyList()){false};error("missingerror")}catch(_:VpnStartException){};yes(protected.observation().isAbsent)
 println("PASS $checks actual native absence/retirement assertions")
}
"""
(a.output/'ActualIdle.kt').write_text(fixture,encoding='utf-8')
cache=Path.home()/'.gradle/caches/modules-2/files-2.1'
def jar(g,n,v):
 hits=list((cache/g/n/v).glob('*/*.jar'));assert len(hits)==1;return hits[0]
stdlib=jar('org.jetbrains.kotlin','kotlin-stdlib','2.1.0');compiler=[jar('org.jetbrains.kotlin','kotlin-compiler-embeddable','2.1.0'),stdlib,jar('org.jetbrains.kotlin','kotlin-script-runtime','2.1.0'),jar('org.jetbrains.kotlin','kotlin-reflect','1.6.10'),jar('org.jetbrains.intellij.deps','trove4j','1.0.20200330'),jar('org.jetbrains','annotations','13.0'),jar('org.jetbrains.kotlinx','kotlinx-coroutines-core-jvm','1.6.4')]
java=Path.home()/'devtools/jdk-17/bin/java.exe';sep=os.pathsep;cp=sep.join(map(str,[stdlib,compiler[-2],compiler[-1]]));target=a.output/'idle-tests.jar'
cmd=[str(java),'-cp',sep.join(map(str,compiler)),'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler','-no-stdlib','-no-reflect','-classpath',cp,'-d',str(target),str(root/'client/android/protocolApi/src/main/kotlin/NativeSessionBinding.kt'),str(a.output/'ActualIdle.kt')]
with (a.output/'compile.log').open('w',encoding='utf-8') as f:r=subprocess.run(cmd,stdout=f,stderr=subprocess.STDOUT,timeout=60)
print('compile',r.returncode)
if r.returncode:raise SystemExit(r.returncode)
with (a.output/'test.log').open('w',encoding='utf-8') as f:r=subprocess.run([str(java),'-cp',str(target)+sep+cp,'ActualIdleKt'],stdout=f,stderr=subprocess.STDOUT,timeout=30)
print('JVM',r.returncode);raise SystemExit(r.returncode)
