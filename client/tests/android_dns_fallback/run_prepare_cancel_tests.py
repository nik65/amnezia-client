"""Actual resolver preparation/cancellation fragment on a host JVM; no app or sockets."""
from pathlib import Path
import argparse,hashlib,json,os,subprocess

p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--source',type=Path);a=p.parse_args()
root=Path(__file__).resolve().parents[3]
source=a.source or root/'client/android/src/org/amnezia/vpn/DnsFallbackProtocol.kt'
text=source.read_text(encoding='utf-8');a.output.mkdir(parents=True,exist_ok=True)
begin=text.index('            for (resolver in mobile.resolvers) {')
end=text.index('            reason = "dns_authenticated_probe_passed"',begin)
fragment=text[begin:end]
at=text.index('} finally {',text.index('private suspend fun prepareDns'))
b=text.index('{',at);e=b+1;depth=1
while depth:
    if text[e]=='{':depth+=1
    elif text[e]=='}':depth-=1
    e+=1
cleanup=text[b+1:e-1]
h=text.index('    private fun retireFailedDnsReplacement(');b=text.index('{',h);e=b+1;depth=1
while depth:
    if text[e]=='{':depth+=1
    elif text[e]=='}':depth-=1
    e+=1
helper=text[h:e]


fixture=r'''
import kotlinx.coroutines.*
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
private enum class ProtocolState{UNKNOWN}
private class VpnStartException(message:String):Exception(message)
private class Physical(val resolvers:List<Int>)
private object Log {fun w(tag:String,message:String){}}
private fun dnsTlsFailureSummary(e:Throwable)=e.javaClass.simpleName
private class DnsFallbackTransport {
 var stopped=false
 val isStopped get()=stopped
 fun close(){stopped=true}
 fun verify(config:Any,protect:(Int)->Boolean):Boolean {verifies.incrementAndGet();return verifyResult}
 companion object {
  val starts=AtomicInteger();val verifies=AtomicInteger();val created=ArrayList<DnsFallbackTransport>()
  var startHook:(()->Unit)?=null;var verifyResult=true
  fun reset(){starts.set(0);verifies.set(0);created.clear();startHook=null;verifyResult=true}
  fun start(context:Any,mobile:Physical,resolver:Int,fallback:Any,protect:(Int)->Boolean):DnsFallbackTransport {
   starts.incrementAndGet();startHook?.invoke()
   return DnsFallbackTransport().also{created.add(it)}
  }
 }
}
private class Fixture {
 var nativeReplacementStarted=false;var dnsStarted=false;var reason=""
 class State{var value=ProtocolState.UNKNOWN};val state=State()
 class Owner{fun revokeProof(){}};val dnsOwner=Owner()
 class Native{fun stopVpnVerified()=true};val xray=Native()
 @@HELPER@@
 val policy=DnsFallbackPolicy(2)
 val ticket=policy.begin(0)
 val context=Any();val fallback=Any();val protect:(Int)->Boolean={true}
 val ownedTransports=java.util.concurrent.ConcurrentHashMap.newKeySet<DnsFallbackTransport>()
 var pendingTransport:DnsFallbackTransport?=null
 var publications=0
 private fun closeTransport(value:DnsFallbackTransport?){value?.close();if(value?.isStopped==true)ownedTransports.remove(value)}
 suspend fun prepare(ownedTicket:Long,mobile:Physical){
  var candidate:DnsFallbackTransport?=null;var stage="start_transport"
  try {
@@FRAGMENT@@
   publications++
   candidate=null
  } finally {@@CLEANUP@@}
 }
}
fun main()=runBlocking {
 var checks=0
 suspend fun expectRetirement(cancelCoroutine:Boolean){
  DnsFallbackTransport.reset();val f=Fixture();val entered=CountDownLatch(1);val release=CountDownLatch(1)
  DnsFallbackTransport.startHook={entered.countDown();check(release.await(3,TimeUnit.SECONDS))}
  val job=launch(Dispatchers.Default){f.prepare(f.ticket,Physical(listOf(1,2)))}
  check(entered.await(2,TimeUnit.SECONDS))
  if(cancelCoroutine)job.cancel() else f.policy.stop()
  release.countDown();job.join()
  check(DnsFallbackTransport.verifies.get()==0){"retired/cancelled owner started transport verification"}
  check(DnsFallbackTransport.starts.get()==1){"retired owner advanced to another resolver"}
  check(f.publications==0 && f.ownedTransports.isEmpty() && f.pendingTransport==null)
  check(DnsFallbackTransport.created.all{it.stopped}){"cancelled candidate leaked"}
  checks++
 }
 expectRetirement(false)
 expectRetirement(true)
 DnsFallbackTransport.reset();val good=Fixture()
 good.prepare(good.ticket,Physical(listOf(1)))
 check(DnsFallbackTransport.verifies.get()==1 && good.publications==1)
 checks++
 DnsFallbackTransport.reset();DnsFallbackTransport.verifyResult=false;val failures=Fixture()
 check(runCatching{failures.prepare(failures.ticket,Physical(listOf(1,2)))}.isFailure)
 check(DnsFallbackTransport.starts.get()==2 && DnsFallbackTransport.verifies.get()==2)
 check(failures.ownedTransports.isEmpty() && failures.pendingTransport==null && DnsFallbackTransport.created.all{it.stopped})
 checks++
 println("prepareCancelChecks=$checks passed=true verifyAfterRetirement=false cleanupPreserved=true")
}
'''.replace('@@FRAGMENT@@',fragment).replace('@@CLEANUP@@',cleanup).replace('@@HELPER@@',helper)
k=a.output/'ActualPrepareCancel.kt';k.write_text(fixture,encoding='utf-8')
cache=Path.home()/'.gradle/caches/modules-2/files-2.1'
def jar(group,name,version):
    hits=list((cache/group/name/version).glob('*/*.jar'))
    if len(hits)!=1:raise SystemExit('Missing exact cached compiler dependency')
    return hits[0]
jars=[jar('org.jetbrains.kotlin','kotlin-compiler-embeddable','2.1.0'),jar('org.jetbrains.kotlin','kotlin-stdlib','2.1.0'),
      jar('org.jetbrains.kotlin','kotlin-script-runtime','2.1.0'),jar('org.jetbrains.kotlin','kotlin-reflect','1.6.10'),
      jar('org.jetbrains.intellij.deps','trove4j','1.0.20200330'),jar('org.jetbrains','annotations','13.0'),
      jar('org.jetbrains.kotlinx','kotlinx-coroutines-core-jvm','1.8.1')]
cp=os.pathsep.join(map(str,jars));classes=a.output/'classes'
policy=root/'client/android/src/org/amnezia/vpn/DnsFallbackPolicy.kt'
policy_fixture=a.output/'ActualPolicy.kt';policy_fixture.write_text(policy.read_text().replace('package org.amnezia.vpn',''),encoding='utf-8')
c=subprocess.run(['java','-cp',cp,'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler','-no-stdlib','-no-reflect','-classpath',cp,
                  '-d',str(classes),str(k),str(policy_fixture)],capture_output=True,text=True)
(a.output/'compile.txt').write_text(c.stdout+c.stderr,encoding='utf-8')
if c.returncode:raise SystemExit('Compilation failed; see '+str(a.output/'compile.txt'))
r=subprocess.run(['java','-cp',str(classes)+os.pathsep+cp,'ActualPrepareCancelKt'],capture_output=True,text=True,timeout=15)
(a.output/'run.txt').write_text(r.stdout+r.stderr,encoding='utf-8')
receipt={'sourceSha256':hashlib.sha256(source.read_bytes()).hexdigest(),'extractedSha256':hashlib.sha256(k.read_bytes()).hexdigest(),
         'compileExit':c.returncode,'runExit':r.returncode,'passed':r.returncode==0,'applicationDeviceOrSocketsStarted':False}
(a.output/'receipt.json').write_text(json.dumps(receipt,indent=2),encoding='utf-8');print(json.dumps(receipt))
if r.returncode:raise SystemExit(1)
