"""Exercise the actual monitor and retained-path branches with fake time/resources, no Android actions."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import subprocess
import urllib.request

p = argparse.ArgumentParser()
p.add_argument('--output', type=Path, required=True)
p.add_argument('--source', type=Path)
p.add_argument('--json-jar', type=Path)
a = p.parse_args()
root = Path(__file__).resolve().parents[3]
source = a.source or root / 'client/android/src/org/amnezia/vpn/DnsFallbackProtocol.kt'
s = source.read_text(encoding='utf-8')
monitor = s[s.index('                    val currentTransport = transport'):s.index('                val success = vpnReachable()')]
monitor = monitor[:monitor.rindex('                }')]
retained = s[s.index('                if (policy.current(ownedTicket) && retainedHealthy'):s.index('            } else policy.retryPrimary')]
a.output.mkdir(parents=True, exist_ok=True)
fixture = r'''
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import org.amnezia.vpn.protocol.*
object SystemClock { var now=0L; fun elapsedRealtime()=now }
class Policy { var live=true; fun current(ticket:Long)=live }
class Physical(val network:Int,val resolvers:List<Int>) { val key get()="$network:"+resolvers.joinToString(",") }
class Transport {
 val network=1;val resolver=7;var isAlive=true;var healthy=true;var cost=0L;var calls=0;var hook:(()->Unit)?=null
 fun verify(c:Any,p:(Int)->Boolean):Boolean {calls++;SystemClock.now+=cost;hook?.invoke();return healthy}
}
class Fixture {
 val policy=Policy();val fallback=Any();val protect:(Int)->Boolean={true}
 var selected:Physical?=Physical(1,listOf(7));var transport:Transport?=Transport()
 var pendingTransport:Transport?=null
 var dnsStarted=true;var observedPhysicalKey:String?=selected!!.key
 var nextDnsAttemptMs=0L;var nextDnsHealthMs=0L;var dnsUnhealthy=false;var dnsHealthFailures=0
 var reason="dns_active";var replacements=0;var vpnPresent=true;var vpnHealthy=true
 val state=MutableStateFlow(ProtocolState.CONNECTED);val dnsState=MutableStateFlow(ProtocolState.CONNECTED)
 val dnsOwner=DnsSessionOwner()
 init {
  SystemClock.now=0
  val id=NativeSessionIdentity("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb","cccccccc-cccc-cccc-cccc-cccccccccccc")
  dnsOwner.activate(NativeSessionDescriptor(id,"test","AWG"),"a".repeat(64))
  check(dnsOwner.confirm(dnsOwner.currentGeneration(),0,true,true,true))
 }
 fun ownedVpnNetwork():Int?=if(vpnPresent)2 else null
 fun vpnReachable()=vpnHealthy
 suspend fun prepareDns(t:Long,m:Physical){replacements++}
 suspend fun scan(healthy:Boolean,cost:Long=0) {
  transport?.healthy=healthy;transport?.cost=cost
  val ownedTicket=1L;val mobile=selected
  do {
  MONITOR
  } while(false)
 }
 fun retainedCommit(retainedHealthy:Boolean) {
  val ownedTicket=1L
  RETAINED
 }
}
fun main()=runBlocking {
 var checks=0
 fun expect(ok:Boolean,label:String){checks++;check(ok){label}}
 val f=Fixture();val original=f.transport
 f.scan(false,10_000)
 expect(f.replacements==0,"first transient must retain TUN")
 expect(f.state.value==ProtocolState.RECONNECTING,"first failure reconnecting")
 expect(f.dnsOwner.binding(SystemClock.now)==null,"first failure revokes proof")
 expect(f.transport===original && f.dnsHealthFailures==1 && f.nextDnsHealthMs==15_000L,"same transport and five second retry")
 SystemClock.now=14_999;f.scan(true)
 expect(f.transport!!.calls==1 && f.dnsOwner.binding(SystemClock.now)==null,"cooldown cannot renew lease")
 SystemClock.now=15_000;f.scan(true,1)
 expect(f.replacements==0 && f.transport===original,"recovery does not rebuild")
 expect(f.state.value==ProtocolState.CONNECTED && f.dnsOwner.binding(SystemClock.now)!=null,"verified recovery renews proof")
 expect(f.dnsHealthFailures==0 && !f.dnsUnhealthy,"recovery resets failure state")
 val d=Fixture();d.scan(false,10_000);SystemClock.now=15_000;d.scan(false,10_000)
 expect(d.replacements==1 && SystemClock.now==25_000L,"two ten second failures and five second retry bound")
 expect(d.state.value==ProtocolState.RECONNECTING && d.dnsOwner.binding(SystemClock.now)==null,"dead path remains unproven")
 for(kind in 0..4){
  val h=Fixture();h.nextDnsHealthMs=60_000
  when(kind){0->h.transport!!.isAlive=false;1->h.dnsState.value=ProtocolState.DISCONNECTED;2->h.selected=Physical(2,listOf(7));3->h.selected=Physical(1,listOf(8));4->h.selected=null}
  h.scan(true)
  expect(h.replacements==if(kind==4)0 else 1,"hard resource/network condition handled immediately")
  expect(h.state.value==ProtocolState.RECONNECTING,"hard condition never connected")
 }
 val c=Fixture();c.transport!!.hook={c.policy.live=false;c.dnsOwner.retire();c.state.value=ProtocolState.UNKNOWN}
 c.scan(false,10_000)
 expect(c.replacements==0 && c.state.value==ProtocolState.UNKNOWN && c.dnsOwner.binding(SystemClock.now)==null,"cancel cannot reconnect or renew")
 val pending=Fixture();pending.pendingTransport=Transport();pending.state.value=ProtocolState.UNKNOWN;pending.dnsOwner.revokeProof()
 pending.scan(true)
 expect(pending.transport!!.calls==0 && pending.state.value==ProtocolState.UNKNOWN && pending.dnsOwner.binding(0)==null,"pending native cleanup cannot renew stale transport health")
 val o=Fixture();o.transport!!.hook={o.dnsOwner.retire()};o.scan(true)
 expect(o.state.value==ProtocolState.RECONNECTING && o.dnsOwner.binding(SystemClock.now)==null,"TLS success cannot replace owner proof")
 for(healthy in listOf(true,false)){
  val r=Fixture();r.dnsHealthFailures=2;r.dnsUnhealthy=true;r.dnsOwner.revokeProof()
  if(!healthy)r.dnsOwner.retire()
  r.retainedCommit(true)
  expect(if(healthy)r.dnsHealthFailures==0 && !r.dnsUnhealthy && r.state.value==ProtocolState.CONNECTED && r.dnsOwner.binding(0)!=null
   else r.dnsHealthFailures==2 && r.dnsUnhealthy && r.state.value==ProtocolState.UNKNOWN && r.dnsOwner.binding(0)==null,"retained path requires owner confirmation before reset")
 }
 println("actual-health checks=$checks PASS")
}
'''.replace('MONITOR', monitor).replace('RETAINED', retained)
(a.output/'ActualHealth.kt').write_text(fixture, encoding='utf-8')
cache=Path.home()/'.gradle/caches/modules-2/files-2.1'
def jar(group,name,version):
    hits=list((cache/group/name/version).glob('*/*.jar'))
    assert len(hits)==1,(group,name,version)
    return hits[0]
stdlib=jar('org.jetbrains.kotlin','kotlin-stdlib','2.1.0')
annotations=jar('org.jetbrains','annotations','13.0')
coroutines=jar('org.jetbrains.kotlinx','kotlinx-coroutines-core-jvm','1.8.1')
compiler=[jar('org.jetbrains.kotlin','kotlin-compiler-embeddable','2.1.0'),stdlib,jar('org.jetbrains.kotlin','kotlin-script-runtime','2.1.0'),jar('org.jetbrains.kotlin','kotlin-reflect','1.6.10'),jar('org.jetbrains.intellij.deps','trove4j','1.0.20200330'),annotations,coroutines]
jsonjar=a.json_jar or a.output/'json-20240303.jar'
if not jsonjar.exists():
    url='https://repo.maven.apache.org/maven2/org/json/json/20240303/json-20240303.jar'
    data=urllib.request.urlopen(url,timeout=30).read()
    expected=urllib.request.urlopen(url+'.sha1',timeout=30).read().decode().strip()
    assert hashlib.sha1(data).hexdigest()==expected
    jsonjar.write_bytes(data)
assert jsonjar.is_file()
cp=os.pathsep.join(map(str,[stdlib,annotations,coroutines,jsonjar]))
java=Path.home()/'devtools/jdk-17/bin/java.exe'
sources=[root/'client/android/protocolApi/src/main/kotlin'/name for name in ['NativeSessionBinding.kt','ProtocolState.kt','DnsSessionOwner.kt']]+[a.output/'ActualHealth.kt']
target=a.output/'health.jar'
cmd=[str(java),'-Xmx384m','-cp',os.pathsep.join(map(str,compiler)),'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler','-no-stdlib','-no-reflect','-classpath',cp,'-d',str(target),*map(str,sources)]
with (a.output/'compile.log').open('w',encoding='utf-8') as log:
    compiled=subprocess.run(cmd,stdout=log,stderr=subprocess.STDOUT,timeout=60)
if compiled.returncode:
    print((a.output/'compile.log').read_text());raise SystemExit(compiled.returncode)
with (a.output/'test.log').open('w',encoding='utf-8') as log:
    tested=subprocess.run([str(java),'-Xmx128m','-cp',str(target)+os.pathsep+cp,'ActualHealthKt'],stdout=log,stderr=subprocess.STDOUT,timeout=15)
receipt={'sourceSha256':hashlib.sha256(source.read_bytes()).hexdigest(),'compileExit':compiled.returncode,'testExit':tested.returncode,'extractedActualBranches':True}
(a.output/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
print((a.output/'test.log').read_text())
raise SystemExit(tested.returncode)
