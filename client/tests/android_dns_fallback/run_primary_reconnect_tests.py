"""Actual DNS wrapper reconnect/StateFlow regression; standalone JVM only, no APK/device."""
from pathlib import Path
import argparse, hashlib, json, os, subprocess
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--source',type=Path);a=p.parse_args()
root=Path(__file__).resolve().parents[3];source=a.source or root/'client/android/src/org/amnezia/vpn/DnsFallbackProtocol.kt';text=source.read_text(encoding='utf8');a.output.mkdir(parents=True,exist_ok=True)
def body(marker):
 start=text.index(marker);start=text.index('{',start);end=start+1;depth=1
 while depth:depth+=(text[end]=='{')-(text[end]=='}');end+=1
 return text[start+1:end-1]
reconnect=body('override fun reconnectVpn(')
start=text.index('primaryState.collect { current ->')+len('primaryState.collect { current ->');end=start;depth=1
while depth:depth+=(text[end]=='{')-(text[end]=='}');end+=1
collector=text[start:end-1]
fixture=r"""
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import org.amnezia.vpn.protocol.ProtocolState
class VpnService {class Builder}
class Policy {var live=true;fun current(ticket:Long)=live}
class Primary(val observed:MutableStateFlow<ProtocolState>) {
 var calls=0;var fail=false;var deferred=false;var hook:(()->Unit)?=null
 fun reconnectVpn(builder:VpnService.Builder,protect:(Int)->Boolean){calls++;if(fail)throw IllegalStateException("controlled failure");hook?.invoke();if(!deferred)observed.value=ProtocolState.CONNECTED}
}
class Fixture {
 val primaryState=MutableStateFlow(ProtocolState.CONNECTED);val state=MutableStateFlow(ProtocolState.CONNECTED)
 val primary=Primary(primaryState);val policy=Policy();val ticket=1L;var primaryRetired=false;var dnsStarted=false;var reason="primary"
 fun watch(scope:CoroutineScope)=scope.launch(start=CoroutineStart.UNDISPATCHED){val ownedTicket=1L;primaryState.collect {current -> @@COLLECTOR@@}}
 fun reconnectVpn(vpnBuilder:VpnService.Builder,protect:(Int)->Boolean){@@RECONNECT@@}
}
fun main()=runBlocking {
 var checks=0
 fun expect(ok:Boolean,label:String){checks++;check(ok){label}}
 val scope=CoroutineScope(SupervisorJob()+Dispatchers.Unconfined)
 val healthy=Fixture();val h=healthy.watch(scope)
 healthy.state.value=ProtocolState.RECONNECTING // actual service's pre-delegate transition
 healthy.reconnectVpn(VpnService.Builder()){true};yield()
 expect(healthy.primary.calls==1,"primary reconnect invoked exactly once")
 expect(healthy.state.value==ProtocolState.CONNECTED,"fresh primary CONNECTED after reconnect must propagate through wrapper")
 val queuedScope=CoroutineScope(coroutineContext+SupervisorJob())
 val queued=Fixture();val q=queued.watch(queuedScope)
 queued.state.value=ProtocolState.RECONNECTING;queued.reconnectVpn(VpnService.Builder()){true};yield()
 expect(queued.state.value==ProtocolState.CONNECTED,"fast backend completion cannot be lost to StateFlow conflation")
 q.cancel();queuedScope.cancel()
 val delayed=Fixture();val d=delayed.watch(scope);delayed.primary.deferred=true
 delayed.state.value=ProtocolState.RECONNECTING;delayed.reconnectVpn(VpnService.Builder()){true};yield()
 expect(delayed.state.value==ProtocolState.RECONNECTING,"no CONNECTED without backend completion")
 delayed.primaryState.value=ProtocolState.CONNECTED;yield()
 expect(delayed.state.value==ProtocolState.CONNECTED,"deferred actual backend completion restores wrapper")
 val failure=Fixture();val f=failure.watch(scope);failure.primary.fail=true
 failure.state.value=ProtocolState.RECONNECTING
 expect(runCatching{failure.reconnectVpn(VpnService.Builder()){true}}.isFailure,"reconnect failure remains visible")
 yield();expect(failure.state.value==ProtocolState.RECONNECTING,"failed reconnect must never assert healthy")
 val dns=Fixture();val n=dns.watch(scope);dns.dnsStarted=true;dns.state.value=ProtocolState.RECONNECTING
 dns.reconnectVpn(VpnService.Builder()){true}
 expect(dns.primary.calls==0&&dns.reason=="dns_network_change"&&dns.state.value==ProtocolState.RECONNECTING,"effective DNS branch unchanged")
 val stale=Fixture();val s=stale.watch(scope);stale.policy.live=false;stale.primary.deferred=true
 stale.state.value=ProtocolState.RECONNECTING;stale.reconnectVpn(VpnService.Builder()){true};stale.primaryState.value=ProtocolState.CONNECTED;yield()
 expect(stale.state.value==ProtocolState.RECONNECTING,"retired generation cannot publish connected")
 for(retireGeneration in listOf(true,false)) {
  val retired=Fixture();val j=retired.watch(scope)
  retired.primary.hook={if(retireGeneration)retired.policy.live=false else retired.primaryRetired=true}
  retired.state.value=ProtocolState.RECONNECTING;retired.reconnectVpn(VpnService.Builder()){true};yield()
  expect(retired.state.value==ProtocolState.RECONNECTING,"owner retired during native delegate cannot publish connected")
  j.cancel()
 }
 listOf(h,d,f,n,s).forEach{it.cancel()};scope.cancel()
 println("actual-primary-reconnect checks=$checks PASS")
}
""".replace('@@COLLECTOR@@',collector).replace('@@RECONNECT@@',reconnect)
(a.output/'PrimaryReconnect.kt').write_text(fixture,encoding='utf8')
cache=Path.home()/'.gradle/caches/modules-2/files-2.1'
def jar(group,name,version):
 hits=list((cache/group/name/version).glob('*/*.jar'));assert len(hits)==1,(group,name,version);return hits[0]
stdlib=jar('org.jetbrains.kotlin','kotlin-stdlib','2.1.0');annotations=jar('org.jetbrains','annotations','13.0');coroutines=jar('org.jetbrains.kotlinx','kotlinx-coroutines-core-jvm','1.8.1')
compiler=[jar('org.jetbrains.kotlin','kotlin-compiler-embeddable','2.1.0'),stdlib,jar('org.jetbrains.kotlin','kotlin-script-runtime','2.1.0'),jar('org.jetbrains.kotlin','kotlin-reflect','1.6.10'),jar('org.jetbrains.intellij.deps','trove4j','1.0.20200330'),annotations,coroutines]
cp=os.pathsep.join(map(str,[stdlib,annotations,coroutines]));java=Path.home()/'devtools/jdk-17/bin/java.exe';target=a.output/'primary-reconnect.jar'
cmd=[str(java),'-Xmx384m','-cp',os.pathsep.join(map(str,compiler)),'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler','-no-stdlib','-no-reflect','-classpath',cp,'-d',str(target),str(root/'client/android/protocolApi/src/main/kotlin/ProtocolState.kt'),str(a.output/'PrimaryReconnect.kt')]
with (a.output/'compile.log').open('w',encoding='utf8') as log:c=subprocess.run(cmd,stdout=log,stderr=subprocess.STDOUT,timeout=60)
if c.returncode:print((a.output/'compile.log').read_text());raise SystemExit(c.returncode)
with (a.output/'test.log').open('w',encoding='utf8') as log:t=subprocess.run([str(java),'-Xmx128m','-cp',str(target)+os.pathsep+cp,'PrimaryReconnectKt'],stdout=log,stderr=subprocess.STDOUT,timeout=15)
(a.output/'receipt.json').write_text(json.dumps({'source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'compile_exit':c.returncode,'test_exit':t.returncode,'actual_reconnect_and_collector_extracted':True},indent=2)+'\n');print((a.output/'test.log').read_text());raise SystemExit(t.returncode)
