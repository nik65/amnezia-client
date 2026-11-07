"""Execute actual production cleanup fragments; host JVM only, no app or sockets."""
from pathlib import Path
import argparse, hashlib, json, os, subprocess
p=argparse.ArgumentParser();p.add_argument('--source',type=Path);p.add_argument('--output',type=Path,required=True)
a=p.parse_args();root=Path(__file__).resolve().parents[3]
a.source=a.source or root/'client/android/src/org/amnezia/vpn/DnsFallbackProtocol.kt'
s=a.source.read_text(encoding='utf-8');a.output.mkdir(parents=True,exist_ok=True)
def block(start):
    at=s.index(start);begin=s.index('{',at);end=begin+1;depth=1
    while depth:
        if s[end]=='{':depth+=1
        elif s[end]=='}':depth-=1
        end+=1
    return s[at:end]
marker='    private fun retireFailedDnsReplacement('
helper=block(marker) if marker in s else ''
stop_method=block('    override fun stopVpn()').replace('override fun','fun',1)
finally_at=s.index('} finally {',s.index('private suspend fun prepareDns'))
begin=s.index('{',finally_at);end=begin+1;depth=1
while depth:
    if s[end]=='{':depth+=1
    elif s[end]=='}':depth-=1
    end+=1
cleanup=s[begin+1:end-1]
entry=''
health_at=s.index('                val retainedHealthy = ')
health_end=s.index('\n                if (policy.current',health_at)
retained_health=s[health_at:health_end].strip()+'\nreturn retainedHealthy'
if 'val retained = pendingTransport' in s:
    at=s.index('            val retained = pendingTransport');stop=s.index('            for (resolver',at);entry=s[at:stop]
fixture=r'''
private enum class ProtocolState { UNKNOWN, CONNECTED, DISCONNECTED }
private class VpnStartException(message:String):Exception(message)
private fun <T> runBlocking(body:()->T)=body()
private class DnsFallbackTransport(val events:MutableList<String>) {
 var stopped=false
 val isAlive get()=!stopped
 fun verify(fallback:Any,protect:Any)=true
 fun close(){events.add("close");stopped=true}
}
private class Fixture {
 val events=mutableListOf<String>()
 var nativeActive=true;var dnsStarted=true;var stopResult=true;var nativeReplacementStarted=true
 var stopThrows=false
 var reason="";var stage="";var starts=0
 val state=State();class State{var value=ProtocolState.CONNECTED}
 val dnsState=State();val fallback=Any();val protect=Any()
 fun vpnReachable()=true
 val dnsOwner=Owner();class Owner{var revoked=false;fun revokeProof(){revoked=true}}
 val xray=Native();inner class Native{fun stopVpnVerified():Boolean{events.add("stop");if(stopThrows)error("native fixture");if(stopResult)nativeActive=false;return stopResult}}
 val owned=mutableSetOf<DnsFallbackTransport>()
 var pendingTransport:DnsFallbackTransport?=null
 var candidate:DnsFallbackTransport?=null
 fun closeTransport(value:DnsFallbackTransport?){value?.close();if(value?.stopped==true)owned.remove(value)}
 @@HELPER@@
 fun canRetain(previous:DnsFallbackTransport?):Boolean{@@RETAINED_HEALTH@@}
 fun finish(){@@CLEANUP@@}
 fun retry(){@@ENTRY@@
   starts++
 }
 fun create(){candidate=DnsFallbackTransport(events);pendingTransport=candidate;owned.add(candidate!!)}
}
private class StopFixture {
 val events=mutableListOf<String>();val lifecycle=Any();var active=true;var joinedResult=true
 var dnsStarted=true;var primaryRetired=true;var stopResult=true;var stopThrows=false;var cleanupConfirmed=false;var reason=""
 val state=Fixture.State()
 class Policy{fun stop(){}};val policy=Policy()
 class Owner{fun retire(){}};val dnsOwner=Owner()
 class Probe{fun disconnect(){}};var primaryProbe:Probe?=Probe()
 class Job{var cancelled=false;fun cancel(){cancelled=true};fun join(){}}
 class Workers{var cancelled=false;fun cancel(){cancelled=true}}
 var monitor:Job?=Job();var workers:Workers?=Workers()
 val ownedTransports=mutableSetOf<DnsFallbackTransport>()
 var transport:DnsFallbackTransport?=null;var pendingTransport:DnsFallbackTransport?=null
 inner class Native{fun stopVpnVerified():Boolean{events.add("stop");if(stopThrows)error("native fixture");return stopResult}}
 val xray=Native()
 inner class Primary{fun stopVpn(){events.add("primaryStop")};fun readNativeIdleObservation()=Idle()}
 class Idle{val isAbsent=true};val primary=Primary()
 fun closeTransport(value:DnsFallbackTransport?){value?.close();if(value?.stopped==true)ownedTransports.remove(value)}
 fun <T> withTimeoutOrNull(ms:Long,body:()->T):T?=if(joinedResult)body() else null
 fun create(){transport=DnsFallbackTransport(events);pendingTransport=DnsFallbackTransport(events);ownedTransports.add(transport!!);ownedTransports.add(pendingTransport!!)}
 @@STOP@@
}
fun main(){
 var checks=0
 val failed=Fixture();failed.create();failed.finish()
 check(!failed.nativeActive && !failed.dnsStarted){"failed TUN consumer survived candidate retirement"}
 check(failed.events==listOf("stop","close")){"native stop must precede relay close"}
 check(failed.pendingTransport==null && failed.owned.isEmpty());checks++
 val uncertain=Fixture();uncertain.create();val exact=uncertain.candidate;uncertain.stopResult=false;uncertain.finish()
 check(uncertain.nativeActive && uncertain.dnsStarted && uncertain.pendingTransport===exact)
 check(exact?.stopped==false && uncertain.owned.contains(exact))
 check(uncertain.state.value==ProtocolState.UNKNOWN && uncertain.dnsOwner.revoked);checks++
 check(runCatching{uncertain.retry()}.isFailure)
 check(uncertain.starts==0 && uncertain.pendingTransport===exact && exact?.stopped==false);checks++
 uncertain.stopResult=true;uncertain.retry()
 check(!uncertain.nativeActive && !uncertain.dnsStarted && uncertain.pendingTransport==null)
 check(exact?.stopped==true && uncertain.starts==1 && uncertain.owned.isEmpty());checks++
 val cancelledBeforeNative=Fixture();cancelledBeforeNative.create();cancelledBeforeNative.nativeReplacementStarted=false
 cancelledBeforeNative.finish()
 check(cancelledBeforeNative.events==listOf("close") && cancelledBeforeNative.pendingTransport==null)
 check(cancelledBeforeNative.nativeActive){"pre-native cancellation stopped unrelated active consumer"};checks++
 val cancelledAfterNative=Fixture();cancelledAfterNative.create();cancelledAfterNative.finish()
 check(cancelledAfterNative.events==listOf("stop","close"));checks++
 val previousStopFailed=Fixture();val oldRelay=DnsFallbackTransport(previousStopFailed.events)
 previousStopFailed.owned.add(oldRelay);previousStopFailed.create();previousStopFailed.stopResult=false
 previousStopFailed.finish()
 check(!oldRelay.stopped && previousStopFailed.owned.size==2){"failed stop must preserve both relays"};checks++
 previousStopFailed.nativeReplacementStarted=false
 check(!previousStopFailed.canRetain(oldRelay)){"pending failed cleanup regained stale committed health"};checks++
 previousStopFailed.pendingTransport=null
 check(previousStopFailed.canRetain(oldRelay)){"unrelated retained healthy path was disabled"};checks++
 val throwing=Fixture();throwing.create();throwing.stopThrows=true;throwing.finish()
 check(throwing.dnsStarted && throwing.pendingTransport!=null && throwing.candidate?.stopped==false);checks++
 val stopOk=StopFixture();stopOk.create();stopOk.stopVpn()
 check(stopOk.cleanupConfirmed && !stopOk.dnsStarted && stopOk.ownedTransports.isEmpty())
 check(stopOk.events.first()=="stop" && stopOk.transport==null && stopOk.pendingTransport==null);checks++
 val stopFailed=StopFixture();stopFailed.create();val committed=stopFailed.transport;val pending=stopFailed.pendingTransport
 stopFailed.stopResult=false;stopFailed.stopVpn()
 check(!stopFailed.cleanupConfirmed && stopFailed.dnsStarted && committed?.stopped==false && pending?.stopped==false)
 check(stopFailed.transport===committed && stopFailed.pendingTransport===pending && stopFailed.ownedTransports.size==2)
 stopFailed.stopResult=true;stopFailed.stopVpn();check(stopFailed.cleanupConfirmed && committed?.stopped==true && pending?.stopped==true);checks++
 val unjoined=StopFixture();unjoined.create();val exactJob=unjoined.monitor;val exactWorkers=unjoined.workers
 unjoined.joinedResult=false;unjoined.stopVpn()
 check(!unjoined.cleanupConfirmed && unjoined.events.isEmpty() && unjoined.ownedTransports.size==2)
 check(unjoined.monitor===exactJob && unjoined.workers===exactWorkers && exactWorkers?.cancelled==false)
 unjoined.joinedResult=true;unjoined.stopVpn();check(unjoined.cleanupConfirmed && unjoined.monitor==null && unjoined.workers==null);checks++
 val terminalThrows=StopFixture();terminalThrows.create();terminalThrows.stopThrows=true;terminalThrows.stopVpn()
 check(!terminalThrows.cleanupConfirmed && terminalThrows.dnsStarted && terminalThrows.ownedTransports.size==2)
 terminalThrows.stopThrows=false;terminalThrows.stopVpn();check(terminalThrows.cleanupConfirmed);checks++
 val startGap=StopFixture();startGap.create();startGap.dnsStarted=false;startGap.joinedResult=false
 startGap.stopVpn();check(startGap.ownedTransports.all{!it.stopped} && startGap.monitor!=null){"native start window relay retired before monitor joined"};checks++
 val preflightOnly=StopFixture();preflightOnly.create();preflightOnly.dnsStarted=false;preflightOnly.primaryRetired=false
 preflightOnly.joinedResult=false;preflightOnly.stopVpn()
 check(preflightOnly.ownedTransports.isEmpty() && !preflightOnly.cleanupConfirmed && preflightOnly.monitor!=null);checks++
 println("failedStartCleanupChecks=$checks passed=true noDeviceOrSockets=true")
}
'''.replace('@@HELPER@@',helper).replace('@@CLEANUP@@',cleanup).replace('@@ENTRY@@',entry).replace('@@RETAINED_HEALTH@@',retained_health).replace('@@STOP@@',stop_method)
k=a.output/'ActualFailedCleanup.kt';k.write_text(fixture,encoding='utf-8')
cache=Path.home()/'.gradle/caches/modules-2/files-2.1'
def jar(group,name,version):
    hits=list((cache/group/name/version).glob('*/*.jar'))
    if len(hits)!=1:raise SystemExit('Missing exact cached compiler dependency')
    return hits[0]
jars=[jar('org.jetbrains.kotlin','kotlin-compiler-embeddable','2.1.0'),jar('org.jetbrains.kotlin','kotlin-stdlib','2.1.0'),jar('org.jetbrains.kotlin','kotlin-script-runtime','2.1.0'),jar('org.jetbrains.kotlin','kotlin-reflect','1.6.10'),jar('org.jetbrains.intellij.deps','trove4j','1.0.20200330'),jar('org.jetbrains','annotations','13.0'),jar('org.jetbrains.kotlinx','kotlinx-coroutines-core-jvm','1.8.1')]
cp=os.pathsep.join(map(str,jars));classes=a.output/'classes'
c=subprocess.run(['java','-Xmx384m','-cp',cp,'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler','-no-stdlib','-no-reflect','-classpath',cp,'-d',str(classes),str(k)],capture_output=True,text=True,timeout=60)
(a.output/'compile.txt').write_text(c.stdout+c.stderr,encoding='utf-8')
if c.returncode:raise SystemExit('Compilation failed; see compile.txt')
r=subprocess.run(['java','-Xmx128m','-cp',str(classes)+os.pathsep+cp,'ActualFailedCleanupKt'],capture_output=True,text=True,timeout=15)
(a.output/'run.txt').write_text(r.stdout+r.stderr,encoding='utf-8')
receipt={'sourceSha256':hashlib.sha256(a.source.read_bytes()).hexdigest(),'fixtureSha256':hashlib.sha256(k.read_bytes()).hexdigest(),'compileExit':c.returncode,'runExit':r.returncode,'passed':r.returncode==0,'actualFragments':True,'deviceOrSockets':False}
(a.output/'receipt.json').write_text(json.dumps(receipt,indent=2),encoding='utf-8');print(json.dumps(receipt))
raise SystemExit(0 if r.returncode==0 else 1)


