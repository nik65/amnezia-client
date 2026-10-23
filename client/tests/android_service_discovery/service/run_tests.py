"""Compile extracted service discovery methods only; no Android app or Gradle."""
from pathlib import Path
import os,subprocess,sys
root=Path(__file__).resolve().parents[4];out=Path(sys.argv[1]);out.mkdir(parents=True,exist_ok=True)
s=(Path(sys.argv[2]) if len(sys.argv)>2 else root/'client/android/src/org/amnezia/vpn/AmneziaVpnService.kt').read_text(encoding='utf-8')
def method(marker):
 i=s.index(marker); j=s.index('{',i); depth=1;k=j+1
 while depth:
  depth += (s[k]=='{')-(s[k]=='}');k+=1
 return s[i:k].replace('this@AmneziaVpnService','this@Fixture').replace('private suspend fun','suspend fun',1).replace('private fun','fun',1)
methods='\n'.join(method(x) for x in ['private fun discoveryJobsIdle(', 'private fun invalidateDiscoveryGrants(', 'private fun updateControlBinding(', 'private suspend fun nativeDiscoveryResult(', 'private fun requestDiscoveryStatus(', 'private fun discoveryConfigMatchesService(', 'private fun acceptDiscoveryConnect(', 'override fun onBind(', 'override fun onUnbind(', 'override fun onRebind('])
pre='''import org.amnezia.vpn.protocol.*
import kotlinx.coroutines.*
import java.util.UUID
import java.util.Locale
class IBinder
class Intent(val action:String?)
const val SERVICE_INTERFACE="system"
const val TAG="test"
object Log {fun d(tag:String,message:String){}}
open class Base {open fun onBind(intent:Intent?):IBinder?=null;open fun onUnbind(intent:Intent?):Boolean=true;open fun onRebind(intent:Intent?) {}}
class ServiceMessenger(val binder:IBinder=IBinder())
class Messenger(val id:Int)
class Bundle { val values=mutableMapOf<String,Any>();fun putString(k:String,v:String){values[k]=v};fun putBoolean(k:String,v:Boolean){values[k]=v};fun getString(k:String)=values[k] as? String }
class Message(val replyTo:Messenger?,val data:Bundle=Bundle())
enum class ServiceEvent { STATUS;fun packToMessage(f:Bundle.()->Unit):Bundle=Bundle().apply(f) }
class Client { val events=mutableListOf<Bundle>();fun send(f:()->Bundle){events.add(f())} }
class Protocol(var observation:NativeIdleObservation=NativeIdleObservation(NativeIdleState.NEVER_STARTED,1)){var pause=0L;val reads=java.util.concurrent.atomic.AtomicInteger();fun readNativeIdleObservation():NativeIdleObservation{reads.incrementAndGet();if(pause>0)Thread.sleep(pause);return observation}}
enum class VpnProto { AWG,WIREGUARD; var cached:Protocol?=null;fun peekProtocol()=cached }
const val MSG_VPN_CONFIG="config"
class JSONObject(val text:String){fun getString(k:String)=text}
class AwgService(scope:CoroutineScope):Fixture(scope)
class OpenVpnService(scope:CoroutineScope):Fixture(scope)
class XrayService(scope:CoroutineScope):Fixture(scope)
open class Fixture(val mainScope:CoroutineScope):Base() {
 data class ActiveNativeSession(val protocol:Protocol,val descriptor:NativeSessionDescriptor)
 var activeNativeSession:ActiveNativeSession?=null
 var discoveryLifecycleEpoch=1L
 val clientMessengers=java.util.concurrent.ConcurrentHashMap<Messenger,Client>()
 val observationClients=mutableSetOf<Messenger>()
 val discoveryRequestTickets=mutableMapOf<Messenger,Any>();val admissionRequests=mutableMapOf<Messenger,String>()
 val discoveryProbeJobs=mutableMapOf<Messenger,Job>();val admissionProbeJobs=mutableMapOf<Messenger,Job>()
 data class DiscoveryGrant(val requester:Messenger,val requestId:String,val generation:String,val epoch:Long,val token:String)
 val discoveryGrants=mutableMapOf<Messenger,DiscoveryGrant>()
 var connectionJob:Job?=null;var disconnectionJob:Job?=null
 var isUnknown=true;var isDisconnected=false;var isConnected=false;var isServiceBound=false
 var connects=0;var stops=0;var observationGroupBound=false;var controlGroupBound=false;val vpnServiceMessenger=ServiceMessenger()
 fun stopService(){stops++}
 fun discoveryStateIdle()=(isUnknown||isDisconnected)&&discoveryJobsIdle()
 fun connect(config:String){connects++;isUnknown=false;invalidateDiscoveryGrants()}
'''
post='''
}
fun main()=runBlocking {
 val dispatcher=newSingleThreadContext("service-fixture")
 try { withContext(dispatcher) {
 val scope=CoroutineScope(SupervisorJob()+dispatcher)
 val f=AwgService(scope);val r=Messenger(1);val client=Client();f.clientMessengers[r]=client;f.observationClients.add(r)
 suspend fun probe():Bundle {f.requestDiscoveryStatus(r,"11111111-1111-1111-1111-111111111111","7");delay(30);return client.events.last()}
 fun command(token:String)=Message(r,Bundle().apply {putString("admissionRequestId",UUID.randomUUID().toString());putString("admissionGeneration","7");putString("discoveryGrant",token);putString(MSG_VPN_CONFIG,"AWG")})
 var result=probe();check(result.getString("discoveryResult")=="IDLE")
 check(f.onBind(Intent("org.amnezia.vpn.RESTORE_OBSERVATION"))!=null);check(!f.isServiceBound)
 check(f.onUnbind(Intent("org.amnezia.vpn.RESTORE_OBSERVATION")));check(f.stops==0)
 f.onRebind(Intent("org.amnezia.vpn.RESTORE_OBSERVATION"));check(!f.isServiceBound);check(f.stops==0)
 result=probe()
 val stale=result.getString("discoveryGrant")!!;f.invalidateDiscoveryGrants();f.acceptDiscoveryConnect(command(stale));check(f.connects==0);check(client.events.last().values["admissionAccepted"]==false)
 val awg=Protocol(NativeIdleObservation(NativeIdleState.ACTIVE,2));VpnProto.AWG.cached=awg
 result=probe();check(result.getString("discoveryResult")=="ACTIVE");check(result.getString("discoveryGrant")=="")
 awg.observation=NativeIdleObservation(NativeIdleState.UNKNOWN,3);result=probe();check(result.getString("discoveryResult")=="UNKNOWN")
 awg.observation=NativeIdleObservation(NativeIdleState.VERIFIED_RETIRED,4)
 VpnProto.WIREGUARD.cached=Protocol(NativeIdleObservation(NativeIdleState.ACTIVE,1));result=probe();check(result.getString("discoveryResult")=="ACTIVE")
 VpnProto.WIREGUARD.cached=null
 val timedOutJob=Job();f.connectionJob=timedOutJob;val beforeTimeout=client.events.size
 f.requestDiscoveryStatus(r,"11111111-1111-1111-1111-111111111111","7");delay(2100)
 check(client.events.size==beforeTimeout+1);check(client.events.last().getString("discoveryResult")=="UNKNOWN");check(client.events.last().getString("discoveryGrant")=="")
 timedOutJob.complete();f.connectionJob=null
 val cancelled=scope.launch(start=CoroutineStart.UNDISPATCHED){try{awaitCancellation()}finally{withContext(NonCancellable){delay(200)}}}
 f.connectionJob=cancelled;cancelled.cancel();check(cancelled.isCancelled&&!cancelled.isCompleted)
 check(!f.discoveryJobsIdle());val beforeCancelled=client.events.size
 f.requestDiscoveryStatus(r,"11111111-1111-1111-1111-111111111111","7");delay(30);check(client.events.size==beforeCancelled)
 cancelled.join();delay(30);check(client.events.last().getString("discoveryResult")=="IDLE");f.connectionJob=null
 result=probe();val wrong=command(result.getString("discoveryGrant")!!);wrong.data.putString(MSG_VPN_CONFIG,"XRAY");f.acceptDiscoveryConnect(wrong);check(f.connects==0);check(client.events.last().values["admissionAccepted"]==false)
 awg.pause=120;val beforeReads=awg.reads.get()
 f.requestDiscoveryStatus(r,"11111111-1111-1111-1111-111111111111","7");delay(10)
 f.requestDiscoveryStatus(r,"33333333-3333-3333-3333-333333333333","8");delay(160)
 check(awg.reads.get()==beforeReads+1);awg.pause=0
 val unfinished=scope.launch(start=CoroutineStart.UNDISPATCHED){try{awaitCancellation()}finally{withContext(NonCancellable){delay(150)}}}
 f.discoveryProbeJobs[r]=unfinished;unfinished.cancel();val boundedReads=awg.reads.get()
 f.requestDiscoveryStatus(r,"11111111-1111-1111-1111-111111111111","7");delay(30);check(awg.reads.get()==boundedReads);unfinished.join()
 val identity=NativeSessionIdentity("11111111-1111-1111-1111-111111111111","22222222-2222-2222-2222-222222222222","33333333-3333-3333-3333-333333333333")
 f.activeNativeSession=Fixture.ActiveNativeSession(awg,NativeSessionDescriptor(identity,"server","AWG"))
 result=probe();check(result.getString("discoveryResult")=="UNKNOWN")
 awg.observation=NativeIdleObservation(NativeIdleState.VERIFIED_RETIRED,5,identity)
 f.isUnknown=false;f.isDisconnected=true
 val finishingCleanup=Job();f.disconnectionJob=finishingCleanup;val beforeCleanup=client.events.size
 f.requestDiscoveryStatus(r,"11111111-1111-1111-1111-111111111111","7");delay(30);check(client.events.size==beforeCleanup)
 finishingCleanup.complete();delay(30);check(client.events.size==beforeCleanup+1);result=client.events.last()
 check(result.getString("discoveryResult")=="IDLE");check(result.getString("discoveryGrant")!!.isNotEmpty());f.disconnectionJob=null
 val changedCleanup=Job();f.disconnectionJob=changedCleanup
 f.requestDiscoveryStatus(r,"11111111-1111-1111-1111-111111111111","11");delay(15);f.invalidateDiscoveryGrants();changedCleanup.complete();delay(30)
 check(client.events.last().getString("discoveryResult")=="UNKNOWN");check(client.events.last().getString("discoveryGrant")=="");f.disconnectionJob=null
 result=probe();check(result.getString("discoveryResult")=="IDLE")
 val token=result.getString("discoveryGrant")!!;val admitted=command(token);awg.pause=120;f.acceptDiscoveryConnect(admitted);f.acceptDiscoveryConnect(admitted)
 delay(10);val oldRequest=f.admissionRequests[r];f.acceptDiscoveryConnect(command(token));check(f.admissionRequests[r]==oldRequest)
 delay(160);awg.pause=0
 check(f.connects==1);check(r !in f.observationClients);check(f.isServiceBound);check(client.events.last().values["admissionAccepted"]==true)
 val eventsBefore=client.events.size;f.acceptDiscoveryConnect(admitted);check(f.connects==1);check(client.events.size==eventsBefore)
 val legacy=OpenVpnService(scope);val lr=Messenger(8);val lc=Client();legacy.clientMessengers[lr]=lc;legacy.observationClients.add(lr)
 legacy.isConnected=true;legacy.isUnknown=false;legacy.activeNativeSession=Fixture.ActiveNativeSession(Protocol(),NativeSessionDescriptor(identity,"legacy","OPENVPN"))
 legacy.requestDiscoveryStatus(lr,"11111111-1111-1111-1111-111111111111","9");delay(30);check(lc.events.last().getString("discoveryResult")=="ACTIVE")
 legacy.isConnected=false;legacy.isDisconnected=true
 legacy.requestDiscoveryStatus(lr,"11111111-1111-1111-1111-111111111111","10");delay(30);check(lc.events.last().getString("discoveryResult")=="IDLE")
 val legacyCommand=Message(lr,Bundle().apply{putString("admissionRequestId",UUID.randomUUID().toString());putString("admissionGeneration","10");putString("discoveryGrant",lc.events.last().getString("discoveryGrant")!!);putString(MSG_VPN_CONFIG,"OPENVPN")})
 legacy.acceptDiscoveryConnect(legacyCommand);delay(30);check(legacy.connects==1);check(lc.events.last().values["admissionAccepted"]==true)
 scope.cancel();println("PASS actual service discovery: empty, stale, activeUNKNOWN, uncertainclose, bothowners, pendingjob, retainedidentity, consumedgrant, promotion, duplicate")
 }} finally {dispatcher.close()}
}
'''
source=out/'ActualServiceDiscovery.kt';source.write_text(pre+methods+post,encoding='utf-8')
cache=Path.home()/'.gradle/caches/modules-2/files-2.1'
def jar(g,n,v):return next((cache/g/n/v).glob('*/*.jar'))
stdlib=jar('org.jetbrains.kotlin','kotlin-stdlib','2.1.0');co=jar('org.jetbrains.kotlinx','kotlinx-coroutines-core-jvm','1.6.4');ann=jar('org.jetbrains','annotations','13.0')
compiler=[jar('org.jetbrains.kotlin','kotlin-compiler-embeddable','2.1.0'),stdlib,jar('org.jetbrains.kotlin','kotlin-script-runtime','2.1.0'),jar('org.jetbrains.kotlin','kotlin-reflect','1.6.10'),jar('org.jetbrains.intellij.deps','trove4j','1.0.20200330'),ann,co]
java=Path.home()/'devtools/jdk-17/bin/java.exe';cp=os.pathsep.join(map(str,[stdlib,ann,co]));target=out/'tests.jar'
cmd=[str(java),'-cp',os.pathsep.join(map(str,compiler)),'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler','-no-stdlib','-no-reflect','-classpath',cp,'-d',str(target),str(root/'client/android/protocolApi/src/main/kotlin/NativeSessionBinding.kt'),str(source)]
with (out/'compile.log').open('w',encoding='utf-8') as log:r=subprocess.run(cmd,stdout=log,stderr=subprocess.STDOUT,timeout=60)
print('compile',r.returncode)
if r.returncode:sys.exit(r.returncode)
with (out/'test.log').open('w',encoding='utf-8') as log:r=subprocess.run([str(java),'-cp',str(target)+os.pathsep+cp,'ActualServiceDiscoveryKt'],stdout=log,stderr=subprocess.STDOUT,timeout=30)
print('tests',r.returncode);sys.exit(r.returncode)


