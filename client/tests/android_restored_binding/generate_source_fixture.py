"""Extract actual native Kotlin lifecycle/readback bodies; fake Android/native effects only."""
from pathlib import Path
import sys
root=Path(sys.argv[1]);out=Path(sys.argv[2]);wire_path=Path(sys.argv[3]) if len(sys.argv)>3 else root/'client/android/wireguard/src/main/kotlin/org/amnezia/vpn/protocol/wireguard/Wireguard.kt';s=wire_path.read_text(encoding='utf-8')
def block(marker):
 i=s.index(marker);a=s.index('{',i);j=a+1;depth=1;quote=None;escape=False;line=False;comment=False
 while depth:
  c=s[j];n=s[j+1:j+2]
  if line:
   if c=='\n':line=False
  elif comment:
   if c=='*' and n=='/':comment=False;j+=1
  elif quote:
   if escape:escape=False
   elif c=='\\':escape=True
   elif c==quote:quote=None
  elif c=='/' and n=='/':line=True;j+=1
  elif c=='/' and n=='*':comment=True;j+=1
  elif c in ['"',"'"]:quote=c
  elif c=='{':depth+=1
  elif c=='}':depth-=1
  j+=1
 return s[i:j].removeprefix('override ')
markers=['override val migrationCleanupObservation:', 'override val migrationObservation:', 'override val statistics:', 'override suspend fun startVpn(', 'private fun getLastHandshake()', 'private fun launchStatusJob()', 'private fun turnOffVpn()', 'override fun stopVpn()', 'override fun reconnectVpn(', 'override fun readRestoredSessionBinding()', 'override fun stopVpnIfBound(']
# expression-body stopIfBound contains a lambda and the extractor includes it through the matching brace.
actual='\n'.join(block(m) for m in markers)
handshake_helpers=s[s.index('internal fun wireguardStateForHandshake'):s.index('open class Wireguard :')].replace('internal fun','private fun')
reset_start=s.index('            cleanedNonce = \"\"',s.index('            val fd = tunFd.detachFd()'))
reset=s[reset_start:s.index('            tunnelHandle = try {',reset_start)]
prefix=r"""
import org.amnezia.vpn.protocol.*
import org.json.JSONObject
import kotlinx.coroutines.*
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread
private const val TAG="owned-native-fixture"
private enum class State {DISCONNECTED,CONNECTED,UNKNOWN}
private typealias ProtocolState=State
private val CONNECTED=State.CONNECTED
private val UNKNOWN=State.UNKNOWN
private const val MAX_UNREADABLE_HANDSHAKE_READS=5
private val DISCONNECTED=State.DISCONNECTED
private class FakeState {@Volatile var value=DISCONNECTED}
private class FakeJob {fun cancel(){}}
private class Address {val isIpv4=true;override fun toString()="10.0.0.2/32"}
private class WireguardConfig {val publicKeyHex="00".repeat(32);val addresses=listOf(Address())}
private class Builder
private class VpnException(message:String):RuntimeException(message)
private object Log {@Volatile var afterHandshake:(()->Unit)?=null;fun d(tag:String,message:String){check(tag.isNotEmpty()&&message.isNotEmpty())};fun v(tag:String,message:String){check(tag.isNotEmpty()&&message.isNotEmpty());val callback=afterHandshake;afterHandshake=null;callback?.invoke()};fun e(tag:String,message:String){check(tag.isNotEmpty()&&message.isNotEmpty())};fun w(tag:String,message:String){check(tag.isNotEmpty()&&message.isNotEmpty())}}
private object GoBackend {
 var active=false
 var handshake="1"
 var beforeStart:(()->Unit)?=null
 fun awgTurnOff(handle:Int){check(handle==42);active=false}
 fun awgGetConfig(handle:Int):String?=if(active&&handle==42)"public_key=${"00".repeat(32)}\nlast_handshake_time_sec=$handshake\nrx_bytes=1\ntx_bytes=2" else null
 fun awgGetSocketV4(handle:Int)=if(active&&handle==42)10 else -1
 fun awgGetSocketV6(handle:Int)=if(active&&handle==42)11 else -1
 fun awgVersion()="owned-fake"
}
private fun parseLastHandshakeTime(value:String?):Long?=value?.lineSequence()?.firstOrNull{it.startsWith("last_handshake_time_sec=")}?.substringAfter('=')?.toLongOrNull()
private class Statistics {
 fun setRxBytes(value:Long){check(value>=0)};fun setTxBytes(value:Long){check(value>=0)}
 companion object {val EMPTY_STATISTICS=Statistics();fun build(block:Statistics.()->Unit)=Statistics().apply(block)}
}
private class ActualWireguard {
 private val nativeSessionGuard=NativeSessionGuard()
 private var tunnelHandle=-1
 private var config:WireguardConfig?=null
 private var migrationConnectionNonce=""
 private var cleanedNonce=""
 private val scope=CoroutineScope(SupervisorJob()+Dispatchers.Default)
 private var statusJob:Job?=null
 private var statusJobGeneration=0L
 private val state=FakeState()
 fun startStatusFixture()=nativeSessionGuard.locked {launchStatusJob();statusJob!!}
 fun statusValue()=state.value
 fun currentStatusJob()=nativeSessionGuard.locked {statusJob}
 fun closeFixture(){scope.cancel()}
 private fun parseConfig(config:JSONObject):WireguardConfig {check(config.optString("protocol","")=="AWG");return WireguardConfig()}
 private fun start(config:WireguardConfig,builder:Builder,protect:(Int)->Boolean,stopExistingVpn:Boolean=false){
  check(config.publicKeyHex.isNotEmpty());check(builder.javaClass.simpleName.isNotEmpty());check(protect(1));if(stopExistingVpn&&tunnelHandle>=0)turnOffVpn();ACTUAL_NATIVE_START_RESET
  tunnelHandle=42;GoBackend.beforeStart?.invoke();GoBackend.active=true
 }
"""
post=r"""
}
fun runActualNativeFixture(){runBlocking {
 val old=NativeSessionIdentity("11111111-1111-4111-8111-111111111111","22222222-2222-4222-8222-222222222222","33333333-3333-4333-8333-333333333333")
 fun cfg(i:NativeSessionIdentity)=JSONObject().put("nativeServiceInstanceId",i.serviceInstanceId).put("nativeServiceActivationId",i.serviceActivationId).put("migrationConnectionNonce",i.connectionNonce).put("nativeSessionServerId","server-local-id").put("protocol","AWG")
 val actual=ActualWireguard();actual.startVpn(cfg(old),Builder()){true}
 val binding=actual.readRestoredSessionBinding()!!;check(binding.descriptor.identity==old)
 actual.reconnectVpn(Builder()){true};check(actual.readRestoredSessionBinding()!!.descriptor.identity==old);check(actual.migrationCleanupObservation==null)
 val newer=old.copy(serviceActivationId="55555555-5555-4555-8555-555555555555")
 actual.stopVpn();actual.startVpn(cfg(newer),Builder()){true}
 check(!actual.stopVpnIfBound(old));check(actual.readRestoredSessionBinding()!!.descriptor.identity==newer)
 check(actual.stopVpnIfBound(newer));check(actual.readRestoredSessionBinding()==null)
 val receipt=JSONObject(actual.migrationCleanupObservation!!);check(receipt.optString("serviceActivationId","")==newer.serviceActivationId)
 val entered=CountDownLatch(1);val release=CountDownLatch(1);val readerDone=CountDownLatch(1);val stopDone=CountDownLatch(1)
 GoBackend.beforeStart={entered.countDown();check(release.await(5,TimeUnit.SECONDS))}
 val starter=thread {runBlocking {actual.startVpn(cfg(old),Builder()){true}}}
 check(entered.await(3,TimeUnit.SECONDS))
 val reader=thread {val sample=actual.readRestoredSessionBinding();if(sample!=null)check(sample.descriptor.identity==old&&sample.deviceIpv4Address=="10.0.0.2");readerDone.countDown()}
 val stopper=thread {actual.stopVpn();stopDone.countDown()}
 check(!readerDone.await(30,TimeUnit.MILLISECONDS)&&!stopDone.await(30,TimeUnit.MILLISECONDS))
 release.countDown();starter.join();reader.join();stopper.join();GoBackend.beforeStart=null
 for(oldHandshake in listOf("invalid","-1")){
  actual.startVpn(cfg(old),Builder()){true};GoBackend.handshake=oldHandshake
  val paused=CountDownLatch(1);val resume=CountDownLatch(1)
  Log.afterHandshake={paused.countDown();check(resume.await(5,TimeUnit.SECONDS))}
  val oldJob=actual.startStatusFixture();check(paused.await(3,TimeUnit.SECONDS))
  actual.stopVpn();GoBackend.handshake=if(oldHandshake=="invalid")"1" else "0"
  actual.startVpn(cfg(newer),Builder()){true};val replacement=actual.startStatusFixture()
  if(oldHandshake=="invalid")withTimeout(3000){replacement.join()}
  resume.countDown();withTimeout(3000){oldJob.join()}
  if(oldHandshake=="invalid")check(actual.statusValue()==CONNECTED){"old cancelled status job overwrote replacement state"}
  else check(actual.statusValue()!=UNKNOWN&&actual.currentStatusJob()===replacement){"old terminal status job cleared replacement owner"}
  actual.stopVpn()
 }
 actual.closeFixture()
 println("Actual Wireguard extracted lifecycle/read-vs-two-writers/old-status-commit/binding/conditional-stop fixture PASS")
}}
"""
(out/'ActualNative.kt').write_text(prefix.replace('private class ActualWireguard {',handshake_helpers+'\nprivate class ActualWireguard {').replace('ACTUAL_NATIVE_START_RESET',reset)+actual+post,encoding='utf-8')
(out/'ActualJson.kt').write_text(r"""package org.json
class JSONObject {
 private val fields=linkedMapOf<String,Any?>()
 constructor()
 constructor(raw:String){Regex("\\\"([^\\\"]+)\\\":\\\"([^\\\"]*)\\\"").findAll(raw).forEach{fields[it.groupValues[1]]=it.groupValues[2]}}
 fun put(key:String,value:Any?):JSONObject{fields[key]=value;return this}
 fun optString(key:String,fallback:String)=fields[key] as? String ?: fallback
 override fun toString()="{"+fields.entries.joinToString(","){org.amnezia.vpn.protocol.NativeSessionWire.quote(it.key)+":"+when(val value=it.value){is String->org.amnezia.vpn.protocol.NativeSessionWire.quote(value);else->value.toString()}}+"}"
}
""",encoding='utf-8')
(out/'ActualAndroid.kt').write_text(r"""package android.util
object Base64 {const val NO_WRAP=2;fun encodeToString(value:ByteArray,flags:Int):String{check(flags==NO_WRAP);return java.util.Base64.getEncoder().encodeToString(value)}}
""",encoding='utf-8')

service=(root/'client/android/src/org/amnezia/vpn/AmneziaVpnService.kt').read_text(encoding='utf-8')
wire=s
s=service
method=block('private fun requestBoundRestoreStatus(').replace('private fun','fun',1)
s=wire
servicePrefix=r"""
import org.amnezia.vpn.protocol.*
import kotlinx.coroutines.*
import java.util.concurrent.Executors
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
private annotation class MainThread
private class Messenger
private class JSONException:RuntimeException()
private class ServiceBundle {val data=linkedMapOf<String,String>();fun putString(k:String,v:String){data[k]=v}}
private enum class ServiceEvent {STATUS;fun packToMessage(body:ServiceBundle.()->Unit)=ServiceBundle().apply(body)}
private class ClientMessenger {val sent=LinkedBlockingQueue<ServiceBundle>();fun send(body:()->ServiceBundle){sent.add(body())}}
private class FakeServiceProtocol(var read:()->NativeSessionBinding?){fun readRestoredSessionBinding()=read()}
private class ActualService {
 private data class ActiveNativeSession(val protocol:FakeServiceProtocol,val descriptor:NativeSessionDescriptor)
 private val dispatcher=Executors.newSingleThreadExecutor().asCoroutineDispatcher()
 private val mainScope=CoroutineScope(SupervisorJob()+dispatcher)
 private val restoreStatusGate=RestoreStatusGate<ActiveNativeSession>()
 private var activeNativeSession:ActiveNativeSession?=null
 private var isConnected=true
 private val clientMessengers=mutableMapOf<Messenger,ClientMessenger>()
 val requester=Messenger();val client=ClientMessenger()
 init{clientMessengers[requester]=client}
 fun install(protocol:FakeServiceProtocol,descriptor:NativeSessionDescriptor)=runBlocking(dispatcher){val owner=ActiveNativeSession(protocol,descriptor);activeNativeSession=owner;restoreStatusGate.activate(owner)}
 fun ask(id:String)=runBlocking(dispatcher){requestBoundRestoreStatus(requester,id,"7")}
 suspend fun finish(){mainScope.coroutineContext[Job]!!.children.toList().joinAll()}
 fun close(){mainScope.cancel();dispatcher.close()}
"""
servicePost=r"""
}
fun runActualServiceFixture()=runBlocking {
 val identity=NativeSessionIdentity("11111111-1111-4111-8111-111111111111","22222222-2222-4222-8222-222222222222","33333333-3333-4333-8333-333333333333")
 val descriptor=NativeSessionDescriptor(identity,"server-local-id","AWG")
 val binding=NativeSessionBinding(descriptor,java.util.Base64.getEncoder().encodeToString(ByteArray(32)),"10.0.0.2",1)
 val protocol=FakeServiceProtocol{binding};val service=ActualService();service.install(protocol,descriptor)
 service.ask("44444444-4444-4444-8444-444444444444");withTimeout(3000){service.finish()}
 check(service.client.sent.poll(2,TimeUnit.SECONDS)?.data?.get("restoreSnapshot")==binding.snapshot("44444444-4444-4444-8444-444444444444","7"))
 val entered=CountDownLatch(1);val release=CountDownLatch(1)
 protocol.read={entered.countDown();check(release.await(5,TimeUnit.SECONDS));binding}
 service.ask("44444444-4444-4444-8444-444444444444");check(entered.await(3,TimeUnit.SECONDS))
 // Same cached protocol reference, new logical activation before IO snapshot commits on Main.
 service.install(protocol,descriptor.copy(identity=identity.copy(serviceActivationId="55555555-5555-4555-8555-555555555555")))
 release.countDown();withTimeout(3000){service.finish()};check(service.client.sent.isEmpty());service.close()
 println("Actual Service extracted IO-snapshot/final-Main-fence fixture PASS")
}
"""
(out/'ActualService.kt').write_text(servicePrefix+method+servicePost,encoding='utf-8')

activity=(Path(sys.argv[4]) if len(sys.argv)>4 else root/'client/android/src/org/amnezia/vpn/AmneziaActivity.kt').read_text(encoding='utf-8')
s=activity
activityMethods='\n'.join(block(m).replace('private fun','fun',1) for m in ['private fun invalidateRestoreRequest()', 'private fun notifyNativeSessionObservedWhenQtReady(', 'private fun notifyServiceDisconnectedWhenQtReady()', 'private fun notifyRestoreServiceReadyWhenQtReady()', 'fun qtAndroidControllerInitialized()', 'fun requestRestoreStatus(', 'fun stopBound(', 'private fun adoptConnectedService(', 'private fun doUnbindService()'])
# Control binding callbacks moved into per-bind closure; compile their real signatures/bodies.
s=block('private fun doBindService()')
activityMethods+='\n'+'\n'.join(block(m) for m in ['override fun onServiceConnected(', 'override fun onServiceDisconnected(', 'override fun onBindingDied('])
s=activity
status=block('ServiceEvent.STATUS ->').replace('ServiceEvent.','ActivityEvent.')
# New admission/discovery envelopes have their own actual-method fixture; retain real bound-restore tail.
status='ActivityEvent.STATUS -> {\n'+status[status.index('                        val request = msg.data?.get("restoreRequestId")'):]
activityMethods=activityMethods.replace('Log.','ActivityLog.').replace('TAG,','ACTIVITY_TAG,')
activityMethods=re.sub(r'\bMessenger\b','ActivityReceiverMessenger',activityMethods) if False else activityMethods
import re
activityMethods=re.sub(r'\bMessenger\b','ActivityReceiverMessenger',activityMethods)
s=activity
dead=block('onDeadObjectException = {').replace('onDeadObjectException = {','fun onDeadObjectExceptionFixture() {',1)
activityMethods+='\n'+dead
receiver=block('private fun createBoundActivityMessenger()').replace('private fun','fun',1)
for original,replacement in [('Messenger','ActivityReceiverMessenger'),('Handler','ActivityReceiverHandler'),('Looper','ActivityReceiverLooper'),('Message','ActivityMessage')]:
 receiver=re.sub(r'\b'+original+r'\b',replacement,receiver)
s=wire
activityMethods+='\n'+receiver

s=wire
activityPrefix=r"""
import org.amnezia.vpn.protocol.*
import kotlinx.coroutines.*
import java.util.concurrent.Executors
private const val ACTIVITY_TAG="owned-activity-fixture"
private object ActivityLog {fun w(tag:String,message:String){check(tag.isNotEmpty()&&message.isNotEmpty())};fun d(tag:String,message:String){check(tag.isNotEmpty()&&message.isNotEmpty())};fun v(tag:String,message:String){check(tag.isNotEmpty()&&message.isNotEmpty())}}
private object QtAndroidController {
 val ready=mutableListOf<Long>();val snapshots=mutableListOf<String>();var legacy=0;var observed=0;var disconnected=0;var registered=false
 fun onServiceDisconnected(){check(registered);disconnected++}
 fun onNativeSessionObserved(){check(registered);observed++}
 fun onRestoreServiceReady(g:Long){check(registered);ready.add(g)}
 fun onRestoreStatus(s:String){snapshots.add(s)}
 fun onStatus(state:Int,index:Int){check(state>=0&&index>=-1);legacy++}
}
private object VpnStateStore {var reads=0;data class Saved(val serverIndex:Int);suspend fun getVpnState():Saved {reads++;return Saved(-1)}}
private enum class ActivityState {DISCONNECTED,CONNECTED}
private class ActivityBundle {val values=linkedMapOf<String,Any?>();fun get(k:String)=values[k];fun putString(k:String,v:String){values[k]=v};fun putBoolean(k:String,v:Boolean){values[k]=v};fun getStatus()=Pair(ActivityState.CONNECTED,Unit)}
private class ActivityMessage(val data:ActivityBundle?) {
 var recycled=false
 fun recycle(){check(!recycled);recycled=true}
 companion object {fun obtain(message:ActivityMessage)=ActivityMessage(message.data?.let {old->ActivityBundle().apply{values.putAll(old.values)}})}
}
private object ActivityReceiverLooper {fun getMainLooper()=this}
private open class ActivityReceiverHandler(looper:ActivityReceiverLooper) {init{check(looper===ActivityReceiverLooper)};open fun handleMessage(msg:ActivityMessage){}}
private class ComponentName(val className:String) {fun flattenToString()=className}
private class IBinder
private enum class FixtureProto(val serviceClass:Class<*>){AWG(AwgService::class.java)}
private class AwgService
private const val MSG_CLIENT_NAME="client"
private const val ACTIVITY_MESSENGER_NAME="activity"
private class ActivityReceiverMessenger {
 private var handler:ActivityReceiverHandler?=null
 constructor(value:ActivityReceiverHandler){handler=value}
 constructor(value:IBinder?){check(value!=null)}
 fun deliver(message:ActivityMessage){handler?.handleMessage(message)}
}
private enum class ActivityEvent {STATUS}
private enum class Action {REQUEST_STATUS,DISCONNECT,REGISTER_CLIENT,UNREGISTER_CLIENT;fun packToMessage(b:ActivityBundle.()->Unit)=ActivityBundle().apply(b)}
private class ActivityMessenger {
 val sent=mutableListOf<ActivityBundle>();var unregisters=0
 fun send(b:()->ActivityBundle){sent.add(b())}
 fun send(message:ActivityBundle,replyTo:ActivityReceiverMessenger){check(replyTo.javaClass.simpleName.isNotEmpty());sent.add(message)}
 fun send(action:Action,replyTo:ActivityReceiverMessenger){check(replyTo.javaClass.simpleName.isNotEmpty());if(action==Action.UNREGISTER_CLIENT)unregisters++}
 fun set(messenger:ActivityReceiverMessenger){check(messenger.javaClass.simpleName.isNotEmpty())}
 fun reset(){}
}
private class ActualActivity {
 private val dispatcher=Executors.newSingleThreadExecutor().asCoroutineDispatcher()
 private val mainScope=CoroutineScope(SupervisorJob()+dispatcher)
 private val qtInitialized=CompletableDeferred<Unit>()
 private var isServiceConnected=false
 private var isWaitingStatus=true
 private var restoreBindingGeneration=1L
 private var restoreReadySentGeneration=0L
 private var pendingRestoreRequest:String?=null
 private var legacyStatusRequestGeneration:Long?=null
 private var isBoundNativeService=true
 private var nativeObservedSentGeneration=0L
 private val vpnServiceMessenger=ActivityMessenger()
 private val serviceEventBindingGate=ServiceEventBindingGate()
 private var isInBoundState=false
 private var boundActivityMessenger:ActivityReceiverMessenger?=null
 private val activityMessenger:ActivityReceiverMessenger get()=checkNotNull(boundActivityMessenger)
 private val serviceConnection=Any()
 private var activeServiceConnection:Any?=serviceConnection
 private var boundServiceComponent:ComponentName?=null
 private var pendingControlComponent:ComponentName?=null
 private val discoveryGeneration=1L
 private val discoveryPhase="UNCERTAIN"
 private fun requestDiscoveryProbe(attempt:FixtureAttempt){}
 private var boundRemoteMessenger:ActivityReceiverMessenger?=null
 private var discoveryAttempt:FixtureAttempt?=null
 private var discoveryDeadline:Job?=null
 private val discoveryForeground=true
 private val discoveryRequestId=""
 private val proto=FixtureProto.AWG
 private class FixtureAttempt {val connection:Any?=null;val generation=0L;fun release(){}}
 private fun release(){}
 private fun invalidateDiscoveryLifecycle(){}
 private fun publishDiscovery(phase:String,reason:String="NONE"){check(phase in setOf("PENDING","UNCERTAIN"))}
 private fun ownServiceInventory():List<ComponentName>?=emptyList()

 private var unbinds=0
 private fun doBindService(){isInBoundState=true}
 fun actualConnected()=runBlocking(dispatcher){activeServiceConnection=this@ActualActivity;isInBoundState=true;onServiceConnected(ComponentName(AwgService::class.java.name),IBinder())}
 fun disconnectedCallback()=runBlocking(dispatcher){onServiceDisconnected(null)}
 fun bindingDiedCallback()=runBlocking(dispatcher){onBindingDied(null)}
 fun deadCallback()=runBlocking(dispatcher){onDeadObjectExceptionFixture()}

 private fun unbindService(connection:Any){check(connection===serviceConnection||connection===this);unbinds++}
 fun pendingBindThenUnbind()=runBlocking(dispatcher){isInBoundState=true;boundActivityMessenger=null;doUnbindService();check(unbinds==1&&vpnServiceMessenger.unregisters==0)}

 private val vpnServiceEventHandler=object:ActivityReceiverHandler(ActivityReceiverLooper){override fun handleMessage(msg:ActivityMessage){handleStatus(ActivityEvent.STATUS,msg)}}
 fun receiver()=runBlocking(dispatcher){createBoundActivityMessenger()}
 fun deliver(receiver:ActivityReceiverMessenger,message:ActivityMessage)=runBlocking(dispatcher){receiver.deliver(message)}
 fun connected()=runBlocking(dispatcher){isServiceConnected=true;isWaitingStatus=true;invalidateRestoreRequest();legacyStatusRequestGeneration=restoreBindingGeneration;notifyRestoreServiceReadyWhenQtReady()}
 fun initializeQt()=runBlocking(dispatcher){QtAndroidController.registered=true;qtAndroidControllerInitialized()}
 fun initializeQtFromForeignThread(){QtAndroidController.registered=true;qtAndroidControllerInitialized()}
 fun request(id:String,g:Long)=runBlocking(dispatcher){requestRestoreStatus(id,g)}
 fun stop(json:String)=runBlocking(dispatcher){stopBound(json)}
 suspend fun finish(){mainScope.coroutineContext[Job]!!.children.toList().joinAll()}
 fun sent()=runBlocking(dispatcher){vpnServiceMessenger.sent.toList()}
 fun status(message:ActivityMessage)=runBlocking(dispatcher){handleStatus(ActivityEvent.STATUS,message)}
 fun close(){mainScope.cancel();dispatcher.close()}
"""
activityPost=r"""
}
fun runActualActivityFixture()=runBlocking {
 val pending=ActualActivity();try{pending.pendingBindThenUnbind()}finally{pending.close()}
 val activity=ActualActivity();val readyBefore=QtAndroidController.ready.size
 activity.connected();delay(20);check(QtAndroidController.ready.size==readyBefore)
 activity.initializeQt();withTimeout(3000){activity.finish()};check(QtAndroidController.ready.size==readyBefore+1)
 val generation=QtAndroidController.ready.last();val id="44444444-4444-4444-8444-444444444444"
 activity.request(id,generation-1);withTimeout(3000){activity.finish()};check(activity.sent().isEmpty())
 activity.request(id,generation);withTimeout(3000){activity.finish()};check(activity.sent().single().get("restoreRequestId")==id)
 val snapshot="{\"schema\":1}"
 activity.status(ActivityMessage(ActivityBundle().apply{putString("restoreRequestId",id);putString("restoreBindingGeneration",generation.toString());putString("restoreSnapshot",snapshot)}))
 withTimeout(3000){activity.finish()};check(QtAndroidController.snapshots.last()==snapshot&&VpnStateStore.reads==0)
 val delivered=QtAndroidController.snapshots.size
 activity.status(ActivityMessage(ActivityBundle().apply{putString("restoreRequestId",id);putString("restoreBindingGeneration",generation.toString());putString("restoreSnapshot",snapshot)}))
 check(QtAndroidController.snapshots.size==delivered)
 activity.stop("malformed");withTimeout(3000){activity.finish()};check(activity.sent().size==1)
 activity.connected();withTimeout(3000){activity.finish()};val newer=QtAndroidController.ready.last();check(newer!=generation)
 activity.request(id,generation);withTimeout(3000){activity.finish()};check(activity.sent().size==1)
 val observedBefore=QtAndroidController.observed;val storesBefore=VpnStateStore.reads
 activity.status(ActivityMessage(ActivityBundle()));withTimeout(3000){activity.finish()}
 check(QtAndroidController.observed==observedBefore+1&&VpnStateStore.reads==storesBefore)
 activity.connected();withTimeout(3000){activity.finish()};activity.stop("malformed");withTimeout(3000){activity.finish()}
 activity.status(ActivityMessage(ActivityBundle()));withTimeout(3000){activity.finish()}
 check(QtAndroidController.observed==observedBefore+1)
 activity.close()
 val receivers=ActualActivity();val observedStart=QtAndroidController.observed
 receivers.connected();val oldReceiver=receivers.receiver();receivers.deliver(oldReceiver,ActivityMessage(ActivityBundle()));delay(20)
 check(QtAndroidController.observed==observedStart)
 receivers.initializeQt();withTimeout(3000){receivers.finish()};check(QtAndroidController.observed==observedStart+1)
 receivers.connected();val replacementReceiver=receivers.receiver();withTimeout(3000){receivers.finish()}
 receivers.deliver(oldReceiver,ActivityMessage(ActivityBundle()));withTimeout(3000){receivers.finish()};check(QtAndroidController.observed==observedStart+1)
 receivers.deliver(replacementReceiver,ActivityMessage(ActivityBundle()));withTimeout(3000){receivers.finish()};check(QtAndroidController.observed==observedStart+2)
 receivers.close()
 QtAndroidController.registered=false;val lifecycle=ActualActivity();val disconnectedBefore=QtAndroidController.disconnected
 lifecycle.actualConnected();lifecycle.disconnectedCallback();delay(20);check(QtAndroidController.disconnected==disconnectedBefore)
 lifecycle.actualConnected();lifecycle.initializeQtFromForeignThread();withTimeout(3000){lifecycle.finish()}
 check(QtAndroidController.disconnected==disconnectedBefore)
 lifecycle.disconnectedCallback();withTimeout(3000){lifecycle.finish()};check(QtAndroidController.disconnected==disconnectedBefore+1)
 lifecycle.actualConnected();lifecycle.bindingDiedCallback();withTimeout(3000){lifecycle.finish()};check(QtAndroidController.disconnected==disconnectedBefore+2)
 lifecycle.actualConnected();lifecycle.deadCallback();withTimeout(3000){lifecycle.finish()};check(QtAndroidController.disconnected==disconnectedBefore+3)
 lifecycle.close();println("Actual Activity callback-signatures/pending-unbind/Qt-ready/deferred-disconnect/challenge/native-observation/old-Binder/stale-status/stopBound fixture PASS")
}
"""
(out/'ActualActivity.kt').write_text(activityPrefix+activityMethods+'\nfun handleStatus(event:ActivityEvent,msg:ActivityMessage){when(event){'+status+'}}\n'+activityPost,encoding='utf-8')
