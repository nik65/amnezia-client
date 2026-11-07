"""Extract actual Activity/service consumers; replace Android/native edges only."""
from pathlib import Path
import hashlib
import json
import sys

root, out, activity_path, service_path = map(Path, sys.argv[1:])
activity = activity_path.read_bytes().decode("utf-8")
service = service_path.read_bytes().decode("utf-8")
wireguard = (root/"client/android/wireguard/src/main/kotlin/org/amnezia/vpn/protocol/wireguard/Wireguard.kt").read_bytes().decode("utf-8")
dns = (root/"client/android/src/org/amnezia/vpn/DnsFallbackProtocol.kt").read_bytes().decode("utf-8")

def block(source, marker, body=False):
    start = source.index(marker)
    opening = source.index("{", start)
    depth, end = 1, opening+1
    while depth:
        depth += (source[end] == "{")-(source[end] == "}")
        end += 1
    return source[opening+1:end-1] if body else source[start:end]

android = r'''
package android.os
open class RemoteException:Exception()
class DeadObjectException:RemoteException()
class Bundle {
 val values=mutableMapOf<String,Any?>()
 fun putString(k:String,v:String?){values[k]=v}
 fun getString(k:String)=values[k] as? String
 fun putBoolean(k:String,v:Boolean){values[k]=v}
 fun getBoolean(k:String,fallback:Boolean)=values[k] as? Boolean ?: fallback
 fun containsKey(k:String)=values.containsKey(k)
 fun get(k:String)=values[k]
}
class Message {var what=0;var data=Bundle();var replyTo:Messenger?=null;companion object{fun obtain()=Message()}}
class IBinder(val receive:(Message)->Unit)
class Messenger(val binder:IBinder=IBinder{}) {fun send(msg:Message){binder.receive(msg)}}
'''
(out/"AndroidOs.kt").write_text(android, encoding="utf-8")
(out/"Log.kt").write_text('package org.amnezia.vpn.util\nobject Log {fun w(tag:String,message:String){};fun d(tag:String,message:String){};fun v(tag:String,message:String){}}\n', encoding="utf-8")
fields = activity[activity.index("    private var discoveryForeground"):activity.index("    private fun publishDiscovery(")]
methods = [block(activity, marker) for marker in ["private fun dispatchAdmittedStart(", "private fun doBindService(",
           "private fun doUnbindService(", "private fun adoptConnectedService(", "private fun disconnectFromVpn(", "fun stop()"]]
if "private fun deliverPendingControlStop(" in activity:
    methods.append(block(activity, "private fun deliverPendingControlStop("))
register = block(service, "Action.REGISTER_CLIENT ->", True)
disconnect = block(service, "Action.DISCONNECT ->", True)
service_disconnect = block(service, "private fun disconnect(")
fixture = r'''
import android.os.*
import org.amnezia.vpn.*
import org.amnezia.vpn.protocol.*
import org.amnezia.vpn.util.Log
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
private const val TAG="inert-fixture"
private const val MSG_VPN_CONFIG="config"
private const val MSG_CLIENT_NAME="clientName"
private const val ACTIVITY_MESSENGER_NAME="activity"
private const val BIND_ABOVE_CLIENT=8
private const val BIND_AUTO_CREATE=1
private const val DISCONNECT_TIMEOUT=1L
// Android main-loop scheduling seam; the extracted consumer still performs its
// real withContext call and current-owner fence synchronously on this JVM.
private object Dispatchers {val Unconfined=kotlinx.coroutines.Dispatchers.Unconfined;object Main {val immediate=kotlinx.coroutines.Dispatchers.Unconfined}}
private class ComponentName(val packageName:String,val className:String) {
 constructor(context:Any,type:Class<*>):this("owned",type.name)
 fun flattenToString()="$packageName/$className"
 override fun equals(other:Any?)=other is ComponentName && packageName==other.packageName && className==other.className
 override fun hashCode()=31*packageName.hashCode()+className.hashCode()
}
private interface ServiceConnection {fun onServiceConnected(name:ComponentName?,service:IBinder?);fun onServiceDisconnected(name:ComponentName?);fun onBindingDied(name:ComponentName?);fun onNullBinding(name:ComponentName?)}
private class Intent(context:Any,type:Class<*>) {val component=ComponentName(context,type);fun putExtra(k:String,v:String)=this}
private object ContextCompat {var starts=0;fun startForegroundService(context:Any,intent:Intent){starts++}}
// Input parser seam only: test configurations contain this one literal string field.
private class JSONObject(val value:String=""){
 val entries=linkedMapOf<String,Any?>()
 fun opt(key:String):Any?=entries[key] ?: Regex("\""+key+"\":\"([^\"]*)\"").find(value)?.groupValues?.get(1)
 fun optString(key:String)=opt(key) as? String ?: ""
 fun put(key:String,v:Any?)=apply{entries[key]=v}
 override fun toString()="{"+entries.entries.joinToString(","){(k,v)->NativeSessionWire.quote(k)+":"+if(v is Boolean)v.toString() else NativeSessionWire.quote(v as String)}+"}"
}
private class AwgService
private class LegacyService
private enum class VpnProto(val serviceClass:Class<*>,val protocol:Protocol?=null){AWG(AwgService::class.java),XRAY(LegacyService::class.java),SSXRAY(LegacyService::class.java)}
private enum class State {UNKNOWN,CONNECTED,DISCONNECTING,DISCONNECTED}
private typealias ProtocolState=State
private val DISCONNECTING=State.DISCONNECTING
private val DISCONNECTED=State.DISCONNECTED
private open class Protocol(val guard:NativeSessionGuard=NativeSessionGuard()) {
 var boundAttempts=0;var unboundAttempts=0;val seen=mutableListOf<NativeSessionIdentity>()
 // Actual identity monitor chooses whether the inert native seam is reached.
 // It deliberately NEVER calls confirmedCleanup: this suite cannot prove TUN retirement.
 fun stopVpnIfBound(expected:NativeSessionIdentity):Boolean {seen.add(expected);return guard.stopIfBound(expected){boundAttempts++}}
 open fun stopVpn(){unboundAttempts++}
 open fun retireUnstartedSession(descriptor:NativeSessionDescriptor)=false
 open val migrationCleanupObservation:String? get()=null
 open fun readNativeIdleObservation()=guard.idleObservation(false)
}
private class WireguardFixture:Protocol(){
 val nativeSessionGuard get()=guard
 var tunnelHandle=-1;var pendingStart:Any?=null;var pendingStartJob:Job?=null;var pendingCleanupUnconfirmed=false
 var config:Any?=null;var migrationConnectionNonce="";var cleanedNonce="";var pendingStartCancelled=false
 val state=MutableStateFlow(State.UNKNOWN)
 // Active native teardown remains inert and unconfirmed; pristine stop returns
 // before this seam, using the exact production method below.
 fun turnOffVpn(){unboundAttempts++}
 __WIREGUARD_RETIRE__
 __WIREGUARD_RECEIPT__
 __WIREGUARD_IDLE__
 __WIREGUARD_STOP__
}
private class Transport
private class Probe {fun disconnect(){}}
private class Policy {fun stop(){}}
private class DnsOwner {fun retire(){}}
private class DnsFallbackProtocol(val primary:Protocol=WireguardFixture()):Protocol(){
 val lifecycle=Any();var identity:NativeSessionIdentity?=null;var active=false;var dnsStarted=false;var primaryRetired=false
 var transport:Transport?=null;var pendingTransport:Transport?=null;val ownedTransports=mutableListOf<Transport>()
 var monitor:Job?=null;var workers:CoroutineScope?=null;var originalConfig:JSONObject?=null;var primaryProbe:Probe?=null;var cleanupConfirmed=false
 val policy=Policy();val dnsOwner=DnsOwner();val state=MutableStateFlow(State.UNKNOWN);var reason=""
 class Xray {fun stopVpnVerified()=false};val xray=Xray()
 fun closeTransport(value:Transport){ownedTransports.remove(value)}
 __DNS_RETIRE__
 __DNS_RECEIPT__
 __DNS_STOP__
}
private data class Session(val descriptor:NativeSessionDescriptor,val protocol:Protocol)
private class Gate {fun invalidate(){};fun removeRequester(requester:Messenger){}}
private class ActualService {
 val clientMessengers=mutableMapOf<Messenger,IpcMessenger>();val observationClients=mutableSetOf<Messenger>()
 val restoreStatusGate=Gate();val protocolState=MutableStateFlow(State.CONNECTED)
 var activeNativeSession:Session?=null;var vpnProto:VpnProto?=null
 var connectionJob:Job?=null;var disconnectionJob:Job?=null
 val connectionScope=CoroutineScope(SupervisorJob()+Dispatchers.Unconfined)
 val isUnknown get()=protocolState.value==State.UNKNOWN
 val isDisconnected get()=protocolState.value==State.DISCONNECTED
 var serviceStops=0
 fun updateControlBinding(){};fun invalidateDiscoveryGrants(){};fun stopRemoteLogUploader(){};fun stopService(){serviceStops++}
 fun register(msg:Message){__REGISTER__}
 fun action(msg:Message){when(msg.extractIpcMessage<Action>()){Action.REGISTER_CLIENT->register(msg);Action.DISCONNECT->disconnectMessage(msg);else->Unit}}
 fun disconnectMessage(msg:Message){__DISCONNECT_BRANCH__}
 __SERVICE_DISCONNECT__
 fun dispose(){connectionScope.cancel()}
}
private class ActualActivity {
 val mainScope=CoroutineScope(SupervisorJob()+Dispatchers.Unconfined)
 val vpnServiceMessenger=IpcMessenger()
 var isServiceConnected=false;var isInBoundState=false;var isWaitingStatus=true;var isBoundNativeService=false
 var vpnProto:VpnProto?=null;var boundActivityMessenger:Messenger?=null
 val activityMessenger:Messenger get()=checkNotNull(boundActivityMessenger)
 var restoreBindingGeneration=1L;var legacyStatusRequestGeneration=0L
 val serviceEventBindingGate=Gate();val connections=mutableListOf<ServiceConnection>();var unbinds=0
 fun createBoundActivityMessenger()=Messenger()
 fun invalidateRestoreRequest(){};fun notifyRestoreServiceReadyWhenQtReady(){};fun notifyServiceDisconnectedWhenQtReady(){}
 fun ownServiceInventory():List<ComponentName>?=emptyList()
 fun ownVpnNetworkAbsenceProven()=true
 fun getVpnProto(config:String)=if(config.startsWith("legacy:"))VpnProto.XRAY else VpnProto.AWG
 fun bindService(intent:Intent,connection:ServiceConnection,flags:Int):Boolean{connections.add(connection);return true}
 fun unbindService(connection:ServiceConnection){unbinds++}
 private fun requestDiscoveryProbe(attempt:DiscoveryAttempt){}
 fun publishDiscovery(phase:String,reason:String="NONE"){discoveryPhase=phase}
 fun invalidateDiscoveryLifecycle(){discoveryForeground=false}
 private fun finishStart(request:PendingStart,outcome:String,reason:String){if(pendingStart===request)pendingStart=null}
 __FIELDS__
 __METHODS__
 fun issue(nonce:String,legacy:Boolean=false){
  discoveryForeground=true;discoveryPhase="EMPTY";discoveryAttempt=null
  val config=(if(legacy)"legacy:" else "")+"{\"migrationConnectionNonce\":\"$nonce\"}"
  val request=PendingStart(config,discoveryGeneration.toString(),"22222222-2222-4222-8222-222222222222")
  pendingStart=request;dispatchAdmittedStart(request)
 }
 fun bind(index:Int,service:ActualService,wrongComponent:Boolean=false){connections[index].onServiceConnected(ComponentName("owned",if(wrongComponent)LegacyService::class.java.name else AwgService::class.java.name),IBinder(service::action))}
 fun unbindNow(){doUnbindService()}
 fun dispose(){mainScope.cancel()}
}
private val nonce="33333333-3333-4333-8333-333333333333"
private val newerNonce="44444444-4444-4444-8444-444444444444"
private fun identity(n:String=nonce)=NativeSessionIdentity("11111111-1111-4111-8111-111111111111","22222222-2222-4222-8222-222222222222",n)
private fun owned(n:String=nonce,nativeN:String=n):Pair<ActualService,Protocol>{
 val s=ActualService();val p=Protocol();s.activeNativeSession=Session(NativeSessionDescriptor(identity(n),"test-owned","AWG"),p)
 p.guard.activate(NativeSessionDescriptor(identity(nativeN),"test-owned","AWG"));return s to p
}
private fun conditional(receiver:Messenger?,value:Any?=nonce)=Action.DISCONNECT.packToMessage{}.apply{replyTo=receiver;data.values["expectedIssuedStartNonce"]=value}
private fun validReceipt(protocol:Protocol,id:NativeSessionIdentity){
 val receipt=protocol.migrationCleanupObservation ?: error("actual backend did not issue a usable receipt")
 check(receipt.contains("\"nativeCleanupConfirmed\":true"))
 for((k,v) in listOf("connectionNonce" to id.connectionNonce,"serviceInstanceId" to id.serviceInstanceId,"serviceActivationId" to id.serviceActivationId)){
  check(JSONObject(receipt).opt(k)==v){"actual backend receipt lacks exact $k"}
 }
}
fun main(){
 val failures=mutableListOf<String>();var passed=0
 fun case(name:String,body:()->Unit){try{body();passed++;println("PASS $name")}catch(e:Throwable){failures.add(name+": "+e.message);println("FAIL "+failures.last())}}
 case("issued EMPTY start, stop before bind, late native CONNECTED"){
  val(a,p)=owned();val activity=ActualActivity();activity.issue(nonce);check(ContextCompat.starts>0)
  activity.stop();check(p.boundAttempts==0&&p.unboundAttempts==0)
  activity.bind(0,a)
  check(p.boundAttempts==1){"stop before bind was dropped; exact-owner stop never reached native seam"}
  check(p.unboundAttempts==0);check(p.seen.single()==identity())
  check(a.protocolState.value==State.DISCONNECTING);check(p.guard.cleanupIdentity()==null){"fixture forged cleanup receipt"}
  activity.dispose();a.dispose()
 }
 __NEW_CASES__
 check(failures.isEmpty()){failures.joinToString("\n")}
 println("PASS $passed real consumer cases; native cleanup/absence remains unproven by inert host seams")
}
'''
new_cases = r'''
 case("repeated pending stop is delivered once"){
  val(s,p)=owned();val a=ActualActivity();a.issue(nonce);a.stop();a.stop();a.bind(0,s);check(p.boundAttempts==1&&p.unboundAttempts==0);a.dispose();s.dispose()
 }
 case("uncancelled issued start does not receive a stop"){
  val(s,p)=owned();val a=ActualActivity();a.issue(nonce);a.bind(0,s)
  check(p.boundAttempts==0&&p.unboundAttempts==0);a.dispose();s.dispose()
 }
 case("replacement binding invalidates old cancellation"){
  val(old,op)=owned();val(current,cp)=owned(newerNonce);val a=ActualActivity()
  a.issue(nonce);a.stop();a.issue(newerNonce);a.bind(0,old);check(!a.isServiceConnected)
  a.bind(1,current);check(op.boundAttempts==0&&cp.boundAttempts==0&&cp.unboundAttempts==0)
  a.dispose();old.dispose();current.dispose()
 }
 case("unbind invalidates cancellation and late callback"){
  val(s,p)=owned();val a=ActualActivity();a.issue(nonce);a.stop();a.unbindNow();a.bind(0,s)
  check(!a.isServiceConnected&&p.boundAttempts==0&&p.unboundAttempts==0);a.dispose();s.dispose()
 }
 case("wrong component never receives cancellation"){
  val(s,p)=owned();val a=ActualActivity();a.issue(nonce);a.stop();a.bind(0,s,true)
  check(!a.isServiceConnected&&p.boundAttempts==0&&p.unboundAttempts==0);a.dispose();s.dispose()
 }
 case("replacement service nonce is preserved"){
  val(s,p)=owned(newerNonce);val a=ActualActivity();a.issue(nonce);a.stop();a.bind(0,s)
  check(p.boundAttempts==0&&p.unboundAttempts==0&&p.seen.isEmpty());a.dispose();s.dispose()
 }
 case("current native monitor rejects replaced owner"){
  val(s,p)=owned(nonce,newerNonce);val a=ActualActivity();a.issue(nonce);a.stop();a.bind(0,s)
  check(p.seen.single()==identity()&&p.boundAttempts==0&&p.unboundAttempts==0&&p.guard.cleanupIdentity()==null);a.dispose();s.dispose()
 }
 case("UNKNOWN exact issued owner may attempt conditional cleanup"){
  val(s,p)=owned();s.protocolState.value=State.UNKNOWN;val a=ActualActivity();a.issue(nonce);a.stop();a.bind(0,s)
  check(p.boundAttempts==1&&p.unboundAttempts==0&&p.guard.cleanupIdentity()==null);a.dispose();s.dispose()
 }
 case("unknown foreign owner remains untouched"){
  val(s,p)=owned(newerNonce);s.protocolState.value=State.UNKNOWN;val a=ActualActivity();a.issue(nonce);a.stop();a.bind(0,s)
  check(p.boundAttempts==0&&p.unboundAttempts==0&&s.protocolState.value==State.UNKNOWN);a.dispose();s.dispose()
 }
 case("unregistered, observer, null, mixed and malformed conditional requests rejected"){
  val(s,p)=owned();val registered=Messenger();val observer=Messenger();val stranger=Messenger()
  s.action(Action.REGISTER_CLIENT.packToMessage{}.apply{replyTo=registered})
  s.action(Action.REGISTER_CLIENT.packToMessage{putBoolean("discoveryObserver",true)}.apply{replyTo=observer})
  listOf(conditional(null),conditional(stranger),conditional(observer),conditional(registered,42),conditional(registered,"bad"),
   conditional(registered).apply{data.putString("expectedNativeSession",identity().toJson())}).forEach{s.action(it)}
  check(p.boundAttempts==0&&p.unboundAttempts==0&&p.seen.isEmpty());s.dispose()
 }
 case("startup without native session produces no cleanup receipt"){
  val(s,p)=owned();s.activeNativeSession=null;val a=ActualActivity();a.issue(nonce);a.stop();a.bind(0,s)
  check(p.boundAttempts==0&&p.unboundAttempts==0&&p.guard.cleanupIdentity()==null);a.dispose();s.dispose()
 }
 case("pre-init cancellation uses actual pristine backend retirement and receipt"){
  val p=WireguardFixture();val s=ActualService();val descriptor=NativeSessionDescriptor(identity(),"test-owned","AWG")
  s.activeNativeSession=Session(descriptor,p);s.protocolState.value=State.UNKNOWN
  var priorJobClosed=false
  s.connectionJob=s.connectionScope.launch(start=CoroutineStart.UNDISPATCHED){try{awaitCancellation()}finally{priorJobClosed=true}}
  val priorJob=s.connectionJob!!;val a=ActualActivity();a.issue(nonce);a.stop();a.bind(0,s)
  check(priorJob.isCancelled&&priorJob.isCompleted&&priorJobClosed&&s.connectionJob==null){"retirement preceded connection-job cancellation"}
  check(s.protocolState.value==State.DISCONNECTED&&p.boundAttempts==0&&p.unboundAttempts==0)
  check(p.guard.idleObservation(false).state==NativeIdleState.VERIFIED_RETIRED&&p.guard.cleanupIdentity()==identity())
  validReceipt(p,identity());check(!p.retireUnstartedSession(descriptor)){"retirement repeated on a nonpristine guard"}
  // The same real guard can acquire a new activation; an old conditional owner cannot stop it.
  val next=NativeSessionDescriptor(identity(newerNonce),"test-owned","AWG");p.guard.activate(next)
  check(p.guard.cleanupIdentity()==null&&p.guard.binding("","")?.descriptor==next)
  check(!p.guard.stopIfBound(identity()){error("old owner reached replacement native seam")})
  check(!p.retireUnstartedSession(next)){"new activation was retired as pristine"}
  a.dispose();s.dispose()
 }
 case("pristine DNS wrapper delegates actual retirement and actual receipt"){
  val w=WireguardFixture();val p=DnsFallbackProtocol(w);val descriptor=NativeSessionDescriptor(identity(),"test-owned","AWG")
  check(p.retireUnstartedSession(descriptor));validReceipt(p,identity())
 }
 case("native monitor refuses prior activation, unknown, cleanup, invalid owner"){
  val d=NativeSessionDescriptor(identity(),"test-owned","AWG")
  val prior=NativeSessionGuard();prior.activate(d);check(!prior.retireNeverStarted(d))
  val unknown=NativeSessionGuard();unknown.replacedNativeHandle();check(!unknown.retireNeverStarted(d))
  val cleanup=NativeSessionGuard();cleanup.beginCleanup();check(!cleanup.retireNeverStarted(d))
  val invalid=NativeSessionGuard();check(!invalid.retireNeverStarted(d.copy(identity=identity("bad"))))
  check(invalid.idleObservation(false).state==NativeIdleState.NEVER_STARTED&&invalid.cleanupIdentity()==null)
 }
 case("Wireguard resource and prior identity fences refuse pristine retirement"){
  val d=NativeSessionDescriptor(identity(),"test-owned","AWG")
  val variations=listOf<(WireguardFixture)->Unit>({it.tunnelHandle=9},{it.pendingStart=Any()},
   {it.pendingStartJob=Job()},{it.pendingCleanupUnconfirmed=true},{it.config=Any()},
   {it.migrationConnectionNonce=newerNonce},{it.cleanedNonce=newerNonce},{it.guard.activate(d)},
   {it.guard.replacedNativeHandle()})
  for(change in variations){val p=WireguardFixture();change(p);check(!p.retireUnstartedSession(d));check(p.migrationCleanupObservation==null||p.cleanedNonce==newerNonce)}
 }
 case("DNS previously owned resources cannot use pristine primary delegation"){
  val d=NativeSessionDescriptor(identity(),"test-owned","AWG")
  val variations=listOf<(DnsFallbackProtocol)->Unit>({it.identity=identity()},{it.active=true},{it.dnsStarted=true},
   {it.primaryRetired=true},{it.transport=Transport()},{it.pendingTransport=Transport()},{it.ownedTransports.add(Transport())},
   {it.monitor=Job()},{it.workers=CoroutineScope(Job())},{it.originalConfig=JSONObject()},{it.primaryProbe=Probe()})
  for(change in variations){val p=DnsFallbackProtocol();change(p);check(!p.retireUnstartedSession(d));check(p.primary.migrationCleanupObservation==null)}
 }
 case("full DNS stop retires never-started primary after wrapper identity was set"){
  val w=WireguardFixture();val p=DnsFallbackProtocol(w);p.identity=identity();p.active=true
  p.originalConfig=JSONObject().put("nativeSessionServerId","test-owned").put("protocol","awg")
  p.stopVpn()
  check(p.cleanupConfirmed&&p.state.value==State.DISCONNECTED&&p.reason=="stopped")
  check(w.readNativeIdleObservation().state==NativeIdleState.VERIFIED_RETIRED)
  validReceipt(p,identity());check(w.unboundAttempts==0&&w.boundAttempts==0)
 }
 case("full DNS stop preserves prior-active, UNKNOWN and live-handle fences"){
  val d=NativeSessionDescriptor(identity(),"test-owned","AWG")
  val variations=listOf<(WireguardFixture)->Unit>({it.guard.activate(d)},{it.guard.replacedNativeHandle()},
   {it.tunnelHandle=7})
  for((index,change) in variations.withIndex()){val w=WireguardFixture();change(w);val p=DnsFallbackProtocol(w)
   p.identity=identity();p.active=true;p.originalConfig=JSONObject().put("nativeSessionServerId","test-owned").put("protocol","awg")
   p.stopVpn();check(!p.cleanupConfirmed&&p.state.value==State.UNKNOWN&&p.migrationCleanupObservation==null){"full stop negative $index: confirmed=${p.cleanupConfirmed} state=${p.state.value} receipt=${p.migrationCleanupObservation!=null}"}
  }
  val w=WireguardFixture();val p=DnsFallbackProtocol(w);p.identity=identity("bad");p.originalConfig=JSONObject().put("nativeSessionServerId","test-owned").put("protocol","awg")
  // Malformed identity cannot enter the real wrapper's startVpn (require(valid)).
  // Even when injected directly, it cannot author the service's exact receipt.
  p.stopVpn();check(p.migrationCleanupObservation==null&&w.guard.cleanupIdentity()==null)
 }
'''
fixture = (fixture.replace("__REGISTER__", register).replace("__DISCONNECT_BRANCH__", disconnect)
           .replace("__SERVICE_DISCONNECT__", service_disconnect).replace("__FIELDS__", fields)
           .replace("__METHODS__", "\n".join(methods))
           .replace("__WIREGUARD_RETIRE__",block(wireguard,"override fun retireUnstartedSession("))
           .replace("__WIREGUARD_RECEIPT__",block(wireguard,"override val migrationCleanupObservation:"))
           .replace("__WIREGUARD_IDLE__",block(wireguard,"override fun readNativeIdleObservation("))
           .replace("__WIREGUARD_STOP__",block(wireguard,"override fun stopVpn()"))
           .replace("__DNS_RETIRE__",block(dns,"override fun retireUnstartedSession("))
           .replace("__DNS_RECEIPT__",block(dns,"override val migrationCleanupObservation:"))
           .replace("__DNS_STOP__",block(dns,"override fun stopVpn()"))
           .replace("__NEW_CASES__", new_cases if "expectedIssuedStartNonce" in service else ""))
(out/"PendingStopFixture.kt").write_text(fixture, encoding="utf-8")
(out/"extracted-inputs.json").write_text(json.dumps({str(p): hashlib.sha256(s.encode("utf-8")).hexdigest() for p,s in [
    (activity_path,activity),(service_path,service),
    (root/"client/android/wireguard/src/main/kotlin/org/amnezia/vpn/protocol/wireguard/Wireguard.kt",wireguard),
    (root/"client/android/src/org/amnezia/vpn/DnsFallbackProtocol.kt",dns)]},indent=2)+"\n",encoding="utf-8")
