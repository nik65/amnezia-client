from pathlib import Path
import sys
root=Path(sys.argv[1]);out=Path(sys.argv[2]);out.mkdir(parents=True,exist_ok=True)
s=(Path(sys.argv[3]) if len(sys.argv)>3 else root/'client/android/src/org/amnezia/vpn/AmneziaActivity.kt').read_text(encoding='utf-8')
def block(marker):
 start=s.index(marker); brace=s.index('{',start); depth=1;i=brace+1
 while depth:
  if s[i]=='{':depth+=1
  if s[i]=='}':depth-=1
  i+=1
 return s[start:i]
assert 'if (state.name == "DISCONNECTED") retireDisconnectedControlBinding()' in block('override fun handleMessage(msg: Message)')
terminal_branch=s[s.index('                        msg.data?.getStatus()?.let { (state) ->'):s.index('                    ServiceEvent.STATUS ->')]
terminal_branch=terminal_branch[:terminal_branch.rindex('                    }')]
assert terminal_branch.index('retireDisconnectedControlBinding()') < terminal_branch.index('QtAndroidController.onVpnStateChanged(state.ordinal)')
region=s[s.index('    private var discoveryForeground'):s.index('    private var isWaitingStatus')]
if 'private var pendingControlComponent:' not in region: region+='\nprivate var pendingControlComponent:ComponentName?=null\n'
methods='\n'.join(block(x) for x in ['fun requestServiceDiscovery(', 'fun requestRestoreStatus(', 'fun startWithDiscovery(', 'private fun dispatchAdmittedStart(', 'private fun doBindService(', 'private fun doUnbindService(', 'private fun createBoundActivityMessenger(', 'private fun deliverPendingControlStop('])
prefix=r'''
import org.amnezia.vpn.protocol.*
import org.amnezia.vpn.ServiceDiscoveryWire
import kotlinx.coroutines.*
import java.util.UUID
private annotation class SuppressLint(val value:String)
private class ComponentName(val packageName:String,val className:String){constructor(context:Any,type:Class<*>):this("owned",type.name);override fun equals(other:Any?)=other is ComponentName&&other.packageName==packageName&&other.className==className;override fun hashCode()=className.hashCode()}
private class IBinder
private interface ServiceConnection {fun onServiceConnected(name:ComponentName?,service:IBinder?);fun onServiceDisconnected(name:ComponentName?);fun onBindingDied(name:ComponentName?);fun onNullBinding(name:ComponentName?)}
private class Bundle {val map=mutableMapOf<String,Any?>();fun putString(key:String,v:String?){map[key]=v};fun getString(key:String)=map[key] as? String;fun get(key:String)=map[key];fun getBoolean(key:String,fallback:Boolean)=map[key] as? Boolean ?: fallback;fun getStatus():Pair<FixtureState,Unit>?=getString("state")?.let{FixtureState.valueOf(it) to Unit}}
private enum class FixtureState{CONNECTED,DISCONNECTED}
private class Message {val data=Bundle();var replyTo:Messenger?=null;fun recycle(){};companion object{fun obtain(other:Message)=other}}
private class Looper {companion object{fun getMainLooper()=Looper()}}
private open class Handler(looper:Looper) {open fun handleMessage(message:Message){}}
private class Messenger(val handler:Handler?=null) {var sends=0;var fail=false;fun send(message:Message){sends++;if(fail)error("inert dispatch failure");handler?.handleMessage(message)}}
private enum class Action {REQUEST_STATUS,CONNECT,DISCONNECT,UNREGISTER_CLIENT;fun packToMessage(body:Bundle.()->Unit)=Message().apply{data.body()}}
private class JSONObject(value:String){fun opt(key:String):Any?=if(key=="migrationConnectionNonce") "33333333-3333-4333-8333-333333333333" else null}
private class Outbound {
 var onSend:(()->Unit)?=null;val messages=mutableListOf<Message>()
 fun send(action:Action,receiver:Messenger){val callback=onSend;onSend=null;callback?.invoke()}
 fun send(body:()->Message){messages.add(body())}
 fun send(message:Message,replyTo:Messenger){message.replyTo=replyTo;messages.add(message)}
 fun reset(){}
}
private class Intent {constructor();constructor(context:Any,type:Class<*>){component=ComponentName("owned",type.name)};var component:ComponentName?=null;var action:String?=null;fun setComponent(c:ComponentName)=apply{component=c};fun setAction(a:String)=apply{action=a};fun putExtra(k:String,v:String)=this}
private class AwgService;private class OpenVpnService;private class XrayService
private class Info(val uid:Int=7)
private class RunningServiceInfo(val service:ComponentName,val uid:Int=7,val started:Boolean=true)
private class ActivityManager {var fail=false;var reads=0;var onRead:(()->Unit)?=null;var records=listOf<RunningServiceInfo>();fun getRunningServices(max:Int):List<RunningServiceInfo>{reads++;onRead?.invoke();if(fail)error("inventory");return records}}
private class Network
private class NetworkCapabilities(val vpn:Boolean=false){fun hasTransport(type:Int)=vpn;companion object{const val TRANSPORT_VPN=4}}
private class ConnectivityManager {var fail=false;var networks=arrayOf<Network>();var capabilities:NetworkCapabilities?=NetworkCapabilities();val allNetworks:Array<Network> get(){if(fail)error("connectivity");return networks};fun getNetworkCapabilities(n:Network)=capabilities}
private const val CONNECTIVITY_SERVICE="connectivity"
private enum class VpnProto(val serviceClass:Class<*>){AWG(AwgService::class.java),OPENVPN(OpenVpnService::class.java),XRAY(XrayService::class.java)}
private object QtAndroidController {val discoveries=mutableListOf<String>();val admissions=mutableListOf<String>();fun onServiceDiscovery(s:String){discoveries.add(s)};fun onStartAdmission(s:String){admissions.add(s)};var onState:((Int)->Unit)?=null;fun onVpnStateChanged(state:Int){onState?.invoke(state)}}
private const val ACTIVITY_SERVICE="activity"
private const val BIND_ABOVE_CLIENT=8
private const val BIND_AUTO_CREATE=1
private const val TAG="fixture"
private object Log {fun d(tag:String,message:String){}}
private const val MSG_VPN_CONFIG="config"
private object ContextCompat {var starts=0;var fail=false;fun startForegroundService(context:Any,intent:Intent){starts++;if(fail)error("dispatch")}}
private class ActualActivity {
 val connectivity=ConnectivityManager();val manager=ActivityManager();val applicationInfo=Info();val packageName="owned"
 val vpnServiceMessenger=Outbound();val serviceEventBindingGate=ServiceEventBindingGate();var isBoundNativeService=false
 val vpnServiceEventHandler=object:Handler(Looper.getMainLooper()){override fun handleMessage(message:Message){__ACTUAL_TERMINAL_BRANCH__}}
 val mainScope=CoroutineScope(SupervisorJob()+Dispatchers.Unconfined);val qtInitialized=CompletableDeferred<Unit>()
 var unbinds=0;var binds=0;var flags=0;var bound:ServiceConnection?=null
 var isInBoundState=false;var isServiceConnected=false;var isWaitingStatus=true;var vpnProto:VpnProto?=null;var activityMessenger=Messenger();var boundActivityMessenger:Messenger?=activityMessenger
 var restoreInvalidations=0;var permissions=0;var permissionGrant:(()->Unit)?=null;var permissionReject:(()->Unit)?=null
 var restoreBindingGeneration=1L;var pendingRestoreRequest:String?=null
 fun observeDnsTransportStatus(status:String?,connected:Boolean){}
 fun getSystemService(key:String):Any=if(key==ACTIVITY_SERVICE)manager else connectivity
 fun unbindService(c:ServiceConnection){unbinds++}
 fun bindService(intent:Intent,c:ServiceConnection,f:Int):Boolean{binds++;flags=f;bound=c;return true}

 fun adoptConnectedService(name:ComponentName?,service:IBinder?,observation:Boolean){boundRemoteMessenger=Messenger();isServiceConnected=true;boundServiceComponent=name}
 fun invalidateRestoreRequest(){restoreInvalidations++}
 fun notifyServiceDisconnectedWhenQtReady(){}
 fun checkVpnPermission(onPermissionGranted:()->Unit,onPermissionDenied:()->Unit){permissions++;permissionGrant=onPermissionGranted;permissionReject=onPermissionDenied}
 fun checkNotificationPermission(block:()->Unit){block()}
 fun getVpnProto(config:String)=when(config){"AWG"->VpnProto.AWG;"OPENVPN"->VpnProto.OPENVPN;else->null}
'''
post=r'''
 fun freshReceiver():Messenger {boundActivityMessenger=createBoundActivityMessenger();return boundActivityMessenger!!}
 fun deliverTerminal(receiver:Messenger){receiver.send(Message().apply{data.putString("state","DISCONNECTED")})}
 fun setup(){qtInitialized.complete(Unit);discoveryForeground=true}
 fun empty(id:String){requestServiceDiscovery(id)}
 fun generation()=discoveryGeneration.toString()
 fun lifecycle(){finishPendingStartOnLifecycle();discoveryForeground=false;invalidateDiscoveryLifecycle()}
 fun grant(){permissionGrant?.invoke()}
 fun reject(){permissionReject?.invoke()}
 fun active()=pendingStart!=null
 fun dispose(){mainScope.cancel()}
 fun prepareAck(id:String) {pendingStart=PendingStart("AWG",discoveryGeneration.toString(),id,true)}
 fun confirmedStop(){pendingControlComponent=null;activeServiceConnection=null;isServiceConnected=false;discoveryAttempt=null}
 fun pendingConnection()=activeServiceConnection
 fun activeProbe()=discoveryProbe
 fun phase()=discoveryPhase
 fun timeoutNow(){discoveryDeadline?.cancel();if(discoveryPhase=="PENDING")publishDiscovery("UNCERTAIN",reason="BIND_TIMEOUT")}
 fun invalidateWhileUnbinding(){vpnServiceMessenger.onSend={invalidateDiscoveryLifecycle()}}

}
fun main(args:Array<String>)=runBlocking {
 val id="11111111-1111-4111-8111-111111111111";val start="22222222-2222-4222-8222-222222222222"
 val restore=ActualActivity();restore.setup();restore.isServiceConnected=true
 restore.requestRestoreStatus(id,1);check(restore.vpnServiceMessenger.messages.single().replyTo===restore.boundActivityMessenger){"restore request lost replyTo"}
 restore.boundActivityMessenger=null;restore.requestRestoreStatus(start,1);check(restore.vpnServiceMessenger.messages.size==1){"restore request sent without a live receiver"};restore.dispose()
 val dying=ActualActivity();dying.setup();dying.manager.records=listOf(RunningServiceInfo(ComponentName("owned",AwgService::class.java.name)))
 dying.empty(id);val dyingConnection=dying.bound!!;dyingConnection.onServiceConnected(ComponentName("owned",AwgService::class.java.name),IBinder())
 dying.invalidateWhileUnbinding();dyingConnection.onServiceDisconnected(null)
 check(dying.phase()=="PENDING" && QtAndroidController.discoveries.last().contains("PENDING")){"stale failure replaced lifecycle reset"};dying.dispose()
 val a=ActualActivity();a.setup();a.empty(id);check(QtAndroidController.discoveries.last().contains("EMPTY"));val g=a.generation()
 a.startWithDiscovery("AWG",g,start);check(ContextCompat.starts==0&&a.permissions==1);a.grant();check(ContextCompat.starts==1&&!a.active());check(QtAndroidController.admissions.last().contains("DISPATCHED"))
 a.startWithDiscovery("AWG",g,start);check(ContextCompat.starts==1&&QtAndroidController.admissions.last().contains("REJECTED"))
 a.confirmedStop();a.empty(id);a.startWithDiscovery("AWG",a.generation(),start);a.reject();check(QtAndroidController.admissions.last().contains("PERMISSION_DENIED"));check(ContextCompat.starts==1)
 a.empty(id);a.startWithDiscovery("AWG",a.generation(),start);a.manager.records=listOf(RunningServiceInfo(ComponentName("owned",AwgService::class.java.name)));a.grant();check(ContextCompat.starts==1&&QtAndroidController.admissions.last().contains("STALE"))
 a.manager.records=emptyList();a.empty(id);a.startWithDiscovery("AWG",a.generation(),start);a.lifecycle();a.grant();check(ContextCompat.starts==1&&QtAndroidController.admissions.last().contains("CANCELLED"));a.dispose()
 val pending=ActualActivity();pending.setup();pending.empty(id);pending.startWithDiscovery("AWG",pending.generation(),start);pending.grant();val original=pending.pendingConnection();check(original!=null);val releasesBefore=pending.unbinds;pending.empty(id);val refreshGeneration=pending.generation();check(pending.unbinds==releasesBefore&&pending.pendingConnection()===original&&pending.phase()=="PENDING");pending.manager.records=listOf(RunningServiceInfo(ComponentName("owned",AwgService::class.java.name)));original.onServiceConnected(ComponentName("owned",AwgService::class.java.name),IBinder());check(pending.activeProbe()!=null&&pending.generation()==refreshGeneration&&pending.unbinds==releasesBefore);pending.dispose()
 val timeout=ActualActivity();timeout.setup();timeout.empty(id);timeout.startWithDiscovery("AWG",timeout.generation(),start);timeout.grant();val timeoutConnection=timeout.pendingConnection()!!;timeout.empty(id);val timeoutReleases=timeout.unbinds;delay(4100);check(timeout.phase()=="UNCERTAIN");timeoutConnection.onServiceConnected(ComponentName("owned",AwgService::class.java.name),IBinder());check(timeout.phase()=="UNCERTAIN"&&timeout.activeProbe()==null&&timeout.unbinds==timeoutReleases);timeout.dispose()
 val ack=ActualActivity();ack.setup();ack.empty(id);ack.prepareAck(start);val invalid=Message().apply{data.putString("admissionRequestId",start);data.putString("admissionGeneration",ack.generation())};ack.admissionReply(invalid);check(ack.active());invalid.data.map["admissionAccepted"]="false";ack.admissionReply(invalid);check(ack.active());invalid.data.map["admissionAccepted"]=false;ack.admissionReply(invalid);check(!ack.active()&&QtAndroidController.admissions.last().contains("REJECTED"));ack.dispose()
 val b=ActualActivity();b.setup();b.manager.records=listOf(RunningServiceInfo(ComponentName("owned",AwgService::class.java.name),started=false));b.empty(id);check(b.binds==0&&QtAndroidController.discoveries.last().contains("INVENTORY_ERROR"));b.dispose()
 val c=ActualActivity();c.setup();c.manager.records=listOf(RunningServiceInfo(ComponentName("owned",AwgService::class.java.name)));c.empty(id);val old=c.bound!!;check(c.flags==BIND_ABOVE_CLIENT);c.empty(id);old.onServiceConnected(ComponentName("owned",AwgService::class.java.name),IBinder());check(c.unbinds==1);c.dispose()
 val retained=ActualActivity();retained.setup();retained.manager.records=listOf(RunningServiceInfo(ComponentName("owned",AwgService::class.java.name)));retained.empty(id);retained.bound!!.onServiceConnected(ComponentName("owned",AwgService::class.java.name),IBinder());val releases=retained.unbinds;retained.empty(id);check(retained.unbinds==releases&&retained.binds==1);retained.dispose()
 // Exercise the real per-Binder callback and terminal retirement helper together.
 val terminal=ActualActivity();terminal.setup();terminal.manager.records=listOf(RunningServiceInfo(ComponentName("owned",AwgService::class.java.name)))
 terminal.empty(id);terminal.bound!!.onServiceConnected(ComponentName("owned",AwgService::class.java.name),IBinder())
 val retiredReceiver=terminal.freshReceiver();val currentReceiver=terminal.freshReceiver();val terminalUnbinds=terminal.unbinds
 terminal.deliverTerminal(retiredReceiver);check(terminal.isServiceConnected&&terminal.unbinds==terminalUnbinds){"old Binder terminal retired current owner"}
 var notified=0;QtAndroidController.onState={state->check(!terminal.isServiceConnected&&terminal.pendingConnection()==null){"Qt observed terminal state before binding retirement"};notified++}
 terminal.deliverTerminal(currentReceiver);check(notified==1);QtAndroidController.onState=null;check(!terminal.isServiceConnected&&terminal.pendingConnection()==null&&terminal.unbinds==terminalUnbinds+1){"current terminal left stale control binding"}
 // Terminal status alone is not EMPTY proof: a still-running component must be observed.
 terminal.empty(start);check(terminal.phase()=="PENDING"&&terminal.binds==2){"terminal status bypassed current service inventory"}
 terminal.bound!!.onServiceConnected(ComponentName("owned",AwgService::class.java.name),IBinder());val rebound=terminal.freshReceiver()
 terminal.deliverTerminal(currentReceiver);check(terminal.isServiceConnected){"late old terminal retired rebound owner"}
 terminal.deliverTerminal(rebound);terminal.manager.fail=true;terminal.empty(id);check(terminal.phase()=="UNCERTAIN"){"terminal converted inventory error to EMPTY"}
 terminal.manager.fail=false;terminal.manager.records=emptyList();terminal.empty(start);check(terminal.phase()=="EMPTY"){"fresh proven empty inventory could not admit reconnect"};terminal.dispose()
 val absence=ActualActivity();absence.setup();absence.connectivity.networks=arrayOf(Network());absence.connectivity.capabilities=NetworkCapabilities(true)
 absence.empty(id);check(absence.phase()=="UNCERTAIN"&&absence.binds==0){"live VPN accepted as empty service ownership"}
 absence.connectivity.capabilities=null;absence.empty(start);check(absence.phase()=="UNCERTAIN"){"unknown network capabilities accepted as absence"}
 absence.connectivity.fail=true;absence.empty(id);check(absence.phase()=="UNCERTAIN"){"connectivity failure accepted as absence"}
 absence.connectivity.fail=false;absence.connectivity.capabilities=NetworkCapabilities(false)
 var samples=0;absence.manager.onRead={samples++;if(samples==2)absence.manager.records=listOf(RunningServiceInfo(ComponentName("owned",AwgService::class.java.name)))}
 absence.empty(start);check(absence.phase()=="UNCERTAIN"){"service appearing during network scan accepted as absence"}
 absence.manager.onRead=null;absence.manager.records=emptyList();absence.empty(id);check(absence.phase()=="EMPTY")
 val startsBeforeNetworkRace=ContextCompat.starts;absence.startWithDiscovery("AWG",absence.generation(),start);absence.connectivity.capabilities=NetworkCapabilities(true);absence.grant()
 check(ContextCompat.starts==startsBeforeNetworkRace&&QtAndroidController.admissions.last().contains("STALE")){"VPN appearing after discovery bypassed final admission"};absence.dispose()
 val d=ActualActivity();d.setup();d.empty(id);d.startWithDiscovery("AWG",d.generation(),start);ContextCompat.fail=true;d.grant();check(QtAndroidController.admissions.last().contains("DISPATCH_UNCERTAIN"));d.dispose()
 if(args.isNotEmpty()) {
  val output=java.io.File(args[0]);output.mkdirs()
  val cases=listOf(Triple("PENDING","NONE","NONE"),Triple("EMPTY","NONE","NONE"),Triple("BOUND_NATIVE","AWG","NONE"),Triple("IDLE_NATIVE","AWG","NONE"),Triple("BOUND_LEGACY","OPENVPN","NONE"),Triple("BOUND_LEGACY","XRAY","NONE"),Triple("UNCERTAIN","NONE","STATUS_UNPROVEN"))
  val snapshots=cases.map{(phase,component,reason)->ServiceDiscoveryWire.snapshot(id,100,phase,component,reason)}+ServiceDiscoveryWire.snapshot("",101,"PENDING","NONE","NONE")
  val admissions=listOf("DISPATCHED" to "NONE","DISPATCH_UNCERTAIN" to "START_EXCEPTION","REJECTED" to "DISCOVERY_UNCONFIRMED","REJECTED" to "STALE","CANCELLED" to "PERMISSION_DENIED","CANCELLED" to "LIFECYCLE_CANCELLED").map{(outcome,reason)->ServiceDiscoveryWire.admission("100",start,outcome,reason)}
  java.io.File(output,"discovery-snapshots.jsonl").writeText(snapshots.joinToString("\n",postfix="\n"),Charsets.UTF_8)
  java.io.File(output,"admission-snapshots.jsonl").writeText(admissions.joinToString("\n",postfix="\n"),Charsets.UTF_8)
  check(snapshots.all{it.toByteArray(Charsets.UTF_8).size<2048}&&admissions.all{it.toByteArray(Charsets.UTF_8).size<2048})
  check(runCatching{ServiceDiscoveryWire.snapshot("",100,"EMPTY","NONE","NONE")}.isFailure)
  check(runCatching{ServiceDiscoveryWire.admission("100",start,"DISPATCHED","STALE")}.isFailure)
 }
 println("Actual Activity discovery methods: cold EMPTY, one-shot, permissioncancel, finalinventoryfence, lifecyclecancel, bound-onlyHOLD, noAUTOrestore, lateattempt, dispatchuncertain, pendingcontrolrefresh, actualdeadline, malformedACK, currentterminalrelease, oldBinderfence and reinventory PASS")
}
'''
admission=s[s.index('                        val admissionId = msg.data?.getString("admissionRequestId")'):s.index('                        val probeId = msg.data?.getString("discoveryRequestId")')]
receiver='fun admissionReply(msg:Message) {\n'+admission+'\n}'
post=post.replace(' fun pendingConnection()', ' '+receiver+'\n fun pendingConnection()')
prefix=prefix.replace('__ACTUAL_TERMINAL_BRANCH__',terminal_branch.replace('msg.data','message.data'))
(out/'ActualActivityDiscovery.kt').write_text(prefix+region+'\n'+methods+'\n'+post,encoding='utf-8')
