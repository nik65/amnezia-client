"""Compile actual fallback source against Android SDK, run bounded JVM contracts, never Gradle/APK."""
from pathlib import Path
import argparse,hashlib,json,os,subprocess,sys,urllib.request,zipfile

p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--xray-source',type=Path);p.add_argument('--resolver-source',type=Path);a=p.parse_args()
root=Path(__file__).resolve().parents[3];a.output.mkdir(parents=True,exist_ok=True)
cache=Path.home()/'.gradle/caches/modules-2/files-2.1'
def jar(group,name,version):
 hits=list((cache/group/name/version).glob('*/*.jar'));assert len(hits)==1,(group,name,version);return hits[0]
stdlib=jar('org.jetbrains.kotlin','kotlin-stdlib','2.1.0')
annotations=jar('org.jetbrains','annotations','13.0')
coroutines=jar('org.jetbrains.kotlinx','kotlinx-coroutines-core-jvm','1.8.1')
compiler=[jar('org.jetbrains.kotlin','kotlin-compiler-embeddable','2.1.0'),stdlib,jar('org.jetbrains.kotlin','kotlin-script-runtime','2.1.0'),jar('org.jetbrains.kotlin','kotlin-reflect','1.6.10'),jar('org.jetbrains.intellij.deps','trove4j','1.0.20200330'),annotations,coroutines]
jsonjar=a.output/'json-20240303.jar'
url='https://repo.maven.apache.org/maven2/org/json/json/20240303/json-20240303.jar'
if not jsonjar.exists():
 data=urllib.request.urlopen(url,timeout=30).read();expected=urllib.request.urlopen(url+'.sha1',timeout=30).read().decode().strip()
 assert hashlib.sha1(data).hexdigest()==expected
 jsonjar.write_bytes(data)
android=Path.home()/'Android/Sdk/platforms/android-36/android.jar';assert android.is_file()

def method(source,marker):
 start=source.index(marker);i=source.index('{',start);depth=0;quote=None;escape=False
 for j in range(i,len(source)):
  c=source[j]
  if quote:
   if escape:escape=False
   elif c=='\\':escape=True
   elif c==quote:quote=None
  elif c in ('"',"'"):quote=c
  elif c=='{':depth+=1
  elif c=='}':
   depth-=1
   if depth==0:return source[start:j+1]
 raise AssertionError('unclosed production method')

(a.output/'ProtocolFixture.kt').write_text('''package org.amnezia.vpn.protocol
import android.content.Context
import android.net.VpnService
import kotlinx.coroutines.flow.MutableStateFlow
import org.json.JSONObject
abstract class Protocol {
 protected lateinit var context: Context
 protected lateinit var state: MutableStateFlow<ProtocolState>
 protected lateinit var onError: (String)->Unit
 abstract val statistics: Statistics
 open val migrationObservation: String? get()=null
 open val migrationCleanupObservation: String? get()=null
 open fun readRestoredSessionBinding(): NativeSessionBinding?=null
 open fun isRestoredSessionBindingCurrent(binding:NativeSessionBinding)=true
 open fun readNativeIdleObservation()=NativeIdleObservation(NativeIdleState.UNKNOWN,0)
 open fun stopVpnIfBound(expected: NativeSessionIdentity)=false
 fun initialize(c:Context,s:MutableStateFlow<ProtocolState>,e:(String)->Unit) {context=c;state=s;onError=e;internalInit()}
 protected abstract fun internalInit()
 abstract suspend fun startVpn(config:JSONObject,builder:VpnService.Builder,protect:(Int)->Boolean)
 abstract fun stopVpn()
 abstract fun reconnectVpn(builder:VpnService.Builder,protect:(Int)->Boolean)
}
class Statistics {companion object {val EMPTY_STATISTICS=Statistics()}}
class VpnStartException(message:String):Exception(message)
''')
(a.output/'LogFixture.kt').write_text('''package org.amnezia.vpn.util
object Log {fun i(tag:String,message:String){};fun w(tag:String,message:String){};fun e(tag:String,message:String){}}
''')
source=(a.xray_source or root/'client/android/xray/src/main/kotlin/Xray.kt').read_text(encoding='utf8')
stop=method(source,'fun stopVpnVerified(): Boolean')
helper=method(source,'private fun String?.isNotNullOrBlank(')
endpoint=method(source,'internal fun xrayEndpointBypassRoute(')
assert 'xrayEndpointBypassRoute(it)?.let { endpoint -> excludeRoute(endpoint) }' in method(source,'private fun parseConfig(')
(a.output/'XrayEndpointFixture.kt').write_text('''package org.amnezia.vpn.protocol.xray
import org.amnezia.vpn.util.net.InetNetwork
import org.amnezia.vpn.util.net.parseInetAddress
'''+endpoint)
(a.output/'InetAddressFixture.kt').write_text('''package org.amnezia.vpn.util.net
import java.net.InetAddress
fun parseInetAddress(address:String):InetAddress=InetAddress.getByName(address)
val InetAddress.ip:String get()=hostAddress.orEmpty()
''')
(a.output/'XrayFixture.kt').write_text('''package org.amnezia.vpn.protocol.xray
import android.net.VpnService
import kotlinx.coroutines.flow.MutableStateFlow
import org.json.JSONObject
import org.amnezia.vpn.protocol.*
import org.amnezia.vpn.protocol.ProtocolState.DISCONNECTED
import org.amnezia.vpn.util.Log
private const val TAG="Xray"
object LibXrayStopFixture {
 var xrayError:String?=null;var tunError:String?=null;var throwXray=false;var calls=0
 fun reset(){xrayError=null;tunError=null;throwXray=false;calls=0}
 fun stopXray():String? {calls++;if(throwXray)throw IllegalStateException();return xrayError}
 fun stopTun2Socks():String? {calls++;return tunError}
}
typealias LibXray=LibXrayStopFixture
class Xray:Protocol() {
 private var isRunning=false
 private var nativeInitialized=true
 init{state=MutableStateFlow(ProtocolState.UNKNOWN)}
 override val statistics=Statistics.EMPTY_STATISTICS
 override fun internalInit(){}
 override suspend fun startVpn(config:JSONObject,builder:VpnService.Builder,protect:(Int)->Boolean){}
 override fun stopVpn(){stopVpnVerified()}
 override fun reconnectVpn(builder:VpnService.Builder,protect:(Int)->Boolean){}
 fun fixtureState()=state.value
 companion object {val instance=Xray()}
'''+stop+'\n}\n'+helper)
assert 'XrayNativeRuntime.await { startOnNativeThread(config, vpnBuilder, protect) }' in source
assert 'override fun internalInit() { }' in source
for native_method in ['private fun initializeNative(', 'private fun startOnNativeThread(', 'private fun start(config:', 'private fun runTun2Socks(']:
 assert 'XrayNativeRuntime.requireOwner()' in method(source,native_method)
assert 'XrayNativeRuntime.call' in method(source,'fun stopVpnVerified(): Boolean')
service=(root/'client/android/src/org/amnezia/vpn/AmneziaVpnService.kt').read_text(encoding='utf8')
disconnect=method(service,'private fun disconnect(').replace('private fun disconnect(', 'fun disconnect(',1)
(a.output/'OwnerStopFixture.kt').write_text('''package org.amnezia.vpn.ownerstop
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import org.amnezia.vpn.protocol.NativeSessionIdentity
import org.amnezia.vpn.protocol.NativeSessionDescriptor
import org.amnezia.vpn.protocol.ProtocolState.*
private const val TAG="test"
private const val DISCONNECT_TIMEOUT=100L
private object Log {fun d(tag:String,msg:String){};fun w(tag:String,msg:String){}}
private open class Protocol(val stopped:()->Unit) {var calls=0;fun stopVpn(){calls++;stopped()};fun stopVpnIfBound(expected:NativeSessionIdentity):Boolean{stopVpn();return true}}
private class DnsFallbackProtocol(stopped:()->Unit):Protocol(stopped)
private class Gate {fun invalidate(){}}
private enum class VpnProto(val protocol:Protocol) {XRAY(Protocol{}),SSXRAY(Protocol{})}
private class Controller {
 data class ActiveNativeSession(val protocol:Protocol,val descriptor:NativeSessionDescriptor)
 val protocolState=MutableStateFlow(UNKNOWN)
 val isUnknown get()=protocolState.value==UNKNOWN
 val isDisconnected get()=protocolState.value==DISCONNECTED
 var activeNativeSession:ActiveNativeSession?=null
 var vpnProto:VpnProto?=null
 val restoreStatusGate=Gate()
 val connectionScope=CoroutineScope(SupervisorJob()+Dispatchers.Unconfined)
 var connectionJob:Job?=null;var disconnectionJob:Job?=null
 fun invalidateDiscoveryGrants(){}
 fun stopRemoteLogUploader(){}
 fun stopService(){}
'''+disconnect+'''
}
fun runOwnerStopTests():Int {
 val id=NativeSessionIdentity("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb","cccccccc-cccc-cccc-cccc-cccccccccccc")
 val c=Controller();val owner=DnsFallbackProtocol{c.protocolState.value=DISCONNECTED}
 c.activeNativeSession=Controller.ActiveNativeSession(owner,NativeSessionDescriptor(id,"server","AWG"))
 c.disconnect();check(owner.calls==1&&c.protocolState.value==DISCONNECTED)
 c.protocolState.value=UNKNOWN
 c.disconnect(id.copy(serviceActivationId="dddddddd-dddd-dddd-dddd-dddddddddddd").toJson());check(owner.calls==1)
 c.disconnect(id.toJson());check(owner.calls==2&&c.protocolState.value==DISCONNECTED)
 c.disconnect();check(owner.calls==2)
 val other=Controller();val ordinary=Protocol{other.protocolState.value=DISCONNECTED}
 other.activeNativeSession=Controller.ActiveNativeSession(ordinary,NativeSessionDescriptor(id,"server","AWG"))
 other.disconnect();check(ordinary.calls==0&&other.protocolState.value==UNKNOWN)
 val legacy=Controller();val legacyOwner=Protocol{legacy.protocolState.value=DISCONNECTED}
 legacy.activeNativeSession=Controller.ActiveNativeSession(legacyOwner,NativeSessionDescriptor(id,"server","XRAY"))
 legacy.vpnProto=VpnProto.XRAY;legacy.disconnect();check(legacyOwner.calls==1&&legacy.protocolState.value==DISCONNECTED)
 c.connectionScope.cancel();other.connectionScope.cancel();legacy.connectionScope.cancel()
 return 6
}
''')
sources=[(a.resolver_source if name == 'DnsResolverSelection.kt' and a.resolver_source else root/'client/android/src/org/amnezia/vpn'/name) for name in ['DnsFallbackPolicy.kt','DnsResolverSelection.kt','DnsFallbackTransport.kt','DnsFallbackProtocol.kt','DnsVlessTls.kt','DnsTunnelReadiness.kt']]
sources += [root/'client/android/xray/src/main/kotlin/XrayNativeRuntime.kt']
sources += [root/'client/android/utils/src/main/kotlin/net/InetNetwork.kt']
sources += [root/'client/android/protocolApi/src/main/kotlin'/name for name in ['NativeSessionBinding.kt','ProtocolState.kt','DnsSessionOwner.kt','DnsTransportNoticeGate.kt']]
sources += [a.output/name for name in ['ProtocolFixture.kt','LogFixture.kt','XrayFixture.kt','OwnerStopFixture.kt','XrayEndpointFixture.kt','InetAddressFixture.kt']]+[Path(__file__).with_name('PolicyTest.kt'),Path(__file__).with_name('DnsResolverSelectionTest.kt'),Path(__file__).with_name('DnsRestoreTest.kt'),Path(__file__).with_name('XrayNativeRuntimeTest.kt'),Path(__file__).with_name('XrayEndpointRouteTest.kt'),Path(__file__).with_name('DnsTunnelReadinessTest.kt')]
sep=os.pathsep;cp=sep.join(map(str,[stdlib,annotations,coroutines,jsonjar,android]));target=a.output/'fallback-tests.jar'
java=Path.home()/'devtools/jdk-17/bin/java.exe'
cmd=[str(java),'-Xmx384m','-cp',sep.join(map(str,compiler)),'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler','-no-stdlib','-no-reflect','-classpath',cp,'-d',str(target),*map(str,sources)]
with (a.output/'compile.log').open('w',encoding='utf8') as f:r=subprocess.run(cmd,stdout=f,stderr=subprocess.STDOUT,timeout=90)
print('kotlinc_exit',r.returncode)
if r.returncode:raise SystemExit(r.returncode)
cmd=[str(java),'-Xmx128m','-Ddns.restore.fixture='+str((a.output/'kotlin-dns-snapshots.jsonl').resolve()),'-cp',str(target)+sep+cp,'org.amnezia.vpn.PolicyTestKt']
with (a.output/'test.log').open('w',encoding='utf8') as f:r=subprocess.run(cmd,stdout=f,stderr=subprocess.STDOUT,timeout=30)
print('jvm_exit',r.returncode);print((a.output/'test.log').read_text())
if r.returncode:raise SystemExit(r.returncode)
r=subprocess.run([sys.executable,'-B',str(Path(__file__).with_name('run_health_tests.py')),'--output',str(a.output/'health'),'--json-jar',str(jsonjar)],timeout=90)
if r.returncode:raise SystemExit(r.returncode)
for runner,directory in [('run_primary_reconnect_tests.py','primary-reconnect'),
                         ('run_prepare_cancel_tests.py','prepare-cancel'),
                         ('run_failed_cleanup_tests.py','failed-cleanup'),
                         ('run_transport_readiness_contract.py','transport-readiness')]:
    command=[sys.executable,'-B',str(Path(__file__).with_name(runner)),
             '--output',str(a.output/directory)]
    if runner == 'run_transport_readiness_contract.py':
        command += ['--compiler-classpath',os.pathsep.join(map(str,compiler))]
    r=subprocess.run(command,timeout=90)
    if r.returncode:raise SystemExit(r.returncode)
