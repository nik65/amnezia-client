"""Actual public-API establishment helper, deterministic Android boundary fakes.

No Android runtime/device, Gradle, APK or native VPN is started. Parcel's nested
IpPrefix component follows the Android15 reference format; it is not a phone
measurement. typecheck_sources.py separately checks the actual Android SDK API.
"""
from pathlib import Path
import argparse, os, subprocess, json

p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args()
a.output.mkdir(parents=True,exist_ok=True)
root=Path(__file__).resolve().parents[3]
cache=Path.home()/'.gradle/caches/modules-2/files-2.1'
def jar(g,n,v): return next((cache/g/n/v).glob('*/*.jar'))
stdlib=jar('org.jetbrains.kotlin','kotlin-stdlib','2.1.0')
coro=jar('org.jetbrains.kotlinx','kotlinx-coroutines-core-jvm','1.6.4')
annotations=jar('org.jetbrains','annotations','13.0')
compiler=[jar('org.jetbrains.kotlin','kotlin-compiler-embeddable','2.1.0'),stdlib,
jar('org.jetbrains.kotlin','kotlin-script-runtime','2.1.0'),jar('org.jetbrains.kotlin','kotlin-reflect','1.6.10'),
jar('org.jetbrains.intellij.deps','trove4j','1.0.20200330'),annotations,coro]
stubs={
'Log.kt':'''package org.amnezia.vpn.util
object Log {fun i(tag:String,message:String){}}
''',
'Context.kt':'''package android.content
import android.net.ConnectivityManager
class Context(val cm:ConnectivityManager) {val contentResolver=Any();fun <T> getSystemService(c:Class<T>):T?=c.cast(cm)}
''',
'Os.kt':'''package android.os
object Build {object VERSION {var SDK_INT=35}}
object Process {fun myUid()=1000}
class Looper {companion object {private val main=Looper();fun myLooper():Looper?=null;fun getMainLooper()=main}}
object IBinder {fun getSuggestedMaxIpcSizeBytes()=65536}
class Parcel {private var bytes=0;fun writeParcelable(p:android.net.IpPrefix,flags:Int) {
 // Parcel.writeParcelable class name String16, then IpPrefix byte[] + mask.
 val name="android.net.IpPrefix";bytes+=4+((2*(name.length+1)+3)/4)*4
 bytes+=4+((p.address.address.size+3)/4)*4+4
 };fun dataSize()=bytes;fun recycle(){};companion object{fun obtain()=Parcel()}}
class ParcelFileDescriptor(val number:Int):java.io.Closeable {var closes=0;var failClose=false;override fun close(){closes++;if(failClose)throw java.io.IOException("close")}}
''',
'Settings.kt':'''package android.provider
object Settings {object Global {var mode:String?="off";fun getString(r:Any,k:String)=mode}}
''',
'Net.kt':'''package android.net
import java.net.InetAddress
import android.os.ParcelFileDescriptor
data class Network(val id:Int)
data class IpPrefix(val address:InetAddress,val prefixLength:Int)
data class LinkAddress(val address:InetAddress,val prefixLength:Int)
data class RouteInfo(val destination:IpPrefix,val type:Int)
class LinkProperties {var interfaceName:String?="tun1";var linkAddresses=listOf<LinkAddress>();var routes=listOf<RouteInfo>()}
class NetworkCapabilities(var ownerUid:Int=1000,var validated:Boolean=true,var vpn:Boolean=true) {
 constructor(c:NetworkCapabilities):this(c.ownerUid,c.validated,c.vpn)
 fun hasTransport(t:Int)=vpn;fun hasCapability(c:Int)=validated
 companion object {const val TRANSPORT_VPN=4;const val NET_CAPABILITY_VALIDATED=16;const val NET_CAPABILITY_NOT_VPN=15}
}
class NetworkRequest {class Builder {fun removeCapability(c:Int)=this;fun addTransportType(t:Int)=this;fun build()=NetworkRequest()}}
open class ConnectivityManager {
 var callback:NetworkCallback?=null;var unregisters=0;var unregisterFailures=0;var unregisterHook:()->Unit={};val existing=linkedMapOf<Network,NetworkCapabilities>()
 val allNetworks:Array<Network> get()=existing.keys.toTypedArray()
 fun getNetworkCapabilities(n:Network)=existing[n]
 fun registerNetworkCallback(r:NetworkRequest,c:NetworkCallback){callback=c}
 fun unregisterNetworkCallback(c:NetworkCallback){check(callback===c);unregisters++;if(unregisterFailures-->0)throw IllegalStateException("unregister");callback=null;unregisterHook()}
 open class NetworkCallback {open fun onCapabilitiesChanged(n:Network,c:NetworkCapabilities){};open fun onLinkPropertiesChanged(n:Network,p:LinkProperties){};open fun onLost(n:Network){}}
 fun emit(n:Network,c:NetworkCapabilities,p:LinkProperties){existing[n]=c;callback!!.onCapabilitiesChanged(n,c);callback!!.onLinkPropertiesChanged(n,p)}
 fun lose(n:Network){existing.remove(n);callback!!.onLost(n)}
}
class VpnService {class Builder(val create:(Int)->ParcelFileDescriptor?) {var calls=0;fun establish()=create(++calls)}}
''',
'Model.kt':'''package org.amnezia.vpn.protocol
import org.amnezia.vpn.util.net.InetNetwork
data class Route(val inetNetwork:InetNetwork,val include:Boolean)
class VpnStartException(message:String):Exception(message)
''',
'NetworkUtils.kt':'''package org.amnezia.vpn.util.net
import java.net.InetAddress
fun parseInetAddress(v:String):InetAddress=InetAddress.getByName(v)
val InetAddress.ip:String get()=hostAddress!!
'''}
for name,text in stubs.items():(a.output/name).write_text(text)
fixture=root/'client/tests/route_rule_matcher/fixtures/android-policy17-installed-route-keys.json'
(a.output/'fixture.txt').write_text('\n'.join(json.loads(fixture.read_text())))
sources=[root/'client/android/protocolApi/src/main/kotlin/LargeRouteEstablishment.kt',
root/'client/android/protocolApi/src/main/kotlin/RouteCompaction.kt',
root/'client/android/utils/src/main/kotlin/net/InetNetwork.kt',Path(__file__).with_name('LargeRouteEstablishmentTest.kt')]
sources+=list(a.output.glob('*.kt'))
cp=os.pathsep.join(map(str,[stdlib,coro,annotations]));target=a.output/'tests.jar'
java=Path.home()/'devtools/jdk-17/bin/java.exe'
subprocess.run([str(java),'-cp',os.pathsep.join(map(str,compiler)),
'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler','-jvm-target','17','-no-stdlib','-no-reflect',
'-classpath',cp,'-d',str(target),*map(str,sources)],check=True,timeout=60)
subprocess.run([str(java),'-cp',str(target)+os.pathsep+cp,
'org.amnezia.vpn.protocol.LargeRouteEstablishmentTestKt',str(a.output/'fixture.txt')],check=True,timeout=60)
