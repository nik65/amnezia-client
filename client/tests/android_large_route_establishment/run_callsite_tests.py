"""Compile the exact production startVpn body with inert JNI/Android boundaries."""
from pathlib import Path
import argparse,os,subprocess
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=True)
root=Path(__file__).resolve().parents[3]
source=(root/'client/android/wireguard/src/main/kotlin/org/amnezia/vpn/protocol/wireguard/Wireguard.kt').read_text()
start=source.index('    override suspend fun startVpn(');brace=source.index('{',start);end=brace+1;depth=1
while depth:
 depth+=(source[end]=='{')-(source[end]=='}');end+=1
method=source[start:end].replace('override suspend fun','suspend fun',1)
stopStart=source.index('    override fun stopVpn()');stopBrace=source.index('{',stopStart);stopEnd=stopBrace+1;depth=1
while depth:
 depth+=(source[stopEnd]=='{')-(source[stopEnd]=='}');stopEnd+=1
stopMethod=source[stopStart:stopEnd].replace('override fun','fun',1)
scaffold='''package org.amnezia.vpn.protocol.wireguard
import kotlinx.coroutines.*
data class Identity(val instance:String,val activation:String,val nonce:String)
typealias NativeSessionIdentity=Identity
data class NativeSessionDescriptor(val identity:Identity,val server:String,val protocol:String)
class NativeSessionGuard {var idle=org.amnezia.vpn.protocol.NativeIdleState.UNKNOWN;var owner:NativeSessionDescriptor?=null
 inline fun <T> locked(f:()->T):T=synchronized(this){f()};fun activate(d:NativeSessionDescriptor){owner=d;idle=org.amnezia.vpn.protocol.NativeIdleState.ACTIVE}
 fun beginCleanup(){idle=org.amnezia.vpn.protocol.NativeIdleState.UNKNOWN};fun confirmedCleanup(){idle=org.amnezia.vpn.protocol.NativeIdleState.VERIFIED_RETIRED}
 fun idleObservation(active:Boolean)=Observation(idle)}
data class Observation(val state:org.amnezia.vpn.protocol.NativeIdleState)
class VpnStartException(s:String):Exception(s)
class JSONObject {fun optString(key:String,default:String)=if(key=="migrationConnectionNonce")"nonce" else key}
class Builder
class WireguardConfig {val addresses=setOf("address")}
class ParcelFileDescriptor {var closes=0;var transferred=false;var failClose=false;fun close(){closes++;if(failClose)throw java.io.IOException("close")}}
class State {var value="initial"}
const val DISCONNECTED="disconnected"
const val TAG="Wireguard"
object Log {fun w(tag:String,message:String){}}
fun bootstrapRouteSubset(routes:List<Int>):List<Int>?=routes
fun routeDestinationParcelExceedsRecommendation(routes:List<Int>)=true
class LargeRouteEstablishment(context:Any) {
 var cleanupConfirmed=true
 suspend fun establish(b:Builder,a:Set<String>,r:List<Int>,configureSmall:()->Unit,appendFinal:()->Unit,ensureOwner:()->Unit):ParcelFileDescriptor? {
  configureSmall();entered.complete(Unit);gate?.await()
  if(mode=="helper-close-fail"){cleanupConfirmed=false;throw java.io.IOException("unclosed")}
  ensureOwner();appendFinal();return fd
 }
 companion object {var mode="success";var fd=ParcelFileDescriptor();var gate:CompletableDeferred<Unit>?=null;var entered=CompletableDeferred<Unit>()}
}
class ActualWireguard {
 val nativeSessionGuard=NativeSessionGuard();var pendingStart:Any?=null;var pendingStartJob:Job?=null;var pendingCleanupUnconfirmed=false;var pendingStartCancelled=false
 var migrationConnectionNonce="";var cleanedNonce="";var tunnelHandle=-1;var config:WireguardConfig?=null;val context=Any();val state=State()
 var starts=0;var stops=0;var small=0;var final=0;var duringNative:()->Unit={}
 fun parseConfig(c:JSONObject)=WireguardConfig();fun interfaceRoutes(c:WireguardConfig)=listOf(1,2)
 fun buildVpnInterfaceWithRoutes(c:WireguardConfig,b:Builder,r:List<Int>){small++}
 fun applyInterfaceRoutes(r:List<Int>,b:Builder){final++}
 fun start(c:WireguardConfig,b:Builder,p:(Int)->Boolean,establishedTun:ParcelFileDescriptor?=null) {
  starts++;check(establishedTun==null||final==1);establishedTun?.transferred=true;tunnelHandle=7;duringNative()
 }
 fun turnOffVpn(){stops++;tunnelHandle=-1;cleanedNonce=migrationConnectionNonce;nativeSessionGuard.confirmedCleanup()}
'''
(a.output/'ActualCallsite.kt').write_text(scaffold+method+'\n'+stopMethod+'\n}\n')
(a.output/'Idle.kt').write_text('package org.amnezia.vpn.protocol\nenum class NativeIdleState {UNKNOWN,ACTIVE,VERIFIED_RETIRED}\n')
cache=Path.home()/'.gradle/caches/modules-2/files-2.1'
def jar(g,n,v):return next((cache/g/n/v).glob('*/*.jar'))
stdlib=jar('org.jetbrains.kotlin','kotlin-stdlib','2.1.0');coro=jar('org.jetbrains.kotlinx','kotlinx-coroutines-core-jvm','1.6.4');ann=jar('org.jetbrains','annotations','13.0')
compiler=[jar('org.jetbrains.kotlin','kotlin-compiler-embeddable','2.1.0'),stdlib,jar('org.jetbrains.kotlin','kotlin-script-runtime','2.1.0'),jar('org.jetbrains.kotlin','kotlin-reflect','1.6.10'),jar('org.jetbrains.intellij.deps','trove4j','1.0.20200330'),ann,coro]
cp=os.pathsep.join(map(str,[stdlib,coro,ann]));java=Path.home()/'devtools/jdk-17/bin/java.exe';target=a.output/'tests.jar'
subprocess.run([str(java),'-cp',os.pathsep.join(map(str,compiler)),'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler','-jvm-target','17','-no-stdlib','-no-reflect','-classpath',cp,'-d',str(target),str(a.output/'ActualCallsite.kt'),str(a.output/'Idle.kt'),str(Path(__file__).with_name('CallsiteTest.kt'))],check=True,timeout=60)
subprocess.run([str(java),'-cp',str(target)+os.pathsep+cp,'org.amnezia.vpn.protocol.wireguard.CallsiteTestKt'],check=True,timeout=30)
