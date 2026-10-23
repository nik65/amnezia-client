package org.amnezia.vpn.protocol.wireguard
import kotlinx.coroutines.*
import org.amnezia.vpn.protocol.NativeIdleState
private var checks=0
private fun verify(v:Boolean){checks++;check(v)}
private fun reset(mode:String="success") {
 LargeRouteEstablishment.mode=mode;LargeRouteEstablishment.fd=ParcelFileDescriptor()
 LargeRouteEstablishment.gate=null;LargeRouteEstablishment.entered=CompletableDeferred()
}
fun main()=runBlocking {
 reset();val success=ActualWireguard();success.startVpn(JSONObject(),Builder()){true}
 verify(success.starts==1&&success.small==1&&success.final==1)
 verify(success.pendingStart==null&&!success.pendingCleanupUnconfirmed&&success.nativeSessionGuard.idle==NativeIdleState.ACTIVE)
 verify(LargeRouteEstablishment.fd.transferred)
 supervisorScope {
  reset();val w=ActualWireguard();val gate=CompletableDeferred<Unit>();LargeRouteEstablishment.gate=gate
  val task=async{w.startVpn(JSONObject(),Builder()){true}}
  LargeRouteEstablishment.entered.await()
  verify(w.nativeSessionGuard.idle==NativeIdleState.UNKNOWN&&w.starts==0)
  try{w.startVpn(JSONObject(),Builder()){true};error("duplicate accepted")}catch(_:VpnStartException){}
  task.cancel();try{task.await()}catch(_:CancellationException){}
  verify(w.starts==0&&w.pendingStart==null&&w.nativeSessionGuard.idle==NativeIdleState.VERIFIED_RETIRED)
 }
 supervisorScope {
  reset();val w=ActualWireguard();val task=async(start=CoroutineStart.LAZY){w.startVpn(JSONObject(),Builder()){true}}
  w.duringNative={task.cancel()};task.start()
  try{task.await()}catch(_:CancellationException){}
  verify(w.starts==1&&w.stops==1&&w.tunnelHandle==-1&&w.pendingStart==null)
  verify(w.nativeSessionGuard.idle==NativeIdleState.VERIFIED_RETIRED)
 }
 reset("helper-close-fail");val blocked=ActualWireguard()
 try{blocked.startVpn(JSONObject(),Builder()){true};error("expected")}catch(_:java.io.IOException){}
 verify(blocked.pendingStart==null&&blocked.pendingCleanupUnconfirmed&&blocked.nativeSessionGuard.idle==NativeIdleState.UNKNOWN)
 try{blocked.startVpn(JSONObject(),Builder()){true};error("unconfirmed cleanup overwritten")}catch(_:VpnStartException){}
 verify(blocked.starts==0)
 reset();LargeRouteEstablishment.fd.failClose=true;val close=ActualWireguard()
 try{close.startVpn(JSONObject(),Builder()){true};error("expected close failure")}catch(_:java.io.IOException){}
 verify(close.pendingStart==null&&close.pendingCleanupUnconfirmed&&close.nativeSessionGuard.idle==NativeIdleState.UNKNOWN)
 supervisorScope {
  reset();LargeRouteEstablishment.fd.failClose=true;val w=ActualWireguard()
  val task=async(start=CoroutineStart.LAZY){w.startVpn(JSONObject(),Builder()){true}}
  w.duringNative={task.cancel()};task.start()
  try{task.await();error("expected cancellation")}catch(_:CancellationException){}
  verify(w.pendingStart==null&&w.pendingCleanupUnconfirmed&&w.nativeSessionGuard.idle==NativeIdleState.UNKNOWN&&w.cleanedNonce.isEmpty())
 }
 supervisorScope {
  reset();val w=ActualWireguard();val gate=CompletableDeferred<Unit>();LargeRouteEstablishment.gate=gate
  val task=async { withContext(NonCancellable){w.startVpn(JSONObject(),Builder()){true}} }
  LargeRouteEstablishment.entered.await();w.stopVpn();gate.complete(Unit)
  try{task.await();error("uncancellable owner proceeded")}catch(_:CancellationException){}
  verify(w.starts==0&&w.pendingStart==null&&w.nativeSessionGuard.idle==NativeIdleState.VERIFIED_RETIRED)
 }
 println("actual-startVpn checks=$checks")
}
