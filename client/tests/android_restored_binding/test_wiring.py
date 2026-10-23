"""Supplement actual JVM execution with cross-file production wiring checks."""
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[3]
def text(relative):return (ROOT/relative).read_text(encoding="utf-8")
ACTIVITY="client/android/src/org/amnezia/vpn/AmneziaActivity.kt"
SERVICE="client/android/src/org/amnezia/vpn/AmneziaVpnService.kt"
WIRE="client/android/wireguard/src/main/kotlin/org/amnezia/vpn/protocol/wireguard/Wireguard.kt"
class NativeBindingWiring(unittest.TestCase):
 def test_ready_waits_for_registered_jni(self):
  a=text(ACTIVITY);section=a[a.index("private fun notifyRestoreServiceReadyWhenQtReady()"):a.index("private val vpnServiceEventHandler")]
  self.assertLess(section.index("qtInitialized.await()"),section.index("QtAndroidController.onRestoreServiceReady"))
  self.assertIn("generation == restoreBindingGeneration",section)
  self.assertIn("NativeSessionWire.nextBindingGeneration()",a)
 def test_challenged_status_never_reads_async_state_store(self):
  a=text(ACTIVITY);section=a[a.index("ServiceEvent.STATUS ->"):a.index("if (isWaitingStatus)",a.index("ServiceEvent.STATUS ->"))]
  self.assertNotIn("VpnStateStore",section);self.assertIn("request == pendingRestoreRequest",section)
  self.assertIn("generation == restoreBindingGeneration.toString()",section);self.assertIn("pendingRestoreRequest = null",section)
 def test_service_io_then_fenced_main_commit(self):
  s=text(SERVICE);section=s[s.index("private fun requestBoundRestoreStatus("):s.index("private fun connect(vpnConfig")]
  self.assertIn("withContext(Dispatchers.IO)",section);self.assertIn("restoreStatusGate.commit(ticket",section)
  self.assertIn("activeNativeSession === ticket.owner",section);self.assertIn("binding.descriptor == ticket.owner.descriptor",section)
 def test_exact_stop_no_downgrade(self):
  a=text(ACTIVITY);section=a[a.index("fun stopBound("):a.index("fun start(vpnConfig",a.index("fun stopBound("))]
  self.assertIn("NativeSessionIdentity.parseExpected",section);self.assertIn('putString("expectedNativeSession"',section)
  self.assertNotIn("disconnectFromVpn()",section)
  s=text(SERVICE);self.assertIn('if (msg.data.containsKey("expectedNativeSession"))',s)
  self.assertIn("retiringProtocol?.stopVpnIfBound(expected) != true",s)
  self.assertIn("nativeSessionGuard.stopIfBound(expected) { stopVpn() }",text(WIRE))
 def test_fresh_activation_and_captured_protocol(self):
  s=text(SERVICE);section=s[s.index("private fun connectToVpn(vpnConfig"):s.index("private fun disconnect(")]
  self.assertIn('put("nativeServiceActivationId", UUID.randomUUID().toString())',section)
  self.assertIn("protocol.startVpn(privateConfig",section);self.assertNotIn("vpnProto?.protocol?.let",section)
  reconnect=s[s.index("private fun reconnect(decisionEpoch"):s.index("private fun configureRemoteLogUploader")]
  self.assertNotIn("UUID.randomUUID",reconnect);self.assertIn("restoreStatusGate.invalidate()",reconnect)
 def test_native_methods_share_guard(self):
  w=text(WIRE)
  for marker in ["override val migrationObservation:","override val statistics:","override suspend fun startVpn(","private fun getLastHandshake()","override fun stopVpn()","override fun reconnectVpn("]:
   start=w.index(marker);self.assertIn("nativeSessionGuard.locked",w[start:start+220],marker)
  self.assertIn("nativeSessionGuard.confirmedCleanup()",w);self.assertIn('put("serviceActivationId", identity.serviceActivationId)',w)
 def test_fixed_qt_api_names(self):
  q=text("client/android/src/org/amnezia/vpn/qt/QtAndroidController.kt")
  self.assertIn("external fun onRestoreServiceReady(bindingGeneration: Long)",q)
  self.assertIn("external fun onRestoreStatus(snapshot: String)",q)
 def test_native_observation_uses_actual_component_without_index(self):
  a=text(ACTIVITY);self.assertIn("name?.className == AwgService::class.java.name",a)
  branch=a[a.index('if (isBoundNativeService && state.name == "CONNECTED")'):a.index("} else mainScope.launch",a.index('if (isBoundNativeService && state.name == "CONNECTED")'))]
  self.assertIn("notifyNativeSessionObservedWhenQtReady(statusGeneration)",branch);self.assertNotIn("VpnStateStore",branch);self.assertNotIn("onStatus",branch)
  self.assertIn("external fun onNativeSessionObserved()",text("client/android/src/org/amnezia/vpn/qt/QtAndroidController.kt"))
 def test_pending_unbind_uses_nullable_receiver(self):
  a=text(ACTIVITY);section=a[a.index("private fun doUnbindService()"):a.index("Methods of starting and stopping VpnService")]
  self.assertIn("val retiringReceiver = boundActivityMessenger",section)
  self.assertIn("if (retiringReceiver != null)",section);self.assertNotIn("Action.UNREGISTER_CLIENT, activityMessenger",section)
 def test_lifecycle_disconnect_waits_for_qt_and_generation(self):
  a=text(ACTIVITY);self.assertEqual(1,a.count("QtAndroidController.onServiceDisconnected()"))
  section=a[a.index("private fun notifyServiceDisconnectedWhenQtReady()"):a.index("private fun notifyRestoreServiceReadyWhenQtReady()")]
  self.assertLess(section.index("qtInitialized.await()"),section.index("QtAndroidController.onServiceDisconnected()"));self.assertIn("generation == restoreBindingGeneration",section)
  ready=a[a.index("fun qtAndroidControllerInitialized()"):a.index("fun requestRestoreStatus(")]
  self.assertLess(ready.index("mainScope.launch"),ready.index("if (isServiceConnected)"))
 def test_rebound_receiver_and_qtready_fence(self):
  a=text(ACTIVITY);section=a[a.index("private fun createBoundActivityMessenger()"):a.index("private fun adoptConnectedService(")]
  self.assertIn("serviceEventBindingGate.bind()",section);self.assertIn("serviceEventBindingGate.accepts(bindingToken)",section)
  self.assertLess(section.index("qtInitialized.await()"),section.index("vpnServiceEventHandler.handleMessage(ownedMessage)"));self.assertIn("ownedMessage.recycle()",section)
 def test_old_handshake_commit_has_generation_and_active_fence(self):
  w=text(WIRE);section=w[w.index("private fun launchStatusJob()"):w.index("private fun getLastHandshake()")]
  self.assertEqual(3,section.count("expectedStatusGeneration != statusJobGeneration"))
  self.assertIn("state.value = UNKNOWN",section);self.assertIn("state.value = nextState",section)
  self.assertIn("++statusJobGeneration",w[w.index("private fun turnOffVpn()"):w.index("override fun readRestoredSessionBinding()")])
if __name__=="__main__":unittest.main()
