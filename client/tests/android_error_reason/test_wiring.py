"""Static JNI/Bundle wiring checks; complements executable Kotlin/Qt tests."""
from pathlib import Path
import re
import unittest

CLIENT = Path(__file__).resolve().parents[2]


class AndroidReasonWiringTests(unittest.TestCase):
    def test_jni_signature_and_all_kotlin_callers(self):
        bridge = (CLIENT / "android/src/org/amnezia/vpn/qt/QtAndroidController.kt").read_text()
        activity = (CLIENT / "android/src/org/amnezia/vpn/AmneziaActivity.kt").read_text()
        native = (CLIENT / "platforms/android/android_controller.cpp").read_text()
        self.assertIn("external fun onServiceError(reasonCode: Int)", bridge)
        self.assertIn('{"onServiceError", "(I)V", reinterpret_cast<void *>(onServiceError)}', native)
        self.assertEqual(3, activity.count("QtAndroidController.onServiceError("))
        self.assertNotIn("QtAndroidController.onServiceError()", activity)
        self.assertIn("getInt(MSG_ERROR_REASON, 0)", activity)
        self.assertIn("AndroidProtocolBinding::errorForServiceReason(reasonCode)", native)

    def test_service_carries_reason_in_integer_bundle(self):
        service = (CLIENT / "android/src/org/amnezia/vpn/AmneziaVpnService.kt").read_text()
        self.assertRegex(service, r"is BadConfigException -> onErrorWithReason\([^\n]+e\.reasonCode\)")
        self.assertIn("putInt(MSG_ERROR_REASON, reasonCode)", service)
        self.assertIn("onErrorWithReason(msg, 0)", service)

    def test_both_pre_android10_refusals_use_typed_reason(self):
        for relative in ["android/protocolApi/src/main/kotlin/ProtocolConfig.kt",
                         "android/wireguard/src/main/kotlin/org/amnezia/vpn/protocol/wireguard/UnionVpnCallbacks.kt"]:
            text = (CLIENT / relative).read_text()
            self.assertIn("reasonCode = ProtocolErrorReason.COMBINED_ROUTING_REQUIRES_ANDROID_10", text)
        exceptions = (CLIENT / "android/protocolApi/src/main/kotlin/Exceptions.kt").read_text()
        self.assertIn("COMBINED_ROUTING_REQUIRES_ANDROID_10 = 105", exceptions)
        self.assertIn("val reasonCode: Int = 0", exceptions)

    def test_production_binding_is_queued_and_receiver_owned(self):
        connection = (CLIENT / "vpnConnection.cpp").read_text()
        match = re.search(r"connect\(AndroidController::instance\(\), &AndroidController::serviceError, androidVpnProtocol,(.*?)Qt::QueuedConnection\);", connection, re.S)
        self.assertIsNotNone(match)
        body = match.group(1)
        self.assertIn("QPointer<AndroidVpnProtocol>(androidVpnProtocol)", body)
        self.assertIn("epoch = m_connectionEpoch", body)
        self.assertIn("AndroidProtocolBinding::deliverServiceError", body)
        self.assertIn("m_vpnProtocol.data()", body)


if __name__ == "__main__":
    unittest.main()
