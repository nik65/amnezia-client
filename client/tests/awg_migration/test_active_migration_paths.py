"""Regression assertions on the actual service/IPC consumers, not inactive hooks.

Runtime native failure acceptance still belongs to the owned Windows/Linux guests
and a real Android phone. These fixtures prevent moving the wire hooks into dead
code and dropping the receipt identity or native cleanup ordering.
"""
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]


def source(path):
    text = (ROOT / path).read_text(encoding="utf-8-sig")
    return re.sub(r"/\*.*?\*/", "", text, flags=re.S)


class ActiveMigrationPaths(unittest.TestCase):
    def test_android_bound_status_and_periodic_observation_are_active(self):
        service = source("android/src/org/amnezia/vpn/AmneziaVpnService.kt")
        status = service.split("Action.REQUEST_STATUS ->", 1)[1].split("Action.NOTIFICATION_PERMISSION_GRANTED", 1)[0]
        self.assertIn('putString("migrationObservation", it)', status)
        periodic = service.split("private fun startTrafficStatsUpdateJob()", 1)[1].split("private fun stopTrafficStatsUpdateJob", 1)[0]
        self.assertIn("clientMessengers.values.toList()", periodic)
        self.assertIn('putString("migrationObservation", it)', periodic)
        cleanup = service.index("protocol?.migrationCleanupObservation")
        self.assertLess(cleanup, service.index("ServiceEvent.STATUS_CHANGED", cleanup))

    def test_daemon_receipt_follows_native_cleanup_and_is_epoch_bound(self):
        daemon = source("daemon/daemonlocalserverconnection.cpp")
        stop = daemon.split('if (type == "deactivate")', 1)[1].split('if (type == "status")', 1)[0]
        self.assertIn("nonce == Daemon::instance()->migrationNonce", stop)
        self.assertLess(stop.index("deactivate(false)"), stop.index('"migrationNativeCleanup"'))
        socket = source("mozilla/localsocketcontroller.cpp")
        stop = socket.split("void LocalSocketController::deactivate()", 1)[1].split("void LocalSocketController::checkStatus", 1)[0]
        self.assertNotIn("emit disconnected()", stop.split("write(json);", 1)[1])
        self.assertIn("nonce == m_migrationNonce", socket)
        vpn = source("vpnConnection.cpp")
        self.assertIn("new MigrationTeardownContext", vpn)
        self.assertIn("context->observeAndroid(receipt, retiringEpoch)", vpn)
        self.assertNotIn("m_startupRouteTeardownConfirmed && m_vpnProtocol.isNull()", vpn)

    def test_committed_ack_renews_target_without_erasing_receipt(self):
        controller = source("core/controllers/awgMigrationController.cpp")
        fetch = controller.split("void AwgMigrationController::enrollOrFetch()", 1)[1].split("void AwgMigrationController::challenge()", 1)[0]
        self.assertLess(fetch.index('== "ack_pending"'), fetch.index('remove("grant")'))
        ack = controller.split("void AwgMigrationController::acknowledge()", 1)[1]
        self.assertIn('request("/migration/v1/renew"', ack)
        self.assertIn('"challengeReceipt"', ack)
        self.assertNotIn('/migration/v1/bootstrap', ack)
        self.assertNotIn('remove("challengeReceipt")', ack)


if __name__ == "__main__":
    unittest.main()
