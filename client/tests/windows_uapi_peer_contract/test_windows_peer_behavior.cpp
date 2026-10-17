#include <QtTest>

#include <QByteArray>

#include <winsock2.h>
#include <windows.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>

namespace PeerMock {
QString reply;
bool routeResult = true;
bool enablePeerResult = true;
bool disablePeerResult = true;
int enablePeerCalls = 0;
int blockIpv6Calls = 0;
int disablePeerCalls = 0;
int disableKillSwitchCalls = 0;
int allowAllCalls = 0;
int uapiCalls = 0;
int routeAddCalls = 0;
int routeDeleteCalls = 0;
int captureDisableCalls = 0;
bool captureResult = true;
DWORD deleteRouteResult = NO_ERROR;
QStringList events;

DWORD deleteRoute(const MIB_IPFORWARD_ROW2*) {
  ++routeDeleteCalls;
  return deleteRouteResult;
}
}

#define DeleteIpForwardEntry2 PeerMock::deleteRoute
#define private public
#include "platforms/windows/daemon/wireguardutilswindows.cpp"
#undef private
#undef DeleteIpForwardEntry2

WindowsTunnelService::WindowsTunnelService(QObject* parent) : QObject(parent) {}
WindowsTunnelService::~WindowsTunnelService() {}
bool WindowsTunnelService::start(const QString&) { return true; }
bool WindowsTunnelService::stop() { return true; }
bool WindowsTunnelService::isRunning() { return true; }
QString WindowsTunnelService::uapiCommand(const QString&) {
  ++PeerMock::uapiCalls;
  PeerMock::events.append(QStringLiteral("uapi"));
  return PeerMock::reply;
}

WindowsFirewall::WindowsFirewall(HANDLE, QObject* parent) : QObject(parent) {}
WindowsFirewall::~WindowsFirewall() {}

WindowsRouteMonitor::WindowsRouteMonitor(quint64, QObject* parent)
    : QObject(parent) {}
WindowsRouteMonitor::~WindowsRouteMonitor() {}
bool WindowsRouteMonitor::setDetaultRouteCapture(bool enable) {
  if (!enable) ++PeerMock::captureDisableCalls;
  return enable || PeerMock::captureResult;
}
bool WindowsRouteMonitor::addExclusionRoute(const IPAddress&) {
  ++PeerMock::routeAddCalls;
  PeerMock::events.append(QStringLiteral("route-add"));
  return PeerMock::routeResult;
}
bool WindowsRouteMonitor::deleteExclusionRoute(const IPAddress&) {
  ++PeerMock::routeDeleteCalls;
  PeerMock::events.append(QStringLiteral("route-delete"));
  return PeerMock::routeResult;
}
void WindowsRouteMonitor::notifyRouteChanged() {}
void WindowsRouteMonitor::routeChanged() {}

bool WindowsFirewall::enableInterface(int) { return true; }
bool WindowsFirewall::enableLanBypass(const QList<IPAddress>&) { return true; }
bool WindowsFirewall::enablePeerTraffic(const InterfaceConfig&) {
  ++PeerMock::enablePeerCalls;
  PeerMock::events.append(QStringLiteral("enable"));
  return PeerMock::enablePeerResult;
}
bool WindowsFirewall::blockIpv6TrafficForPeer(const QString&) {
  ++PeerMock::blockIpv6Calls;
  PeerMock::events.append(QStringLiteral("block-ipv6"));
  return true;
}
bool WindowsFirewall::disablePeerTraffic(const QString&) {
  ++PeerMock::disablePeerCalls;
  PeerMock::events.append(QStringLiteral("disable-peer"));
  return PeerMock::disablePeerResult;
}
bool WindowsFirewall::disableKillSwitch() {
  ++PeerMock::disableKillSwitchCalls;
  PeerMock::events.append(QStringLiteral("disable-killswitch"));
  return true;
}
bool WindowsFirewall::allowAllTraffic() {
  ++PeerMock::allowAllCalls;
  PeerMock::events.append(QStringLiteral("allow-all"));
  return true;
}
bool WindowsFirewall::allowTrafficRange(const QStringList&) { return true; }

class WindowsPeerBehaviorTest final : public QObject {
  Q_OBJECT

  static InterfaceConfig config() {
    InterfaceConfig result;
    result.m_hopType = InterfaceConfig::SingleHop;
    result.m_privateKey = QByteArray(32, 'k').toBase64();
    result.m_deviceIpv4Address = QStringLiteral("10.0.0.2/32");
    result.m_serverPublicKey = QByteArray(32, 'p').toBase64();
    result.m_serverIpv4AddrIn = QStringLiteral("198.51.100.1");
    result.m_serverPort = 51820;
    result.m_allowedIPAddressRanges.append(IPAddress(QStringLiteral("0.0.0.0/0")));
    result.m_killSwitchEnabled = false;
    return result;
  }

 private slots:
  void nativeAwgEvidence_data() {
    QTest::addColumn<QString>("device");
    QTest::addColumn<QString>("peerFields");
    QTest::addColumn<bool>("capable");
    QTest::addColumn<bool>("keyHash");
    const auto key = QString(64, 'a');
    const auto flags = QStringLiteral("random_trailers=false\ndisable_cookies=true\n");
    QTest::newRow("first-line-flag") << flags + "header_protection_key=" + key + "\n" << QString() << true << true;
    QTest::newRow("invalid-hex") << flags + "header_protection_key=" + key + "z\n" << QString() << true << false;
    QTest::newRow("duplicate-key") << flags + "header_protection_key=" + key + "\nheader_protection_key=" + key + "\n" << QString() << true << false;
    QTest::newRow("invalid-flag") << QStringLiteral("random_trailers=garbage\ndisable_cookies=true\n") << QString() << false << false;
    QTest::newRow("duplicate-flag") << flags + "random_trailers=false\n" << QString() << false << false;
    QTest::newRow("peer-lookalike") << QString() << flags + "header_protection_key=" + key + "\n" << false << false;
  }

  void nativeAwgEvidence() {
    QFETCH(QString, device);
    QFETCH(QString, peerFields);
    QFETCH(bool, capable);
    QFETCH(bool, keyHash);
    PeerMock::reply = device + "public_key=" + QString(64, 'b') + "\n" + peerFields + "errno=0";
    WindowsFirewall firewall(reinterpret_cast<HANDLE>(1), nullptr);
    auto utils = WireguardUtilsWindows::create(&firewall, nullptr);
    const auto peers = utils->getPeerStatus();
    QCOMPARE(peers.size(), 1);
    QCOMPARE(peers.first().m_awg3Capable, capable);
    QCOMPARE(!peers.first().m_headerProtectionKeyHash.isEmpty(), keyHash);
  }

  void successfulUpdateRecordsPeerOnlyAfterUapiSuccess() {
    PeerMock::reply = QStringLiteral("errno=0");
    PeerMock::routeResult = true;
    PeerMock::enablePeerResult = true;
    PeerMock::disablePeerResult = true;
    PeerMock::enablePeerCalls = 0;
    PeerMock::blockIpv6Calls = 0;
    PeerMock::disablePeerCalls = 0;
    PeerMock::disableKillSwitchCalls = 0;
    PeerMock::allowAllCalls = 0;
    PeerMock::uapiCalls = 0;
    PeerMock::routeAddCalls = 0;
    PeerMock::routeDeleteCalls = 0;
    PeerMock::events.clear();
    WindowsFirewall firewall(reinterpret_cast<HANDLE>(1), nullptr);
    auto utils = WireguardUtilsWindows::create(&firewall, nullptr);
    QVERIFY(utils);

    const InterfaceConfig peer = config();
    QVERIFY(utils->updatePeer(peer));
    QVERIFY(utils->m_configuredPeers.contains(peer.m_serverPublicKey));
  }

  void failedUpdateDoesNotRecordPeer() {
    PeerMock::reply = QStringLiteral("errno=5");
    PeerMock::routeResult = true;
    PeerMock::enablePeerResult = true;
    PeerMock::enablePeerCalls = 0;
    PeerMock::blockIpv6Calls = 0;
    PeerMock::disablePeerCalls = 0;
    PeerMock::disableKillSwitchCalls = 0;
    PeerMock::allowAllCalls = 0;
    PeerMock::uapiCalls = 0;
    PeerMock::events.clear();
    WindowsFirewall firewall(reinterpret_cast<HANDLE>(1), nullptr);
    auto utils = WireguardUtilsWindows::create(&firewall, nullptr);
    QVERIFY(utils);

    const InterfaceConfig peer = config();
    QVERIFY(!utils->updatePeer(peer));
    QVERIFY(!utils->m_configuredPeers.contains(peer.m_serverPublicKey));
  }

  void failedDeleteRetainsPeerForRetry() {
    const InterfaceConfig peer = config();
    PeerMock::routeResult = true;
    PeerMock::enablePeerResult = true;
    PeerMock::disablePeerResult = true;
    PeerMock::enablePeerCalls = 0;
    PeerMock::blockIpv6Calls = 0;
    PeerMock::disablePeerCalls = 0;
    PeerMock::disableKillSwitchCalls = 0;
    PeerMock::allowAllCalls = 0;
    PeerMock::uapiCalls = 0;
    PeerMock::events.clear();
    WindowsFirewall firewall(reinterpret_cast<HANDLE>(1), nullptr);
    auto utils = WireguardUtilsWindows::create(&firewall, nullptr);
    QVERIFY(utils);

    PeerMock::reply = QStringLiteral("errno=0");
    QVERIFY(utils->updatePeer(peer));
    QVERIFY(utils->m_configuredPeers.contains(peer.m_serverPublicKey));

    PeerMock::reply = QStringLiteral("errno=5");
    QVERIFY(!utils->deletePeer(peer));
    QVERIFY(utils->m_configuredPeers.contains(peer.m_serverPublicKey));

    PeerMock::reply = QStringLiteral("errno=0");
    QVERIFY(utils->deletePeer(peer));
    QVERIFY(!utils->m_configuredPeers.contains(peer.m_serverPublicKey));
  }

  void failedEndpointCleanupRetainsPeerForRetry() {
    const InterfaceConfig peer = config();
    WindowsFirewall firewall(reinterpret_cast<HANDLE>(1), nullptr);
    WindowsRouteMonitor monitor(9, nullptr);
    auto utils = WireguardUtilsWindows::create(&firewall, nullptr);
    QVERIFY(utils);
    utils->m_routeMonitor = &monitor;

    PeerMock::routeResult = true;
    PeerMock::enablePeerResult = true;
    PeerMock::blockIpv6Calls = 0;
    PeerMock::reply = QStringLiteral("errno=0");
    QVERIFY(utils->updatePeer(peer));

    PeerMock::routeResult = false;
    QVERIFY(!utils->deletePeer(peer));
    QVERIFY(utils->m_configuredPeers.contains(peer.m_serverPublicKey));
  }

  void failedCaptureCleanupMakesDefaultRouteDeleteFailClosed() {
    WindowsFirewall firewall(reinterpret_cast<HANDLE>(1), nullptr);
    WindowsRouteMonitor monitor(9, nullptr);
    auto utils = WireguardUtilsWindows::create(&firewall, nullptr);
    QVERIFY(utils);
    utils->m_routeMonitor = &monitor;

    PeerMock::captureDisableCalls = 0;
    PeerMock::routeDeleteCalls = 0;
    PeerMock::captureResult = false;
    PeerMock::deleteRouteResult = ERROR_NOT_FOUND;
    QVERIFY(!utils->deleteRoutePrefix(IPAddress(QStringLiteral("0.0.0.0/0"))));
    QCOMPARE(PeerMock::captureDisableCalls, 1);
    QCOMPARE(PeerMock::routeDeleteCalls, 1);

    PeerMock::captureResult = true;
    QVERIFY(utils->deleteRoutePrefix(IPAddress(QStringLiteral("0.0.0.0/0"))));
    QCOMPARE(PeerMock::captureDisableCalls, 2);
    QCOMPARE(PeerMock::routeDeleteCalls, 2);
  }

  void lastPeerFirewallRemovalIsDeferred() {
    const InterfaceConfig peer = config();
    WindowsFirewall firewall(reinterpret_cast<HANDLE>(1), nullptr);
    WindowsRouteMonitor monitor(9, nullptr);
    auto utils = WireguardUtilsWindows::create(&firewall, nullptr);
    QVERIFY(utils);
    utils->m_routeMonitor = &monitor;

    PeerMock::routeResult = true;
    PeerMock::enablePeerResult = true;
    PeerMock::blockIpv6Calls = 0;
    PeerMock::disablePeerResult = false;
    PeerMock::disablePeerCalls = 0;
    PeerMock::reply = QStringLiteral("errno=0");
    QVERIFY(utils->updatePeer(peer));
    QVERIFY(utils->deletePeer(peer));
    QCOMPARE(PeerMock::disablePeerCalls, 0);
  }

  void twoPeerFirewallFailureRetainsPeerUntilRetry() {
    InterfaceConfig first = config();
    InterfaceConfig second = config();
    second.m_serverPublicKey = QByteArray(32, 'q').toBase64();
    WindowsFirewall firewall(reinterpret_cast<HANDLE>(1), nullptr);
    WindowsRouteMonitor monitor(9, nullptr);
    auto utils = WireguardUtilsWindows::create(&firewall, nullptr);
    QVERIFY(utils);
    utils->m_routeMonitor = &monitor;

    PeerMock::routeResult = true;
    PeerMock::enablePeerResult = true;
    PeerMock::blockIpv6Calls = 0;
    PeerMock::disablePeerResult = true;
    PeerMock::disablePeerCalls = 0;
    PeerMock::reply = QStringLiteral("errno=0");
    QVERIFY(utils->updatePeer(first));
    QVERIFY(utils->updatePeer(second));

    PeerMock::disablePeerResult = false;
    QVERIFY(!utils->deletePeer(first));
    QCOMPARE(PeerMock::disablePeerCalls, 1);
    QVERIFY(utils->m_configuredPeers.contains(first.m_serverPublicKey));
    QVERIFY(utils->m_configuredPeers.contains(second.m_serverPublicKey));

    PeerMock::disablePeerResult = true;
    QVERIFY(utils->deletePeer(first));
    QVERIFY(!utils->m_configuredPeers.contains(first.m_serverPublicKey));
    QVERIFY(utils->deletePeer(second));
    QCOMPARE(PeerMock::disablePeerCalls, 2);
  }

  void killSwitchRouteSetupFailureStaysFailClosedWithoutReceipt() {
    InterfaceConfig peer = config();
    peer.m_killSwitchEnabled = true;
    peer.m_blockIpv6Traffic = true;
    WindowsFirewall firewall(reinterpret_cast<HANDLE>(1), nullptr);
    WindowsRouteMonitor monitor(9, nullptr);
    auto utils = WireguardUtilsWindows::create(&firewall, nullptr);
    QVERIFY(utils);
    utils->m_routeMonitor = &monitor;

    PeerMock::enablePeerResult = true;
    PeerMock::enablePeerCalls = 0;
    PeerMock::blockIpv6Calls = 0;
    PeerMock::disablePeerCalls = 0;
    PeerMock::disableKillSwitchCalls = 0;
    PeerMock::allowAllCalls = 0;
    PeerMock::uapiCalls = 0;
    PeerMock::routeAddCalls = 0;
    PeerMock::routeDeleteCalls = 0;
    PeerMock::events.clear();
    PeerMock::routeResult = false;
    PeerMock::reply = QStringLiteral("errno=0");

    QVERIFY(!utils->updatePeer(peer));
    QCOMPARE(PeerMock::enablePeerCalls, 1);
    QCOMPARE(PeerMock::blockIpv6Calls, 1);
    QCOMPARE(PeerMock::routeAddCalls, 1);
    QCOMPARE(PeerMock::routeDeleteCalls, 0);
    QCOMPARE(PeerMock::uapiCalls, 0);
    QCOMPARE(PeerMock::disablePeerCalls, 0);
    QCOMPARE(PeerMock::disableKillSwitchCalls, 0);
    QCOMPARE(PeerMock::allowAllCalls, 0);
    QCOMPARE(PeerMock::events,
             QStringList({QStringLiteral("enable"),
                          QStringLiteral("block-ipv6"),
                          QStringLiteral("route-add")}));
    QVERIFY(utils->m_configuredPeers.isEmpty());
  }

  void killSwitchUapiFailureKeepsPermitAndNoReceipt() {
    InterfaceConfig peer = config();
    peer.m_killSwitchEnabled = true;
    peer.m_blockIpv6Traffic = true;
    WindowsFirewall firewall(reinterpret_cast<HANDLE>(1), nullptr);
    WindowsRouteMonitor monitor(9, nullptr);
    auto utils = WireguardUtilsWindows::create(&firewall, nullptr);
    QVERIFY(utils);
    utils->m_routeMonitor = &monitor;

    PeerMock::enablePeerResult = true;
    PeerMock::enablePeerCalls = 0;
    PeerMock::blockIpv6Calls = 0;
    PeerMock::disablePeerCalls = 0;
    PeerMock::disableKillSwitchCalls = 0;
    PeerMock::allowAllCalls = 0;
    PeerMock::uapiCalls = 0;
    PeerMock::routeAddCalls = 0;
    PeerMock::routeDeleteCalls = 0;
    PeerMock::events.clear();
    PeerMock::routeResult = true;
    PeerMock::reply = QStringLiteral("errno=5");

    QVERIFY(!utils->updatePeer(peer));
    QCOMPARE(PeerMock::enablePeerCalls, 1);
    QCOMPARE(PeerMock::blockIpv6Calls, 1);
    QCOMPARE(PeerMock::routeAddCalls, 1);
    QCOMPARE(PeerMock::routeDeleteCalls, 0);
    QCOMPARE(PeerMock::uapiCalls, 1);
    QCOMPARE(PeerMock::disablePeerCalls, 0);
    QCOMPARE(PeerMock::disableKillSwitchCalls, 0);
    QCOMPARE(PeerMock::allowAllCalls, 0);
    QCOMPARE(PeerMock::events,
             QStringList({QStringLiteral("enable"),
                          QStringLiteral("block-ipv6"),
                          QStringLiteral("route-add"),
                          QStringLiteral("uapi")}));
    QVERIFY(utils->m_configuredPeers.isEmpty());
  }

  void existingPeerRemainsAfterFailedKillSwitchUpdate() {
    InterfaceConfig peer = config();
    peer.m_killSwitchEnabled = true;
    peer.m_blockIpv6Traffic = true;
    WindowsFirewall firewall(reinterpret_cast<HANDLE>(1), nullptr);
    WindowsRouteMonitor monitor(9, nullptr);
    auto utils = WireguardUtilsWindows::create(&firewall, nullptr);
    QVERIFY(utils);
    utils->m_routeMonitor = &monitor;

    PeerMock::enablePeerResult = true;
    PeerMock::disablePeerResult = true;
    PeerMock::routeResult = true;
    PeerMock::reply = QStringLiteral("errno=0");
    PeerMock::uapiCalls = 0;
    PeerMock::disablePeerCalls = 0;
    PeerMock::disableKillSwitchCalls = 0;
    PeerMock::allowAllCalls = 0;
    QVERIFY(utils->updatePeer(peer));
    QVERIFY(utils->m_configuredPeers.contains(peer.m_serverPublicKey));

    PeerMock::events.clear();
    PeerMock::routeResult = false;
    PeerMock::reply = QStringLiteral("errno=0");
    QVERIFY(!utils->updatePeer(peer));
    QVERIFY(utils->m_configuredPeers.contains(peer.m_serverPublicKey));
    QCOMPARE(PeerMock::uapiCalls, 1);
    QCOMPARE(PeerMock::disablePeerCalls, 0);
    QCOMPARE(PeerMock::disableKillSwitchCalls, 0);
    QCOMPARE(PeerMock::allowAllCalls, 0);
    QCOMPARE(PeerMock::events,
             QStringList({QStringLiteral("enable"),
                          QStringLiteral("block-ipv6"),
                          QStringLiteral("route-add")}));
  }

  void missingEndpointStopsBeforeUapiAndBookkeeping() {
    InterfaceConfig peer = config();
    peer.m_serverIpv4AddrIn.clear();
    peer.m_serverIpv6AddrIn.clear();
    PeerMock::reply = QStringLiteral("errno=0");
    PeerMock::routeResult = true;
    WindowsFirewall firewall(reinterpret_cast<HANDLE>(1), nullptr);
    auto utils = WireguardUtilsWindows::create(&firewall, nullptr);
    QVERIFY(utils);

    QVERIFY(!utils->updatePeer(peer));
    QVERIFY(utils->m_configuredPeers.isEmpty());
  }
};

QTEST_GUILESS_MAIN(WindowsPeerBehaviorTest)
#include "test_windows_peer_behavior.moc"
