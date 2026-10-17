#include <QtTest>

#include "daemon/daemon.h"

class InertDns final : public DnsUtils {
 public:
  InertDns() : DnsUtils(nullptr) {}
  bool restoreResolvers() override {
    ++restoreCalls;
    return true;
  }
  int restoreCalls = 0;
};

class DeactivateBackend final : public WireguardUtils {
 public:
  DeactivateBackend() : WireguardUtils(nullptr) {}

  bool interfaceExists() override { return monitorActive; }
  bool addInterface(const InterfaceConfig&) override { return false; }
  bool deleteInterface() override {
    ++deleteInterfaceCalls;
    monitorActive = false;
    return true;
  }
  bool updatePeer(const InterfaceConfig&) override { return true; }
  bool deletePeer(const InterfaceConfig&) override {
    ++deletePeerCalls;
    return true;
  }
  QList<PeerStatus> getPeerStatus() override { return {}; }
  bool updateRoutePrefix(const IPAddress&) override { return true; }
  bool deleteRoutePrefix(const IPAddress& prefix) override {
    deletedAllowedRoutes.append(prefix.toString());
    return true;
  }
  bool addExclusionRoute(const IPAddress&) override { return true; }
  bool deleteExclusionRoute(const IPAddress& prefix) override {
    const QString route = prefix.toString();
    deletedExclusionRoutes.append(route);
    if (route == failedRoute && failedRouteAttempts++ == 0) return false;
    return true;
  }
  bool excludeLocalNetworks(const QList<IPAddress>&) override { return true; }

  const QString failedRoute = QStringLiteral("10.31.0.1/32");
  int failedRouteAttempts = 0;
  int deleteInterfaceCalls = 0;
  int deletePeerCalls = 0;
  bool monitorActive = true;
  QStringList deletedAllowedRoutes;
  QStringList deletedExclusionRoutes;
};

class DeactivateDaemon final : public Daemon {
 public:
  DeactivateDaemon() : Daemon(nullptr) {
    InterfaceConfig config;
    config.m_hopType = InterfaceConfig::SingleHop;
    config.m_allowedIPAddressRanges = {IPAddress(QStringLiteral("0.0.0.0/0"))};
    config.m_excludedAddresses = {backend.failedRoute,
                                  QStringLiteral("10.32.0.1")};
    m_connections.insert(InterfaceConfig::SingleHop, ConnectionState(config));
    for (const auto& route : config.m_excludedAddresses) {
      m_excludedAddrSet.insert(IPAddress(route), 1);
    }
  }

  WireguardUtils* wgutils() const override {
    return const_cast<DeactivateBackend*>(&backend);
  }
  DnsUtils* dnsutils() override { return &dns; }

  bool hasExclusion(const QString& route) const {
    return m_excludedAddrSet.contains(IPAddress(route));
  }
  int exclusionReferences(const QString& route) const {
    return m_excludedAddrSet.value(IPAddress(route));
  }
  int connectionCount() const { return m_connections.size(); }

  DeactivateBackend backend;
  InertDns dns;
};

class DaemonDeactivateCleanupTests final : public QObject {
  Q_OBJECT

 private slots:
  void failedExclusionCleanupRetainsOnlyFailedOwnershipUntilRetry() {
    DeactivateDaemon daemon;

    QVERIFY(!daemon.deactivate(false));

    QCOMPARE(daemon.backend.deletedAllowedRoutes,
             QStringList({QStringLiteral("0.0.0.0/0")}));
    QCOMPARE(daemon.backend.deletedExclusionRoutes.size(), 2);
    QVERIFY(daemon.backend.deletedExclusionRoutes.contains(
        QStringLiteral("10.31.0.1/32")));
    QVERIFY(daemon.backend.deletedExclusionRoutes.contains(
        QStringLiteral("10.32.0.1/32")));
    QCOMPARE(daemon.exclusionReferences(QStringLiteral("10.31.0.1")), 1);
    QVERIFY(!daemon.hasExclusion(QStringLiteral("10.32.0.1")));
    QCOMPARE(daemon.connectionCount(), 1);
    QCOMPARE(daemon.backend.deleteInterfaceCalls, 0);
    QVERIFY(daemon.backend.monitorActive);

    QVERIFY(daemon.deactivate(false));

    QCOMPARE(daemon.backend.deletedExclusionRoutes.size(), 3);
    QCOMPARE(daemon.backend.deletedExclusionRoutes.count(
                 QStringLiteral("10.31.0.1/32")), 2);
    QCOMPARE(daemon.backend.deletedExclusionRoutes.count(
                 QStringLiteral("10.32.0.1/32")), 1);
    QVERIFY(!daemon.hasExclusion(QStringLiteral("10.31.0.1")));
    QCOMPARE(daemon.backend.deleteInterfaceCalls, 1);
    QVERIFY(!daemon.backend.monitorActive);
    QCOMPARE(daemon.connectionCount(), 0);
    QCOMPARE(daemon.backend.deletePeerCalls, 2);
    QCOMPARE(daemon.dns.restoreCalls, 2);
  }
};

QTEST_GUILESS_MAIN(DaemonDeactivateCleanupTests)
#include "test_daemon_deactivate_cleanup.moc"
