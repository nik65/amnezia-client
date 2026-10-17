#include <QtTest>
#include "daemon/daemon.h"

using namespace amnezia::exclusionPolicy;

class InertWireguard : public WireguardUtils {
public:
    InertWireguard() : WireguardUtils(nullptr) {}
    int calls = 0;
    Result next = Updated;
    InterfaceConfig observed;
    Result replaceExclusionPolicy(const InterfaceConfig&, const InterfaceConfig& after) override {
        ++calls; observed = after; return next;
    }
    bool interfaceExists() override { return true; }
    bool addInterface(const InterfaceConfig&) override { qFatal("unexpected activation"); return false; }
    bool deleteInterface() override { qFatal("unexpected teardown"); return false; }
    bool updatePeer(const InterfaceConfig&) override { qFatal("unexpected peer mutation"); return false; }
    bool deletePeer(const InterfaceConfig&) override { qFatal("unexpected peer removal"); return false; }
    QList<PeerStatus> getPeerStatus() override { return {}; }
    bool updateRoutePrefix(const IPAddress&) override { qFatal("unexpected route mutation"); return false; }
    bool deleteRoutePrefix(const IPAddress&) override { qFatal("unexpected route removal"); return false; }
    bool addExclusionRoute(const IPAddress&) override { qFatal("unexpected individual exclusion"); return false; }
    bool deleteExclusionRoute(const IPAddress&) override { qFatal("unexpected individual removal"); return false; }
    bool excludeLocalNetworks(const QList<IPAddress>&) override { qFatal("unexpected LAN mutation"); return false; }
};

class InertDaemon : public Daemon {
public:
    InertWireguard backend;
    const QString nonce = QString(36, 'n');
    InertDaemon() : Daemon(nullptr) {
        InterfaceConfig config;
        config.m_hopType = InterfaceConfig::SingleHop;
        config.m_serverIpv4AddrIn = "5.0.0.8";
        config.m_primaryDnsServer = "1.1.1.1";
        config.m_killSwitchEnabled = true;
        config.m_allowedIPAddressRanges = {IPAddress("0.0.0.0/0")};
        config.m_managedExcludedAddresses = {"10.31.0.1"};
        config.m_excludedAddresses = {"5.0.0.8", "10.32.0.1", "10.31.0.1"};
        config.m_routeConnectionNonce = nonce;
        config.m_managedExclusionsKnown = true;
        m_connections.insert(InterfaceConfig::SingleHop, ConnectionState(config));
        for (const auto& route : config.m_excludedAddresses) m_excludedAddrSet.insert(IPAddress(route), 1);
    }
    WireguardUtils* wgutils() const override { return const_cast<InertWireguard*>(&backend); }
    InterfaceConfig& config() { return m_connections[InterfaceConfig::SingleHop].m_config; }
    int references(const QString& route) const { return m_excludedAddrSet.value(IPAddress(route)); }
    void shareOldRoute() { m_excludedAddrSet[IPAddress("10.31.0.1")] = 2; }
    int replace() { return replaceManagedExclusions(nonce, {"10.31.0.1"}, {"10.31.0.2"}); }
};

class DaemonExclusionTests : public QObject {
    Q_OBJECT
private slots:
    void successReplacesOnlyOwnedManagedRoutes() {
        InertDaemon d;
        QCOMPARE(d.replace(), int(Updated));
        QCOMPARE(d.backend.calls, 1);
        QCOMPARE(d.config().m_managedExcludedAddresses, QStringList({"10.31.0.2"}));
        QCOMPARE(d.config().m_excludedAddresses, QStringList({"5.0.0.8", "10.32.0.1", "10.31.0.2"}));
        QCOMPARE(d.references("10.31.0.1"), 0);
        QCOMPARE(d.references("10.31.0.2"), 1);
        QCOMPARE(d.references("10.32.0.1"), 1);
    }
    void staleEpochBaseSharedRouteAndProtectedHostsRejectBeforeBackend() {
        for (int test = 0; test < 7; ++test) {
            InertDaemon d;
            int result;
            if (test == 0) result = d.replaceManagedExclusions("wrong", {"10.31.0.1"}, {"10.31.0.2"});
            else if (test == 1) result = d.replaceManagedExclusions(d.nonce, {"10.31.0.3"}, {"10.31.0.2"});
            else if (test == 2) { d.shareOldRoute(); result = d.replace(); }
            else if (test == 3) result = d.replaceManagedExclusions(d.nonce, {"10.31.0.1"}, {"1.1.1.1"});
            else if (test == 4) result = d.replaceManagedExclusions(d.nonce, {"10.31.0.1"}, {"0.0.0.0/0"});
            else if (test == 5) { d.config().m_managedExclusionsKnown = false; result = d.replace(); }
            else result = d.replaceManagedExclusions(d.nonce, {"10.31.0.1"}, {"10.32.0.1"});
            QCOMPARE(result, int(Rejected));
            QCOMPARE(d.backend.calls, 0);
            QCOMPARE(d.config().m_managedExcludedAddresses, QStringList({"10.31.0.1"}));
        }
    }
    void unsupportedOrRollbackRetainsAuthoritativeReceipt() {
        for (auto outcome : {Unsupported, RolledBack}) {
            InertDaemon d; d.backend.next = outcome;
            QCOMPARE(d.replace(), int(outcome));
            QCOMPARE(d.config().m_managedExcludedAddresses, QStringList({"10.31.0.1"}));
            QVERIFY(d.config().m_managedExclusionsKnown);
            QCOMPARE(d.references("10.31.0.2"), 0);
        }
    }
    void killSwitchOffKeepsAuthenticatedManagedReceipt() {
        InertDaemon d;
        d.config().m_killSwitchEnabled = false;
        QCOMPARE(d.replace(), int(Updated));
        QCOMPARE(d.backend.calls, 1);
        QVERIFY(!d.backend.observed.m_killSwitchEnabled);
        QCOMPARE(d.config().m_managedExcludedAddresses, QStringList({"10.31.0.2"}));
        QCOMPARE(d.references("10.31.0.1"), 0);
        QCOMPARE(d.references("10.31.0.2"), 1);
    }
    void uncertainRetainsEveryPossiblyInstalledRouteForCleanup() {
        InertDaemon d; d.backend.next = Uncertain;
        QCOMPARE(d.replace(), int(Uncertain));
        QVERIFY(!d.config().m_managedExclusionsKnown);
        QCOMPARE(d.references("10.31.0.1"), 1);
        QCOMPARE(d.references("10.31.0.2"), 1);
        QCOMPARE(d.replace(), int(Rejected));
        QCOMPARE(d.backend.calls, 1);
    }
};
QTEST_GUILESS_MAIN(DaemonExclusionTests)
#include "test_daemon_exclusions.moc"
