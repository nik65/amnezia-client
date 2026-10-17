#include <QtTest>
#include <QElapsedTimer>
#include <QJsonObject>
#include <QThread>
#include <QTimer>
#include <QVariantMap>
#include "core/utils/managedRoutePolicy.h"
#include "core/utils/managedDnsConvergence.h"
#include "core/utils/managedRouteMismatchDiagnostic.h"
#include "core/utils/managedRouteReconcileDiagnostic.h"
#include "core/utils/routeModes.h"

using namespace amnezia;
namespace Vpn { enum class ConnectionState { Connected, Reconnecting }; }
namespace configKey { const QString dns1 = "dns1", dns2 = "dns2"; }
struct Logger {
    enum class ConfigurationEvent { Applied, Deferred, Rejected };
    static void configurationDiagnostic(ConfigurationEvent, int, int, qint64, bool) {}
};
namespace ContainerUtils { int defaultProtocol(int) { return 0; } }
constexpr qint64 managedRouteReconnectMinimumIntervalMs = 7200000;
QString digest(char value) { return QStringLiteral("sha256:") + QString(64, value); }

// Inert dependencies surround the exact production methods included below.
// No live protocol, installer, service, route, DNS or firewall is invoked.
class VpnConnection : public QObject {
public:
    enum class ManagedRouteUpdateResult { Updated, ReconnectRequired, ReconnectDeferred, RuntimeUncertain };
    QJsonObject m_vpnConfiguration;
    QString m_serverId = "server-a";
    quint64 m_connectionEpoch = 1;
    quint64 m_latestManagedRouteReconcileGeneration = 0;
    quint64 m_latestPreparedManagedRouteSnapshotGeneration = 0;
    bool m_hasAuthoritativeManagedRouteBase = true;
    bool m_managedRouteTransitionPending = false;
    RouteMode m_authoritativeManagedRouteMode = RouteMode::VpnAllExceptSites;
    QStringList m_authoritativeManagedRoutes { "10.31.0.1" };
    quint64 m_authoritativeManagedRouteBaseRevision = 1;
    quint64 m_authoritativeManagedRouteConnectionEpoch = 1;
    QString m_authoritativeManagedRouteServerId = "server-a";
    QString m_authoritativeManagedRoutePolicyRevision = "1";
    QString m_authoritativeManagedRoutePolicyContentHash = digest('a');
    QVariantMap m_authoritativeManagedRouteLocalSites;
    QStringList m_authoritativeManagedRouteProtectedHosts;
    QString m_preparedManagedRouteServerId;
    RouteMode m_preparedManagedRouteMode = RouteMode::VpnAllSites;
    QStringList m_preparedManagedRoutes;
    QString m_preparedManagedRoutePolicyRevision, m_preparedManagedRoutePolicyContentHash;
    QVariantMap m_preparedLocalSites;
    bool m_hasPreparedManagedRouteSnapshot = false;
    bool m_startupRouteTeardownConfirmed = true;
    int m_container = 0;
    Vpn::ConnectionState m_connectionState = Vpn::ConnectionState::Connected;
    QTimer m_managedRouteReconnectCooldownTimer;
    QElapsedTimer m_managedRouteReconnectClock;
    managedDnsConvergence::ReconnectGate m_managedRouteReconnectGate;
    bool m_managedRouteReconnectAwaitingBase = false;
    QStringList protectedHosts;
    RouteMode actualMode = RouteMode::VpnAllExceptSites;
    ManagedRouteUpdateResult nextMutationResult = ManagedRouteUpdateResult::ReconnectRequired;
    int mutations = 0, restarts = 0;
    QStringList oldMutationRoutes;
    struct Receipt { bool accepted = false, updated = false, scheduled = false; QStringList routes; } receipt;
    VpnConnection() {
        m_managedRouteReconnectClock.start();
        m_managedRouteReconnectGate.beginSession(m_serverId);
    }
    QStringList serverRoutingRulesSyncHosts() const { return protectedHosts; }
    RouteMode appliedSiteRouteMode() const { return actualMode; }
    int m_pendingClientSplitRouteLookups = 0;
    // Production normalization and its route/network helpers are extracted below.
    QStringList normalizedManagedRoutesForRuntime(RouteMode, const QStringList&,
                const QVariantMap&, const QStringList&, bool*) const;
    ManagedRouteUpdateResult updateManagedSplitTunnelRoutes(RouteMode, const QStringList& oldRoutes,
                const QStringList&, const QVariantMap&) {
        ++mutations; oldMutationRoutes = oldRoutes; return nextMutationResult;
    }
    struct ManagedRouteRuntimeSnapshot {
        bool confirmed; RouteMode mode; QStringList installedRoutes;
        quint64 revision; QString policyRevision, policyContentHash;
    };
    ManagedRouteRuntimeSnapshot managedRouteRuntimeSnapshot() const {
        return {m_hasAuthoritativeManagedRouteBase, m_authoritativeManagedRouteMode,
                m_authoritativeManagedRoutes, m_authoritativeManagedRouteBaseRevision,
                m_authoritativeManagedRoutePolicyRevision, m_authoritativeManagedRoutePolicyContentHash};
    }
    void managedSplitTunnelRoutesReconciled(quint64, quint64, const QString&, bool accepted,
                bool updated, bool scheduled, int, const QStringList& routes, quint64,
                const QString&, const QString&) { receipt = {accepted, updated, scheduled, routes}; }
    void managedSplitTunnelRouteBaseReady(quint64, const QString&, int, const QStringList&,
                quint64, const QString&, const QString&, bool) {}
    void recordReconnectFloor() { m_managedRouteReconnectGate.recordReconnect(m_serverId, m_managedRouteReconnectClock.elapsed()); }
    void reconnectToVpn() { ++restarts; }
    void invalidateAuthoritativeManagedRouteBase();
    void publishManagedRouteBase(RouteMode, const QStringList&, const QVariantMap&, const QString&, const QString&, bool);
    void prepareManagedRouteConnectionSnapshot(quint64, const QString&, int, const QStringList&, const QString&, const QString&, const QVariantMap&);
    void scheduleManagedRouteReconnect(quint64, const QString&, const QString&);
    void flushManagedRouteReconnect();
    bool latestPreparedManagedRouteSnapshotIsApplied() const;
    void reconcileManagedSplitTunnelRoutes(quint64, quint64, const QString&, quint64, const QString&,
                const QString&, int, const QStringList&, const QStringList&, const QString&, const QString&, const QVariantMap&);
    void reconcile(const QStringList& desired, const QVariantMap& local = {}, quint64 revision = 1,
                   const QStringList& old = {"10.31.0.1"}) {
        reconcileManagedSplitTunnelRoutes(++m_latestPreparedManagedRouteSnapshotGeneration,
                1, "server-a", revision, "1", digest('a'), static_cast<int>(actualMode),
                old, desired, "2", digest('b'), local);
    }
};
#include "production_methods.inc"

class WorkerRecoveryTests : public QObject {
    Q_OBJECT
private slots:
    void equal1266RuleReceiptDoesNotMutateOrRestart() {
        VpnConnection worker;
        QStringList routes;
        for (int index = 0; index < 1266; ++index) {
            routes.append(QStringLiteral("10.%1.%2.%3")
                    .arg(32 + index / 65536).arg((index / 256) % 256).arg(index % 256));
        }
        bool valid = false;
        routes = managedRoutePolicy::validatedManagedRoutes(routes, &valid);
        QVERIFY(valid);
        QCOMPARE(routes.size(), 1266);
        // Production runtime normalization sorts the installed receipt; policy
        // validation preserves input order. Match that receipt premise here.
        routes.sort();
        worker.m_authoritativeManagedRoutes = routes;
        // Execute production reconciliation and normalization. Full native
        // VpnConnection startup and IPC mutation are not tested here.
        worker.reconcile(routes, {}, 999, routes);
        QVERIFY(worker.receipt.accepted && worker.receipt.updated && !worker.receipt.scheduled);
        QCOMPARE(worker.receipt.routes, routes);
        QCOMPARE(worker.mutations, 0);
        QCOMPARE(worker.restarts, 0);
        QVERIFY(!worker.m_managedRouteReconnectGate.pending());
    }
    void metadataOrStaleReceiptDoesNotRestart() {
        VpnConnection worker;
        worker.reconcile({"10.31.0.1"}, {}, 999);
        QVERIFY(worker.receipt.accepted && worker.receipt.updated);
        QCOMPARE(worker.mutations, 0);
        QCOMPARE(worker.restarts, 0);
        QCOMPARE(worker.m_authoritativeManagedRoutePolicyRevision, QString("2"));
    }
    void installedReceiptIsNotRenormalizedUnderNewLocalOwnership() {
        VpnConnection worker;
        worker.reconcile({"10.31.0.1", "10.31.0.2"}, {{"local.test", "10.31.0.1"}});
        QVERIFY(worker.receipt.scheduled && !worker.receipt.updated);
        QVERIFY(worker.m_hasAuthoritativeManagedRouteBase);
        QCOMPARE(worker.receipt.routes, QStringList({"10.31.0.1"}));
        QCOMPARE(worker.mutations, 0); // ownership transition still requires rebuild
    }
    void equalRoutesCannotHideChangedOwnershipOrProtectedHosts() {
        VpnConnection localChanged;
        localChanged.reconcile({"10.31.0.1"}, {{"new-local.test", "10.32.0.1"}});
        QVERIFY(!localChanged.receipt.updated);
        VpnConnection protectedChanged;
        protectedChanged.protectedHosts = {"10.32.0.2"};
        protectedChanged.reconcile({"10.31.0.1"});
        QVERIFY(!protectedChanged.receipt.updated);
    }
    void nonmutatingRefusalRetainsBaseThenRevertedDesiredCancels() {
        VpnConnection worker;
        worker.reconcile({"10.31.0.1", "10.31.0.2"});
        QVERIFY(worker.receipt.scheduled);
        QVERIFY(worker.m_hasAuthoritativeManagedRouteBase);
        QVERIFY(worker.m_managedRouteReconnectGate.pending());
        worker.prepareManagedRouteConnectionSnapshot(2, "server-a", static_cast<int>(worker.actualMode),
                {"10.31.0.1"}, "3", digest('c'), {});
        worker.flushManagedRouteReconnect();
        QCOMPARE(worker.restarts, 0);
        QVERIFY(!worker.m_managedRouteReconnectGate.pending());
        QVERIFY(!worker.m_managedRouteTransitionPending);
        QCOMPARE(worker.m_authoritativeManagedRoutePolicyRevision, QString("3"));
    }
    void partialMutationCannotCancelRebuild() {
        VpnConnection worker;
        worker.nextMutationResult = VpnConnection::ManagedRouteUpdateResult::RuntimeUncertain;
        worker.reconcile({"10.31.0.1", "10.31.0.2"});
        QVERIFY(!worker.m_hasAuthoritativeManagedRouteBase);
        QCOMPARE(worker.restarts, 1);
        worker.prepareManagedRouteConnectionSnapshot(2, "server-a", static_cast<int>(worker.actualMode),
                {"10.31.0.1"}, "3", digest('c'), {});
        QVERIFY(!worker.latestPreparedManagedRouteSnapshotIsApplied());
        worker.flushManagedRouteReconnect();
        QCOMPARE(worker.restarts, 1);
    }
    void uncertainMutationIgnoresRoutineRefreshCooldown() {
        VpnConnection worker;
        worker.recordReconnectFloor();
        worker.nextMutationResult = VpnConnection::ManagedRouteUpdateResult::RuntimeUncertain;
        worker.reconcile({"10.31.0.1", "10.31.0.2"});
        QCOMPARE(worker.restarts, 1);
        QVERIFY(!worker.m_hasAuthoritativeManagedRouteBase);
        QVERIFY(!worker.m_managedRouteReconnectGate.pending());
    }
    void genuineDeltaUsesExactOldReceiptAndStillApplies() {
        VpnConnection worker;
        worker.nextMutationResult = VpnConnection::ManagedRouteUpdateResult::Updated;
        worker.reconcile({"10.31.0.1", "10.31.0.2"});
        QVERIFY(worker.receipt.updated);
        QCOMPARE(worker.oldMutationRoutes, QStringList({"10.31.0.1"}));
        QCOMPARE(worker.receipt.routes, QStringList({"10.31.0.1", "10.31.0.2"}));
    }
    void epochServerAndModePreventCancellation() {
        for (int changed = 0; changed < 4; ++changed) {
            VpnConnection worker;
            worker.prepareManagedRouteConnectionSnapshot(1, "server-a", static_cast<int>(worker.actualMode),
                    {"10.31.0.1"}, "2", digest('b'), {});
            if (changed == 0) worker.m_connectionEpoch = 2;
            if (changed == 1) worker.m_serverId = "server-b";
            if (changed == 2) worker.actualMode = RouteMode::VpnAllSites;
            if (changed == 3) worker.m_hasAuthoritativeManagedRouteBase = false;
            QVERIFY(!worker.latestPreparedManagedRouteSnapshotIsApplied());
        }
    }
    void olderInFlightAckCannotOverrideNewerPreparedSnapshotOrCancelItsRebuild() {
        VpnConnection worker;
        worker.recordReconnectFloor();
        worker.scheduleManagedRouteReconnect(1, "server-a", "new desired policy");
        worker.prepareManagedRouteConnectionSnapshot(5, "server-a", static_cast<int>(worker.actualMode),
                {"10.31.0.1", "10.31.0.2"}, "3", digest('c'), {});
        worker.reconcileManagedSplitTunnelRoutes(4, 1, "server-a", 1, "1", digest('a'),
                static_cast<int>(worker.actualMode), {"10.31.0.1"}, {"10.31.0.1"}, "2", digest('b'), {});
        QVERIFY(worker.receipt.accepted && worker.receipt.updated);
        QCOMPARE(worker.m_authoritativeManagedRoutePolicyRevision, QString("2"));
        QCOMPARE(worker.m_preparedManagedRoutePolicyRevision, QString("3"));
        QCOMPARE(worker.m_preparedManagedRoutes, QStringList({"10.31.0.1", "10.31.0.2"}));
        QVERIFY(worker.m_managedRouteReconnectGate.pending());
    }
};
QTEST_GUILESS_MAIN(WorkerRecoveryTests)
#include "test_worker.moc"
