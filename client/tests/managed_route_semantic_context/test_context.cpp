#include "production_context.inc"

class SemanticContextTests : public QObject {
    Q_OBJECT
    static QStringList rules() {
        QStringList routes;
        for (int index = 0; index < 1263; ++index)
            routes.append(QStringLiteral("10.32.%1.%2").arg(index / 256).arg(index % 256));
        routes.sort();
        return routes;
    }
    static QVariantMap before() { return {{"local.fixture", "10.31.0.10, 10.31.0.11"}}; }
    static QVariantMap reordered() { return {{"local.fixture", "10.31.0.11;10.31.0.10 10.31.0.11"}}; }
    static QStringList actualLocalRoutes(const QVariantMap& local) {
        QStringList routes;
        appendSplitTunnelSiteRoutes(routes, local, SplitTunnelRouteSource::Client);
        routes = normalizedSupportedIpv4Routes(splitRoutesKeepingHostsInVpn(routes, {}));
        routes.removeDuplicates(); routes.sort(); return routes;
    }
    static void initialize(VpnConnection& worker) {
        worker.m_authoritativeManagedRoutes = rules();
        worker.m_authoritativeManagedRouteLocalSites = before();
    }
private slots:
    void identical1263RulesRemainNoop() {
        VpnConnection worker; initialize(worker);
        worker.reconcile(rules(), before(), 1, rules());
        QVERIFY(worker.receipt.updated && !worker.receipt.scheduled);
        QCOMPARE(worker.restarts, 0);
    }
    void reorderedDuplicateLocalDnsAnswersMustNotReconnect() {
        VpnConnection worker; initialize(worker);
        QVERIFY(before() != reordered());
        QCOMPARE(actualLocalRoutes(before()), actualLocalRoutes(reordered()));
        bool validBefore = false, validAfter = false;
        const auto installedBefore = worker.normalizedManagedRoutesForRuntime(worker.actualMode, rules(), before(), {}, &validBefore);
        const auto desiredAfter = worker.normalizedManagedRoutesForRuntime(worker.actualMode, rules(), reordered(), {}, &validAfter);
        QVERIFY(validBefore && validAfter);
        QCOMPARE(installedBefore.size(), 1263);
        QCOMPARE(installedBefore, desiredAfter);
        worker.reconcile(rules(), reordered(), 1, rules());
        QVERIFY2(worker.receipt.updated && !worker.receipt.scheduled,
                 "same local DNS ownership and same1263 installed managed routes requested a reconnect");
        QCOMPARE(worker.restarts, 0);
    }
    void latestEquivalentPreparedSnapshotMustCancelDeferredReconnect() {
        VpnConnection worker; initialize(worker);
        worker.recordReconnectFloor();
        worker.scheduleManagedRouteReconnect(1, "server-a", "fixture cooldown");
        QVERIFY(worker.m_managedRouteReconnectGate.pending());
        worker.prepareManagedRouteConnectionSnapshot(1, "server-a", static_cast<int>(worker.actualMode),
            rules(), "1", digest('a'), reordered());
        QVERIFY(worker.latestPreparedManagedRouteSnapshotIsApplied());
        worker.flushManagedRouteReconnect();
        QVERIFY(!worker.m_managedRouteReconnectGate.pending());
        QCOMPARE(worker.restarts, 0);
    }
    void changedLocalOwnershipMustNotBeAcceptedAsNoop() {
        VpnConnection worker; initialize(worker);
        worker.reconcile(rules(), {{"local.fixture", "10.31.0.12"}}, 1, rules());
        QVERIFY(!worker.receipt.updated && worker.receipt.scheduled);
    }
    void changedProtectedHostMustNotBeAcceptedAsNoop() {
        VpnConnection worker; initialize(worker);
        worker.protectedHosts = {"10.31.0.15"};
        worker.reconcile(rules(), before(), 1, rules());
        QVERIFY(!worker.receipt.updated && worker.receipt.scheduled);
    }
    void changedEpochMustNotAcceptOldRuntimeBase() {
        VpnConnection worker; initialize(worker);
        worker.m_authoritativeManagedRouteConnectionEpoch = 2;
        worker.reconcile(rules(), before(), 1, rules());
        QVERIFY(!worker.receipt.updated && worker.receipt.scheduled);
    }
    void changedDomainIdentityMustNotBeAcceptedAsNoop() {
        VpnConnection worker; initialize(worker);
        worker.reconcile(rules(), {{"other.fixture", "10.31.0.10,10.31.0.11"}}, 1, rules());
        QVERIFY(!worker.receipt.updated && worker.receipt.scheduled);
    }
    void pendingLookupMustNotRelaxDifferentRawContext() {
        VpnConnection worker; initialize(worker);
        worker.m_pendingClientSplitRouteLookups = 1;
        worker.reconcile(rules(), reordered(), 1, rules());
        QVERIFY(!worker.receipt.updated && worker.receipt.scheduled);
    }
    void invalidNewDnsTokenMustNotDisappearIntoEquivalentContext() {
        VpnConnection worker; initialize(worker);
        worker.reconcile(rules(), {{"local.fixture", "10.31.0.10,10.31.0.11 invalid"}}, 1, rules());
        QVERIFY(!worker.receipt.updated && worker.receipt.scheduled);
    }
    void malformedOldReceiptMustNotBeAcceptedAsNoop() {
        VpnConnection worker; initialize(worker);
        auto invalid = rules(); invalid.append("0.0.0.0/0");
        worker.reconcile(rules(), reordered(), 1, invalid);
        QVERIFY(!worker.receipt.updated && worker.receipt.scheduled);
    }
    void staleBaseRevisionWithSameRuntimeStillDoesNotMutate() {
        VpnConnection worker; initialize(worker);
        worker.reconcile(rules(), reordered(), 999, rules());
        QVERIFY(worker.receipt.updated && !worker.receipt.scheduled);
    }
    void staleBaseRevisionDoesNotHideDifferentLocalOwnership() {
        VpnConnection worker; initialize(worker);
        worker.reconcile(rules(), {{"local.fixture", "10.31.0.12"}}, 999, rules());
        QVERIFY(!worker.receipt.updated && worker.receipt.scheduled);
    }
    void duplicateOldReceiptMustNotBeAcceptedAsNoop() {
        VpnConnection worker; initialize(worker);
        auto invalid = rules(); invalid.append(invalid.first());
        worker.reconcile(rules(), reordered(), 1, invalid);
        QVERIFY(!worker.receipt.updated && worker.receipt.scheduled);
    }
    void changedAuthoritativeModeMustNotAcceptOldContext() {
        VpnConnection worker; initialize(worker);
        worker.m_authoritativeManagedRouteMode = RouteMode::VpnAllSites;
        worker.reconcile(rules(), reordered(), 1, rules());
        QVERIFY(!worker.receipt.updated && worker.receipt.scheduled);
    }
    void changedLiveServerRejectsOldRequest() {
        VpnConnection worker; initialize(worker);
        worker.m_serverId = "server-b";
        worker.reconcile(rules(), reordered(), 1, rules());
        QVERIFY(!worker.receipt.accepted && !worker.receipt.updated);
    }
};
QTEST_GUILESS_MAIN(SemanticContextTests)
#include "test_context.moc"
