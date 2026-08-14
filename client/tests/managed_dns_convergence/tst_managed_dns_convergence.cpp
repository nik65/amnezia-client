#include <QtTest/QtTest>

#include "core/utils/managedDnsConvergence.h"

using amnezia::managedDnsConvergence::State;
using amnezia::managedDnsConvergence::ReconnectGate;

class ManagedDnsConvergenceTest final : public QObject
{
    Q_OBJECT

private slots:
    void retriesOnlyFailuresAndKeepsSuccessfulResults();
    void keepsLastKnownGoodUntilFailedDomainSucceeds();
    void supersedingSourceCannotAcceptOldDomains();
    void boundedWavesFinalizeAtMostOnce();
    void retryAfterDelaysButDoesNotSuppressNextCycle();
    void partialCycleRetriesOnlyPersistedFailures();
    void scheduledRefreshChecksEveryDomain();
    void firstReconnectIsImmediateThenTwoHourFloorApplies();
    void reconnectRequestsCoalesceWithoutSlidingTheDeadline();
    void freshLogicalSessionRestoresOneImmediateReconnect();
    void externalReconnectPreservesPendingAtTheSameDeadline();
    void partialCyclesStillRunADailyFullSweep();
};

void ManagedDnsConvergenceTest::retriesOnlyFailuresAndKeepsSuccessfulResults()
{
    State state;
    state.begin(QStringLiteral("server-a"), QStringLiteral("source-1"),
                { QStringLiteral("a.test"), QStringLiteral("b.test"), QStringLiteral("c.test") },
                {});

    QCOMPARE(state.takePendingWave(),
             QStringList({ QStringLiteral("a.test"), QStringLiteral("b.test"), QStringLiteral("c.test") }));
    QVERIFY(state.recordSuccess(QStringLiteral("a.test"), QStringLiteral("192.0.2.1")));
    state.recordFailure(QStringLiteral("b.test"));
    QVERIFY(state.recordSuccess(QStringLiteral("c.test"), QStringLiteral("192.0.2.3")));

    QCOMPARE(state.pending(), QStringList({ QStringLiteral("b.test") }));
    QCOMPARE(state.cache().value(QStringLiteral("a.test")).toString(), QStringLiteral("192.0.2.1"));
    QCOMPARE(state.cache().value(QStringLiteral("c.test")).toString(), QStringLiteral("192.0.2.3"));
    QVERIFY(!state.complete());

    QCOMPARE(state.takePendingWave(), QStringList({ QStringLiteral("b.test") }));
    QVERIFY(state.recordSuccess(QStringLiteral("b.test"), QStringLiteral("192.0.2.2")));
    QVERIFY(state.complete());
    QCOMPARE(state.cache().size(), 3);
}

void ManagedDnsConvergenceTest::keepsLastKnownGoodUntilFailedDomainSucceeds()
{
    const QJsonObject baseline {
        { QStringLiteral("stale.test"), QStringLiteral("198.51.100.10") },
    };
    State state;
    state.begin(QStringLiteral("server-a"), QStringLiteral("source-1"),
                { QStringLiteral("stale.test") }, baseline);

    state.takePendingWave();
    state.recordFailure(QStringLiteral("stale.test"));
    QCOMPARE(state.cache().value(QStringLiteral("stale.test")).toString(),
             QStringLiteral("198.51.100.10"));

    state.takePendingWave();
    QVERIFY(state.recordSuccess(QStringLiteral("stale.test"), QStringLiteral("198.51.100.11")));
    QCOMPARE(state.cache().value(QStringLiteral("stale.test")).toString(),
             QStringLiteral("198.51.100.11"));
}

void ManagedDnsConvergenceTest::supersedingSourceCannotAcceptOldDomains()
{
    State state;
    state.begin(QStringLiteral("server-a"), QStringLiteral("source-1"),
                { QStringLiteral("removed.test") }, {});
    state.takePendingWave();

    state.begin(QStringLiteral("server-a"), QStringLiteral("source-2"),
                { QStringLiteral("current.test") }, {});
    QVERIFY(!state.matches(QStringLiteral("server-a"), QStringLiteral("source-1")));
    QVERIFY(!state.recordSuccess(QStringLiteral("removed.test"), QStringLiteral("203.0.113.1")));
    QVERIFY(!state.cache().contains(QStringLiteral("removed.test")));
    QCOMPARE(state.takePendingWave(), QStringList({ QStringLiteral("current.test") }));
}

void ManagedDnsConvergenceTest::boundedWavesFinalizeAtMostOnce()
{
    State state;
    state.begin(QStringLiteral("server-a"), QStringLiteral("source-1"),
                { QStringLiteral("persistent-failure.test") }, {});

    for (int completedWave = 1; completedWave <= 6; ++completedWave) {
        QCOMPARE(state.takePendingWave(),
                 QStringList({ QStringLiteral("persistent-failure.test") }));
        state.recordFailure(QStringLiteral("persistent-failure.test"));
        state.finishWave();
        QCOMPARE(state.completedWaves(), completedWave);
        QCOMPARE(state.shouldRetry(5), completedWave <= 5);
    }

    QVERIFY(state.tryFinalize());
    QVERIFY(!state.tryFinalize());
    QVERIFY(!state.shouldRetry(5));
}

void ManagedDnsConvergenceTest::retryAfterDelaysButDoesNotSuppressNextCycle()
{
    const QDateTime now = QDateTime::fromString(
            QStringLiteral("2026-08-13T12:00:00Z"), Qt::ISODate);
    QCOMPARE(amnezia::managedDnsConvergence::initialDelayMs(
                     QStringLiteral("2026-08-13T12:05:00Z"), now, 2000),
             300000);
    QCOMPARE(amnezia::managedDnsConvergence::initialDelayMs(
                     QStringLiteral("2026-08-13T11:59:59Z"), now, 2000),
             2000);
    QCOMPARE(amnezia::managedDnsConvergence::initialDelayMs(QString(), now, 2000),
             2000);
}

void ManagedDnsConvergenceTest::partialCycleRetriesOnlyPersistedFailures()
{
    const QStringList domains {
        QStringLiteral("fresh.test"),
        QStringLiteral("lkg.test"),
        QStringLiteral("empty.test"),
    };
    const QJsonObject baseline {
        { QStringLiteral("fresh.test"), QStringLiteral("192.0.2.10") },
        { QStringLiteral("lkg.test"), QStringLiteral("198.51.100.20") },
        { QStringLiteral("empty.test"), QString() },
    };
    const QStringList pending = amnezia::managedDnsConvergence::pendingDomainsForCycle(
            domains, baseline,
            { QStringLiteral("lkg.test"), QStringLiteral("removed.test") }, false);

    QCOMPARE(pending,
             QStringList({ QStringLiteral("lkg.test"), QStringLiteral("empty.test") }));

    State state;
    state.begin(QStringLiteral("server-a"), QStringLiteral("source-1"),
                domains, baseline, pending);
    QCOMPARE(state.takePendingWave(), pending);
    QCOMPARE(state.cache().value(QStringLiteral("fresh.test")).toString(),
             QStringLiteral("192.0.2.10"));
    QCOMPARE(state.cache().value(QStringLiteral("lkg.test")).toString(),
             QStringLiteral("198.51.100.20"));
}

void ManagedDnsConvergenceTest::scheduledRefreshChecksEveryDomain()
{
    const QStringList domains {
        QStringLiteral("a.test"), QStringLiteral("b.test"), QStringLiteral("c.test")
    };
    const QJsonObject baseline {
        { QStringLiteral("a.test"), QStringLiteral("192.0.2.1") },
        { QStringLiteral("b.test"), QStringLiteral("192.0.2.2") },
        { QStringLiteral("c.test"), QStringLiteral("192.0.2.3") },
    };

    QCOMPARE(amnezia::managedDnsConvergence::pendingDomainsForCycle(
                     domains, baseline, { QStringLiteral("b.test") }, true),
             domains);
}

void ManagedDnsConvergenceTest::firstReconnectIsImmediateThenTwoHourFloorApplies()
{
    constexpr qint64 minimumIntervalMs = 2LL * 60 * 60 * 1000;
    ReconnectGate gate;
    gate.beginSession(QStringLiteral("server-a"));

    const auto first = gate.request(QStringLiteral("server-a"), 0, minimumIntervalMs);
    QVERIFY(first.accepted);
    QVERIFY(first.newlyPending);
    QCOMPARE(first.delayMs, 0);
    QVERIFY(gate.takeDue(QStringLiteral("server-a"), 0, minimumIntervalMs));
    gate.recordReconnect(QStringLiteral("server-a"), 0);

    const auto second = gate.request(QStringLiteral("server-a"), 1, minimumIntervalMs);
    QVERIFY(second.accepted);
    QVERIFY(second.newlyPending);
    QCOMPARE(second.delayMs, minimumIntervalMs - 1);
    QVERIFY(!gate.takeDue(QStringLiteral("server-a"), minimumIntervalMs - 1,
                         minimumIntervalMs));
    QVERIFY(gate.takeDue(QStringLiteral("server-a"), minimumIntervalMs,
                        minimumIntervalMs));
}

void ManagedDnsConvergenceTest::reconnectRequestsCoalesceWithoutSlidingTheDeadline()
{
    constexpr qint64 minimumIntervalMs = 2LL * 60 * 60 * 1000;
    ReconnectGate gate;
    gate.beginSession(QStringLiteral("server-a"));
    gate.request(QStringLiteral("server-a"), 0, minimumIntervalMs);
    QVERIFY(gate.takeDue(QStringLiteral("server-a"), 0, minimumIntervalMs));
    gate.recordReconnect(QStringLiteral("server-a"), 0);

    const auto firstDeferred = gate.request(
            QStringLiteral("server-a"), 1000, minimumIntervalMs);
    QVERIFY(firstDeferred.newlyPending);
    QCOMPARE(firstDeferred.delayMs, minimumIntervalMs - 1000);

    const auto coalesced = gate.request(
            QStringLiteral("server-a"), minimumIntervalMs / 2, minimumIntervalMs);
    QVERIFY(coalesced.accepted);
    QVERIFY(!coalesced.newlyPending);
    QCOMPARE(coalesced.delayMs, minimumIntervalMs / 2);
    QVERIFY(gate.takeDue(QStringLiteral("server-a"), minimumIntervalMs,
                        minimumIntervalMs));
}

void ManagedDnsConvergenceTest::freshLogicalSessionRestoresOneImmediateReconnect()
{
    constexpr qint64 minimumIntervalMs = 2LL * 60 * 60 * 1000;
    ReconnectGate gate;
    gate.beginSession(QStringLiteral("server-a"));
    gate.request(QStringLiteral("server-a"), 0, minimumIntervalMs);
    QVERIFY(gate.takeDue(QStringLiteral("server-a"), 0, minimumIntervalMs));
    gate.recordReconnect(QStringLiteral("server-a"), 0);

    gate.beginSession(QStringLiteral("server-b"));
    const auto fresh = gate.request(QStringLiteral("server-b"), 1000, minimumIntervalMs);
    QVERIFY(fresh.accepted);
    QVERIFY(fresh.newlyPending);
    QCOMPARE(fresh.delayMs, 0);
    QVERIFY(!gate.request(QStringLiteral("server-a"), 1000, minimumIntervalMs).accepted);
}

void ManagedDnsConvergenceTest::externalReconnectPreservesPendingAtTheSameDeadline()
{
    constexpr qint64 minimumIntervalMs = 2LL * 60 * 60 * 1000;
    ReconnectGate gate;
    gate.beginSession(QStringLiteral("server-a"));
    QVERIFY(gate.request(QStringLiteral("server-a"), 0, minimumIntervalMs).newlyPending);

    gate.recordReconnect(QStringLiteral("server-a"), 1000);
    QVERIFY(gate.pending());
    const auto coalesced = gate.request(
            QStringLiteral("server-a"), 2000, minimumIntervalMs);
    QVERIFY(coalesced.accepted);
    QVERIFY(!coalesced.newlyPending);
    QCOMPARE(coalesced.delayMs, minimumIntervalMs - 1000);
}

void ManagedDnsConvergenceTest::partialCyclesStillRunADailyFullSweep()
{
    const QDateTime now = QDateTime::fromString(
            QStringLiteral("2026-08-14T20:00:00Z"), Qt::ISODate);
    constexpr int refreshIntervalSeconds = 24 * 60 * 60;

    QVERIFY(amnezia::managedDnsConvergence::fullSweepDue(
            QString(), now, refreshIntervalSeconds));
    QVERIFY(!amnezia::managedDnsConvergence::fullSweepDue(
            now.addSecs(-60 * 60).toString(Qt::ISODate),
            now, refreshIntervalSeconds));
    QVERIFY(amnezia::managedDnsConvergence::fullSweepDue(
            now.addSecs(-refreshIntervalSeconds).toString(Qt::ISODate),
            now, refreshIntervalSeconds));
    QVERIFY(amnezia::managedDnsConvergence::fullSweepDue(
            now.addSecs(11 * 60).toString(Qt::ISODate),
            now, refreshIntervalSeconds));

    const QString originalFullSweep =
            now.addSecs(-refreshIntervalSeconds).toString(Qt::ISODate);
    const QString latePartialSuccess =
            now.addSecs(-60 * 60).toString(Qt::ISODate);
    QVERIFY(amnezia::managedDnsConvergence::completeCacheRefreshDue(
            originalFullSweep, latePartialSuccess,
            now, refreshIntervalSeconds));
}

QTEST_GUILESS_MAIN(ManagedDnsConvergenceTest)

#include "tst_managed_dns_convergence.moc"
