#include <QtTest/QtTest>

#include "core/utils/managedDnsConvergence.h"

using amnezia::managedDnsConvergence::State;

class ManagedDnsConvergenceTest final : public QObject
{
    Q_OBJECT

private slots:
    void retriesOnlyFailuresAndKeepsSuccessfulResults();
    void keepsLastKnownGoodUntilFailedDomainSucceeds();
    void supersedingSourceCannotAcceptOldDomains();
    void boundedWavesFinalizeAtMostOnce();
    void retryAfterDelaysButDoesNotSuppressNextCycle();
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

QTEST_GUILESS_MAIN(ManagedDnsConvergenceTest)

#include "tst_managed_dns_convergence.moc"
