#include <QtTest>
#include "daemon/exclusionpolicytransaction.h"

using namespace amnezia::exclusionPolicy;

class ExclusionTransactionTests : public QObject {
    Q_OBJECT
    struct Fixture {
        QStringList before {"local", "old1", "old2"}, after {"local", "new1", "new2"};
        QSet<QString> routes {"local", "old1", "old2"}, permits = routes;
        QStringList calls;
        int operation = 0, failAt = -1;
        bool failAfter = false, rollbackFails = false, fenced = false, leak = false;
        bool mutate(const QString& kind, const QString& route, const QStringList& policy = {}) {
            const int index = ++operation;
            calls.append(kind + ":" + route);
            const bool failing = index == failAt || (rollbackFails && index > failAt);
            if (failing && !failAfter) return false;
            if (kind == "fw") {
                permits = QSet<QString>(policy.begin(), policy.end());
                fenced = true;
            } else if (kind == "add") routes.insert(route);
            else routes.remove(route);
            // A permit must always have its physical route already installed.
            if (fenced && !(permits - routes).isEmpty()) leak = true;
            return !failing;
        }
        Result run() {
            return replace(before, after,
                [&](const QStringList& policy) { return mutate("fw", "", policy); },
                [&](const QString& route) { return mutate("add", route); },
                [&](const QString& route) { return mutate("del", route); });
        }
        Result runRoutes() {
            return replaceRoutes(before, after,
                [&](const QString& route) { return mutate("add", route); },
                [&](const QString& route) { return mutate("del", route); });
        }
    };
private slots:
    void successKeepsLocalBypassAndOrdersCommits() {
        Fixture f;
        QCOMPARE(f.run(), Updated);
        QCOMPARE(f.routes, QSet<QString>(f.after.begin(), f.after.end()));
        QCOMPARE(f.permits, f.routes);
        QVERIFY(!f.leak);
        QCOMPARE(f.calls, QStringList({"fw:", "del:old1", "del:old2", "add:new1", "add:new2", "fw:"}));
    }
    void failuresRollbackWithoutOpeningUnrestoredRoutes_data() {
        QTest::addColumn<int>("failAt");
        QTest::addColumn<bool>("failAfter");
        for (int step = 2; step <= 6; ++step) {
            for (bool partial : {false, true}) {
                QTest::newRow(qPrintable(QString("step%1-partial%2").arg(step).arg(partial))) << step << partial;
            }
        }
    }
    void failuresRollbackWithoutOpeningUnrestoredRoutes() {
        QFETCH(int, failAt); QFETCH(bool, failAfter);
        Fixture f; f.failAt = failAt; f.failAfter = failAfter;
        QCOMPARE(f.run(), RolledBack);
        QCOMPARE(f.routes, QSet<QString>(f.before.begin(), f.before.end()));
        QCOMPARE(f.permits, f.routes);
        QVERIFY(!f.leak);
    }
    void uncertainFenceDoesNotMutateRoutes() {
        Fixture f; f.failAt = 1;
        QCOMPARE(f.run(), Uncertain);
        QCOMPARE(f.calls.size(), 1);
        QCOMPARE(f.routes, QSet<QString>(f.before.begin(), f.before.end()));
    }
    void failedRollbackKeepsRestrictiveFence() {
        Fixture f; f.failAt = 4; f.rollbackFails = true;
        QCOMPARE(f.run(), Uncertain);
        QCOMPARE(f.permits, QSet<QString>({"local"}));
        QVERIFY(!f.leak);
    }
    void equalPoliciesDoNotTouchBackend() {
        Fixture f; f.after = f.before;
        QCOMPARE(f.run(), Updated);
        QVERIFY(f.calls.isEmpty());
    }
    void routeOnlySuccessAddsBeforeRemoving() {
        Fixture f;
        QCOMPARE(f.runRoutes(), Updated);
        QCOMPARE(f.routes, QSet<QString>(f.after.begin(), f.after.end()));
        QCOMPARE(f.calls, QStringList({"add:new1", "add:new2", "del:old1", "del:old2"}));
    }
    void routeOnlyFailuresRollbackEveryAttemptedOperation_data() {
        QTest::addColumn<int>("failAt");
        QTest::addColumn<bool>("failAfter");
        for (int step = 1; step <= 4; ++step) {
            for (bool partial : {false, true}) {
                QTest::newRow(qPrintable(QString("route-step%1-partial%2").arg(step).arg(partial)))
                    << step << partial;
            }
        }
    }
    void routeOnlyFailuresRollbackEveryAttemptedOperation() {
        QFETCH(int, failAt); QFETCH(bool, failAfter);
        Fixture f; f.failAt = failAt; f.failAfter = failAfter;
        QCOMPARE(f.runRoutes(), RolledBack);
        QCOMPARE(f.routes, QSet<QString>(f.before.begin(), f.before.end()));
    }
    void routeOnlyRollbackRestoresOldBeforeRemovingNew() {
        Fixture f; f.failAt = 3;
        QCOMPARE(f.runRoutes(), RolledBack);
        QCOMPARE(f.calls, QStringList({
            "add:new1", "add:new2", "del:old1", "add:old1", "del:new1", "del:new2"}));
        QCOMPARE(f.routes, QSet<QString>(f.before.begin(), f.before.end()));
    }
    void routeOnlyFailedRollbackIsUncertain() {
        Fixture f; f.failAt = 3; f.rollbackFails = true;
        QCOMPARE(f.runRoutes(), Uncertain);
        QVERIFY(f.calls.size() >= 4);
    }
    void routeOnlyEqualPoliciesDoNotTouchBackend() {
        Fixture f; f.after = f.before;
        QCOMPARE(f.runRoutes(), Updated);
        QVERIFY(f.calls.isEmpty());
    }
};
QTEST_GUILESS_MAIN(ExclusionTransactionTests)
#include "test_exclusion_transaction.moc"
