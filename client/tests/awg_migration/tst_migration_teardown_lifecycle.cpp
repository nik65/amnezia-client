#include <QtTest>
#include <QPointer>
#include "core/utils/migrationTeardownContext.h"

class MigrationTeardownLifecycleTests final : public QObject {
    Q_OBJECT
private slots:
    void staleReceiptsCannotExtendActualDeadline()
    {
        int completions = 0;
        bool confirmed = true;
        QSharedPointer<QObject> owner(new QObject);
        QPointer<QObject> retained(owner.data());
        QPointer<MigrationTeardownContext> context = new MigrationTeardownContext(owner,
                "current-session", 10, 11, true, [] { return quint64(11); },
                [&](bool result) { ++completions; confirmed = result; }, this, 20);
        owner.clear();
        QTimer staleReceipts;
        QObject::connect(&staleReceipts, &QTimer::timeout, context, [context] {
            context->observe("previous-session", 10, true);
            context->observe("current-session", 9, true);
        });
        staleReceipts.start(1);
        QTRY_COMPARE(completions, 1);
        QVERIFY(!confirmed);
        QVERIFY(retained.isNull());
        QTRY_VERIFY(context.isNull());
    }

    void malformedAndroidReceiptCannotAuthorizeCompletion_data()
    {
        QTest::addColumn<QJsonObject>("receipt");
        QTest::newRow("missing-confirmation") << QJsonObject{{"connectionNonce", "session"}};
        QTest::newRow("string-confirmation") << QJsonObject{{"connectionNonce", "session"},
                                                                           {"nativeCleanupConfirmed", "true"}};
        QTest::newRow("numeric-confirmation") << QJsonObject{{"connectionNonce", "session"},
                                                                            {"nativeCleanupConfirmed", 1}};
        QTest::newRow("missing-nonce") << QJsonObject{{"nativeCleanupConfirmed", true}};
    }

    void malformedAndroidReceiptCannotAuthorizeCompletion()
    {
        QFETCH(QJsonObject, receipt);
        int completions = 0;
        auto *context = new MigrationTeardownContext(QSharedPointer<QObject>(new QObject),
                "session", 10, 11, true, [] { return quint64(11); },
                [&](bool result) { ++completions; QVERIFY(result); }, this);
        context->observeAndroid(receipt, 10);
        QCOMPARE(completions, 0);
        context->observeAndroid(QJsonObject{{"connectionNonce", "session"},
                                          {"nativeCleanupConfirmed", true}}, 10);
        QCOMPARE(completions, 1);
    }

    void parentDestructionCancelsQueuedReceiptAndDeadline()
    {
        int completions = 0;
        bool queuedCallbackRan = false;
        QObject *parent = new QObject;
        QSharedPointer<QObject> owner(new QObject);
        QPointer<QObject> retained(owner.data());
        QPointer<MigrationTeardownContext> context = new MigrationTeardownContext(owner,
                "session", 10, 11, true, [] { return quint64(11); },
                [&](bool) { ++completions; }, parent, 1);
        owner.clear();
        QVERIFY(QMetaObject::invokeMethod(context.data(), [&, context] {
            queuedCallbackRan = true;
            context->observe("session", 10, true);
        }, Qt::QueuedConnection));
        delete parent;
        QVERIFY(context.isNull());
        QVERIFY(retained.isNull());
        QTest::qWait(20);
        QVERIFY(!queuedCallbackRan);
        QCOMPARE(completions, 0);
    }

    void successfulReceiptWinsOnceAgainstPendingDeadline()
    {
        int completions = 0;
        QPointer<MigrationTeardownContext> context = new MigrationTeardownContext(
                QSharedPointer<QObject>(new QObject), "session", 10, 11, true,
                [] { return quint64(11); }, [&](bool result) {
                    ++completions;
                    QVERIFY(result);
                }, this, 1);
        context->observe("session", 10, true);
        QCOMPARE(completions, 1);
        context->expire();
        context->observe("session", 10, false);
        QCOMPARE(completions, 1);
        QTest::qWait(20);
        QVERIFY(context.isNull());
        QCOMPARE(completions, 1);
    }
};

QTEST_GUILESS_MAIN(MigrationTeardownLifecycleTests)
#include "tst_migration_teardown_lifecycle.moc"
