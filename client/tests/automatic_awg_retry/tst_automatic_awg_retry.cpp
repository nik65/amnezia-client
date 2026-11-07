#include <QtTest>
#include <QPointer>
#include "../../core/utils/automaticAwgRetry.h"

using amnezia::ErrorCode;

class RetryTests : public QObject
{
    Q_OBJECT
    static void advanceClock(AutomaticAwgRetry &retry)
    {
        // Deliver the actual timer signal deterministically, without real
        // wall-clock delays; all production guard/dispatch logic executes.
        auto timer = retry.findChild<QTimer *>();
        QVERIFY(timer);
        QVERIFY(QMetaObject::invokeMethod(timer, "timeout", Qt::DirectConnection));
    }
    static QJsonObject retirementReceipt()
    {
        return {{"ok", true}, {"native", true}, {"reconciled", true}, {"retired", true},
            {"retiredVerified", true}, {"liveVerified", false}, {"pendingRecovery", false},
            {"mode", "abort-prepare"}, {"phase", "aborted"}, {"source", "amnezia-awg"},
            {"generation", 7}, {"clientOperationId", "11111111-2222-4333-8444-555555555555"},
            {"journalSha256", QString(64, 'a')},
            {"controlHashes", QJsonObject{{"awg-feed", QString(64, 'b')}}}};
    }
private slots:
    void retirementRequiresVerifiedCausalReceiptAndNoCleanupFailure()
    {
        const auto receipt = retirementReceipt();
        QVERIFY(AutomaticAwgRetry::verifiedRetirement(ErrorCode::NoError, receipt, "amnezia-awg"));
        QVERIFY(!AutomaticAwgRetry::verifiedRetirement(ErrorCode::SshTimeoutError, receipt, "amnezia-awg"));
        QVERIFY(!AutomaticAwgRetry::verifiedRetirement(ErrorCode::NoError, receipt, "amnezia-awg2"));
        for (const QString &field : {QStringLiteral("ok"), QStringLiteral("native"), QStringLiteral("reconciled"),
                QStringLiteral("retired"), QStringLiteral("retiredVerified"), QStringLiteral("journalSha256"),
                QStringLiteral("clientOperationId"), QStringLiteral("generation")}) {
            auto changed = receipt;
            changed.remove(field);
            QVERIFY(!AutomaticAwgRetry::verifiedRetirement(ErrorCode::NoError, changed, "amnezia-awg"));
        }
        for (const QString &field : {QStringLiteral("pendingRecovery"), QStringLiteral("cleanupRequired"),
                QStringLiteral("liveVerified")}) {
            auto changed = receipt;
            changed.insert(field, true);
            QVERIFY(!AutomaticAwgRetry::verifiedRetirement(ErrorCode::NoError, changed, "amnezia-awg"));
        }
        for (const QString &mode : {QStringLiteral("inspect-prepare"), QStringLiteral("status"), QStringLiteral("verify")}) {
            auto changed = receipt;
            changed.insert("mode", mode);
            QVERIFY(!AutomaticAwgRetry::verifiedRetirement(ErrorCode::NoError, changed, "amnezia-awg"));
        }
    }
    void verifiedRetirementHasFiniteBudgetAcrossCancellation()
    {
        AutomaticAwgRetry retry;
        int attempts = 0;
        const auto receipt = retirementReceipt();
        for (int delay : {1000, 3000, 10000}) {
            QVERIFY(retry.scheduleAfterRetirement(ErrorCode::NoError, receipt, "amnezia-awg",
                [] { return true; }, [&] { ++attempts; }));
            QCOMPARE(retry.delayMs(), delay);
            advanceClock(retry);
            retry.cancel(); // an unrelated failure must not recreate the budget
        }
        QCOMPARE(attempts, 3);
        QVERIFY(!retry.scheduleAfterRetirement(ErrorCode::NoError, receipt, "amnezia-awg",
            [] { return true; }, [&] { ++attempts; }));
        advanceClock(retry);
        QCOMPARE(attempts, 3);
    }
    void retirementNeverRetriesChangedBindingOrUnprovedAbsence()
    {
        AutomaticAwgRetry retry;
        int attempts = 0;
        QString binding = "exact-credentials-endpoint-source";
        QVERIFY(retry.scheduleAfterRetirement(ErrorCode::NoError, retirementReceipt(), "amnezia-awg",
            [&] { return binding == "exact-credentials-endpoint-source"; }, [&] { ++attempts; }));
        binding = "changed";
        advanceClock(retry);
        QCOMPARE(attempts, 0);
        const QJsonObject absent{{"retired", true}, {"reason", "journal_absent"}};
        QVERIFY(!retry.scheduleAfterRetirement(ErrorCode::NoError, absent, "amnezia-awg",
            [] { return true; }, [&] { ++attempts; }));
        advanceClock(retry);
        QCOMPARE(attempts, 0);
    }
    void transportAndDependencyClassification()
    {
        QVERIFY(AutomaticAwgRetry::transient(ErrorCode::SshTimeoutError, {}));
        QVERIFY(AutomaticAwgRetry::transient(ErrorCode::ServerCheckFailed, "image_fetch_unavailable"));
        QVERIFY(AutomaticAwgRetry::transient(ErrorCode::ServerCheckFailed, "migration_dependency_unavailable"));
        QVERIFY(!AutomaticAwgRetry::transient(ErrorCode::SshInternalError, {}));
        for (auto error : {ErrorCode::SshHostKeyMismatchError, ErrorCode::SshRequestDeniedError,
                           ErrorCode::SshPrivateKeyError, ErrorCode::SshHostKeyMissingError})
            QVERIFY(!AutomaticAwgRetry::transient(error, "image_fetch_unavailable"));
        for (const auto reason : {"trusted_image_unavailable", "unsupported_server_architecture",
                                 "unsupported_namespace_firewall", "migration_ready_drift", "migration_journal_conflict"})
            QVERIFY(!AutomaticAwgRetry::transient(ErrorCode::SshTimeoutError, reason));
    }
    void backoffContinuesWithoutUserActionAndCapsAtFifteenMinutes()
    {
        AutomaticAwgRetry retry;
        int attempts = 0;
        for (int delay : {30000, 120000, 300000, 900000, 900000, 900000}) {
            QVERIFY(retry.schedule(ErrorCode::SshTimeoutError, {}, [] { return true; }, [&] { ++attempts; }));
            QCOMPARE(retry.delayMs(), delay);
            advanceClock(retry);
        }
        QCOMPARE(attempts, 6);
        retry.cancel();
        retry.schedule(ErrorCode::SshTimeoutError, {}, [] { return true; }, [&] { ++attempts; });
        QCOMPARE(retry.delayMs(), 30000);
    }
    void changedOrDeletedBindingNeverEnqueuesAndPendingTimerDeduplicates()
    {
        AutomaticAwgRetry retry;
        QString binding = "original";
        int attempts = 0;
        retry.schedule(ErrorCode::SshTimeoutError, {}, [&] { return binding == "original"; }, [&] { ++attempts; });
        // A repeated UI/settings event must not replace the active timer/guard.
        retry.schedule(ErrorCode::SshTimeoutError, {}, [] { return true; }, [&] { attempts += 100; });
        binding = "changed";
        advanceClock(retry);
        QCOMPARE(attempts, 0);
        retry.schedule(ErrorCode::SshTimeoutError, {}, [] { return false; }, [&] { ++attempts; });
        advanceClock(retry);
        QCOMPARE(attempts, 0);
    }
    void permanentFailureCancelsAndDestroyedReceiverDropsQueuedTimeout()
    {
        QObject *owner = new QObject;
        auto retry = new AutomaticAwgRetry(owner);
        int attempts = 0;
        retry->schedule(ErrorCode::SshTimeoutError, {}, [] { return true; }, [&] { ++attempts; });
        QVERIFY(!retry->schedule(ErrorCode::SshHostKeyMismatchError, {}, [] { return true; }, [&] { ++attempts; }));
        advanceClock(*retry);
        QCOMPARE(attempts, 0);
        retry->schedule(ErrorCode::SshTimeoutError, {}, [] { return true; }, [&] { ++attempts; });
        QPointer<QTimer> timer = retry->findChild<QTimer *>();
        QVERIFY(QMetaObject::invokeMethod(timer, "timeout", Qt::QueuedConnection));
        delete owner;
        QVERIFY(timer.isNull());
        QCoreApplication::sendPostedEvents();
        QCOMPARE(attempts, 0);
    }
};
QTEST_GUILESS_MAIN(RetryTests)
#include "tst_automatic_awg_retry.moc"
