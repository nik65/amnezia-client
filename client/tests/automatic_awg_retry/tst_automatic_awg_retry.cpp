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
private slots:
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
