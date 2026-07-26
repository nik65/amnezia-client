#include <QtTest/QtTest>

#include <QSemaphore>
#include <QThread>
#include <QTimer>

#include <atomic>
#include <optional>

#include "core/utils/boundedQueuedSnapshot.h"
#include "core/utils/remoteLogBatchHealth.h"

namespace
{
class SnapshotTarget final : public QObject
{
    Q_OBJECT

public:
    int value = 42;
};

class ThreadGuard final
{
public:
    explicit ThreadGuard(QThread &thread, QSemaphore *blocker = nullptr)
        : m_thread(thread), m_blocker(blocker)
    {
    }

    ~ThreadGuard()
    {
        if (m_blocker) {
            m_blocker->release();
        }
        m_thread.quit();
        m_thread.wait(2000);
    }

    void releaseBlocker()
    {
        if (m_blocker) {
            m_blocker->release();
            m_blocker = nullptr;
        }
    }

private:
    QThread &m_thread;
    QSemaphore *m_blocker;
};
}

class BoundedQueuedSnapshotTest final : public QObject
{
    Q_OBJECT

private slots:
    void remoteLogHealthRequiresEveryExpectedSource()
    {
        QVERIFY(amnezia::remoteLogBatchCanBecomeHealthy(false, true, false, false));
        QVERIFY(!amnezia::remoteLogBatchCanBecomeHealthy(true, true, false, false));
        QVERIFY(!amnezia::remoteLogBatchCanBecomeHealthy(false, false, false, false));
        QVERIFY(!amnezia::remoteLogBatchCanBecomeHealthy(false, true, true, false));
        QVERIFY(!amnezia::remoteLogBatchCanBecomeHealthy(false, true, false, true));
    }

    void missingTargetCompletesAsUnavailable()
    {
        int callbackCount = 0;
        amnezia::BoundedQueuedSnapshotStatus receivedStatus =
                amnezia::BoundedQueuedSnapshotStatus::Ready;
        amnezia::requestBoundedQueuedSnapshot(
                static_cast<SnapshotTarget *>(nullptr), this, 500,
                [](SnapshotTarget *snapshotTarget) { return snapshotTarget->value; },
                [&](amnezia::BoundedQueuedSnapshotStatus status, std::optional<int> value) {
                    ++callbackCount;
                    receivedStatus = status;
                    QVERIFY(!value.has_value());
                });

        QTRY_COMPARE_WITH_TIMEOUT(callbackCount, 1, 1000);
        QCOMPARE(receivedStatus, amnezia::BoundedQueuedSnapshotStatus::TargetUnavailable);
    }

    void deliversReadyInReceiverThread()
    {
        QThread worker;
        SnapshotTarget target;
        target.moveToThread(&worker);
        worker.start();
        ThreadGuard guard(worker);

        int callbackCount = 0;
        QThread *readerThread = nullptr;
        QThread *completionThread = nullptr;
        std::optional<int> received;
        amnezia::requestBoundedQueuedSnapshot(
                &target, this, 500,
                [&readerThread](SnapshotTarget *snapshotTarget) {
                    readerThread = QThread::currentThread();
                    return snapshotTarget->value;
                },
                [&](amnezia::BoundedQueuedSnapshotStatus status, std::optional<int> value) {
                    ++callbackCount;
                    completionThread = QThread::currentThread();
                    QCOMPARE(status, amnezia::BoundedQueuedSnapshotStatus::Ready);
                    received = value;
                });

        QTRY_COMPARE_WITH_TIMEOUT(callbackCount, 1, 1000);
        QCOMPARE(readerThread, &worker);
        QCOMPARE(completionThread, QThread::currentThread());
        QCOMPARE(received, std::optional<int>(42));
    }

    void completionMaySynchronouslyDestroyReceiver()
    {
        QThread worker;
        SnapshotTarget target;
        target.moveToThread(&worker);
        worker.start();
        ThreadGuard guard(worker);

        auto *receiver = new QObject;
        int callbackCount = 0;
        amnezia::requestBoundedQueuedSnapshot(
                &target, receiver, 500,
                [](SnapshotTarget *snapshotTarget) { return snapshotTarget->value; },
                [&](amnezia::BoundedQueuedSnapshotStatus status, std::optional<int> value) {
                    ++callbackCount;
                    QCOMPARE(status, amnezia::BoundedQueuedSnapshotStatus::Ready);
                    QCOMPARE(value, std::optional<int>(42));
                    delete receiver;
                    receiver = nullptr;
                });

        QTRY_COMPARE_WITH_TIMEOUT(callbackCount, 1, 1000);
        QCOMPARE(receiver, nullptr);
        QTest::qWait(50);
        QCOMPARE(callbackCount, 1);
    }

    void blockedThreadTimesOutWithoutBlockingReceiver()
    {
        QThread worker;
        SnapshotTarget target;
        target.moveToThread(&worker);
        QSemaphore blockerEntered;
        QSemaphore releaseBlocker;
        worker.start();
        ThreadGuard guard(worker, &releaseBlocker);

        QVERIFY(QMetaObject::invokeMethod(&target, [&]() {
            blockerEntered.release();
            releaseBlocker.acquire();
        }, Qt::QueuedConnection));
        QVERIFY(blockerEntered.tryAcquire(1, 1000));

        int callbackCount = 0;
        std::atomic_int readerCount { 0 };
        bool heartbeatFired = false;
        amnezia::BoundedQueuedSnapshotStatus receivedStatus =
                amnezia::BoundedQueuedSnapshotStatus::Ready;
        amnezia::requestBoundedQueuedSnapshot(
                &target, this, 50,
                [&readerCount](SnapshotTarget *snapshotTarget) {
                    readerCount.fetch_add(1, std::memory_order_relaxed);
                    return snapshotTarget->value;
                },
                [&](amnezia::BoundedQueuedSnapshotStatus status, std::optional<int>) {
                    ++callbackCount;
                    receivedStatus = status;
                });
        QTimer::singleShot(0, this, [&]() { heartbeatFired = true; });

        QTest::qWait(150);
        const int countAtTimeout = callbackCount;
        const auto statusAtTimeout = receivedStatus;
        const bool heartbeatAtTimeout = heartbeatFired;
        guard.releaseBlocker();
        QTest::qWait(100);

        QVERIFY(heartbeatAtTimeout);
        QCOMPARE(countAtTimeout, 1);
        QCOMPARE(statusAtTimeout, amnezia::BoundedQueuedSnapshotStatus::Timeout);
        QCOMPARE(callbackCount, 1);
        QCOMPARE(readerCount.load(std::memory_order_relaxed), 0);
    }

    void runningReaderResultAfterTimeoutIsDiscarded()
    {
        QThread worker;
        SnapshotTarget target;
        target.moveToThread(&worker);
        QSemaphore readerEntered;
        QSemaphore releaseReader;
        worker.start();
        ThreadGuard guard(worker, &releaseReader);

        std::atomic_int readerCount { 0 };
        int callbackCount = 0;
        amnezia::BoundedQueuedSnapshotStatus receivedStatus =
                amnezia::BoundedQueuedSnapshotStatus::Ready;
        amnezia::requestBoundedQueuedSnapshot(
                &target, this, 50,
                [&](SnapshotTarget *snapshotTarget) {
                    readerCount.fetch_add(1, std::memory_order_relaxed);
                    readerEntered.release();
                    releaseReader.acquire();
                    return snapshotTarget->value;
                },
                [&](amnezia::BoundedQueuedSnapshotStatus status, std::optional<int> value) {
                    ++callbackCount;
                    receivedStatus = status;
                    QVERIFY(!value.has_value());
                });

        QVERIFY(readerEntered.tryAcquire(1, 1000));
        QTRY_COMPARE_WITH_TIMEOUT(callbackCount, 1, 1000);
        QCOMPARE(receivedStatus, amnezia::BoundedQueuedSnapshotStatus::Timeout);
        QCOMPARE(readerCount.load(std::memory_order_relaxed), 1);

        guard.releaseBlocker();
        QTest::qWait(100);
        QCOMPARE(callbackCount, 1);
        QCOMPARE(readerCount.load(std::memory_order_relaxed), 1);
    }

    void destroyedReceiverDropsLateCompletion()
    {
        QThread worker;
        SnapshotTarget target;
        target.moveToThread(&worker);
        QSemaphore blockerEntered;
        QSemaphore releaseBlocker;
        worker.start();
        ThreadGuard guard(worker, &releaseBlocker);

        QVERIFY(QMetaObject::invokeMethod(&target, [&]() {
            blockerEntered.release();
            releaseBlocker.acquire();
        }, Qt::QueuedConnection));
        QVERIFY(blockerEntered.tryAcquire(1, 1000));

        std::atomic_int callbackCount { 0 };
        auto *receiver = new QObject;
        amnezia::requestBoundedQueuedSnapshot(
                &target, receiver, 25,
                [](SnapshotTarget *snapshotTarget) { return snapshotTarget->value; },
                [&](amnezia::BoundedQueuedSnapshotStatus, std::optional<int>) {
                    callbackCount.fetch_add(1, std::memory_order_relaxed);
                });
        delete receiver;
        guard.releaseBlocker();
        QTest::qWait(100);

        QCOMPARE(callbackCount.load(std::memory_order_relaxed), 0);
    }

    void destroyedTargetCancelsQueuedReader()
    {
        QThread worker;
        auto *target = new SnapshotTarget;
        target->moveToThread(&worker);
        QSemaphore blockerEntered;
        QSemaphore releaseBlocker;
        worker.start();
        ThreadGuard guard(worker, &releaseBlocker);

        QVERIFY(QMetaObject::invokeMethod(target, [&]() {
            blockerEntered.release();
            releaseBlocker.acquire();
        }, Qt::QueuedConnection));
        QVERIFY(blockerEntered.tryAcquire(1, 1000));
        QVERIFY(QMetaObject::invokeMethod(target, [target]() { delete target; },
                                          Qt::QueuedConnection));

        std::atomic_int readerCount { 0 };
        int callbackCount = 0;
        amnezia::BoundedQueuedSnapshotStatus receivedStatus =
                amnezia::BoundedQueuedSnapshotStatus::Ready;
        amnezia::requestBoundedQueuedSnapshot(
                target, this, 500,
                [&readerCount](SnapshotTarget *snapshotTarget) {
                    readerCount.fetch_add(1, std::memory_order_relaxed);
                    return snapshotTarget->value;
                },
                [&](amnezia::BoundedQueuedSnapshotStatus status, std::optional<int>) {
                    ++callbackCount;
                    receivedStatus = status;
                });

        guard.releaseBlocker();
        QTRY_COMPARE_WITH_TIMEOUT(callbackCount, 1, 1000);
        QCOMPARE(receivedStatus, amnezia::BoundedQueuedSnapshotStatus::TargetUnavailable);
        QCOMPARE(readerCount.load(std::memory_order_relaxed), 0);
    }
};

QTEST_MAIN(BoundedQueuedSnapshotTest)
#include "tst_bounded_queued_snapshot.moc"
