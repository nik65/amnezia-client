#ifndef BOUNDEDQUEUEDSNAPSHOT_H
#define BOUNDEDQUEUEDSNAPSHOT_H

#include <QFutureWatcher>
#include <QMetaObject>
#include <QObject>
#include <QPointer>
#include <QPromise>
#include <QThread>
#include <QTimer>

#include <atomic>
#include <memory>
#include <mutex>
#include <optional>
#include <type_traits>
#include <utility>

namespace amnezia
{

enum class BoundedQueuedSnapshotStatus {
    Ready,
    Timeout,
    TargetUnavailable,
    QueueFailed,
};

// Runs a pure snapshot reader in target's owning thread without ever blocking
// the receiver thread. Completion is delivered at most once in receiver's
// thread. A timed-out queued reader becomes a no-op; a reader that was already
// running may finish, but its late value is discarded.
template<typename Target, typename Reader, typename Completion>
void requestBoundedQueuedSnapshot(Target *target, QObject *receiver, int timeoutMs,
                                  Reader reader, Completion completion)
{
    using Value = std::decay_t<std::invoke_result_t<Reader, Target *>>;
    static_assert(!std::is_void_v<Value>, "A snapshot reader must return a value");

    if (!receiver) {
        return;
    }

    // The watcher and timeout timer are receiver-owned. If a caller is not in
    // that thread, first transfer the whole setup there instead of creating a
    // QObject with a foreign-thread parent.
    if (receiver->thread() != QThread::currentThread()) {
        const QPointer<Target> guardedTarget(target);
        const QPointer<QObject> guardedReceiver(receiver);
        QMetaObject::invokeMethod(
                receiver,
                [guardedTarget, guardedReceiver, timeoutMs,
                 reader = std::move(reader), completion = std::move(completion)]() mutable {
                    if (!guardedReceiver) {
                        return;
                    }
                    requestBoundedQueuedSnapshot(
                            guardedTarget.data(), guardedReceiver.data(), timeoutMs,
                            std::move(reader), std::move(completion));
                },
                Qt::QueuedConnection);
        return;
    }

    auto completeLater = [receiver, completion = std::move(completion)](
                                 BoundedQueuedSnapshotStatus status) mutable {
        QTimer::singleShot(0, receiver, [completion = std::move(completion), status]() mutable {
            completion(status, std::optional<Value> {});
        });
    };

    // Callers keep target alive for this synchronous setup call. Every
    // deferred access after setup is guarded, and QObject removes a queued
    // context-bound reader if target is destroyed before it can run.
    const QPointer<Target> guardedTarget(target);
    if (!guardedTarget || !guardedTarget->thread()) {
        completeLater(BoundedQueuedSnapshotStatus::TargetUnavailable);
        return;
    }
    QThread *const targetThread = guardedTarget->thread();
    if (targetThread != QThread::currentThread() && !targetThread->isRunning()) {
        completeLater(BoundedQueuedSnapshotStatus::TargetUnavailable);
        return;
    }

    struct SharedState
    {
        std::atomic_bool cancelled { false };
        std::atomic_bool resolved { false };
        std::atomic_bool promiseFinished { false };
        std::atomic_bool targetDestroyed { false };
        std::atomic_bool queueFailed { false };
        std::mutex promiseMutex;
    };

    auto state = std::make_shared<SharedState>();
    const std::weak_ptr<SharedState> weakState = state;
    auto *watcher = new QFutureWatcher<Value>(receiver);
    auto *timeoutTimer = new QTimer(watcher);
    timeoutTimer->setSingleShot(true);
    const auto completionPtr = std::make_shared<Completion>(std::move(completion));
    auto promise = std::make_shared<QPromise<Value>>();
    promise->start();
    const auto finishPromise = [state, promise](std::optional<Value> value = {}) {
        {
            std::lock_guard<std::mutex> lock(state->promiseMutex);
            if (state->promiseFinished.exchange(true, std::memory_order_acq_rel)) {
                return;
            }
            if (value.has_value()
                && !state->cancelled.load(std::memory_order_acquire)) {
                promise->addResult(std::move(value.value()));
            }
        }
        // Never hold promiseMutex while notifying the watcher. A future
        // implementation is allowed to deliver finished synchronously.
        promise->finish();
    };
    auto resolve = [state, watcher, timeoutTimer, completionPtr, finishPromise](
                           BoundedQueuedSnapshotStatus status,
                           std::optional<Value> value) mutable {
        if (state->resolved.exchange(true, std::memory_order_acq_rel)) {
            return;
        }
        state->cancelled.store(true, std::memory_order_release);
        finishPromise();
        timeoutTimer->stop();
        // Detach and schedule cleanup before invoking user code. A completion
        // is allowed to synchronously destroy receiver and all of its children.
        watcher->setParent(nullptr);
        watcher->deleteLater();
        (*completionPtr)(status, std::move(value));
    };

    QObject::connect(watcher, &QObject::destroyed, [weakState, finishPromise]() mutable {
        if (const auto locked = weakState.lock()) {
            locked->cancelled.store(true, std::memory_order_release);
            locked->resolved.exchange(true, std::memory_order_acq_rel);
            finishPromise();
        }
    });

    watcher->setFuture(promise->future());
    QObject::connect(watcher, &QFutureWatcher<Value>::finished, watcher,
                     [state, watcher, resolve]() mutable {
        if (state->queueFailed.load(std::memory_order_acquire)) {
            resolve(BoundedQueuedSnapshotStatus::QueueFailed, {});
            return;
        }
        if (state->targetDestroyed.load(std::memory_order_acquire)
            || watcher->future().resultCount() != 1) {
            resolve(BoundedQueuedSnapshotStatus::TargetUnavailable, {});
            return;
        }
        resolve(BoundedQueuedSnapshotStatus::Ready, watcher->result());
    });
    QObject::connect(timeoutTimer, &QTimer::timeout, watcher,
                     [state, resolve]() mutable {
        BoundedQueuedSnapshotStatus status = BoundedQueuedSnapshotStatus::Timeout;
        if (state->queueFailed.load(std::memory_order_acquire)) {
            status = BoundedQueuedSnapshotStatus::QueueFailed;
        } else if (state->targetDestroyed.load(std::memory_order_acquire)) {
            status = BoundedQueuedSnapshotStatus::TargetUnavailable;
        }
        resolve(status, {});
    });
    QObject::connect(guardedTarget.data(), &QObject::destroyed, watcher,
                     [state, resolve]() mutable {
        state->targetDestroyed.store(true, std::memory_order_release);
        resolve(BoundedQueuedSnapshotStatus::TargetUnavailable, {});
    }, Qt::QueuedConnection);
    timeoutTimer->start(qMax(0, timeoutMs));

    const bool queued = QMetaObject::invokeMethod(
            guardedTarget.data(),
            [state, finishPromise, guardedTarget,
             reader = std::move(reader)]() mutable {
                if (state->cancelled.load(std::memory_order_acquire)) {
                    finishPromise();
                    return;
                }
                Target *const liveTarget = guardedTarget.data();
                if (!liveTarget) {
                    state->targetDestroyed.store(true, std::memory_order_release);
                    finishPromise();
                    return;
                }
                Value value = reader(liveTarget);
                if (state->cancelled.load(std::memory_order_acquire)) {
                    finishPromise();
                    return;
                }
                finishPromise(std::optional<Value>(std::move(value)));
            },
            Qt::QueuedConnection);
    if (!queued) {
        state->queueFailed.store(true, std::memory_order_release);
        finishPromise();
    }
}

} // namespace amnezia

#endif // BOUNDEDQUEUEDSNAPSHOT_H
