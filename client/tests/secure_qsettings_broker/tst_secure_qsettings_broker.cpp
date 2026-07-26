#include "secureQSettings.h"

#include <QTextStream>

#include <atomic>
#include <chrono>
#include <mutex>
#include <set>
#include <thread>
#include <vector>

namespace
{
class TestRunner
{
public:
    void check(bool condition, const char *expression, int line)
    {
        ++m_assertions;
        if (!condition) {
            ++m_failures;
            QTextStream(stderr) << "FAIL line " << line << ": "
                                << expression << Qt::endl;
        }
    }

    int finish() const
    {
        QTextStream stream(m_failures == 0 ? stdout : stderr);
        stream << (m_failures == 0 ? "PASS" : "FAIL") << ": "
               << m_assertions << " assertions, " << m_failures
               << " failures" << Qt::endl;
        return m_failures == 0 ? 0 : 1;
    }

private:
    int m_assertions = 0;
    int m_failures = 0;
};
}

#define CHECK(expression) runner.check((expression), #expression, __LINE__)

int main()
{
    using AdmissionStatus =
            amnezia::secureSettingsPolicy::KeychainBrokerAdmissionStatus;
    using Gate = amnezia::secureSettingsPolicy::KeychainBrokerGate;

    TestRunner runner;

    Gate boundedQueue(2);
    const auto first = boundedQueue.admitOperation();
    const auto second = boundedQueue.admitOperation();
    const auto third = boundedQueue.admitOperation();
    const auto overflow = boundedQueue.admitOperation();
    CHECK(first.status == AdmissionStatus::Started);
    CHECK(second.status == AdmissionStatus::Queued);
    CHECK(third.status == AdmissionStatus::Queued);
    CHECK(overflow.status == AdmissionStatus::QueueFull);
    CHECK(overflow.operationId == 0);
    CHECK(boundedQueue.pendingOperationCount() == 2);
    CHECK(boundedQueue.startedOperationCount() == 1);

    const auto firstFinished =
            boundedQueue.completeAndStartNext(first.operationId);
    CHECK(firstFinished.accepted);
    CHECK(firstFinished.nextOperationId == second.operationId);
    CHECK(boundedQueue.startedOperationCount() == 2);
    const auto secondFinished =
            boundedQueue.completeAndStartNext(second.operationId);
    CHECK(secondFinished.accepted);
    CHECK(secondFinished.nextOperationId == third.operationId);
    CHECK(boundedQueue.startedOperationCount() == 3);
    const auto thirdFinished =
            boundedQueue.completeAndStartNext(third.operationId);
    CHECK(thirdFinished.accepted);
    CHECK(thirdFinished.nextOperationId == 0);
    CHECK(!boundedQueue.hasActiveOperation());

    // A never-completing native job owns the only active slot. Once its caller
    // reaches the deadline, queued work is discarded and the process-local
    // broker remains quarantined even if that job finishes much later.
    Gate neverCompleting(4);
    const auto stuck = neverCompleting.admitOperation();
    const auto waitingOne = neverCompleting.admitOperation();
    const auto waitingTwo = neverCompleting.admitOperation();
    CHECK(stuck.status == AdmissionStatus::Started);
    CHECK(waitingOne.status == AdmissionStatus::Queued);
    CHECK(waitingTwo.status == AdmissionStatus::Queued);
    CHECK(neverCompleting.deadlineExceeded(stuck.operationId));
    CHECK(neverCompleting.isFailedClosed());
    CHECK(neverCompleting.hasActiveOperation());
    CHECK(neverCompleting.pendingOperationCount() == 0);
    CHECK(neverCompleting.startedOperationCount() == 1);
    CHECK(neverCompleting.admitOperation().status
          == AdmissionStatus::FailedClosed);

    const auto lateFinish =
            neverCompleting.completeAndStartNext(stuck.operationId);
    CHECK(lateFinish.accepted);
    CHECK(lateFinish.nextOperationId == 0);
    CHECK(!neverCompleting.hasActiveOperation());
    CHECK(neverCompleting.isFailedClosed());
    CHECK(neverCompleting.startedOperationCount() == 1);
    CHECK(neverCompleting.admitOperation().status
          == AdmissionStatus::FailedClosed);

    Gate queuedDeadline(3);
    const auto active = queuedDeadline.admitOperation();
    const auto queued = queuedDeadline.admitOperation();
    CHECK(active.status == AdmissionStatus::Started);
    CHECK(queued.status == AdmissionStatus::Queued);
    CHECK(queuedDeadline.deadlineExceeded(queued.operationId));
    CHECK(queuedDeadline.isFailedClosed());
    CHECK(queuedDeadline.activeOperationId() == active.operationId);
    CHECK(queuedDeadline.pendingOperationCount() == 0);
    CHECK(queuedDeadline.completeAndStartNext(active.operationId).nextOperationId
          == 0);

    Gate concurrentGate(5);
    std::mutex concurrentMutex;
    std::atomic<bool> startConcurrent { false };
    std::vector<amnezia::secureSettingsPolicy::KeychainBrokerAdmissionDecision>
            concurrentResults(32);
    std::vector<std::thread> callers;
    callers.reserve(concurrentResults.size());
    for (std::size_t index = 0; index < concurrentResults.size(); ++index) {
        callers.emplace_back([&, index]() {
            while (!startConcurrent.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }
            std::lock_guard<std::mutex> lock(concurrentMutex);
            concurrentResults[index] = concurrentGate.admitOperation();
        });
    }
    startConcurrent.store(true, std::memory_order_release);
    for (std::thread &caller : callers) {
        caller.join();
    }

    int started = 0;
    int queuedCount = 0;
    int full = 0;
    std::set<quint64> admittedIds;
    for (const auto &result : concurrentResults) {
        if (result.status == AdmissionStatus::Started) {
            ++started;
        } else if (result.status == AdmissionStatus::Queued) {
            ++queuedCount;
        } else if (result.status == AdmissionStatus::QueueFull) {
            ++full;
        }
        if (result.operationId != 0) {
            admittedIds.insert(result.operationId);
        }
    }
    CHECK(started == 1);
    CHECK(queuedCount == 5);
    CHECK(full == 26);
    CHECK(admittedIds.size() == 6);
    CHECK(concurrentGate.startedOperationCount() == 1);
    CHECK(concurrentGate.pendingOperationCount() == 5);

    Gate shutdownGate(2);
    const auto shutdownActive = shutdownGate.admitOperation();
    CHECK(shutdownGate.admitOperation().status == AdmissionStatus::Queued);
    const auto shutdownStartedAt = std::chrono::steady_clock::now();
    CHECK(shutdownGate.beginShutdown());
    const auto shutdownElapsed = std::chrono::steady_clock::now()
            - shutdownStartedAt;
    CHECK(shutdownElapsed < std::chrono::milliseconds(50));
    CHECK(shutdownGate.isShuttingDown());
    CHECK(shutdownGate.isFailedClosed());
    CHECK(shutdownGate.pendingOperationCount() == 0);
    CHECK(shutdownGate.admitOperation().status
          == AdmissionStatus::ShuttingDown);
    CHECK(!shutdownGate.beginShutdown());
    const auto completionAfterShutdown =
            shutdownGate.completeAndStartNext(shutdownActive.operationId);
    CHECK(completionAfterShutdown.accepted);
    CHECK(completionAfterShutdown.nextOperationId == 0);
    CHECK(!shutdownGate.hasActiveOperation());

    CHECK(amnezia::secureSettingsPolicy::keychainReadAllowed(false, true));
    CHECK(!amnezia::secureSettingsPolicy::keychainReadAllowed(true, true));
    CHECK(amnezia::secureSettingsPolicy::keychainReadAllowed(true, false));
    CHECK(amnezia::secureSettingsPolicy::keychainMaterialCreationAllowed(false, false));
    CHECK(!amnezia::secureSettingsPolicy::keychainMaterialCreationAllowed(true, false));
    CHECK(!amnezia::secureSettingsPolicy::keychainMaterialCreationAllowed(false, true));
    CHECK(!amnezia::secureSettingsPolicy::keychainMaterialCreationAllowed(true, true));

    return runner.finish();
}
