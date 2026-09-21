#include <QCoreApplication>
#include <QEventLoop>
#include <QMetaType>
#include <QJsonValue>
#include <QScopedPointer>
#include <QTextStream>

#include <limits>

#include "core/utils/errorCodes.h"
#include "core/protocols/wireGuardProtocolBinding.h"
#include "core/utils/selfhostedUpdatePolicy.h"
#include "daemon/daemonerrors.h"

namespace
{
    class TestRunner
    {
    public:
        void check(bool condition, const char *expression, int line)
        {
            ++m_assertions;
            if (condition) {
                return;
            }
            ++m_failures;
            QTextStream(stderr) << "FAIL line " << line << ": " << expression
                                << Qt::endl;
        }

        int finish() const
        {
            QTextStream stream(m_failures == 0 ? stdout : stderr);
            stream << (m_failures == 0 ? "PASS" : "FAIL")
                   << ": " << m_assertions << " assertions, " << m_failures
                   << " failures" << Qt::endl;
            return m_failures == 0 ? 0 : 1;
        }

    private:
        int m_assertions = 0;
        int m_failures = 0;
    };

    struct FakeQuarantine
    {
        bool processExited = false;
        QuarantineCleanup cleanup = QuarantineCleanup::Pending;

        bool canRetry() const
        {
            return mayReleaseQuarantine(processExited, cleanup);
        }
    };

    class FakeController final : public ControllerImpl
    {
    public:
        void initialize(const Device *, const Keys *) override {}
        void activate(const QJsonObject &) override {}
        void deactivate() override {}
        void checkStatus() override {}
        void getBackendLogs(std::function<void(const QString &)>&&) override {}
        void cleanupBackendLogs() override {}

        void emitBackendFailure(DaemonError error) { emit backendFailure(error); }
        void emitConnected() { emit connected(QStringLiteral("test")); }
        void emitDisconnected() { emit disconnected(); }
    };

}

#define CHECK(expression) runner.check((expression), #expression, __LINE__)

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    TestRunner runner;

    // A timeout with an unfinished helper never authorizes a retry.
    FakeQuarantine timeout;
    timeout.cleanup = QuarantineCleanup::Failed;
    CHECK(!timeout.canRetry());

    // Only process exit plus explicit cleanup verification permits retry.
    FakeQuarantine verified;
    verified.processExited = true;
    verified.cleanup = QuarantineCleanup::Verified;
    CHECK(verified.canRetry());

    // Unknown and old IPC values remain typed as a safe generic service error.
    CHECK(amnezia::wireguardProtocolPolicy::errorCodeForDaemonFailure(
              DaemonError::ERROR_NONE)
          == amnezia::ErrorCode::AmneziaServiceConnectionFailed);
    CHECK(amnezia::wireguardProtocolPolicy::errorCodeForDaemonFailure(
              DaemonError::ERROR_SPLIT_TUNNEL_CONFIG_TIMEOUT)
          == amnezia::ErrorCode::SplitTunnelConfigurationTimeout);
    CHECK(amnezia::wireguardProtocolPolicy::errorCodeForDaemonFailure(
              DaemonError::ERROR_SPLIT_TUNNEL_INIT_FAILURE)
          == amnezia::ErrorCode::SplitTunnelInitializationFailed);
    CHECK(amnezia::wireguardProtocolPolicy::errorCodeForDaemonFailure(
              DaemonError::ERROR_SPLIT_TUNNEL_START_FAILURE)
          == amnezia::ErrorCode::SplitTunnelStartFailed);
    CHECK(amnezia::wireguardProtocolPolicy::errorCodeForDaemonFailure(
              DaemonError::ERROR_SPLIT_TUNNEL_EXCLUDE_FAILURE)
          == amnezia::ErrorCode::SplitTunnelExclusionFailed);
    CHECK(amnezia::wireguardProtocolPolicy::errorCodeForDaemonFailure(
              DaemonError::ERROR_SPLIT_TUNNEL_CONFIG_WAIT_FAILED)
          == amnezia::ErrorCode::SplitTunnelConfigurationWaitFailed);
    CHECK(amnezia::wireguardProtocolPolicy::errorCodeForDaemonFailure(
              DaemonError::ERROR_SPLIT_TUNNEL_CONFIG_CLEANUP_FAILED)
          == amnezia::ErrorCode::SplitTunnelConfigurationCleanupFailed);
    CHECK(daemonErrorLegacyIpcValue(DaemonError::ERROR_SPLIT_TUNNEL_CONFIG_TIMEOUT) == 4);
    CHECK(daemonErrorTypedReasonIpcValue(DaemonError::ERROR_SPLIT_TUNNEL_CONFIG_TIMEOUT) == 5);
    CHECK(daemonErrorFromIpcValues(4, 6) == DaemonError::ERROR_SPLIT_TUNNEL_CONFIG_WAIT_FAILED);
    CHECK(daemonErrorFromIpcValues(4) == DaemonError::ERROR_SPLIT_TUNNEL_EXCLUDE_FAILURE);
    CHECK(daemonErrorFromIpcValues(255, 6) == DaemonError::ERROR_FATAL);
    CHECK(!isDaemonFailureIpcValue(0));
    CHECK(isDaemonFailureIpcValue(2));
    CHECK(isDaemonFailureIpcValue(7));
    CHECK(!isDaemonFailureIpcValue(255));
    CHECK(!isDaemonFailureIpcValue(256));
    CHECK(!isDaemonFailureIpcValue(-1));
    CHECK(daemonErrorFromIpcValue(255) == DaemonError::ERROR_FATAL);
    CHECK(isValidDaemonFailureNumber(2.0));
    CHECK(!isValidDaemonFailureNumber(2.5));
    CHECK(!isValidDaemonFailureNumber(std::numeric_limits<double>::quiet_NaN()));
    CHECK(!QJsonValue(QStringLiteral("2")).isDouble());
    CHECK(!QJsonValue().isDouble());

    // Exercise the production ControllerImpl signal binding with queued Qt
    // delivery. The setter mirrors VpnProtocol::setLastError's state effect,
    // while the signal/latch ordering is the actual production binding.
    FakeController controller;
    QObject receiver;
    amnezia::wireguardProtocolPolicy::BackendFailureLatch failureLatch;
    amnezia::ErrorCode lastError = amnezia::ErrorCode::NoError;
    bool connected = false;
    bool errorState = false;
    const auto setLastError = [&](amnezia::ErrorCode error) {
        lastError = error;
        if (error != amnezia::ErrorCode::NoError) {
            errorState = true;
        }
    };
    const auto setConnectionState = [&](bool next) { connected = next; };
    amnezia::wireguardProtocolPolicy::bindControllerSignals(
            &controller, &receiver, &failureLatch, setLastError, setConnectionState,
            Qt::QueuedConnection);

    controller.emitConnected();
    QCoreApplication::processEvents(QEventLoop::AllEvents);
    CHECK(connected);

    controller.emitBackendFailure(DaemonError::ERROR_SPLIT_TUNNEL_CONFIG_TIMEOUT);
    QCoreApplication::processEvents(QEventLoop::AllEvents);
    CHECK(failureLatch.isLatched());
    CHECK(lastError == amnezia::ErrorCode::SplitTunnelConfigurationTimeout);
    CHECK(errorState);
    CHECK(QMetaType::fromType<DaemonError>().id() != QMetaType::UnknownType);

    controller.emitConnected();
    controller.emitDisconnected();
    QCoreApplication::processEvents(QEventLoop::AllEvents);
    CHECK(errorState);

    // A queued signal from the retired attempt is bound to its context and
    // must be discarded when that context is retired for the retry.
    QScopedPointer<QObject> attemptContext(new QObject());
    amnezia::wireguardProtocolPolicy::BackendFailureLatch retryLatch;
    bool retryConnected = false;
    amnezia::wireguardProtocolPolicy::bindControllerSignals(
            &controller, attemptContext.get(), &retryLatch,
            [](amnezia::ErrorCode) {},
            [&retryConnected](bool next) { retryConnected = next; },
            Qt::QueuedConnection);
    controller.emitConnected();
    controller.emitBackendFailure(DaemonError::ERROR_FATAL);
    attemptContext.reset(new QObject());
    QCoreApplication::processEvents(QEventLoop::AllEvents);
    CHECK(!retryLatch.isLatched());
    CHECK(!retryConnected);

    failureLatch.beginAttempt();
    setLastError(amnezia::ErrorCode::NoError);
    controller.emitConnected();
    QCoreApplication::processEvents(QEventLoop::AllEvents);
    CHECK(!failureLatch.isLatched());
    CHECK(connected);

    return runner.finish();
}
