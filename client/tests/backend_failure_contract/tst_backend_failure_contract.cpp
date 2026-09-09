#include <QCoreApplication>
#include <QJsonValue>
#include <QTextStream>

#include <limits>

#include "core/utils/errorCodes.h"
#include "core/protocols/wireGuardProtocol.h"
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

    struct FakeProtocol
    {
        enum class State
        {
            Disconnected,
            Connecting,
            Connected,
            Error,
        };

        amnezia::wireguardProtocolPolicy::BackendFailureLatch failureLatch;
        State state = State::Disconnected;

        void backendFailure()
        {
            failureLatch.latch();
            state = State::Error;
        }

        void connected()
        {
            if (failureLatch.acceptsConnectionEvent()) {
                state = State::Connected;
            }
        }

        void disconnected()
        {
            if (failureLatch.acceptsConnectionEvent()) {
                state = State::Disconnected;
            }
        }

        void explicitRetry()
        {
            failureLatch.beginAttempt();
            state = State::Connecting;
        }
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

    // Late transport events cannot erase a latched backend failure.
    FakeProtocol protocol;
    protocol.backendFailure();
    protocol.connected();
    protocol.disconnected();
    CHECK(protocol.failureLatch.isLatched());
    CHECK(protocol.state == FakeProtocol::State::Error);
    protocol.explicitRetry();
    protocol.connected();
    CHECK(!protocol.failureLatch.isLatched());
    CHECK(protocol.state == FakeProtocol::State::Connected);

    return runner.finish();
}
