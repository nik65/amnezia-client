#ifndef SSHCLIENT_H
#define SSHCLIENT_H

#include <algorithm>
#include <cstdint>
#include <limits>
#include <QString>

// These small, dependency-free decisions are shared by the production SSH
// pump and the deterministic focused test.  Defining
// AMNEZIA_SSH_CLIENT_STATE_ONLY lets that test exercise the real decisions
// without linking libssh or the application object graph.
namespace libssh::detail
{
    enum class BoundaryState {
        Ready,
        Cancelled,
        TimedOut,
    };

    inline BoundaryState boundaryState(std::int64_t nowMs,
                                       std::int64_t deadlineMs,
                                       bool cancelRequested)
    {
        if (cancelRequested) {
            return BoundaryState::Cancelled;
        }
        if (deadlineMs <= 0 || nowMs >= deadlineMs) {
            return BoundaryState::TimedOut;
        }
        return BoundaryState::Ready;
    }

    inline std::int64_t cappedPhaseDeadline(std::int64_t nowMs,
                                            std::int64_t operationDeadlineMs,
                                            std::int64_t phaseCapMs)
    {
        if (operationDeadlineMs <= 0 || phaseCapMs <= 0) {
            return 0;
        }
        const std::int64_t maximum = (std::numeric_limits<std::int64_t>::max)();
        const std::int64_t capped = phaseCapMs > maximum - nowMs
                ? maximum : nowMs + phaseCapMs;
        return (std::min)(operationDeadlineMs, capped);
    }

    enum class WriteState {
        Progress,
        Retry,
        Failure,
    };

    inline WriteState classifyWriteResult(int result, int sshAgain)
    {
        if (result > 0) {
            return WriteState::Progress;
        }
        if (result == 0 || result == sshAgain) {
            return WriteState::Retry;
        }
        return WriteState::Failure;
    }

    inline std::uint32_t boundedWriteSize(std::uint32_t remoteWindow,
                                          std::uint32_t pendingBytes,
                                          std::uint32_t maximumChunk)
    {
        // Parenthesized calls are immune to the legacy Windows min macro when
        // this header follows windows.h in an application translation unit.
        return (std::min)(remoteWindow, (std::min)(pendingBytes, maximumChunk));
    }

    enum class ExitState {
        Pending,
        Success,
        Failure,
        MissingStatus,
    };

    inline ExitState exitState(bool remoteEof,
                               bool remoteClosed,
                               bool stdoutDrained,
                               bool stderrDrained,
                               bool exitStatusReceived,
                               int exitStatus)
    {
        if ((!remoteEof && !remoteClosed) || !stdoutDrained || !stderrDrained) {
            return ExitState::Pending;
        }
        if (!exitStatusReceived) {
            return remoteClosed ? ExitState::MissingStatus : ExitState::Pending;
        }
        return exitStatus == 0 ? ExitState::Success : ExitState::Failure;
    }

    enum class TeardownMode {
        Graceful,
        AbortTransport,
    };

    inline TeardownMode teardownMode(BoundaryState boundary)
    {
        return boundary == BoundaryState::Ready
                ? TeardownMode::Graceful : TeardownMode::AbortTransport;
    }

    inline QString uploadReceiptPrintCommand()
    {
        // QString::arg() replaces only numbered placeholders. A doubled
        // percent sign is not a printf escape at that layer and would reach
        // the remote shell unchanged, making printf emit the literal "%s".
        return QStringLiteral("printf '%s\\n' \"$receipt\"");
    }
}

#ifndef AMNEZIA_SSH_CLIENT_STATE_ONLY

#include <QFile>
#include <QMutex>
#include <QObject>

#include <atomic>
#include <fcntl.h>
#include <functional>

#include <libssh/libssh.h>

#include "core/utils/commonStructs.h"
#include "core/utils/errorCodes.h"
#include "core/utils/routeModes.h"

using namespace amnezia;

namespace libssh
{
    enum ScpOverwriteMode {
        /*! Overwrite an existing file through verified atomic replacement. */
        ScpOverwriteExisting = O_TRUNC,
        /*! Retained for container-level callers; direct host append is rejected. */
        ScpAppendToExisting = O_APPEND,
    };

    class Client : public QObject
    {
        Q_OBJECT
    public:
        static constexpr int DefaultConnectTimeoutMs = 30 * 1000;
        static constexpr int DefaultChannelOpenTimeoutMs = 30 * 1000;
        static constexpr int DefaultCommandTimeoutMs = 15 * 60 * 1000;
        static constexpr int DefaultScpTimeoutMs = 15 * 60 * 1000;

        Client() = default;
        ~Client() override;

        ErrorCode beginOperation(int timeoutMs);
        ErrorCode finishOperation(ErrorCode result);
        ErrorCode connectToHost(const ServerCredentials &credentials,
                                int timeoutMs = DefaultConnectTimeoutMs);
        void disconnectFromHost();
        ErrorCode executeCommand(const QString &data,
                                 const std::function<ErrorCode(const QString &, Client &)> &cbReadStdOut,
                                 const std::function<ErrorCode(const QString &, Client &)> &cbReadStdErr,
                                 int timeoutMs = DefaultCommandTimeoutMs);
        ErrorCode executeScript(const QString &script,
                                const std::function<ErrorCode(const QString &, Client &)> &cbReadStdOut,
                                const std::function<ErrorCode(const QString &, Client &)> &cbReadStdErr,
                                int timeoutMs = DefaultCommandTimeoutMs);
        ErrorCode writeResponse(const QString &data);
        ErrorCode scpFileCopy(ScpOverwriteMode overwriteMode,
                              const QString &localPath,
                              const QString &remotePath,
                              const QString &fileDesc,
                              int timeoutMs = DefaultScpTimeoutMs);
        void cancelCurrentOperation();
        ErrorCode getDecryptedPrivateKey(
                const ServerCredentials &credentials,
                QString &decryptedPrivateKey,
                const std::function<QString()> &passphraseCallback);

    private:
        ErrorCode ensureOperation(int timeoutMs);
        ErrorCode executeChannel(
                const QByteArray &command,
                const QByteArray &standardInput,
                const QString &standardInputFilePath,
                bool sendEofAfterInput,
                const std::function<ErrorCode(const QString &, Client &)> &cbReadStdOut,
                const std::function<ErrorCode(const QString &, Client &)> &cbReadStdErr,
                int timeoutMs);
        static qint64 monotonicNowMs();
        qint64 cappedPhaseDeadlineMs(int timeoutMs) const;
        ErrorCode boundaryError(qint64 phaseDeadlineMs = 0) const;
        int remainingTimeoutMs(qint64 phaseDeadlineMs = 0) const;
        void waitForProgress(qint64 phaseDeadlineMs = 0) const;
        ErrorCode resolveHostName(const QString &hostName,
                                  QString &numericHost,
                                  qint64 phaseDeadlineMs);
        bool prepareNonBlockingSession(qint64 phaseDeadlineMs = 0);
        bool setSessionTimeout(qint64 phaseDeadlineMs = 0);
        ErrorCode closeChannel(qint64 phaseDeadlineMs = 0);
        void abortSession();
        ErrorCode fromLibsshErrorCode();
        ErrorCode fromFileErrorCode(QFileDevice::FileError fileError);
        static int callback(const char *prompt,
                            char *buf,
                            size_t len,
                            int echo,
                            int verify,
                            void *userdata);

        ssh_session m_session = nullptr;
        ssh_channel m_channel = nullptr;
        ServerCredentials m_credentials;
        std::atomic_bool m_cancelRequested { false };
        std::atomic<qint64> m_operationDeadlineMs { 0 };
        QMutex m_pendingResponseMutex;
        QByteArray m_pendingResponse;

    signals:
        void writeToChannelFinished();
        void scpFileCopyFinished();
    };
}

#endif // AMNEZIA_SSH_CLIENT_STATE_ONLY
#endif // SSHCLIENT_H
