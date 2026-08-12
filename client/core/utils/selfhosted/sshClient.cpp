#include "sshClient.h"

#include "sshHostKeyPin.h"

#include <QCryptographicHash>
#include <QDir>
#include <QEventLoop>
#include <QFileInfo>
#include <QHostAddress>
#include <QHostInfo>
#include <QTemporaryFile>
#include <QThread>
#include <QTimer>
#include <QUuid>

#include <libssh/callbacks.h>

#include <chrono>
#include <cstring>
#include <limits>

#ifdef Q_OS_WINDOWS
#include <io.h>
#else
#include <unistd.h>
#endif

namespace
{
    ErrorCode hostKeyPinResolutionError(amnezia::sshHostKeyPin::Error error)
    {
        switch (error) {
        case amnezia::sshHostKeyPin::Error::None:
            return ErrorCode::NoError;
        case amnezia::sshHostKeyPin::Error::Missing:
            return ErrorCode::SshHostKeyMissingError;
        case amnezia::sshHostKeyPin::Error::Malformed:
            return ErrorCode::SshHostKeyMalformedError;
        }
        return ErrorCode::SshInternalError;
    }

    ErrorCode verifyServerHostKey(ssh_session session, const QString &expectedFingerprint)
    {
        ssh_key serverKey = nullptr;
        unsigned char *hash = nullptr;
        size_t hashLength = 0;

        if (ssh_get_server_publickey(session, &serverKey) != SSH_OK || serverKey == nullptr) {
            if (serverKey != nullptr) {
                ssh_key_free(serverKey);
            }
            return ErrorCode::SshInternalError;
        }
        const int hashResult = ssh_get_publickey_hash(
                serverKey, SSH_PUBLICKEY_HASH_SHA256, &hash, &hashLength);
        ssh_key_free(serverKey);

        const bool hashRead = hashResult == SSH_OK && hash != nullptr && hashLength == 32;
        bool matches = false;
        if (hashRead) {
            const QByteArray actualDigest(reinterpret_cast<const char *>(hash), 32);
            matches = amnezia::sshHostKeyPin::matchesFingerprint(expectedFingerprint, actualDigest);
        }
        if (hash != nullptr) {
            ssh_clean_pubkey_hash(&hash);
        }

        if (!hashRead) {
            return ErrorCode::SshInternalError;
        }
        return matches ? ErrorCode::NoError : ErrorCode::SshHostKeyMismatchError;
    }

    struct ChannelCallbackState
    {
        bool remoteEof = false;
        bool remoteClosed = false;
        bool exitStatusReceived = false;
        int exitStatus = -1;
        std::uint32_t writableBytes = 0;
    };

    void channelEofCallback(ssh_session, ssh_channel, void *userdata)
    {
        static_cast<ChannelCallbackState *>(userdata)->remoteEof = true;
    }

    void channelCloseCallback(ssh_session, ssh_channel, void *userdata)
    {
        static_cast<ChannelCallbackState *>(userdata)->remoteClosed = true;
    }

    void channelExitStatusCallback(ssh_session, ssh_channel, int exitStatus, void *userdata)
    {
        auto *state = static_cast<ChannelCallbackState *>(userdata);
        state->exitStatusReceived = true;
        state->exitStatus = exitStatus;
    }

    int channelWriteWontBlockCallback(ssh_session,
                                      ssh_channel,
                                      std::uint32_t bytes,
                                      void *userdata)
    {
        static_cast<ChannelCallbackState *>(userdata)->writableBytes = bytes;
        return 0;
    }
}

namespace libssh
{
    constexpr auto libsshTimeoutError = "Timeout connecting to";
    constexpr int kProgressPollMs = 2;
    constexpr std::uint32_t kMaximumWriteChunk = 2048;
    constexpr qsizetype kMaximumReceiptBytes = 512;

    Client::~Client()
    {
        disconnectFromHost();
    }

    qint64 Client::monotonicNowMs()
    {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::steady_clock::now().time_since_epoch())
                .count();
    }

    ErrorCode Client::beginOperation(int timeoutMs)
    {
        if (timeoutMs <= 0) {
            return ErrorCode::SshTimeoutError;
        }
        if (m_operationDeadlineMs.load(std::memory_order_acquire) != 0) {
            return ErrorCode::SshInternalError;
        }

        // A completed operation never lends a connection or cancellation bit
        // to the next one.  The deadline is established exactly once here and
        // is reused by DNS, connect, auth, channel I/O, exit handling and close.
        abortSession();
        m_credentials = {};
        m_cancelRequested.store(false, std::memory_order_release);
        {
            QMutexLocker locker(&m_pendingResponseMutex);
            m_pendingResponse.clear();
        }

        const qint64 nowMs = monotonicNowMs();
        const qint64 maximum = std::numeric_limits<qint64>::max();
        const qint64 deadlineMs = timeoutMs > maximum - nowMs
                ? maximum : nowMs + static_cast<qint64>(timeoutMs);
        m_operationDeadlineMs.store(deadlineMs, std::memory_order_release);
        return ErrorCode::NoError;
    }

    ErrorCode Client::ensureOperation(int timeoutMs)
    {
        if (m_operationDeadlineMs.load(std::memory_order_acquire) == 0) {
            return beginOperation(timeoutMs);
        }
        return boundaryError();
    }

    ErrorCode Client::finishOperation(ErrorCode result)
    {
        if (m_channel != nullptr) {
            const ErrorCode closeError = closeChannel();
            if (result == ErrorCode::NoError) {
                result = closeError;
            }
        }
        if (result == ErrorCode::NoError) {
            result = boundaryError();
        }

        // ssh_silent_disconnect closes the socket before libssh disposes its
        // channel list.  This prevents ssh_channel_free()/ssh_free() from
        // performing a hidden graceful close after timeout or cancellation.
        abortSession();
        m_credentials = {};
        {
            QMutexLocker locker(&m_pendingResponseMutex);
            m_pendingResponse.clear();
        }
        m_operationDeadlineMs.store(0, std::memory_order_release);
        return result;
    }

    qint64 Client::cappedPhaseDeadlineMs(int timeoutMs) const
    {
        return detail::cappedPhaseDeadline(
                monotonicNowMs(),
                m_operationDeadlineMs.load(std::memory_order_acquire),
                timeoutMs);
    }

    ErrorCode Client::boundaryError(qint64 phaseDeadlineMs) const
    {
        const qint64 operationDeadline =
                m_operationDeadlineMs.load(std::memory_order_acquire);
        const qint64 effectiveDeadline = phaseDeadlineMs > 0
                ? qMin(operationDeadline, phaseDeadlineMs) : operationDeadline;
        const auto state = detail::boundaryState(
                monotonicNowMs(),
                effectiveDeadline,
                m_cancelRequested.load(std::memory_order_acquire));
        switch (state) {
        case detail::BoundaryState::Ready:
            return ErrorCode::NoError;
        case detail::BoundaryState::Cancelled:
            return ErrorCode::SshInterruptedError;
        case detail::BoundaryState::TimedOut:
            return ErrorCode::SshTimeoutError;
        }
        return ErrorCode::SshInternalError;
    }

    int Client::remainingTimeoutMs(qint64 phaseDeadlineMs) const
    {
        const qint64 operationDeadline =
                m_operationDeadlineMs.load(std::memory_order_acquire);
        const qint64 effectiveDeadline = phaseDeadlineMs > 0
                ? qMin(operationDeadline, phaseDeadlineMs) : operationDeadline;
        const qint64 remaining = effectiveDeadline - monotonicNowMs();
        if (remaining <= 0) {
            return 0;
        }
        return static_cast<int>(qMin<qint64>(remaining, std::numeric_limits<int>::max()));
    }

    void Client::waitForProgress(qint64 phaseDeadlineMs) const
    {
        const int remainingMs = remainingTimeoutMs(phaseDeadlineMs);
        if (remainingMs > 0) {
            QThread::msleep(static_cast<unsigned long>(qMin(kProgressPollMs, remainingMs)));
        }
    }

    ErrorCode Client::resolveHostName(const QString &hostName,
                                      QString &numericHost,
                                      qint64 phaseDeadlineMs)
    {
        QString lookupName = hostName.trimmed();
        if (lookupName.startsWith(u'[') && lookupName.endsWith(u']')) {
            lookupName = lookupName.mid(1, lookupName.size() - 2);
        }
        if (lookupName.isEmpty()) {
            return ErrorCode::SshInternalError;
        }

        QHostAddress literalAddress;
        if (literalAddress.setAddress(lookupName)) {
            numericHost = literalAddress.toString();
            return boundaryError(phaseDeadlineMs);
        }

        QEventLoop loop;
        QObject callbackContext;
        QTimer wakeTimer;
        wakeTimer.setSingleShot(true);
        QObject::connect(&wakeTimer, &QTimer::timeout, &loop, &QEventLoop::quit);

        bool completed = false;
        QHostInfo resolved;
        const int lookupId = QHostInfo::lookupHost(
                lookupName,
                &callbackContext,
                [&completed, &resolved, &loop](const QHostInfo &result) {
                    resolved = result;
                    completed = true;
                    loop.quit();
                });
        if (lookupId < 0) {
            return ErrorCode::SshInternalError;
        }

        while (!completed) {
            const ErrorCode boundary = boundaryError(phaseDeadlineMs);
            if (boundary != ErrorCode::NoError) {
                QHostInfo::abortHostLookup(lookupId);
                return boundary;
            }
            wakeTimer.start(qMin(kProgressPollMs, remainingTimeoutMs(phaseDeadlineMs)));
            loop.exec(QEventLoop::ExcludeUserInputEvents);
        }

        const ErrorCode boundary = boundaryError(phaseDeadlineMs);
        if (boundary != ErrorCode::NoError) {
            return boundary;
        }
        if (resolved.error() != QHostInfo::NoError || resolved.addresses().isEmpty()) {
            qWarning() << "SSH hostname resolution failed" << lookupName << resolved.errorString();
            return ErrorCode::SshInternalError;
        }

        for (const QHostAddress &address : resolved.addresses()) {
            if (address.protocol() == QAbstractSocket::IPv4Protocol
                || address.protocol() == QAbstractSocket::IPv6Protocol) {
                numericHost = address.toString();
                break;
            }
        }
        return numericHost.isEmpty() ? ErrorCode::SshInternalError : ErrorCode::NoError;
    }

    bool Client::setSessionTimeout(qint64 phaseDeadlineMs)
    {
        if (!m_session) {
            return false;
        }
        const int remainingMs = remainingTimeoutMs(phaseDeadlineMs);
        if (remainingMs <= 0) {
            return false;
        }
        long timeoutSeconds = remainingMs / 1000;
        long timeoutMicroseconds = (remainingMs % 1000) * 1000L;
        if (timeoutSeconds == 0 && timeoutMicroseconds == 0) {
            timeoutMicroseconds = 1000;
        }
        return ssh_options_set(m_session, SSH_OPTIONS_TIMEOUT, &timeoutSeconds) == SSH_OK
                && ssh_options_set(m_session, SSH_OPTIONS_TIMEOUT_USEC, &timeoutMicroseconds) == SSH_OK;
    }

    bool Client::prepareNonBlockingSession(qint64 phaseDeadlineMs)
    {
        if (!setSessionTimeout(phaseDeadlineMs)) {
            return false;
        }
        ssh_set_blocking(m_session, 0);
        return ssh_is_blocking(m_session) == 0;
    }

    int Client::callback(const char *, char *buf, size_t len, int, int, void *userdata)
    {
        if (!userdata || !buf || len == 0) {
            return -1;
        }
        auto *passphraseCallback = static_cast<std::function<QString()> *>(userdata);
        const QByteArray passphrase = (*passphraseCallback)().toUtf8();
        if (passphrase.size() >= static_cast<qsizetype>(len)) {
            return -1;
        }
        std::memcpy(buf, passphrase.constData(), static_cast<size_t>(passphrase.size()));
        buf[passphrase.size()] = '\0';
        return 0;
    }

    void Client::cancelCurrentOperation()
    {
        m_cancelRequested.store(true, std::memory_order_release);
    }

    ErrorCode Client::connectToHost(const ServerCredentials &credentials, int timeoutMs)
    {
        ErrorCode error = ensureOperation(timeoutMs);
        if (error != ErrorCode::NoError) {
            return error;
        }
        const qint64 connectDeadlineMs =
                cappedPhaseDeadlineMs(qMin(timeoutMs, DefaultConnectTimeoutMs));
        const ErrorCode connectBoundary = boundaryError(connectDeadlineMs);
        if (connectBoundary != ErrorCode::NoError) {
            return connectBoundary;
        }

        const amnezia::sshHostKeyPin::Resolution pinResolution =
                amnezia::sshHostKeyPin::resolve(
                        credentials.hostName, credentials.sshHostKeyFingerprint);
        error = hostKeyPinResolutionError(pinResolution.error);
        if (error != ErrorCode::NoError) {
            return error;
        }
        ServerCredentials effectiveCredentials = credentials;
        effectiveCredentials.sshHostKeyFingerprint = pinResolution.fingerprint;

        if (m_session != nullptr && ssh_is_connected(m_session)) {
            const bool sameEndpoint = m_credentials.hostName == effectiveCredentials.hostName
                    && m_credentials.userName == effectiveCredentials.userName
                    && m_credentials.secretData == effectiveCredentials.secretData
                    && m_credentials.sshHostKeyFingerprint == effectiveCredentials.sshHostKeyFingerprint
                    && m_credentials.port == effectiveCredentials.port;
            if (sameEndpoint) {
                return boundaryError(connectDeadlineMs);
            }
            abortSession();
        } else if (m_session != nullptr) {
            abortSession();
        }

        m_credentials = effectiveCredentials;
        QString numericHost;
        error = resolveHostName(effectiveCredentials.hostName, numericHost, connectDeadlineMs);
        if (error != ErrorCode::NoError) {
            abortSession();
            return error;
        }

        m_session = ssh_new();
        if (!m_session) {
            return ErrorCode::SshInternalError;
        }

        int port = effectiveCredentials.port;
        int logVerbosity = SSH_LOG_NOLOG;
        const QByteArray host = numericHost.toUtf8();
        const QByteArray username = effectiveCredentials.userName.toUtf8();
        if (ssh_options_set(m_session, SSH_OPTIONS_HOST, host.constData()) != SSH_OK
            || ssh_options_set(m_session, SSH_OPTIONS_PORT, &port) != SSH_OK
            || ssh_options_set(m_session, SSH_OPTIONS_USER, username.constData()) != SSH_OK
            || ssh_options_set(m_session, SSH_OPTIONS_LOG_VERBOSITY, &logVerbosity) != SSH_OK
            || !prepareNonBlockingSession(connectDeadlineMs)) {
            abortSession();
            return boundaryError(connectDeadlineMs) == ErrorCode::NoError
                    ? ErrorCode::SshInternalError : boundaryError(connectDeadlineMs);
        }

        while (true) {
            error = boundaryError(connectDeadlineMs);
            if (error != ErrorCode::NoError) {
                abortSession();
                return error;
            }
            setSessionTimeout(connectDeadlineMs);
            const int connectionResult = ssh_connect(m_session);
            error = boundaryError(connectDeadlineMs);
            if (error != ErrorCode::NoError) {
                abortSession();
                return error;
            }
            if (connectionResult == SSH_OK) {
                break;
            }
            if (connectionResult != SSH_AGAIN) {
                error = fromLibsshErrorCode();
                abortSession();
                return error == ErrorCode::NoError ? ErrorCode::SshInternalError : error;
            }
            waitForProgress(connectDeadlineMs);
        }

        error = boundaryError(connectDeadlineMs);
        if (error == ErrorCode::NoError) {
            error = verifyServerHostKey(m_session, effectiveCredentials.sshHostKeyFingerprint);
        }
        if (error != ErrorCode::NoError) {
            abortSession();
            return error;
        }

        if (!prepareNonBlockingSession(connectDeadlineMs)) {
            error = boundaryError(connectDeadlineMs);
            abortSession();
            return error == ErrorCode::NoError ? ErrorCode::SshInternalError : error;
        }

        const std::string authUsername = effectiveCredentials.userName.toStdString();
        const auto runAuthOperation = [this, connectDeadlineMs](
                                              const std::function<int()> &operation) {
            int result = SSH_AUTH_AGAIN;
            while (result == SSH_AUTH_AGAIN) {
                if (boundaryError(connectDeadlineMs) != ErrorCode::NoError) {
                    return result;
                }
                setSessionTimeout(connectDeadlineMs);
                result = operation();
                if (result == SSH_AUTH_AGAIN
                    && boundaryError(connectDeadlineMs) == ErrorCode::NoError) {
                    waitForProgress(connectDeadlineMs);
                }
            }
            return result;
        };

        int authResult = SSH_AUTH_ERROR;
        if (effectiveCredentials.secretData.contains("BEGIN")
            && effectiveCredentials.secretData.contains("PRIVATE KEY")) {
            ssh_key privateKey = nullptr;
            ssh_key publicKey = nullptr;
            authResult = ssh_pki_import_privkey_base64(
                    effectiveCredentials.secretData.toUtf8().constData(),
                    nullptr,
                    nullptr,
                    nullptr,
                    &privateKey);
            if (authResult == SSH_OK) {
                authResult = ssh_pki_export_privkey_to_pubkey(privateKey, &publicKey);
            }
            if (authResult == SSH_OK
                && boundaryError(connectDeadlineMs) == ErrorCode::NoError) {
                authResult = runAuthOperation([this, &authUsername, publicKey]() {
                    return ssh_userauth_try_publickey(m_session, authUsername.c_str(), publicKey);
                });
            }
            if (authResult == SSH_AUTH_SUCCESS
                && boundaryError(connectDeadlineMs) == ErrorCode::NoError) {
                authResult = runAuthOperation([this, &authUsername, privateKey]() {
                    return ssh_userauth_publickey(m_session, authUsername.c_str(), privateKey);
                });
            }
            if (publicKey) {
                ssh_key_free(publicKey);
            }
            if (privateKey) {
                ssh_key_free(privateKey);
            }

            error = boundaryError(connectDeadlineMs);
            if (error != ErrorCode::NoError) {
                abortSession();
                return error;
            }
            if (authResult != SSH_AUTH_SUCCESS) {
                error = fromLibsshErrorCode();
                abortSession();
                return error == ErrorCode::NoError
                        ? ErrorCode::SshPrivateKeyFormatError : error;
            }
        } else {
            const std::string password = effectiveCredentials.secretData.toStdString();
            authResult = runAuthOperation([this, &authUsername, &password]() {
                return ssh_userauth_password(m_session, authUsername.c_str(), password.c_str());
            });
            error = boundaryError(connectDeadlineMs);
            if (error != ErrorCode::NoError) {
                abortSession();
                return error;
            }
            if (authResult != SSH_AUTH_SUCCESS) {
                error = fromLibsshErrorCode();
                abortSession();
                return error == ErrorCode::NoError
                        ? ErrorCode::SshRequestDeniedError : error;
            }
        }

        return ErrorCode::NoError;
    }

    void Client::abortSession()
    {
        if (m_session) {
            ssh_silent_disconnect(m_session);
            m_channel = nullptr;
            ssh_free(m_session);
            m_session = nullptr;
        } else {
            m_channel = nullptr;
        }
    }

    void Client::disconnectFromHost()
    {
        m_cancelRequested.store(true, std::memory_order_release);
        abortSession();
        m_credentials = {};
        m_operationDeadlineMs.store(0, std::memory_order_release);
    }

    ErrorCode Client::executeCommand(
            const QString &data,
            const std::function<ErrorCode(const QString &, Client &)> &cbReadStdOut,
            const std::function<ErrorCode(const QString &, Client &)> &cbReadStdErr,
            int timeoutMs)
    {
        return executeChannel(data.toUtf8(), {}, {}, false,
                              cbReadStdOut, cbReadStdErr, timeoutMs);
    }

    ErrorCode Client::executeScript(
            const QString &script,
            const std::function<ErrorCode(const QString &, Client &)> &cbReadStdOut,
            const std::function<ErrorCode(const QString &, Client &)> &cbReadStdErr,
            int timeoutMs)
    {
        QByteArray scriptBytes = script.toUtf8();
        if (!scriptBytes.endsWith('\n')) {
            scriptBytes.append('\n');
        }
        return executeChannel(QByteArrayLiteral("sh -s --"), scriptBytes, {}, true,
                              cbReadStdOut, cbReadStdErr, timeoutMs);
    }

    ErrorCode Client::executeChannel(
            const QByteArray &command,
            const QByteArray &standardInput,
            const QString &standardInputFilePath,
            bool sendEofAfterInput,
            const std::function<ErrorCode(const QString &, Client &)> &cbReadStdOut,
            const std::function<ErrorCode(const QString &, Client &)> &cbReadStdErr,
            int timeoutMs)
    {
        ErrorCode error = ensureOperation(timeoutMs);
        if (error != ErrorCode::NoError) {
            return error;
        }
        const qint64 commandDeadlineMs = cappedPhaseDeadlineMs(timeoutMs);
        const qint64 openDeadlineMs = qMin(
                commandDeadlineMs,
                cappedPhaseDeadlineMs(DefaultChannelOpenTimeoutMs));
        if (!m_session || !ssh_is_connected(m_session)
            || command.isEmpty() || command.contains('\0')) {
            return ErrorCode::SshInternalError;
        }
        if (!prepareNonBlockingSession(commandDeadlineMs)) {
            return boundaryError(commandDeadlineMs) == ErrorCode::NoError
                    ? ErrorCode::SshInternalError : boundaryError(commandDeadlineMs);
        }

        ChannelCallbackState callbackState;
        ssh_channel_callbacks_struct callbacks {};
        callbacks.userdata = &callbackState;
        callbacks.channel_eof_function = channelEofCallback;
        callbacks.channel_close_function = channelCloseCallback;
        callbacks.channel_exit_status_function = channelExitStatusCallback;
        callbacks.channel_write_wontblock_function = channelWriteWontBlockCallback;
        ssh_callbacks_init(&callbacks);

        const auto finishChannel = [this, commandDeadlineMs](ErrorCode result) {
            const ErrorCode closeError = closeChannel(commandDeadlineMs);
            return result == ErrorCode::NoError ? closeError : result;
        };
        const auto transportFailure = [this, &finishChannel]() {
            ErrorCode result = fromLibsshErrorCode();
            if (result == ErrorCode::NoError) {
                result = ErrorCode::SshInternalError;
            }
            return finishChannel(result);
        };

        error = boundaryError(openDeadlineMs);
        if (error != ErrorCode::NoError) {
            return error;
        }
        m_channel = ssh_channel_new(m_session);
        if (!m_channel) {
            return transportFailure();
        }
        if (ssh_set_channel_callbacks(m_channel, &callbacks) != SSH_OK) {
            return transportFailure();
        }

        while (true) {
            error = boundaryError(openDeadlineMs);
            if (error != ErrorCode::NoError) {
                return finishChannel(error);
            }
            const int openResult = ssh_channel_open_session(m_channel);
            error = boundaryError(openDeadlineMs);
            if (error != ErrorCode::NoError) {
                return finishChannel(error);
            }
            if (openResult == SSH_OK && ssh_channel_is_open(m_channel)) {
                break;
            }
            if (openResult != SSH_AGAIN) {
                return transportFailure();
            }
            waitForProgress(openDeadlineMs);
        }

        while (true) {
            error = boundaryError(openDeadlineMs);
            if (error != ErrorCode::NoError) {
                return finishChannel(error);
            }
            const int requestResult = ssh_channel_request_exec(m_channel, command.constData());
            error = boundaryError(openDeadlineMs);
            if (error != ErrorCode::NoError) {
                return finishChannel(error);
            }
            if (requestResult == SSH_OK) {
                break;
            }
            if (requestResult != SSH_AGAIN) {
                return transportFailure();
            }
            waitForProgress(openDeadlineMs);
        }

        QFile standardInputFile;
        const bool hasStandardInputFile = !standardInputFilePath.isEmpty();
        if (hasStandardInputFile) {
            standardInputFile.setFileName(standardInputFilePath);
            if (!standardInputFile.open(QIODevice::ReadOnly)) {
                return finishChannel(fromFileErrorCode(standardInputFile.error()));
            }
        }

        qsizetype inputOffset = 0;
        QByteArray fileInputChunk;
        qsizetype fileInputOffset = 0;
        bool fileInputComplete = !hasStandardInputFile;
        bool eofSent = false;
        bool stderrFirst = false;
        bool terminalObserved = false;
        bool stdoutDrained = false;
        bool stderrDrained = false;
        char stdoutBuffer[4096];
        char stderrBuffer[4096];

        const auto readOneChunk = [this,
                                   commandDeadlineMs,
                                   &cbReadStdOut,
                                   &cbReadStdErr,
                                   &terminalObserved](
                                           bool standardError,
                                           char *buffer,
                                           bool &readData,
                                           bool &streamDrained) {
            ErrorCode readBoundary = boundaryError(commandDeadlineMs);
            if (readBoundary != ErrorCode::NoError) {
                return readBoundary;
            }
            const int bytesRead = ssh_channel_read_nonblocking(
                    m_channel, buffer, 4096, standardError ? 1 : 0);
            readBoundary = boundaryError(commandDeadlineMs);
            if (readBoundary != ErrorCode::NoError) {
                return readBoundary;
            }
            if (bytesRead == SSH_AGAIN || bytesRead == SSH_EOF || bytesRead == 0) {
                if (terminalObserved) {
                    streamDrained = true;
                }
                return ErrorCode::NoError;
            }
            if (bytesRead < 0) {
                ErrorCode readError = fromLibsshErrorCode();
                return readError == ErrorCode::NoError
                        ? ErrorCode::SshInternalError : readError;
            }
            readData = true;
            streamDrained = false;
            const auto &readCallback = standardError ? cbReadStdErr : cbReadStdOut;
            if (readCallback) {
                const ErrorCode callbackError = readCallback(
                        QString::fromUtf8(buffer, bytesRead), *this);
                if (callbackError != ErrorCode::NoError) {
                    return callbackError;
                }
            }
            return boundaryError(commandDeadlineMs);
        };

        while (true) {
            error = boundaryError(commandDeadlineMs);
            if (error != ErrorCode::NoError) {
                return finishChannel(error);
            }

            bool stdoutRead = false;
            bool stderrRead = false;
            ErrorCode readError = ErrorCode::NoError;
            if (stderrFirst) {
                readError = readOneChunk(true, stderrBuffer, stderrRead, stderrDrained);
                if (readError == ErrorCode::NoError) {
                    readError = readOneChunk(false, stdoutBuffer, stdoutRead, stdoutDrained);
                }
            } else {
                readError = readOneChunk(false, stdoutBuffer, stdoutRead, stdoutDrained);
                if (readError == ErrorCode::NoError) {
                    readError = readOneChunk(true, stderrBuffer, stderrRead, stderrDrained);
                }
            }
            stderrFirst = !stderrFirst;
            if (readError != ErrorCode::NoError) {
                return finishChannel(readError);
            }
            bool madeProgress = stdoutRead || stderrRead;

            QByteArray pendingChunk;
            const char *inputData = nullptr;
            qsizetype pendingInputSize = 0;
            bool writingScript = false;
            bool writingFile = false;
            if (inputOffset < standardInput.size()) {
                writingScript = true;
                inputData = standardInput.constData() + inputOffset;
                pendingInputSize = standardInput.size() - inputOffset;
            } else if (!fileInputComplete) {
                if (fileInputOffset >= fileInputChunk.size()) {
                    error = boundaryError(commandDeadlineMs);
                    if (error != ErrorCode::NoError) {
                        return finishChannel(error);
                    }
                    fileInputChunk = standardInputFile.read(16 * 1024);
                    error = boundaryError(commandDeadlineMs);
                    if (error != ErrorCode::NoError) {
                        return finishChannel(error);
                    }
                    fileInputOffset = 0;
                    if (fileInputChunk.isEmpty()) {
                        if (standardInputFile.error() != QFileDevice::NoError) {
                            return finishChannel(fromFileErrorCode(standardInputFile.error()));
                        }
                        fileInputComplete = true;
                    }
                }
                if (!fileInputComplete) {
                    writingFile = true;
                    inputData = fileInputChunk.constData() + fileInputOffset;
                    pendingInputSize = fileInputChunk.size() - fileInputOffset;
                }
            } else {
                QMutexLocker locker(&m_pendingResponseMutex);
                if (!m_pendingResponse.isEmpty()) {
                    pendingChunk = m_pendingResponse.left(kMaximumWriteChunk);
                    inputData = pendingChunk.constData();
                    pendingInputSize = pendingChunk.size();
                }
            }

            if (pendingInputSize > 0) {
                const auto pendingBytes = static_cast<std::uint32_t>(
                        qMin<qsizetype>(pendingInputSize,
                                        std::numeric_limits<std::uint32_t>::max()));
                const std::uint32_t remoteWindow = ssh_channel_window_size(m_channel);
                const std::uint32_t attemptSize = detail::boundedWriteSize(
                        remoteWindow, pendingBytes, kMaximumWriteChunk);
                if (attemptSize > 0) {
                    callbackState.writableBytes = 0;
                    const int bytesWritten = ssh_channel_write(m_channel, inputData, attemptSize);
                    error = boundaryError(commandDeadlineMs);
                    if (error != ErrorCode::NoError) {
                        return finishChannel(error);
                    }
                    switch (detail::classifyWriteResult(bytesWritten, SSH_AGAIN)) {
                    case detail::WriteState::Progress:
                        if (writingScript) {
                            inputOffset += bytesWritten;
                        } else if (writingFile) {
                            fileInputOffset += bytesWritten;
                        } else {
                            QMutexLocker locker(&m_pendingResponseMutex);
                            m_pendingResponse.remove(0, bytesWritten);
                        }
                        madeProgress = true;
                        break;
                    case detail::WriteState::Retry:
                        break;
                    case detail::WriteState::Failure:
                        return transportFailure();
                    }
                }
            }

            if (sendEofAfterInput && !eofSent
                && inputOffset == standardInput.size() && fileInputComplete) {
                bool hasPendingResponse = false;
                {
                    QMutexLocker locker(&m_pendingResponseMutex);
                    hasPendingResponse = !m_pendingResponse.isEmpty();
                }
                if (!hasPendingResponse) {
                    const int eofResult = ssh_channel_send_eof(m_channel);
                    error = boundaryError(commandDeadlineMs);
                    if (error != ErrorCode::NoError) {
                        return finishChannel(error);
                    }
                    if (eofResult == SSH_OK) {
                        eofSent = true;
                        madeProgress = true;
                    } else if (eofResult != SSH_AGAIN) {
                        return transportFailure();
                    }
                }
            }

            const bool remoteEof = ssh_channel_is_eof(m_channel) != 0;
            const bool remoteClosed = callbackState.remoteClosed
                    || ssh_channel_is_closed(m_channel) != 0;
            terminalObserved = remoteEof || remoteClosed;
            switch (detail::exitState(remoteEof,
                                      remoteClosed,
                                      stdoutDrained,
                                      stderrDrained,
                                      callbackState.exitStatusReceived,
                                      callbackState.exitStatus)) {
            case detail::ExitState::Pending:
                break;
            case detail::ExitState::Success:
                return finishChannel(ErrorCode::NoError);
            case detail::ExitState::Failure:
                qWarning() << "SSH command failed with exit status"
                           << callbackState.exitStatus << command;
                return finishChannel(ErrorCode::ServerCheckFailed);
            case detail::ExitState::MissingStatus:
                qWarning() << "SSH command closed without a verified exit status" << command;
                return finishChannel(ErrorCode::ServerCheckFailed);
            }

            if (!madeProgress) {
                waitForProgress(commandDeadlineMs);
            }
        }
    }

    ErrorCode Client::writeResponse(const QString &data)
    {
        if (!m_channel) {
            return ErrorCode::SshInternalError;
        }
        const ErrorCode error = boundaryError();
        if (error != ErrorCode::NoError) {
            return error;
        }
        QByteArray response = data.toUtf8();
        response.append('\n');
        QMutexLocker locker(&m_pendingResponseMutex);
        m_pendingResponse.append(response);
        return ErrorCode::NoError;
    }

    ErrorCode Client::closeChannel(qint64 phaseDeadlineMs)
    {
        if (!m_channel) {
            return ErrorCode::NoError;
        }

        while (true) {
            const ErrorCode boundary = boundaryError(phaseDeadlineMs);
            const qint64 operationDeadline =
                    m_operationDeadlineMs.load(std::memory_order_acquire);
            const qint64 effectiveDeadline = phaseDeadlineMs > 0
                    ? qMin(operationDeadline, phaseDeadlineMs) : operationDeadline;
            const auto boundaryState = detail::boundaryState(
                    monotonicNowMs(),
                    effectiveDeadline,
                    m_cancelRequested.load(std::memory_order_acquire));
            if (detail::teardownMode(boundaryState) == detail::TeardownMode::AbortTransport) {
                abortSession();
                return boundary;
            }

            const int closeResult = ssh_channel_close(m_channel);
            const ErrorCode afterCallBoundary = boundaryError(phaseDeadlineMs);
            if (afterCallBoundary != ErrorCode::NoError) {
                abortSession();
                return afterCallBoundary;
            }
            if (closeResult == SSH_OK) {
                ssh_channel_free(m_channel);
                m_channel = nullptr;
                return ErrorCode::NoError;
            }
            if (closeResult != SSH_AGAIN) {
                ErrorCode result = fromLibsshErrorCode();
                abortSession();
                return result == ErrorCode::NoError ? ErrorCode::SshInternalError : result;
            }
            waitForProgress(phaseDeadlineMs);
        }
    }

    ErrorCode Client::scpFileCopy(ScpOverwriteMode overwriteMode,
                                  const QString &localPath,
                                  const QString &remotePath,
                                  const QString &fileDesc,
                                  int timeoutMs)
    {
        Q_UNUSED(fileDesc);
        ErrorCode error = ensureOperation(timeoutMs);
        if (error != ErrorCode::NoError) {
            return error;
        }
        if (overwriteMode != ScpOverwriteExisting) {
            // Direct host append has no atomic or reconcilable completion
            // protocol. Container append callers upload an overwrite snapshot
            // to a private host temp file and append inside the container.
            return ErrorCode::NotImplementedError;
        }
        if (remotePath.isEmpty() || remotePath.contains(QChar::Null)
            || remotePath.contains(u'\r') || remotePath.contains(u'\n')) {
            return ErrorCode::ReadError;
        }

        QFile source(localPath);
        if (!source.open(QIODevice::ReadOnly) || !QFileInfo(source).isFile()) {
            return source.isOpen() ? ErrorCode::ReadError : fromFileErrorCode(source.error());
        }

        QTemporaryFile snapshot(
                QDir::tempPath() + QStringLiteral("/amnezia-upload-snapshot-XXXXXX"));
        snapshot.setAutoRemove(true);
        if (!snapshot.open()) {
            return fromFileErrorCode(snapshot.error());
        }

        QCryptographicHash snapshotHash(QCryptographicHash::Sha256);
        qint64 snapshotSize = 0;
        while (!source.atEnd()) {
            error = boundaryError();
            if (error != ErrorCode::NoError) {
                return error;
            }
            const QByteArray chunk = source.read(64 * 1024);
            if (chunk.isEmpty()) {
                if (source.error() != QFileDevice::NoError) {
                    return fromFileErrorCode(source.error());
                }
                break;
            }
            snapshotHash.addData(chunk);
            qsizetype written = 0;
            while (written < chunk.size()) {
                const qint64 writeResult = snapshot.write(
                        chunk.constData() + written, chunk.size() - written);
                if (writeResult <= 0) {
                    return fromFileErrorCode(snapshot.error());
                }
                written += writeResult;
            }
            snapshotSize += chunk.size();
        }
        error = boundaryError();
        if (error != ErrorCode::NoError) {
            return error;
        }
        if (!snapshot.flush()) {
            return fromFileErrorCode(snapshot.error());
        }
#ifdef Q_OS_WINDOWS
        if (_commit(snapshot.handle()) != 0) {
            return ErrorCode::FatalError;
        }
#else
        if (::fsync(snapshot.handle()) != 0) {
            return ErrorCode::FatalError;
        }
#endif
        error = boundaryError();
        if (error != ErrorCode::NoError) {
            return error;
        }
        const QString snapshotPath = snapshot.fileName();
        if (!snapshot.setPermissions(QFileDevice::ReadOwner)) {
            return ErrorCode::PermissionsError;
        }
        snapshot.close();
        const QByteArray expectedSha256 = snapshotHash.result().toHex();
        const QByteArray expectedReceipt = QByteArrayLiteral("AMNEZIA_UPLOAD_V1\t")
                + QByteArray::number(snapshotSize) + '\t' + expectedSha256 + '\n';

        const auto shellQuote = [](QString value) {
            value.replace(u'\'', QStringLiteral("'\"'\"'"));
            return QStringLiteral("'") + value + QStringLiteral("'");
        };
        const QString uploadSuffix = QUuid::createUuid().toString(QUuid::WithoutBraces);
        const QString temporaryPath = remotePath + QStringLiteral(".amnezia-upload.") + uploadSuffix;
        const QString receiptText = QString::fromLatin1(expectedReceipt.chopped(1));
        const QString command = (QStringLiteral(
                "upload_target=%1; upload_tmp=%2; expected_size=%3; expected_sha=%4; receipt=%5; "
                "upload_parent=${upload_target%/*}; "
                "if test -z \"$upload_parent\"; then upload_parent=/; "
                "elif test \"$upload_parent\" = \"$upload_target\"; then upload_parent=.; fi; "
                "durable_sync() { sync_path=$1; "
                 "if command -v sync >/dev/null 2>&1 && sync --help 2>&1 | grep -q -- '-f'; then "
                 "sync -f -- \"$sync_path\" || exit 74; return; fi; "
                 "if command -v fsync >/dev/null 2>&1; then "
                 "fsync \"$sync_path\" || exit 74; return; fi; "
                 "exit 69; }; "
                "cleanup_upload() { rm -f -- \"$upload_tmp\"; }; "
                "umask 077; trap cleanup_upload EXIT HUP INT TERM; "
                "command -v sha256sum >/dev/null 2>&1 || exit 69; "
                "cat > \"$upload_tmp\" || exit 74; "
                "actual_size=$(wc -c < \"$upload_tmp\") || exit 74; "
                "test \"$actual_size\" = \"$expected_size\" || exit 65; "
                "actual_sha=$(sha256sum -- \"$upload_tmp\" | awk '{print $1}') || exit 74; "
                "test \"$actual_sha\" = \"$expected_sha\" || exit 65; "
                "chmod 0600 -- \"$upload_tmp\" || exit 73; "
                "durable_sync \"$upload_tmp\"; "
                "mv -fT -- \"$upload_tmp\" \"$upload_target\" || exit 73; "
                "trap - EXIT HUP INT TERM; durable_sync \"$upload_parent\"; ")
                                        + detail::uploadReceiptPrintCommand())
                                        .arg(shellQuote(remotePath),
                                             shellQuote(temporaryPath),
                                             QString::number(snapshotSize),
                                             QString::fromLatin1(expectedSha256),
                                             shellQuote(receiptText));

        QByteArray receiptOutput;
        QString receiptError;
        const auto captureReceipt = [&receiptOutput](const QString &data, Client &) {
            const QByteArray bytes = data.toUtf8();
            if (receiptOutput.size() + bytes.size() > kMaximumReceiptBytes) {
                return ErrorCode::ReadError;
            }
            receiptOutput += bytes;
            return ErrorCode::NoError;
        };
        const auto captureReceiptError = [&receiptError](const QString &data, Client &) {
            if (receiptError.size() < kMaximumReceiptBytes) {
                receiptError += data.left(kMaximumReceiptBytes - receiptError.size());
            }
            return ErrorCode::NoError;
        };

        const ErrorCode uploadError = executeChannel(
                command.toUtf8(), {}, snapshotPath, true,
                captureReceipt, captureReceiptError, timeoutMs);
        error = boundaryError();
        if (error != ErrorCode::NoError) {
            return error;
        }
        if (receiptOutput == expectedReceipt) {
            return ErrorCode::NoError;
        }

        // The atomic rename may have completed while its stdout/exit ACK was
        // lost. Reconnect under the same absolute deadline and reconcile the
        // exact target bytes; never resend or append the payload.
        const ServerCredentials reconnectCredentials = m_credentials;
        abortSession();
        error = boundaryError();
        if (error != ErrorCode::NoError) {
            return error;
        }
        error = connectToHost(reconnectCredentials, timeoutMs);
        if (error != ErrorCode::NoError) {
            const ErrorCode reconciliationBoundary = boundaryError();
            if (reconciliationBoundary != ErrorCode::NoError) {
                return reconciliationBoundary;
            }
            return uploadError == ErrorCode::NoError ? error : uploadError;
        }

        receiptOutput.clear();
        receiptError.clear();
        const QString reconcileCommand = (QStringLiteral(
                "upload_target=%1; expected_size=%2; expected_sha=%3; receipt=%4; "
                "upload_parent=${upload_target%/*}; "
                "if test -z \"$upload_parent\"; then upload_parent=/; "
                "elif test \"$upload_parent\" = \"$upload_target\"; then upload_parent=.; fi; "
                "test -d \"$upload_parent\" && ! test -L \"$upload_parent\" || exit 65; "
                "durable_sync() { sync_path=$1; "
                 "if command -v sync >/dev/null 2>&1 && sync --help 2>&1 | grep -q -- '-f'; then "
                 "sync -f -- \"$sync_path\" || exit 74; return; fi; "
                 "if command -v fsync >/dev/null 2>&1; then "
                 "fsync \"$sync_path\" || exit 74; return; fi; "
                 "exit 69; }; "
                "command -v sha256sum >/dev/null 2>&1 || exit 69; "
                "test -f \"$upload_target\" && ! test -L \"$upload_target\" || exit 65; "
                "test \"$(wc -c < \"$upload_target\")\" = \"$expected_size\" || exit 65; "
                "test \"$(sha256sum -- \"$upload_target\" | awk '{print $1}')\" = \"$expected_sha\" || exit 65; "
                "durable_sync \"$upload_parent\"; ")
                                                 + detail::uploadReceiptPrintCommand())
                                                 .arg(shellQuote(remotePath),
                                                      QString::number(snapshotSize),
                                                      QString::fromLatin1(expectedSha256),
                                                      shellQuote(receiptText));
        const ErrorCode reconcileError = executeChannel(
                reconcileCommand.toUtf8(), {}, {}, false,
                captureReceipt, captureReceiptError, timeoutMs);
        error = boundaryError();
        if (error != ErrorCode::NoError) {
            return error;
        }
        if (receiptOutput == expectedReceipt) {
            return ErrorCode::NoError;
        }
        qWarning() << "SSH upload receipt reconciliation failed"
                   << remotePath << receiptError.trimmed();
        if (uploadError != ErrorCode::NoError) {
            return uploadError;
        }
        return reconcileError == ErrorCode::NoError
                ? ErrorCode::SshScpFailureError : reconcileError;
    }

    ErrorCode Client::fromLibsshErrorCode()
    {
        if (!m_session) {
            return ErrorCode::SshInternalError;
        }
        const int errorCode = ssh_get_error_code(m_session);
        if (errorCode != SSH_NO_ERROR) {
            const QString errorMessage = QString::fromUtf8(ssh_get_error(m_session));
            qCritical() << errorMessage;
            if (errorMessage.contains(QString::fromLatin1(libsshTimeoutError))) {
                return ErrorCode::SshTimeoutError;
            }
        }

        switch (errorCode) {
        case SSH_NO_ERROR:
            return ErrorCode::NoError;
        case SSH_REQUEST_DENIED:
            return ErrorCode::SshRequestDeniedError;
        case SSH_EINTR:
            return ErrorCode::SshInterruptedError;
        case SSH_FATAL:
            return ErrorCode::SshInternalError;
        default:
            return ErrorCode::SshInternalError;
        }
    }

    ErrorCode Client::fromFileErrorCode(QFileDevice::FileError fileError)
    {
        switch (fileError) {
        case QFileDevice::NoError:
            return ErrorCode::NoError;
        case QFileDevice::ReadError:
            return ErrorCode::ReadError;
        case QFileDevice::OpenError:
            return ErrorCode::OpenError;
        case QFileDevice::PermissionsError:
            return ErrorCode::PermissionsError;
        case QFileDevice::FatalError:
            return ErrorCode::FatalError;
        case QFileDevice::AbortError:
            return ErrorCode::AbortError;
        default:
            return ErrorCode::UnspecifiedError;
        }
    }

    ErrorCode Client::getDecryptedPrivateKey(
            const ServerCredentials &credentials,
            QString &decryptedPrivateKey,
            const std::function<QString()> &passphraseCallback)
    {
        ssh_key privateKey = nullptr;
        std::function<QString()> callbackCopy = passphraseCallback;
        int result = ssh_pki_import_privkey_base64(
                credentials.secretData.toUtf8().constData(),
                nullptr,
                callback,
                &callbackCopy,
                &privateKey);
        if (result != SSH_OK) {
            return ErrorCode::SshPrivateKeyError;
        }

        char *base64 = nullptr;
        result = ssh_pki_export_privkey_base64(privateKey, nullptr, nullptr, nullptr, &base64);
        if (result == SSH_OK && base64) {
            decryptedPrivateKey = QString::fromLatin1(base64);
        }
        if (base64) {
            ssh_string_free_char(base64);
        }
        ssh_key_free(privateKey);
        return result == SSH_OK ? ErrorCode::NoError : ErrorCode::InternalError;
    }
}
