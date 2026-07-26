#include "amneziaApplication.h"

#include <QClipboard>
#include <QCryptographicHash>
#include <QDateTime>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QFileInfo>
#include <QFontDatabase>
#include <QHostAddress>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonParseError>
#include <QLocalServer>
#include <QLocalSocket>
#include <QLockFile>
#include <QMimeData>
#include <QPointer>
#include <QQuickItem>
#include <QQuickStyle>
#include <QRegularExpression>
#include <QResource>
#include <QSemaphore>
#include <QStandardPaths>
#include <QTextDocument>
#include <QTimer>
#include <QTranslator>
#include <QUrl>
#include <QEvent>
#include <QDir>
#include <QSettings>
#include <QtQuick/QQuickWindow>  
#include <QWindow>     

#include "core/controllers/selfhosted/selfHostedUpdateBootstrapper.h"
#include "core/repositories/secureAppSettingsRepository.h"
#include "core/repositories/secureServersRepository.h"
#include "core/protocols/qmlRegisterProtocols.h"
#include "core/utils/containers/containerUtils.h"
#include "core/utils/constants/configKeys.h"
#include "core/utils/constants/protocolConstants.h"
#include "core/utils/managedRoutePolicy.h"
#include "core/utils/routeRuleMatcher.h"
#ifdef AMNEZIA_DESKTOP
    #include "core/utils/ipcClient.h"
#endif
#include "../ipc/localpeerauthentication.h"
#include "../ipc/windowsprivilegedpipe.h"
#include "logger.h"
#include "ui/controllers/qml/pageController.h"
#include "ui/models/installedAppsModel.h"
#include "version.h"

#include "platforms/ios/QRCodeReaderBase.h"

#include <cstdio>
#include <utility>

#ifdef Q_OS_WIN
    #include <Windows.h>
#endif

namespace
{
constexpr auto operatorServerBaseName = "AmneziaVPNInstance";
constexpr auto coreOwnershipLockBaseName = "AmneziaVPNCoreOwnership";
constexpr auto sharedSettingsOwnershipIdentity = "AmneziaVPN-QSettings-Core-v1";
constexpr int operatorConnectRetryWindowMs = 1500;
constexpr int operatorConnectAttemptMs = 200;
constexpr int operatorConnectRetryDelayMs = 75;
constexpr int operatorResponseTimeoutMs = 15000;
constexpr int ordinaryLaunchAcknowledgementTimeoutMs = 2000;
constexpr int operatorSnapshotSyncTimeoutMs = 750;
constexpr int operatorDisconnectCompletionTimeoutMs =
        operatorResponseTimeoutMs - (2 * operatorSnapshotSyncTimeoutMs) - 1000;
constexpr int operatorWatchIntervalMs = 1000;
constexpr int operatorWatchConnectTimeoutMs = 1500;
constexpr int operatorWatchResponseTimeoutMs = 3000;
constexpr int operatorSnapshotRefreshIntervalMs = 1000;
constexpr int operatorSnapshotStaleAfterMs = 3000;
constexpr int vpnWorkerShutdownTimeoutMs = 8000;
constexpr int operatorMaximumActiveClients = 16;
constexpr qsizetype operatorMaximumIdentifierOutputLength = 1024;
constexpr qsizetype operatorMaximumMatchedValueOutputLength = 2048;
constexpr qsizetype operatorMaximumHumanFieldLength = 256;
static_assert(operatorMaximumMatchedValueOutputLength
              == routeRuleMatcher::maximumMatchedValueLength);

void writeConsole(FILE *stream, const QString &text)
{
    QByteArray data = text.toUtf8();
    if (!data.endsWith('\n')) {
        data.append('\n');
    }
#ifdef Q_OS_WIN
    const DWORD standardHandle = stream == stderr ? STD_ERROR_HANDLE : STD_OUTPUT_HANDLE;
    HANDLE handle = GetStdHandle(standardHandle);
    if (handle == nullptr || handle == INVALID_HANDLE_VALUE) {
        // The desktop binary uses the Windows GUI subsystem. Attach only when
        // no inherited/redirected standard handle exists, so pipes continue to
        // receive exact JSON output.
        AttachConsole(ATTACH_PARENT_PROCESS);
        handle = GetStdHandle(standardHandle);
    }
    if (handle != nullptr && handle != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        if (WriteFile(handle, data.constData(), static_cast<DWORD>(data.size()), &written, nullptr)
            && written == static_cast<DWORD>(data.size())) {
            return;
        }
    }
#endif
    std::fwrite(data.constData(), 1, static_cast<size_t>(data.size()), stream);
    std::fflush(stream);
}

#if !defined(Q_OS_ANDROID) && !defined(Q_OS_IOS) && !defined(MACOS_NE)
enum class OperatorPeerRole {
    Server,
    Client,
};

bool operatorPeerIsTrusted(QLocalSocket *socket, OperatorPeerRole role,
                           qint64 *peerProcessId = nullptr, QString *error = nullptr)
{
#ifdef Q_OS_WIN
    if (!amnezia::ipc::isWindowsPrivilegedPipeSocket(socket)) {
        if (error) {
            *error = QStringLiteral(
                    "Local operator peer identity verification requires the hardened local pipe transport.");
        }
        return false;
    }
#endif
    amnezia::ipc::LocalPeerIdentity identity;
    QString identityError;
    const bool identityRead = role == OperatorPeerRole::Server
            ? amnezia::ipc::queryLocalServerIdentity(socket, identity, &identityError)
            : amnezia::ipc::queryLocalPeerIdentity(socket, identity, &identityError);
    const QString currentUser = amnezia::ipc::currentProcessUserIdentifier(&identityError);
    const QString currentExecutable = amnezia::ipc::canonicalExecutablePath(
            QCoreApplication::applicationFilePath());
    const bool trusted = identityRead && identity.isValid()
            && !currentUser.isEmpty() && identity.userIdentifier == currentUser
            && amnezia::ipc::executablePathsMatch(identity.executablePath, currentExecutable);
    if (trusted && peerProcessId) {
        *peerProcessId = identity.processId;
    }
    if (error) {
        *error = trusted ? QString()
                         : QStringLiteral("Local operator peer identity verification failed: %1")
                                   .arg(identityError.isEmpty()
                                                ? QStringLiteral("identity mismatch") : identityError);
    }
    return trusted;
}

bool connectOperatorSocket(QLocalSocket *socket, const QString &serverName,
                           int timeoutMs, QString *error = nullptr)
{
#ifdef Q_OS_WIN
    return amnezia::ipc::connectWindowsPrivilegedPipe(
            socket, serverName, timeoutMs, error);
#else
    socket->connectToServer(serverName, QIODevice::ReadWrite);
    const bool connected = socket->waitForConnected(timeoutMs);
    if (!connected && error) {
        *error = socket->errorString();
    }
    return connected;
#endif
}

bool requestPrimaryWindowRaise(QLocalSocket *socket, QString *error = nullptr)
{
    if (!socket || socket->state() != QLocalSocket::ConnectedState) {
        if (error) {
            *error = QStringLiteral("The primary-instance connection is not open.");
        }
        return false;
    }

    const amnezia::operatorMode::CommandRequest request {
        amnezia::operatorMode::CommandType::Raise,
        false,
        QString(),
    };
    QByteArray payload = QJsonDocument(request.toJson()).toJson(QJsonDocument::Compact);
    payload.append('\n');
    if (amnezia::operatorMode::wireFrameState(payload)
            != amnezia::operatorMode::WireFrameState::Complete
        || socket->write(payload) != payload.size()) {
        if (error) {
            *error = QStringLiteral("Failed to send the authenticated window-raise request.");
        }
        return false;
    }
    socket->flush();

    QElapsedTimer timer;
    timer.start();
    while (!socket->canReadLine()
           && timer.elapsed() < ordinaryLaunchAcknowledgementTimeoutMs) {
        if (socket->bytesAvailable() > amnezia::operatorMode::MaximumWireFrameSize) {
            break;
        }
        const int remaining = ordinaryLaunchAcknowledgementTimeoutMs
                - static_cast<int>(timer.elapsed());
        if (remaining <= 0 || !socket->waitForReadyRead(remaining)) {
            break;
        }
    }

    if (!socket->canReadLine()
        || socket->bytesAvailable() > amnezia::operatorMode::MaximumWireFrameSize) {
        if (error) {
            *error = QStringLiteral("The running instance did not acknowledge the window-raise request.");
        }
        return false;
    }

    const QByteArray responseLine = socket->readLine(
            amnezia::operatorMode::MaximumWireFrameSize + 1).trimmed();
    QJsonParseError parseError;
    const QJsonDocument responseDocument = QJsonDocument::fromJson(responseLine, &parseError);
    amnezia::operatorMode::CommandResponse response;
    QString responseError;
    const bool acknowledged = parseError.error == QJsonParseError::NoError
            && responseDocument.isObject()
            && amnezia::operatorMode::CommandResponse::fromJson(
                    responseDocument.object(), &response, &responseError)
            && response.exitCode == 0
            && response.result.value(QStringLiteral("schema")).toString()
                    == QStringLiteral("amnezia.operator.raise.v1")
            && response.result.value(QStringLiteral("ok")).toBool(false);
    if (!acknowledged && error) {
        *error = QStringLiteral("The running instance returned an invalid window-raise acknowledgement.");
    }
    return acknowledged;
}
#endif

#if !defined(Q_OS_ANDROID) && !defined(Q_OS_IOS)
QString coreOwnershipLockName()
{
    // Core/update state is stored in one per-user QSettings namespace, even
    // when the same executable is launched from different paths. Its ownership
    // lock must therefore be settings-global rather than executable-scoped.
    // The containing AppConfigLocation is already per-user, so this name does
    // not depend on desktop IPC support (MACOS_NE intentionally has none).
    const QByteArray digest = QCryptographicHash::hash(
            QByteArray(sharedSettingsOwnershipIdentity), QCryptographicHash::Sha256).toHex();
    return QStringLiteral("%1-%2")
            .arg(QString::fromLatin1(coreOwnershipLockBaseName),
                 QString::fromLatin1(digest.left(32)));
}

QString coreOwnershipDirectoryPath()
{
    // Keep the authoritative lock beside the per-user application config,
    // whose namespace follows the same XDG/config-root selection as QSettings.
    // RuntimeLocation and TempLocation are process-environment-dependent and
    // can differ while both processes still address the same settings store.
    const QString appConfigPath =
            QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation);
    if (appConfigPath.isEmpty() || !QDir::isAbsolutePath(appConfigPath)) {
        return {};
    }

    const QString ownershipDirectory = QDir::cleanPath(
            QDir(appConfigPath).filePath(QStringLiteral(".instance")));
    QFileInfo directoryInfo(ownershipDirectory);
    if ((directoryInfo.exists() && (!directoryInfo.isDir() || directoryInfo.isSymLink()))
        || !QDir().mkpath(ownershipDirectory)) {
        return {};
    }

#ifndef Q_OS_WIN
    // The namespace contains process metadata written by QLockFile and must
    // not be writable or searchable by another local account.
    const QFileDevice::Permissions ownerOnlyPermissions =
            QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner;
    if (!QFile::setPermissions(ownershipDirectory, ownerOnlyPermissions)) {
        return {};
    }
    directoryInfo.refresh();
    const QFileDevice::Permissions nonOwnerPermissions =
            QFileDevice::ReadGroup | QFileDevice::WriteGroup | QFileDevice::ExeGroup
            | QFileDevice::ReadOther | QFileDevice::WriteOther | QFileDevice::ExeOther;
    if (!directoryInfo.isDir() || directoryInfo.isSymLink()
        || (directoryInfo.permissions() & nonOwnerPermissions)
                != QFileDevice::Permissions()) {
        return {};
    }
#endif

    return directoryInfo.absoluteFilePath();
}
#endif

QString connectionStateName(Vpn::ConnectionState state)
{
    switch (state) {
    case Vpn::ConnectionState::Unknown:
        return QStringLiteral("unknown");
    case Vpn::ConnectionState::Disconnected:
        return QStringLiteral("disconnected");
    case Vpn::ConnectionState::Preparing:
        return QStringLiteral("preparing");
    case Vpn::ConnectionState::Connecting:
        return QStringLiteral("connecting");
    case Vpn::ConnectionState::Connected:
        return QStringLiteral("connected");
    case Vpn::ConnectionState::Disconnecting:
        return QStringLiteral("disconnecting");
    case Vpn::ConnectionState::Reconnecting:
        return QStringLiteral("reconnecting");
    case Vpn::ConnectionState::Error:
        return QStringLiteral("error");
    }
    return QStringLiteral("unknown");
}

QString routeModeName(amnezia::RouteMode mode)
{
    switch (mode) {
    case amnezia::RouteMode::VpnAllSites:
        return QStringLiteral("vpn_all_sites");
    case amnezia::RouteMode::VpnOnlyForwardSites:
        return QStringLiteral("vpn_only_listed_sites");
    case amnezia::RouteMode::VpnAllExceptSites:
        return QStringLiteral("vpn_except_listed_sites");
    }
    return QStringLiteral("unknown");
}

bool isWritableLocation(const QString &path)
{
    if (path.isEmpty()) {
        return false;
    }

    QFileInfo info(path);
    if (info.exists()) {
        return info.isWritable();
    }

    QDir parent = info.dir();
    while (!parent.exists() && parent.cdUp()) {
    }
    return parent.exists() && QFileInfo(parent.absolutePath()).isWritable();
}

QString boundedOperatorField(const QString &value, qsizetype maximumLength,
                             bool *truncated = nullptr)
{
    const bool wasTruncated = value.size() > maximumLength;
    if (truncated) {
        *truncated = wasTruncated;
    }
    return wasTruncated ? value.left(maximumLength) + QStringLiteral("...") : value;
}

QString terminalSafeOperatorField(const QString &value)
{
    QString safe = boundedOperatorField(value, operatorMaximumHumanFieldLength);
    for (QChar &character : safe) {
        const QChar::Category category = character.category();
        if (character.unicode() == 0x7f || category == QChar::Other_Control
            || category == QChar::Other_Format || category == QChar::Other_Surrogate
            || category == QChar::Other_PrivateUse || category == QChar::Other_NotAssigned
            || category == QChar::Separator_Line || category == QChar::Separator_Paragraph) {
            character = QLatin1Char('?');
        }
    }
    return safe;
}

struct OperatorServerView {
    int count = 0;
    int index = -1;
    QString id;
    QJsonObject config;
};

OperatorServerView readOperatorServerView(SecureQSettings *settings, int preferredIndex = -1)
{
    OperatorServerView view;
    if (!settings) {
        return view;
    }

    // Use the same validated/deduplicated repository view as the runtime. Raw
    // settings may contain invalid or duplicate records that are intentionally
    // ignored by SecureServersRepository.
    SecureServersRepository repository(settings, nullptr, false);
    view.count = repository.serversCount();
    if (view.count == 0) {
        return view;
    }

    int index = preferredIndex;
    if (index < 0 || index >= view.count) {
        index = repository.defaultServerIndex();
    }
    if (index < 0 || index >= view.count) {
        index = 0;
    }

    view.index = index;
    view.id = repository.serverIdAt(index);
    view.config = repository.serverJson(index);
    return view;
}

struct OperatorVpnSnapshot {
    bool available = false;
    Vpn::ConnectionState connectionState = Vpn::ConnectionState::Unknown;
    int serverIndex = -1;
    QString serverId;
    DockerContainer container = DockerContainer::None;
    RouteMode appliedSiteRouteMode = RouteMode::VpnAllSites;
    quint64 connectionEpoch = 0;
    QString remoteAddress;
    QString serverRoutingRulesSyncHost;
    QString vpnGateway;
    VpnConnection::ManagedRouteRuntimeSnapshot managedRouteSnapshot;
    int lastError = static_cast<int>(ErrorCode::NoError);
};

OperatorVpnSnapshot captureVpnSnapshot(VpnConnection *vpnConnection)
{
    OperatorVpnSnapshot snapshot;
    if (!vpnConnection) {
        return snapshot;
    }
    snapshot.connectionState = vpnConnection->connectionState();
    snapshot.serverIndex = vpnConnection->serverIndex();
    snapshot.serverId = vpnConnection->serverId();
    snapshot.container = vpnConnection->container();
    snapshot.appliedSiteRouteMode = vpnConnection->appliedSiteRouteMode();
    snapshot.connectionEpoch = vpnConnection->connectionEpoch();
    snapshot.managedRouteSnapshot = vpnConnection->managedRouteRuntimeSnapshot();
    snapshot.remoteAddress = vpnConnection->remoteAddress();
    snapshot.serverRoutingRulesSyncHost = vpnConnection->serverRoutingRulesSyncHost();
    const QSharedPointer<VpnProtocol> protocol = vpnConnection->vpnProtocol();
    if (protocol) {
        snapshot.vpnGateway = protocol->vpnGateway();
    }
    if (snapshot.connectionState == Vpn::ConnectionState::Error) {
        snapshot.lastError = static_cast<int>(vpnConnection->lastError());
    }
    snapshot.available = true;
    return snapshot;
}

OperatorVpnSnapshot readVpnSnapshot(const QSharedPointer<VpnConnection> &vpnConnection)
{
    if (!vpnConnection) {
        return {};
    }

    struct PendingSnapshot {
        OperatorVpnSnapshot value;
        QSemaphore ready;
    };
    const auto pending = QSharedPointer<PendingSnapshot>::create();
    const QPointer<VpnConnection> guardedVpnConnection(vpnConnection.get());
    const bool invoked = QMetaObject::invokeMethod(guardedVpnConnection,
        [guardedVpnConnection, pending]() {
            if (!guardedVpnConnection) {
                pending->ready.release();
                return;
            }
            pending->value = captureVpnSnapshot(guardedVpnConnection);
            pending->ready.release();
        }, Qt::QueuedConnection);
    if (!invoked || !pending->ready.tryAcquire(1, operatorSnapshotSyncTimeoutMs)) {
        return {};
    }
    return pending->value;
}

#if !defined(Q_OS_ANDROID) && !defined(Q_OS_IOS) && !defined(MACOS_NE)
class OperatorWatchSession final : public QObject
{
public:
    explicit OperatorWatchSession(bool json, QObject *parent)
        : QObject(parent), m_json(json)
    {
        m_pollTimer.setSingleShot(true);
        m_deadlineTimer.setSingleShot(true);
        connect(&m_pollTimer, &QTimer::timeout, this, [this]() { poll(); });
        connect(&m_deadlineTimer, &QTimer::timeout, this, [this]() {
            const bool initialPrimaryUnavailable = !m_requestSent && !m_publishedAny;
            fail(m_requestSent ? QStringLiteral("response_timeout")
                               : (initialPrimaryUnavailable
                                          ? QStringLiteral("primary_unavailable")
                                          : QStringLiteral("primary_lost")),
                 m_requestSent
                         ? QStringLiteral("Timed out waiting for the running Amnezia instance.")
                         : QStringLiteral("Timed out connecting to the running Amnezia instance."),
                 initialPrimaryUnavailable);
        });
    }

    void start()
    {
        m_pollTimer.start(0);
    }

private:
    void resetSocket()
    {
        if (!m_socket) {
            return;
        }
        disconnect(m_socket, nullptr, this, nullptr);
        m_socket->abort();
        m_socket->deleteLater();
        m_socket = nullptr;
    }

    void fail(const QString &reason, const QString &message,
              bool initialPrimaryUnavailable = false)
    {
        if (m_stopping) {
            return;
        }
        m_stopping = true;
        m_pollTimer.stop();
        m_deadlineTimer.stop();
        resetSocket();
        const int exitCode = initialPrimaryUnavailable && !m_publishedAny ? 4 : 5;
        if (m_json) {
            const QByteArray frame = amnezia::operatorMode::watchTerminalFrame(
                    reason, message, exitCode, m_sequence,
                    QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs), m_primaryPid);
            if (!frame.isEmpty()) {
                writeConsole(stdout, QString::fromUtf8(frame));
            } else {
                writeConsole(stderr, message);
            }
        } else {
            writeConsole(stderr, message);
        }
        QCoreApplication::exit(exitCode);
    }

    void publish(const amnezia::operatorMode::CommandResponse &response)
    {
        ++m_sequence;
        if (m_sequence == 0) {
            fail(QStringLiteral("sequence_exhausted"),
                 QStringLiteral("Operator watch sequence exhausted."));
            return;
        }
        const QString observedAt = QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs);
        if (m_json) {
            const QByteArray frame = amnezia::operatorMode::watchSnapshotFrame(
                    response.result, response.exitCode, m_sequence, observedAt, m_primaryPid);
            if (frame.isEmpty()) {
                fail(QStringLiteral("invalid_status"),
                     QStringLiteral("Invalid or oversized status snapshot from the running Amnezia instance."));
                return;
            }
            writeConsole(stdout, QString::fromUtf8(frame));
        } else {
            writeConsole(stdout,
                         QStringLiteral("[%1] status snapshot %2\n%3\n\n")
                                 .arg(observedAt, QString::number(m_sequence), response.humanOutput));
        }

        m_publishedAny = true;
        m_handled = true;
        m_deadlineTimer.stop();
        resetSocket();
        m_connectDeadlineAtMs = 0;
        m_pollTimer.start(operatorWatchIntervalMs);
    }

    bool retryInitialConnection(const QString &failureMessage)
    {
        if (m_publishedAny || m_requestSent) {
            return false;
        }
        const qint64 remaining = m_connectDeadlineAtMs
                - QDateTime::currentMSecsSinceEpoch();
        if (remaining <= 0) {
            fail(QStringLiteral("primary_unavailable"), failureMessage, true);
            return true;
        }
        resetSocket();
        m_pollTimer.start(static_cast<int>(qMin<qint64>(operatorConnectRetryDelayMs, remaining)));
        return true;
    }

    void consumeResponse()
    {
        if (!m_socket || m_handled) {
            return;
        }
        const qsizetype remaining = amnezia::operatorMode::MaximumWireFrameSize + 1
                - m_buffer.size();
        if (remaining > 0) {
            m_buffer.append(m_socket->read(remaining));
        }
        const amnezia::operatorMode::WireFrameState frameState =
                amnezia::operatorMode::wireFrameState(m_buffer);
        if (frameState == amnezia::operatorMode::WireFrameState::TooLarge) {
            fail(QStringLiteral("oversized_response"),
                 QStringLiteral("Oversized status response from the running Amnezia instance."));
            return;
        }
        if (frameState == amnezia::operatorMode::WireFrameState::Incomplete) {
            return;
        }

        const QByteArray line = m_buffer.left(m_buffer.indexOf('\n'));
        QJsonParseError jsonError;
        const QJsonDocument document = QJsonDocument::fromJson(line, &jsonError);
        amnezia::operatorMode::CommandResponse response;
        QString responseError;
        if (jsonError.error != QJsonParseError::NoError || !document.isObject()
            || !amnezia::operatorMode::CommandResponse::fromJson(
                    document.object(), &response, &responseError)
            || response.result.value(QStringLiteral("schema")).toString()
                    != QStringLiteral("amnezia.operator.status.v1")
            || response.result.value(QStringLiteral("pid")).toInteger(-1) != m_primaryPid) {
            fail(QStringLiteral("invalid_status"),
                 QStringLiteral("Invalid status response from the running Amnezia instance."));
            return;
        }
        publish(response);
    }

    void sendRequest()
    {
        if (!m_socket || m_handled) {
            return;
        }
        QString peerError;
        qint64 peerProcessId = -1;
        if (!operatorPeerIsTrusted(m_socket, OperatorPeerRole::Server,
                                   &peerProcessId, &peerError)) {
            fail(QStringLiteral("peer_auth_failed"), peerError);
            return;
        }
        if (m_primaryPid < 0) {
            m_primaryPid = peerProcessId;
        } else if (m_primaryPid != peerProcessId) {
            fail(QStringLiteral("primary_replaced"),
                 QStringLiteral("The watched Amnezia primary instance was replaced."));
            return;
        }

        const amnezia::operatorMode::CommandRequest request {
            amnezia::operatorMode::CommandType::Status,
            false,
            QString(),
        };
        QByteArray payload = QJsonDocument(request.toJson()).toJson(QJsonDocument::Compact);
        payload.append('\n');
        if (amnezia::operatorMode::wireFrameState(payload)
                != amnezia::operatorMode::WireFrameState::Complete
            || m_socket->write(payload) != payload.size()) {
            fail(QStringLiteral("request_failed"),
                 QStringLiteral("Failed to send a watch status request."));
            return;
        }
        m_requestSent = true;
        m_socket->flush();
        m_deadlineTimer.start(operatorWatchResponseTimeoutMs);
    }

    void poll()
    {
        if (m_stopping) {
            return;
        }
        const qint64 now = QDateTime::currentMSecsSinceEpoch();
        if (m_connectDeadlineAtMs == 0) {
            m_connectDeadlineAtMs = now + operatorWatchConnectTimeoutMs;
        } else if (now >= m_connectDeadlineAtMs) {
            fail(m_publishedAny ? QStringLiteral("primary_lost")
                                : QStringLiteral("primary_unavailable"),
                 QStringLiteral("Unable to contact the running Amnezia instance."), !m_publishedAny);
            return;
        }
        const QString serverName = AmneziaApplication::localServerName();
        if (serverName.isEmpty()) {
            fail(QStringLiteral("endpoint_namespace_failed"),
                 QStringLiteral("Unable to establish a private operator endpoint namespace."));
            return;
        }

        resetSocket();
        m_buffer.clear();
        m_handled = false;
        m_requestSent = false;
        QLocalSocket *socket = new QLocalSocket(this);
        m_socket = socket;
        socket->setReadBufferSize(amnezia::operatorMode::MaximumWireFrameSize + 1);
#ifndef Q_OS_WIN
        connect(socket, &QLocalSocket::connected, this, [this]() { sendRequest(); });
#endif
        connect(socket, &QLocalSocket::readyRead, this, [this]() { consumeResponse(); });
        connect(socket, &QLocalSocket::disconnected, this, [this]() {
            if (!m_handled && !m_stopping && m_socket && m_socket->bytesAvailable() > 0) {
                consumeResponse();
            }
            if (!m_handled && !m_stopping) {
                const QString message = QStringLiteral("The running Amnezia instance was lost.");
                if (!retryInitialConnection(message)) {
                    fail(QStringLiteral("primary_lost"), message, false);
                }
            }
        });
        connect(socket, &QLocalSocket::errorOccurred, this,
                [this](QLocalSocket::LocalSocketError) {
            if (!m_handled && !m_stopping) {
                const QString message = QStringLiteral("Unable to contact the running Amnezia instance.");
                if (!retryInitialConnection(message)) {
                    fail(QStringLiteral("primary_lost"), message, false);
                }
            }
        });
        m_deadlineTimer.start(static_cast<int>(qMax<qint64>(
                1, m_connectDeadlineAtMs - QDateTime::currentMSecsSinceEpoch())));
#ifdef Q_OS_WIN
        QString connectionError;
        const int connectionTimeout = static_cast<int>(qMax<qint64>(
                1, qMin<qint64>(operatorConnectAttemptMs,
                                m_connectDeadlineAtMs - QDateTime::currentMSecsSinceEpoch())));
        if (!amnezia::ipc::connectWindowsPrivilegedPipe(
                    socket, serverName, connectionTimeout, &connectionError)) {
            const QString message = QStringLiteral("Unable to contact the running Amnezia instance: %1")
                                            .arg(connectionError);
            if (!retryInitialConnection(message)) {
                fail(QStringLiteral("primary_lost"), message, false);
            }
            return;
        }
        // setSocketDescriptor() adopts an already-connected native pipe and
        // does not provide the asynchronous QLocalSocket::connected contract.
        sendRequest();
#else
        socket->connectToServer(serverName, QIODevice::ReadWrite);
#endif
    }

    const bool m_json;
    bool m_handled = false;
    bool m_requestSent = false;
    bool m_stopping = false;
    bool m_publishedAny = false;
    quint64 m_sequence = 0;
    qint64 m_primaryPid = -1;
    qint64 m_connectDeadlineAtMs = 0;
    QByteArray m_buffer;
    QPointer<QLocalSocket> m_socket;
    QTimer m_pollTimer;
    QTimer m_deadlineTimer;
};
#endif
}

QString AmneziaApplication::localServerName()
{
#if defined(Q_OS_ANDROID) || defined(Q_OS_IOS) || defined(MACOS_NE)
    return {};
#else
    return amnezia::operatorMode::scopedLocalServerName(
            QString::fromLatin1(operatorServerBaseName),
            amnezia::ipc::currentProcessUserIdentifier(),
            amnezia::ipc::canonicalExecutablePath(QCoreApplication::applicationFilePath()));
#endif
}

bool AmneziaApplication::isTrustedPrimaryRunning(int timeoutMs)
{
#if defined(Q_OS_ANDROID) || defined(Q_OS_IOS) || defined(MACOS_NE)
    Q_UNUSED(timeoutMs)
    return false;
#else
    const QString serverName = localServerName();
    if (serverName.isEmpty() || timeoutMs <= 0) {
        return false;
    }
    QLocalSocket socket;
    if (!connectOperatorSocket(&socket, serverName, timeoutMs)
        || !operatorPeerIsTrusted(&socket, OperatorPeerRole::Server)) {
        return false;
    }

    // Keep the Windows pipe alive until the primary has accepted and
    // authenticated this client. Destroying the socket immediately after the
    // server-PID check can make ImpersonateNamedPipeClient fail before the
    // primary sees newConnection(), losing the ordinary second-launch raise.
    QString acknowledgementError;
    const bool acknowledged = requestPrimaryWindowRaise(&socket, &acknowledgementError);
    if (!acknowledged) {
        qWarning() << acknowledgementError;
    }
    return acknowledged;
#endif
}

bool AmneziaApplication::m_forceQuit = false;

AmneziaApplication::AmneziaApplication(
        int &argc, char *argv[],
        const amnezia::operatorMode::CommandParseResult &startupOperatorArguments,
        bool publishBundledUpdatesOnceCommand)
    : AMNEZIA_BASE_CLASS(argc, argv),
      m_optAutostart({QStringLiteral("a"), QStringLiteral("autostart")}, QStringLiteral("System autostart")),
      m_optCleanup  ({QStringLiteral("c"), QStringLiteral("cleanup")}, QStringLiteral("Cleanup logs")),
      m_optConnect  ({QStringLiteral("connect")}, QStringLiteral("Connect to server by index on startup"), QStringLiteral("index")),
      m_optImport   ({QStringLiteral("import")}, QStringLiteral("Import configuration from data string"), QStringLiteral("data")),
      m_optStatus   ({QStringLiteral("status")}, QStringLiteral("Print live VPN status and exit")),
      m_optJson     ({QStringLiteral("json")}, QStringLiteral("Print machine-readable JSON for the selected operator command")),
      m_optDisconnect({QStringLiteral("disconnect")}, QStringLiteral("Disconnect the active VPN tunnel and exit")),
      m_optDoctor   ({QStringLiteral("doctor")}, QStringLiteral("Run local VPN diagnostics and exit")),
      m_optRoutesExplain({QStringLiteral("routes-explain")},
                         QStringLiteral("Explain how a host is routed and exit"), QStringLiteral("host")),
      m_optWatch    ({QStringLiteral("watch")}, QStringLiteral("Stream live VPN status until interrupted")),
      m_optPublishBundledUpdatesOnce({QStringLiteral("publish-bundled-updates-once")},
                                      QStringLiteral("Publish bundled self-hosted update payload once and exit"))
{
    m_startupOperatorArguments = startupOperatorArguments;
    m_operatorCommandLineDetected = startupOperatorArguments.hasOperatorArguments;
    m_publishBundledUpdatesOnceCommand = publishBundledUpdatesOnceCommand;
    // Establish the explicit settings identity before resolving the stable
    // AppConfigLocation used by the settings-global ownership lock.
    setApplicationName(QStringLiteral(APPLICATION_NAME));
    setOrganizationName(QStringLiteral(ORGANIZATION_NAME));
    setDesktopFileName(QStringLiteral(APPLICATION_NAME));
    setQuitOnLastWindowClosed(false);

#if !defined(Q_OS_ANDROID) && !defined(Q_OS_IOS)
    // Acquire the settings-global Core lock before QSettings migrations or any
    // other shared-state access. A race loser stays a lightweight forwarding
    // process and cannot instantiate per-process settings/update caches.
    if (!m_operatorCommandLineDetected && !acquireCoreOwnership()) {
        return;
    }
#endif

    // Fix config file permissions
#if defined(Q_OS_LINUX) && !defined(Q_OS_ANDROID)
    if (!m_operatorCommandLineDetected) {
        QSettings s(ORGANIZATION_NAME, APPLICATION_NAME);
        s.setValue("permFixed", true);

        QString configLoc1 = QStandardPaths::standardLocations(QStandardPaths::ConfigLocation).first() + "/" + ORGANIZATION_NAME + "/"
                + APPLICATION_NAME + ".conf";
        QFile::setPermissions(configLoc1, QFileDevice::ReadOwner | QFileDevice::WriteOwner);

        QString configLoc2 = QStandardPaths::standardLocations(QStandardPaths::ConfigLocation).first() + "/" + ORGANIZATION_NAME + "/"
                + APPLICATION_NAME + "/" + APPLICATION_NAME + ".conf";
        QFile::setPermissions(configLoc2, QFileDevice::ReadOwner | QFileDevice::WriteOwner);
    }
#endif

    m_settings = new SecureQSettings(
            ORGANIZATION_NAME, APPLICATION_NAME, this,
            m_operatorCommandLineDetected ? SecureQSettings::AccessMode::ReadOnly
                                          : SecureQSettings::AccessMode::ReadWrite);
    if (!m_operatorCommandLineDetected) {
        m_nam = new QNetworkAccessManager(this);
    }
}

AmneziaApplication::~AmneziaApplication()
{
    m_operatorSnapshotRefreshTimer.stop();
    bool vpnWorkerShutdownQueued = false;
    QThread *const destructionThread = QThread::currentThread();
    if (m_vpnConnection && m_vpnConnectionThread.isRunning()) {
        bool disconnectVpn = false;
#ifdef AMNEZIA_DESKTOP
        const bool explicitOperatorDisconnect = m_hasOperatorCommand
                && m_operatorCommand.type == amnezia::operatorMode::CommandType::Disconnect;
        disconnectVpn = !m_hasOperatorCommand || explicitOperatorDisconnect;
#endif
        VpnConnection *const vpnConnection = m_vpnConnection.get();
        vpnWorkerShutdownQueued = QMetaObject::invokeMethod(
                vpnConnection,
                [vpnConnection, disconnectVpn, destructionThread]() {
                    vpnConnection->shutdownForApplicationExit(disconnectVpn, destructionThread);
                },
                Qt::QueuedConnection);
    }

    m_vpnConnectionThread.requestInterruption();
    if (!vpnWorkerShutdownQueued) {
        m_vpnConnectionThread.quit();
    }

    if (!m_vpnConnectionThread.wait(vpnWorkerShutdownTimeoutMs)) {
        qFatal("VPN worker did not stop cooperatively; refusing forced termination or live-object destruction");
    }
    if (m_vpnConnection && m_vpnConnection->thread() != destructionThread) {
        qFatal("VPN worker stopped without transferring VpnConnection to its destruction thread");
    }

    // Keep the authoritative lock while controllers, update timers and the VPN
    // worker are torn down. Otherwise a new process could initialize a second
    // Core while this one still owns stale per-process state.
    m_coreController.reset();
    m_vpnConnection.reset();
    m_containerProps.reset();
    m_protocolProps.reset();
    if (m_engine) {
        delete m_engine;
        m_engine = nullptr;
    }
    if (m_nam) {
        delete m_nam;
        m_nam = nullptr;
    }
    if (m_settings) {
        delete m_settings;
        m_settings = nullptr;
    }

#if !defined(Q_OS_ANDROID) && !defined(Q_OS_IOS) && !defined(MACOS_NE)
    if (m_localServer) {
        delete m_localServer;
        m_localServer = nullptr;
    }
#endif
#if !defined(Q_OS_ANDROID) && !defined(Q_OS_IOS)
    m_localServerLock.reset();
#endif
}

#ifdef Q_OS_ANDROID
namespace {
    static void clearQtCaches()
    {
        const QString cacheRoot = QStandardPaths::writableLocation(QStandardPaths::CacheLocation);
        if (!cacheRoot.isEmpty()) {
            QDir(cacheRoot + "/QtShaderCache").removeRecursively();
            QDir(cacheRoot + "/qmlcache").removeRecursively();
        }
    }
}
#endif

void AmneziaApplication::init()
{
    // A local operator invocation must stay genuinely headless. In particular,
    // status/doctor/route inspection only need the encrypted settings store;
    // constructing CoreController would also start QML, update checks, news and
    // the remote-log uploader. A disconnect is forwarded to a running primary;
    // without one we fail closed instead of pretending a fresh worker owns the
    // existing service-side tunnel.
    if (m_hasOperatorCommand) {
        QTimer::singleShot(0, this, &AmneziaApplication::runStartupOperatorCommand);
        return;
    }

    m_engine = new QQmlApplicationEngine;

    const QUrl url(QStringLiteral("qrc:/ui/qml/main2.qml"));
    QObject::connect(
        m_engine, &QQmlApplicationEngine::objectCreated, this,
        [this, url](QObject *obj, const QUrl &objUrl) {
            if (!obj && url == objUrl) {
                QCoreApplication::exit(-1);
                return;
            }
            // install filter on main window
            if (auto win = qobject_cast<QQuickWindow*>(obj)) {
                win->installEventFilter(this);
#ifdef Q_OS_ANDROID
                QObject::connect(win, &QQuickWindow::sceneGraphError,
                    [](QQuickWindow::SceneGraphError, const QString &msg) {
                        qWarning() << "Scene graph error (suppressed):" << msg;
                    });
                // Keep graphics context alive across hide/show cycles to avoid
                // eglSwapBuffers/makeCurrent being called on a context Android has reclaimed.
                win->setPersistentSceneGraph(true);
                win->setPersistentGraphics(true);
#endif
                win->show();
            }
        },
        Qt::QueuedConnection);

    m_engine->rootContext()->setContextProperty("Debug", &Logger::Instance());

#ifdef MACOS_NE
    m_engine->rootContext()->setContextProperty("IsMacOsNeBuild", true);
#else
    m_engine->rootContext()->setContextProperty("IsMacOsNeBuild", false);
#endif

    initVpnConnection();

    m_coreController.reset(new CoreController(m_vpnConnection, m_settings, m_engine));

    m_engine->addImportPath("qrc:/ui/qml/Modules/");

    if (m_parser.isSet(m_optImport)) {
        const QString data = m_parser.value(m_optImport);
        if (!data.isEmpty()) {
            if (m_coreController) {
                m_coreController->importConfigFromData(data);
            }
        }
    }

    m_engine->load(url);

    m_coreController->setQmlRoot();

#ifdef Q_OS_WIN //TODO
    if (m_parser.isSet(m_optAutostart))
        m_coreController->pageController()->showOnStartup();
    else
        emit m_coreController->pageController()->raiseMainWindow();
#else
    m_coreController->pageController()->showOnStartup();
#endif

// Android TextArea clipboard workaround
// Text from TextArea always has "text/html" mime-type:
// /qt/6.6.1/Src/qtdeclarative/src/quick/items/qquicktextcontrol.cpp:1865
// Next, html is created for this mime-type:
// /qt/6.6.1/Src/qtdeclarative/src/quick/items/qquicktextcontrol.cpp:1885
// And this html goes to the Androids clipboard, i.e. text from TextArea is always copied as richText:
// /qt/6.6.1/Src/qtbase/src/plugins/platforms/android/androidjniclipboard.cpp:46
// So we catch all the copies to the clipboard and clear them from "text/html"
#ifdef Q_OS_ANDROID
    connect(QGuiApplication::clipboard(), &QClipboard::dataChanged, []() {
        auto clipboard = QGuiApplication::clipboard();
        if (clipboard->mimeData()->hasHtml()) {
            clipboard->setText(clipboard->text());
        }
    });
#endif

    if (m_parser.isSet(m_optConnect)) {
        bool ok = false;
        int idx = m_parser.value(m_optConnect).toInt(&ok);
        if (ok) {
            QTimer::singleShot(0, this, [this, idx]() {
                if (m_coreController) {
                    m_coreController->openConnectionByIndex(idx);
                }
            });
        }
    }
}

void AmneziaApplication::registerTypes()
{
    if (m_operatorCommandLineDetected) {
        return;
    }

    qRegisterMetaType<ServerCredentials>("ServerCredentials");

    qRegisterMetaType<DockerContainer>("DockerContainer");
    using namespace amnezia::ProtocolEnumNS;
    qRegisterMetaType<TransportProto>("TransportProto");
    qRegisterMetaType<Proto>("Proto");
    qRegisterMetaType<ServiceType>("ServiceType");

    qmlRegisterType<QRCodeReader>("QRCodeReader", 1, 0, "QRCodeReader");

    m_containerProps.reset(new ContainerProps());
    qmlRegisterSingletonInstance("ContainerProps", 1, 0, "ContainerProps", m_containerProps.get());

    m_protocolProps.reset(new ProtocolProps());
    qmlRegisterSingletonInstance("ProtocolProps", 1, 0, "ProtocolProps", m_protocolProps.get());

    qmlRegisterSingletonType(QUrl("qrc:/ui/qml/Filters/ContainersModelFilters.qml"), "ContainersModelFilters", 1, 0,
                             "ContainersModelFilters");

    qmlRegisterType<InstalledAppsModel>("InstalledAppsModel", 1, 0, "InstalledAppsModel");

    amnezia::declareQmlProtocolEnum();
    Vpn::declareQmlVpnConnectionStateEnum();
    PageLoader::declareQmlPageEnum();
}

void AmneziaApplication::loadFonts()
{
    if (m_operatorCommandLineDetected) {
        return;
    }

    QQuickStyle::setStyle("Basic");

    QFontDatabase::addApplicationFont(":/fonts/pt-root-ui_vf.ttf");
}

bool AmneziaApplication::parseCommands()
{
    m_parser.setApplicationDescription(APPLICATION_NAME);
    m_parser.addHelpOption();
    m_parser.addVersionOption();

    m_parser.addOption(m_optAutostart);
    m_parser.addOption(m_optCleanup);
    m_parser.addOption(m_optConnect);
    m_parser.addOption(m_optImport);
    m_parser.addOption(m_optStatus);
    m_parser.addOption(m_optJson);
    m_parser.addOption(m_optDisconnect);
    m_parser.addOption(m_optDoctor);
    m_parser.addOption(m_optRoutesExplain);
    m_parser.addOption(m_optWatch);
    m_parser.addOption(m_optPublishBundledUpdatesOnce);
    
    m_parser.process(*this);

    const int operatorCommandCount = static_cast<int>(m_parser.isSet(m_optStatus))
            + static_cast<int>(m_parser.isSet(m_optDisconnect))
            + static_cast<int>(m_parser.isSet(m_optDoctor))
            + static_cast<int>(m_parser.isSet(m_optRoutesExplain))
            + static_cast<int>(m_parser.isSet(m_optWatch));
    if (m_startupOperatorArguments.hasOperatorArguments
        && !m_startupOperatorArguments.valid) {
        writeConsole(stderr, m_startupOperatorArguments.error);
        m_commandExitCode = 2;
        return false;
    }
    if (!m_startupOperatorArguments.hasOperatorArguments
        && (operatorCommandCount != 0 || m_parser.isSet(m_optJson))) {
        // QApplication may consume option/value pairs before QCommandLineParser
        // runs. Never allow a late classification to enable an operator bypass
        // or turn an early operator invocation into a normal Core startup.
        writeConsole(stderr, QStringLiteral(
                "Command-line mode changed during Qt argument processing; refusing startup."));
        m_commandExitCode = 2;
        return false;
    }

    if (m_startupOperatorArguments.hasOperatorArguments) {
        m_hasOperatorCommand = true;
        m_operatorCommand = m_startupOperatorArguments.request;
        QString validationError;
        m_operatorCommand.isValid(&validationError);
        if (!validationError.isEmpty()) {
            writeConsole(stderr, validationError);
            m_commandExitCode = 2;
            return false;
        }
    }

    if (m_publishBundledUpdatesOnceCommand
        || m_parser.isSet(m_optPublishBundledUpdatesOnce)) {
        Logger::init(false);
        SecureServersRepository serversRepository(m_settings);
        SelfHostedUpdateBootstrapper bootstrapper(&serversRepository);
        const bool ok = bootstrapper.publishNow();
        qInfo().noquote() << QStringLiteral("Bundled self-hosted update publish %1").arg(ok ? QStringLiteral("finished") : QStringLiteral("failed"));
        Logger::deInit();
        m_commandExitCode = ok ? 0 : 2;
        return false;
    }

    if (m_parser.isSet(m_optCleanup)) {
        Logger::cleanUp();
        QTimer::singleShot(100, this, [this] { quit(); });
        exec();
        return false;
    }
    return true;
}

int AmneziaApplication::commandExitCode() const
{
    return m_commandExitCode;
}

void AmneziaApplication::initVpnConnection()
{
    if (m_vpnConnection) {
        return;
    }

    m_vpnConnection.reset(new VpnConnection());
    m_operatorConnectionState = m_vpnConnection->connectionState();
    connect(m_vpnConnection.get(), &VpnConnection::connectionStateChanged, this,
            [this](Vpn::ConnectionState state) {
                m_operatorConnectionState = state;
                ++m_operatorSnapshotGeneration;
                m_operatorSnapshotAvailable = false;
                m_operatorSnapshotLastError = static_cast<int>(ErrorCode::NoError);
                if (state == Vpn::ConnectionState::Disconnected
                    || state == Vpn::ConnectionState::Unknown) {
                    m_operatorReceivedBytes = 0;
                    m_operatorSentBytes = 0;
                }
#ifdef AMNEZIA_DESKTOP
                requestOperatorVpnSnapshotRefresh(true);
#endif
            });
    connect(m_vpnConnection.get(), &VpnConnection::bytesChanged, this,
            [this](quint64 received, quint64 sent) {
                m_operatorReceivedBytes = received;
                m_operatorSentBytes = sent;
            });
    m_vpnConnection->moveToThread(&m_vpnConnectionThread);
    m_vpnConnectionThread.start();
#ifdef AMNEZIA_DESKTOP
    m_operatorSnapshotRefreshTimer.setInterval(operatorSnapshotRefreshIntervalMs);
    m_operatorSnapshotRefreshTimer.setTimerType(Qt::PreciseTimer);
    connect(&m_operatorSnapshotRefreshTimer, &QTimer::timeout, this,
            [this]() { requestOperatorVpnSnapshotRefresh(); });
    m_operatorSnapshotRefreshTimer.start();
    requestOperatorVpnSnapshotRefresh(true);
#endif
}

void AmneziaApplication::requestOperatorVpnSnapshotRefresh(bool force)
{
    if (!m_vpnConnection || !m_vpnConnectionThread.isRunning()
        || m_operatorSnapshotRefreshPending) {
        return;
    }
    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    if (!force && m_operatorSnapshotRequestedAtMs > 0
        && now - m_operatorSnapshotRequestedAtMs < operatorSnapshotRefreshIntervalMs) {
        return;
    }

    m_operatorSnapshotRefreshPending = true;
    m_operatorSnapshotRequestedAtMs = now;
    const quint64 snapshotGeneration = m_operatorSnapshotGeneration;
    const QPointer<VpnConnection> guardedVpnConnection(m_vpnConnection.get());
    const QPointer<AmneziaApplication> guardedApplication(this);
    const bool invoked = QMetaObject::invokeMethod(guardedVpnConnection,
        [guardedVpnConnection, guardedApplication, snapshotGeneration]() {
            const OperatorVpnSnapshot snapshot = captureVpnSnapshot(guardedVpnConnection);
            if (!guardedApplication) {
                return;
            }
            QMetaObject::invokeMethod(guardedApplication,
                [guardedApplication, snapshot, snapshotGeneration]() {
                    if (!guardedApplication) {
                        return;
                    }
                    guardedApplication->m_operatorSnapshotRefreshPending = false;
                    if (snapshotGeneration != guardedApplication->m_operatorSnapshotGeneration) {
                        guardedApplication->requestOperatorVpnSnapshotRefresh(true);
                        return;
                    }
                    if (!snapshot.available) {
                        return;
                    }
                    guardedApplication->m_operatorSnapshotAvailable = true;
                    guardedApplication->m_operatorSnapshotCompletedAtMs =
                            QDateTime::currentMSecsSinceEpoch();
                    guardedApplication->m_operatorConnectionState = snapshot.connectionState;
                    guardedApplication->m_operatorSnapshotServerIndex = snapshot.serverIndex;
                    guardedApplication->m_operatorSnapshotServerId = snapshot.serverId;
                    guardedApplication->m_operatorSnapshotContainer = snapshot.container;
                    guardedApplication->m_operatorSnapshotRouteMode = snapshot.appliedSiteRouteMode;
                    guardedApplication->m_operatorSnapshotRemoteAddress = snapshot.remoteAddress;
                    guardedApplication->m_operatorSnapshotRoutingSyncHost =
                            snapshot.serverRoutingRulesSyncHost;
                    guardedApplication->m_operatorSnapshotVpnGateway = snapshot.vpnGateway;
                    guardedApplication->m_operatorSnapshotLastError = snapshot.lastError;
                    if (snapshot.connectionState == Vpn::ConnectionState::Disconnected
                        || snapshot.connectionState == Vpn::ConnectionState::Unknown) {
                        guardedApplication->m_operatorReceivedBytes = 0;
                        guardedApplication->m_operatorSentBytes = 0;
                    }
                }, Qt::QueuedConnection);
        }, Qt::QueuedConnection);
    if (!invoked) {
        m_operatorSnapshotRefreshPending = false;
    }
}

bool AmneziaApplication::tryForwardOperatorCommand(
        const amnezia::operatorMode::CommandParseResult &parsed, int &exitCode)
{
    if (!parsed.hasOperatorArguments) {
        return false;
    }
    if (!parsed.valid) {
        writeConsole(stderr, parsed.error);
        exitCode = 2;
        return true;
    }
    if (parsed.request.type == amnezia::operatorMode::CommandType::Watch) {
        // Watch owns an event-driven sequence of short status connections. It
        // must enter app.exec() so SIGINT/SIGTERM and socket loss are handled
        // without starting the normal UI/core runtime.
        return false;
    }

#if defined(Q_OS_ANDROID) || defined(Q_OS_IOS) || defined(MACOS_NE)
    Q_UNUSED(exitCode)
    return false;
#else
    const QString serverName = localServerName();
    if (serverName.isEmpty()) {
        writeConsole(stderr, QStringLiteral("Unable to establish a private operator endpoint namespace."));
        exitCode = 5;
        return true;
    }
    QLocalSocket socket;
    socket.setReadBufferSize(amnezia::operatorMode::MaximumWireFrameSize + 1);
    QElapsedTimer connectTimer;
    connectTimer.start();
    bool connected = false;
    do {
        socket.abort();
        const int remaining = operatorConnectRetryWindowMs - static_cast<int>(connectTimer.elapsed());
        QString connectionError;
        connected = remaining > 0
                && connectOperatorSocket(&socket, serverName,
                                         qMin(operatorConnectAttemptMs, remaining),
                                         &connectionError);
        if (connected) {
            break;
        }

#ifndef Q_OS_WIN
        const QLocalSocket::LocalSocketError socketError = socket.error();
        const bool transientError = socketError == QLocalSocket::ServerNotFoundError
                || socketError == QLocalSocket::ConnectionRefusedError
                || socketError == QLocalSocket::SocketTimeoutError;
        if (!transientError) {
            writeConsole(stderr, QStringLiteral("Unable to contact the running Amnezia instance: %1")
                                     .arg(socket.errorString()));
            exitCode = 5;
            return true;
        }
#endif

        const int delay = qMin(operatorConnectRetryDelayMs,
                               operatorConnectRetryWindowMs - static_cast<int>(connectTimer.elapsed()));
        if (delay > 0) {
            QThread::msleep(static_cast<unsigned long>(delay));
        }
    } while (connectTimer.elapsed() < operatorConnectRetryWindowMs);

    if (!connected) {
        // No primary instance became reachable during the bounded startup-race
        // window. Let the normal path execute this command locally.
        return false;
    }

    QString peerError;
    if (!operatorPeerIsTrusted(&socket, OperatorPeerRole::Server, nullptr, &peerError)) {
        writeConsole(stderr, peerError);
        exitCode = 5;
        return true;
    }

    QByteArray request = QJsonDocument(parsed.request.toJson()).toJson(QJsonDocument::Compact);
    request.append('\n');
    if (amnezia::operatorMode::wireFrameState(request)
        != amnezia::operatorMode::WireFrameState::Complete) {
        writeConsole(stderr, QStringLiteral("Operator command exceeds the wire-message limit."));
        exitCode = 2;
        return true;
    }
    if (socket.write(request) != request.size() || !socket.waitForBytesWritten(1000)) {
        writeConsole(stderr, QStringLiteral("Failed to send the operator command to the running Amnezia instance."));
        exitCode = 5;
        return true;
    }

    QElapsedTimer timer;
    timer.start();
    while (!socket.canReadLine() && timer.elapsed() < operatorResponseTimeoutMs) {
        const int remaining = operatorResponseTimeoutMs - static_cast<int>(timer.elapsed());
        if (remaining <= 0 || !socket.waitForReadyRead(remaining)) {
            break;
        }
        if (socket.bytesAvailable() > amnezia::operatorMode::MaximumWireFrameSize) {
            break;
        }
    }

    const QByteArray responseLine = socket.readLine(amnezia::operatorMode::MaximumWireFrameSize + 1);
    if (responseLine.isEmpty()
        || amnezia::operatorMode::wireFrameState(responseLine)
                != amnezia::operatorMode::WireFrameState::Complete) {
        const bool peerClosed = socket.state() == QLocalSocket::UnconnectedState
                || socket.error() == QLocalSocket::PeerClosedError;
        writeConsole(stderr, peerClosed
                        ? QStringLiteral("The running Amnezia instance does not support the operator command protocol; update or restart it.")
                        : QStringLiteral("Timed out waiting for the running Amnezia instance."));
        exitCode = 5;
        return true;
    }

    QJsonParseError jsonError;
    const QJsonDocument document = QJsonDocument::fromJson(responseLine, &jsonError);
    amnezia::operatorMode::CommandResponse response;
    QString responseError;
    if (jsonError.error != QJsonParseError::NoError || !document.isObject()
        || !amnezia::operatorMode::CommandResponse::fromJson(document.object(), &response, &responseError)) {
        if (responseError.isEmpty()) {
            responseError = jsonError.errorString();
        }
        writeConsole(stderr, QStringLiteral("Invalid response from the running Amnezia instance: %1").arg(responseError));
        exitCode = 5;
        return true;
    }

    if (parsed.request.json) {
        writeConsole(stdout, QString::fromUtf8(QJsonDocument(response.result).toJson(QJsonDocument::Compact)));
    } else {
        writeConsole(response.exitCode == 0 ? stdout : stderr, response.humanOutput);
    }
    exitCode = response.exitCode;
    return true;
#endif
}

#if !defined(Q_OS_ANDROID) && !defined(Q_OS_IOS)
bool AmneziaApplication::hasCoreOwnership() const
{
    return m_localServerLock && m_localServerLock->isLocked();
}

bool AmneziaApplication::acquireCoreOwnership()
{
    if (m_localServerLock) {
        return m_localServerLock->isLocked();
    }

    const QString ownershipLockName = coreOwnershipLockName();
    if (ownershipLockName.isEmpty()) {
        qWarning() << "Unable to establish the settings-global Core ownership namespace";
        return false;
    }

    const QString ownershipDirectory = coreOwnershipDirectoryPath();
    if (ownershipDirectory.isEmpty()) {
        qWarning() << "Unable to establish a protected settings-global Core lock directory";
        return false;
    }

    const QString lockPath = QDir(ownershipDirectory).filePath(
            ownershipLockName + QStringLiteral(".lock"));
    m_localServerLock.reset(new QLockFile(lockPath));
    // Never steal ownership merely because startup took longer than Qt's
    // default stale-lock interval. QLockFile may still recover a lock whose
    // recorded owner is provably gone; ambiguous ownership remains fail-closed.
    m_localServerLock->setStaleLockTime(0);
    if (m_localServerLock->tryLock(0)) {
        return true;
    }

    // tryLock() already performs Qt's guarded recovery for a provably dead
    // owner. removeStaleLockFile() is a forceful/user-consent API and could
    // unlink a fresh Unix lock during its pre-flock creation window.
    m_localServerLock.reset();
    return false;
}

#if !defined(MACOS_NE)
bool AmneziaApplication::startLocalServer() {
    if (m_operatorCommandLineDetected || m_publishBundledUpdatesOnceCommand) {
        // A one-shot local command must not publish the primary-instance
        // endpoint or remove a server that won the startup race.
        return false;
    }

    const QString serverName = localServerName();
    if (serverName.isEmpty()) {
        qWarning() << "Unable to establish a private local application endpoint namespace";
        return false;
    }
    if (m_localServer) {
        return m_localServer->isListening() && m_localServerLock
                && m_localServerLock->isLocked();
    }
    if (!m_localServerLock || !m_localServerLock->isLocked()) {
        qWarning() << "This process does not own the settings-global Core lock";
        return false;
    }

    m_localServer = new amnezia::ipc::PrivilegedLocalServer(this);
#ifndef Q_OS_WIN
    m_localServer->setSocketOptions(QLocalServer::UserAccessOption);
#endif
    m_localServer->setMaxPendingConnections(operatorMaximumActiveClients);
    if (!m_localServer->listen(serverName)) {
#ifdef Q_OS_WIN
        // Named-pipe endpoints disappear with their final handle. A listen
        // failure is therefore live or ambiguous and must remain fail-closed.
        qWarning() << "Unable to start hardened local application command server:"
                   << m_localServer->errorString();
        delete m_localServer;
        m_localServer = nullptr;
        return false;
#else
        QLocalSocket liveProbe;
        const bool endpointIsLive = connectOperatorSocket(&liveProbe, serverName, 250);
        if (!endpointIsLive && QLocalServer::removeServer(serverName)
            && m_localServer->listen(serverName)) {
            // A failed connection probe establishes that the filesystem entry
            // was stale. The held lock prevents cooperating instances from
            // racing this one between cleanup and listen.
        } else {
            qWarning() << "Unable to start local application command server:"
                       << m_localServer->errorString();
            delete m_localServer;
            m_localServer = nullptr;
            return false;
        }
#endif
    }

    const auto activeConnections = QSharedPointer<int>::create(0);
    QObject::connect(m_localServer, &amnezia::ipc::PrivilegedLocalServer::newConnection, this,
                     [this, activeConnections]() {
        if (!m_localServer) {
            return;
        }

        while (m_localServer->hasPendingConnections()) {
            QLocalSocket *socket = m_localServer->nextPendingConnection();
            if (!socket) {
                continue;
            }
            if (*activeConnections >= operatorMaximumActiveClients
                || !operatorPeerIsTrusted(socket, OperatorPeerRole::Client)) {
                socket->abort();
                socket->deleteLater();
                continue;
            }
            ++*activeConnections;
            connect(socket, &QObject::destroyed, this, [activeConnections]() {
                if (*activeConnections > 0) {
                    --*activeConnections;
                }
            });
            socket->setReadBufferSize(amnezia::operatorMode::MaximumWireFrameSize + 1);

            const QPointer<QLocalSocket> guardedSocket(socket);
            const QPointer<AmneziaApplication> guardedApplication(this);
            const auto buffer = QSharedPointer<QByteArray>::create();
            const auto handled = QSharedPointer<bool>::create(false);
            const auto processing = QSharedPointer<bool>::create(false);
            const auto raiseWindow = [guardedApplication]() {
                if (guardedApplication && guardedApplication->m_coreController
                    && guardedApplication->m_coreController->pageController()) {
                    emit guardedApplication->m_coreController->pageController()->raiseMainWindow();
                }
            };
            const auto sendResponse = [guardedSocket, handled](const amnezia::operatorMode::CommandResponse &response) {
                if (*handled) {
                    return;
                }
                *handled = true;
                if (!guardedSocket) {
                    return;
                }
                QByteArray payload = QJsonDocument(response.toJson()).toJson(QJsonDocument::Compact);
                payload.append('\n');
                if (amnezia::operatorMode::wireFrameState(payload)
                    != amnezia::operatorMode::WireFrameState::Complete) {
                    guardedSocket->disconnectFromServer();
                    return;
                }
                guardedSocket->write(payload);
                guardedSocket->flush();
                guardedSocket->disconnectFromServer();
            };

            const auto consumeRequest =
                    [this, guardedSocket, buffer, handled, processing, sendResponse]() {
                if (!guardedSocket) {
                    return;
                }
                if (!amnezia::operatorMode::canProcessWireFrame(*handled, *processing)) {
                    if (*handled) {
                        guardedSocket->read(amnezia::operatorMode::MaximumWireFrameSize + 1);
                    }
                    return;
                }
                const qsizetype remaining = amnezia::operatorMode::MaximumWireFrameSize + 1
                        - buffer->size();
                if (remaining > 0) {
                    buffer->append(guardedSocket->read(remaining));
                }
                const amnezia::operatorMode::WireFrameState frameState =
                        amnezia::operatorMode::wireFrameState(*buffer);
                if (frameState == amnezia::operatorMode::WireFrameState::TooLarge) {
                    amnezia::operatorMode::CommandResponse response;
                    response.exitCode = 2;
                    response.humanOutput = QStringLiteral("Operator command message is too large.");
                    response.result = {
                        { QStringLiteral("ok"), false },
                        { QStringLiteral("error"), response.humanOutput },
                    };
                    sendResponse(response);
                    return;
                }
                if (frameState == amnezia::operatorMode::WireFrameState::Incomplete) {
                    return;
                }
                const qsizetype newline = buffer->indexOf('\n');
                const QByteArray line = buffer->left(newline);
                QJsonParseError jsonError;
                const QJsonDocument document = QJsonDocument::fromJson(line, &jsonError);
                amnezia::operatorMode::CommandRequest request;
                QString validationError;
                if (jsonError.error != QJsonParseError::NoError || !document.isObject()
                    || !amnezia::operatorMode::CommandRequest::fromJson(document.object(), &request,
                                                                        &validationError)) {
                    if (validationError.isEmpty()) {
                        validationError = jsonError.errorString();
                    }
                    amnezia::operatorMode::CommandResponse response;
                    response.exitCode = 2;
                    response.humanOutput = QStringLiteral("Invalid operator command: %1").arg(validationError);
                    response.result = {
                        { QStringLiteral("ok"), false },
                        { QStringLiteral("error"), response.humanOutput },
                    };
                    sendResponse(response);
                    return;
                }
                *processing = true;
                const amnezia::operatorMode::CommandResponse response = executeOperatorCommand(request);
                *processing = false;
                sendResponse(response);
                    };
            connect(socket, &QLocalSocket::readyRead, this, consumeRequest);
            if (socket->bytesAvailable() > 0) {
                // A native Windows client can write its Raise request before
                // the primary processes newConnection(). Do not depend on a
                // second readyRead edge after adopting an already-readable
                // pipe handle.
                QTimer::singleShot(0, socket, consumeRequest);
            }

            connect(socket, &QLocalSocket::disconnected, socket,
                    [guardedSocket, buffer, handled, processing, raiseWindow]() {
                if (!*handled && !*processing && buffer->isEmpty()) {
                    // Preserve the old behavior for an ordinary second launch:
                    // an empty connection raises the existing window.
                    *handled = true;
                    raiseWindow();
                }
                if (guardedSocket) {
                    guardedSocket->deleteLater();
                }
            });

            QTimer::singleShot(500, socket, [guardedSocket, buffer, handled, processing, raiseWindow]() {
                if (*handled || *processing) {
                    return;
                }
                *handled = true;
                if (buffer->isEmpty()) {
                    raiseWindow();
                }
                if (guardedSocket) {
                    guardedSocket->disconnectFromServer();
                }
            });
        }
    });
    return true;
}
#endif
#endif

void AmneziaApplication::runStartupOperatorCommand()
{
#if !defined(Q_OS_ANDROID) && !defined(Q_OS_IOS) && !defined(MACOS_NE)
    if (m_operatorCommand.type == amnezia::operatorMode::CommandType::Watch) {
        (new OperatorWatchSession(m_operatorCommand.json, this))->start();
        return;
    }
#endif
    const amnezia::operatorMode::CommandResponse response = executeOperatorCommand(m_operatorCommand);
    if (m_operatorCommand.json) {
        writeConsole(stdout, QString::fromUtf8(QJsonDocument(response.result).toJson(QJsonDocument::Compact)));
    } else {
        writeConsole(response.exitCode == 0 ? stdout : stderr, response.humanOutput);
    }
    m_commandExitCode = response.exitCode;
    QCoreApplication::exit(response.exitCode);
}

amnezia::operatorMode::CommandResponse AmneziaApplication::executeOperatorCommand(
    const amnezia::operatorMode::CommandRequest &request)
{
    QString validationError;
    if (!request.isValid(&validationError)) {
        amnezia::operatorMode::CommandResponse response;
        response.exitCode = 2;
        response.humanOutput = validationError;
        response.result = {
            { QStringLiteral("ok"), false },
            { QStringLiteral("error"), validationError },
        };
        return response;
    }

    if (request.type == amnezia::operatorMode::CommandType::Raise) {
        bool raised = false;
        if (m_coreController && m_coreController->pageController()) {
            emit m_coreController->pageController()->raiseMainWindow();
            raised = true;
        }
        amnezia::operatorMode::CommandResponse response;
        response.exitCode = 0;
        response.humanOutput = raised
                ? QStringLiteral("Amnezia window raised.")
                : QStringLiteral("Amnezia primary instance acknowledged the launch.");
        response.result = {
            { QStringLiteral("schema"), QStringLiteral("amnezia.operator.raise.v1") },
            { QStringLiteral("ok"), true },
            { QStringLiteral("raised"), raised },
        };
        return response;
    }

    const bool needsVpnWorker = request.type == amnezia::operatorMode::CommandType::Disconnect;
    if (!m_settings) {
        amnezia::operatorMode::CommandResponse response;
        response.exitCode = 4;
        response.humanOutput = QStringLiteral("Amnezia is still starting; retry the command in a moment.");
        response.result = {
            { QStringLiteral("ok"), false },
            { QStringLiteral("error"), QStringLiteral("application_not_ready") },
        };
        return response;
    }
    if (needsVpnWorker && (!m_vpnConnection || !m_vpnConnectionThread.isRunning())) {
        amnezia::operatorMode::CommandResponse response;
        response.exitCode = 4;
        response.humanOutput = QStringLiteral(
                "No running Amnezia primary instance owns a VPN session; disconnect was not attempted.");
        response.result = {
            { QStringLiteral("schema"), QStringLiteral("amnezia.operator.disconnect.v1") },
            { QStringLiteral("ok"), false },
            { QStringLiteral("requested"), false },
            { QStringLiteral("completed"), false },
            { QStringLiteral("changedKnown"), false },
            { QStringLiteral("changed"), false },
            { QStringLiteral("stateBefore"), QStringLiteral("unknown") },
            { QStringLiteral("state"), QStringLiteral("unknown") },
            { QStringLiteral("error"), QStringLiteral("application_not_running") },
        };
        return response;
    }

    switch (request.type) {
    case amnezia::operatorMode::CommandType::Status:
        return operatorStatus();
    case amnezia::operatorMode::CommandType::Disconnect:
        return operatorDisconnect();
    case amnezia::operatorMode::CommandType::Doctor:
        return operatorDoctor();
    case amnezia::operatorMode::CommandType::RoutesExplain:
        return operatorRoutesExplain(request.argument);
    case amnezia::operatorMode::CommandType::Watch: {
        amnezia::operatorMode::CommandResponse response;
        response.exitCode = 2;
        response.humanOutput = QStringLiteral("Watch is a client-side streaming command.");
        response.result = {
            { QStringLiteral("schema"), QStringLiteral("amnezia.operator.watch.v1") },
            { QStringLiteral("ok"), false },
            { QStringLiteral("error"), QStringLiteral("watch_is_client_side") },
        };
        return response;
    }
    case amnezia::operatorMode::CommandType::Raise:
        // Handled before settings readiness checks above.
        break;
    case amnezia::operatorMode::CommandType::None:
        break;
    }

    amnezia::operatorMode::CommandResponse response;
    response.exitCode = 2;
    response.humanOutput = QStringLiteral("Unsupported operator command.");
    response.result = {
        { QStringLiteral("ok"), false },
        { QStringLiteral("error"), QStringLiteral("unsupported_command") },
    };
    return response;
}

amnezia::operatorMode::CommandResponse AmneziaApplication::operatorStatus()
{
    const bool workerRunning = m_vpnConnection && m_vpnConnectionThread.isRunning();
    bool applicationRunning = workerRunning;
#if !defined(Q_OS_ANDROID) && !defined(Q_OS_IOS) && !defined(MACOS_NE)
    applicationRunning = applicationRunning || (m_localServer && m_localServer->isListening());
#endif
    if (!workerRunning) {
        const bool starting = applicationRunning;
        amnezia::operatorMode::CommandResponse response;
        response.exitCode = 4;
        response.humanOutput = starting
                ? QStringLiteral("The running Amnezia primary instance is still starting; live VPN status is not ready.")
                : QStringLiteral("No running Amnezia primary instance is available; live VPN status is unknown.");
        response.result = {
            { QStringLiteral("schema"), QStringLiteral("amnezia.operator.status.v1") },
            { QStringLiteral("ok"), false },
            { QStringLiteral("applicationRunning"), applicationRunning },
            { QStringLiteral("applicationReady"), false },
            { QStringLiteral("detailsAvailable"), false },
            { QStringLiteral("detailsFresh"), false },
            { QStringLiteral("snapshotAgeMs"), -1 },
            { QStringLiteral("snapshotRefreshPending"), false },
            { QStringLiteral("state"), QStringLiteral("unknown") },
            { QStringLiteral("stateFresh"), false },
            { QStringLiteral("connected"), false },
            { QStringLiteral("connectedKnown"), false },
            { QStringLiteral("pid"), static_cast<qint64>(QCoreApplication::applicationPid()) },
            { QStringLiteral("error"), starting
                        ? QStringLiteral("application_not_ready")
                        : QStringLiteral("application_not_running") },
            { QStringLiteral("version"), QStringLiteral(APP_VERSION) },
            { QStringLiteral("commit"), QStringLiteral(GIT_COMMIT_HASH) },
        };
        return response;
    }

    // Serving status must remain O(1) on the GUI thread. Refresh the detailed
    // worker snapshot asynchronously and coalesce all watchers to at most one
    // worker read per interval.
    requestOperatorVpnSnapshotRefresh();
    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    const qint64 snapshotAgeMs = m_operatorSnapshotCompletedAtMs > 0
            ? qMax<qint64>(0, now - m_operatorSnapshotCompletedAtMs) : -1;
    const bool snapshotFresh = m_operatorSnapshotAvailable && snapshotAgeMs >= 0
            && snapshotAgeMs <= operatorSnapshotStaleAfterMs;
    const Vpn::ConnectionState effectiveConnectionState = m_operatorConnectionState;
    const bool sessionActive = snapshotFresh
            && effectiveConnectionState != Vpn::ConnectionState::Disconnected
            && effectiveConnectionState != Vpn::ConnectionState::Unknown;
    const int effectiveServerIndex = sessionActive ? m_operatorSnapshotServerIndex : -1;
    bool serverIdTruncated = false;
    const QString serverId = sessionActive
            ? boundedOperatorField(m_operatorSnapshotServerId,
                                   operatorMaximumIdentifierOutputLength, &serverIdTruncated)
            : QString();
    const QString state = connectionStateName(effectiveConnectionState);
    const QString protocol = !sessionActive || m_operatorSnapshotContainer == DockerContainer::None
            ? QString() : ContainerUtils::containerToString(m_operatorSnapshotContainer);
    bool remoteAddressTruncated = false;
    const QString remoteAddress = sessionActive
            ? boundedOperatorField(m_operatorSnapshotRemoteAddress,
                                   operatorMaximumIdentifierOutputLength, &remoteAddressTruncated)
            : QString();
    const quint64 receivedRate = sessionActive ? m_operatorReceivedBytes : 0;
    const quint64 sentRate = sessionActive ? m_operatorSentBytes : 0;
    const int lastError = snapshotFresh
                    && effectiveConnectionState == Vpn::ConnectionState::Error
            ? m_operatorSnapshotLastError : static_cast<int>(ErrorCode::NoError);
    const QString snapshotError = snapshotFresh ? QString()
            : (m_operatorSnapshotCompletedAtMs > 0
                       ? QStringLiteral("worker_snapshot_stale")
                       : QStringLiteral("worker_snapshot_pending"));

    QJsonObject result {
        { QStringLiteral("schema"), QStringLiteral("amnezia.operator.status.v1") },
        { QStringLiteral("ok"), snapshotFresh },
        { QStringLiteral("applicationRunning"), true },
        { QStringLiteral("applicationReady"), true },
        { QStringLiteral("state"), state },
        { QStringLiteral("stateFresh"), snapshotFresh },
        { QStringLiteral("connected"), snapshotFresh
                    && effectiveConnectionState == Vpn::ConnectionState::Connected },
        { QStringLiteral("connectedKnown"), snapshotFresh },
        { QStringLiteral("detailsAvailable"), snapshotFresh },
        { QStringLiteral("detailsFresh"), snapshotFresh },
        { QStringLiteral("snapshotAgeMs"), snapshotAgeMs },
        { QStringLiteral("snapshotRefreshPending"), m_operatorSnapshotRefreshPending },
        { QStringLiteral("inProgress"), snapshotFresh
                                           && (effectiveConnectionState == Vpn::ConnectionState::Preparing
                                           || effectiveConnectionState == Vpn::ConnectionState::Connecting
                                           || effectiveConnectionState == Vpn::ConnectionState::Disconnecting
                                           || effectiveConnectionState == Vpn::ConnectionState::Reconnecting) },
        { QStringLiteral("serverIndex"), effectiveServerIndex },
        { QStringLiteral("serverId"), serverId },
        { QStringLiteral("serverIdTruncated"), serverIdTruncated },
        { QStringLiteral("protocol"), protocol },
        { QStringLiteral("remoteAddress"), remoteAddress },
        { QStringLiteral("remoteAddressTruncated"), remoteAddressTruncated },
        { QStringLiteral("receivedBytesPerSecond"), static_cast<qint64>(receivedRate) },
        { QStringLiteral("sentBytesPerSecond"), static_cast<qint64>(sentRate) },
        { QStringLiteral("lastError"), lastError },
        { QStringLiteral("pid"), static_cast<qint64>(QCoreApplication::applicationPid()) },
        { QStringLiteral("version"), QStringLiteral(APP_VERSION) },
        { QStringLiteral("commit"), QStringLiteral(GIT_COMMIT_HASH) },
    };
    if (!snapshotError.isEmpty()) {
        result.insert(QStringLiteral("error"), snapshotError);
    }

    QStringList lines {
        QStringLiteral("%1: %2").arg(snapshotFresh
                    ? QStringLiteral("State") : QStringLiteral("State (last observed)"), state),
        QStringLiteral("Server: %1").arg(sessionActive
                    ? (serverId.isEmpty() ? QStringLiteral("unavailable")
                                          : terminalSafeOperatorField(serverId))
                    : QStringLiteral("inactive")),
    };
    if (!protocol.isEmpty()) {
        lines.append(QStringLiteral("Protocol: %1").arg(protocol));
    }
    if (!remoteAddress.isEmpty()) {
        lines.append(QStringLiteral("Remote: %1").arg(terminalSafeOperatorField(remoteAddress)));
    }
    if (!snapshotFresh) {
        lines.append(snapshotError == QStringLiteral("worker_snapshot_stale")
                             ? QStringLiteral("Details: worker snapshot is stale; live fields are suppressed")
                             : QStringLiteral("Details: worker snapshot refresh is pending"));
    }
    lines.append(QStringLiteral("Traffic rate: %1 received, %2 sent")
                         .arg(VpnConnection::bytesPerSecToText(receivedRate),
                              VpnConnection::bytesPerSecToText(sentRate)));

    amnezia::operatorMode::CommandResponse response;
    response.exitCode = snapshotFresh ? 0 : 4;
    response.result = result;
    response.humanOutput = lines.join(QLatin1Char('\n'));
    return response;
}

amnezia::operatorMode::CommandResponse AmneziaApplication::operatorDisconnect()
{
    amnezia::operatorMode::CommandResponse response;
    if (m_operatorDisconnectInProgress) {
        response.exitCode = 4;
        response.humanOutput = QStringLiteral("A VPN disconnect is already in progress.");
        response.result = {
            { QStringLiteral("schema"), QStringLiteral("amnezia.operator.disconnect.v1") },
            { QStringLiteral("ok"), false },
            { QStringLiteral("requested"), false },
            { QStringLiteral("completed"), false },
            { QStringLiteral("changedKnown"), false },
            { QStringLiteral("changed"), false },
            { QStringLiteral("stateBefore"), QStringLiteral("unknown") },
            { QStringLiteral("state"), connectionStateName(m_operatorConnectionState) },
            { QStringLiteral("error"), QStringLiteral("disconnect_in_progress") },
        };
        return response;
    }

    const OperatorVpnSnapshot snapshot = readVpnSnapshot(m_vpnConnection);
    const Vpn::ConnectionState currentState = snapshot.available
            ? snapshot.connectionState : m_operatorConnectionState;
    const bool stateBeforeKnown = snapshot.available;
    if (stateBeforeKnown && currentState == Vpn::ConnectionState::Disconnected) {
        response.humanOutput = QStringLiteral("VPN is already disconnected.");
        response.result = {
            { QStringLiteral("schema"), QStringLiteral("amnezia.operator.disconnect.v1") },
            { QStringLiteral("ok"), true },
            { QStringLiteral("requested"), false },
            { QStringLiteral("completed"), true },
            { QStringLiteral("changedKnown"), true },
            { QStringLiteral("changed"), false },
            { QStringLiteral("stateBefore"), QStringLiteral("disconnected") },
            { QStringLiteral("state"), QStringLiteral("disconnected") },
        };
        return response;
    }

    m_operatorDisconnectInProgress = true;
    QEventLoop waitLoop;
    QTimer timeout;
    timeout.setSingleShot(true);
    bool disconnected = false;
    const QMetaObject::Connection stateConnection = connect(
        m_vpnConnection.get(), &VpnConnection::connectionStateChanged, &waitLoop,
        [&waitLoop, &disconnected](Vpn::ConnectionState state) {
            if (state == Vpn::ConnectionState::Disconnected) {
                disconnected = true;
                waitLoop.quit();
            }
        });
    connect(&timeout, &QTimer::timeout, &waitLoop, &QEventLoop::quit);

    const bool invoked = QMetaObject::invokeMethod(m_vpnConnection.get(), &VpnConnection::disconnectFromVpn,
                                                    Qt::QueuedConnection);
    if (invoked) {
        timeout.start(operatorDisconnectCompletionTimeoutMs);
        waitLoop.exec();
    }
    disconnect(stateConnection);
    m_operatorDisconnectInProgress = false;

    const OperatorVpnSnapshot finalSnapshot = readVpnSnapshot(m_vpnConnection);
    const Vpn::ConnectionState finalState = finalSnapshot.available
            ? finalSnapshot.connectionState : m_operatorConnectionState;
    const bool completed = disconnected || finalState == Vpn::ConnectionState::Disconnected;
    const bool changed = stateBeforeKnown
            && currentState != Vpn::ConnectionState::Disconnected && completed;
    const QString error = completed ? QString()
                                    : (invoked ? QStringLiteral("disconnect_timeout")
                                               : QStringLiteral("disconnect_invoke_failed"));

    response.exitCode = completed ? 0 : 5;
    response.humanOutput = completed
            ? QStringLiteral("VPN disconnected.")
            : (invoked ? QStringLiteral("VPN disconnect did not complete before the timeout.")
                       : QStringLiteral("VPN disconnect request could not be queued."));
    response.result = {
        { QStringLiteral("schema"), QStringLiteral("amnezia.operator.disconnect.v1") },
        { QStringLiteral("ok"), completed },
        { QStringLiteral("requested"), invoked },
        { QStringLiteral("completed"), completed },
        { QStringLiteral("changedKnown"), stateBeforeKnown },
        { QStringLiteral("changed"), changed },
        { QStringLiteral("stateBefore"), stateBeforeKnown
                    ? connectionStateName(currentState) : QStringLiteral("unknown") },
        { QStringLiteral("state"), connectionStateName(finalState) },
    };
    if (!error.isEmpty()) {
        response.result.insert(QStringLiteral("error"), error);
    }
    return response;
}

amnezia::operatorMode::CommandResponse AmneziaApplication::operatorDoctor() const
{
    QJsonArray checks;
    int passed = 0;
    int warnings = 0;
    int failed = 0;
    const auto addCheck = [&checks, &passed, &warnings, &failed](const QString &id, const QString &status,
                                                               const QString &message, const QJsonObject &details = {}) {
        QJsonObject check {
            { QStringLiteral("id"), id },
            { QStringLiteral("status"), status },
            { QStringLiteral("message"), message },
        };
        if (!details.isEmpty()) {
            check.insert(QStringLiteral("details"), details);
        }
        checks.append(check);
        if (status == QStringLiteral("pass")) {
            ++passed;
        } else if (status == QStringLiteral("warning")) {
            ++warnings;
        } else {
            ++failed;
        }
    };

    const bool headlessOperator = m_operatorCommandLineDetected;
    const bool coreReady = !m_coreController.isNull();
    const QString runtimeStatus = !m_settings ? QStringLiteral("fail")
            : (coreReady || headlessOperator ? QStringLiteral("pass") : QStringLiteral("warning"));
    addCheck(QStringLiteral("operator-runtime"), runtimeStatus,
             m_settings
                     ? (coreReady ? QStringLiteral("Application core is ready.")
                                         : (headlessOperator
                                                    ? QStringLiteral("Minimal headless operator runtime is ready.")
                                                    : QStringLiteral("Application core is still starting.")))
                     : QStringLiteral("Operator settings runtime is not initialized."),
             { { QStringLiteral("headless"), headlessOperator },
               { QStringLiteral("coreReady"), coreReady } });

#ifdef AMNEZIA_DESKTOP
    const bool serviceAvailable = IpcClient::withInterface(
        [](const QSharedPointer<IpcInterfaceReplica> &) { return true; },
        []() { return false; });
    addCheck(QStringLiteral("service"), serviceAvailable ? QStringLiteral("pass") : QStringLiteral("fail"),
             serviceAvailable ? QStringLiteral("Privileged service IPC is reachable.")
                              : QStringLiteral("Privileged service IPC is unavailable."));
#else
    addCheck(QStringLiteral("service"), QStringLiteral("warning"),
             QStringLiteral("Privileged service IPC check is not available on this platform."));
#endif

    const QString configPath = QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation);
    addCheck(QStringLiteral("config-path"), isWritableLocation(configPath) ? QStringLiteral("pass")
                                                                            : QStringLiteral("fail"),
             isWritableLocation(configPath) ? QStringLiteral("Configuration location is writable.")
                                             : QStringLiteral("Configuration location is not writable."),
             { { QStringLiteral("path"), configPath } });

    const QString logPath = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation)
            + QStringLiteral("/log");
    addCheck(QStringLiteral("log-path"), isWritableLocation(logPath) ? QStringLiteral("pass")
                                                                       : QStringLiteral("fail"),
             isWritableLocation(logPath) ? QStringLiteral("Log location is writable.")
                                          : QStringLiteral("Log location is not writable."),
             { { QStringLiteral("path"), logPath } });

    const OperatorServerView serverView = readOperatorServerView(m_settings);
    const int serverCount = serverView.count;
    bool defaultServerIdTruncated = false;
    const QString defaultServerId = boundedOperatorField(
            serverView.id, operatorMaximumIdentifierOutputLength, &defaultServerIdTruncated);
    addCheck(QStringLiteral("servers"), serverCount > 0 ? QStringLiteral("pass") : QStringLiteral("warning"),
             serverCount > 0 ? QStringLiteral("At least one VPN server is configured.")
                             : QStringLiteral("No VPN servers are configured."),
             { { QStringLiteral("count"), serverCount },
               { QStringLiteral("defaultServerId"), defaultServerId },
               { QStringLiteral("defaultServerIdTruncated"), defaultServerIdTruncated } });

    SecureAppSettingsRepository appSettings(m_settings);
    const int routeModeValue = static_cast<int>(appSettings.routeMode());
    const bool routeModeValid = routeModeValue >= static_cast<int>(RouteMode::VpnAllSites)
            && routeModeValue <= static_cast<int>(RouteMode::VpnAllExceptSites);
    addCheck(QStringLiteral("routing-settings"), routeModeValid ? QStringLiteral("pass") : QStringLiteral("fail"),
             routeModeValid ? QStringLiteral("Routing settings are valid.")
                            : QStringLiteral("Routing mode is outside the supported range."),
             { { QStringLiteral("mode"), routeModeValue },
               { QStringLiteral("siteSplitTunneling"), appSettings.isSitesSplitTunnelingEnabled() },
               { QStringLiteral("appSplitTunneling"), appSettings.isAppsSplitTunnelingEnabled() },
               { QStringLiteral("killSwitch"), appSettings.isKillSwitchEnabled() } });

    const bool workerRunning = m_vpnConnection && m_vpnConnectionThread.isRunning();
    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    const qint64 snapshotAgeMs = m_operatorSnapshotCompletedAtMs > 0
            ? qMax<qint64>(0, now - m_operatorSnapshotCompletedAtMs) : -1;
    const qint64 refreshAgeMs = m_operatorSnapshotRefreshPending
            ? qMax<qint64>(0, now - m_operatorSnapshotRequestedAtMs) : 0;
    const bool snapshotFresh = workerRunning && m_operatorSnapshotAvailable
            && snapshotAgeMs >= 0 && snapshotAgeMs <= operatorSnapshotStaleAfterMs;
    const bool snapshotStuck = workerRunning
            && ((m_operatorSnapshotRefreshPending
                 && refreshAgeMs > operatorSnapshotStaleAfterMs)
                || (snapshotAgeMs > operatorSnapshotStaleAfterMs));
    addCheck(QStringLiteral("vpn-worker-snapshot"),
             snapshotFresh ? QStringLiteral("pass")
                           : (snapshotStuck ? QStringLiteral("fail") : QStringLiteral("warning")),
             snapshotFresh ? QStringLiteral("VPN worker snapshot is fresh.")
                           : (snapshotStuck
                                      ? QStringLiteral("VPN worker snapshot is stale or the refresh is stuck.")
                                      : QStringLiteral("VPN worker snapshot is unavailable or still pending.")),
             { { QStringLiteral("workerRunning"), workerRunning },
               { QStringLiteral("snapshotAgeMs"), snapshotAgeMs },
               { QStringLiteral("refreshPending"), m_operatorSnapshotRefreshPending },
               { QStringLiteral("refreshAgeMs"), refreshAgeMs } });

    QString connectionCheckStatus = QStringLiteral("pass");
    QString connectionMessage = QStringLiteral("Connection state is %1.").arg(connectionStateName(m_operatorConnectionState));
    if (!snapshotFresh) {
        connectionCheckStatus = QStringLiteral("warning");
        connectionMessage = QStringLiteral("Last observed connection state is %1; worker freshness is not established.")
                                    .arg(connectionStateName(m_operatorConnectionState));
    } else if (m_operatorConnectionState == Vpn::ConnectionState::Error) {
        connectionCheckStatus = QStringLiteral("fail");
    } else if (m_operatorConnectionState == Vpn::ConnectionState::Unknown) {
        connectionCheckStatus = QStringLiteral("warning");
        connectionMessage = QStringLiteral("No connection state has been observed yet.");
    }
    addCheck(QStringLiteral("connection"), connectionCheckStatus, connectionMessage);

    QJsonObject summary {
        { QStringLiteral("passed"), passed },
        { QStringLiteral("warnings"), warnings },
        { QStringLiteral("failed"), failed },
    };
    QJsonObject result {
        { QStringLiteral("schema"), QStringLiteral("amnezia.operator.doctor.v1") },
        { QStringLiteral("ok"), failed == 0 },
        { QStringLiteral("version"), QStringLiteral(APP_VERSION) },
        { QStringLiteral("commit"), QStringLiteral(GIT_COMMIT_HASH) },
        { QStringLiteral("platform"), QSysInfo::prettyProductName() },
        { QStringLiteral("architecture"), QSysInfo::currentCpuArchitecture() },
        { QStringLiteral("summary"), summary },
        { QStringLiteral("checks"), checks },
    };

    QStringList lines {
        QStringLiteral("Doctor: %1 passed, %2 warning(s), %3 failed").arg(passed).arg(warnings).arg(failed),
    };
    for (const QJsonValue &value : checks) {
        const QJsonObject check = value.toObject();
        lines.append(QStringLiteral("[%1] %2: %3")
                             .arg(check.value(QStringLiteral("status")).toString().toUpper(),
                                  check.value(QStringLiteral("id")).toString(),
                                  check.value(QStringLiteral("message")).toString()));
    }

    amnezia::operatorMode::CommandResponse response;
    response.exitCode = failed == 0 ? 0 : 1;
    response.humanOutput = lines.join(QLatin1Char('\n'));
    response.result = result;
    return response;
}

amnezia::operatorMode::CommandResponse AmneziaApplication::operatorRoutesExplain(const QString &hostInput) const
{
    amnezia::operatorMode::CommandResponse response;
    const routeRuleMatcher::NormalizedTarget normalizedTarget =
            routeRuleMatcher::normalizeTarget(
                    hostInput, routeRuleMatcher::InputPolicy::BareHostOrAddress);
    if (!normalizedTarget.error.isEmpty()) {
        response.exitCode = 2;
        response.humanOutput = QStringLiteral("Invalid host name or IP address.");
        response.result = {
            { QStringLiteral("schema"), QStringLiteral("amnezia.operator.routes-explain.v1") },
            { QStringLiteral("ok"), false },
            { QStringLiteral("error"), QStringLiteral("invalid_host") },
        };
        return response;
    }
    const QString host = normalizedTarget.host;

    const OperatorVpnSnapshot snapshot = m_vpnConnection && m_vpnConnectionThread.isRunning()
            ? readVpnSnapshot(m_vpnConnection) : OperatorVpnSnapshot();
    const Vpn::ConnectionState effectiveConnectionState = snapshot.available
            ? snapshot.connectionState : m_operatorConnectionState;
    const bool runtimeConnected = snapshot.available
            && effectiveConnectionState == Vpn::ConnectionState::Connected;
    const int activeServerIndex = runtimeConnected ? snapshot.serverIndex : -1;

    SecureAppSettingsRepository appSettings(m_settings);
    const OperatorServerView serverView = readOperatorServerView(m_settings, activeServerIndex);
    const int serverIndex = serverView.index;
    const RouteMode localMode = appSettings.routeMode();
    const bool localSplitEnabled = appSettings.isSitesSplitTunnelingEnabled();
    SecureServersRepository serverRepository(m_settings, nullptr, false);
    const RouteMode desiredMode = serverRepository.effectiveSiteRouteMode(
            serverIndex, localSplitEnabled, localMode);
    const QJsonObject serverConfig = serverIndex >= 0
            ? serverRepository.serverJson(serverIndex) : QJsonObject();
    const bool managedPolicyPresent =
            !serverConfig.value(managedRoutePolicy::stateKey()).isUndefined()
            || managedRoutePolicy::containsSourceSites(serverConfig);
    const bool managedPolicyEffective =
            managedRoutePolicy::isEffective(serverConfig);
    const QString effectivePolicyRevision =
            managedRoutePolicy::effectiveRevision(serverConfig);
    const QString effectivePolicyContentHash =
            managedRoutePolicy::effectiveContentHash(serverConfig);
    const VpnConnection::ManagedRouteRuntimeSnapshot &managedSnapshot =
            snapshot.managedRouteSnapshot;
    const bool receiptConfirmed = runtimeConnected && managedSnapshot.confirmed
            && !managedSnapshot.transitionPending;
    const bool serverEpochMatches = receiptConfirmed
            && managedSnapshot.connectionEpoch != 0
            && managedSnapshot.connectionEpoch == snapshot.connectionEpoch
            && !snapshot.serverId.isEmpty()
            && managedSnapshot.serverId == snapshot.serverId
            && serverView.id == snapshot.serverId;
    const bool modeMatches = receiptConfirmed
            && managedSnapshot.mode == snapshot.appliedSiteRouteMode
            && managedSnapshot.mode == desiredMode;
    const bool policyIdentityMatches = receiptConfirmed
            && managedRoutePolicy::isCanonicalPolicyIdentity(
                    managedSnapshot.policyRevision,
                    managedSnapshot.policyContentHash)
            && managedSnapshot.policyRevision == effectivePolicyRevision
            && managedSnapshot.policyContentHash == effectivePolicyContentHash
            && (!managedPolicyPresent || managedPolicyEffective);
    const bool snapshotAuthoritative = receiptConfirmed
            && serverEpochMatches && modeMatches && policyIdentityMatches;
    const RouteMode inspectedMode = receiptConfirmed
            ? managedSnapshot.mode : desiredMode;

    QVariantMap installedRules;
    if (snapshotAuthoritative && inspectedMode != RouteMode::VpnAllSites) {
        for (const QString &route : managedSnapshot.installedRoutes) {
            installedRules.insert(route, QVariant());
        }
    }
    const routeRuleMatcher::MatchResult matchResult =
            snapshotAuthoritative
            ? routeRuleMatcher::matchRules(
                    {}, installedRules, host, normalizedTarget.literalAddress,
                    routeRuleMatcher::DomainMatchPolicy::PolicyOnly)
            : routeRuleMatcher::MatchResult {};
    const routeRuleMatcher::RuleMatch &match = matchResult.accepted;
    const bool ruleCoverageComplete = !snapshotAuthoritative
            || matchResult.coverageComplete;
    const bool matched = snapshotAuthoritative
            && ruleCoverageComplete && match.matched;
    const QString matchedRule = matched ? match.configuredRule : QString();
    const QString matchedSource = matched
            ? QStringLiteral("server-managed") : QString();
    bool matchedRuleTruncated = false;
    const QString outputMatchedRule = boundedOperatorField(
            matchedRule, operatorMaximumIdentifierOutputLength, &matchedRuleTruncated);
    const bool matchedValueTruncated = matched && match.matchedValueTruncated;
    const QString outputMatchedValue = !matched ? QString()
            : match.matchedValue
                    + (matchedValueTruncated ? QStringLiteral("...") : QString());
    bool serverIdTruncated = false;
    const QString outputServerId = boundedOperatorField(
            serverView.id, operatorMaximumIdentifierOutputLength, &serverIdTruncated);

    QString snapshotRoute = QStringLiteral("unknown");
    QString reason;
    if (!snapshotAuthoritative) {
        reason = QStringLiteral("confirmed installed route snapshot is unavailable or diverged");
    } else {
        switch (inspectedMode) {
        case RouteMode::VpnAllSites:
            snapshotRoute = QStringLiteral("vpn");
            reason = QStringLiteral("confirmed client snapshot applies full-tunnel site routing");
            break;
        case RouteMode::VpnOnlyForwardSites:
            if (matched) {
                snapshotRoute = QStringLiteral("vpn");
                reason = QStringLiteral("target matches a confirmed installed managed route");
            } else {
                // The managed receipt says nothing about best-effort local
                // routes, so absence of a managed match cannot prove that the
                // target uses the split-mode default.
                snapshotRoute = QStringLiteral("unknown");
                reason = QStringLiteral("no managed receipt matched and local route installation is unconfirmed");
            }
            break;
        case RouteMode::VpnAllExceptSites:
            if (matched) {
                snapshotRoute = QStringLiteral("direct");
                reason = QStringLiteral("target matches a confirmed installed managed bypass route");
            } else {
                snapshotRoute = QStringLiteral("unknown");
                reason = QStringLiteral("no managed bypass receipt matched and local route installation is unconfirmed");
            }
            break;
        }
    }
    if (snapshotAuthoritative && !ruleCoverageComplete) {
        snapshotRoute = QStringLiteral("unknown");
        reason = QStringLiteral("installed rule coverage exceeded bounded inspection limits");
    }

    const QHostAddress targetAddress = normalizedTarget.literalAddress;
    const bool literalTarget = !targetAddress.isNull();
    const bool ipv6Target = literalTarget
            && targetAddress.protocol() == QAbstractSocket::IPv6Protocol;

    QStringList protectedRouteCandidates;
    const auto addProtectedRouteCandidate = [&protectedRouteCandidates](const QString &candidate) {
        const QString trimmed = candidate.trimmed();
        if (!trimmed.isEmpty() && !protectedRouteCandidates.contains(trimmed)) {
            protectedRouteCandidates.append(trimmed);
        }
    };
    if (runtimeConnected) {
        addProtectedRouteCandidate(snapshot.remoteAddress);
        addProtectedRouteCandidate(snapshot.serverRoutingRulesSyncHost);
        addProtectedRouteCandidate(snapshot.vpnGateway);
    }
    addProtectedRouteCandidate(serverView.config.value(configKey::dns1).toString());
    addProtectedRouteCandidate(serverView.config.value(configKey::dns2).toString());
    addProtectedRouteCandidate(appSettings.primaryDns());
    addProtectedRouteCandidate(appSettings.secondaryDns());
    addProtectedRouteCandidate(QString::fromLatin1(protocols::dns::amneziaDnsIp));
    addProtectedRouteCandidate(QString::fromLatin1(protocols::serverRoutingRules::syncHost));
    addProtectedRouteCandidate(QString::fromLatin1(protocols::selfHostedUpdates::syncHost));
    addProtectedRouteCandidate(QString::fromLatin1(protocols::clientLogs::syncHost));

    bool protectedTarget = false;
    if (literalTarget) {
        for (const QString &candidate : std::as_const(protectedRouteCandidates)) {
            QHostAddress protectedAddress;
            if (protectedAddress.setAddress(candidate) && protectedAddress == targetAddress) {
                protectedTarget = true;
                break;
            }
        }
    }

    const bool splitMode = inspectedMode != RouteMode::VpnAllSites;
    const amnezia::operatorMode::RouteRuntimeDecision runtimeDecision =
            amnezia::operatorMode::assessRouteRuntime(
                snapshotRoute, snapshot.available,
                effectiveConnectionState == Vpn::ConnectionState::Connected,
                snapshotAuthoritative,
                literalTarget, ipv6Target, splitMode, protectedTarget,
                modeMatches);

    QJsonArray warnings;
    if (!runtimeDecision.warning.isEmpty()) {
        warnings.append(runtimeDecision.warning);
    }
    if (!ruleCoverageComplete) {
        warnings.append(QStringLiteral("route_rule_coverage_truncated"));
    }
    if (receiptConfirmed && !serverEpochMatches) {
        warnings.append(QStringLiteral("runtime_snapshot_binding_diverged"));
    }
    if (receiptConfirmed && !modeMatches) {
        warnings.append(QStringLiteral("runtime_route_mode_diverged"));
    }
    if (receiptConfirmed && !policyIdentityMatches) {
        warnings.append(QStringLiteral("runtime_policy_identity_diverged"));
    }

    QJsonObject result {
        { QStringLiteral("schema"), QStringLiteral("amnezia.operator.routes-explain.v1") },
        { QStringLiteral("ok"), true },
        { QStringLiteral("host"), host },
        { QStringLiteral("route"), runtimeDecision.route },
        { QStringLiteral("policyRoute"), snapshotRoute },
        { QStringLiteral("snapshotRoute"), snapshotRoute },
        { QStringLiteral("reason"), reason },
        { QStringLiteral("mode"), routeModeName(inspectedMode) },
        { QStringLiteral("desiredMode"), routeModeName(desiredMode) },
        { QStringLiteral("appliedMode"), runtimeConnected
                    ? routeModeName(snapshot.appliedSiteRouteMode) : QStringLiteral("unknown") },
        { QStringLiteral("connectionState"), connectionStateName(effectiveConnectionState) },
        { QStringLiteral("applicationRunning"), m_vpnConnection && m_vpnConnectionThread.isRunning() },
        { QStringLiteral("detailsAvailable"), snapshot.available },
        { QStringLiteral("runtimeApplied"), runtimeDecision.runtimeApplied },
        { QStringLiteral("inspectionBasis"), runtimeDecision.inspectionBasis },
        { QStringLiteral("osRouteVerified"), false },
        { QStringLiteral("managedRouteReceiptConfirmed"), receiptConfirmed },
        { QStringLiteral("managedRouteSnapshotAuthoritative"), snapshotAuthoritative },
        { QStringLiteral("runtimeServerEpochMatches"), serverEpochMatches },
        { QStringLiteral("runtimeModeMatches"), modeMatches },
        { QStringLiteral("runtimePolicyIdentityMatches"), policyIdentityMatches },
        { QStringLiteral("managedRouteSnapshotRevision"),
                    QString::number(managedSnapshot.revision) },
        { QStringLiteral("managedPolicyRevision"), managedSnapshot.policyRevision },
        { QStringLiteral("managedPolicyContentHash"), managedSnapshot.policyContentHash },
        { QStringLiteral("protectedRoute"), protectedTarget },
        { QStringLiteral("targetKind"), literalTarget
                    ? (ipv6Target ? QStringLiteral("ipv6") : QStringLiteral("ipv4"))
                    : QStringLiteral("hostname") },
        { QStringLiteral("warnings"), warnings },
        { QStringLiteral("serverIndex"), serverIndex },
        { QStringLiteral("serverId"), outputServerId },
        { QStringLiteral("serverIdTruncated"), serverIdTruncated },
        { QStringLiteral("matched"), matched },
        { QStringLiteral("matchedRule"), outputMatchedRule },
        { QStringLiteral("matchedValue"), outputMatchedValue },
        { QStringLiteral("matchedRuleTruncated"), matchedRuleTruncated },
        { QStringLiteral("matchedValueTruncated"), matchedValueTruncated },
        { QStringLiteral("matchedSource"), matchedSource },
        { QStringLiteral("ruleCoverageComplete"), ruleCoverageComplete },
        { QStringLiteral("localRulesInspected"), matchResult.localRulesInspected },
        { QStringLiteral("managedRulesInspected"), matchResult.managedRulesInspected },
        { QStringLiteral("localRulesTruncated"), matchResult.localRulesTruncated },
        { QStringLiteral("managedRulesTruncated"), matchResult.managedRulesTruncated },
        { QStringLiteral("storedValuesTruncated"), matchResult.storedValuesTruncated },
        { QStringLiteral("localRuleCount"), 0 },
        { QStringLiteral("managedRuleCount"), installedRules.size() },
    };

    QStringList lines {
        QStringLiteral("%1 -> %2").arg(host, runtimeDecision.route),
        QStringLiteral("Confirmed client snapshot candidate: %1 (%2)")
                .arg(snapshotRoute, routeModeName(inspectedMode)),
        QStringLiteral("Snapshot reason: %1").arg(reason),
    };
    if (runtimeDecision.route == QStringLiteral("unknown")) {
        lines.append(QStringLiteral("Runtime: not asserted (%1)").arg(runtimeDecision.warning));
    } else {
        lines.append(QStringLiteral("Runtime: derived from a confirmed client route receipt; OS route table not inspected"));
    }
    if (matched) {
        lines.append(QStringLiteral("Matched: %1 (%2)")
                             .arg(terminalSafeOperatorField(outputMatchedRule), matchedSource));
    }

    response.humanOutput = lines.join(QLatin1Char('\n'));
    response.result = result;
    return response;
}

bool AmneziaApplication::eventFilter(QObject *watched, QEvent *event)
{
    if (event->type() == QEvent::Close) {
#if defined(Q_OS_ANDROID) || defined(Q_OS_IOS)
        quit();
#else
        if (m_forceQuit) {
            quit();
        } else {
            if (m_coreController && m_coreController->pageController()) {
                m_coreController->pageController()->hideMainWindow();
            }
        }
#endif
        return true; // eat the close
    }
    // call base QObject::eventFilter
    return QObject::eventFilter(watched, event);
}

void AmneziaApplication::forceQuit()
{
    m_forceQuit = true;
    quit();
}

QQmlApplicationEngine *AmneziaApplication::qmlEngine() const
{
    return m_engine;
}

QNetworkAccessManager *AmneziaApplication::networkManager()
{
    return m_nam;
}

QClipboard *AmneziaApplication::getClipboard()
{
    return this->clipboard();
}
