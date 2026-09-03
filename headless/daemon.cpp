#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include "daemon.h"

#include <QDir>
#include <QDateTime>
#include <QFileInfo>
#include <QJsonArray>
#include <QLocalSocket>
#include <QHostInfo>
#include <QLockFile>

#if defined(Q_OS_LINUX)
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#include <utility>
#include <algorithm>

namespace amnezia::headless
{

namespace
{
constexpr qint64 InstanceLockStaleAgeMs = 5000;

std::unique_ptr<QLockFile> acquireInstanceLock(const QString &socketPath)
{
    auto lock = std::make_unique<QLockFile>(socketPath + QStringLiteral(".lock"));
    lock->setStaleLockTime(static_cast<int>(InstanceLockStaleAgeMs));
    if (lock->tryLock(0)) return lock;

    qint64 pid = 0;
    QString host;
    QString application;
    if (!lock->getLockInfo(&pid, &host, &application)
        || pid <= 0 || host != QHostInfo::localHostName()) {
        return {};
    }
    const QFileInfo lockInfo(lock->fileName());
    if (!lockInfo.exists()
        || lockInfo.lastModified().msecsTo(QDateTime::currentDateTime())
            < InstanceLockStaleAgeMs) {
        return {};
    }
#if defined(Q_OS_LINUX)
    errno = 0;
    if (::kill(static_cast<pid_t>(pid), 0) == 0 || errno == EPERM) return {};
    if (errno != ESRCH) return {};
#else
    // Without a portable PID probe, never retire a lock automatically.
    return {};
#endif
    if (!lock->removeStaleLockFile() || !lock->tryLock(0)) return {};
    return lock;
}
}

Daemon::Daemon(QString socketPath, QString profileStorePath,
               std::shared_ptr<CommandRunner> runner,
               QString configRoot,
               bool requireRootOwnedConfig,
               QObject *parent,
               QString stagingRoot)
    : QObject(parent),
      m_socketPath(socketPath.trimmed().isEmpty() ? defaultSocketPath() : std::move(socketPath)),
      m_profileStore(std::move(profileStorePath)),
      m_vpnBackend(runner, std::move(configRoot), requireRootOwnedConfig,
                   std::move(stagingRoot)),
      m_routingController(runner, routeStatePathForStore(m_profileStore.path()), false),
      m_updateManager(runner, updateStatePathForStore(m_profileStore.path()))
{
    connect(&m_server, &QLocalServer::newConnection,
            this, &Daemon::acceptConnections);
    m_routingRefreshTimer.setInterval(24 * 60 * 60 * 1000);
    connect(&m_routingRefreshTimer, &QTimer::timeout,
            this, &Daemon::refreshManagedRoutes);
    m_updateTimer.setInterval(24 * 60 * 60 * 1000);
    connect(&m_updateTimer, &QTimer::timeout,
            this, &Daemon::checkAutomaticUpdates);
    m_healthTimer.setInterval(30'000);
    connect(&m_healthTimer, &QTimer::timeout,
            this, &Daemon::ensureBackendHealthy);
}

Daemon::~Daemon()
{
    stop();
}

bool Daemon::start(QString *error)
{
    if (m_server.isListening()) {
        setError(error, {});
        return true;
    }

    // This must be the first operation that can precede a host-state probe.
    // The routing controller is deliberately lazy-constructed above so its
    // constructor cannot inspect or migrate kernel state before this lock.
    m_instanceLock = acquireInstanceLock(m_socketPath);
    if (!m_instanceLock) {
        setError(error, QStringLiteral("another headless daemon owns the control socket"));
        return false;
    }
    m_startPhase = StartPhase::LockOwned;
    const auto failStart = [this, error](const QString &message) {
        m_instanceLock->unlock();
        m_instanceLock.reset();
        m_startPhase = StartPhase::NotStarted;
        m_state = QStringLiteral("recovery_required");
        setError(error, message);
        return false;
    };

    if (!m_routingController.initializeState()) {
        return failStart(QStringLiteral("managed routing state requires manual recovery"));
    }
    if (!m_profileStore.load()) {
        setError(error, m_profileStore.lastError());
        m_instanceLock->unlock();
        m_instanceLock.reset();
        m_startPhase = StartPhase::NotStarted;
        return false;
    }

    // Backend sessions are deliberately in-memory.  A native interface or
    // resolver binding matching configured profile evidence is therefore an
    // orphan after restart; the reconciler separately rejects unfinished
    // mutation intents and ambiguous persisted routing state.
    const auto isNativeProtocol = [](const QString &rawProtocol) {
        const QString protocol = rawProtocol.trimmed().toLower();
        return protocol == QStringLiteral("wireguard")
            || protocol == QStringLiteral("amneziawg")
            || protocol == QStringLiteral("amnezia-wg")
            || protocol == QStringLiteral("awg")
            || protocol == QStringLiteral("awg2")
            || protocol == QStringLiteral("openvpn");
    };
    for (const Profile &profile : m_profileStore.profiles()) {
        if (!isNativeProtocol(profile.protocol)) continue;
        if (m_vpnBackend.configuredInterfacePresent(profile)
            || m_vpnBackend.configuredDnsBindingPresent(profile)) {
            return failStart(QStringLiteral("a configured VPN interface or DNS binding may be orphaned; manual recovery is required"));
        }
    }

    // A crashed daemon cannot prove that persisted host state belongs to this
    // process.  Detect it and stop; never clean up state without ownership.
    const QJsonObject routingReceipt = m_routingController.status();
    const bool persistedRoutingState =
            !routingReceipt.value(QStringLiteral("activeProfile")).toString().isEmpty()
            || !routingReceipt.value(QStringLiteral("activeInterface")).toString().isEmpty()
            || routingReceipt.value(QStringLiteral("policyLoaded")).toBool()
            || routingReceipt.value(QStringLiteral("mode")).toString()
                == QStringLiteral("all-except")
            || !routingReceipt.value(QStringLiteral("routes")).toArray().isEmpty()
            || !routingReceipt.value(QStringLiteral("dnsInterface")).toString().isEmpty()
            || routingReceipt.value(QStringLiteral("recoveryRequired")).toBool();
    if (persistedRoutingState) {
        return failStart(QStringLiteral("orphaned VPN routes, DNS, or recovery markers require manual recovery"));
    }

    const QFileInfo socketInfo(m_socketPath);
    const QString parentPath = socketInfo.absolutePath();
    if (!parentPath.isEmpty() && parentPath != QStringLiteral(".")) {
        if (!QDir().mkpath(parentPath)) {
            setError(error, QStringLiteral("unable to create socket directory"));
            m_instanceLock->unlock();
            m_instanceLock.reset();
            m_startPhase = StartPhase::NotStarted;
            return false;
        }
    }

    // Hold an ownership lock for the daemon lifetime.  Socket probing alone
    // cannot distinguish a slow live daemon from a stale endpoint, and
    // removing the endpoint after a short timeout could create two daemons
    // racing over VPN routes and update receipts.
    if (!m_server.listen(m_socketPath)) {
        // A previous daemon may have left a stale local-server endpoint. Never
        // remove an endpoint that answers: that is an active daemon owned by
        // another process and must remain untouched.
        QLocalSocket probe;
        probe.connectToServer(m_socketPath, QIODevice::ReadWrite);
        if (probe.waitForConnected(100)) {
            m_instanceLock->unlock();
            m_instanceLock.reset();
            m_startPhase = StartPhase::NotStarted;
            setError(error, m_server.errorString());
            return false;
        }

        QLocalServer::removeServer(m_socketPath);
        if (!m_server.listen(m_socketPath)) {
            m_instanceLock->unlock();
            m_instanceLock.reset();
            setError(error, m_server.errorString());
            return false;
        }
    }

#ifndef Q_OS_WIN
    // The systemd service runs as root:amnezia. Keep the socket private to
    // that group; the containing RuntimeDirectory is separately restricted.
    QFile::setPermissions(m_socketPath,
                           QFileDevice::ReadOwner | QFileDevice::WriteOwner
                               | QFileDevice::ReadGroup | QFileDevice::WriteGroup);
#endif

    setError(error, {});
    m_startPhase = StartPhase::Listening;
    m_updateTimer.start();
    m_healthTimer.start();
    QTimer::singleShot(1000, this, &Daemon::connectAutomaticProfile);
    QTimer::singleShot(10'000, this, &Daemon::checkAutomaticUpdates);
    return true;
}

void Daemon::stop()
{
    // Tear down an active backend before closing the control plane. Errors are
    // deliberately not exposed during process shutdown; the daemon is going
    // away and the next start will report any remaining host state.
    m_routingRefreshTimer.stop();
    m_updateTimer.stop();
    m_healthTimer.stop();
    BackendResult backendResult { true, {}, {} };
    if (m_backendOwned) backendResult = m_vpnBackend.disconnect();
    // Keep policy routes in place until the tunnel process has stopped.  This
    // avoids a window in which traffic can fall back to the underlay.
    const RoutingResult routingResult = !backendResult.ok
            ? RoutingResult { false, QStringLiteral("backend_stop_failed"),
                              QStringLiteral("VPN backend did not stop; routing teardown was withheld") }
            : m_routingOwned ? m_routingController.disconnect()
                             : RoutingResult { true, {}, {} };
    if (backendResult.ok) m_backendOwned = false;
    if (routingResult.ok) m_routingOwned = false;
    m_state = (!routingResult.ok || !backendResult.ok)
            ? QStringLiteral("cleanup_failed") : QStringLiteral("disconnected");
    m_backendConnectedTimer.invalidate();
    m_activeProfile.clear();
    m_activeProfileData.reset();
    m_startPhase = StartPhase::NotStarted;

    const auto clients = m_clientBuffers.keys();
    for (QLocalSocket *client : clients) {
        if (!client) {
            continue;
        }
        disconnect(client, nullptr, this, nullptr);
        m_clientBuffers.remove(client);
        client->disconnectFromServer();
        client->deleteLater();
    }
    if (m_server.isListening()) {
        m_server.close();
        QLocalServer::removeServer(m_socketPath);
    }
    if (m_instanceLock) {
        m_instanceLock->unlock();
        m_instanceLock.reset();
    }
}

bool Daemon::isRunning() const
{
    return m_server.isListening();
}

QString Daemon::socketPath() const
{
    return m_socketPath;
}

int Daemon::connectedClientCount() const
{
    return m_clientBuffers.size();
}

int Daemon::processedRequestCount() const
{
    return m_processedRequestCount;
}

void Daemon::acceptConnections()
{
    while (m_server.hasPendingConnections()) {
        QLocalSocket *client = m_server.nextPendingConnection();
        if (!client) {
            continue;
        }
        if (m_clientBuffers.size() >= 64) {
            client->disconnectFromServer();
            client->deleteLater();
            continue;
        }
        m_clientBuffers.insert(client, {});
        auto *frameTimer = new QTimer(client);
        frameTimer->setSingleShot(true);
        frameTimer->setInterval(10'000);
        m_clientFrameTimers.insert(client, frameTimer);
        frameTimer->start();
        connect(frameTimer, &QTimer::timeout, client, [client]() {
            client->disconnectFromServer();
        });
        connect(client, &QLocalSocket::readyRead,
                this, &Daemon::readFromClient);
        connect(client, &QLocalSocket::disconnected,
                this, &Daemon::removeClient);
    }
}

void Daemon::readFromClient()
{
    auto *client = qobject_cast<QLocalSocket *>(sender());
    if (!client || !m_clientBuffers.contains(client)) {
        return;
    }

    m_clientBuffers[client].append(client->readAll());
    processFrames(client);
}

void Daemon::removeClient()
{
    auto *client = qobject_cast<QLocalSocket *>(sender());
    if (!client) {
        return;
    }
    m_clientBuffers.remove(client);
    m_clientFrameTimers.remove(client);
    client->deleteLater();
}

void Daemon::processFrames(QLocalSocket *client)
{
    QByteArray &buffer = m_clientBuffers[client];
    while (true) {
        const qsizetype newline = buffer.indexOf('\n');
        if (newline < 0) {
            if (buffer.size() > MaximumFrameSize) {
                client->write(encodeError({}, QStringLiteral("frame_too_large"),
                                          QStringLiteral("request frame is too large")));
                client->flush();
                client->disconnectFromServer();
            }
            if (auto *timer = m_clientFrameTimers.value(client)) timer->start();
            return;
        }

        if (newline + 1 > MaximumFrameSize) {
            client->write(encodeError({}, QStringLiteral("frame_too_large"),
                                      QStringLiteral("request frame is too large")));
            client->flush();
            client->disconnectFromServer();
            return;
        }

        const QByteArray frame = buffer.left(newline + 1);
        buffer.remove(0, newline + 1);
        if (auto *timer = m_clientFrameTimers.value(client)) timer->stop();

        Request request;
        QString error;
        if (!parseRequest(frame, request, &error)) {
            client->write(encodeError({}, QStringLiteral("invalid_request"), error));
        } else {
            ++m_processedRequestCount;
            client->write(handleRequest(request, client));
        }
        client->flush();
        // A complete frame makes progress, so give the peer one bounded idle
        // interval for its next request.  Leaving the timer stopped here
        // would turn a one-request connection into an immortal idle socket.
        if (auto *timer = m_clientFrameTimers.value(client)) timer->start();

        if (buffer.isEmpty()) {
            return;
        }
        // A packet may contain one complete request followed by the prefix
        // of another request.  processFrames() stops the timer after the
        // complete frame; restart it while the tail remains incomplete so a
        // peer cannot hold a local socket forever.
        if (buffer.indexOf('\n') < 0) {
            if (auto *timer = m_clientFrameTimers.value(client)) timer->start();
            return;
        }
    }
}

QByteArray Daemon::handleRequest(const Request &request, QLocalSocket *client)
{
    if (!authorizePrivilegedCommand(client, request)) {
        return encodeError(request.requestId, QStringLiteral("permission_denied"),
                           QStringLiteral("this daemon operation requires a root-owned local peer"));
    }
    ensureBackendHealthy();
    switch (request.command) {
    case Command::Status:
        return statusResponse(request.requestId);
    case Command::ListProfiles:
        return profileListResponse(request);
    case Command::Doctor: {
        QJsonObject result = m_vpnBackend.doctor();
        result.insert(QStringLiteral("state"), m_state);
        result.insert(QStringLiteral("socket"), m_socketPath);
        result.insert(QStringLiteral("routing"), m_routingController.status());
        result.insert(QStringLiteral("updates"), m_updateManager.status());
        return encodeResponse(request.requestId, result);
    }
    case Command::Connect: {
        if (m_state == QStringLiteral("cleanup_failed")
            || m_state == QStringLiteral("recovery_required")) {
            return encodeError(request.requestId, m_state,
                               QStringLiteral("daemon requires cleanup or recovery before another connection"));
        }
        const QString profile = request.parameters.value(QStringLiteral("profile"))
                                         .toString().trimmed();
        if (profile.isEmpty()) {
            return encodeError(request.requestId, QStringLiteral("invalid_parameters"),
                               QStringLiteral("connect requires a profile"));
        }
        Profile storedProfile;
        if (!m_profileStore.profile(profile, storedProfile)) {
            return encodeError(request.requestId, QStringLiteral("profile_not_found"),
                               QStringLiteral("profile does not exist"));
        }

        const BackendResult result = m_vpnBackend.connect(storedProfile);
        if (!result.ok) {
            return encodeError(request.requestId, result.code, result.message);
        }
        m_backendOwned = true;
        const RoutingResult routingResult = m_routingController.connect(storedProfile);
        if (!routingResult.ok) {
            // The reconciler owns rollback of its own transaction.  This
            // daemon did not acquire routing ownership on a failed connect,
            // so do not issue an extra cleanup mutation here.
            const BackendResult backendCleanup = m_vpnBackend.disconnect();
            if (backendCleanup.ok) m_backendOwned = false;
            m_routingRefreshTimer.stop();
            if (!backendCleanup.ok) {
                m_state = QStringLiteral("cleanup_failed");
                m_activeProfile = storedProfile.id;
                m_activeProfileData = storedProfile;
                return encodeError(request.requestId, QStringLiteral("cleanup_failed"),
                                   QStringLiteral("connection failed and cleanup requires recovery"));
            }
            m_state = QStringLiteral("disconnected");
            m_backendConnectedTimer.invalidate();
            m_activeProfile.clear();
            m_activeProfileData.reset();
            return encodeError(request.requestId, routingResult.code, routingResult.message);
        }
        m_routingOwned = true;
        m_state = QStringLiteral("connected");
        m_backendConnectedTimer.start();
        m_activeProfile = storedProfile.id;
        m_activeProfileData = storedProfile;
        if (!storedProfile.serverRulesUrl.isEmpty()) {
            m_routingRefreshTimer.start();
        } else {
            m_routingRefreshTimer.stop();
        }
        return statusResponse(request.requestId);
    }
    case Command::Disconnect: {
        const BackendResult result = m_backendOwned
                ? m_vpnBackend.disconnect() : BackendResult { true, {}, {} };
        if (result.ok) m_backendOwned = false;
        const RoutingResult routingResult = !result.ok
                ? RoutingResult { false, QStringLiteral("backend_stop_failed"),
                                  QStringLiteral("VPN backend did not stop; routing cleanup was withheld") }
                : m_routingOwned ? m_routingController.disconnect()
                                 : RoutingResult { true, {}, {} };
        if (routingResult.ok) m_routingOwned = false;
        m_routingRefreshTimer.stop();
        if (!result.ok || !routingResult.ok) {
            m_state = QStringLiteral("cleanup_failed");
            const QString code = !result.ok ? result.code : routingResult.code;
            const QString message = QStringLiteral("disconnect did not complete; recovery is required");
            return encodeError(request.requestId, code.isEmpty()
                               ? QStringLiteral("cleanup_failed") : code, message);
        }
        m_state = QStringLiteral("disconnected");
        m_backendConnectedTimer.invalidate();
        m_activeProfile.clear();
        m_activeProfileData.reset();
        return statusResponse(request.requestId);
    }
    case Command::Import:
        return importProfileResponse(request);
    case Command::Export:
        return exportProfileResponse(request);
    case Command::UpdateRollback: {
        const HeadlessUpdateResult result = m_updateManager.rollback();
        if (!result.ok) {
            return encodeError(request.requestId, result.code, result.message);
        }
        return statusResponse(request.requestId);
    }
    }

    return encodeError(request.requestId, QStringLiteral("internal_error"),
                       QStringLiteral("unknown daemon command"));
}

QByteArray Daemon::profileListResponse(const Request &request) const
{
    bool offsetOk = true;
    bool limitOk = true;
    const int offset = request.parameters.value(QStringLiteral("offset")).isUndefined()
            ? 0 : request.parameters.value(QStringLiteral("offset")).toInt(&offsetOk);
    const int limit = request.parameters.value(QStringLiteral("limit")).isUndefined()
            ? 32 : request.parameters.value(QStringLiteral("limit")).toInt(&limitOk);
    const QList<Profile> allProfiles = m_profileStore.profiles();
    if (!offsetOk || !limitOk || offset < 0 || offset > allProfiles.size()
        || limit < 1 || limit > 64) {
        return encodeError(request.requestId, QStringLiteral("invalid_parameters"),
                           QStringLiteral("list-profiles offset/limit is invalid"));
    }
    QJsonArray profiles;
    const qsizetype end = std::min<qsizetype>(offset + limit, allProfiles.size());
    for (qsizetype index = offset; index < end; ++index) {
        profiles.append(m_profileStore.toJson(allProfiles.at(index)));
    }
    return encodeResponse(request.requestId, QJsonObject {
        { QStringLiteral("profiles"), profiles },
        { QStringLiteral("active"), m_activeProfile },
        { QStringLiteral("offset"), offset },
        { QStringLiteral("limit"), limit },
        { QStringLiteral("total"), allProfiles.size() },
        { QStringLiteral("nextOffset"), end < allProfiles.size() ? QJsonValue(end) : QJsonValue() },
    });
}

bool Daemon::peerIsRoot(QLocalSocket *client) const
{
#if defined(Q_OS_LINUX)
    if (!client || client->socketDescriptor() < 0) return false;
    struct ucred peer {};
    socklen_t size = sizeof(peer);
    return ::getsockopt(static_cast<int>(client->socketDescriptor()), SOL_SOCKET,
                        SO_PEERCRED, &peer, &size) == 0 && peer.uid == 0 && peer.pid > 0;
#else
    Q_UNUSED(client);
    return false;
#endif
}

bool Daemon::authorizePrivilegedCommand(QLocalSocket *client, const Request &request) const
{
    switch (request.command) {
    case Command::Import:
    case Command::UpdateRollback:
        return peerIsRoot(client);
    default:
        return true;
    }
}

QByteArray Daemon::importProfileResponse(const Request &request)
{
    const QJsonValue profileValue = request.parameters.value(QStringLiteral("profile"));
    if (!profileValue.isObject()) {
        return encodeError(request.requestId, QStringLiteral("invalid_parameters"),
                           QStringLiteral("import requires a profile object"));
    }

    Profile profile;
    if (!m_profileStore.fromJson(profileValue.toObject(), profile)) {
        return encodeError(request.requestId, QStringLiteral("invalid_profile"),
                           m_profileStore.lastError());
    }
    if (!m_profileStore.add(profile)) {
        return encodeError(request.requestId, QStringLiteral("profile_rejected"),
                           m_profileStore.lastError());
    }
    return encodeResponse(request.requestId, QJsonObject {
        { QStringLiteral("profile"), m_profileStore.toJson(profile) },
    });
}

QByteArray Daemon::exportProfileResponse(const Request &request) const
{
    const QString id = request.parameters.value(QStringLiteral("id")).toString().trimmed();
    if (id.isEmpty()) {
        return encodeError(request.requestId, QStringLiteral("invalid_parameters"),
                           QStringLiteral("export requires a profile id"));
    }

    Profile profile;
    if (!m_profileStore.profile(id, profile)) {
        return encodeError(request.requestId, QStringLiteral("profile_not_found"),
                           QStringLiteral("profile does not exist"));
    }
    return encodeResponse(request.requestId, QJsonObject {
        { QStringLiteral("profile"), m_profileStore.toJson(profile) },
    });
}

QByteArray Daemon::statusResponse(const QString &requestId)
{
    ensureBackendHealthy();
    return encodeResponse(requestId, QJsonObject {
        { QStringLiteral("state"), m_state },
        { QStringLiteral("activeProfile"), m_activeProfile },
        { QStringLiteral("routing"), m_routingController.status() },
        { QStringLiteral("updates"), m_updateManager.status() },
    });
}

void Daemon::ensureBackendHealthy()
{
    // The backend owns the session interface.  The routing receipt may be
    // intentionally empty for a native only-forward profile, so using it as
    // the health target would make a dead tun/wg session look healthy.
    const bool handshakeGraceElapsed = m_backendConnectedTimer.isValid()
        && m_backendConnectedTimer.elapsed() >= 30'000;
    if (m_state != QStringLiteral("connected")
        || (m_vpnBackend.sessionAlive()
            && (!handshakeGraceElapsed || m_vpnBackend.sessionHealthyAfterRouting()))) {
        return;
    }
    m_routingRefreshTimer.stop();
    const BackendResult backend = m_backendOwned
            ? m_vpnBackend.disconnect() : BackendResult { true, {}, {} };
    if (backend.ok) m_backendOwned = false;
    const RoutingResult routing = backend.ok
            ? m_routingOwned ? m_routingController.disconnect()
                             : RoutingResult { true, {}, {} }
            : RoutingResult { false, QStringLiteral("backend_stop_failed"),
                              QStringLiteral("VPN backend did not stop; routing cleanup was withheld") };
    if (routing.ok) m_routingOwned = false;
    if (!routing.ok || !backend.ok) {
        m_state = QStringLiteral("cleanup_failed");
        return;
    }
    m_state = QStringLiteral("disconnected");
    m_backendConnectedTimer.invalidate();
    m_activeProfile.clear();
    m_activeProfileData.reset();
}

void Daemon::refreshManagedRoutes()
{
    ensureBackendHealthy();
    if (m_state != QStringLiteral("connected") || !m_activeProfileData.has_value()) {
        m_routingRefreshTimer.stop();
        return;
    }
    const RoutingResult result = m_routingController.refresh(m_activeProfileData.value());
    if (!result.ok) {
        // Refreshes retain the previous route set.  The warning is bounded and
        // intentionally omits the URL, domains and any profile material.
        qWarning() << "Headless managed route refresh failed:" << result.code;
        if (result.code == QStringLiteral("recovery_required")
            || m_routingController.status().value(QStringLiteral("recoveryRequired")).toBool()) {
            m_routingRefreshTimer.stop();
            m_state = QStringLiteral("recovery_required");
        }
    }
}

void Daemon::connectAutomaticProfile()
{
    if (m_state != QStringLiteral("disconnected")) {
        return;
    }
    if (m_routingController.status().value(QStringLiteral("recoveryRequired")).toBool()) {
        m_state = QStringLiteral("recovery_required");
        m_routingRefreshTimer.stop();
        return;
    }

    for (const Profile &profile : m_profileStore.profiles()) {
        if (!profile.autoConnect) {
            continue;
        }

        const BackendResult backend = m_vpnBackend.connect(profile);
        if (!backend.ok) {
            qWarning() << "Headless automatic VPN connection failed:" << backend.code;
            return;
        }
        m_backendOwned = true;
        const RoutingResult routing = m_routingController.connect(profile);
        if (!routing.ok) {
            const BackendResult backendCleanup = m_vpnBackend.disconnect();
            if (backendCleanup.ok) m_backendOwned = false;
            m_routingRefreshTimer.stop();
            if (!backendCleanup.ok) {
                m_state = QStringLiteral("cleanup_failed");
                m_activeProfile = profile.id;
                m_activeProfileData = profile;
            }
            qWarning() << "Headless automatic route setup failed:" << routing.code;
            return;
        }

        m_state = QStringLiteral("connected");
        m_routingOwned = true;
        m_backendConnectedTimer.start();
        m_activeProfile = profile.id;
        m_activeProfileData = profile;
        if (!profile.serverRulesUrl.isEmpty()) {
            m_routingRefreshTimer.start();
        }
        return;
    }
}

void Daemon::checkAutomaticUpdates()
{
    for (const Profile &profile : m_profileStore.profiles()) {
        if (!profile.autoUpdate) {
            continue;
        }
        const HeadlessUpdateResult result = m_updateManager.checkAndApply(
                profile, QStringLiteral(AMNEZIA_HEADLESS_VERSION));
        if (!result.ok && result.code != QStringLiteral("no_headless_artifact")) {
            qWarning() << "Headless automatic update failed:" << result.code;
        }
        if (result.code == QStringLiteral("updated")) {
            // systemd is expected to restart this daemon as part of the
            // transaction. Do not continue probing profiles in the old image.
            return;
        }
        if (result.code == QStringLiteral("restart_pending")
            || result.code == QStringLiteral("rollback_restart_pending")) {
            // Never begin a second transaction while systemd is replacing or
            // health-checking the daemon image.
            m_updateTimer.stop();
            return;
        }
    }
}

QString Daemon::defaultSocketPath()
{
#ifdef Q_OS_UNIX
    QString runtimeDirectory = qEnvironmentVariable("XDG_RUNTIME_DIR").trimmed();
    if (runtimeDirectory.isEmpty()) {
        runtimeDirectory = QDir::tempPath();
    }
    return QDir(runtimeDirectory).filePath(QStringLiteral("amneziad.sock"));
#else
    return QStringLiteral("amneziad");
#endif
}

QString Daemon::routeStatePathForStore(const QString &storePath)
{
    const QFileInfo storeInfo(storePath);
    if (storeInfo.absolutePath().isEmpty()) {
        return {};
    }
    return QDir(storeInfo.absolutePath()).filePath(QStringLiteral("managed-routes.json"));
}

QString Daemon::updateStatePathForStore(const QString &storePath)
{
    const QFileInfo storeInfo(storePath);
    if (storeInfo.absolutePath().isEmpty()) {
        return {};
    }
    return QDir(storeInfo.absolutePath()).filePath(QStringLiteral("headless-updates.json"));
}

void Daemon::setError(QString *error, const QString &message)
{
    if (error) {
        *error = message;
    }
}

} // namespace amnezia::headless
