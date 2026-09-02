#include "daemon.h"

#include <QDir>
#include <QFileInfo>
#include <QJsonArray>
#include <QLocalSocket>

#include <utility>

namespace amnezia::headless
{

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
      m_routingController(runner, routeStatePathForStore(m_profileStore.path())),
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

    if (!m_profileStore.load()) {
        setError(error, m_profileStore.lastError());
        return false;
    }

    const QFileInfo socketInfo(m_socketPath);
    const QString parentPath = socketInfo.absolutePath();
    if (!parentPath.isEmpty() && parentPath != QStringLiteral(".")) {
        if (!QDir().mkpath(parentPath)) {
            setError(error, QStringLiteral("unable to create socket directory"));
            return false;
        }
    }

    if (!m_server.listen(m_socketPath)) {
        // A previous daemon may have left a stale local-server endpoint. Never
        // remove an endpoint that answers: that is an active daemon owned by
        // another process and must remain untouched.
        QLocalSocket probe;
        probe.connectToServer(m_socketPath, QIODevice::ReadWrite);
        if (probe.waitForConnected(100)) {
            setError(error, m_server.errorString());
            return false;
        }

        QLocalServer::removeServer(m_socketPath);
        if (!m_server.listen(m_socketPath)) {
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
    m_updateTimer.start();
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
    m_routingController.disconnect();
    m_vpnBackend.disconnect();
    m_state = QStringLiteral("disconnected");
    m_activeProfile.clear();
    m_activeProfileData.reset();

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
        m_clientBuffers.insert(client, {});
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

        Request request;
        QString error;
        if (!parseRequest(frame, request, &error)) {
            client->write(encodeError({}, QStringLiteral("invalid_request"), error));
        } else {
            ++m_processedRequestCount;
            client->write(handleRequest(request));
        }
        client->flush();

        if (buffer.isEmpty()) {
            return;
        }
    }
}

QByteArray Daemon::handleRequest(const Request &request)
{
    switch (request.command) {
    case Command::Status:
        return statusResponse(request.requestId);
    case Command::ListProfiles:
        return profileListResponse(request.requestId);
    case Command::Doctor: {
        QJsonObject result = m_vpnBackend.doctor();
        result.insert(QStringLiteral("state"), m_state);
        result.insert(QStringLiteral("socket"), m_socketPath);
        result.insert(QStringLiteral("routing"), m_routingController.status());
        result.insert(QStringLiteral("updates"), m_updateManager.status());
        return encodeResponse(request.requestId, result);
    }
    case Command::Connect: {
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
        const RoutingResult routingResult = m_routingController.connect(storedProfile);
        if (!routingResult.ok) {
            // Routing setup may already have installed a bootstrap route used
            // to reach the server policy endpoint.  Always roll it back when
            // connection setup fails, before tearing down the VPN backend.
            m_routingController.disconnect();
            m_vpnBackend.disconnect();
            return encodeError(request.requestId, routingResult.code, routingResult.message);
        }
        m_state = QStringLiteral("connected");
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
        const RoutingResult routingResult = m_routingController.disconnect();
        const BackendResult result = m_vpnBackend.disconnect();
        if (!result.ok) {
            return encodeError(request.requestId, result.code, result.message);
        }
        if (!routingResult.ok) {
            return encodeError(request.requestId, routingResult.code, routingResult.message);
        }
        m_routingRefreshTimer.stop();
        m_state = QStringLiteral("disconnected");
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

QByteArray Daemon::profileListResponse(const QString &requestId) const
{
    QJsonArray profiles;
    for (const Profile &profile : m_profileStore.profiles()) {
        profiles.append(m_profileStore.toJson(profile));
    }
    return encodeResponse(requestId, QJsonObject {
        { QStringLiteral("profiles"), profiles },
        { QStringLiteral("active"), m_activeProfile },
    });
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

QByteArray Daemon::statusResponse(const QString &requestId) const
{
    return encodeResponse(requestId, QJsonObject {
        { QStringLiteral("state"), m_state },
        { QStringLiteral("activeProfile"), m_activeProfile },
        { QStringLiteral("routing"), m_routingController.status() },
        { QStringLiteral("updates"), m_updateManager.status() },
    });
}

void Daemon::refreshManagedRoutes()
{
    if (m_state != QStringLiteral("connected") || !m_activeProfileData.has_value()) {
        m_routingRefreshTimer.stop();
        return;
    }
    const RoutingResult result = m_routingController.refresh(m_activeProfileData.value());
    if (!result.ok) {
        // Refreshes retain the previous route set.  The warning is bounded and
        // intentionally omits the URL, domains and any profile material.
        qWarning() << "Headless managed route refresh failed:" << result.code;
    }
}

void Daemon::connectAutomaticProfile()
{
    if (m_state != QStringLiteral("disconnected")) {
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
        const RoutingResult routing = m_routingController.connect(profile);
        if (!routing.ok) {
            m_routingController.disconnect();
            m_vpnBackend.disconnect();
            qWarning() << "Headless automatic route setup failed:" << routing.code;
            return;
        }

        m_state = QStringLiteral("connected");
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
