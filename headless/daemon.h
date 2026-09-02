#ifndef AMNEZIA_HEADLESS_DAEMON_H
#define AMNEZIA_HEADLESS_DAEMON_H

#include <QHash>
#include <QLocalServer>
#include <QPointer>
#include <QString>
#include <QTimer>

#include <optional>

#include "headlessProtocol.h"
#include "headlessRoutingController.h"
#include "headlessUpdateManager.h"
#include "profileStore.h"
#include "vpnBackend.h"

class QLocalSocket;

namespace amnezia::headless
{

class Daemon final : public QObject
{
    Q_OBJECT

public:
    explicit Daemon(QString socketPath = {}, QString profileStorePath = {},
                    std::shared_ptr<CommandRunner> runner = {},
                    QString configRoot = {},
                    bool requireRootOwnedConfig = false,
                    QObject *parent = nullptr,
                    QString stagingRoot = {});
    ~Daemon() override;

    bool start(QString *error = nullptr);
    void stop();

    bool isRunning() const;
    QString socketPath() const;
    int connectedClientCount() const;
    int processedRequestCount() const;

private:
    void acceptConnections();
    void readFromClient();
    void removeClient();
    void processFrames(QLocalSocket *client);
    QByteArray handleRequest(const Request &request);
    QByteArray statusResponse(const QString &requestId) const;
    QByteArray profileListResponse(const QString &requestId) const;
    QByteArray importProfileResponse(const Request &request);
    QByteArray exportProfileResponse(const Request &request) const;

    static QString defaultSocketPath();
    static QString routeStatePathForStore(const QString &storePath);
    static QString updateStatePathForStore(const QString &storePath);
    static void setError(QString *error, const QString &message);
    void connectAutomaticProfile();
    void refreshManagedRoutes();
    void checkAutomaticUpdates();

    QLocalServer m_server;
    QString m_socketPath;
    QHash<QLocalSocket *, QByteArray> m_clientBuffers;
    ProfileStore m_profileStore;
    VpnBackend m_vpnBackend;
    HeadlessRoutingController m_routingController;
    HeadlessUpdateManager m_updateManager;
    QTimer m_routingRefreshTimer;
    QTimer m_updateTimer;
    int m_processedRequestCount = 0;
    QString m_state = QStringLiteral("disconnected");
    QString m_activeProfile;
    std::optional<Profile> m_activeProfileData;
};

} // namespace amnezia::headless

#endif // AMNEZIA_HEADLESS_DAEMON_H
