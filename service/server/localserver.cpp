#include "localserver.h"

#include <cstdlib>

#include <QCoreApplication>
#include <QDebug>
#include <QFileInfo>
#include <QLocalServer>
#include <QLocalSocket>
#include <QObject>
#include <QSharedPointer>
#include <QString>
#include <QTimer>

#include "ipc.h"
#include "localpeerauthentication.h"
#include "killswitch.h"
#include "logger.h"

#ifdef Q_OS_WIN
    #include "tapcontroller_win.h"
#endif

namespace {
Logger logger("WgDaemonServer");
}

LocalServer::LocalServer(QObject *parent) : QObject(parent),
    m_ipcServer(this)
{
    auto failStartup = [](const QString &message) {
        qCritical() << message;
        QTimer::singleShot(0, qApp, []() { QCoreApplication::exit(EXIT_FAILURE); });
    };

#ifdef Q_OS_WIN
    if (!daemon.isInitialized()) {
        failStartup(QStringLiteral("Unable to initialize Windows VPN firewall"));
        return;
    }
#endif

    QString runtimeError;
    if (!amnezia::ipc::preparePrivilegedIpcRuntime(&runtimeError)) {
        failStartup(QStringLiteral("Unable to prepare privileged IPC: %1").arg(runtimeError));
        return;
    }

    // Create the server and listen outside of QtRO
    m_server = QSharedPointer<amnezia::ipc::PrivilegedLocalServer>(
            new amnezia::ipc::PrivilegedLocalServer(this));
    // The service is intentionally reachable by unelevated desktop users. Each
    // accepted socket is authenticated from OS peer credentials before QtRO.
#ifndef Q_OS_WIN
    m_server->setSocketOptions(QLocalServer::WorldAccessOption);
#endif
    m_server->setMaxPendingConnections(32);
    m_server->setListenBacklogSize(1);

    const QString serviceUrl = amnezia::getIpcServiceUrl();
    if (!amnezia::ipc::removeStalePrivilegedSocket(serviceUrl, &runtimeError)
        || !m_server->listen(serviceUrl)) {
        failStartup(QStringLiteral("Unable to start privileged IPC server: %1")
                        .arg(runtimeError.isEmpty() ? m_server->errorString() : runtimeError));
        return;
    }

    QObject::connect(m_server.data(), &amnezia::ipc::PrivilegedLocalServer::newConnection,
                     this, [this]() {
        while (m_server->hasPendingConnections()) {
            QLocalSocket *connection = m_server->nextPendingConnection();
            if (!connection) {
                continue;
            }

            QString authorizationError;
            amnezia::ipc::LocalPeerIdentity peerIdentity;
            if (!amnezia::ipc::authorizePrivilegedClient(
                    connection, amnezia::ipc::installedClientExecutablePath(), &peerIdentity,
                    &authorizationError)) {
                qWarning() << "Rejected unauthorized privileged IPC connection:"
                           << authorizationError;
                connection->abort();
                connection->deleteLater();
                continue;
            }

            qDebug() << "Accepted authenticated privileged IPC connection from"
                     << peerIdentity.userIdentifier << "session" << peerIdentity.sessionId;
            m_serverNode.addHostSideConnection(connection);

            if (!m_isRemotingEnabled) {
                m_isRemotingEnabled = true;
                m_serverNode.enableRemoting(&m_ipcServer);
            }
        }
    });

    // Init Mozilla Wireguard Daemon
    if (!server.initialize()) {
        logger.error() << "Failed to initialize the server";
        failStartup(QStringLiteral("Unable to start privileged VPN daemon IPC"));
        return;
    }

    m_networkWatcher.initialize();
    connect(&m_networkWatcher, &NetworkWatcher::networkChanged, &m_ipcServer, &IpcServer::networkChanged);
    connect(&m_networkWatcher, &NetworkWatcher::wakeup, &m_ipcServer, &IpcServer::wakeup);
    if (!KillSwitch::instance()->init()) {
        logger.error() << "Failed to initialize the kill switch";
        failStartup(QStringLiteral("Unable to initialize firewall policy"));
        return;
    }

#ifdef Q_OS_LINUX
    // Signal handling for a proper shutdown.
    QObject::connect(qApp, &QCoreApplication::aboutToQuit,
                     []() { LinuxDaemon::instance()->deactivate(); });
#endif

#ifdef Q_OS_MAC
    // Signal handling for a proper shutdown.
    QObject::connect(qApp, &QCoreApplication::aboutToQuit,
                     []() { MacOSDaemon::instance()->deactivate(); });
#endif

#ifdef Q_OS_WIN
    // Signal handling for a proper shutdown.
    QObject::connect(qApp, &QCoreApplication::aboutToQuit,
                     []() { WindowsDaemon::instance()->deactivate(); });
#endif
}

LocalServer::~LocalServer()
{
    qDebug() << "Local server stopped";
}

