#ifndef AMNEZIA_APPLICATION_H
#define AMNEZIA_APPLICATION_H

#include <QCommandLineParser>
#include <QNetworkAccessManager>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QThread>
#include <QTimer>
#if defined(Q_OS_ANDROID) || defined(Q_OS_IOS)
  #include <QGuiApplication>
#else
  #include <QApplication>
#endif
#include <QClipboard>

#include "core/controllers/coreController.h"
#include "core/utils/operatorCommand.h"
#include "../ipc/windowsprivilegedpipe.h"
#include "secureQSettings.h"
#include "ui/controllers/marketplaceUpdateController.h"
#include "vpnConnection.h"
#include "ui/models/containerProps.h"
#include "ui/models/protocolProps.h"

class QLocalServer;
class QLockFile;

#define amnApp (static_cast<AmneziaApplication *>(QCoreApplication::instance()))

#if defined(Q_OS_ANDROID) || defined(Q_OS_IOS)
  #define AMNEZIA_BASE_CLASS QGuiApplication
#else
  #define AMNEZIA_BASE_CLASS QApplication
#endif

class AmneziaApplication : public AMNEZIA_BASE_CLASS
{
    Q_OBJECT
public:
    AmneziaApplication(
        int &argc, char *argv[],
        const amnezia::operatorMode::CommandParseResult &startupOperatorArguments,
        bool publishBundledUpdatesOnceCommand);
    virtual ~AmneziaApplication();

    void init();
    void registerTypes();
    void loadFonts();
    bool parseCommands();
    int commandExitCode() const;

    // Called by main before the legacy single-instance probe. Returns true only
    // when an operator command was handled by an already running instance (or
    // rejected locally), in which case exitCode contains the process result.
    static bool tryForwardOperatorCommand(
        const amnezia::operatorMode::CommandParseResult &parsed, int &exitCode);
    static QString localServerName();
    static bool isTrustedPrimaryRunning(int timeoutMs = 500);

#if !defined(Q_OS_ANDROID) && !defined(Q_OS_IOS)
    bool hasCoreOwnership() const;
#endif
#if !defined(Q_OS_ANDROID) && !defined(Q_OS_IOS) && !defined(MACOS_NE)
    // Returns true only after this process owns both the singleton lock and a
    // listening command endpoint. Callers must not initialize the application
    // core when ownership could not be established.
    bool startLocalServer();
#endif

    QQmlApplicationEngine *qmlEngine() const;
    QNetworkAccessManager *networkManager();
    QClipboard *getClipboard();

public slots:
    void forceQuit();

private:
    static bool m_forceQuit;
    QQmlApplicationEngine *m_engine {};
    SecureQSettings* m_settings {};

    QScopedPointer<CoreController> m_coreController;
    QScopedPointer<MarketplaceUpdateController> m_marketplaceUpdateController;

    QSharedPointer<ContainerProps> m_containerProps;
    QSharedPointer<ProtocolProps> m_protocolProps;

    QCommandLineParser m_parser;

    QCommandLineOption m_optAutostart;
    QCommandLineOption m_optCleanup;
    QCommandLineOption m_optConnect;
    QCommandLineOption m_optImport;
    QCommandLineOption m_optStatus;
    QCommandLineOption m_optJson;
    QCommandLineOption m_optDisconnect;
    QCommandLineOption m_optDoctor;
    QCommandLineOption m_optRoutesExplain;
    QCommandLineOption m_optWatch;
    QCommandLineOption m_optPublishBundledUpdatesOnce;
    int m_commandExitCode = 0;

    amnezia::operatorMode::CommandParseResult m_startupOperatorArguments;
    amnezia::operatorMode::CommandRequest m_operatorCommand;
    bool m_operatorCommandLineDetected = false;
    bool m_publishBundledUpdatesOnceCommand = false;
    bool m_hasOperatorCommand = false;
    bool m_operatorDisconnectInProgress = false;
    Vpn::ConnectionState m_operatorConnectionState = Vpn::ConnectionState::Unknown;
    quint64 m_operatorReceivedBytes = 0;
    quint64 m_operatorSentBytes = 0;
    bool m_operatorSnapshotAvailable = false;
    bool m_operatorSnapshotRefreshPending = false;
    quint64 m_operatorSnapshotGeneration = 0;
    qint64 m_operatorSnapshotRequestedAtMs = 0;
    qint64 m_operatorSnapshotCompletedAtMs = 0;
    int m_operatorSnapshotServerIndex = -1;
    QString m_operatorSnapshotServerId;
    DockerContainer m_operatorSnapshotContainer = DockerContainer::None;
    amnezia::RouteMode m_operatorSnapshotRouteMode = amnezia::RouteMode::VpnAllSites;
    QString m_operatorSnapshotRemoteAddress;
    QString m_operatorSnapshotRoutingSyncHost;
    QString m_operatorSnapshotVpnGateway;
    int m_operatorSnapshotLastError = static_cast<int>(amnezia::ErrorCode::NoError);

    QSharedPointer<VpnConnection> m_vpnConnection;
    QThread m_vpnConnectionThread;
    QTimer m_operatorSnapshotRefreshTimer;

    QNetworkAccessManager *m_nam {};

#if !defined(Q_OS_ANDROID) && !defined(Q_OS_IOS)
    QScopedPointer<QLockFile> m_localServerLock;
    bool acquireCoreOwnership();
#endif
#if !defined(Q_OS_ANDROID) && !defined(Q_OS_IOS) && !defined(MACOS_NE)
    amnezia::ipc::PrivilegedLocalServer *m_localServer {};
#endif

    void initVpnConnection();
    void requestOperatorVpnSnapshotRefresh(bool force = false);
    void runStartupOperatorCommand();
    amnezia::operatorMode::CommandResponse executeOperatorCommand(
        const amnezia::operatorMode::CommandRequest &request);
    amnezia::operatorMode::CommandResponse operatorStatus();
    amnezia::operatorMode::CommandResponse operatorDisconnect();
    amnezia::operatorMode::CommandResponse operatorDoctor() const;
    amnezia::operatorMode::CommandResponse operatorRoutesExplain(const QString &host) const;
protected:
    bool eventFilter(QObject *watched, QEvent *event) override;
};

#endif // AMNEZIA_APPLICATION_H
