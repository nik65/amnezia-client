#include "coreController.h"

#include <QDateTime>
#include <QDirIterator>
#include <QNetworkAccessManager>
#include <QNetworkProxy>
#include <QTranslator>
#include <QTimer>
#include <QUrl>

#include <algorithm>
#include <optional>

#include "core/utils/boundedQueuedSnapshot.h"
#include "core/utils/selfhosted/sshSession.h"
#include "core/controllers/selfhosted/installController.h"
#include "core/controllers/selfhosted/importController.h"
#include "core/controllers/coreSignalHandlers.h"
#include "logger.h"
#include "secureQSettings.h"

#if defined(Q_OS_ANDROID)
    #include "core/utils/installedAppsImageProvider.h"
    #include "platforms/android/android_controller.h"
#endif

#if defined(Q_OS_IOS)
    #include "platforms/ios/ios_controller.h"
#endif

#if defined(Q_OS_IOS) || defined(MACOS_NE)
    #include <AmneziaVPN-Swift.h>
#endif

namespace
{
constexpr int guardianVpnSnapshotTimeoutMs = 750;
constexpr int guardianRecoveryDeadlineMs = 30000;

struct GuardianTunnelRuntimeSnapshot
{
    bool connected = false;
    bool applicationRoutedThroughVpn = false;
    bool tunnelPathVerified = false;
    quint64 connectionEpoch = 0;
};

}

CoreController::CoreController(const QSharedPointer<VpnConnection> &vpnConnection, SecureQSettings* settings,
                               QQmlApplicationEngine *engine, QObject *parent)
    : QObject(parent), m_vpnConnection(vpnConnection), m_settings(settings), m_engine(engine)
{
    m_guardianNetworkManager = new QNetworkAccessManager(this);
    m_guardianNetworkManager->setProxy(QNetworkProxy::NoProxy);

    m_guardianPeriodicProbeTimer.setInterval(90 * 1000);
    m_guardianPeriodicProbeTimer.setSingleShot(false);
    connect(&m_guardianPeriodicProbeTimer, &QTimer::timeout, this, [this]() {
        if (m_latestConnectionState == Vpn::ConnectionState::Connected
            && m_connectionHealthController && !m_connectionHealthController->probeRunning()) {
            scheduleGuardianConnectivityProbe(0);
        }
    });
    m_guardianRecoveryDeadlineTimer.setSingleShot(true);
    m_guardianRecoveryDeadlineTimer.setInterval(guardianRecoveryDeadlineMs);
    connect(&m_guardianRecoveryDeadlineTimer, &QTimer::timeout, this, [this]() {
        if (m_guardianRecoveryInFlight) {
            finishGuardianRecovery(
                    false, QStringLiteral("recovery_timeout"),
                    m_guardianInFlightRecoveryEpoch);
        }
    });

    initRepositories();
    initCoreControllers();
    initModels();
    initControllers();
    initSignalHandlers();

    initAndroidController();
    initAppleController();
    initLogging();
    initRemoteLogUploader();
    initDiagnosticsControllers();

    m_translator = new QTranslator(this);
    if (m_appSettingsRepository) {
        updateTranslator(m_appSettingsRepository->getAppLanguage());
    }

    // A successful process launch alone is not a health signal. Give the GUI,
    // controllers and companion service a bounded startup observation window
    // before acknowledging the newly installed version.
    QTimer::singleShot(30000, this, &CoreController::confirmRunningVersionHealthWhenReady);
}

void CoreController::setQmlContextProperty(const QString &name, QObject *value)
{
    if (m_engine) {
        m_engine->rootContext()->setContextProperty(name, value);
    }
}

void CoreController::initModels()
{
    m_containersModel = new ContainersModel(this);
    setQmlContextProperty("ContainersModel", m_containersModel);

    m_defaultServerContainersModel = new ContainersModel(this);
    setQmlContextProperty("DefaultServerContainersModel", m_defaultServerContainersModel);

    m_serversModel = new ServersModel(this);
    setQmlContextProperty("ServersModel", m_serversModel);

    m_languageModel = new LanguageModel(this);
    setQmlContextProperty("LanguageModel", m_languageModel);

    m_ipSplitTunnelingModel = new IpSplitTunnelingModel(this);
    setQmlContextProperty("IpSplitTunnelingModel", m_ipSplitTunnelingModel);

    m_managedExceptSitesModel = new IpSplitTunnelingModel(this);
    setQmlContextProperty("ManagedExceptSitesModel", m_managedExceptSitesModel);

    m_allowedDnsModel = new AllowedDnsModel(this);
    setQmlContextProperty("AllowedDnsModel", m_allowedDnsModel);

    m_appSplitTunnelingModel = new AppSplitTunnelingModel(this);
    setQmlContextProperty("AppSplitTunnelingModel", m_appSplitTunnelingModel);

    m_protocolsModel = new ProtocolsModel(this);
    setQmlContextProperty("ProtocolsModel", m_protocolsModel);

    m_openVpnConfigModel = new OpenVpnConfigModel(this);
    setQmlContextProperty("OpenVpnConfigModel", m_openVpnConfigModel);

    m_wireGuardConfigModel = new WireGuardConfigModel(this);
    setQmlContextProperty("WireGuardConfigModel", m_wireGuardConfigModel);

    m_awgConfigModel = new AwgConfigModel(this);
    setQmlContextProperty("AwgConfigModel", m_awgConfigModel);

    m_xrayConfigModel = new XrayConfigModel(this);
    setQmlContextProperty("XrayConfigModel", m_xrayConfigModel);

    m_xrayConfigSnapshotsModel = new XrayConfigSnapshotsModel(m_appSettingsRepository, m_xrayConfigModel, this);
    setQmlContextProperty("XrayConfigSnapshotsModel", m_xrayConfigSnapshotsModel);

    m_torConfigModel = new TorConfigModel(this);
    setQmlContextProperty("TorConfigModel", m_torConfigModel);

#ifdef Q_OS_WINDOWS
    m_ikev2ConfigModel = new Ikev2ConfigModel(this);
    setQmlContextProperty("Ikev2ConfigModel", m_ikev2ConfigModel);
#endif

    m_sftpConfigModel = new SftpConfigModel(this);
    setQmlContextProperty("SftpConfigModel", m_sftpConfigModel);

    m_socks5ConfigModel = new Socks5ProxyConfigModel(this);
    setQmlContextProperty("Socks5ProxyConfigModel", m_socks5ConfigModel);

    m_mtProxyConfigModel = new MtProxyConfigModel(this);
    setQmlContextProperty("MtProxyConfigModel", m_mtProxyConfigModel);

    m_telemtConfigModel = new TelemtConfigModel(this);
    setQmlContextProperty("TelemtConfigModel", m_telemtConfigModel);

    m_clientManagementModel = new ClientManagementModel(this);
    setQmlContextProperty("ClientManagementModel", m_clientManagementModel);

    m_apiServicesModel = new ApiServicesModel(this);
    setQmlContextProperty("ApiServicesModel", m_apiServicesModel);

    m_apiCountryModel = new ApiCountryModel(this);
    setQmlContextProperty("ApiCountryModel", m_apiCountryModel);

    m_apiSubscriptionPlansModel = new ApiSubscriptionPlansModel(this);
    setQmlContextProperty("ApiSubscriptionPlansModel", m_apiSubscriptionPlansModel);

    m_apiBenefitsModel = new ApiBenefitsModel(this);
    setQmlContextProperty("ApiBenefitsModel", m_apiBenefitsModel);

    m_apiAccountInfoModel = new ApiAccountInfoModel(this);
    setQmlContextProperty("ApiAccountInfoModel", m_apiAccountInfoModel);

    m_apiDevicesModel = new ApiDevicesModel(this);
    setQmlContextProperty("ApiDevicesModel", m_apiDevicesModel);

    m_newsModel = new NewsModel(m_appSettingsRepository, this);
    setQmlContextProperty("NewsModel", m_newsModel);
}

void CoreController::initRepositories()
{
    m_serversRepository = new SecureServersRepository(m_settings, this);
    m_appSettingsRepository = new SecureAppSettingsRepository(m_settings, this);

}

void CoreController::initCoreControllers()
{
    m_serversController = new ServersController(m_serversRepository, m_appSettingsRepository, this);
    m_appSplitTunnelingController = new AppSplitTunnelingController(m_appSettingsRepository);
    m_usersController = new UsersController(m_serversRepository, this);
    m_ipSplitTunnelingController = new IpSplitTunnelingController(m_appSettingsRepository, this);
    m_allowedDnsController = new AllowedDnsController(m_appSettingsRepository);
    m_servicesCatalogController = new ServicesCatalogController(m_appSettingsRepository);
    m_subscriptionController = new SubscriptionController(m_serversRepository, m_appSettingsRepository);
    m_newsController = new NewsController(m_appSettingsRepository, m_serversRepository);
    m_updateController = new UpdateController(m_appSettingsRepository, m_serversRepository, this);
    m_selfHostedUpdateBootstrapper = new SelfHostedUpdateBootstrapper(m_serversRepository, this);
    
    m_installController = new InstallController(m_serversRepository, m_appSettingsRepository, this);
    m_exportController = new ExportController(m_serversRepository, m_appSettingsRepository, this);
    m_importCoreController = new ImportController(m_serversRepository, m_appSettingsRepository, this);
    m_connectionController = new ConnectionController(m_serversRepository, m_appSettingsRepository, m_vpnConnection.get(), this);
    m_connectionHealthController = new ConnectionHealthController(this);
    m_routeInspectorController = new RouteInspectorController(m_serversRepository, m_appSettingsRepository,
                                                              m_vpnConnection.get(), this);
    m_settingsController = new SettingsController(m_serversRepository, m_appSettingsRepository, this);

    connect(m_vpnConnection.get(), &VpnConnection::connectionContextChanged,
            this, [this](const QString &, const QString &, quint64 connectionEpoch) {
                m_latestConnectionEpoch = connectionEpoch;
            }, Qt::QueuedConnection);
    connect(m_connectionHealthController,
            &ConnectionHealthController::recoverySuggested,
            this, [this](ConnectionHealthController::RecoveryAction action,
                         const QString &, int attempt) {
                m_guardianSuggestedRecoveryAction = action;
                m_guardianSuggestedRecoveryAttempt = attempt;
                m_guardianSuggestedRecoveryEpoch =
                        m_connectionHealthController->pendingRecoveryEpoch();
                m_guardianSuggestedConnectionEpoch = m_latestConnectionEpoch;
            });
    connect(m_connectionHealthController,
            &ConnectionHealthController::recoveryActionRequested,
            this, &CoreController::handleGuardianRecoveryRequest);

    connect(m_connectionController, &ConnectionController::connectionStateChanged,
            m_connectionHealthController, [this](Vpn::ConnectionState state) {
                using HealthState = ConnectionHealthController::HealthState;
                m_latestConnectionState = state;
                if (m_guardianRecoveryInFlight) {
                    if (state == Vpn::ConnectionState::Connected
                        && m_latestConnectionEpoch
                                != m_guardianRecoveryConnectionEpoch) {
                        finishGuardianRecovery(
                                true, QStringLiteral("recovery_succeeded"),
                                m_guardianInFlightRecoveryEpoch);
                    } else if (state == Vpn::ConnectionState::Error
                               || state == Vpn::ConnectionState::Disconnected) {
                        finishGuardianRecovery(
                                false, QStringLiteral("recovery_failed"),
                                m_guardianInFlightRecoveryEpoch);
                    }
                }
                switch (state) {
                case Vpn::ConnectionState::Connected: {
                    const bool reachable = !m_networkReachabilityController
                            || m_networkReachabilityController->hasInternetAccess();
                    m_connectionHealthController->recordHealthState(
                        HealthState::Unknown,
                        reachable ? QStringLiteral("awaiting_probe")
                                  : QStringLiteral("reachability_hint_offline"));
                    if (!reachable) {
                        m_connectionHealthController->recordEvent(
                                QStringLiteral("reachability"), QStringLiteral("hint_offline"),
                                { { QStringLiteral("authoritative"), false } });
                    }
                    // Platform reachability/NCSI is only a hint and can be false
                    // under a kill switch or restricted network. Route/DNS setup
                    // completes immediately before Connected; let the bounded
                    // origin probe provide the actual observation.
                    scheduleGuardianConnectivityProbe(500);
                    break;
                }
                case Vpn::ConnectionState::Reconnecting:
                    cancelGuardianConnectivityProbe(QStringLiteral("tunnel_connecting"));
                    if (!m_guardianRecoveryInFlight) {
                        m_connectionHealthController->recordHealthState(
                                HealthState::Recovering,
                                QStringLiteral("recovering"));
                    }
                    break;
                case Vpn::ConnectionState::Error:
                    cancelGuardianConnectivityProbe(QStringLiteral("tunnel_error"));
                    m_connectionHealthController->recordHealthState(HealthState::Unhealthy,
                                                                    QStringLiteral("tunnel_error"));
                    m_connectionHealthController->evaluateRecovery(QStringLiteral("tunnel_error"));
                    break;
                case Vpn::ConnectionState::Preparing:
                case Vpn::ConnectionState::Connecting:
                    cancelGuardianConnectivityProbe(QStringLiteral("tunnel_connecting"));
                    m_connectionHealthController->recordHealthState(HealthState::Unknown,
                                                                    QStringLiteral("tunnel_connecting"));
                    break;
                case Vpn::ConnectionState::Disconnecting:
                    cancelGuardianConnectivityProbe(QStringLiteral("tunnel_disconnected"));
                    m_connectionHealthController->recordHealthState(HealthState::Unknown,
                                                                    QStringLiteral("tunnel_disconnected"));
                    break;
                case Vpn::ConnectionState::Disconnected:
                case Vpn::ConnectionState::Unknown:
                    cancelGuardianConnectivityProbe(QStringLiteral("tunnel_disconnected"));
                    m_connectionHealthController->recordHealthState(HealthState::Unknown,
                                                                    QStringLiteral("tunnel_disconnected"));
                    break;
                }
            });
}

void CoreController::initControllers()
{
    m_connectionUiController = new ConnectionUiController(m_connectionController, m_serversController, this);
    setQmlContextProperty("ConnectionController", m_connectionUiController);
    setQmlContextProperty("ConnectionHealthController", m_connectionHealthController);
    setQmlContextProperty("RouteInspectorController", m_routeInspectorController);

    if (m_engine) {
        m_focusController = new FocusController(m_engine, this);
        setQmlContextProperty("FocusController", m_focusController);
    }

    m_installUiController = new InstallUiController(m_installController, m_serversController, m_settingsController, m_protocolsModel, m_usersController,
                                                     m_awgConfigModel, m_wireGuardConfigModel, m_openVpnConfigModel, m_xrayConfigModel, m_torConfigModel,
#ifdef Q_OS_WINDOWS
                                                     m_ikev2ConfigModel,
#endif
                                                     m_sftpConfigModel, m_socks5ConfigModel, m_mtProxyConfigModel, m_telemtConfigModel,
                                                     m_connectionController, this);
    setQmlContextProperty("InstallController", m_installUiController);

    m_importController = new ImportUiController(m_importCoreController, this);
    setQmlContextProperty("ImportController", m_importController);

    m_exportUiController = new ExportUiController(m_exportController, this);
    setQmlContextProperty("ExportController", m_exportUiController);

    m_languageUiController = new LanguageUiController(m_settingsController, m_languageModel, this);
    setQmlContextProperty("LanguageUiController", m_languageUiController);

    m_settingsUiController = new SettingsUiController(m_settingsController, m_serversController, this);
    setQmlContextProperty("SettingsController", m_settingsUiController);

    m_pageController = new PageController(m_serversController, m_settingsController, this);
    setQmlContextProperty("PageController", m_pageController);

    m_serversUiController = new ServersUiController(m_serversController, m_settingsController, m_serversModel, m_containersModel, m_defaultServerContainersModel, this);
    setQmlContextProperty("ServersUiController", m_serversUiController);

    m_sitesController = new SitesController(m_serversRepository, m_serversUiController, m_installController, m_managedExceptSitesModel, this);
    setQmlContextProperty("SitesController", m_sitesController);
    connect(m_serversUiController, &ServersUiController::processedServerIndexChanged,
            m_sitesController, [this]() { m_sitesController->reloadManagedSites(); });
    connect(m_connectionController, &ConnectionController::serverRoutingRulesChanged,
            m_sitesController, [this](int serverIndex) {
                if (m_serversUiController && serverIndex == m_serversUiController->getProcessedServerIndex()) {
                    m_sitesController->reloadManagedSites();
                }
            });
    connect(m_serversRepository, &SecureServersRepository::serverEdited,
            m_sitesController, [this](const QString &serverId) {
                const int serverIndex = m_serversRepository->indexOfServerId(serverId);
                if (m_serversUiController && serverIndex == m_serversUiController->getProcessedServerIndex()) {
                    m_sitesController->reloadManagedSites();
                }
            });
    connect(m_sitesController, &SitesController::managedSplitTunnelingRulesPublished,
            m_connectionController, &ConnectionController::onManagedSplitTunnelingRulesPublished);

    m_ipSplitTunnelingUiController = new IpSplitTunnelingUiController(m_ipSplitTunnelingController, m_ipSplitTunnelingModel, this);
    setQmlContextProperty("IpSplitTunnelingController", m_ipSplitTunnelingUiController);

    m_allowedDnsUiController = new AllowedDnsUiController(m_allowedDnsController, m_allowedDnsModel, this);
    setQmlContextProperty("AllowedDnsController", m_allowedDnsUiController);

    m_appSplitTunnelingUiController = new AppSplitTunnelingUiController(m_appSplitTunnelingController, m_appSplitTunnelingModel, this);
    setQmlContextProperty("AppSplitTunnelingController", m_appSplitTunnelingUiController);

    m_systemController = new SystemController(this);
    setQmlContextProperty("SystemController", m_systemController);

    m_networkReachabilityController = new NetworkReachabilityController(this);
    setQmlContextProperty("NetworkReachabilityController", m_networkReachabilityController);
    setQmlContextProperty("NetworkReachability", m_networkReachabilityController);
    connect(m_networkReachabilityController, &NetworkReachabilityController::hasInternetAccessChanged,
            m_connectionHealthController, [this]() {
                if (m_latestConnectionState != Vpn::ConnectionState::Connected) {
                    return;
                }
                const bool reachable = m_networkReachabilityController->hasInternetAccess();
                m_connectionHealthController->recordHealthState(
                    ConnectionHealthController::HealthState::Unknown,
                    reachable ? QStringLiteral("awaiting_probe")
                              : QStringLiteral("reachability_hint_offline"));
                if (!reachable) {
                    m_connectionHealthController->recordEvent(
                            QStringLiteral("reachability"), QStringLiteral("hint_offline"),
                            { { QStringLiteral("authoritative"), false } });
                }
                scheduleGuardianConnectivityProbe(250);
            });

    m_servicesCatalogUiController = new ServicesCatalogUiController(m_servicesCatalogController, m_apiServicesModel, this);
    setQmlContextProperty("ServicesCatalogUiController", m_servicesCatalogUiController);

    m_subscriptionUiController = new SubscriptionUiController(m_serversController, m_apiServicesModel, m_servicesCatalogController, m_subscriptionController,
                                                              m_apiSubscriptionPlansModel, m_apiBenefitsModel, m_apiAccountInfoModel,
                                                              m_apiCountryModel, m_apiDevicesModel, m_settingsController,
                                                              m_connectionController, this);
    setQmlContextProperty("SubscriptionUiController", m_subscriptionUiController);

    m_apiNewsUiController = new ApiNewsUiController(m_newsModel, m_newsController, this);
    setQmlContextProperty("ApiNewsController", m_apiNewsUiController);

    m_updateUiController = new UpdateUiController(m_updateController, this);
    setQmlContextProperty("UpdateController", m_updateUiController);
}

void CoreController::initAndroidController()
{
#ifdef Q_OS_ANDROID
    if (!AndroidController::initLogging()) {
        qFatal("Android logging initialization failed");
    }
    m_appSettingsRepository->setSaveLogs(true);
    AndroidController::instance()->setSaveLogs(true);
    AndroidController::instance()->setScreenshotsEnabled(m_appSettingsRepository->isScreenshotsEnabled());

    if (!AndroidController::instance()->initialize()) {
        qFatal("Android controller initialization failed");
    }

    if (m_engine) {
        m_engine->addImageProvider(QLatin1String("installedAppImage"), new InstalledAppsImageProvider);
    }
#endif
}

void CoreController::initAppleController()
{
#ifdef Q_OS_IOS
    IosController::Instance()->initialize();
#endif
#if defined(Q_OS_IOS) || defined(MACOS_NE)
    AmneziaVPN::toggleLogging(true);
#endif
#ifdef Q_OS_IOS
    QTimer::singleShot(0, this, [this]() { AmneziaVPN::toggleScreenshots(m_appSettingsRepository->isScreenshotsEnabled()); });
#endif
}

void CoreController::scheduleGuardianConnectivityProbe(int delayMs)
{
    if (m_latestConnectionState == Vpn::ConnectionState::Connected
        && !m_guardianPeriodicProbeTimer.isActive()) {
        m_guardianPeriodicProbeTimer.start();
    }
    const quint64 requestGeneration = ++m_guardianProbeRequestGeneration;
    QTimer::singleShot(std::max(0, delayMs), this, [this, requestGeneration]() {
        if (requestGeneration != m_guardianProbeRequestGeneration
            || !m_connectionHealthController || !m_appSettingsRepository
            || m_latestConnectionState != Vpn::ConnectionState::Connected) {
            return;
        }

        QUrl guardianProbeEndpoint(m_appSettingsRepository->getGatewayEndpoint());
        // The production gateway historically defaults to plain HTTP for the
        // legacy API transport. Guardian needs an authenticated origin before
        // it may treat a successful exchange as meaningful health evidence.
        // Upgrade only the known production origin; custom/dev endpoints keep
        // their configured scheme and therefore remain explicitly unverified.
        if (guardianProbeEndpoint.scheme().compare(QStringLiteral("http"), Qt::CaseInsensitive) == 0
            && guardianProbeEndpoint.host().compare(QStringLiteral("gw.amnezia.org"), Qt::CaseInsensitive) == 0) {
            guardianProbeEndpoint.setScheme(QStringLiteral("https"));
            guardianProbeEndpoint.setPort(-1);
        }

        requestBoundedQueuedSnapshot(
                m_vpnConnection.get(), this, guardianVpnSnapshotTimeoutMs,
                [](VpnConnection *vpnConnection) {
                    GuardianTunnelRuntimeSnapshot snapshot;
                    snapshot.connected = vpnConnection->connectionState()
                            == Vpn::ConnectionState::Connected;
                    const VpnConnection::ManagedRouteRuntimeSnapshot routeSnapshot =
                            vpnConnection->managedRouteRuntimeSnapshot();
                    snapshot.connectionEpoch = routeSnapshot.connectionEpoch;
                    snapshot.applicationRoutedThroughVpn =
                            vpnConnection->applicationUsesVpnDataPath(
                                    QStringLiteral("org.amnezia.vpn"));
                    // A confirmed full-tunnel route receipt is read-only,
                    // connection-epoch-bound evidence that ordinary origin
                    // traffic is assigned to the VPN data path. Split modes
                    // remain unverified until a target-specific route receipt
                    // exists.
                    snapshot.tunnelPathVerified = snapshot.connected
                            && routeSnapshot.confirmed
                            && !routeSnapshot.transitionPending
                            && routeSnapshot.mode == RouteMode::VpnAllSites
                            && vpnConnection->appliedSiteRouteMode()
                                    == RouteMode::VpnAllSites
                            && snapshot.applicationRoutedThroughVpn
                            && !vpnConnection->remoteAddress().isEmpty();
                    return snapshot;
                },
                [this, requestGeneration, guardianProbeEndpoint](
                        BoundedQueuedSnapshotStatus status,
                        std::optional<GuardianTunnelRuntimeSnapshot> snapshot) {
                    if (requestGeneration != m_guardianProbeRequestGeneration
                        || !m_connectionHealthController
                        || m_latestConnectionState
                                != Vpn::ConnectionState::Connected) {
                        return;
                    }
                    const bool snapshotCurrent =
                            status == BoundedQueuedSnapshotStatus::Ready
                            && snapshot.has_value()
                            && snapshot->connected
                            && snapshot->connectionEpoch
                                    == m_latestConnectionEpoch;
                    const bool applicationPathVerified = snapshotCurrent
                            && snapshot->applicationRoutedThroughVpn;
                    if (!applicationPathVerified) {
                        m_connectionHealthController->recordHealthState(
                                ConnectionHealthController::HealthState::Unknown,
                                QStringLiteral("probe_app_route_unverified"));
                        return;
                    }
                    if (!snapshot->tunnelPathVerified) {
                        m_connectionHealthController->recordHealthState(
                                ConnectionHealthController::HealthState::Unknown,
                                QStringLiteral("probe_tunnel_path_unverified"));
                        return;
                    }
                    // The Guardian transport is a CoreController child, so it
                    // follows this object's thread and lifetime. Re-validate
                    // its immutable direct-transport policy at the last
                    // possible point before creating a request.
                    if (!m_guardianNetworkManager
                        || m_guardianNetworkManager->thread() != thread()
                        || m_guardianNetworkManager->proxyFactory() != nullptr
                        || m_guardianNetworkManager->proxy().type()
                                != QNetworkProxy::NoProxy) {
                        m_connectionHealthController->recordHealthState(
                                ConnectionHealthController::HealthState::Unknown,
                                QStringLiteral("probe_proxy_path_unverified"));
                        return;
                    }
                    m_connectionHealthController->startConnectivityProbe(
                            m_guardianNetworkManager, guardianProbeEndpoint,
                            true, 5000, true);
                });
    });
}

void CoreController::handleGuardianRecoveryRequest(
        ConnectionHealthController::RecoveryAction action,
        const QString &reasonCode, int attempt, quint64 recoveryEpoch)
{
    Q_UNUSED(reasonCode)
    if (!m_connectionHealthController || recoveryEpoch == 0) {
        return;
    }
    const bool suggestionCurrent = !m_guardianRecoveryInFlight
            && recoveryEpoch == m_guardianSuggestedRecoveryEpoch
            && action == m_guardianSuggestedRecoveryAction
            && attempt == m_guardianSuggestedRecoveryAttempt
            && m_latestConnectionState == Vpn::ConnectionState::Connected
            && m_latestConnectionEpoch == m_guardianSuggestedConnectionEpoch;
    if (!suggestionCurrent) {
        m_connectionHealthController->acknowledgeRecoveryResult(
                false, QStringLiteral("recovery_stale_epoch"), recoveryEpoch);
        return;
    }

    const bool restartAction =
            action == ConnectionHealthController::RecoveryAction::RefreshNetwork
            || action == ConnectionHealthController::RecoveryAction::RepairDns
            || action == ConnectionHealthController::RecoveryAction::RepairRoutes
            || action == ConnectionHealthController::RecoveryAction::ReconnectTunnel;
    if (!restartAction || !m_vpnConnection) {
        m_connectionHealthController->acknowledgeRecoveryResult(
                false, QStringLiteral("recovery_dispatch_failed"), recoveryEpoch);
        return;
    }

    m_guardianRecoveryInFlight = true;
    m_guardianRecoveryConnectionEpoch = m_latestConnectionEpoch;
    m_guardianInFlightRecoveryEpoch = recoveryEpoch;
    const bool queued = QMetaObject::invokeMethod(
            m_vpnConnection.get(), "reconnectToVpn", Qt::QueuedConnection);
    if (!queued) {
        finishGuardianRecovery(
                false, QStringLiteral("recovery_dispatch_failed"),
                recoveryEpoch);
        return;
    }

    m_guardianRecoveryDeadlineTimer.start();
    m_connectionHealthController->recordEvent(
            QStringLiteral("recovery"), QStringLiteral("recovery_dispatched"),
            { { QStringLiteral("attempt"), attempt },
              { QStringLiteral("recovery_epoch"),
                QString::number(recoveryEpoch) } });
}

void CoreController::finishGuardianRecovery(
        bool success, const QString &reasonCode, quint64 recoveryEpoch)
{
    if (!m_guardianRecoveryInFlight
        || recoveryEpoch == 0
        || recoveryEpoch != m_guardianInFlightRecoveryEpoch) {
        return;
    }
    m_guardianRecoveryInFlight = false;
    m_guardianRecoveryDeadlineTimer.stop();
    m_guardianInFlightRecoveryEpoch = 0;
    if (m_connectionHealthController) {
        m_connectionHealthController->acknowledgeRecoveryResult(
                success, reasonCode, recoveryEpoch);
    }
    if (success
        && m_latestConnectionState == Vpn::ConnectionState::Connected) {
        scheduleGuardianConnectivityProbe(500);
    }
}

void CoreController::cancelGuardianConnectivityProbe(const QString &reason)
{
    ++m_guardianProbeRequestGeneration;
    m_guardianPeriodicProbeTimer.stop();
    if (m_connectionHealthController) {
        m_connectionHealthController->cancelConnectivityProbe(reason);
    }
}

void CoreController::initLogging()
{
    m_appSettingsRepository->setSaveLogs(true);
#if !defined(Q_OS_ANDROID)
    if (!Logger::init(false)) {
        qWarning() << "Initialization of debug subsystem failed";
    }
#endif
#if !defined(Q_OS_ANDROID) && !defined(Q_OS_IOS)
    Logger::setServiceLogsEnabled(true);
#endif
}

void CoreController::initRemoteLogUploader()
{
#ifdef Q_OS_ANDROID
    return;
#endif

    m_remoteLogUploader = new RemoteLogUploader(m_serversRepository, m_appSettingsRepository, m_vpnConnection.get(), this);
    m_remoteLogUploader->start();
}

void CoreController::initDiagnosticsControllers()
{
    // Keep the UI facade available on every platform. On Android the uploader
    // is intentionally absent and the facade reports its safe unavailable state.
    m_remoteLogHealthUiController = new RemoteLogHealthUiController(m_remoteLogUploader, this);
    setQmlContextProperty("RemoteLogHealthUiController", m_remoteLogHealthUiController);

    connect(this, &CoreController::translationsUpdated,
            m_remoteLogHealthUiController, &RemoteLogHealthUiController::onTranslationsUpdated);
}

void CoreController::confirmRunningVersionHealthWhenReady()
{
    if (!m_updateController || !m_connectionController) {
        return;
    }

    m_updateController->refreshPendingUpdateHealth();
    if (!m_updateController->isUpdateHealthConfirmationPending()) {
        return;
    }

    if (m_qmlRootReady && m_connectionController->isServiceReady()
        && m_updateController->confirmRunningVersionHealthy()) {
        return;
    }

    // Confirmation can fail because the companion service is still starting,
    // or because this process is not yet the target version. Continue only
    // while UpdateController still considers the receipt actionable.
    if (!m_updateController->isUpdateHealthConfirmationPending()) {
        return;
    }

    const QVariantMap receipt = m_updateController->getPendingUpdateHealthReceipt();
    const QVariant storedDeadline = receipt.value(QStringLiteral("deadlineAt"));
    QDateTime deadlineAt = storedDeadline.toDateTime();
    if (!deadlineAt.isValid()) {
        deadlineAt = QDateTime::fromString(storedDeadline.toString(), Qt::ISODateWithMs);
    }
    if (!deadlineAt.isValid()) {
        deadlineAt = QDateTime::fromString(storedDeadline.toString(), Qt::ISODate);
    }
    if (!deadlineAt.isValid()) {
        return;
    }

    deadlineAt = deadlineAt.toUTC();
    const qint64 remainingMs = QDateTime::currentDateTimeUtc().msecsTo(deadlineAt);
    if (remainingMs <= 0) {
        m_updateController->refreshPendingUpdateHealth();
        return;
    }

    const int retryDelayMs = remainingMs < 10000 ? static_cast<int>(remainingMs) : 10000;
    QTimer::singleShot(retryDelayMs, this, &CoreController::confirmRunningVersionHealthWhenReady);
}

void CoreController::initSignalHandlers()
{
    m_signalHandlers = new CoreSignalHandlers(this, this);
    m_signalHandlers->initAllHandlers();

    // Trigger initial update after handlers are connected
    m_serversUiController->updateModel();
    if (m_serversUiController->hasServersFromGatewayApi()) {
        m_apiNewsUiController->fetchNews(false);
    }
}

void CoreController::updateTranslator(const QLocale &locale)
{
    if (!m_translator->isEmpty()) {
        QCoreApplication::removeTranslator(m_translator);
    }

    QStringList availableTranslations;
    QDirIterator it(":/translations", QStringList("amneziavpn_*.qm"), QDir::Files);
    while (it.hasNext()) {
        availableTranslations << it.next();
    }

    // This code allow to load translation for the language only, without country code
    const QString lang = locale.name().split("_").first();
    const QString translationFilePrefix = QString(":/translations/amneziavpn_") + lang;
    QString strFileName = QString(":/translations/amneziavpn_%1.qm").arg(locale.name());
    for (const QString &translation : availableTranslations) {
        if (translation.contains(translationFilePrefix)) {
            strFileName = translation;
            break;
        }
    }

    if (m_translator->load(strFileName)) {
        QCoreApplication::installTranslator(m_translator);
    } else {
        if (m_translator->load(QString(":/translations/amneziavpn_en.qm"))) {
            QCoreApplication::installTranslator(m_translator);
        }
    }

    if (m_engine) {
        m_engine->retranslate();
    }

    emit translationsUpdated();
    if (m_languageUiController) {
        emit websiteUrlChanged(m_languageUiController->getCurrentSiteUrl());
    }
}

void CoreController::setQmlRoot()
{
    if (m_engine && m_systemController) {
        QObject *qmlRoot = m_engine->rootObjects().value(0);
        m_qmlRootReady = qmlRoot != nullptr;
        m_systemController->setQmlRoot(qmlRoot);
    }
}

PageController* CoreController::pageController() const
{
    return m_pageController;
}

void CoreController::openConnectionByIndex(int serverIndex)
{
    const QString serverId =
        m_serversUiController ? m_serversUiController->getServerId(serverIndex) : QString();
    if (serverId.isEmpty()) {
        return;
    }
    if (m_serversController) {
        m_serversController->setDefaultServer(serverId);
    }
    m_connectionUiController->toggleConnection();
}

void CoreController::importConfigFromData(const QString &data)
{
    if (!m_importController)
        return;

    if (m_importController->extractConfigFromData(data)) {
        m_importController->importConfig();
    }
}
