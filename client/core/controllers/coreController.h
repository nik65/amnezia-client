#ifndef CORECONTROLLER_H
#define CORECONTROLLER_H

#include <QObject>
#include <QQmlContext>
#include <QThread>
#include <QTimer>

#if !defined(Q_OS_ANDROID) && !defined(Q_OS_IOS)
    #include "ui/utils/systemTrayNotificationHandler.h"
#endif

#include "ui/controllers/api/subscriptionUiController.h"
#include "ui/controllers/api/apiNewsUiController.h"
#include "ui/controllers/appSplitTunnelingUiController.h"
#include "ui/controllers/allowedDnsUiController.h"
#include "ui/controllers/connectionUiController.h"
#include "ui/controllers/selfhosted/exportUiController.h"
#include "core/controllers/selfhosted/exportController.h"
#include "ui/controllers/qml/focusController.h"
#include "ui/controllers/importUiController.h"
#include "core/controllers/selfhosted/importController.h"
#include "ui/controllers/selfhosted/installUiController.h"
#include "ui/controllers/qml/pageController.h"
#include "ui/controllers/settingsUiController.h"
#include "ui/controllers/serversUiController.h"
#include "ui/controllers/sitesController.h"
#include "ui/controllers/ipSplitTunnelingUiController.h"
#include "ui/controllers/systemController.h"
#include "ui/controllers/languageUiController.h"
#include "ui/controllers/updateUiController.h"
#include "ui/controllers/api/servicesCatalogUiController.h"
#include "ui/controllers/networkReachabilityController.h"
#include "ui/controllers/remoteLogHealthUiController.h"

#include "core/controllers/serversController.h"
#include "core/controllers/selfhosted/usersController.h"
#include "core/controllers/appSplitTunnelingController.h"
#include "core/controllers/ipSplitTunnelingController.h"
#include "core/controllers/allowedDnsController.h"
#include "core/controllers/selfhosted/selfHostedUpdateBootstrapper.h"
#include "core/controllers/api/servicesCatalogController.h"
#include "core/controllers/api/subscriptionController.h"
#include "core/controllers/api/newsController.h"
#include "core/controllers/selfhosted/installController.h"
#include "core/controllers/settingsController.h"
#include "core/controllers/connectionController.h"
#include "core/controllers/connectionHealthController.h"
#include "core/controllers/routeInspectorController.h"
#include "core/controllers/updateController.h"
#include "core/controllers/remoteLogUploader.h"

#include "core/repositories/secureServersRepository.h"
#include "core/repositories/secureAppSettingsRepository.h"
#include "secureQSettings.h"

#include "ui/models/allowedDnsModel.h"
#include "ui/models/containersModel.h"
#include "ui/models/languageModel.h"
#ifdef Q_OS_WINDOWS
    #include "ui/models/protocols/ikev2ConfigModel.h"
#endif
#include "ui/models/api/apiAccountInfoModel.h"
#include "ui/models/api/apiBenefitsModel.h"
#include "ui/models/api/apiCountryModel.h"
#include "ui/models/api/apiDevicesModel.h"
#include "ui/models/api/apiServicesModel.h"
#include "ui/models/api/apiSubscriptionPlansModel.h"
#include "ui/models/appSplitTunnelingModel.h"
#include "ui/models/clientManagementModel.h"
#include "ui/models/protocols/awgConfigModel.h"
#include "ui/models/protocols/openvpnConfigModel.h"
#include "ui/models/protocols/wireguardConfigModel.h"
#include "ui/models/protocols/xrayConfigModel.h"
#include "ui/models/protocols/xrayConfigSnapshotsModel.h"
#include "ui/models/protocolsModel.h"
#include "ui/models/services/torConfigModel.h"
#include "ui/models/serversModel.h"
#include "ui/models/services/sftpConfigModel.h"
#include "ui/models/services/socks5ProxyConfigModel.h"
#include "ui/models/services/mtProxyConfigModel.h"
#include "ui/models/services/telemtConfigModel.h"

#include "ui/models/ipSplitTunnelingModel.h"
#include "ui/models/newsModel.h"

#if !defined(Q_OS_ANDROID) && !defined(Q_OS_IOS)
    #include "ui/utils/notificationHandler.h"
#endif

class CoreSignalHandlers;
class QNetworkAccessManager;

class CoreController : public QObject
{
    Q_OBJECT
    friend class CoreSignalHandlers;

public:
    explicit CoreController(const QSharedPointer<VpnConnection> &vpnConnection, SecureQSettings* settings,
                            QQmlApplicationEngine *engine, QObject *parent = nullptr);

    PageController* pageController() const;
    void setQmlRoot();

    void openConnectionByIndex(int serverIndex);
    void importConfigFromData(const QString &data);
    void updateTranslator(const QLocale &locale);

signals:
    void translationsUpdated();
    void websiteUrlChanged(const QString &newUrl);

protected:
    SecureServersRepository* serversRepositoryProtected() const { return m_serversRepository; }
    SecureAppSettingsRepository* appSettingsRepositoryProtected() const { return m_appSettingsRepository; }
    ServersModel* serversModelProtected() const { return m_serversModel; }
    ContainersModel* containersModelProtected() const { return m_containersModel; }
    ApiServicesModel* apiServicesModelProtected() const { return m_apiServicesModel; }
    NewsModel* newsModelProtected() const { return m_newsModel; }
    AllowedDnsModel* allowedDnsModelProtected() const { return m_allowedDnsModel; }
    AppSplitTunnelingModel* appSplitTunnelingModelProtected() const { return m_appSplitTunnelingModel; }
    IpSplitTunnelingModel* ipSplitTunnelingModelProtected() const { return m_ipSplitTunnelingModel; }
    LanguageModel* languageModelProtected() const { return m_languageModel; }

    InstallUiController* installUiControllerProtected() const { return m_installUiController; }
    ImportController* importCoreControllerProtected() const { return m_importCoreController; }
    ExportController* exportControllerProtected() const { return m_exportController; }
    InstallController* installControllerProtected() const { return m_installController; }
    ServersController* serversControllerProtected() const { return m_serversController; }
    SettingsUiController* settingsUiControllerProtected() const { return m_settingsUiController; }
    SettingsController* settingsControllerProtected() const { return m_settingsController; }
    AllowedDnsUiController* allowedDnsUiControllerProtected() const { return m_allowedDnsUiController; }
    AllowedDnsController* allowedDnsControllerProtected() const { return m_allowedDnsController; }
    LanguageUiController* languageUiControllerProtected() const { return m_languageUiController; }
    IpSplitTunnelingController* ipSplitTunnelingControllerProtected() const { return m_ipSplitTunnelingController; }
    IpSplitTunnelingUiController* ipSplitTunnelingUiControllerProtected() const { return m_ipSplitTunnelingUiController; }
    AppSplitTunnelingController* appSplitTunnelingControllerProtected() const { return m_appSplitTunnelingController; }
    AppSplitTunnelingUiController* appSplitTunnelingUiControllerProtected() const { return m_appSplitTunnelingUiController; }
    ServersUiController* serversUiControllerProtected() const { return m_serversUiController; }
    ServicesCatalogUiController* servicesCatalogUiControllerProtected() const { return m_servicesCatalogUiController; }
    ApiNewsUiController* apiNewsUiControllerProtected() const { return m_apiNewsUiController; }

private:
    void initRepositories();
    void initCoreControllers();
    void initModels();
    void initControllers();
    void initAndroidController();
    void initAppleController();
    void initLogging();
    void initRemoteLogUploader();
    void initDiagnosticsControllers();
    void initSignalHandlers();
    void confirmRunningVersionHealthWhenReady();
    void scheduleGuardianConnectivityProbe(int delayMs = 500);
    void cancelGuardianConnectivityProbe(const QString &reason);
    void handleGuardianRecoveryRequest(
            ConnectionHealthController::RecoveryAction action,
            const QString &reasonCode, int attempt, quint64 recoveryEpoch);
    void finishGuardianRecovery(bool success, const QString &reasonCode,
                                quint64 recoveryEpoch);
    void setQmlContextProperty(const QString &name, QObject *value);

    QQmlApplicationEngine *m_engine {}; // TODO use parent child system here?
    SecureQSettings* m_settings;
    QSharedPointer<VpnConnection> m_vpnConnection;
    QTranslator* m_translator;
    bool m_qmlRootReady = false;

    SecureServersRepository* m_serversRepository;
    SecureAppSettingsRepository* m_appSettingsRepository;

#if !defined(Q_OS_ANDROID) && !defined(Q_OS_IOS)
    NotificationHandler* m_notificationHandler;
#endif

    QMetaObject::Connection m_reloadConfigErrorOccurredConnection;

    ConnectionUiController* m_connectionUiController;
    FocusController* m_focusController;
    PageController* m_pageController;
    InstallUiController* m_installUiController;
    ImportUiController* m_importController;
    ImportController* m_importCoreController;
    ExportUiController* m_exportUiController;
    SettingsUiController* m_settingsUiController;
    ServersUiController* m_serversUiController;
    SitesController* m_sitesController;
    IpSplitTunnelingUiController* m_ipSplitTunnelingUiController;
    SystemController* m_systemController;
    NetworkReachabilityController* m_networkReachabilityController = nullptr;
    AppSplitTunnelingUiController* m_appSplitTunnelingUiController;
    AllowedDnsUiController* m_allowedDnsUiController;
    LanguageUiController* m_languageUiController;
    UpdateUiController* m_updateUiController;

    SubscriptionUiController* m_subscriptionUiController;
    ApiNewsUiController* m_apiNewsUiController;
    
    ServicesCatalogUiController* m_servicesCatalogUiController;

    ServersController* m_serversController;
    UsersController* m_usersController;
    AppSplitTunnelingController* m_appSplitTunnelingController;
    IpSplitTunnelingController* m_ipSplitTunnelingController;
    AllowedDnsController* m_allowedDnsController;
    ServicesCatalogController* m_servicesCatalogController;
    SubscriptionController* m_subscriptionController;
    NewsController* m_newsController;
    UpdateController* m_updateController;
    RemoteLogUploader* m_remoteLogUploader = nullptr;
    RemoteLogHealthUiController* m_remoteLogHealthUiController = nullptr;
    SelfHostedUpdateBootstrapper* m_selfHostedUpdateBootstrapper;
    InstallController* m_installController;
    ExportController* m_exportController;
    ConnectionController* m_connectionController;
    ConnectionHealthController* m_connectionHealthController = nullptr;
    QNetworkAccessManager* m_guardianNetworkManager = nullptr;
    RouteInspectorController* m_routeInspectorController = nullptr;
    Vpn::ConnectionState m_latestConnectionState = Vpn::ConnectionState::Unknown;
    quint64 m_guardianProbeRequestGeneration = 0;
    QTimer m_guardianPeriodicProbeTimer;
    QTimer m_guardianRecoveryDeadlineTimer;
    quint64 m_latestConnectionEpoch = 0;
    quint64 m_guardianSuggestedRecoveryEpoch = 0;
    quint64 m_guardianSuggestedConnectionEpoch = 0;
    quint64 m_guardianRecoveryConnectionEpoch = 0;
    quint64 m_guardianInFlightRecoveryEpoch = 0;
    ConnectionHealthController::RecoveryAction m_guardianSuggestedRecoveryAction =
            ConnectionHealthController::RecoveryAction::None;
    int m_guardianSuggestedRecoveryAttempt = 0;
    bool m_guardianRecoveryInFlight = false;
    SettingsController* m_settingsController;

    ContainersModel* m_containersModel;
    ContainersModel* m_defaultServerContainersModel;
    ServersModel* m_serversModel;
    LanguageModel* m_languageModel;
    ProtocolsModel* m_protocolsModel;
    IpSplitTunnelingModel* m_ipSplitTunnelingModel;
    IpSplitTunnelingModel* m_managedExceptSitesModel;
    NewsModel* m_newsModel;
    AllowedDnsModel* m_allowedDnsModel;
    AppSplitTunnelingModel* m_appSplitTunnelingModel;
    ClientManagementModel* m_clientManagementModel;

    ApiServicesModel* m_apiServicesModel;
    ApiSubscriptionPlansModel* m_apiSubscriptionPlansModel;
    ApiBenefitsModel* m_apiBenefitsModel;
    ApiCountryModel* m_apiCountryModel;
    ApiAccountInfoModel* m_apiAccountInfoModel;
    ApiDevicesModel* m_apiDevicesModel;

    OpenVpnConfigModel* m_openVpnConfigModel;
    XrayConfigModel* m_xrayConfigModel;
    XrayConfigSnapshotsModel* m_xrayConfigSnapshotsModel;
    TorConfigModel* m_torConfigModel;
    WireGuardConfigModel* m_wireGuardConfigModel;
    AwgConfigModel* m_awgConfigModel;
#ifdef Q_OS_WINDOWS
    Ikev2ConfigModel* m_ikev2ConfigModel;
#endif
    SftpConfigModel* m_sftpConfigModel;
    Socks5ProxyConfigModel* m_socks5ConfigModel;
    MtProxyConfigModel* m_mtProxyConfigModel;
    TelemtConfigModel* m_telemtConfigModel;

    CoreSignalHandlers* m_signalHandlers;
};

#endif // CORECONTROLLER_H
