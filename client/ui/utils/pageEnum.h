#ifndef PAGE_ENUM_H
#define PAGE_ENUM_H

#include <QObject>
#include <QQmlEngine>

// Single canonical definition of PageLoader::PageEnum.
//
// History: upstream introduced this file in the branding rework while the
// fork still carried its own copy of the enum inside
// ui/controllers/qml/pageController.h. Two Q_NAMESPACE definitions of the
// same enum made AUTOMOC emit colliding meta-objects and broke the build.
// The lists were merged here: fork entries first, in the exact fork order
// (numeric values are part of the stored UI state contract), followed by
// the upstream-only entry at the end.

namespace PageLoader
{
    Q_NAMESPACE
    enum class PageEnum {
        PageStart = 0,
        PageHome,
        PageShare,
        PageDeinstalling,

        PageSettingsServersList,
        PageSettings,
        PageSettingsServerData,
        PageSettingsServerInfo,
        PageSettingsServerProtocols,
        PageSettingsServerServices,
        PageSettingsServerManagedSplitTunneling,
        PageSettingsServerProtocol,
        PageSettingsConnection,
        PageSettingsDns,
        PageSettingsApplication,
        PageSettingsNewsNotifications,
        PageSettingsNewsDetail,
        PageSettingsBackup,
        PageSettingsAbout,
        PageSettingsLogging,
        PageSettingsSplitTunneling,
        PageSettingsAppSplitTunneling,
        PageSettingsKillSwitch,
        PageSettingsApiServerInfo,
        PageSettingsApiAvailableCountries,
        PageSettingsApiSupport,
        PageSettingsApiInstructions,
        PageSettingsApiNativeConfigs,
        PageSettingsApiDevices,
        PageSettingsApiSubscriptionKey,
        PageSettingsKillSwitchExceptions,

        PageServiceSftpSettings,
        PageServiceTorWebsiteSettings,
        PageServiceDnsSettings,
        PageServiceSocksProxySettings,
        PageServiceMtProxySettings,
        PageServiceTelemtSettings,

        PageSetupWizardStart,
        PageSetupWizardCredentials,
        PageSetupWizardProtocols,
        PageSetupWizardEasy,
        PageSetupWizardProtocolSettings,
        PageSetupWizardInstalling,
        PageSetupWizardConfigSource,
        PageSetupWizardTextKey,
        PageSetupWizardViewConfig,
        PageSetupWizardQrReader,
        PageSetupWizardApiServicesList,
        PageSetupWizardApiFreeInfo,

        PageProtocolOpenVpnSettings,
        PageProtocolXraySettings,
        PageProtocolWireGuardSettings,
        PageProtocolAwgSettings,
        PageProtocolIKev2Settings,
        PageProtocolRaw,

        PageProtocolWireGuardClientSettings,
        PageProtocolAwgClientSettings,

        PageShareFullAccess,
        PageShareConnection,

        PageSetupWizardApiPremiumInfo,
        PageSetupWizardApiTrialEmail,

        PageDevMenu,

        PageProtocolXraySnapshots,
        PageProtocolXrayTransportSettings,
        PageProtocolXrayXmuxSettings,
        PageProtocolXrayFlowSettings,
        PageProtocolXraySecuritySettings,
        PageProtocolXrayXPaddingSettings,
        PageProtocolXrayXPaddingBytesSettings,

        PageFleetCenter,
        PageRouteInspector,

        PageSettingsLanguage,
    };
    Q_ENUM_NS(PageEnum)

    static void declareQmlPageEnum()
    {
        qmlRegisterUncreatableMetaObject(PageLoader::staticMetaObject, "PageEnum", 1, 0, "PageEnum", "Error: only enums");
    }
}

#endif // PAGE_ENUM_H
