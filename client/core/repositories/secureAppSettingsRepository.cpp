#include "secureAppSettingsRepository.h"

#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonObject>
#include <QUuid>

#include "core/utils/errorCodes.h"
#include "core/utils/routeModes.h"
#include "core/utils/commonStructs.h"
#include "core/utils/serverConfigUtils.h"
#include "core/utils/constants/apiKeys.h"
#include "core/utils/constants/apiConstants.h"
#include "core/utils/constants/configKeys.h"
#include "core/utils/networkUtilities.h"

using namespace amnezia;

namespace {
    constexpr char gatewayEndpoint[] = "http://gw.amnezia.org:80/";
    constexpr char proxyUrlsKey[] = "Conf/proxyUrls/";
}

SecureAppSettingsRepository::SecureAppSettingsRepository(SecureQSettings* settings, QObject *parent)
    : QObject(parent), m_settings(settings)
{
    QString storedEndpoint = value("Conf/gatewayEndpoint", gatewayEndpoint).toString();
    m_gatewayEndpoint = storedEndpoint.isEmpty() ? gatewayEndpoint : storedEndpoint;
}

QVariant SecureAppSettingsRepository::value(const QString &key, const QVariant &defaultValue) const
{
    return m_settings->value(key, defaultValue);
}

void SecureAppSettingsRepository::setValue(const QString &key, const QVariant &value)
{
    m_settings->setValue(key, value);
}

QLocale SecureAppSettingsRepository::getAppLanguage() const
{
    QString localeStr = value("Conf/appLanguage", QLocale::system().name()).toString();
    return QLocale(localeStr);
}

void SecureAppSettingsRepository::setAppLanguage(QLocale locale)
{
    setValue("Conf/appLanguage", locale.name());
    emit appLanguageChanged(locale);
}

bool SecureAppSettingsRepository::useAmneziaDns() const
{
    return value("Conf/useAmneziaDns", true).toBool();
}

void SecureAppSettingsRepository::setUseAmneziaDns(bool enabled)
{
    setValue("Conf/useAmneziaDns", enabled);
    emit useAmneziaDnsChanged(enabled);
}

QStringList SecureAppSettingsRepository::getAllowedDnsServers() const
{
    return value("Conf/allowedDnsServers").toStringList();
}

void SecureAppSettingsRepository::setAllowedDnsServers(const QStringList &servers)
{
    setValue("Conf/allowedDnsServers", servers);
    emit allowedDnsServersChanged(servers);
}

QString SecureAppSettingsRepository::primaryDns() const
{
    constexpr char cloudFlareNs1[] = "1.1.1.1";
    return value("Conf/primaryDns", cloudFlareNs1).toString();
}

void SecureAppSettingsRepository::setPrimaryDns(const QString &dns)
{
    setValue("Conf/primaryDns", dns);
}

QString SecureAppSettingsRepository::secondaryDns() const
{
    constexpr char cloudFlareNs2[] = "1.0.0.1";
    return value("Conf/secondaryDns", cloudFlareNs2).toString();
}

void SecureAppSettingsRepository::setSecondaryDns(const QString &dns)
{
    setValue("Conf/secondaryDns", dns);
}

namespace {
    QString routeModeString(RouteMode mode) {
        switch (mode) {
        case RouteMode::VpnAllSites: return "AllSites";
        case RouteMode::VpnOnlyForwardSites: return "ForwardSites";
        case RouteMode::VpnAllExceptSites: return "ExceptSites";
        }
        return QString();
    }
}

RouteMode SecureAppSettingsRepository::routeMode() const
{
    return static_cast<RouteMode>(value("Conf/routeMode", 0).toInt());
}

void SecureAppSettingsRepository::setRouteMode(RouteMode mode)
{
    setValue("Conf/routeMode", static_cast<int>(mode));
    emit routeModeChanged(mode);
}

QVariantMap SecureAppSettingsRepository::vpnSites(RouteMode mode) const
{
    return value("Conf/" + routeModeString(mode)).toMap();
}

QStringList SecureAppSettingsRepository::siteIpList(const QVariant &value)
{
    // QVariant::toStringList() handles both a QStringList/QVariantList and a single QString
    // (a single string is returned as a one-element list), which covers the legacy format.
    QStringList result = value.toStringList();
    result.removeAll(QString());
    result.removeDuplicates();
    return result;
}

void SecureAppSettingsRepository::setVpnSites(RouteMode mode, const QVariantMap &sites)
{
    setValue("Conf/" + routeModeString(mode), sites);
}

bool SecureAppSettingsRepository::addVpnSite(RouteMode mode, const QString &site, const QStringList &ips)
{
    QVariantMap sites = vpnSites(mode);
    const bool siteExisted = sites.contains(site);

    if (siteExisted && ips.isEmpty())
        return false;

    QStringList mergedIps = siteIpList(sites.value(site));
    bool changed = !siteExisted;
    for (const QString &ip : ips) {
        if (!ip.isEmpty() && !mergedIps.contains(ip)) {
            mergedIps.append(ip);
            changed = true;
        }
    }

    if (!changed)
        return false;

    sites.insert(site, mergedIps);
    setVpnSites(mode, sites);
    emit sitesChanged(mode);
    return true;
}

void SecureAppSettingsRepository::addVpnSites(RouteMode mode, const QMap<QString, QStringList> &sites)
{
    QVariantMap allSites = vpnSites(mode);
    for (auto i = sites.constBegin(); i != sites.constEnd(); ++i) {
        const QString &site = i.key();

        QStringList mergedIps = siteIpList(allSites.value(site));
        for (const QString &ip : i.value()) {
            if (!ip.isEmpty() && !mergedIps.contains(ip))
                mergedIps.append(ip);
        }

        allSites.insert(site, mergedIps);
    }

    setVpnSites(mode, allSites);
    emit sitesChanged(mode);
}

void SecureAppSettingsRepository::removeVpnSite(RouteMode mode, const QString &site)
{
    QVariantMap sites = vpnSites(mode);
    if (!sites.contains(site))
        return;

    sites.remove(site);
    setVpnSites(mode, sites);
    emit sitesChanged(mode);
}

void SecureAppSettingsRepository::removeAllVpnSites(RouteMode mode)
{
    setVpnSites(mode, QVariantMap());
    emit sitesChanged(mode);
}

bool SecureAppSettingsRepository::isSitesSplitTunnelingEnabled() const
{
    return value("Conf/sitesSplitTunnelingEnabled", false).toBool();
}

void SecureAppSettingsRepository::setSitesSplitTunnelingEnabled(bool enabled)
{
    setValue("Conf/sitesSplitTunnelingEnabled", enabled);
    emit sitesSplitTunnelingEnabledChanged(enabled);
}

namespace {
    QString appsRouteModeString(AppsRouteMode mode) {
        switch (mode) {
        case AppsRouteMode::VpnAllApps: return "AllApps";
        case AppsRouteMode::VpnOnlyForwardApps: return "ForwardApps";
        case AppsRouteMode::VpnAllExceptApps: return "ExceptApps";
        }
        return QString();
    }
}

AppsRouteMode SecureAppSettingsRepository::appsRouteMode() const
{
    return static_cast<AppsRouteMode>(value("Conf/appsRouteMode", 0).toInt());
}

void SecureAppSettingsRepository::setAppsRouteMode(AppsRouteMode mode)
{
    setValue("Conf/appsRouteMode", static_cast<int>(mode));
    emit appsRouteModeChanged(mode);
}

QVector<InstalledAppInfo> SecureAppSettingsRepository::vpnApps(AppsRouteMode mode) const
{
    QVector<InstalledAppInfo> apps;
    auto appsArray = value("Conf/" + appsRouteModeString(mode)).toJsonArray();
    for (const auto &app : appsArray) {
        InstalledAppInfo appInfo;
        appInfo.appName = app.toObject().value("appName").toString();
        appInfo.packageName = app.toObject().value("packageName").toString();
        appInfo.appPath = app.toObject().value("appPath").toString();

        apps.push_back(appInfo);
    }
    return apps;
}

void SecureAppSettingsRepository::setVpnApps(AppsRouteMode mode, const QVector<InstalledAppInfo> &apps)
{
    QJsonArray appsArray;
    for (const auto &app : apps) {
        QJsonObject appInfo;
        appInfo.insert("appName", app.appName);
        appInfo.insert("packageName", app.packageName);
        appInfo.insert("appPath", app.appPath);
        appsArray.push_back(appInfo);
    }
    setValue("Conf/" + appsRouteModeString(mode), appsArray);
    emit appsChanged(mode);
}

bool SecureAppSettingsRepository::isAppsSplitTunnelingEnabled() const
{
    return value("Conf/appsSplitTunnelingEnabled", false).toBool();
}

void SecureAppSettingsRepository::setAppsSplitTunnelingEnabled(bool enabled)
{
    setValue("Conf/appsSplitTunnelingEnabled", enabled);
    emit appsSplitTunnelingEnabledChanged(enabled);
}

QString SecureAppSettingsRepository::getGatewayEndpoint(bool isTestPurchase) const
{
    if (isTestPurchase) {
        return QString(DEV_AGW_ENDPOINT);
    }
    return m_gatewayEndpoint;
}

void SecureAppSettingsRepository::setGatewayEndpoint(const QString &endpoint)
{
    m_gatewayEndpoint = endpoint;
    setValue("Conf/gatewayEndpoint", endpoint);
}

void SecureAppSettingsRepository::resetGatewayEndpoint()
{
    m_gatewayEndpoint = gatewayEndpoint;
    setValue("Conf/gatewayEndpoint", gatewayEndpoint);
}

void SecureAppSettingsRepository::setDevGatewayEndpoint()
{
    m_gatewayEndpoint = QString(DEV_AGW_ENDPOINT);
    setValue("Conf/gatewayEndpoint", DEV_AGW_ENDPOINT);
}

bool SecureAppSettingsRepository::isDevGatewayEnv(bool isTestPurchase) const
{
    return isTestPurchase ? true : value("Conf/devGatewayEnv", false).toBool();
}

void SecureAppSettingsRepository::toggleDevGatewayEnv(bool enabled)
{
    setValue("Conf/devGatewayEnv", enabled);
}

QByteArray SecureAppSettingsRepository::readGatewayProxyUrls(const QString &cacheKey) const
{
    if (cacheKey.isEmpty()) {
        return {};
    }

    return value(QString(proxyUrlsKey) + cacheKey).toByteArray();
}

void SecureAppSettingsRepository::writeGatewayProxyUrls(const QString &cacheKey, const QByteArray &proxyUrlsEncrypted)
{
    if (cacheKey.isEmpty()) {
        return;
    }

    setValue(QString(proxyUrlsKey) + cacheKey, proxyUrlsEncrypted);
}

bool SecureAppSettingsRepository::isKillSwitchEnabled() const
{
    return value("Conf/killSwitchEnabled", true).toBool();
}

void SecureAppSettingsRepository::setKillSwitchEnabled(bool enabled)
{
    setValue("Conf/killSwitchEnabled", enabled);
}

bool SecureAppSettingsRepository::isStrictKillSwitchEnabled() const
{
    return value("Conf/strictKillSwitchEnabled", false).toBool();
}

void SecureAppSettingsRepository::setStrictKillSwitchEnabled(bool enabled)
{
    setValue("Conf/strictKillSwitchEnabled", enabled);
}

bool SecureAppSettingsRepository::isAutoConnect() const
{
    return value("Conf/autoConnect", false).toBool();
}

void SecureAppSettingsRepository::setAutoConnect(bool enabled)
{
    setValue("Conf/autoConnect", enabled);
}

bool SecureAppSettingsRepository::isStartMinimized() const
{
    return value("Conf/startMinimized", false).toBool();
}

void SecureAppSettingsRepository::setStartMinimized(bool enabled)
{
    setValue("Conf/startMinimized", enabled);
}

bool SecureAppSettingsRepository::isScreenshotsEnabled() const
{
    return value("Conf/screenshotsEnabled", true).toBool();
}

void SecureAppSettingsRepository::setScreenshotsEnabled(bool enabled)
{
    setValue("Conf/screenshotsEnabled", enabled);
    emit screenshotsEnabledChanged(enabled);
}

bool SecureAppSettingsRepository::isNewsNotifications() const
{
    return value("Conf/newsNotifications", true).toBool();
}

void SecureAppSettingsRepository::setNewsNotifications(bool enabled)
{
    setValue("Conf/newsNotifications", enabled);
}

bool SecureAppSettingsRepository::isSaveLogs() const
{
    return true;
}

void SecureAppSettingsRepository::setSaveLogs(bool enabled)
{
    Q_UNUSED(enabled);

    setValue("Conf/saveLogs", true);
    emit saveLogsChanged(true);
}

QDateTime SecureAppSettingsRepository::getLogEnableDate() const
{
    return value("Conf/logEnableDate").toDateTime();
}

void SecureAppSettingsRepository::setLogEnableDate(const QDateTime &date)
{
    setValue("Conf/logEnableDate", date);
}

QString SecureAppSettingsRepository::getInstallationUuid(bool createIfNotExists) const
{
    auto uuid = value("Conf/installationUuid", "").toString();
    if (createIfNotExists && uuid.isEmpty()) {
        uuid = QUuid::createUuid().toString();
        uuid.remove(0, 1);
        uuid.chop(1);
        const_cast<SecureAppSettingsRepository*>(this)->setValue("Conf/installationUuid", uuid);
    } else if (uuid.contains("{") && uuid.contains("}")) {
        uuid.remove(0, 1);
        uuid.chop(1);
        const_cast<SecureAppSettingsRepository*>(this)->setValue("Conf/installationUuid", uuid);
    }
    return uuid;
}

QStringList SecureAppSettingsRepository::getReadNewsIds() const
{
    return value("News/readIds").toStringList();
}

void SecureAppSettingsRepository::setReadNewsIds(const QStringList &ids)
{
    setValue("News/readIds", ids);
}

QString SecureAppSettingsRepository::selfHostedUpdateLastAutoInstallAttempt() const
{
    return value("Conf/selfHostedUpdateLastAutoInstallAttempt").toString();
}

void SecureAppSettingsRepository::setSelfHostedUpdateLastAutoInstallAttempt(const QString &attemptId)
{
    setValue("Conf/selfHostedUpdateLastAutoInstallAttempt", attemptId);
}

qint64 SecureAppSettingsRepository::selfHostedUpdateLastAcceptedPolicyGeneration() const
{
    return qMax<qint64>(0, value(QStringLiteral("Conf/selfHostedUpdate/lastAcceptedPolicyGeneration"), 0).toLongLong());
}

void SecureAppSettingsRepository::setSelfHostedUpdateLastAcceptedPolicyGeneration(qint64 generation)
{
    if (generation <= selfHostedUpdateLastAcceptedPolicyGeneration()) {
        return;
    }
    setValue(QStringLiteral("Conf/selfHostedUpdate/lastAcceptedPolicyGeneration"), generation);
}

QString SecureAppSettingsRepository::selfHostedUpdateLastAcceptedPolicyPayloadSha256() const
{
    return value(QStringLiteral("Conf/selfHostedUpdate/lastAcceptedPolicyPayloadSha256"))
            .toString().trimmed().toLower();
}

void SecureAppSettingsRepository::setSelfHostedUpdateLastAcceptedPolicy(qint64 generation,
                                                                        const QString &payloadSha256)
{
    const QString normalizedSha256 = payloadSha256.trimmed().toLower();
    if (generation <= 0 || normalizedSha256.size() != 64) {
        return;
    }
    for (const QChar character : normalizedSha256) {
        const ushort codePoint = character.unicode();
        if (!((codePoint >= '0' && codePoint <= '9')
              || (codePoint >= 'a' && codePoint <= 'f'))) {
            return;
        }
    }

    const qint64 currentGeneration = selfHostedUpdateLastAcceptedPolicyGeneration();
    if (generation < currentGeneration) {
        return;
    }
    if (generation == currentGeneration) {
        const QString currentSha256 = selfHostedUpdateLastAcceptedPolicyPayloadSha256();
        if (!currentSha256.isEmpty() && currentSha256 != normalizedSha256) {
            return;
        }
    }

    // Advance the anti-replay floor first. If the process or storage fails
    // before the digest is durably paired with it, equal-generation payloads
    // are rejected as missing/conflicting while a later generation can still
    // recover. Writing the digest first would leave the old floor in place and
    // permit a different signed payload at this new generation after restart.
    setValue(QStringLiteral("Conf/selfHostedUpdate/lastAcceptedPolicyGeneration"), generation);
    setValue(QStringLiteral("Conf/selfHostedUpdate/lastAcceptedPolicyPayloadSha256"), normalizedSha256);
}

QVariantMap SecureAppSettingsRepository::selfHostedUpdatePendingHealthReceipt() const
{
    return value(QStringLiteral("Conf/selfHostedUpdate/pendingHealthReceipt")).toMap();
}

void SecureAppSettingsRepository::setSelfHostedUpdatePendingHealthReceipt(const QVariantMap &receipt)
{
    if (receipt.isEmpty()) {
        clearSelfHostedUpdatePendingHealthReceipt();
        return;
    }
    setValue(QStringLiteral("Conf/selfHostedUpdate/pendingHealthReceipt"), receipt);
}

void SecureAppSettingsRepository::clearSelfHostedUpdatePendingHealthReceipt()
{
    m_settings->remove(QStringLiteral("Conf/selfHostedUpdate/pendingHealthReceipt"));
}

QVariantMap SecureAppSettingsRepository::selfHostedUpdateLastHealthReceipt() const
{
    return value(QStringLiteral("Conf/selfHostedUpdate/lastHealthReceipt")).toMap();
}

void SecureAppSettingsRepository::setSelfHostedUpdateLastHealthReceipt(const QVariantMap &receipt)
{
    if (receipt.isEmpty()) {
        m_settings->remove(QStringLiteral("Conf/selfHostedUpdate/lastHealthReceipt"));
        return;
    }
    setValue(QStringLiteral("Conf/selfHostedUpdate/lastHealthReceipt"), receipt);
}

QVariantMap SecureAppSettingsRepository::selfHostedUpdateAndroidInstallerAuthorization() const
{
    return value(QStringLiteral("Conf/selfHostedUpdate/androidInstallerAuthorization")).toMap();
}

void SecureAppSettingsRepository::setSelfHostedUpdateAndroidInstallerAuthorization(
        const QVariantMap &authorization)
{
    if (authorization.isEmpty()) {
        clearSelfHostedUpdateAndroidInstallerAuthorization();
        return;
    }
    setValue(QStringLiteral("Conf/selfHostedUpdate/androidInstallerAuthorization"), authorization);
}

void SecureAppSettingsRepository::clearSelfHostedUpdateAndroidInstallerAuthorization()
{
    m_settings->remove(QStringLiteral("Conf/selfHostedUpdate/androidInstallerAuthorization"));
}

QString SecureAppSettingsRepository::remoteLogToken(const QString &cacheKey) const
{
    return value(QStringLiteral("Conf/remoteLogTokens")).toMap().value(cacheKey).toString();
}

void SecureAppSettingsRepository::setRemoteLogToken(const QString &cacheKey, const QString &token)
{
    QVariantMap tokens = value(QStringLiteral("Conf/remoteLogTokens")).toMap();
    tokens.insert(cacheKey, token);
    setValue(QStringLiteral("Conf/remoteLogTokens"), tokens);
}

void SecureAppSettingsRepository::clearRemoteLogToken(const QString &cacheKey)
{
    QVariantMap tokens = value(QStringLiteral("Conf/remoteLogTokens")).toMap();
    tokens.remove(cacheKey);
    setValue(QStringLiteral("Conf/remoteLogTokens"), tokens);
}

bool SecureAppSettingsRepository::isHomeAdLabelVisible() const
{
    return value("Conf/homeAdLabelVisible", true).toBool();
}

void SecureAppSettingsRepository::disableHomeAdLabel()
{
    setValue("Conf/homeAdLabelVisible", false);
}

QByteArray SecureAppSettingsRepository::backupAppConfig() const
{
    return m_settings->backupAppConfig();
}

bool SecureAppSettingsRepository::restoreAppConfig(const QByteArray &cfg)
{
    return m_settings->restoreAppConfig(cfg);
}

void SecureAppSettingsRepository::clearSettings()
{
    const QString uuid = getInstallationUuid(false);
    const qint64 policyGeneration = selfHostedUpdateLastAcceptedPolicyGeneration();
    const QString policyPayloadSha256 = selfHostedUpdateLastAcceptedPolicyPayloadSha256();
    const QVariantMap pendingHealthReceipt = selfHostedUpdatePendingHealthReceipt();
    const QVariantMap lastHealthReceipt = selfHostedUpdateLastHealthReceipt();

    m_settings->clearSettings();
    m_settings->setValue("Conf/installationUuid", uuid);
    if (policyGeneration > 0) {
        if (!policyPayloadSha256.isEmpty()) {
            setSelfHostedUpdateLastAcceptedPolicy(policyGeneration, policyPayloadSha256);
        } else {
            // Preserve a fail-closed generation floor from pre-binding builds.
            setSelfHostedUpdateLastAcceptedPolicyGeneration(policyGeneration);
        }
    }
    if (!pendingHealthReceipt.isEmpty()) {
        setSelfHostedUpdatePendingHealthReceipt(pendingHealthReceipt);
    }
    if (!lastHealthReceipt.isEmpty()) {
        setSelfHostedUpdateLastHealthReceipt(lastHealthReceipt);
    }
    emit settingsCleared();
}

void SecureAppSettingsRepository::setInstallationUuid(const QString &uuid)
{
    m_settings->setValue("Conf/installationUuid", uuid);
}

QByteArray SecureAppSettingsRepository::xraySavedConfigs() const
{
    return value("Xray/savedConfigs").toByteArray();
}

void SecureAppSettingsRepository::setXraySavedConfigs(const QByteArray &data)
{
    setValue("Xray/savedConfigs", data);
}
