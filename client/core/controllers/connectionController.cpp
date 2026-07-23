#include "connectionController.h"

#include <QDateTime>
#include <QHostAddress>
#include <QHostInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QRandomGenerator>
#include <QRegularExpression>
#include <QSharedPointer>

#include "amneziaApplication.h"
#include "core/configurators/configuratorBase.h"
#include "core/payloadSender.h"
#include "core/utils/protocolEnum.h"
#include "core/protocols/protocolUtils.h"
#include "core/utils/constants/configKeys.h"
#include "core/utils/selfhosted/clientLogsUtils.h"
#include "core/utils/utilities.h"
#include "core/utils/serverConfigUtils.h"
#include "version.h"
#include "core/utils/containerEnum.h"
#include "core/utils/containers/containerUtils.h"
#include "core/utils/networkUtilities.h"
#include "core/utils/protocolEnum.h"
#ifdef AMNEZIA_DESKTOP
#include "core/utils/ipcClient.h"
#endif
#include "core/models/containerConfig.h"
#include "core/models/protocolConfig.h"

using namespace amnezia;
using namespace ProtocolUtils;

namespace
{
constexpr int serverRoutingRulesInitialSyncIntervalMs = 1000;
constexpr int serverRoutingRulesPeriodicSyncIntervalMs = 24 * 60 * 60 * 1000;
constexpr int serverRoutingRulesFastRetryIntervalMs = 15 * 1000;
constexpr int serverRoutingRulesMaxFastRetryCount = 3;
constexpr int serverRoutingRulesExpiredPolicyRetryIntervalMs = 5 * 60 * 1000;
constexpr int serverRoutingRulesMinimumDeadlineIntervalMs = 1000;
constexpr int serverRoutingRulesClientResolveIntervalSeconds = 24 * 60 * 60;
constexpr int serverRoutingRulesClientResolveInitialDelayMs = 2000;
constexpr int serverRoutingRulesClientResolveJitterMs = 30 * 1000;
constexpr int serverRoutingRulesClientResolveRetryBaseMs = 15 * 1000;
constexpr int serverRoutingRulesClientResolveRetryMaxMs = 5 * 60 * 1000;
constexpr int serverRoutingRulesClientResolveRetryJitterMs = 5 * 1000;
constexpr int serverRoutingRulesClientResolveMaxBackoffExponent = 5;
constexpr int serverRoutingRulesRequestDeadlineMs = 6000;
constexpr qsizetype serverRoutingRulesMaxPayloadBytes = 4 * 1024 * 1024;

QString serverRoutingRulesSyncUrl(const QString &host)
{
    const QString syncHost = host.trimmed().isEmpty()
            ? QString::fromLatin1(protocols::serverRoutingRules::syncHost)
            : host.trimmed();

    return QStringLiteral("http://%1:%2%3")
            .arg(syncHost,
                 QString::number(protocols::serverRoutingRules::syncPort),
                 QString::fromLatin1(protocols::serverRoutingRules::syncPath));
}

QList<QUrl> serverRoutingRulesSyncUrls(const QString &primaryHost)
{
    QStringList hosts;
    const auto addHost = [&hosts](const QString &host) {
        const QString trimmedHost = host.trimmed();
        if (!trimmedHost.isEmpty() && !hosts.contains(trimmedHost)) {
            hosts.append(trimmedHost);
        }
    };

    addHost(primaryHost);
    addHost(QString::fromLatin1(protocols::serverRoutingRules::syncHost));

    QList<QUrl> urls;
    urls.reserve(hosts.size());
    for (const QString &host : hosts) {
        urls.append(QUrl(serverRoutingRulesSyncUrl(host)));
    }
    return urls;
}

bool isServerRoutingRulesSitesValue(const QJsonValue &value)
{
    return value.isObject() || value.isArray();
}

QJsonObject normalizedServerRoutingRulesSites(const QJsonValue &value)
{
    QJsonObject sites;
    if (value.isObject()) {
        const QJsonObject object = value.toObject();
        for (auto it = object.constBegin(); it != object.constEnd(); ++it) {
            const QString site = it.key().trimmed().toLower();
            if (!site.isEmpty() && it.value().isString()) {
                sites.insert(site, it.value().toString());
            }
        }
        return sites;
    }
    if (!value.isArray()) {
        return sites;
    }

    const QJsonArray items = value.toArray();
    for (const QJsonValue &item : items) {
        if (!item.isObject()) {
            continue;
        }
        const QJsonObject siteObject = item.toObject();
        const QString site = siteObject.value("hostname").toString(siteObject.value("url").toString()).trimmed().toLower();
        if (!site.isEmpty()) {
            sites.insert(site, siteObject.value("ip").toString());
        }
    }
    return sites;
}

QJsonValue serverRoutingRulesExceptSitesValue(const QJsonObject &payload)
{
    QJsonValue sitesValue = payload.value(configKey::serverExcept);
    if (!isServerRoutingRulesSitesValue(sitesValue)) {
        sitesValue = payload.value(configKey::managedSplitTunnelExceptSites);
    }
    if (!isServerRoutingRulesSitesValue(sitesValue)) {
        sitesValue = payload.value(configKey::managedSplitTunnelExceptSourceSites);
    }
    return sitesValue;
}

QJsonValue serverRoutingRulesSourceSitesValue(const QJsonObject &payload)
{
    QJsonValue sitesValue = payload.value(configKey::managedSplitTunnelExceptSourceSites);
    if (!isServerRoutingRulesSitesValue(sitesValue)) {
        sitesValue = payload.value(configKey::managedSplitTunnelExceptSites);
    }
    if (!isServerRoutingRulesSitesValue(sitesValue)) {
        sitesValue = payload.value(configKey::serverExcept);
    }
    return sitesValue;
}

QJsonObject serverRoutingRulesExceptSites(const QJsonObject &payload)
{
    bool valid = false;
    const QJsonObject sites = managedRoutePolicy::canonicalSourceSites(
            serverRoutingRulesExceptSitesValue(payload), &valid);
    return valid ? sites : QJsonObject();
}

QJsonObject serverRoutingRulesSourceSites(const QJsonObject &payload)
{
    bool valid = false;
    const QJsonObject sites = managedRoutePolicy::canonicalSourceSites(
            serverRoutingRulesSourceSitesValue(payload), &valid);
    return valid ? sites : QJsonObject();
}

bool hasServerRoutingRulesExceptSites(const QJsonObject &payload)
{
    return isServerRoutingRulesSitesValue(payload.value(configKey::serverExcept))
           || isServerRoutingRulesSitesValue(payload.value(configKey::managedSplitTunnelExceptSourceSites))
           || isServerRoutingRulesSitesValue(payload.value(configKey::managedSplitTunnelExceptSites));
}

bool isValidServerRoutingRulesSitesValue(const QJsonValue &value)
{
    bool valid = false;
    managedRoutePolicy::canonicalSourceSites(value, &valid);
    return valid;
}

QJsonObject canonicalManagedRoutePolicyContent(const QJsonObject &sourceSites, bool forceEnabled)
{
    QJsonObject content;
    content.insert(QStringLiteral("schemaVersion"), 1);
    content.insert(configKey::managedSplitTunnelExceptSourceSites, sourceSites);
    content.insert(configKey::managedSplitTunnelForceEnabled, forceEnabled);
    return content;
}

QStringList splitTunnelStoredIps(const QString &value)
{
    bool valid = false;
    const QStringList routes = managedRoutePolicy::validatedManagedRouteTokens(value, &valid);
    if (!valid) {
        qWarning() << "ConnectionController: rejected an unsafe or oversized managed route value";
        return {};
    }
    return routes;
}

QString mergedStoredIps(const QStringList &values)
{
    QStringList ips;
    for (const QString &value : values) {
        const QStringList storedIps = splitTunnelStoredIps(value);
        for (const QString &ip : storedIps) {
            if (!ips.contains(ip)) {
                ips.append(ip);
            }
        }
    }
    return ips.join(QStringLiteral(", "));
}

QJsonObject sitesBoundToSource(const QJsonObject &sites, const QJsonObject &sourceSites)
{
    QJsonObject boundedSites;
    for (auto it = sourceSites.constBegin(); it != sourceSites.constEnd(); ++it) {
        if (sites.contains(it.key())) {
            boundedSites.insert(it.key(), sites.value(it.key()));
        }
    }
    return boundedSites;
}

QJsonObject clientResolvedSitesBoundToSource(const QJsonObject &serverConfig, const QJsonObject &sourceSites)
{
    const QJsonObject clientResolvedSites =
            normalizedServerRoutingRulesSites(serverConfig.value(configKey::managedSplitTunnelClientResolvedExceptSites));
    bool valid = false;
    const QJsonObject boundedSites = managedRoutePolicy::canonicalSourceSites(
            sitesBoundToSource(clientResolvedSites, sourceSites), &valid);
    if (!valid) {
        qWarning() << "ConnectionController: discarded an unsafe or oversized managed DNS cache";
        return {};
    }
    return boundedSites;
}

bool isManagedResolveDomain(const QString &site)
{
    return !NetworkUtilities::checkIpSubnetFormat(site) && NetworkUtilities::domainRegExp().exactMatch(site);
}

QStringList managedResolveDomains(const QJsonObject &sourceSites)
{
    QStringList domains;
    for (auto it = sourceSites.constBegin(); it != sourceSites.constEnd(); ++it) {
        const QString site = it.key().trimmed().toLower();
        if (isManagedResolveDomain(site) && !domains.contains(site)) {
            domains.append(site);
        }
    }
    return domains;
}

bool shouldRunClientManagedResolve(const QJsonObject &serverConfig, const QJsonObject &sourceSites)
{
    const QStringList domains = managedResolveDomains(sourceSites);
    if (domains.isEmpty()) {
        return false;
    }

    const QJsonObject clientResolvedSites = clientResolvedSitesBoundToSource(serverConfig, sourceSites);
    for (const QString &domain : domains) {
        if (!clientResolvedSites.contains(domain)) {
            return true;
        }
    }

    const QDateTime resolvedAt =
            QDateTime::fromString(serverConfig.value(configKey::managedSplitTunnelClientResolvedAt).toString(), Qt::ISODate);
    if (!resolvedAt.isValid()) {
        return true;
    }

    const QDateTime now = QDateTime::currentDateTimeUtc();
    if (resolvedAt.toUTC() > now.addSecs(10 * 60)) {
        return true;
    }
    return resolvedAt.toUTC().secsTo(now) >= serverRoutingRulesClientResolveIntervalSeconds;
}

QStringList hostInfoIpv4Addresses(const QHostInfo &hostInfo)
{
    QStringList ips;
    if (hostInfo.error() != QHostInfo::NoError) {
        return ips;
    }
    for (const QHostAddress &addr : hostInfo.addresses()) {
        const QString route = addr.toString();
        if (addr.protocol() == QAbstractSocket::NetworkLayerProtocol::IPv4Protocol
            && managedRoutePolicy::isAllowedManagedIpv4Route(route)
            && !ips.contains(route)) {
            ips.append(route);
            if (ips.size() >= managedRoutePolicy::maximumRoutesPerSite) {
                break;
            }
        }
    }
    return ips;
}
}

ConnectionController::ConnectionController(SecureServersRepository* serversRepository,
                                         SecureAppSettingsRepository* appSettingsRepository,
                                         VpnConnection* vpnConnection,
                                         QObject* parent)
    : QObject(parent),
      m_serversRepository(serversRepository),
      m_appSettingsRepository(appSettingsRepository),
      m_vpnConnection(vpnConnection)
{
    connect(m_vpnConnection, &VpnConnection::connectionStateChanged, this, &ConnectionController::onVpnConnectionStateChanged);
    connect(this, &ConnectionController::openConnectionRequested, m_vpnConnection, &VpnConnection::connectToVpn, Qt::QueuedConnection);
    connect(this, &ConnectionController::closeConnectionRequested, m_vpnConnection, &VpnConnection::disconnectFromVpn, Qt::QueuedConnection);
    connect(this, &ConnectionController::setConnectionStateRequested, m_vpnConnection, &VpnConnection::setConnectionState, Qt::QueuedConnection);
    connect(this, &ConnectionController::killSwitchModeChangedRequested, m_vpnConnection, &VpnConnection::onKillSwitchModeChanged, Qt::QueuedConnection);
#ifdef Q_OS_ANDROID
    connect(this, &ConnectionController::restoreConnectionRequested, m_vpnConnection, &VpnConnection::restoreConnection, Qt::QueuedConnection);
#endif
    m_serverRoutingRulesSyncTimer.setSingleShot(true);
    connect(&m_serverRoutingRulesSyncTimer, &QTimer::timeout, this, &ConnectionController::syncServerRoutingRules);
    m_serverRoutingRulesClientResolveTimer.setSingleShot(true);
    connect(&m_serverRoutingRulesClientResolveTimer, &QTimer::timeout, this, &ConnectionController::startClientManagedSitesResolve);
}

bool ConnectionController::isConnected() const
{
    return m_vpnConnection && m_vpnConnection->connectionState() == Vpn::ConnectionState::Connected;
}

void ConnectionController::setConnectionState(Vpn::ConnectionState state)
{
    if (m_vpnConnection) {
        emit setConnectionStateRequested(state);
    }
}

void ConnectionController::onVpnConnectionStateChanged(Vpn::ConnectionState state)
{
    switch (state) {
    case Vpn::ConnectionState::Connected:
        ++m_serverRoutingRulesSyncGeneration;
        m_isServerRoutingRulesSyncInProgress = false;
        m_serverRoutingRulesSyncPendingRefresh = false;
        m_serverRoutingRulesSyncFastRetryCount = 0;
        m_clientManagedSitesResolveRetryCount = 0;
        cancelClientManagedSitesResolve();
        if (const int serverIndex = currentConnectionServerIndex();
            serverIndex >= 0 && serverIndex < m_serversRepository->serversCount()) {
            const bool localSplitEnabled = m_appSettingsRepository->isSitesSplitTunnelingEnabled();
            const RouteMode localRouteMode = m_appSettingsRepository->routeMode();
            m_appliedManagedRouteMode = m_serversRepository->effectiveSiteRouteMode(
                    serverIndex, localSplitEnabled, localRouteMode);
            m_appliedManagedSplitTunnelIps = m_appliedManagedRouteMode == RouteMode::VpnAllExceptSites
                    ? managedSplitTunnelIpsForSync(serverIndex, RouteMode::VpnAllExceptSites)
                    : QStringList();
            m_appliedManagedContentHash = effectiveManagedRouteContentHash(serverIndex);
            m_hasAppliedManagedRouteState = true;
        } else {
            m_hasAppliedManagedRouteState = false;
        }
        scheduleServerRoutingRulesSync(serverRoutingRulesInitialSyncIntervalMs);
        break;
    case Vpn::ConnectionState::Disconnected:
        m_serverRoutingRulesSyncTimer.stop();
        ++m_serverRoutingRulesSyncGeneration;
        m_isServerRoutingRulesSyncInProgress = false;
        m_serverRoutingRulesSyncPendingRefresh = false;
        m_serverRoutingRulesSyncFastRetryCount = 0;
        m_clientManagedSitesResolveRetryCount = 0;
        cancelClientManagedSitesResolve();
        m_hasAppliedManagedRouteState = false;
        break;
    case Vpn::ConnectionState::Error:
    case Vpn::ConnectionState::Unknown:
        m_serverRoutingRulesSyncTimer.stop();
        ++m_serverRoutingRulesSyncGeneration;
        m_isServerRoutingRulesSyncInProgress = false;
        m_serverRoutingRulesSyncPendingRefresh = false;
        m_clientManagedSitesResolveRetryCount = 0;
        cancelClientManagedSitesResolve();
        m_hasAppliedManagedRouteState = false;
        break;
    default:
        break;
    }

    emit connectionStateChanged(state);
}

ErrorCode ConnectionController::defaultContainerForServer(const QString &serverId, DockerContainer &container) const
{
    const auto kind = m_serversRepository->serverKind(serverId);
    switch (kind) {
    case serverConfigUtils::ConfigType::SelfHostedAdmin: {
        const auto cfg = m_serversRepository->selfHostedAdminConfig(serverId);
        if (!cfg.has_value()) {
            return ErrorCode::InternalError;
        }
        container = cfg->defaultContainer;
        return ErrorCode::NoError;
    }
    case serverConfigUtils::ConfigType::SelfHostedUser: {
        const auto cfg = m_serversRepository->selfHostedUserConfig(serverId);
        if (!cfg.has_value()) {
            return ErrorCode::InternalError;
        }
        container = cfg->defaultContainer;
        return ErrorCode::NoError;
    }
    case serverConfigUtils::ConfigType::Native: {
        const auto cfg = m_serversRepository->nativeConfig(serverId);
        if (!cfg.has_value()) {
            return ErrorCode::InternalError;
        }
        container = cfg->defaultContainer;
        return ErrorCode::NoError;
    }
    case serverConfigUtils::ConfigType::AmneziaPremiumV2:
    case serverConfigUtils::ConfigType::AmneziaFreeV3:
    case serverConfigUtils::ConfigType::ExternalPremium: {
        const auto cfg = m_serversRepository->apiV2Config(serverId);
        if (!cfg.has_value()) {
            return ErrorCode::InternalError;
        }
        container = cfg->defaultContainer;
        return ErrorCode::NoError;
    }
    case serverConfigUtils::ConfigType::AmneziaPremiumV1:
    case serverConfigUtils::ConfigType::AmneziaFreeV2:
        return ErrorCode::LegacyApiV1NotSupportedError;
    case serverConfigUtils::ConfigType::Invalid:
    default:
        return ErrorCode::InternalError;
    }
}

ErrorCode ConnectionController::isConnectionSupported(const QString &serverId) const
{
    if (serverId.isEmpty()) {
        return ErrorCode::InternalError;
    }

    if (!isServiceReady()) {
        return ErrorCode::AmneziaServiceNotRunning;
    }

    if (serverConfigUtils::isLegacyApiSubscription(m_serversRepository->serverKind(serverId))) {
        return ErrorCode::LegacyApiV1NotSupportedError;
    }

    DockerContainer container = DockerContainer::None;
    const ErrorCode errorCode = defaultContainerForServer(serverId, container);
    if (errorCode != ErrorCode::NoError) {
        return errorCode;
    }

    if (container == DockerContainer::None) {
        return ErrorCode::NoInstalledContainersError;
    }

    if (ContainerUtils::isUnsupportedContainer(container)) {
        return ErrorCode::LegacyContainerNotSupportedError;
    }

    if (!isContainerSupported(container)) {
        return ErrorCode::NotSupportedOnThisPlatform;
    }

    return ErrorCode::NoError;
}

ErrorCode ConnectionController::prepareConnection(const QString &serverId,
                                                 QJsonObject& vpnConfiguration,
                                                 DockerContainer& container)
{
    if (!isServiceReady()) {
        return ErrorCode::AmneziaServiceNotRunning;
    }
    const int serverIndex = m_serversRepository->indexOfServerId(serverId);
    if (serverIndex < 0) {
        return ErrorCode::InternalError;
    }

    ContainerConfig containerConfigModel;
    QPair<QString, QString> dns;
    QString hostName;
    QString description;
    int configVersion = 0;
    bool isApiConfig = false;

    const auto kind = m_serversRepository->serverKind(serverId);
    const QString primaryDns = m_appSettingsRepository->primaryDns();
    const QString secondaryDns = m_appSettingsRepository->secondaryDns();
    switch (kind) {
    case serverConfigUtils::ConfigType::SelfHostedAdmin: {
        const auto cfg = m_serversRepository->selfHostedAdminConfig(serverId);
        if (!cfg.has_value()) return ErrorCode::InternalError;
        container = cfg->defaultContainer;
        containerConfigModel = cfg->containerConfig(container);
        dns = cfg->getDnsPair(m_appSettingsRepository->useAmneziaDns(), primaryDns, secondaryDns);
        hostName = cfg->hostName;
        description = cfg->description;
        break;
    }
    case serverConfigUtils::ConfigType::SelfHostedUser: {
        const auto cfg = m_serversRepository->selfHostedUserConfig(serverId);
        if (!cfg.has_value()) return ErrorCode::InternalError;
        container = cfg->defaultContainer;
        containerConfigModel = cfg->containerConfig(container);
        dns = cfg->getDnsPair(primaryDns, secondaryDns);
        hostName = cfg->hostName;
        description = cfg->description;
        break;
    }
    case serverConfigUtils::ConfigType::Native: {
        const auto cfg = m_serversRepository->nativeConfig(serverId);
        if (!cfg.has_value()) return ErrorCode::InternalError;
        container = cfg->defaultContainer;
        containerConfigModel = cfg->containerConfig(container);
        dns = cfg->getDnsPair(primaryDns, secondaryDns);
        hostName = cfg->hostName;
        description = cfg->description;
        break;
    }
    case serverConfigUtils::ConfigType::AmneziaPremiumV2:
    case serverConfigUtils::ConfigType::AmneziaFreeV3:
    case serverConfigUtils::ConfigType::ExternalPremium: {
        const auto cfg = m_serversRepository->apiV2Config(serverId);
        if (!cfg.has_value()) return ErrorCode::InternalError;
        container = cfg->defaultContainer;
        containerConfigModel = cfg->containerConfig(container);
        dns = cfg->getDnsPair(primaryDns, secondaryDns);
        hostName = cfg->hostName;
        description = cfg->description;
        configVersion = serverConfigUtils::ConfigSource::AmneziaGateway;
        isApiConfig = true;
        break;
    }
    case serverConfigUtils::ConfigType::AmneziaPremiumV1:
    case serverConfigUtils::ConfigType::AmneziaFreeV2:
        return ErrorCode::InternalError;
    case serverConfigUtils::ConfigType::Invalid:
    default:
        return ErrorCode::InternalError;
    }

    if (!isContainerSupported(container)) {
        return ErrorCode::NotSupportedOnThisPlatform;
    }

    vpnConfiguration = createConnectionConfiguration(serverIndex, dns, isApiConfig, hostName, description, configVersion,
                                                     containerConfigModel, container);

    return ErrorCode::NoError;
}

ErrorCode ConnectionController::openConnection(const QString &serverId)
{
    QJsonObject vpnConfiguration;
    DockerContainer container;

    ErrorCode errorCode = prepareConnection(serverId, vpnConfiguration, container);
    if (errorCode != ErrorCode::NoError) {
        return errorCode;
    }

    const int serverIndex = m_serversRepository->indexOfServerId(serverId);
    if (serverIndex >= 0) {
        const QJsonArray sendPayload = m_serversRepository->serverJson(serverIndex).value(configKey::sendPayload).toArray();
        if (!sendPayload.isEmpty()) {
            PayloadSender::sendAll(sendPayload);
        }
    }

    emit openConnectionRequested(serverId, container, vpnConfiguration);
    return ErrorCode::NoError;
}

void ConnectionController::closeConnection()
{
    if (m_vpnConnection) {
        emit closeConnectionRequested();
    }
}

#ifdef Q_OS_ANDROID
void ConnectionController::restoreConnection(Vpn::ConnectionState state, int serverIndex)
{
    if (!m_vpnConnection) {
        return;
    }

    if (serverIndex < 0 || serverIndex >= m_serversRepository->serversCount()) {
        serverIndex = m_serversRepository->defaultServerIndex();
    }
    if (serverIndex < 0 || serverIndex >= m_serversRepository->serversCount()) {
        return;
    }

    QJsonObject vpnConfiguration;
    DockerContainer container = DockerContainer::None;
    const QString serverId = m_serversRepository->serverIdAt(serverIndex);
    if (serverId.isEmpty() || prepareConnection(serverId, vpnConfiguration, container) != ErrorCode::NoError) {
        return;
    }

    emit restoreConnectionRequested(serverIndex, container, vpnConfiguration, state);
}
#endif

void ConnectionController::onKillSwitchModeChanged(bool enabled)
{
    if (m_vpnConnection) {
        emit killSwitchModeChangedRequested(enabled);
    }
}

void ConnectionController::onManagedSplitTunnelingRulesPublished(int serverIndex)
{
    emit serverRoutingRulesChanged(serverIndex);
    if (!isConnected() || !isCurrentConnectionServerIndex(serverIndex)) {
        return;
    }
    // A publish replaces the managed source set. Invalidate only this
    // controller's managed DNS callbacks; local split-tunnel lookups are owned
    // by VpnConnection and must not share this generation token.
    m_clientManagedSitesResolveRetryCount = 0;
    cancelClientManagedSitesResolve();
    scheduleServerRoutingRulesSync(0);
}

ErrorCode ConnectionController::lastConnectionError() const
{
    return m_vpnConnection->lastError();
}

QJsonObject ConnectionController::createConnectionConfiguration(int serverIndex,
                                                              const QPair<QString, QString> &dns,
                                                              bool isApiConfig,
                                                              const QString &hostName,
                                                              const QString &description,
                                                              int configVersion,
                                                              const ContainerConfig &containerConfig,
                                                              DockerContainer container)
{
    QJsonObject vpnConfiguration {};

    if (ContainerUtils::containerService(container) == ServiceType::Other) {
        return vpnConfiguration;
    }

    Proto proto = ContainerUtils::defaultProtocol(container);

    const RouteMode routeMode = m_serversRepository->effectiveSiteRouteMode(
            serverIndex, m_appSettingsRepository->isSitesSplitTunnelingEnabled(), m_appSettingsRepository->routeMode());

    ConnectionSettings connectionSettings = {
        { dns.first, dns.second },
        isApiConfig,
        {
            routeMode != RouteMode::VpnAllSites,
            routeMode
        }
    };

    auto configurator = ConfiguratorBase::create(proto, nullptr);
    ProtocolConfig processedConfig = configurator->processConfigWithLocalSettings(connectionSettings,
                                                                                  containerConfig.protocolConfig);

    QJsonObject vpnConfigData = processedConfig.getClientConfigJson();
    if (ContainerUtils::isAwgContainer(container) || container == DockerContainer::WireGuard) {
        if (vpnConfigData[configKey::mtu].toString().isEmpty()) {
            vpnConfigData[configKey::mtu] =
                    ContainerUtils::isAwgContainer(container) ? protocols::awg::defaultMtu :
                    protocols::wireguard::defaultMtu;
        }
    }

    vpnConfiguration.insert(ProtocolUtils::key_proto_config_data(proto), vpnConfigData);
    vpnConfiguration[configKey::vpnProto] = ProtocolUtils::protoToString(proto);

    vpnConfiguration[configKey::dns1] = dns.first;
    vpnConfiguration[configKey::dns2] = dns.second;

    vpnConfiguration[configKey::hostName] = hostName;
    vpnConfiguration[configKey::description] = description;
    vpnConfiguration[configKey::serverIndex] = serverIndex;
    vpnConfiguration[configKey::configVersion] = configVersion;

    const QJsonObject serverJson = m_serversRepository->serverJson(serverIndex);
    const QString syncHost = serverJson.value(configKey::serverRoutingRulesSyncHost).toString().trimmed();
    if (!syncHost.isEmpty()) {
        vpnConfiguration[configKey::serverRoutingRulesSyncHost] = syncHost;
    }
    const QJsonObject clientLogs = serverJson.value(configKey::clientLogs).toObject();
    if (!clientLogs.isEmpty()) {
        vpnConfiguration[configKey::clientLogs] = clientLogs;
    } else {
        const serverConfigUtils::ConfigType serverKind = serverConfigUtils::configTypeFromJson(serverJson);
        if (serverKind == serverConfigUtils::ConfigType::SelfHostedAdmin
            || serverKind == serverConfigUtils::ConfigType::SelfHostedUser) {
            const QJsonObject legacyClientLogs = clientLogsUtils::legacyBootstrapTarget(container, containerConfig);
            if (!legacyClientLogs.isEmpty()) {
                vpnConfiguration[configKey::clientLogs] = legacyClientLogs;
            }
        }
    }

    return vpnConfiguration;
}

void ConnectionController::scheduleServerRoutingRulesSync(int intervalMs)
{
    if (!isConnected()) {
        return;
    }
    m_serverRoutingRulesSyncTimer.start(intervalMs);
}

void ConnectionController::scheduleNextServerRoutingRulesSync(bool success)
{
    if (success) {
        m_serverRoutingRulesSyncFastRetryCount = 0;
        int nextIntervalMs = serverRoutingRulesPeriodicSyncIntervalMs;
        const int serverIndex = currentConnectionServerIndex();
        const auto metadata = m_serversRepository->managedRoutePolicyMetadata(serverIndex);
        if (metadata.has_value() && metadata->expiresAt.isValid()) {
            const qint64 untilExpiryMs =
                    QDateTime::currentDateTimeUtc().msecsTo(metadata->expiresAt.toUTC());
            if (untilExpiryMs <= 0) {
                nextIntervalMs = serverRoutingRulesExpiredPolicyRetryIntervalMs;
            } else {
                nextIntervalMs = static_cast<int>(qMin<qint64>(
                        serverRoutingRulesPeriodicSyncIntervalMs,
                        qMax<qint64>(serverRoutingRulesMinimumDeadlineIntervalMs, untilExpiryMs)));
            }
        }
        scheduleServerRoutingRulesSync(nextIntervalMs);
        return;
    }

    const auto metadata =
            m_serversRepository->managedRoutePolicyMetadata(currentConnectionServerIndex());
    if (metadata.has_value() && metadata->isExpired()) {
        // An unavailable publisher must not silently turn an expired policy
        // into another 24-hour wait. Retain the LKG for availability, but keep
        // revalidating on a bounded cadence until a valid revision arrives.
        m_serverRoutingRulesSyncFastRetryCount = serverRoutingRulesMaxFastRetryCount;
        scheduleServerRoutingRulesSync(serverRoutingRulesExpiredPolicyRetryIntervalMs);
        return;
    }

    if (m_serverRoutingRulesSyncFastRetryCount < serverRoutingRulesMaxFastRetryCount) {
        ++m_serverRoutingRulesSyncFastRetryCount;
        scheduleServerRoutingRulesSync(serverRoutingRulesFastRetryIntervalMs);
        return;
    }

    int nextIntervalMs = serverRoutingRulesPeriodicSyncIntervalMs;
    if (metadata.has_value() && metadata->expiresAt.isValid()) {
        const qint64 untilExpiryMs =
                QDateTime::currentDateTimeUtc().msecsTo(metadata->expiresAt.toUTC());
        if (untilExpiryMs > 0) {
            nextIntervalMs = static_cast<int>(qMin<qint64>(
                    serverRoutingRulesPeriodicSyncIntervalMs,
                    qMax<qint64>(serverRoutingRulesMinimumDeadlineIntervalMs, untilExpiryMs)));
        }
    }
    scheduleServerRoutingRulesSync(nextIntervalMs);
}

void ConnectionController::finishServerRoutingRulesSync(bool success)
{
    m_isServerRoutingRulesSyncInProgress = false;
    if (m_serverRoutingRulesSyncPendingRefresh && isConnected()) {
        m_serverRoutingRulesSyncPendingRefresh = false;
        scheduleServerRoutingRulesSync(0);
        return;
    }
    m_serverRoutingRulesSyncPendingRefresh = false;
    scheduleNextServerRoutingRulesSync(success);
}

QStringList ConnectionController::managedSplitTunnelIpsForSync(int serverIndex, RouteMode routeMode) const
{
    if (routeMode == RouteMode::VpnAllSites) {
        return {};
    }

    QStringList ips;
    const auto appendSites = [&ips](const QVariantMap &sites) {
        for (auto it = sites.constBegin(); it != sites.constEnd(); ++it) {
            if (NetworkUtilities::checkIpSubnetFormat(it.key())) {
                ips.append(it.key());
            }
            ips.append(splitTunnelStoredIps(it.value().toString()));
        }
    };

    // This set is passed to updateManagedSplitTunnelRoutes(), whose delta goes
    // through trusted route IPC. Never mix the user's concurrently editable
    // local rules into this snapshot.
    appendSites(m_serversRepository->managedVpnSitesForRouting(serverIndex, routeMode));
    ips.removeDuplicates();
    bool routesValid = false;
    ips = managedRoutePolicy::validatedManagedRoutes(ips, &routesValid);
    if (!routesValid) {
        qWarning() << "ConnectionController: managed route snapshot exceeded its safety boundary";
        return {};
    }
    ips.sort();
    return ips;
}

QString ConnectionController::effectiveManagedRouteContentHash(int serverIndex) const
{
    if (serverIndex < 0 || serverIndex >= m_serversRepository->serversCount()) {
        return {};
    }
    const QJsonObject serverConfig = m_serversRepository->serverJson(serverIndex);
    if (!managedRoutePolicy::isEffective(serverConfig)) {
        return {};
    }
    return managedRoutePolicy::derivedRevision(
            canonicalManagedRoutePolicyContent(
                    serverRoutingRulesSourceSites(serverConfig),
                    serverConfig.value(configKey::managedSplitTunnelForceEnabled).toBool(false)));
}

bool ConnectionController::reconcileManagedRouteState(
        const QString &serverId, const ManagedRouteSyncSnapshot &routeSnapshot,
        const QString &reason)
{
    const int serverIndex = m_serversRepository->indexOfServerId(serverId);
    if (!isConnected() || serverIndex < 0 || !isCurrentConnectionServerId(serverId)) {
        m_isServerRoutingRulesSyncInProgress = false;
        return true;
    }

    const bool currentLocalSplitEnabled = m_appSettingsRepository->isSitesSplitTunnelingEnabled();
    const RouteMode currentLocalRouteMode = m_appSettingsRepository->routeMode();
    const RouteMode newRouteMode = m_serversRepository->effectiveSiteRouteMode(
            serverIndex, currentLocalSplitEnabled, currentLocalRouteMode);
    const QStringList newManagedIps = newRouteMode == RouteMode::VpnAllExceptSites
            ? managedSplitTunnelIpsForSync(serverIndex, RouteMode::VpnAllExceptSites)
            : QStringList();
    const QString newContentHash = effectiveManagedRouteContentHash(serverIndex);
    const bool localSettingsChanged = currentLocalSplitEnabled != routeSnapshot.localSplitEnabled
            || currentLocalRouteMode != routeSnapshot.localRouteMode;
    const bool managedContentChanged = newManagedIps != routeSnapshot.appliedManagedIps
            || newContentHash != routeSnapshot.appliedContentHash;

    if (localSettingsChanged && !managedContentChanged) {
        qInfo() << "ConnectionController: local routing changed while reconciling managed policy;"
                   " leaving it to the local routing owner";
        return false;
    }
    if (newRouteMode == routeSnapshot.appliedRouteMode
        && newManagedIps == routeSnapshot.appliedManagedIps) {
        m_hasAppliedManagedRouteState = true;
        m_appliedManagedRouteMode = newRouteMode;
        m_appliedManagedSplitTunnelIps = newManagedIps;
        m_appliedManagedContentHash = newContentHash;
        return false;
    }

    cancelClientManagedSitesResolve();
    if (newRouteMode != routeSnapshot.appliedRouteMode) {
        qInfo() << "ConnectionController: managed route mode requires immediate reconnect:" << reason;
        m_isServerRoutingRulesSyncInProgress = false;
        m_serverRoutingRulesSyncPendingRefresh = false;
        QTimer::singleShot(0, m_vpnConnection, &VpnConnection::reconnectToVpn);
        return true;
    }
    if (newRouteMode == RouteMode::VpnAllExceptSites
        && newManagedIps != routeSnapshot.appliedManagedIps) {
        if (!m_vpnConnection->updateManagedSplitTunnelRoutes(
                    newRouteMode, routeSnapshot.appliedManagedIps, newManagedIps)) {
            qInfo() << "ConnectionController: managed route removal/change requires immediate reconnect:"
                    << reason;
            m_isServerRoutingRulesSyncInProgress = false;
            m_serverRoutingRulesSyncPendingRefresh = false;
            QTimer::singleShot(0, m_vpnConnection, &VpnConnection::reconnectToVpn);
            return true;
        }
        qInfo() << "ConnectionController: reconciled managed route delta before remote refresh:" << reason;
    }

    m_hasAppliedManagedRouteState = true;
    m_appliedManagedRouteMode = newRouteMode;
    m_appliedManagedSplitTunnelIps = newManagedIps;
    m_appliedManagedContentHash = newContentHash;
    return false;
}

int ConnectionController::currentConnectionServerIndex() const
{
    const QString serverId = currentConnectionServerId();
    return serverId.isEmpty() ? -1 : m_serversRepository->indexOfServerId(serverId);
}

QString ConnectionController::currentConnectionServerId() const
{
    return m_vpnConnection ? m_vpnConnection->serverId() : QString();
}

bool ConnectionController::isCurrentConnectionServerIndex(int serverIndex) const
{
    return serverIndex >= 0
            && isCurrentConnectionServerId(m_serversRepository->serverIdAt(serverIndex));
}

bool ConnectionController::isCurrentConnectionServerId(const QString &serverId) const
{
    return !serverId.isEmpty() && currentConnectionServerId() == serverId;
}

void ConnectionController::syncServerRoutingRules()
{
    if (!isConnected()) {
        return;
    }
    if (m_isServerRoutingRulesSyncInProgress) {
        m_serverRoutingRulesSyncPendingRefresh = true;
        return;
    }

    const QString serverId = currentConnectionServerId();
    const int serverIndex = m_serversRepository->indexOfServerId(serverId);
    if (serverIndex < 0 || serverIndex >= m_serversRepository->serversCount()) {
        scheduleNextServerRoutingRulesSync(false);
        return;
    }

    ManagedRouteSyncSnapshot routeSnapshot;
    routeSnapshot.localSplitEnabled = m_appSettingsRepository->isSitesSplitTunnelingEnabled();
    routeSnapshot.localRouteMode = m_appSettingsRepository->routeMode();
    if (m_hasAppliedManagedRouteState) {
        routeSnapshot.appliedRouteMode = m_appliedManagedRouteMode;
        routeSnapshot.appliedManagedIps = m_appliedManagedSplitTunnelIps;
        routeSnapshot.appliedContentHash = m_appliedManagedContentHash;
    } else {
        routeSnapshot.appliedRouteMode = m_serversRepository->effectiveSiteRouteMode(
                serverIndex, routeSnapshot.localSplitEnabled, routeSnapshot.localRouteMode);
        routeSnapshot.appliedManagedIps = routeSnapshot.appliedRouteMode == RouteMode::VpnAllExceptSites
                ? managedSplitTunnelIpsForSync(serverIndex, RouteMode::VpnAllExceptSites)
                : QStringList();
        routeSnapshot.appliedContentHash = effectiveManagedRouteContentHash(serverIndex);
    }
    m_isServerRoutingRulesSyncInProgress = true;
    const int syncGeneration = ++m_serverRoutingRulesSyncGeneration;
    if (reconcileManagedRouteState(
                serverId, routeSnapshot,
                QStringLiteral("stored policy expired or no longer matches its declaration"))) {
        return;
    }
    routeSnapshot.appliedRouteMode = m_appliedManagedRouteMode;
    routeSnapshot.appliedManagedIps = m_appliedManagedSplitTunnelIps;
    routeSnapshot.appliedContentHash = m_appliedManagedContentHash;
    routeSnapshot.localSplitEnabled = m_appSettingsRepository->isSitesSplitTunnelingEnabled();
    routeSnapshot.localRouteMode = m_appSettingsRepository->routeMode();

    const QList<QUrl> syncUrls = serverRoutingRulesSyncUrls(m_vpnConnection->serverRoutingRulesSyncHost());
    if (syncUrls.isEmpty()) {
        finishServerRoutingRulesSync(false);
        return;
    }

    syncServerRoutingRulesFromUrls(syncUrls, 0, serverId, routeSnapshot, syncGeneration);
}

void ConnectionController::syncServerRoutingRulesFromUrls(const QList<QUrl> &syncUrls, int urlIndex,
                                                           const QString &serverId,
                                                           const ManagedRouteSyncSnapshot &routeSnapshot,
                                                           int syncGeneration)
{
    if (syncGeneration != m_serverRoutingRulesSyncGeneration) {
        return;
    }
    const int serverIndex = m_serversRepository->indexOfServerId(serverId);
    if (!isConnected() || serverIndex < 0 || !isCurrentConnectionServerId(serverId)) {
        m_isServerRoutingRulesSyncInProgress = false;
        return;
    }
    if (urlIndex < 0 || urlIndex >= syncUrls.size()) {
        if (reconcileManagedRouteState(
                    serverId, routeSnapshot,
                    QStringLiteral("all routing policy endpoints failed"))) {
            return;
        }
        finishServerRoutingRulesSync(false);
        return;
    }

    const QUrl syncUrl = syncUrls.at(urlIndex);
    qInfo() << "ConnectionController: syncing server routing rules from" << syncUrl;

    QNetworkRequest request { syncUrl };
    request.setTransferTimeout(4000);

    QNetworkReply *reply = amnApp->networkManager()->get(request);
    reply->setReadBufferSize(serverRoutingRulesMaxPayloadBytes + 1);
    const auto payloadBuffer = QSharedPointer<QByteArray>::create();
    const auto payloadTooLarge = QSharedPointer<bool>::create(false);
    const auto deadlineExceeded = QSharedPointer<bool>::create(false);
    const auto drainReply = [reply, payloadBuffer, payloadTooLarge]() {
        while (!*payloadTooLarge && reply->bytesAvailable() > 0) {
            const qint64 remaining = serverRoutingRulesMaxPayloadBytes - payloadBuffer->size();
            const qint64 requested = qMin<qint64>(reply->bytesAvailable(), remaining + 1);
            const QByteArray chunk = reply->read(requested);
            if (chunk.isEmpty()) {
                break;
            }
            if (chunk.size() > remaining) {
                *payloadTooLarge = true;
                reply->abort();
                return;
            }
            payloadBuffer->append(chunk);
        }
    };
    connect(reply, &QNetworkReply::readyRead, reply, drainReply);
    connect(reply, &QNetworkReply::metaDataChanged, reply, [reply, payloadTooLarge]() {
        const QVariant contentLength = reply->header(QNetworkRequest::ContentLengthHeader);
        if (contentLength.isValid()
            && contentLength.toLongLong() > serverRoutingRulesMaxPayloadBytes) {
            *payloadTooLarge = true;
            reply->abort();
        }
    });
    auto *deadlineTimer = new QTimer(reply);
    deadlineTimer->setSingleShot(true);
    connect(deadlineTimer, &QTimer::timeout, reply, [reply, deadlineExceeded]() {
        *deadlineExceeded = true;
        reply->abort();
    });
    deadlineTimer->start(serverRoutingRulesRequestDeadlineMs);
    connect(reply, &QNetworkReply::finished, this,
            [this, reply, deadlineTimer, payloadBuffer, payloadTooLarge, deadlineExceeded, drainReply,
             syncUrls, urlIndex, serverId, routeSnapshot, syncGeneration]() {
                deadlineTimer->stop();
                drainReply();
                reply->deleteLater();

                if (syncGeneration != m_serverRoutingRulesSyncGeneration) {
                    return;
                }
                const int serverIndex = m_serversRepository->indexOfServerId(serverId);
                if (!isConnected() || serverIndex < 0 || !isCurrentConnectionServerId(serverId)) {
                    m_isServerRoutingRulesSyncInProgress = false;
                    return;
                }

                if (*deadlineExceeded) {
                    qWarning() << "ConnectionController: server routing rules request exceeded total deadline for"
                               << syncUrls.at(urlIndex);
                    syncServerRoutingRulesFromUrls(
                            syncUrls, urlIndex + 1, serverId, routeSnapshot, syncGeneration);
                    return;
                }
                if (*payloadTooLarge) {
                    qWarning() << "ConnectionController: server routing rules payload exceeded the byte limit";
                    syncServerRoutingRulesFromUrls(
                            syncUrls, urlIndex + 1, serverId, routeSnapshot, syncGeneration);
                    return;
                }
                if (reply->error() != QNetworkReply::NoError) {
                    qWarning() << "ConnectionController: failed to sync server routing rules from" << syncUrls.at(urlIndex)
                               << reply->errorString();
                    syncServerRoutingRulesFromUrls(syncUrls, urlIndex + 1, serverId, routeSnapshot, syncGeneration);
                    return;
                }

                const QVariant contentLength = reply->header(QNetworkRequest::ContentLengthHeader);
                if (contentLength.isValid() && contentLength.toLongLong() > serverRoutingRulesMaxPayloadBytes) {
                    qWarning() << "ConnectionController: server routing rules payload is too large, content length"
                               << contentLength.toLongLong();
                    syncServerRoutingRulesFromUrls(syncUrls, urlIndex + 1, serverId, routeSnapshot, syncGeneration);
                    return;
                }

                const QByteArray payload = *payloadBuffer;
                const int statusCode = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
                if (payload.size() > serverRoutingRulesMaxPayloadBytes) {
                    qWarning() << "ConnectionController: server routing rules payload is too large, bytes" << payload.size();
                    syncServerRoutingRulesFromUrls(syncUrls, urlIndex + 1, serverId, routeSnapshot, syncGeneration);
                    return;
                }
                if (statusCode < 200 || statusCode >= 300) {
                    qWarning() << "ConnectionController: unexpected server routing rules http status" << statusCode
                               << "from" << syncUrls.at(urlIndex);
                    syncServerRoutingRulesFromUrls(syncUrls, urlIndex + 1, serverId, routeSnapshot, syncGeneration);
                    return;
                }

                QJsonParseError parseError;
                const QJsonDocument document = QJsonDocument::fromJson(payload, &parseError);
                if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
                    qWarning() << "ConnectionController: invalid server routing rules payload from"
                               << syncUrls.at(urlIndex) << parseError.errorString();
                    syncServerRoutingRulesFromUrls(syncUrls, urlIndex + 1, serverId, routeSnapshot, syncGeneration);
                    return;
                }

                const QJsonObject payloadObject = document.object();
                if (!hasServerRoutingRulesExceptSites(payloadObject)) {
                    qWarning() << "ConnectionController: server routing rules payload does not contain managed site list";
                    syncServerRoutingRulesFromUrls(syncUrls, urlIndex + 1, serverId, routeSnapshot, syncGeneration);
                    return;
                }
                if (!isValidServerRoutingRulesSitesValue(serverRoutingRulesExceptSitesValue(payloadObject))
                    || !isValidServerRoutingRulesSitesValue(serverRoutingRulesSourceSitesValue(payloadObject))) {
                    qWarning() << "ConnectionController: invalid server routing rules managed site list";
                    syncServerRoutingRulesFromUrls(syncUrls, urlIndex + 1, serverId, routeSnapshot, syncGeneration);
                    return;
                }
                const QJsonValue forceValue =
                        payloadObject.value(configKey::managedSplitTunnelForceEnabled);
                if (!forceValue.isUndefined() && !forceValue.isNull() && !forceValue.isBool()) {
                    qWarning() << "ConnectionController: invalid managed routing force flag from"
                               << syncUrls.at(urlIndex);
                    syncServerRoutingRulesFromUrls(syncUrls, urlIndex + 1, serverId, routeSnapshot, syncGeneration);
                    return;
                }

                const QJsonObject candidateSourceSites = serverRoutingRulesSourceSites(payloadObject);
                const bool candidateForceEnabled =
                        payloadObject.value(configKey::managedSplitTunnelForceEnabled).toBool(false);

                // Admin configurations retain the locally published source set.
                // A downloaded candidate is acceptable only when it represents
                // that same effective content; otherwise its revision metadata
                // must not be attached to content that the client did not use.
                const QJsonObject currentServerConfig = m_serversRepository->serverJson(serverIndex);
                const ServerCredentials credentials = m_serversRepository->serverCredentials(serverIndex);
                if (!credentials.userName.isEmpty() && !credentials.secretData.isEmpty()) {
                    QJsonValue currentSourceValue =
                            currentServerConfig.value(configKey::managedSplitTunnelExceptSourceSites);
                    if (!isServerRoutingRulesSitesValue(currentSourceValue)) {
                        currentSourceValue = isServerRoutingRulesSitesValue(
                                                     currentServerConfig.value(configKey::managedSplitTunnelExceptSites))
                                ? currentServerConfig.value(configKey::managedSplitTunnelExceptSites)
                                : currentServerConfig.value(configKey::serverExcept);
                    }
                    bool currentSourceValid = false;
                    const QJsonObject currentSourceSites = managedRoutePolicy::canonicalSourceSites(
                            currentSourceValue, &currentSourceValid);
                    const bool currentForceEnabled =
                            currentServerConfig.value(configKey::managedSplitTunnelForceEnabled).toBool(false);
                    if (!currentSourceValid || candidateSourceSites != currentSourceSites
                        || candidateForceEnabled != currentForceEnabled) {
                        qWarning() << "ConnectionController: downloaded policy conflicts with locally published managed routes from"
                                   << syncUrls.at(urlIndex);
                        syncServerRoutingRulesFromUrls(syncUrls, urlIndex + 1, serverId, routeSnapshot,
                                                       syncGeneration);
                        return;
                    }
                }

                const QJsonObject canonicalContent =
                        canonicalManagedRoutePolicyContent(candidateSourceSites, candidateForceEnabled);
                const QString effectiveContentHash = managedRoutePolicy::derivedRevision(canonicalContent);
                const QString declaredContentHash = payloadObject.value(QStringLiteral("policy"))
                                                            .toObject()
                                                            .value(QStringLiteral("contentSha256"))
                                                            .toString()
                                                            .trimmed();
                if (!declaredContentHash.isEmpty() && declaredContentHash != effectiveContentHash) {
                    qWarning() << "ConnectionController: downloaded policy content hash does not match effective managed routes from"
                               << syncUrls.at(urlIndex);
                    syncServerRoutingRulesFromUrls(syncUrls, urlIndex + 1, serverId, routeSnapshot, syncGeneration);
                    return;
                }

                const auto currentMetadata = m_serversRepository->managedRoutePolicyMetadata(serverIndex);
                auto metadataForValidation = currentMetadata;
                if (metadataForValidation.has_value()) {
                    // validateCandidate historically hashed the entire wire
                    // envelope. The authoritative hash below covers only the
                    // canonical managed content that is actually applied.
                    metadataForValidation->contentHash.clear();
                }

                QString policyError;
                auto metadata = managedRoutePolicy::validateCandidate(
                        payloadObject, metadataForValidation, QDateTime::currentDateTimeUtc(), &policyError);
                if (!metadata.has_value()) {
                    qWarning() << "ConnectionController: rejected server routing policy from"
                               << syncUrls.at(urlIndex) << policyError;
                    syncServerRoutingRulesFromUrls(syncUrls, urlIndex + 1, serverId, routeSnapshot, syncGeneration);
                    return;
                }

                if (currentMetadata.has_value() && metadata->revision == currentMetadata->revision
                    && !currentMetadata->contentHash.isEmpty()
                    && currentMetadata->contentHash != effectiveContentHash
                    && currentMetadata->contentHash != managedRoutePolicy::derivedRevision(payloadObject)) {
                    qWarning() << "ConnectionController: downloaded policy changed effective content without a new revision from"
                               << syncUrls.at(urlIndex);
                    syncServerRoutingRulesFromUrls(syncUrls, urlIndex + 1, serverId, routeSnapshot, syncGeneration);
                    return;
                }
                metadata->contentHash = effectiveContentHash;
                metadata->source = syncUrls.at(urlIndex).toString();

                applyServerRoutingRulesPayload(serverIndex, payloadObject, metadata.value());
                scheduleClientManagedSitesResolve(serverIndex);

                const bool currentLocalSplitEnabled = m_appSettingsRepository->isSitesSplitTunnelingEnabled();
                const RouteMode currentLocalRouteMode = m_appSettingsRepository->routeMode();
                const RouteMode newRouteMode = m_serversRepository->effectiveSiteRouteMode(
                        serverIndex, currentLocalSplitEnabled, currentLocalRouteMode);
                const QStringList newManagedSplitTunnelIps = newRouteMode == RouteMode::VpnAllExceptSites
                        ? managedSplitTunnelIpsForSync(serverIndex, RouteMode::VpnAllExceptSites)
                        : QStringList();
                const bool localSettingsChanged =
                        currentLocalSplitEnabled != routeSnapshot.localSplitEnabled
                        || currentLocalRouteMode != routeSnapshot.localRouteMode;
                const bool managedRuntimeChanged =
                        newManagedSplitTunnelIps != routeSnapshot.appliedManagedIps
                        || effectiveContentHash != routeSnapshot.appliedContentHash;
                if (localSettingsChanged && !managedRuntimeChanged) {
                    qInfo() << "ConnectionController: local routing changed during policy sync;"
                               " no managed runtime delta to reconcile";
                    finishServerRoutingRulesSync(true);
                    return;
                }

                if (newRouteMode != routeSnapshot.appliedRouteMode) {
                    qInfo() << "ConnectionController: server routing rules changed route mode, reconnecting VPN";
                    m_isServerRoutingRulesSyncInProgress = false;
                    m_serverRoutingRulesSyncPendingRefresh = false;
                    QTimer::singleShot(0, m_vpnConnection, &VpnConnection::reconnectToVpn);
                    return;
                }
                if (newRouteMode == RouteMode::VpnAllExceptSites
                    && managedRuntimeChanged) {
                    if (m_vpnConnection->updateManagedSplitTunnelRoutes(
                                newRouteMode, routeSnapshot.appliedManagedIps, newManagedSplitTunnelIps)) {
                        qInfo() << "ConnectionController: applied server routing rule IP delta without reconnect";
                    } else {
                        qInfo() << "ConnectionController: active route delta requires reconnect on this platform/protocol";
                        m_isServerRoutingRulesSyncInProgress = false;
                        m_serverRoutingRulesSyncPendingRefresh = false;
                        QTimer::singleShot(0, m_vpnConnection, &VpnConnection::reconnectToVpn);
                        return;
                    }
                }

                m_hasAppliedManagedRouteState = true;
                m_appliedManagedRouteMode = newRouteMode;
                m_appliedManagedSplitTunnelIps = newManagedSplitTunnelIps;
                m_appliedManagedContentHash = effectiveContentHash;

                finishServerRoutingRulesSync(true);
            });
}

bool ConnectionController::applyServerRoutingRulesPayload(int serverIndex, const QJsonObject &payload,
                                                          const ManagedRoutePolicyMetadata &metadata)
{
    if (serverIndex < 0 || serverIndex >= m_serversRepository->serversCount()) {
        return false;
    }
    if (!hasServerRoutingRulesExceptSites(payload)) {
        return false;
    }

    QJsonObject exceptSites = serverRoutingRulesExceptSites(payload);
    QJsonObject managedExceptSites = serverRoutingRulesSourceSites(payload);
    bool forceEnabled = payload.value(configKey::managedSplitTunnelForceEnabled).toBool(false);

    QJsonObject serverConfig = m_serversRepository->serverJson(serverIndex);
    const ServerCredentials credentials = m_serversRepository->serverCredentials(serverIndex);
    if (!credentials.userName.isEmpty() && !credentials.secretData.isEmpty()) {
        QJsonValue sourceSitesValue = serverConfig.value(configKey::managedSplitTunnelExceptSourceSites);
        if (!isServerRoutingRulesSitesValue(sourceSitesValue)) {
            sourceSitesValue = isServerRoutingRulesSitesValue(serverConfig.value(configKey::managedSplitTunnelExceptSites))
                    ? serverConfig.value(configKey::managedSplitTunnelExceptSites)
                    : serverConfig.value(configKey::serverExcept);
        }
        if (isServerRoutingRulesSitesValue(sourceSitesValue)) {
            bool sourceSitesValid = false;
            const QJsonObject canonicalSourceSites = managedRoutePolicy::canonicalSourceSites(
                    sourceSitesValue, &sourceSitesValid);
            managedExceptSites = sourceSitesValid ? canonicalSourceSites : QJsonObject();
        }
        forceEnabled = serverConfig.value(configKey::managedSplitTunnelForceEnabled).toBool(false);
    }

    exceptSites = sitesBoundToSource(exceptSites, managedExceptSites);
    const QJsonObject clientResolvedSites = clientResolvedSitesBoundToSource(serverConfig, managedExceptSites);

    bool changed = false;
    if (serverConfig.value(configKey::serverExcept).toObject() != exceptSites) {
        serverConfig.insert(configKey::serverExcept, exceptSites);
        changed = true;
    }
    const bool managedSourceChanged =
            serverConfig.value(configKey::managedSplitTunnelExceptSourceSites).toObject() != managedExceptSites;
    if (managedSourceChanged) {
        serverConfig.insert(configKey::managedSplitTunnelExceptSourceSites, managedExceptSites);
        changed = true;
    }
    if (serverConfig.value(configKey::managedSplitTunnelExceptSites).toObject() != managedExceptSites) {
        serverConfig.insert(configKey::managedSplitTunnelExceptSites, managedExceptSites);
        changed = true;
    }

    const bool currentForceEnabled = serverConfig.value(configKey::managedSplitTunnelForceEnabled).toBool(false);
    if (currentForceEnabled != forceEnabled) {
        if (forceEnabled) {
            serverConfig.insert(configKey::managedSplitTunnelForceEnabled, true);
        } else {
            serverConfig.remove(configKey::managedSplitTunnelForceEnabled);
        }
        changed = true;
    }

    if (serverConfig.value(configKey::managedSplitTunnelClientResolvedExceptSites).toObject() != clientResolvedSites) {
        if (clientResolvedSites.isEmpty()) {
            serverConfig.remove(configKey::managedSplitTunnelClientResolvedExceptSites);
            serverConfig.remove(configKey::managedSplitTunnelClientResolvedAt);
        } else {
            serverConfig.insert(configKey::managedSplitTunnelClientResolvedExceptSites, clientResolvedSites);
        }
        changed = true;
    } else if (clientResolvedSites.isEmpty() && serverConfig.contains(configKey::managedSplitTunnelClientResolvedAt)) {
        serverConfig.remove(configKey::managedSplitTunnelClientResolvedAt);
        changed = true;
    }

    if (managedRoutePolicy::storeLastKnownGood(serverConfig, metadata)) {
        changed = true;
    }

    if (changed) {
        if (managedSourceChanged) {
            m_clientManagedSitesResolveRetryCount = 0;
        }
        m_serversRepository->editServerJson(serverIndex, serverConfig);
        qInfo() << "ConnectionController: server routing rules synced for server" << serverIndex
                << "source sites" << managedExceptSites.size() << "resolved sites" << exceptSites.size()
                << "force" << forceEnabled;
        emit serverRoutingRulesChanged(serverIndex);
    }
    return changed;
}

void ConnectionController::cancelClientManagedSitesResolve()
{
    ++m_clientManagedSitesResolveGeneration;
    m_serverRoutingRulesClientResolveTimer.stop();
    m_isClientManagedSitesResolveInProgress = false;
    m_clientManagedSitesResolveServerId.clear();
    m_clientManagedSitesResolveQueue.clear();
    m_clientManagedSitesResolvedCache = {};
    m_clientManagedSitesResolveHadFailure = false;
}

void ConnectionController::scheduleClientManagedSitesResolve(int serverIndex)
{
    if (!isConnected() || serverIndex < 0 || serverIndex >= m_serversRepository->serversCount()
        || !isCurrentConnectionServerIndex(serverIndex)) {
        return;
    }

    // Invalidate callbacks from an older policy before examining the new
    // source set. QHostInfo lookups are not cancellable, so the generation is
    // the ownership token for all asynchronous results.
    cancelClientManagedSitesResolve();
    const QJsonObject serverConfig = m_serversRepository->serverJson(serverIndex);
    const QJsonObject sourceSites = serverRoutingRulesSourceSites(serverConfig);
    if (!shouldRunClientManagedResolve(serverConfig, sourceSites)) {
        return;
    }

    m_clientManagedSitesResolveServerId = m_serversRepository->serverIdAt(serverIndex);
    const int jitterMs = QRandomGenerator::global()->bounded(serverRoutingRulesClientResolveJitterMs + 1);
    const int delayMs = serverRoutingRulesClientResolveInitialDelayMs + jitterMs;
    qInfo() << "ConnectionController: scheduled client-side managed site resolve in" << delayMs << "ms for server" << serverIndex;
    m_serverRoutingRulesClientResolveTimer.start(delayMs);
}

void ConnectionController::scheduleClientManagedSitesResolveRetry(int serverIndex)
{
    if (!isConnected() || !isCurrentConnectionServerIndex(serverIndex)) {
        return;
    }

    const int exponent = qMin(m_clientManagedSitesResolveRetryCount,
                              serverRoutingRulesClientResolveMaxBackoffExponent);
    const int exponentialDelayMs = serverRoutingRulesClientResolveRetryBaseMs * (1 << exponent);
    const int boundedDelayMs = qMin(exponentialDelayMs, serverRoutingRulesClientResolveRetryMaxMs);
    const int jitterMs = QRandomGenerator::global()->bounded(serverRoutingRulesClientResolveRetryJitterMs + 1);
    const int delayMs = qMin(boundedDelayMs + jitterMs, serverRoutingRulesClientResolveRetryMaxMs);
    m_clientManagedSitesResolveRetryCount =
            qMin(m_clientManagedSitesResolveRetryCount + 1,
                 serverRoutingRulesClientResolveMaxBackoffExponent);
    m_clientManagedSitesResolveServerId = m_serversRepository->serverIdAt(serverIndex);
    qInfo() << "ConnectionController: managed DNS resolve incomplete; retrying in" << delayMs
            << "ms for server" << serverIndex;
    m_serverRoutingRulesClientResolveTimer.start(delayMs);
}

void ConnectionController::startClientManagedSitesResolve()
{
    if (!isConnected() || m_isClientManagedSitesResolveInProgress) {
        return;
    }

    const QString serverId = m_clientManagedSitesResolveServerId;
    const int serverIndex = m_serversRepository->indexOfServerId(serverId);
    if (serverIndex < 0 || serverIndex >= m_serversRepository->serversCount()) {
        return;
    }
    if (!isCurrentConnectionServerId(serverId)) {
        cancelClientManagedSitesResolve();
        return;
    }

    const QJsonObject serverConfig = m_serversRepository->serverJson(serverIndex);
    const QJsonObject sourceSites = serverRoutingRulesSourceSites(serverConfig);
    m_clientManagedSitesResolveQueue = managedResolveDomains(sourceSites);
    if (m_clientManagedSitesResolveQueue.isEmpty()) {
        return;
    }

    // QHostInfo has no cancellation primitive. Each managed run owns a fresh
    // generation so a late result can neither update the LKG cache nor advance
    // its freshness marker.
    ++m_clientManagedSitesResolveGeneration;
    m_clientManagedSitesResolvedCache = clientResolvedSitesBoundToSource(serverConfig, sourceSites);
    m_clientManagedSitesResolveHadFailure = false;
    m_clientManagedSitesResolveOldLocalSplitEnabled =
            m_appSettingsRepository->isSitesSplitTunnelingEnabled();
    m_clientManagedSitesResolveOldLocalRouteMode = m_appSettingsRepository->routeMode();
    if (m_hasAppliedManagedRouteState) {
        m_clientManagedSitesResolveOldRouteMode = m_appliedManagedRouteMode;
        m_clientManagedSitesResolveOldManagedSplitTunnelIps = m_appliedManagedSplitTunnelIps;
        m_clientManagedSitesResolveOldContentHash = m_appliedManagedContentHash;
    } else {
        m_clientManagedSitesResolveOldRouteMode = m_serversRepository->effectiveSiteRouteMode(
                serverIndex, m_clientManagedSitesResolveOldLocalSplitEnabled,
                m_clientManagedSitesResolveOldLocalRouteMode);
        m_clientManagedSitesResolveOldManagedSplitTunnelIps =
                m_clientManagedSitesResolveOldRouteMode == RouteMode::VpnAllExceptSites
                ? managedSplitTunnelIpsForSync(serverIndex, RouteMode::VpnAllExceptSites)
                : QStringList();
        m_clientManagedSitesResolveOldContentHash = effectiveManagedRouteContentHash(serverIndex);
    }
    m_isClientManagedSitesResolveInProgress = true;
    qInfo() << "ConnectionController: starting client-side managed site resolve for server" << serverIndex
            << "domains" << m_clientManagedSitesResolveQueue.size();
    resolveNextClientManagedSite();
}

void ConnectionController::resolveNextClientManagedSite()
{
    if (!isConnected() || !m_isClientManagedSitesResolveInProgress) {
        m_isClientManagedSitesResolveInProgress = false;
        m_clientManagedSitesResolveQueue.clear();
        return;
    }

    if (m_clientManagedSitesResolveQueue.isEmpty()) {
        finishClientManagedSitesResolve();
        return;
    }

    const QString serverId = m_clientManagedSitesResolveServerId;
    const QString domain = m_clientManagedSitesResolveQueue.takeFirst();
    const int resolveGeneration = m_clientManagedSitesResolveGeneration;
    QHostInfo::lookupHost(domain, this, [this, serverId, domain, resolveGeneration](const QHostInfo &hostInfo) {
        if (resolveGeneration != m_clientManagedSitesResolveGeneration) {
            return;
        }
        if (!isConnected() || !m_isClientManagedSitesResolveInProgress) {
            return;
        }
        if (serverId != m_clientManagedSitesResolveServerId || !isCurrentConnectionServerId(serverId)) {
            cancelClientManagedSitesResolve();
            return;
        }

        if (hostInfo.error() != QHostInfo::NoError) {
            qDebug() << "ConnectionController: client-side managed site resolve failed"
                     << hostInfo.errorString();
            m_clientManagedSitesResolveHadFailure = true;
            resolveNextClientManagedSite();
            return;
        }

        const QStringList resolvedIps = hostInfoIpv4Addresses(hostInfo);
        if (resolvedIps.isEmpty()) {
            qDebug() << "ConnectionController: client-side managed site resolve produced no IPv4 addresses";
            m_clientManagedSitesResolveHadFailure = true;
            resolveNextClientManagedSite();
            return;
        }

        const QString mergedIps = mergedStoredIps({ resolvedIps.join(QStringLiteral(", ")) });
        if (!mergedIps.isEmpty()) {
            QJsonObject candidateCache = m_clientManagedSitesResolvedCache;
            candidateCache.insert(domain, mergedIps);
            bool candidateValid = false;
            candidateCache = managedRoutePolicy::canonicalSourceSites(candidateCache, &candidateValid);
            if (candidateValid) {
                m_clientManagedSitesResolvedCache = candidateCache;
            } else {
                qWarning() << "ConnectionController: managed DNS cache reached its safety boundary";
                m_clientManagedSitesResolveHadFailure = true;
            }
        } else {
            m_clientManagedSitesResolveHadFailure = true;
        }
        qDebug() << "ConnectionController: client-side managed site resolved"
                 << resolvedIps.size() << "IPv4 addresses";
        resolveNextClientManagedSite();
    });
}

void ConnectionController::finishClientManagedSitesResolve()
{
    const QString serverId = m_clientManagedSitesResolveServerId;
    const int serverIndex = m_serversRepository->indexOfServerId(serverId);
    m_isClientManagedSitesResolveInProgress = false;
    m_clientManagedSitesResolveQueue.clear();

    if (!isConnected() || serverIndex < 0 || serverIndex >= m_serversRepository->serversCount()) {
        return;
    }
    if (!isCurrentConnectionServerId(serverId)) {
        cancelClientManagedSitesResolve();
        return;
    }

    QJsonObject serverConfig = m_serversRepository->serverJson(serverIndex);
    const QJsonObject sourceSites = serverRoutingRulesSourceSites(serverConfig);
    bool resolvedCacheValid = false;
    const QJsonObject resolvedCacheCandidate = managedRoutePolicy::canonicalSourceSites(
            sitesBoundToSource(m_clientManagedSitesResolvedCache, sourceSites), &resolvedCacheValid);
    const QJsonObject resolvedCache = resolvedCacheValid ? resolvedCacheCandidate : QJsonObject();
    if (!resolvedCacheValid) {
        qWarning() << "ConnectionController: refusing to persist an unsafe or oversized managed DNS cache";
        m_clientManagedSitesResolveHadFailure = true;
    }

    if (m_clientManagedSitesResolveHadFailure) {
        // A partial DNS pass is not a new authoritative route snapshot. Keep
        // both the persisted last-known-good cache and the routes currently
        // installed by the tunnel, then retry with the existing bounded
        // backoff. Persisting successful answers from an incomplete pass can
        // otherwise create a route delta; AWG/WireGuard conservatively apply
        // that delta through a full reconnect, which resets the retry backoff
        // and turns a single unresolved domain into a reconnect loop.
        qInfo() << "ConnectionController: managed DNS resolve incomplete; preserving last-known-good routes";
        scheduleClientManagedSitesResolveRetry(serverIndex);
        return;
    }

    bool changed = false;
    if (serverConfig.value(configKey::managedSplitTunnelClientResolvedExceptSites).toObject() != resolvedCache) {
        if (resolvedCache.isEmpty()) {
            serverConfig.remove(configKey::managedSplitTunnelClientResolvedExceptSites);
        } else {
            serverConfig.insert(configKey::managedSplitTunnelClientResolvedExceptSites, resolvedCache);
        }
        changed = true;
    }

    const QString resolvedAt = QDateTime::currentDateTimeUtc().toString(Qt::ISODate);
    if (serverConfig.value(configKey::managedSplitTunnelClientResolvedAt).toString() != resolvedAt) {
        serverConfig.insert(configKey::managedSplitTunnelClientResolvedAt, resolvedAt);
        changed = true;
    }
    m_clientManagedSitesResolveRetryCount = 0;

    if (changed) {
        m_serversRepository->editServerJson(serverIndex, serverConfig);
        emit serverRoutingRulesChanged(serverIndex);
    }

    const bool currentLocalSplitEnabled = m_appSettingsRepository->isSitesSplitTunnelingEnabled();
    const RouteMode currentLocalRouteMode = m_appSettingsRepository->routeMode();
    const RouteMode newRouteMode = m_serversRepository->effectiveSiteRouteMode(
            serverIndex, currentLocalSplitEnabled, currentLocalRouteMode);
    const QStringList newManagedSplitTunnelIps = newRouteMode == RouteMode::VpnAllExceptSites
            ? managedSplitTunnelIpsForSync(serverIndex, RouteMode::VpnAllExceptSites)
            : QStringList();
    const QString newContentHash = effectiveManagedRouteContentHash(serverIndex);
    const bool localSettingsChanged =
            currentLocalSplitEnabled != m_clientManagedSitesResolveOldLocalSplitEnabled
            || currentLocalRouteMode != m_clientManagedSitesResolveOldLocalRouteMode;
    const bool managedRuntimeChanged =
            newManagedSplitTunnelIps != m_clientManagedSitesResolveOldManagedSplitTunnelIps
            || newContentHash != m_clientManagedSitesResolveOldContentHash;
    if (localSettingsChanged && !managedRuntimeChanged) {
        qInfo() << "ConnectionController: local routing changed during managed DNS resolve;"
                   " no managed runtime delta to reconcile";
        return;
    }
    if (newRouteMode != m_clientManagedSitesResolveOldRouteMode) {
        qInfo() << "ConnectionController: client-side managed site resolve changed route mode, reconnecting VPN";
        QTimer::singleShot(0, m_vpnConnection, &VpnConnection::reconnectToVpn);
        return;
    } else if (newManagedSplitTunnelIps != m_clientManagedSitesResolveOldManagedSplitTunnelIps) {
        if (m_vpnConnection->updateManagedSplitTunnelRoutes(
                    newRouteMode, m_clientManagedSitesResolveOldManagedSplitTunnelIps,
                    newManagedSplitTunnelIps)) {
            qInfo() << "ConnectionController: applied client-resolved managed route delta without reconnect";
        } else {
            qInfo() << "ConnectionController: client-resolved route delta requires reconnect on this platform/protocol";
            QTimer::singleShot(0, m_vpnConnection, &VpnConnection::reconnectToVpn);
            return;
        }
    }
    m_hasAppliedManagedRouteState = true;
    m_appliedManagedRouteMode = newRouteMode;
    m_appliedManagedSplitTunnelIps = newManagedSplitTunnelIps;
    m_appliedManagedContentHash = newContentHash;
}

bool ConnectionController::isServiceReady() const
{
#ifdef AMNEZIA_DESKTOP
    return IpcClient::withInterface(
            [](const QSharedPointer<IpcInterfaceReplica> &) { return true; },
            []() { return false; });
#else
    return true;
#endif
}

bool ConnectionController::isContainerSupported(DockerContainer container) const
{
    return ContainerUtils::isSupportedByCurrentPlatform(container);
}
