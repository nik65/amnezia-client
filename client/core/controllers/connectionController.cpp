#include "connectionController.h"

#include <limits>
#include <utility>

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
#include "core/utils/protocolEnum.h"
#include "core/protocols/protocolUtils.h"
#include "core/utils/constants/configKeys.h"
#include "core/utils/selfhosted/clientLogsUtils.h"
#include "core/utils/payloadSender.h"
#include "core/utils/utilities.h"
#include "core/utils/serverConfigUtils.h"
#include "version.h"
#include "core/utils/containerEnum.h"
#include "core/utils/containers/containerUtils.h"
#include "core/utils/managedRoutePolicy.h"
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
constexpr int serverRoutingRulesClientResolveLookupTimeoutMs = 8 * 1000;
constexpr int serverRoutingRulesClientResolveMaxRetryWaves = 5;
constexpr int serverRoutingRulesClientResolveCycleDeadlineMs = 10 * 60 * 1000;
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

QStringList persistedManagedResolvePendingDomains(const QJsonObject &serverConfig,
                                                   const QStringList &domains)
{
    QStringList pending;
    const QJsonValue value =
            serverConfig.value(configKey::managedSplitTunnelClientResolvePendingSites);
    if (!value.isArray()) {
        return pending;
    }

    const QJsonArray items = value.toArray();
    for (const QJsonValue &item : items) {
        const QString domain = item.toString().trimmed().toLower();
        if (domains.contains(domain) && !pending.contains(domain)) {
            pending.append(domain);
        }
    }
    return pending;
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

    return managedDnsConvergence::completeCacheRefreshDue(
            serverConfig.value(
                    configKey::managedSplitTunnelClientResolveLastFullSweepAt).toString(),
            serverConfig.value(configKey::managedSplitTunnelClientResolvedAt).toString(),
            QDateTime::currentDateTimeUtc(),
            serverRoutingRulesClientResolveIntervalSeconds);
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
    connect(this, &ConnectionController::killSwitchModeChangedRequested, m_vpnConnection, &VpnConnection::onKillSwitchModeChanged, Qt::QueuedConnection);
    connect(m_vpnConnection, &VpnConnection::connectionContextChanged, this,
            &ConnectionController::onVpnConnectionContextChanged, Qt::QueuedConnection);
    connect(this, &ConnectionController::managedRouteConnectionSnapshotPrepared, m_vpnConnection,
            &VpnConnection::prepareManagedRouteConnectionSnapshot, Qt::QueuedConnection);
    connect(this, &ConnectionController::managedRouteReconcileRequested, m_vpnConnection,
            &VpnConnection::reconcileManagedSplitTunnelRoutes, Qt::QueuedConnection);
    connect(this, &ConnectionController::managedRouteFullRebuildRequested, m_vpnConnection,
            &VpnConnection::rebuildManagedSplitTunnelRoutes, Qt::QueuedConnection);
    connect(m_vpnConnection, &VpnConnection::managedSplitTunnelRoutesReconciled, this,
            &ConnectionController::onManagedRouteReconciled, Qt::QueuedConnection);
    connect(m_vpnConnection, &VpnConnection::managedSplitTunnelRouteBaseReady, this,
            &ConnectionController::onManagedRouteBaseReady, Qt::QueuedConnection);
    connect(m_vpnConnection, &VpnConnection::vpnProtocolError, this,
            [this](ErrorCode error) { m_cachedLastConnectionError = error; },
            Qt::QueuedConnection);
    connect(m_serversRepository, &SecureServersRepository::serverRemoved, this,
            [this](const QString &removedServerId, int removedIndex) {
        Q_UNUSED(removedIndex)
        if (!removedServerId.isEmpty()
            && removedServerId == m_cachedConnectionServerId
            && m_cachedConnectionState != Vpn::ConnectionState::Disconnected
            && m_cachedConnectionState != Vpn::ConnectionState::Disconnecting
            && m_cachedConnectionState != Vpn::ConnectionState::Unknown) {
            qWarning() << "ConnectionController: active server was removed; disconnecting its VPN session";
            emit closeConnectionRequested();
        }
    });
#ifdef Q_OS_ANDROID
    connect(this, &ConnectionController::restoreConnectionRequested, m_vpnConnection, &VpnConnection::restoreConnection, Qt::QueuedConnection);
#endif
    m_serverRoutingRulesSyncTimer.setSingleShot(true);
    connect(&m_serverRoutingRulesSyncTimer, &QTimer::timeout, this, &ConnectionController::syncServerRoutingRules);
    m_serverRoutingRulesClientResolveTimer.setSingleShot(true);
    connect(&m_serverRoutingRulesClientResolveTimer, &QTimer::timeout, this, &ConnectionController::startClientManagedSitesResolve);
    m_clientManagedSitesLookupTimeoutTimer.setSingleShot(true);
    connect(&m_clientManagedSitesLookupTimeoutTimer, &QTimer::timeout,
            this, &ConnectionController::onClientManagedSiteResolveTimeout);
}

bool ConnectionController::isConnected() const
{
    return m_vpnConnection && m_cachedConnectionState == Vpn::ConnectionState::Connected;
}

void ConnectionController::setConnectionState(Vpn::ConnectionState state)
{
    emit connectionStateChanged(state);
}

void ConnectionController::onVpnConnectionStateChanged(Vpn::ConnectionState state)
{
    m_cachedConnectionState = state;
    if (state != Vpn::ConnectionState::Connected) {
        preservePendingManagedRouteDesired();
        ++m_managedRouteReconcileGeneration;
        clearPendingManagedRouteReconciliation();
        m_hasConfirmedManagedRouteState = false;
        m_managedRouteIncrementalBlocked = true;
    }
    switch (state) {
    case Vpn::ConnectionState::Connected:
        ++m_serverRoutingRulesSyncGeneration;
        m_isServerRoutingRulesSyncInProgress = false;
        m_serverRoutingRulesSyncPendingRefresh = false;
        m_serverRoutingRulesSyncFastRetryCount = 0;
        m_clientManagedSitesResolveRetryCount = 0;
        cancelClientManagedSitesResolve();
        // Connected is not an installation receipt. The worker publishes the
        // exact route base only after the initial trusted-route batch has a
        // bounded, full-count acknowledgement (or protocol startup itself is
        // the receipt on platforms where routes live in the tunnel config).
        preservePendingManagedRouteDesired();
        clearPendingManagedRouteReconciliation();
        m_hasConfirmedManagedRouteState = false;
        m_managedRouteIncrementalBlocked = true;
        if (const int serverIndex = currentConnectionServerIndex(); serverIndex >= 0) {
            // Managed-domain resolution belongs to this main-thread
            // controller. The worker receives only immutable, already-bounded
            // route snapshots, so its authoritative base cannot drift while
            // asynchronous DNS answers arrive.
            scheduleClientManagedSitesResolve(serverIndex);
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
        m_coalescedManagedRouteDesired = {};
        m_managedRouteFullRebuildAttempted = false;
        break;
    case Vpn::ConnectionState::Error:
    case Vpn::ConnectionState::Unknown:
        m_serverRoutingRulesSyncTimer.stop();
        ++m_serverRoutingRulesSyncGeneration;
        m_isServerRoutingRulesSyncInProgress = false;
        m_serverRoutingRulesSyncPendingRefresh = false;
        m_clientManagedSitesResolveRetryCount = 0;
        cancelClientManagedSitesResolve();
        m_coalescedManagedRouteDesired = {};
        m_managedRouteFullRebuildAttempted = false;
        break;
    default:
        break;
    }

    emit connectionStateChanged(state);
}

void ConnectionController::onVpnConnectionContextChanged(
        const QString &serverId, const QString &serverRoutingRulesSyncHost,
        quint64 connectionEpoch)
{
    if (connectionEpoch != m_cachedConnectionEpoch
        || serverId != m_cachedConnectionServerId) {
        if (serverId == m_cachedConnectionServerId) {
            preservePendingManagedRouteDesired();
        }
        ++m_managedRouteReconcileGeneration;
        clearPendingManagedRouteReconciliation();
        m_hasConfirmedManagedRouteState = false;
        m_managedRouteIncrementalBlocked = true;
        if (serverId != m_cachedConnectionServerId) {
            m_coalescedManagedRouteDesired = {};
            m_managedRouteFullRebuildAttempted = false;
        }
    }
    m_cachedConnectionServerId = serverId;
    m_cachedServerRoutingRulesSyncHost = serverRoutingRulesSyncHost;
    m_cachedConnectionEpoch = connectionEpoch;
}

void ConnectionController::onManagedRouteReconciled(
        quint64 generation, quint64 connectionEpoch, const QString &serverId,
        bool requestAccepted, bool updated, bool reconnectScheduled,
        int appliedModeValue, const QStringList &appliedRoutes,
        quint64 appliedBaseRevision,
        const QString &appliedPolicyRevision,
        const QString &appliedPolicyContentHash)
{
    if (generation != m_managedRouteReconcileGeneration
        || connectionEpoch != m_cachedConnectionEpoch
        || serverId != m_cachedConnectionServerId
        || generation != m_pendingManagedRouteReconcileGeneration
        || serverId != m_pendingManagedRouteReconcileServerId) {
        return;
    }
    ManagedRouteDesiredSnapshot acknowledgedDesired;
    acknowledgedDesired.valid = true;
    acknowledgedDesired.serverId = m_pendingManagedRouteReconcileServerId;
    acknowledgedDesired.routeMode = m_pendingManagedRouteMode;
    acknowledgedDesired.managedIps = m_pendingManagedRouteIps;
    acknowledgedDesired.policyRevision = m_pendingManagedRoutePolicyRevision;
    acknowledgedDesired.contentHash = m_pendingManagedRouteContentHash;
    acknowledgedDesired.localSites = m_pendingManagedRouteLocalSites;
    const auto appliedMode = static_cast<RouteMode>(appliedModeValue);
    const bool modeValid = appliedMode == RouteMode::VpnAllSites
            || appliedMode == RouteMode::VpnOnlyForwardSites
            || appliedMode == RouteMode::VpnAllExceptSites;
    bool routesValid = false;
    const QStringList canonicalAppliedRoutes =
            managedRoutePolicy::validatedManagedRoutes(appliedRoutes, &routesValid);
    const bool appliedReceiptValid = modeValid && routesValid
            && canonicalAppliedRoutes == appliedRoutes
            && (appliedMode == RouteMode::VpnAllExceptSites
                || appliedRoutes.isEmpty())
            && managedRoutePolicy::isCanonicalPolicyIdentity(
                    appliedPolicyRevision, appliedPolicyContentHash)
            && (appliedRoutes.isEmpty() || !appliedPolicyRevision.isEmpty());
    const bool reconciliationConfirmed = requestAccepted && updated
            && !reconnectScheduled && appliedReceiptValid
            && appliedMode == m_pendingManagedRouteMode
            && appliedPolicyRevision == m_pendingManagedRoutePolicyRevision
            && appliedPolicyContentHash == m_pendingManagedRouteContentHash;
    const bool needsExplicitFullRebuild = !reconciliationConfirmed
            && !reconnectScheduled;

    if (reconciliationConfirmed) {
        // Commit the exact normalized state acknowledged by the worker. Do not
        // substitute either the raw request or mutable repository state: the
        // worker may have removed protected hosts or canonicalized the batch.
        m_confirmedManagedRouteMode = appliedMode;
        m_confirmedManagedSplitTunnelIps = appliedRoutes;
        m_confirmedManagedPolicyRevision = appliedPolicyRevision;
        m_confirmedManagedContentHash = appliedPolicyContentHash;
        m_confirmedManagedRouteBaseRevision = appliedBaseRevision;
        m_hasConfirmedManagedRouteState = true;
        m_managedRouteIncrementalBlocked = false;
        qInfo() << "ConnectionController: worker completed managed route reconciliation";
    } else {
        // Deferred, reconnect-required and rejected requests all leave the
        // runtime base unconfirmed. Preserve the newest desired snapshot, but
        // never project it into applied state while reconnect is pending.
        if (!m_coalescedManagedRouteDesired.valid) {
            preserveLatestManagedRouteDesired(acknowledgedDesired);
        }
        m_hasConfirmedManagedRouteState = false;
        m_managedRouteIncrementalBlocked = true;
        qInfo() << (reconnectScheduled
                            ? "ConnectionController: worker scheduled a full managed-route rebuild"
                            : "ConnectionController: managed-route request was not confirmed");
    }
    clearPendingManagedRouteReconciliation();
    if (needsExplicitFullRebuild) {
        requestManagedRouteFullRebuild();
    }

    if (m_hasConfirmedManagedRouteState && m_coalescedManagedRouteDesired.valid) {
        const ManagedRouteDesiredSnapshot desired = m_coalescedManagedRouteDesired;
        m_coalescedManagedRouteDesired = {};
        dispatchManagedRouteReconciliation(desired, QStringLiteral("coalesced managed-route policy"));
    }
}

void ConnectionController::onManagedRouteBaseReady(
        quint64 connectionEpoch, const QString &serverId, int modeValue,
        const QStringList &managedRoutes, quint64 baseRevision,
        const QString &policyRevision, const QString &policyContentHash,
        bool confirmed)
{
    const auto mode = static_cast<RouteMode>(modeValue);
    const bool modeValid = mode == RouteMode::VpnAllSites
            || mode == RouteMode::VpnOnlyForwardSites
            || mode == RouteMode::VpnAllExceptSites;
    bool routesValid = false;
    const QStringList canonicalRoutes =
            managedRoutePolicy::validatedManagedRoutes(managedRoutes, &routesValid);
    const bool receiptValid = modeValid && routesValid
            && canonicalRoutes == managedRoutes
            && (mode == RouteMode::VpnAllExceptSites || managedRoutes.isEmpty())
            && managedRoutePolicy::isCanonicalPolicyIdentity(
                    policyRevision, policyContentHash)
            && (managedRoutes.isEmpty() || !policyRevision.isEmpty());
    if (!isConnected() || connectionEpoch != m_cachedConnectionEpoch
        || serverId.isEmpty() || serverId != m_cachedConnectionServerId) {
        return;
    }

    preservePendingManagedRouteDesired();
    clearPendingManagedRouteReconciliation();
    m_confirmedManagedRouteBaseRevision = baseRevision;
    if (!confirmed || !receiptValid) {
        m_hasConfirmedManagedRouteState = false;
        m_managedRouteIncrementalBlocked = true;
        const ManagedRouteDesiredSnapshot desired = managedRouteDesiredSnapshot(serverId);
        preserveLatestManagedRouteDesired(desired);
        requestManagedRouteFullRebuild();
        return;
    }

    m_confirmedManagedRouteMode = mode;
    m_confirmedManagedSplitTunnelIps = managedRoutes;
    m_confirmedManagedPolicyRevision = policyRevision;
    m_confirmedManagedContentHash = policyContentHash;
    m_hasConfirmedManagedRouteState = true;
    m_managedRouteIncrementalBlocked = false;
    m_managedRouteFullRebuildAttempted = false;

    if (m_coalescedManagedRouteDesired.valid) {
        const ManagedRouteDesiredSnapshot desired = m_coalescedManagedRouteDesired;
        m_coalescedManagedRouteDesired = {};
        dispatchManagedRouteReconciliation(desired, QStringLiteral("confirmed connected route base"));
    } else {
        scheduleServerRoutingRulesSync(0);
    }
}

ConnectionController::ManagedRouteDesiredSnapshot
ConnectionController::managedRouteDesiredSnapshot(const QString &serverId) const
{
    ManagedRouteDesiredSnapshot desired;
    const int serverIndex = m_serversRepository->indexOfServerId(serverId);
    if (serverId.isEmpty() || serverIndex < 0
        || serverIndex >= m_serversRepository->serversCount()) {
        return desired;
    }

    desired.valid = true;
    desired.serverId = serverId;
    const bool localSplitEnabled = m_appSettingsRepository->isSitesSplitTunnelingEnabled();
    const RouteMode localRouteMode = m_appSettingsRepository->routeMode();
    desired.routeMode = m_serversRepository->effectiveSiteRouteMode(
            serverIndex, localSplitEnabled, localRouteMode);
    desired.managedIps = desired.routeMode == RouteMode::VpnAllExceptSites
            ? managedSplitTunnelIpsForSync(serverIndex, RouteMode::VpnAllExceptSites)
            : QStringList();
    desired.policyRevision = effectiveManagedRoutePolicyRevision(serverIndex);
    desired.contentHash = effectiveManagedRouteContentHash(serverIndex);
    desired.localSites = m_appSettingsRepository->vpnSites(desired.routeMode);
    if (!managedRoutePolicy::isCanonicalPolicyIdentity(
                desired.policyRevision, desired.contentHash)
        || (!desired.managedIps.isEmpty()
            && desired.policyRevision.isEmpty())) {
        desired = {};
    }
    return desired;
}

void ConnectionController::prepareManagedRouteConnectionSnapshot(const QString &serverId)
{
    const ManagedRouteDesiredSnapshot desired = managedRouteDesiredSnapshot(serverId);
    if (!desired.valid) {
        return;
    }
    emit managedRouteConnectionSnapshotPrepared(
            m_managedRouteReconcileGeneration, desired.serverId,
            static_cast<int>(desired.routeMode),
            desired.managedIps, desired.policyRevision,
            desired.contentHash, desired.localSites);
}

void ConnectionController::preserveLatestManagedRouteDesired(
        const ManagedRouteDesiredSnapshot &desired)
{
    if (desired.valid && desired.serverId == m_cachedConnectionServerId) {
        m_coalescedManagedRouteDesired = desired;
        // Coalescing suppresses a second mutation request, but a reconnect
        // triggered by the in-flight request must rebuild from the newest
        // immutable desired snapshot rather than from mutable repositories.
        emit managedRouteConnectionSnapshotPrepared(
                m_managedRouteReconcileGeneration, desired.serverId,
                static_cast<int>(desired.routeMode),
                desired.managedIps, desired.policyRevision,
                desired.contentHash, desired.localSites);
    }
}

void ConnectionController::clearPendingManagedRouteReconciliation()
{
    m_managedRouteReconcileInFlight = false;
    m_pendingManagedRouteReconcileGeneration = 0;
    m_pendingManagedRouteReconcileServerId.clear();
    m_pendingManagedRouteMode = RouteMode::VpnAllSites;
    m_pendingManagedRouteIps.clear();
    m_pendingManagedRoutePolicyRevision.clear();
    m_pendingManagedRouteContentHash.clear();
    m_pendingManagedRouteLocalSites.clear();
    m_pendingManagedRouteExpectedBaseRevision = 0;
}

void ConnectionController::preservePendingManagedRouteDesired()
{
    if (!m_managedRouteReconcileInFlight
        || m_pendingManagedRouteReconcileServerId.isEmpty()
        || m_coalescedManagedRouteDesired.valid) {
        return;
    }

    ManagedRouteDesiredSnapshot pendingDesired;
    pendingDesired.valid = true;
    pendingDesired.serverId = m_pendingManagedRouteReconcileServerId;
    pendingDesired.routeMode = m_pendingManagedRouteMode;
    pendingDesired.managedIps = m_pendingManagedRouteIps;
    pendingDesired.policyRevision = m_pendingManagedRoutePolicyRevision;
    pendingDesired.contentHash = m_pendingManagedRouteContentHash;
    pendingDesired.localSites = m_pendingManagedRouteLocalSites;
    preserveLatestManagedRouteDesired(pendingDesired);
}

void ConnectionController::dispatchManagedRouteReconciliation(
        const ManagedRouteDesiredSnapshot &desired, const QString &reason)
{
    if (!desired.valid || !isConnected()
        || desired.serverId != m_cachedConnectionServerId) {
        return;
    }
    if (m_managedRouteReconcileInFlight) {
        preserveLatestManagedRouteDesired(desired);
        return;
    }
    if (!m_hasConfirmedManagedRouteState || m_managedRouteIncrementalBlocked) {
        preserveLatestManagedRouteDesired(desired);
        return;
    }
    if (desired.routeMode == m_confirmedManagedRouteMode
        && desired.managedIps == m_confirmedManagedSplitTunnelIps
        && desired.policyRevision == m_confirmedManagedPolicyRevision
        && desired.contentHash == m_confirmedManagedContentHash) {
        return;
    }

    ++m_managedRouteReconcileGeneration;
    m_managedRouteReconcileInFlight = true;
    m_pendingManagedRouteReconcileGeneration = m_managedRouteReconcileGeneration;
    m_pendingManagedRouteReconcileServerId = desired.serverId;
    m_pendingManagedRouteMode = desired.routeMode;
    m_pendingManagedRouteIps = desired.managedIps;
    m_pendingManagedRoutePolicyRevision = desired.policyRevision;
    m_pendingManagedRouteContentHash = desired.contentHash;
    m_pendingManagedRouteLocalSites = desired.localSites;
    m_pendingManagedRouteExpectedBaseRevision = m_confirmedManagedRouteBaseRevision;
    qInfo() << "ConnectionController: queued managed route reconciliation:" << reason;
    emit managedRouteReconcileRequested(
            m_managedRouteReconcileGeneration, m_cachedConnectionEpoch,
            desired.serverId, m_pendingManagedRouteExpectedBaseRevision,
            m_confirmedManagedPolicyRevision, m_confirmedManagedContentHash,
            static_cast<int>(desired.routeMode), m_confirmedManagedSplitTunnelIps,
            desired.managedIps, desired.policyRevision,
            desired.contentHash, desired.localSites);
}

void ConnectionController::requestManagedRouteReconciliation(
        const QString &serverId, const QString &reason)
{
    const ManagedRouteDesiredSnapshot desired = managedRouteDesiredSnapshot(serverId);
    if (!desired.valid || !isConnected() || serverId != m_cachedConnectionServerId) {
        return;
    }
    if (m_managedRouteReconcileInFlight
        || !m_hasConfirmedManagedRouteState
        || m_managedRouteIncrementalBlocked) {
        preserveLatestManagedRouteDesired(desired);
        return;
    }
    dispatchManagedRouteReconciliation(desired, reason);
}

void ConnectionController::requestManagedRouteFullRebuild()
{
    if (!isConnected() || m_cachedConnectionServerId.isEmpty()
        || m_managedRouteFullRebuildAttempted) {
        return;
    }
    m_managedRouteFullRebuildAttempted = true;
    qWarning() << "ConnectionController: initial managed-route base is unknown; requesting one full rebuild";
    emit managedRouteFullRebuildRequested(
            m_cachedConnectionEpoch, m_cachedConnectionServerId);
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

    const serverConfigUtils::ConfigType kind = m_serversRepository->serverKind(serverId);
    if (serverConfigUtils::isLegacyApiSubscription(kind)) {
        return ErrorCode::LegacyApiV1NotSupportedError;
    }

    DockerContainer container = DockerContainer::None;
    const ErrorCode errorCode = defaultContainerForServer(serverId, container);
    if (errorCode != ErrorCode::NoError) {
        return errorCode;
    }

    if (container == DockerContainer::None) {
        if (serverConfigUtils::isApiV2Subscription(kind)) {
            return ErrorCode::NoError;
        }
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
    QJsonArray sendPayload;
    const auto apiV2 = m_serversRepository->apiV2Config(serverId);
    if (apiV2.has_value()) {
        sendPayload = apiV2->sendPayload;
    }
    if (sendPayload.isEmpty() && serverIndex >= 0) {
        sendPayload = m_serversRepository->serverJson(serverIndex).value(configKey::sendPayload).toArray();
    }
    if (!sendPayload.isEmpty()) {
        PayloadSender::sendAll(sendPayload);
    }

    ++m_managedRouteReconcileGeneration;
    clearPendingManagedRouteReconciliation();
    m_coalescedManagedRouteDesired = {};
    m_hasConfirmedManagedRouteState = false;
    m_managedRouteIncrementalBlocked = true;
    m_managedRouteFullRebuildAttempted = false;
    m_cachedLastConnectionError = ErrorCode::NoError;
    prepareManagedRouteConnectionSnapshot(serverId);
    emit openConnectionRequested(serverId, serverIndex, container, vpnConfiguration);
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

    ++m_managedRouteReconcileGeneration;
    clearPendingManagedRouteReconciliation();
    m_coalescedManagedRouteDesired = {};
    m_hasConfirmedManagedRouteState = false;
    m_managedRouteIncrementalBlocked = true;
    m_managedRouteFullRebuildAttempted = false;
    prepareManagedRouteConnectionSnapshot(serverId);
    emit restoreConnectionRequested(serverId, serverIndex, container, vpnConfiguration, state);
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
    return m_cachedLastConnectionError;
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

    // VpnConnection lives on its worker thread. Copy every repository-backed
    // runtime setting into the immutable connection context before queuing the
    // start so the worker never dereferences main-thread repositories.
    vpnConfiguration.insert(
            configKey::killSwitchOption,
            QVariant(m_appSettingsRepository->isKillSwitchEnabled()).toString());
    vpnConfiguration.insert(
            configKey::allowedDnsServers,
            QVariant(m_appSettingsRepository->getAllowedDnsServers()).toJsonValue());

    amnezia::AppsRouteMode appsRouteMode = amnezia::AppsRouteMode::VpnAllApps;
    QJsonArray appsJsonArray;
    if (m_appSettingsRepository->isAppsSplitTunnelingEnabled()) {
        appsRouteMode = m_appSettingsRepository->appsRouteMode();
        const auto apps = m_appSettingsRepository->vpnApps(appsRouteMode);
        for (const auto &app : apps) {
            appsJsonArray.append(app.appPath.isEmpty() ? app.packageName : app.appPath);
        }
        if (appsRouteMode == amnezia::AppsRouteMode::VpnOnlyForwardApps
            && !vpnConfiguration.value(configKey::clientLogs).toObject().isEmpty()) {
            appsJsonArray.append(QStringLiteral("org.amnezia.vpn"));
        }
        if (appsJsonArray.isEmpty()) {
            appsRouteMode = amnezia::AppsRouteMode::VpnAllApps;
        }
    }
    vpnConfiguration.insert(configKey::appSplitTunnelType,
                            static_cast<int>(appsRouteMode));
    vpnConfiguration.insert(configKey::splitTunnelApps, appsJsonArray);

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

QString ConnectionController::effectiveManagedRoutePolicyRevision(int serverIndex) const
{
    if (serverIndex < 0 || serverIndex >= m_serversRepository->serversCount()) {
        return {};
    }
    return managedRoutePolicy::effectiveRevision(
            m_serversRepository->serverJson(serverIndex));
}

QString ConnectionController::effectiveManagedRouteContentHash(int serverIndex) const
{
    if (serverIndex < 0 || serverIndex >= m_serversRepository->serversCount()) {
        return {};
    }
    return managedRoutePolicy::effectiveContentHash(
            m_serversRepository->serverJson(serverIndex));
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

    const ManagedRouteDesiredSnapshot desired = managedRouteDesiredSnapshot(serverId);
    if (!desired.valid) {
        m_isServerRoutingRulesSyncInProgress = false;
        return true;
    }
    const bool currentLocalSplitEnabled = m_appSettingsRepository->isSitesSplitTunnelingEnabled();
    const RouteMode currentLocalRouteMode = m_appSettingsRepository->routeMode();
    const bool localSettingsChanged = currentLocalSplitEnabled != routeSnapshot.localSplitEnabled
            || currentLocalRouteMode != routeSnapshot.localRouteMode;
    const bool managedContentChanged = !routeSnapshot.hasConfirmedAppliedState
            || desired.managedIps != routeSnapshot.appliedManagedIps
            || desired.policyRevision != routeSnapshot.appliedPolicyRevision
            || desired.contentHash != routeSnapshot.appliedContentHash;

    if (routeSnapshot.hasConfirmedAppliedState
        && localSettingsChanged && !managedContentChanged) {
        qInfo() << "ConnectionController: local routing changed while reconciling managed policy;"
                   " leaving it to the local routing owner";
        return false;
    }
    if (routeSnapshot.hasConfirmedAppliedState
        && desired.routeMode == routeSnapshot.appliedRouteMode
        && desired.managedIps == routeSnapshot.appliedManagedIps
        && desired.policyRevision == routeSnapshot.appliedPolicyRevision
        && desired.contentHash == routeSnapshot.appliedContentHash) {
        return false;
    }

    cancelClientManagedSitesResolve();
    requestManagedRouteReconciliation(serverId, reason);
    if (routeSnapshot.hasConfirmedAppliedState
        && desired.routeMode != routeSnapshot.appliedRouteMode) {
        m_isServerRoutingRulesSyncInProgress = false;
        m_serverRoutingRulesSyncPendingRefresh = false;
        return true;
    }
    return false;
}

int ConnectionController::currentConnectionServerIndex() const
{
    const QString serverId = currentConnectionServerId();
    return serverId.isEmpty() ? -1 : m_serversRepository->indexOfServerId(serverId);
}

QString ConnectionController::currentConnectionServerId() const
{
    return m_vpnConnection ? m_cachedConnectionServerId : QString();
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
    routeSnapshot.hasConfirmedAppliedState = m_hasConfirmedManagedRouteState;
    if (routeSnapshot.hasConfirmedAppliedState) {
        routeSnapshot.appliedBaseRevision = m_confirmedManagedRouteBaseRevision;
        routeSnapshot.appliedRouteMode = m_confirmedManagedRouteMode;
        routeSnapshot.appliedManagedIps = m_confirmedManagedSplitTunnelIps;
        routeSnapshot.appliedPolicyRevision = m_confirmedManagedPolicyRevision;
        routeSnapshot.appliedContentHash = m_confirmedManagedContentHash;
    }
    m_isServerRoutingRulesSyncInProgress = true;
    const int syncGeneration = ++m_serverRoutingRulesSyncGeneration;
    if (reconcileManagedRouteState(
                serverId, routeSnapshot,
                QStringLiteral("stored policy expired or no longer matches its declaration"))) {
        return;
    }
    routeSnapshot.hasConfirmedAppliedState = m_hasConfirmedManagedRouteState;
    if (routeSnapshot.hasConfirmedAppliedState) {
        routeSnapshot.appliedBaseRevision = m_confirmedManagedRouteBaseRevision;
        routeSnapshot.appliedRouteMode = m_confirmedManagedRouteMode;
        routeSnapshot.appliedManagedIps = m_confirmedManagedSplitTunnelIps;
        routeSnapshot.appliedPolicyRevision = m_confirmedManagedPolicyRevision;
        routeSnapshot.appliedContentHash = m_confirmedManagedContentHash;
    }
    routeSnapshot.localSplitEnabled = m_appSettingsRepository->isSitesSplitTunnelingEnabled();
    routeSnapshot.localRouteMode = m_appSettingsRepository->routeMode();

    const QList<QUrl> syncUrls = serverRoutingRulesSyncUrls(m_cachedServerRoutingRulesSyncHost);
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
                const bool clientManagedResolvePending =
                        m_clientManagedSitesConvergence.active()
                        && m_clientManagedSitesConvergence.serverId() == serverId;

                const bool currentLocalSplitEnabled = m_appSettingsRepository->isSitesSplitTunnelingEnabled();
                const RouteMode currentLocalRouteMode = m_appSettingsRepository->routeMode();
                const RouteMode newRouteMode = m_serversRepository->effectiveSiteRouteMode(
                        serverIndex, currentLocalSplitEnabled, currentLocalRouteMode);
                const QStringList newManagedSplitTunnelIps = newRouteMode == RouteMode::VpnAllExceptSites
                        ? managedSplitTunnelIpsForSync(serverIndex, RouteMode::VpnAllExceptSites)
                        : QStringList();
                const QString effectivePolicyRevision =
                        effectiveManagedRoutePolicyRevision(serverIndex);
                const bool localSettingsChanged =
                        currentLocalSplitEnabled != routeSnapshot.localSplitEnabled
                        || currentLocalRouteMode != routeSnapshot.localRouteMode;
                const bool managedRuntimeChanged =
                        newManagedSplitTunnelIps != routeSnapshot.appliedManagedIps
                        || effectivePolicyRevision
                                != routeSnapshot.appliedPolicyRevision
                        || effectiveContentHash != routeSnapshot.appliedContentHash;
                if (localSettingsChanged && !managedRuntimeChanged) {
                    qInfo() << "ConnectionController: local routing changed during policy sync;"
                               " no managed runtime delta to reconcile";
                    finishServerRoutingRulesSync(true);
                    return;
                }

                if (newRouteMode != routeSnapshot.appliedRouteMode) {
                    if (clientManagedResolvePending
                        && newRouteMode == RouteMode::VpnAllExceptSites) {
                        qInfo() << "ConnectionController: deferring managed route-mode transition until DNS convergence";
                    } else {
                        requestManagedRouteReconciliation(
                                serverId,
                                QStringLiteral("server routing rules changed route mode"));
                        m_isServerRoutingRulesSyncInProgress = false;
                        m_serverRoutingRulesSyncPendingRefresh = false;
                        return;
                    }
                }
                if (newRouteMode == RouteMode::VpnAllExceptSites
                    && managedRuntimeChanged) {
                    if (clientManagedResolvePending) {
                        qInfo() << "ConnectionController: deferring managed route reconciliation until DNS convergence";
                    } else {
                        requestManagedRouteReconciliation(
                                serverId,
                                QStringLiteral("server routing rule IP delta"));
                    }
                }

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
        serverConfig.remove(configKey::managedSplitTunnelClientResolveRetryAfter);
        serverConfig.remove(configKey::managedSplitTunnelClientResolvePendingSites);
        serverConfig.remove(configKey::managedSplitTunnelClientResolvePendingSourceDigest);
        serverConfig.remove(configKey::managedSplitTunnelClientResolveLastFullSweepAt);
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
    m_clientManagedSitesLookupTimeoutTimer.stop();
    if (m_clientManagedSitesLookupId >= 0) {
        QHostInfo::abortHostLookup(m_clientManagedSitesLookupId);
    }
    m_clientManagedSitesLookupId = -1;
    m_isClientManagedSitesResolveInProgress = false;
    m_clientManagedSitesResolveServerId.clear();
    m_clientManagedSitesResolveQueue.clear();
    m_clientManagedSitesCurrentDomain.clear();
    m_clientManagedSitesConvergence.clear();
    m_clientManagedSitesResolveSnapshotCaptured = false;
    m_clientManagedSitesResolveIsFullSweep = false;
}

void ConnectionController::scheduleClientManagedSitesResolve(int serverIndex)
{
    if (!isConnected() || serverIndex < 0 || serverIndex >= m_serversRepository->serversCount()
        || !isCurrentConnectionServerIndex(serverIndex)) {
        return;
    }

    const QJsonObject serverConfig = m_serversRepository->serverJson(serverIndex);
    const QJsonObject sourceSites = serverRoutingRulesSourceSites(serverConfig);
    if (!shouldRunClientManagedResolve(serverConfig, sourceSites)) {
        cancelClientManagedSitesResolve();
        return;
    }

    const QString serverId = m_serversRepository->serverIdAt(serverIndex);
    const QString sourceDigest = managedRoutePolicy::derivedRevision(sourceSites);
    if (m_clientManagedSitesConvergence.matches(serverId, sourceDigest)) {
        return;
    }

    // A source-policy change owns a new convergence generation. A repeated
    // sync of the same source cannot reset its pending-only retry wave.
    cancelClientManagedSitesResolve();
    const QStringList domains = managedResolveDomains(sourceSites);
    const QJsonObject baseline = clientResolvedSitesBoundToSource(serverConfig, sourceSites);
    const QDateTime now = QDateTime::currentDateTimeUtc();
    const bool refreshAll = managedDnsConvergence::fullSweepDue(
            serverConfig.value(
                    configKey::managedSplitTunnelClientResolveLastFullSweepAt).toString(),
            now, serverRoutingRulesClientResolveIntervalSeconds);
    const bool resumePartialCycle =
            serverConfig.value(configKey::managedSplitTunnelClientResolvePendingSites).isArray()
            && serverConfig.value(
                       configKey::managedSplitTunnelClientResolvePendingSourceDigest).toString()
                    == sourceDigest
            && !refreshAll
            && !QDateTime::fromString(
                        serverConfig.value(configKey::managedSplitTunnelClientResolvedAt).toString(),
                        Qt::ISODate).isValid();
    const QStringList persistedPending =
            persistedManagedResolvePendingDomains(serverConfig, domains);
    const QStringList pending = managedDnsConvergence::pendingDomainsForCycle(
            domains, baseline, persistedPending, !resumePartialCycle);
    m_clientManagedSitesResolveIsFullSweep = !resumePartialCycle;
    m_clientManagedSitesConvergence.begin(
            serverId, sourceDigest, domains, baseline, pending);
    m_clientManagedSitesResolveDeadline =
            QDeadlineTimer(serverRoutingRulesClientResolveCycleDeadlineMs);
    m_clientManagedSitesResolveServerId = serverId;
    const int jitterMs = QRandomGenerator::global()->bounded(serverRoutingRulesClientResolveJitterMs + 1);
    const int delayMs = managedDnsConvergence::initialDelayMs(
            resumePartialCycle
                    ? serverConfig.value(
                              configKey::managedSplitTunnelClientResolveRetryAfter).toString()
                    : QString(),
            now,
            serverRoutingRulesClientResolveInitialDelayMs + jitterMs);
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
    int delayMs = qMin(boundedDelayMs + jitterMs, serverRoutingRulesClientResolveRetryMaxMs);
    const qint64 remainingMs = m_clientManagedSitesResolveDeadline.remainingTime();
    if (remainingMs >= 0) {
        delayMs = qMin(delayMs, static_cast<int>(qMin<qint64>(remainingMs, (std::numeric_limits<int>::max)())));
    }
    m_clientManagedSitesResolveRetryCount =
            qMin(m_clientManagedSitesResolveRetryCount + 1,
                 serverRoutingRulesClientResolveMaxBackoffExponent);
    qInfo() << "ConnectionController: managed DNS resolve incomplete; retrying in" << delayMs
            << "ms for server" << serverIndex
            << "pending domains" << m_clientManagedSitesConvergence.pending().size();
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
    const QString sourceDigest = managedRoutePolicy::derivedRevision(sourceSites);
    if (!m_clientManagedSitesConvergence.matches(serverId, sourceDigest)) {
        scheduleClientManagedSitesResolve(serverIndex);
        return;
    }

    m_clientManagedSitesResolveQueue = m_clientManagedSitesConvergence.takePendingWave();
    if (m_clientManagedSitesResolveQueue.isEmpty()) {
        finishClientManagedSitesResolve();
        return;
    }
    if (m_clientManagedSitesResolveDeadline.hasExpired()) {
        for (const QString &domain : std::as_const(m_clientManagedSitesResolveQueue)) {
            m_clientManagedSitesConvergence.recordFailure(domain);
        }
        m_clientManagedSitesResolveQueue.clear();
        finishClientManagedSitesResolve();
        return;
    }

    // Each wave owns a fresh generation. A timed-out or superseded callback
    // cannot update the staged cache or advance its bounded retry cycle.
    ++m_clientManagedSitesResolveGeneration;
    if (!m_clientManagedSitesResolveSnapshotCaptured) {
        m_clientManagedSitesResolveOldLocalSplitEnabled =
                m_appSettingsRepository->isSitesSplitTunnelingEnabled();
        m_clientManagedSitesResolveOldLocalRouteMode = m_appSettingsRepository->routeMode();
        m_clientManagedSitesResolveOldStateConfirmed = m_hasConfirmedManagedRouteState;
        m_clientManagedSitesResolveOldRouteMode = m_hasConfirmedManagedRouteState
                ? m_confirmedManagedRouteMode : RouteMode::VpnAllSites;
        m_clientManagedSitesResolveOldManagedSplitTunnelIps = m_hasConfirmedManagedRouteState
                ? m_confirmedManagedSplitTunnelIps : QStringList();
        m_clientManagedSitesResolveOldPolicyRevision = m_hasConfirmedManagedRouteState
                ? m_confirmedManagedPolicyRevision : QString();
        m_clientManagedSitesResolveOldContentHash = m_hasConfirmedManagedRouteState
                ? m_confirmedManagedContentHash : QString();
        m_clientManagedSitesResolveSnapshotCaptured = true;
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
    if (m_clientManagedSitesResolveDeadline.hasExpired()) {
        for (const QString &domain : std::as_const(m_clientManagedSitesResolveQueue)) {
            m_clientManagedSitesConvergence.recordFailure(domain);
        }
        m_clientManagedSitesResolveQueue.clear();
        finishClientManagedSitesResolve();
        return;
    }

    const QString serverId = m_clientManagedSitesResolveServerId;
    const QString domain = m_clientManagedSitesResolveQueue.takeFirst();
    const int resolveGeneration = m_clientManagedSitesResolveGeneration;
    m_clientManagedSitesCurrentDomain = domain;
    m_clientManagedSitesLookupId = QHostInfo::lookupHost(
            domain, this, [this, serverId, domain, resolveGeneration](const QHostInfo &hostInfo) {
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
        if (domain != m_clientManagedSitesCurrentDomain) {
            return;
        }

        m_clientManagedSitesLookupTimeoutTimer.stop();
        m_clientManagedSitesLookupId = -1;
        m_clientManagedSitesCurrentDomain.clear();

        if (hostInfo.error() != QHostInfo::NoError) {
            qDebug() << "ConnectionController: client-side managed site resolve failed"
                     << "errorCode" << static_cast<int>(hostInfo.error());
            m_clientManagedSitesConvergence.recordFailure(domain);
            resolveNextClientManagedSite();
            return;
        }

        const QStringList resolvedIps = hostInfoIpv4Addresses(hostInfo);
        if (resolvedIps.isEmpty()) {
            qDebug() << "ConnectionController: client-side managed site resolve produced no IPv4 addresses";
            m_clientManagedSitesConvergence.recordFailure(domain);
            resolveNextClientManagedSite();
            return;
        }

        const QString mergedIps = mergedStoredIps({ resolvedIps.join(QStringLiteral(", ")) });
        if (!mergedIps.isEmpty()) {
            QJsonObject candidateCache = m_clientManagedSitesConvergence.cache();
            candidateCache.insert(domain, mergedIps);
            bool candidateValid = false;
            candidateCache = managedRoutePolicy::canonicalSourceSites(candidateCache, &candidateValid);
            if (candidateValid
                && m_clientManagedSitesConvergence.recordSuccess(domain, candidateCache.value(domain).toString())) {
                // The state keeps earlier successful domains across retry waves.
            } else {
                qWarning() << "ConnectionController: managed DNS cache reached its safety boundary";
                m_clientManagedSitesConvergence.recordFailure(domain);
            }
        } else {
            m_clientManagedSitesConvergence.recordFailure(domain);
        }
        qDebug() << "ConnectionController: client-side managed site resolved"
                 << resolvedIps.size() << "IPv4 addresses";
        resolveNextClientManagedSite();
    });
    const qint64 remainingMs = m_clientManagedSitesResolveDeadline.remainingTime();
    const int lookupTimeoutMs = remainingMs < 0
            ? serverRoutingRulesClientResolveLookupTimeoutMs
            : qMin(serverRoutingRulesClientResolveLookupTimeoutMs,
                   static_cast<int>(qMin<qint64>(remainingMs, (std::numeric_limits<int>::max)())));
    if (lookupTimeoutMs <= 0) {
        onClientManagedSiteResolveTimeout();
        return;
    }
    m_clientManagedSitesLookupTimeoutTimer.start(lookupTimeoutMs);
}

void ConnectionController::onClientManagedSiteResolveTimeout()
{
    if (!m_isClientManagedSitesResolveInProgress || m_clientManagedSitesCurrentDomain.isEmpty()) {
        return;
    }

    const QString domain = m_clientManagedSitesCurrentDomain;
    const int lookupId = m_clientManagedSitesLookupId;
    m_clientManagedSitesLookupId = -1;
    m_clientManagedSitesCurrentDomain.clear();
    if (lookupId >= 0) {
        QHostInfo::abortHostLookup(lookupId);
    }
    qDebug() << "ConnectionController: client-side managed site resolve timed out";
    m_clientManagedSitesConvergence.recordFailure(domain);
    resolveNextClientManagedSite();
}

void ConnectionController::finishClientManagedSitesResolve()
{
    const QString serverId = m_clientManagedSitesResolveServerId;
    const int serverIndex = m_serversRepository->indexOfServerId(serverId);
    m_isClientManagedSitesResolveInProgress = false;
    m_clientManagedSitesResolveQueue.clear();
    m_clientManagedSitesLookupTimeoutTimer.stop();
    m_clientManagedSitesLookupId = -1;
    m_clientManagedSitesCurrentDomain.clear();

    if (!isConnected() || serverIndex < 0 || serverIndex >= m_serversRepository->serversCount()) {
        return;
    }
    if (!isCurrentConnectionServerId(serverId)) {
        cancelClientManagedSitesResolve();
        return;
    }

    QJsonObject serverConfig = m_serversRepository->serverJson(serverIndex);
    const QJsonObject sourceSites = serverRoutingRulesSourceSites(serverConfig);
    const QString sourceDigest = managedRoutePolicy::derivedRevision(sourceSites);
    if (!m_clientManagedSitesConvergence.matches(serverId, sourceDigest)) {
        scheduleClientManagedSitesResolve(serverIndex);
        return;
    }

    m_clientManagedSitesConvergence.finishWave();
    if (!m_clientManagedSitesConvergence.complete()
        && !m_clientManagedSitesResolveDeadline.hasExpired()
        && m_clientManagedSitesConvergence.shouldRetry(serverRoutingRulesClientResolveMaxRetryWaves)) {
        qInfo() << "ConnectionController: managed DNS wave retained successful answers;"
                   " only unresolved domains will be retried"
                << "pending domains" << m_clientManagedSitesConvergence.pending().size();
        scheduleClientManagedSitesResolveRetry(serverIndex);
        return;
    }

    if (!m_clientManagedSitesConvergence.tryFinalize()) {
        return;
    }

    QJsonObject stagedCache = m_clientManagedSitesConvergence.cache();
    // An empty value is an explicit completed-attempt marker. It suppresses an
    // immediate post-reconnect rerun while contributing no route; any LKG value
    // already present for a failed domain remains untouched.
    for (const QString &domain : m_clientManagedSitesConvergence.pending()) {
        if (!stagedCache.contains(domain)) {
            stagedCache.insert(domain, QString());
        }
    }
    bool resolvedCacheValid = false;
    const QJsonObject resolvedCacheCandidate = managedRoutePolicy::canonicalSourceSites(
            sitesBoundToSource(stagedCache, sourceSites), &resolvedCacheValid);
    const QJsonObject resolvedCache = resolvedCacheValid ? resolvedCacheCandidate : QJsonObject();
    if (!resolvedCacheValid) {
        qWarning() << "ConnectionController: refusing to persist an unsafe or oversized managed DNS cache";
        cancelClientManagedSitesResolve();
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

    const QDateTime now = QDateTime::currentDateTimeUtc();
    const int unresolvedCount = m_clientManagedSitesConvergence.pending().size();
    const bool completedFullSweep = m_clientManagedSitesResolveIsFullSweep;
    if (unresolvedCount == 0) {
        const QString resolvedAt = now.toString(Qt::ISODate);
        if (serverConfig.value(configKey::managedSplitTunnelClientResolvedAt).toString() != resolvedAt) {
            serverConfig.insert(configKey::managedSplitTunnelClientResolvedAt, resolvedAt);
            changed = true;
        }
        if (serverConfig.contains(configKey::managedSplitTunnelClientResolveRetryAfter)) {
            serverConfig.remove(configKey::managedSplitTunnelClientResolveRetryAfter);
            changed = true;
        }
        if (serverConfig.contains(configKey::managedSplitTunnelClientResolvePendingSites)) {
            serverConfig.remove(configKey::managedSplitTunnelClientResolvePendingSites);
            changed = true;
        }
        if (serverConfig.contains(configKey::managedSplitTunnelClientResolvePendingSourceDigest)) {
            serverConfig.remove(configKey::managedSplitTunnelClientResolvePendingSourceDigest);
            changed = true;
        }
        if (completedFullSweep
            && serverConfig.contains(configKey::managedSplitTunnelClientResolveLastFullSweepAt)) {
            serverConfig.remove(configKey::managedSplitTunnelClientResolveLastFullSweepAt);
            changed = true;
        }
    } else {
        if (serverConfig.contains(configKey::managedSplitTunnelClientResolvedAt)) {
            serverConfig.remove(configKey::managedSplitTunnelClientResolvedAt);
            changed = true;
        }
        const QString retryAfter = now.addSecs(serverRoutingRulesClientResolveRetryMaxMs / 1000)
                                           .toString(Qt::ISODate);
        if (serverConfig.value(configKey::managedSplitTunnelClientResolveRetryAfter).toString() != retryAfter) {
            serverConfig.insert(configKey::managedSplitTunnelClientResolveRetryAfter, retryAfter);
            changed = true;
        }
        QJsonArray pendingSites;
        for (const QString &domain : m_clientManagedSitesConvergence.pending()) {
            pendingSites.append(domain);
        }
        if (serverConfig.value(configKey::managedSplitTunnelClientResolvePendingSites).toArray()
            != pendingSites) {
            serverConfig.insert(configKey::managedSplitTunnelClientResolvePendingSites, pendingSites);
            changed = true;
        }
        if (serverConfig.value(
                    configKey::managedSplitTunnelClientResolvePendingSourceDigest).toString()
            != sourceDigest) {
            serverConfig.insert(
                    configKey::managedSplitTunnelClientResolvePendingSourceDigest,
                    sourceDigest);
            changed = true;
        }
        if (completedFullSweep) {
            const QString lastFullSweepAt = now.toString(Qt::ISODate);
            if (serverConfig.value(
                        configKey::managedSplitTunnelClientResolveLastFullSweepAt).toString()
                != lastFullSweepAt) {
                serverConfig.insert(
                        configKey::managedSplitTunnelClientResolveLastFullSweepAt,
                        lastFullSweepAt);
                changed = true;
            }
        }
    }
    m_clientManagedSitesResolveRetryCount = 0;
    m_clientManagedSitesConvergence.clear();
    m_clientManagedSitesResolveServerId.clear();
    m_clientManagedSitesResolveSnapshotCaptured = false;
    m_clientManagedSitesResolveIsFullSweep = false;
    qInfo() << "ConnectionController: managed DNS convergence finalized"
            << "unresolved domains" << unresolvedCount;

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
    const QString newPolicyRevision = effectiveManagedRoutePolicyRevision(serverIndex);
    const bool localSettingsChanged =
            currentLocalSplitEnabled != m_clientManagedSitesResolveOldLocalSplitEnabled
            || currentLocalRouteMode != m_clientManagedSitesResolveOldLocalRouteMode;
    const bool managedRuntimeChanged =
            !m_clientManagedSitesResolveOldStateConfirmed
            || newManagedSplitTunnelIps != m_clientManagedSitesResolveOldManagedSplitTunnelIps
            || newPolicyRevision != m_clientManagedSitesResolveOldPolicyRevision
            || newContentHash != m_clientManagedSitesResolveOldContentHash;
    if (m_clientManagedSitesResolveOldStateConfirmed
        && localSettingsChanged && !managedRuntimeChanged) {
        qInfo() << "ConnectionController: local routing changed during managed DNS resolve;"
                   " no managed runtime delta to reconcile";
        return;
    }
    if (!m_clientManagedSitesResolveOldStateConfirmed
        || newRouteMode != m_clientManagedSitesResolveOldRouteMode) {
        requestManagedRouteReconciliation(
                serverId,
                QStringLiteral("client-side managed site resolve changed route mode"));
        return;
    } else if (newManagedSplitTunnelIps != m_clientManagedSitesResolveOldManagedSplitTunnelIps) {
        requestManagedRouteReconciliation(
                serverId,
                QStringLiteral("client-resolved managed route delta"));
    }
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
