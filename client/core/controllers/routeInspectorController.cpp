#include "routeInspectorController.h"

#include <QAbstractSocket>
#include <QHostAddress>
#include <QHostInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>
#include <QSet>
#include <QTimer>
#include <QUrl>
#include <QVariantList>

#include <optional>

#include "core/repositories/secureAppSettingsRepository.h"
#include "core/repositories/secureServersRepository.h"
#include "core/utils/constants/configKeys.h"
#include "core/utils/constants/protocolConstants.h"
#include "core/utils/boundedQueuedSnapshot.h"
#include "core/utils/routeRuleMatcher.h"
#include "core/utils/routeModes.h"
#include "vpnConnection.h"

using namespace amnezia;

namespace
{
constexpr int maxPolicyRevisionLength = 128;
constexpr int dnsLookupTimeoutMs = 8000;
constexpr int vpnSnapshotTimeoutMs = 750;

struct ProtectedRouteContext
{
    QSet<QHostAddress> vpnAddresses;
    QSet<QHostAddress> directAddresses;
};

QString bounded(const QString &value, int maximumLength)
{
    return value.left(maximumLength);
}

QString routeModeName(RouteMode mode)
{
    switch (mode) {
    case RouteMode::VpnAllSites:
        return QStringLiteral("VpnAllSites");
    case RouteMode::VpnOnlyForwardSites:
        return QStringLiteral("VpnOnlyForwardSites");
    case RouteMode::VpnAllExceptSites:
        return QStringLiteral("VpnAllExceptSites");
    }
    return QStringLiteral("Unknown");
}

QString privacySafePolicySource(const QString &source)
{
    const QString trimmed = source.trimmed();
    if (trimmed.isEmpty()) {
        return {};
    }

    const QUrl url(trimmed, QUrl::StrictMode);
    if (url.isValid() && !url.scheme().isEmpty() && !url.host().isEmpty()) {
        const auto normalized = routeRuleMatcher::normalizeTarget(
                url.host(), routeRuleMatcher::InputPolicy::BareHostOrAddress);
        if (!normalized.error.isEmpty()
            || (!normalized.literalAddress.isNull()
                && normalized.literalAddress.protocol() != QAbstractSocket::IPv4Protocol)) {
            return {};
        }
        const QString host = normalized.host;
        QString origin = url.scheme().toLower() + QStringLiteral("://") + host;
        if (url.port() > 0) {
            origin += QLatin1Char(':') + QString::number(url.port());
        }
        return bounded(origin, 128);
    }

    static const QRegularExpression safeLabel(QStringLiteral("^[A-Za-z0-9._:-]{1,64}$"));
    return safeLabel.match(trimmed).hasMatch() ? trimmed : QString();
}

QVariantMap policyMetadata(const SecureServersRepository *repository, int serverIndex)
{
    QVariantMap policy;
    if (!repository || serverIndex < 0) {
        return policy;
    }

    const auto metadata = repository->managedRoutePolicyMetadata(serverIndex);
    if (!metadata.has_value()) {
        return policy;
    }

    policy.insert(QStringLiteral("schemaVersion"), metadata->schemaVersion);
    policy.insert(QStringLiteral("revision"), bounded(metadata->revision, maxPolicyRevisionLength));
    if (metadata->issuedAt.isValid()) {
        policy.insert(QStringLiteral("issuedAt"), metadata->issuedAt.toUTC().toString(Qt::ISODateWithMs));
    }
    if (metadata->expiresAt.isValid()) {
        policy.insert(QStringLiteral("expiresAt"), metadata->expiresAt.toUTC().toString(Qt::ISODateWithMs));
    }
    if (metadata->acceptedAt.isValid()) {
        policy.insert(QStringLiteral("acceptedAt"), metadata->acceptedAt.toUTC().toString(Qt::ISODateWithMs));
    }
    policy.insert(QStringLiteral("expired"), metadata->isExpired());
    policy.insert(QStringLiteral("trustState"),
                  metadata->trustState.isEmpty() ? QStringLiteral("unsigned") : metadata->trustState);
    policy.insert(QStringLiteral("contentMatchesDeclaration"), metadata->contentMatchesDeclaration);
    policy.insert(QStringLiteral("authenticated"),
                  metadata->trustState == QStringLiteral("verified"));
    const QString source = privacySafePolicySource(metadata->source);
    if (!source.isEmpty()) {
        policy.insert(QStringLiteral("source"), source);
    }
    return policy;
}

QString dnsError(const QHostInfo &hostInfo)
{
    if (hostInfo.error() == QHostInfo::NoError) {
        return QStringLiteral("dns_no_addresses");
    }
    if (hostInfo.error() == QHostInfo::HostNotFound) {
        return QStringLiteral("dns_host_not_found");
    }
    return QStringLiteral("dns_lookup_failed");
}

void addLiteralAddress(QSet<QHostAddress> &addresses, const QString &value)
{
    QHostAddress address(value.trimmed());
    if (!address.isNull() && address.scopeId().isEmpty()) {
        addresses.insert(address);
    }
}

ProtectedRouteContext protectedRouteContext(const SecureServersRepository *serversRepository,
                                            const SecureAppSettingsRepository *appSettingsRepository,
                                            const RouteInspectorController::VpnConnectionSnapshot &vpnSnapshot,
                                            int serverIndex,
                                            RouteMode routeMode)
{
    ProtectedRouteContext context;
    if (vpnSnapshot.connected) {
        // The tunnel endpoint is always kept outside the tunnel so the tunnel
        // itself cannot recursively route into its own interface.
        addLiteralAddress(context.directAddresses, vpnSnapshot.remoteAddress);
        addLiteralAddress(context.vpnAddresses, vpnSnapshot.serverRoutingRulesSyncHost);
        addLiteralAddress(context.vpnAddresses, vpnSnapshot.vpnGateway);
    }

    addLiteralAddress(context.vpnAddresses,
                      QString::fromLatin1(protocols::serverRoutingRules::syncHost));
    addLiteralAddress(context.vpnAddresses,
                      QString::fromLatin1(protocols::selfHostedUpdates::syncHost));
    if (serversRepository && serverIndex >= 0
        && !serversRepository->serverJson(serverIndex).value(configKey::clientLogs).toObject().isEmpty()) {
        addLiteralAddress(context.vpnAddresses,
                          QString::fromLatin1(protocols::clientLogs::syncHost));
    }

    if (appSettingsRepository) {
        QStringList dnsAddresses { appSettingsRepository->primaryDns(),
                                   appSettingsRepository->secondaryDns() };
        if (appSettingsRepository->useAmneziaDns()) {
            dnsAddresses.append(QString::fromLatin1(protocols::dns::amneziaDnsIp));
        }
        for (const QString &dnsAddress : dnsAddresses) {
#if defined(Q_OS_MACOS)
            const bool nonWireGuard = vpnSnapshot.connected
                    && vpnSnapshot.container != DockerContainer::WireGuard
                    && vpnSnapshot.container != DockerContainer::Awg
                    && vpnSnapshot.container != DockerContainer::Awg2;
            if (routeMode == RouteMode::VpnAllExceptSites && nonWireGuard) {
                addLiteralAddress(context.directAddresses, dnsAddress);
                continue;
            }
#else
            Q_UNUSED(routeMode)
#endif
            addLiteralAddress(context.vpnAddresses, dnsAddress);
        }
    }

    // A more-specific direct exception (macOS DNS or the VPN endpoint) wins
    // over the generic protected-host VPN list.
    for (const QHostAddress &address : context.directAddresses) {
        context.vpnAddresses.remove(address);
    }
    return context;
}

QString platformName()
{
#if defined(Q_OS_WIN)
    return QStringLiteral("windows");
#elif defined(Q_OS_ANDROID)
    return QStringLiteral("android");
#elif defined(Q_OS_IOS)
    return QStringLiteral("ios");
#elif defined(Q_OS_MACOS) || defined(Q_OS_MAC)
    return QStringLiteral("macos");
#elif defined(Q_OS_LINUX)
    return QStringLiteral("linux");
#else
    return QStringLiteral("unknown");
#endif
}
} // namespace

RouteInspectorController::RouteInspectorController(SecureServersRepository *serversRepository,
                                                   SecureAppSettingsRepository *appSettingsRepository,
                                                   VpnConnection *vpnConnection,
                                                   QObject *parent)
    : QObject(parent),
      m_serversRepository(serversRepository),
      m_appSettingsRepository(appSettingsRepository),
      m_vpnConnection(vpnConnection)
{
}

void RouteInspectorController::setVpnConnection(VpnConnection *vpnConnection)
{
    m_vpnConnection = vpnConnection;
}

QVariantMap RouteInspectorController::inspectHost(const QString &host)
{
    cancelPendingLookup();
    ++m_generation;
    if (m_generation == 0) {
        ++m_generation;
    }
    const quint64 generation = m_generation;
    const routeRuleMatcher::NormalizedTarget target =
            routeRuleMatcher::normalizeTarget(host);

    if (!target.error.isEmpty()) {
        QVariantMap result = resultFor({}, {}, {}, false,
                                       QStringLiteral("error"), target.error,
                                       generation, {}, true);
        QTimer::singleShot(0, this, [this, generation, result]() { publishResult(generation, result); });
        return result;
    }

    if (!m_serversRepository || !m_appSettingsRepository) {
        QVariantMap result = resultFor(target.host,
                                       {},
                                       {},
                                       false,
                                       QStringLiteral("error"),
                                       QStringLiteral("route_configuration_unavailable"),
                                       generation,
                                       {},
                                       true);
        QTimer::singleShot(0, this, [this, generation, result]() { publishResult(generation, result); });
        return result;
    }

    const QVariantMap resolvingResult = pendingResult(target.host, generation);
    if (!target.literalAddress.isNull()) {
        QStringList ipv4Addresses;
        QStringList ipv6Addresses;
        if (target.literalAddress.protocol() == QAbstractSocket::IPv4Protocol) {
            ipv4Addresses.append(target.host);
        } else {
            ipv6Addresses.append(target.host);
        }
        requestResultWithSnapshot(target.host, ipv4Addresses, ipv6Addresses, false,
                                  QStringLiteral("ready"), {}, generation);
        return resolvingResult;
    }

    m_activeLookupGeneration = generation;
    const int lookupId = QHostInfo::lookupHost(
            target.host, this, [this, generation, normalizedHost = target.host](const QHostInfo &hostInfo) {
        if (generation != m_generation || m_activeLookupGeneration != generation) {
            return;
        }
        m_activeLookupId = -1;
        m_activeLookupGeneration = 0;

        const routeInspectorBounds::BoundedDnsAddresses boundedAddresses =
                routeInspectorBounds::boundedDnsAddresses(hostInfo.addresses());
        const QStringList ipv4Addresses = boundedAddresses.ipv4;
        const QStringList ipv6Addresses = boundedAddresses.ipv6;

        const bool hasAddresses = !ipv4Addresses.isEmpty() || !ipv6Addresses.isEmpty();
        const QString error = hasAddresses ? QString() : dnsError(hostInfo);
        requestResultWithSnapshot(normalizedHost, ipv4Addresses, ipv6Addresses,
                                  boundedAddresses.processingTruncated,
                                  error.isEmpty() ? QStringLiteral("ready") : QStringLiteral("error"),
                                  error, generation);
    });
    if (m_activeLookupGeneration == generation) {
        m_activeLookupId = lookupId;
    } else {
        QHostInfo::abortHostLookup(lookupId);
    }
    QTimer::singleShot(dnsLookupTimeoutMs, this,
                       [this, generation, lookupId, normalizedHost = target.host]() {
        if (generation != m_generation || m_activeLookupGeneration != generation
            || m_activeLookupId != lookupId) {
            return;
        }

        QHostInfo::abortHostLookup(lookupId);
        m_activeLookupId = -1;
        m_activeLookupGeneration = 0;
        const QVariantMap result = resultFor(normalizedHost,
                                             {},
                                             {},
                                             false,
                                             QStringLiteral("error"),
                                             QStringLiteral("dns_lookup_timeout"),
                                             generation,
                                             {},
                                             true);
        publishResult(generation, result);
    });
    return resolvingResult;
}

QString RouteInspectorController::routesExplainJson(const QString &host)
{
    return resultToJson(inspectHost(host));
}

int RouteInspectorController::activeServerIndex(const QString &connectedServerId) const
{
    if (!m_serversRepository) {
        return -1;
    }
    if (!connectedServerId.isEmpty()) {
        const int connectedServerIndex =
                m_serversRepository->indexOfServerId(connectedServerId);
        if (connectedServerIndex >= 0
            && connectedServerIndex < m_serversRepository->serversCount()) {
            return connectedServerIndex;
        }
    }
    return m_serversRepository->defaultServerIndex();
}

void RouteInspectorController::cancelPendingLookup()
{
    if (m_activeLookupId >= 0) {
        QHostInfo::abortHostLookup(m_activeLookupId);
    }
    m_activeLookupId = -1;
    m_activeLookupGeneration = 0;
}

QVariantMap RouteInspectorController::pendingResult(const QString &normalizedHost,
                                                    quint64 generation) const
{
    return {
        { QStringLiteral("requestId"), QString::number(generation) },
        { QStringLiteral("state"), QStringLiteral("resolving") },
        { QStringLiteral("normalizedHost"),
          bounded(normalizedHost, routeRuleMatcher::maximumHostLength) },
        { QStringLiteral("resolvedIpv4"), QStringList() },
        { QStringLiteral("resolvedIpv6"), QStringList() },
        { QStringLiteral("error"), QString() },
        { QStringLiteral("platform"), platformName() },
        { QStringLiteral("runtimeApplied"), false },
        { QStringLiteral("inspectionBasis"), QStringLiteral("runtimeSnapshotPending") },
        { QStringLiteral("osRouteVerified"), false },
        { QStringLiteral("decision"), QStringLiteral("unknown") },
        { QStringLiteral("route"), QStringLiteral("unknown") },
        { QStringLiteral("aggregateRoute"), QStringLiteral("unknown") },
        { QStringLiteral("source"), QStringLiteral("runtimeUnknown") },
        { QStringLiteral("matchedRule"), QString() },
        { QStringLiteral("matchType"), QString() },
        { QStringLiteral("addressDecisions"), QVariantList() },
    };
}

void RouteInspectorController::requestResultWithSnapshot(
        const QString &normalizedHost, const QStringList &ipv4Addresses,
        const QStringList &ipv6Addresses, bool dnsProcessingTruncated,
        const QString &state, const QString &error,
        quint64 generation)
{
    requestBoundedQueuedSnapshot(
            m_vpnConnection, this, vpnSnapshotTimeoutMs,
            [](VpnConnection *vpnConnection) {
                VpnConnectionSnapshot snapshot;
                snapshot.connected =
                        vpnConnection->connectionState() == Vpn::ConnectionState::Connected;
                snapshot.appliedSiteRouteMode = vpnConnection->appliedSiteRouteMode();
                const VpnConnection::ManagedRouteRuntimeSnapshot managedSnapshot =
                        vpnConnection->managedRouteRuntimeSnapshot();
                snapshot.managedRouteSnapshotConfirmed = managedSnapshot.confirmed;
                snapshot.managedRouteTransitionPending = managedSnapshot.transitionPending;
                snapshot.managedRouteSnapshotMode = managedSnapshot.mode;
                snapshot.installedManagedRoutes = managedSnapshot.installedRoutes;
                snapshot.managedRouteSnapshotRevision = managedSnapshot.revision;
                snapshot.managedRoutePolicyRevision = managedSnapshot.policyRevision;
                snapshot.managedRoutePolicyContentHash =
                        managedSnapshot.policyContentHash;
                snapshot.connectionEpoch = managedSnapshot.connectionEpoch;
                if (!snapshot.connected) {
                    return snapshot;
                }

                snapshot.serverId = vpnConnection->serverId();
                snapshot.remoteAddress = vpnConnection->remoteAddress();
                snapshot.serverRoutingRulesSyncHost =
                        vpnConnection->serverRoutingRulesSyncHost();
                snapshot.container = vpnConnection->container();
                const QSharedPointer<VpnProtocol> protocol = vpnConnection->vpnProtocol();
                if (protocol) {
                    snapshot.vpnGateway = protocol->vpnGateway();
                }
                return snapshot;
            },
            [this, generation, normalizedHost, ipv4Addresses, ipv6Addresses,
             dnsProcessingTruncated, state, error](
                    BoundedQueuedSnapshotStatus status,
                    std::optional<VpnConnectionSnapshot> snapshot) {
                if (generation != m_generation) {
                    return;
                }

                const bool snapshotAvailable =
                        status == BoundedQueuedSnapshotStatus::Ready && snapshot.has_value();
                QString finalState = state;
                QString finalError = error;
                if (!snapshotAvailable && finalError.isEmpty()) {
                    finalState = QStringLiteral("error");
                    finalError = status == BoundedQueuedSnapshotStatus::Timeout
                            ? QStringLiteral("vpn_snapshot_timeout")
                            : QStringLiteral("vpn_snapshot_unavailable");
                }
                const QVariantMap result = resultFor(
                        normalizedHost, ipv4Addresses, ipv6Addresses,
                        dnsProcessingTruncated,
                        finalState, finalError, generation,
                        snapshot.value_or(VpnConnectionSnapshot {}), snapshotAvailable);
                publishResult(generation, result);
            });
}

QVariantMap RouteInspectorController::resultFor(const QString &normalizedHost,
                                                const QStringList &ipv4Addresses,
                                                const QStringList &ipv6Addresses,
                                                 bool dnsProcessingTruncated,
                                                 const QString &state,
                                                 const QString &error,
                                                 quint64 generation,
                                                 const VpnConnectionSnapshot &vpnSnapshot,
                                                 bool snapshotAvailable) const
{
    QVariantMap result;
    result.insert(QStringLiteral("requestId"), QString::number(generation));
    result.insert(QStringLiteral("state"), state);
    result.insert(QStringLiteral("normalizedHost"),
                  bounded(normalizedHost, routeRuleMatcher::maximumHostLength));
    const QStringList boundedIpv4 = ipv4Addresses.mid(
            0, routeInspectorBounds::maximumDisplayedAddressesPerFamily);
    const QStringList boundedIpv6 = ipv6Addresses.mid(
            0, routeInspectorBounds::maximumDisplayedAddressesPerFamily);
    const bool displayAddressesTruncated =
            boundedIpv4.size() != ipv4Addresses.size()
            || boundedIpv6.size() != ipv6Addresses.size();
    result.insert(QStringLiteral("resolvedIpv4"), boundedIpv4);
    result.insert(QStringLiteral("resolvedIpv6"), boundedIpv6);
    result.insert(QStringLiteral("dnsProcessingTruncated"), dnsProcessingTruncated);
    result.insert(QStringLiteral("resolvedAddressesTruncated"),
                  displayAddressesTruncated || dnsProcessingTruncated);
    result.insert(QStringLiteral("error"), error);
    result.insert(QStringLiteral("platform"), platformName());
    result.insert(QStringLiteral("splitRoutingAddressFamilies"), QStringList { QStringLiteral("ipv4") });
    const bool runtimeConnected = snapshotAvailable && vpnSnapshot.connected;
    const bool installedSnapshotReceiptConfirmed = runtimeConnected
            && vpnSnapshot.managedRouteSnapshotConfirmed
            && !vpnSnapshot.managedRouteTransitionPending;
    result.insert(QStringLiteral("runtimeApplied"), false);
    result.insert(QStringLiteral("inspectionBasis"),
                  !snapshotAvailable
                          ? QStringLiteral("runtimeSnapshotUnavailable")
                          : !runtimeConnected
                                  ? QStringLiteral("policyPreview")
                                  : installedSnapshotReceiptConfirmed
                                          ? QStringLiteral("runtimeSnapshotIdentityPending")
                                          : vpnSnapshot.managedRouteTransitionPending
                                                  ? QStringLiteral("runtimeRouteTransitionPending")
                                                  : QStringLiteral("runtimeRouteSnapshotUnconfirmed"));
    result.insert(QStringLiteral("osRouteVerified"), false);
    result.insert(QStringLiteral("managedRouteReceiptConfirmed"),
                  installedSnapshotReceiptConfirmed);
    result.insert(QStringLiteral("managedRouteSnapshotConfirmed"),
                  false);
    result.insert(QStringLiteral("managedRouteTransitionPending"),
                  runtimeConnected && vpnSnapshot.managedRouteTransitionPending);
    result.insert(QStringLiteral("managedRouteSnapshotRevision"),
                  QString::number(vpnSnapshot.managedRouteSnapshotRevision));
    result.insert(QStringLiteral("connectionEpoch"),
                  QString::number(vpnSnapshot.connectionEpoch));

    if (!m_serversRepository || !m_appSettingsRepository) {
        result.insert(QStringLiteral("routeMode"), static_cast<int>(RouteMode::VpnAllSites));
        result.insert(QStringLiteral("routeModeName"), routeModeName(RouteMode::VpnAllSites));
        result.insert(QStringLiteral("decision"), QStringLiteral("unknown"));
        result.insert(QStringLiteral("route"), QStringLiteral("unknown"));
        result.insert(QStringLiteral("aggregateRoute"), QStringLiteral("unknown"));
        result.insert(QStringLiteral("source"), QStringLiteral("default"));
        result.insert(QStringLiteral("matchedRule"), QString());
        result.insert(QStringLiteral("matchType"), QString());
        result.insert(QStringLiteral("addressDecisions"), QVariantList {});
        return result;
    }

    // A disconnected VpnConnection retains its most recent server index. That
    // stale worker state must not override the user's current default-server
    // policy preview.
    const int serverIndex = activeServerIndex(
            vpnSnapshot.connected ? vpnSnapshot.serverId : QString());
    const bool localSplitEnabled = m_appSettingsRepository->isSitesSplitTunnelingEnabled();
    const RouteMode localRouteMode = m_appSettingsRepository->routeMode();
    const RouteMode effectiveRouteMode = m_serversRepository->effectiveSiteRouteMode(
            serverIndex, localSplitEnabled, localRouteMode);
    const RouteMode decisionRouteMode = installedSnapshotReceiptConfirmed
            ? vpnSnapshot.managedRouteSnapshotMode : effectiveRouteMode;
    const bool runtimeRouteModeDiverged = installedSnapshotReceiptConfirmed
            && (vpnSnapshot.managedRouteSnapshotMode != effectiveRouteMode
                || vpnSnapshot.appliedSiteRouteMode
                        != vpnSnapshot.managedRouteSnapshotMode);

    result.insert(QStringLiteral("routeMode"), static_cast<int>(effectiveRouteMode));
    result.insert(QStringLiteral("routeModeName"), routeModeName(effectiveRouteMode));
    if (installedSnapshotReceiptConfirmed) {
        result.insert(QStringLiteral("appliedRouteMode"),
                      static_cast<int>(decisionRouteMode));
        result.insert(QStringLiteral("appliedRouteModeName"),
                      routeModeName(decisionRouteMode));
    }
    result.insert(QStringLiteral("runtimeRouteModeDiverged"), runtimeRouteModeDiverged);
    if (runtimeRouteModeDiverged) {
        result.insert(QStringLiteral("inspectionBasis"),
                      QStringLiteral("runtimePolicyDiverged"));
    }

    const QJsonObject serverConfig = serverIndex >= 0
            ? m_serversRepository->serverJson(serverIndex) : QJsonObject();
    QVariantMap policy = policyMetadata(m_serversRepository, serverIndex);
    const QJsonValue lifecycleStateValue = serverConfig.value(managedRoutePolicy::stateKey());
    const bool lifecycleStatePresent = !lifecycleStateValue.isUndefined();
    const bool legacyPolicyPresent = policy.isEmpty()
            && !lifecycleStatePresent
            && managedRoutePolicy::containsSourceSites(serverConfig);
    if (legacyPolicyPresent) {
        policy.insert(QStringLiteral("policyType"), QStringLiteral("legacy"));
        policy.insert(QStringLiteral("trustState"), QStringLiteral("unsigned"));
        policy.insert(QStringLiteral("authenticated"), false);
        policy.insert(QStringLiteral("contentMatchesDeclaration"), true);
        policy.insert(QStringLiteral("expired"), false);
    }
    if (!policy.isEmpty()) {
        result.insert(QStringLiteral("policy"), policy);
    }

    const QJsonObject lifecycleState = lifecycleStateValue.toObject();
    const bool retainedPolicyPresent = !lifecycleState.value(
            managedRoutePolicy::lastKnownGoodKey()).toObject().isEmpty();
    const bool policyExpired = policy.value(QStringLiteral("expired")).toBool();
    const bool policyEffective = managedRoutePolicy::isEffective(serverConfig);
    const bool lifecycleInvalid = lifecycleStatePresent && policy.isEmpty();
    const QString effectivePolicyRevision =
            managedRoutePolicy::effectiveRevision(serverConfig);
    const QString effectivePolicyContentHash =
            managedRoutePolicy::effectiveContentHash(serverConfig);
    const bool runtimeServerBindingMatches = installedSnapshotReceiptConfirmed
            && vpnSnapshot.connectionEpoch != 0
            && serverIndex >= 0
            && m_serversRepository->serverIdAt(serverIndex) == vpnSnapshot.serverId;
    const bool runtimePolicyIdentityMatches =
            installedSnapshotReceiptConfirmed
            && managedRoutePolicy::isCanonicalPolicyIdentity(
                    vpnSnapshot.managedRoutePolicyRevision,
                    vpnSnapshot.managedRoutePolicyContentHash)
            && vpnSnapshot.managedRoutePolicyRevision
                    == effectivePolicyRevision
            && vpnSnapshot.managedRoutePolicyContentHash
                    == effectivePolicyContentHash;
    const bool installedSnapshotStale = installedSnapshotReceiptConfirmed
            && (!runtimeServerBindingMatches
                || !runtimePolicyIdentityMatches
                || ((lifecycleStatePresent || legacyPolicyPresent)
                    && !policyEffective));
    const bool installedSnapshotAuthoritative =
            installedSnapshotReceiptConfirmed
            && !runtimeRouteModeDiverged && !installedSnapshotStale;
    result.insert(QStringLiteral("runtimeApplied"),
                  installedSnapshotAuthoritative);
    result.insert(QStringLiteral("managedRouteSnapshotConfirmed"),
                  installedSnapshotAuthoritative);
    result.insert(QStringLiteral("runtimeServerBindingMatches"),
                  runtimeServerBindingMatches);
    result.insert(QStringLiteral("runtimePolicyIdentityMatches"),
                  runtimePolicyIdentityMatches);
    result.insert(QStringLiteral("managedRoutePolicyRevision"),
                  vpnSnapshot.managedRoutePolicyRevision);
    result.insert(QStringLiteral("managedRoutePolicyContentHash"),
                  vpnSnapshot.managedRoutePolicyContentHash);
    if (installedSnapshotAuthoritative) {
        result.insert(QStringLiteral("inspectionBasis"),
                      QStringLiteral("authoritativeManagedRouteSnapshot"));
    } else if (installedSnapshotReceiptConfirmed) {
        result.insert(QStringLiteral("inspectionBasis"),
                      QStringLiteral("runtimePolicyDiverged"));
    }

    QStringList warnings;
    if (!snapshotAvailable) {
        warnings.append(error == QStringLiteral("vpn_snapshot_timeout")
                                ? QStringLiteral("vpn_snapshot_timeout")
                                : QStringLiteral("vpn_snapshot_unavailable"));
    } else if (!runtimeConnected) {
        warnings.append(QStringLiteral("vpn_not_connected_policy_preview"));
    }
    if (runtimeRouteModeDiverged) {
        warnings.append(QStringLiteral("runtime_route_mode_diverged"));
    }
    if (runtimeConnected && !installedSnapshotReceiptConfirmed) {
        warnings.append(vpnSnapshot.managedRouteTransitionPending
                                ? QStringLiteral("runtime_route_transition_pending")
                                : QStringLiteral("runtime_route_snapshot_unconfirmed"));
    } else if (installedSnapshotReceiptConfirmed
               && !runtimeServerBindingMatches) {
        warnings.append(QStringLiteral("runtime_snapshot_binding_diverged"));
    }
    if (installedSnapshotReceiptConfirmed
        && !runtimePolicyIdentityMatches) {
        warnings.append(QStringLiteral("runtime_policy_identity_diverged"));
    }
    if (dnsProcessingTruncated) {
        warnings.append(QStringLiteral("dns_addresses_truncated_unexamined"));
    }
    const bool runtimeDecisionUnknown = !snapshotAvailable
            || (runtimeConnected && !installedSnapshotAuthoritative)
            || dnsProcessingTruncated;
    QString policyIneffectiveReason;
    if (lifecycleInvalid) {
        policyIneffectiveReason = QStringLiteral("lifecycle_metadata_invalid");
    } else if (legacyPolicyPresent && !policyEffective) {
        policyIneffectiveReason = QStringLiteral("legacy_content_invalid");
    } else if (retainedPolicyPresent
               && !policy.value(QStringLiteral("contentMatchesDeclaration"), true).toBool()) {
        policyIneffectiveReason = QStringLiteral("content_digest_mismatch");
    } else if (policyExpired) {
        policyIneffectiveReason = QStringLiteral("expired");
    }
    result.insert(QStringLiteral("policyEffective"), policyEffective);
    result.insert(QStringLiteral("installedSnapshotStale"), installedSnapshotStale);
    if (!policyIneffectiveReason.isEmpty()) {
        result.insert(QStringLiteral("policyIneffectiveReason"), policyIneffectiveReason);
    }
    if (!policy.isEmpty()
        && policy.value(QStringLiteral("trustState")).toString() == QStringLiteral("unsigned")) {
        warnings.append(QStringLiteral("managed_policy_unsigned"));
    }
    if (policyExpired) {
        // The repository stops exposing expired routes immediately, while an
        // already-connected OS route set is reconciled only on refresh or
        // reconnect. Without an installed-route snapshot, that divergence
        // must be reported as unknown instead of guessed.
        warnings.append(runtimeConnected
                                ? QStringLiteral("managed_policy_expired_installed_state_unknown")
                                : QStringLiteral("managed_policy_expired_ignored"));
    } else if (lifecycleInvalid) {
        warnings.append(runtimeConnected
                                ? QStringLiteral("managed_policy_invalid_installed_state_unknown")
                                : QStringLiteral("managed_policy_invalid_ignored"));
    } else if (policyIneffectiveReason == QStringLiteral("content_digest_mismatch")) {
        warnings.append(runtimeConnected
                                ? QStringLiteral("managed_policy_content_mismatch_installed_state_unknown")
                                : QStringLiteral("managed_policy_content_mismatch_ignored"));
    } else if (policyIneffectiveReason == QStringLiteral("legacy_content_invalid")) {
        warnings.append(QStringLiteral("legacy_managed_policy_invalid_ignored"));
    }
    if (!ipv6Addresses.isEmpty() && decisionRouteMode != RouteMode::VpnAllSites) {
        warnings.append(QStringLiteral("ipv6_split_rules_not_installed"));
    }

    QVariantList addressDecisions;
    const ProtectedRouteContext protectedRoutes = protectedRouteContext(
            m_serversRepository, m_appSettingsRepository, vpnSnapshot,
            serverIndex, decisionRouteMode);
    // Connected runtime decisions must not substitute mutable repository
    // settings for an installation receipt. Local desktop routes are added by
    // the legacy best-effort IPC and have no exact receipt, so they remain a
    // disconnected-policy-preview input only.
    const QVariantMap localRules = !runtimeConnected
                    && decisionRouteMode != RouteMode::VpnAllSites
            ? m_appSettingsRepository->vpnSites(decisionRouteMode)
            : QVariantMap();
    QVariantMap managedRules;
    if (decisionRouteMode != RouteMode::VpnAllSites) {
        if (runtimeConnected) {
            // Connected decisions use only the worker-owned, confirmed
            // installed-route receipt. Repository rules are desired state and
            // may already contain the next policy revision.
            if (installedSnapshotReceiptConfirmed) {
                for (const QString &installedRoute : vpnSnapshot.installedManagedRoutes) {
                    managedRules.insert(installedRoute, QVariant());
                }
            }
        } else if (serverIndex >= 0) {
            managedRules = m_serversRepository->managedVpnSitesForRouting(
                    serverIndex, decisionRouteMode);
        }
    }
    bool ruleCoverageComplete = true;
    bool localRulesTruncated = false;
    bool managedRulesTruncated = false;
    bool storedValuesTruncated = false;
    bool localRouteReceiptUnavailable = false;
    const bool runtimeManagedRouteDiverged =
            installedSnapshotReceiptConfirmed
            && (!runtimeServerBindingMatches
                || !runtimePolicyIdentityMatches);

    const auto appendAddressDecision = [&](const QString &addressText, const QString &family) {
        QHostAddress address(addressText);
        if (address.isNull()) {
            return;
        }

        routeRuleMatcher::RuleMatch match;
        routeRuleMatcher::RuleMatch rejected;
        bool addressRuleCoverageComplete = true;
        if (decisionRouteMode != RouteMode::VpnAllSites
            && address.protocol() == QAbstractSocket::IPv4Protocol) {
            const routeRuleMatcher::MatchResult matchResult =
                    routeRuleMatcher::matchRules(
                            localRules, managedRules, normalizedHost, address,
                            routeRuleMatcher::DomainMatchPolicy::RequireResolvedIpv4);
            match = matchResult.accepted;
            rejected = matchResult.rejected;
            addressRuleCoverageComplete = matchResult.coverageComplete;
            ruleCoverageComplete = ruleCoverageComplete
                    && matchResult.coverageComplete;
            localRulesTruncated = localRulesTruncated
                    || matchResult.localRulesTruncated;
            managedRulesTruncated = managedRulesTruncated
                    || matchResult.managedRulesTruncated;
            storedValuesTruncated = storedValuesTruncated
                    || matchResult.storedValuesTruncated;
            if (!addressRuleCoverageComplete) {
                match = {};
                rejected = {};
            }

        }

        const bool unsupportedIpv6Split = address.protocol() == QAbstractSocket::IPv6Protocol
                && decisionRouteMode != RouteMode::VpnAllSites;
        QString route = QStringLiteral("vpn");
        if (decisionRouteMode == RouteMode::VpnOnlyForwardSites) {
            route = match.matched ? QStringLiteral("vpn") : QStringLiteral("direct");
        } else if (decisionRouteMode == RouteMode::VpnAllExceptSites) {
            route = match.matched ? QStringLiteral("direct") : QStringLiteral("vpn");
        }

        QString source = match.matched ? match.source : QStringLiteral("default");
        QString safetyTransform = match.safetyTransform;
        if (protectedRoutes.directAddresses.contains(address)) {
            route = QStringLiteral("direct");
            source = QStringLiteral("tunnelSafety");
            safetyTransform = QStringLiteral("tunnel_endpoint_kept_direct");
        } else if (protectedRoutes.vpnAddresses.contains(address)) {
            route = QStringLiteral("vpn");
            source = QStringLiteral("tunnelSafety");
            safetyTransform = QStringLiteral("protected_host_kept_in_vpn");
        } else if (!match.matched && rejected.matched) {
            safetyTransform = rejected.safetyTransform;
        }

        // This client installs site split routes for IPv4 only. Never promote
        // the mode's IPv4 default into a definitive IPv6 route decision.
        if (unsupportedIpv6Split) {
            route = QStringLiteral("unknown");
            source = QStringLiteral("runtimeUnknown");
            safetyTransform = QStringLiteral("ipv6_split_route_unavailable");
        }

        if (!addressRuleCoverageComplete) {
            route = QStringLiteral("unknown");
            source = QStringLiteral("runtimeUnknown");
            safetyTransform = QStringLiteral("route_rule_coverage_truncated");
        }
        if (runtimeManagedRouteDiverged) {
            route = QStringLiteral("unknown");
            source = QStringLiteral("runtimeUnknown");
            safetyTransform = QStringLiteral("runtime_managed_route_diverged");
        }

        // In a connected split-mode snapshot, a confirmed managed match is a
        // usable client receipt. Absence of such a match is not proof of the
        // mode default because a local route may have been installed through
        // the best-effort owner. Keep that case explicitly unknown.
        if (runtimeConnected && installedSnapshotAuthoritative
            && decisionRouteMode != RouteMode::VpnAllSites
            && !match.matched) {
            localRouteReceiptUnavailable = true;
            route = QStringLiteral("unknown");
            source = QStringLiteral("runtimeUnknown");
            safetyTransform = QStringLiteral("local_route_receipt_unavailable");
        }

        if (runtimeDecisionUnknown) {
            route = QStringLiteral("unknown");
            source = QStringLiteral("runtimeUnknown");
            if (!snapshotAvailable) {
                safetyTransform = QStringLiteral("vpn_runtime_snapshot_unavailable");
            } else if (dnsProcessingTruncated) {
                safetyTransform = QStringLiteral("dns_addresses_truncated_unexamined");
            } else if (!installedSnapshotReceiptConfirmed) {
                safetyTransform = vpnSnapshot.managedRouteTransitionPending
                        ? QStringLiteral("runtime_route_transition_pending")
                        : QStringLiteral("runtime_route_snapshot_unconfirmed");
            } else if (!runtimeServerBindingMatches) {
                safetyTransform = QStringLiteral("runtime_snapshot_binding_diverged");
            } else if (!runtimePolicyIdentityMatches) {
                safetyTransform = QStringLiteral("runtime_policy_identity_diverged");
            } else if (runtimeRouteModeDiverged) {
                safetyTransform = QStringLiteral("runtime_route_mode_diverged");
            } else {
                safetyTransform = policyExpired
                        ? QStringLiteral("expired_policy_installed_state_unknown")
                        : QStringLiteral("invalid_policy_installed_state_unknown");
            }
        }

        QVariantMap addressResult;
        addressResult.insert(QStringLiteral("address"), address.toString().toLower());
        addressResult.insert(QStringLiteral("family"), family);
        addressResult.insert(QStringLiteral("decision"), route);
        addressResult.insert(QStringLiteral("route"), route);
        addressResult.insert(QStringLiteral("source"), source);
        addressResult.insert(QStringLiteral("matchedRule"), match.matched ? match.rule : QString());
        addressResult.insert(QStringLiteral("matchType"), match.matched ? match.matchType : QString());
        if (!safetyTransform.isEmpty()) {
            addressResult.insert(QStringLiteral("safetyTransform"), safetyTransform);
        }
        if (unsupportedIpv6Split) {
            addressResult.insert(QStringLiteral("splitRuleEvaluation"), QStringLiteral("unsupported"));
            addressResult.insert(QStringLiteral("limitation"), QStringLiteral("ipv6_split_rules_not_installed"));
            addressResult.insert(QStringLiteral("reachability"), QStringLiteral("unknown"));
        } else {
            addressResult.insert(QStringLiteral("splitRuleEvaluation"), QStringLiteral("supported"));
        }
        if (match.source == QStringLiteral("managed") && policyExpired) {
            addressResult.insert(QStringLiteral("policyExpired"), true);
        }
        addressDecisions.append(addressResult);
    };

    for (const QString &address : ipv4Addresses) {
        appendAddressDecision(address, QStringLiteral("ipv4"));
    }
    for (const QString &address : ipv6Addresses) {
        appendAddressDecision(address, QStringLiteral("ipv6"));
    }
    result.insert(QStringLiteral("addressDecisions"), addressDecisions);
    result.insert(QStringLiteral("ruleCoverageComplete"), ruleCoverageComplete);
    result.insert(QStringLiteral("localRulesTruncated"), localRulesTruncated);
    result.insert(QStringLiteral("managedRulesTruncated"), managedRulesTruncated);
    result.insert(QStringLiteral("storedValuesTruncated"), storedValuesTruncated);
    result.insert(QStringLiteral("runtimeManagedRouteDiverged"),
                  runtimeManagedRouteDiverged);
    if (!ruleCoverageComplete) {
        warnings.append(QStringLiteral("route_rule_coverage_truncated"));
    }
    if (runtimeManagedRouteDiverged) {
        warnings.append(QStringLiteral("runtime_managed_route_diverged"));
        result.insert(QStringLiteral("inspectionBasis"),
                      QStringLiteral("runtimePolicyDiverged"));
    }
    if (localRouteReceiptUnavailable) {
        warnings.append(QStringLiteral("local_route_receipt_unavailable"));
    }

    QString aggregateRoute = QStringLiteral("unknown");
    QString aggregateSource = QStringLiteral("default");
    QString aggregateRule;
    QString aggregateMatchType;
    if (state == QStringLiteral("ready") && !addressDecisions.isEmpty()) {
        const QVariantMap first = addressDecisions.first().toMap();
        aggregateRoute = first.value(QStringLiteral("route")).toString();
        aggregateSource = first.value(QStringLiteral("source")).toString();
        aggregateRule = first.value(QStringLiteral("matchedRule")).toString();
        aggregateMatchType = first.value(QStringLiteral("matchType")).toString();
        bool hasUnknownRoute = aggregateRoute == QStringLiteral("unknown");
        for (const QVariant &decisionValue : addressDecisions) {
            const QVariantMap addressResult = decisionValue.toMap();
            const QString addressRoute = addressResult.value(QStringLiteral("route")).toString();
            hasUnknownRoute = hasUnknownRoute || addressRoute == QStringLiteral("unknown");
            if (!hasUnknownRoute && addressRoute != aggregateRoute) {
                aggregateRoute = QStringLiteral("mixed");
            }
            if (addressResult.value(QStringLiteral("source")).toString() != aggregateSource
                || addressResult.value(QStringLiteral("matchedRule")).toString() != aggregateRule
                || addressResult.value(QStringLiteral("matchType")).toString() != aggregateMatchType) {
                aggregateSource = QStringLiteral("multiple");
                aggregateRule.clear();
                aggregateMatchType.clear();
            }
        }
        if (hasUnknownRoute) {
            aggregateRoute = QStringLiteral("unknown");
            aggregateSource = QStringLiteral("runtimeUnknown");
            aggregateRule.clear();
            aggregateMatchType.clear();
        }
    }
    if (dnsProcessingTruncated || !ruleCoverageComplete
        || runtimeManagedRouteDiverged) {
        aggregateRoute = QStringLiteral("unknown");
        aggregateSource = QStringLiteral("runtimeUnknown");
        aggregateRule.clear();
        aggregateMatchType.clear();
    }

    result.insert(QStringLiteral("decision"), aggregateRoute);
    result.insert(QStringLiteral("route"), aggregateRoute);
    result.insert(QStringLiteral("aggregateRoute"), aggregateRoute);
    result.insert(QStringLiteral("source"), aggregateSource);
    result.insert(QStringLiteral("matchedRule"), aggregateRule);
    result.insert(QStringLiteral("matchType"), aggregateMatchType);
    if (!warnings.isEmpty()) {
        result.insert(QStringLiteral("warnings"), warnings);
    }
    return result;
}

void RouteInspectorController::publishResult(quint64 generation, const QVariantMap &result)
{
    if (generation != m_generation) {
        return;
    }
    emit inspectionReady(result);
    emit routesExplainJsonReady(resultToJson(result));
}

QString RouteInspectorController::resultToJson(const QVariantMap &result)
{
    return QString::fromUtf8(QJsonDocument(QJsonObject::fromVariantMap(result)).toJson(QJsonDocument::Compact));
}
