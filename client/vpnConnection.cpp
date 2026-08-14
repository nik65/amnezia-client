#include "vpnConnection.h"

#include <limits>

#include <QDebug>
#include <QEventLoop>
#include <QFile>
#include <QHostAddress>
#include <QHostInfo>
#include <QJsonArray>
#include <QJsonObject>
#include <QObject>
#include <QRegularExpression>
#include <QSet>
#include <QSharedPointer>
#include <QString>
#include <QStringList>
#include <QThread>
#include <QTimer>

#include <core/configurators/openVpnConfigurator.h>
#include <core/configurators/wireguardConfigurator.h>

#ifdef AMNEZIA_DESKTOP
    #include "core/utils/ipcClient.h"
    #include <core/protocols/wireGuardProtocol.h>
#endif

#ifdef Q_OS_ANDROID
    #include "platforms/android/android_controller.h"
#endif

#if defined(Q_OS_IOS) || defined(MACOS_NE)
    #include "platforms/ios/ios_controller.h"
#endif

#include "core/utils/networkUtilities.h"
#include "core/utils/managedRoutePolicy.h"
#include "core/utils/constants/configKeys.h"
#include "core/utils/constants/protocolConstants.h"
#include "core/utils/containers/containerUtils.h"
#include "core/utils/serverConfigUtils.h"
#include "vpnConnection.h"

using namespace ProtocolUtils;

namespace
{
constexpr int maxIncrementalManagedRouteDelta = 256;
constexpr int incrementalManagedRouteIpcTimeoutMs = 5000;
constexpr int killSwitchIpcTimeoutMs = 1000;
constexpr int dnsFlushIpcTimeoutMs = 1000;
constexpr int clearSavedRoutesIpcTimeoutMs = 5000;
constexpr int deferredManagedRouteDeadlineMs = 10000;
constexpr qint64 managedRouteReconnectMinimumIntervalMs = 2LL * 60 * 60 * 1000;

enum class SplitTunnelRouteSource {
    Client,
    ServerManaged,
};

bool isRoutableSplitTunnelRoute(const QString &route);

QStringList splitTunnelStoredIps(const QString &value)
{
    QStringList ips;
    const QStringList tokens = value.split(QRegularExpression("[,;\\s]+"), Qt::SkipEmptyParts);
    for (const QString &token : tokens) {
        const QString ip = token.trimmed();
        if (NetworkUtilities::checkIpSubnetFormat(ip) && !ips.contains(ip)) {
            ips.append(ip);
        }
    }
    return ips;
}

void appendSplitTunnelRoute(QStringList &routes, const QString &route, SplitTunnelRouteSource source)
{
    if (route.trimmed().isEmpty()) {
        return;
    }
    if (source == SplitTunnelRouteSource::Client && !isRoutableSplitTunnelRoute(route)) {
        qWarning() << "Skipping non-routable split tunnel route" << route;
        return;
    }
    if (source == SplitTunnelRouteSource::ServerManaged
        && !managedRoutePolicy::isAllowedManagedIpv4Route(route)) {
        qWarning() << "Skipping unsafe server-managed split tunnel route";
        return;
    }
    routes.append(route);
}

void appendSplitTunnelRoutes(QStringList &routes, const QStringList &newRoutes, SplitTunnelRouteSource source)
{
    for (const QString &route : newRoutes) {
        appendSplitTunnelRoute(routes, route, source);
    }
}

void appendSplitTunnelSiteRoutes(QStringList &routes, const QVariantMap &siteMap, SplitTunnelRouteSource source)
{
    for (auto i = siteMap.constBegin(); i != siteMap.constEnd(); ++i) {
        if (NetworkUtilities::checkIpSubnetFormat(i.key())) {
            appendSplitTunnelRoute(routes, i.key(), source);
        } else {
            appendSplitTunnelRoutes(routes, splitTunnelStoredIps(i.value().toString()), source);
        }
    }
}

QString serverRoutingRulesSyncHostFromConfig(const QJsonObject &vpnConfiguration)
{
    return vpnConfiguration.value(configKey::serverRoutingRulesSyncHost).toString().trimmed();
}

bool parseIpv4Route(const QString &route, quint32 &address, int &prefixLength)
{
    const QStringList routeParts = route.trimmed().split('/');
    if (routeParts.isEmpty() || routeParts.size() > 2) {
        return false;
    }

    const QHostAddress routeAddress(routeParts.at(0));
    if (routeAddress.protocol() != QAbstractSocket::NetworkLayerProtocol::IPv4Protocol) {
        return false;
    }

    address = routeAddress.toIPv4Address();
    prefixLength = 32;
    if (routeParts.size() == 1) {
        return true;
    }

    bool prefixOk = false;
    prefixLength = routeParts.at(1).toInt(&prefixOk);
    return prefixOk && prefixLength >= 0 && prefixLength <= 32;
}

bool parseIpv4Host(const QString &host, quint32 &address)
{
    const QHostAddress hostAddress(host.trimmed());
    if (hostAddress.protocol() != QAbstractSocket::NetworkLayerProtocol::IPv4Protocol) {
        return false;
    }
    address = hostAddress.toIPv4Address();
    return true;
}

QStringList splitWireGuardList(const QString &value)
{
    return value.split(QRegularExpression("\\s*,\\s*"), Qt::SkipEmptyParts);
}

QStringList wireGuardStringListFromJsonValue(const QJsonValue &value)
{
    if (value.isString()) {
        return splitWireGuardList(value.toString());
    }

    QStringList values;
    if (value.isArray()) {
        const QJsonArray array = value.toArray();
        for (const QJsonValue &item : array) {
            values.append(splitWireGuardList(item.toString()));
        }
    }
    return values;
}

QString wireGuardNativeConfigValue(const QString &nativeConfig, const QString &key)
{
    const QRegularExpression valueLine(QStringLiteral("^\\s*%1\\s*=\\s*(.*?)\\s*$")
        .arg(QRegularExpression::escape(key)));
    const QStringList nativeConfigLines = nativeConfig.split('\n');
    for (const QString &line : nativeConfigLines) {
        const QRegularExpressionMatch match = valueLine.match(line);
        if (match.hasMatch()) {
            return match.captured(1).trimmed();
        }
    }
    return {};
}

bool parseNetworkAddress(const QString &network, QHostAddress &address)
{
    const QString trimmed = network.trimmed();
    if (trimmed.isEmpty()) {
        return false;
    }

    const QStringList parts = trimmed.split('/');
    if (parts.isEmpty() || parts.size() > 2) {
        return false;
    }

    if (parts.size() == 2) {
        bool prefixOk = false;
        parts.at(1).toInt(&prefixOk);
        if (!prefixOk) {
            return false;
        }
    }

    address = QHostAddress(parts.at(0).trimmed());
    return address.protocol() != QAbstractSocket::UnknownNetworkLayerProtocol;
}

bool isUniqueLocalIpv6Address(const QHostAddress &address)
{
    if (address.protocol() != QAbstractSocket::IPv6Protocol) {
        return false;
    }

    const Q_IPV6ADDR rawAddress = address.toIPv6Address();
    return (rawAddress[0] & 0xfe) == 0xfc;
}

bool isIpv6Network(const QString &network)
{
    QHostAddress address;
    return parseNetworkAddress(network, address)
        && address.protocol() == QAbstractSocket::IPv6Protocol;
}

bool isUsableIpv6TunnelAddress(const QString &network)
{
    QHostAddress address;
    if (!parseNetworkAddress(network, address)
        || address.protocol() != QAbstractSocket::IPv6Protocol) {
        return false;
    }

    return !address.isNull()
        && !address.isLoopback()
        && !address.isLinkLocal()
        && !address.isMulticast()
        && !isUniqueLocalIpv6Address(address);
}

QStringList wireGuardClientAddressesFromNativeConfig(const QString &nativeConfig)
{
    return splitWireGuardList(wireGuardNativeConfigValue(nativeConfig, QStringLiteral("Address")));
}

bool wireGuardServerHasUsableIpv6Egress(const QJsonObject &configData)
{
    if (configData.value(configKey::serverIpv6Available).isBool()) {
        return configData.value(configKey::serverIpv6Available).toBool();
    }

    QStringList clientAddresses = wireGuardStringListFromJsonValue(configData.value(configKey::clientIp));
    if (clientAddresses.isEmpty()) {
        clientAddresses = wireGuardClientAddressesFromNativeConfig(configData.value(configKey::config).toString());
    }

    for (const QString &clientAddress : clientAddresses) {
        if (isUsableIpv6TunnelAddress(clientAddress)) {
            return true;
        }
    }
    return false;
}

QJsonArray allowedIpsWithoutUnavailableIpv6Routes(const QJsonArray &allowedIps, bool serverIpv6Available)
{
    if (serverIpv6Available) {
        return allowedIps;
    }

    QJsonArray filteredAllowedIps;
    for (const QJsonValue &allowedIpValue : allowedIps) {
        const QStringList allowedIps = splitWireGuardList(allowedIpValue.toString());
        for (const QString &allowedIpValueString : allowedIps) {
            const QString allowedIp = allowedIpValueString.trimmed();
            if (allowedIp.isEmpty()) {
                continue;
            }
            if (isIpv6Network(allowedIp)) {
                qWarning() << "Skipping IPv6 allowed IP because server IPv6 egress is unavailable" << allowedIp;
                continue;
            }
            filteredAllowedIps.append(allowedIp);
        }
    }
    return filteredAllowedIps;
}

QJsonArray defaultWireGuardAllowedIps(bool serverIpv6Available)
{
    QJsonArray allowedIps { QStringLiteral("0.0.0.0/0") };
    if (serverIpv6Available) {
        allowedIps.append(QStringLiteral("::/0"));
    }
    return allowedIps;
}

quint32 ipv4Mask(int prefixLength)
{
    return prefixLength == 0 ? 0 : (0xffffffffu << (32 - prefixLength));
}

bool routeOverlapsIpv4Range(quint32 address, int prefixLength, quint32 base, int rangePrefixLength)
{
    const quint32 routeStart = address & ipv4Mask(prefixLength);
    const quint32 routeEnd = routeStart | ~ipv4Mask(prefixLength);
    const quint32 rangeStart = base & ipv4Mask(rangePrefixLength);
    const quint32 rangeEnd = rangeStart | ~ipv4Mask(rangePrefixLength);
    return routeStart <= rangeEnd && rangeStart <= routeEnd;
}

QString ipv4RouteToString(quint32 address, int prefixLength)
{
    const QString ip = QHostAddress(address).toString();
    return prefixLength == 32 ? ip : QStringLiteral("%1/%2").arg(ip).arg(prefixLength);
}

QStringList normalizedSupportedIpv4Routes(const QStringList &routes, QStringList *unsupportedRoutes = nullptr)
{
    QStringList normalizedRoutes;
    for (const QString &route : routes) {
        quint32 address = 0;
        int prefixLength = 32;
        if (!parseIpv4Route(route, address, prefixLength)
            || (address & ipv4Mask(prefixLength)) != address) {
            if (unsupportedRoutes) {
                unsupportedRoutes->append(route.trimmed());
            }
            continue;
        }

        const QString normalizedRoute = ipv4RouteToString(address, prefixLength);
        if (!normalizedRoutes.contains(normalizedRoute)) {
            normalizedRoutes.append(normalizedRoute);
        }
    }
    return normalizedRoutes;
}

int trailingZeroBits(quint32 value)
{
    if (value == 0) {
        return 32;
    }

    int bits = 0;
    while ((value & 1u) == 0) {
        ++bits;
        value >>= 1;
    }
    return bits;
}

QStringList ipv4RangeToRoutes(quint32 start, quint32 end)
{
    QStringList routes;
    quint64 current = start;
    const quint64 rangeEnd = end;
    while (current <= rangeEnd) {
        int hostBits = trailingZeroBits(static_cast<quint32>(current));
        quint64 blockSize = 1ull << hostBits;
        const quint64 remaining = rangeEnd - current + 1;
        while (blockSize > remaining) {
            blockSize >>= 1;
            --hostBits;
        }

        routes.append(ipv4RouteToString(static_cast<quint32>(current), 32 - hostBits));
        current += blockSize;
    }
    return routes;
}

QStringList subtractIpv4HostFromRoute(const QString &route, quint32 hostAddress)
{
    quint32 routeAddress = 0;
    int prefixLength = 32;
    if (!parseIpv4Route(route, routeAddress, prefixLength)) {
        return { route };
    }

    const quint32 mask = ipv4Mask(prefixLength);
    const quint32 networkStart = routeAddress & mask;
    const quint32 networkEnd = networkStart | ~mask;
    if (hostAddress < networkStart || hostAddress > networkEnd) {
        return { ipv4RouteToString(networkStart, prefixLength) };
    }

    QStringList routes;
    if (hostAddress > networkStart) {
        routes.append(ipv4RangeToRoutes(networkStart, hostAddress - 1));
    }
    if (hostAddress < networkEnd) {
        routes.append(ipv4RangeToRoutes(hostAddress + 1, networkEnd));
    }
    return routes;
}

QStringList splitRoutesKeepingHostsInVpn(const QStringList &routes, const QStringList &protectedHosts)
{
    QList<quint32> protectedAddresses;
    for (const QString &host : protectedHosts) {
        quint32 hostAddress = 0;
        if (parseIpv4Host(host, hostAddress) && !protectedAddresses.contains(hostAddress)) {
            protectedAddresses.append(hostAddress);
        }
    }
    if (protectedAddresses.isEmpty()) {
        return routes;
    }

    QStringList result;
    for (const QString &route : routes) {
        QStringList splitRoutes { route };
        for (quint32 hostAddress : protectedAddresses) {
            QStringList nextRoutes;
            for (const QString &splitRoute : splitRoutes) {
                nextRoutes.append(subtractIpv4HostFromRoute(splitRoute, hostAddress));
            }
            splitRoutes = nextRoutes;
        }
        result.append(splitRoutes);
    }
    result.removeDuplicates();
    return result;
}

bool isRoutableSplitTunnelRoute(const QString &route)
{
    constexpr int minPublicBypassPrefixLength = 16;
    constexpr int minLocalBypassPrefixLength = 24;
    quint32 address = 0;
    int prefixLength = 32;
    if (!parseIpv4Route(route, address, prefixLength) || prefixLength == 0) {
        return false;
    }

    const QHostAddress hostAddress(address);
    const auto inRange = [address](quint32 base, int prefix) {
        const quint32 mask = ipv4Mask(prefix);
        return (address & mask) == (base & mask);
    };
    const auto routeOverlapsRange = [address, prefixLength](quint32 base, int prefix) {
        return routeOverlapsIpv4Range(address, prefixLength, base, prefix);
    };
    if (prefixLength < 32 && (address & ipv4Mask(prefixLength)) != address) {
        return false;
    }

    if (hostAddress.isNull() || hostAddress.isLoopback() || hostAddress.isBroadcast()
        || hostAddress.isLinkLocal() || hostAddress.isMulticast()) {
        return false;
    }
    const bool localOrServiceRoute = inRange(0x0a000000u, 8)
        || inRange(0x64400000u, 10)
        || inRange(0xac100000u, 12)
        || inRange(0xc0a80000u, 16);
    if (routeOverlapsRange(0x00000000u, 8) || routeOverlapsRange(0x7f000000u, 8)
        || routeOverlapsRange(0xc0000000u, 24)
        || routeOverlapsRange(0xc0000200u, 24) || routeOverlapsRange(0xc01f0000u, 24)
        || routeOverlapsRange(0xc01fc400u, 24) || routeOverlapsRange(0xc034c100u, 24)
        || routeOverlapsRange(0xc0586300u, 24) || routeOverlapsRange(0xc0af3000u, 24)
        || routeOverlapsRange(0xc6120000u, 15) || routeOverlapsRange(0xc6336400u, 24)
        || routeOverlapsRange(0xcb007100u, 24) || routeOverlapsRange(0xe0000000u, 4)
        || routeOverlapsRange(0xf0000000u, 4)) {
        return false;
    }
    const int minPrefixLength = localOrServiceRoute
        ? minLocalBypassPrefixLength
        : minPublicBypassPrefixLength;
    return prefixLength >= minPrefixLength;
}

QStringList routableSplitTunnelRoutes(const QStringList &routes)
{
    QStringList result;
    for (const QString &route : routes) {
        appendSplitTunnelRoute(result, route, SplitTunnelRouteSource::Client);
    }
    result.removeDuplicates();
    return result;
}

#ifdef AMNEZIA_DESKTOP
bool addTrustedRoutesWithReceipt(const QString &gateway, const QStringList &routes)
{
    if (routes.isEmpty()) {
        return true;
    }
    return IpcClient::withInterface(
            [&gateway, &routes](QSharedPointer<IpcInterfaceReplica> iface) {
                auto reply = iface->routeAddTrustedList(gateway, routes);
                return reply.waitForFinished(incrementalManagedRouteIpcTimeoutMs)
                        && reply.returnValue() == routes.size();
            },
            []() { return false; });
}
#endif
}

VpnConnection::VpnConnection(QObject *parent)
    : QObject(parent), m_checkTimer(this), m_deferredManagedRouteReconnectTimer(this),
      m_managedRouteReconnectCooldownTimer(this)
{
    m_managedRouteReconnectClock.start();
    m_deferredManagedRouteReconnectTimer.setSingleShot(true);
    m_deferredManagedRouteReconnectTimer.setInterval(deferredManagedRouteDeadlineMs);
    connect(&m_deferredManagedRouteReconnectTimer, &QTimer::timeout, this, [this]() {
        if (!m_reconnectAfterClientRouteResolution || m_pendingClientSplitRouteLookups <= 0) {
            return;
        }

        m_reconnectAfterClientRouteResolution = false;
        qWarning() << "VpnConnection: local DNS resolution exceeded managed policy deadline; queueing a bounded reconnect";
        scheduleManagedRouteReconnect(
                m_connectionEpoch, m_serverId,
                QStringLiteral("local DNS resolution deadline"));
    });
    m_managedRouteReconnectCooldownTimer.setSingleShot(true);
    connect(&m_managedRouteReconnectCooldownTimer, &QTimer::timeout,
            this, &VpnConnection::flushManagedRouteReconnect);
#if defined(Q_OS_IOS) || defined(MACOS_NE)
    m_checkTimer.setInterval(1000);
    connect(IosController::Instance(), &IosController::connectionStateChanged, this, &VpnConnection::setConnectionState);
    connect(IosController::Instance(), &IosController::bytesChanged, this, &VpnConnection::onBytesChanged);
#endif
}

VpnConnection::~VpnConnection()
{
}

QStringList VpnConnection::normalizedManagedRoutesForRuntime(
        RouteMode mode, const QStringList &managedRoutes,
        const QVariantMap &localSites, const QStringList &protectedHosts,
        bool *valid) const
{
    bool routesValid = false;
    QStringList boundedRoutes = managedRoutePolicy::validatedManagedRoutes(
            managedRoutes, &routesValid);
    if (!routesValid) {
        if (valid) {
            *valid = false;
        }
        return {};
    }
    if (mode != RouteMode::VpnAllExceptSites) {
        const bool emptyAsRequired = boundedRoutes.isEmpty();
        if (valid) {
            *valid = emptyAsRequired;
        }
        return {};
    }

    QStringList unsupportedManagedRoutes;
    boundedRoutes = normalizedSupportedIpv4Routes(
            splitRoutesKeepingHostsInVpn(boundedRoutes, protectedHosts),
            &unsupportedManagedRoutes);
    boundedRoutes = managedRoutePolicy::validatedManagedRoutes(
            boundedRoutes, &routesValid);
    if (!routesValid || !unsupportedManagedRoutes.isEmpty()) {
        if (valid) {
            *valid = false;
        }
        return {};
    }

    QStringList localRoutes;
    appendSplitTunnelSiteRoutes(
            localRoutes, localSites, SplitTunnelRouteSource::Client);
    localRoutes = normalizedSupportedIpv4Routes(
            splitRoutesKeepingHostsInVpn(localRoutes, protectedHosts));
    const QSet<QString> localSet(localRoutes.cbegin(), localRoutes.cend());

    QStringList result;
    for (const QString &route : boundedRoutes) {
        if (!localSet.contains(route) && !result.contains(route)) {
            result.append(route);
        }
    }
    result.sort();
    if (valid) {
        *valid = true;
    }
    return result;
}

void VpnConnection::invalidateAuthoritativeManagedRouteBase()
{
    ++m_authoritativeManagedRouteBaseRevision;
    m_hasAuthoritativeManagedRouteBase = false;
    m_managedRouteTransitionPending = true;
    m_authoritativeManagedRouteMode = RouteMode::VpnAllSites;
    m_authoritativeManagedRoutes.clear();
    m_authoritativeManagedRouteConnectionEpoch = 0;
    m_authoritativeManagedRouteServerId.clear();
    m_authoritativeManagedRoutePolicyRevision.clear();
    m_authoritativeManagedRoutePolicyContentHash.clear();
}

void VpnConnection::publishManagedRouteBase(
        RouteMode mode, const QStringList &managedRoutes,
        const QVariantMap &localSites, const QString &policyRevision,
        const QString &policyContentHash, bool confirmed)
{
    QStringList protectedHosts = serverRoutingRulesSyncHosts();
    protectedHosts << m_vpnConfiguration.value(configKey::dns1).toString()
                   << m_vpnConfiguration.value(configKey::dns2).toString();
    protectedHosts.removeAll(QString());
    protectedHosts.removeDuplicates();
    bool normalizedValid = false;
    const QStringList normalizedRoutes = normalizedManagedRoutesForRuntime(
            mode, managedRoutes, localSites, protectedHosts,
            &normalizedValid);
    const bool identityValid = managedRoutePolicy::isCanonicalPolicyIdentity(
            policyRevision, policyContentHash)
            && (normalizedRoutes.isEmpty() || !policyRevision.isEmpty());
    const bool baseConfirmed = confirmed && normalizedValid
            && identityValid && m_startupRouteTeardownConfirmed
            && !m_serverId.isEmpty();

    ++m_authoritativeManagedRouteBaseRevision;
    m_hasAuthoritativeManagedRouteBase = baseConfirmed;
    m_managedRouteTransitionPending = !baseConfirmed;
    m_authoritativeManagedRouteMode = mode;
    m_authoritativeManagedRoutes = baseConfirmed ? normalizedRoutes : QStringList();
    m_authoritativeManagedRouteConnectionEpoch = baseConfirmed
            ? m_connectionEpoch : 0;
    m_authoritativeManagedRouteServerId = baseConfirmed
            ? m_serverId : QString();
    m_authoritativeManagedRoutePolicyRevision = baseConfirmed
            ? policyRevision : QString();
    m_authoritativeManagedRoutePolicyContentHash = baseConfirmed
            ? policyContentHash : QString();

    if (m_managedRouteReconnectGate.pending()
        && m_managedRouteReconnectGate.serverId() == m_serverId) {
        // A route-base attempt (confirmed or fail-closed) is the barrier for an
        // unrelated reconnect. Resume the original fixed cooldown without
        // polling; a confirmed equal base will cancel it in flush().
        m_managedRouteReconnectAwaitingBase = false;
        QTimer::singleShot(0, this, &VpnConnection::flushManagedRouteReconnect);
    }

    const quint64 epoch = m_connectionEpoch;
    const QString serverId = m_serverId;
    const quint64 revision = m_authoritativeManagedRouteBaseRevision;
    QTimer::singleShot(0, this, [this, epoch, serverId, mode, normalizedRoutes,
                                revision, policyRevision, policyContentHash,
                                baseConfirmed]() {
        if (epoch != m_connectionEpoch || serverId != m_serverId
            || revision != m_authoritativeManagedRouteBaseRevision
            || m_connectionState != Vpn::ConnectionState::Connected) {
            return;
        }
        emit managedSplitTunnelRouteBaseReady(
                epoch, serverId, static_cast<int>(mode),
                baseConfirmed ? normalizedRoutes : QStringList(),
                revision,
                baseConfirmed ? policyRevision : QString(),
                baseConfirmed ? policyContentHash : QString(),
                baseConfirmed);
    });
}

void VpnConnection::prepareManagedRouteConnectionSnapshot(
        quint64 generation, const QString &serverId, int modeValue,
        const QStringList &managedRoutes, const QString &policyRevision,
        const QString &policyContentHash, const QVariantMap &localSites)
{
    if (QThread::currentThread() != thread()) {
        qCritical() << "VpnConnection: refusing managed-route snapshot preparation outside the VPN worker thread";
        return;
    }
    if (generation < m_latestPreparedManagedRouteSnapshotGeneration
        || (generation == m_latestPreparedManagedRouteSnapshotGeneration
            && !m_preparedManagedRouteServerId.isEmpty()
            && serverId != m_preparedManagedRouteServerId)) {
        return;
    }
    m_latestPreparedManagedRouteSnapshotGeneration = generation;
    m_preparedManagedRouteServerId = serverId;
    const auto mode = static_cast<RouteMode>(modeValue);
    const bool modeValid = mode == RouteMode::VpnAllSites
            || mode == RouteMode::VpnOnlyForwardSites
            || mode == RouteMode::VpnAllExceptSites;
    bool routesValid = false;
    const QStringList boundedRoutes = managedRoutePolicy::validatedManagedRoutes(
            managedRoutes, &routesValid);
    const QString normalizedContentHash =
            managedRoutePolicy::normalizedSha256(policyContentHash);
    const bool identityValid = managedRoutePolicy::isCanonicalPolicyIdentity(
            policyRevision, normalizedContentHash)
            && (boundedRoutes.isEmpty() || !policyRevision.isEmpty());
    if (serverId.isEmpty() || !modeValid || !routesValid || !identityValid) {
        m_hasPreparedManagedRouteSnapshot = false;
        m_preparedManagedRouteServerId.clear();
        m_preparedManagedRouteMode = RouteMode::VpnAllSites;
        m_preparedManagedRoutes.clear();
        m_preparedManagedRoutePolicyRevision.clear();
        m_preparedManagedRoutePolicyContentHash.clear();
        m_preparedLocalSites.clear();
        return;
    }

    m_preparedManagedRouteMode = mode;
    m_preparedManagedRoutes = boundedRoutes;
    m_preparedManagedRoutes.removeDuplicates();
    m_preparedManagedRoutes.sort();
    m_preparedManagedRoutePolicyRevision = policyRevision;
    m_preparedManagedRoutePolicyContentHash = normalizedContentHash;
    m_preparedLocalSites = localSites;
    m_hasPreparedManagedRouteSnapshot = true;
}

void VpnConnection::rebuildManagedSplitTunnelRoutes(
        quint64 expectedConnectionEpoch, const QString &expectedServerId)
{
    if (QThread::currentThread() != thread()
        || expectedConnectionEpoch != m_connectionEpoch
        || expectedServerId.isEmpty() || expectedServerId != m_serverId
        || m_connectionState != Vpn::ConnectionState::Connected) {
        return;
    }
    invalidateAuthoritativeManagedRouteBase();
    scheduleManagedRouteReconnect(
            expectedConnectionEpoch, expectedServerId,
            QStringLiteral("managed route base rebuild"));
}

void VpnConnection::onBytesChanged(quint64 receivedBytes, quint64 sentBytes)
{
    emit bytesChanged(receivedBytes, sentBytes);
}

void VpnConnection::onKillSwitchModeChanged(bool enabled)
{
#ifdef AMNEZIA_DESKTOP
    IpcClient::withInterface([enabled](QSharedPointer<IpcInterfaceReplica> iface){
        QRemoteObjectPendingReply<bool> reply = iface->refreshKillSwitch(enabled);
        if (reply.waitForFinished(killSwitchIpcTimeoutMs) && reply.returnValue())
            qDebug() << "VpnConnection::onKillSwitchModeChanged: Killswitch refreshed";
        else
            qWarning() << "VpnConnection::onKillSwitchModeChanged: Failed to execute remote refreshKillSwitch call";
    });
#endif
}

void VpnConnection::onConnectionStateChanged(Vpn::ConnectionState state)
{
    if ((state == Vpn::ConnectionState::Connecting
         || state == Vpn::ConnectionState::Reconnecting
         || state == Vpn::ConnectionState::Error)
        && m_managedRouteReconnectGate.pending()
        && m_managedRouteReconnectGate.serverId() == m_serverId) {
        m_managedRouteReconnectAwaitingBase = true;
        m_managedRouteReconnectCooldownTimer.stop();
    }
#ifdef AMNEZIA_DESKTOP
    const DockerContainer container = m_container;

    IpcClient::withInterface([&](QSharedPointer<IpcInterfaceReplica> iface) {
        switch (state) {
            case Vpn::ConnectionState::Connected: {
                iface->resetIpStack();

                auto flushDns = iface->flushDns();
                if (flushDns.waitForFinished(dnsFlushIpcTimeoutMs) && flushDns.returnValue())
                    qDebug() << "VpnConnection::onConnectionStateChanged: Successfully flushed DNS";
                else
                    qWarning() << "VpnConnection::onConnectionStateChanged: Failed to flush DNS";

                if (!ContainerUtils::isAwgContainer(container) && container != DockerContainer::WireGuard) {
                    QString dns1 = m_vpnConfiguration.value(configKey::dns1).toString();
                    QString dns2 = m_vpnConfiguration.value(configKey::dns2).toString();

                    const RouteMode effectiveRouteMode = appliedSiteRouteMode();

                    QStringList vpnGatewayRoutes = serverRoutingRulesSyncHosts();
#ifdef Q_OS_MACOS
                    if (effectiveRouteMode != amnezia::RouteMode::VpnAllExceptSites) {
                        vpnGatewayRoutes << dns1 << dns2;
                    }
#else
                    vpnGatewayRoutes << dns1 << dns2;
#endif
                    vpnGatewayRoutes.removeAll(QString());
                    vpnGatewayRoutes.removeDuplicates();
                    if (!vpnGatewayRoutes.isEmpty()) {
                        iface->routeAddList(m_vpnProtocol->vpnGateway(), vpnGatewayRoutes);
                    }

                    if (effectiveRouteMode != RouteMode::VpnAllSites) {
                        iface->routeDeleteList(m_vpnProtocol->vpnGateway(), QStringList() << "0.0.0.0");
                        if (effectiveRouteMode == RouteMode::VpnOnlyForwardSites) {
                            const quint64 expectedConnectionEpoch = m_connectionEpoch;
                            const QString expectedServerId = m_serverId;
                            QTimer::singleShot(1000, m_vpnProtocol.data(),
                                               [this, effectiveRouteMode, expectedConnectionEpoch,
                                                expectedServerId]() {
                                if (expectedConnectionEpoch == m_connectionEpoch
                                    && expectedServerId == m_serverId
                                    && m_connectionState == Vpn::ConnectionState::Connected
                                    && !m_vpnProtocol.isNull()) {
                                    addSitesRoutes(m_vpnProtocol->vpnGateway(), effectiveRouteMode);
                                }
                            });
                        } else if (effectiveRouteMode == RouteMode::VpnAllExceptSites) {
                            iface->routeAddList(m_vpnProtocol->vpnGateway(), QStringList() << "0.0.0.0/1");
                            iface->routeAddList(m_vpnProtocol->vpnGateway(), QStringList() << "128.0.0.0/1");

                            iface->routeAddList(m_vpnProtocol->routeGateway(), QStringList() << remoteAddress());
#ifdef Q_OS_MACOS
                            iface->routeAddList(m_vpnProtocol->routeGateway(), QStringList() << dns1 << dns2);
#endif
                            addSitesRoutes(m_vpnProtocol->routeGateway(), effectiveRouteMode);
                        }
                    }
                }
            } break;
            case Vpn::ConnectionState::Disconnected:
            case Vpn::ConnectionState::Error: {
                auto flushDns = iface->flushDns();
                if (flushDns.waitForFinished(dnsFlushIpcTimeoutMs) && flushDns.returnValue())
                    qDebug() << "VpnConnection::onConnectionStateChanged: Successfully flushed DNS";
                else
                    qWarning() << "VpnConnection::onConnectionStateChanged: Failed to flush DNS";
            } break;
            default:
                break;
        }
    });
#endif

    if (state == Vpn::ConnectionState::Disconnected
        || state == Vpn::ConnectionState::Error) {
        m_startupRouteTeardownConfirmed = clearSavedRoutesWithReceipt();
        if (m_startupRouteTeardownConfirmed) {
            qDebug() << "VpnConnection::onConnectionStateChanged: Successfully cleared saved routes";
        } else {
            qWarning() << "VpnConnection::onConnectionStateChanged: Saved-route teardown was not confirmed";
        }
    }

    if (state == Vpn::ConnectionState::Connected) {
        const RouteMode connectedMode = appliedSiteRouteMode();
        bool protocolStartupConfirmsManagedBase = !m_connectionRestoredWithoutStartup;
#ifdef AMNEZIA_DESKTOP
        const bool routeReceiptWillArriveAsynchronously = connectedMode != RouteMode::VpnAllSites
                && !ContainerUtils::isAwgContainer(container)
                && container != DockerContainer::WireGuard;
        protocolStartupConfirmsManagedBase = !m_connectionRestoredWithoutStartup
                && !routeReceiptWillArriveAsynchronously;
#endif
        if (protocolStartupConfirmsManagedBase) {
            const bool startupSnapshotMatches = m_hasStartupManagedRouteSnapshot
                    && m_startupManagedRouteServerId == m_serverId
                    && m_startupManagedRouteMode == connectedMode;
            publishManagedRouteBase(
                    connectedMode,
                    startupSnapshotMatches ? m_startupManagedRoutes : QStringList(),
                    startupSnapshotMatches ? m_startupLocalSites : QVariantMap(),
                    startupSnapshotMatches
                            ? m_startupManagedRoutePolicyRevision : QString(),
                    startupSnapshotMatches
                            ? m_startupManagedRoutePolicyContentHash : QString(),
                    startupSnapshotMatches);
        } else if (m_connectionRestoredWithoutStartup) {
            // Android can restore a service-owned tunnel after the UI process
            // restarts. There is no process-local route receipt and cycling
            // this live tunnel would be disruptive, so keep reconciliation
            // blocked until a natural, user-initiated connection start.
            qInfo() << "VpnConnection: restored Android tunnel has no managed-route receipt; waiting for natural reconnect";
        }
    }

#if defined(Q_OS_IOS) || defined(MACOS_NE)
    if (state == Vpn::ConnectionState::Connected ||
        state == Vpn::ConnectionState::Connecting ||
        state == Vpn::ConnectionState::Reconnecting) {
        m_checkTimer.start();
    } else {
        m_checkTimer.stop();
    }
#endif
}

const QString &VpnConnection::remoteAddress() const
{
    return m_remoteAddress;
}

int VpnConnection::serverIndex() const
{
    return m_serverIndex;
}

QString VpnConnection::serverId() const
{
    return m_serverId;
}

quint64 VpnConnection::connectionEpoch() const
{
    return m_connectionEpoch;
}

VpnConnection::ManagedRouteRuntimeSnapshot
VpnConnection::managedRouteRuntimeSnapshot() const
{
    ManagedRouteRuntimeSnapshot snapshot;
    const bool bindingMatches = m_authoritativeManagedRouteConnectionEpoch
                    == m_connectionEpoch
            && m_authoritativeManagedRouteServerId == m_serverId
            && m_authoritativeManagedRouteMode == appliedSiteRouteMode()
            && managedRoutePolicy::isCanonicalPolicyIdentity(
                    m_authoritativeManagedRoutePolicyRevision,
                    m_authoritativeManagedRoutePolicyContentHash)
            && (m_authoritativeManagedRoutes.isEmpty()
                || !m_authoritativeManagedRoutePolicyRevision.isEmpty());
    snapshot.confirmed = m_hasAuthoritativeManagedRouteBase
            && !m_managedRouteTransitionPending && bindingMatches
            && m_connectionState == Vpn::ConnectionState::Connected;
    snapshot.transitionPending = m_managedRouteTransitionPending
            || m_connectionState == Vpn::ConnectionState::Reconnecting
            || m_connectionState == Vpn::ConnectionState::Connecting
            || m_connectionState == Vpn::ConnectionState::Preparing;
    snapshot.mode = snapshot.confirmed
            ? m_authoritativeManagedRouteMode : RouteMode::VpnAllSites;
    snapshot.installedRoutes = snapshot.confirmed
            ? m_authoritativeManagedRoutes : QStringList();
    snapshot.revision = m_authoritativeManagedRouteBaseRevision;
    snapshot.connectionEpoch = m_connectionEpoch;
    snapshot.serverId = m_serverId;
    snapshot.policyRevision = snapshot.confirmed
            ? m_authoritativeManagedRoutePolicyRevision : QString();
    snapshot.policyContentHash = snapshot.confirmed
            ? m_authoritativeManagedRoutePolicyContentHash : QString();
    return snapshot;
}

DockerContainer VpnConnection::container() const
{
    return m_container;
}

RouteMode VpnConnection::appliedSiteRouteMode() const
{
    const int storedMode = m_vpnConfiguration.value(configKey::splitTunnelType)
                                   .toInt(static_cast<int>(RouteMode::VpnAllSites));
    if (storedMode == static_cast<int>(RouteMode::VpnOnlyForwardSites)
        || storedMode == static_cast<int>(RouteMode::VpnAllExceptSites)) {
        return static_cast<RouteMode>(storedMode);
    }
    return RouteMode::VpnAllSites;
}

AppsRouteMode VpnConnection::appliedAppsRouteMode() const
{
    const int storedMode = m_vpnConfiguration.value(configKey::appSplitTunnelType)
                                   .toInt(static_cast<int>(AppsRouteMode::VpnAllApps));
    if (storedMode == static_cast<int>(AppsRouteMode::VpnOnlyForwardApps)
        || storedMode == static_cast<int>(AppsRouteMode::VpnAllExceptApps)) {
        return static_cast<AppsRouteMode>(storedMode);
    }
    return AppsRouteMode::VpnAllApps;
}

bool VpnConnection::applicationUsesVpnDataPath(const QString &applicationId) const
{
    const AppsRouteMode mode = appliedAppsRouteMode();
    if (mode == AppsRouteMode::VpnAllApps) {
        return true;
    }

    // App identifiers are platform-specific. Android exposes stable package
    // names, so the Guardian request can be bound to this process exactly.
    // Other platforms remain fail-closed for selective app routing.
#ifdef Q_OS_ANDROID
    const QString normalizedId = applicationId.trimmed();
    if (normalizedId.isEmpty()) {
        return false;
    }
    QStringList configuredApps;
    const QJsonArray configuredArray =
            m_vpnConfiguration.value(configKey::splitTunnelApps).toArray();
    configuredApps.reserve(configuredArray.size());
    for (const QJsonValue &value : configuredArray) {
        const QString candidate = value.toString().trimmed();
        if (!candidate.isEmpty() && !configuredApps.contains(candidate)) {
            configuredApps.append(candidate);
        }
    }
    const bool listed = configuredApps.contains(normalizedId);
    return mode == AppsRouteMode::VpnOnlyForwardApps ? listed : !listed;
#else
    Q_UNUSED(applicationId)
    return false;
#endif
}

QString VpnConnection::serverRoutingRulesSyncHost() const
{
    const QString syncHost = serverRoutingRulesSyncHostFromConfig(m_vpnConfiguration);
    if (!syncHost.isEmpty()) {
        return syncHost;
    }
    if (m_vpnProtocol && !m_vpnProtocol->vpnGateway().isEmpty()) {
        return m_vpnProtocol->vpnGateway();
    }
    return QString::fromLatin1(protocols::serverRoutingRules::syncHost);
}

QStringList VpnConnection::serverRoutingRulesSyncHosts() const
{
    QStringList hosts;
    const auto addHost = [&hosts](const QString &host) {
        const QString trimmedHost = host.trimmed();
        if (!trimmedHost.isEmpty() && !hosts.contains(trimmedHost)) {
            hosts.append(trimmedHost);
        }
    };

    addHost(serverRoutingRulesSyncHostFromConfig(m_vpnConfiguration));
    if (hosts.isEmpty() && m_vpnProtocol && !m_vpnProtocol->vpnGateway().isEmpty()) {
        addHost(m_vpnProtocol->vpnGateway());
    }
    addHost(QString::fromLatin1(protocols::serverRoutingRules::syncHost));
    addHost(QString::fromLatin1(protocols::selfHostedUpdates::syncHost));
    if (!m_vpnConfiguration.value(configKey::clientLogs).toObject().isEmpty()) {
        addHost(QString::fromLatin1(protocols::clientLogs::syncHost));
    }
    return hosts;
}

void VpnConnection::invalidateAllSplitRouteResolutions()
{
    ++m_clientSplitRouteResolveGeneration;
    ++m_managedSplitRouteResolveGeneration;
    m_pendingClientSplitRouteLookups = 0;
    m_reconnectAfterClientRouteResolution = false;
    m_deferredManagedRouteReconnectTimer.stop();
    invalidateAuthoritativeManagedRouteBase();
}

void VpnConnection::beginManagedRouteReconnectSession(const QString &serverId)
{
    m_managedRouteReconnectCooldownTimer.stop();
    m_managedRouteReconnectAwaitingBase = false;
    m_managedRouteReconnectGate.beginSession(serverId);
}

void VpnConnection::clearManagedRouteReconnectSession()
{
    m_managedRouteReconnectCooldownTimer.stop();
    m_managedRouteReconnectAwaitingBase = false;
    m_managedRouteReconnectGate.clear();
}

void VpnConnection::recordReconnectFloor()
{
    m_managedRouteReconnectCooldownTimer.stop();
    m_managedRouteReconnectAwaitingBase = false;
    m_managedRouteReconnectGate.recordReconnect(
            m_serverId, m_managedRouteReconnectClock.elapsed());
}

void VpnConnection::scheduleManagedRouteReconnect(
        quint64 expectedConnectionEpoch, const QString &expectedServerId,
        const QString &reason)
{
    if (QThread::currentThread() != thread()
        || expectedConnectionEpoch != m_connectionEpoch
        || expectedServerId.isEmpty() || expectedServerId != m_serverId
        || m_connectionState != Vpn::ConnectionState::Connected) {
        return;
    }

    const auto request = m_managedRouteReconnectGate.request(
            expectedServerId, m_managedRouteReconnectClock.elapsed(),
            managedRouteReconnectMinimumIntervalMs);
    if (!request.accepted) {
        return;
    }
    if (!request.newlyPending) {
        qInfo() << "VpnConnection: coalesced managed-route reconnect behind the existing cooldown";
        return;
    }

    const int delayMs = static_cast<int>(qMin<qint64>(
            request.delayMs, (std::numeric_limits<int>::max)()));
    qInfo() << "VpnConnection: scheduled managed-route reconnect"
            << reason << "in" << delayMs << "ms";
    m_managedRouteReconnectCooldownTimer.start(delayMs);
}

void VpnConnection::flushManagedRouteReconnect()
{
    if (!m_managedRouteReconnectGate.pending()) {
        return;
    }
    if (m_connectionState != Vpn::ConnectionState::Connected
        || m_serverId.isEmpty()
        || m_serverId != m_managedRouteReconnectGate.serverId()) {
        if (!m_serverId.isEmpty()
            && m_serverId == m_managedRouteReconnectGate.serverId()) {
            m_managedRouteReconnectAwaitingBase = true;
        }
        return;
    }

    if (m_managedRouteReconnectAwaitingBase
        && !m_hasAuthoritativeManagedRouteBase) {
        return;
    }
    m_managedRouteReconnectAwaitingBase = false;

    if (latestPreparedManagedRouteSnapshotIsApplied()) {
        m_managedRouteReconnectGate.cancelPending();
        qInfo() << "VpnConnection: cancelled deferred managed-route reconnect because the latest snapshot is already applied";
        return;
    }

    const qint64 nowMs = m_managedRouteReconnectClock.elapsed();
    const auto request = m_managedRouteReconnectGate.request(
            m_serverId, nowMs, managedRouteReconnectMinimumIntervalMs);
    if (!request.accepted) {
        return;
    }
    if (request.delayMs > 0) {
        const int delayMs = static_cast<int>(qMin<qint64>(
                request.delayMs, (std::numeric_limits<int>::max)()));
        m_managedRouteReconnectCooldownTimer.start(delayMs);
        return;
    }
    if (!m_managedRouteReconnectGate.takeDue(
                m_serverId, nowMs, managedRouteReconnectMinimumIntervalMs)) {
        return;
    }

    recordReconnectFloor();
    qInfo() << "VpnConnection: applying the latest managed routes with a bounded reconnect";
    reconnectToVpn();
}

bool VpnConnection::latestPreparedManagedRouteSnapshotIsApplied() const
{
    if (!m_hasPreparedManagedRouteSnapshot || !m_hasAuthoritativeManagedRouteBase
        || m_preparedManagedRouteServerId != m_authoritativeManagedRouteServerId
        || m_preparedManagedRouteMode != m_authoritativeManagedRouteMode
        || m_preparedManagedRoutePolicyRevision
                != m_authoritativeManagedRoutePolicyRevision
        || m_preparedManagedRoutePolicyContentHash
                != m_authoritativeManagedRoutePolicyContentHash) {
        return false;
    }

    QStringList protectedHosts = serverRoutingRulesSyncHosts();
    protectedHosts << m_vpnConfiguration.value(configKey::dns1).toString()
                   << m_vpnConfiguration.value(configKey::dns2).toString();
    protectedHosts.removeAll(QString());
    protectedHosts.removeDuplicates();
    bool normalizedValid = false;
    const QStringList normalizedPreparedRoutes = normalizedManagedRoutesForRuntime(
            m_preparedManagedRouteMode, m_preparedManagedRoutes,
            m_preparedLocalSites, protectedHosts, &normalizedValid);
    return normalizedValid
            && normalizedPreparedRoutes == m_authoritativeManagedRoutes;
}

bool VpnConnection::clearSavedRoutesWithReceipt()
{
#ifdef AMNEZIA_DESKTOP
    return IpcClient::withInterface(
            [](QSharedPointer<IpcInterfaceReplica> iface) {
                auto reply = iface->clearSavedRoutes();
                return reply.waitForFinished(clearSavedRoutesIpcTimeoutMs)
                        && reply.returnValue();
            },
            []() { return false; });
#else
    // Mobile and NetworkExtension routes are protocol-owned; no desktop route
    // registry exists on those platforms.
    return true;
#endif
}

void VpnConnection::addSitesRoutes(const QString &gw, amnezia::RouteMode mode)
{
#ifdef AMNEZIA_DESKTOP
    const QString activeServerId = m_serverId;
    const bool startupSnapshotMatches = m_hasStartupManagedRouteSnapshot
            && !activeServerId.isEmpty()
            && m_startupManagedRouteServerId == activeServerId
            && m_startupManagedRouteMode == mode;
    const quint64 clientResolveGeneration = ++m_clientSplitRouteResolveGeneration;
    const quint64 managedResolveGeneration = ++m_managedSplitRouteResolveGeneration;
    m_pendingClientSplitRouteLookups = 0;
    m_reconnectAfterClientRouteResolution = false;
    m_deferredManagedRouteReconnectTimer.stop();
    QStringList ips;
    QStringList managedIps = startupSnapshotMatches
            ? m_startupManagedRoutes : QStringList();
    QStringList clientSites;
    QStringList protectedHosts = serverRoutingRulesSyncHosts();
    protectedHosts << m_vpnConfiguration.value(configKey::dns1).toString()
                   << m_vpnConfiguration.value(configKey::dns2).toString();
    protectedHosts.removeAll(QString());
    protectedHosts.removeDuplicates();
    const QVariantMap localSitesSnapshot = startupSnapshotMatches
            ? m_startupLocalSites : QVariantMap();
    const QString policyRevision = startupSnapshotMatches
            ? m_startupManagedRoutePolicyRevision : QString();
    const QString policyContentHash = startupSnapshotMatches
            ? m_startupManagedRoutePolicyContentHash : QString();
    for (auto i = localSitesSnapshot.constBegin(); i != localSitesSnapshot.constEnd(); ++i) {
        if (NetworkUtilities::checkIpSubnetFormat(i.key())) {
            appendSplitTunnelRoute(ips, i.key(), SplitTunnelRouteSource::Client);
        } else {
            appendSplitTunnelRoutes(ips, splitTunnelStoredIps(i.value().toString()), SplitTunnelRouteSource::Client);
            clientSites.append(i.key());
        }
    }

    bool initialManagedSnapshotConfirmable = startupSnapshotMatches;
    bool managedBatchValid = false;
    managedIps = managedRoutePolicy::validatedManagedRoutes(managedIps, &managedBatchValid);
    if (!managedBatchValid) {
        qWarning() << "VpnConnection: rejected unsafe or oversized server-managed route snapshot";
        initialManagedSnapshotConfirmable = false;
        managedIps.clear();
    }
    ips.removeDuplicates();
    managedIps.removeDuplicates();
    if (mode == RouteMode::VpnAllExceptSites) {
        ips = splitRoutesKeepingHostsInVpn(ips, protectedHosts);
        managedIps = splitRoutesKeepingHostsInVpn(managedIps, protectedHosts);
    }

    managedIps = managedRoutePolicy::validatedManagedRoutes(managedIps, &managedBatchValid);
    if (!managedBatchValid) {
        qWarning() << "VpnConnection: protected-host expansion exceeded the managed route boundary";
        initialManagedSnapshotConfirmable = false;
        managedIps.clear();
    }

    QStringList unsupportedClientRoutes;
    QStringList unsupportedManagedRoutes;
    ips = normalizedSupportedIpv4Routes(ips, &unsupportedClientRoutes);
    managedIps = normalizedSupportedIpv4Routes(managedIps, &unsupportedManagedRoutes);
    if (!unsupportedClientRoutes.isEmpty()) {
        qWarning() << "VpnConnection: desktop split-route IPC supports canonical IPv4 routes only; skipped local routes"
                   << unsupportedClientRoutes;
    }
    if (!unsupportedManagedRoutes.isEmpty()) {
        qWarning() << "VpnConnection: desktop split-route IPC supports canonical IPv4 routes only; skipped managed routes"
                   << unsupportedManagedRoutes;
        initialManagedSnapshotConfirmable = false;
    }

    auto activeClientRoutes = QSharedPointer<QSet<QString>>::create();
    for (const QString &route : ips) {
        activeClientRoutes->insert(route);
    }
    auto activeManagedRoutes = QSharedPointer<QSet<QString>>::create();
    auto managedAddsConfirmed = QSharedPointer<bool>::create(initialManagedSnapshotConfirmable);

    // Local routes keep their existing best-effort owner. Server-managed
    // routes below are not published as an authoritative base until every
    // trusted batch has a bounded, full-count receipt.
    IpcClient::withInterface([gw, ips](QSharedPointer<IpcInterfaceReplica> iface) {
        if (!ips.isEmpty()) {
            iface->routeAddList(gw, ips);
        }
    });

    // Managed routes are installed only after local domains finish resolving.
    // This makes the source boundary explicit: an address learned from a user
    // rule is never subsequently sent through the trusted managed-route API.
    const auto startManagedRoutes = [this, gw, mode, managedIps, localSitesSnapshot,
                                     policyRevision, policyContentHash,
                                     activeServerId, managedResolveGeneration, activeClientRoutes,
                                     activeManagedRoutes, managedAddsConfirmed]() {
        if (managedResolveGeneration != m_managedSplitRouteResolveGeneration
            || m_connectionState != Vpn::ConnectionState::Connected
            || m_serverId != activeServerId || m_vpnProtocol.isNull()) {
            return;
        }

        const QString currentGateway = mode == RouteMode::VpnAllExceptSites
                ? m_vpnProtocol->routeGateway()
                : m_vpnProtocol->vpnGateway();
        if (gw != currentGateway) {
            return;
        }

        QStringList managedOnlyRoutes;
        for (const QString &route : managedIps) {
            if (!activeClientRoutes->contains(route) && !activeManagedRoutes->contains(route)) {
                managedOnlyRoutes.append(route);
            }
        }
        if (addTrustedRoutesWithReceipt(gw, managedOnlyRoutes)) {
            for (const QString &route : managedOnlyRoutes) {
                activeManagedRoutes->insert(route);
            }
        } else {
            *managedAddsConfirmed = false;
            qWarning() << "VpnConnection: initial managed route add was incomplete; base remains unknown";
        }
        QStringList installedManagedRoutes = activeManagedRoutes->values();
        installedManagedRoutes.sort();
        publishManagedRouteBase(
                mode, installedManagedRoutes, localSitesSnapshot,
                policyRevision, policyContentHash,
                *managedAddsConfirmed);
    };

    m_pendingClientSplitRouteLookups = clientSites.size();
    if (clientSites.isEmpty()) {
        QTimer::singleShot(0, this, startManagedRoutes);
        return;
    }

    for (const QString &site : clientSites) {
        QHostInfo::lookupHost(site, this,
                              [this, site, gw, mode, protectedHosts, activeServerId, clientResolveGeneration,
                               activeClientRoutes, startManagedRoutes](const QHostInfo &hostInfo) {
            if (clientResolveGeneration != m_clientSplitRouteResolveGeneration) {
                return;
            }

            const auto finishClientLookup = [this, clientResolveGeneration, startManagedRoutes]() {
                if (clientResolveGeneration != m_clientSplitRouteResolveGeneration
                    || m_pendingClientSplitRouteLookups <= 0) {
                    return;
                }
                --m_pendingClientSplitRouteLookups;
                if (m_pendingClientSplitRouteLookups != 0) {
                    return;
                }
                if (m_reconnectAfterClientRouteResolution) {
                    m_reconnectAfterClientRouteResolution = false;
                    m_deferredManagedRouteReconnectTimer.stop();
                    qInfo() << "VpnConnection: local DNS resolution completed; queueing a bounded managed-policy reconnect";
                    scheduleManagedRouteReconnect(
                            m_connectionEpoch, m_serverId,
                            QStringLiteral("local DNS resolution completed"));
                    return;
                }
                QTimer::singleShot(0, this, startManagedRoutes);
            };

            if (m_connectionState != Vpn::ConnectionState::Connected
                || m_serverId != activeServerId || m_vpnProtocol.isNull()) {
                finishClientLookup();
                return;
            }

            const QString currentGateway = mode == RouteMode::VpnAllExceptSites
                    ? m_vpnProtocol->routeGateway()
                    : m_vpnProtocol->vpnGateway();
            if (gw != currentGateway) {
                finishClientLookup();
                return;
            }

            QStringList resolvedIps;
            for (const QHostAddress &address : hostInfo.addresses()) {
                if (address.protocol() == QAbstractSocket::IPv4Protocol) {
                    const QString ip = address.toString();
                    if (!resolvedIps.contains(ip)) {
                        resolvedIps.append(ip);
                    }
                }
            }

            QStringList routeIps = resolvedIps;
            if (mode == RouteMode::VpnAllExceptSites) {
                routeIps = splitRoutesKeepingHostsInVpn(routeIps, protectedHosts);
            }
            routeIps = normalizedSupportedIpv4Routes(routableSplitTunnelRoutes(routeIps));

            QStringList newClientRoutes;
            for (const QString &route : routeIps) {
                if (!activeClientRoutes->contains(route)) {
                    newClientRoutes.append(route);
                    activeClientRoutes->insert(route);
                }
            }
            if (!newClientRoutes.isEmpty()) {
                IpcClient::withInterface([gw, newClientRoutes](QSharedPointer<IpcInterfaceReplica> iface) {
                    iface->routeAddList(gw, newClientRoutes);
                });
            }
            // The worker consumes only the immutable connection snapshot. DNS
            // answers are deliberately process-local: persisting here would
            // race a main-thread UI deletion and could resurrect that rule.

            IpcClient::withInterface([](QSharedPointer<IpcInterfaceReplica> iface) {
                auto reply = iface->flushDns();
                if (!reply.waitForFinished(1000) || !reply.returnValue()) {
                    qWarning() << "VpnConnection::addSitesRoutes: Failed to flush DNS";
                }
            });
            finishClientLookup();
        });
    }
#endif
}

VpnConnection::ManagedRouteUpdateResult VpnConnection::updateManagedSplitTunnelRoutes(
        amnezia::RouteMode mode,
        const QStringList &oldRoutes,
        const QStringList &newRoutes,
        const QVariantMap &localSites)
{
    if (QThread::currentThread() != thread()) {
        qCritical() << "VpnConnection: refusing managed route mutation outside the VPN worker thread";
        return ManagedRouteUpdateResult::ReconnectRequired;
    }
#ifdef AMNEZIA_DESKTOP
    if (m_vpnProtocol.isNull() || m_connectionState != Vpn::ConnectionState::Connected
        || mode != RouteMode::VpnAllExceptSites
        || ContainerUtils::isAwgContainer(m_container) || m_container == DockerContainer::WireGuard) {
        return ManagedRouteUpdateResult::ReconnectRequired;
    }

    // Invalidate only stale managed-domain answers. Local lookups remain valid
    // and are allowed to finish before a conservative reconnect applies the
    // new policy.
    ++m_managedSplitRouteResolveGeneration;
    if (m_pendingClientSplitRouteLookups > 0) {
        m_reconnectAfterClientRouteResolution = true;
        if (!m_deferredManagedRouteReconnectTimer.isActive()) {
            m_deferredManagedRouteReconnectTimer.start();
        }
        qInfo() << "VpnConnection: queued managed policy refresh behind"
                << m_pendingClientSplitRouteLookups << "local DNS lookups; reconnect deadline"
                << deferredManagedRouteDeadlineMs << "ms";
        return ManagedRouteUpdateResult::ReconnectDeferred;
    }

    QStringList protectedHosts = serverRoutingRulesSyncHosts();
    protectedHosts << m_vpnConfiguration.value(configKey::dns1).toString()
                   << m_vpnConfiguration.value(configKey::dns2).toString();
    protectedHosts.removeAll(QString());
    protectedHosts.removeDuplicates();

    bool oldManagedRoutesValid = false;
    bool newManagedRoutesValid = false;
    const QStringList normalizedOldRoutes = normalizedManagedRoutesForRuntime(
            mode, oldRoutes, localSites, protectedHosts, &oldManagedRoutesValid);
    const QStringList normalizedNewRoutes = normalizedManagedRoutesForRuntime(
            mode, newRoutes, localSites, protectedHosts, &newManagedRoutesValid);
    if (!oldManagedRoutesValid || !newManagedRoutesValid) {
        qWarning() << "VpnConnection: managed route update failed its immutable snapshot safety boundary";
        return ManagedRouteUpdateResult::ReconnectRequired;
    }

    QSet<QString> oldSet;
    QSet<QString> newSet;
    for (const QString &route : normalizedOldRoutes) {
        oldSet.insert(route);
    }
    for (const QString &route : normalizedNewRoutes) {
        newSet.insert(route);
    }
    QStringList addedRoutes;
    QStringList removedRoutes;
    for (const QString &route : newSet) {
        if (!oldSet.contains(route)) {
            addedRoutes.append(route);
        }
    }
    for (const QString &route : oldSet) {
        if (!newSet.contains(route)) {
            removedRoutes.append(route);
        }
    }
    addedRoutes.sort();
    removedRoutes.sort();
    if (addedRoutes.isEmpty() && removedRoutes.isEmpty()) {
        return ManagedRouteUpdateResult::Updated;
    }
    if (addedRoutes.size() + removedRoutes.size() > maxIncrementalManagedRouteDelta) {
        qInfo() << "VpnConnection: managed route delta is too large for a safe incremental update";
        return ManagedRouteUpdateResult::ReconnectRequired;
    }


    // The current service contract has no transactional replace operation and
    // its delete reply cannot prove that every requested route was removed.
    // Refuse removals before mutating anything; the caller reconnects and the
    // normal route teardown/rebuild path applies the complete policy.
    if (!removedRoutes.isEmpty()) {
        qInfo() << "VpnConnection: managed route removal requires an atomic reconnect; no incremental mutation attempted";
        return ManagedRouteUpdateResult::ReconnectRequired;
    }

    const QString gateway = m_vpnProtocol->routeGateway();
    if (!NetworkUtilities::checkIPv4Format(gateway)) {
        return ManagedRouteUpdateResult::ReconnectRequired;
    }

    const bool updated = IpcClient::withInterface(
            [&gateway, &addedRoutes](QSharedPointer<IpcInterfaceReplica> iface) -> bool {
                auto addReply = iface->routeAddTrustedList(gateway, addedRoutes);
                if (!addReply.waitForFinished(incrementalManagedRouteIpcTimeoutMs)
                    || addReply.returnValue() != addedRoutes.size()) {
                    // A service-side batch can report a partial add. Returning
                    // false makes the caller reconnect, which clears all saved
                    // routes before rebuilding from the current policy.
                    qWarning() << "VpnConnection: incremental managed route add was incomplete; reconnect required";
                    return false;
                }
                return true;
            },
            []() { return false; });

    if (updated) {
        qInfo() << "VpnConnection: incrementally updated managed routes, added" << addedRoutes.size()
                << "removed" << removedRoutes.size();
    }
    return updated ? ManagedRouteUpdateResult::Updated
                   : ManagedRouteUpdateResult::ReconnectRequired;
#else
    Q_UNUSED(mode)
    Q_UNUSED(oldRoutes)
    Q_UNUSED(newRoutes)
    Q_UNUSED(localSites)
    return ManagedRouteUpdateResult::ReconnectRequired;
#endif
}

void VpnConnection::reconcileManagedSplitTunnelRoutes(
        quint64 generation, quint64 expectedConnectionEpoch,
        const QString &expectedServerId, quint64 expectedBaseRevision,
        const QString &expectedPolicyRevision,
        const QString &expectedPolicyContentHash,
        int modeValue, const QStringList &oldRoutes,
        const QStringList &newRoutes,
        const QString &desiredPolicyRevision,
        const QString &desiredPolicyContentHash,
        const QVariantMap &localSites)
{
    if (QThread::currentThread() != thread()) {
        qCritical() << "VpnConnection: refusing managed route reconciliation outside the VPN worker thread";
        emit managedSplitTunnelRoutesReconciled(
                generation, expectedConnectionEpoch, expectedServerId,
                false, false, false,
                static_cast<int>(RouteMode::VpnAllSites), QStringList(),
                0, QString(), QString());
        return;
    }
    const bool generationAccepted = generation > m_latestManagedRouteReconcileGeneration;
    if (generationAccepted) {
        m_latestManagedRouteReconcileGeneration = generation;
    }
    const auto requestedMode = static_cast<RouteMode>(modeValue);
    const bool modeValid = requestedMode == RouteMode::VpnAllSites
            || requestedMode == RouteMode::VpnOnlyForwardSites
            || requestedMode == RouteMode::VpnAllExceptSites;
    const bool expectedIdentityValid =
            managedRoutePolicy::isCanonicalPolicyIdentity(
                    expectedPolicyRevision, expectedPolicyContentHash)
            && (oldRoutes.isEmpty() || !expectedPolicyRevision.isEmpty());
    const bool desiredIdentityValid =
            managedRoutePolicy::isCanonicalPolicyIdentity(
                    desiredPolicyRevision, desiredPolicyContentHash)
            && (newRoutes.isEmpty() || !desiredPolicyRevision.isEmpty());
    const bool bindingMatches = generationAccepted && modeValid
            && expectedIdentityValid && desiredIdentityValid
            && expectedConnectionEpoch == m_connectionEpoch
            && !expectedServerId.isEmpty()
            && expectedServerId == m_serverId
            && m_connectionState == Vpn::ConnectionState::Connected;
    if (!bindingMatches) {
        const ManagedRouteRuntimeSnapshot applied = managedRouteRuntimeSnapshot();
        emit managedSplitTunnelRoutesReconciled(
                generation, m_connectionEpoch, m_serverId, false, false, false,
                static_cast<int>(applied.confirmed
                                         ? applied.mode : RouteMode::VpnAllSites),
                applied.confirmed ? applied.installedRoutes : QStringList(),
                applied.revision,
                applied.confirmed ? applied.policyRevision : QString(),
                applied.confirmed ? applied.policyContentHash : QString());
        return;
    }
    m_managedRouteTransitionPending = true;

    bool expectedOldValid = false;
    bool desiredNewValid = false;
    QStringList protectedHosts = serverRoutingRulesSyncHosts();
    protectedHosts << m_vpnConfiguration.value(configKey::dns1).toString()
                   << m_vpnConfiguration.value(configKey::dns2).toString();
    protectedHosts.removeAll(QString());
    protectedHosts.removeDuplicates();
    const QStringList normalizedExpectedOld = normalizedManagedRoutesForRuntime(
            requestedMode, oldRoutes, localSites, protectedHosts,
            &expectedOldValid);
    const QStringList normalizedDesiredNew = normalizedManagedRoutesForRuntime(
            requestedMode, newRoutes, localSites, protectedHosts,
            &desiredNewValid);
    prepareManagedRouteConnectionSnapshot(
            generation, expectedServerId, modeValue, newRoutes,
            desiredPolicyRevision, desiredPolicyContentHash, localSites);

    const bool baseMatches = expectedOldValid && desiredNewValid
            && m_hasAuthoritativeManagedRouteBase
            && expectedBaseRevision == m_authoritativeManagedRouteBaseRevision
            && expectedConnectionEpoch
                    == m_authoritativeManagedRouteConnectionEpoch
            && expectedServerId == m_authoritativeManagedRouteServerId
            && requestedMode == m_authoritativeManagedRouteMode
            && normalizedExpectedOld == m_authoritativeManagedRoutes
            && expectedPolicyRevision
                    == m_authoritativeManagedRoutePolicyRevision
            && expectedPolicyContentHash
                    == m_authoritativeManagedRoutePolicyContentHash;

    ManagedRouteUpdateResult updateResult = ManagedRouteUpdateResult::ReconnectRequired;
    if (!baseMatches) {
        qWarning() << "VpnConnection: rejected managed-route delta because the expected base no longer matches";
    } else if (normalizedExpectedOld == normalizedDesiredNew) {
        // A content revision may change while the effective route set does
        // not. The authoritative base comparison itself is the receipt.
        updateResult = ManagedRouteUpdateResult::Updated;
    } else if (appliedSiteRouteMode() == requestedMode) {
        updateResult = updateManagedSplitTunnelRoutes(
                requestedMode, oldRoutes, newRoutes, localSites);
    }

    const bool updated = updateResult == ManagedRouteUpdateResult::Updated;
    bool reconnectScheduled = updateResult == ManagedRouteUpdateResult::ReconnectDeferred;
    if (updated) {
        ++m_authoritativeManagedRouteBaseRevision;
        m_hasAuthoritativeManagedRouteBase = true;
        m_managedRouteTransitionPending = false;
        m_authoritativeManagedRouteMode = requestedMode;
        m_authoritativeManagedRoutes = normalizedDesiredNew;
        m_authoritativeManagedRouteConnectionEpoch = m_connectionEpoch;
        m_authoritativeManagedRouteServerId = m_serverId;
        m_authoritativeManagedRoutePolicyRevision = desiredPolicyRevision;
        m_authoritativeManagedRoutePolicyContentHash = desiredPolicyContentHash;
    } else {
        invalidateAuthoritativeManagedRouteBase();
    }
    if (updateResult == ManagedRouteUpdateResult::ReconnectRequired) {
        reconnectScheduled = true;
    }

    emit managedSplitTunnelRoutesReconciled(
            generation, expectedConnectionEpoch, expectedServerId,
            true, updated, reconnectScheduled,
            static_cast<int>(m_hasAuthoritativeManagedRouteBase
                                     ? m_authoritativeManagedRouteMode
                                     : RouteMode::VpnAllSites),
             m_hasAuthoritativeManagedRouteBase
                     ? m_authoritativeManagedRoutes : QStringList(),
             m_authoritativeManagedRouteBaseRevision,
             m_hasAuthoritativeManagedRouteBase
                     ? m_authoritativeManagedRoutePolicyRevision : QString(),
             m_hasAuthoritativeManagedRouteBase
                     ? m_authoritativeManagedRoutePolicyContentHash : QString());

    if (updateResult == ManagedRouteUpdateResult::ReconnectRequired) {
        scheduleManagedRouteReconnect(
                expectedConnectionEpoch, expectedServerId,
                QStringLiteral("managed route reconciliation"));
    }
}

QSharedPointer<VpnProtocol> VpnConnection::vpnProtocol() const
{
    return m_vpnProtocol;
}

void VpnConnection::disconnectSlots()
{
    if (m_vpnProtocol) {
        m_vpnProtocol->disconnect();
    }
}

ErrorCode VpnConnection::lastError() const
{
#ifdef Q_OS_ANDROID
    return ErrorCode::AndroidError;
#endif

    if (m_vpnProtocol.isNull()) {
        return ErrorCode::InternalError;
    }

    return m_vpnProtocol.data()->lastError();
}

Vpn::ConnectionState VpnConnection::connectionState() const
{
    return m_connectionState;
}

void VpnConnection::connectToVpn(const QString &serverId, int serverIndex,
                                 DockerContainer container,
                                 const QJsonObject &vpnConfiguration)
{
    qDebug() << QString("Trying to connect to VPN, server id is %1, container is %2, route mode is")
                        .arg(serverId)
                        .arg(ContainerUtils::containerToString(container))
             << m_preparedManagedRouteMode;

    if (serverId.isEmpty() || serverIndex < 0) {
        qCritical() << "VpnConnection::connectToVpn: invalid server id" << serverId;
        setConnectionState(Vpn::ConnectionState::Error);
        return;
    }
    beginManagedRouteReconnectSession(serverId);

    // A fresh protocol start may reuse the same gateway and route keys. Clear
    // the service registry while the old protocol is still authoritative and
    // retain the bounded receipt; an incomplete teardown makes the next base
    // unknown even if all subsequent additions succeed.
    m_startupRouteTeardownConfirmed = clearSavedRoutesWithReceipt();
    if (!m_startupRouteTeardownConfirmed) {
        qWarning() << "VpnConnection::connectToVpn: saved-route teardown was not confirmed";
    }
    invalidateAllSplitRouteResolutions();
    ++m_connectionEpoch;
    m_connectionRestoredWithoutStartup = false;
    m_remoteAddress = NetworkUtilities::getIPAddress(vpnConfiguration.value(configKey::hostName).toString());
    m_serverIndex = serverIndex;
    m_serverId = serverId;
    m_container = container;
    m_vpnConfiguration = vpnConfiguration;
    setConnectionState(Vpn::ConnectionState::Connecting);

#ifdef AMNEZIA_DESKTOP
    if (m_vpnProtocol) {
        disconnect(m_vpnProtocol.data(), &VpnProtocol::protocolError, this, &VpnConnection::vpnProtocolError);
        m_vpnProtocol->stop();
        m_vpnProtocol.reset();
    }
    appendKillSwitchConfig();
#endif

    appendSplitTunnelingConfig();

#if !defined(Q_OS_ANDROID) && !defined(Q_OS_IOS) && !defined(MACOS_NE)
    m_vpnProtocol.reset(VpnProtocol::factory(container, m_vpnConfiguration));
    if (!m_vpnProtocol) {
        setConnectionState(Vpn::ConnectionState::Error);
        return;
    }
    m_vpnProtocol->prepare();
#elif defined Q_OS_ANDROID
    androidVpnProtocol = createDefaultAndroidVpnProtocol();
    createAndroidConnections();

    m_vpnProtocol.reset(androidVpnProtocol);
#elif defined Q_OS_IOS || defined(MACOS_NE)
    Proto proto = ContainerUtils::defaultProtocol(container);
    IosController::Instance()->connectVpn(proto, m_vpnConfiguration);
    connect(&m_checkTimer, &QTimer::timeout, IosController::Instance(), &IosController::checkStatus);
    return;
#endif

    createProtocolConnections();

    if (ErrorCode err = m_vpnProtocol->start(); err != ErrorCode::NoError) {
        setConnectionState(Vpn::ConnectionState::Error);
        emit vpnProtocolError(err);
    }
}

void VpnConnection::createProtocolConnections()
{
    connect(m_vpnProtocol.data(), &VpnProtocol::protocolError, this, &VpnConnection::vpnProtocolError);
    connect(m_vpnProtocol.data(), &VpnProtocol::connectionStateChanged, this, &VpnConnection::setConnectionState);
    connect(m_vpnProtocol.data(), SIGNAL(bytesChanged(quint64, quint64)), this, SLOT(onBytesChanged(quint64, quint64)));

#ifdef AMNEZIA_DESKTOP
    IpcClient::withInterface([this](QSharedPointer<IpcInterfaceReplica> rep) {
        connect(rep.data(), &IpcInterfaceReplica::networkChanged, this, &VpnConnection::reconnectToVpn, Qt::QueuedConnection);
        connect(rep.data(), &IpcInterfaceReplica::wakeup, this, &VpnConnection::reconnectToVpn, Qt::QueuedConnection);
    });
#endif
}

void VpnConnection::appendKillSwitchConfig()
{
    if (!m_vpnConfiguration.contains(configKey::killSwitchOption)) {
        m_vpnConfiguration.insert(configKey::killSwitchOption, QStringLiteral("false"));
    }
    if (!m_vpnConfiguration.contains(configKey::allowedDnsServers)) {
        m_vpnConfiguration.insert(configKey::allowedDnsServers, QJsonArray());
    }
}

void VpnConnection::appendSplitTunnelingConfig()
{
    bool allowSiteBasedSplitTunneling = true;

    // this block is for old native configs and for old self-hosted configs
    auto protocolName = m_vpnConfiguration.value(configKey::vpnProto).toString();
    if (protocolName == ProtocolUtils::protoToString(Proto::Awg) || protocolName == ProtocolUtils::protoToString(Proto::WireGuard)) {
        allowSiteBasedSplitTunneling = false;
        auto configData = m_vpnConfiguration.value(protocolName + "_config_data").toObject();
        if (configData.value(configKey::allowedIps).isString()) {
            QJsonArray allowedIpsJsonArray = QJsonArray::fromStringList(splitWireGuardList(configData.value(configKey::allowedIps).toString()));
            configData.insert(configKey::allowedIps, allowedIpsJsonArray);
        } else if (configData.value(configKey::allowedIps).isUndefined()) {
            auto nativeConfig = configData.value(configKey::config).toString();
            const QString allowedIpsString = wireGuardNativeConfigValue(nativeConfig, QStringLiteral("AllowedIPs"));
            if (!allowedIpsString.isEmpty()) {
                QJsonArray allowedIpsJsonArray = QJsonArray::fromStringList(splitWireGuardList(allowedIpsString));
                configData.insert(configKey::allowedIps, allowedIpsJsonArray);
            }
        }

        if (configData.value(configKey::persistentKeepAlive).isUndefined()) {
            auto nativeConfig = configData.value(configKey::config).toString();
            const QString persistentKeepaliveString = wireGuardNativeConfigValue(nativeConfig, QStringLiteral("PersistentKeepalive"));
            if (!persistentKeepaliveString.isEmpty()) {
                configData.insert(configKey::persistentKeepAlive, persistentKeepaliveString);
                m_vpnConfiguration.insert(protocolName + "_config_data", configData);
            }
        }

        const bool serverIpv6Available = wireGuardServerHasUsableIpv6Egress(configData);
        m_vpnConfiguration.insert(configKey::serverIpv6Available, serverIpv6Available);
        configData.insert(configKey::serverIpv6Available, serverIpv6Available);

        const QJsonArray rawAllowedIpsJsonArray = configData.value(configKey::allowedIps).isArray()
            ? configData.value(configKey::allowedIps).toArray()
            : defaultWireGuardAllowedIps(serverIpv6Available);
        const QJsonArray allowedIpsJsonArray = allowedIpsWithoutUnavailableIpv6Routes(rawAllowedIpsJsonArray, serverIpv6Available);
        configData.insert(configKey::allowedIps, allowedIpsJsonArray);
        m_vpnConfiguration.insert(protocolName + "_config_data", configData);

        for (const QJsonValue &allowedIpValue : allowedIpsJsonArray) {
            const QString allowedIp = allowedIpValue.toString().trimmed();
            if (allowedIp == QStringLiteral("0.0.0.0/0") || allowedIp == QStringLiteral("::/0")) {
                allowSiteBasedSplitTunneling = true;
                break;
            }
        }
    }

    const bool preparedSnapshotMatches = m_hasPreparedManagedRouteSnapshot
            && m_preparedManagedRouteServerId == m_serverId;
    RouteMode routeMode = preparedSnapshotMatches
            ? m_preparedManagedRouteMode : RouteMode::VpnAllSites;
    QStringList startupManagedRoutes;
    bool startupSnapshotConfirmable = preparedSnapshotMatches;
    QJsonArray sitesJsonArray;
    if (allowSiteBasedSplitTunneling && routeMode != RouteMode::VpnAllSites) {
        QStringList localSites;
        QStringList managedSites = m_preparedManagedRoutes;
        QStringList protectedHosts = serverRoutingRulesSyncHosts();
        protectedHosts << m_vpnConfiguration.value(configKey::dns1).toString()
                       << m_vpnConfiguration.value(configKey::dns2).toString();
        protectedHosts.removeAll(QString());
        protectedHosts.removeDuplicates();
        appendSplitTunnelSiteRoutes(localSites, m_preparedLocalSites,
                                    SplitTunnelRouteSource::Client);
        localSites.removeDuplicates();

        bool managedSitesValid = false;
        managedSites = managedRoutePolicy::validatedManagedRoutes(managedSites, &managedSitesValid);
        if (!managedSitesValid) {
            qWarning() << "VpnConnection: mobile managed route snapshot failed its safety boundary";
            startupSnapshotConfirmable = false;
            managedSites.clear();
        }
        if (routeMode == RouteMode::VpnAllExceptSites) {
            localSites = splitRoutesKeepingHostsInVpn(localSites, protectedHosts);
            managedSites = splitRoutesKeepingHostsInVpn(managedSites, protectedHosts);
            managedSites = managedRoutePolicy::validatedManagedRoutes(managedSites, &managedSitesValid);
            if (!managedSitesValid) {
                qWarning() << "VpnConnection: mobile protected-host expansion exceeded the managed route boundary";
                startupSnapshotConfirmable = false;
                managedSites.clear();
            }
        }
        startupManagedRoutes = managedSites;

        QStringList sites = localSites;
        sites.append(managedSites);
        sites.removeDuplicates();
        for (const auto &site : sites) {
            sitesJsonArray.append(site);
        }

        if (sitesJsonArray.isEmpty()) {
            routeMode = RouteMode::VpnAllSites;
        } else if (routeMode == RouteMode::VpnOnlyForwardSites) {
            sitesJsonArray.append(m_vpnConfiguration.value(configKey::dns1).toString());
            sitesJsonArray.append(m_vpnConfiguration.value(configKey::dns2).toString());
            for (const QString &syncHost : serverRoutingRulesSyncHosts()) {
                sitesJsonArray.append(syncHost);
            }
        }
    } else if (!allowSiteBasedSplitTunneling && routeMode != RouteMode::VpnAllSites) {
        // This legacy protocol shape does not accept the site list through the
        // shared split-tunnel config, so startup cannot receipt the prepared
        // managed snapshot.
        startupSnapshotConfirmable = false;
    }

    if (routeMode == RouteMode::VpnAllSites) {
        startupManagedRoutes.clear();
    }
    if (preparedSnapshotMatches && routeMode != m_preparedManagedRouteMode) {
        startupSnapshotConfirmable = false;
    }
    m_startupManagedRouteServerId = m_serverId;
    m_startupManagedRouteMode = routeMode;
    m_startupManagedRoutes = startupManagedRoutes;
    m_startupManagedRoutePolicyRevision = preparedSnapshotMatches
            ? m_preparedManagedRoutePolicyRevision : QString();
    m_startupManagedRoutePolicyContentHash = preparedSnapshotMatches
            ? m_preparedManagedRoutePolicyContentHash : QString();
    m_startupLocalSites = preparedSnapshotMatches ? m_preparedLocalSites : QVariantMap();
    m_hasStartupManagedRouteSnapshot = startupSnapshotConfirmable;

    m_vpnConfiguration.insert(configKey::splitTunnelType, routeMode);
    m_vpnConfiguration.insert(configKey::splitTunnelSites, sitesJsonArray);

    const int appsRouteModeValue = m_vpnConfiguration.value(configKey::appSplitTunnelType)
                                           .toInt(static_cast<int>(amnezia::AppsRouteMode::VpnAllApps));
    amnezia::AppsRouteMode appsRouteMode = static_cast<amnezia::AppsRouteMode>(appsRouteModeValue);
    QJsonArray appsJsonArray = m_vpnConfiguration.value(configKey::splitTunnelApps).toArray();
    if (appsRouteMode != amnezia::AppsRouteMode::VpnOnlyForwardApps
        && appsRouteMode != amnezia::AppsRouteMode::VpnAllExceptApps) {
        appsRouteMode = amnezia::AppsRouteMode::VpnAllApps;
        appsJsonArray = {};
    } else if (appsRouteMode == amnezia::AppsRouteMode::VpnOnlyForwardApps
               && !m_vpnConfiguration.value(configKey::clientLogs).toObject().isEmpty()
               && !appsJsonArray.contains(QStringLiteral("org.amnezia.vpn"))) {
        // Always-on client-log uploads originate in the Android application.
        // Keep that application inside an allow-list tunnel without consulting
        // repositories from the worker thread.
        appsJsonArray.append(QStringLiteral("org.amnezia.vpn"));
    } else if (appsJsonArray.isEmpty()) {
        appsRouteMode = amnezia::AppsRouteMode::VpnAllApps;
    }

    m_vpnConfiguration.insert(configKey::appSplitTunnelType, appsRouteMode);
    m_vpnConfiguration.insert(configKey::splitTunnelApps, appsJsonArray);

    qDebug() << QString("Site split tunneling is %1, route mode is %2")
                        .arg(preparedSnapshotMatches ? "enabled" : "disabled")
                        .arg(routeMode);
    qDebug() << QString("App split tunneling is %1, route mode is %2")
                        .arg(appsRouteMode != amnezia::AppsRouteMode::VpnAllApps ? "enabled" : "disabled")
                        .arg(appsRouteMode);
}

#ifdef Q_OS_ANDROID
void VpnConnection::restoreConnection(const QString &serverId, int serverIndex,
                                      DockerContainer container, const QJsonObject &vpnConfiguration,
                                      Vpn::ConnectionState state)
{
    beginManagedRouteReconnectSession(serverId);
    invalidateAllSplitRouteResolutions();
    ++m_connectionEpoch;
    m_connectionRestoredWithoutStartup = true;
    m_serverIndex = serverIndex;
    m_serverId = serverId;
    m_container = container;
    m_vpnConfiguration = vpnConfiguration;
    // Restoring a service-owned tunnel is not a new manual connection. Start
    // the floor now so a UI-process restart cannot consume a fresh immediate
    // managed-route reconnect allowance.
    recordReconnectFloor();
    m_remoteAddress = NetworkUtilities::getIPAddress(vpnConfiguration.value(configKey::hostName).toString());

    createAndroidConnections();

    m_vpnProtocol.reset(androidVpnProtocol);

    createProtocolConnections();
    setConnectionState(state);
}

void VpnConnection::createAndroidConnections()
{
    androidVpnProtocol = createDefaultAndroidVpnProtocol();

    connect(AndroidController::instance(), &AndroidController::connectionStateChanged, androidVpnProtocol,
            &AndroidVpnProtocol::setConnectionState);
    connect(AndroidController::instance(), &AndroidController::statisticsUpdated, androidVpnProtocol, &AndroidVpnProtocol::setBytesChanged);
}

AndroidVpnProtocol *VpnConnection::createDefaultAndroidVpnProtocol()
{
    return new AndroidVpnProtocol(m_vpnConfiguration);
}
#endif

#if defined(Q_OS_IOS) || defined(MACOS_NE)
void VpnConnection::startIosVpnWithCurrentConfig()
{
    IosController::Instance()->connectVpn(ContainerUtils::defaultProtocol(m_container), m_vpnConfiguration, true);
}
#endif

QString VpnConnection::bytesPerSecToText(quint64 bytes)
{
    double mbps = bytes * 8 / 1e6;
    return QString("%1 %2").arg(QString::number(mbps, 'f', 2)).arg(tr("Mbps")); // Mbit/s
}

void VpnConnection::reconnectToVpn() {
#if defined(Q_OS_IOS) || defined(MACOS_NE)
    if (m_vpnConfiguration.isEmpty() || m_container == DockerContainer::None
        || m_connectionState != Vpn::ConnectionState::Connected) {
        return;
    }
    recordReconnectFloor();
    m_startupRouteTeardownConfirmed = clearSavedRoutesWithReceipt();
    if (!m_startupRouteTeardownConfirmed) {
        qWarning() << "VpnConnection::reconnectToVpn: saved-route teardown was not confirmed";
    }
    ++m_connectionEpoch;
    invalidateAllSplitRouteResolutions();
    m_connectionRestoredWithoutStartup = false;
    const quint64 reconnectEpoch = m_connectionEpoch;
    const QString reconnectServerId = m_serverId;
    setConnectionState(Vpn::ConnectionState::Reconnecting);
#ifdef AMNEZIA_DESKTOP
    appendKillSwitchConfig();
#endif
    appendSplitTunnelingConfig();
    m_reconnectPending = true;
    IosController::Instance()->disconnectVpn();
    QTimer::singleShot(10000, this, [this, reconnectEpoch, reconnectServerId]() {
        if (reconnectEpoch != m_connectionEpoch || reconnectServerId != m_serverId
            || !m_reconnectPending
            || m_connectionState != Vpn::ConnectionState::Reconnecting) {
            return;
        }
        qWarning() << "Reconnect timeout while waiting for NetworkExtension disconnect, starting VPN";
        m_reconnectPending = false;
        startIosVpnWithCurrentConfig();
    });
    return;
#else
    if (m_vpnProtocol.isNull())
        return;

    if (m_connectionState != Vpn::ConnectionState::Connected) {
        qWarning() << QString("Reconnect triggered on %1 during inappropriate state: %2; ignoring slot")
                              .arg(QMetaEnum::fromType<Vpn::ConnectionState>().valueToKey(m_connectionState));
        return;
    }

    recordReconnectFloor();
    qDebug() << "Reconnect triggered. Reconnecting to the server";
    // The authoritative removal receipt must arrive before protocol signals
    // are disconnected and before the old protocol is stopped. Otherwise a
    // reconnect can strand A+B while later claiming that only A is applied.
    m_startupRouteTeardownConfirmed = clearSavedRoutesWithReceipt();
    if (!m_startupRouteTeardownConfirmed) {
        qWarning() << "VpnConnection::reconnectToVpn: saved-route teardown was not confirmed";
    }
    ++m_connectionEpoch;
    invalidateAllSplitRouteResolutions();
    m_connectionRestoredWithoutStartup = false;
    const quint64 reconnectEpoch = m_connectionEpoch;
    const QString reconnectServerId = m_serverId;

    setConnectionState(Vpn::ConnectionState::Reconnecting);
#ifdef AMNEZIA_DESKTOP
    appendKillSwitchConfig();
#endif
    appendSplitTunnelingConfig();

    const auto startUpdatedProtocol = [this, reconnectEpoch, reconnectServerId]() {
        if (reconnectEpoch != m_connectionEpoch || reconnectServerId != m_serverId
            || m_connectionState != Vpn::ConnectionState::Reconnecting) {
            return;
        }
#ifdef Q_OS_ANDROID
        createAndroidConnections();
        m_vpnProtocol.reset(androidVpnProtocol);
#else
        m_vpnProtocol.reset(VpnProtocol::factory(m_container, m_vpnConfiguration));
        if (!m_vpnProtocol) {
            setConnectionState(Vpn::ConnectionState::Error);
            return;
        }
        m_vpnProtocol->prepare();
#endif
        createProtocolConnections();
        if (ErrorCode err = m_vpnProtocol->start(); err != ErrorCode::NoError) {
            setConnectionState(Vpn::ConnectionState::Error);
            emit vpnProtocolError(err);
        }
    };

    disconnectSlots();
    m_vpnProtocol->stop();
    m_vpnProtocol.reset();
#ifdef Q_OS_ANDROID
    QTimer::singleShot(1000, this, [this, startUpdatedProtocol,
                                   reconnectEpoch, reconnectServerId]() {
        if (reconnectEpoch == m_connectionEpoch && reconnectServerId == m_serverId
            && m_connectionState == Vpn::ConnectionState::Reconnecting) {
            startUpdatedProtocol();
        }
    });
#else
    startUpdatedProtocol();
#endif
#endif
}

void VpnConnection::disconnectFromVpn()
{
    clearManagedRouteReconnectSession();
    m_startupRouteTeardownConfirmed = clearSavedRoutesWithReceipt();
    if (!m_startupRouteTeardownConfirmed) {
        qWarning() << "VpnConnection::disconnectFromVpn: saved-route teardown was not confirmed";
    }
    ++m_connectionEpoch;
    invalidateAllSplitRouteResolutions();
#if defined(Q_OS_IOS) || defined(MACOS_NE)
    // iOS/macOS NE use IosController directly; m_vpnProtocol is not set there.
    IosController::Instance()->disconnectVpn();
    disconnect(&m_checkTimer, &QTimer::timeout, IosController::Instance(), &IosController::checkStatus);
#endif

    if (m_vpnProtocol.isNull()) {
        setConnectionState(Vpn::ConnectionState::Disconnected);
        return;
    }

    setConnectionState(Vpn::ConnectionState::Disconnecting);

#ifdef Q_OS_ANDROID
    auto *const connection = new QMetaObject::Connection;
    *connection = connect(AndroidController::instance(), &AndroidController::vpnStateChanged, this,
                          [this, connection](AndroidController::ConnectionState state) {
                              if (state == AndroidController::ConnectionState::DISCONNECTED) {
                                  setConnectionState(Vpn::ConnectionState::Disconnected);
                                  disconnect(*connection);
                                  delete connection;
                              }
                          });
#endif

    m_vpnProtocol->stop();

#if !defined(Q_OS_ANDROID) && !defined(AMNEZIA_DESKTOP)
    m_vpnProtocol->deleteLater();
#endif

    m_vpnProtocol = nullptr;
}

void VpnConnection::shutdownForApplicationExit(bool disconnectVpn, QThread *destructionThread)
{
    if (QThread::currentThread() != thread()) {
        qCritical() << "VpnConnection: refusing application-exit shutdown outside the VPN worker thread";
        return;
    }
    // Preserve the same teardown-before-signal-disconnect ordering used by a
    // reconnect, but never touch the shared desktop route registry for a
    // read-only operator process that intentionally leaves the live VPN alone.
    if (disconnectVpn) {
        m_startupRouteTeardownConfirmed = clearSavedRoutesWithReceipt();
        if (!m_startupRouteTeardownConfirmed) {
            qWarning() << "VpnConnection::shutdownForApplicationExit: saved-route teardown was not confirmed";
        }
    }
    disconnectSlots();
    m_checkTimer.stop();
    clearManagedRouteReconnectSession();
    if (disconnectVpn) {
        disconnectFromVpn();
    } else {
        // QHostInfo callbacks and the deferred reconnect deadline outlive no
        // process-local protocol owner. Invalidate both generations and stop
        // the timer before releasing the wrapper.
        ++m_connectionEpoch;
        invalidateAllSplitRouteResolutions();
        // The platform VPN may intentionally outlive this process (for
        // example Android's service). Release only the process-local protocol
        // wrapper while it is still in its owning thread.
        m_vpnProtocol.clear();
#ifdef Q_OS_ANDROID
        androidVpnProtocol = nullptr;
#endif
    }
    QThread *const workerThread = QThread::currentThread();
    if (!destructionThread || destructionThread == workerThread
        || !moveToThread(destructionThread)) {
        qFatal("VpnConnection: failed to transfer ownership before worker shutdown");
    }
    workerThread->quit();
}

void VpnConnection::setConnectionState(Vpn::ConnectionState state) {
    onConnectionStateChanged(state);

#if defined(Q_OS_IOS) || defined(MACOS_NE)
    if (state == Vpn::Disconnected && m_connectionState == Vpn::Reconnecting && m_reconnectPending) {
        m_reconnectPending = false;
        startIosVpnWithCurrentConfig();
        return;
    }
#endif

    if (state == Vpn::Disconnected && m_connectionState == Vpn::Reconnecting)
        return;

    m_connectionState = state;
    emit connectionContextChanged(m_serverId, serverRoutingRulesSyncHost(), m_connectionEpoch);
    emit connectionStateChanged(state);
}
