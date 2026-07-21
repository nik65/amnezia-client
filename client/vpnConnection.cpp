#include "vpnConnection.h"

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
#include <QTimer>

#include <functional>

#include <core/configurators/openVpnConfigurator.h>
#include <core/configurators/wireguardConfigurator.h>

#ifdef AMNEZIA_DESKTOP
    #include "core/utils/ipcClient.h"
    #include <core/protocols/wireGuardProtocol.h>
#endif

#ifdef Q_OS_ANDROID
    #include "platforms/android/android_controller.h"
    #include <QThread>

#endif

#if defined(Q_OS_IOS) || defined(MACOS_NE)
    #include "platforms/ios/ios_controller.h"
#endif

#include "core/utils/networkUtilities.h"
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
constexpr int deferredManagedRouteDeadlineMs = 10000;
constexpr int maxConcurrentManagedRouteLookups = 4;

struct ManagedRouteLookupState
{
    QStringList sites;
    qsizetype nextIndex = 0;
    int inFlight = 0;
    std::function<void()> pump;
};

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
}

VpnConnection::VpnConnection(SecureServersRepository* serversRepository, SecureAppSettingsRepository* appSettingsRepository, QObject *parent)
    : QObject(parent), m_serversRepository(serversRepository), m_appSettingsRepository(appSettingsRepository),
      m_checkTimer(this), m_deferredManagedRouteReconnectTimer(this)
{
    m_deferredManagedRouteReconnectTimer.setSingleShot(true);
    m_deferredManagedRouteReconnectTimer.setInterval(deferredManagedRouteDeadlineMs);
    connect(&m_deferredManagedRouteReconnectTimer, &QTimer::timeout, this, [this]() {
        if (!m_reconnectAfterClientRouteResolution || m_pendingClientSplitRouteLookups <= 0) {
            return;
        }

        m_reconnectAfterClientRouteResolution = false;
        qWarning() << "VpnConnection: local DNS resolution exceeded managed policy deadline; reconnecting safely";
        if (m_connectionState == Vpn::ConnectionState::Connected) {
            reconnectToVpn();
        }
    });
#if defined(Q_OS_IOS) || defined(MACOS_NE)
    m_checkTimer.setInterval(1000);
    connect(IosController::Instance(), &IosController::connectionStateChanged, this, &VpnConnection::setConnectionState);
    connect(IosController::Instance(), &IosController::bytesChanged, this, &VpnConnection::onBytesChanged);
#endif
}

VpnConnection::~VpnConnection()
{
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
        if (reply.waitForFinished() && reply.returnValue())
            qDebug() << "VpnConnection::onKillSwitchModeChanged: Killswitch refreshed";
        else
            qWarning() << "VpnConnection::onKillSwitchModeChanged: Failed to execute remote refreshKillSwitch call";
    });
#endif
}

void VpnConnection::onConnectionStateChanged(Vpn::ConnectionState state)
{
#ifdef AMNEZIA_DESKTOP
    if (!m_serversRepository || !m_appSettingsRepository) {
        qCritical() << "VpnConnection::onConnectionStateChanged: repositories not initialized";
        return;
    }

    DockerContainer container = DockerContainer::None;
    if (m_container != DockerContainer::None) {
        container = m_container;
    }
    const int currentServerIndex = serverIndex();
    const int activeServerIndex = currentServerIndex >= 0
            ? currentServerIndex : m_serversRepository->defaultServerIndex();
    const QString activeServerId = m_serverId.isEmpty()
            ? m_serversRepository->serverIdAt(activeServerIndex) : m_serverId;
    switch (m_serversRepository->serverKind(activeServerId)) {
    case serverConfigUtils::ConfigType::SelfHostedAdmin: {
        const auto cfg = m_serversRepository->selfHostedAdminConfig(activeServerId);
        if (cfg.has_value()) {
            if (container == DockerContainer::None) {
                container = cfg->defaultContainer;
            }
        }
        break;
    }
    case serverConfigUtils::ConfigType::SelfHostedUser: {
        const auto cfg = m_serversRepository->selfHostedUserConfig(activeServerId);
        if (cfg.has_value()) {
            if (container == DockerContainer::None) {
                container = cfg->defaultContainer;
            }
        }
        break;
    }
    case serverConfigUtils::ConfigType::Native: {
        const auto cfg = m_serversRepository->nativeConfig(activeServerId);
        if (cfg.has_value()) {
            if (container == DockerContainer::None) {
                container = cfg->defaultContainer;
            }
        }
        break;
    }
    case serverConfigUtils::ConfigType::AmneziaPremiumV2:
    case serverConfigUtils::ConfigType::AmneziaFreeV3:
    case serverConfigUtils::ConfigType::ExternalPremium: {
        const auto cfg = m_serversRepository->apiV2Config(activeServerId);
        if (cfg.has_value()) {
            if (container == DockerContainer::None) {
                container = cfg->defaultContainer;
            }
        }
        break;
    }
    case serverConfigUtils::ConfigType::AmneziaPremiumV1:
    case serverConfigUtils::ConfigType::AmneziaFreeV2:
        break;
    case serverConfigUtils::ConfigType::Invalid:
    default:
        break;
    }

    IpcClient::withInterface([&](QSharedPointer<IpcInterfaceReplica> iface) {
        switch (state) {
            case Vpn::ConnectionState::Connected: {
                iface->resetIpStack();

                auto flushDns = iface->flushDns();
                if (flushDns.waitForFinished() && flushDns.returnValue())
                    qDebug() << "VpnConnection::onConnectionStateChanged: Successfully flushed DNS";
                else
                    qWarning() << "VpnConnection::onConnectionStateChanged: Failed to flush DNS";

                if (!ContainerUtils::isAwgContainer(container) && container != DockerContainer::WireGuard) {
                    QString dns1 = m_vpnConfiguration.value(configKey::dns1).toString();
                    QString dns2 = m_vpnConfiguration.value(configKey::dns2).toString();

                    const RouteMode effectiveRouteMode = m_serversRepository->effectiveSiteRouteMode(
                            activeServerIndex, m_appSettingsRepository->isSitesSplitTunnelingEnabled(),
                            m_appSettingsRepository->routeMode());

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
                            QTimer::singleShot(1000, m_vpnProtocol.data(),
                                               [this, effectiveRouteMode]() { addSitesRoutes(m_vpnProtocol->vpnGateway(), effectiveRouteMode); });
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
                if (flushDns.waitForFinished() && flushDns.returnValue())
                    qDebug() << "VpnConnection::onConnectionStateChanged: Successfully flushed DNS";
                else
                    qWarning() << "VpnConnection::onConnectionStateChanged: Failed to flush DNS";

                auto clearSavedRoutes = iface->clearSavedRoutes();
                if (clearSavedRoutes.waitForFinished() && clearSavedRoutes.returnValue())
                    qDebug() << "VpnConnection::onConnectionStateChanged: Successfully cleared saved routes";
                else
                    qWarning() << "VpnConnection::onConnectionStateChanged: Failed to clear saved routes";
            } break;
            default:
                break;
        }
    });
#endif

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
    if (m_serversRepository && !m_serverId.isEmpty()) {
        return m_serversRepository->indexOfServerId(m_serverId);
    }
    return m_serverIndex;
}

QString VpnConnection::serverId() const
{
    return m_serverId;
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

void VpnConnection::setRepositories(SecureServersRepository* serversRepository, SecureAppSettingsRepository* appSettingsRepository)
{
    if (m_serversRepository) {
        disconnect(m_serversRepository, &SecureServersRepository::serverRemoved, this, nullptr);
    }
    m_serversRepository = serversRepository;
    m_appSettingsRepository = appSettingsRepository;
    if (m_serversRepository) {
        connect(m_serversRepository, &SecureServersRepository::serverRemoved, this,
                [this](const QString &removedServerId, int removedIndex) {
            Q_UNUSED(removedIndex)
            if (removedServerId != m_serverId) {
                m_serverIndex = m_serverId.isEmpty()
                        ? -1 : m_serversRepository->indexOfServerId(m_serverId);
                return;
            }

            qWarning() << "VpnConnection: active server was removed; disconnecting the bound VPN session";
            m_serverId.clear();
            m_serverIndex = -1;
            invalidateAllSplitRouteResolutions();
            if (m_connectionState != Vpn::ConnectionState::Disconnected
                && m_connectionState != Vpn::ConnectionState::Disconnecting
                && m_connectionState != Vpn::ConnectionState::Unknown) {
                disconnectFromVpn();
            }
        }, Qt::QueuedConnection);
    }
}

void VpnConnection::invalidateAllSplitRouteResolutions()
{
    ++m_clientSplitRouteResolveGeneration;
    ++m_managedSplitRouteResolveGeneration;
    m_pendingClientSplitRouteLookups = 0;
    m_reconnectAfterClientRouteResolution = false;
    m_deferredManagedRouteReconnectTimer.stop();
}

void VpnConnection::addSitesRoutes(const QString &gw, amnezia::RouteMode mode)
{
#ifdef AMNEZIA_DESKTOP
    if (!m_appSettingsRepository || !m_serversRepository) {
        qCritical() << "VpnConnection::addSitesRoutes: repositories not initialized";
        return;
    }

    const int currentServerIndex = serverIndex();
    const int activeServerIndex = currentServerIndex >= 0
            ? currentServerIndex : m_serversRepository->defaultServerIndex();
    const QString activeServerId = m_serverId.isEmpty()
            ? m_serversRepository->serverIdAt(activeServerIndex) : m_serverId;
    const quint64 clientResolveGeneration = ++m_clientSplitRouteResolveGeneration;
    const quint64 managedResolveGeneration = ++m_managedSplitRouteResolveGeneration;
    m_pendingClientSplitRouteLookups = 0;
    m_reconnectAfterClientRouteResolution = false;
    m_deferredManagedRouteReconnectTimer.stop();
    QStringList ips;
    QStringList managedIps;
    QStringList clientSites;
    QStringList managedSitesToResolve;
    QStringList protectedHosts = serverRoutingRulesSyncHosts();
    protectedHosts << m_vpnConfiguration.value(configKey::dns1).toString()
                   << m_vpnConfiguration.value(configKey::dns2).toString();
    protectedHosts.removeAll(QString());
    protectedHosts.removeDuplicates();
    const QVariantMap localSitesSnapshot = m_appSettingsRepository->vpnSites(mode);
    for (auto i = localSitesSnapshot.constBegin(); i != localSitesSnapshot.constEnd(); ++i) {
        if (NetworkUtilities::checkIpSubnetFormat(i.key())) {
            appendSplitTunnelRoute(ips, i.key(), SplitTunnelRouteSource::Client);
        } else {
            appendSplitTunnelRoutes(ips, splitTunnelStoredIps(i.value().toString()), SplitTunnelRouteSource::Client);
            clientSites.append(i.key());
        }
    }

    const QVariantMap managedSites = m_serversRepository->managedVpnSitesForRouting(activeServerIndex, mode);
    qsizetype managedSiteCount = 0;
    bool managedRoutesValid = true;
    for (auto i = managedSites.constBegin(); i != managedSites.constEnd(); ++i) {
        if (managedSiteCount++ >= managedRoutePolicy::maximumSiteCount) {
            qWarning() << "VpnConnection: managed route set exceeds the safe site limit; ignoring the remainder";
            break;
        }
        if (NetworkUtilities::checkIpSubnetFormat(i.key())) {
            if (!managedRoutePolicy::isAllowedManagedIpv4Route(i.key())) {
                managedRoutesValid = false;
                break;
            }
            appendSplitTunnelRoute(managedIps, i.key(), SplitTunnelRouteSource::ServerManaged);
        } else {
            bool valueValid = false;
            const QStringList storedRoutes = managedRoutePolicy::validatedManagedRouteTokens(
                    i.value().toString(), &valueValid);
            if (!valueValid || !managedRoutePolicy::isAllowedManagedSiteKey(i.key())) {
                managedRoutesValid = false;
                break;
            }
            appendSplitTunnelRoutes(managedIps, storedRoutes, SplitTunnelRouteSource::ServerManaged);
            managedSitesToResolve.append(i.key());
        }
    }
    bool managedBatchValid = false;
    managedIps = managedRoutePolicy::validatedManagedRoutes(managedIps, &managedBatchValid);
    if (!managedRoutesValid || !managedBatchValid) {
        qWarning() << "VpnConnection: rejected unsafe or oversized server-managed route snapshot";
        managedIps.clear();
        managedSitesToResolve.clear();
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
        managedIps.clear();
        managedSitesToResolve.clear();
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
    }

    auto activeClientRoutes = QSharedPointer<QSet<QString>>::create();
    for (const QString &route : ips) {
        activeClientRoutes->insert(route);
    }
    auto activeManagedRoutes = QSharedPointer<QSet<QString>>::create();

    // The existing IPC protocol has no transactional asynchronous route-add
    // receipt. Initial connection/DNS additions therefore remain best-effort;
    // making them confirmable requires a versioned service contract change.
    IpcClient::withInterface([gw, ips](QSharedPointer<IpcInterfaceReplica> iface) {
        if (!ips.isEmpty()) {
            iface->routeAddList(gw, ips);
        }
    });

    // Managed routes are installed only after local domains finish resolving.
    // This makes the source boundary explicit: an address learned from a user
    // rule is never subsequently sent through the trusted managed-route API.
    const auto startManagedRoutes = [this, gw, mode, managedIps, managedSitesToResolve, protectedHosts,
                                     activeServerId, managedResolveGeneration, activeClientRoutes,
                                     activeManagedRoutes]() {
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
                activeManagedRoutes->insert(route);
            }
        }
        if (!managedOnlyRoutes.isEmpty()) {
            IpcClient::withInterface([gw, managedOnlyRoutes](QSharedPointer<IpcInterfaceReplica> iface) {
                iface->routeAddTrustedList(gw, managedOnlyRoutes);
            });
        }

        auto lookupState = QSharedPointer<ManagedRouteLookupState>::create();
        lookupState->sites = managedSitesToResolve.mid(0, managedRoutePolicy::maximumSiteCount);
        const QWeakPointer<ManagedRouteLookupState> weakLookupState(lookupState);
        lookupState->pump = [this, gw, mode, protectedHosts, activeServerId, managedResolveGeneration,
                             activeClientRoutes, activeManagedRoutes, weakLookupState]() {
            const auto state = weakLookupState.toStrongRef();
            if (!state) {
                return;
            }
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

            while (state->inFlight < maxConcurrentManagedRouteLookups
                   && state->nextIndex < state->sites.size()) {
                const QString site = state->sites.at(state->nextIndex++);
                ++state->inFlight;
                QHostInfo::lookupHost(site, this,
                                      [this, gw, mode, protectedHosts, activeServerId, managedResolveGeneration,
                                       activeClientRoutes, activeManagedRoutes, state](const QHostInfo &hostInfo) {
                    --state->inFlight;
                    if (managedResolveGeneration == m_managedSplitRouteResolveGeneration
                        && m_connectionState == Vpn::ConnectionState::Connected
                        && m_serverId == activeServerId && !m_vpnProtocol.isNull()) {
                        const QString currentGateway = mode == RouteMode::VpnAllExceptSites
                                ? m_vpnProtocol->routeGateway()
                                : m_vpnProtocol->vpnGateway();
                        if (gw == currentGateway) {
                            QStringList resolvedRoutes;
                            for (const QHostAddress &address : hostInfo.addresses()) {
                                const QString route = address.toString();
                                if (address.protocol() == QAbstractSocket::IPv4Protocol
                                    && managedRoutePolicy::isAllowedManagedIpv4Route(route)
                                    && !resolvedRoutes.contains(route)) {
                                    resolvedRoutes.append(route);
                                    if (resolvedRoutes.size() >= managedRoutePolicy::maximumRoutesPerSite) {
                                        break;
                                    }
                                }
                            }
                            if (mode == RouteMode::VpnAllExceptSites) {
                                resolvedRoutes = splitRoutesKeepingHostsInVpn(resolvedRoutes, protectedHosts);
                            }
                            resolvedRoutes = normalizedSupportedIpv4Routes(resolvedRoutes);

                            QStringList managedOnlyRoutes;
                            for (const QString &route : resolvedRoutes) {
                                if (activeManagedRoutes->size()
                                    >= managedRoutePolicy::maximumTotalRouteCount) {
                                    qWarning() << "VpnConnection: managed DNS route budget exhausted";
                                    break;
                                }
                                if (!activeClientRoutes->contains(route)
                                    && !activeManagedRoutes->contains(route)) {
                                    managedOnlyRoutes.append(route);
                                    activeManagedRoutes->insert(route);
                                }
                            }
                            if (!managedOnlyRoutes.isEmpty()) {
                                IpcClient::withInterface(
                                        [gw, managedOnlyRoutes](QSharedPointer<IpcInterfaceReplica> iface) {
                                    iface->routeAddTrustedList(gw, managedOnlyRoutes);
                                });
                            }
                        }
                    }

                    if (state->pump) {
                        QTimer::singleShot(0, this, [state]() {
                            if (state->pump) {
                                state->pump();
                            }
                        });
                    }
                });
            }
        };
        lookupState->pump();
    };

    m_pendingClientSplitRouteLookups = clientSites.size();
    if (clientSites.isEmpty()) {
        QTimer::singleShot(0, this, startManagedRoutes);
        return;
    }

    for (const QString &site : clientSites) {
        const QVariant expectedSiteValue = localSitesSnapshot.value(site);
        QHostInfo::lookupHost(site, this,
                              [this, site, gw, mode, protectedHosts, activeServerId, clientResolveGeneration,
                               expectedSiteValue, activeClientRoutes, startManagedRoutes](const QHostInfo &hostInfo) {
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
                    qInfo() << "VpnConnection: local DNS resolution completed; reconnecting to apply deferred managed policy safely";
                    QTimer::singleShot(0, this, [this]() {
                        if (m_connectionState == Vpn::ConnectionState::Connected) {
                            reconnectToVpn();
                        }
                    });
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

            // DNS completion is not ownership: the user may have removed the
            // rule or changed its stored value while the lookup was pending.
            // Only the exact snapshot that launched this lookup may update it.
            const QVariantMap currentLocalSites = m_appSettingsRepository->vpnSites(mode);
            if (!currentLocalSites.contains(site) || currentLocalSites.value(site) != expectedSiteValue) {
                qInfo() << "VpnConnection: ignoring a stale local split-route DNS result";
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
            if (!resolvedIps.isEmpty()) {
                m_appSettingsRepository->addVpnSite(mode, site, resolvedIps.join(QStringLiteral(", ")));
            }

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

bool VpnConnection::updateManagedSplitTunnelRoutes(amnezia::RouteMode mode,
                                                    const QStringList &oldRoutes,
                                                    const QStringList &newRoutes)
{
#ifdef AMNEZIA_DESKTOP
    if (!m_serversRepository || !m_appSettingsRepository || m_vpnProtocol.isNull()
        || m_connectionState != Vpn::ConnectionState::Connected
        || mode != RouteMode::VpnAllExceptSites
        || ContainerUtils::isAwgContainer(m_container) || m_container == DockerContainer::WireGuard) {
        return false;
    }

    const RouteMode effectiveMode = m_serversRepository->effectiveSiteRouteMode(
            serverIndex(), m_appSettingsRepository->isSitesSplitTunnelingEnabled(),
            m_appSettingsRepository->routeMode());
    if (effectiveMode != mode) {
        return false;
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
        return true;
    }

    QStringList protectedHosts = serverRoutingRulesSyncHosts();
    protectedHosts << m_vpnConfiguration.value(configKey::dns1).toString()
                   << m_vpnConfiguration.value(configKey::dns2).toString();
    protectedHosts.removeAll(QString());
    protectedHosts.removeDuplicates();

    QStringList localRoutes;
    appendSplitTunnelSiteRoutes(localRoutes, m_appSettingsRepository->vpnSites(mode), SplitTunnelRouteSource::Client);
    localRoutes = splitRoutesKeepingHostsInVpn(localRoutes, protectedHosts);
    localRoutes = normalizedSupportedIpv4Routes(localRoutes);

    QStringList unsupportedOldRoutes;
    QStringList unsupportedNewRoutes;
    bool oldManagedRoutesValid = false;
    bool newManagedRoutesValid = false;
    const QStringList boundedOldRoutes = managedRoutePolicy::validatedManagedRoutes(
            oldRoutes, &oldManagedRoutesValid);
    const QStringList boundedNewRoutes = managedRoutePolicy::validatedManagedRoutes(
            newRoutes, &newManagedRoutesValid);
    if (!oldManagedRoutesValid || !newManagedRoutesValid) {
        qWarning() << "VpnConnection: managed route update failed its safety boundary";
        return false;
    }
    QStringList normalizedOldRoutes = normalizedSupportedIpv4Routes(
            splitRoutesKeepingHostsInVpn(boundedOldRoutes, protectedHosts), &unsupportedOldRoutes);
    QStringList normalizedNewRoutes = normalizedSupportedIpv4Routes(
            splitRoutesKeepingHostsInVpn(boundedNewRoutes, protectedHosts), &unsupportedNewRoutes);
    normalizedOldRoutes = managedRoutePolicy::validatedManagedRoutes(
            normalizedOldRoutes, &oldManagedRoutesValid);
    normalizedNewRoutes = managedRoutePolicy::validatedManagedRoutes(
            normalizedNewRoutes, &newManagedRoutesValid);
    if (!oldManagedRoutesValid || !newManagedRoutesValid) {
        qWarning() << "VpnConnection: managed route update expansion exceeded its safety boundary";
        return false;
    }
    unsupportedOldRoutes.removeDuplicates();
    unsupportedNewRoutes.removeDuplicates();
    unsupportedOldRoutes.sort();
    unsupportedNewRoutes.sort();
    if (unsupportedOldRoutes != unsupportedNewRoutes) {
        qInfo() << "VpnConnection: managed route delta contains changed non-IPv4 or non-canonical routes; reconnect required";
        return false;
    }

    QSet<QString> oldSet;
    QSet<QString> newSet;
    for (const QString &route : normalizedOldRoutes) {
        oldSet.insert(route);
    }
    for (const QString &route : normalizedNewRoutes) {
        newSet.insert(route);
    }
    for (const QString &localRoute : localRoutes) {
        oldSet.remove(localRoute);
        newSet.remove(localRoute);
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
        return true;
    }
    if (addedRoutes.size() + removedRoutes.size() > maxIncrementalManagedRouteDelta) {
        qInfo() << "VpnConnection: managed route delta is too large for a safe incremental update";
        return false;
    }


    // The current service contract has no transactional replace operation and
    // its delete reply cannot prove that every requested route was removed.
    // Refuse removals before mutating anything; the caller reconnects and the
    // normal route teardown/rebuild path applies the complete policy.
    if (!removedRoutes.isEmpty()) {
        qInfo() << "VpnConnection: managed route removal requires an atomic reconnect; no incremental mutation attempted";
        return false;
    }

    const QString gateway = m_vpnProtocol->routeGateway();
    if (!NetworkUtilities::checkIPv4Format(gateway)) {
        return false;
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
    return updated;
#else
    Q_UNUSED(mode)
    Q_UNUSED(oldRoutes)
    Q_UNUSED(newRoutes)
    return false;
#endif
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

void VpnConnection::connectToVpn(const QString &serverId, DockerContainer container, const QJsonObject &vpnConfiguration)
{
    if (!m_appSettingsRepository || !m_serversRepository) {
        qCritical() << "VpnConnection::connectToVpn: repositories not initialized";
        setConnectionState(Vpn::ConnectionState::Error);
        return;
    }

    qDebug() << QString("Trying to connect to VPN, server id is %1, container is %2, route mode is")
                        .arg(serverId)
                        .arg(ContainerUtils::containerToString(container))
             << m_appSettingsRepository->routeMode();

    const int serverIndex = m_serversRepository->indexOfServerId(serverId);
    if (serverIndex < 0) {
        qCritical() << "VpnConnection::connectToVpn: invalid server id" << serverId;
        setConnectionState(Vpn::ConnectionState::Error);
        return;
    }

    invalidateAllSplitRouteResolutions();
    m_remoteAddress = NetworkUtilities::getIPAddress(vpnConfiguration.value(configKey::hostName).toString());
    m_serverIndex = serverIndex;
    m_serverId = serverId;
    m_container = container;
    setConnectionState(Vpn::ConnectionState::Connecting);

    m_vpnConfiguration = vpnConfiguration;

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
    if (!m_appSettingsRepository) {
        qCritical() << "VpnConnection::appendKillSwitchConfig: repositories not initialized";
        return;
    }

    m_vpnConfiguration.insert(configKey::killSwitchOption, QVariant(m_appSettingsRepository->isKillSwitchEnabled()).toString());
    m_vpnConfiguration.insert(configKey::allowedDnsServers, QVariant(m_appSettingsRepository->getAllowedDnsServers()).toJsonValue());
}

void VpnConnection::appendSplitTunnelingConfig()
{
    if (!m_appSettingsRepository || !m_serversRepository) {
        qCritical() << "VpnConnection::appendSplitTunnelingConfig: repositories not initialized";
        return;
    }

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

    const int currentServerIndex = serverIndex();
    const int activeServerIndex = currentServerIndex >= 0
            ? currentServerIndex : m_serversRepository->defaultServerIndex();
    RouteMode routeMode = m_serversRepository->effectiveSiteRouteMode(
            activeServerIndex, m_appSettingsRepository->isSitesSplitTunnelingEnabled(), m_appSettingsRepository->routeMode());
    QJsonArray sitesJsonArray;
    if (allowSiteBasedSplitTunneling && routeMode != RouteMode::VpnAllSites) {
        QStringList localSites;
        QStringList managedSites;
        QStringList protectedHosts = serverRoutingRulesSyncHosts();
        protectedHosts << m_vpnConfiguration.value(configKey::dns1).toString()
                       << m_vpnConfiguration.value(configKey::dns2).toString();
        protectedHosts.removeAll(QString());
        protectedHosts.removeDuplicates();
        appendSplitTunnelSiteRoutes(localSites, m_appSettingsRepository->vpnSites(routeMode),
                                    SplitTunnelRouteSource::Client);
        appendSplitTunnelSiteRoutes(managedSites,
                                    m_serversRepository->managedVpnSitesForRouting(activeServerIndex, routeMode),
                                    SplitTunnelRouteSource::ServerManaged);
        localSites.removeDuplicates();

        bool managedSitesValid = false;
        managedSites = managedRoutePolicy::validatedManagedRoutes(managedSites, &managedSitesValid);
        if (!managedSitesValid) {
            qWarning() << "VpnConnection: mobile managed route snapshot failed its safety boundary";
            managedSites.clear();
        }
        if (routeMode == RouteMode::VpnAllExceptSites) {
            localSites = splitRoutesKeepingHostsInVpn(localSites, protectedHosts);
            managedSites = splitRoutesKeepingHostsInVpn(managedSites, protectedHosts);
            managedSites = managedRoutePolicy::validatedManagedRoutes(managedSites, &managedSitesValid);
            if (!managedSitesValid) {
                qWarning() << "VpnConnection: mobile protected-host expansion exceeded the managed route boundary";
                managedSites.clear();
            }
        }

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
    }

    m_vpnConfiguration.insert(configKey::splitTunnelType, routeMode);
    m_vpnConfiguration.insert(configKey::splitTunnelSites, sitesJsonArray);

    amnezia::AppsRouteMode appsRouteMode = amnezia::AppsRouteMode::VpnAllApps;
    QJsonArray appsJsonArray;
    if (m_appSettingsRepository->isAppsSplitTunnelingEnabled()) {
        appsRouteMode = m_appSettingsRepository->appsRouteMode();

        auto apps = m_appSettingsRepository->vpnApps(appsRouteMode);
        for (const auto &app : apps) {
            appsJsonArray.append(app.appPath.isEmpty() ? app.packageName : app.appPath);
        }
        if (appsRouteMode == amnezia::AppsRouteMode::VpnOnlyForwardApps
            && !m_vpnConfiguration.value(configKey::clientLogs).toObject().isEmpty()) {
            appsJsonArray.append(QStringLiteral("org.amnezia.vpn"));
        }

        if (appsJsonArray.isEmpty()) {
            appsRouteMode = amnezia::AppsRouteMode::VpnAllApps;
        }
    }

    m_vpnConfiguration.insert(configKey::appSplitTunnelType, appsRouteMode);
    m_vpnConfiguration.insert(configKey::splitTunnelApps, appsJsonArray);

    qDebug() << QString("Site split tunneling is %1, route mode is %2")
                        .arg(m_appSettingsRepository->isSitesSplitTunnelingEnabled() ? "enabled" : "disabled")
                        .arg(routeMode);
    qDebug() << QString("App split tunneling is %1, route mode is %2")
                        .arg(m_appSettingsRepository->isAppsSplitTunnelingEnabled() ? "enabled" : "disabled")
                        .arg(appsRouteMode);
}

#ifdef Q_OS_ANDROID
void VpnConnection::restoreConnection(int serverIndex, DockerContainer container, const QJsonObject &vpnConfiguration,
                                      Vpn::ConnectionState state)
{
    m_serverIndex = serverIndex;
    m_serverId = m_serversRepository ? m_serversRepository->serverIdAt(serverIndex) : QString();
    m_container = container;
    m_vpnConfiguration = vpnConfiguration;
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
    invalidateAllSplitRouteResolutions();
    setConnectionState(Vpn::ConnectionState::Reconnecting);
#ifdef AMNEZIA_DESKTOP
    appendKillSwitchConfig();
#endif
    appendSplitTunnelingConfig();
    m_reconnectPending = true;
    IosController::Instance()->disconnectVpn();
    QTimer::singleShot(10000, this, [this]() {
        if (!m_reconnectPending || m_connectionState != Vpn::ConnectionState::Reconnecting) {
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

    qDebug() << "Reconnect triggered. Reconnecting to the server";
    invalidateAllSplitRouteResolutions();

    setConnectionState(Vpn::ConnectionState::Reconnecting);
#ifdef AMNEZIA_DESKTOP
    appendKillSwitchConfig();
#endif
    appendSplitTunnelingConfig();

    const auto startUpdatedProtocol = [this]() {
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
    QTimer::singleShot(1000, this, [this, startUpdatedProtocol]() {
        if (m_connectionState == Vpn::ConnectionState::Reconnecting) {
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
    emit connectionStateChanged(state);
}
