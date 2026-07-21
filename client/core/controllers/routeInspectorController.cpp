#include "routeInspectorController.h"

#include <QAbstractSocket>
#include <QHostAddress>
#include <QHostInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMetaObject>
#include <QRegularExpression>
#include <QSet>
#include <QThread>
#include <QTimer>
#include <QUrl>
#include <QVariantList>

#include <algorithm>

#include "core/repositories/secureAppSettingsRepository.h"
#include "core/repositories/secureServersRepository.h"
#include "core/utils/constants/configKeys.h"
#include "core/utils/constants/protocolConstants.h"
#include "core/utils/networkUtilities.h"
#include "core/utils/routeModes.h"
#include "vpnConnection.h"

using namespace amnezia;

namespace
{
constexpr int maxInputLength = 2048;
constexpr int maxHostLength = 253;
constexpr int maxRuleOutputLength = 255;
constexpr int maxPolicyRevisionLength = 128;
constexpr int maxResolvedAddressesPerFamily = 16;
constexpr int maxResolvedAddressesForMatching = 64;
constexpr int maxStoredRoutesPerRule = 64;
constexpr int dnsLookupTimeoutMs = 8000;

struct NormalizedTarget
{
    QString host;
    QHostAddress literalAddress;
    QString error;
};

struct RuleMatch
{
    bool matched = false;
    QString source;
    QString rule;
    QString matchType;
    QString safetyTransform;
    int score = -1;
};

struct ProtectedRouteContext
{
    QSet<QHostAddress> vpnAddresses;
    QSet<QHostAddress> directAddresses;
};

struct VpnConnectionSnapshot
{
    bool connected = false;
    int serverIndex = -1;
    QString remoteAddress;
    QString serverRoutingRulesSyncHost;
    QString vpnGateway;
    DockerContainer container = DockerContainer::None;
};

VpnConnectionSnapshot takeVpnConnectionSnapshot(VpnConnection *vpnConnection)
{
    VpnConnectionSnapshot snapshot;
    if (!vpnConnection) {
        return snapshot;
    }

    const auto capture = [vpnConnection, &snapshot]() {
        snapshot.connected = vpnConnection->connectionState() == Vpn::ConnectionState::Connected;
        if (!snapshot.connected) {
            return;
        }

        snapshot.serverIndex = vpnConnection->serverIndex();
        snapshot.remoteAddress = vpnConnection->remoteAddress();
        snapshot.serverRoutingRulesSyncHost = vpnConnection->serverRoutingRulesSyncHost();
        snapshot.container = vpnConnection->container();
        const QSharedPointer<VpnProtocol> protocol = vpnConnection->vpnProtocol();
        if (protocol) {
            snapshot.vpnGateway = protocol->vpnGateway();
        }
    };

    QThread *const ownerThread = vpnConnection->thread();
    if (!ownerThread) {
        return {};
    }
    if (QThread::currentThread() == ownerThread) {
        capture();
        return snapshot;
    }
    if (!ownerThread->isRunning()) {
        return {};
    }

    if (!QMetaObject::invokeMethod(vpnConnection, capture, Qt::BlockingQueuedConnection)) {
        return {};
    }
    return snapshot;
}

QString bounded(const QString &value, int maximumLength)
{
    return value.left(maximumLength);
}

bool hasControlCharacters(const QString &value)
{
    return std::any_of(value.cbegin(), value.cend(), [](QChar character) {
        return character.category() == QChar::Other_Control;
    });
}

bool isValidAceHostname(const QString &host)
{
    if (host.isEmpty() || host.size() > maxHostLength) {
        return false;
    }

    static const QRegularExpression labelExpression(
            QStringLiteral("^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"));
    const QStringList labels = host.split(QLatin1Char('.'), Qt::KeepEmptyParts);
    for (const QString &label : labels) {
        if (label.size() > 63 || !labelExpression.match(label).hasMatch()) {
            return false;
        }
    }
    return true;
}

NormalizedTarget normalizeTarget(const QString &input)
{
    NormalizedTarget target;
    const QString trimmed = input.trimmed();
    if (trimmed.isEmpty()) {
        target.error = QStringLiteral("host_required");
        return target;
    }
    if (trimmed.size() > maxInputLength || hasControlCharacters(trimmed)) {
        target.error = QStringLiteral("invalid_host");
        return target;
    }

    QString candidate = trimmed;
    if (candidate.startsWith(QLatin1Char('[')) && candidate.endsWith(QLatin1Char(']'))) {
        candidate = candidate.mid(1, candidate.size() - 2);
    }

    QHostAddress literalAddress;
    if (literalAddress.setAddress(candidate)) {
        // Interface scope identifiers reveal local interface names and are not
        // useful for portable routing explanations.
        if (!literalAddress.scopeId().isEmpty()) {
            target.error = QStringLiteral("scoped_ipv6_not_supported");
            return target;
        }
        target.literalAddress = literalAddress;
        target.host = literalAddress.toString().toLower();
        return target;
    }

    QString hostname;
    const bool hasScheme = trimmed.contains(QStringLiteral("://"));
    const bool needsUrlParsing = hasScheme || trimmed.startsWith(QStringLiteral("//"))
            || trimmed.contains(QLatin1Char('/')) || trimmed.contains(QLatin1Char('?'))
            || trimmed.contains(QLatin1Char('#')) || trimmed.contains(QLatin1Char('@'))
            || trimmed.contains(QLatin1Char(':'));
    if (needsUrlParsing) {
        QString urlText = trimmed;
        if (urlText.startsWith(QStringLiteral("//"))) {
            urlText.prepend(QStringLiteral("route:"));
        } else if (!hasScheme) {
            urlText.prepend(QStringLiteral("route://"));
        }
        const QUrl url(urlText, QUrl::StrictMode);
        if (!url.isValid() || url.host().isEmpty()) {
            target.error = QStringLiteral("invalid_host");
            return target;
        }
        hostname = url.host();
    } else {
        hostname = trimmed;
    }

    while (hostname.endsWith(QLatin1Char('.'))) {
        hostname.chop(1);
    }

    if (literalAddress.setAddress(hostname)) {
        if (!literalAddress.scopeId().isEmpty()) {
            target.error = QStringLiteral("scoped_ipv6_not_supported");
            return target;
        }
        target.literalAddress = literalAddress;
        target.host = literalAddress.toString().toLower();
        return target;
    }

    const QByteArray ace = QUrl::toAce(hostname);
    const QString normalized = QString::fromLatin1(ace).toLower();
    if (!isValidAceHostname(normalized)) {
        target.error = QStringLiteral("invalid_host");
        return target;
    }

    target.host = normalized;
    return target;
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

bool addressMatchesRoute(const QHostAddress &address, const QString &route, int *prefixLength = nullptr)
{
    if (address.isNull()) {
        return false;
    }

    const QString trimmedRoute = route.trimmed();
    QHostAddress routeAddress;
    if (!trimmedRoute.contains(QLatin1Char('/')) && routeAddress.setAddress(trimmedRoute)) {
        if (prefixLength) {
            *prefixLength = routeAddress.protocol() == QAbstractSocket::IPv4Protocol ? 32 : 128;
        }
        return address == routeAddress;
    }

    const QPair<QHostAddress, int> subnet = QHostAddress::parseSubnet(trimmedRoute);
    if (subnet.second < 0 || subnet.first.protocol() != address.protocol()) {
        return false;
    }
    if (prefixLength) {
        *prefixLength = subnet.second;
    }
    return address.isInSubnet(subnet.first, subnet.second);
}

QStringList storedRouteTokens(const QVariant &value)
{
    QStringList tokens;
    static const QRegularExpression separator(QStringLiteral("[,;\\s]+"));
    const QStringList parts = value.toString().split(separator, Qt::SkipEmptyParts);
    for (const QString &part : parts) {
        const QString route = part.trimmed();
        // VpnConnection deliberately accepts only IPv4 hosts/CIDRs from the
        // client-side route store. Keeping the same parser here prevents the
        // inspector from promising IPv6 or malformed routes that are never
        // installed by the runtime.
        if (route.size() <= 128 && NetworkUtilities::checkIpSubnetFormat(route)
            && !tokens.contains(route)) {
            tokens.append(route);
            if (tokens.size() >= maxStoredRoutesPerRule) {
                return tokens;
            }
        }
    }
    return tokens;
}

QString normalizedDomainRule(const QString &rawRule)
{
    QString rule = rawRule.trimmed().toLower();
    const NormalizedTarget target = normalizeTarget(rule);
    if (!target.error.isEmpty() || !target.literalAddress.isNull()) {
        return {};
    }
    return target.host;
}

QString privacySafeRule(const QString &rawRule)
{
    const QString trimmedRule = rawRule.trimmed();
    const QPair<QHostAddress, int> subnet = QHostAddress::parseSubnet(trimmedRule);
    if (subnet.second >= 0) {
        const int maximumPrefix = subnet.first.protocol() == QAbstractSocket::IPv4Protocol ? 32 : 128;
        if (subnet.second <= maximumPrefix) {
            const int exactPrefix = maximumPrefix;
            return subnet.second == exactPrefix && !trimmedRule.contains(QLatin1Char('/'))
                    ? subnet.first.toString().toLower()
                    : QStringLiteral("%1/%2").arg(subnet.first.toString().toLower()).arg(subnet.second);
        }
    }

    const QString domainRule = normalizedDomainRule(trimmedRule);
    if (!domainRule.isEmpty()) {
        return domainRule;
    }
    return QStringLiteral("configured-rule");
}

quint32 ipv4Mask(int prefixLength)
{
    return prefixLength == 0 ? 0 : (0xffffffffu << (32 - prefixLength));
}

bool parseIpv4Route(const QString &route, quint32 &address, int &prefixLength)
{
    const QStringList routeParts = route.trimmed().split(QLatin1Char('/'));
    if (routeParts.isEmpty() || routeParts.size() > 2) {
        return false;
    }

    const QHostAddress routeAddress(routeParts.at(0));
    if (routeAddress.protocol() != QAbstractSocket::IPv4Protocol) {
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

bool routeOverlapsIpv4Range(quint32 address, int prefixLength, quint32 base, int rangePrefixLength)
{
    const quint32 routeStart = address & ipv4Mask(prefixLength);
    const quint32 routeEnd = routeStart | ~ipv4Mask(prefixLength);
    const quint32 rangeStart = base & ipv4Mask(rangePrefixLength);
    const quint32 rangeEnd = rangeStart | ~ipv4Mask(rangePrefixLength);
    return routeStart <= rangeEnd && rangeStart <= routeEnd;
}

bool isCanonicalRuntimeIpv4Route(const QString &route)
{
    quint32 address = 0;
    int prefixLength = 32;
    return parseIpv4Route(route, address, prefixLength)
            && (address & ipv4Mask(prefixLength)) == address;
}

// Mirrors VpnConnection::isRoutableSplitTunnelRoute. Local/client CIDRs pass
// through this guard before they reach the OS; server-managed routes use the
// trusted IPC path and intentionally do not.
bool isRoutableClientRoute(const QString &route)
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
    const auto overlaps = [address, prefixLength](quint32 base, int prefix) {
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
            || inRange(0x64400000u, 10) || inRange(0xac100000u, 12)
            || inRange(0xc0a80000u, 16);
    if (overlaps(0x00000000u, 8) || overlaps(0x7f000000u, 8)
        || overlaps(0xc0000000u, 24) || overlaps(0xc0000200u, 24)
        || overlaps(0xc01f0000u, 24) || overlaps(0xc01fc400u, 24)
        || overlaps(0xc034c100u, 24) || overlaps(0xc0586300u, 24)
        || overlaps(0xc0af3000u, 24) || overlaps(0xc6120000u, 15)
        || overlaps(0xc6336400u, 24) || overlaps(0xcb007100u, 24)
        || overlaps(0xe0000000u, 4) || overlaps(0xf0000000u, 4)) {
        return false;
    }

    const int minimumPrefixLength = localOrServiceRoute
            ? minLocalBypassPrefixLength : minPublicBypassPrefixLength;
    return prefixLength >= minimumPrefixLength;
}

void considerMatch(RuleMatch &best,
                   const QString &source,
                   const QString &rule,
                   const QString &matchType,
                   int score,
                   const QString &safetyTransform = {})
{
    const bool localTieBreaker = score == best.score && source == QStringLiteral("local")
            && best.source != QStringLiteral("local");
    if (!best.matched || score > best.score || localTieBreaker) {
        best.matched = true;
        best.source = source;
        best.rule = bounded(rule, maxRuleOutputLength);
        best.matchType = matchType;
        best.safetyTransform = safetyTransform;
        best.score = score;
    }
}

void inspectRules(const QVariantMap &rules,
                  const QString &source,
                  const QString &host,
                  const QHostAddress &address,
                  RuleMatch &best,
                  RuleMatch &rejected)
{
    const bool trustedManaged = source == QStringLiteral("managed");
    const QString rejectionReason = trustedManaged
            ? QStringLiteral("unsupported_managed_cidr_rejected")
            : QStringLiteral("client_cidr_rejected");
    for (auto it = rules.constBegin(); it != rules.constEnd(); ++it) {
        const QString rawRule = it.key().trimmed();
        if (rawRule.isEmpty()) {
            continue;
        }

        int prefixLength = -1;
        const bool keyIsRuntimeRoute = NetworkUtilities::checkIpSubnetFormat(rawRule);
        const bool keyMatched = keyIsRuntimeRoute
                && addressMatchesRoute(address, rawRule, &prefixLength);
        if (keyMatched) {
            if ((trustedManaged && isCanonicalRuntimeIpv4Route(rawRule))
                || (!trustedManaged && isRoutableClientRoute(rawRule))) {
                considerMatch(best,
                              source,
                              privacySafeRule(rawRule),
                              QStringLiteral("address"),
                              8000 + prefixLength);
            } else {
                considerMatch(rejected,
                              source,
                              privacySafeRule(rawRule),
                              QStringLiteral("address"),
                              8000 + prefixLength,
                              rejectionReason);
            }
        }

        if (!keyMatched) {
            const QString domainRule = normalizedDomainRule(rawRule);
            // Runtime DNS route installation consumes A records only. A
            // syntactic "*.example" key is not a suffix rule; normalization
            // rejects it and the runtime would fail to resolve it as well.
            if (address.protocol() == QAbstractSocket::IPv4Protocol
                && !domainRule.isEmpty() && host == domainRule) {
                const QString hostRoute = address.toString();
                if ((trustedManaged && isCanonicalRuntimeIpv4Route(hostRoute))
                    || (!trustedManaged && isRoutableClientRoute(hostRoute))) {
                    considerMatch(best,
                                  source,
                                  domainRule,
                                  QStringLiteral("domain"),
                                  10032 + domainRule.size());
                } else {
                    considerMatch(rejected,
                                  source,
                                  domainRule,
                                  QStringLiteral("domain"),
                                  10032 + domainRule.size(),
                                  rejectionReason);
                }
            }
        }

        const QStringList storedRoutes = storedRouteTokens(it.value());
        for (const QString &storedRoute : storedRoutes) {
            if (addressMatchesRoute(address, storedRoute, &prefixLength)) {
                if ((trustedManaged && isCanonicalRuntimeIpv4Route(storedRoute))
                    || (!trustedManaged && isRoutableClientRoute(storedRoute))) {
                    considerMatch(best,
                                  source,
                                  privacySafeRule(rawRule),
                                  QStringLiteral("resolvedAddress"),
                                  7000 + prefixLength);
                } else {
                    considerMatch(rejected,
                                  source,
                                  privacySafeRule(rawRule),
                                  QStringLiteral("resolvedAddress"),
                                  7000 + prefixLength,
                                  rejectionReason);
                }
            }
        }
    }
}

QString privacySafePolicySource(const QString &source)
{
    const QString trimmed = source.trimmed();
    if (trimmed.isEmpty()) {
        return {};
    }

    const QUrl url(trimmed, QUrl::StrictMode);
    if (url.isValid() && !url.scheme().isEmpty() && !url.host().isEmpty()) {
        const QString host = QString::fromLatin1(QUrl::toAce(url.host())).toLower();
        if (!isValidAceHostname(host)) {
            return {};
        }
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
                                            const VpnConnectionSnapshot &vpnSnapshot,
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
    const NormalizedTarget target = normalizeTarget(host);

    if (!target.error.isEmpty()) {
        QVariantMap result = resultFor({}, {}, {}, QStringLiteral("error"), target.error, generation);
        QTimer::singleShot(0, this, [this, generation, result]() { publishResult(generation, result); });
        return result;
    }

    if (!m_serversRepository || !m_appSettingsRepository) {
        QVariantMap result = resultFor(target.host,
                                       {},
                                       {},
                                       QStringLiteral("error"),
                                       QStringLiteral("route_configuration_unavailable"),
                                       generation);
        QTimer::singleShot(0, this, [this, generation, result]() { publishResult(generation, result); });
        return result;
    }

    if (!target.literalAddress.isNull()) {
        QStringList ipv4Addresses;
        QStringList ipv6Addresses;
        if (target.literalAddress.protocol() == QAbstractSocket::IPv4Protocol) {
            ipv4Addresses.append(target.host);
        } else {
            ipv6Addresses.append(target.host);
        }
        const QVariantMap result = resultFor(target.host,
                                             ipv4Addresses,
                                             ipv6Addresses,
                                             QStringLiteral("ready"),
                                             {},
                                             generation);
        QTimer::singleShot(0, this, [this, generation, result]() { publishResult(generation, result); });
        return result;
    }

    const QVariantMap resolvingResult =
            resultFor(target.host, {}, {}, QStringLiteral("resolving"), {}, generation);
    m_activeLookupGeneration = generation;
    const int lookupId = QHostInfo::lookupHost(
            target.host, this, [this, generation, normalizedHost = target.host](const QHostInfo &hostInfo) {
        if (generation != m_generation || m_activeLookupGeneration != generation) {
            return;
        }
        m_activeLookupId = -1;
        m_activeLookupGeneration = 0;

        QStringList ipv4Addresses;
        QStringList ipv6Addresses;
        for (const QHostAddress &address : hostInfo.addresses()) {
            if (!address.scopeId().isEmpty()) {
                continue;
            }
            const QString value = address.toString().toLower();
            QStringList *targetList = address.protocol() == QAbstractSocket::IPv4Protocol
                    ? &ipv4Addresses
                    : address.protocol() == QAbstractSocket::IPv6Protocol ? &ipv6Addresses : nullptr;
            if (targetList && !targetList->contains(value)
                && targetList->size() < maxResolvedAddressesForMatching) {
                targetList->append(value);
            }
        }
        ipv4Addresses.sort();
        ipv6Addresses.sort();

        const bool hasAddresses = !ipv4Addresses.isEmpty() || !ipv6Addresses.isEmpty();
        const QString error = hasAddresses ? QString() : dnsError(hostInfo);
        const QVariantMap result = resultFor(normalizedHost,
                                             ipv4Addresses,
                                             ipv6Addresses,
                                             error.isEmpty() ? QStringLiteral("ready") : QStringLiteral("error"),
                                             error,
                                             generation);
        publishResult(generation, result);
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
                                             QStringLiteral("error"),
                                             QStringLiteral("dns_lookup_timeout"),
                                             generation);
        publishResult(generation, result);
    });
    return resolvingResult;
}

QString RouteInspectorController::routesExplainJson(const QString &host)
{
    return resultToJson(inspectHost(host));
}

int RouteInspectorController::activeServerIndex(int connectedServerIndex) const
{
    if (!m_serversRepository) {
        return -1;
    }
    if (connectedServerIndex >= 0 && connectedServerIndex < m_serversRepository->serversCount()) {
        return connectedServerIndex;
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

QVariantMap RouteInspectorController::resultFor(const QString &normalizedHost,
                                                const QStringList &ipv4Addresses,
                                                const QStringList &ipv6Addresses,
                                                const QString &state,
                                                const QString &error,
                                                quint64 generation) const
{
    const VpnConnectionSnapshot vpnSnapshot = takeVpnConnectionSnapshot(m_vpnConnection);
    QVariantMap result;
    result.insert(QStringLiteral("requestId"), QString::number(generation));
    result.insert(QStringLiteral("state"), state);
    result.insert(QStringLiteral("normalizedHost"), bounded(normalizedHost, maxHostLength));
    const QStringList boundedIpv4 = ipv4Addresses.mid(0, maxResolvedAddressesPerFamily);
    const QStringList boundedIpv6 = ipv6Addresses.mid(0, maxResolvedAddressesPerFamily);
    result.insert(QStringLiteral("resolvedIpv4"), boundedIpv4);
    result.insert(QStringLiteral("resolvedIpv6"), boundedIpv6);
    result.insert(QStringLiteral("error"), error);
    result.insert(QStringLiteral("platform"), platformName());
    result.insert(QStringLiteral("splitRoutingAddressFamilies"), QStringList { QStringLiteral("ipv4") });
    const bool runtimeApplied = vpnSnapshot.connected;
    result.insert(QStringLiteral("runtimeApplied"), runtimeApplied);
    result.insert(QStringLiteral("inspectionBasis"), runtimeApplied
                          ? QStringLiteral("effectivePolicyWhileConnected")
                          : QStringLiteral("policyPreview"));
    result.insert(QStringLiteral("osRouteVerified"), false);

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
            vpnSnapshot.connected ? vpnSnapshot.serverIndex : -1);
    const bool localSplitEnabled = m_appSettingsRepository->isSitesSplitTunnelingEnabled();
    const RouteMode localRouteMode = m_appSettingsRepository->routeMode();
    const RouteMode effectiveRouteMode = m_serversRepository->effectiveSiteRouteMode(
            serverIndex, localSplitEnabled, localRouteMode);

    result.insert(QStringLiteral("routeMode"), static_cast<int>(effectiveRouteMode));
    result.insert(QStringLiteral("routeModeName"), routeModeName(effectiveRouteMode));

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

    QStringList warnings;
    if (!runtimeApplied) {
        warnings.append(QStringLiteral("vpn_not_connected_policy_preview"));
    }
    const QJsonObject lifecycleState = lifecycleStateValue.toObject();
    const bool retainedPolicyPresent = !lifecycleState.value(
            managedRoutePolicy::lastKnownGoodKey()).toObject().isEmpty();
    const bool policyExpired = policy.value(QStringLiteral("expired")).toBool();
    const bool policyEffective = managedRoutePolicy::isEffective(serverConfig);
    const bool lifecycleInvalid = lifecycleStatePresent && policy.isEmpty();
    const bool installedSnapshotStale = runtimeApplied
            && (lifecycleStatePresent || legacyPolicyPresent) && !policyEffective;
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
        warnings.append(runtimeApplied
                                ? QStringLiteral("managed_policy_expired_installed_state_unknown")
                                : QStringLiteral("managed_policy_expired_ignored"));
    } else if (lifecycleInvalid) {
        warnings.append(runtimeApplied
                                ? QStringLiteral("managed_policy_invalid_installed_state_unknown")
                                : QStringLiteral("managed_policy_invalid_ignored"));
    } else if (policyIneffectiveReason == QStringLiteral("content_digest_mismatch")) {
        warnings.append(runtimeApplied
                                ? QStringLiteral("managed_policy_content_mismatch_installed_state_unknown")
                                : QStringLiteral("managed_policy_content_mismatch_ignored"));
    } else if (policyIneffectiveReason == QStringLiteral("legacy_content_invalid")) {
        warnings.append(QStringLiteral("legacy_managed_policy_invalid_ignored"));
    }
    if (!boundedIpv6.isEmpty() && effectiveRouteMode != RouteMode::VpnAllSites) {
        warnings.append(QStringLiteral("ipv6_split_rules_not_installed"));
    }

    QVariantList addressDecisions;
    const ProtectedRouteContext protectedRoutes = protectedRouteContext(
            m_serversRepository, m_appSettingsRepository, vpnSnapshot,
            serverIndex, effectiveRouteMode);
    const QVariantMap localRules = effectiveRouteMode == RouteMode::VpnAllSites
            ? QVariantMap() : m_appSettingsRepository->vpnSites(effectiveRouteMode);
    const QVariantMap managedRules = effectiveRouteMode == RouteMode::VpnAllSites || serverIndex < 0
            ? QVariantMap()
            : m_serversRepository->managedVpnSitesForRouting(serverIndex, effectiveRouteMode);

    const auto appendAddressDecision = [&](const QString &addressText, const QString &family) {
        QHostAddress address(addressText);
        if (address.isNull()) {
            return;
        }

        RuleMatch match;
        RuleMatch rejected;
        if (effectiveRouteMode != RouteMode::VpnAllSites
            && address.protocol() == QAbstractSocket::IPv4Protocol) {
            inspectRules(localRules, QStringLiteral("local"), normalizedHost,
                         address, match, rejected);
            inspectRules(managedRules, QStringLiteral("managed"), normalizedHost,
                         address, match, rejected);
        }

        const bool unsupportedIpv6Split = address.protocol() == QAbstractSocket::IPv6Protocol
                && effectiveRouteMode != RouteMode::VpnAllSites;
        QString route = QStringLiteral("vpn");
        if (effectiveRouteMode == RouteMode::VpnOnlyForwardSites) {
            route = match.matched ? QStringLiteral("vpn") : QStringLiteral("direct");
        } else if (effectiveRouteMode == RouteMode::VpnAllExceptSites) {
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

        if (installedSnapshotStale && source != QStringLiteral("tunnelSafety")) {
            route = QStringLiteral("unknown");
            source = QStringLiteral("runtimeUnknown");
            safetyTransform = policyExpired
                    ? QStringLiteral("expired_policy_installed_state_unknown")
                    : QStringLiteral("invalid_policy_installed_state_unknown");
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

    for (const QString &address : boundedIpv4) {
        appendAddressDecision(address, QStringLiteral("ipv4"));
    }
    for (const QString &address : boundedIpv6) {
        appendAddressDecision(address, QStringLiteral("ipv6"));
    }
    result.insert(QStringLiteral("addressDecisions"), addressDecisions);

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
