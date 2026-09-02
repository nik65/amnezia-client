#include "headlessRoutingController.h"

#include <QFile>
#include <QEventLoop>
#include <QHostAddress>
#include <QHostInfo>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QRegularExpression>
#include <QTimer>
#include <QUrl>

#include <algorithm>
#include <utility>

namespace amnezia::headless
{
namespace
{

constexpr int PolicyRequestTimeoutMs = 5000;
constexpr qsizetype MaximumPolicyBytes = 1024 * 1024;
constexpr qsizetype MaximumProfileConfigBytes = 1024 * 1024;

bool parseIpv4Route(const QString &value, quint32 *address, int *prefix)
{
    const QStringList parts = value.split(QLatin1Char('/'));
    QHostAddress host(parts.value(0));
    if (parts.size() < 1 || parts.size() > 2
        || host.protocol() != QAbstractSocket::IPv4Protocol) {
        return false;
    }
    bool ok = true;
    const int length = parts.size() == 2 ? parts.at(1).toInt(&ok) : 32;
    if (!ok || length < 0 || length > 32) {
        return false;
    }
    if (address) {
        *address = host.toIPv4Address();
    }
    if (prefix) {
        *prefix = length;
    }
    return true;
}

bool ipv4RoutesOverlap(const QString &left, const QString &right)
{
    quint32 leftAddress = 0;
    quint32 rightAddress = 0;
    int leftPrefix = 32;
    int rightPrefix = 32;
    if (!parseIpv4Route(left, &leftAddress, &leftPrefix)
        || !parseIpv4Route(right, &rightAddress, &rightPrefix)) {
        return false;
    }
    const quint32 leftMask = leftPrefix == 0 ? 0u : 0xffffffffu << (32 - leftPrefix);
    const quint32 rightMask = rightPrefix == 0 ? 0u : 0xffffffffu << (32 - rightPrefix);
    const quint32 leftStart = leftAddress & leftMask;
    const quint32 rightStart = rightAddress & rightMask;
    const quint64 leftEnd = static_cast<quint64>(leftStart)
            | static_cast<quint64>(0xffffffffu ^ leftMask);
    const quint64 rightEnd = static_cast<quint64>(rightStart)
            | static_cast<quint64>(0xffffffffu ^ rightMask);
    return leftStart <= rightEnd && rightStart <= leftEnd;
}

bool ipv4ContainedByRoute(const QHostAddress &address, const QString &route)
{
    if (address.protocol() != QAbstractSocket::IPv4Protocol) {
        return false;
    }
    quint32 network = 0;
    int prefix = 0;
    if (!parseIpv4Route(route, &network, &prefix)) {
        return false;
    }
    const quint32 mask = prefix == 0 ? 0u : 0xffffffffu << (32 - prefix);
    return (address.toIPv4Address() & mask) == (network & mask);
}

bool privateOrLocalIpv4(const QHostAddress &address)
{
    if (address.protocol() != QAbstractSocket::IPv4Protocol) return false;
    const quint32 value = address.toIPv4Address();
    return ((value >> 24) == 10)
        || ((value >> 20) == ((172u << 4) | 1u))
        || ((value >> 16) == ((192u << 8) | 168u))
        || ((value >> 24) == 127)
        || ((value >> 16) == 169 * 256 + 254)
        || value == 0;
}

bool privateOrLocalAddress(const QHostAddress &address)
{
    if (privateOrLocalIpv4(address) || address.isLoopback() || address.isLinkLocal()
        || address.isMulticast() || address.isNull()) {
        return true;
    }
    if (address.protocol() == QAbstractSocket::IPv6Protocol) {
        const Q_IPV6ADDR bytes = address.toIPv6Address();
        // fc00::/7 (ULA) is not a public policy endpoint.
        return (bytes.c[0] & 0xfe) == 0xfc;
    }
    return false;
}

QStringList mergeRoutes(QStringList left, const QStringList &right, bool *valid)
{
    left.append(right);
    bool routesValid = false;
    left = amnezia::managedRoutePolicy::validatedManagedRoutes(left, &routesValid);
    if (valid) {
        *valid = routesValid;
    }
    left.removeDuplicates();
    left.sort();
    return routesValid ? left : QStringList();
}

void appendHostRoutes(QStringList &routes, const QString &rawHost)
{
    QString host = rawHost.trimmed();
    if (host.startsWith(QLatin1Char('[')) && host.endsWith(QLatin1Char(']'))) {
        host = host.mid(1, host.size() - 2);
    }
    if (host.isEmpty()) {
        return;
    }

    QHostAddress address;
    if (address.setAddress(host)) {
        if (address.protocol() == QAbstractSocket::IPv4Protocol) {
            routes.append(address.toString() + QStringLiteral("/32"));
        }
        return;
    }

    const QHostInfo info = QHostInfo::fromName(host);
    for (const QHostAddress &resolved : info.addresses()) {
        if (resolved.protocol() == QAbstractSocket::IPv4Protocol) {
            routes.append(resolved.toString() + QStringLiteral("/32"));
        }
    }
}

QStringList endpointHostsFromConfig(const Profile &profile)
{
    QStringList hosts;
    QFile file(profile.configPath);
    if (!file.open(QIODevice::ReadOnly) || file.size() > MaximumProfileConfigBytes) {
        return hosts;
    }
    const QString content = QString::fromUtf8(file.readAll());

    // WireGuard/AmneziaWG endpoint syntax is host:port or [IPv6]:port.  The
    // route policy is IPv4-only, but retaining the bracket handling prevents
    // an IPv6 literal from being misread as a malformed IPv4 host.
    const QRegularExpression wireGuardEndpoint(
            QStringLiteral(R"(^\s*Endpoint\s*=\s*(\[[^\]]+\]|[^:\s]+)(?::\d+)?\s*$)"),
            QRegularExpression::MultilineOption);
    auto match = wireGuardEndpoint.globalMatch(content);
    while (match.hasNext()) {
        hosts.append(match.next().captured(1));
    }

    // OpenVPN permits one or more "remote host [port]" lines.  Only the host
    // is needed for an exact main-table bypass route.
    const QRegularExpression openVpnRemote(
            QStringLiteral(R"(^\s*remote\s+(\S+)(?:\s+\S+)?\s*$)"),
            QRegularExpression::MultilineOption | QRegularExpression::CaseInsensitiveOption);
    match = openVpnRemote.globalMatch(content);
    while (match.hasNext()) {
        hosts.append(match.next().captured(1));
    }
    hosts.removeDuplicates();
    return hosts;
}

QStringList protectedRoutesForProfile(const Profile &profile, bool *valid)
{
    if (valid) {
        *valid = true;
    }
    QStringList routes;
    for (const QString &endpoint : endpointHostsFromConfig(profile)) {
        QString normalizedEndpoint = endpoint;
        if (normalizedEndpoint.startsWith(QLatin1Char('['))
            && normalizedEndpoint.endsWith(QLatin1Char(']'))) {
            normalizedEndpoint = normalizedEndpoint.mid(1, normalizedEndpoint.size() - 2);
        }
        QHostAddress address(normalizedEndpoint);
        bool hasIpv6 = address.protocol() == QAbstractSocket::IPv6Protocol;
        if (address.protocol() == QAbstractSocket::UnknownNetworkLayerProtocol) {
            const QHostInfo resolved = QHostInfo::fromName(normalizedEndpoint);
            hasIpv6 = std::any_of(resolved.addresses().cbegin(), resolved.addresses().cend(),
                                  [](const QHostAddress &candidate) {
                return candidate.protocol() == QAbstractSocket::IPv6Protocol;
            });
        }
        if (hasIpv6) {
            if (valid) {
                *valid = false;
            }
            return {};
        }
        appendHostRoutes(routes, endpoint);
    }
    bool routesValid = false;
    routes = amnezia::managedRoutePolicy::validatedManagedRoutes(routes, &routesValid);
    if (!routesValid && valid) {
        *valid = false;
    }
    return routesValid ? routes : QStringList();
}

} // namespace

QStringList allExceptBypassRoutes(const Profile &profile,
                                  const QStringList &serverRoutes,
                                  bool *valid)
{
    bool routesValid = true;
    QStringList routes;
    for (const QString &serverRoute : serverRoutes) {
        bool overlapsInternal = false;
        for (const QString &forwardRoute : profile.forwardRoutes) {
            if (ipv4RoutesOverlap(serverRoute, forwardRoute)) {
                overlapsInternal = true;
                break;
            }
        }
        if (!overlapsInternal) {
            routes.append(serverRoute);
            continue;
        }

        // A host allow-list entry inside the VPN subnet is redundant and is
        // removed so it cannot accidentally create a main-table bypass.  A
        // wider/partial overlap is ambiguous; reject it rather than invent a
        // route split that could leak part of the VPN-internal network.
        quint32 serverAddress = 0;
        int serverPrefix = 32;
        parseIpv4Route(serverRoute, &serverAddress, &serverPrefix);
        bool safelyContained = serverPrefix == 32;
        if (!safelyContained) {
            for (const QString &forwardRoute : profile.forwardRoutes) {
                quint32 forwardAddress = 0;
                int forwardPrefix = 32;
                if (parseIpv4Route(forwardRoute, &forwardAddress, &forwardPrefix)
                    && serverPrefix >= forwardPrefix
                    && ipv4RoutesOverlap(serverRoute, forwardRoute)) {
                    safelyContained = true;
                    break;
                }
            }
        }
        if (!safelyContained) {
            routesValid = false;
            break;
        }
    }
    bool protectedValid = true;
    routes.append(protectedRoutesForProfile(profile, &protectedValid));
    routesValid = routesValid && protectedValid;
    bool validated = false;
    routes = amnezia::managedRoutePolicy::validatedManagedRoutes(routes, &validated);
    routesValid = routesValid && validated;
    routes.removeDuplicates();
    routes.sort();
    if (valid) {
        *valid = routesValid;
    }
    return routesValid ? routes : QStringList();
}

HeadlessRoutingController::HeadlessRoutingController(
        std::shared_ptr<CommandRunner> runner, QString routeStatePath)
    : m_reconciler(runner ? std::move(runner) : std::make_shared<RealCommandRunner>(),
                   std::move(routeStatePath))
{
}

RoutingResult HeadlessRoutingController::connect(const Profile &profile)
{
    m_lastError.clear();
    const bool allExcept = profile.routingMode == QStringLiteral("all-except");
    const QString protocol = profile.protocol.trimmed().toLower();
    if (allExcept && (protocol == QStringLiteral("xray")
                      || protocol == QStringLiteral("ssxray"))) {
        return failure(QStringLiteral("routing_mode_unsupported"),
                       QStringLiteral("all-except requires a VPN interface; XRay proxy mode cannot provide a full tunnel"));
    }
    if (allExcept && profile.serverRulesUrl.isEmpty()) {
        return failure(QStringLiteral("server_policy_required"),
                       QStringLiteral("all-except requires a server routing policy URL"));
    }
    if (!allExcept && profile.serverRulesUrl.isEmpty() && profile.forwardRoutes.isEmpty()) {
        m_activeProfile = profile.id;
        m_activeInterface.clear();
        m_hasPolicy = false;
        return { true, {}, {} };
    }
    return fetchAndApply(profile);
}

RoutingResult HeadlessRoutingController::refresh(const Profile &profile)
{
    if (m_activeProfile != profile.id) {
        return failure(QStringLiteral("profile_not_active"),
                       QStringLiteral("cannot refresh routes for an inactive profile"));
    }
    // A refresh failure deliberately leaves the last-known-good route set in
    // place, matching the desktop client's availability-first behavior.
    return fetchAndApply(profile);
}

RoutingResult HeadlessRoutingController::disconnect()
{
    const RouteReconcileResult result = m_reconciler.clear();
    if (!result.ok) {
        return failure(result.code, result.message);
    }
    const RouteReconcileResult dnsResult = m_reconciler.clearDns(m_activeInterface);
    if (!dnsResult.ok) {
        return failure(dnsResult.code, dnsResult.message);
    }
    m_activeProfile.clear();
    m_activeInterface.clear();
    m_policyRevision.clear();
    m_policyContentHash.clear();
    m_policySource.clear();
    m_hasPolicy = false;
    m_policyMetadata.reset();
    return { true, {}, {} };
}

QJsonObject HeadlessRoutingController::status() const
{
    QJsonObject result = m_reconciler.status();
    result.insert(QStringLiteral("activeProfile"), m_activeProfile);
    result.insert(QStringLiteral("policyRevision"), m_policyRevision);
    result.insert(QStringLiteral("policyContentHash"), m_policyContentHash);
    result.insert(QStringLiteral("policySource"), m_policySource);
    result.insert(QStringLiteral("policyLoaded"), m_hasPolicy);
    return result;
}

RoutingResult HeadlessRoutingController::failure(const QString &code,
                                                 const QString &message) const
{
    m_lastError = message;
    return { false, code, message };
}

RoutingResult HeadlessRoutingController::fetchAndApply(const Profile &profile)
{
    const QString interfaceName = defaultInterfaceFor(profile);
    if (interfaceName.isEmpty()) {
        return failure(QStringLiteral("invalid_interface"),
                       QStringLiteral("a VPN interface is required for managed routes"));
    }

    QStringList serverRoutes;
    if (!profile.serverRulesUrl.isEmpty()) {
        // The policy endpoint is intentionally reached through the VPN.  On
        // the first connection there is no managed route yet, so install the
        // profile's small bootstrap set before fetching the server policy.
        // Refreshes keep the last-known-good server routes in place and must
        // not clear them before a network request that may fail.
        if (m_activeProfile != profile.id) {
            const RoutingResult bootstrap = applyRoutes(profile, {});
            if (!bootstrap.ok) {
                return bootstrap;
            }
        }
        const std::optional<amnezia::ManagedRoutePolicyMetadata> current = m_policyMetadata;

        QString policyUrlError;
        if (!isSafePolicyEndpoint(profile, profile.serverRulesUrl, &policyUrlError)) {
            return failure(QStringLiteral("policy_transport_invalid"), policyUrlError);
        }
        const ServerRoutingPolicyResult fetched = fetchPolicy(profile, current);
        if (!fetched.ok) {
            return failure(fetched.code, fetched.message);
        }
        const ServerRoutingPolicyResult resolved = ServerRoutingPolicy::resolve(fetched.policy);
        if (!resolved.ok) {
            return failure(resolved.code, resolved.message);
        }
        serverRoutes = resolved.policy.routes;
        const RoutingResult applied = applyRoutes(profile, serverRoutes);
        if (!applied.ok) {
            return applied;
        }
        // Advance the policy receipt only after the route transaction commits;
        // a failed apply must not make a newer policy look like LKG state.
        m_policyRevision = resolved.policy.revision;
        m_policyContentHash = resolved.policy.contentHash;
        m_policySource = resolved.policy.source;
        m_hasPolicy = true;
        m_policyMetadata = resolved.policy.metadata;
        return applied;
    }

    const RoutingResult applied = applyRoutes(profile, serverRoutes);
    return applied;
}

RoutingResult HeadlessRoutingController::applyRoutes(const Profile &profile,
                                                     const QStringList &serverRoutes)
{
    const bool allExcept = profile.routingMode == QStringLiteral("all-except");
    bool routesValid = false;
    QStringList routes = mergeRoutes(profile.forwardRoutes, serverRoutes, &routesValid);
    if (!routesValid) {
        return failure(QStringLiteral("invalid_routes"),
                       QStringLiteral("profile and server managed routes exceed the safety boundary"));
    }
    const QString interfaceName = defaultInterfaceFor(profile);
    RouteReconcileResult result;
    if (allExcept) {
        // forwardRoutes are VPN-internal (for example the ServerX 10.8.1.0/24
        // subnet) and must not become main-table bypasses.  The policy URL is
        // likewise intentionally fetched through the tunnel.  Only resolved
        // server allow-list, DNS, and public endpoint routes are bypassed.
        routes = allExceptBypassRoutes(profile, serverRoutes, &routesValid);
        if (!routesValid) {
            return failure(QStringLiteral("invalid_routes"),
                           QStringLiteral("full-tunnel bypass routes exceed the safety boundary"));
        }
        result = m_reconciler.applyAllExcept(interfaceName, routes);
    } else {
        result = m_reconciler.apply(interfaceName, routes);
    }
    if (!result.ok) {
        return failure(result.code, result.message);
    }
    if (!profile.dnsServers.isEmpty()) {
        const RouteReconcileResult dnsResult = m_reconciler.configureDns(
                interfaceName, profile.dnsServers, profile.dnsDomains);
        if (!dnsResult.ok) {
            const RouteReconcileResult dnsCleanup = m_reconciler.clearDns(interfaceName);
            const RouteReconcileResult routeCleanup = m_reconciler.clear();
            if (!dnsCleanup.ok || !routeCleanup.ok) {
                return failure(QStringLiteral("recovery_required"),
                               QStringLiteral("DNS setup failed and managed routes or DNS could not be rolled back"));
            }
            return failure(dnsResult.code, dnsResult.message);
        }
    }
    m_activeProfile = profile.id;
    m_activeInterface = interfaceName;
    return { true, {}, {} };
}

QString HeadlessRoutingController::defaultInterfaceFor(const Profile &profile)
{
    if (!profile.interfaceName.isEmpty()) {
        return profile.interfaceName;
    }
    const QString protocol = profile.protocol.trimmed().toLower();
    if (protocol == QStringLiteral("wireguard")) {
        return QStringLiteral("wg0");
    }
    if (protocol == QStringLiteral("amneziawg") || protocol == QStringLiteral("awg")
        || protocol == QStringLiteral("awg2")) {
        return QStringLiteral("amn0");
    }
    if (protocol == QStringLiteral("openvpn")) {
        return QStringLiteral("tun0");
    }
    return {};
}

bool isSafePolicyEndpoint(const Profile &profile, const QString &rawUrl,
                          QString *error)
{
    const QUrl url(rawUrl, QUrl::StrictMode);
    const auto fail = [error](const QString &message) {
        if (error) *error = message;
        return false;
    };
    if (!url.isValid() || url.host().isEmpty() || url.userInfo().size() > 0
        || url.hasFragment() || (url.port() != -1 && (url.port() < 1 || url.port() > 65535))) {
        return fail(QStringLiteral("server routing policy URL is invalid"));
    }
    const QHostAddress literal(url.host());
    if (url.scheme() == QStringLiteral("http")) {
        if (literal.protocol() != QAbstractSocket::IPv4Protocol
            || privateOrLocalIpv4(literal) == false) {
            return fail(QStringLiteral("plain HTTP policy endpoints are allowed only for literal VPN-internal addresses"));
        }
        const bool contained = std::any_of(profile.forwardRoutes.cbegin(), profile.forwardRoutes.cend(),
                                           [&literal](const QString &route) {
            return ipv4ContainedByRoute(literal, route);
        });
        if (!contained) {
            return fail(QStringLiteral("plain HTTP policy endpoint is not contained in forwardRoutes"));
        }
        return true;
    }
    if (url.scheme() != QStringLiteral("https")) {
        return fail(QStringLiteral("server routing policy requires HTTPS or the documented VPN-internal HTTP exception"));
    }
    if (literal.protocol() != QAbstractSocket::UnknownNetworkLayerProtocol
        && privateOrLocalAddress(literal)) {
        const bool contained = std::any_of(profile.forwardRoutes.cbegin(), profile.forwardRoutes.cend(),
                                           [&literal](const QString &route) {
            return ipv4ContainedByRoute(literal, route);
        });
        if (!contained) {
            return fail(QStringLiteral("HTTPS policy endpoint resolves to an unsafe private address"));
        }
    }
    const QString lowerHost = url.host().toLower();
    if (lowerHost == QStringLiteral("localhost") || lowerHost.endsWith(QStringLiteral(".localhost"))
        || lowerHost.endsWith(QStringLiteral(".local")) || lowerHost.endsWith(QStringLiteral(".internal"))) {
        return fail(QStringLiteral("policy endpoint hostname is reserved for local or internal resolution"));
    }
    if (literal.protocol() == QAbstractSocket::UnknownNetworkLayerProtocol) {
        const QHostInfo resolved = QHostInfo::fromName(url.host());
        for (const QHostAddress &address : resolved.addresses()) {
            if (!privateOrLocalAddress(address)) continue;
            if (address.protocol() != QAbstractSocket::IPv4Protocol
                || !std::any_of(profile.forwardRoutes.cbegin(), profile.forwardRoutes.cend(),
                                [&address](const QString &route) {
                return ipv4ContainedByRoute(address, route);
            })) {
                return fail(QStringLiteral("policy endpoint hostname resolves to an unsafe private address"));
            }
        }
    }
    return true;
}

ServerRoutingPolicyResult HeadlessRoutingController::fetchPolicy(
        const Profile &profile, const std::optional<amnezia::ManagedRoutePolicyMetadata> &current)
{
    const QString url = profile.serverRulesUrl;
    QNetworkAccessManager manager;
    QNetworkRequest request { QUrl(url) };
    request.setTransferTimeout(PolicyRequestTimeoutMs);
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute,
                         QNetworkRequest::ManualRedirectPolicy);
    QNetworkReply *reply = manager.get(request);
    QEventLoop loop;
    QTimer timer;
    timer.setSingleShot(true);
    QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    QObject::connect(&timer, &QTimer::timeout, &loop, &QEventLoop::quit);
    timer.start(PolicyRequestTimeoutMs);
    loop.exec();

    if (!reply->isFinished()) {
        reply->abort();
        reply->deleteLater();
        return { false, QStringLiteral("policy_timeout"),
                 QStringLiteral("server routing policy request timed out"), {} };
    }
    const QByteArray data = reply->readAll();
    const int statusCode = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    const QString error = reply->error() == QNetworkReply::NoError
            ? QString() : reply->errorString();
    reply->deleteLater();
    if (!error.isEmpty()) {
        return { false, QStringLiteral("policy_unreachable"),
                 QStringLiteral("server routing policy request failed"), {} };
    }
    if (statusCode < 200 || statusCode >= 300) {
        return { false, QStringLiteral("policy_http_error"),
                 QStringLiteral("server routing policy returned an unexpected HTTP status"), {} };
    }
    if (data.size() > MaximumPolicyBytes) {
        return { false, QStringLiteral("policy_too_large"),
                 QStringLiteral("server routing policy exceeds the byte limit"), {} };
    }
    return ServerRoutingPolicy::parse(data, current, url);
}

} // namespace amnezia::headless
