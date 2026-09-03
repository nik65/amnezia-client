#include "headlessRoutingController.h"

#include <QFile>
#include <QDir>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonArray>
#include <QEventLoop>
#include <QHostAddress>
#include <QHostInfo>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QRegularExpression>
#include <QSaveFile>
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
constexpr int HostResolveTimeoutMs = 1500;

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
        || ((value & 0xffc00000u) == 0x64400000u) // RFC 6598 CGNAT
        || ((value & 0xffffff00u) == 0xc0000000u) // IETF protocol assignments
        || ((value & 0xfffe0000u) == 0xc6120000u) // benchmarking
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
        // IPv4-mapped IPv6 literals must receive the same private/loopback
        // treatment as their IPv4 spelling; otherwise ::ffff:127.0.0.1 can
        // bypass the endpoint policy.
        bool mapped = true;
        for (int i = 0; i < 10; ++i) mapped = mapped && bytes.c[i] == 0;
        mapped = mapped && bytes.c[10] == 0xff && bytes.c[11] == 0xff;
        if (mapped) {
            const quint32 ipv4 = (static_cast<quint32>(bytes.c[12]) << 24)
                    | (static_cast<quint32>(bytes.c[13]) << 16)
                    | (static_cast<quint32>(bytes.c[14]) << 8)
                    | static_cast<quint32>(bytes.c[15]);
            return privateOrLocalIpv4(QHostAddress(ipv4));
        }
        // fc00::/7 (ULA) is not a public policy endpoint.
        return (bytes.c[0] & 0xfe) == 0xfc;
    }
    return false;
}

QHostInfo resolveHostBounded(const QString &host, bool *completed)
{
    QHostInfo result;
    bool finished = false;
    QEventLoop loop;
    QTimer timer;
    timer.setSingleShot(true);
    const int lookup = QHostInfo::lookupHost(
            host, &loop, [&loop, &result, &finished](const QHostInfo &info) {
        result = info;
        finished = true;
        loop.quit();
    });
    QObject::connect(&timer, &QTimer::timeout, &loop, &QEventLoop::quit);
    timer.start(HostResolveTimeoutMs);
    loop.exec();
    if (!finished && lookup != -1) QHostInfo::abortHostLookup(lookup);
    if (completed) *completed = finished;
    return result;
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

bool appendHostRoutes(QStringList &routes, const QString &rawHost)
{
    QString host = rawHost.trimmed();
    if (host.startsWith(QLatin1Char('[')) && host.endsWith(QLatin1Char(']'))) {
        host = host.mid(1, host.size() - 2);
    }
    if (host.isEmpty()) {
        return false;
    }

    QHostAddress address;
    if (address.setAddress(host)) {
        if (address.protocol() == QAbstractSocket::IPv4Protocol) {
            routes.append(address.toString() + QStringLiteral("/32"));
        }
        return address.protocol() == QAbstractSocket::IPv4Protocol;
    }

    bool resolved = false;
    const QHostInfo info = resolveHostBounded(host, &resolved);
    if (!resolved) return false;
    bool added = false;
    for (const QHostAddress &resolved : info.addresses()) {
        if (resolved.protocol() == QAbstractSocket::IPv4Protocol) {
            routes.append(resolved.toString() + QStringLiteral("/32"));
            added = true;
        }
    }
    return added;
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

    // OpenVPN's canonical syntax is "remote host port proto".  Keep parsing
    // strict and complete even though all-except currently fails closed for
    // OpenVPN until its endpoint ownership can be reconciled safely.
    const QRegularExpression openVpnRemote(
            QStringLiteral(R"(^\s*remote\s+(\S+)\s+(\d{1,5})\s+(udp|udp6|tcp|tcp6)(?:\s+\S+)*\s*$)"),
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
            // Do not perform an unbounded resolver call while preparing a
            // full-tunnel bypass. A hostname can be DNS-rebound between the
            // check and route installation; require a literal endpoint and
            // let the backend's own resolver handle ordinary tunnel setup.
            if (valid) *valid = false;
            return {};
        }
        if (hasIpv6) {
            if (valid) {
                *valid = false;
            }
            return {};
        }
        if (!appendHostRoutes(routes, endpoint) && valid) {
            *valid = false;
        }
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
    : m_reconciler(runner ? runner : std::make_shared<RealCommandRunner>(),
                   routeStatePath),
      m_statePath(routeStatePath.isEmpty() ? QString() : QDir(QFileInfo(routeStatePath).absolutePath())
                   .filePath(QStringLiteral("routing-controller.json")))
{
    m_stateValid = loadState();
    if (!m_stateValid) m_lastError = QStringLiteral("routing controller state is invalid");
}

RoutingResult HeadlessRoutingController::connect(const Profile &profile)
{
    m_lastError.clear();
    if (!m_stateValid) {
        return failure(QStringLiteral("recovery_required"),
                       QStringLiteral("routing controller state is invalid; manual recovery is required"));
    }
    if (m_reconciler.status().value(QStringLiteral("recoveryRequired")).toBool()) {
        return failure(QStringLiteral("recovery_required"),
                       QStringLiteral("managed route state is invalid; manual route recovery is required"));
    }
    const bool allExcept = profile.routingMode == QStringLiteral("all-except");
    const QString protocol = profile.protocol.trimmed().toLower();
    if (allExcept && (protocol == QStringLiteral("xray")
                      || protocol == QStringLiteral("ssxray")
                      || protocol == QStringLiteral("openvpn"))) {
        return failure(QStringLiteral("routing_mode_unsupported"),
                       QStringLiteral("all-except is fail-closed for proxy/OpenVPN profiles until endpoint route ownership is proven"));
    }
    if (allExcept && profile.serverRulesUrl.isEmpty()) {
        return failure(QStringLiteral("server_policy_required"),
                       QStringLiteral("all-except requires a server routing policy URL"));
    }
    if (!allExcept && profile.serverRulesUrl.isEmpty() && profile.forwardRoutes.isEmpty()) {
        if (m_reconciler.status().value(QStringLiteral("recoveryRequired")).toBool()) {
            return failure(QStringLiteral("recovery_required"),
                           QStringLiteral("managed route state is invalid; manual route recovery is required"));
        }
        m_activeProfile = profile.id;
        m_activeInterface.clear();
        m_hasPolicy = false;
        if (!saveState()) {
            m_stateValid = false;
            return failure(QStringLiteral("recovery_required"),
                           QStringLiteral("routing controller receipt could not be saved"));
        }
        return { true, {}, {} };
    }
    return fetchAndApply(profile);
}

RoutingResult HeadlessRoutingController::refresh(const Profile &profile)
{
    if (!m_stateValid) {
        return failure(QStringLiteral("recovery_required"),
                       QStringLiteral("routing controller state is invalid; manual recovery is required"));
    }
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
    if (!m_stateValid) {
        return failure(QStringLiteral("recovery_required"),
                       QStringLiteral("routing controller state is invalid; manual recovery is required"));
    }
    const QJsonObject receipt = m_reconciler.status();
    if (receipt.value(QStringLiteral("recoveryRequired")).toBool()) {
        return failure(QStringLiteral("recovery_required"),
                       QStringLiteral("managed route receipt is invalid; refusing cleanup mutation"));
    }
    // DNS ownership is independent from the route interface.  Clear it
    // first using the persisted receipt, so a route cleanup cannot erase the
    // only interface identity needed to revert systemd-resolved.
    const QString dnsInterface = receipt.value(QStringLiteral("dnsInterface")).toString();
    const RouteReconcileResult dnsResult = m_reconciler.clearDns(dnsInterface);
    if (!dnsResult.ok) {
        return failure(dnsResult.code,
                       QStringLiteral("route and DNS cleanup did not complete"));
    }
    const RouteReconcileResult result = m_reconciler.clear();
    if (!result.ok) {
        return failure(result.code,
                       QStringLiteral("route cleanup did not complete"));
    }
    m_activeProfile.clear();
    m_activeInterface.clear();
    m_policyRevision.clear();
    m_policyContentHash.clear();
    m_policySource.clear();
    m_hasPolicy = false;
    m_policyMetadata.reset();
    if (!saveState()) {
        m_stateValid = false;
        return failure(QStringLiteral("recovery_required"),
                       QStringLiteral("routing controller state could not be cleared"));
    }
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
    result.insert(QStringLiteral("recoveryRequired"), !m_stateValid
                  || result.value(QStringLiteral("recoveryRequired")).toBool());
    return result;
}

RoutingResult HeadlessRoutingController::failure(const QString &code,
                                                 const QString &message) const
{
    m_lastError = message;
    return { false, code, message };
}

bool HeadlessRoutingController::loadState()
{
    if (m_statePath.isEmpty()) return true;
    QFile file(m_statePath);
    if (!file.exists() || !file.open(QIODevice::ReadOnly)) return !file.exists();
    QJsonParseError error;
    const QJsonDocument document = QJsonDocument::fromJson(file.readAll(), &error);
    if (error.error != QJsonParseError::NoError || !document.isObject()) return false;
    const QJsonObject object = document.object();
    if (!object.value(QStringLiteral("version")).isDouble()
        || object.value(QStringLiteral("version")).toDouble() != 1.0
        || !object.value(QStringLiteral("activeProfile")).isString()
        || !object.value(QStringLiteral("activeInterface")).isString()
        || !object.value(QStringLiteral("policyRevision")).isString()
        || !object.value(QStringLiteral("policyContentHash")).isString()
        || !object.value(QStringLiteral("policySource")).isString()
        || !object.value(QStringLiteral("policyLoaded")).isBool()) return false;
    m_activeProfile = object.value(QStringLiteral("activeProfile")).toString();
    m_activeInterface = object.value(QStringLiteral("activeInterface")).toString();
    m_policyRevision = object.value(QStringLiteral("policyRevision")).toString();
    m_policyContentHash = object.value(QStringLiteral("policyContentHash")).toString();
    m_policySource = object.value(QStringLiteral("policySource")).toString();
    m_hasPolicy = object.value(QStringLiteral("policyLoaded")).toBool();
    return true;
}

bool HeadlessRoutingController::saveState() const
{
    if (m_statePath.isEmpty()) return true;
    const QFileInfo info(m_statePath);
    if (!QDir().mkpath(info.absolutePath())) return false;
    QSaveFile file(m_statePath);
    if (!file.open(QIODevice::WriteOnly)) return false;
    const QJsonObject object {
        { QStringLiteral("version"), 1 },
        { QStringLiteral("activeProfile"), m_activeProfile },
        { QStringLiteral("activeInterface"), m_activeInterface },
        { QStringLiteral("policyRevision"), m_policyRevision },
        { QStringLiteral("policyContentHash"), m_policyContentHash },
        { QStringLiteral("policySource"), m_policySource },
        { QStringLiteral("policyLoaded"), m_hasPolicy },
    };
    return file.write(QJsonDocument(object).toJson(QJsonDocument::Compact)) >= 0
        && file.commit();
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
        const QJsonObject persistedRouting = m_reconciler.status();
        const bool persistedFullTunnel =
                persistedRouting.value(QStringLiteral("mode")).toString()
                    == QStringLiteral("all-except")
                && persistedRouting.value(QStringLiteral("interface")).toString()
                    == interfaceName;
        if (m_activeProfile != profile.id && !persistedFullTunnel) {
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
        if (!saveState()) {
            m_stateValid = false;
            return failure(QStringLiteral("recovery_required"),
                           QStringLiteral("routing policy receipt could not be saved"));
        }
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
    const QJsonObject previousRouting = m_reconciler.status();
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
    const QString previousDnsInterface = previousRouting.value(QStringLiteral("dnsInterface")).toString();
    RouteReconcileResult dnsResult { true, {}, {} };
    if (!profile.dnsServers.isEmpty()) {
        dnsResult = m_reconciler.configureDns(interfaceName, profile.dnsServers, profile.dnsDomains);
    } else if (!previousDnsInterface.isEmpty()) {
        // A profile without DNS ownership must remove the previous profile's
        // resolver binding rather than carrying stale DNS into the new one.
        dnsResult = m_reconciler.clearDns(previousDnsInterface);
    }
    if (!dnsResult.ok) {
            // DNS is part of the same LKG transaction as policy routes.  Put
            // both the previous route receipt and previous resolver binding
            // back before exposing the failed refresh to the caller.
            const QStringList oldBypass = [&previousRouting]() {
                        QStringList values;
                        for (const QJsonValue &value : previousRouting
                                .value(QStringLiteral("bypassRoutes")).toArray()) {
                            if (value.isString()) values.append(value.toString());
                        }
                        return values;
                    }();
            const QStringList oldRoutes = [&previousRouting]() {
                QStringList values;
                for (const QJsonValue &value : previousRouting
                        .value(QStringLiteral("routes")).toArray()) {
                    if (value.isString()) values.append(value.toString());
                }
                return values;
            }();
            RouteReconcileResult routeRestore;
            if (previousRouting.value(QStringLiteral("mode")).toString()
                    == QStringLiteral("all-except")) {
                routeRestore = m_reconciler.applyAllExcept(
                        previousRouting.value(QStringLiteral("interface")).toString(), oldBypass);
            } else if (!oldRoutes.isEmpty()) {
                routeRestore = m_reconciler.apply(
                        previousRouting.value(QStringLiteral("interface")).toString(), oldRoutes);
            } else {
                routeRestore = m_reconciler.clear();
            }
            const QJsonArray oldDnsServers = previousRouting.value(QStringLiteral("dnsServers")).toArray();
            const QJsonArray oldDnsDomains = previousRouting.value(QStringLiteral("dnsDomains")).toArray();
            QStringList oldServers;
            QStringList oldDomains;
            for (const QJsonValue &value : oldDnsServers) if (value.isString()) oldServers.append(value.toString());
            for (const QJsonValue &value : oldDnsDomains) if (value.isString()) oldDomains.append(value.toString());
            const QString oldDnsInterface = previousRouting.value(QStringLiteral("dnsInterface")).toString();
            const RouteReconcileResult dnsRestore = oldServers.isEmpty() || oldDomains.isEmpty()
                    ? m_reconciler.clearDns(oldDnsInterface)
                    : m_reconciler.configureDns(oldDnsInterface, oldServers, oldDomains);
            if (!routeRestore.ok || !dnsRestore.ok) {
                return failure(QStringLiteral("recovery_required"),
                               QStringLiteral("DNS refresh failed and the previous route/DNS receipt could not be restored"));
            }
        return failure(dnsResult.code, dnsResult.message);
    }
    m_activeProfile = profile.id;
    m_activeInterface = interfaceName;
    if (!saveState()) {
        m_stateValid = false;
        return failure(QStringLiteral("recovery_required"),
                       QStringLiteral("routing controller receipt could not be saved"));
    }
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
        return fail(QStringLiteral("policy endpoint must use a literal IP to prevent DNS rebinding"));
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
