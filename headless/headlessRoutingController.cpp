#include "headlessRoutingController.h"

#include <QFile>
#include <QDir>
#include <QDebug>
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
#include <QSet>
#include <QSaveFile>
#include <QTimer>
#include <QVariant>
#include <QUrl>

#include <algorithm>
#include <cmath>
#include <utility>

namespace amnezia::headless
{
namespace
{

constexpr int PolicyRequestTimeoutMs = 5000;
constexpr qsizetype MaximumPolicyBytes = 1024 * 1024;
constexpr qsizetype MaximumProfileConfigBytes = 1024 * 1024;
constexpr int HostResolveTimeoutMs = 1500;

std::optional<amnezia::ManagedRoutePolicyMetadata> policyMetadataFromJson(
        const QJsonValue &value)
{
    if (!value.isObject()) return std::nullopt;
    const QJsonObject object = value.toObject();
    const QStringList allowed {
        QStringLiteral("schemaVersion"), QStringLiteral("policyType"),
        QStringLiteral("revision"), QStringLiteral("revisionNumber"),
        QStringLiteral("contentHash"), QStringLiteral("declaredContentHash"),
        QStringLiteral("contentMatchesDeclaration"), QStringLiteral("trustState"),
        QStringLiteral("issuedAt"), QStringLiteral("expiresAt"),
        QStringLiteral("acceptedAt"), QStringLiteral("source")
    };
    for (auto it = object.constBegin(); it != object.constEnd(); ++it) {
        if (!allowed.contains(it.key())) return std::nullopt;
    }
    const QJsonValue schema = object.value(QStringLiteral("schemaVersion"));
    if (!schema.isDouble() || schema.toDouble() != 1.0
        || !object.value(QStringLiteral("policyType")).isString()
        || !object.value(QStringLiteral("revision")).isString()
        || !object.value(QStringLiteral("contentMatchesDeclaration")).isBool()
        || !object.value(QStringLiteral("trustState")).isString()) {
        return std::nullopt;
    }
    const QString policyType = object.value(QStringLiteral("policyType")).toString();
    if (policyType != QStringLiteral("legacy") && policyType != QStringLiteral("versioned")) {
        return std::nullopt;
    }
    amnezia::ManagedRoutePolicyMetadata metadata;
    metadata.schemaVersion = 1;
    metadata.versioned = policyType == QStringLiteral("versioned");
    metadata.revision = object.value(QStringLiteral("revision")).toString();
    metadata.contentMatchesDeclaration = object.value(
            QStringLiteral("contentMatchesDeclaration")).toBool();
    metadata.trustState = object.value(QStringLiteral("trustState")).toString();
    if (metadata.revision.isEmpty() || metadata.trustState.isEmpty()) return std::nullopt;
    if (object.contains(QStringLiteral("contentHash"))) {
        if (!object.value(QStringLiteral("contentHash")).isString()) return std::nullopt;
        metadata.contentHash = object.value(QStringLiteral("contentHash")).toString();
    }
    if (object.contains(QStringLiteral("declaredContentHash"))) {
        if (!object.value(QStringLiteral("declaredContentHash")).isString()) return std::nullopt;
        metadata.declaredContentHash = object.value(QStringLiteral("declaredContentHash")).toString();
    }
    const auto validPolicyHash = [](const QString &hash) {
        if (!hash.startsWith(QStringLiteral("sha256:")) || hash.size() != 71) return false;
        for (qsizetype index = 7; index < hash.size(); ++index) {
            const QChar ch = hash.at(index);
            if (!ch.isDigit() && (ch < QLatin1Char('a') || ch > QLatin1Char('f'))) return false;
        }
        return true;
    };
    if (!validPolicyHash(metadata.contentHash)
        || !validPolicyHash(metadata.declaredContentHash)
        || !metadata.contentMatchesDeclaration
        || metadata.contentHash != metadata.declaredContentHash) return std::nullopt;
    if (metadata.versioned) {
        const QJsonValue revisionNumber = object.value(QStringLiteral("revisionNumber"));
        constexpr double maxExactJsonInteger = 9007199254740991.0;
        if (!revisionNumber.isDouble() || revisionNumber.toDouble() < 1.0
            || revisionNumber.toDouble() > maxExactJsonInteger
            || revisionNumber.toDouble() != std::floor(revisionNumber.toDouble())) {
            return std::nullopt;
        }
        metadata.revisionNumber = static_cast<qint64>(revisionNumber.toDouble());
        if (metadata.revision != QString::number(metadata.revisionNumber)) return std::nullopt;
    } else if (object.contains(QStringLiteral("revisionNumber"))) {
        return std::nullopt;
    }
    const auto readDate = [&object](const QString &key, QDateTime &target) {
        if (!object.contains(key)) return true;
        if (!object.value(key).isString()) return false;
        target = QDateTime::fromString(object.value(key).toString(), Qt::ISODateWithMs);
        if (!target.isValid()) target = QDateTime::fromString(object.value(key).toString(), Qt::ISODate);
        if (!target.isValid()) return false;
        target = target.toUTC();
        return true;
    };
    if (!readDate(QStringLiteral("issuedAt"), metadata.issuedAt)
        || !readDate(QStringLiteral("expiresAt"), metadata.expiresAt)
        || !readDate(QStringLiteral("acceptedAt"), metadata.acceptedAt)) {
        return std::nullopt;
    }
    if (object.contains(QStringLiteral("source"))) {
        if (!object.value(QStringLiteral("source")).isString()) return std::nullopt;
        metadata.source = object.value(QStringLiteral("source")).toString();
    }
    if (metadata.issuedAt.isValid() && metadata.expiresAt.isValid()
        && metadata.expiresAt <= metadata.issuedAt) return std::nullopt;
    return metadata;
}

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
                                  bool *valid,
                                  QStringList *criticalRoutes)
{
    bool routesValid = true;
    QStringList routes;
    bool protectedValid = true;
    const QStringList endpointRoutes = protectedRoutesForProfile(profile, &protectedValid);
    routes.append(endpointRoutes);
    if (criticalRoutes) *criticalRoutes = endpointRoutes;
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
    // A VPN endpoint already contained by a profile forward route is reached
    // through the tunnel and must not be promoted to a main-table bypass.
    // This is common for the documented ServerX 10.8.1.0/24 endpoint.
    QStringList underlayEndpoints;
    for (const QString &route : routes) {
        quint32 address = 0;
        int prefix = 32;
        if (!parseIpv4Route(route, &address, &prefix)) continue;
        const QHostAddress endpoint(address);
        const bool internal = std::any_of(profile.forwardRoutes.cbegin(),
                                          profile.forwardRoutes.cend(),
                                          [&endpoint](const QString &forwardRoute) {
            return ipv4ContainedByRoute(endpoint, forwardRoute);
        });
        if (!internal) underlayEndpoints.append(route);
    }
    routes = underlayEndpoints;
    if (criticalRoutes) {
        QSet<QString> endpointSet;
        for (const QString &route : endpointRoutes) endpointSet.insert(route);
        criticalRoutes->clear();
        for (const QString &route : underlayEndpoints) {
            if (endpointSet.contains(route)) criticalRoutes->append(route);
        }
    }
    routesValid = routesValid && protectedValid;
    bool validated = false;
    routes = amnezia::managedRoutePolicy::validatedManagedRoutes(routes, &validated);
    routesValid = routesValid && validated;
    routes.removeDuplicates();
    if (criticalRoutes) {
        criticalRoutes->removeDuplicates();
        criticalRoutes->removeIf([&routes](const QString &route) {
            return !routes.contains(route);
        });
    }
    if (valid) {
        *valid = routesValid;
    }
    return routesValid ? routes : QStringList();
}

HeadlessRoutingController::HeadlessRoutingController(
        std::shared_ptr<CommandRunner> runner, QString routeStatePath,
        bool initializeStateNow)
    : m_reconciler(runner ? runner : std::make_shared<RealCommandRunner>(),
                   routeStatePath, initializeStateNow),
      m_statePath(routeStatePath.isEmpty() ? QString() : QDir(QFileInfo(routeStatePath).absolutePath())
                   .filePath(QStringLiteral("routing-controller.json")))
{
    if (initializeStateNow) initializeState();
}

bool HeadlessRoutingController::initializeState()
{
    if (m_initialized) return m_stateValid;
    m_initialized = true;
    if (!m_reconciler.initializeState()) {
        m_stateValid = false;
        m_lastError = QStringLiteral("LinuxRouteReconciler initialize failed");
        qWarning().noquote() << QStringLiteral(
                "HeadlessRoutingController initialize failed stage=reconciler code=recovery_required message=%1")
                .arg(m_reconciler.status().value(QStringLiteral("lastError")).toString().left(512));
        return false;
    }
    if (!loadState()) {
        m_stateValid = false;
        m_lastError = QStringLiteral("routing controller receipt load failed");
        qWarning().noquote() << QStringLiteral(
                "HeadlessRoutingController initialize failed stage=controller_receipt code=recovery_required message=%1")
                .arg(m_lastError);
    }
    return m_stateValid;
}

RoutingResult HeadlessRoutingController::connect(const Profile &profile)
{
    m_lastError.clear();
    if (!m_initialized || !m_stateValid) {
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
                      || protocol == QStringLiteral("ssxray"))) {
        return failure(QStringLiteral("routing_mode_unsupported"),
                       QStringLiteral("all-except requires a native VPN interface; XRay proxy mode is not a full tunnel"));
    }
    if (allExcept) {
        for (const QString &endpoint : endpointHostsFromConfig(profile)) {
            QString literal = endpoint;
            if (literal.startsWith(QLatin1Char('[')) && literal.endsWith(QLatin1Char(']'))) {
                literal = literal.mid(1, literal.size() - 2);
            }
            if (QHostAddress(literal).protocol() == QAbstractSocket::IPv6Protocol) {
                return failure(QStringLiteral("ipv6_endpoint_unsupported"),
                               QStringLiteral("all-except currently requires an IPv4 VPN endpoint"));
            }
        }
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
        const QString dnsInterface = defaultInterfaceFor(profile);
        const QString currentDnsInterface = m_reconciler.status()
                .value(QStringLiteral("dnsInterface")).toString();
        RouteReconcileResult dnsResult { true, {}, {} };
        if (!profile.dnsServers.isEmpty() || !profile.dnsDomains.isEmpty()) {
            if (dnsInterface.isEmpty()) {
                return failure(QStringLiteral("invalid_interface"),
                               QStringLiteral("a VPN interface is required for managed DNS"));
            }
            dnsResult = m_reconciler.configureDns(
                    dnsInterface, profile.dnsServers, profile.dnsDomains);
        } else if (!currentDnsInterface.isEmpty()) {
            dnsResult = m_reconciler.clearDns(currentDnsInterface);
        }
        if (!dnsResult.ok) {
            return failure(dnsResult.code, dnsResult.message);
        }
        m_activeProfile = profile.id;
        // An all-except profile without a server policy is still a valid full
        // tunnel receipt.  Retain the reconciler's interface identity so a
        // restart can bind the kernel table to the controller owner even when
        // the bypass list is intentionally empty.
        m_activeInterface = profile.routingMode == QStringLiteral("all-except")
                ? m_reconciler.status().value(QStringLiteral("interface")).toString()
                : QString();
        m_policyRevision.clear();
        m_policyContentHash.clear();
        m_policySource.clear();
        m_policyEndpoint.clear();
        m_policyResolvedSites = {};
        m_hasPolicy = false;
        m_routingDegraded = false;
        m_routingError.clear();
        m_needsReapply = false;
        if (!saveState()) {
            markRecoveryRequired(QStringLiteral("routing controller receipt could not be saved"));
            return failure(QStringLiteral("recovery_required"),
                           QStringLiteral("routing controller receipt could not be saved"));
        }
        return { true, {}, {} };
    }
    return fetchAndApply(profile);
}

RoutingResult HeadlessRoutingController::refresh(const Profile &profile)
{
    if (!m_initialized || !m_stateValid) {
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
    if (!m_initialized || !m_stateValid) {
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
    m_policyResolvedSites = {};
    m_hasPolicy = false;
    m_policyMetadata.reset();
    m_routingDegraded = false;
    m_routingError.clear();
    m_needsReapply = false;
    if (!saveState()) {
        markRecoveryRequired(QStringLiteral("routing controller state could not be cleared"));
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
    result.insert(QStringLiteral("policyEndpoint"), m_policyEndpoint);
    result.insert(QStringLiteral("policyLoaded"), m_hasPolicy);
    result.insert(QStringLiteral("routingDegraded"), m_routingDegraded);
    result.insert(QStringLiteral("routingError"), m_routingError);
    result.insert(QStringLiteral("needsReapply"), m_needsReapply);
    result.insert(QStringLiteral("policyMetadata"), m_policyMetadata.has_value()
                  ? QJsonValue(m_policyMetadata->toJson()) : QJsonValue(QJsonValue::Null));
    result.insert(QStringLiteral("recoveryRequired"), !m_initialized || !m_stateValid
                  || result.value(QStringLiteral("recoveryRequired")).toBool());
    return result;
}

RoutingResult HeadlessRoutingController::failure(const QString &code,
                                                  const QString &message) const
{
    m_lastError = message;
    qWarning().noquote() << QStringLiteral(
            "HeadlessRoutingController apply failure code=%1 message=%2")
            .arg(code, message.left(512));
    return { false, code, message };
}

RoutingResult HeadlessRoutingController::fallbackToOnlyForward(const Profile &profile,
                                                               const QString &reason)
{
    // Availability-preserving fallback contract: retain the VPN-internal
    // forward routes and send ordinary internet traffic over the underlay.
    // The reconciler's receipt-bound bypass ownership leaves foreign narrow
    // underlay rules untouched while rebuilding this state.
    const QString interfaceName = defaultInterfaceFor(profile);
    if (interfaceName.isEmpty()) {
        markRecoveryRequired(QStringLiteral("all-except failed and fallback has no VPN interface"));
        return failure(QStringLiteral("recovery_required"),
                       QStringLiteral("all-except failed and only-forward fallback is unavailable"));
    }
    const RouteReconcileResult routes = m_reconciler.apply(interfaceName, profile.forwardRoutes);
    if (!routes.ok || m_reconciler.status().value(QStringLiteral("recoveryRequired")).toBool()) {
        markRecoveryRequired(QStringLiteral("all-except failed and only-forward fallback route apply failed"));
        return failure(QStringLiteral("recovery_required"),
                       QStringLiteral("all-except failed and only-forward fallback could not be installed"));
    }
    const QJsonObject beforeDns = m_reconciler.status();
    RouteReconcileResult dns { true, {}, {} };
    if (!profile.dnsServers.isEmpty() || !profile.dnsDomains.isEmpty()) {
        dns = m_reconciler.configureDns(interfaceName, profile.dnsServers, profile.dnsDomains);
    } else if (!beforeDns.value(QStringLiteral("dnsInterface")).toString().isEmpty()) {
        dns = m_reconciler.clearDns(beforeDns.value(QStringLiteral("dnsInterface")).toString());
    }
    if (!dns.ok) {
        markRecoveryRequired(QStringLiteral("all-except failed and only-forward fallback DNS apply failed"));
        return failure(QStringLiteral("recovery_required"),
                       QStringLiteral("all-except failed and only-forward fallback DNS could not be installed"));
    }
    const QJsonObject after = m_reconciler.status();
    if (after.value(QStringLiteral("recoveryRequired")).toBool()
        || after.value(QStringLiteral("mode")).toString() != QStringLiteral("only-forward")
        || ((!profile.forwardRoutes.isEmpty()
             && after.value(QStringLiteral("interface")).toString() != interfaceName)
            || (profile.forwardRoutes.isEmpty()
                && !after.value(QStringLiteral("interface")).toString().isEmpty()))) {
        markRecoveryRequired(QStringLiteral("only-forward fallback readback did not match"));
        return failure(QStringLiteral("recovery_required"),
                       QStringLiteral("all-except failed and fallback readback could not be verified"));
    }
    m_activeProfile = profile.id;
    m_activeInterface = interfaceName;
    m_policyRevision.clear();
    m_policyContentHash.clear();
    m_policySource.clear();
    m_policyEndpoint.clear();
    m_policyResolvedSites = {};
    m_hasPolicy = false;
    m_policyMetadata.reset();
    m_routingDegraded = true;
    m_routingError = reason;
    m_needsReapply = false;
    if (!saveState()) {
        markRecoveryRequired(QStringLiteral("only-forward fallback receipt could not be saved"));
        return failure(QStringLiteral("recovery_required"),
                       QStringLiteral("all-except failed and fallback receipt could not be saved"));
    }
    return failure(QStringLiteral("routing_degraded"),
                   QStringLiteral("all-except routing failed; profile remains connected in only-forward mode: %1")
                           .arg(reason));
}

bool HeadlessRoutingController::markRecoveryRequired(const QString &message)
{
    m_stateValid = false;
    m_lastError = message;
    const bool routingMarked = m_reconciler.requireRecovery(message);
    const bool controllerSaved = saveState();
    if (controllerSaved && routingMarked) return true;
    if (!m_statePath.isEmpty()) {
        QSaveFile marker(m_statePath + QStringLiteral(".recovery-required"));
        if (marker.open(QIODevice::WriteOnly)
            && marker.write(message.toUtf8()) >= 0
            && marker.commit()) {
            QFile::setPermissions(m_statePath + QStringLiteral(".recovery-required"),
                                  QFileDevice::ReadOwner | QFileDevice::WriteOwner);
        }
    }
    return false;
}

bool HeadlessRoutingController::loadState()
{
    if (m_statePath.isEmpty()) return true;
    if (QFileInfo::exists(m_statePath + QStringLiteral(".recovery-required"))) return false;
    QFile file(m_statePath);
    if (!file.exists() || !file.open(QIODevice::ReadOnly)) return !file.exists();
    QJsonParseError error;
    const QJsonDocument document = QJsonDocument::fromJson(file.readAll(), &error);
    if (error.error != QJsonParseError::NoError || !document.isObject()) return false;
    const QJsonObject object = document.object();
    const QStringList allowedFields {
        QStringLiteral("version"), QStringLiteral("activeProfile"),
        QStringLiteral("activeInterface"), QStringLiteral("policyRevision"),
         QStringLiteral("policyContentHash"), QStringLiteral("policySource"),
         QStringLiteral("policyEndpoint"),
         QStringLiteral("policyResolvedSites"), QStringLiteral("policyLoaded"),
         QStringLiteral("policyMetadata"), QStringLiteral("routingDegraded"),
         QStringLiteral("routingError"), QStringLiteral("needsReapply"),
         QStringLiteral("recoveryRequired")
    };
    for (auto it = object.constBegin(); it != object.constEnd(); ++it) {
        if (!allowedFields.contains(it.key())) return false;
    }
    const double stateVersion = object.value(QStringLiteral("version")).toDouble();
    if (!object.value(QStringLiteral("version")).isDouble()
        || (stateVersion != 1.0 && stateVersion != 2.0)
        || !object.value(QStringLiteral("activeProfile")).isString()
        || !object.value(QStringLiteral("activeInterface")).isString()
        || !object.value(QStringLiteral("policyRevision")).isString()
        || !object.value(QStringLiteral("policyContentHash")).isString()
        || !object.value(QStringLiteral("policySource")).isString()
        || !object.value(QStringLiteral("policyLoaded")).isBool()
        || (object.contains(QStringLiteral("policyEndpoint"))
            && !object.value(QStringLiteral("policyEndpoint")).isString())) return false;
    if (object.contains(QStringLiteral("routingDegraded"))
        && !object.value(QStringLiteral("routingDegraded")).isBool()) return false;
    if (object.contains(QStringLiteral("routingError"))
        && !object.value(QStringLiteral("routingError")).isString()) return false;
    if (object.contains(QStringLiteral("needsReapply"))
        && !object.value(QStringLiteral("needsReapply")).isBool()) return false;
    if (object.contains(QStringLiteral("recoveryRequired"))
        && (!object.value(QStringLiteral("recoveryRequired")).isBool()
            || object.value(QStringLiteral("recoveryRequired")).toBool())) return false;
    m_activeProfile = object.value(QStringLiteral("activeProfile")).toString();
    m_activeInterface = object.value(QStringLiteral("activeInterface")).toString();
    m_policyRevision = object.value(QStringLiteral("policyRevision")).toString();
    m_policyContentHash = object.value(QStringLiteral("policyContentHash")).toString();
    m_policySource = object.value(QStringLiteral("policySource")).toString();
    m_policyEndpoint = object.value(QStringLiteral("policyEndpoint")).toString();
    m_hasPolicy = object.value(QStringLiteral("policyLoaded")).toBool();
    m_routingDegraded = object.value(QStringLiteral("routingDegraded")).toBool();
    m_routingError = object.value(QStringLiteral("routingError")).toString();
    const bool hasNeedsReapplyField = object.contains(QStringLiteral("needsReapply"));
    const bool persistedNeedsReapply = object.value(QStringLiteral("needsReapply")).toBool();
    m_needsReapply = persistedNeedsReapply;
    if (!m_routingDegraded && !m_routingError.isEmpty()) return false;
    if (m_routingDegraded
        && (m_activeProfile.isEmpty() || m_activeInterface.isEmpty()
            || m_routingError.trimmed().isEmpty()
            || !QRegularExpression(QStringLiteral("^[A-Za-z0-9_.-]{1,15}$"))
                    .match(m_activeInterface).hasMatch())) {
        return false;
    }
    m_policyMetadata.reset();
    if (object.contains(QStringLiteral("policyMetadata"))) {
        if (!object.value(QStringLiteral("policyMetadata")).isNull()
            && !object.value(QStringLiteral("policyMetadata")).isObject()) return false;
        if (!object.value(QStringLiteral("policyMetadata")).isNull()) {
            m_policyMetadata = policyMetadataFromJson(object.value(QStringLiteral("policyMetadata")));
            if (!m_policyMetadata.has_value()) return false;
        }
    }
    if (object.contains(QStringLiteral("policyResolvedSites"))) {
        if (!object.value(QStringLiteral("policyResolvedSites")).isObject()) return false;
        m_policyResolvedSites = object.value(QStringLiteral("policyResolvedSites")).toObject();
        if (m_policyResolvedSites.size() > amnezia::managedRoutePolicy::maximumSiteCount) {
            return false;
        }
        for (auto it = m_policyResolvedSites.constBegin();
             it != m_policyResolvedSites.constEnd(); ++it) {
            if (it.key().trimmed().isEmpty() || !it.value().isString()) return false;
            bool routesValid = false;
            amnezia::managedRoutePolicy::validatedManagedRouteTokens(
                    it.value().toString(), &routesValid);
            if (!routesValid) return false;
        }
    }
    if (m_hasPolicy) {
        if (m_activeProfile.isEmpty() || m_activeInterface.isEmpty()
            || m_policyRevision.isEmpty() || m_policyContentHash.isEmpty()
            || m_policySource.isEmpty()
            || !QRegularExpression(QStringLiteral("^[A-Za-z0-9_.-]{1,15}$"))
                    .match(m_activeInterface).hasMatch()) {
            return false;
        }
        // Version-1 controller receipts predate the complete metadata object.
        // Reconstruct a conservative legacy identity so the next policy fetch
        // still has a monotonic content/hash anchor; new receipts always write
        // the complete metadata below.
        // v2 receipts always carry the complete metadata object.  Only v1 may
        // synthesize legacy metadata from its three legacy identity fields.
        if (stateVersion == 2.0 && !m_policyMetadata.has_value()) {
            return false;
        }
        if (!m_policyMetadata.has_value()) {
            if (m_policyRevision.isEmpty() || m_policyContentHash.isEmpty()) return false;
            amnezia::ManagedRoutePolicyMetadata legacy;
            legacy.revision = m_policyRevision;
            legacy.contentHash = m_policyContentHash;
            legacy.declaredContentHash = m_policyContentHash;
            legacy.source = m_policySource;
            legacy.acceptedAt = QDateTime::currentDateTimeUtc();
            bool numericRevision = !m_policyRevision.isEmpty();
            for (const QChar ch : m_policyRevision) numericRevision = numericRevision && ch.isDigit();
            bool revisionOk = false;
            const qlonglong revisionNumber = m_policyRevision.toLongLong(&revisionOk);
            if (numericRevision && revisionOk && revisionNumber > 0
                && revisionNumber <= 9007199254740991LL) {
                legacy.versioned = true;
                legacy.revisionNumber = revisionNumber;
            }
            m_policyMetadata = legacy;
        }
        if (stateVersion == 2.0) {
            const QJsonObject metadata = m_policyMetadata->toJson();
            if (metadata.value(QStringLiteral("revision")).toString() != m_policyRevision
                || metadata.value(QStringLiteral("contentHash")).toString()
                    != m_policyContentHash
                || metadata.value(QStringLiteral("declaredContentHash")).toString()
                    != m_policyContentHash
                || metadata.value(QStringLiteral("source")).toString() != m_policySource
                || m_policyEndpoint.isEmpty()) {
                return false;
            }
        }
    } else if (!m_policyRevision.isEmpty() || !m_policyContentHash.isEmpty()
               || !m_policySource.isEmpty() || !m_policyResolvedSites.isEmpty()
               || m_policyMetadata.has_value() || !m_policyEndpoint.isEmpty()) {
        return false;
    }
    const QJsonObject routing = m_reconciler.status();
    if (routing.value(QStringLiteral("recoveryRequired")).toBool()) return false;
    const bool routingNeedsReapply = routing.value(QStringLiteral("needsReapply")).toBool();
    // The reconciler derives this startup-only marker from exact kernel state;
    // the controller receipt is merely a cache.  Adopt that evidence in both
    // directions so stale true/false values cannot block a legitimate restart
    // transition.  The value is persisted below after all controller checks.
    m_needsReapply = routingNeedsReapply;
    if (m_needsReapply) {
        if (m_routingDegraded || m_activeProfile.isEmpty() || m_activeInterface.isEmpty()
            || routing.value(QStringLiteral("mode")).toString() != QStringLiteral("all-except")
            || !routing.value(QStringLiteral("needsReapply")).toBool()
            || !routing.value(QStringLiteral("interfaceOffline")).toBool()
            || routing.value(QStringLiteral("interface")).toString() != m_activeInterface
            || routing.value(QStringLiteral("routeTable")).toInt() != 51821
            || !routing.value(QStringLiteral("routes")).toArray().isEmpty()) {
            return false;
        }
    }
    if (m_hasPolicy) {
        const QString routeInterface = routing.value(QStringLiteral("interface")).toString();
        const QString routeMode = routing.value(QStringLiteral("mode")).toString();
        if (routeInterface.isEmpty() || routeInterface != m_activeInterface
            || (routeMode != QStringLiteral("only-forward")
                && routeMode != QStringLiteral("all-except"))) {
            return false;
        }
        // An empty server policy is valid: the full-tunnel rule and its
        // receipt still provide the all-except invariant, while there are no
        // main-table destinations that need a bypass selector.
    } else if (m_routingDegraded) {
        const QString routeInterface = routing.value(QStringLiteral("interface")).toString();
        const bool routeIdentityValid = routing.value(QStringLiteral("routes")).toArray().isEmpty()
                ? routeInterface.isEmpty()
                : routeInterface == m_activeInterface;
        if (routing.value(QStringLiteral("mode")).toString() != QStringLiteral("only-forward")
            || routing.value(QStringLiteral("routeTable")).toInt() != 0
            || !routing.value(QStringLiteral("bypassRoutes")).toArray().isEmpty()
            || !routing.value(QStringLiteral("criticalBypassRoutes")).toArray().isEmpty()
            || !routeIdentityValid
            || (!routeInterface.isEmpty() && routeInterface != m_activeInterface)) return false;
    } else if (routing.value(QStringLiteral("mode")).toString() == QStringLiteral("all-except")) {
        // A policy-less all-except profile is valid when the full-tunnel
        // table/rules are intact; an empty bypass set means the server policy
        // simply has no main-table exceptions.
        if (m_activeProfile.isEmpty() || m_activeInterface.isEmpty()
            || routing.value(QStringLiteral("interface")).toString() != m_activeInterface
            || routing.value(QStringLiteral("routeTable")).toInt() != 51821
            || routing.value(QStringLiteral("routes")).toArray().size() != 0) {
            return false;
        }
    } else if (!m_activeInterface.isEmpty()
               || !routing.value(QStringLiteral("interface")).toString().isEmpty()
               || !routing.value(QStringLiteral("routes")).toArray().isEmpty()
               || routing.value(QStringLiteral("mode")).toString() == QStringLiteral("all-except")) {
        return false;
    }
    if ((!hasNeedsReapplyField || persistedNeedsReapply != m_needsReapply)
        && !saveState()) return false;
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
        { QStringLiteral("version"), 2 },
        { QStringLiteral("activeProfile"), m_activeProfile },
        { QStringLiteral("activeInterface"), m_activeInterface },
        { QStringLiteral("policyRevision"), m_policyRevision },
        { QStringLiteral("policyContentHash"), m_policyContentHash },
        { QStringLiteral("policySource"), m_policySource },
        { QStringLiteral("policyEndpoint"), m_policyEndpoint },
        { QStringLiteral("policyResolvedSites"), m_policyResolvedSites },
        { QStringLiteral("policyLoaded"), m_hasPolicy },
        { QStringLiteral("policyMetadata"), m_policyMetadata.has_value()
              ? QJsonValue(m_policyMetadata->toJson()) : QJsonValue(QJsonValue::Null) },
        { QStringLiteral("routingDegraded"), m_routingDegraded },
        { QStringLiteral("routingError"), m_routingError },
        { QStringLiteral("needsReapply"), m_needsReapply },
        { QStringLiteral("recoveryRequired"), !m_stateValid },
    };
    const bool committed = file.write(QJsonDocument(object).toJson(QJsonDocument::Compact)) >= 0
        && file.commit();
    if (committed && m_stateValid) {
        QFile::remove(m_statePath + QStringLiteral(".recovery-required"));
    }
    return committed;
}

bool HeadlessRoutingController::restoreRoutingSnapshot(const QJsonObject &snapshot,
                                                       QString *error)
{
    const QString mode = snapshot.value(QStringLiteral("mode")).toString();
    const QString interfaceName = snapshot.value(QStringLiteral("interface")).toString();
    QStringList routes;
    for (const QJsonValue &value : snapshot.value(QStringLiteral("routes")).toArray()) {
        if (!value.isString()) {
            if (error) *error = QStringLiteral("previous route receipt is malformed");
            return false;
        }
        routes.append(value.toString());
    }
    QStringList bypassRoutes;
    for (const QJsonValue &value : snapshot.value(QStringLiteral("bypassRoutes")).toArray()) {
        if (!value.isString()) {
            if (error) *error = QStringLiteral("previous bypass receipt is malformed");
            return false;
        }
        bypassRoutes.append(value.toString());
    }
    QStringList criticalBypassRoutes;
    for (const QJsonValue &value : snapshot.value(QStringLiteral("criticalBypassRoutes")).toArray()) {
        if (!value.isString()) {
            if (error) *error = QStringLiteral("previous critical bypass receipt is malformed");
            return false;
        }
        criticalBypassRoutes.append(value.toString());
    }
    RouteReconcileResult routing;
    if (mode == QStringLiteral("all-except")) {
        if (interfaceName.isEmpty()) return false;
        routing = m_reconciler.applyAllExcept(interfaceName, bypassRoutes, criticalBypassRoutes);
    } else if (mode == QStringLiteral("only-forward") && !interfaceName.isEmpty()) {
        routing = m_reconciler.apply(interfaceName, routes);
    } else if (mode == QStringLiteral("only-forward")) {
        routing = m_reconciler.clear();
    } else {
        if (error) *error = QStringLiteral("previous route receipt has an unsupported mode");
        return false;
    }
    if (!routing.ok) {
        if (error) *error = routing.message;
        return false;
    }
    const QString currentDnsInterface = m_reconciler.status()
            .value(QStringLiteral("dnsInterface")).toString();
    const QString dnsInterface = snapshot.value(QStringLiteral("dnsInterface")).toString();
    QStringList dnsServers;
    QStringList dnsDomains;
    for (const QJsonValue &value : snapshot.value(QStringLiteral("dnsServers")).toArray()) {
        if (!value.isString()) return false;
        dnsServers.append(value.toString());
    }
    for (const QJsonValue &value : snapshot.value(QStringLiteral("dnsDomains")).toArray()) {
        if (!value.isString()) return false;
        dnsDomains.append(value.toString());
    }
    const RouteReconcileResult dns = dnsInterface.isEmpty()
            ? m_reconciler.clearDns(currentDnsInterface)
            : (dnsServers.isEmpty() || dnsDomains.isEmpty()
               ? m_reconciler.clearDns(dnsInterface)
               : m_reconciler.configureDns(dnsInterface, dnsServers, dnsDomains));
    if (!dns.ok) {
        if (error) *error = dns.message;
        return false;
    }
    return true;
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
        const bool persistedSameRouting =
                persistedRouting.value(QStringLiteral("mode")).toString()
                    == profile.routingMode
                && persistedRouting.value(QStringLiteral("interface")).toString()
                    == interfaceName;
        const bool bootstrapRequired = m_needsReapply
                || m_activeProfile != profile.id || !persistedSameRouting;
        const bool reconnectingOffline = m_needsReapply;
        const QJsonObject previousController {
            { QStringLiteral("activeProfile"), m_activeProfile },
            { QStringLiteral("activeInterface"), m_activeInterface },
            { QStringLiteral("policyRevision"), m_policyRevision },
            { QStringLiteral("policyContentHash"), m_policyContentHash },
            { QStringLiteral("policySource"), m_policySource },
            { QStringLiteral("policyEndpoint"), m_policyEndpoint },
            { QStringLiteral("policyResolvedSites"), m_policyResolvedSites },
            { QStringLiteral("policyLoaded"), m_hasPolicy },
            { QStringLiteral("needsReapply"), m_needsReapply },
        };
        const std::optional<amnezia::ManagedRoutePolicyMetadata> previousMetadata = m_policyMetadata;
        const auto restoreBootstrap = [&]() {
            QString restoreError;
            const bool routesRestored = restoreRoutingSnapshot(persistedRouting, &restoreError);
            m_activeProfile = previousController.value(QStringLiteral("activeProfile")).toString();
            m_activeInterface = previousController.value(QStringLiteral("activeInterface")).toString();
            m_policyRevision = previousController.value(QStringLiteral("policyRevision")).toString();
            m_policyContentHash = previousController.value(QStringLiteral("policyContentHash")).toString();
            m_policySource = previousController.value(QStringLiteral("policySource")).toString();
            m_policyEndpoint = previousController.value(QStringLiteral("policyEndpoint")).toString();
            m_policyResolvedSites = previousController.value(QStringLiteral("policyResolvedSites")).toObject();
            m_hasPolicy = previousController.value(QStringLiteral("policyLoaded")).toBool();
            m_needsReapply = previousController.value(QStringLiteral("needsReapply")).toBool();
            m_policyMetadata = previousMetadata;
            if (!routesRestored || !saveState()) {
                if (!markRecoveryRequired(restoreError.isEmpty()
                                           ? QStringLiteral("policy bootstrap rollback failed") : restoreError)) {
                    m_lastError = QStringLiteral("policy bootstrap rollback and durable recovery marker failed");
                }
                return false;
            }
            return true;
        };
        const auto failAllExcept = [&](const QString &reason) {
            if (profile.routingMode == QStringLiteral("all-except")
                && !m_reconciler.status().value(QStringLiteral("recoveryRequired")).toBool()) {
                return fallbackToOnlyForward(profile, reason);
            }
            return failure(QStringLiteral("recovery_required"), reason);
        };
        if (bootstrapRequired) {
            // An offline all-except receipt is the last known-good allow-list.
            // Reconnect must restore that complete set before the policy
            // endpoint is queried; rebuilding from the profile's current
            // critical selectors would otherwise delete the retained policy
            // rules while the VPN interface is still coming back.
            const RoutingResult bootstrap = applyRoutes(
                    profile, {}, reconnectingOffline
                        && profile.routingMode == QStringLiteral("all-except"));
            if (!bootstrap.ok) {
                if (profile.routingMode == QStringLiteral("all-except")
                    && bootstrap.code != QStringLiteral("recovery_required")
                    && bootstrap.code != QStringLiteral("routing_degraded")) {
                    return failAllExcept(bootstrap.message);
                }
                if (!restoreBootstrap()) {
                    return failure(QStringLiteral("recovery_required"),
                                   QStringLiteral("policy bootstrap failed and previous state could not be restored"));
                }
                return bootstrap;
            }
            if (reconnectingOffline) {
                // applyRoutes is also used for the bootstrap transaction and
                // normally retires needsReapply after its own table/DNS
                // postcondition.  Keep the explicit marker through policy
                // fetch and the final critical/server route apply so a crash
                // in this window reconnects safely on the next start.
                m_needsReapply = true;
                if (!saveState()) {
                    markRecoveryRequired(QStringLiteral(
                            "offline routing reapply marker could not be retained"));
                    return failure(QStringLiteral("recovery_required"),
                                   QStringLiteral("offline routing reapply state could not be saved"));
                }
            }
        }
        const std::optional<amnezia::ManagedRoutePolicyMetadata> current = m_policyMetadata;

        QString policyUrlError;
        if (!isSafePolicyEndpoint(profile, profile.serverRulesUrl, &policyUrlError)) {
            if (profile.routingMode == QStringLiteral("all-except")) {
                return failAllExcept(policyUrlError);
            }
            if (bootstrapRequired && !restoreBootstrap()) {
                return failure(QStringLiteral("recovery_required"),
                               QStringLiteral("policy endpoint was rejected and bootstrap state could not be restored"));
            }
            return failure(QStringLiteral("policy_transport_invalid"), policyUrlError);
        }
        const ServerRoutingPolicyResult fetched = fetchPolicy(profile, current);
        if (!fetched.ok) {
            if (profile.routingMode == QStringLiteral("all-except")) {
                return failAllExcept(fetched.message);
            }
            if (bootstrapRequired && !restoreBootstrap()) {
                return failure(QStringLiteral("recovery_required"),
                               QStringLiteral("policy fetch failed and bootstrap state could not be restored"));
            }
            return failure(fetched.code, fetched.message);
        }
        const QJsonObject previousResolvedSites = m_policyEndpoint == profile.serverRulesUrl
                ? m_policyResolvedSites : QJsonObject {};
        const ServerRoutingPolicyResult resolved = ServerRoutingPolicy::resolve(
                fetched.policy, 4000, previousResolvedSites);
        if (!resolved.ok) {
            if (profile.routingMode == QStringLiteral("all-except")) {
                return failAllExcept(resolved.message);
            }
            if (bootstrapRequired && !restoreBootstrap()) {
                return failure(QStringLiteral("recovery_required"),
                               QStringLiteral("policy resolution failed and bootstrap state could not be restored"));
            }
            return failure(resolved.code, resolved.message);
        }
        serverRoutes = resolved.policy.routes;
        const RoutingResult applied = applyRoutes(profile, serverRoutes);
        if (!applied.ok) {
            if (profile.routingMode == QStringLiteral("all-except")
                && applied.code != QStringLiteral("recovery_required")
                && applied.code != QStringLiteral("routing_degraded")) {
                return failAllExcept(applied.message);
            }
            if (applied.code == QStringLiteral("routing_degraded")) {
                return applied;
            }
            if (bootstrapRequired && !restoreBootstrap()) {
                return failure(QStringLiteral("recovery_required"),
                               QStringLiteral("policy apply failed and bootstrap state could not be restored"));
            }
            return applied;
        }
        // Advance the policy receipt only after the route transaction commits;
        // a failed apply must not make a newer policy look like LKG state.
        m_policyRevision = resolved.policy.revision;
        m_policyContentHash = resolved.policy.contentHash;
        m_policySource = resolved.policy.source;
        m_policyEndpoint = profile.serverRulesUrl;
        m_policyResolvedSites = resolved.policy.resolvedSites;
        m_hasPolicy = true;
        m_policyMetadata = resolved.policy.metadata;
        // The controller receipt binds policy metadata to the transport
        // endpoint.  The generic policy validator intentionally does not own
        // that transport identity, so stamp it here before persisting v2.
        m_policyMetadata->source = m_policySource;
        if (!saveState()) {
            markRecoveryRequired(QStringLiteral("routing policy receipt could not be saved"));
            return failure(QStringLiteral("recovery_required"),
                           QStringLiteral("routing policy receipt could not be saved"));
        }
        return applied;
    }

    const RoutingResult applied = applyRoutes(profile, serverRoutes);
    if (applied.ok) {
        m_policyRevision.clear();
        m_policyContentHash.clear();
        m_policySource.clear();
        m_policyEndpoint.clear();
        m_policyResolvedSites = {};
        m_hasPolicy = false;
        m_policyMetadata.reset();
        if (!saveState()) {
            markRecoveryRequired(QStringLiteral("routing controller receipt could not be saved"));
            return failure(QStringLiteral("recovery_required"),
                           QStringLiteral("routing controller receipt could not be saved"));
        }
    }
    return applied;
}

RoutingResult HeadlessRoutingController::applyRoutes(const Profile &profile,
                                                     const QStringList &serverRoutes,
                                                     bool preserveOfflineLkg)
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
        QStringList criticalRoutes;
        QStringList underlayRoutes;
        if (preserveOfflineLkg) {
            const bool receiptShape = previousRouting.value(QStringLiteral("mode")).toString()
                    == QStringLiteral("all-except")
                && previousRouting.value(QStringLiteral("interface")).toString()
                    == interfaceName
                && previousRouting.value(QStringLiteral("routes")).toArray().isEmpty()
                && previousRouting.value(QStringLiteral("needsReapply")).toBool()
                && previousRouting.value(QStringLiteral("interfaceOffline")).toBool()
                && previousRouting.value(QStringLiteral("routeTable")).toInt() == 51821;
            if (!receiptShape) {
                return failure(QStringLiteral("offline_lkg_invalid"),
                               QStringLiteral("offline all-except receipt is not reconnectable"));
            }
            // This branch intentionally replaces the generic profile/server
            // merge with the persisted all-except LKG. Keep forwardRoutes on
            // the VPN side; never turn them into underlay bypass selectors
            // during reconnect.
            routes.clear();
            for (const QJsonValue &value : previousRouting
                     .value(QStringLiteral("bypassRoutes")).toArray()) {
                if (!value.isString()) {
                    return failure(QStringLiteral("offline_lkg_invalid"),
                                   QStringLiteral("offline all-except bypass receipt is malformed"));
                }
                routes.append(value.toString());
            }
            for (const QJsonValue &value : previousRouting
                     .value(QStringLiteral("criticalBypassRoutes")).toArray()) {
                if (!value.isString()) {
                    return failure(QStringLiteral("offline_lkg_invalid"),
                                   QStringLiteral("offline all-except critical receipt is malformed"));
                }
                criticalRoutes.append(value.toString());
            }
            bool lkgValid = false;
            const QStringList boundedLkg = amnezia::managedRoutePolicy::validatedManagedRoutes(
                    routes, &lkgValid);
            bool criticalValid = false;
            const QStringList boundedCritical = amnezia::managedRoutePolicy::validatedManagedRoutes(
                    criticalRoutes, &criticalValid);
            if (!lkgValid || boundedLkg.size() != routes.size()
                || !criticalValid || boundedCritical.size() != criticalRoutes.size()
                || !std::all_of(criticalRoutes.cbegin(), criticalRoutes.cend(),
                                [&routes](const QString &route) { return routes.contains(route); })) {
                return failure(QStringLiteral("offline_lkg_invalid"),
                               QStringLiteral("offline all-except receipt contains invalid routes"));
            }
            // Keep the persisted route order byte-for-byte.  Add only new
            // endpoint/underlay selectors discovered for the reconnect, and
            // classify them as critical so they are installed first.
            bool currentValid = false;
            QStringList currentCritical;
            allExceptBypassRoutes(profile, {}, &currentValid, &currentCritical);
            if (!currentValid) {
                return failure(QStringLiteral("invalid_routes"),
                               QStringLiteral("full-tunnel endpoint bootstrap routes are invalid"));
            }
            QString underlayError;
            underlayRoutes = m_reconciler.activeUnderlayProtectedRoutes(
                    interfaceName, profile.forwardRoutes, &underlayError);
            if (!underlayError.isEmpty()) {
                return failure(QStringLiteral("full_tunnel_underlay_probe_failed"), underlayError);
            }
            currentCritical.append(underlayRoutes);
            currentCritical.removeDuplicates();
            for (const QString &route : currentCritical) {
                if (!routes.contains(route)) routes.append(route);
                if (!criticalRoutes.contains(route)) criticalRoutes.append(route);
            }
            routesValid = true;
        } else {
            routes = allExceptBypassRoutes(profile, serverRoutes, &routesValid, &criticalRoutes);
            if (!routesValid) {
                return failure(QStringLiteral("invalid_routes"),
                               QStringLiteral("full-tunnel bypass routes exceed the safety boundary"));
            }
        }
        if (!preserveOfflineLkg) {
            QString underlayError;
            underlayRoutes = m_reconciler.activeUnderlayProtectedRoutes(
                    interfaceName, profile.forwardRoutes, &underlayError);
            if (!underlayError.isEmpty()) {
                return failure(QStringLiteral("full_tunnel_underlay_probe_failed"), underlayError);
            }
        }
        // Keep endpoint and directly-connected underlay selectors at the head
        // of the target list.  Their order is the safety contract: critical
        // routes are installed before any server policy batch.
        QStringList orderedRoutes;
        if (preserveOfflineLkg) {
            orderedRoutes = routes;
        } else {
            orderedRoutes = criticalRoutes;
            orderedRoutes.append(underlayRoutes);
            QSet<QString> orderedSeen;
            for (const QString &route : std::as_const(orderedRoutes)) orderedSeen.insert(route);
            for (const QString &route : routes) {
                if (!orderedSeen.contains(route)) {
                    orderedRoutes.append(route);
                    orderedSeen.insert(route);
                }
            }
        }
        bool orderedValid = false;
        orderedRoutes = amnezia::managedRoutePolicy::validatedManagedRoutes(
                orderedRoutes, &orderedValid);
        if (!orderedValid) {
            return failure(QStringLiteral("invalid_routes"),
                           QStringLiteral("full-tunnel underlay routes exceed the safety boundary"));
        }
        criticalRoutes.append(underlayRoutes);
        criticalRoutes.removeDuplicates();
        result = m_reconciler.applyAllExcept(interfaceName, orderedRoutes, criticalRoutes);
    } else {
        result = m_reconciler.apply(interfaceName, routes);
    }
    if (!result.ok) {
        qWarning().noquote() << QStringLiteral(
                "HeadlessRoutingController apply failed code=%1 message=%2")
                .arg(result.code, result.message.left(512));
        if (allExcept && result.code == QStringLiteral("full_tunnel_postcondition_failed")) {
            return fallbackToOnlyForward(profile, result.message);
        }
        return failure(result.code, result.message);
    }
    const QString previousDnsInterface = previousRouting.value(QStringLiteral("dnsInterface")).toString();
    RouteReconcileResult dnsResult { true, {}, {} };
    if (!profile.dnsServers.isEmpty() || !profile.dnsDomains.isEmpty()) {
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
                QStringList oldCriticalBypass;
                for (const QJsonValue &value : previousRouting
                         .value(QStringLiteral("criticalBypassRoutes")).toArray()) {
                    if (value.isString()) oldCriticalBypass.append(value.toString());
                }
                routeRestore = m_reconciler.applyAllExcept(
                        previousRouting.value(QStringLiteral("interface")).toString(), oldBypass,
                        oldCriticalBypass);
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
            const QString currentDnsInterface = m_reconciler.status()
                    .value(QStringLiteral("dnsInterface")).toString();
            const RouteReconcileResult dnsRestore = oldServers.isEmpty() || oldDomains.isEmpty()
                    ? m_reconciler.clearDns(oldDnsInterface.isEmpty()
                                                ? currentDnsInterface : oldDnsInterface)
                    : m_reconciler.configureDns(oldDnsInterface, oldServers, oldDomains);
            if (!routeRestore.ok || !dnsRestore.ok) {
                const QString recoveryMessage = QStringLiteral(
                        "DNS refresh failed and previous route/DNS state could not be restored");
                markRecoveryRequired(recoveryMessage);
                return failure(QStringLiteral("recovery_required"),
                               QStringLiteral("DNS refresh failed and the previous route/DNS receipt could not be restored"));
            }
        return failure(dnsResult.code, dnsResult.message);
    }
    m_activeProfile = profile.id;
    m_activeInterface = interfaceName;
    m_routingDegraded = false;
    m_routingError.clear();
    // applyAllExcept/apply and the DNS readback above are the postcondition
    // gate.  Do not clear the offline marker before both have succeeded.
    m_needsReapply = false;
    if (!saveState()) {
        markRecoveryRequired(QStringLiteral("routing controller receipt could not be saved"));
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
    QByteArray data;
    bool tooLarge = false;
    const QVariant contentLength = reply->header(QNetworkRequest::ContentLengthHeader);
    bool contentLengthOk = false;
    const qlonglong declaredLength = contentLength.toLongLong(&contentLengthOk);
    if (contentLengthOk && declaredLength > MaximumPolicyBytes) {
        tooLarge = true;
        reply->abort();
    }
    const auto consumeReadyData = [&]() {
        if (tooLarge) return;
        const QByteArray chunk = reply->readAll();
        if (chunk.isEmpty()) return;
        if (data.size() > MaximumPolicyBytes - chunk.size()) {
            tooLarge = true;
            reply->abort();
            return;
        }
        data.append(chunk);
    };
    QObject::connect(reply, &QNetworkReply::readyRead, &loop, consumeReadyData);
    timer.start(PolicyRequestTimeoutMs);
    loop.exec();

    if (!reply->isFinished()) {
        reply->abort();
        reply->deleteLater();
        return { false, QStringLiteral("policy_timeout"),
                 QStringLiteral("server routing policy request timed out"), {} };
    }
    consumeReadyData();
    if (tooLarge) {
        reply->deleteLater();
        return { false, QStringLiteral("policy_too_large"),
                 QStringLiteral("server routing policy exceeds the byte limit"), {} };
    }
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
    return ServerRoutingPolicy::parse(data, current, url);
}

} // namespace amnezia::headless
