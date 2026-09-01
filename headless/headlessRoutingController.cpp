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

#include <utility>

namespace amnezia::headless
{
namespace
{

constexpr int PolicyRequestTimeoutMs = 5000;
constexpr qsizetype MaximumPolicyBytes = 1024 * 1024;
constexpr qsizetype MaximumProfileConfigBytes = 1024 * 1024;

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

QStringList protectedRoutesForProfile(const Profile &profile)
{
    QStringList routes;
    const QUrl rulesUrl(profile.serverRulesUrl, QUrl::StrictMode);
    appendHostRoutes(routes, rulesUrl.host());
    for (const QString &dnsServer : profile.dnsServers) {
        appendHostRoutes(routes, dnsServer);
    }
    for (const QString &endpoint : endpointHostsFromConfig(profile)) {
        appendHostRoutes(routes, endpoint);
    }
    bool valid = false;
    routes = amnezia::managedRoutePolicy::validatedManagedRoutes(routes, &valid);
    return valid ? routes : QStringList();
}

} // namespace

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
        if (m_activeProfile != profile.id && !profile.forwardRoutes.isEmpty()) {
            const RoutingResult bootstrap = applyRoutes(profile, {});
            if (!bootstrap.ok) {
                return bootstrap;
            }
        }
        const std::optional<amnezia::ManagedRoutePolicyMetadata> current = m_policyMetadata;

        const ServerRoutingPolicyResult fetched = fetchPolicy(profile.serverRulesUrl, current);
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
        routes.append(protectedRoutesForProfile(profile));
        routes = mergeRoutes({}, routes, &routesValid);
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

ServerRoutingPolicyResult HeadlessRoutingController::fetchPolicy(
        const QString &url, const std::optional<amnezia::ManagedRoutePolicyMetadata> &current)
{
    QNetworkAccessManager manager;
    QNetworkRequest request { QUrl(url) };
    request.setTransferTimeout(PolicyRequestTimeoutMs);
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
