#include "serverRoutingPolicy.h"

#include <QElapsedTimer>
#include <QEventLoop>
#include <QHostInfo>
#include <QJsonDocument>
#include <QJsonParseError>
#include <QTimer>

#include <algorithm>
#include <utility>

namespace amnezia::headless
{
namespace
{

constexpr qsizetype MaximumPayloadBytes = 1024 * 1024;
constexpr int MinimumLookupTimeoutMs = 50;

QJsonValue firstSiteValue(const QJsonObject &payload,
                          const QStringList &keys)
{
    for (const QString &key : keys) {
        const QJsonValue value = payload.value(key);
        if (value.isObject() || value.isArray()) {
            return value;
        }
    }
    return {};
}

bool containsSiteValue(const QJsonObject &payload)
{
    return !firstSiteValue(payload, {
        QStringLiteral("server.except"),
        QStringLiteral("serverExcept"),
        QStringLiteral("managedSplitTunnelExceptSourceSites"),
        QStringLiteral("managedSplitTunnelExceptSites"),
    }).isUndefined();
}

QStringList routesFromSites(const QJsonObject &sites,
                            QStringList *unresolvedSites,
                            bool *valid)
{
    QStringList routes;
    bool isValid = true;
    if (unresolvedSites) {
        unresolvedSites->clear();
    }

    for (auto it = sites.constBegin(); it != sites.constEnd(); ++it) {
        const QString directRoute = amnezia::managedRoutePolicy::canonicalManagedIpv4Route(it.key());
        if (!directRoute.isEmpty()) {
            routes.append(directRoute);
            continue;
        }

        bool valueValid = false;
        const QStringList fallbackRoutes =
                amnezia::managedRoutePolicy::validatedManagedRouteTokens(
                        it.value().toString(), &valueValid);
        if (!valueValid) {
            isValid = false;
            break;
        }
        if (fallbackRoutes.isEmpty()) {
            if (unresolvedSites) {
                unresolvedSites->append(it.key());
            }
        } else {
            routes.append(fallbackRoutes);
        }
    }

    bool routesValid = false;
    routes = amnezia::managedRoutePolicy::validatedManagedRoutes(routes, &routesValid);
    isValid = isValid && routesValid;
    routes.removeDuplicates();
    routes.sort();
    if (valid) {
        *valid = isValid;
    }
    return isValid ? routes : QStringList();
}

bool boundedSites(const QJsonObject &source, const QJsonObject &candidate,
                  QJsonObject &bounded)
{
    bounded = {};
    for (auto it = candidate.constBegin(); it != candidate.constEnd(); ++it) {
        if (!source.contains(it.key())) {
            return false;
        }
        bounded.insert(it.key(), it.value());
    }
    return true;
}

} // namespace

ServerRoutingPolicyResult ServerRoutingPolicy::failure(const QString &code,
                                                        const QString &message)
{
    return { false, code, message, {} };
}

ServerRoutingPolicyResult ServerRoutingPolicy::parse(
        const QByteArray &payload,
        const std::optional<amnezia::ManagedRoutePolicyMetadata> &current,
        const QString &source)
{
    if (payload.isEmpty() || payload.size() > MaximumPayloadBytes) {
        return failure(QStringLiteral("policy_too_large"),
                       QStringLiteral("server routing policy exceeds the byte limit"));
    }

    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(payload, &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
        return failure(QStringLiteral("invalid_policy"),
                       QStringLiteral("server routing policy is not a JSON object"));
    }
    const QJsonObject object = document.object();
    if (!containsSiteValue(object)) {
        return failure(QStringLiteral("invalid_policy"),
                       QStringLiteral("server routing policy has no managed site list"));
    }

    const QJsonValue sourceValue = firstSiteValue(object, {
        QStringLiteral("managedSplitTunnelExceptSourceSites"),
        QStringLiteral("managedSplitTunnelExceptSites"),
        QStringLiteral("server.except"),
        QStringLiteral("serverExcept"),
    });
    const QJsonValue resolvedValue = firstSiteValue(object, {
        QStringLiteral("server.except"),
        QStringLiteral("serverExcept"),
        QStringLiteral("managedSplitTunnelExceptSites"),
        QStringLiteral("managedSplitTunnelExceptSourceSites"),
    });
    bool sourceValid = false;
    bool resolvedValid = false;
    const QJsonObject sourceSites = amnezia::managedRoutePolicy::canonicalSourceSites(
            sourceValue, &sourceValid);
    const QJsonObject resolvedSitesCandidate = amnezia::managedRoutePolicy::canonicalSourceSites(
            resolvedValue, &resolvedValid);
    if (!sourceValid || !resolvedValid) {
        return failure(QStringLiteral("invalid_policy"),
                       QStringLiteral("managed site list is invalid or oversized"));
    }

    QJsonObject resolvedSites;
    if (!boundedSites(sourceSites, resolvedSitesCandidate, resolvedSites)) {
        return failure(QStringLiteral("invalid_policy"),
                       QStringLiteral("resolved managed sites are not bound to source sites"));
    }

    QString metadataError;
    const auto metadata = amnezia::managedRoutePolicy::validateCandidate(
            object, current, QDateTime::currentDateTimeUtc(), &metadataError);
    if (!metadata.has_value()) {
        return failure(QStringLiteral("stale_or_invalid_policy"),
                       metadataError.isEmpty() ? QStringLiteral("server routing policy was rejected")
                                               : metadataError);
    }

    QStringList unresolvedSites;
    bool routesValid = false;
    const QStringList routes = routesFromSites(resolvedSites, &unresolvedSites, &routesValid);
    if (!routesValid) {
        return failure(QStringLiteral("invalid_policy"),
                       QStringLiteral("managed route list is invalid or oversized"));
    }

    const QJsonValue forceValue = object.value(QStringLiteral("managedSplitTunnelForceEnabled"));
    if (!forceValue.isUndefined() && !forceValue.isBool()) {
        return failure(QStringLiteral("invalid_policy"),
                       QStringLiteral("managed routing force flag is malformed"));
    }

    ServerRoutingPolicySnapshot snapshot;
    snapshot.sourceSites = sourceSites;
    snapshot.resolvedSites = resolvedSites;
    snapshot.routes = routes;
    snapshot.unresolvedSites = unresolvedSites;
    snapshot.revision = metadata->revision;
    snapshot.contentHash = metadata->contentHash;
    snapshot.issuedAt = metadata->issuedAt;
    snapshot.expiresAt = metadata->expiresAt;
    snapshot.forceEnabled = forceValue.toBool(false);
    snapshot.source = source;
    snapshot.metadata = metadata.value();
    return { true, {}, {}, std::move(snapshot) };
}

ServerRoutingPolicyResult ServerRoutingPolicy::resolve(
        ServerRoutingPolicySnapshot policy, int deadlineMs)
{
    if (deadlineMs < MinimumLookupTimeoutMs || policy.unresolvedSites.size()
        > amnezia::managedRoutePolicy::maximumSiteCount) {
        return failure(QStringLiteral("invalid_resolution_deadline"),
                       QStringLiteral("managed DNS resolution deadline is invalid"));
    }

    QElapsedTimer elapsed;
    elapsed.start();
    QObject context;
    for (const QString &domain : std::as_const(policy.unresolvedSites)) {
        const int remaining = deadlineMs - static_cast<int>(elapsed.elapsed());
        if (remaining < MinimumLookupTimeoutMs) {
            return failure(QStringLiteral("managed_dns_timeout"),
                           QStringLiteral("managed DNS resolution deadline exceeded"));
        }

        QHostInfo result;
        bool completed = false;
        QEventLoop loop;
        QTimer timer;
        timer.setSingleShot(true);
        const int lookupId = QHostInfo::lookupHost(
                domain, &context, [&result, &completed, &loop](const QHostInfo &info) {
                    result = info;
                    completed = true;
                    loop.quit();
                });
        QObject::connect(&timer, &QTimer::timeout, &loop, &QEventLoop::quit);
        timer.start(remaining);
        loop.exec();
        if (!completed) {
            QHostInfo::abortHostLookup(lookupId);
            return failure(QStringLiteral("managed_dns_timeout"),
                           QStringLiteral("managed DNS resolution deadline exceeded"));
        }
        if (result.error() != QHostInfo::NoError) {
            return failure(QStringLiteral("managed_dns_unresolved"),
                           QStringLiteral("a managed site could not be resolved"));
        }

        QStringList addresses;
        for (const QHostAddress &address : result.addresses()) {
            if (address.protocol() != QAbstractSocket::IPv4Protocol) {
                continue;
            }
            const QString route = amnezia::managedRoutePolicy::canonicalManagedIpv4Route(
                    address.toString());
            if (!route.isEmpty() && !addresses.contains(route)) {
                addresses.append(route);
            }
            if (addresses.size() >= amnezia::managedRoutePolicy::maximumRoutesPerSite) {
                break;
            }
        }
        if (addresses.isEmpty()) {
            return failure(QStringLiteral("managed_dns_unresolved"),
                           QStringLiteral("a managed site has no allowed IPv4 address"));
        }
        policy.resolvedSites.insert(domain, addresses.join(QStringLiteral(", ")));
        policy.routes.append(addresses);
    }

    bool routesValid = false;
    policy.routes = amnezia::managedRoutePolicy::validatedManagedRoutes(
            policy.routes, &routesValid);
    if (!routesValid) {
        return failure(QStringLiteral("invalid_policy"),
                       QStringLiteral("resolved managed routes exceed the safety boundary"));
    }
    policy.routes.removeDuplicates();
    policy.routes.sort();
    policy.unresolvedSites.clear();
    return { true, {}, {}, std::move(policy) };
}

} // namespace amnezia::headless
