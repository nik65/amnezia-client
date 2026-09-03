#ifndef AMNEZIA_HEADLESS_SERVER_ROUTING_POLICY_H
#define AMNEZIA_HEADLESS_SERVER_ROUTING_POLICY_H

#include <QJsonObject>
#include <QString>
#include <QStringList>

#include <optional>

#include "../client/core/utils/managedRoutePolicy.h"

namespace amnezia::headless
{

struct ServerRoutingPolicySnapshot
{
    QJsonObject sourceSites;
    QJsonObject resolvedSites;
    QStringList routes;
    QStringList unresolvedSites;
    QString revision;
    QString contentHash;
    QDateTime issuedAt;
    QDateTime expiresAt;
    bool forceEnabled = false;
    QString source;
    amnezia::ManagedRoutePolicyMetadata metadata;
};

struct ServerRoutingPolicyResult
{
    bool ok = false;
    QString code;
    QString message;
    ServerRoutingPolicySnapshot policy;
};

class ServerRoutingPolicy final
{
public:
    static ServerRoutingPolicyResult parse(
            const QByteArray &payload,
            const std::optional<amnezia::ManagedRoutePolicyMetadata> &current = std::nullopt,
            const QString &source = {},
            const QJsonObject &previousResolvedSites = {});

    // Resolve only domains whose server value is empty.  The result is bounded
    // and fail-closed; unresolved new names never become bypass routes, while
    // a still-present name may retain its last-known-good resolution.
    static ServerRoutingPolicyResult resolve(
            ServerRoutingPolicySnapshot policy, int deadlineMs = 4000,
            const QJsonObject &previousResolvedSites = {});

private:
    static ServerRoutingPolicyResult failure(const QString &code,
                                             const QString &message);
};

} // namespace amnezia::headless

#endif // AMNEZIA_HEADLESS_SERVER_ROUTING_POLICY_H
