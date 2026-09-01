#ifndef AMNEZIA_HEADLESS_ROUTING_CONTROLLER_H
#define AMNEZIA_HEADLESS_ROUTING_CONTROLLER_H

#include <QJsonObject>
#include <QString>

#include <memory>
#include <optional>

#include "linuxRouteReconciler.h"
#include "profileStore.h"
#include "serverRoutingPolicy.h"

namespace amnezia::headless
{

struct RoutingResult
{
    bool ok = false;
    QString code;
    QString message;
};

class HeadlessRoutingController final
{
public:
    explicit HeadlessRoutingController(std::shared_ptr<CommandRunner> runner = {},
                                       QString routeStatePath = {});

    RoutingResult connect(const Profile &profile);
    RoutingResult refresh(const Profile &profile);
    RoutingResult disconnect();
    QJsonObject status() const;

private:
    RoutingResult failure(const QString &code, const QString &message) const;
    RoutingResult fetchAndApply(const Profile &profile);
    RoutingResult applyRoutes(const Profile &profile,
                              const QStringList &serverRoutes);
    static QString defaultInterfaceFor(const Profile &profile);
    static ServerRoutingPolicyResult fetchPolicy(
            const QString &url,
            const std::optional<amnezia::ManagedRoutePolicyMetadata> &current);

    LinuxRouteReconciler m_reconciler;
    QString m_activeProfile;
    QString m_activeInterface;
    QString m_policyRevision;
    QString m_policyContentHash;
    QString m_policySource;
    bool m_hasPolicy = false;
    std::optional<amnezia::ManagedRoutePolicyMetadata> m_policyMetadata;
    mutable QString m_lastError;
};

} // namespace amnezia::headless

#endif // AMNEZIA_HEADLESS_ROUTING_CONTROLLER_H
