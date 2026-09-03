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

// Build only the destinations that must bypass the all-except tunnel.  The
// profile's forwardRoutes are VPN-internal routes and deliberately remain on
// the tunnel side; only the server allow-list, DNS servers, and public VPN
// endpoint bootstrap routes use the main/underlay table.
QStringList allExceptBypassRoutes(const Profile &profile,
                                  const QStringList &serverRoutes,
                                  bool *valid = nullptr);

// Validate policy transport before any network request. HTTP is accepted only
// for a literal VPN-internal address covered by profile.forwardRoutes.
bool isSafePolicyEndpoint(const Profile &profile, const QString &url,
                          QString *error = nullptr);

class HeadlessRoutingController final
{
public:
    explicit HeadlessRoutingController(std::shared_ptr<CommandRunner> runner = {},
                                       QString routeStatePath = {},
                                       bool initializeState = true);

    bool initializeState();

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
            const Profile &profile,
            const std::optional<amnezia::ManagedRoutePolicyMetadata> &current);
    bool loadState();
    bool saveState() const;
    bool restoreRoutingSnapshot(const QJsonObject &snapshot, QString *error = nullptr);
    bool markRecoveryRequired(const QString &message);

    LinuxRouteReconciler m_reconciler;
    QString m_activeProfile;
    QString m_activeInterface;
    QString m_policyRevision;
    QString m_policyContentHash;
    QString m_policySource;
    QString m_policyEndpoint;
    QJsonObject m_policyResolvedSites;
    bool m_hasPolicy = false;
    std::optional<amnezia::ManagedRoutePolicyMetadata> m_policyMetadata;
    QString m_statePath;
    bool m_stateValid = true;
    bool m_initialized = false;
    mutable QString m_lastError;
};

} // namespace amnezia::headless

#endif // AMNEZIA_HEADLESS_ROUTING_CONTROLLER_H
