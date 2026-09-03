#ifndef AMNEZIA_HEADLESS_LINUX_ROUTE_RECONCILER_H
#define AMNEZIA_HEADLESS_LINUX_ROUTE_RECONCILER_H

#include <QJsonObject>
#include <QString>
#include <QStringList>

#include <memory>
#include <QSet>

#include "vpnBackend.h"

namespace amnezia::headless
{

struct RouteReconcileResult
{
    bool ok = false;
    QString code;
    QString message;
};

class LinuxRouteReconciler final
{
public:
    explicit LinuxRouteReconciler(std::shared_ptr<CommandRunner> runner = {},
                                  QString statePath = {});

    RouteReconcileResult apply(const QString &interfaceName,
                               const QStringList &routes);
    // Install a policy-routing full tunnel.  The supplied routes are the
    // server-managed allow-list and must stay in the ordinary main table;
    // every other IPv4/IPv6 destination is sent to the VPN interface.
    RouteReconcileResult applyAllExcept(const QString &interfaceName,
                                        const QStringList &bypassRoutes);
    RouteReconcileResult configureDns(const QString &interfaceName,
                                      const QStringList &dnsServers,
                                      const QStringList &dnsDomains);
    RouteReconcileResult clearDns(const QString &interfaceName);
    RouteReconcileResult clear();
    QJsonObject status() const;

private:
    RouteReconcileResult failure(const QString &code, const QString &message) const;
    bool markRecoveryRequired(const QString &message);
    QString ipExecutable() const;
    QString resolvectlExecutable() const;
    bool loadState();
    bool saveState() const;
    RouteReconcileResult clearFullTunnel();
    RouteReconcileResult applyFullTunnel(const QString &interfaceName,
                                         const QStringList &bypassRoutes);
    bool addFullTunnelRule(const QStringList &arguments);
    bool removeFullTunnelRule(const QStringList &arguments);
    bool addFullTunnelRoute(const QStringList &arguments);
    bool removeFullTunnelRoute(const QStringList &arguments);
    struct RuleSnapshot
    {
        QSet<int> occupied;
        QSet<int> ownedBypass;
        QSet<int> ownedFull;
        QSet<int> ownedFullV4;
        QSet<int> ownedFullV6;
        QStringList lines;
        QStringList tableLines;
        bool valid = false;
    };
    RuleSnapshot readRuleSnapshot() const;
    bool selectRulePriorities(const RuleSnapshot &snapshot,
                              int *bypassPriority, int *fullPriority) const;
    static bool ruleLineMatches(const QString &line, int priority,
                                const QString &needle);
    QStringList bypassRuleArguments(const QString &operation, int priority,
                                    const QString &route) const;
    QStringList fullRuleArguments(const QString &operation, int priority,
                                  bool ipv6) const;
    bool removeRoutes(const QString &interfaceName, const QStringList &routes,
                      QString *failedRoute = nullptr,
                      QStringList *removedRoutes = nullptr);
    bool restoreRoutes(const QString &interfaceName, const QStringList &routes);
    static bool validInterfaceName(const QString &value);

    static constexpr int FullTunnelRouteTable = 51821;
    static constexpr int FullTunnelBypassRulePriority = 1000;
    static constexpr int FullTunnelRulePriority = 1100;
    static constexpr int FullTunnelPriorityLimit = 1999;

    std::shared_ptr<CommandRunner> m_runner;
    QString m_statePath;
    QString m_mode = QStringLiteral("only-forward");
    QString m_interfaceName;
    QStringList m_routes;
    QStringList m_bypassRoutes;
    QString m_dnsInterface;
    QStringList m_dnsServers;
    QStringList m_dnsDomains;
    int m_bypassRulePriority = FullTunnelBypassRulePriority;
    int m_fullRulePriority = FullTunnelRulePriority;
    bool m_stateValid = true;
    mutable QString m_lastError;
};

} // namespace amnezia::headless

#endif // AMNEZIA_HEADLESS_LINUX_ROUTE_RECONCILER_H
