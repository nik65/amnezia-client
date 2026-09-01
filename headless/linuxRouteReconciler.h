#ifndef AMNEZIA_HEADLESS_LINUX_ROUTE_RECONCILER_H
#define AMNEZIA_HEADLESS_LINUX_ROUTE_RECONCILER_H

#include <QJsonObject>
#include <QString>
#include <QStringList>

#include <memory>

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
    bool removeRoutes(const QString &interfaceName, const QStringList &routes,
                      QString *failedRoute = nullptr);
    static bool validInterfaceName(const QString &value);

    static constexpr int FullTunnelRouteTable = 51821;
    static constexpr int FullTunnelBypassRulePriority = 1000;
    static constexpr int FullTunnelRulePriority = 1100;

    std::shared_ptr<CommandRunner> m_runner;
    QString m_statePath;
    QString m_mode = QStringLiteral("only-forward");
    QString m_interfaceName;
    QStringList m_routes;
    QStringList m_bypassRoutes;
    mutable QString m_lastError;
};

} // namespace amnezia::headless

#endif // AMNEZIA_HEADLESS_LINUX_ROUTE_RECONCILER_H
