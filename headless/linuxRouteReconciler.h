#ifndef AMNEZIA_HEADLESS_LINUX_ROUTE_RECONCILER_H
#define AMNEZIA_HEADLESS_LINUX_ROUTE_RECONCILER_H

#include <QJsonObject>
#include <QString>
#include <QStringList>
#include <QList>
#include <QElapsedTimer>

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
    // Bounded, machine-readable evidence for a failed postcondition.  This is
    // intentionally a summary rather than a dump of the managed destination
    // set, which may contain more than one thousand entries.
    QJsonObject diagnostics;
};

class LinuxRouteReconciler final
{
public:
    explicit LinuxRouteReconciler(std::shared_ptr<CommandRunner> runner = {},
                                  QString statePath = {},
                                  bool initializeState = true);

    bool initializeState();

    RouteReconcileResult apply(const QString &interfaceName,
                               const QStringList &routes);
    // Install a policy-routing full tunnel.  The supplied routes are the
    // server-managed allow-list and must stay in the ordinary main table;
    // every other IPv4/IPv6 destination is sent to the VPN interface.
    RouteReconcileResult applyAllExcept(const QString &interfaceName,
                                        const QStringList &bypassRoutes,
                                        const QStringList &criticalBypassRoutes = {});
    // Resolve directly-connected private/link-local IPv4 prefixes from the
    // numeric main-table snapshot.  Every non-VPN interface is considered so
    // container bridges remain reachable while full-tunnel policy is active;
    // VPN/internal routes and loopback/tunnel interfaces are excluded.
    QStringList activeUnderlayProtectedRoutes(const QString &vpnInterface,
                                              const QStringList &forwardRoutes,
                                              QString *error = nullptr) const;
    RouteReconcileResult configureDns(const QString &interfaceName,
                                      const QStringList &dnsServers,
                                      const QStringList &dnsDomains);
    RouteReconcileResult clearDns(const QString &interfaceName);
    RouteReconcileResult clear();
    // Force a durable fail-closed state when a controller-level receipt cannot
    // be committed after host mutation.
    bool requireRecovery(const QString &message);
    QJsonObject status() const;

private:
    RouteReconcileResult failure(const QString &code, const QString &message) const;
    bool markRecoveryRequired(const QString &message);
    bool beginMutation(const QString &operation,
                       const QString &interfaceName,
                       const QStringList &routes,
                       const QStringList &bypassRoutes,
                       const QStringList &dnsServers = {},
                       const QStringList &dnsDomains = {},
                       const QStringList &criticalBypassRoutes = {});
    bool finishMutation();
    bool saveTransactionIntent(const QString &operation,
                               const QJsonObject &target) const;
    bool clearTransactionIntent() const;
    RouteReconcileResult finishTransaction(RouteReconcileResult result);
    QString transactionIntentPath() const;
    QString ipExecutable() const;
    QString resolvectlExecutable() const;
    bool loadState();
    bool saveState() const;
    RouteReconcileResult clearFullTunnel();
    RouteReconcileResult applyFullTunnel(const QString &interfaceName,
                                         const QStringList &bypassRoutes,
                                         const QStringList &criticalBypassRoutes);
    bool addFullTunnelRule(const QStringList &arguments,
                           QString *failureDetail = nullptr);
    bool removeFullTunnelRule(const QStringList &arguments,
                              QString *failureDetail = nullptr);
    bool addFullTunnelRulesBatch(const QList<QStringList> &arguments,
                                 QString *failureDetail = nullptr);
    bool removeFullTunnelRulesBatch(const QList<QStringList> &arguments,
                                    QString *failureDetail = nullptr);
    bool addFullTunnelRoute(const QStringList &arguments,
                            QString *failureDetail = nullptr);
    bool removeFullTunnelRoute(const QStringList &arguments,
                               QString *failureDetail = nullptr);
    struct RuleSnapshot
    {
        QSet<int> occupied;
        QSet<int> occupiedV4;
        QSet<int> occupiedV6;
        QSet<int> ownedBypass;
        QSet<int> ownedBypassV4;
        QSet<int> ownedBypassV6;
        QSet<int> ownedFull;
        QSet<int> ownedFullV4;
        QSet<int> ownedFullV6;
        QStringList lines;
        QStringList linesV4;
        QStringList linesV6;
        QStringList tableLines;
        QStringList mainRouteLines;
        bool valid = false;
    };
    RuleSnapshot readRuleSnapshot() const;
    bool selectRulePriorities(const RuleSnapshot &snapshot,
                              int *bypassPriority, int *fullPriority) const;
    static bool ruleLineMatches(const QString &line, int priority,
                                const QString &needle);
    static bool managedMainRouteLineMatches(const QString &line,
                                            const QString &prefix,
                                            const QString &interfaceName);
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
    // 1000 was used by early receipts.  A fresh headless allocation starts at
    // 1001 so a foreign underlay rule at 1000 is never adopted implicitly.
    static constexpr int FullTunnelBypassRulePriority = 1000;
    static constexpr int FullTunnelBypassPreferredPriority = 1001;
    static constexpr int FullTunnelBypassPriorityLimit = 1099;
    static constexpr int FullTunnelRulePriority = 1100;
    static constexpr int FullTunnelPriorityLimit = 1999;
    static constexpr int FullTunnelRuleBatchSize = 16;
    static constexpr int FullTunnelBatchTotalDeadlineMs = 120'000;

    std::shared_ptr<CommandRunner> m_runner;
    QString m_statePath;
    QString m_intentPath;
    QString m_mode = QStringLiteral("only-forward");
    QString m_interfaceName;
    QStringList m_routes;
    QStringList m_bypassRoutes;
    QStringList m_criticalBypassRoutes;
    QString m_dnsInterface;
    QStringList m_dnsServers;
    QStringList m_dnsDomains;
    int m_bypassRulePriority = FullTunnelBypassRulePriority;
    int m_fullRulePriority = FullTunnelRulePriority;
    bool m_stateValid = true;
    // A persisted all-except receipt may survive a backend/systemd restart
    // after the tunnel interface and table have disappeared.  The exact
    // receipt-bound policy rules are still safe evidence, but must be
    // re-applied after the backend creates the interface again.
    bool m_needsReapply = false;
    bool m_interfaceOffline = false;
    bool m_initialized = false;
    mutable QString m_lastError;
    mutable QJsonObject m_lastDiagnostics;
    // One absolute budget is shared by every full-tunnel batch and retry in a
    // transaction; individual helpers must never restart a fresh 120-second
    // allowance for each chunk.
    QElapsedTimer m_fullTunnelDeadline;
};

} // namespace amnezia::headless

#endif // AMNEZIA_HEADLESS_LINUX_ROUTE_RECONCILER_H
