#include "linuxRouteReconciler.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QRegularExpression>
#include <QSaveFile>

#include <algorithm>
#include <utility>

#include "../client/core/utils/managedRoutePolicy.h"

namespace amnezia::headless
{

LinuxRouteReconciler::LinuxRouteReconciler(std::shared_ptr<CommandRunner> runner,
                                           QString statePath)
    : m_runner(runner ? std::move(runner) : std::make_shared<RealCommandRunner>()),
      m_statePath(std::move(statePath))
{
    m_stateValid = loadState();
    if (!m_stateValid) {
        m_mode = QStringLiteral("recovery_required");
        m_lastError = QStringLiteral("managed route state is invalid; refusing to mutate host routes");
    }
}

RouteReconcileResult LinuxRouteReconciler::apply(const QString &interfaceName,
                                                 const QStringList &routes)
{
    m_lastError.clear();
    if (!m_stateValid) {
        return failure(QStringLiteral("recovery_required"),
                       QStringLiteral("managed route state is invalid; manual route recovery is required"));
    }
    if (!validInterfaceName(interfaceName)) {
        return failure(QStringLiteral("invalid_interface"),
                       QStringLiteral("VPN interface name is invalid"));
    }

    bool routesValid = false;
    QStringList boundedRoutes = amnezia::managedRoutePolicy::validatedManagedRoutes(
            routes, &routesValid);
    if (!routesValid || boundedRoutes.size() != routes.size()) {
        return failure(QStringLiteral("invalid_routes"),
                       QStringLiteral("managed routes are invalid or duplicated"));
    }
    boundedRoutes.removeDuplicates();
    boundedRoutes.sort();
    if (boundedRoutes.isEmpty()) {
        return clear();
    }
    if (m_mode == QStringLiteral("all-except")) {
        const RouteReconcileResult cleared = clearFullTunnel();
        if (!cleared.ok) {
            return cleared;
        }
    }

    const QString executable = ipExecutable();
    if (executable.isEmpty()) {
        return failure(QStringLiteral("route_backend_unavailable"),
                       QStringLiteral("the Linux ip command is not installed"));
    }

    // Add the new set before removing the old set.  A failed addition therefore
    // leaves the previously applied routes intact and can be rolled back.
    QStringList added;
    for (const QString &route : boundedRoutes) {
        // Always replace even when the receipt says the route exists. This
        // repairs external drift after a VPN backend restart.
        const CommandResult result = m_runner->run(
                executable, { QStringLiteral("route"), QStringLiteral("replace"), route,
                              QStringLiteral("dev"), interfaceName,
                              QStringLiteral("metric"), QStringLiteral("1") });
        if (!result.ok) {
            // A route that belonged to the previous set was only refreshed;
            // deleting it here would make a failed transaction worse.
            removeRoutes(interfaceName, added);
            return failure(QStringLiteral("route_add_failed"),
                           QStringLiteral("failed to apply a managed route"));
        }
        if (m_interfaceName != interfaceName || !m_routes.contains(route)) {
            added.append(route);
        }
    }

    if (m_interfaceName != interfaceName) {
        if (!removeRoutes(m_interfaceName, m_routes)) {
            removeRoutes(interfaceName, added);
            return failure(QStringLiteral("route_remove_failed"),
                           QStringLiteral("failed to retire the previous route set"));
        }
    } else {
        QStringList retired;
        for (const QString &route : std::as_const(m_routes)) {
            if (boundedRoutes.contains(route)) {
                continue;
            }
            const CommandResult result = m_runner->run(
                    executable, { QStringLiteral("route"), QStringLiteral("del"), route,
                                  QStringLiteral("dev"), interfaceName,
                                  QStringLiteral("metric"), QStringLiteral("1") });
            if (!result.ok) {
                removeRoutes(interfaceName, added);
                return failure(QStringLiteral("route_remove_failed"),
                               QStringLiteral("failed to retire a managed route"));
            }
            retired.append(route);
        }
    }

    m_interfaceName = interfaceName;
    m_mode = QStringLiteral("only-forward");
    m_routes = boundedRoutes;
    m_bypassRoutes.clear();
    if (!saveState()) {
        // Without a durable receipt we cannot safely distinguish ownership on
        // the next start. Fail closed and require recovery before another
        // mutation rather than claiming a persisted route set.
        m_stateValid = false;
        m_mode = QStringLiteral("recovery_required");
        return failure(QStringLiteral("recovery_required"),
                       QStringLiteral("managed routes applied but state was not persisted"));
    }
    return { true, {}, {} };
}

RouteReconcileResult LinuxRouteReconciler::applyAllExcept(
        const QString &interfaceName, const QStringList &bypassRoutes)
{
    m_lastError.clear();
    if (!m_stateValid) {
        return failure(QStringLiteral("recovery_required"),
                       QStringLiteral("managed route state is invalid; manual route recovery is required"));
    }
    if (!validInterfaceName(interfaceName)) {
        return failure(QStringLiteral("invalid_interface"),
                       QStringLiteral("VPN interface name is invalid"));
    }

    bool routesValid = false;
    QStringList boundedRoutes = amnezia::managedRoutePolicy::validatedManagedRoutes(
            bypassRoutes, &routesValid);
    if (!routesValid || boundedRoutes.size() != bypassRoutes.size()) {
        return failure(QStringLiteral("invalid_routes"),
                       QStringLiteral("full-tunnel bypass routes are invalid or duplicated"));
    }
    boundedRoutes.removeDuplicates();
    boundedRoutes.sort();
    return applyFullTunnel(interfaceName, boundedRoutes);
}

bool LinuxRouteReconciler::addFullTunnelRule(const QStringList &arguments)
{
    const QString executable = ipExecutable();
    return !executable.isEmpty()
        && m_runner->run(executable, arguments).ok;
}

bool LinuxRouteReconciler::removeFullTunnelRule(const QStringList &arguments)
{
    const QString executable = ipExecutable();
    if (executable.isEmpty()) return false;
    const CommandResult result = m_runner->run(executable, arguments);
    // iproute2 returns EX_TEMPFAIL-like status 2 when a requested owned
    // object is already absent. Clear is intentionally idempotent for that
    // case; all other failures remain fatal.
    return result.ok || (result.exitCode == 2 && arguments.value(1) == QStringLiteral("del"));
}

bool LinuxRouteReconciler::addFullTunnelRoute(const QStringList &arguments)
{
    const QString executable = ipExecutable();
    return !executable.isEmpty()
        && m_runner->run(executable, arguments).ok;
}

bool LinuxRouteReconciler::removeFullTunnelRoute(const QStringList &arguments)
{
    const QString executable = ipExecutable();
    if (executable.isEmpty()) return false;
    const CommandResult result = m_runner->run(executable, arguments);
    return result.ok || (result.exitCode == 2 && arguments.contains(QStringLiteral("del")));
}

LinuxRouteReconciler::RuleSnapshot LinuxRouteReconciler::readRuleSnapshot() const
{
    RuleSnapshot snapshot;
    const QString executable = ipExecutable();
    if (executable.isEmpty()) {
        return snapshot;
    }
    const QList<QStringList> ruleQueries {
        { QStringLiteral("rule"), QStringLiteral("show") },
        { QStringLiteral("-6"), QStringLiteral("rule"), QStringLiteral("show") }
    };
    for (int family = 0; family < ruleQueries.size(); ++family) {
        const QStringList &arguments = ruleQueries.at(family);
        const CommandResult result = m_runner->runCaptured(executable, arguments);
        if (!result.ok) {
            return snapshot;
        }
        const QStringList lines = result.output.split(QRegularExpression(QStringLiteral("[\\r\\n]")),
                                                        Qt::SkipEmptyParts);
        for (const QString &line : lines) {
            const QRegularExpressionMatch match =
                    QRegularExpression(QStringLiteral("^\\s*(\\d+):")).match(line);
            if (!match.hasMatch()) {
                continue;
            }
            const int priority = match.captured(1).toInt();
            snapshot.occupied.insert(priority);
            snapshot.lines.append(line);
            if (QRegularExpression(QStringLiteral("(?:^|\\s)lookup\\s+51821(?:\\s|$)")).match(line).hasMatch()) {
                snapshot.ownedFull.insert(priority);
                (family == 0 ? snapshot.ownedFullV4 : snapshot.ownedFullV6).insert(priority);
            }
            if (QRegularExpression(QStringLiteral("(?:^|\\s)lookup\\s+main(?:\\s|$)")).match(line).hasMatch()) {
                snapshot.ownedBypass.insert(priority);
            }
        }
    }
    const QList<QStringList> tableQueries {
        { QStringLiteral("route"), QStringLiteral("show"), QStringLiteral("table"),
          QString::number(FullTunnelRouteTable) },
        { QStringLiteral("-6"), QStringLiteral("route"), QStringLiteral("show"),
          QStringLiteral("table"), QString::number(FullTunnelRouteTable) },
    };
    for (const QStringList &arguments : tableQueries) {
        const CommandResult result = m_runner->runCaptured(executable, arguments);
        if (!result.ok) return snapshot;
        const QStringList lines = result.output.split(QRegularExpression(QStringLiteral("[\\r\\n]")),
                                                       Qt::SkipEmptyParts);
        for (const QString &line : lines) {
            if (!QRegularExpression(QStringLiteral("^\\s*\\d+:")).match(line).hasMatch()) {
                snapshot.tableLines.append(line);
            }
        }
    }
    snapshot.valid = true;
    return snapshot;
}

bool LinuxRouteReconciler::selectRulePriorities(const RuleSnapshot &snapshot,
                                                int *bypassPriority,
                                                int *fullPriority) const
{
    if (!snapshot.valid || !bypassPriority || !fullPriority) {
        return false;
    }
    auto hasOwnedBypassPriority = [this, &snapshot](int priority) {
        return std::any_of(m_bypassRoutes.cbegin(), m_bypassRoutes.cend(),
                           [&snapshot, priority](const QString &route) {
            return std::any_of(snapshot.lines.cbegin(), snapshot.lines.cend(),
                               [priority, &route](const QString &line) {
                return ruleLineMatches(line, priority,
                                       QStringLiteral("to %1 ").arg(route));
            });
        });
    };
    auto select = [&snapshot](int preferred, int first, int last, bool preferredOwned,
                              int *selected) {
        if (preferred >= first && preferred <= last && preferredOwned) {
            *selected = preferred;
            return true;
        }
        for (int candidate = first; candidate <= last; ++candidate) {
            if (!snapshot.occupied.contains(candidate)) {
                *selected = candidate;
                return true;
            }
        }
        return false;
    };
    return select(m_bypassRulePriority, FullTunnelBypassRulePriority, 1099,
                  hasOwnedBypassPriority(m_bypassRulePriority), bypassPriority)
        && select(m_fullRulePriority, FullTunnelRulePriority, FullTunnelPriorityLimit,
                  snapshot.ownedFull.contains(m_fullRulePriority), fullPriority);
}

bool LinuxRouteReconciler::ruleLineMatches(const QString &line, int priority,
                                            const QString &needle)
{
    if (!QRegularExpression(QStringLiteral("^\\s*%1:").arg(priority)).match(line).hasMatch()) {
        return false;
    }
    // The caller supplies a complete destination token (including its
    // trailing delimiter).  Require it at a whitespace boundary so a route
    // such as 10.0.0.1/32 cannot accidentally match a longer prefix.
    return QRegularExpression(QStringLiteral("(?:^|\\s)%1(?:\\s|$)")
                               .arg(QRegularExpression::escape(needle.trimmed())))
            .match(line).hasMatch();
}

QStringList LinuxRouteReconciler::bypassRuleArguments(const QString &operation,
                                                      int priority,
                                                      const QString &route) const
{
    return { QStringLiteral("rule"), operation, QStringLiteral("priority"),
             QString::number(priority), QStringLiteral("to"), route,
             QStringLiteral("lookup"), QStringLiteral("main") };
}

QStringList LinuxRouteReconciler::fullRuleArguments(const QString &operation,
                                                    int priority, bool ipv6) const
{
    QStringList arguments;
    if (ipv6) {
        arguments.append(QStringLiteral("-6"));
    }
    arguments << QStringLiteral("rule") << operation << QStringLiteral("priority")
              << QString::number(priority) << QStringLiteral("lookup")
              << QString::number(FullTunnelRouteTable);
    return arguments;
}

RouteReconcileResult LinuxRouteReconciler::applyFullTunnel(
        const QString &interfaceName, const QStringList &bypassRoutes)
{
    if (ipExecutable().isEmpty()) {
        return failure(QStringLiteral("route_backend_unavailable"),
                       QStringLiteral("the Linux ip command is not installed"));
    }

    const RuleSnapshot ruleSnapshot = readRuleSnapshot();
    int bypassPriority = FullTunnelBypassRulePriority;
    int fullPriority = FullTunnelRulePriority;
    if (!selectRulePriorities(ruleSnapshot, &bypassPriority, &fullPriority)) {
        return failure(QStringLiteral("full_tunnel_rule_probe_failed"),
                       QStringLiteral("could not find safe policy-rule priorities"));
    }
    for (const QString &line : ruleSnapshot.tableLines) {
        if (!QRegularExpression(QStringLiteral("\\sdev\\s+%1(?:\\s|$)")
                                .arg(QRegularExpression::escape(interfaceName))).match(line).hasMatch()) {
            return failure(QStringLiteral("full_tunnel_table_conflict"),
                           QStringLiteral("route table 51821 contains an unowned route"));
        }
    }

    const bool hadFullTunnel = m_mode == QStringLiteral("all-except");
    const QString previousInterface = m_interfaceName;
    const QStringList previousBypassRoutes = m_bypassRoutes;
    const int previousBypassPriority = m_bypassRulePriority;

    const QList<QStringList> fullRoutes {
        { QStringLiteral("route"), QStringLiteral("replace"), QStringLiteral("0.0.0.0/1"),
          QStringLiteral("dev"), interfaceName, QStringLiteral("table"),
          QString::number(FullTunnelRouteTable) },
        { QStringLiteral("route"), QStringLiteral("replace"), QStringLiteral("128.0.0.0/1"),
          QStringLiteral("dev"), interfaceName, QStringLiteral("table"),
          QString::number(FullTunnelRouteTable) },
        { QStringLiteral("-6"), QStringLiteral("route"), QStringLiteral("replace"),
          QStringLiteral("::/1"), QStringLiteral("dev"), interfaceName,
          QStringLiteral("table"), QString::number(FullTunnelRouteTable) },
        { QStringLiteral("-6"), QStringLiteral("route"), QStringLiteral("replace"),
          QStringLiteral("8000::/1"), QStringLiteral("dev"), interfaceName,
          QStringLiteral("table"), QString::number(FullTunnelRouteTable) },
    };
    int installedRoutes = 0;
    for (const QStringList &arguments : fullRoutes) {
        if (!addFullTunnelRoute(arguments)) {
            bool rollbackOk = true;
            if (!hadFullTunnel || previousInterface != interfaceName) {
                for (int index = 0; index < installedRoutes; ++index) {
                    QStringList deletion = fullRoutes.at(index);
                    deletion.replace(deletion.indexOf(QStringLiteral("replace")),
                                     QStringLiteral("del"));
                    rollbackOk = removeFullTunnelRoute(deletion) && rollbackOk;
                }
            }
            // Restore the previous full-tunnel table when a refresh changed
            // the interface and only part of the replacement was accepted.
            if (hadFullTunnel && !previousInterface.isEmpty()) {
                rollbackOk = addFullTunnelRoute({ QStringLiteral("route"), QStringLiteral("replace"),
                                     QStringLiteral("0.0.0.0/1"), QStringLiteral("dev"),
                                     previousInterface, QStringLiteral("table"),
                                     QString::number(FullTunnelRouteTable) });
                rollbackOk = addFullTunnelRoute({ QStringLiteral("route"), QStringLiteral("replace"),
                                     QStringLiteral("128.0.0.0/1"), QStringLiteral("dev"),
                                     previousInterface, QStringLiteral("table"),
                                     QString::number(FullTunnelRouteTable) });
                rollbackOk = addFullTunnelRoute({ QStringLiteral("-6"), QStringLiteral("route"),
                                     QStringLiteral("replace"), QStringLiteral("::/1"),
                                     QStringLiteral("dev"), previousInterface,
                                     QStringLiteral("table"),
                                     QString::number(FullTunnelRouteTable) });
                rollbackOk = addFullTunnelRoute({ QStringLiteral("-6"), QStringLiteral("route"),
                                     QStringLiteral("replace"), QStringLiteral("8000::/1"),
                                     QStringLiteral("dev"), previousInterface,
                                     QStringLiteral("table"),
                                     QString::number(FullTunnelRouteTable) });
            }
            return failure(rollbackOk ? QStringLiteral("full_tunnel_route_failed")
                                      : QStringLiteral("full_tunnel_rollback_failed"),
                           QStringLiteral("failed to install the full-tunnel route table"));
        }
        ++installedRoutes;
    }

    QStringList addedBypassRoutes;
    bool addedFullV4 = false;
    bool addedFullV6 = false;
    auto rollback = [&]() {
        bool ok = true;
        for (const QString &route : addedBypassRoutes) {
            ok = removeFullTunnelRule(bypassRuleArguments(QStringLiteral("del"), bypassPriority, route)) && ok;
        }
        if (addedFullV4) {
            ok = removeFullTunnelRule(fullRuleArguments(QStringLiteral("del"), fullPriority, false)) && ok;
        }
        if (addedFullV6) {
            ok = removeFullTunnelRule(fullRuleArguments(QStringLiteral("del"), fullPriority, true)) && ok;
        }
        if (!hadFullTunnel) {
            for (const QStringList &route : fullRoutes) {
                QStringList deletion { route };
                deletion.replace(deletion.indexOf(QStringLiteral("replace")),
                                 QStringLiteral("del"));
                ok = removeFullTunnelRoute(deletion) && ok;
            }
        } else if (previousInterface != interfaceName && !previousInterface.isEmpty()) {
            for (const QStringList &route : fullRoutes) {
                QStringList restore = route;
                restore.replace(restore.indexOf(interfaceName), previousInterface);
                ok = addFullTunnelRoute(restore) && ok;
            }
        }
        return ok;
    };

    for (const QString &route : bypassRoutes) {
        bool owned = false;
        for (const QString &line : ruleSnapshot.lines) {
            if (ruleLineMatches(line, bypassPriority,
                                QStringLiteral("to %1 ").arg(route))) {
                owned = true;
                break;
            }
        }
        if (owned) {
            continue;
        }
        if (!addFullTunnelRule(bypassRuleArguments(QStringLiteral("add"), bypassPriority, route))) {
            if (!rollback()) {
                return failure(QStringLiteral("full_tunnel_rollback_failed"),
                               QStringLiteral("full-tunnel route transaction rollback failed"));
            }
            return failure(QStringLiteral("full_tunnel_rule_conflict"),
                           QStringLiteral("a full-tunnel bypass rule could not be installed"));
        }
        addedBypassRoutes.append(route);
    }

    const bool fullV4Present = ruleSnapshot.ownedFullV4.contains(fullPriority);
    if (!fullV4Present) {
        if (!addFullTunnelRule(fullRuleArguments(QStringLiteral("add"), fullPriority, false))) {
            if (!rollback()) {
                return failure(QStringLiteral("full_tunnel_rollback_failed"),
                               QStringLiteral("full-tunnel rule transaction rollback failed"));
            }
            return failure(QStringLiteral("full_tunnel_rule_conflict"),
                           QStringLiteral("the full-tunnel policy rule could not be installed"));
        }
        addedFullV4 = true;
    }
    const bool fullV6Present = ruleSnapshot.ownedFullV6.contains(fullPriority);
    if (!fullV6Present) {
        if (!addFullTunnelRule(fullRuleArguments(QStringLiteral("add"), fullPriority, true))) {
            if (!rollback()) {
                return failure(QStringLiteral("full_tunnel_rollback_failed"),
                               QStringLiteral("full-tunnel rule transaction rollback failed"));
            }
            return failure(QStringLiteral("full_tunnel_rule_conflict"),
                           QStringLiteral("the IPv6 full-tunnel policy rule could not be installed"));
        }
        addedFullV6 = true;
    }

    if (hadFullTunnel) {
        QStringList removedPreviousBypassRoutes;
        for (const QString &route : previousBypassRoutes) {
            bool owned = false;
            for (const QString &line : ruleSnapshot.lines) {
                if (ruleLineMatches(line, previousBypassPriority,
                                    QStringLiteral("to %1 ").arg(route))) {
                    owned = true;
                    break;
                }
            }
            if (!bypassRoutes.contains(route) && owned
                && !removeFullTunnelRule(bypassRuleArguments(QStringLiteral("del"),
                                                              previousBypassPriority, route))) {
                if (!rollback()) {
                    return failure(QStringLiteral("full_tunnel_rollback_failed"),
                                   QStringLiteral("full-tunnel cleanup rollback failed"));
                }
                for (const QString &removed : removedPreviousBypassRoutes) {
                    if (!addFullTunnelRule(bypassRuleArguments(QStringLiteral("add"),
                                                                previousBypassPriority, removed))) {
                        return failure(QStringLiteral("full_tunnel_rollback_failed"),
                                       QStringLiteral("full-tunnel stale-rule rollback failed"));
                    }
                }
                return failure(QStringLiteral("full_tunnel_rule_cleanup_failed"),
                               QStringLiteral("a stale full-tunnel bypass rule could not be removed"));
            }
            if (!bypassRoutes.contains(route) && owned) {
                removedPreviousBypassRoutes.append(route);
            }
        }
    } else if (!m_routes.isEmpty()) {
        if (!removeRoutes(m_interfaceName, m_routes)) {
            if (!rollback()) {
                return failure(QStringLiteral("full_tunnel_rollback_failed"),
                               QStringLiteral("full-tunnel route transaction rollback failed"));
            }
            return failure(QStringLiteral("route_remove_failed"),
                           QStringLiteral("failed to retire the previous managed routes"));
        }
    }

    m_mode = QStringLiteral("all-except");
    m_interfaceName = interfaceName;
    m_routes.clear();
    m_bypassRoutes = bypassRoutes;
    m_bypassRulePriority = bypassPriority;
    m_fullRulePriority = fullPriority;
    if (!saveState()) {
        m_stateValid = false;
        m_mode = QStringLiteral("recovery_required");
        return failure(QStringLiteral("recovery_required"),
                       QStringLiteral("full-tunnel routes applied but state was not persisted"));
    }
    return { true, {}, {} };
}

RouteReconcileResult LinuxRouteReconciler::clearFullTunnel()
{
    if (ipExecutable().isEmpty()) {
        return failure(QStringLiteral("route_backend_unavailable"),
                       QStringLiteral("the Linux ip command is not installed"));
    }
    const RuleSnapshot snapshot = readRuleSnapshot();
    if (!snapshot.valid) {
        return failure(QStringLiteral("full_tunnel_rule_probe_failed"),
                       QStringLiteral("could not inspect policy rules safely"));
    }
    for (const QString &route : m_bypassRoutes) {
        bool owned = false;
        for (const QString &line : snapshot.lines) {
            if (ruleLineMatches(line, m_bypassRulePriority,
                                QStringLiteral("to %1 ").arg(route))) {
                owned = true;
                break;
            }
        }
        if (!owned) {
            continue;
        }
        if (!removeFullTunnelRule(bypassRuleArguments(QStringLiteral("del"),
                                                       m_bypassRulePriority, route))) {
            return failure(QStringLiteral("full_tunnel_rule_cleanup_failed"),
                           QStringLiteral("a full-tunnel bypass rule could not be removed"));
        }
    }
    const bool fullV4Owned = snapshot.ownedFullV4.contains(m_fullRulePriority);
    const bool fullV6Owned = snapshot.ownedFullV6.contains(m_fullRulePriority);
    if ((fullV4Owned && !removeFullTunnelRule(fullRuleArguments(QStringLiteral("del"),
                                                                    m_fullRulePriority, false)))
        || (fullV6Owned && !removeFullTunnelRule(fullRuleArguments(QStringLiteral("del"),
                                                                    m_fullRulePriority, true)))) {
        return failure(QStringLiteral("full_tunnel_rule_cleanup_failed"),
                       QStringLiteral("the full-tunnel policy rule could not be removed"));
    }
    const QStringList v4Route = { QStringLiteral("route"), QStringLiteral("del"),
                                  QStringLiteral("0.0.0.0/1"), QStringLiteral("table"),
                                  QString::number(FullTunnelRouteTable) };
    const QStringList v4RouteUpper = { QStringLiteral("route"), QStringLiteral("del"),
                                       QStringLiteral("128.0.0.0/1"), QStringLiteral("table"),
                                       QString::number(FullTunnelRouteTable) };
    const QStringList v6Route = { QStringLiteral("-6"), QStringLiteral("route"),
                                  QStringLiteral("del"), QStringLiteral("::/1"),
                                  QStringLiteral("table"), QString::number(FullTunnelRouteTable) };
    const QStringList v6RouteUpper = { QStringLiteral("-6"), QStringLiteral("route"),
                                       QStringLiteral("del"), QStringLiteral("8000::/1"),
                                       QStringLiteral("table"), QString::number(FullTunnelRouteTable) };
    if (!removeFullTunnelRoute(v4Route) || !removeFullTunnelRoute(v4RouteUpper)
        || !removeFullTunnelRoute(v6Route) || !removeFullTunnelRoute(v6RouteUpper)) {
        return failure(QStringLiteral("full_tunnel_route_cleanup_failed"),
                       QStringLiteral("the full-tunnel route table could not be removed"));
    }

    m_mode = QStringLiteral("only-forward");
    m_interfaceName.clear();
    m_routes.clear();
    m_bypassRoutes.clear();
    if (!saveState()) {
        m_stateValid = false;
        m_mode = QStringLiteral("recovery_required");
        return failure(QStringLiteral("recovery_required"),
                       QStringLiteral("full-tunnel state could not be cleared"));
    }
    return { true, {}, {} };
}

RouteReconcileResult LinuxRouteReconciler::configureDns(const QString &interfaceName,
                                                        const QStringList &dnsServers,
                                                        const QStringList &dnsDomains)
{
    if (!validInterfaceName(interfaceName) || dnsServers.isEmpty() || dnsDomains.isEmpty()) {
        return failure(QStringLiteral("invalid_dns_configuration"),
                       QStringLiteral("a VPN interface, DNS server and routing domain are required"));
    }
    const QString executable = resolvectlExecutable();
    if (executable.isEmpty()) {
        return failure(QStringLiteral("dns_backend_unavailable"),
                       QStringLiteral("systemd-resolved resolvectl is not installed"));
    }

    QStringList dnsArguments { QStringLiteral("dns"), interfaceName };
    dnsArguments.append(dnsServers);
    const CommandResult dnsResult = m_runner->run(executable, dnsArguments);
    if (!dnsResult.ok) {
        return failure(QStringLiteral("dns_configure_failed"),
                       QStringLiteral("failed to assign the VPN DNS server"));
    }

    QStringList domainArguments { QStringLiteral("domain"), interfaceName };
    domainArguments.append(dnsDomains);
    const CommandResult domainResult = m_runner->run(executable, domainArguments);
    if (!domainResult.ok) {
        return failure(QStringLiteral("dns_configure_failed"),
                       QStringLiteral("failed to assign the VPN DNS routing domain"));
    }
    // This is a cache invalidation only; DNS servers and domains are already
    // configured above.  A stale negative answer must not hide a new policy.
    m_runner->run(executable, { QStringLiteral("flush-caches") });
    return { true, {}, {} };
}

RouteReconcileResult LinuxRouteReconciler::clearDns(const QString &interfaceName)
{
    if (interfaceName.isEmpty()) {
        return { true, {}, {} };
    }
    const QString executable = resolvectlExecutable();
    if (executable.isEmpty()) {
        return { true, {}, {} };
    }
    const CommandResult result = m_runner->run(
            executable, { QStringLiteral("revert"), interfaceName });
    if (!result.ok) {
        return failure(QStringLiteral("dns_clear_failed"),
                       QStringLiteral("failed to clear the VPN DNS configuration"));
    }
    return { true, {}, {} };
}

RouteReconcileResult LinuxRouteReconciler::clear()
{
    m_lastError.clear();
    if (!m_stateValid) {
        return failure(QStringLiteral("recovery_required"),
                       QStringLiteral("managed route state is invalid; manual route recovery is required"));
    }
    if (m_mode == QStringLiteral("all-except")) {
        return clearFullTunnel();
    }
    if (m_routes.isEmpty()) {
        m_interfaceName.clear();
        m_mode = QStringLiteral("only-forward");
        m_bypassRoutes.clear();
        saveState();
        return { true, {}, {} };
    }
    if (ipExecutable().isEmpty()) {
        return failure(QStringLiteral("route_backend_unavailable"),
                       QStringLiteral("the Linux ip command is not installed"));
    }
    QString failedRoute;
    if (!removeRoutes(m_interfaceName, m_routes, &failedRoute)) {
        return failure(QStringLiteral("route_remove_failed"),
                       QStringLiteral("failed to clear a managed route"));
    }
    m_interfaceName.clear();
    m_routes.clear();
    m_mode = QStringLiteral("only-forward");
    m_bypassRoutes.clear();
    if (!saveState()) {
        m_stateValid = false;
        m_mode = QStringLiteral("recovery_required");
        return failure(QStringLiteral("recovery_required"),
                       QStringLiteral("managed route state could not be cleared"));
    }
    return { true, {}, {} };
}

QJsonObject LinuxRouteReconciler::status() const
{
    return QJsonObject {
        { QStringLiteral("interface"), m_interfaceName },
        { QStringLiteral("mode"), m_mode },
        { QStringLiteral("routes"), QJsonArray::fromStringList(m_routes) },
        { QStringLiteral("bypassRoutes"), QJsonArray::fromStringList(m_bypassRoutes) },
        { QStringLiteral("routeTable"), m_mode == QStringLiteral("all-except")
                                               ? FullTunnelRouteTable : 0 },
        { QStringLiteral("bypassRulePriority"), m_bypassRulePriority },
        { QStringLiteral("fullRulePriority"), m_fullRulePriority },
        { QStringLiteral("statePath"), m_statePath },
        { QStringLiteral("recoveryRequired"), !m_stateValid
                                                 || m_mode == QStringLiteral("recovery_required") },
    };
}

RouteReconcileResult LinuxRouteReconciler::failure(const QString &code,
                                                   const QString &message) const
{
    m_lastError = message;
    return { false, code, message };
}

QString LinuxRouteReconciler::ipExecutable() const
{
    return m_runner->resolveExecutable({ QStringLiteral("ip"),
                                         QStringLiteral("/usr/sbin/ip"),
                                         QStringLiteral("/sbin/ip") });
}

QString LinuxRouteReconciler::resolvectlExecutable() const
{
    return m_runner->resolveExecutable({ QStringLiteral("resolvectl"),
                                         QStringLiteral("/usr/bin/resolvectl"),
                                         QStringLiteral("/bin/resolvectl") });
}

bool LinuxRouteReconciler::loadState()
{
    m_mode = QStringLiteral("only-forward");
    m_interfaceName.clear();
    m_routes.clear();
    m_bypassRoutes.clear();
    m_bypassRulePriority = FullTunnelBypassRulePriority;
    m_fullRulePriority = FullTunnelRulePriority;
    if (m_statePath.isEmpty()) {
        return true;
    }
    const QFileInfo stateInfo(m_statePath);
    if (!stateInfo.exists()) {
        return true;
    }
    if (stateInfo.isSymLink() || !stateInfo.isFile()) {
        return false;
    }
    QFile file(m_statePath);
    if (!file.open(QIODevice::ReadOnly)) {
        return false;
    }
    QJsonParseError error;
    const QJsonDocument document = QJsonDocument::fromJson(file.readAll(), &error);
    if (error.error != QJsonParseError::NoError || !document.isObject()) {
        return false;
    }
    const QJsonObject object = document.object();
    if (object.contains(QStringLiteral("version"))
        && object.value(QStringLiteral("version")).toInt(2) != 2) {
        return false;
    }
    const QString mode = object.value(QStringLiteral("mode"))
                                 .toString(QStringLiteral("only-forward"));
    if (mode != QStringLiteral("only-forward") && mode != QStringLiteral("all-except")) {
        return false;
    }
    const QString interfaceName = object.value(QStringLiteral("interface")).toString();
    const QJsonArray routeArray = object.value(QStringLiteral("routes")).toArray();
    QStringList routes;
    for (const QJsonValue &value : routeArray) {
        if (!value.isString()) {
            return false;
        }
        routes.append(value.toString());
    }
    bool routesValid = false;
    const QStringList bounded = amnezia::managedRoutePolicy::validatedManagedRoutes(
            routes, &routesValid);
    if (!interfaceName.isEmpty() && (!validInterfaceName(interfaceName)
                                     || !routesValid || bounded.size() != routes.size())) {
        return false;
    }
    QStringList bypassRoutes;
    const QJsonArray bypassArray = object.value(QStringLiteral("bypassRoutes")).toArray();
    for (const QJsonValue &value : bypassArray) {
        if (!value.isString()) {
            return false;
        }
        bypassRoutes.append(value.toString());
    }
    bool bypassValid = false;
    const QStringList boundedBypass = amnezia::managedRoutePolicy::validatedManagedRoutes(
            bypassRoutes, &bypassValid);
    if (!bypassValid || boundedBypass.size() != bypassRoutes.size()
        || (mode == QStringLiteral("all-except") && interfaceName.isEmpty())) {
        return false;
    }
    if (mode == QStringLiteral("only-forward") && !bypassRoutes.isEmpty()) {
        return false;
    }
    m_mode = mode;
    m_interfaceName = interfaceName;
    m_routes = bounded;
    m_bypassRoutes = boundedBypass;
    const int storedBypassPriority = object.value(QStringLiteral("bypassRulePriority"))
                                             .toInt(FullTunnelBypassRulePriority);
    const int storedFullPriority = object.value(QStringLiteral("fullRulePriority"))
                                           .toInt(FullTunnelRulePriority);
    if (storedBypassPriority < FullTunnelBypassRulePriority
        || storedBypassPriority > 1099
        || storedFullPriority < FullTunnelRulePriority
        || storedFullPriority > FullTunnelPriorityLimit
        || storedBypassPriority >= storedFullPriority) {
        return false;
    }
    m_bypassRulePriority = storedBypassPriority;
    m_fullRulePriority = storedFullPriority;
    return true;
}

bool LinuxRouteReconciler::saveState() const
{
    if (m_statePath.isEmpty()) {
        return true;
    }
    const QFileInfo info(m_statePath);
    if (!info.absolutePath().isEmpty() && !QDir().mkpath(info.absolutePath())) {
        return false;
    }
    QSaveFile file(m_statePath);
    if (!file.open(QIODevice::WriteOnly)) {
        return false;
    }
    const QJsonObject object {
        { QStringLiteral("version"), 2 },
        { QStringLiteral("mode"), m_mode },
        { QStringLiteral("interface"), m_interfaceName },
        { QStringLiteral("routes"), QJsonArray::fromStringList(m_routes) },
        { QStringLiteral("bypassRoutes"), QJsonArray::fromStringList(m_bypassRoutes) },
        { QStringLiteral("bypassRulePriority"), m_bypassRulePriority },
        { QStringLiteral("fullRulePriority"), m_fullRulePriority },
    };
    if (file.write(QJsonDocument(object).toJson(QJsonDocument::Compact)) < 0
        || !file.commit()) {
        return false;
    }
#ifndef Q_OS_WIN
    QFile::setPermissions(m_statePath, QFileDevice::ReadOwner | QFileDevice::WriteOwner);
#endif
    return true;
}

bool LinuxRouteReconciler::removeRoutes(const QString &interfaceName,
                                        const QStringList &routes,
                                        QString *failedRoute)
{
    if (routes.isEmpty()) {
        return true;
    }
    if (interfaceName.isEmpty()) {
        return false;
    }
    const QString executable = ipExecutable();
    if (executable.isEmpty()) {
        return false;
    }
    for (const QString &route : routes) {
        const CommandResult result = m_runner->run(
                executable, { QStringLiteral("route"), QStringLiteral("del"), route,
                              QStringLiteral("dev"), interfaceName,
                              QStringLiteral("metric"), QStringLiteral("1") });
        if (!result.ok) {
            if (failedRoute) {
                *failedRoute = route;
            }
            return false;
        }
    }
    return true;
}

bool LinuxRouteReconciler::validInterfaceName(const QString &value)
{
    static const QRegularExpression pattern(QStringLiteral("^[A-Za-z0-9_.-]{1,15}$"));
    return pattern.match(value).hasMatch();
}

} // namespace amnezia::headless
