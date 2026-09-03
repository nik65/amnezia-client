#include "linuxRouteReconciler.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QRegularExpression>
#include <QSaveFile>

#include <algorithm>
#include <cmath>
#include <utility>

#include "../client/core/utils/managedRoutePolicy.h"

namespace amnezia::headless
{

namespace
{
// Reserved protocol number used as a durable ownership marker for the
// split-default routes.  A route in table 51821 without this marker is not
// ours and is treated as a conflict rather than being deleted.
constexpr int AmneziaRouteProtocol = 186;

enum class ManagedRuleKind { None, FullTunnel, Bypass };

bool parseManagedRuleLine(const QString &line, int *priority,
                          ManagedRuleKind *kind, QString *destination = nullptr)
{
    const auto full = QRegularExpression(
            QStringLiteral("^\\s*(\\d+):\\s+from\\s+all\\s+lookup\\s+51821\\s*$")).match(line);
    if (full.hasMatch()) {
        if (priority) *priority = full.captured(1).toInt();
        if (kind) *kind = ManagedRuleKind::FullTunnel;
        if (destination) destination->clear();
        return true;
    }
    const auto bypass = QRegularExpression(
            QStringLiteral("^\\s*(\\d+):\\s+to\\s+(\\S+)\\s+lookup\\s+main\\s*$")).match(line);
    if (bypass.hasMatch()) {
        if (priority) *priority = bypass.captured(1).toInt();
        if (kind) *kind = ManagedRuleKind::Bypass;
        if (destination) *destination = bypass.captured(2);
        return true;
    }
    if (kind) *kind = ManagedRuleKind::None;
    return false;
}
}

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
    const bool previousFullTunnel = m_mode == QStringLiteral("all-except");
    const QString previousInterface = m_interfaceName;
    const QStringList previousRoutes = m_routes;
    const QStringList previousBypassRoutes = m_bypassRoutes;
    if (previousFullTunnel) {
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
    QStringList removedPreviousRoutes;
    const auto restorePrevious = [&]() {
        bool restored = removeRoutes(interfaceName, added);
        if (previousFullTunnel) {
            const RouteReconcileResult full = applyFullTunnel(previousInterface, previousBypassRoutes);
            restored = full.ok && restored;
        } else {
            restored = restoreRoutes(previousInterface, removedPreviousRoutes) && restored;
        }
        return restored;
    };
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
            if (!restorePrevious()) {
                markRecoveryRequired(QStringLiteral("split-route addition rollback failed"));
                return failure(QStringLiteral("recovery_required"),
                               QStringLiteral("managed route addition failed and previous routing could not be restored"));
            }
            return failure(QStringLiteral("route_add_failed"),
                           QStringLiteral("failed to apply a managed route"));
        }
        if (m_interfaceName != interfaceName || !m_routes.contains(route)) {
            added.append(route);
        }
    }

    if (m_interfaceName != interfaceName) {
        if (!removeRoutes(m_interfaceName, m_routes, nullptr, &removedPreviousRoutes)) {
            if (!restorePrevious()) {
                markRecoveryRequired(QStringLiteral("split-route interface transition rollback failed"));
                return failure(QStringLiteral("recovery_required"),
                               QStringLiteral("previous route interface could not be restored"));
            }
            return failure(QStringLiteral("route_remove_failed"),
                           QStringLiteral("failed to retire the previous route set"));
        }
    } else {
        for (const QString &route : std::as_const(m_routes)) {
            if (boundedRoutes.contains(route)) {
                continue;
            }
            const CommandResult result = m_runner->run(
                    executable, { QStringLiteral("route"), QStringLiteral("del"), route,
                                  QStringLiteral("dev"), interfaceName,
                                  QStringLiteral("metric"), QStringLiteral("1") });
            if (!result.ok) {
                if (!restorePrevious()) {
                    markRecoveryRequired(QStringLiteral("split-route retirement rollback failed"));
                    return failure(QStringLiteral("recovery_required"),
                                   QStringLiteral("retired split routes could not be restored"));
                }
                return failure(QStringLiteral("route_remove_failed"),
                               QStringLiteral("failed to retire a managed route"));
            }
            removedPreviousRoutes.append(route);
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
        const bool restored = restorePrevious();
        if (restored) {
            m_mode = previousFullTunnel ? QStringLiteral("all-except") : QStringLiteral("only-forward");
            m_interfaceName = previousInterface;
            m_routes = previousRoutes;
            m_bypassRoutes = previousBypassRoutes;
        }
        markRecoveryRequired(restored
                                 ? QStringLiteral("route state save failed after host state was restored")
                                 : QStringLiteral("route state save and host rollback both failed"));
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
    // Do not treat an arbitrary exit code 2 as "already absent": permission,
    // syntax and RTNETLINK failures can use the same code.  The caller's
    // ownership snapshot makes the operation idempotent, so an actual command
    // failure must remain visible and fail closed.
    if (result.ok) return true;
    if (result.exitCode != 2 || !arguments.contains(QStringLiteral("del"))) return false;
    const RuleSnapshot snapshot = readRuleSnapshot();
    if (!snapshot.valid) return false;
    const int priorityIndex = arguments.indexOf(QStringLiteral("priority"));
    if (priorityIndex < 0 || priorityIndex + 1 >= arguments.size()) return false;
    bool priorityOk = false;
    const int priority = arguments.at(priorityIndex + 1).toInt(&priorityOk);
    if (!priorityOk) return false;
    if (arguments.contains(QStringLiteral("to"))) {
        const int toIndex = arguments.indexOf(QStringLiteral("to"));
        if (toIndex + 1 >= arguments.size()) return false;
        return !std::any_of(snapshot.lines.cbegin(), snapshot.lines.cend(),
                            [priority, &arguments, toIndex](const QString &line) {
            return ruleLineMatches(line, priority,
                                   QStringLiteral("to %1 ").arg(arguments.at(toIndex + 1)));
        });
    }
    const bool ipv6 = arguments.contains(QStringLiteral("-6"));
    return !(ipv6 ? snapshot.ownedFullV6.contains(priority)
                  : snapshot.ownedFullV4.contains(priority));
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
    if (result.ok) return true;
    if (result.exitCode != 2 || !arguments.contains(QStringLiteral("del"))) return false;
    const RuleSnapshot snapshot = readRuleSnapshot();
    if (!snapshot.valid) return false;
    const int routeIndex = arguments.indexOf(QStringLiteral("route"));
    if (routeIndex < 0 || routeIndex + 2 >= arguments.size()) return false;
    const QString prefix = arguments.at(routeIndex + 2);
    const QRegularExpression routePattern(
            QStringLiteral("^\\s*%1\\s+dev\\s+\\S+\\s+proto\\s+%2(?:\\s|$)")
                .arg(QRegularExpression::escape(prefix)).arg(AmneziaRouteProtocol));
    return !std::any_of(snapshot.tableLines.cbegin(), snapshot.tableLines.cend(),
                        [&routePattern](const QString &line) {
        return routePattern.match(line).hasMatch();
    });
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
            // ip-rule(8) has no installer protocol field (only ipproto,
            // which filters packet traffic).  Do not emit the invalid
            // `ip rule ... protocol 186` form; route protocol 186 plus exact
            // rule grammar and priority ownership is the safe marker.
            int managedPriority = 0;
            ManagedRuleKind managedKind = ManagedRuleKind::None;
            if (parseManagedRuleLine(line, &managedPriority, &managedKind)
                && managedPriority == priority && managedKind == ManagedRuleKind::FullTunnel) {
                snapshot.ownedFull.insert(priority);
                (family == 0 ? snapshot.ownedFullV4 : snapshot.ownedFullV6).insert(priority);
            }
            if (managedKind == ManagedRuleKind::Bypass && managedPriority == priority) {
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
    int parsedPriority = 0;
    ManagedRuleKind kind = ManagedRuleKind::None;
    QString destination;
    if (!parseManagedRuleLine(line, &parsedPriority, &kind, &destination)
        || parsedPriority != priority || kind != ManagedRuleKind::Bypass) {
        return false;
    }
    const QString expected = needle.trimmed().mid(QStringLiteral("to ").size()).trimmed();
    return !expected.isEmpty() && destination == expected;
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
    const bool hadFullTunnel = m_mode == QStringLiteral("all-except");
    if ((!hadFullTunnel && (ruleSnapshot.occupied.contains(m_bypassRulePriority)
                            || ruleSnapshot.occupied.contains(m_fullRulePriority)))
        || (ruleSnapshot.occupied.contains(m_bypassRulePriority)
         && !ruleSnapshot.ownedBypass.contains(m_bypassRulePriority))
        || (ruleSnapshot.occupied.contains(m_fullRulePriority)
            && !ruleSnapshot.ownedFull.contains(m_fullRulePriority))) {
        return failure(QStringLiteral("full_tunnel_rule_conflict"),
                       QStringLiteral("a persisted full-tunnel priority is occupied by a foreign rule"));
    }
    if (hadFullTunnel) {
        for (const QString &line : ruleSnapshot.lines) {
            int priority = 0;
            ManagedRuleKind kind = ManagedRuleKind::None;
            QString destination;
            const auto priorityMatch = QRegularExpression(QStringLiteral("^\\s*(\\d+):")).match(line);
            if (!priorityMatch.hasMatch()) continue;
            priority = priorityMatch.captured(1).toInt();
            if (!parseManagedRuleLine(line, &priority, &kind, &destination)) {
                if (priority == m_bypassRulePriority || priority == m_fullRulePriority) {
                    return failure(QStringLiteral("full_tunnel_rule_conflict"),
                                   QStringLiteral("a persisted priority contains an unparseable rule"));
                }
                continue;
            }
            if (priority == m_bypassRulePriority
                && (kind != ManagedRuleKind::Bypass || !m_bypassRoutes.contains(destination))) {
                return failure(QStringLiteral("full_tunnel_rule_conflict"),
                               QStringLiteral("the persisted bypass priority contains an ambiguous rule"));
            }
            if (priority == m_fullRulePriority && kind != ManagedRuleKind::FullTunnel) {
                return failure(QStringLiteral("full_tunnel_rule_conflict"),
                               QStringLiteral("the persisted full-tunnel priority contains an ambiguous rule"));
            }
        }
    }
    int bypassPriority = FullTunnelBypassRulePriority;
    int fullPriority = FullTunnelRulePriority;
    if (!selectRulePriorities(ruleSnapshot, &bypassPriority, &fullPriority)) {
        return failure(QStringLiteral("full_tunnel_rule_probe_failed"),
                       QStringLiteral("could not find safe policy-rule priorities"));
    }
    QSet<QString> tableRoutes;
    const QString previousInterface = m_interfaceName;
    const QRegularExpression ownedTableRoute(
            QStringLiteral("^\\s*(0\\.0\\.0\\.0/1|128\\.0\\.0\\.0/1|::/1|8000::/1)\\s+dev\\s+(\\S+)\\s+proto\\s+%1(?:\\s|$)")
                .arg(AmneziaRouteProtocol));
    QString markedInterface;
    for (const QString &line : ruleSnapshot.tableLines) {
        const QRegularExpressionMatch match = ownedTableRoute.match(line);
        if (!match.hasMatch()) {
            return failure(QStringLiteral("full_tunnel_table_conflict"),
                           QStringLiteral("route table 51821 contains an unowned route"));
        }
        if (tableRoutes.contains(match.captured(1))) {
            return failure(QStringLiteral("full_tunnel_table_conflict"),
                           QStringLiteral("route table 51821 contains duplicate managed prefixes"));
        }
        tableRoutes.insert(match.captured(1));
        if (markedInterface.isEmpty()) {
            markedInterface = match.captured(2);
        } else if (markedInterface != match.captured(2)) {
            return failure(QStringLiteral("full_tunnel_table_conflict"),
                           QStringLiteral("route table 51821 contains multiple owned interfaces"));
        }
    }
    if (tableRoutes.size() > 4) {
        return failure(QStringLiteral("full_tunnel_table_conflict"),
                       QStringLiteral("route table 51821 contains too many routes"));
    }
    // During a legitimate reconnect the target interface can change.  The
    // kernel marker must still match the persisted owner; accepting a marked
    // table whose owner differs from the receipt would take over foreign
    // routes, while rejecting a receipt-owned old interface traps safe
    // interface migration.  The route transaction below replaces the exact
    // prefixes and restores the previous subset if any step fails.
    if (!markedInterface.isEmpty()
        && (!hadFullTunnel || previousInterface.isEmpty() || markedInterface != previousInterface)) {
        return failure(QStringLiteral("full_tunnel_ownership_ambiguous"),
                       QStringLiteral("kernel full-tunnel table does not match the persisted interface receipt"));
    }
    if (!hadFullTunnel && !tableRoutes.isEmpty()) {
        return failure(QStringLiteral("full_tunnel_ownership_ambiguous"),
                       QStringLiteral("a pre-existing route table cannot be attributed to this daemon"));
    }

    const QStringList previousBypassRoutes = m_bypassRoutes;
    const int previousBypassPriority = m_bypassRulePriority;
    const auto fullRoutePrefix = [](const QStringList &arguments) {
        const int routeIndex = arguments.indexOf(QStringLiteral("route"));
        return routeIndex >= 0 && routeIndex + 2 < arguments.size()
                ? arguments.at(routeIndex + 2) : QString();
    };

    const QList<QStringList> fullRoutes {
        { QStringLiteral("route"), QStringLiteral("replace"), QStringLiteral("0.0.0.0/1"),
          QStringLiteral("dev"), interfaceName, QStringLiteral("table"),
          QString::number(FullTunnelRouteTable), QStringLiteral("proto"),
          QString::number(AmneziaRouteProtocol) },
        { QStringLiteral("route"), QStringLiteral("replace"), QStringLiteral("128.0.0.0/1"),
          QStringLiteral("dev"), interfaceName, QStringLiteral("table"),
          QString::number(FullTunnelRouteTable), QStringLiteral("proto"),
          QString::number(AmneziaRouteProtocol) },
        { QStringLiteral("-6"), QStringLiteral("route"), QStringLiteral("replace"),
          QStringLiteral("::/1"), QStringLiteral("dev"), interfaceName,
          QStringLiteral("table"), QString::number(FullTunnelRouteTable),
          QStringLiteral("proto"), QString::number(AmneziaRouteProtocol) },
        { QStringLiteral("-6"), QStringLiteral("route"), QStringLiteral("replace"),
          QStringLiteral("8000::/1"), QStringLiteral("dev"), interfaceName,
          QStringLiteral("table"), QString::number(FullTunnelRouteTable),
          QStringLiteral("proto"), QString::number(AmneziaRouteProtocol) },
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
            } else {
                // Same-interface refreshes can start from a partial table.
                // Remove only routes introduced by this transaction; retain
                // the pre-existing owned subset as the LKG.
                for (int index = 0; index < installedRoutes; ++index) {
                    if (tableRoutes.contains(fullRoutePrefix(fullRoutes.at(index)))) continue;
                    QStringList deletion = fullRoutes.at(index);
                    deletion.replace(deletion.indexOf(QStringLiteral("replace")),
                                     QStringLiteral("del"));
                    rollbackOk = removeFullTunnelRoute(deletion) && rollbackOk;
                }
            }
            // Restore the previous full-tunnel table when a refresh changed
            // the interface and only part of the replacement was accepted.
            if (hadFullTunnel && !previousInterface.isEmpty()) {
                // Restore exactly the prefixes observed before this
                // transaction.  Recreating all four defaults would destroy a
                // legitimate partial LKG table after an interface switch.
                for (const QStringList &route : fullRoutes) {
                    if (!tableRoutes.contains(fullRoutePrefix(route))) continue;
                    QStringList restore = route;
                    const int interfaceIndex = restore.indexOf(interfaceName);
                    if (interfaceIndex < 0) {
                        rollbackOk = false;
                        continue;
                    }
                    restore[interfaceIndex] = previousInterface;
                    rollbackOk = addFullTunnelRoute(restore) && rollbackOk;
                }
            }
            if (!rollbackOk) {
                const bool persisted = markRecoveryRequired(
                        QStringLiteral("full-tunnel route rollback was incomplete"));
                return failure(QStringLiteral("recovery_required"),
                               persisted
                                   ? QStringLiteral("failed to install the full-tunnel route table and rollback was incomplete")
                                   : QStringLiteral("full-tunnel rollback and durable recovery receipt both failed"));
            }
            return failure(QStringLiteral("full_tunnel_route_failed"),
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
                if (tableRoutes.contains(fullRoutePrefix(route))) continue;
                QStringList deletion { route };
                deletion.replace(deletion.indexOf(QStringLiteral("replace")),
                                 QStringLiteral("del"));
                ok = removeFullTunnelRoute(deletion) && ok;
            }
        } else if (previousInterface == interfaceName) {
            for (const QStringList &route : fullRoutes) {
                if (tableRoutes.contains(fullRoutePrefix(route))) continue;
                QStringList deletion = route;
                deletion.replace(deletion.indexOf(QStringLiteral("replace")),
                                 QStringLiteral("del"));
                ok = removeFullTunnelRoute(deletion) && ok;
            }
        } else if (previousInterface != interfaceName && !previousInterface.isEmpty()) {
            for (const QStringList &route : fullRoutes) {
                if (!tableRoutes.contains(fullRoutePrefix(route))) continue;
                QStringList restore = route;
                restore.replace(restore.indexOf(interfaceName), previousInterface);
                ok = addFullTunnelRoute(restore) && ok;
            }
        }
        return ok;
    };

    for (const QString &route : bypassRoutes) {
        if (ruleSnapshot.occupied.contains(bypassPriority)) {
            const bool exactOwned = std::any_of(ruleSnapshot.lines.cbegin(), ruleSnapshot.lines.cend(),
                                                [bypassPriority, &route](const QString &line) {
                return ruleLineMatches(line, bypassPriority,
                                       QStringLiteral("to %1 ").arg(route));
            });
            const bool ambiguous = std::any_of(ruleSnapshot.lines.cbegin(), ruleSnapshot.lines.cend(),
                                               [bypassPriority, &bypassRoutes](const QString &line) {
                return QRegularExpression(QStringLiteral("^\\s*%1:").arg(bypassPriority)).match(line).hasMatch()
                    && !std::any_of(bypassRoutes.cbegin(), bypassRoutes.cend(),
                                    [bypassPriority, &line](const QString &candidate) {
                return ruleLineMatches(line, bypassPriority,
                                       QStringLiteral("to %1 ").arg(candidate));
            });
            });
            if (!exactOwned || ambiguous) {
                return failure(QStringLiteral("full_tunnel_rule_conflict"),
                               QStringLiteral("the bypass-rule priority is occupied by an ambiguous rule"));
            }
        }
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
                const bool persisted = markRecoveryRequired(QStringLiteral("full-tunnel rule rollback failed"));
                return failure(QStringLiteral("recovery_required"), persisted
                                   ? QStringLiteral("full-tunnel route transaction rollback failed")
                                   : QStringLiteral("full-tunnel rollback recovery receipt could not be persisted"));
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
                const bool persisted = markRecoveryRequired(QStringLiteral("full-tunnel IPv4 rule rollback failed"));
                return failure(QStringLiteral("recovery_required"), persisted
                                   ? QStringLiteral("full-tunnel rule transaction rollback failed")
                                   : QStringLiteral("full-tunnel rollback recovery receipt could not be persisted"));
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
                const bool persisted = markRecoveryRequired(QStringLiteral("full-tunnel IPv6 rule rollback failed"));
                return failure(QStringLiteral("recovery_required"), persisted
                                   ? QStringLiteral("full-tunnel rule transaction rollback failed")
                                   : QStringLiteral("full-tunnel rollback recovery receipt could not be persisted"));
            }
            return failure(QStringLiteral("full_tunnel_rule_conflict"),
                           QStringLiteral("the IPv6 full-tunnel policy rule could not be installed"));
        }
        addedFullV6 = true;
    }

    QStringList removedPreviousBypassRoutes;
    QStringList removedSplitRoutes;
    if (hadFullTunnel) {
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
                const bool rollbackOk = rollback();
                bool retiredRestoreOk = true;
                for (const QString &removed : removedPreviousBypassRoutes) {
                    if (!addFullTunnelRule(bypassRuleArguments(QStringLiteral("add"),
                                                                previousBypassPriority, removed))) {
                        retiredRestoreOk = false;
                    }
                }
                if (!rollbackOk || !retiredRestoreOk) {
                    const bool persisted = markRecoveryRequired(QStringLiteral("full-tunnel cleanup rollback failed"));
                    return failure(QStringLiteral("recovery_required"), persisted
                                       ? QStringLiteral("full-tunnel cleanup rollback failed")
                                       : QStringLiteral("full-tunnel cleanup recovery receipt could not be persisted"));
                }
                return failure(QStringLiteral("full_tunnel_rule_cleanup_failed"),
                               QStringLiteral("a stale full-tunnel bypass rule could not be removed"));
            }
            if (!bypassRoutes.contains(route) && owned) {
                removedPreviousBypassRoutes.append(route);
            }
        }
    } else if (!m_routes.isEmpty()) {
        if (!removeRoutes(m_interfaceName, m_routes, nullptr, &removedSplitRoutes)) {
            const bool routesRestored = restoreRoutes(m_interfaceName, removedSplitRoutes);
            const bool tunnelRestored = rollback();
            if (!routesRestored || !tunnelRestored) {
                markRecoveryRequired(QStringLiteral("split-to-full transition rollback failed"));
                return failure(QStringLiteral("recovery_required"),
                               QStringLiteral("full-tunnel transition failed and split routes could not be restored"));
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
        bool restored = rollback();
        restored = restoreRoutes(previousInterface, removedSplitRoutes) && restored;
        for (const QString &route : removedPreviousBypassRoutes) {
            restored = addFullTunnelRule(bypassRuleArguments(QStringLiteral("add"),
                                                              previousBypassPriority, route)) && restored;
        }
        markRecoveryRequired(restored
                                 ? QStringLiteral("full-tunnel state save failed after host rollback")
                                 : QStringLiteral("full-tunnel state save and host rollback both failed"));
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
    // Rules alone do not prove ownership: another service can legitimately
    // reference table 51821.  Require at least one exact, protocol-marked
    // route for this interface and reject any unmarked/foreign table entry
    // before deleting a rule or route.
    const QRegularExpression ownedTableRoute(
            QStringLiteral("^\\s*(0\\.0\\.0\\.0/1|128\\.0\\.0\\.0/1|::/1|8000::/1)\\s+dev\\s+%1\\s+proto\\s+%2(?:\\s|$)")
                .arg(QRegularExpression::escape(m_interfaceName))
                .arg(AmneziaRouteProtocol));
    if (m_interfaceName.isEmpty()) {
        return failure(QStringLiteral("full_tunnel_ownership_ambiguous"),
                       QStringLiteral("full-tunnel ownership receipt has no positively-owned route"));
    }
    if (snapshot.tableLines.isEmpty()) {
        // A crash may leave only the durable receipt after the kernel has
        // already removed the table.  With no owned rule either, there is no
        // host object to mutate; retire the stale receipt safely.
        if (snapshot.ownedFull.contains(m_fullRulePriority)
            || snapshot.ownedBypass.contains(m_bypassRulePriority)) {
            return failure(QStringLiteral("full_tunnel_ownership_ambiguous"),
                           QStringLiteral("full-tunnel rules exist without an owned route table"));
        }
        m_mode = QStringLiteral("only-forward");
        m_interfaceName.clear();
        m_routes.clear();
        m_bypassRoutes.clear();
        if (!saveState()) {
            m_stateValid = false;
            m_mode = QStringLiteral("recovery_required");
            return failure(QStringLiteral("recovery_required"),
                           QStringLiteral("stale full-tunnel state could not be retired"));
        }
        return { true, {}, {} };
    }
    for (const QString &line : snapshot.tableLines) {
        if (!ownedTableRoute.match(line).hasMatch()) {
            return failure(QStringLiteral("full_tunnel_ownership_ambiguous"),
                           QStringLiteral("route table 51821 contains a foreign or unmarked route"));
        }
    }
    // A route marker alone does not prove that policy rules at the persisted
    // priorities belong to this daemon.  Refuse to delete or take over a
    // same-priority foreign rule; only an exact protocol-marked rule is ours.
    if ((snapshot.occupied.contains(m_fullRulePriority)
         && !snapshot.ownedFull.contains(m_fullRulePriority))
        || (snapshot.occupied.contains(m_bypassRulePriority)
            && !snapshot.ownedBypass.contains(m_bypassRulePriority))) {
        return failure(QStringLiteral("full_tunnel_ownership_ambiguous"),
                       QStringLiteral("a policy rule priority is occupied by a foreign rule"));
    }
    QStringList removedBypassRoutes;
    bool removedFullV4 = false;
    bool removedFullV6 = false;
    const auto restoreRemovedRules = [&]() {
        bool restored = true;
        for (const QString &route : removedBypassRoutes) {
            restored = addFullTunnelRule(bypassRuleArguments(QStringLiteral("add"),
                                                              m_bypassRulePriority, route)) && restored;
        }
        if (removedFullV4) {
            restored = addFullTunnelRule(fullRuleArguments(QStringLiteral("add"),
                                                            m_fullRulePriority, false)) && restored;
        }
        if (removedFullV6) {
            restored = addFullTunnelRule(fullRuleArguments(QStringLiteral("add"),
                                                            m_fullRulePriority, true)) && restored;
        }
        return restored;
    };
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
            if (!restoreRemovedRules()) {
                markRecoveryRequired(QStringLiteral("full-tunnel bypass-rule restoration failed"));
                return failure(QStringLiteral("recovery_required"),
                               QStringLiteral("a bypass rule could not be removed and rollback failed"));
            }
            return failure(QStringLiteral("full_tunnel_rule_cleanup_failed"),
                           QStringLiteral("a full-tunnel bypass rule could not be removed"));
        }
        removedBypassRoutes.append(route);
    }
    const bool fullV4Owned = snapshot.ownedFullV4.contains(m_fullRulePriority);
    const bool fullV6Owned = snapshot.ownedFullV6.contains(m_fullRulePriority);
    if (fullV4Owned && !removeFullTunnelRule(fullRuleArguments(QStringLiteral("del"),
                                                                    m_fullRulePriority, false))) {
        if (!restoreRemovedRules()) {
            markRecoveryRequired(QStringLiteral("full-tunnel IPv4-rule restoration failed"));
            return failure(QStringLiteral("recovery_required"),
                           QStringLiteral("the IPv4 rule could not be removed and rollback failed"));
        }
        return failure(QStringLiteral("full_tunnel_rule_cleanup_failed"),
                       QStringLiteral("the full-tunnel policy rule could not be removed"));
    }
    removedFullV4 = fullV4Owned;
    if (fullV6Owned && !removeFullTunnelRule(fullRuleArguments(QStringLiteral("del"),
                                                                    m_fullRulePriority, true))) {
        if (!restoreRemovedRules()) {
            markRecoveryRequired(QStringLiteral("full-tunnel IPv6-rule restoration failed"));
            return failure(QStringLiteral("recovery_required"),
                           QStringLiteral("the IPv6 rule could not be removed and rollback failed"));
        }
        return failure(QStringLiteral("full_tunnel_rule_cleanup_failed"),
                       QStringLiteral("the IPv6 full-tunnel policy rule could not be removed"));
    }
    removedFullV6 = fullV6Owned;
    const QStringList v4Route = { QStringLiteral("route"), QStringLiteral("del"),
                                  QStringLiteral("0.0.0.0/1"), QStringLiteral("table"),
                                  QString::number(FullTunnelRouteTable), QStringLiteral("proto"),
                                  QString::number(AmneziaRouteProtocol) };
    const QStringList v4RouteUpper = { QStringLiteral("route"), QStringLiteral("del"),
                                       QStringLiteral("128.0.0.0/1"), QStringLiteral("table"),
                                       QString::number(FullTunnelRouteTable), QStringLiteral("proto"),
                                       QString::number(AmneziaRouteProtocol) };
    const QStringList v6Route = { QStringLiteral("-6"), QStringLiteral("route"),
                                  QStringLiteral("del"), QStringLiteral("::/1"),
                                  QStringLiteral("table"), QString::number(FullTunnelRouteTable),
                                  QStringLiteral("proto"), QString::number(AmneziaRouteProtocol) };
    const QStringList v6RouteUpper = { QStringLiteral("-6"), QStringLiteral("route"),
                                       QStringLiteral("del"), QStringLiteral("8000::/1"),
                                       QStringLiteral("table"), QString::number(FullTunnelRouteTable),
                                       QStringLiteral("proto"), QString::number(AmneziaRouteProtocol) };
    const auto restoreOwnedTable = [&]() {
        bool restored = true;
        for (const QString &line : snapshot.tableLines) {
            const QRegularExpressionMatch match = QRegularExpression(
                    QStringLiteral("^\\s*(0\\.0\\.0\\.0/1|128\\.0\\.0\\.0/1|::/1|8000::/1)\\s+dev\\s+(\\S+)\\s+proto\\s+%1(?:\\s|$)")
                        .arg(AmneziaRouteProtocol)).match(line);
            if (!match.hasMatch()) continue;
            QStringList restore { QStringLiteral("route"), QStringLiteral("replace"),
                                  match.captured(1), QStringLiteral("dev"),
                                  match.captured(2), QStringLiteral("table"),
                                  QString::number(FullTunnelRouteTable), QStringLiteral("proto"),
                                  QString::number(AmneziaRouteProtocol) };
            if (match.captured(1).contains(QLatin1Char(':'))) restore.prepend(QStringLiteral("-6"));
            restored = addFullTunnelRoute(restore) && restored;
        }
        return restored;
    };
    if (!removeFullTunnelRoute(v4Route) || !removeFullTunnelRoute(v4RouteUpper)
        || !removeFullTunnelRoute(v6Route) || !removeFullTunnelRoute(v6RouteUpper)) {
        const bool restored = restoreOwnedTable();
        const bool rulesRestored = restoreRemovedRules();
        if (!restored || !rulesRestored) {
            markRecoveryRequired(QStringLiteral("full-tunnel route-table restoration failed"));
            return failure(QStringLiteral("recovery_required"),
                           QStringLiteral("the route table could not be removed and restoration failed"));
        }
        return failure(QStringLiteral("full_tunnel_route_cleanup_failed"),
                       restored && rulesRestored ? QStringLiteral("the full-tunnel route table could not be removed")
                               : QStringLiteral("the full-tunnel route table could not be removed and restoration failed"));
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
    if (!m_stateValid || m_mode == QStringLiteral("recovery_required")) {
        return failure(QStringLiteral("recovery_required"),
                       QStringLiteral("managed DNS state is invalid; manual recovery is required"));
    }
    if (!validInterfaceName(interfaceName) || dnsServers.isEmpty() || dnsDomains.isEmpty()) {
        return failure(QStringLiteral("invalid_dns_configuration"),
                       QStringLiteral("a VPN interface, DNS server and routing domain are required"));
    }
    const QString executable = resolvectlExecutable();
    if (executable.isEmpty()) {
        return failure(QStringLiteral("dns_backend_unavailable"),
                       QStringLiteral("systemd-resolved resolvectl is not installed"));
    }

    const QString previousInterface = m_dnsInterface;
    const QStringList previousServers = m_dnsServers;
    const QStringList previousDomains = m_dnsDomains;
    const auto restorePreviousDns = [&]() {
        bool restored = true;
        // A failed refresh may have configured a different interface before
        // the domain command failed.  Revert that new binding first; only
        // then restore the exact previous receipt.
        if (interfaceName != previousInterface && !interfaceName.isEmpty()) {
            restored = m_runner->run(executable,
                                     { QStringLiteral("revert"), interfaceName }).ok
                    && restored;
        }
        if (previousInterface.isEmpty() || previousServers.isEmpty() || previousDomains.isEmpty()) {
            return restored;
        }
        QStringList restoreDns { QStringLiteral("dns"), previousInterface };
        restoreDns.append(previousServers);
        QStringList restoreDomain { QStringLiteral("domain"), previousInterface };
        restoreDomain.append(previousDomains);
        return m_runner->run(executable, restoreDns).ok
            && m_runner->run(executable, restoreDomain).ok
            && restored;
    };
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
        if (!restorePreviousDns()) {
            markRecoveryRequired(QStringLiteral("DNS domain rollback failed"));
            return failure(QStringLiteral("recovery_required"),
                           QStringLiteral("DNS configuration failed and the previous resolver binding could not be restored"));
        }
        return failure(QStringLiteral("dns_configure_failed"),
                       QStringLiteral("failed to assign the VPN DNS routing domain"));
    }
    if (!previousInterface.isEmpty() && previousInterface != interfaceName
        && !m_runner->run(executable,
                          { QStringLiteral("revert"), previousInterface }).ok) {
        if (!restorePreviousDns()) {
            markRecoveryRequired(QStringLiteral("DNS interface transition rollback failed"));
            return failure(QStringLiteral("recovery_required"),
                           QStringLiteral("DNS interface transition failed and the previous resolver binding could not be restored"));
        }
        return failure(QStringLiteral("dns_configure_failed"),
                       QStringLiteral("the previous VPN DNS interface could not be retired"));
    }
    // This is a cache invalidation only; DNS servers and domains are already
    // configured above.  A stale negative answer must not hide a new policy.
    m_runner->run(executable, { QStringLiteral("flush-caches") });
    m_dnsInterface = interfaceName;
    m_dnsServers = dnsServers;
    m_dnsDomains = dnsDomains;
    if (!saveState()) {
        const bool restored = restorePreviousDns();
        m_dnsInterface = previousInterface;
        m_dnsServers = previousServers;
        m_dnsDomains = previousDomains;
        markRecoveryRequired(restored
                                 ? QStringLiteral("DNS receipt save failed after resolver rollback")
                                 : QStringLiteral("DNS receipt save and resolver rollback both failed"));
        return failure(QStringLiteral("recovery_required"),
                       QStringLiteral("VPN DNS was applied but its durable receipt could not be saved"));
    }
    return { true, {}, {} };
}

RouteReconcileResult LinuxRouteReconciler::clearDns(const QString &interfaceName)
{
    if (!m_stateValid || m_mode == QStringLiteral("recovery_required")) {
        return failure(QStringLiteral("recovery_required"),
                       QStringLiteral("managed DNS state is invalid; refusing to mutate resolver state"));
    }
    if (!m_dnsInterface.isEmpty() && interfaceName != m_dnsInterface) {
        return failure(QStringLiteral("dns_interface_mismatch"),
                       QStringLiteral("DNS cleanup interface does not match the persisted receipt"));
    }
    if (interfaceName.isEmpty()) {
        if (!m_dnsInterface.isEmpty()) {
            return failure(QStringLiteral("dns_interface_required"),
                           QStringLiteral("cannot retire a DNS receipt without its persisted interface"));
        }
        m_dnsInterface.clear();
        m_dnsServers.clear();
        m_dnsDomains.clear();
        if (!saveState()) {
            m_stateValid = false;
            m_mode = QStringLiteral("recovery_required");
            return failure(QStringLiteral("recovery_required"),
                           QStringLiteral("VPN DNS receipt could not be cleared"));
        }
        return { true, {}, {} };
    }
    const QString executable = resolvectlExecutable();
    if (executable.isEmpty()) {
        return failure(QStringLiteral("dns_backend_unavailable"),
                       QStringLiteral("cannot clear VPN DNS receipt without resolvectl"));
    }
    const CommandResult result = m_runner->run(
            executable, { QStringLiteral("revert"), interfaceName });
    if (!result.ok) {
        return failure(QStringLiteral("dns_clear_failed"),
                       QStringLiteral("failed to clear the VPN DNS configuration"));
    }
    const QString previousInterface = m_dnsInterface;
    const QStringList previousServers = m_dnsServers;
    const QStringList previousDomains = m_dnsDomains;
    m_dnsInterface.clear();
    m_dnsServers.clear();
    m_dnsDomains.clear();
    if (!saveState()) {
        bool restored = true;
        QStringList dnsArguments { QStringLiteral("dns"), previousInterface };
        dnsArguments.append(previousServers);
        QStringList domainArguments { QStringLiteral("domain"), previousInterface };
        domainArguments.append(previousDomains);
        if (!previousInterface.isEmpty()) {
            restored = m_runner->run(executable, dnsArguments).ok && restored;
            restored = m_runner->run(executable, domainArguments).ok && restored;
        }
        m_dnsInterface = previousInterface;
        m_dnsServers = previousServers;
        m_dnsDomains = previousDomains;
        markRecoveryRequired(restored
                                 ? QStringLiteral("DNS clear receipt save failed after resolver restoration")
                                 : QStringLiteral("DNS clear receipt save and resolver restoration both failed"));
        return failure(QStringLiteral("recovery_required"),
                       QStringLiteral("VPN DNS receipt could not be cleared"));
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
        if (!saveState()) {
            m_stateValid = false;
            m_mode = QStringLiteral("recovery_required");
            return failure(QStringLiteral("recovery_required"),
                           QStringLiteral("managed route receipt could not be cleared"));
        }
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
        { QStringLiteral("dnsInterface"), m_dnsInterface },
        { QStringLiteral("dnsServers"), QJsonArray::fromStringList(m_dnsServers) },
        { QStringLiteral("dnsDomains"), QJsonArray::fromStringList(m_dnsDomains) },
    };
}

RouteReconcileResult LinuxRouteReconciler::failure(const QString &code,
                                                   const QString &message) const
{
    m_lastError = message;
    return { false, code, message };
}

bool LinuxRouteReconciler::markRecoveryRequired(const QString &message)
{
    m_stateValid = false;
    m_mode = QStringLiteral("recovery_required");
    m_lastError = message;
    return saveState();
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
    m_dnsInterface.clear();
    m_dnsServers.clear();
    m_dnsDomains.clear();
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
    for (auto it = object.constBegin(); it != object.constEnd(); ++it) {
        if (!QStringList {
                QStringLiteral("version"), QStringLiteral("mode"),
                QStringLiteral("interface"), QStringLiteral("routes"),
                QStringLiteral("bypassRoutes"), QStringLiteral("bypassRulePriority"),
                QStringLiteral("fullRulePriority"), QStringLiteral("dnsInterface"),
                QStringLiteral("dnsServers"), QStringLiteral("dnsDomains")
            }.contains(it.key())) {
            return false;
        }
    }
    const auto strictInt = [](const QJsonValue &value, int minimum, int maximum, int *result) {
        if (!value.isDouble()) return false;
        const double number = value.toDouble();
        if (!std::isfinite(number) || std::floor(number) != number
            || number < minimum || number > maximum) return false;
        if (result) *result = static_cast<int>(number);
        return true;
    };
    int stateVersion = 0;
    if (!strictInt(object.value(QStringLiteral("version")), 2, 2, &stateVersion)
        || !object.value(QStringLiteral("mode")).isString()
        || !object.value(QStringLiteral("interface")).isString()
        || !object.value(QStringLiteral("routes")).isArray()
        || !object.value(QStringLiteral("bypassRoutes")).isArray()) {
        return false;
    }
    Q_UNUSED(stateVersion);
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
    if (!routesValid || bounded.size() != routes.size()
        || (!interfaceName.isEmpty() && !validInterfaceName(interfaceName))) {
        return false;
    }
    if (mode == QStringLiteral("only-forward")
        && (interfaceName.isEmpty() != bounded.isEmpty())) {
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
    if (mode == QStringLiteral("all-except") && !routes.isEmpty()) {
        return false;
    }
    if (object.contains(QStringLiteral("dnsInterface"))
        && (!object.value(QStringLiteral("dnsInterface")).isString()
            || !object.value(QStringLiteral("dnsServers")).isArray()
            || !object.value(QStringLiteral("dnsDomains")).isArray())) {
        return false;
    }
    if (object.contains(QStringLiteral("dnsInterface"))
        || object.contains(QStringLiteral("dnsServers"))
        || object.contains(QStringLiteral("dnsDomains"))) {
        if (!object.value(QStringLiteral("dnsInterface")).isString()
            || !object.value(QStringLiteral("dnsServers")).isArray()
            || !object.value(QStringLiteral("dnsDomains")).isArray()) {
            return false;
        }
        m_dnsInterface = object.value(QStringLiteral("dnsInterface")).toString();
        for (const QJsonValue &value : object.value(QStringLiteral("dnsServers")).toArray()) {
            if (!value.isString()) return false;
            m_dnsServers.append(value.toString());
        }
        for (const QJsonValue &value : object.value(QStringLiteral("dnsDomains")).toArray()) {
            if (!value.isString()) return false;
            m_dnsDomains.append(value.toString());
        }
        if (m_dnsInterface.isEmpty() != m_dnsServers.isEmpty()
            || m_dnsServers.isEmpty() != m_dnsDomains.isEmpty()) return false;
        if (!m_dnsInterface.isEmpty()
            && (!validInterfaceName(m_dnsInterface)
                || (!interfaceName.isEmpty() && m_dnsInterface != interfaceName))) return false;
    }
    m_mode = mode;
    m_interfaceName = interfaceName;
    m_routes = bounded;
    m_bypassRoutes = boundedBypass;
    int storedBypassPriority = 0;
    int storedFullPriority = 0;
    if (!strictInt(object.value(QStringLiteral("bypassRulePriority")),
                   FullTunnelBypassRulePriority, 1099, &storedBypassPriority)
        || !strictInt(object.value(QStringLiteral("fullRulePriority")),
                      FullTunnelRulePriority, FullTunnelPriorityLimit, &storedFullPriority)) {
        return false;
    }
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
        { QStringLiteral("dnsInterface"), m_dnsInterface },
        { QStringLiteral("dnsServers"), QJsonArray::fromStringList(m_dnsServers) },
        { QStringLiteral("dnsDomains"), QJsonArray::fromStringList(m_dnsDomains) },
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
                                        QString *failedRoute,
                                        QStringList *removedRoutes)
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
        if (removedRoutes) removedRoutes->append(route);
    }
    return true;
}

bool LinuxRouteReconciler::restoreRoutes(const QString &interfaceName,
                                         const QStringList &routes)
{
    const QString executable = ipExecutable();
    if (executable.isEmpty() || (interfaceName.isEmpty() && !routes.isEmpty())) return false;
    bool ok = true;
    for (const QString &route : routes) {
        ok = m_runner->run(executable,
                           { QStringLiteral("route"), QStringLiteral("replace"), route,
                             QStringLiteral("dev"), interfaceName,
                             QStringLiteral("metric"), QStringLiteral("1") }).ok && ok;
    }
    return ok;
}

bool LinuxRouteReconciler::validInterfaceName(const QString &value)
{
    static const QRegularExpression pattern(QStringLiteral("^[A-Za-z0-9_.-]{1,15}$"));
    return pattern.match(value).hasMatch();
}

} // namespace amnezia::headless
