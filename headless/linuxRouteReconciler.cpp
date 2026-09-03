#include "linuxRouteReconciler.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QRegularExpression>
#include <QSaveFile>
#include <QLockFile>

#include <algorithm>
#include <cmath>
#include <functional>
#include <utility>

#include "../client/core/utils/managedRoutePolicy.h"

namespace amnezia::headless
{

namespace
{
std::unique_ptr<QLockFile> acquireRouteLock(const QString &statePath)
{
    if (statePath.trimmed().isEmpty()) return {};
    auto lock = std::make_unique<QLockFile>(statePath + QStringLiteral(".lock"));
    // Never guess that a live daemon is stale.  A lock is retired only by
    // the owning process, so probe/intent/kernel/state remain one transaction.
    lock->setStaleLockTime(0);
    if (!lock->tryLock(0)) return nullptr;
    return lock;
}
// Reserved protocol number used as a durable ownership marker for the
// split-default routes.  A route in table 51821 without this marker is not
// ours and is treated as a conflict rather than being deleted.
constexpr int AmneziaRouteProtocol = 186;
constexpr int AmneziaSplitRouteProtocol = 187;

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

bool parseManagedMainRouteLine(const QString &line, QString *prefix,
                               QString *interfaceName)
{
    const QStringList tokens = line.trimmed().split(QRegularExpression(QStringLiteral("\\s+")),
                                                     Qt::SkipEmptyParts);
    // `ip route show` may insert scope/src before or after proto/metric.  Do
    // not rely on one presentation order, but keep the ownership identity
    // strict: a managed route is a direct device route with our protocol and
    // metric, and has no gateway or unrelated route attributes.
    if (tokens.size() < 7 || tokens.at(1) != QStringLiteral("dev")) return false;
    int protoIndex = -1;
    int metricIndex = -1;
    for (int index = 3; index + 1 < tokens.size(); ++index) {
        if (tokens.at(index) == QStringLiteral("proto")) {
            if (protoIndex >= 0 || tokens.at(index + 1) != QStringLiteral("187")) return false;
            protoIndex = index;
        } else if (tokens.at(index) == QStringLiteral("metric")) {
            if (metricIndex >= 0 || tokens.at(index + 1) != QStringLiteral("1")) return false;
            metricIndex = index;
        } else if (tokens.at(index) == QStringLiteral("via")
                   || tokens.at(index) == QStringLiteral("onlink")) {
            return false;
        }
    }
    if (protoIndex < 0 || metricIndex < 0) return false;
    if (prefix) *prefix = tokens.at(0);
    if (interfaceName) *interfaceName = tokens.at(2);
    return true;
}

QStringList routeTokensWithoutMarkers(const QString &line)
{
    QStringList tokens = line.trimmed().split(QRegularExpression(QStringLiteral("\\s+")),
                                              Qt::SkipEmptyParts);
    for (int index = 0; index < tokens.size();) {
        if (tokens.at(index) == QStringLiteral("proto")
            || tokens.at(index) == QStringLiteral("table")) {
            if (index + 1 >= tokens.size()) return {};
            tokens.remove(index, 2);
            continue;
        }
        ++index;
    }
    if (tokens.size() > 3) {
        QStringList attributes = tokens.mid(3);
        std::sort(attributes.begin(), attributes.end());
        tokens = tokens.mid(0, 3);
        tokens.append(attributes);
    }
    return tokens;
}

QStringList legacyRouteArguments(const QString &line, const QString &operation,
                                 const QString &interfaceName, bool addProtocol)
{
    const QStringList tokens = line.trimmed().split(QRegularExpression(QStringLiteral("\\s+")),
                                                     Qt::SkipEmptyParts);
    if (tokens.size() < 3 || tokens.at(1) != QStringLiteral("dev")
        || tokens.at(2) != interfaceName) return {};
    for (int index = 3; index < tokens.size(); ++index) {
        if (tokens.at(index) == QStringLiteral("proto")
            || tokens.at(index) == QStringLiteral("table")
            || tokens.at(index) == QStringLiteral("via")
            || tokens.at(index) == QStringLiteral("onlink")) {
            return {};
        }
    }
    QStringList arguments { QStringLiteral("route"), operation };
    arguments.append(tokens);
    arguments << QStringLiteral("table") << QStringLiteral("51821");
    if (addProtocol) {
        arguments << QStringLiteral("proto") << QString::number(AmneziaRouteProtocol);
    }
    if (tokens.constFirst().contains(QLatin1Char(':'))) arguments.prepend(QStringLiteral("-6"));
    return arguments;
}
}

LinuxRouteReconciler::LinuxRouteReconciler(std::shared_ptr<CommandRunner> runner,
                                           QString statePath,
                                           bool initializeStateNow)
    : m_runner(runner ? std::move(runner) : std::make_shared<RealCommandRunner>()),
      m_statePath(std::move(statePath))
{
    if (!m_statePath.isEmpty()) {
        m_intentPath = m_statePath + QStringLiteral(".mutation-intent");
    }
    if (initializeStateNow) initializeState();
}

bool LinuxRouteReconciler::initializeState()
{
    if (m_initialized) return m_stateValid;
    m_initialized = true;
    m_stateValid = loadState();
    if (!m_stateValid) {
        m_mode = QStringLiteral("recovery_required");
        m_lastError = QStringLiteral("managed route state is invalid; refusing to mutate host routes");
    }
    return m_stateValid;
}

QString LinuxRouteReconciler::transactionIntentPath() const
{
    return m_intentPath;
}

bool LinuxRouteReconciler::beginMutation(const QString &operation,
                                         const QString &interfaceName,
                                         const QStringList &routes,
                                         const QStringList &bypassRoutes)
{
    return saveTransactionIntent(operation, QJsonObject {
        { QStringLiteral("interface"), interfaceName },
        { QStringLiteral("routes"), QJsonArray::fromStringList(routes) },
        { QStringLiteral("bypassRoutes"), QJsonArray::fromStringList(bypassRoutes) },
    });
}

bool LinuxRouteReconciler::finishMutation()
{
    return clearTransactionIntent();
}

bool LinuxRouteReconciler::saveTransactionIntent(const QString &operation,
                                                 const QJsonObject &target) const
{
    const QString path = transactionIntentPath();
    if (path.isEmpty()) return true;
    const QFileInfo existing(path);
    if (existing.exists() && (!existing.isFile() || existing.isSymLink())) return false;
    if (existing.exists()) return false;
    const QFileInfo info(path);
    if (!QDir().mkpath(info.absolutePath())) return false;
    QSaveFile file(path);
    if (!file.open(QIODevice::WriteOnly)) return false;
    const QJsonObject object {
        { QStringLiteral("version"), 1 },
        { QStringLiteral("operation"), operation },
        { QStringLiteral("previous"), status() },
        { QStringLiteral("target"), target },
    };
    if (file.write(QJsonDocument(object).toJson(QJsonDocument::Compact)) < 0
        || !file.commit()) {
        return false;
    }
#ifndef Q_OS_WIN
    QFile::setPermissions(path, QFileDevice::ReadOwner | QFileDevice::WriteOwner);
#endif
    return true;
}

bool LinuxRouteReconciler::clearTransactionIntent() const
{
    const QString path = transactionIntentPath();
    if (path.isEmpty() || !QFileInfo::exists(path)) return true;
    const QFileInfo info(path);
    return info.isFile() && !info.isSymLink() && QFile::remove(path);
}

RouteReconcileResult LinuxRouteReconciler::finishTransaction(RouteReconcileResult result)
{
    if (!result.ok && result.code == QStringLiteral("recovery_required")) {
        return result;
    }
    if (clearTransactionIntent()) return result;
    const bool persisted = markRecoveryRequired(
            QStringLiteral("managed routing transaction intent could not be retired"));
    return failure(QStringLiteral("recovery_required"), persisted
                   ? QStringLiteral("managed routing transaction completed but its intent could not be retired")
                   : QStringLiteral("managed routing transaction intent and recovery receipt could not be persisted"));
}

RouteReconcileResult LinuxRouteReconciler::apply(const QString &interfaceName,
                                                 const QStringList &routes)
{
    m_lastError.clear();
    if (!m_initialized || !m_stateValid) {
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
    const auto routeLock = acquireRouteLock(m_statePath);
    if (!m_statePath.isEmpty() && !routeLock) {
        return failure(QStringLiteral("route_mutation_in_progress"),
                       QStringLiteral("another routing transaction owns the managed route lock"));
    }
    const bool previousFullTunnel = m_mode == QStringLiteral("all-except");
    const QString previousInterface = m_interfaceName;
    const QStringList previousRoutes = m_routes;
    const QStringList previousBypassRoutes = m_bypassRoutes;
    const QString executable = ipExecutable();
    if (executable.isEmpty()) {
        return failure(QStringLiteral("route_backend_unavailable"),
                       QStringLiteral("the Linux ip command is not installed"));
    }
    // Probe and reject foreign target routes before clearing a current full
    // tunnel. A target preflight failure must not disturb the LKG tunnel.
    const RuleSnapshot routeSnapshot = readRuleSnapshot();
    if (!routeSnapshot.valid) {
        return failure(QStringLiteral("route_probe_failed"),
                       QStringLiteral("could not inspect the main routing table safely"));
    }
    for (const QString &route : boundedRoutes) {
        const QRegularExpression prefixPattern(
                QStringLiteral(R"(^\s*%1\s+)").arg(QRegularExpression::escape(route)));
        for (const QString &line : routeSnapshot.mainRouteLines) {
            if (!prefixPattern.match(line).hasMatch()) continue;
            const bool ownedByTarget = managedMainRouteLineMatches(line, route, interfaceName);
            const bool ownedByPrevious = !previousInterface.isEmpty()
                    && managedMainRouteLineMatches(line, route, previousInterface);
            if (!ownedByTarget && !ownedByPrevious) {
                return failure(QStringLiteral("only_forward_route_conflict"),
                               QStringLiteral("a main-table route is occupied by a foreign or ambiguous owner"));
            }
        }
    }
    if (!beginMutation(QStringLiteral("only-forward"), interfaceName,
                       boundedRoutes, {})) {
        return failure(QStringLiteral("recovery_required"),
                       QStringLiteral("managed route mutation intent could not be persisted"));
    }
    if (previousFullTunnel) {
        const RouteReconcileResult cleared = clearFullTunnel();
        if (!cleared.ok) {
            return finishTransaction(cleared);
        }
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
                              QStringLiteral("proto"), QString::number(AmneziaSplitRouteProtocol),
                              QStringLiteral("metric"), QStringLiteral("1") });
        if (!result.ok) {
            // A route that belonged to the previous set was only refreshed;
            // deleting it here would make a failed transaction worse.
            if (!restorePrevious()) {
                markRecoveryRequired(QStringLiteral("split-route addition rollback failed"));
            return finishTransaction(failure(QStringLiteral("recovery_required"),
                                             QStringLiteral("managed route addition failed and previous routing could not be restored")));
            }
            return finishTransaction(failure(QStringLiteral("route_add_failed"),
                                             QStringLiteral("failed to apply a managed route")));
        }
        if (m_interfaceName != interfaceName || !m_routes.contains(route)) {
            added.append(route);
        }
    }

    if (m_interfaceName != interfaceName) {
        if (!removeRoutes(m_interfaceName, m_routes, nullptr, &removedPreviousRoutes)) {
            if (!restorePrevious()) {
                markRecoveryRequired(QStringLiteral("split-route interface transition rollback failed"));
                return finishTransaction(failure(QStringLiteral("recovery_required"),
                                                 QStringLiteral("previous route interface could not be restored")));
            }
            return finishTransaction(failure(QStringLiteral("route_remove_failed"),
                                             QStringLiteral("failed to retire the previous route set")));
        }
    } else {
        for (const QString &route : std::as_const(m_routes)) {
            if (boundedRoutes.contains(route)) {
                continue;
            }
            QStringList removed;
            if (!removeRoutes(interfaceName, { route }, nullptr, &removed)) {
                if (!restorePrevious()) {
                    markRecoveryRequired(QStringLiteral("split-route retirement rollback failed"));
                    return finishTransaction(failure(QStringLiteral("recovery_required"),
                                                     QStringLiteral("retired split routes could not be restored")));
                }
                return finishTransaction(failure(QStringLiteral("route_remove_failed"),
                                                 QStringLiteral("failed to retire a managed route")));
            }
            removedPreviousRoutes.append(removed);
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
    if (!finishMutation()) {
        const bool restored = restorePrevious();
        markRecoveryRequired(restored
                                 ? QStringLiteral("managed route mutation intent could not be retired after rollback")
                                 : QStringLiteral("managed route mutation intent and rollback could not be completed"));
        return failure(QStringLiteral("recovery_required"),
                       QStringLiteral("managed routes committed but mutation intent remains"));
    }
    return finishTransaction({ true, {}, {} });
}

RouteReconcileResult LinuxRouteReconciler::applyAllExcept(
        const QString &interfaceName, const QStringList &bypassRoutes)
{
    m_lastError.clear();
    if (!m_initialized || !m_stateValid) {
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
    const auto routeLock = acquireRouteLock(m_statePath);
    if (!m_statePath.isEmpty() && !routeLock) {
        return failure(QStringLiteral("route_mutation_in_progress"),
                       QStringLiteral("another routing transaction owns the managed route lock"));
    }
    if (!beginMutation(QStringLiteral("all-except"), interfaceName, {}, boundedRoutes)) {
        return failure(QStringLiteral("recovery_required"),
                       QStringLiteral("full-tunnel mutation intent could not be persisted"));
    }
    const RouteReconcileResult result = applyFullTunnel(interfaceName, boundedRoutes);
    if (!result.ok) {
        return finishTransaction(result);
    }
    if (!finishMutation()) {
        const bool persisted = markRecoveryRequired(
                QStringLiteral("full-tunnel mutation intent could not be retired"));
        return failure(QStringLiteral("recovery_required"), persisted
                           ? QStringLiteral("full-tunnel routes committed but mutation intent remains")
                           : QStringLiteral("full-tunnel commit and recovery receipt both failed"));
    }
    return result;
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
        return !std::any_of(snapshot.linesV4.cbegin(), snapshot.linesV4.cend(),
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
    QSet<QString> seenManagedRules;
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
            QSet<int> &familyOccupied = family == 0
                    ? snapshot.occupiedV4 : snapshot.occupiedV6;
            QStringList &familyLines = family == 0
                    ? snapshot.linesV4 : snapshot.linesV6;
            familyOccupied.insert(priority);
            familyLines.append(line);
            // ip-rule(8) has no installer protocol field (only ipproto,
            // which filters packet traffic).  Do not emit the invalid
            // `ip rule ... protocol 186` form; route protocol 186 plus exact
            // rule grammar and priority ownership is the safe marker.
            int managedPriority = 0;
            ManagedRuleKind managedKind = ManagedRuleKind::None;
            QString destination;
            if (parseManagedRuleLine(line, &managedPriority, &managedKind, &destination)
                && managedPriority == priority && managedKind == ManagedRuleKind::FullTunnel) {
                const QString key = QStringLiteral("%1|full|%2").arg(family).arg(priority);
                if (seenManagedRules.contains(key)) return snapshot;
                seenManagedRules.insert(key);
                snapshot.ownedFull.insert(priority);
                (family == 0 ? snapshot.ownedFullV4 : snapshot.ownedFullV6).insert(priority);
            }
            if (managedKind == ManagedRuleKind::Bypass && managedPriority == priority) {
                const QString key = QStringLiteral("%1|bypass|%2|%3")
                        .arg(family).arg(priority).arg(destination);
                if (seenManagedRules.contains(key)) return snapshot;
                seenManagedRules.insert(key);
                snapshot.ownedBypass.insert(priority);
                (family == 0 ? snapshot.ownedBypassV4 : snapshot.ownedBypassV6).insert(priority);
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
    const CommandResult mainRoutes = m_runner->runCaptured(
            executable, { QStringLiteral("route"), QStringLiteral("show"),
                          QStringLiteral("table"), QStringLiteral("main") });
    if (!mainRoutes.ok) return snapshot;
    snapshot.mainRouteLines = mainRoutes.output.split(
            QRegularExpression(QStringLiteral("[\\r\\n]")), Qt::SkipEmptyParts);
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
        return snapshot.ownedBypassV4.contains(priority)
                && std::any_of(m_bypassRoutes.cbegin(), m_bypassRoutes.cend(),
                               [&snapshot, priority](const QString &route) {
            return std::any_of(snapshot.linesV4.cbegin(), snapshot.linesV4.cend(),
                               [priority, &route](const QString &line) {
                return ruleLineMatches(line, priority,
                                       QStringLiteral("to %1 ").arg(route));
            });
        });
    };
    auto select = [](int preferred, int first, int last, bool preferredOwned,
                     const std::function<bool(int)> &isOccupied, int *selected) {
        if (preferred >= first && preferred <= last && preferredOwned) {
            *selected = preferred;
            return true;
        }
        for (int candidate = first; candidate <= last; ++candidate) {
            if (!isOccupied(candidate)) {
                *selected = candidate;
                return true;
            }
        }
        return false;
    };
    return select(m_bypassRulePriority, FullTunnelBypassRulePriority, 1099,
                  hasOwnedBypassPriority(m_bypassRulePriority),
                  [&snapshot](int priority) { return snapshot.occupiedV4.contains(priority); },
                  bypassPriority)
        && select(m_fullRulePriority, FullTunnelRulePriority, FullTunnelPriorityLimit,
                  snapshot.ownedFull.contains(m_fullRulePriority)
                      && !(snapshot.occupiedV4.contains(m_fullRulePriority)
                           && !snapshot.ownedFullV4.contains(m_fullRulePriority))
                      && !(snapshot.occupiedV6.contains(m_fullRulePriority)
                           && !snapshot.ownedFullV6.contains(m_fullRulePriority)),
                  [&snapshot](int priority) {
                      return snapshot.occupiedV4.contains(priority)
                          || snapshot.occupiedV6.contains(priority);
                  },
                  fullPriority);
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

bool LinuxRouteReconciler::managedMainRouteLineMatches(
        const QString &line, const QString &prefix, const QString &interfaceName)
{
    QString actualPrefix;
    QString actualInterface;
    return parseManagedMainRouteLine(line, &actualPrefix, &actualInterface)
        && actualPrefix == prefix && actualInterface == interfaceName;
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
    if (!ruleSnapshot.valid) {
        return failure(QStringLiteral("full_tunnel_rule_probe_failed"),
                       QStringLiteral("could not inspect policy rules safely"));
    }
    // IPv4 and IPv6 policy rules live in separate namespaces.  Every family
    // must be checked independently: a foreign rule in one family cannot be
    // hidden by an owned rule at the same numeric priority in the other.
    const auto hasForeign = [](const QSet<int> &occupied,
                               const QSet<int> &owned, int priority) {
        return occupied.contains(priority) && !owned.contains(priority);
    };
    if (hasForeign(ruleSnapshot.occupiedV4, ruleSnapshot.ownedFullV4,
                   m_fullRulePriority)
        || hasForeign(ruleSnapshot.occupiedV6, ruleSnapshot.ownedFullV6,
                      m_fullRulePriority)
        || hasForeign(ruleSnapshot.occupiedV4, ruleSnapshot.ownedBypassV4,
                      m_bypassRulePriority)) {
        return failure(QStringLiteral("full_tunnel_rule_conflict"),
                       QStringLiteral("a persisted full-tunnel priority is occupied by a foreign rule"));
    }
    const bool hadFullTunnel = m_mode == QStringLiteral("all-except");
    QSet<QString> allowedBypassRoutes;
    if (hadFullTunnel) {
        for (const QString &route : m_bypassRoutes) allowedBypassRoutes.insert(route);
    }
    const auto validateReservedRules = [this, &allowedBypassRoutes](
            const QStringList &lines, bool ipv6) {
        QSet<QString> seenBypassRoutes;
        QSet<int> seenFullPriorities;
        for (const QString &line : lines) {
            const QRegularExpressionMatch priorityMatch =
                    QRegularExpression(QStringLiteral("^\\s*(\\d+):")).match(line);
            if (!priorityMatch.hasMatch()) continue;
            const int priority = priorityMatch.captured(1).toInt();
            if (priority != m_bypassRulePriority && priority != m_fullRulePriority) continue;
            int parsedPriority = 0;
            ManagedRuleKind kind = ManagedRuleKind::None;
            QString destination;
            if (!parseManagedRuleLine(line, &parsedPriority, &kind, &destination)
                || parsedPriority != priority) {
                return false;
            }
            if (priority == m_fullRulePriority) {
                if (kind != ManagedRuleKind::FullTunnel
                    || seenFullPriorities.contains(priority)) return false;
                seenFullPriorities.insert(priority);
            } else {
                if (ipv6 || kind != ManagedRuleKind::Bypass
                    || !allowedBypassRoutes.contains(destination)
                    || seenBypassRoutes.contains(destination)) return false;
                seenBypassRoutes.insert(destination);
            }
        }
        return true;
    };
    if (!validateReservedRules(ruleSnapshot.linesV4, false)
        || !validateReservedRules(ruleSnapshot.linesV6, true)) {
        return failure(QStringLiteral("full_tunnel_rule_conflict"),
                       QStringLiteral("a reserved policy-rule priority contains an extra or unparseable rule"));
    }
    if (!hadFullTunnel
        && (ruleSnapshot.occupiedV4.contains(m_bypassRulePriority)
            || ruleSnapshot.occupiedV4.contains(m_fullRulePriority)
            || ruleSnapshot.occupiedV6.contains(m_fullRulePriority))) {
        return failure(QStringLiteral("full_tunnel_rule_conflict"),
                       QStringLiteral("a persisted full-tunnel priority is occupied by a foreign rule"));
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
    const QSet<QString> completeFullTunnelPrefixes {
        QStringLiteral("0.0.0.0/1"), QStringLiteral("128.0.0.0/1"),
        QStringLiteral("::/1"), QStringLiteral("8000::/1") };
    const bool exactPreviousInterfaceTable = hadFullTunnel
        && !previousInterface.isEmpty()
        && markedInterface == previousInterface
        && tableRoutes == completeFullTunnelPrefixes;
    // During a legitimate reconnect the target interface can change.  The
    // kernel marker must still match the persisted owner; accepting a marked
    // table whose owner differs from the receipt would take over foreign
    // routes, while rejecting a receipt-owned old interface traps safe
    // interface migration.  The route transaction below replaces the exact
    // prefixes and restores the previous subset if any step fails.
    if (!markedInterface.isEmpty()
        && (!hadFullTunnel || previousInterface.isEmpty()
            || (markedInterface != previousInterface && !exactPreviousInterfaceTable))) {
        return failure(QStringLiteral("full_tunnel_ownership_ambiguous"),
                       QStringLiteral("kernel full-tunnel table does not match the persisted interface receipt"));
    }
    if (hadFullTunnel && previousInterface != interfaceName
        && !exactPreviousInterfaceTable) {
        return failure(QStringLiteral("full_tunnel_ownership_ambiguous"),
                       QStringLiteral("interface migration requires an exact persisted full-tunnel route identity"));
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
                    const int devIndex = restore.indexOf(QStringLiteral("dev"));
                    const int interfaceIndex = devIndex + 1;
                    if (devIndex < 0 || interfaceIndex >= restore.size()) {
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
                const QString prefix = fullRoutePrefix(route);
                if (!tableRoutes.contains(prefix)) {
                    QStringList deletion = route;
                    deletion.replace(deletion.indexOf(QStringLiteral("replace")), QStringLiteral("del"));
                    ok = removeFullTunnelRoute(deletion) && ok;
                    continue;
                }
                QStringList restore = route;
                const int devIndex = restore.indexOf(QStringLiteral("dev"));
                if (devIndex < 0 || devIndex + 1 >= restore.size()) {
                    ok = false;
                    continue;
                }
                restore.replace(devIndex + 1, previousInterface);
                ok = addFullTunnelRoute(restore) && ok;
            }
        }
        return ok;
    };

    for (const QString &route : bypassRoutes) {
        if (ruleSnapshot.occupiedV4.contains(bypassPriority)) {
            const bool exactOwned = std::any_of(ruleSnapshot.linesV4.cbegin(), ruleSnapshot.linesV4.cend(),
                                                [bypassPriority, &route](const QString &line) {
                return ruleLineMatches(line, bypassPriority,
                                       QStringLiteral("to %1 ").arg(route));
            });
            const bool ambiguous = std::any_of(ruleSnapshot.linesV4.cbegin(), ruleSnapshot.linesV4.cend(),
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
        for (const QString &line : ruleSnapshot.linesV4) {
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
            for (const QString &line : ruleSnapshot.linesV4) {
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
    QSet<QString> seenFullTunnelPrefixes;
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
        const QString prefix = line.trimmed().split(
                QRegularExpression(QStringLiteral("\\s+")), Qt::SkipEmptyParts).value(0);
        if (seenFullTunnelPrefixes.contains(prefix)) {
            return failure(QStringLiteral("full_tunnel_ownership_ambiguous"),
                           QStringLiteral("route table 51821 contains duplicate managed prefixes"));
        }
        seenFullTunnelPrefixes.insert(prefix);
    }
    // A route marker alone does not prove that policy rules at the persisted
    // priorities belong to this daemon.  Refuse to delete or take over a
    // same-priority foreign rule; only an exact protocol-marked rule is ours.
    const auto foreignAt = [](const QSet<int> &occupied,
                              const QSet<int> &owned, int priority) {
        return occupied.contains(priority) && !owned.contains(priority);
    };
    if (foreignAt(snapshot.occupiedV4, snapshot.ownedFullV4, m_fullRulePriority)
        || foreignAt(snapshot.occupiedV6, snapshot.ownedFullV6, m_fullRulePriority)
        || foreignAt(snapshot.occupiedV4, snapshot.ownedBypassV4, m_bypassRulePriority)
        || foreignAt(snapshot.occupiedV6, snapshot.ownedBypassV6, m_bypassRulePriority)) {
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
        for (const QString &line : snapshot.linesV4) {
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
    const auto observedTablePrefix = [&snapshot](const QString &prefix) {
        const QRegularExpression pattern(QStringLiteral("^\\s*%1\\s+dev\\s+\\S+\\s+proto\\s+%2(?:\\s|$)")
                                                  .arg(QRegularExpression::escape(prefix))
                                                  .arg(AmneziaRouteProtocol));
        return std::any_of(snapshot.tableLines.cbegin(), snapshot.tableLines.cend(),
                           [&pattern](const QString &line) { return pattern.match(line).hasMatch(); });
    };
    bool tableRemoved = true;
    if (observedTablePrefix(QStringLiteral("0.0.0.0/1"))) {
        tableRemoved = removeFullTunnelRoute(v4Route) && tableRemoved;
    }
    if (observedTablePrefix(QStringLiteral("128.0.0.0/1"))) {
        tableRemoved = removeFullTunnelRoute(v4RouteUpper) && tableRemoved;
    }
    if (observedTablePrefix(QStringLiteral("::/1"))) {
        tableRemoved = removeFullTunnelRoute(v6Route) && tableRemoved;
    }
    if (observedTablePrefix(QStringLiteral("8000::/1"))) {
        tableRemoved = removeFullTunnelRoute(v6RouteUpper) && tableRemoved;
    }
    if (!tableRemoved) {
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
    if (!m_initialized || !m_stateValid || m_mode == QStringLiteral("recovery_required")) {
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
    const auto routeLock = acquireRouteLock(m_statePath);
    if (!m_statePath.isEmpty() && !routeLock) {
        return failure(QStringLiteral("route_mutation_in_progress"),
                       QStringLiteral("another routing transaction owns the managed route lock"));
    }
    if (!beginMutation(QStringLiteral("dns-configure"), interfaceName, {}, {})) {
        return failure(QStringLiteral("recovery_required"),
                       QStringLiteral("DNS mutation intent could not be persisted"));
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
        return finishTransaction(failure(QStringLiteral("dns_configure_failed"),
                                         QStringLiteral("failed to assign the VPN DNS server")));
    }

    QStringList domainArguments { QStringLiteral("domain"), interfaceName };
    domainArguments.append(dnsDomains);
    const CommandResult domainResult = m_runner->run(executable, domainArguments);
    if (!domainResult.ok) {
        if (!restorePreviousDns()) {
            markRecoveryRequired(QStringLiteral("DNS domain rollback failed"));
            return finishTransaction(failure(QStringLiteral("recovery_required"),
                                             QStringLiteral("DNS configuration failed and the previous resolver binding could not be restored")));
        }
        return finishTransaction(failure(QStringLiteral("dns_configure_failed"),
                                         QStringLiteral("failed to assign the VPN DNS routing domain")));
    }
    if (!previousInterface.isEmpty() && previousInterface != interfaceName
        && !m_runner->run(executable,
                          { QStringLiteral("revert"), previousInterface }).ok) {
        if (!restorePreviousDns()) {
            markRecoveryRequired(QStringLiteral("DNS interface transition rollback failed"));
            return finishTransaction(failure(QStringLiteral("recovery_required"),
                                             QStringLiteral("DNS interface transition failed and the previous resolver binding could not be restored")));
        }
        return finishTransaction(failure(QStringLiteral("dns_configure_failed"),
                                         QStringLiteral("the previous VPN DNS interface could not be retired")));
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
        return finishTransaction(failure(QStringLiteral("recovery_required"),
                                         QStringLiteral("VPN DNS was applied but its durable receipt could not be saved")));
    }
    if (!finishMutation()) {
        const bool persisted = markRecoveryRequired(
                QStringLiteral("DNS mutation intent could not be retired"));
        return failure(QStringLiteral("recovery_required"), persisted
                           ? QStringLiteral("DNS was committed but its mutation intent remains")
                           : QStringLiteral("DNS commit and recovery receipt both failed"));
    }
    return { true, {}, {} };
}

RouteReconcileResult LinuxRouteReconciler::clearDns(const QString &interfaceName)
{
    if (!m_initialized || !m_stateValid) {
        return failure(QStringLiteral("recovery_required"),
                       QStringLiteral("managed route state is invalid; refusing DNS cleanup mutation"));
    }
    if (!m_initialized || !m_stateValid || m_mode == QStringLiteral("recovery_required")) {
        return failure(QStringLiteral("recovery_required"),
                       QStringLiteral("managed DNS state is invalid; refusing to mutate resolver state"));
    }
    // An empty argument means "the persisted DNS owner".  This is needed for
    // restoring a no-DNS snapshot after a failed refresh; rejecting the empty
    // form would strand the newly configured resolver binding.
    const QString targetInterface = interfaceName.trimmed().isEmpty()
            ? m_dnsInterface : interfaceName.trimmed();
    if (!m_dnsInterface.isEmpty() && targetInterface != m_dnsInterface) {
        return failure(QStringLiteral("dns_interface_mismatch"),
                       QStringLiteral("DNS cleanup interface does not match the persisted receipt"));
    }
    const auto routeLock = acquireRouteLock(m_statePath);
    if (!m_statePath.isEmpty() && !routeLock) {
        return failure(QStringLiteral("route_mutation_in_progress"),
                       QStringLiteral("another routing transaction owns the managed route lock"));
    }
    if (targetInterface.isEmpty()) {
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
    if (!beginMutation(QStringLiteral("dns-clear"), targetInterface, {}, {})) {
        return failure(QStringLiteral("recovery_required"),
                       QStringLiteral("DNS cleanup intent could not be persisted"));
    }
    const CommandResult result = m_runner->run(
            executable, { QStringLiteral("revert"), targetInterface });
    if (!result.ok) {
        return finishTransaction(failure(QStringLiteral("dns_clear_failed"),
                                         QStringLiteral("failed to clear the VPN DNS configuration")));
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
        return finishTransaction(failure(QStringLiteral("recovery_required"),
                                         QStringLiteral("VPN DNS receipt could not be cleared")));
    }
    if (!finishMutation()) {
        const bool persisted = markRecoveryRequired(
                QStringLiteral("DNS cleanup intent could not be retired"));
        return failure(QStringLiteral("recovery_required"), persisted
                           ? QStringLiteral("DNS cleanup committed but cleanup intent remains")
                           : QStringLiteral("DNS cleanup and recovery receipt both failed"));
    }
    return { true, {}, {} };
}

RouteReconcileResult LinuxRouteReconciler::clear()
{
    m_lastError.clear();
    if (!m_initialized || !m_stateValid) {
        return failure(QStringLiteral("recovery_required"),
                       QStringLiteral("managed route state is invalid; manual route recovery is required"));
    }
    const auto routeLock = acquireRouteLock(m_statePath);
    if (!m_statePath.isEmpty() && !routeLock) {
        return failure(QStringLiteral("route_mutation_in_progress"),
                       QStringLiteral("another routing transaction owns the managed route lock"));
    }
    if (m_mode == QStringLiteral("all-except")) {
        if (!beginMutation(QStringLiteral("all-except-clear"), m_interfaceName,
                           {}, m_bypassRoutes)) {
            return failure(QStringLiteral("recovery_required"),
                           QStringLiteral("full-tunnel cleanup intent could not be persisted"));
        }
        const RouteReconcileResult result = clearFullTunnel();
        if (!result.ok) return finishTransaction(result);
        if (!finishMutation()) {
            const bool persisted = markRecoveryRequired(
                    QStringLiteral("full-tunnel cleanup intent could not be retired"));
            return failure(QStringLiteral("recovery_required"), persisted
                               ? QStringLiteral("full-tunnel cleanup committed but intent remains")
                               : QStringLiteral("full-tunnel cleanup and recovery receipt both failed"));
        }
        return result;
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
    if (!beginMutation(QStringLiteral("only-forward-clear"), m_interfaceName,
                       m_routes, {})) {
        return failure(QStringLiteral("recovery_required"),
                       QStringLiteral("route cleanup intent could not be persisted"));
    }
    const QString previousInterface = m_interfaceName;
    const QStringList previousRoutes = m_routes;
    const QString previousMode = m_mode;
    const QStringList previousBypassRoutes = m_bypassRoutes;
    QStringList removedRoutes;
    QString failedRoute;
    if (!removeRoutes(previousInterface, previousRoutes, &failedRoute, &removedRoutes)) {
        if (!restoreRoutes(previousInterface, removedRoutes)) {
            markRecoveryRequired(QStringLiteral("managed route cleanup rollback failed"));
            return failure(QStringLiteral("recovery_required"),
                           QStringLiteral("managed route cleanup failed and removed routes could not be restored"));
        }
        return finishTransaction(failure(QStringLiteral("route_remove_failed"),
                                         QStringLiteral("failed to clear a managed route")));
    }
    m_interfaceName.clear();
    m_routes.clear();
    m_mode = QStringLiteral("only-forward");
    m_bypassRoutes.clear();
    if (!saveState()) {
        const bool restored = restoreRoutes(previousInterface, previousRoutes);
        m_interfaceName = previousInterface;
        m_routes = previousRoutes;
        m_mode = previousMode;
        m_bypassRoutes = previousBypassRoutes;
        markRecoveryRequired(restored
                                 ? QStringLiteral("managed route cleanup state save failed after host rollback")
                                 : QStringLiteral("managed route cleanup state save and host rollback failed"));
        return failure(QStringLiteral("recovery_required"),
                       QStringLiteral("managed route state could not be cleared"));
    }
    if (!finishMutation()) {
        const bool persisted = markRecoveryRequired(
                QStringLiteral("route cleanup intent could not be retired"));
        return failure(QStringLiteral("recovery_required"), persisted
                           ? QStringLiteral("route cleanup committed but intent remains")
                           : QStringLiteral("route cleanup and recovery receipt both failed"));
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
        { QStringLiteral("recoveryRequired"), !m_initialized || !m_stateValid
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
    const bool saved = saveState();
    const QString markerPath = m_statePath.isEmpty() ? QString() : m_statePath + QStringLiteral(".recovery-required");
    if (saved) {
        if (!markerPath.isEmpty()) QFile::remove(markerPath);
        return true;
    }
    // Keep an independent, tiny marker when the JSON receipt cannot be
    // replaced. On the next start this marker is enough to keep the daemon
    // fail-closed instead of trusting an older receipt.
    if (markerPath.isEmpty()) return false;
    QSaveFile marker(markerPath);
    if (!marker.open(QIODevice::WriteOnly)
        || marker.write(message.toUtf8()) < 0
        || !marker.commit()) {
        return false;
    }
    QFile::setPermissions(markerPath, QFileDevice::ReadOwner | QFileDevice::WriteOwner);
    return true;
}

bool LinuxRouteReconciler::requireRecovery(const QString &message)
{
    return markRecoveryRequired(message);
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
    // A clean-looking receipt is not enough to prove that the host is clean.
    // Without `ip` there is no safe way to inspect or reconcile kernel state,
    // including when this instance has no durable receipt yet.
    if (ipExecutable().isEmpty()) {
        return false;
    }
    const auto resolverProbeHealthy = [this]() {
        const QString resolver = resolvectlExecutable();
        if (resolver.isEmpty()) return false;
        return m_runner->runCaptured(resolver, { QStringLiteral("status") }).ok;
    };
    const auto resolverRequired = [this]() {
        return !m_dnsInterface.isEmpty() || !m_dnsServers.isEmpty()
            || !m_dnsDomains.isEmpty();
    };
    if (m_statePath.isEmpty()) {
        return true;
    }
    const QFileInfo stateInfo(m_statePath);
    if (QFileInfo::exists(m_statePath + QStringLiteral(".recovery-required"))) {
        return false;
    }
    if (!m_intentPath.isEmpty() && QFileInfo::exists(m_intentPath)) {
        // A durable intent is written before the first kernel/resolver
        // mutation.  Its presence means the previous process may have died in
        // the transaction window; do not infer ownership or mutate anything
        // until an operator performs recovery.
        return false;
    }
    // Older builds used a shorter sidecar suffix.  Never delete it silently:
    // an orphaned legacy intent still means the previous host mutation may
    // have completed after its receipt write and requires operator recovery.
    if (!m_statePath.isEmpty()
        && (QFileInfo::exists(m_statePath + QStringLiteral(".intent"))
            || QFileInfo::exists(m_statePath + QStringLiteral(".transaction-intent")))) {
        return false;
    }
    if (!stateInfo.exists()) {
        // A missing receipt is not proof that the kernel is clean. Probe the
        // owned table/rules before allowing a fresh daemon to mutate routes;
        // a crash between kernel mutation and receipt commit must fail closed.
        // There is no safe way to prove that the kernel is clean without the
        // probe tool.  A missing receipt must therefore fail closed instead of
        // treating an unavailable `ip` as an empty routing table.
        const RuleSnapshot snapshot = readRuleSnapshot();
        if (!snapshot.valid) return false;
        const auto hasReservedRule = [](const QStringList &lines) {
            for (const QString &line : lines) {
                const QRegularExpressionMatch match =
                        QRegularExpression(QStringLiteral("^\\s*(\\d+):")).match(line);
                if (!match.hasMatch()) continue;
                const int priority = match.captured(1).toInt();
                if (priority == FullTunnelBypassRulePriority
                    || priority == FullTunnelRulePriority) return true;
            }
            return false;
        };
        if (!snapshot.tableLines.isEmpty()
            || !snapshot.ownedFull.isEmpty()
            || !snapshot.ownedBypass.isEmpty()
            || hasReservedRule(snapshot.linesV4)
            || hasReservedRule(snapshot.linesV6)) {
            return false;
        }
        for (const QString &line : snapshot.mainRouteLines) {
            QString prefix;
            QString interfaceName;
            if (parseManagedMainRouteLine(line, &prefix, &interfaceName)) {
                return false;
            }
        }
        // Do not infer ownership from resolver text or an interface-name
        // regex.  With no DNS receipt or mutation intent there is no durable
        // identity tying a custom link's resolver state to this daemon.
        // There is no persisted DNS owner in the missing-receipt case.  The
        // daemon's profile-aware startup gate is responsible for checking
        // configured/custom interfaces when a profile declares DNS.
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
    // A receipt is not the only startup evidence.  If a previous crash left
    // policy objects in the reserved namespace while the persisted mode says
    // only-forward, do not let the daemon listen and later overwrite them.
    // Conversely, a foreign/ambiguous object in the reserved table or rule
    // priorities must never be treated as an orphan owned by this process.
    // A valid receipt with an empty route set is not proof that the kernel is
    // clean: reserved full-tunnel objects may have survived a crash while the
    // JSON receipt was truncated.  Always probe the kernel on startup, and
    // fail closed if the probe executable is unavailable.
    if (ipExecutable().isEmpty()) {
        return false;
    }
    {
        RuleSnapshot snapshot = readRuleSnapshot();
        if (!snapshot.valid) return false;
        // 5.0.1.11 wrote v2 receipts but did not attach a route protocol
        // marker.  Permit exactly one migration shape: all four split-default
        // routes, one interface matching the old receipt, no `proto` token,
        // and only direct-route attributes that can be replayed verbatim. Any
        // partial/ambiguous table remains a manual-recovery condition.
        if (mode == QStringLiteral("all-except") && snapshot.tableLines.size() == 4) {
            const QSet<QString> expectedLegacyPrefixes {
                    QStringLiteral("0.0.0.0/1"), QStringLiteral("128.0.0.0/1"),
                    QStringLiteral("::/1"), QStringLiteral("8000::/1") };
            QSet<QString> legacyPrefixes;
            bool legacyExact = true;
            for (const QString &line : snapshot.tableLines) {
                const QStringList tokens = line.trimmed().split(
                        QRegularExpression(QStringLiteral("\\s+")), Qt::SkipEmptyParts);
                const QString prefix = tokens.value(0);
                if (!expectedLegacyPrefixes.contains(prefix)
                    || legacyRouteArguments(line, QStringLiteral("replace"),
                                             interfaceName, false).isEmpty()) {
                    legacyExact = false;
                    break;
                }
                legacyPrefixes.insert(prefix);
            }
            if (legacyExact && legacyPrefixes.size() == 4) {
                const QStringList originalLegacyLines = snapshot.tableLines;
                const auto routeLock = acquireRouteLock(m_statePath);
                if (!m_statePath.isEmpty() && !routeLock) return false;
                const QString executable = ipExecutable();
                const QStringList prefixes {
                    QStringLiteral("0.0.0.0/1"), QStringLiteral("128.0.0.0/1"),
                    QStringLiteral("::/1"), QStringLiteral("8000::/1") };
                if (!saveTransactionIntent(QStringLiteral("legacy-proto-migration"), QJsonObject {
                        { QStringLiteral("interface"), interfaceName },
                        { QStringLiteral("prefixes"), QJsonArray::fromStringList(prefixes) },
                        { QStringLiteral("fromProtocol"), 0 },
                        { QStringLiteral("toProtocol"), AmneziaRouteProtocol },
                    })) {
                    return false;
                }
                const auto restoreLegacy = [&]() {
                    bool restored = true;
                    for (const QString &line : originalLegacyLines) {
                        const QStringList command = legacyRouteArguments(
                                line, QStringLiteral("replace"), interfaceName, false);
                        restored = !command.isEmpty()
                                && m_runner->run(executable, command).ok && restored;
                    }
                    RuleSnapshot restoredSnapshot = readRuleSnapshot();
                    QStringList expected;
                    for (const QString &line : originalLegacyLines) {
                        expected.append(routeTokensWithoutMarkers(line).join(QLatin1Char(' ')));
                    }
                    QStringList actual;
                    if (restoredSnapshot.valid) {
                        for (const QString &line : restoredSnapshot.tableLines) {
                            actual.append(routeTokensWithoutMarkers(line).join(QLatin1Char(' ')));
                        }
                    } else {
                        restored = false;
                    }
                    std::sort(expected.begin(), expected.end());
                    std::sort(actual.begin(), actual.end());
                    return restored && expected == actual;
                };
                bool migrated = true;
                for (const QString &prefix : prefixes) {
                    const auto lineIt = std::find_if(snapshot.tableLines.cbegin(),
                                                     snapshot.tableLines.cend(),
                                                     [&prefix](const QString &line) {
                        return line.trimmed().startsWith(prefix + QStringLiteral(" "));
                    });
                    if (lineIt == snapshot.tableLines.cend()) {
                        migrated = false;
                        break;
                    }
                    const QStringList command = legacyRouteArguments(
                            *lineIt, QStringLiteral("replace"), interfaceName, true);
                    if (command.isEmpty() || !m_runner->run(executable, command).ok) {
                        migrated = false;
                        break;
                    }
                }
                if (migrated) {
                    snapshot = readRuleSnapshot();
                    migrated = snapshot.valid && snapshot.tableLines.size() == 4;
                    QSet<QString> migratedPrefixes;
                    for (const QString &line : snapshot.tableLines) {
                        const QStringList tokens = line.trimmed().split(
                                QRegularExpression(QStringLiteral("\\s+")), Qt::SkipEmptyParts);
                        migrated = migrated && tokens.size() >= 5
                                && tokens.at(1) == QStringLiteral("dev")
                                && tokens.at(2) == interfaceName
                                && tokens.contains(QStringLiteral("proto"))
                                && tokens.value(tokens.indexOf(QStringLiteral("proto")) + 1)
                                    == QString::number(AmneziaRouteProtocol);
                        if (!tokens.isEmpty()) migratedPrefixes.insert(tokens.constFirst());
                    }
                    const QSet<QString> expectedPrefixes {
                            QStringLiteral("0.0.0.0/1"), QStringLiteral("128.0.0.0/1"),
                            QStringLiteral("::/1"), QStringLiteral("8000::/1") };
                    migrated = migrated && migratedPrefixes == expectedPrefixes;
                    if (migrated) {
                        QStringList expected;
                        for (const QString &line : originalLegacyLines) {
                            expected.append(routeTokensWithoutMarkers(line).join(QLatin1Char(' ')));
                        }
                        QStringList actual;
                        for (const QString &line : snapshot.tableLines) {
                            actual.append(routeTokensWithoutMarkers(line).join(QLatin1Char(' ')));
                        }
                        std::sort(expected.begin(), expected.end());
                        std::sort(actual.begin(), actual.end());
                        migrated = expected == actual;
                    }
                }
                if (!migrated) {
                    const bool restored = restoreLegacy();
                    if (!restored) {
                        markRecoveryRequired(QStringLiteral("legacy route protocol migration rollback failed"));
                    }
                    return false;
                }
                if (!clearTransactionIntent()) {
                    markRecoveryRequired(QStringLiteral("legacy route protocol migration intent could not be retired"));
                    return false;
                }
            }
        }
        if (mode == QStringLiteral("only-forward")
            && (!snapshot.tableLines.isEmpty()
                || !snapshot.occupiedV4.isEmpty() &&
                    (snapshot.occupiedV4.contains(storedBypassPriority)
                     || snapshot.occupiedV4.contains(storedFullPriority))
                || !snapshot.occupiedV6.isEmpty() &&
                    (snapshot.occupiedV6.contains(storedBypassPriority)
                     || snapshot.occupiedV6.contains(storedFullPriority)))) {
            return false;
        }
        if (mode == QStringLiteral("only-forward")) {
            for (const QString &line : snapshot.mainRouteLines) {
                QString prefix;
                QString routeInterface;
                if (parseManagedMainRouteLine(line, &prefix, &routeInterface)
                    && (!routes.contains(prefix) || routeInterface != interfaceName)) {
                    return false;
                }
            }
        }
        if (mode == QStringLiteral("only-forward")) {
            for (const QString &line : snapshot.mainRouteLines) {
                QString prefix;
                QString routeInterface;
                if (!parseManagedMainRouteLine(line, &prefix, &routeInterface)) continue;
                if (!bounded.contains(prefix)
                    || routeInterface != interfaceName) {
                    return false;
                }
            }
            for (const QString &route : bounded) {
                if (!std::any_of(snapshot.mainRouteLines.cbegin(), snapshot.mainRouteLines.cend(),
                                 [&route, &interfaceName](const QString &line) {
                    return managedMainRouteLineMatches(line, route, interfaceName);
                })) {
                    return false;
                }
            }
        }
        if (mode == QStringLiteral("all-except")) {
            const QRegularExpression ownedTableRoute(
                    QStringLiteral("^\\s*(0\\.0\\.0\\.0/1|128\\.0\\.0\\.0/1|::/1|8000::/1)\\s+dev\\s+%1\\s+proto\\s+%2(?:\\s|$)")
                        .arg(QRegularExpression::escape(interfaceName))
                        .arg(AmneziaRouteProtocol));
            QSet<QString> tablePrefixes;
            for (const QString &line : snapshot.tableLines) {
                if (!ownedTableRoute.match(line).hasMatch()) return false;
                const QString prefix = line.trimmed().split(
                        QRegularExpression(QStringLiteral("\\s+")), Qt::SkipEmptyParts).value(0);
                if (tablePrefixes.contains(prefix)) return false;
                tablePrefixes.insert(prefix);
            }
            if (snapshot.tableLines.size() != 4
                || !snapshot.ownedFullV4.contains(storedFullPriority)
                || !snapshot.ownedFullV6.contains(storedFullPriority)) {
                return false;
            }
            const auto validReservedRules = [this, storedBypassPriority, storedFullPriority](
                    const QStringList &lines, bool ipv6, bool requireBypassRoutes) {
                QSet<QString> bypasses;
                int fullRules = 0;
                for (const QString &line : lines) {
                    const QRegularExpressionMatch priorityMatch =
                            QRegularExpression(QStringLiteral("^\\s*(\\d+):")).match(line);
                    if (!priorityMatch.hasMatch()) continue;
                    const int priority = priorityMatch.captured(1).toInt();
                    if (priority != storedBypassPriority && priority != storedFullPriority) continue;
                    int parsedPriority = 0;
                    ManagedRuleKind kind = ManagedRuleKind::None;
                    QString destination;
                    if (!parseManagedRuleLine(line, &parsedPriority, &kind, &destination)
                        || parsedPriority != priority) return false;
                    if (priority == storedFullPriority) {
                        if (kind != ManagedRuleKind::FullTunnel || ++fullRules > 1) return false;
                    } else {
                        if (ipv6 || kind != ManagedRuleKind::Bypass
                            || !m_bypassRoutes.contains(destination)
                            || bypasses.contains(destination)) return false;
                        bypasses.insert(destination);
                    }
                }
                if (fullRules != 1) return false;
                if (requireBypassRoutes) {
                    for (const QString &route : m_bypassRoutes) {
                        if (!bypasses.contains(route)) return false;
                    }
                }
                return true;
            };
            if (!validReservedRules(snapshot.linesV4, false, true)
                || !validReservedRules(snapshot.linesV6, true, false)) {
                return false;
            }
        }
    }
    // DNS bindings are independent from the route receipt.  A persisted DNS
    // owner requires a resolver probe because cleanup cannot be verified
    // without resolvectl.  Profile-aware startup separately checks configured
    // and custom interfaces for orphan DNS bindings.
    return !resolverRequired() || resolverProbeHealthy();
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
        const RuleSnapshot snapshot = readRuleSnapshot();
        if (!snapshot.valid) {
            if (failedRoute) *failedRoute = route;
            return false;
        }
        const QRegularExpression prefixPattern(
                QStringLiteral(R"(^\s*%1\s+)").arg(QRegularExpression::escape(route)));
        bool exact = false;
        bool ambiguous = false;
        for (const QString &line : snapshot.mainRouteLines) {
            if (!prefixPattern.match(line).hasMatch()) continue;
            if (managedMainRouteLineMatches(line, route, interfaceName)) {
                exact = true;
            } else {
                ambiguous = true;
            }
        }
        if (ambiguous) {
            if (failedRoute) *failedRoute = route;
            return false;
        }
        if (!exact) {
            continue;
        }
        const CommandResult result = m_runner->run(
                executable, { QStringLiteral("route"), QStringLiteral("del"), route,
                              QStringLiteral("dev"), interfaceName,
                              QStringLiteral("proto"), QString::number(AmneziaSplitRouteProtocol),
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
        const RuleSnapshot snapshot = readRuleSnapshot();
        if (!snapshot.valid) return false;
        const QRegularExpression prefixPattern(
                QStringLiteral(R"(^\s*%1\s+)").arg(QRegularExpression::escape(route)));
        for (const QString &line : snapshot.mainRouteLines) {
            if (prefixPattern.match(line).hasMatch()
                && !managedMainRouteLineMatches(line, route, interfaceName)) {
                return false;
            }
        }
        ok = m_runner->run(executable,
                           { QStringLiteral("route"), QStringLiteral("replace"), route,
                             QStringLiteral("dev"), interfaceName,
                             QStringLiteral("proto"), QString::number(AmneziaSplitRouteProtocol),
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
