#include "linuxRouteReconciler.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QHostAddress>
#include <QDebug>
#include <QRegularExpression>
#include <QSaveFile>
#include <QLockFile>
#include <QElapsedTimer>

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

// `ip rule show` is allowed to print a host selector either as an address or
// with its explicit host prefix.  Keep this parser deliberately narrower than
// a general route parser: only canonical host/network text is accepted, and
// host bits in a network selector are rejected.  This prevents a malformed or
// foreign extra rule from becoming an apparent owned bypass during readback.
QString canonicalRuleDestination(const QString &raw)
{
    const QString value = raw.trimmed();
    const QStringList parts = value.split(QLatin1Char('/'));
    if (parts.isEmpty() || parts.size() > 2 || parts.at(0).isEmpty()) return {};
    const QHostAddress address(parts.at(0));
    const auto protocol = address.protocol();
    if (protocol != QAbstractSocket::IPv4Protocol
        && protocol != QAbstractSocket::IPv6Protocol
        || address.toString() != parts.at(0)) return {};
    const int maximum = protocol == QAbstractSocket::IPv4Protocol ? 32 : 128;
    int prefix = maximum;
    if (parts.size() == 2) {
        bool ok = false;
        prefix = parts.at(1).toInt(&ok);
        if (!ok || prefix < 0 || prefix > maximum
            || QString::number(prefix) != parts.at(1)) return {};
    }
    if (prefix < maximum) {
        if (protocol == QAbstractSocket::IPv4Protocol) {
            const quint32 mask = prefix == 0 ? 0u : (0xffffffffu << (32 - prefix));
            if ((address.toIPv4Address() & mask) != address.toIPv4Address()) return {};
        } else {
            const Q_IPV6ADDR bytes = address.toIPv6Address();
            int remaining = prefix;
            for (int index = 0; index < 16; ++index) {
                const uchar byte = bytes.c[index];
                const int kept = std::min(remaining, 8);
                const uchar mask = kept == 0 ? 0 : static_cast<uchar>(0xffu << (8 - kept));
                if ((byte & mask) != byte) return {};
                remaining -= kept;
            }
        }
        return QStringLiteral("%1/%2").arg(address.toString()).arg(prefix);
    }
    return address.toString();
}

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
    // `ip rule show` emits `from all` for an explicitly supplied selector,
    // while older iproute2 versions omit it for the same destination rule.
    // Accept only that exact optional selector: source, fwmark, uid, table,
    // protocol and extra attributes must never be attributed to us.
    const auto bypass = QRegularExpression(
            QStringLiteral("^\\s*(\\d+):\\s+(?:(?:from\\s+all)\\s+)?to\\s+(\\S+)\\s+lookup\\s+main\\s*$"))
            .match(line);
    if (bypass.hasMatch()) {
        if (priority) *priority = bypass.captured(1).toInt();
        if (kind) *kind = ManagedRuleKind::Bypass;
        const QString canonical = canonicalRuleDestination(bypass.captured(2));
        if (canonical.isEmpty()) {
            if (kind) *kind = ManagedRuleKind::None;
            return false;
        }
        if (destination) *destination = canonical;
        return true;
    }
    if (kind) *kind = ManagedRuleKind::None;
    return false;
}

bool parseBroadMainRuleLine(const QString &line, int *priority)
{
    const QRegularExpressionMatch match = QRegularExpression(
            QStringLiteral("^\\s*(\\d+):\\s+from\\s+all\\s+lookup\\s+main\\s*$"))
            .match(line);
    if (!match.hasMatch()) return false;
    if (priority) *priority = match.captured(1).toInt();
    return true;
}

bool commandIndicatesMissingInterface(const CommandResult &result)
{
    if (result.ok || result.exitCode != 1) return false;
    const QString diagnostic = (result.message + QLatin1Char('\n') + result.output).toLower();
    return diagnostic.contains(QStringLiteral("cannot find device"))
        || diagnostic.contains(QStringLiteral("no such device"))
        || diagnostic.contains(QStringLiteral("does not exist"))
        || diagnostic.contains(QStringLiteral("not found"));
}

bool resolverOutputHasManagedBinding(const QString &output)
{
    // `resolvectl status <link>` reports these fields for a link-scoped
    // binding.  Empty/none scopes are deliberately treated as no binding;
    // unrelated global resolver output is not enough to claim ownership.
    for (const QString &rawLine : output.split(QLatin1Char('\n'))) {
        const QString line = rawLine.trimmed().toLower();
        if (line.startsWith(QStringLiteral("current scopes:"))) {
            const QString value = line.mid(QStringLiteral("current scopes:").size()).trimmed();
            if (!value.isEmpty() && value != QStringLiteral("none")) {
                return value.contains(QStringLiteral("dns"));
            }
        }
        if (line.startsWith(QStringLiteral("dns servers:"))
            || line.startsWith(QStringLiteral("dns domain:"))
            || line.startsWith(QStringLiteral("dns domains:"))) {
            const QString value = line.section(QLatin1Char(':'), 1).trimmed();
            if (!value.isEmpty() && value != QStringLiteral("-")
                && value != QStringLiteral("none")) {
                return true;
            }
        }
    }
    return false;
}

bool resolverOutputMatchesBinding(const QString &output,
                                  const QStringList &expectedServers,
                                  const QStringList &expectedDomains)
{
    QStringList servers;
    QStringList domains;
    for (const QString &rawLine : output.split(QLatin1Char('\n'))) {
        const QString line = rawLine.trimmed();
        const QString lower = line.toLower();
        QString value;
        if (lower.startsWith(QStringLiteral("dns servers:"))) {
            value = line.mid(QStringLiteral("DNS Servers:").size()).trimmed();
            servers.append(value.split(QRegularExpression(QStringLiteral("\\s+")),
                                       Qt::SkipEmptyParts));
        } else if (lower.startsWith(QStringLiteral("dns domain:"))) {
            value = line.mid(QStringLiteral("DNS Domain:").size()).trimmed();
            if (!value.isEmpty() && value != QStringLiteral("-")) domains.append(value);
        } else if (lower.startsWith(QStringLiteral("dns domains:"))) {
            value = line.mid(QStringLiteral("DNS Domains:").size()).trimmed();
            domains.append(value.split(QRegularExpression(QStringLiteral("\\s+")),
                                       Qt::SkipEmptyParts));
        }
    }
    return servers == expectedServers && domains == expectedDomains;
}

const QStringList &managedFullTunnelRoutePrefixes()
{
    static const QStringList prefixes {
        QStringLiteral("0.0.0.0/1"), QStringLiteral("128.0.0.0/1"),
        QStringLiteral("::/1"), QStringLiteral("8000::/1") };
    return prefixes;
}

// iproute2 renders protocol identifiers differently depending on the
// installed /etc/iproute2/rt_protos mapping.  Ownership must follow only the
// two semantic spellings that are permanently assigned to our markers:
// protocol 187 may be printed as `187` or `isis`, and protocol 186 may be
// printed as `186` or `bgp`.  Do not accept arbitrary names/numbers here:
// those are foreign or ambiguous kernel state and must remain untouched.
bool managedProtocolTokenMatches(int expectedProtocol, const QString &token)
{
    if (expectedProtocol == AmneziaSplitRouteProtocol) {
        return token == QStringLiteral("187") || token == QStringLiteral("isis");
    }
    if (expectedProtocol == AmneziaRouteProtocol) {
        return token == QStringLiteral("186") || token == QStringLiteral("bgp");
    }
    return false;
}

QString routeProtocolToken(const QString &line)
{
    const QStringList tokens = line.trimmed().split(QRegularExpression(QStringLiteral("\\s+")),
                                                     Qt::SkipEmptyParts);
    const int protocolIndex = tokens.indexOf(QStringLiteral("proto"));
    if (protocolIndex < 0 || protocolIndex + 1 >= tokens.size()) return {};
    // Protocol names are kernel metadata, not user input.  Keep the emitted
    // diagnostic deliberately short even if a hostile route probe returns a
    // pathological token.
    return tokens.at(protocolIndex + 1).left(32);
}

bool parseOwnedRouteLine(const QString &line, int expectedProtocol,
                         const QString &expectedInterface, QString *prefix,
                         QString *interfaceName, int expectedMetric = -1,
                         const QStringList &allowedPrefixes = {})
{
    const QStringList tokens = line.trimmed().split(QRegularExpression(QStringLiteral("\\s+")),
                                                     Qt::SkipEmptyParts);
    if (tokens.size() < 5 || tokens.at(1) != QStringLiteral("dev")) return false;
    const QString canonicalPrefix = canonicalRuleDestination(tokens.at(0));
    if (canonicalPrefix.isEmpty()) return false;
    if (!allowedPrefixes.isEmpty() && !allowedPrefixes.contains(canonicalPrefix)) return false;
    if (!expectedInterface.isEmpty() && tokens.at(2) != expectedInterface) return false;

    bool seenProtocol = false;
    bool seenMetric = false;
    bool seenScope = false;
    bool seenPreference = false;
    bool seenSource = false;
    int metric = -1;
    for (int index = 3; index < tokens.size();) {
        const QString &token = tokens.at(index);
        if (token == QStringLiteral("proto")) {
            if (seenProtocol || index + 1 >= tokens.size()
                || !managedProtocolTokenMatches(expectedProtocol, tokens.at(index + 1))) {
                return false;
            }
            seenProtocol = true;
            index += 2;
        } else if (token == QStringLiteral("metric")) {
            if (seenMetric || index + 1 >= tokens.size()
                || !QRegularExpression(QStringLiteral("^[0-9]+$")).match(tokens.at(index + 1)).hasMatch()) {
                return false;
            }
            if (expectedMetric >= 0
                && tokens.at(index + 1) != QString::number(expectedMetric)) return false;
            bool ok = false;
            metric = tokens.at(index + 1).toInt(&ok);
            if (!ok) return false;
            seenMetric = true;
            index += 2;
        } else if (token == QStringLiteral("scope")) {
            if (seenScope || index + 1 >= tokens.size()
                || (tokens.at(index + 1) != QStringLiteral("link")
                    && tokens.at(index + 1) != QStringLiteral("253"))) return false;
            seenScope = true;
            index += 2;
        } else if (token == QStringLiteral("pref")) {
            if (seenPreference || index + 1 >= tokens.size()
                || (tokens.at(index + 1) != QStringLiteral("low")
                    && tokens.at(index + 1) != QStringLiteral("medium")
                    && tokens.at(index + 1) != QStringLiteral("high"))) {
                return false;
            }
            seenPreference = true;
            index += 2;
        } else if (token == QStringLiteral("src")) {
            if (seenSource || index + 1 >= tokens.size()) return false;
            const QHostAddress source(tokens.at(index + 1));
            if (source.protocol() != QAbstractSocket::IPv4Protocol
                && source.protocol() != QAbstractSocket::IPv6Protocol) return false;
            seenSource = true;
            index += 2;
        } else {
            // Gateways, nexthops, tables, and future/unknown attributes are
            // route-changing or ambiguous and must not be attributed to us.
            return false;
        }
    }
    if (!seenProtocol || (expectedMetric >= 0 && (!seenMetric || metric != expectedMetric))) {
        return false;
    }
    // The kernel commonly renders a host route as `x.x.x.x/32`, while our
    // validated receipts intentionally use the shorter `x.x.x.x` spelling.
    // Compare and persist one canonical identity so cleanup cannot mistake a
    // receipt-owned route for a foreign collision (IPv6 /128 is normalized in
    // the same way).
    if (prefix) *prefix = canonicalPrefix;
    if (interfaceName) *interfaceName = tokens.at(2);
    return true;
}

bool parseManagedFullTunnelRouteLine(const QString &line,
                                     const QString &expectedInterface,
                                     QString *prefix = nullptr,
                                     QString *interfaceName = nullptr)
{
    return parseOwnedRouteLine(line, AmneziaRouteProtocol, expectedInterface,
                               prefix, interfaceName, -1,
                               managedFullTunnelRoutePrefixes());
}

bool parseManagedMainRouteLine(const QString &line, QString *prefix,
                               QString *interfaceName)
{
    // `ip -N route show` may insert scope/src/pref before or after proto and
    // metric.  The helper accepts only the bounded, non-route-changing
    // attributes emitted by the kernel and requires the split-route marker.
    return parseOwnedRouteLine(line, AmneziaSplitRouteProtocol, {}, prefix,
                               interfaceName, 1);
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

struct NumericMainRoute
{
    QString prefix;
    QString interfaceName;
    QString protocol;
    int metric = 0;
    bool isDefault = false;
    bool directlyConnected = false;
};

bool parseNumericMainRoute(const QString &line, NumericMainRoute *route)
{
    const QStringList tokens = line.trimmed().split(QRegularExpression(QStringLiteral("\\s+")),
                                                     Qt::SkipEmptyParts);
    if (tokens.size() < 3 || !route) return false;
    const bool defaultRoute = tokens.at(0) == QStringLiteral("default")
            || tokens.at(0) == QStringLiteral("0.0.0.0/0");
    QString prefix = defaultRoute ? QStringLiteral("0.0.0.0/0") : tokens.at(0);
    quint32 address = 0;
    int prefixLength = 0;
    if (!defaultRoute) {
        const QStringList prefixParts = prefix.split(QLatin1Char('/'));
        if (prefixParts.size() < 1 || prefixParts.size() > 2) return false;
        const QHostAddress host(prefixParts.at(0));
        if (host.protocol() != QAbstractSocket::IPv4Protocol
            || host.toString() != prefixParts.at(0)) return false;
        prefixLength = 32;
        if (prefixParts.size() == 2) {
            bool ok = false;
            prefixLength = prefixParts.at(1).toInt(&ok);
            if (!ok || prefixLength < 0 || prefixLength > 32
                || QString::number(prefixLength) != prefixParts.at(1)) return false;
        }
        address = host.toIPv4Address();
        const quint32 mask = prefixLength == 0 ? 0u : 0xffffffffu << (32 - prefixLength);
        if ((address & mask) != address) return false;
        prefix = prefixLength == 32 ? host.toString()
                                    : QStringLiteral("%1/%2").arg(host.toString()).arg(prefixLength);
    }
    const int devIndex = tokens.indexOf(QStringLiteral("dev"));
    if (devIndex < 0 || devIndex + 1 >= tokens.size()) return false;
    bool hasVia = tokens.contains(QStringLiteral("via"));
    int metric = 0;
    const int metricIndex = tokens.indexOf(QStringLiteral("metric"));
    if (metricIndex >= 0) {
        if (metricIndex + 1 >= tokens.size()) return false;
        bool ok = false;
        metric = tokens.at(metricIndex + 1).toInt(&ok);
        if (!ok || metric < 0) return false;
    }
    const int scopeIndex = tokens.indexOf(QStringLiteral("scope"));
    const int protoIndex = tokens.indexOf(QStringLiteral("proto"));
    QString protocol;
    if (protoIndex >= 0 && protoIndex + 1 < tokens.size()) {
        protocol = tokens.at(protoIndex + 1);
    }
    const bool scopeLink = scopeIndex >= 0 && scopeIndex + 1 < tokens.size()
            && (tokens.at(scopeIndex + 1) == QStringLiteral("link")
                || tokens.at(scopeIndex + 1) == QStringLiteral("253"));
    // `ip -N route show table main` renders the kernel protocol numerically
    // (`proto 2`), while non-numeric/readable output uses `proto kernel`.
    // No other protocol name or number is safe to treat as a directly
    // connected kernel route; reject those lines instead of silently
    // downgrading them to a non-critical candidate.
    const bool kernelProto = protoIndex >= 0 && protoIndex + 1 < tokens.size()
            && (tokens.at(protoIndex + 1) == QStringLiteral("kernel")
                || tokens.at(protoIndex + 1) == QStringLiteral("2"));
    if (!defaultRoute && !kernelProto && protocol != QStringLiteral("static")) {
        return false;
    }
    route->prefix = prefixLength == 32 ? QHostAddress(address).toString()
                                       : QStringLiteral("%1/%2")
                                             .arg(QHostAddress(address).toString())
                                             .arg(prefixLength);
    route->interfaceName = tokens.at(devIndex + 1);
    route->metric = metric;
    route->isDefault = defaultRoute;
    route->directlyConnected = !defaultRoute && !hasVia && scopeLink;
    route->protocol = protocol;
    return true;
}

bool privateOrLinkLocalPrefix(const QString &prefix)
{
    quint32 address = 0;
    int length = 32;
    if (!amnezia::managedRoutePolicy::parseCanonicalIpv4Route(prefix, &address, &length)) {
        return false;
    }
    const auto contained = [address, length](quint32 base, int baseLength) {
        return amnezia::managedRoutePolicy::ipv4RouteIsWithinRange(
                address, length, base, baseLength);
    };
    // Keep this list limited to private/CGNAT underlay space.  IPv4LL
    // (169.254/16) is not a supported reachability promise for this client.
    return contained(0x0a000000u, 8) || contained(0xac100000u, 12)
            || contained(0xc0a80000u, 16) || contained(0x64400000u, 10);
}

bool prefixOverlapsAny(const QString &prefix, const QStringList &routes)
{
    quint32 address = 0;
    int length = 32;
    if (!amnezia::managedRoutePolicy::parseCanonicalIpv4Route(prefix, &address, &length)) {
        return false;
    }
    for (const QString &candidate : routes) {
        quint32 candidateAddress = 0;
        int candidateLength = 32;
        if (amnezia::managedRoutePolicy::parseCanonicalIpv4Route(
                    candidate, &candidateAddress, &candidateLength)
            && amnezia::managedRoutePolicy::ipv4RouteOverlapsRange(
                    address, length, candidateAddress, candidateLength)) {
            return true;
        }
    }
    return false;
}

bool isVpnOrLoopbackInterface(const QString &interfaceName)
{
    const QString normalized = interfaceName.trimmed().toLower();
    if (normalized.isEmpty()) return true;
    if (normalized == QStringLiteral("lo")
        || normalized.startsWith(QStringLiteral("tun"))
        || normalized.startsWith(QStringLiteral("tap"))
        || normalized.startsWith(QStringLiteral("amn"))
        || normalized.startsWith(QStringLiteral("wg"))
        || normalized.startsWith(QStringLiteral("ppp"))
        || normalized.startsWith(QStringLiteral("vpn"))
        || normalized.startsWith(QStringLiteral("tailscale"))
        || normalized.startsWith(QStringLiteral("zt"))
        || normalized.startsWith(QStringLiteral("ipsec"))) {
        return true;
    }
    return false;
}

bool isContainerBridgeInterface(const QString &interfaceName)
{
    const QString normalized = interfaceName.trimmed().toLower();
    return normalized == QStringLiteral("docker0")
        || normalized.startsWith(QStringLiteral("br-"))
        || normalized.startsWith(QStringLiteral("virbr"))
        || normalized.startsWith(QStringLiteral("cni"))
        || normalized.startsWith(QStringLiteral("podman"));
}

bool isLikelyPhysicalInterface(const QString &interfaceName)
{
    const QString normalized = interfaceName.trimmed().toLower();
    return normalized.startsWith(QStringLiteral("eth"))
        || normalized.startsWith(QStringLiteral("en"))
        || normalized.startsWith(QStringLiteral("wl"))
        || normalized.startsWith(QStringLiteral("wlan"))
        || normalized.startsWith(QStringLiteral("em"))
        || normalized.startsWith(QStringLiteral("bond"));
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
        if (m_lastError.isEmpty()) {
            m_lastError = QStringLiteral(
                    "managed route state is invalid; refusing to mutate host routes");
        }
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
                                         const QStringList &bypassRoutes,
                                         const QStringList &dnsServers,
                                         const QStringList &dnsDomains,
                                         const QStringList &criticalBypassRoutes)
{
    QJsonObject target {
        { QStringLiteral("interface"), interfaceName },
        { QStringLiteral("routes"), QJsonArray::fromStringList(routes) },
        { QStringLiteral("bypassRoutes"), QJsonArray::fromStringList(bypassRoutes) },
    };
    if (!dnsServers.isEmpty() || !dnsDomains.isEmpty()) {
        target.insert(QStringLiteral("dnsServers"), QJsonArray::fromStringList(dnsServers));
        target.insert(QStringLiteral("dnsDomains"), QJsonArray::fromStringList(dnsDomains));
    }
    if (!criticalBypassRoutes.isEmpty()) {
        target.insert(QStringLiteral("criticalBypassRoutes"),
                      QJsonArray::fromStringList(criticalBypassRoutes));
    }
    return saveTransactionIntent(operation, target);
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
    m_fullTunnelDeadline.start();
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
    const QStringList previousCriticalBypassRoutes = m_criticalBypassRoutes;
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
        const QString canonicalRoute = canonicalRuleDestination(route);
        for (const QString &line : routeSnapshot.mainRouteLines) {
            QString parsedPrefix;
            QString parsedInterface;
            const bool parsed = parseManagedMainRouteLine(line, &parsedPrefix, &parsedInterface);
            const QString rawPrefix = line.trimmed().section(QLatin1Char(' '), 0, 0);
            const bool sameDestination = parsed ? parsedPrefix == canonicalRoute
                    : canonicalRuleDestination(rawPrefix) == canonicalRoute;
            if (!sameDestination) continue;
            const bool ownedByTarget = managedMainRouteLineMatches(line, route, interfaceName);
            const bool ownedByPrevious = !previousInterface.isEmpty()
                    && managedMainRouteLineMatches(line, route, previousInterface);
            if (!ownedByTarget && !ownedByPrevious) {
                const QString rejectedProtocol = routeProtocolToken(line);
                if (!rejectedProtocol.isEmpty()
                    && !managedProtocolTokenMatches(AmneziaSplitRouteProtocol,
                                                     rejectedProtocol)) {
                    m_lastDiagnostics = QJsonObject {
                        { QStringLiteral("rejectedProtocol"), rejectedProtocol },
                        { QStringLiteral("rejectedProtocolLine"), line.left(512) },
                        { QStringLiteral("expectedProtocol"), QStringLiteral("187 or isis") },
                    };
                }
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
            const RouteReconcileResult full = applyFullTunnel(
                    previousInterface, previousBypassRoutes, previousCriticalBypassRoutes);
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
    m_criticalBypassRoutes.clear();
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
            m_criticalBypassRoutes = previousCriticalBypassRoutes;
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

QStringList LinuxRouteReconciler::activeUnderlayProtectedRoutes(
        const QString &vpnInterface, const QStringList &forwardRoutes, QString *error) const
{
    if (error) error->clear();
    const RuleSnapshot snapshot = readRuleSnapshot();
    if (!snapshot.valid) {
        if (error) *error = QStringLiteral("could not inspect the numeric main-route snapshot");
        return {};
    }
    QString selectedPhysicalInterface;
    for (const QString &line : snapshot.mainRouteLines) {
        NumericMainRoute candidate;
        if (!parseNumericMainRoute(line, &candidate) || !candidate.isDefault
            || isVpnOrLoopbackInterface(candidate.interfaceName)
            || isContainerBridgeInterface(candidate.interfaceName)) continue;
        if (isLikelyPhysicalInterface(candidate.interfaceName)) {
            selectedPhysicalInterface = candidate.interfaceName;
            break;
        }
    }
    if (selectedPhysicalInterface.isEmpty()) {
        if (error) *error = QStringLiteral("could not identify the selected physical default interface");
        return {};
    }
    QStringList protectedRoutes;
    QSet<QString> seen;
    for (const QString &line : snapshot.mainRouteLines) {
        NumericMainRoute candidate;
        if (!parseNumericMainRoute(line, &candidate) || !candidate.directlyConnected
            || candidate.interfaceName == vpnInterface
            || isVpnOrLoopbackInterface(candidate.interfaceName)
            || !privateOrLinkLocalPrefix(candidate.prefix)
            || prefixOverlapsAny(candidate.prefix, forwardRoutes)
            || (!isContainerBridgeInterface(candidate.interfaceName)
                && candidate.interfaceName != selectedPhysicalInterface)
            || (candidate.protocol == QStringLiteral("static")
                && candidate.interfaceName != selectedPhysicalInterface)
            || seen.contains(candidate.prefix)) continue;
        seen.insert(candidate.prefix);
        protectedRoutes.append(candidate.prefix);
    }
    return protectedRoutes;
}

RouteReconcileResult LinuxRouteReconciler::applyAllExcept(
        const QString &interfaceName, const QStringList &bypassRoutes,
        const QStringList &criticalBypassRoutes)
{
    m_lastError.clear();
    m_fullTunnelDeadline.start();
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
    bool criticalValid = false;
    QStringList boundedCritical = amnezia::managedRoutePolicy::validatedManagedRoutes(
            criticalBypassRoutes, &criticalValid);
    if (!criticalValid || boundedCritical.size() != criticalBypassRoutes.size()
        || !std::all_of(boundedCritical.cbegin(), boundedCritical.cend(),
                        [&boundedRoutes](const QString &route) {
                            return boundedRoutes.contains(route);
                        })) {
        return failure(QStringLiteral("invalid_routes"),
                       QStringLiteral("critical full-tunnel bypass routes are invalid or not in the target set"));
    }
    const auto routeLock = acquireRouteLock(m_statePath);
    if (!m_statePath.isEmpty() && !routeLock) {
        return failure(QStringLiteral("route_mutation_in_progress"),
                       QStringLiteral("another routing transaction owns the managed route lock"));
    }
    if (!beginMutation(QStringLiteral("all-except"), interfaceName, {}, boundedRoutes,
                       {}, {}, boundedCritical)) {
        return failure(QStringLiteral("recovery_required"),
                       QStringLiteral("full-tunnel mutation intent could not be persisted"));
    }
    const RouteReconcileResult result = applyFullTunnel(
            interfaceName, boundedRoutes, boundedCritical);
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

bool LinuxRouteReconciler::addFullTunnelRule(const QStringList &arguments,
                                             QString *failureDetail)
{
    const QString executable = ipExecutable();
    if (executable.isEmpty()) {
        if (failureDetail) *failureDetail = QStringLiteral("ip executable unavailable");
        return false;
    }
    const CommandResult result = m_runner->run(executable, arguments);
    if (!result.ok && failureDetail) *failureDetail = result.message.left(512);
    return result.ok;
}

bool LinuxRouteReconciler::removeFullTunnelRule(const QStringList &arguments,
                                                QString *failureDetail)
{
    const QString executable = ipExecutable();
    if (executable.isEmpty()) {
        if (failureDetail) *failureDetail = QStringLiteral("ip executable unavailable");
        return false;
    }
    const CommandResult result = m_runner->run(executable, arguments);
    // Do not treat an arbitrary exit code 2 as "already absent": permission,
    // syntax and RTNETLINK failures can use the same code.  The caller's
    // ownership snapshot makes the operation idempotent, so an actual command
    // failure must remain visible and fail closed.
    if (result.ok) return true;
    if (result.exitCode != 2 || !arguments.contains(QStringLiteral("del"))) {
        if (failureDetail) *failureDetail = result.message.left(512);
        return false;
    }
    const RuleSnapshot snapshot = readRuleSnapshot();
    if (!snapshot.valid) {
        if (failureDetail) *failureDetail = QStringLiteral("%1; post-delete rule probe failed")
                .arg(result.message.left(384));
        return false;
    }
    const int priorityIndex = arguments.indexOf(QStringLiteral("priority"));
    if (priorityIndex < 0 || priorityIndex + 1 >= arguments.size()) {
        if (failureDetail) *failureDetail = result.message.left(512);
        return false;
    }
    bool priorityOk = false;
    const int priority = arguments.at(priorityIndex + 1).toInt(&priorityOk);
    if (!priorityOk) {
        if (failureDetail) *failureDetail = result.message.left(512);
        return false;
    }
    if (arguments.contains(QStringLiteral("to"))) {
        const int toIndex = arguments.indexOf(QStringLiteral("to"));
        if (toIndex + 1 >= arguments.size()) {
            if (failureDetail) *failureDetail = result.message.left(512);
            return false;
        }
        const bool absent = !std::any_of(snapshot.linesV4.cbegin(), snapshot.linesV4.cend(),
                            [priority, &arguments, toIndex](const QString &line) {
            return ruleLineMatches(line, priority,
                                   QStringLiteral("to %1 ").arg(arguments.at(toIndex + 1)));
        });
        if (!absent && failureDetail) *failureDetail = result.message.left(512);
        return absent;
    }
    const bool ipv6 = arguments.contains(QStringLiteral("-6"));
    const bool absent = !(ipv6 ? snapshot.ownedFullV6.contains(priority)
                               : snapshot.ownedFullV4.contains(priority));
    if (!absent && failureDetail) *failureDetail = result.message.left(512);
    return absent;
}

bool LinuxRouteReconciler::addFullTunnelRulesBatch(const QList<QStringList> &arguments,
                                                   QString *failureDetail)
{
    const QString executable = ipExecutable();
    if (executable.isEmpty()) {
        if (failureDetail) *failureDetail = QStringLiteral("ip executable unavailable");
        return false;
    }
    const int batchCount = (arguments.size() + FullTunnelRuleBatchSize - 1)
            / FullTunnelRuleBatchSize;
    int completed = 0;
    for (int offset = 0, batch = 0; offset < arguments.size();
         offset += FullTunnelRuleBatchSize, ++batch) {
        if (m_fullTunnelDeadline.elapsed() > FullTunnelBatchTotalDeadlineMs) {
            if (failureDetail) *failureDetail = QStringLiteral(
                    "bypass add deadline exceeded completed=%1/%2 elapsedMs=%3")
                    .arg(completed).arg(arguments.size()).arg(m_fullTunnelDeadline.elapsed());
            return false;
        }
        QList<QStringList> commands;
        const int count = std::min(FullTunnelRuleBatchSize,
                                   static_cast<int>(arguments.size() - offset));
        for (int index = 0; index < count; ++index) commands.append(arguments.at(offset + index));
        const CommandResult result = m_runner->runBatch(executable, commands);
        if (!result.ok) {
            if (failureDetail) {
                *failureDetail = QStringLiteral(
                        "bypass add batch %1/%2 failed completed=%3/%4 elapsedMs=%5: %6")
                        .arg(batch + 1).arg(batchCount).arg(completed)
                        .arg(arguments.size()).arg(m_fullTunnelDeadline.elapsed()).arg(result.message.left(512));
            }
            return false;
        }
        completed += count;
        qInfo().noquote() << QStringLiteral(
                "LinuxRouteReconciler bypass batch progress completed=%1/%2 elapsedMs=%3")
                .arg(completed).arg(arguments.size()).arg(m_fullTunnelDeadline.elapsed());
    }
    return true;
}

bool LinuxRouteReconciler::removeFullTunnelRulesBatch(const QList<QStringList> &arguments,
                                                      QString *failureDetail)
{
    const QString executable = ipExecutable();
    if (executable.isEmpty()) {
        if (failureDetail) *failureDetail = QStringLiteral("ip executable unavailable");
        return false;
    }
    const int batchCount = (arguments.size() + FullTunnelRuleBatchSize - 1)
            / FullTunnelRuleBatchSize;
    int completed = 0;
    for (int offset = 0, batch = 0; offset < arguments.size();
         offset += FullTunnelRuleBatchSize, ++batch) {
        if (m_fullTunnelDeadline.elapsed() > FullTunnelBatchTotalDeadlineMs) {
            if (failureDetail) *failureDetail = QStringLiteral(
                    "bypass delete deadline exceeded completed=%1/%2 elapsedMs=%3")
                    .arg(completed).arg(arguments.size()).arg(m_fullTunnelDeadline.elapsed());
            return false;
        }
        QList<QStringList> commands;
        const int count = std::min(FullTunnelRuleBatchSize,
                                   static_cast<int>(arguments.size() - offset));
        for (int index = 0; index < count; ++index) commands.append(arguments.at(offset + index));
        const CommandResult result = m_runner->runBatch(executable, commands);
        if (!result.ok) {
            // `ip -batch` stops at the first failing command.  Retry every
            // exact delete individually so a selector that raced with a
            // peer cleanup cannot strand later selectors in this batch.
            for (const QStringList &command : commands) {
                if (m_fullTunnelDeadline.elapsed() > FullTunnelBatchTotalDeadlineMs) {
                    if (failureDetail) *failureDetail = QStringLiteral(
                            "bypass delete retry deadline exceeded completed=%1/%2 elapsedMs=%3")
                            .arg(completed).arg(arguments.size())
                            .arg(m_fullTunnelDeadline.elapsed());
                    return false;
                }
                m_runner->run(executable, command);
            }
            if (m_fullTunnelDeadline.elapsed() > FullTunnelBatchTotalDeadlineMs) {
                if (failureDetail) *failureDetail = QStringLiteral(
                        "bypass delete readback deadline exceeded completed=%1/%2 elapsedMs=%3")
                        .arg(completed).arg(arguments.size())
                        .arg(m_fullTunnelDeadline.elapsed());
                return false;
            }
            const RuleSnapshot after = readRuleSnapshot();
            int remaining = -1;
            if (after.valid) {
                remaining = 0;
                for (const QStringList &command : commands) {
                    const int priorityIndex = command.indexOf(QStringLiteral("priority"));
                    const int toIndex = command.indexOf(QStringLiteral("to"));
                    bool priorityOk = false;
                    const int priority = priorityIndex >= 0 && priorityIndex + 1 < command.size()
                            ? command.at(priorityIndex + 1).toInt(&priorityOk) : -1;
                    if (!priorityOk || toIndex < 0 || toIndex + 1 >= command.size()) {
                        remaining = -1;
                        break;
                    }
                    const QString selector = QStringLiteral("to %1 ").arg(command.at(toIndex + 1));
                    if (std::any_of(after.linesV4.cbegin(), after.linesV4.cend(),
                                    [priority, &selector](const QString &line) {
                        return ruleLineMatches(line, priority, selector);
                    })) {
                        ++remaining;
                    }
                }
            }
            if (remaining != 0) {
                if (failureDetail) {
                    *failureDetail = QStringLiteral(
                            "bypass delete batch %1/%2 failed completed=%3/%4 exit=%5 remaining=%6 elapsedMs=%7: %8")
                            .arg(batch + 1).arg(batchCount).arg(completed)
                            .arg(arguments.size()).arg(result.exitCode)
                            .arg(remaining).arg(m_fullTunnelDeadline.elapsed()).arg(result.message.left(512));
                }
                return false;
            }
            // The failed batch is now proven clean.  Continue with later
            // batches; the final kernel snapshot remains authoritative.
        }
        completed += count;
        qInfo().noquote() << QStringLiteral(
                "LinuxRouteReconciler bypass delete batch progress completed=%1/%2 elapsedMs=%3")
                .arg(completed).arg(arguments.size()).arg(m_fullTunnelDeadline.elapsed());
    }
    return true;
}

bool LinuxRouteReconciler::addFullTunnelRoute(const QStringList &arguments,
                                              QString *failureDetail)
{
    const QString executable = ipExecutable();
    if (executable.isEmpty()) {
        if (failureDetail) *failureDetail = QStringLiteral("ip executable unavailable");
        return false;
    }
    const CommandResult result = m_runner->run(executable, arguments);
    if (!result.ok && failureDetail) *failureDetail = result.message.left(512);
    return result.ok;
}

bool LinuxRouteReconciler::removeFullTunnelRoute(const QStringList &arguments,
                                                 QString *failureDetail)
{
    const QString executable = ipExecutable();
    if (executable.isEmpty()) {
        if (failureDetail) *failureDetail = QStringLiteral("ip executable unavailable");
        return false;
    }
    const CommandResult result = m_runner->run(executable, arguments);
    if (result.ok) return true;
    if (result.exitCode != 2 || !arguments.contains(QStringLiteral("del"))) {
        if (failureDetail) *failureDetail = result.message.left(512);
        return false;
    }
    const RuleSnapshot snapshot = readRuleSnapshot();
    if (!snapshot.valid) {
        if (failureDetail) *failureDetail = QStringLiteral("%1; post-delete route probe failed")
                .arg(result.message.left(384));
        return false;
    }
    const int routeIndex = arguments.indexOf(QStringLiteral("route"));
    if (routeIndex < 0 || routeIndex + 2 >= arguments.size()) {
        if (failureDetail) *failureDetail = result.message.left(512);
        return false;
    }
    const QString prefix = arguments.at(routeIndex + 2);
    const bool absent = !std::any_of(snapshot.tableLines.cbegin(), snapshot.tableLines.cend(),
                                     [this, &prefix](const QString &line) {
        QString parsedPrefix;
        return parseManagedFullTunnelRouteLine(line, m_interfaceName, &parsedPrefix)
                && parsedPrefix == prefix;
    });
    if (!absent && failureDetail) *failureDetail = result.message.left(512);
    return absent;
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
            // A narrow `to ... lookup main` rule is not a durable marker: it
            // is also commonly installed by the underlay/network manager.
            // Only an active all-except receipt binds this selector and
            // priority to the reconciler.  In particular, a missing or
            // only-forward receipt must preserve foreign priority 1000.
            if (managedKind == ManagedRuleKind::Bypass
                && managedPriority == priority
                && m_mode == QStringLiteral("all-except")
                && managedPriority == m_bypassRulePriority
                && m_bypassRoutes.contains(destination)) {
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
        { QStringLiteral("-N"), QStringLiteral("route"), QStringLiteral("show"), QStringLiteral("table"),
          QString::number(FullTunnelRouteTable) },
        { QStringLiteral("-6"), QStringLiteral("-N"), QStringLiteral("route"), QStringLiteral("show"),
          QStringLiteral("table"), QString::number(FullTunnelRouteTable) },
    };
    for (const QStringList &arguments : tableQueries) {
        const CommandResult result = m_runner->runCaptured(executable, arguments);
        if (!result.ok) return snapshot;
        const QStringList lines = result.output.split(QRegularExpression(QStringLiteral("[\\r\\n]")),
                                                       Qt::SkipEmptyParts);
        for (const QString &line : lines) {
            if (!QRegularExpression(QStringLiteral("^\\s*\\d+:\\s+")).match(line).hasMatch()) {
                snapshot.tableLines.append(line);
            }
        }
    }
    const CommandResult mainRoutes = m_runner->runCaptured(
            executable, { QStringLiteral("-N"), QStringLiteral("route"), QStringLiteral("show"),
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
    const bool persistedFullTunnel = m_mode == QStringLiteral("all-except");
    const auto hasOnlyOwnedBypass = [this, &snapshot](int priority) {
        bool found = false;
        QSet<QString> routes;
        for (const QString &line : snapshot.linesV4) {
            const QRegularExpressionMatch priorityMatch =
                    QRegularExpression(QStringLiteral("^\\s*(\\d+):")).match(line);
            if (!priorityMatch.hasMatch() || priorityMatch.captured(1).toInt() != priority) {
                continue;
            }
            int parsedPriority = 0;
            ManagedRuleKind kind = ManagedRuleKind::None;
            QString destination;
            if (!parseManagedRuleLine(line, &parsedPriority, &kind, &destination)
                || parsedPriority != priority || kind != ManagedRuleKind::Bypass
                || !m_bypassRoutes.contains(destination) || routes.contains(destination)) {
                return false;
            }
            found = true;
            routes.insert(destination);
        }
        // A persisted priority is reusable only when every retained route is
        // represented by an exact owned rule.  An empty priority cannot prove
        // ownership and must be selected afresh.
        QSet<QString> expectedRoutes;
        for (const QString &route : m_bypassRoutes) expectedRoutes.insert(route);
        return found && routes == expectedRoutes;
    };
    const auto hasOnlyOwnedFull = [&snapshot](int priority) {
        bool found = false;
        for (const QStringList *familyLines : { &snapshot.linesV4, &snapshot.linesV6 }) {
            for (const QString &line : *familyLines) {
                const QRegularExpressionMatch priorityMatch =
                        QRegularExpression(QStringLiteral("^\\s*(\\d+):")).match(line);
                if (!priorityMatch.hasMatch() || priorityMatch.captured(1).toInt() != priority) {
                    continue;
                }
                int parsedPriority = 0;
                ManagedRuleKind kind = ManagedRuleKind::None;
                if (!parseManagedRuleLine(line, &parsedPriority, &kind)
                    || parsedPriority != priority || kind != ManagedRuleKind::FullTunnel) {
                    return false;
                }
                found = true;
            }
        }
        return found;
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
    const bool persistedBypassOwned = persistedFullTunnel
            && hasOnlyOwnedBypass(m_bypassRulePriority);
    return select(m_bypassRulePriority,
                  persistedBypassOwned ? FullTunnelBypassRulePriority
                                       : FullTunnelBypassPreferredPriority,
                  FullTunnelBypassPriorityLimit,
                  persistedBypassOwned,
                  [&snapshot](int priority) { return snapshot.occupiedV4.contains(priority); },
                  bypassPriority)
        && select(m_fullRulePriority, FullTunnelRulePriority, FullTunnelPriorityLimit,
                  persistedFullTunnel && hasOnlyOwnedFull(m_fullRulePriority),
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
    const QString expected = canonicalRuleDestination(
            needle.trimmed().mid(QStringLiteral("to ").size()).trimmed());
    return !expected.isEmpty() && destination == expected;
}

bool LinuxRouteReconciler::managedMainRouteLineMatches(
        const QString &line, const QString &prefix, const QString &interfaceName)
{
    QString actualPrefix;
    QString actualInterface;
    return parseManagedMainRouteLine(line, &actualPrefix, &actualInterface)
        && actualPrefix == canonicalRuleDestination(prefix)
        && actualInterface == interfaceName;
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
        const QString &interfaceName, const QStringList &bypassRoutes,
        const QStringList &criticalBypassRoutes)
{
    if (!m_fullTunnelDeadline.isValid()) m_fullTunnelDeadline.start();
    if (ipExecutable().isEmpty()) {
        return failure(QStringLiteral("route_backend_unavailable"),
                       QStringLiteral("the Linux ip command is not installed"));
    }

    const RuleSnapshot ruleSnapshot = readRuleSnapshot();
    if (!ruleSnapshot.valid) {
        return failure(QStringLiteral("full_tunnel_rule_probe_failed"),
                       QStringLiteral("could not inspect policy rules safely"));
    }
    const bool hadFullTunnel = m_mode == QStringLiteral("all-except");
    // Select priorities from the fresh snapshot before interpreting the
    // historical defaults.  A foreign preferred priority is not ours to
    // delete or overwrite; a fresh transition therefore advances to the
    // first free slot (for example 1001 when 1000 is occupied).
    int bypassPriority = FullTunnelBypassRulePriority;
    int fullPriority = FullTunnelRulePriority;
    if (!selectRulePriorities(ruleSnapshot, &bypassPriority, &fullPriority)) {
        return failure(QStringLiteral("full_tunnel_rule_probe_failed"),
                       QStringLiteral("could not find safe policy-rule priorities"));
    }
    // A broad main-table rule before the selected full-tunnel rule wins for
    // every destination and silently defeats all-except.  It is foreign state,
    // so leave it untouched but reject the transaction before its first host
    // mutation.  Narrow endpoint rules remain valid and are preserved.
    for (const QStringList *familyLines : { &ruleSnapshot.linesV4, &ruleSnapshot.linesV6 }) {
        for (const QString &line : *familyLines) {
            int broadPriority = 0;
            if (parseBroadMainRuleLine(line, &broadPriority)
                && broadPriority < fullPriority) {
                return failure(QStringLiteral("full_tunnel_rule_conflict"),
                               QStringLiteral("a broad foreign main-table rule would preempt the full-tunnel rule"));
            }
        }
    }
    // IPv4 and IPv6 policy rules live in separate namespaces.  Every family
    // must be checked independently: a foreign rule in one family cannot be
    // hidden by an owned rule at the same numeric priority in the other.
    const auto hasForeign = [](const QSet<int> &occupied,
                               const QSet<int> &owned, int priority) {
        return occupied.contains(priority) && !owned.contains(priority);
    };
    // Only a persisted active tunnel may claim a priority.  If a claimed
    // priority contains both exact owned and foreign/ambiguous rules, refuse
    // the transition rather than deleting an entry that cannot be attributed.
    if (hadFullTunnel
        && (hasForeign(ruleSnapshot.occupiedV4, ruleSnapshot.ownedFullV4,
                       m_fullRulePriority)
            || hasForeign(ruleSnapshot.occupiedV6, ruleSnapshot.ownedFullV6,
                          m_fullRulePriority)
            || hasForeign(ruleSnapshot.occupiedV4, ruleSnapshot.ownedBypassV4,
                          m_bypassRulePriority)
            || hasForeign(ruleSnapshot.occupiedV6, ruleSnapshot.ownedBypassV6,
                          m_bypassRulePriority))) {
        return failure(QStringLiteral("full_tunnel_rule_conflict"),
                       QStringLiteral("a persisted full-tunnel priority is occupied by a foreign rule"));
    }
    QSet<QString> allowedBypassRoutes;
    if (hadFullTunnel) {
        for (const QString &route : m_bypassRoutes) allowedBypassRoutes.insert(route);
    }
    const auto persistedPriorityIsExact = [&allowedBypassRoutes, &ruleSnapshot, this](int priority,
                                                                        bool bypass) {
        QSet<QString> seenBypass;
        bool found = false;
        const auto inspect = [&](const QStringList &lines, bool ipv6) {
            for (const QString &line : lines) {
                const QRegularExpressionMatch priorityMatch =
                        QRegularExpression(QStringLiteral("^\\s*(\\d+):")).match(line);
                if (!priorityMatch.hasMatch() || priorityMatch.captured(1).toInt() != priority) {
                    continue;
                }
                int parsedPriority = 0;
                ManagedRuleKind kind = ManagedRuleKind::None;
                QString destination;
                if (!parseManagedRuleLine(line, &parsedPriority, &kind, &destination)
                    || parsedPriority != priority) {
                    return false;
                }
                if (bypass) {
                    if (ipv6 || kind != ManagedRuleKind::Bypass
                        || !allowedBypassRoutes.contains(destination)
                        || seenBypass.contains(destination)) {
                        return false;
                    }
                    seenBypass.insert(destination);
                } else if (kind != ManagedRuleKind::FullTunnel) {
                    return false;
                }
                found = true;
            }
            return true;
        };
        return inspect(ruleSnapshot.linesV4, false)
            && inspect(ruleSnapshot.linesV6, true)
            && (!bypass || seenBypass == allowedBypassRoutes)
            && (bypass || found);
    };
    if (hadFullTunnel
        && (!persistedPriorityIsExact(m_bypassRulePriority, true)
            || !persistedPriorityIsExact(m_fullRulePriority, false))) {
        return failure(QStringLiteral("full_tunnel_rule_conflict"),
                       QStringLiteral("a persisted policy-rule priority contains a foreign or ambiguous rule"));
    }
    const auto validateReservedRules = [&allowedBypassRoutes, bypassPriority, fullPriority](
            const QStringList &lines, bool ipv6) {
        QSet<QString> seenBypassRoutes;
        QSet<int> seenFullPriorities;
        for (const QString &line : lines) {
            const QRegularExpressionMatch priorityMatch =
                    QRegularExpression(QStringLiteral("^\\s*(\\d+):")).match(line);
            if (!priorityMatch.hasMatch()) continue;
            const int priority = priorityMatch.captured(1).toInt();
            if (priority != bypassPriority && priority != fullPriority) continue;
            int parsedPriority = 0;
            ManagedRuleKind kind = ManagedRuleKind::None;
            QString destination;
            if (!parseManagedRuleLine(line, &parsedPriority, &kind, &destination)
                || parsedPriority != priority) {
                return false;
            }
            if (priority == fullPriority) {
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
    QSet<QString> tableRoutes;
    const QString previousInterface = m_interfaceName;
    QString markedInterface;
    for (const QString &line : ruleSnapshot.tableLines) {
        QString prefix;
        QString routeInterface;
        if (!parseManagedFullTunnelRouteLine(line, {}, &prefix, &routeInterface)) {
            return failure(QStringLiteral("full_tunnel_table_conflict"),
                           QStringLiteral("route table 51821 contains an unowned route"));
        }
        if (tableRoutes.contains(prefix)) {
            return failure(QStringLiteral("full_tunnel_table_conflict"),
                           QStringLiteral("route table 51821 contains duplicate managed prefixes"));
        }
        tableRoutes.insert(prefix);
        if (markedInterface.isEmpty()) {
            markedInterface = routeInterface;
        } else if (markedInterface != routeInterface) {
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
    // Retire stale allow-list rules before reusing priority 1000.  `ip rule
    // add` permits duplicate priorities, which can leave an old allow-list
    // entry active or make rule selection order-dependent.  Delete only exact
    // protocol/priority/route-owned entries; the existing full-tunnel rule
    // keeps non-allow-listed traffic on the VPN while this replacement runs.
    QStringList removedPreviousBypassRoutes;
    if (hadFullTunnel) {
        QList<QStringList> staleDeletes;
        for (const QString &route : previousBypassRoutes) {
            if (bypassRoutes.contains(route)) {
                continue;
            }
            bool owned = false;
            for (const QString &line : ruleSnapshot.linesV4) {
                if (ruleLineMatches(line, previousBypassPriority,
                                    QStringLiteral("to %1 ").arg(route))) {
                    owned = true;
                    break;
                }
            }
            if (!owned) {
                continue;
            }
            staleDeletes.append(bypassRuleArguments(QStringLiteral("del"),
                                                    previousBypassPriority, route));
            removedPreviousBypassRoutes.append(route);
        }
        QString batchError;
        if (!removeFullTunnelRulesBatch(staleDeletes, &batchError)) {
            const bool persisted = markRecoveryRequired(
                    QStringLiteral("stale full-tunnel allow-list rule removal failed: %1")
                            .arg(batchError));
            return failure(QStringLiteral("recovery_required"),
                           persisted
                               ? QStringLiteral("stale full-tunnel allow-list rules could not be retired")
                               : QStringLiteral("stale allow-list removal and recovery receipt both failed"));
        }
    }
    const auto restoreRemovedPreviousBypassRoutes = [&]() {
        if (removedPreviousBypassRoutes.isEmpty()) return true;
        RuleSnapshot current = readRuleSnapshot();
        if (!current.valid) return false;
        QList<QStringList> restore;
        for (const QString &removed : std::as_const(removedPreviousBypassRoutes)) {
            const bool present = std::any_of(current.linesV4.cbegin(), current.linesV4.cend(),
                                             [this, previousBypassPriority, &removed](const QString &line) {
                return ruleLineMatches(line, previousBypassPriority,
                                       QStringLiteral("to %1 ").arg(removed));
            });
            if (!present) restore.append(bypassRuleArguments(QStringLiteral("add"),
                                                              previousBypassPriority, removed));
        }
        QString restoreError;
        const bool restored = addFullTunnelRulesBatch(restore, &restoreError);
        if (restored) {
            removedPreviousBypassRoutes.clear();
        }
        return restored;
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
            const bool staleRestored = restoreRemovedPreviousBypassRoutes();
            if (!rollbackOk || !staleRestored) {
                const bool persisted = markRecoveryRequired(
                        staleRestored ? QStringLiteral("full-tunnel route rollback was incomplete")
                                      : QStringLiteral("stale full-tunnel allow-list restore failed"));
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
    QJsonObject rollbackDiagnostics;
    auto rollback = [&]() {
        bool ok = true;
        QList<QStringList> bypassDeletes;
        for (const QString &route : addedBypassRoutes) {
            bypassDeletes.append(bypassRuleArguments(QStringLiteral("del"), bypassPriority, route));
        }
        QString rollbackBatchError;
        const bool bypassDeleteOk = removeFullTunnelRulesBatch(bypassDeletes, &rollbackBatchError);
        ok = bypassDeleteOk && ok;
        bool fullV4DeleteOk = true;
        bool fullV6DeleteOk = true;
        QString fullV4Error;
        QString fullV6Error;
        if (addedFullV4) {
            fullV4DeleteOk = removeFullTunnelRule(
                    fullRuleArguments(QStringLiteral("del"), fullPriority, false), &fullV4Error);
            ok = fullV4DeleteOk && ok;
        }
        if (addedFullV6) {
            fullV6DeleteOk = removeFullTunnelRule(
                    fullRuleArguments(QStringLiteral("del"), fullPriority, true), &fullV6Error);
            ok = fullV6DeleteOk && ok;
        }
        bool tableDeleteOk = true;
        QString tableDeleteError;
        bool splitRestoreOk = true;
        QString splitRestoreError;
        if (!hadFullTunnel) {
            for (const QStringList &route : fullRoutes) {
                if (tableRoutes.contains(fullRoutePrefix(route))) continue;
                QStringList deletion { route };
                deletion.replace(deletion.indexOf(QStringLiteral("replace")),
                                 QStringLiteral("del"));
                QString detail;
                const bool routeOk = removeFullTunnelRoute(deletion, &detail);
                tableDeleteOk = routeOk && tableDeleteOk;
                if (!routeOk && tableDeleteError.isEmpty()) tableDeleteError = detail;
                ok = routeOk && ok;
            }
        } else if (previousInterface == interfaceName) {
            for (const QStringList &route : fullRoutes) {
                if (tableRoutes.contains(fullRoutePrefix(route))) continue;
                QStringList deletion = route;
                deletion.replace(deletion.indexOf(QStringLiteral("replace")),
                                 QStringLiteral("del"));
                QString detail;
                const bool routeOk = removeFullTunnelRoute(deletion, &detail);
                tableDeleteOk = routeOk && tableDeleteOk;
                if (!routeOk && tableDeleteError.isEmpty()) tableDeleteError = detail;
                ok = routeOk && ok;
            }
        } else if (previousInterface != interfaceName && !previousInterface.isEmpty()) {
            for (const QStringList &route : fullRoutes) {
                const QString prefix = fullRoutePrefix(route);
                if (!tableRoutes.contains(prefix)) {
                    QStringList deletion = route;
                    deletion.replace(deletion.indexOf(QStringLiteral("replace")), QStringLiteral("del"));
                    QString detail;
                    const bool routeOk = removeFullTunnelRoute(deletion, &detail);
                    tableDeleteOk = routeOk && tableDeleteOk;
                    if (!routeOk && tableDeleteError.isEmpty()) tableDeleteError = detail;
                    ok = routeOk && ok;
                    continue;
                }
                QStringList restore = route;
                const int devIndex = restore.indexOf(QStringLiteral("dev"));
                if (devIndex < 0 || devIndex + 1 >= restore.size()) {
                    splitRestoreOk = false;
                    splitRestoreError = QStringLiteral("invalid route restore arguments");
                    ok = false;
                    continue;
                }
                restore.replace(devIndex + 1, previousInterface);
                QString detail;
                const bool routeOk = addFullTunnelRoute(restore, &detail);
                splitRestoreOk = routeOk && splitRestoreOk;
                if (!routeOk && splitRestoreError.isEmpty()) splitRestoreError = detail;
                ok = routeOk && ok;
            }
        }
        const bool splitRestoreRoutesOk = restoreRemovedPreviousBypassRoutes();
        ok = splitRestoreRoutesOk && ok;
        if (!splitRestoreRoutesOk && splitRestoreError.isEmpty()) {
            splitRestoreError = QStringLiteral("stale bypass restoration failed");
        }
        const RuleSnapshot after = readRuleSnapshot();
        bool postSnapshotOk = after.valid;
        for (const QString &route : addedBypassRoutes) {
            if (std::any_of(after.linesV4.cbegin(), after.linesV4.cend(),
                            [bypassPriority, &route](const QString &line) {
                return ruleLineMatches(line, bypassPriority,
                                       QStringLiteral("to %1 ").arg(route));
            })) postSnapshotOk = false;
        }
        if (!hadFullTunnel && (!after.valid || !after.tableLines.isEmpty())) postSnapshotOk = false;
        rollbackDiagnostics = QJsonObject {
            { QStringLiteral("bypassDelete"), bypassDeleteOk },
            { QStringLiteral("bypassDeleteError"), rollbackBatchError.left(512) },
            { QStringLiteral("fullV4Delete"), fullV4DeleteOk },
            { QStringLiteral("fullV4DeleteError"), fullV4Error.left(512) },
            { QStringLiteral("fullV6Delete"), fullV6DeleteOk },
            { QStringLiteral("fullV6DeleteError"), fullV6Error.left(512) },
            { QStringLiteral("tableRouteDelete"), tableDeleteOk },
            { QStringLiteral("tableRouteDeleteError"), tableDeleteError.left(512) },
            { QStringLiteral("splitRestore"), splitRestoreOk && splitRestoreRoutesOk },
            { QStringLiteral("splitRestoreError"), splitRestoreError.left(512) },
            { QStringLiteral("postSnapshot"), postSnapshotOk },
            { QStringLiteral("postSnapshotError"), postSnapshotOk ? QString() : QStringLiteral("managed state remained") },
        };
        return ok && postSnapshotOk;
    };

    QSet<QString> targetBypassSet;
    for (const QString &route : bypassRoutes) targetBypassSet.insert(route);
    QSet<QString> retiredBypassSet;
    for (const QString &route : removedPreviousBypassRoutes) retiredBypassSet.insert(route);
    QSet<QString> existingBypassSet;
    if (ruleSnapshot.occupiedV4.contains(bypassPriority)) {
        for (const QString &line : ruleSnapshot.linesV4) {
            const QRegularExpressionMatch priorityMatch = QRegularExpression(
                    QStringLiteral("^\\s*(\\d+):")).match(line);
            if (!priorityMatch.hasMatch() || priorityMatch.captured(1).toInt() != bypassPriority) {
                continue;
            }
            int parsedPriority = 0;
            ManagedRuleKind kind = ManagedRuleKind::None;
            QString destination;
            if (!parseManagedRuleLine(line, &parsedPriority, &kind, &destination)
                || kind != ManagedRuleKind::Bypass || existingBypassSet.contains(destination)
                || (!targetBypassSet.contains(destination) && !retiredBypassSet.contains(destination))) {
                const bool staleRestored = restoreRemovedPreviousBypassRoutes();
                if (!staleRestored) {
                    const bool persisted = markRecoveryRequired(
                            QStringLiteral("stale full-tunnel allow-list restore failed"));
                    return failure(QStringLiteral("recovery_required"),
                                   persisted ? QStringLiteral("stale allow-list restore failed")
                                             : QStringLiteral("stale allow-list restore and recovery receipt both failed"));
                }
                return failure(QStringLiteral("full_tunnel_rule_conflict"),
                               QStringLiteral("the bypass-rule priority is occupied by an ambiguous rule"));
            }
            existingBypassSet.insert(destination);
        }
    }
    QList<QStringList> bypassAdds;
    for (const QString &route : bypassRoutes) {
        if (existingBypassSet.contains(route)) {
            continue;
        }
        bypassAdds.append(bypassRuleArguments(QStringLiteral("add"), bypassPriority, route));
        addedBypassRoutes.append(route);
    }
    QList<QStringList> criticalBypassAdds;
    QList<QStringList> nonCriticalBypassAdds;
    for (const QStringList &command : std::as_const(bypassAdds)) {
        const int toIndex = command.indexOf(QStringLiteral("to"));
        const QString route = toIndex >= 0 && toIndex + 1 < command.size()
                ? command.at(toIndex + 1) : QString();
        if (criticalBypassRoutes.contains(route)) {
            criticalBypassAdds.append(command);
        } else {
            nonCriticalBypassAdds.append(command);
        }
    }
    QString bypassBatchError;
    // A refresh may already have the full-tunnel rule active.  Install every
    // endpoint/underlay critical selector first, so no management traffic can
    // be caught by table 51821 while the larger server policy is expanded.
    // If this first batch fails, the rollback below retains the prior LKG.
    if (!addFullTunnelRulesBatch(criticalBypassAdds, &bypassBatchError)) {
        if (!rollback()) {
            const bool persisted = markRecoveryRequired(
                    QStringLiteral("full-tunnel rule rollback failed: %1").arg(bypassBatchError));
            return failure(QStringLiteral("recovery_required"), persisted
                               ? QStringLiteral("full-tunnel route transaction rollback failed")
                               : QStringLiteral("full-tunnel rollback recovery receipt could not be persisted"));
        }
        return failure(QStringLiteral("full_tunnel_rule_conflict"),
                       QStringLiteral("a full-tunnel bypass rule batch could not be installed: %1")
                               .arg(bypassBatchError));
    }
    if (!criticalBypassRoutes.isEmpty()) {
        const RuleSnapshot criticalSnapshot = readRuleSnapshot();
        QSet<QString> presentCritical;
        if (criticalSnapshot.valid) {
            for (const QString &line : criticalSnapshot.linesV4) {
                int priority = 0;
                ManagedRuleKind kind = ManagedRuleKind::None;
                QString destination;
                if (parseManagedRuleLine(line, &priority, &kind, &destination)
                    && priority == bypassPriority && kind == ManagedRuleKind::Bypass) {
                    presentCritical.insert(destination);
                }
            }
        }
        bool criticalPostcondition = criticalSnapshot.valid;
        for (const QString &route : criticalBypassRoutes) {
            criticalPostcondition = criticalPostcondition && presentCritical.contains(route);
        }
        if (!criticalPostcondition) {
            bypassBatchError = QStringLiteral(
                    "critical bypass postcondition failed completed=%1/%2")
                    .arg(criticalBypassAdds.size()).arg(criticalBypassRoutes.size());
            if (!rollback()) {
                const bool persisted = markRecoveryRequired(
                        QStringLiteral("critical full-tunnel bypass rollback failed"));
                return failure(QStringLiteral("recovery_required"), persisted
                                   ? QStringLiteral("critical bypass postcondition failed and rollback was incomplete")
                                   : QStringLiteral("critical bypass postcondition failed and recovery receipt could not be persisted"));
            }
            return failure(QStringLiteral("full_tunnel_rule_conflict"), bypassBatchError);
        }
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

    // The full-tunnel rule is now active only after every critical selector
    // has been installed and read back.  Expand the larger server policy only
    // after that safety boundary has been crossed.
    if (!addFullTunnelRulesBatch(nonCriticalBypassAdds, &bypassBatchError)) {
        if (!rollback()) {
            const bool persisted = markRecoveryRequired(
                    QStringLiteral("full-tunnel rule rollback failed: %1").arg(bypassBatchError));
            return failure(QStringLiteral("recovery_required"), persisted
                               ? QStringLiteral("full-tunnel route transaction rollback failed")
                               : QStringLiteral("full-tunnel rollback recovery receipt could not be persisted"));
        }
        return failure(QStringLiteral("full_tunnel_rule_conflict"),
                       QStringLiteral("a full-tunnel bypass rule batch could not be installed: %1")
                               .arg(bypassBatchError));
    }

    QStringList removedSplitRoutes;
    if (hadFullTunnel) {
        // Stale rules were retired before the replacement priority was reused.
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

    // Command success is not sufficient evidence: ip rule accepts duplicate
    // priorities and a batch can stop after partially applying its input.
    // Verify the complete kernel postcondition before publishing the receipt.
    // Keep the postcondition snapshot explicit: diagnostics must describe the
    // exact kernel state observed after the batch, before any rollback.
    // postcondition snapshot
    const RuleSnapshot committed = readRuleSnapshot();
    const QSet<QString> expectedPrefixes {
            QStringLiteral("0.0.0.0/1"), QStringLiteral("128.0.0.0/1"),
            QStringLiteral("::/1"), QStringLiteral("8000::/1") };
    QSet<QString> actualPrefixes;
    QString firstInvalidRouteLine;
    QString rejectedProtocol;
    if (committed.valid) {
        for (const QString &line : committed.tableLines) {
            QString prefix;
            if (!parseManagedFullTunnelRouteLine(line, interfaceName, &prefix)
                || actualPrefixes.contains(prefix)) {
                if (firstInvalidRouteLine.isEmpty()) {
                    firstInvalidRouteLine = line.left(512);
                }
                if (rejectedProtocol.isEmpty()) {
                    const QString candidate = routeProtocolToken(line);
                    if (!candidate.isEmpty()
                        && !managedProtocolTokenMatches(AmneziaRouteProtocol, candidate)) {
                        rejectedProtocol = candidate;
                    }
                }
                actualPrefixes.insert(QStringLiteral("<invalid>"));
                break;
            }
            actualPrefixes.insert(prefix);
        }
    }
    int fullV4Count = 0;
    int fullV6Count = 0;
    QSet<QString> actualBypasses;
    bool selectedRulesValid = committed.valid;
    if (committed.valid) {
        for (const QString &line : committed.linesV4) {
            const QRegularExpressionMatch priorityMatch =
                    QRegularExpression(QStringLiteral("^\\s*(\\d+):")).match(line);
            if (!priorityMatch.hasMatch()) continue;
            const int priority = priorityMatch.captured(1).toInt();
            if (priority != bypassPriority && priority != fullPriority) continue;
            ManagedRuleKind kind = ManagedRuleKind::None;
            QString destination;
            if (!parseManagedRuleLine(line, nullptr, &kind, &destination)) {
                selectedRulesValid = false;
                continue;
            }
            if (priority == fullPriority) {
                if (kind != ManagedRuleKind::FullTunnel) selectedRulesValid = false;
                else ++fullV4Count;
            } else if (kind != ManagedRuleKind::Bypass
                       || actualBypasses.contains(destination)) {
                selectedRulesValid = false;
            }
        }
        for (const QString &line : committed.linesV6) {
            const QRegularExpressionMatch priorityMatch =
                    QRegularExpression(QStringLiteral("^\\s*(\\d+):")).match(line);
            if (!priorityMatch.hasMatch()) continue;
            const int priority = priorityMatch.captured(1).toInt();
            if (priority != bypassPriority && priority != fullPriority) continue;
            ManagedRuleKind kind = ManagedRuleKind::None;
            QString destination;
            if (!parseManagedRuleLine(line, nullptr, &kind, &destination)) {
                selectedRulesValid = false;
                continue;
            }
            if (priority == fullPriority) {
                if (kind != ManagedRuleKind::FullTunnel) selectedRulesValid = false;
                else ++fullV6Count;
            } else if (kind != ManagedRuleKind::Bypass) {
                // Bypass selectors are IPv4-only.  A syntactically valid
                // IPv6 entry at the selected bypass priority is foreign.
                selectedRulesValid = false;
            }
        }
    }
    bool bypassRulesValid = committed.valid;
    if (committed.valid) {
        for (const QString &line : committed.linesV4) {
            const QRegularExpressionMatch priorityMatch =
                    QRegularExpression(QStringLiteral("^\\s*(\\d+):")).match(line);
            if (!priorityMatch.hasMatch()
                || priorityMatch.captured(1).toInt() != bypassPriority) continue;
            int priority = 0; ManagedRuleKind kind = ManagedRuleKind::None;
            QString destination;
            if (!parseManagedRuleLine(line, &priority, &kind, &destination)) {
                bypassRulesValid = false;
                break;
            }
            if (kind != ManagedRuleKind::Bypass || actualBypasses.contains(destination)) {
                bypassRulesValid = false;
                break;
            }
            actualBypasses.insert(destination);
        }
    }
    QSet<QString> expectedBypasses;
    for (const QString &route : bypassRoutes) {
        const QString canonical = canonicalRuleDestination(route);
        if (!canonical.isEmpty()) expectedBypasses.insert(canonical);
    }
    QJsonObject diagnostics {
        { QStringLiteral("committedValid"), committed.valid },
        { QStringLiteral("tableLineCount"), committed.tableLines.size() },
        { QStringLiteral("actualPrefixCount"), actualPrefixes.contains(QStringLiteral("<invalid>"))
              ? committed.tableLines.size() : actualPrefixes.size() },
        { QStringLiteral("expectedPrefixCount"), expectedPrefixes.size() },
        { QStringLiteral("fullV4Count"), fullV4Count },
        { QStringLiteral("fullV6Count"), fullV6Count },
        { QStringLiteral("selectedRulesValid"), selectedRulesValid },
        { QStringLiteral("bypassRulesValid"), bypassRulesValid },
        { QStringLiteral("actualBypassCount"), actualBypasses.size() },
        { QStringLiteral("expectedBypassCount"), expectedBypasses.size() },
        { QStringLiteral("selectedBypassPriority"), bypassPriority },
        { QStringLiteral("selectedFullPriority"), fullPriority },
    };
    if (!firstInvalidRouteLine.isEmpty()) {
        diagnostics.insert(QStringLiteral("firstInvalidRouteLine"), firstInvalidRouteLine);
    }
    if (!rejectedProtocol.isEmpty()) {
        diagnostics.insert(QStringLiteral("rejectedProtocol"), rejectedProtocol);
        diagnostics.insert(QStringLiteral("rejectedProtocolLine"), firstInvalidRouteLine);
        diagnostics.insert(QStringLiteral("expectedProtocol"), QStringLiteral("186 or bgp"));
    }
    if (actualPrefixes != expectedPrefixes) {
        QString mismatch;
        // A malformed compact route is more actionable than the derived
        // missing-prefix symptom: report the rejected line first, while the
        // bounded firstInvalidRouteLine field retains the exact evidence.
        if (!firstInvalidRouteLine.isEmpty()
            || actualPrefixes.contains(QStringLiteral("<invalid>"))) {
            mismatch = QStringLiteral("invalid-route-line");
        }
        if (mismatch.isEmpty()) {
            for (const QString &prefix : expectedPrefixes) {
                if (!actualPrefixes.contains(prefix)) {
                    mismatch = QStringLiteral("missing:%1").arg(prefix);
                    break;
                }
            }
        }
        if (mismatch.isEmpty()) {
            for (const QString &prefix : actualPrefixes) {
                if (!expectedPrefixes.contains(prefix)) {
                    mismatch = QStringLiteral("unexpected:%1").arg(prefix);
                    break;
                }
            }
        }
        if (!mismatch.isEmpty()) diagnostics.insert(QStringLiteral("firstMismatch"), mismatch);
    }
    const bool postconditionFailed = !committed.valid || committed.tableLines.size() != 4
        || actualPrefixes != expectedPrefixes || fullV4Count != 1 || fullV6Count != 1
        || !selectedRulesValid || !bypassRulesValid || actualBypasses != expectedBypasses;
    if (postconditionFailed) {
        diagnostics.insert(QStringLiteral("originalOperationFailure"),
                           QStringLiteral("full-tunnel postcondition verification failed"));
        m_lastDiagnostics = diagnostics;
        const bool rulesRestored = rollback();
        const bool routesRestored = restoreRoutes(previousInterface, removedSplitRoutes);
        // A successful rollback must be read back before the intent is retired.
        // This keeps a transient command success from being mistaken for a
        // healthy only-forward state after an all-except downgrade.
        bool rollbackReadback = false;
        const RuleSnapshot restored = readRuleSnapshot();
        if (restored.valid) {
            if (!hadFullTunnel) {
                rollbackReadback = restored.tableLines.isEmpty()
                        && restored.ownedFull.isEmpty();
            } else {
                QSet<QString> restoredPrefixes;
                bool restoredTableExact = restored.tableLines.size() == tableRoutes.size();
                for (const QString &line : restored.tableLines) {
                    QString prefix;
                    if (!parseManagedFullTunnelRouteLine(line, previousInterface, &prefix)
                        || restoredPrefixes.contains(prefix)) {
                        restoredTableExact = false;
                        break;
                    }
                    restoredPrefixes.insert(prefix);
                }
                QSet<QString> restoredBypasses;
                bool restoredRulesExact = restored.ownedFullV4.contains(m_fullRulePriority)
                        && restored.ownedFullV6.contains(m_fullRulePriority);
                for (const QString &line : restored.linesV4) {
                    int priority = 0; ManagedRuleKind kind = ManagedRuleKind::None;
                    QString destination;
                    if (!parseManagedRuleLine(line, &priority, &kind, &destination)) continue;
                    if (priority == previousBypassPriority) {
                        if (kind != ManagedRuleKind::Bypass || restoredBypasses.contains(destination)) {
                            restoredRulesExact = false;
                            break;
                        }
                        restoredBypasses.insert(destination);
                    }
                }
                QSet<QString> previousCanonicalBypasses;
                for (const QString &route : m_bypassRoutes) {
                    previousCanonicalBypasses.insert(canonicalRuleDestination(route));
                }
                rollbackReadback = restoredTableExact && restoredPrefixes == tableRoutes
                        && restoredRulesExact && restoredBypasses == previousCanonicalBypasses;
            }
        }
        diagnostics.insert(QStringLiteral("rollbackSucceeded"), rulesRestored && routesRestored);
        diagnostics.insert(QStringLiteral("rollbackReadbackValid"), rollbackReadback);
        diagnostics.insert(QStringLiteral("rollbackSubsteps"), rollbackDiagnostics);
        m_lastDiagnostics = diagnostics;
        if (rulesRestored && routesRestored && rollbackReadback && saveState()) {
            // The outer applyAllExcept() retires the mutation intent.  Keep
            // this distinct code so the controller can install only-forward.
            return failure(QStringLiteral("full_tunnel_postcondition_failed"),
                           QStringLiteral("full-tunnel postcondition failed; rollback completed"));
        }
        markRecoveryRequired(QStringLiteral("full-tunnel postcondition failed and rollback/readback was incomplete"));
        return failure(QStringLiteral("recovery_required"),
                       QStringLiteral("full-tunnel postcondition verification and rollback failed"));
    }

    m_mode = QStringLiteral("all-except");
    m_interfaceName = interfaceName;
    m_routes.clear();
    m_bypassRoutes = bypassRoutes;
    m_criticalBypassRoutes = criticalBypassRoutes;
    m_bypassRulePriority = bypassPriority;
    m_fullRulePriority = fullPriority;
    // A successful re-application proves that the native interface and the
    // complete reserved table are back.  Retire the startup-only offline
    // marker before publishing the healthy receipt, so the next restart is
    // validated against the live four-route table rather than treated as
    // another pending re-apply.
    m_needsReapply = false;
    m_interfaceOffline = false;
    if (!saveState()) {
        bool restored = rollback();
        restored = restoreRoutes(previousInterface, removedSplitRoutes) && restored;
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
        m_criticalBypassRoutes.clear();
        m_needsReapply = false;
        m_interfaceOffline = false;
        if (!saveState()) {
            m_stateValid = false;
            m_mode = QStringLiteral("recovery_required");
            return failure(QStringLiteral("recovery_required"),
                           QStringLiteral("stale full-tunnel state could not be retired"));
        }
        return { true, {}, {} };
    }
    for (const QString &line : snapshot.tableLines) {
        QString prefix;
        if (!parseManagedFullTunnelRouteLine(line, m_interfaceName, &prefix)) {
            const QString rejectedProtocol = routeProtocolToken(line);
            if (!rejectedProtocol.isEmpty()
                && !managedProtocolTokenMatches(AmneziaRouteProtocol, rejectedProtocol)) {
                m_lastDiagnostics = QJsonObject {
                    { QStringLiteral("rejectedProtocol"), rejectedProtocol },
                    { QStringLiteral("rejectedProtocolLine"), line.left(512) },
                    { QStringLiteral("expectedProtocol"), QStringLiteral("186 or bgp") },
                };
            }
            return failure(QStringLiteral("full_tunnel_ownership_ambiguous"),
                           QStringLiteral("route table 51821 contains a foreign or unmarked route"));
        }
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
    const auto persistedPriorityExact = [this, &snapshot](int priority, bool bypass) {
        QSet<QString> expectedBypass;
        for (const QString &route : m_bypassRoutes) expectedBypass.insert(route);
        QSet<QString> seenBypass;
        bool found = false;
        const auto inspect = [&](const QStringList &lines, bool ipv6) {
            for (const QString &line : lines) {
                const QRegularExpressionMatch match =
                        QRegularExpression(QStringLiteral("^\\s*(\\d+):")).match(line);
                if (!match.hasMatch() || match.captured(1).toInt() != priority) continue;
                int parsedPriority = 0;
                ManagedRuleKind kind = ManagedRuleKind::None;
                QString destination;
                if (!parseManagedRuleLine(line, &parsedPriority, &kind, &destination)
                    || parsedPriority != priority) return false;
                if (bypass) {
                    if (ipv6 || kind != ManagedRuleKind::Bypass
                        || !expectedBypass.contains(destination)
                        || seenBypass.contains(destination)) return false;
                    seenBypass.insert(destination);
                } else if (kind != ManagedRuleKind::FullTunnel) {
                    return false;
                }
                found = true;
            }
            return true;
        };
        return inspect(snapshot.linesV4, false) && inspect(snapshot.linesV6, true)
            && (!bypass || seenBypass == expectedBypass) && (bypass || found);
    };
    if (foreignAt(snapshot.occupiedV4, snapshot.ownedFullV4, m_fullRulePriority)
        || foreignAt(snapshot.occupiedV6, snapshot.ownedFullV6, m_fullRulePriority)
        || foreignAt(snapshot.occupiedV4, snapshot.ownedBypassV4, m_bypassRulePriority)
        || foreignAt(snapshot.occupiedV6, snapshot.ownedBypassV6, m_bypassRulePriority)
        || !persistedPriorityExact(m_fullRulePriority, false)
        || !persistedPriorityExact(m_bypassRulePriority, true)) {
        return failure(QStringLiteral("full_tunnel_ownership_ambiguous"),
                       QStringLiteral("a policy rule priority is occupied by a foreign rule"));
    }
    QStringList removedBypassRoutes;
    bool removedFullV4 = false;
    bool removedFullV6 = false;
    const auto restoreRemovedRules = [&]() {
        QList<QStringList> bypassRestores;
        for (const QString &route : removedBypassRoutes) {
            bypassRestores.append(bypassRuleArguments(QStringLiteral("add"),
                                                       m_bypassRulePriority, route));
        }
        QString restoreError;
        bool restored = addFullTunnelRulesBatch(bypassRestores, &restoreError);
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
    QList<QStringList> bypassDeletes;
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
        bypassDeletes.append(bypassRuleArguments(QStringLiteral("del"),
                                                  m_bypassRulePriority, route));
        removedBypassRoutes.append(route);
    }
    QString bypassDeleteError;
    if (!removeFullTunnelRulesBatch(bypassDeletes, &bypassDeleteError)) {
        if (!restoreRemovedRules()) {
            markRecoveryRequired(QStringLiteral("full-tunnel bypass-rule restoration failed"));
            return failure(QStringLiteral("recovery_required"),
                           QStringLiteral("a bypass rule batch could not be removed and rollback failed"));
        }
        return failure(QStringLiteral("full_tunnel_rule_cleanup_failed"),
                       QStringLiteral("a full-tunnel bypass-rule batch could not be removed: %1")
                               .arg(bypassDeleteError));
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
            QString prefix;
            QString routeInterface;
            if (!parseManagedFullTunnelRouteLine(line, {}, &prefix, &routeInterface)) continue;
            QStringList restore { QStringLiteral("route"), QStringLiteral("replace"),
                                  prefix, QStringLiteral("dev"), routeInterface,
                                  QStringLiteral("table"),
                                  QString::number(FullTunnelRouteTable), QStringLiteral("proto"),
                                  QString::number(AmneziaRouteProtocol) };
            if (prefix.contains(QLatin1Char(':'))) restore.prepend(QStringLiteral("-6"));
            restored = addFullTunnelRoute(restore) && restored;
        }
        return restored;
    };
    const auto observedTablePrefix = [&snapshot, this](const QString &prefix) {
        return std::any_of(snapshot.tableLines.cbegin(), snapshot.tableLines.cend(),
                           [this, &prefix](const QString &line) {
            QString parsedPrefix;
            return parseManagedFullTunnelRouteLine(line, m_interfaceName, &parsedPrefix)
                    && parsedPrefix == prefix;
        });
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
    const RuleSnapshot cleared = readRuleSnapshot();
    if (!cleared.valid || !cleared.ownedFull.isEmpty() || !cleared.ownedBypass.isEmpty()
        || !cleared.tableLines.isEmpty()) {
        const bool restored = restoreOwnedTable() && restoreRemovedRules();
        if (!restored) markRecoveryRequired(QStringLiteral("full-tunnel cleanup postcondition and rollback failed"));
        return failure(restored ? QStringLiteral("full_tunnel_route_cleanup_failed")
                                : QStringLiteral("recovery_required"),
                       restored ? QStringLiteral("full-tunnel cleanup left managed state behind")
                                : QStringLiteral("full-tunnel cleanup postcondition failed and rollback failed"));
    }

    m_mode = QStringLiteral("only-forward");
    m_interfaceName.clear();
    m_routes.clear();
    m_bypassRoutes.clear();
    m_criticalBypassRoutes.clear();
    m_needsReapply = false;
    m_interfaceOffline = false;
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
    if (!beginMutation(QStringLiteral("dns-configure"), interfaceName, {}, {},
                      dnsServers, dnsDomains)) {
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
    const CommandResult readback = m_runner->runCaptured(
            executable, { QStringLiteral("status"), interfaceName });
    if (!readback.ok || !resolverOutputMatchesBinding(readback.output, dnsServers, dnsDomains)) {
        const bool restored = restorePreviousDns();
        if (!restored) {
            markRecoveryRequired(QStringLiteral("DNS readback mismatch and rollback failed"));
            return finishTransaction(failure(QStringLiteral("recovery_required"),
                                             QStringLiteral("DNS configuration readback mismatched and rollback failed")));
        }
        return finishTransaction(failure(QStringLiteral("dns_readback_mismatch"),
                                         QStringLiteral("DNS configuration readback did not match the requested servers/domains")));
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
    if (!targetInterface.isEmpty() && !validInterfaceName(targetInterface)) {
        return failure(QStringLiteral("invalid_dns_interface"),
                       QStringLiteral("DNS cleanup interface name is invalid"));
    }
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
    if (!beginMutation(QStringLiteral("dns-clear"), targetInterface, {}, {},
                      m_dnsServers, m_dnsDomains)) {
        return failure(QStringLiteral("recovery_required"),
                       QStringLiteral("DNS cleanup intent could not be persisted"));
    }
    const CommandResult result = m_runner->run(
            executable, { QStringLiteral("revert"), targetInterface });
    if (!result.ok) {
        // `resolvectl revert` is not idempotent when the link disappeared
        // between the snapshot and cleanup.  Prove that this is the benign
        // race using the kernel link probe and the link-scoped resolver
        // status.  Never infer absence from a generic resolver failure.
        const QString ip = ipExecutable();
        const CommandResult linkProbe = ip.isEmpty()
                ? CommandResult { false, -1, QStringLiteral("ip probe unavailable"), {} }
                : m_runner->runCaptured(ip, { QStringLiteral("link"), QStringLiteral("show"),
                                               QStringLiteral("dev"), targetInterface });
        const bool linkAbsent = commandIndicatesMissingInterface(linkProbe);
        const CommandResult resolverProbe = m_runner->runCaptured(
                executable, { QStringLiteral("status"), targetInterface });
        const bool resolverBindingAbsent = resolverProbe.ok
                ? !resolverOutputHasManagedBinding(resolverProbe.output)
                : commandIndicatesMissingInterface(resolverProbe);
        if (linkAbsent && resolverBindingAbsent) {
            // The resolver binding cannot survive removal of its link.  The
            // receipt is now stale, so retire it through the same atomic
            // save/intent path as a successful revert.
            m_dnsInterface.clear();
            m_dnsServers.clear();
            m_dnsDomains.clear();
            m_lastDiagnostics = {};
            if (!saveState()) {
                m_stateValid = false;
                m_mode = QStringLiteral("recovery_required");
                return finishTransaction(failure(
                        QStringLiteral("recovery_required"),
                        QStringLiteral("DNS link disappeared but its receipt could not be cleared")));
            }
            if (!finishMutation()) {
                const bool persisted = markRecoveryRequired(
                        QStringLiteral("DNS link disappeared but cleanup intent could not be retired"));
                return failure(QStringLiteral("recovery_required"), persisted
                                   ? QStringLiteral("DNS link disappeared and cleanup intent remains")
                                   : QStringLiteral("DNS link disappeared and recovery receipt could not be persisted"));
            }
            return { true, {}, {} };
        }
        return finishTransaction(failure(QStringLiteral("dns_clear_failed"),
                                         QStringLiteral("failed to clear the VPN DNS configuration: %1")
                                                  .arg(result.message.left(512))));
    }
    const CommandResult resolverReadback = m_runner->runCaptured(
            executable, { QStringLiteral("status"), targetInterface });
    const bool resolverAbsent = resolverReadback.ok
            ? !resolverOutputHasManagedBinding(resolverReadback.output)
            : commandIndicatesMissingInterface(resolverReadback);
    const QString ipForReadback = ipExecutable();
    const CommandResult linkReadback = ipForReadback.isEmpty()
            ? CommandResult { true, 0, {}, {} }
            : m_runner->runCaptured(ipForReadback,
                                    { QStringLiteral("link"), QStringLiteral("show"),
                                      QStringLiteral("dev"), targetInterface });
    const bool linkReadbackValid = linkReadback.ok || commandIndicatesMissingInterface(linkReadback);
    if (!resolverAbsent || !linkReadbackValid) {
        return finishTransaction(failure(QStringLiteral("dns_clear_readback_mismatch"),
                                         QStringLiteral("DNS clear readback still reports a binding or could not verify the link")));
    }
    const QString previousInterface = m_dnsInterface;
    const QStringList previousServers = m_dnsServers;
    const QStringList previousDomains = m_dnsDomains;
    m_dnsInterface.clear();
    m_dnsServers.clear();
    m_dnsDomains.clear();
    m_lastDiagnostics = {};
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
    if (m_mode == QStringLiteral("all-except")) m_fullTunnelDeadline.start();
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
        m_criticalBypassRoutes.clear();
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
    m_criticalBypassRoutes.clear();
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
        { QStringLiteral("criticalBypassRoutes"), QJsonArray::fromStringList(m_criticalBypassRoutes) },
        { QStringLiteral("routeTable"), m_mode == QStringLiteral("all-except")
                                               ? FullTunnelRouteTable : 0 },
        { QStringLiteral("bypassRulePriority"), m_bypassRulePriority },
        { QStringLiteral("fullRulePriority"), m_fullRulePriority },
        { QStringLiteral("statePath"), m_statePath },
        { QStringLiteral("lastError"), m_lastError.left(512) },
        { QStringLiteral("recoveryRequired"), !m_initialized || !m_stateValid
                                                 || m_mode == QStringLiteral("recovery_required") },
        { QStringLiteral("needsReapply"), m_needsReapply },
        { QStringLiteral("interfaceOffline"), m_needsReapply && m_interfaceOffline },
        { QStringLiteral("dnsInterface"), m_dnsInterface },
        { QStringLiteral("dnsServers"), QJsonArray::fromStringList(m_dnsServers) },
        { QStringLiteral("dnsDomains"), QJsonArray::fromStringList(m_dnsDomains) },
        { QStringLiteral("postconditionDiagnostics"), m_lastDiagnostics },
    };
}

RouteReconcileResult LinuxRouteReconciler::failure(const QString &code,
                                                   const QString &message) const
{
    m_lastError = message;
    qWarning().noquote() << QStringLiteral("LinuxRouteReconciler failure code=%1 message=%2")
                                .arg(code, message.left(512));
    return { false, code, message, m_lastDiagnostics };
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
    // Startup rejects are deliberately structured and bounded.  The receipt
    // and kernel probes may contain interface names, routes, or resolver
    // details; none of that belongs in the durable status or log.  Keep one
    // stable category so operators can identify the failed gate without
    // exposing probe output or policy data.
    const auto reject = [this](const QString &category) {
        if (!m_lastError.isEmpty()) return false;
        const QString bounded = category.left(96);
        m_lastError = QStringLiteral("load_state_rejected:%1").arg(bounded);
        qWarning().noquote() << QStringLiteral(
                "LinuxRouteReconciler startup reject category=%1").arg(bounded);
        return false;
    };
    m_lastError.clear();
    m_mode = QStringLiteral("only-forward");
    m_interfaceName.clear();
    m_routes.clear();
    m_bypassRoutes.clear();
    m_criticalBypassRoutes.clear();
    m_dnsInterface.clear();
    m_dnsServers.clear();
    m_dnsDomains.clear();
    m_lastDiagnostics = {};
    m_needsReapply = false;
    m_interfaceOffline = false;
    m_bypassRulePriority = FullTunnelBypassRulePriority;
    m_fullRulePriority = FullTunnelRulePriority;
    // A clean-looking receipt is not enough to prove that the host is clean.
    // Without `ip` there is no safe way to inspect or reconcile kernel state,
    // including when this instance has no durable receipt yet.
    if (ipExecutable().isEmpty()) {
        return reject(QStringLiteral("ip_unavailable"));
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
        return reject(QStringLiteral("recovery_marker"));
    }
    if (!m_intentPath.isEmpty() && QFileInfo::exists(m_intentPath)) {
        // A durable intent is written before the first kernel/resolver
        // mutation.  Its presence means the previous process may have died in
        // the transaction window; do not infer ownership or mutate anything
        // until an operator performs recovery.
        return reject(QStringLiteral("transaction_intent"));
    }
    // Older builds used a shorter sidecar suffix.  Never delete it silently:
    // an orphaned legacy intent still means the previous host mutation may
    // have completed after its receipt write and requires operator recovery.
    if (!m_statePath.isEmpty()
        && (QFileInfo::exists(m_statePath + QStringLiteral(".intent"))
            || QFileInfo::exists(m_statePath + QStringLiteral(".transaction-intent")))) {
        return reject(QStringLiteral("legacy_transaction_intent"));
    }
    if (!stateInfo.exists()) {
        // A missing receipt is not proof that the kernel is clean. Probe the
        // owned table/rules before allowing a fresh daemon to mutate routes;
        // a crash between kernel mutation and receipt commit must fail closed.
        // There is no safe way to prove that the kernel is clean without the
        // probe tool.  A missing receipt must therefore fail closed instead of
        // treating an unavailable `ip` as an empty routing table.
        const RuleSnapshot snapshot = readRuleSnapshot();
        if (!snapshot.valid) return reject(QStringLiteral("kernel_snapshot"));
        if (!snapshot.tableLines.isEmpty()
            || !snapshot.ownedFull.isEmpty()) {
            return reject(QStringLiteral("orphan_owned_state"));
        }
        for (const QString &line : snapshot.mainRouteLines) {
            QString prefix;
            QString interfaceName;
            if (parseManagedMainRouteLine(line, &prefix, &interfaceName)) {
                return reject(QStringLiteral("orphan_main_route"));
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
        return reject(QStringLiteral("receipt_path"));
    }
    QFile file(m_statePath);
    if (!file.open(QIODevice::ReadOnly)) {
        return reject(QStringLiteral("receipt_open"));
    }
    QJsonParseError error;
    const QJsonDocument document = QJsonDocument::fromJson(file.readAll(), &error);
    if (error.error != QJsonParseError::NoError || !document.isObject()) {
        return reject(QStringLiteral("receipt_json"));
    }
    const QJsonObject object = document.object();
    for (auto it = object.constBegin(); it != object.constEnd(); ++it) {
        if (!QStringList {
                QStringLiteral("version"), QStringLiteral("mode"),
                QStringLiteral("interface"), QStringLiteral("routes"),
                QStringLiteral("bypassRoutes"), QStringLiteral("bypassRulePriority"),
                 QStringLiteral("criticalBypassRoutes"),
                 QStringLiteral("fullRulePriority"), QStringLiteral("dnsInterface"),
                 QStringLiteral("dnsServers"), QStringLiteral("dnsDomains"),
                 QStringLiteral("postconditionDiagnostics"), QStringLiteral("needsReapply")
            }.contains(it.key())) {
            return reject(QStringLiteral("receipt_unknown_field"));
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
        return reject(QStringLiteral("receipt_schema"));
    }
    Q_UNUSED(stateVersion);
    const QString mode = object.value(QStringLiteral("mode"))
                                 .toString(QStringLiteral("only-forward"));
    if (mode != QStringLiteral("only-forward") && mode != QStringLiteral("all-except")) {
        return reject(QStringLiteral("receipt_mode"));
    }
    const QString interfaceName = object.value(QStringLiteral("interface")).toString();
    const QJsonArray routeArray = object.value(QStringLiteral("routes")).toArray();
    QStringList routes;
    for (const QJsonValue &value : routeArray) {
        if (!value.isString()) {
            return reject(QStringLiteral("receipt_routes_type"));
        }
        routes.append(value.toString());
    }
    bool routesValid = false;
    const QStringList bounded = amnezia::managedRoutePolicy::validatedManagedRoutes(
            routes, &routesValid);
    if (!routesValid || bounded.size() != routes.size()
        || (!interfaceName.isEmpty() && !validInterfaceName(interfaceName))) {
        return reject(QStringLiteral("receipt_routes"));
    }
    if (mode == QStringLiteral("only-forward")
        && (interfaceName.isEmpty() != bounded.isEmpty())) {
        return reject(QStringLiteral("receipt_only_forward_interface"));
    }
    QStringList bypassRoutes;
    const QJsonArray bypassArray = object.value(QStringLiteral("bypassRoutes")).toArray();
    for (const QJsonValue &value : bypassArray) {
        if (!value.isString()) {
            return reject(QStringLiteral("receipt_bypass_routes_type"));
        }
        bypassRoutes.append(value.toString());
    }
    bool bypassValid = false;
    const QStringList boundedBypass = amnezia::managedRoutePolicy::validatedManagedRoutes(
            bypassRoutes, &bypassValid);
    if (!bypassValid || boundedBypass.size() != bypassRoutes.size()
        || (mode == QStringLiteral("all-except") && interfaceName.isEmpty())) {
        return reject(QStringLiteral("receipt_bypass_routes"));
    }
    QStringList criticalBypassRoutes;
    if (object.contains(QStringLiteral("criticalBypassRoutes"))) {
        if (!object.value(QStringLiteral("criticalBypassRoutes")).isArray()) {
            return reject(QStringLiteral("receipt_critical_bypass_schema"));
        }
        for (const QJsonValue &value : object.value(QStringLiteral("criticalBypassRoutes")).toArray()) {
            if (!value.isString()) return reject(QStringLiteral("receipt_critical_bypass_type"));
            criticalBypassRoutes.append(value.toString());
        }
    }
    bool criticalValid = false;
    const QStringList boundedCritical = amnezia::managedRoutePolicy::validatedManagedRoutes(
            criticalBypassRoutes, &criticalValid);
    if (!criticalValid || boundedCritical.size() != criticalBypassRoutes.size()
        || (mode == QStringLiteral("only-forward") && !criticalBypassRoutes.isEmpty())
        || !std::all_of(boundedCritical.cbegin(), boundedCritical.cend(),
                        [&boundedBypass](const QString &route) {
                            return boundedBypass.contains(route);
                        })) {
        return reject(QStringLiteral("receipt_critical_bypass"));
    }
    if (mode == QStringLiteral("only-forward") && !bypassRoutes.isEmpty()) {
        return reject(QStringLiteral("receipt_only_forward_bypass"));
    }
    if (mode == QStringLiteral("all-except") && !routes.isEmpty()) {
        return reject(QStringLiteral("receipt_all_except_routes"));
    }
    if (object.contains(QStringLiteral("dnsInterface"))
        && (!object.value(QStringLiteral("dnsInterface")).isString()
            || !object.value(QStringLiteral("dnsServers")).isArray()
            || !object.value(QStringLiteral("dnsDomains")).isArray())) {
        return reject(QStringLiteral("receipt_dns_schema"));
    }
    if (object.contains(QStringLiteral("postconditionDiagnostics"))
        && !object.value(QStringLiteral("postconditionDiagnostics")).isObject()) {
        return reject(QStringLiteral("receipt_diagnostics_schema"));
    }
    if (object.contains(QStringLiteral("postconditionDiagnostics"))) {
        m_lastDiagnostics = object.value(QStringLiteral("postconditionDiagnostics")).toObject();
    }
    if (object.contains(QStringLiteral("needsReapply"))
        && !object.value(QStringLiteral("needsReapply")).isBool()) {
        return reject(QStringLiteral("receipt_needs_reapply_schema"));
    }
    if (object.contains(QStringLiteral("dnsInterface"))
        || object.contains(QStringLiteral("dnsServers"))
        || object.contains(QStringLiteral("dnsDomains"))) {
        if (!object.value(QStringLiteral("dnsInterface")).isString()
            || !object.value(QStringLiteral("dnsServers")).isArray()
            || !object.value(QStringLiteral("dnsDomains")).isArray()) {
            return reject(QStringLiteral("receipt_dns_schema"));
        }
        m_dnsInterface = object.value(QStringLiteral("dnsInterface")).toString();
        for (const QJsonValue &value : object.value(QStringLiteral("dnsServers")).toArray()) {
            if (!value.isString()) return reject(QStringLiteral("receipt_dns_server_type"));
            m_dnsServers.append(value.toString());
        }
        for (const QJsonValue &value : object.value(QStringLiteral("dnsDomains")).toArray()) {
            if (!value.isString()) return reject(QStringLiteral("receipt_dns_domain_type"));
            m_dnsDomains.append(value.toString());
        }
        if (m_dnsInterface.isEmpty() != m_dnsServers.isEmpty()
            || m_dnsServers.isEmpty() != m_dnsDomains.isEmpty()) {
            return reject(QStringLiteral("receipt_dns_cardinality"));
        }
        if (!m_dnsInterface.isEmpty()
            && (!validInterfaceName(m_dnsInterface)
                || (!interfaceName.isEmpty() && m_dnsInterface != interfaceName))) {
            return reject(QStringLiteral("receipt_dns_interface"));
        }
    }
    m_mode = mode;
    m_interfaceName = interfaceName;
    m_routes = bounded;
    m_bypassRoutes = boundedBypass;
    m_criticalBypassRoutes = boundedCritical;
    int storedBypassPriority = 0;
    int storedFullPriority = 0;
    if (!strictInt(object.value(QStringLiteral("bypassRulePriority")),
                   FullTunnelBypassRulePriority, 1099, &storedBypassPriority)
        || !strictInt(object.value(QStringLiteral("fullRulePriority")),
                      FullTunnelRulePriority, FullTunnelPriorityLimit, &storedFullPriority)) {
        return reject(QStringLiteral("receipt_priorities_schema"));
    }
    if (storedBypassPriority < FullTunnelBypassRulePriority
        || storedBypassPriority > 1099
        || storedFullPriority < FullTunnelRulePriority
        || storedFullPriority > FullTunnelPriorityLimit
        || storedBypassPriority >= storedFullPriority) {
        return reject(QStringLiteral("receipt_priorities_order"));
    }
    m_bypassRulePriority = storedBypassPriority;
    m_fullRulePriority = storedFullPriority;
    const bool hasNeedsReapplyField = object.contains(QStringLiteral("needsReapply"));
    const bool persistedNeedsReapply = object.value(QStringLiteral("needsReapply")).toBool();
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
        return reject(QStringLiteral("kernel_snapshot"));
    }
    {
        RuleSnapshot snapshot = readRuleSnapshot();
        if (!snapshot.valid) return reject(QStringLiteral("kernel_snapshot"));
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
                if (!m_statePath.isEmpty() && !routeLock) {
                    return reject(QStringLiteral("legacy_migration_lock"));
                }
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
                    return reject(QStringLiteral("legacy_migration_intent"));
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
                        QString prefix;
                        migrated = migrated
                                && parseManagedFullTunnelRouteLine(line, interfaceName, &prefix);
                        if (!prefix.isEmpty()) migratedPrefixes.insert(prefix);
                    }
                    QSet<QString> expectedPrefixes;
                    for (const QString &prefix : managedFullTunnelRoutePrefixes()) {
                        expectedPrefixes.insert(prefix);
                    }
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
                    return reject(QStringLiteral("legacy_migration_rollback"));
                }
                if (!clearTransactionIntent()) {
                    markRecoveryRequired(QStringLiteral("legacy route protocol migration intent could not be retired"));
                    return reject(QStringLiteral("legacy_migration_intent"));
                }
            }
        }
        if (mode == QStringLiteral("only-forward") && !snapshot.tableLines.isEmpty()) {
            return reject(QStringLiteral("only_forward_table"));
        }
        if (mode == QStringLiteral("only-forward")) {
            // A clean only-forward receipt must not coexist with a previous
            // all-except rule left by a crash (including dynamically selected
            // 1001/1002... priorities).  These objects are only evidence of an
            // orphan, never permission to delete a foreign rule.
            for (const QStringList *familyLines : { &snapshot.linesV4, &snapshot.linesV6 }) {
                for (const QString &line : *familyLines) {
                    int priority = 0;
                    ManagedRuleKind kind = ManagedRuleKind::None;
                    if (!parseManagedRuleLine(line, &priority, &kind)) continue;
                    if (kind == ManagedRuleKind::FullTunnel
                            && priority >= FullTunnelRulePriority
                            && priority <= FullTunnelPriorityLimit) {
                        return reject(QStringLiteral("only_forward_full_rule"));
                    }
                }
            }
        }
        if (mode == QStringLiteral("only-forward")) {
            for (const QString &line : snapshot.mainRouteLines) {
                QString prefix;
                QString routeInterface;
                if (parseManagedMainRouteLine(line, &prefix, &routeInterface)
                    && (!routes.contains(prefix) || routeInterface != interfaceName)) {
                    return reject(QStringLiteral("only_forward_main_route"));
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
                    return reject(QStringLiteral("only_forward_route"));
                }
            }
            for (const QString &route : bounded) {
                if (!std::any_of(snapshot.mainRouteLines.cbegin(), snapshot.mainRouteLines.cend(),
                                 [&route, &interfaceName](const QString &line) {
                    return managedMainRouteLineMatches(line, route, interfaceName);
                })) {
                    return reject(QStringLiteral("only_forward_route_missing"));
                }
            }
        }
        if (mode == QStringLiteral("all-except")) {
            // On a systemd/backend restart the native interface can vanish
            // while the receipt-bound v4/v6 policy rules remain.  A missing
            // table is safe to recover only when the interface is proven
            // absent/down and the rules are exact; partial/foreign state
            // remains a manual-recovery condition.
            bool interfaceOffline = false;
            if (snapshot.tableLines.isEmpty()) {
                const CommandResult interfaceProbe = m_runner->runCaptured(
                        ipExecutable(), { QStringLiteral("link"), QStringLiteral("show"),
                                          QStringLiteral("dev"), interfaceName });
                if (!interfaceProbe.ok) {
                    if (!commandIndicatesMissingInterface(interfaceProbe)) {
                        return reject(QStringLiteral("all_except_link_probe"));
                    }
                    interfaceOffline = true;
                } else {
                    // An empty managed table is reconnectable when the native
                    // interface is absent or explicitly DOWN.  A successful
                    // link probe without unambiguous DOWN evidence (including
                    // an UP link) is an ambiguous present-interface/empty-table
                    // state and must recover manually.
                    const QRegularExpression linkLine(QStringLiteral(
                        "(?m)^\\s*\\d+:\\s*%1(?:[@:]|\\s).*$")
                        .arg(QRegularExpression::escape(interfaceName)));
                    const QRegularExpressionMatch linkMatch = linkLine.match(interfaceProbe.output);
                    if (!linkMatch.hasMatch()) {
                        return reject(QStringLiteral("all_except_link_identity"));
                    }
                    const QString link = linkMatch.captured(0).toUpper();
                    const bool up = QRegularExpression(
                            QStringLiteral("<[^>]*\\bUP\\b[^>]*>|\\bSTATE\\s+UP\\b"))
                            .match(link).hasMatch();
                    const bool down = QRegularExpression(
                            QStringLiteral("<[^>]*\\bDOWN\\b[^>]*>|\\bSTATE\\s+DOWN\\b"))
                            .match(link).hasMatch();
                    if (up || !down) return reject(QStringLiteral("all_except_link_state"));
                    interfaceOffline = true;
                }
            }
            if (interfaceOffline && snapshot.tableLines.isEmpty()) {
                // Keep the strict rule validation below, then expose this as
                // reconnectable offline state rather than live full tunnel.
                m_needsReapply = true;
                m_interfaceOffline = true;
            }
            // `needsReapply` is derived startup state, not an ownership
            // assertion.  A stale persisted value must never mask an exact
            // kernel transition (for example, a clean receipt after the
            // interface disappeared during restart).  The type is validated
            // above, while the value is reconciled and rewritten below.
            QSet<QString> tablePrefixes;
            for (const QString &line : snapshot.tableLines) {
                QString prefix;
                if (!parseManagedFullTunnelRouteLine(line, interfaceName, &prefix)) {
                    return reject(QStringLiteral("all_except_table_route"));
                }
                if (tablePrefixes.contains(prefix)) {
                    return reject(QStringLiteral("all_except_table_duplicate"));
                }
                tablePrefixes.insert(prefix);
            }
            if ((!m_needsReapply && snapshot.tableLines.size() != 4)
                || (m_needsReapply && !snapshot.tableLines.isEmpty())
                || !snapshot.ownedFullV4.contains(storedFullPriority)
                || !snapshot.ownedFullV6.contains(storedFullPriority)) {
                return reject(QStringLiteral("all_except_table_shape"));
            }
            for (const QStringList *familyLines : { &snapshot.linesV4, &snapshot.linesV6 }) {
                for (const QString &line : *familyLines) {
                    int broadPriority = 0;
                    if (parseBroadMainRuleLine(line, &broadPriority)
                        && broadPriority < storedFullPriority) {
                        return reject(QStringLiteral("all_except_reserved_rule"));
                    }
                }
            }
            const auto validReservedRules = [this, &reject, storedBypassPriority, storedFullPriority](
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
                        || parsedPriority != priority) {
                        return reject(QStringLiteral("all_except_reserved_rule"));
                    }
                    if (priority == storedFullPriority) {
                        if (kind != ManagedRuleKind::FullTunnel || ++fullRules > 1) {
                            return reject(QStringLiteral("all_except_full_rule"));
                        }
                    } else {
                        if (ipv6 || kind != ManagedRuleKind::Bypass
                            || !m_bypassRoutes.contains(destination)
                            || bypasses.contains(destination)) {
                            return reject(QStringLiteral("all_except_bypass_rule"));
                        }
                        bypasses.insert(destination);
                    }
                }
                if (fullRules != 1) return reject(QStringLiteral("all_except_full_rule_count"));
                if (requireBypassRoutes) {
                    for (const QString &route : m_bypassRoutes) {
                        if (!bypasses.contains(route)) {
                            return reject(QStringLiteral("all_except_bypass_missing"));
                        }
                    }
                }
                return true;
            };
            if (!validReservedRules(snapshot.linesV4, false, true)
                || !validReservedRules(snapshot.linesV6, true, false)) {
                return reject(QStringLiteral("all_except_reserved_rules"));
            }
            // Only the daemon's dynamic bypass namespace is an orphan
            // indicator.  A narrow `to ... lookup main` rule at priority 1000
            // is commonly owned by the underlay/network manager and is
            // intentionally preserved unless this receipt itself still owns
            // the legacy 1000 slot.  Likewise, selectors outside 1001..1099
            // are not attributable to this daemon; broad main preemptors are
            // checked independently above.
            for (const QStringList *familyLines : { &snapshot.linesV4, &snapshot.linesV6 }) {
                for (const QString &line : *familyLines) {
                    int priority = 0;
                    ManagedRuleKind kind = ManagedRuleKind::None;
                    QString destination;
                    if (!parseManagedRuleLine(line, &priority, &kind, &destination)) continue;
                    if (kind == ManagedRuleKind::FullTunnel
                        && priority != storedFullPriority) {
                        return reject(QStringLiteral("all_except_foreign_full_rule"));
                    }
                    const bool daemonManagedBypassPriority =
                            (priority >= FullTunnelBypassPreferredPriority
                             && priority <= FullTunnelBypassPriorityLimit)
                            || (priority == FullTunnelBypassRulePriority
                                && storedBypassPriority == FullTunnelBypassRulePriority);
                    if (kind == ManagedRuleKind::Bypass && daemonManagedBypassPriority
                        && (priority != storedBypassPriority
                            || !m_bypassRoutes.contains(destination))) {
                        return reject(QStringLiteral("all_except_foreign_bypass_rule"));
                    }
                }
            }
        }
    }
    // DNS bindings are independent from the route receipt.  A persisted DNS
    // owner requires a resolver probe because cleanup cannot be verified
    // without resolvectl.  The one reconnectable exception is an exact
    // all-except receipt whose VPN link is absent/down and whose link-scoped
    // resolver binding disappeared with it.  Keep the desired DNS fields in
    // the receipt so the next autoconnect can reapply them and verify the
    // exact resolver readback.  A present/up link, a mismatched DNS owner, or
    // an ambiguous resolver failure remains fail-closed.
    const auto reconnectableOffline = [this, &mode, &interfaceName]() {
        if (!m_needsReapply || !m_interfaceOffline
            || mode != QStringLiteral("all-except")
            || m_dnsInterface.isEmpty() || m_dnsInterface != interfaceName) {
            return false;
        }
        return true;
    };
    if (resolverRequired()) {
        const QString resolver = resolvectlExecutable();
        if (resolver.isEmpty()) return reject(QStringLiteral("dns_resolver_unavailable"));
        const CommandResult linkProbe = m_runner->runCaptured(
                resolver, { QStringLiteral("status"), m_dnsInterface });
        const bool resolverBindingMissing = linkProbe.ok
                ? !resolverOutputHasManagedBinding(linkProbe.output)
                : commandIndicatesMissingInterface(linkProbe);
        const bool resolverMissingForReconnect = reconnectableOffline()
                && resolverBindingMissing;
        if (!resolverMissingForReconnect
            && (!linkProbe.ok || resolverBindingMissing || !resolverProbeHealthy())) {
            return reject(QStringLiteral("dns_binding"));
        }
        if (resolverMissingForReconnect) {
            qInfo().noquote() << QStringLiteral(
                    "LinuxRouteReconciler retaining DNS receipt for offline all-except reapply interface=%1")
                    .arg(m_dnsInterface);
        }
    }

    // 5.0.1.18 receipts used 1000 as the only-forward default even though no
    // bypass rule was owned in that mode.  Normalize that legacy field while
    // retaining any foreign kernel rule at 1000; the next fresh all-except
    // transition will therefore choose the new 1001 starting slot.
    if (mode == QStringLiteral("only-forward")
        && storedBypassPriority == FullTunnelBypassRulePriority) {
        m_bypassRulePriority = FullTunnelBypassPreferredPriority;
        if (!saveState()) return reject(QStringLiteral("save_state_rewrite"));
    }
    if (m_needsReapply && (mode != QStringLiteral("all-except") || !m_interfaceOffline)) {
        return reject(QStringLiteral("needs_reapply_state"));
    }
    if (!m_needsReapply) m_interfaceOffline = false;
    if ((!hasNeedsReapplyField || persistedNeedsReapply != m_needsReapply)
        && !saveState()) {
        return reject(QStringLiteral("save_state_rewrite"));
    }
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
        { QStringLiteral("criticalBypassRoutes"), QJsonArray::fromStringList(m_criticalBypassRoutes) },
        { QStringLiteral("bypassRulePriority"), m_bypassRulePriority },
        { QStringLiteral("fullRulePriority"), m_fullRulePriority },
        { QStringLiteral("dnsInterface"), m_dnsInterface },
        { QStringLiteral("dnsServers"), QJsonArray::fromStringList(m_dnsServers) },
        { QStringLiteral("dnsDomains"), QJsonArray::fromStringList(m_dnsDomains) },
        { QStringLiteral("postconditionDiagnostics"), m_lastDiagnostics },
        { QStringLiteral("needsReapply"), m_needsReapply },
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
        bool exact = false;
        bool ambiguous = false;
        for (const QString &line : snapshot.mainRouteLines) {
            QString parsedPrefix;
            QString parsedInterface;
            if (!parseManagedMainRouteLine(line, &parsedPrefix, &parsedInterface)
                || parsedPrefix != canonicalRuleDestination(route)) continue;
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
        for (const QString &line : snapshot.mainRouteLines) {
            QString parsedPrefix;
            QString parsedInterface;
            if (parseManagedMainRouteLine(line, &parsedPrefix, &parsedInterface)
                && parsedPrefix == canonicalRuleDestination(route)
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
