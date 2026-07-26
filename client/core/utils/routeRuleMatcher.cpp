#include "routeRuleMatcher.h"

#include <QAbstractSocket>
#include <QRegularExpression>
#include <QUrl>

#include <algorithm>

namespace amnezia::routeRuleMatcher
{
namespace
{
QString bounded(const QString &value, int maximumLength)
{
    return value.left(maximumLength);
}

bool hasControlCharacters(const QString &value)
{
    return std::any_of(value.cbegin(), value.cend(), [](QChar character) {
        return character.category() == QChar::Other_Control;
    });
}

bool isValidAceHostname(const QString &host)
{
    if (host.isEmpty() || host.size() > maximumHostLength) {
        return false;
    }

    static const QRegularExpression labelExpression(
            QStringLiteral("^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"));
    const QStringList labels = host.split(QLatin1Char('.'), Qt::KeepEmptyParts);
    for (const QString &label : labels) {
        if (label.size() > 63 || !labelExpression.match(label).hasMatch()) {
            return false;
        }
    }
    return true;
}

bool hasForbiddenBareHostCharacter(const QString &input)
{
    return std::any_of(input.cbegin(), input.cend(), [](QChar character) {
        const QChar::Category category = character.category();
        return character.isNull() || character.isSpace()
                || category == QChar::Other_Control
                || category == QChar::Other_Format
                || category == QChar::Other_Surrogate
                || category == QChar::Other_PrivateUse
                || category == QChar::Other_NotAssigned;
    });
}

NormalizedTarget normalizeTargetImpl(const QString &input, InputPolicy inputPolicy)
{
    NormalizedTarget target;
    const bool bareHostOnly = inputPolicy == InputPolicy::BareHostOrAddress;
    const QString trimmed = bareHostOnly ? input : input.trimmed();
    if (trimmed.isEmpty()) {
        target.error = QStringLiteral("host_required");
        return target;
    }
    if (trimmed.size() > maximumInputLength
        || (bareHostOnly ? hasForbiddenBareHostCharacter(trimmed)
                         : hasControlCharacters(trimmed))) {
        target.error = QStringLiteral("invalid_host");
        return target;
    }

    QString candidate = trimmed;
    if (candidate.startsWith(QLatin1Char('[')) && candidate.endsWith(QLatin1Char(']'))) {
        candidate = candidate.mid(1, candidate.size() - 2);
    }

    QHostAddress literalAddress;
    if (literalAddress.setAddress(candidate)) {
        if (!literalAddress.scopeId().isEmpty()) {
            target.error = QStringLiteral("scoped_ipv6_not_supported");
            return target;
        }
        target.literalAddress = literalAddress;
        target.host = literalAddress.toString().toLower();
        return target;
    }

    QString hostname;
    if (bareHostOnly) {
        if (trimmed.contains(QLatin1Char(':')) || trimmed.contains(QLatin1Char('/'))
            || trimmed.contains(QLatin1Char('\\')) || trimmed.contains(QLatin1Char('@'))
            || trimmed.contains(QLatin1Char('?')) || trimmed.contains(QLatin1Char('#'))
            || trimmed.contains(QLatin1Char('%'))) {
            target.error = QStringLiteral("invalid_host");
            return target;
        }
        hostname = trimmed;
    } else {
        const bool hasScheme = trimmed.contains(QStringLiteral("://"));
        const bool needsUrlParsing = hasScheme || trimmed.startsWith(QStringLiteral("//"))
                || trimmed.contains(QLatin1Char('/')) || trimmed.contains(QLatin1Char('?'))
                || trimmed.contains(QLatin1Char('#')) || trimmed.contains(QLatin1Char('@'))
                || trimmed.contains(QLatin1Char(':'));
        if (needsUrlParsing) {
            QString urlText = trimmed;
            if (urlText.startsWith(QStringLiteral("//"))) {
                urlText.prepend(QStringLiteral("route:"));
            } else if (!hasScheme) {
                urlText.prepend(QStringLiteral("route://"));
            }
            const QUrl url(urlText, QUrl::StrictMode);
            if (!url.isValid() || url.host().isEmpty()) {
                target.error = QStringLiteral("invalid_host");
                return target;
            }
            hostname = url.host();
        } else {
            hostname = trimmed;
        }
    }

    while (hostname.endsWith(QLatin1Char('.'))) {
        hostname.chop(1);
    }

    if (literalAddress.setAddress(hostname)) {
        if (!literalAddress.scopeId().isEmpty()) {
            target.error = QStringLiteral("scoped_ipv6_not_supported");
            return target;
        }
        target.literalAddress = literalAddress;
        target.host = literalAddress.toString().toLower();
        return target;
    }

    const QByteArray ace = QUrl::toAce(hostname);
    const QString normalized = QString::fromLatin1(ace).toLower();
    if (!isValidAceHostname(normalized)) {
        target.error = QStringLiteral("invalid_host");
        return target;
    }

    target.host = normalized;
    return target;
}

bool addressMatchesRoute(const QHostAddress &address, const QString &route,
                         int *prefixLength = nullptr)
{
    if (address.isNull()) {
        return false;
    }

    const QString trimmedRoute = route.trimmed();
    QHostAddress routeAddress;
    if (!trimmedRoute.contains(QLatin1Char('/')) && routeAddress.setAddress(trimmedRoute)) {
        if (prefixLength) {
            *prefixLength = routeAddress.protocol() == QAbstractSocket::IPv4Protocol ? 32 : 128;
        }
        return address == routeAddress;
    }

    const QPair<QHostAddress, int> subnet = QHostAddress::parseSubnet(trimmedRoute);
    if (subnet.second < 0 || subnet.first.protocol() != address.protocol()) {
        return false;
    }
    if (prefixLength) {
        *prefixLength = subnet.second;
    }
    return address.isInSubnet(subnet.first, subnet.second);
}

bool isIpv4HostOrCidr(const QString &route)
{
    const QString trimmed = route.trimmed();
    if (!trimmed.contains(QLatin1Char('/'))) {
        return QHostAddress(trimmed).protocol() == QAbstractSocket::IPv4Protocol;
    }

    const QStringList parts = trimmed.split(QLatin1Char('/'));
    if (parts.size() != 2
        || QHostAddress(parts.at(0)).protocol() != QAbstractSocket::IPv4Protocol) {
        return false;
    }
    bool ok = false;
    const int prefixLength = parts.at(1).toInt(&ok);
    return ok && prefixLength >= 0 && prefixLength <= 32;
}

bool isStoredRouteSeparator(QChar character)
{
    return character == QLatin1Char(',') || character == QLatin1Char(';')
            || character.isSpace();
}

QStringList storedRouteTokens(const QVariant &value, bool *coverageComplete)
{
    const QString rawValue = value.toString();
    const bool rawValueBounded = rawValue.size() <= maximumRawStoredValueLength;
    const QString boundedValue = rawValue.left(maximumRawStoredValueLength);
    QStringList tokens;
    bool tokenLimitReached = false;

    // Do not split an attacker-sized value into an attacker-sized temporary
    // list. Scan the bounded prefix and retain at most the documented number
    // of route tokens. A token cut by the raw-value boundary is discarded.
    int cursor = 0;
    while (cursor < boundedValue.size()) {
        while (cursor < boundedValue.size()
               && isStoredRouteSeparator(boundedValue.at(cursor))) {
            ++cursor;
        }
        if (cursor >= boundedValue.size()) {
            break;
        }

        const int tokenStart = cursor;
        while (cursor < boundedValue.size()
               && !isStoredRouteSeparator(boundedValue.at(cursor))) {
            ++cursor;
        }
        const bool tokenComplete = cursor < boundedValue.size() || rawValueBounded;
        const int tokenLength = cursor - tokenStart;
        if (tokenComplete && tokenLength <= maximumStoredRouteLength) {
            const QString route = boundedValue.mid(tokenStart, tokenLength);
            if (isIpv4HostOrCidr(route) && !tokens.contains(route)) {
                if (tokens.size() >= maximumStoredRoutesPerRule) {
                    tokenLimitReached = true;
                    break;
                }
                tokens.append(route);
            }
        }
    }

    if (coverageComplete) {
        *coverageComplete = rawValueBounded && !tokenLimitReached;
    }
    return tokens;
}

QString normalizedDomainRule(const QString &rawRule)
{
    const NormalizedTarget target = normalizeTargetImpl(
            rawRule.trimmed().toLower(), InputPolicy::BareHostOrAddress);
    if (!target.error.isEmpty() || !target.literalAddress.isNull()) {
        return {};
    }
    return target.host;
}

QString privacySafeRule(const QString &rawRule)
{
    const QString trimmedRule = rawRule.trimmed();
    const QPair<QHostAddress, int> subnet = QHostAddress::parseSubnet(trimmedRule);
    if (subnet.second >= 0) {
        const int maximumPrefix = subnet.first.protocol() == QAbstractSocket::IPv4Protocol ? 32 : 128;
        if (subnet.second <= maximumPrefix) {
            const int exactPrefix = maximumPrefix;
            return subnet.second == exactPrefix && !trimmedRule.contains(QLatin1Char('/'))
                    ? subnet.first.toString().toLower()
                    : QStringLiteral("%1/%2")
                              .arg(subnet.first.toString().toLower())
                              .arg(subnet.second);
        }
    }

    const QString domainRule = normalizedDomainRule(trimmedRule);
    if (!domainRule.isEmpty()) {
        return domainRule;
    }
    return QStringLiteral("configured-rule");
}

quint32 ipv4Mask(int prefixLength)
{
    return prefixLength == 0 ? 0 : (0xffffffffu << (32 - prefixLength));
}

bool parseIpv4Route(const QString &route, quint32 &address, int &prefixLength)
{
    const QStringList routeParts = route.trimmed().split(QLatin1Char('/'));
    if (routeParts.isEmpty() || routeParts.size() > 2) {
        return false;
    }

    const QHostAddress routeAddress(routeParts.at(0));
    if (routeAddress.protocol() != QAbstractSocket::IPv4Protocol) {
        return false;
    }

    address = routeAddress.toIPv4Address();
    prefixLength = 32;
    if (routeParts.size() == 1) {
        return true;
    }

    bool prefixOk = false;
    prefixLength = routeParts.at(1).toInt(&prefixOk);
    return prefixOk && prefixLength >= 0 && prefixLength <= 32;
}

bool routeOverlapsIpv4Range(quint32 address, int prefixLength,
                            quint32 base, int rangePrefixLength)
{
    const quint32 routeStart = address & ipv4Mask(prefixLength);
    const quint32 routeEnd = routeStart | ~ipv4Mask(prefixLength);
    const quint32 rangeStart = base & ipv4Mask(rangePrefixLength);
    const quint32 rangeEnd = rangeStart | ~ipv4Mask(rangePrefixLength);
    return routeStart <= rangeEnd && rangeStart <= routeEnd;
}

bool isCanonicalRuntimeIpv4Route(const QString &route)
{
    quint32 address = 0;
    int prefixLength = 32;
    return parseIpv4Route(route, address, prefixLength)
            && (address & ipv4Mask(prefixLength)) == address;
}

bool isRoutableClientRoute(const QString &route)
{
    constexpr int minimumPublicBypassPrefixLength = 16;
    constexpr int minimumLocalBypassPrefixLength = 24;
    quint32 address = 0;
    int prefixLength = 32;
    if (!parseIpv4Route(route, address, prefixLength) || prefixLength == 0) {
        return false;
    }

    const QHostAddress hostAddress(address);
    const auto inRange = [address](quint32 base, int prefix) {
        const quint32 mask = ipv4Mask(prefix);
        return (address & mask) == (base & mask);
    };
    const auto overlaps = [address, prefixLength](quint32 base, int prefix) {
        return routeOverlapsIpv4Range(address, prefixLength, base, prefix);
    };
    if (prefixLength < 32 && (address & ipv4Mask(prefixLength)) != address) {
        return false;
    }

    if (hostAddress.isNull() || hostAddress.isLoopback() || hostAddress.isBroadcast()
        || hostAddress.isLinkLocal() || hostAddress.isMulticast()) {
        return false;
    }
    const bool localOrServiceRoute = inRange(0x0a000000u, 8)
            || inRange(0x64400000u, 10) || inRange(0xac100000u, 12)
            || inRange(0xc0a80000u, 16);
    if (overlaps(0x00000000u, 8) || overlaps(0x7f000000u, 8)
        || overlaps(0xc0000000u, 24) || overlaps(0xc0000200u, 24)
        || overlaps(0xc01f0000u, 24) || overlaps(0xc01fc400u, 24)
        || overlaps(0xc034c100u, 24) || overlaps(0xc0586300u, 24)
        || overlaps(0xc0af3000u, 24) || overlaps(0xc6120000u, 15)
        || overlaps(0xc6336400u, 24) || overlaps(0xcb007100u, 24)
        || overlaps(0xe0000000u, 4) || overlaps(0xf0000000u, 4)) {
        return false;
    }

    const int minimumPrefixLength = localOrServiceRoute
            ? minimumLocalBypassPrefixLength : minimumPublicBypassPrefixLength;
    return prefixLength >= minimumPrefixLength;
}

void considerMatch(RuleMatch &best, const QString &source,
                   const QString &rule, const QString &configuredRule,
                   const QVariant &configuredValue, const QString &matchType,
                   int score, const QString &safetyTransform = {})
{
    const bool localTieBreaker = score == best.score && source == QStringLiteral("local")
            && best.source != QStringLiteral("local");
    if (!best.matched || score > best.score || localTieBreaker) {
        best.matched = true;
        best.source = source;
        best.rule = bounded(rule, maximumRuleOutputLength);
        best.configuredRule = configuredRule;
        const QString matchedValue = configuredValue.toString();
        best.matchedValueTruncated = matchedValue.size() > maximumMatchedValueLength;
        best.matchedValue = matchedValue.left(maximumMatchedValueLength);
        best.matchType = matchType;
        best.safetyTransform = safetyTransform;
        best.score = score;
    }
}

void inspectRules(const QVariantMap &rules, const QString &source,
                  const QString &host, const QHostAddress &address,
                  DomainMatchPolicy domainMatchPolicy, MatchResult &result)
{
    const bool trustedManaged = source == QStringLiteral("managed");
    const bool mapTruncated = rules.size() > maximumRulesPerSource;
    if (trustedManaged) {
        result.managedRulesTruncated = mapTruncated;
    } else {
        result.localRulesTruncated = mapTruncated;
    }
    result.coverageComplete = result.coverageComplete && !mapTruncated;
    const QString rejectionReason = trustedManaged
            ? QStringLiteral("unsupported_managed_cidr_rejected")
            : QStringLiteral("client_cidr_rejected");

    int inspectedRules = 0;
    for (auto it = rules.constBegin(); it != rules.constEnd(); ++it) {
        if (inspectedRules >= maximumRulesPerSource) {
            break;
        }
        ++inspectedRules;
        if (trustedManaged) {
            ++result.managedRulesInspected;
        } else {
            ++result.localRulesInspected;
        }
        if (it.key().size() > maximumInputLength) {
            result.coverageComplete = false;
            result.storedValuesTruncated = true;
            continue;
        }
        const QString rawRule = it.key().trimmed();
        if (rawRule.isEmpty()) {
            continue;
        }

        int prefixLength = -1;
        const bool keyIsRuntimeRoute = isIpv4HostOrCidr(rawRule);
        const bool keyMatched = keyIsRuntimeRoute
                && addressMatchesRoute(address, rawRule, &prefixLength);
        if (keyMatched) {
            if ((trustedManaged && isCanonicalRuntimeIpv4Route(rawRule))
                || (!trustedManaged && isRoutableClientRoute(rawRule))) {
                considerMatch(result.accepted, source, privacySafeRule(rawRule),
                              it.key(), it.value(),
                              QStringLiteral("address"), addressScoreBase + prefixLength);
            } else {
                considerMatch(result.rejected, source, privacySafeRule(rawRule),
                              it.key(), it.value(),
                              QStringLiteral("address"), addressScoreBase + prefixLength,
                              rejectionReason);
            }
        }

        if (!keyMatched) {
            const QString domainRule = normalizedDomainRule(rawRule);
            if (!domainRule.isEmpty() && host == domainRule
                && domainMatchPolicy == DomainMatchPolicy::PolicyOnly) {
                considerMatch(result.accepted, source, domainRule,
                              it.key(), it.value(), QStringLiteral("domain"),
                              domainScoreBase + domainRule.size());
            } else if (address.protocol() == QAbstractSocket::IPv4Protocol
                       && !domainRule.isEmpty() && host == domainRule) {
                const QString hostRoute = address.toString();
                if ((trustedManaged && isCanonicalRuntimeIpv4Route(hostRoute))
                    || (!trustedManaged && isRoutableClientRoute(hostRoute))) {
                    considerMatch(result.accepted, source, domainRule,
                                  it.key(), it.value(),
                                  QStringLiteral("domain"),
                                  domainScoreBase + domainRule.size());
                } else {
                    considerMatch(result.rejected, source, domainRule,
                                  it.key(), it.value(),
                                  QStringLiteral("domain"),
                                  domainScoreBase + domainRule.size(), rejectionReason);
                }
            }
        }

        bool storedValueComplete = true;
        const QStringList storedRoutes = storedRouteTokens(
                it.value(), &storedValueComplete);
        if (!storedValueComplete) {
            result.coverageComplete = false;
            result.storedValuesTruncated = true;
        }
        for (const QString &storedRoute : storedRoutes) {
            if (!addressMatchesRoute(address, storedRoute, &prefixLength)) {
                continue;
            }
            if ((trustedManaged && isCanonicalRuntimeIpv4Route(storedRoute))
                || (!trustedManaged && isRoutableClientRoute(storedRoute))) {
                considerMatch(result.accepted, source, privacySafeRule(rawRule),
                              it.key(), it.value(),
                              QStringLiteral("resolvedAddress"),
                              resolvedAddressScoreBase + prefixLength);
            } else {
                considerMatch(result.rejected, source, privacySafeRule(rawRule),
                              it.key(), it.value(),
                              QStringLiteral("resolvedAddress"),
                              resolvedAddressScoreBase + prefixLength, rejectionReason);
            }
        }
    }
}
}

NormalizedTarget normalizeTarget(const QString &input, InputPolicy inputPolicy)
{
    return normalizeTargetImpl(input, inputPolicy);
}

MatchResult matchRules(const QVariantMap &localRules,
                       const QVariantMap &managedRules,
                       const QString &host,
                       const QHostAddress &resolvedAddress,
                       DomainMatchPolicy domainMatchPolicy)
{
    MatchResult result;
    const NormalizedTarget normalized = normalizeTargetImpl(
            host, InputPolicy::BareHostOrAddress);
    const QString canonicalHost = normalized.error.isEmpty()
            && normalized.literalAddress.isNull() ? normalized.host : QString();
    inspectRules(localRules, QStringLiteral("local"), canonicalHost,
                 resolvedAddress, domainMatchPolicy, result);
    inspectRules(managedRules, QStringLiteral("managed"), canonicalHost,
                 resolvedAddress, domainMatchPolicy, result);
    return result;
}
}
