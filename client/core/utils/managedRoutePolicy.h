#ifndef MANAGEDROUTEPOLICY_H
#define MANAGEDROUTEPOLICY_H

#include <QCryptographicHash>
#include <QDateTime>
#include <QHostAddress>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>
#include <QString>
#include <QStringList>
#include <QTimeZone>
#include <QUrl>
#include <QVariant>
#include <QtGlobal>
#include <cmath>
#include <initializer_list>
#include <optional>

namespace amnezia
{

// Metadata is retained even after expiry so diagnostics can explain why a
// managed route policy is no longer effective. `contentHash` always describes
// the source rules and force flag that are actually stored on the client;
// mutable DNS results are deliberately outside that identity.
struct ManagedRoutePolicyMetadata
{
    int schemaVersion = 1;
    QString revision;
    qint64 revisionNumber = -1;
    bool versioned = false;
    QString contentHash;
    QString declaredContentHash;
    bool contentMatchesDeclaration = true;
    QDateTime issuedAt;
    QDateTime expiresAt;
    QDateTime acceptedAt;
    QString source;
    // Route-policy payloads currently have no configured trust anchor. A
    // matching digest provides integrity consistency, not authenticity.
    QString trustState = QStringLiteral("unsigned");

    bool isExpired(const QDateTime &now = QDateTime::currentDateTimeUtc()) const
    {
        return expiresAt.isValid() && expiresAt <= now.toUTC();
    }

    QJsonObject toJson() const
    {
        QJsonObject json;
        json.insert(QStringLiteral("schemaVersion"), schemaVersion);
        json.insert(QStringLiteral("policyType"), versioned ? QStringLiteral("versioned")
                                                             : QStringLiteral("legacy"));
        json.insert(QStringLiteral("revision"), revision);
        if (versioned && revisionNumber >= 0) {
            json.insert(QStringLiteral("revisionNumber"), static_cast<double>(revisionNumber));
        }
        if (!contentHash.isEmpty()) {
            json.insert(QStringLiteral("contentHash"), contentHash);
        }
        if (!declaredContentHash.isEmpty()) {
            json.insert(QStringLiteral("declaredContentHash"), declaredContentHash);
        }
        json.insert(QStringLiteral("contentMatchesDeclaration"), contentMatchesDeclaration);
        json.insert(QStringLiteral("trustState"), trustState.isEmpty() ? QStringLiteral("unsigned") : trustState);
        if (issuedAt.isValid()) {
            json.insert(QStringLiteral("issuedAt"), issuedAt.toUTC().toString(Qt::ISODateWithMs));
        }
        if (expiresAt.isValid()) {
            json.insert(QStringLiteral("expiresAt"), expiresAt.toUTC().toString(Qt::ISODateWithMs));
        }
        if (acceptedAt.isValid()) {
            json.insert(QStringLiteral("acceptedAt"), acceptedAt.toUTC().toString(Qt::ISODateWithMs));
        }
        if (!source.isEmpty()) {
            json.insert(QStringLiteral("source"), source);
        }
        return json;
    }
};

namespace managedRoutePolicy
{

inline constexpr qsizetype maximumSiteCount = 2048;
inline constexpr qsizetype maximumRoutesPerSite = 64;
inline constexpr qsizetype maximumTotalRouteCount = 4096;
inline constexpr qsizetype maximumStoredRouteValueLength = 4096;
inline constexpr qsizetype maximumSiteKeyLength = 253;
inline constexpr qsizetype maximumRouteTokenLength = 18;

inline quint32 ipv4Mask(int prefixLength)
{
    return prefixLength == 0 ? 0 : (0xffffffffu << (32 - prefixLength));
}

inline bool parseCanonicalIpv4Route(const QString &value, quint32 *address = nullptr,
                                    int *prefixLength = nullptr)
{
    const QString route = value.trimmed();
    if (route.size() > maximumRouteTokenLength) {
        return false;
    }
    const QStringList parts = route.split(QLatin1Char('/'));
    if (parts.isEmpty() || parts.size() > 2 || parts.at(0).isEmpty()) {
        return false;
    }

    const QHostAddress host(parts.at(0));
    if (host.protocol() != QAbstractSocket::IPv4Protocol
        || host.toString() != parts.at(0)) {
        return false;
    }

    int prefix = 32;
    if (parts.size() == 2) {
        bool ok = false;
        prefix = parts.at(1).toInt(&ok);
        if (!ok || prefix < 0 || prefix > 32 || QString::number(prefix) != parts.at(1)) {
            return false;
        }
    }

    const quint32 ipv4 = host.toIPv4Address();
    if ((ipv4 & ipv4Mask(prefix)) != ipv4) {
        return false;
    }
    if (address) {
        *address = ipv4;
    }
    if (prefixLength) {
        *prefixLength = prefix;
    }
    return true;
}

inline bool ipv4RouteOverlapsRange(quint32 address, int prefixLength,
                                   quint32 rangeBase, int rangePrefixLength)
{
    const quint32 routeStart = address & ipv4Mask(prefixLength);
    const quint32 routeEnd = routeStart | ~ipv4Mask(prefixLength);
    const quint32 rangeStart = rangeBase & ipv4Mask(rangePrefixLength);
    const quint32 rangeEnd = rangeStart | ~ipv4Mask(rangePrefixLength);
    return routeStart <= rangeEnd && rangeStart <= routeEnd;
}

inline bool ipv4RouteIsWithinRange(quint32 address, int prefixLength,
                                   quint32 rangeBase, int rangePrefixLength)
{
    if (prefixLength < rangePrefixLength) {
        return false;
    }
    const quint32 rangeMask = ipv4Mask(rangePrefixLength);
    return (address & rangeMask) == (rangeBase & rangeMask);
}

// Managed rules may intentionally cover an RFC1918 corporate network, but a
// typo must never turn a connected VPN into a broad public bypass. Public
// routes therefore keep the existing /16 floor, while the three RFC1918 roots
// are explicit reviewed exceptions. Special-purpose ranges remain forbidden.
inline bool isAllowedManagedIpv4Route(const QString &value)
{
    constexpr int minimumPublicPrefixLength = 16;
    quint32 address = 0;
    int prefixLength = 32;
    if (!parseCanonicalIpv4Route(value, &address, &prefixLength) || prefixLength == 0) {
        return false;
    }

    const QHostAddress host(address);
    if (host.isNull() || host.isLoopback() || host.isBroadcast()
        || host.isLinkLocal() || host.isMulticast()) {
        return false;
    }

    if (ipv4RouteOverlapsRange(address, prefixLength, 0x00000000u, 8)
        || ipv4RouteOverlapsRange(address, prefixLength, 0x7f000000u, 8)
        || ipv4RouteOverlapsRange(address, prefixLength, 0x64400000u, 10)
        || ipv4RouteOverlapsRange(address, prefixLength, 0xa9fe0000u, 16)
        || ipv4RouteOverlapsRange(address, prefixLength, 0xc0000000u, 24)
        || ipv4RouteOverlapsRange(address, prefixLength, 0xc0000200u, 24)
        || ipv4RouteOverlapsRange(address, prefixLength, 0xc01f0000u, 24)
        || ipv4RouteOverlapsRange(address, prefixLength, 0xc01fc400u, 24)
        || ipv4RouteOverlapsRange(address, prefixLength, 0xc034c100u, 24)
        || ipv4RouteOverlapsRange(address, prefixLength, 0xc0586300u, 24)
        || ipv4RouteOverlapsRange(address, prefixLength, 0xc0af3000u, 24)
        || ipv4RouteOverlapsRange(address, prefixLength, 0xc6120000u, 15)
        || ipv4RouteOverlapsRange(address, prefixLength, 0xc6336400u, 24)
        || ipv4RouteOverlapsRange(address, prefixLength, 0xcb007100u, 24)
        || ipv4RouteOverlapsRange(address, prefixLength, 0xe0000000u, 4)
        || ipv4RouteOverlapsRange(address, prefixLength, 0xf0000000u, 4)) {
        return false;
    }

    const bool withinRfc1918 = ipv4RouteIsWithinRange(address, prefixLength, 0x0a000000u, 8)
            || ipv4RouteIsWithinRange(address, prefixLength, 0xac100000u, 12)
            || ipv4RouteIsWithinRange(address, prefixLength, 0xc0a80000u, 16);
    return withinRfc1918 || prefixLength >= minimumPublicPrefixLength;
}

// A host and the same host written with an explicit /32 are the same route.
// Normalize that alias before dedupe and resource accounting so the client and
// privileged service enforce exactly the same cumulative budget.
inline QString canonicalManagedIpv4Route(const QString &value)
{
    quint32 address = 0;
    int prefixLength = 32;
    if (!isAllowedManagedIpv4Route(value)
        || !parseCanonicalIpv4Route(value, &address, &prefixLength)) {
        return {};
    }

    const QString host = QHostAddress(address).toString();
    return prefixLength == 32
            ? host
            : QStringLiteral("%1/%2").arg(host).arg(prefixLength);
}

inline QStringList validatedManagedRouteTokens(const QString &value, bool *valid = nullptr)
{
    bool isValid = value.size() <= maximumStoredRouteValueLength;
    QStringList routes;
    if (isValid) {
        static const QRegularExpression separator(QStringLiteral("[,;\\s]+"));
        const QStringList tokens = value.split(separator, Qt::SkipEmptyParts);
        isValid = tokens.size() <= maximumRoutesPerSite;
        for (const QString &token : tokens) {
            const QString route = canonicalManagedIpv4Route(token);
            if (route.isEmpty()) {
                isValid = false;
                break;
            }
            if (!routes.contains(route)) {
                routes.append(route);
            }
        }
    }
    if (!isValid) {
        routes.clear();
    }
    if (valid) {
        *valid = isValid;
    }
    return routes;
}

inline QStringList validatedManagedRoutes(const QStringList &values, bool *valid = nullptr)
{
    bool isValid = values.size() <= maximumTotalRouteCount;
    QStringList routes;
    if (isValid) {
        for (const QString &value : values) {
            const QString route = canonicalManagedIpv4Route(value);
            if (route.isEmpty()) {
                isValid = false;
                break;
            }
            if (!routes.contains(route)) {
                routes.append(route);
                if (routes.size() > maximumTotalRouteCount) {
                    isValid = false;
                    break;
                }
            }
        }
    }
    if (!isValid) {
        routes.clear();
    }
    if (valid) {
        *valid = isValid;
    }
    return routes;
}

inline bool isAllowedManagedSiteKey(const QString &rawSite)
{
    const QString site = rawSite.trimmed().toLower();
    if (site.isEmpty() || site.size() > maximumSiteKeyLength) {
        return false;
    }
    if (site.contains(QLatin1Char('/')) || QHostAddress(site).protocol() != QAbstractSocket::UnknownNetworkLayerProtocol) {
        return isAllowedManagedIpv4Route(site);
    }

    const QByteArray ace = QUrl::toAce(site);
    const QString hostname = QString::fromLatin1(ace).toLower();
    if (hostname.isEmpty() || hostname.size() > maximumSiteKeyLength) {
        return false;
    }
    static const QRegularExpression labelExpression(
            QStringLiteral("^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"));
    const QStringList labels = hostname.split(QLatin1Char('.'), Qt::KeepEmptyParts);
    for (const QString &label : labels) {
        if (label.size() > 63 || !labelExpression.match(label).hasMatch()) {
            return false;
        }
    }
    return true;
}

inline QString stateKey()
{
    return QStringLiteral("managedRoutePolicyState");
}

inline QString lastKnownGoodKey()
{
    return QStringLiteral("lastKnownGood");
}

inline QDateTime dateTimeFromJson(const QJsonValue &value)
{
    QDateTime dateTime;
    if (value.isString()) {
        dateTime = QDateTime::fromString(value.toString(), Qt::ISODateWithMs);
        if (!dateTime.isValid()) {
            dateTime = QDateTime::fromString(value.toString(), Qt::ISODate);
        }
    } else if (value.isDouble()) {
        const qint64 timestamp = value.toVariant().toLongLong();
        dateTime = timestamp > 100000000000LL
                ? QDateTime::fromMSecsSinceEpoch(timestamp, QTimeZone::utc())
                : QDateTime::fromSecsSinceEpoch(timestamp, QTimeZone::utc());
    }
    return dateTime.isValid() ? dateTime.toUTC() : QDateTime();
}

inline QJsonValue firstValue(const QJsonObject &primary, const QJsonObject &fallback,
                             std::initializer_list<const char *> keys)
{
    for (const char *key : keys) {
        const QString stringKey = QString::fromLatin1(key);
        if (primary.contains(stringKey)) {
            return primary.value(stringKey);
        }
    }
    for (const char *key : keys) {
        const QString stringKey = QString::fromLatin1(key);
        if (fallback.contains(stringKey)) {
            return fallback.value(stringKey);
        }
    }
    return QJsonValue(QJsonValue::Undefined);
}

inline bool canonicalRevisionNumber(const QJsonValue &value, qint64 *revision)
{
    // QJson stores numbers as doubles, so only the exactly representable JSON
    // integer range can be accepted without silently changing policy order.
    constexpr double maxExactJsonInteger = 9007199254740991.0;
    if (!value.isDouble()) {
        return false;
    }
    const double number = value.toDouble();
    if (!std::isfinite(number) || number < 1.0 || number > maxExactJsonInteger
        || std::floor(number) != number) {
        return false;
    }
    if (revision) {
        *revision = static_cast<qint64>(number);
    }
    return true;
}

inline bool storedCanonicalRevisionNumber(const QString &value, qint64 *revision)
{
    const QString trimmed = value.trimmed();
    if (trimmed.isEmpty() || (trimmed.size() > 1 && trimmed.startsWith(QLatin1Char('0')))) {
        return false;
    }
    for (const QChar character : trimmed) {
        if (!character.isDigit()) {
            return false;
        }
    }
    bool ok = false;
    const qulonglong number = trimmed.toULongLong(&ok);
    constexpr qulonglong maxExactJsonInteger = 9007199254740991ULL;
    if (!ok || number < 1 || number > maxExactJsonInteger) {
        return false;
    }
    if (revision) {
        *revision = static_cast<qint64>(number);
    }
    return true;
}

inline QString normalizedSha256(const QString &value)
{
    const QString normalized = value.trimmed().toLower();
    if (!normalized.startsWith(QStringLiteral("sha256:")) || normalized.size() != 71) {
        return {};
    }
    for (qsizetype index = 7; index < normalized.size(); ++index) {
        const QChar character = normalized.at(index);
        if (!character.isDigit() && (character < QLatin1Char('a') || character > QLatin1Char('f'))) {
            return {};
        }
    }
    return normalized;
}

inline bool containsSourceSites(const QJsonObject &object)
{
    return object.contains(QStringLiteral("managedSplitTunnelExceptSourceSites"))
            || object.contains(QStringLiteral("managedSplitTunnelExceptSites"))
            || object.contains(QStringLiteral("serverExcept"));
}

inline QJsonValue sourceSitesValue(const QJsonObject &object)
{
    static const QStringList keys = {
        QStringLiteral("managedSplitTunnelExceptSourceSites"),
        QStringLiteral("managedSplitTunnelExceptSites"),
        QStringLiteral("serverExcept"),
    };
    for (const QString &key : keys) {
        const QJsonValue value = object.value(key);
        if (value.isObject() || value.isArray()) {
            return value;
        }
    }
    return QJsonValue(QJsonValue::Undefined);
}

inline QJsonObject canonicalSourceSites(const QJsonValue &value, bool *valid = nullptr)
{
    QJsonObject sites;
    bool isValid = value.isObject() || value.isArray();
    qsizetype totalRouteBudget = 0;
    const auto insertSite = [&sites, &isValid, &totalRouteBudget](const QString &rawSite,
                                                                 const QJsonValue &rawValue) {
        if (!rawValue.isString()) {
            isValid = false;
            return;
        }
        QString site = rawSite.trimmed().toLower();
        if (!isAllowedManagedSiteKey(site)) {
            isValid = false;
            return;
        }
        const QString directRoute = canonicalManagedIpv4Route(site);
        if (!directRoute.isEmpty()) {
            site = directRoute;
        }
        bool routesValid = false;
        const QStringList routes = validatedManagedRouteTokens(rawValue.toString(), &routesValid);
        if (!routesValid || (!directRoute.isEmpty() && !routes.isEmpty())) {
            // A CIDR key already is the route. A non-empty fallback value is
            // ambiguous and was historically ignored by runtime consumers.
            isValid = false;
            return;
        }
        const QJsonValue canonicalValue(routes.join(QStringLiteral(", ")));
        const QJsonValue previous = sites.value(site);
        if (!previous.isUndefined()) {
            if (previous != canonicalValue) {
                isValid = false;
            }
            return;
        }
        totalRouteBudget += routes.size();
        if (directRoute.isEmpty()) {
            // Reserve one route for the domain's eventual A-record result so
            // a policy cannot hide an unbounded DNS fan-out behind empty
            // fallback values.
            ++totalRouteBudget;
        } else {
            ++totalRouteBudget;
        }
        if (totalRouteBudget > maximumTotalRouteCount) {
            isValid = false;
            return;
        }
        sites.insert(site, canonicalValue);
    };

    if (value.isObject()) {
        const QJsonObject object = value.toObject();
        if (object.size() > maximumSiteCount) {
            isValid = false;
        }
        for (auto it = object.constBegin(); it != object.constEnd(); ++it) {
            insertSite(it.key(), it.value());
        }
    } else if (value.isArray()) {
        const QJsonArray array = value.toArray();
        if (array.size() > maximumSiteCount) {
            isValid = false;
        }
        for (const QJsonValue &item : array) {
            if (!item.isObject()) {
                isValid = false;
                continue;
            }
            const QJsonObject object = item.toObject();
            const QString site = object.value(QStringLiteral("hostname"))
                                         .toString(object.value(QStringLiteral("url")).toString());
            insertSite(site, object.value(QStringLiteral("ip")));
        }
    }

    if (valid) {
        *valid = isValid;
    }
    return sites;
}

inline QJsonObject canonicalSourcePolicyContent(const QJsonObject &object, bool *valid = nullptr)
{
    bool sitesValid = false;
    const QJsonObject sites = canonicalSourceSites(sourceSitesValue(object), &sitesValid);
    const bool isValid = containsSourceSites(object) && sitesValid;

    QJsonObject content;
    content.insert(QStringLiteral("schemaVersion"), 1);
    content.insert(QStringLiteral("managedSplitTunnelExceptSourceSites"), sites);
    content.insert(QStringLiteral("managedSplitTunnelForceEnabled"),
                   object.value(QStringLiteral("managedSplitTunnelForceEnabled")).toBool(false));
    if (valid) {
        *valid = isValid;
    }
    return content;
}

inline QString canonicalSourcePolicyHash(const QJsonObject &object, bool *valid = nullptr)
{
    bool contentValid = false;
    const QJsonObject content = canonicalSourcePolicyContent(object, &contentValid);
    const QByteArray digest = QCryptographicHash::hash(
            QJsonDocument(content).toJson(QJsonDocument::Compact), QCryptographicHash::Sha256).toHex();
    if (valid) {
        *valid = contentValid;
    }
    return QStringLiteral("sha256:%1").arg(QString::fromLatin1(digest));
}

// Kept as a small generic digest helper for callers that already construct the
// canonical object explicitly. Policy validation itself does not use the wire
// envelope as identity.
inline QString derivedRevision(const QJsonObject &canonicalObject)
{
    const QByteArray digest = QCryptographicHash::hash(
            QJsonDocument(canonicalObject).toJson(QJsonDocument::Compact),
            QCryptographicHash::Sha256).toHex();
    return QStringLiteral("sha256:%1").arg(QString::fromLatin1(digest));
}

inline std::optional<ManagedRoutePolicyMetadata> metadataFromJson(const QJsonObject &json)
{
    if (json.isEmpty()) {
        return std::nullopt;
    }

    ManagedRoutePolicyMetadata metadata;
    metadata.schemaVersion = json.value(QStringLiteral("schemaVersion")).toInt(1);
    metadata.revision = json.value(QStringLiteral("revision")).toString().trimmed();
    metadata.contentHash = normalizedSha256(json.value(QStringLiteral("contentHash")).toString());
    metadata.declaredContentHash = normalizedSha256(
            json.value(QStringLiteral("declaredContentHash")).toString());
    if (metadata.declaredContentHash.isEmpty()) {
        metadata.declaredContentHash = metadata.contentHash;
    }
    metadata.contentMatchesDeclaration = json.value(QStringLiteral("contentMatchesDeclaration"))
                                                 .toBool(metadata.declaredContentHash.isEmpty()
                                                         || metadata.declaredContentHash == metadata.contentHash);
    metadata.issuedAt = dateTimeFromJson(json.value(QStringLiteral("issuedAt")));
    metadata.expiresAt = dateTimeFromJson(json.value(QStringLiteral("expiresAt")));
    metadata.acceptedAt = dateTimeFromJson(json.value(QStringLiteral("acceptedAt")));
    metadata.source = json.value(QStringLiteral("source")).toString().trimmed();
    metadata.trustState = json.value(QStringLiteral("trustState")).toString(QStringLiteral("unsigned"));

    const QString policyType = json.value(QStringLiteral("policyType")).toString().trimmed().toLower();
    qint64 parsedRevision = -1;
    const bool numericRevision = storedCanonicalRevisionNumber(metadata.revision, &parsedRevision);
    if ((!policyType.isEmpty()
         && policyType != QStringLiteral("versioned")
         && policyType != QStringLiteral("legacy"))
        || (policyType == QStringLiteral("legacy") && numericRevision)) {
        // A numeric versioned revision cannot be relabelled as legacy to drop
        // its mandatory expiry/integrity fields.
        return std::nullopt;
    }
    metadata.versioned = policyType == QStringLiteral("versioned")
            || (policyType.isEmpty() && numericRevision);
    if (metadata.versioned) {
        qint64 storedRevisionNumber = -1;
        if (canonicalRevisionNumber(json.value(QStringLiteral("revisionNumber")), &storedRevisionNumber)) {
            metadata.revisionNumber = storedRevisionNumber;
        } else if (numericRevision) {
            metadata.revisionNumber = parsedRevision;
        }
    }

    if (metadata.schemaVersion != 1 || metadata.revision.isEmpty()
        || (metadata.versioned && metadata.revisionNumber < 1)) {
        return std::nullopt;
    }
    if (metadata.versioned
        && (!numericRevision
            || !canonicalRevisionNumber(json.value(QStringLiteral("revisionNumber")), nullptr)
            || metadata.revisionNumber != parsedRevision
            || metadata.contentHash.isEmpty() || metadata.declaredContentHash.isEmpty()
            || normalizedSha256(json.value(QStringLiteral("declaredContentHash")).toString()).isEmpty()
            || !json.value(QStringLiteral("contentMatchesDeclaration")).isBool()
            || !metadata.issuedAt.isValid() || !metadata.expiresAt.isValid()
            || metadata.expiresAt <= metadata.issuedAt)) {
        // Versioned LKG state is an enforcement boundary, not merely display
        // metadata. Missing lifecycle/hash fields must disable it instead of
        // silently turning an expiring policy into a permanent legacy policy.
        return std::nullopt;
    }
    // Never promote an unverified persisted claim to a trusted state.
    if (metadata.trustState != QStringLiteral("unsigned")) {
        metadata.trustState = QStringLiteral("unsigned");
    }
    return metadata;
}

inline std::optional<ManagedRoutePolicyMetadata> lastKnownGood(const QJsonObject &serverConfig)
{
    const QJsonObject state = serverConfig.value(stateKey()).toObject();
    return metadataFromJson(state.value(lastKnownGoodKey()).toObject());
}

inline ManagedRoutePolicyMetadata metadataForEffectiveContent(
        const QJsonObject &serverConfig, const ManagedRoutePolicyMetadata &metadata)
{
    ManagedRoutePolicyMetadata effective = metadata;
    if (effective.declaredContentHash.isEmpty()) {
        effective.declaredContentHash = effective.contentHash;
    }
    bool contentValid = false;
    const QString effectiveHash = canonicalSourcePolicyHash(serverConfig, &contentValid);
    if (contentValid) {
        effective.contentHash = effectiveHash;
        effective.contentMatchesDeclaration = effective.declaredContentHash.isEmpty()
                || effective.declaredContentHash == effectiveHash;
    } else {
        effective.contentHash.clear();
        effective.contentMatchesDeclaration = false;
    }
    effective.trustState = QStringLiteral("unsigned");
    return effective;
}

inline std::optional<ManagedRoutePolicyMetadata> lastKnownGoodForEffectiveContent(
        const QJsonObject &serverConfig)
{
    const auto metadata = lastKnownGood(serverConfig);
    if (!metadata.has_value()) {
        return std::nullopt;
    }
    return metadataForEffectiveContent(serverConfig, metadata.value());
}

inline bool isEffective(const QJsonObject &serverConfig,
                        const QDateTime &now = QDateTime::currentDateTimeUtc())
{
    const QJsonValue stateValue = serverConfig.value(stateKey());
    if (stateValue.isUndefined()) {
        // Configurations that predate lifecycle metadata remain compatible
        // only when their actual route content passes today's fail-closed
        // safety and resource bounds.
        bool legacyContentValid = false;
        canonicalSourcePolicyContent(serverConfig, &legacyContentValid);
        return legacyContentValid;
    }
    if (!stateValue.isObject()) {
        return false;
    }
    const QJsonObject state = stateValue.toObject();
    const QJsonValue retainedValue = state.value(lastKnownGoodKey());
    if (!retainedValue.isObject() || retainedValue.toObject().isEmpty()) {
        // Once lifecycle state exists, a torn or cleared LKG must never be
        // reinterpreted as a permanent metadata-less legacy policy.
        return false;
    }
    const QJsonObject retained = retainedValue.toObject();
    const auto metadata = metadataFromJson(retained);
    // A malformed retained lifecycle record must not reactivate routes whose
    // expiry can no longer be evaluated safely.
    if (!metadata.has_value()) {
        return false;
    }
    const ManagedRoutePolicyMetadata effective = metadataForEffectiveContent(serverConfig, metadata.value());
    return effective.contentMatchesDeclaration && !effective.isExpired(now);
}

inline QString effectiveContentHash(
        const QJsonObject &serverConfig,
        const QDateTime &now = QDateTime::currentDateTimeUtc())
{
    if (!isEffective(serverConfig, now)) {
        return {};
    }
    bool contentValid = false;
    const QString contentHash = canonicalSourcePolicyHash(serverConfig, &contentValid);
    return contentValid ? contentHash : QString();
}

// Runtime receipts bind both parts of the accepted policy identity. Empty
// values are a valid pair only when no managed policy is effective; a partial
// identity must never be promoted to an authoritative snapshot.
inline bool isCanonicalPolicyIdentity(const QString &revision,
                                      const QString &contentHash)
{
    if (revision.isEmpty() || contentHash.isEmpty()) {
        return revision.isEmpty() && contentHash.isEmpty();
    }

    qint64 numericRevision = -1;
    const bool revisionValid =
            (revision.trimmed() == revision
             && storedCanonicalRevisionNumber(revision, &numericRevision))
            || normalizedSha256(revision) == revision;
    return revisionValid && normalizedSha256(contentHash) == contentHash;
}

inline QString effectiveRevision(
        const QJsonObject &serverConfig,
        const QDateTime &now = QDateTime::currentDateTimeUtc())
{
    const QString contentHash = effectiveContentHash(serverConfig, now);
    if (contentHash.isEmpty()) {
        return {};
    }

    const QJsonValue stateValue = serverConfig.value(stateKey());
    if (stateValue.isUndefined()) {
        // Legacy policies use their canonical source-policy digest as both
        // revision and content identity.
        return contentHash;
    }

    const auto metadata = lastKnownGoodForEffectiveContent(serverConfig);
    if (!metadata.has_value() || metadata->isExpired(now)
        || !metadata->contentMatchesDeclaration
        || metadata->contentHash != contentHash) {
        return {};
    }
    return metadata->revision;
}

inline std::optional<ManagedRoutePolicyMetadata> validateCandidate(
        const QJsonObject &payload,
        const std::optional<ManagedRoutePolicyMetadata> &currentLastKnownGood,
        const QDateTime &now,
        QString *error = nullptr)
{
    const auto reject = [error](const QString &message) -> std::optional<ManagedRoutePolicyMetadata> {
        if (error) {
            *error = message;
        }
        return std::nullopt;
    };

    const bool policyMemberPresent = payload.contains(QStringLiteral("policy"));
    if (policyMemberPresent && !payload.value(QStringLiteral("policy")).isObject()) {
        return reject(QStringLiteral("invalid policy envelope"));
    }
    const bool versioned = policyMemberPresent;
    const QJsonObject policyObject = payload.value(QStringLiteral("policy")).toObject();
    ManagedRoutePolicyMetadata metadata;
    metadata.versioned = versioned;
    metadata.trustState = QStringLiteral("unsigned");

    const QJsonValue schemaVersionValue = versioned
            ? policyObject.value(QStringLiteral("schemaVersion"))
            : firstValue(policyObject, payload, { "schemaVersion", "schema_version" });
    if (schemaVersionValue.isUndefined()) {
        metadata.schemaVersion = 1;
    } else if (schemaVersionValue.isDouble()
               && std::floor(schemaVersionValue.toDouble()) == schemaVersionValue.toDouble()) {
        metadata.schemaVersion = schemaVersionValue.toInt(0);
    } else if (!versioned && schemaVersionValue.isString()) {
        bool parsed = false;
        metadata.schemaVersion = schemaVersionValue.toString().toInt(&parsed);
        if (!parsed) {
            metadata.schemaVersion = 0;
        }
    } else {
        metadata.schemaVersion = 0;
    }
    if (metadata.schemaVersion != 1) {
        return reject(QStringLiteral("unsupported policy schema version"));
    }

    bool effectiveContentValid = false;
    const QJsonObject effectiveContent = canonicalSourcePolicyContent(payload, &effectiveContentValid);
    if (!effectiveContentValid) {
        return reject(QStringLiteral("invalid canonical source policy"));
    }

    QJsonObject declaredContent = effectiveContent;
    if (versioned) {
        if (!canonicalRevisionNumber(policyObject.value(QStringLiteral("revision")), &metadata.revisionNumber)) {
            return reject(QStringLiteral("policy revision must be a canonical positive integer"));
        }
        metadata.revision = QString::number(metadata.revisionNumber);

        const QJsonValue contentValue = policyObject.value(QStringLiteral("content"));
        if (!contentValue.isObject()) {
            return reject(QStringLiteral("versioned policy has no canonical content"));
        }
        const QJsonObject contentObject = contentValue.toObject();
        if (contentObject.value(QStringLiteral("schemaVersion")).toInt(0) != 1
            || !contentObject.value(QStringLiteral("schemaVersion")).isDouble()
            || !contentObject.contains(QStringLiteral("managedSplitTunnelExceptSourceSites"))
            || !contentObject.value(QStringLiteral("managedSplitTunnelForceEnabled")).isBool()) {
            return reject(QStringLiteral("versioned policy content schema is invalid"));
        }
        bool declaredContentValid = false;
        declaredContent = canonicalSourcePolicyContent(contentObject, &declaredContentValid);
        if (!declaredContentValid || declaredContent != effectiveContent) {
            return reject(QStringLiteral("policy content does not match effective source rules"));
        }
    }

    const QByteArray digest = QCryptographicHash::hash(
            QJsonDocument(declaredContent).toJson(QJsonDocument::Compact), QCryptographicHash::Sha256).toHex();
    metadata.contentHash = QStringLiteral("sha256:%1").arg(QString::fromLatin1(digest));
    metadata.declaredContentHash = metadata.contentHash;

    if (versioned) {
        const QString declaredHash = normalizedSha256(
                policyObject.value(QStringLiteral("contentSha256")).toString());
        if (declaredHash.isEmpty() || declaredHash != metadata.declaredContentHash) {
            return reject(QStringLiteral("policy content digest mismatch"));
        }
    } else {
        // A stable source-policy digest gives unversioned legacy payloads an
        // identity while preserving their established wire format.
        metadata.revision = metadata.contentHash;
    }

    const QJsonValue issuedValue = firstValue(
            policyObject, payload, { "issuedAt", "issued_at", "issued", "generatedAt" });
    const QJsonValue expiresValue = firstValue(
            policyObject, payload, { "expiresAt", "expires_at", "expires" });
    metadata.issuedAt = dateTimeFromJson(issuedValue);
    metadata.expiresAt = dateTimeFromJson(expiresValue);

    if ((!issuedValue.isUndefined() && !metadata.issuedAt.isValid())
        || (versioned && !metadata.issuedAt.isValid())) {
        return reject(QStringLiteral("invalid policy issue time"));
    }
    if ((!expiresValue.isUndefined() && !metadata.expiresAt.isValid())
        || (versioned && !metadata.expiresAt.isValid())) {
        return reject(QStringLiteral("invalid policy expiry time"));
    }

    const QDateTime utcNow = now.isValid() ? now.toUTC() : QDateTime::currentDateTimeUtc();
    if (metadata.issuedAt.isValid() && metadata.issuedAt > utcNow.addSecs(10 * 60)) {
        return reject(QStringLiteral("policy issue time is in the future"));
    }
    if (metadata.expiresAt.isValid() && metadata.expiresAt <= utcNow) {
        return reject(QStringLiteral("policy is expired"));
    }
    if (metadata.issuedAt.isValid() && metadata.expiresAt.isValid()
        && metadata.expiresAt <= metadata.issuedAt) {
        return reject(QStringLiteral("policy expiry is not after issue time"));
    }

    if (currentLastKnownGood.has_value()) {
        const ManagedRoutePolicyMetadata &current = currentLastKnownGood.value();
        const QString currentDeclaredHash = current.declaredContentHash.isEmpty()
                ? current.contentHash : current.declaredContentHash;

        if (current.versioned && !versioned) {
            return reject(QStringLiteral("legacy policy cannot replace a versioned policy"));
        }

        if (versioned && current.versioned) {
            if (current.revisionNumber < 1) {
                return reject(QStringLiteral("stored versioned policy revision is invalid"));
            }
            if (metadata.revisionNumber < current.revisionNumber) {
                return reject(QStringLiteral("policy revision is older than last-known-good"));
            }
            if (metadata.revisionNumber == current.revisionNumber) {
                if (!currentDeclaredHash.isEmpty() && metadata.declaredContentHash != currentDeclaredHash) {
                    return reject(QStringLiteral("policy content changed without a new revision"));
                }
                if ((current.issuedAt.isValid() && metadata.issuedAt != current.issuedAt)
                    || (current.expiresAt.isValid() && metadata.expiresAt != current.expiresAt)) {
                    return reject(QStringLiteral("policy lifecycle changed without a new revision"));
                }
                metadata.acceptedAt = current.acceptedAt;
            } else if (current.issuedAt.isValid() && metadata.issuedAt < current.issuedAt) {
                return reject(QStringLiteral("policy issue time is older than last-known-good"));
            }
        } else if (!versioned && !current.versioned) {
            if (metadata.declaredContentHash == currentDeclaredHash && current.acceptedAt.isValid()) {
                metadata.acceptedAt = current.acceptedAt;
            } else if (current.issuedAt.isValid()) {
                if (!metadata.issuedAt.isValid()) {
                    return reject(QStringLiteral("policy without issue time would replace last-known-good"));
                }
                if (metadata.issuedAt < current.issuedAt) {
                    return reject(QStringLiteral("policy is older than last-known-good"));
                }
            }
        }
    }

    if (!metadata.acceptedAt.isValid()) {
        metadata.acceptedAt = utcNow;
    }
    if (error) {
        error->clear();
    }
    return metadata;
}

inline bool storeLastKnownGood(QJsonObject &serverConfig, const ManagedRoutePolicyMetadata &metadata)
{
    QJsonObject state = serverConfig.value(stateKey()).toObject();
    const ManagedRoutePolicyMetadata effective = metadataForEffectiveContent(serverConfig, metadata);
    const QJsonObject metadataJson = effective.toJson();
    if (state.value(lastKnownGoodKey()).toObject() == metadataJson) {
        return false;
    }
    state.insert(QStringLiteral("schemaVersion"), 1);
    state.insert(lastKnownGoodKey(), metadataJson);
    serverConfig.insert(stateKey(), state);
    return true;
}

inline bool refreshEffectiveContentMetadata(QJsonObject &serverConfig)
{
    const auto metadata = lastKnownGood(serverConfig);
    if (!metadata.has_value()) {
        return false;
    }
    return storeLastKnownGood(serverConfig, metadata.value());
}

} // namespace managedRoutePolicy
} // namespace amnezia

#endif // MANAGEDROUTEPOLICY_H
