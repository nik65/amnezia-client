#pragma once

#include <QJsonDocument>
#include <QCryptographicHash>
#include <QJsonArray>
#include <QJsonObject>
#include <QJsonValue>
#include <QRegularExpression>
#include <QUrl>
#include "core/utils/routeModes.h"

// Imported, owner-provisioned per-profile transport credentials. Never infer a
// fallback from a server hostname or inject one into unrelated subscriptions.
namespace amnezia::dnsFallbackConfig
{
inline constexpr QLatin1String key("dnsFallback");

inline bool isDomain(const QString &name)
{
    if (name.size() > 128 || !name.contains(QLatin1Char('.')))
        return false;
    static const QRegularExpression label(QStringLiteral("^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"));
    const auto parts = name.split(QLatin1Char('.'));
    for (const auto &part : parts) {
        if (!label.match(part).hasMatch())
            return false;
    }
    static const QRegularExpression numeric(QStringLiteral("^[0-9.]+$"));
    return !numeric.match(name).hasMatch()
            && !name.endsWith(QLatin1String(".localhost"))
            && !name.endsWith(QLatin1String(".local"));
}

inline QJsonObject normalized(const QJsonValue &value)
{
    if (!value.isObject())
        return {};
    const auto input = value.toObject();
    if (QJsonDocument(input).toJson(QJsonDocument::Compact).size() > 2048
            || !input.value(QStringLiteral("enabled")).isBool())
        return {};
    if (!input.value(QStringLiteral("enabled")).toBool())
        return { { QStringLiteral("enabled"), false } };

    auto domain = input.value(QStringLiteral("domain")).toString().trimmed().toLower();
    if (domain.endsWith(QLatin1Char('.')))
        domain.chop(1);
    if (!isDomain(domain))
        return {};
    const auto publicKey = input.value(QStringLiteral("publicKey")).toString().toLower();
    static const QRegularExpression keyPattern(QStringLiteral("^[0-9a-f]{64}$"));
    if (!keyPattern.match(publicKey).hasMatch() || publicKey == QString(64, QLatin1Char('0')))
        return {};
    const auto vlessId = input.value(QStringLiteral("vlessId")).toString().toLower();
    static const QRegularExpression uuidPattern(
            QStringLiteral("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"));
    if (!uuidPattern.match(vlessId).hasMatch()
            || vlessId == QLatin1String("00000000-0000-0000-0000-000000000000"))
        return {};

    const auto thresholdValue = input.value(QStringLiteral("failureThreshold"));
    const double threshold = thresholdValue.isUndefined() ? 3.0 : thresholdValue.toDouble(-1.0);
    if ((!thresholdValue.isUndefined() && !thresholdValue.isDouble())
            || threshold < 2 || threshold > 8 || threshold != static_cast<int>(threshold))
        return {};

    const auto probeValue = input.value(QStringLiteral("probeUrl"));
    if (!probeValue.isUndefined() && !probeValue.isString())
        return {};
    const auto probeText = probeValue.isUndefined()
            ? QStringLiteral("https://example.com/") : probeValue.toString();
    const QUrl probe(probeText, QUrl::StrictMode);
    if (probeText.size() > 512 || !probe.isValid() || probe.scheme() != QLatin1String("https")
            || !isDomain(probe.host().toLower()) || !probe.userInfo().isEmpty()
            || probe.hasFragment() || (probe.port(-1) != -1 && probe.port() != 443))
        return {};

    return {
        { QStringLiteral("enabled"), true },
        { QStringLiteral("domain"), domain },
        { QStringLiteral("publicKey"), publicKey },
        { QStringLiteral("vlessId"), vlessId },
        { QStringLiteral("probeUrl"), probe.toString(QUrl::FullyEncoded) },
        { QStringLiteral("failureThreshold"), static_cast<int>(threshold) }
    };
}

inline void copyToConnection(const QJsonObject &profile, QJsonObject &connection,
                             bool isApiSubscription = false)
{
    // The destination may be reused: an absent/invalid descriptor must clear a
    // previous profile's credentials rather than inherit its DNS endpoint.
    connection.remove(key);
    connection.remove(QStringLiteral("dnsFallbackUnavailableReason"));
    if (isApiSubscription)
        return;
    const auto descriptor = normalized(profile.value(key));
    if (!descriptor.isEmpty())
        connection.insert(key, descriptor);
}

inline void applyOwnerApplicationPolicy(QJsonObject &connection, AppsRouteMode mode, QJsonArray &apps)
{
    const auto descriptor = normalized(connection.value(key));
    if (!descriptor.value(QStringLiteral("enabled")).toBool())
        return;
    const auto owner = QStringLiteral("org.amnezia.vpn");
    if (mode == AppsRouteMode::VpnOnlyForwardApps) {
        if (!apps.contains(owner))
            apps.append(owner);
    } else if (mode == AppsRouteMode::VpnAllExceptApps && apps.contains(owner)) {
        // Respect an explicit owner exclusion. Its sockets cannot be used as
        // proof of the selected apps' VPN health, so keep the primary transport.
        connection.remove(key);
        connection.insert(QStringLiteral("dnsFallbackUnavailableReason"),
                          QStringLiteral("owner_excluded_by_app_split"));
    }
}

inline QString profileDigest(const QJsonValue &value)
{
    const auto descriptor = normalized(value);
    if (!descriptor.value(QStringLiteral("enabled")).toBool())
        return {};
    const auto material = descriptor.value(QStringLiteral("domain")).toString()
            + QLatin1Char('\n') + descriptor.value(QStringLiteral("publicKey")).toString()
            + QLatin1Char('\n') + descriptor.value(QStringLiteral("vlessId")).toString();
    return QString::fromLatin1(QCryptographicHash::hash(material.toUtf8(), QCryptographicHash::Sha256).toHex());
}
} // namespace amnezia::dnsFallbackConfig
