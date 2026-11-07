#pragma once

#include <QByteArray>
#include <QJsonArray>
#include <QJsonObject>
#include <QSet>
#include <QString>
#include <optional>

namespace AwgMaintenance {
// Directory names are locators only. Caller-saved nonce/payload and the trusted
// native consumer still have to authenticate the selected generation afterwards.
inline std::optional<qint64> prepareRecoveryGeneration(const QByteArray &findOutput,
        const QString &fixedRoot, const QJsonArray &trustedRetiredHistory = {},
        qint64 minimumGeneration = 1)
{
    constexpr qint64 maximumGeneration = 9007199254740991LL;
    if ((fixedRoot != QStringLiteral("/opt/amnezia/awg-migration/amnezia-awg/")
            && fixedRoot != QStringLiteral("/opt/amnezia/awg-migration/amnezia-awg2/"))
            || findOutput.isEmpty() || findOutput.size() > 4096 || !findOutput.endsWith('\n')
            || findOutput.count('\n') > 33 || trustedRetiredHistory.size() > 32
            || minimumGeneration < 1 || minimumGeneration > maximumGeneration)
        return std::nullopt;
    QSet<qint64> retired;
    qint64 previous = 0;
    for (const auto &entry : trustedRetiredHistory) {
        if (!entry.isObject()) return std::nullopt;
        const auto number = entry.toObject().value(QStringLiteral("generation"));
        if (!number.isDouble() || number.toDouble() <= previous || number.toDouble() > maximumGeneration
                || number.toDouble() != static_cast<double>(number.toInteger())) return std::nullopt;
        previous = number.toInteger();
        retired.insert(previous);
    }
    if (!retired.isEmpty() && minimumGeneration <= previous) return std::nullopt;
    const QByteArray prefix = fixedRoot.toLatin1();
    const auto paths = findOutput.chopped(1).split('\n');
    QSet<qint64> seen;
    std::optional<qint64> candidate;
    for (const auto &path : paths) {
        if (!path.startsWith(prefix)) return std::nullopt;
        const QByteArray token = path.mid(prefix.size());
        if (token.isEmpty()) return std::nullopt;
        for (const auto ch : token) if (ch < '0' || ch > '9') return std::nullopt;
        bool ok = false;
        const qint64 number = token.toLongLong(&ok, 10);
        if (!ok || number < 1 || number > maximumGeneration
                || QString::number(number).toLatin1() != token || seen.contains(number)) return std::nullopt;
        seen.insert(number);
        if (retired.contains(number)) continue;
        // An unknown older path is not proof of retirement and must not be
        // silently hidden by a newer candidate from the same scan.
        if (number < minimumGeneration || candidate.has_value()) return std::nullopt;
        candidate = number;
    }
    return candidate;
}
} // namespace AwgMaintenance
