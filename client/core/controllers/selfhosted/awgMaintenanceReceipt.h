#pragma once
#include <QJsonObject>
#include <QRegularExpression>

namespace AwgMaintenance {
inline bool validReceipt(const QJsonObject &receipt, const QString &source,
                         qint64 generation, const QJsonObject &expectedHashes)
{
    const QRegularExpression hash(QStringLiteral("^[a-f0-9]{64}$"));
    return receipt.value(QStringLiteral("maintained")).isBool()
        && receipt.value(QStringLiteral("maintained")).toBool()
        && receipt.value(QStringLiteral("loaded")).isBool()
        && receipt.value(QStringLiteral("loaded")).toBool()
        && receipt.value(QStringLiteral("source")).toString() == source
        && receipt.value(QStringLiteral("generation")).isDouble()
        && receipt.value(QStringLiteral("generation")).toDouble() == generation
        && receipt.value(QStringLiteral("controlHashes")).toObject() == expectedHashes
        && hash.match(receipt.value(QStringLiteral("journalSha256")).toString()).hasMatch();
}
}
