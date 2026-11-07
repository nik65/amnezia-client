#pragma once
#include <QJsonObject>
#include <QRegularExpression>
#include <QString>

namespace AwgMaintenance {
// Explicit native-control selection. The variant is authoritative: legacy
// generations carry no selection and keep their existing Python recipe. The
// current-control digest is a caller-authoritative pin; it is never read from
// the journal, a receipt, or the selected replacement payload.
struct Selection {
    QString nativeControlVariant;
    QString currentControlSha256;
    bool native() const { return !nativeControlVariant.isEmpty(); }
};

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

// Native maintenance receipt. In a native-control generation the only loaded
// payload identity is "awg-feed". The replacement digest is the independently
// selected bundle payload, never a value derived from this receipt; equality
// with the current pin is the explicit unchanged-bytes no-op.
inline bool validNativeReceipt(const QJsonObject &receipt, const QString &source,
                               qint64 generation, const QString &currentControlSha256,
                               const QString &replacementControlSha256)
{
    const QRegularExpression hash(QStringLiteral("^[a-f0-9]{64}$"));
    if (!hash.match(currentControlSha256).hasMatch()
            || !hash.match(replacementControlSha256).hasMatch()) return false;
    const QJsonObject hashes = receipt.value(QStringLiteral("controlHashes")).toObject();
    return receipt.value(QStringLiteral("ok")).isBool()
        && receipt.value(QStringLiteral("ok")).toBool()
        && receipt.value(QStringLiteral("mode")).toString() == QStringLiteral("maintain")
        && receipt.value(QStringLiteral("source")).toString() == source
        && receipt.value(QStringLiteral("generation")).isDouble()
        && receipt.value(QStringLiteral("generation")).toDouble() == generation
        && receipt.value(QStringLiteral("native")).isBool()
        && receipt.value(QStringLiteral("native")).toBool()
        && receipt.value(QStringLiteral("pendingRecovery")).isBool()
        && !receipt.value(QStringLiteral("pendingRecovery")).toBool()
        && hashes.size() == 1
        && hash.match(hashes.value(QStringLiteral("awg-feed")).toString()).hasMatch()
        && hashes.value(QStringLiteral("awg-feed")).toString() == replacementControlSha256
        && hash.match(receipt.value(QStringLiteral("journalSha256")).toString()).hasMatch();
}
}
