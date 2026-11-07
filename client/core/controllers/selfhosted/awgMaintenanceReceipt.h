#pragma once
#include <QJsonObject>
#include <QJsonDocument>
#include <QRegularExpression>
#include <QString>

namespace AwgMaintenance {
// Preserve actionable recovery locations without reflecting arbitrary SSH output
// or credentials through operator JSON when the primary operation failed.
inline QJsonObject failureDetails(const QJsonObject &receipt)
{
    QJsonObject details;
    const QString reason = receipt.value(QStringLiteral("reason")).toString();
    if (QRegularExpression(QStringLiteral("\\A[a-z][a-z0-9_]{0,159}\\z")).match(reason).hasMatch())
        details.insert(QStringLiteral("reason"), reason);
    const QString retained = receipt.value(QStringLiteral("retainedDirectory")).toString();
    if (QRegularExpression(QStringLiteral("\\A/tmp/amnezia-migration-maintenance-[A-Za-z0-9]{24}\\z"))
            .match(retained).hasMatch()) {
        details.insert(QStringLiteral("retainedDirectory"), retained);
        const auto pending = receipt.value(QStringLiteral("pendingRecovery"));
        details.insert(QStringLiteral("pendingRecovery"), pending.isBool() ? pending.toBool() : true);
        if (receipt.value(QStringLiteral("cleanupRequired")).isBool()
                && receipt.value(QStringLiteral("cleanupRequired")).toBool())
            details.insert(QStringLiteral("cleanupRequired"), true);
    }
    // PREPARE cleanup is independent of generation recovery. Do not invent a
    // pendingRecovery value when only an ephemeral input tree remains.
    bool preparePath = false;
    for (const auto &entry : {qMakePair(QStringLiteral("retainedPrepareDirectory"), QStringLiteral("/tmp/amnezia-migration-")),
                             qMakePair(QStringLiteral("retainedProgramDirectory"), QStringLiteral("/tmp/amnezia-migration-programs-"))}) {
        const QString path = receipt.value(entry.first).toString();
        if (QRegularExpression(QStringLiteral("\\A") + entry.second + QStringLiteral("[A-Za-z0-9]{24}\\z"))
                .match(path).hasMatch()) {
            details.insert(entry.first, path);
            preparePath = true;
        }
    }
    if (preparePath && receipt.value(QStringLiteral("cleanupRequired")).isBool()
            && receipt.value(QStringLiteral("cleanupRequired")).toBool())
        details.insert(QStringLiteral("cleanupRequired"), true);
    return details;
}

// Explicit native-control selection. The variant is authoritative: legacy
// generations carry no selection and keep their existing Python recipe. The
// current-control digest is a caller-authoritative pin; it is never read from
// the journal, a receipt, or the selected replacement payload.
enum class Operation { Maintain, Status, Recover, VerifyPrepare, InspectPrepare, AbortPrepare };
struct Selection {
    Operation operation = Operation::Maintain;
    QString clientOperationId;
    QString nativeControlVariant;
    QString currentControlSha256;
    bool native() const { return !nativeControlVariant.isEmpty(); }
};

inline bool validReceipt(const QJsonObject &receipt, const QString &source,
                         qint64 generation, const QJsonObject &expectedHashes)
{
    const QRegularExpression hash(QStringLiteral("\\A[a-f0-9]{64}\\z"));
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

// Native PREPARE emits an envelope whose receipt member is a JSON STRING.
// Bind the actual nested success receipt, not similarly named request metadata.
inline bool nativePrepareReceipt(const QJsonObject &envelope, const QString &expectedOperationId,
        qint64 requestedGeneration, bool automatic, QJsonObject *receipt)
{
    if (!receipt) return false;
    *receipt = {};
    if (!envelope.value("prepared").isBool() || !envelope.value("prepared").toBool()
            || !envelope.value("receipt").isString() || expectedOperationId.isEmpty()) return false;
    const QByteArray bytes = envelope.value("receipt").toString().toUtf8();
    if (bytes.isEmpty() || bytes.size() > 16384) return false;
    const auto parsed = QJsonDocument::fromJson(bytes);
    if (!parsed.isObject()) return false;
    const auto value = parsed.object();
    const auto number = value.value("generation");
    const double generation = number.toDouble();
    if (!value.value("prepared").isBool() || !value.value("prepared").toBool()
            || !value.value("legacyRetained").isBool() || !value.value("legacyRetained").toBool()
            || !number.isDouble() || generation < 1 || generation > 9007199254740991.0
            || generation != static_cast<double>(number.toInteger())
            || (!automatic && number.toInteger() != requestedGeneration)
            || value.value("clientOperationId").toString() != expectedOperationId) return false;
    *receipt = value;
    return true;
}

// Read-only status selects among already authorized pins; it cannot settle a
// local pending intent. Only verify/recover receipts with full LIVE proof may.
inline bool validNativeOperationReceipt(const QJsonObject &receipt, const QString &mode,
        const QString &source, qint64 generation, const QString &knownSha,
        const QString &clientOperationId = QString())
{
    const QRegularExpression hash(QStringLiteral("\\A[a-f0-9]{64}\\z"));
    const auto hashes = receipt.value(QStringLiteral("controlHashes")).toObject();
    if (!hash.match(knownSha).hasMatch()
            || !receipt.value("ok").isBool() || !receipt.value("ok").toBool()
            || receipt.value("mode").toString() != mode || receipt.value("source").toString() != source
            || !receipt.value("generation").isDouble() || receipt.value("generation").toDouble() != generation
            || !receipt.value("native").isBool() || !receipt.value("native").toBool()
            || !receipt.value("pendingRecovery").isBool() || hashes.size() != 1
            || hashes.value("awg-feed").toString() != knownSha
            || !hash.match(receipt.value("journalSha256").toString()).hasMatch()
            || (!clientOperationId.isEmpty() && receipt.value("clientOperationId").toString() != clientOperationId))
        return false;
    if (mode == QStringLiteral("inspect-prepare") || mode == QStringLiteral("abort-prepare")) {
        const QString phase = receipt.value("phase").toString();
        const bool partial = phase == QStringLiteral("preparing") || phase == QStringLiteral("creating")
            || phase == QStringLiteral("activating") || phase == QStringLiteral("aborted");
        if (clientOperationId.isEmpty() || !partial || receipt.value("pendingRecovery").toBool()
                || !receipt.value("liveVerified").isBool() || receipt.value("liveVerified").toBool()
                || !receipt.value("retiredVerified").isBool()) return false;
        return mode == QStringLiteral("inspect-prepare") ? !receipt.value("retiredVerified").toBool()
            : phase == QStringLiteral("aborted") && receipt.value("retiredVerified").toBool();
    }
    return mode == QStringLiteral("status")
        || ((mode == QStringLiteral("recover") || mode == QStringLiteral("verify"))
            && !receipt.value("pendingRecovery").toBool()
            && receipt.value("phase").toString() == QStringLiteral("ready")
            && receipt.value("liveVerified").isBool() && receipt.value("liveVerified").toBool());
}

// Native maintenance receipt. In a native-control generation the only loaded
// payload identity is "awg-feed". The replacement digest is the independently
// selected bundle payload, never a value derived from this receipt; equality
// with the current pin is the explicit unchanged-bytes no-op.
inline bool validNativeReceipt(const QJsonObject &receipt, const QString &source,
                               qint64 generation, const QString &currentControlSha256,
                               const QString &replacementControlSha256)
{
    const QRegularExpression hash(QStringLiteral("\\A[a-f0-9]{64}\\z"));
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
