#pragma once

#include "awgMigration.h"
#include <cmath>
#include <functional>

namespace amnezia::awgMigration {
// The caller supplies an actual native cleanup receipt, never a timer result.
inline bool cleanupAuthorizationAllowed(const QString &serverId, const QString &expectedServerId,
                                        const QString &token, const QString &expectedToken,
                                        quint64 teardownEpoch, const QString &lastCleanupToken)
{
    return !serverId.isEmpty() && serverId == expectedServerId && !token.isEmpty()
            && token == expectedToken && teardownEpoch != 0 && token != lastCleanupToken;
}
// Classifies persisted profile identity only. The caller must independently
// confirm native cleanup and the journal's connection/peer binding first.
inline bool rollbackRecoveryAllowed(const QString &state, const QString &currentHash,
                                    const QString &sourceHash, const QString &candidateHash)
{
    return state == "recovery_required" && !currentHash.isEmpty() && !sourceHash.isEmpty()
            && currentHash == sourceHash && (candidateHash.isEmpty() || candidateHash != currentHash);
}
inline QString recoveryCredentialHash(const QString &value)
{
    return QString::fromLatin1(QCryptographicHash::hash(value.toUtf8(), QCryptographicHash::Sha256).toHex());
}
inline QJsonObject createRecoveryAuthorization(const QJsonObject &journal)
{
    const auto offer = journal.value("offer").toObject();
    const auto sourceHash = journal.value("sourceHash").toString();
    const auto signer = journal.value("signingPublicKey").toString();
    const auto nonce = journal.value("nonce").toString();
    const auto grant = journal.value("grant").toString();
    const auto generation = offer.value("generation").toDouble(-1);
    bool epochValid = false;
    const auto cleanupEpoch = journal.value("lastRecoveryCleanupEpoch").toString().toULongLong(&epochValid);
    if (sourceHash.isEmpty() || signer.isEmpty() || nonce.isEmpty() || grant.isEmpty()
        || journal.value("lastRecoveryCleanupToken").toString().isEmpty() || !epochValid || !cleanupEpoch
        || offer.value("target").toObject().isEmpty() || generation <= 0
        || generation > 9007199254740991.0 || std::floor(generation) != generation
        || generation != journal.value("highestGeneration").toDouble(-2)
        || generation != journal.value("stagedGeneration").toDouble(-3)
        || digest(offer.value("target").toObject()) != journal.value("stagedTargetHash").toString()) return {};
    return {{"sourceHash", sourceHash}, {"generation", generation},
            {"targetHash", digest(offer.value("target").toObject())}, {"signingPublicKey", signer},
            {"previousNonceHash", recoveryCredentialHash(nonce)},
            {"previousGrantHash", recoveryCredentialHash(grant)},
            {"cleanupToken", journal.value("lastRecoveryCleanupToken")},
            {"cleanupEpoch", journal.value("lastRecoveryCleanupEpoch")}};
}
// This exception is evaluated only after normal envelope signature and binding
// validation. A successful result does not itself consume authorization: the
// caller must remove it in the durable trial write before starting the backend.
inline bool sameGenerationRecoveryAllowed(const QJsonObject &journal, const QJsonObject &offer,
                                          const QString &currentSourceHash)
{
    const auto authorization = journal.value("recoveryAuthorization").toObject();
    if (!hasExactKeys(authorization, {"sourceHash", "generation", "targetHash", "signingPublicKey",
                                    "previousNonceHash", "previousGrantHash", "cleanupToken", "cleanupEpoch"})) return false;
    bool epochValid = false;
    const auto cleanupEpoch = authorization.value("cleanupEpoch").toString().toULongLong(&epochValid);
    const auto nonce = journal.value("nonce").toString();
    const auto grant = journal.value("grant").toString();
    const auto generation = authorization.value("generation").toDouble(-1);
    const auto sourceHash = authorization.value("sourceHash").toString();
    const auto signer = authorization.value("signingPublicKey").toString();
    return epochValid && cleanupEpoch != 0
            && !authorization.value("cleanupToken").toString().isEmpty()
            && authorization.value("cleanupToken") == journal.value("lastRecoveryCleanupToken")
            && authorization.value("cleanupEpoch") == journal.value("lastRecoveryCleanupEpoch")
            && !sourceHash.isEmpty() && sourceHash == currentSourceHash
            && sourceHash == journal.value("sourceHash").toString()
            && !signer.isEmpty() && signer == journal.value("signingPublicKey").toString()
            && generation > 0 && generation <= 9007199254740991.0 && std::floor(generation) == generation
            && generation == journal.value("highestGeneration").toDouble(-2)
            && generation == journal.value("stagedGeneration").toDouble(-4)
            && generation == offer.value("generation").toDouble(-3)
            && !offer.value("target").toObject().isEmpty()
            && authorization.value("targetHash").toString() == digest(offer.value("target").toObject())
            && authorization.value("targetHash").toString() == journal.value("stagedTargetHash").toString()
            && !nonce.isEmpty() && nonce == offer.value("nonce").toString() && !grant.isEmpty()
            && !authorization.value("previousNonceHash").toString().isEmpty()
            && !authorization.value("previousGrantHash").toString().isEmpty()
            && recoveryCredentialHash(nonce) != authorization.value("previousNonceHash").toString()
            && recoveryCredentialHash(grant) != authorization.value("previousGrantHash").toString();
}
inline QJsonObject recoveryJournalAfterCleanup(QJsonObject journal, const QString &token, quint64 epoch)
{
    journal["lastRecoveryCleanupToken"] = token;
    journal["lastRecoveryCleanupEpoch"] = QString::number(epoch);
    const auto authorization = createRecoveryAuthorization(journal);
    for (const auto &key : {"grant", "grantExpiresAt", "nonce", "offer", "challengeReceipt", "candidateHash", "recoveryAuthorization"})
        journal.remove(key);
    if (!authorization.isEmpty()) journal["recoveryAuthorization"] = authorization;
    journal["state"] = "rolled_back";
    return journal;
}
inline QJsonObject recoveryJournalForTrial(QJsonObject journal, const QJsonValue &generation)
{
    journal["highestGeneration"] = generation;
    journal.remove("recoveryAuthorization");
    journal["state"] = "trial";
    return journal;
}
inline bool storeRecoveryJournal(QJsonObject &current, const QJsonObject &next,
                                 const std::function<bool(const QJsonObject &)> &write)
{
    if (!write(next)) return false;
    current = next;
    return true;
}
} // namespace amnezia::awgMigration
