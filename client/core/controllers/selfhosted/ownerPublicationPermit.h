#pragma once

#include "releaseAcceptance.h"
#include <QDir>

namespace amnezia::selfhostedUpdates {
enum class PublicationAuthorization { FullAccepted, OwnerUnverified13 };
inline constexpr auto ownerPublicationPermitSchema = "amnezia-owner-publication-permit-v1";

inline bool decodeOwnerPublicationPermit(const QByteArray &bytes, const QByteArray &publicKeyPem, QJsonObject &result)
{
    if (bytes.isEmpty() || bytes.size() > maximumAcceptanceBytes || publicKeyPem.isEmpty()) return false;
    const QJsonDocument envelopeDocument = QJsonDocument::fromJson(bytes);
    if (!envelopeDocument.isObject() || envelopeDocument.toJson(QJsonDocument::Compact) != bytes) return false;
    const QJsonObject envelope = envelopeDocument.object();
    if (!acceptanceKeys(envelope, { "schema", "signatureAlgorithm", "payload", "signature" })
        || envelope.value("schema").toString() != QLatin1String(ownerPublicationPermitSchema)
        || envelope.value("signatureAlgorithm").toString() != QStringLiteral("Ed25519")) return false;
    QByteArray signedBytes, signature;
    if (!acceptanceBase64(envelope.value("payload").toString(), true, signedBytes)
        || !acceptanceBase64(envelope.value("signature").toString(), false, signature) || signature.size() != 64) return false;
    const QByteArray domain = QByteArray(ownerPublicationPermitSchema) + '\n';
    if (!signedBytes.startsWith(domain)) return false;
    BIO *bio = BIO_new_mem_buf(publicKeyPem.constData(), int(publicKeyPem.size()));
    if (!bio) return false;
    EVP_PKEY *key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!key) return false;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    const bool valid = ctx && EVP_PKEY_base_id(key) == EVP_PKEY_ED25519
        && EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, key) == 1
        && EVP_DigestVerify(ctx, reinterpret_cast<const unsigned char *>(signature.constData()), size_t(signature.size()),
                            reinterpret_cast<const unsigned char *>(signedBytes.constData()), size_t(signedBytes.size())) == 1;
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(key);
    if (!valid) return false;
    const QByteArray payload = signedBytes.mid(domain.size());
    const QJsonDocument document = QJsonDocument::fromJson(payload);
    if (!document.isObject() || document.toJson(QJsonDocument::Compact) != payload) return false;
    result = document.object();
    return true;
}

inline bool validateOwnerPublicationPermit(const QJsonObject &permit, const QString &manifestSha256,
        const QString &publisherSha256, const QString &version, int androidVersionCode,
        const QJsonArray &artifacts, const QDateTime &now, PublicationAuthorization mode)
{
    if (mode != PublicationAuthorization::OwnerUnverified13 || !acceptanceKeys(permit, { "schema", "policyId", "manifestSha256", "publisherSha256", "version",
            "androidVersionCode", "issuedAt", "expiresAt", "artifacts", "acceptanceStatus", "unverifiedTargets", "invocation" })
        || permit.value("schema") != QJsonValue(1)
        || permit.value("policyId") != QJsonValue("amnezia-owner-release-50313-v1")
        || version != QStringLiteral("5.0.3.13") || androidVersionCode != 2199
        || permit.value("version") != QJsonValue(version)
        || permit.value("androidVersionCode") != QJsonValue(androidVersionCode)
        || !acceptanceDigest(manifestSha256) || !acceptanceDigest(publisherSha256)
        || permit.value("manifestSha256") != QJsonValue(manifestSha256)
        || permit.value("publisherSha256") != QJsonValue(publisherSha256)
        || permit.value("acceptanceStatus") != QJsonValue("owner-approved-unverified")
        || permit.value("invocation") != QJsonValue("normal")
        || permit.value("unverifiedTargets") != QJsonValue(QJsonArray {
                "android-real-device", "linux-gui", "linux-headless", "windows-runtime" })
        || artifacts.size() != 5
        || permit.value("artifacts") != QJsonValue(artifacts)) return false;
    QString previousPath;
    for (const QJsonValue &entry : artifacts) {
        const QJsonObject artifact = entry.toObject();
        const QString path = artifact.value("path").toString();
        const QJsonValue size = artifact.value("size");
        if (!acceptanceKeys(artifact, { "path", "sha256", "size" })
            || !path.startsWith(QStringLiteral("files/")) || QDir::cleanPath(path) != path
            || path.contains(u'\\') || path.contains(u':') || path.contains(u'?') || path.contains(u'#')
            || (!previousPath.isEmpty() && path <= previousPath)
            || !acceptanceDigest(artifact.value("sha256").toString())
            || !size.isDouble() || size.toDouble() <= 0 || size.toDouble() > 9007199254740991.0
            || double(qint64(size.toDouble())) != size.toDouble()) return false;
        for (const QChar c : path) if (c.unicode() < 0x20 || c.unicode() == 0x7f) return false;
        previousPath = path;
    }
    const auto timestamp = [](const QJsonValue &value) {
        const QString text = value.toString();
        const QDateTime utc = QDateTime::fromString(text, Qt::ISODate).toUTC();
        return utc.isValid() && utc.toString(QStringLiteral("yyyy-MM-dd'T'HH:mm:ss'Z'")) == text ? utc : QDateTime();
    };
    const QDateTime issued = timestamp(permit.value("issuedAt")), expires = timestamp(permit.value("expiresAt"));
    return now.isValid() && issued.isValid() && expires.isValid() && issued <= now && now < expires
            && issued < expires && issued.secsTo(expires) <= 24 * 60 * 60;
}
// A full acceptance always has priority; a narrowly signed owner waiver is
// considered only when full acceptance is unavailable. Neither input is a
// caller-supplied PASS flag: callbacks perform the actual signature checks.
template <typename Full, typename Owner>
bool selectPublicationAuthorization(Full full, Owner owner, PublicationAuthorization &authorization)
{
    if (full()) { authorization = PublicationAuthorization::FullAccepted; return true; }
    if (owner()) { authorization = PublicationAuthorization::OwnerUnverified13; return true; }
    return false;
}

// Recovery remains available when an approval expires after prepare, but a new
// commit must never begin without fresh authorization.
template <typename Authorize, typename Abort, typename Commit>
bool runAuthorizedPublicationCommit(Authorize authorize, Abort abort, Commit commit)
{
    if (!authorize()) { abort(); return false; }
    commit();
    return true;
}

}
