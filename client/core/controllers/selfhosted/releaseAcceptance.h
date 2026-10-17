#pragma once

#include <QDateTime>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSet>
#include <QFile>
#include <QFileInfo>
#include <QCryptographicHash>
#include <openssl/evp.h>
#include <openssl/pem.h>

namespace amnezia::selfhostedUpdates {
inline constexpr auto acceptanceSchema = "amnezia-release-acceptance-v1";
inline constexpr qsizetype maximumAcceptanceBytes = 128 * 1024;

inline bool snapshotAcceptanceArtifact(const QString &source, const QString &target, qint64 size, const QByteArray &digest)
{
    if (size <= 0 || !QFile::copy(source, target)) return false;
    QFile snapshot(target);
    if (!snapshot.open(QIODevice::ReadOnly) || snapshot.size() != size) return false;
    QCryptographicHash hash(QCryptographicHash::Sha256);
    if (!hash.addData(&snapshot)) return false;
    return snapshot.atEnd() && hash.result().toHex() == digest;
}

inline bool acceptanceKeys(const QJsonObject &object, const QStringList &keys)
{
    const QStringList actual = object.keys();
    return QSet<QString>(actual.begin(), actual.end()) == QSet<QString>(keys.begin(), keys.end());
}

inline bool acceptanceDigest(const QString &value)
{
    if (value.size() != 64) return false;
    for (const QChar c : value) if (!(c >= u'0' && c <= u'9') && !(c >= u'a' && c <= u'f')) return false;
    return true;
}

inline bool acceptanceBase64(const QString &value, bool url, QByteArray &decoded)
{
    const auto options = url ? QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals : QByteArray::Base64Encoding;
    const QByteArray encoded = value.toUtf8();
    decoded = QByteArray::fromBase64(encoded, options | QByteArray::AbortOnBase64DecodingErrors);
    return !decoded.isEmpty() && decoded.toBase64(options) == encoded;
}

// Signature authenticates a release authority's attestation, not a local PASS boolean.
// Exact canonical bytes reject duplicate JSON keys before QJson can erase them.
inline bool decodeReleaseAcceptance(const QByteArray &bytes, const QByteArray &publicKeyPem, QJsonObject &result)
{
    if (bytes.isEmpty() || bytes.size() > maximumAcceptanceBytes || publicKeyPem.isEmpty()) return false;
    const QJsonDocument envelopeDocument = QJsonDocument::fromJson(bytes);
    if (!envelopeDocument.isObject() || envelopeDocument.toJson(QJsonDocument::Compact) != bytes) return false;
    const QJsonObject envelope = envelopeDocument.object();
    if (!acceptanceKeys(envelope, { "schema", "signatureAlgorithm", "payload", "signature" })
        || envelope.value("schema").toString() != QLatin1String(acceptanceSchema)
        || envelope.value("signatureAlgorithm").toString() != QStringLiteral("Ed25519")) return false;
    QByteArray signedBytes, signature;
    if (!acceptanceBase64(envelope.value("payload").toString(), true, signedBytes)
        || !acceptanceBase64(envelope.value("signature").toString(), false, signature) || signature.size() != 64) return false;
    const QByteArray domain = QByteArray(acceptanceSchema) + '\n';
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

inline bool validateReleaseAcceptance(const QJsonObject &approval, const QString &manifestSha256,
                                     const QString &publisherSha256, const QString &version,
                                     int androidVersionCode, const QJsonArray &artifacts, const QDateTime &now)
{
    if (!acceptanceKeys(approval, { "schema", "policyId", "manifestSha256", "publisherSha256", "version", "androidVersionCode", "issuedAt", "expiresAt", "artifacts", "receipts" })
        || approval.value("schema") != QJsonValue(1)
        || approval.value("policyId") != QJsonValue("amnezia-release-full-v1")
        || !acceptanceDigest(manifestSha256) || !acceptanceDigest(publisherSha256)
        || approval.value("manifestSha256") != QJsonValue(manifestSha256)
        || approval.value("publisherSha256") != QJsonValue(publisherSha256)
        || approval.value("version") != QJsonValue(version) || version.isEmpty()
        || androidVersionCode <= 0 || approval.value("androidVersionCode") != QJsonValue(androidVersionCode)
        || !approval.value("artifacts").isArray() || artifacts.isEmpty() || artifacts.size() > 64
        || approval.value("artifacts").toArray() != artifacts) return false;
    const auto timestamp = [](const QJsonValue &value) {
        const QString text = value.toString();
        const QDateTime utc = QDateTime::fromString(text, Qt::ISODate).toUTC();
        return utc.isValid() && utc.toString(QStringLiteral("yyyy-MM-dd'T'HH:mm:ss'Z'")) == text ? utc : QDateTime();
    };
    const QDateTime issued = timestamp(approval.value("issuedAt")), expires = timestamp(approval.value("expiresAt"));
    if (!now.isValid() || !issued.isValid() || !expires.isValid() || issued > now || expires <= now
        || issued >= expires || issued.secsTo(expires) > 24 * 60 * 60) return false;
    const QJsonArray receipts = approval.value("receipts").toArray();
    const QStringList platforms { "android", "linux", "windows" };
    if (receipts.size() != platforms.size()) return false;
    for (qsizetype i = 0; i < receipts.size(); ++i) {
        const QJsonObject receipt = receipts.at(i).toObject();
        if (!acceptanceKeys(receipt, { "platform", "kind", "runId", "profileId", "receiptSha256", "cleanupSha256", "status" })
            || receipt.value("platform") != QJsonValue(platforms.at(i))
            || receipt.value("kind") != QJsonValue(i == 0 ? "real-device" : "owned-guest")
            || receipt.value("status") != QJsonValue("PASS")
            || !acceptanceDigest(receipt.value("receiptSha256").toString())
            || !acceptanceDigest(receipt.value("cleanupSha256").toString())) return false;
        for (const auto &name : { "runId", "profileId" }) {
            const QString id = receipt.value(name).toString();
            if (id.isEmpty() || id.size() > 128) return false;
            for (const QChar c : id) if (c.unicode() < 0x21 || c.unicode() > 0x7e) return false;
        }
    }
    return true;
}
}
