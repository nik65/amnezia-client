#pragma once

#include <QCryptographicHash>
#include <QDateTime>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QSet>
#include <QRegularExpression>
#include <QStringList>
#include <openssl/evp.h>

// The signer is enrolled through the old authenticated peer tunnel, never
// accepted from an offer. The envelope signs the exact decoded payload bytes.
namespace amnezia::awgMigration {
inline constexpr int Schema = 1;
inline constexpr int MaximumDocumentBytes = 32768;
inline QStringList parameterKeys()
{
    return {"Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4",
            "I1", "I2", "I3", "I4", "I5", "HeaderProtectionKey", "ContentPaddingAddition",
            "RekeyAfterTime", "RekeyTimeout", "RejectAfterTime", "KeepaliveTimeout",
            "MaxHandshakeAttempts", "RandomTrailers", "DisableCookies"};
}
inline QString digest(const QJsonObject &object)
{
    return QString::fromLatin1(QCryptographicHash::hash(
            QJsonDocument(object).toJson(QJsonDocument::Compact), QCryptographicHash::Sha256).toHex());
}
inline QString sourceFingerprint(const QJsonObject &client)
{
    QJsonObject identity;
    QStringList fields = parameterKeys();
    fields.append({"hostName", "port", "client_ip", "client_pub_key", "server_pub_key"});
    for (const auto &name : fields) {
        if (client.contains(name)) identity.insert(name, client.value(name));
    }
    if (!client.value("psk_key").toString().isEmpty()) {
        identity["pskHash"] = QString::fromLatin1(QCryptographicHash::hash(
                client.value("psk_key").toString().toUtf8(), QCryptographicHash::Sha256).toHex());
    }
    // Never send the private key, native configuration, PSK, routes or DNS.
    return digest(identity);
}
inline bool hasExactKeys(const QJsonObject &object, const QStringList &keys)
{
    const auto actualKeys = object.keys();
    return QSet<QString>(actualKeys.begin(), actualKeys.end()) == QSet<QString>(keys.begin(), keys.end());
}
inline QByteArray strictBase64(const QString &value, int expectedBytes = -1)
{
    const QByteArray encoded = value.toLatin1();
    const auto decoded = QByteArray::fromBase64Encoding(encoded, QByteArray::AbortOnBase64DecodingErrors);
    if (!decoded || decoded.decoded.toBase64() != encoded
        || (expectedBytes >= 0 && decoded.decoded.size() != expectedBytes)) return {};
    return decoded.decoded;
}
inline bool verifyEnvelope(const QJsonObject &envelope, const QByteArray &pinnedKey,
                           QJsonObject &payload)
{
    payload = {};
    if (!hasExactKeys(envelope, {"payload", "signature"}) || pinnedKey.size() != 32) return false;
    if (!envelope.value("payload").isString() || !envelope.value("signature").isString()
        || envelope.value("payload").toString().size() > MaximumDocumentBytes * 2) return false;
    const QByteArray bytes = strictBase64(envelope.value("payload").toString());
    const QByteArray signature = strictBase64(envelope.value("signature").toString(), 64);
    if (bytes.isEmpty() || bytes.size() > MaximumDocumentBytes || signature.isEmpty()) return false;
    EVP_PKEY *key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr,
            reinterpret_cast<const unsigned char *>(pinnedKey.constData()), pinnedKey.size());
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    const bool valid = key && context && EVP_DigestVerifyInit(context, nullptr, nullptr, nullptr, key) == 1
            && EVP_DigestVerify(context, reinterpret_cast<const unsigned char *>(signature.constData()),
                    signature.size(), reinterpret_cast<const unsigned char *>(bytes.constData()), bytes.size()) == 1;
    EVP_MD_CTX_free(context);
    EVP_PKEY_free(key);
    if (!valid) return false;
    QJsonParseError error;
    const auto document = QJsonDocument::fromJson(bytes, &error);
    if (error.error != QJsonParseError::NoError || !document.isObject()) return false;
    payload = document.object();
    return true;
}
struct Binding {
    QString serverPublicKey;
    QString peerPublicKey;
    QString containerId;
    QString sourceFingerprint;
    QString nonce;
    qint64 highestGeneration = 0;
};
inline bool validateOffer(const QJsonObject &offer, const Binding &binding, qint64 now,
                          QString *reason = nullptr)
{
    auto reject = [reason](const char *code) { if (reason) *reason = QString::fromLatin1(code); return false; };
    if (!hasExactKeys(offer, {"schema", "serverPublicKey", "peerPublicKey", "containerId",
                            "sourceFingerprint", "nonce", "generation", "expiresAt", "target", "challenge"}))
        return reject("offer_fields");
    if (offer.value("schema").toInt(-1) != Schema) return reject("offer_schema");
    const auto generation = offer.value("generation").toDouble(-1);
    if (generation <= binding.highestGeneration || generation > 9007199254740991.0
        || generation != static_cast<qint64>(generation)) return reject("offer_generation");
    if (offer.value("expiresAt").toDouble(-1) <= now) return reject("offer_expired");
    if (offer.value("serverPublicKey").toString() != binding.serverPublicKey
        || offer.value("peerPublicKey").toString() != binding.peerPublicKey
        || offer.value("containerId").toString() != binding.containerId
        || offer.value("sourceFingerprint").toString() != binding.sourceFingerprint
        || offer.value("nonce").toString() != binding.nonce) return reject("offer_binding");
    const auto target = offer.value("target").toObject();
    if (!hasExactKeys(target, {"endpoint", "clientAddress", "parameters"})) return reject("target_fields");
    const auto endpoint = target.value("endpoint").toString();
    static const QRegularExpression endpointPattern(QStringLiteral("^[A-Za-z0-9.-]{1,253}:([0-9]{1,5})$"));
    const auto match = endpointPattern.match(endpoint);
    if (!match.hasMatch() || match.captured(1).toInt() < 1 || match.captured(1).toInt() > 65535)
        return reject("endpoint_invalid");
    static const QRegularExpression addressPattern(QStringLiteral("^[0-9.]{7,15}(/[0-9]{1,2})?$"));
    if (!addressPattern.match(target.value("clientAddress").toString()).hasMatch()) return reject("address_invalid");
    const auto parameters = target.value("parameters").toObject();
    if (parameters.isEmpty()) return reject("parameters_empty");
    const auto allowed = parameterKeys();
    for (auto it = parameters.begin(); it != parameters.end(); ++it) {
        if (!allowed.contains(it.key()) || !it.value().isString() || it.value().toString().size() > 4096
            || it.value().toString().contains('\n') || it.value().toString().contains('\r'))
            return reject("parameter_invalid");
    }
    if (strictBase64(parameters.value("HeaderProtectionKey").toString(), 32).isEmpty())
        return reject("header_key_invalid");
    for (const auto &name : {"S1", "S2", "S3", "S4"}) {
        bool ok = false;
        const int value = parameters.value(name).toString().toInt(&ok);
        if (!ok || value < 12 || value > 65535) return reject("padding_invalid");
    }
    const auto challenge = offer.value("challenge").toObject();
    if (!hasExactKeys(challenge, {"address", "port", "nonce"})
        || challenge.value("nonce").toString().isEmpty()) return reject("challenge_fields");
    return true;
}
} // namespace amnezia::awgMigration
