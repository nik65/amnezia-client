#pragma once
#include <QCryptographicHash>
#include <QJsonObject>
#include <QMap>
#include <QStringList>

namespace amnezia::awgBackendObservation {
inline QString normalized(const QString &key, QString value)
{
    value = value.trimmed();
    if (key == "RandomTrailers" || key == "DisableCookies") {
        value = value.toLower();
        if (value == "false" || value == "off" || value == "0") return "0";
        if (value == "true" || value == "on" || value == "1") return "1";
    }
    return value;
}
inline QString digest(const QString &key, const QString &value)
{
    return QString::fromLatin1(QCryptographicHash::hash(normalized(key, value).toUtf8(), QCryptographicHash::Sha256).toHex());
}
inline QJsonObject parameterDigests(const QString &reply)
{
    const QMap<QString, QString> names{{"jc", "Jc"}, {"jmin", "Jmin"}, {"jmax", "Jmax"},
        {"s1", "S1"}, {"s2", "S2"}, {"s3", "S3"}, {"s4", "S4"},
        {"h1", "H1"}, {"h2", "H2"}, {"h3", "H3"}, {"h4", "H4"},
        {"i1", "I1"}, {"i2", "I2"}, {"i3", "I3"}, {"i4", "I4"}, {"i5", "I5"},
        {"header_protection_key", "HeaderProtectionKey"}, {"content_padding_addition", "ContentPaddingAddition"},
        {"rekey_after_time", "RekeyAfterTime"}, {"rekey_timeout", "RekeyTimeout"},
        {"reject_after_time", "RejectAfterTime"}, {"keepalive_timeout", "KeepaliveTimeout"},
        {"max_handshake_attempts", "MaxHandshakeAttempts"}, {"random_trailers", "RandomTrailers"}, {"disable_cookies", "DisableCookies"}};
    QJsonObject result;
    for (const auto &key : {"Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "ContentPaddingAddition"})
        result[QLatin1String(key)] = digest(QLatin1String(key), "0");
    for (const auto &key : {"I1", "I2", "I3", "I4", "I5"}) result[QLatin1String(key)] = digest(QLatin1String(key), "");
    for (const auto &line : reply.split('\n')) {
        const auto nativeKey = line.section('=', 0, 0);
        if (!names.contains(nativeKey)) continue;
        const auto key = names.value(nativeKey);
        auto value = line.section('=', 1).trimmed();
        if (key == "HeaderProtectionKey") value = QString::fromLatin1(QByteArray::fromHex(value.toUtf8()).toBase64());
        result[key] = digest(key, value);
    }
    return result;
}
}
