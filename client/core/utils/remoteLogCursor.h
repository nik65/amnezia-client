#ifndef REMOTELOGCURSOR_H
#define REMOTELOGCURSOR_H

#include <QSettings>
#include <QString>

namespace amnezia
{

inline bool remoteLogCursorMetadataPresent(const QSettings &settings,
                                           const QString &prefix)
{
    return settings.contains(prefix + QStringLiteral("offset"))
            || settings.contains(prefix + QStringLiteral("fingerprint"))
            || settings.contains(prefix + QStringLiteral("fingerprintBytes"))
            || settings.contains(prefix + QStringLiteral("anchor"))
            || settings.contains(prefix + QStringLiteral("sanitizerSecretSetSha256"))
            || settings.contains(prefix + QStringLiteral("streamStateVersion"))
            || settings.contains(prefix + QStringLiteral("streamStateBlockKind"))
            || settings.contains(prefix + QStringLiteral("streamStateArrayOpen"))
            || settings.contains(prefix + QStringLiteral("streamStateArrayDepth"))
            || settings.contains(prefix + QStringLiteral("streamStateArrayQuote"))
            || settings.contains(prefix + QStringLiteral("streamStateArrayEscaped"))
            || settings.contains(prefix + QStringLiteral("streamStatePendingKind"))
            || settings.contains(prefix + QStringLiteral("streamStatePendingPhase"))
            || settings.contains(prefix + QStringLiteral("streamStatePendingWhitespaceBytes"))
            || settings.contains(prefix + QStringLiteral("streamStateOffset"))
            || settings.contains(prefix + QStringLiteral("privateKeyBlockOpen"));
}

inline qint64 remoteLogCursorInt64(const QVariant &value, qint64 fallback,
                                   bool *conversionOk)
{
    if (!value.isValid()) {
        if (conversionOk) {
            *conversionOk = true;
        }
        return fallback;
    }
    return value.toLongLong(conversionOk);
}

} // namespace amnezia

#endif // REMOTELOGCURSOR_H
