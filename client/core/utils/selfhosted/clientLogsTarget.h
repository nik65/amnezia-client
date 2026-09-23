#ifndef CLIENTLOGSTARGET_H
#define CLIENTLOGSTARGET_H

#include <QJsonObject>
#include <QRegularExpression>
#include <QString>
#include <QUrl>

#include "core/utils/constants/configKeys.h"
#include "core/utils/constants/protocolConstants.h"

namespace amnezia::clientLogsTarget
{

inline QString endpoint()
{
    return QStringLiteral("http://%1:%2%3")
            .arg(QString::fromLatin1(protocols::clientLogs::syncHost),
                 QString::number(protocols::clientLogs::syncPort),
                 QString::fromLatin1(protocols::clientLogs::uploadPath));
}

inline QString bootstrapEndpoint()
{
    return QStringLiteral("http://%1:%2%3")
            .arg(QString::fromLatin1(protocols::clientLogs::syncHost),
                 QString::number(protocols::clientLogs::syncPort),
                 QString::fromLatin1(protocols::clientLogs::bootstrapPath));
}

inline bool isTrustedEndpoint(const QString &value)
{
    const QUrl url(value);
    return url.isValid() && url.scheme() == QStringLiteral("http")
            && url.host() == QString::fromLatin1(protocols::clientLogs::syncHost)
            && url.port() == protocols::clientLogs::syncPort
            && url.path() == QString::fromLatin1(protocols::clientLogs::uploadPath)
            && url.query().isEmpty() && url.fragment().isEmpty();
}

inline bool isClientId(const QString &value)
{
    static const QRegularExpression expression(QStringLiteral("^[0-9a-fA-F]{64}$"));
    return expression.match(value).hasMatch();
}

inline bool validate(const QJsonObject &target, QString *error = nullptr)
{
    const auto fail = [error](const QString &message) {
        if (error) *error = message;
        return false;
    };
    const QString targetEndpoint = target.value(configKey::clientLogsEndpoint).toString().trimmed();
    const QString clientId = target.value(configKey::clientLogsClientId).toString().trimmed();
    const QString token = target.value(configKey::clientLogsToken).toString();
    const bool bootstrap = target.value(configKey::clientLogsBootstrap).toBool(false);
    if (!isTrustedEndpoint(targetEndpoint)) return fail(QStringLiteral("clientLogs endpoint is not trusted"));
    if (!isClientId(clientId)) return fail(QStringLiteral("clientLogs clientId is invalid"));
    if (token.isEmpty() && !bootstrap) return fail(QStringLiteral("clientLogs token is missing"));
    if (token.size() > 4096) return fail(QStringLiteral("clientLogs token is too large"));
    return true;
}

} // namespace amnezia::clientLogsTarget

#endif // CLIENTLOGSTARGET_H
