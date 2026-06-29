#include "clientLogsUtils.h"

#include <QCryptographicHash>

#include "core/utils/constants/configKeys.h"
#include "core/utils/constants/protocolConstants.h"
#include "core/utils/containers/containerUtils.h"

namespace amnezia::clientLogsUtils
{
QString endpoint()
{
    return QStringLiteral("http://%1:%2%3")
            .arg(QString::fromLatin1(protocols::clientLogs::syncHost),
                 QString::number(protocols::clientLogs::syncPort),
                 QString::fromLatin1(protocols::clientLogs::uploadPath));
}

QString bootstrapEndpoint()
{
    return QStringLiteral("http://%1:%2%3")
            .arg(QString::fromLatin1(protocols::clientLogs::syncHost),
                 QString::number(protocols::clientLogs::syncPort),
                 QString::fromLatin1(protocols::clientLogs::bootstrapPath));
}

QString storageId(DockerContainer container, const QString &clientId)
{
    if (clientId.isEmpty() || ContainerUtils::containerService(container) == ServiceType::Other) {
        return {};
    }
    const QString scope = QStringLiteral("%1\t%2").arg(ContainerUtils::containerToString(container), clientId);
    return QString::fromLatin1(QCryptographicHash::hash(scope.toUtf8(), QCryptographicHash::Sha256).toHex());
}

QJsonObject explicitTarget(const QString &clientLogId, const QString &token)
{
    QJsonObject clientLogs;
    if (clientLogId.isEmpty() || token.isEmpty()) {
        return clientLogs;
    }
    clientLogs.insert(configKey::clientLogsEndpoint, endpoint());
    clientLogs.insert(configKey::clientLogsClientId, clientLogId);
    clientLogs.insert(configKey::clientLogsToken, token);
    return clientLogs;
}

QJsonObject legacyBootstrapTarget(DockerContainer container, const ContainerConfig &containerConfig)
{
    QJsonObject clientLogs;
    if (container != DockerContainer::Awg
        && container != DockerContainer::Awg2
        && container != DockerContainer::WireGuard) {
        return clientLogs;
    }

    QString clientId = containerConfig.protocolConfig.clientId();
    if (clientId.isEmpty()) {
        clientId = containerConfig.protocolConfig.getClientConfigJson().value(configKey::clientPubKey).toString();
    }
    const QString clientLogId = storageId(container, clientId);
    if (clientLogId.isEmpty()) {
        return clientLogs;
    }
    clientLogs.insert(configKey::clientLogsEndpoint, endpoint());
    clientLogs.insert(configKey::clientLogsClientId, clientLogId);
    clientLogs.insert(configKey::clientLogsBootstrap, true);
    return clientLogs;
}
}
