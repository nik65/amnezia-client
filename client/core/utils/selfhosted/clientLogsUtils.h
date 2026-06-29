#ifndef CLIENTLOGSUTILS_H
#define CLIENTLOGSUTILS_H

#include <QJsonObject>
#include <QString>

#include "core/models/containerConfig.h"
#include "core/utils/containerEnum.h"

namespace amnezia::clientLogsUtils
{
    QString endpoint();
    QString bootstrapEndpoint();
    QString storageId(DockerContainer container, const QString &clientId);
    QJsonObject explicitTarget(const QString &clientLogId, const QString &token);
    QJsonObject legacyBootstrapTarget(DockerContainer container, const ContainerConfig &containerConfig);
}

#endif // CLIENTLOGSUTILS_H
