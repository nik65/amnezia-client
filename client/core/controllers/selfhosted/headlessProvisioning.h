#ifndef AMNEZIA_HEADLESS_PROVISIONING_H
#define AMNEZIA_HEADLESS_PROVISIONING_H

#include <QJsonArray>
#include <QStringList>

namespace amnezia::selfhostedUpdates
{
inline bool hasSupportedHeadlessProvisioningFiles(const QJsonValue &value)
{
    if (!value.isArray()) {
        return false;
    }
    static const QStringList legacy {
        QStringLiteral("install_headless.sh"), QStringLiteral("amneziad"),
        QStringLiteral("amnezia-cli"), QStringLiteral("amneziad.service"),
        QStringLiteral("package-manifest.json"), QStringLiteral("runtime-dependencies.json"),
        QStringLiteral("runtime-dependencies.txt"), QStringLiteral("SHA256SUMS")
    };
    const QJsonArray files = value.toArray();
    if (files.size() != legacy.size() && files.size() != legacy.size() + 1) {
        return false;
    }
    for (qsizetype index = 0; index < legacy.size(); ++index) {
        if (!files.at(index).isString() || files.at(index).toString() != legacy.at(index)) {
            return false;
        }
    }
    return files.size() == legacy.size()
            || (files.last().isString() && files.last().toString() == QStringLiteral("amnezia-headless-fs"));
}
}

#endif
