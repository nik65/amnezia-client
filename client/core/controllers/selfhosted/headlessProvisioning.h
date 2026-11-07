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
    static const QString nativeVerifier = QStringLiteral("amnezia-verify-provisioning-native");
    static const QString nativeHelper = QStringLiteral("amnezia-headless-fs");
    const qsizetype count = files.size();
    if (count != legacy.size() && count != legacy.size() + 1 && count != legacy.size() + 2) {
        return false;
    }
    for (qsizetype index = 0; index < legacy.size(); ++index) {
        if (!files.at(index).isString() || files.at(index).toString() != legacy.at(index)) {
            return false;
        }
    }
    if (count == legacy.size()) {
        return true;
    }
    const bool hasHelper = files.at(legacy.size()).isString()
            && files.at(legacy.size()).toString() == nativeHelper;
    if (count == legacy.size() + 1) {
        return hasHelper
                || (files.last().isString() && files.last().toString() == nativeVerifier);
    }
    return hasHelper
            && files.last().isString() && files.last().toString() == nativeVerifier;
}
}

#endif
