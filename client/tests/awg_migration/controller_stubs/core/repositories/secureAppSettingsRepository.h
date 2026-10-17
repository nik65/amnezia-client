#pragma once
#include <QString>
class SecureAppSettingsRepository {
public:
    QString remoteLogToken(const QString &) const { return "fixture-token"; }
};
