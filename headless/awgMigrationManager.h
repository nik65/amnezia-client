#pragma once

#include <QJsonObject>
#include "profileStore.h"
#include "vpnBackend.h"
#include "../common/awgMigration.h"
class AwgMigrationTest;

namespace amnezia::headless {
// All writes are confined to a private cache. The imported profile is immutable.
class AwgMigrationManager final {
public:
    AwgMigrationManager(QString root, QString credentialsPath, bool requireRoot, QString trustedSourceRoot = {});
    bool load(QString *error);
    bool candidate(const Profile &profile, QString &path, QString &sourceHash);
    bool enroll(const Profile &profile, const QString &interfaceName, VpnBackend *backend = nullptr);
    bool begin(const Profile &profile);
    bool verify(const Profile &profile, VpnBackend &backend, qint64 startedAt);
    bool commit(const Profile &profile);
    bool abandon(const Profile &profile);
    bool acknowledge(const Profile &profile, VpnBackend &backend);
    QJsonObject status() const;
    QString profileRoot(const Profile &profile) const;
private:
    friend class ::AwgMigrationTest;
    bool secureDirectory(const QString &path) const;
    bool read(const QString &path, QByteArray &bytes) const;
    bool readLegacy(const QString &path, QByteArray &bytes) const;
    bool save(const QString &path, const QByteArray &bytes) const;
    bool writeState(const Profile &profile, const QJsonObject &state);
    QJsonObject state(const Profile &profile) const;
    bool source(const Profile &profile, QByteArray &bytes, QJsonObject &identity,
                amnezia::awgMigration::Binding &binding) const;
    bool exchange(const QString &interfaceName, const QString &address, int port,
                  const QString &path, const QJsonObject &body, const QJsonObject &headers,
                  QJsonObject &response) const;
    bool retireStaged(const Profile &profile, QJsonObject &journal);
    static QJsonObject enrollmentRequest(const amnezia::awgMigration::Binding &binding);
    static bool validateRefreshedOffer(const QJsonObject &offer, const QJsonObject &previous,
                                      const amnezia::awgMigration::Binding &binding, qint64 now);
    static bool validateRenewal(const QJsonObject &renewal, const QJsonObject &journal,
                               const QString &nonce, qint64 now);
    QString m_root;
    QString m_credentialsPath;
    QString m_sourceRoot;
    bool m_requireRoot;
    QString m_lastState = QStringLiteral("not_enrolled");
};
}
