#pragma once
#include <QObject>
#include <QJsonObject>
#include <QTimer>
#include <functional>
#include "core/repositories/secureServersRepository.h"
#include "core/repositories/secureAppSettingsRepository.h"

class AwgMigrationController final : public QObject {
public:
    AwgMigrationController(SecureServersRepository *, SecureAppSettingsRepository *, QObject *parent);
    QJsonObject prepare(const QString &serverId, const QJsonObject &connection);
    void observe(const QString &serverId, quint64 epoch, const QJsonObject &observation);
    void cancel();
    void failed();
    QString serverId() const { return m_serverId; }
    void cleanupFailed() { persist("recovery_required"); }
    std::function<void(const QJsonObject &)> reconnectLegacy;
private:
    void enrollOrFetch();
    void challenge();
    void acknowledge();
    void request(const QString &path, const QJsonObject &body,
                 std::function<void(const QJsonObject &)> callback);
    bool persist(const QString &state);
    SecureServersRepository *m_servers;
    SecureAppSettingsRepository *m_settings;
    QString m_serverId;
    QJsonObject m_originalConnection, m_sourceProfile, m_journal, m_observation;
    QTimer m_deadline;
    quint64 m_epoch = 0, m_callbackGeneration = 0;
    qint64 m_startedAt = 0;
    qint64 m_pollAfter = 0;
    double m_initialRx = 0, m_initialTx = 0;
    bool m_trial = false, m_busy = false, m_cancelled = false;
    bool m_committingProfile = false;
};
